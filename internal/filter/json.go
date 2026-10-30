package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// JSONPolicy constrains structured API requests. Paths are JSON pointers;
// a whole '*' segment matches one object key or array index.
type JSONPolicy struct {
	RequireJSON bool       `json:"require_json"`
	AllowModels []string   `json:"allow_models"`
	DenyFields  []string   `json:"deny_fields"`
	Rules       []JSONRule `json:"rules"`
}
type JSONRule struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Pattern string `json:"pattern"`
	Action  string `json:"action"`
}
type jsonRule struct {
	JSONRule
	re *regexp.Regexp
}
type JSONFilter struct {
	cfg   JSONPolicy
	rules []jsonRule
}

func NewJSON(cfg JSONPolicy) (*JSONFilter, error) {
	f := &JSONFilter{cfg: cfg}
	for _, p := range cfg.DenyFields {
		if !validPointer(p) {
			return nil, fmt.Errorf("invalid JSON field pointer %q", p)
		}
	}
	for _, r := range cfg.Rules {
		if !validPointer(r.Path) {
			return nil, fmt.Errorf("invalid JSON rule pointer %q", r.Path)
		}
		if !validAction(r.Action) {
			return nil, fmt.Errorf("JSON rule %q: invalid action %q", r.Name, r.Action)
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("JSON rule %q: %w", r.Name, err)
		}
		f.rules = append(f.rules, jsonRule{r, re})
	}
	return f, nil
}
func validPointer(p string) bool {
	if p != "" && !strings.HasPrefix(p, "/") {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] == '~' {
			if i+1 == len(p) || (p[i+1] != '0' && p[i+1] != '1') {
				return false
			}
			i++
		}
	}
	return true
}
func validAction(a string) bool {
	switch a {
	case "", "block", "redact", "flag":
		return true
	}
	return false
}
func pointerPart(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
func pointerMatches(pattern, path string) bool {
	a, b := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != "*" && a[i] != b[i] {
			return false
		}
	}
	return true
}
func decodeJSON(body []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	v, err := readJSONValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("expected one JSON value")
	}
	return v, nil
}
func readJSONValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 256 {
		return nil, fmt.Errorf("JSON nesting exceeds 256 levels")
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return token, nil
	}
	switch delimiter {
	case '{':
		obj := map[string]any{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("invalid JSON object key")
			}
			if _, exists := obj[key]; exists {
				return nil, fmt.Errorf("duplicate JSON key")
			}
			value, err := readJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			obj[key] = value
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim('}') {
			return nil, fmt.Errorf("invalid JSON object")
		}
		return obj, nil
	case '[':
		values := []any{}
		for dec.More() {
			value, err := readJSONValue(dec, depth+1)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		end, err := dec.Token()
		if err != nil || end != json.Delim(']') {
			return nil, fmt.Errorf("invalid JSON array")
		}
		return values, nil
	}
	return nil, fmt.Errorf("unexpected JSON delimiter")
}

// Request applies route restrictions first, then scans decoded JSON strings.
// Unchanged requests retain their original bytes, including in monitor mode.
func (j *JSONFilter) Request(body []byte, f *Filter) ([]byte, Decision) {
	return j.apply(body, f.Request)
}
func (j *JSONFilter) Response(body []byte, f *Filter) ([]byte, Decision) {
	return j.apply(body, f.ResponseText)
}
func (j *JSONFilter) apply(body []byte, inspect func([]byte) ([]byte, Decision)) ([]byte, Decision) {
	v, err := decodeJSON(body)
	if err != nil {
		if j.cfg.RequireJSON || len(j.cfg.AllowModels) > 0 || len(j.cfg.DenyFields) > 0 || len(j.rules) > 0 {
			return body, Decision{Action: Block, Rule: "invalid_json"}
		}
		return inspect(body)
	}
	if len(j.cfg.AllowModels) > 0 {
		obj, ok := v.(map[string]any)
		model, _ := obj["model"].(string)
		allowed := false
		for _, m := range j.cfg.AllowModels {
			if model == m {
				allowed = true
			}
		}
		if !ok || !allowed {
			return body, Decision{Action: Block, Rule: "model_not_allowed"}
		}
	}
	total := Decision{Action: Allow}
	var walk func(any, string) any
	walk = func(value any, path string) any {
		if total.Action == Block {
			return value
		}
		for _, p := range j.cfg.DenyFields {
			if pointerMatches(p, path) {
				total = Decision{Action: Block, Rule: "forbidden_json_field:" + p}
				return value
			}
		}
		// Evaluate all block rules against the original value before redactions.
		text, ok := value.(string)
		encoded := false
		var redactions []jsonRule
		for _, r := range j.rules {
			if !pointerMatches(r.Path, path) {
				continue
			}
			if !ok && !encoded {
				b, _ := json.Marshal(value)
				text = string(b)
				encoded = true
			}
			if !r.re.MatchString(text) {
				continue
			}
			switch parseAction(r.Action, Block) {
			case Block:
				total = Decision{Action: Block, Rule: r.Name}
				return value
			case Redact:
				if !ok {
					total = Decision{Action: Block, Rule: "redact_requires_string:" + r.Name}
					return value
				}
				redactions = append(redactions, r)
			default:
				total.Flagged = append(total.Flagged, r.Name)
			}
		}
		switch x := value.(type) {
		case string:
			// Global content policy scans decoded strings, before route redaction.
			out, d := inspect([]byte(x))
			mergeDecision(&total, d)
			if total.Action == Block {
				return value
			}
			text = string(out)
			for _, r := range redactions {
				text = r.re.ReplaceAllStringFunc(text, func(string) string { total.Count++; return "[REDACTED:" + r.Name + "]" })
				total.Action = Redact
				total.Rule = r.Name
			}
			return text
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				_, d := inspect([]byte(k))
				if d.Action == Redact {
					d.Action = Block
					d.Rule = "redaction_in_json_key"
				}
				mergeDecision(&total, d)
				x[k] = walk(x[k], path+"/"+pointerPart(k))
			}
		case []any:
			for i := range x {
				x[i] = walk(x[i], path+"/"+strconv.Itoa(i))
			}
		}
		return value
	}
	v = walk(v, "")
	if total.Action != Redact {
		return body, total
	}
	out, err := json.Marshal(v)
	if err != nil {
		return body, Decision{Action: Block, Rule: "json_encode_error"}
	}
	return out, total
}
func mergeDecision(dst *Decision, src Decision) {
	if dst.Action == Block {
		return
	}
	dst.Flagged = append(dst.Flagged, src.Flagged...)
	dst.Monitored = dst.Monitored || src.Monitored
	if src.Action == Block {
		dst.Action = Block
		dst.Rule = src.Rule
		return
	}
	if src.Action == Redact {
		dst.Action = Redact
		dst.Rule = src.Rule
		dst.Count += src.Count
	}
}

// DecodeJSON rejects duplicate keys, trailing documents and excessive nesting.
func DecodeJSON(body []byte) (any, error) { return decodeJSON(body) }
