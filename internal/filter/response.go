package filter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
)

func compileResponseSchema(raw json.RawMessage, path string) (*jsonschema.Resolved, error) {
	if !validPointer(path) || strings.Contains(path, "*") {
		return nil, fmt.Errorf("response_schema_path must be an exact JSON pointer")
	}
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		if path != "" {
			return nil, fmt.Errorf("response_schema_path requires response_schema")
		}
		return nil, nil
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(raw, &schema); err != nil {
		return nil, err
	}
	return schema.Resolve(&jsonschema.ResolveOptions{Loader: func(*url.URL) (*jsonschema.Schema, error) {
		return nil, fmt.Errorf("external response schema references disabled")
	}})
}
func (f *Filter) ResponseLimits() (int, time.Duration) {
	max := f.cfg.ResponseMaxBytes
	if max == 0 {
		max = 8 << 20
	}
	seconds := f.cfg.ResponseTimeoutSec
	if seconds == 0 {
		seconds = 120
	}
	return max, time.Duration(seconds) * time.Second
}
func (f *Filter) HasResponseSchema() bool                     { return f.responseSchema != nil }
func (f *Filter) ResponseText(body []byte) ([]byte, Decision) { return f.responseText(body, 0) }
func (f *Filter) responseText(body []byte, depth int) ([]byte, Decision) {
	if !f.ScanResponses() {
		return body, Decision{Action: Allow}
	}
	if depth > 16 {
		return body, f.responseDecision("embedded_response_json_depth")
	}
	out, d := f.scanRules("response", body, f.respBlock)
	if d.Action == Block {
		return body, d
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') || !json.Valid(body) {
		return out, d
	}
	value, err := decodeJSON(body)
	if err != nil {
		return body, f.responseDecision("invalid_embedded_response_json")
	}
	total := Decision{Action: Allow}
	var walk func(any) any
	walk = func(v any) any {
		if total.Action == Block {
			return v
		}
		switch x := v.(type) {
		case string:
			clean, decision := f.responseText([]byte(x), depth+1)
			mergeDecision(&total, decision)
			return string(clean)
		case map[string]any:
			for key, value := range x {
				_, kd := f.scanRules("response", []byte(key), f.respBlock)
				if kd.Action == Redact {
					kd.Action = Block
					kd.Rule = "redaction_in_response_json_key"
				}
				mergeDecision(&total, kd)
				x[key] = walk(value)
			}
		case []any:
			for i, value := range x {
				x[i] = walk(value)
			}
		}
		return v
	}
	value = walk(value)
	if total.Action == Block {
		return body, total
	}
	if total.Action == Redact {
		clean, err := json.Marshal(value)
		if err != nil {
			return body, f.responseDecision("response_json_encoding")
		}
		return clean, total
	}
	if d.Action == Redact {
		return body, f.responseDecision("unsafe_response_json_redaction")
	}
	mergeDecision(&total, d)
	return body, total
}

// ResponseEvent scans decoded strings and structured paths, without requiring
// every intermediate SSE event to satisfy the final-response JSON schema.
func (f *Filter) ResponseEvent(body []byte) ([]byte, Decision) {
	if !f.ScanResponses() {
		return body, Decision{Action: Allow}
	}
	_, raw := f.ResponseText(body)
	if raw.Action == Block {
		return body, raw
	}
	out, d := f.responseJSON.Response(body, f)
	// Structured response policies are mandatory even in monitor mode, matching
	// request JSON policies. Only free-text regex actions become monitor-only.
	return out, d
}
func (f *Filter) ValidateResponseSchema(body []byte) Decision {
	if f.responseSchema == nil {
		return Decision{Action: Allow}
	}
	v, err := decodeJSON(body)
	if err != nil {
		return f.responseDecision("response_schema_invalid_json")
	}
	if path := f.cfg.ResponseSchemaPath; path != "" {
		for _, part := range strings.Split(path[1:], "/") {
			part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
			switch x := v.(type) {
			case map[string]any:
				var ok bool
				v, ok = x[part]
				if !ok {
					return f.responseDecision("response_schema_path_missing")
				}
			case []any:
				i, e := strconv.Atoi(part)
				if e != nil || i < 0 || i >= len(x) {
					return f.responseDecision("response_schema_path_missing")
				}
				v = x[i]
			default:
				return f.responseDecision("response_schema_path_missing")
			}
		}
		if text, ok := v.(string); ok {
			v, err = decodeJSON([]byte(text))
			if err != nil {
				return f.responseDecision("response_schema_invalid_json")
			}
		}
	}
	if err := f.responseSchema.Validate(v); err != nil {
		return f.responseDecision("response_schema_mismatch")
	}
	return Decision{Action: Allow}
}
func (f *Filter) responseDecision(rule string) Decision {
	d := Decision{Action: Block, Rule: rule}
	f.Record("response", d)
	return d
}
func (f *Filter) Response(body []byte) ([]byte, Decision) {
	if !f.ScanResponses() {
		return body, Decision{Action: Allow}
	}
	if d := f.ValidateResponseSchema(body); d.Action == Block {
		return body, d
	}
	out, d := f.ResponseEvent(body)
	if d.Action == Redact && !bytes.Equal(out, body) {
		if valid := f.ValidateResponseSchema(out); valid.Action == Block {
			return body, valid
		}
	}
	return out, d
}
