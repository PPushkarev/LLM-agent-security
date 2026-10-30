package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"guard/internal/filter"
)

// scanResponse gates the WHOLE response before any bytes or tool calls reach the
// harness. Bounded buffering intentionally replaces token-by-token streaming.
func (p *Proxy) scanResponse(resp *http.Response) error {
	if p.filter == nil || !p.filter.ScanResponses() {
		return nil
	}
	select {
	case p.responseSlots <- struct{}{}:
		defer func() { <-p.responseSlots }()
	default:
		resp.Body.Close()
		return p.responseBlocked(resp, "response_parallel_limit")
	}
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
		resp.Body.Close()
		return p.responseBlocked(resp, "encoded_response")
	}
	max, timeout := p.filter.ResponseLimits()
	timer := time.AfterFunc(timeout, func() { resp.Body.Close() })
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(max)+1))
	timely := timer.Stop()
	resp.Body.Close()
	if !timely {
		return p.responseBlocked(resp, "response_timeout")
	}
	if err != nil {
		return p.responseBlocked(resp, "response_read_error")
	}
	if len(body) > max {
		p.filter.Record("response", filter.Decision{Action: filter.Block, Rule: "response_max_bytes"})
		return fmt.Errorf("response body exceeds buffering limit")
	}
	var out []byte
	var decision filter.Decision
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		out, decision = p.scanSSE(body)
	} else {
		out, decision = p.filter.Response(body)
	}
	p.filter.Record("response", decision)
	if err := p.filter.AuditError(); err != nil {
		return fmt.Errorf("response audit write failed: %w", err)
	}
	if len(decision.Flagged) > 0 {
		p.logger.Printf("FILTER FLAG response rules=%s", strings.Join(decision.Flagged, ","))
	}
	if decision.Action == filter.Block {
		return p.responseBlocked(resp, decision.Rule)
	}
	if len(out) > max {
		return p.responseBlocked(resp, "response_max_bytes_after_redaction")
	}
	if decision.Action == filter.Redact {
		p.mu.Lock()
		p.filterCount++
		p.mu.Unlock()
		p.logger.Printf("FILTER REDACT response rule=%s", decision.Rule)
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	resp.Header.Set("Content-Length", fmt.Sprint(len(out)))
	resp.Header.Del("ETag")
	resp.Header.Del("Content-MD5")
	resp.Header.Del("Digest")
	return nil
}
func (p *Proxy) responseBlocked(resp *http.Response, rule string) error {
	d := filter.Decision{Action: filter.Block, Rule: rule}
	p.filter.Record("response", d)
	if err := p.filter.AuditError(); err != nil {
		return fmt.Errorf("response audit write failed: %w", err)
	}
	p.mu.Lock()
	p.filterCount++
	p.mu.Unlock()
	p.logger.Printf("FILTER BLOCK response rule=%s", rule)
	body, _ := json.Marshal(map[string]any{"error": map[string]string{"type": "guardrail_violation", "message": "guard blocked model response", "rule": rule}})
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.StatusCode = http.StatusForbidden
	resp.Status = "403 Forbidden"
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Content-Length", fmt.Sprint(len(body)))
	for _, h := range []string{"Content-Encoding", "ETag", "Content-MD5", "Digest"} {
		resp.Header.Del(h)
	}
	return nil
}

type responseFrame struct {
	lines     []string
	value     any
	dataLines []string
	data      string
	hasData   bool
	done      bool
}
type responseFragment struct {
	object    map[string]any
	key, text string
}

func (p *Proxy) scanSSE(body []byte) ([]byte, filter.Decision) {
	block := func(rule string) ([]byte, filter.Decision) {
		return body, filter.Decision{Action: filter.Block, Rule: rule}
	}
	text := strings.ReplaceAll(strings.ReplaceAll(strings.TrimPrefix(string(body), "\xef\xbb\xbf"), "\r\n", "\n"), "\r", "\n")
	var frames []*responseFrame
	frame := &responseFrame{}
	flush := func() {
		if len(frame.lines) > 0 {
			frame.data = strings.Join(frame.dataLines, "\n")
			frames = append(frames, frame)
		}
		frame = &responseFrame{}
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 131072 {
		return block("response_line_limit")
	}
	for _, line := range lines {
		if line == "" {
			flush()
			continue
		}
		frame.lines = append(frame.lines, line)
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			key = line
			value = ""
		}
		value = strings.TrimPrefix(value, " ")
		if key == "data" {
			frame.dataLines = append(frame.dataLines, value)
			frame.hasData = true
		}

	}
	flush()
	if len(frames) > 32768 {
		return block("response_event_limit")
	}
	groups := map[string][]responseFragment{}
	terminal := false
	var final any
	decision := filter.Decision{Action: filter.Allow}
	for _, frame := range frames {
		for _, line := range frame.lines {
			key, _, _ := strings.Cut(line, ":")
			if key == "data" {
				continue
			}
			_, d := p.filter.ResponseText([]byte(line))
			if d.Action == filter.Block {
				return body, d
			}
			if d.Action == filter.Redact {
				return block("redaction_in_sse_metadata")
			}
		}
		if !frame.hasData {
			continue
		}
		if strings.TrimSpace(frame.data) == "[DONE]" {
			frame.done = true
			terminal = true
			continue
		}
		if terminal {
			return block("data_after_model_completion")
		}
		value, err := filter.DecodeJSON([]byte(frame.data))
		if err != nil {
			return block("invalid_model_event_json")
		}
		frame.value = value
		_, d := p.filter.ResponseEvent([]byte(frame.data))
		if d.Action == filter.Block {
			return body, d
		}
		obj, ok := value.(map[string]any)
		if !ok {
			return block("unsupported_model_event_shape")
		}
		kind, _ := obj["type"].(string)
		if kind == "response.completed" {
			terminal = true
			final = obj["response"]
		}
		if kind == "message_stop" {
			terminal = true
		}
		// Every delta field is aggregated by event type, output identity and JSON
		// path. Separate choices/tools never share a concatenation buffer.
		identity := fmt.Sprint(kind, "/", obj["item_id"], "/", obj["output_index"], "/", obj["content_index"], "/", obj["index"])
		collectResponseFragments(value, "", identity, false, groups)
	}
	if !terminal {
		return block("incomplete_model_stream")
	}
	if p.filter.HasResponseSchema() {
		if final == nil {
			return block("missing_final_response_for_schema")
		}
		raw, _ := json.Marshal(final)
		if d := p.filter.ValidateResponseSchema(raw); d.Action == filter.Block {
			return body, d
		}
	}
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fragments := groups[key]
		var combined strings.Builder
		for _, fragment := range fragments {
			combined.WriteString(fragment.text)
		}
		clean, d := p.filter.ResponseText([]byte(combined.String()))
		if d.Action == filter.Block {
			return body, d
		}
		if d.Action == filter.Redact {
			for _, fragment := range fragments {
				fragment.object[fragment.key] = ""
			}
			fragments[0].object[fragments[0].key] = string(clean)
			decision.Action = filter.Redact
			decision.Rule = d.Rule
			decision.Count += d.Count
		}
		decision.Flagged = append(decision.Flagged, d.Flagged...)
	}
	var output bytes.Buffer
	for _, frame := range frames {
		var clean []byte
		if frame.hasData && !frame.done {
			raw, _ := json.Marshal(frame.value)
			var d filter.Decision
			clean, d = p.filter.ResponseEvent(raw)
			if d.Action == filter.Block {
				return body, d
			}
			if d.Action == filter.Redact {
				decision.Action = d.Action
				decision.Rule = d.Rule
				decision.Count += d.Count
			}
			decision.Flagged = append(decision.Flagged, d.Flagged...)
			obj, _ := frame.value.(map[string]any)
			if obj["type"] == "response.completed" && p.filter.HasResponseSchema() {
				v, _ := filter.DecodeJSON(clean)
				m, _ := v.(map[string]any)
				finalBody, _ := json.Marshal(m["response"])
				if d := p.filter.ValidateResponseSchema(finalBody); d.Action == filter.Block {
					return body, d
				}
			}
		}
		wroteData := false
		for _, line := range frame.lines {
			key, _, _ := strings.Cut(line, ":")
			if key == "data" && frame.hasData && !frame.done {
				if !wroteData {
					output.WriteString("data: ")
					output.Write(clean)
					output.WriteByte('\n')
					wroteData = true
				}
				continue
			}
			output.WriteString(line)
			output.WriteByte('\n')
		}
		output.WriteByte('\n')
	}
	if decision.Action != filter.Redact {
		return body, decision
	}
	return output.Bytes(), decision
}
func collectResponseFragments(value any, path, identity string, inDelta bool, groups map[string][]responseFragment) {
	switch x := value.(type) {
	case map[string]any:
		if index, ok := x["index"]; ok {
			identity += fmt.Sprint("/index=", index)
		}
		for key, v := range x {
			delta := inDelta || key == "delta"
			if s, ok := v.(string); ok && delta && (key == "delta" || key == "text" || key == "content" || key == "arguments" || key == "partial_json") {
				group := identity + path + "/" + key
				groups[group] = append(groups[group], responseFragment{x, key, s})
			} else {
				collectResponseFragments(v, path+"/"+key, identity, delta, groups)
			}
		}
	case []any:
		for i, v := range x {
			segment := fmt.Sprint(i)
			if obj, ok := v.(map[string]any); ok {
				if index, ok := obj["index"]; ok {
					segment = fmt.Sprint("index=", index)
				}
			}
			collectResponseFragments(v, path+"/"+segment, identity, inDelta, groups)
		}
	}
}
