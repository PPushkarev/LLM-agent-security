package proxy

import (
	"encoding/json"
	"fmt"
	"guard/internal/filter"
	"guard/internal/policy"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func responseProxy(t *testing.T, cfg filter.Config) *Proxy {
	t.Helper()
	p, err := New(&policy.Resolved{PromptFilter: cfg}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.CloseFilter() })
	return p
}
func sseEvent(kind string, value any) string {
	b, _ := json.Marshal(value)
	return fmt.Sprintf("event: %s\ndata: %s\n\n", kind, b)
}
func modelResponse(body, kind string) *http.Response {
	return &http.Response{StatusCode: 200, Status: "200 OK", Header: http.Header{"Content-Type": []string{kind}}, Body: io.NopCloser(strings.NewReader(body))}
}
func TestModelSSESplitGuardrails(t *testing.T) {
	for _, action := range []string{"block", "redact", "flag"} {
		t.Run(action, func(t *testing.T) {
			cfg := filter.Config{Enabled: true, ScanResponses: true, ResponseRules: []filter.Rule{{Name: "email", Pattern: `[A-Za-z]+@[A-Za-z]+\.[A-Za-z]+`, Action: action}}}
			p := responseProxy(t, cfg)
			body := sseEvent("response.output_text.delta", map[string]any{"type": "response.output_text.delta", "item_id": "one", "output_index": 0, "delta": "alice@"}) + sseEvent("response.output_text.delta", map[string]any{"type": "response.output_text.delta", "item_id": "one", "output_index": 0, "delta": "example.com"}) + sseEvent("response.completed", map[string]any{"type": "response.completed", "response": map[string]any{"output": []any{map[string]any{"text": "alice@example.com"}}}})
			resp := modelResponse(body, "text/event-stream")
			if err := p.scanResponse(resp); err != nil {
				t.Fatal(err)
			}
			out, _ := io.ReadAll(resp.Body)
			switch action {
			case "block":
				if resp.StatusCode != 403 || strings.Contains(string(out), "alice@") {
					t.Fatalf("leaked blocked SSE: %s", out)
				}
			case "redact":
				if resp.StatusCode != 200 || strings.Contains(string(out), "alice@") || strings.Contains(string(out), "example.com") || !strings.Contains(string(out), "[REDACTED:email]") {
					t.Fatalf("unredacted fragments: %s", out)
				}
			case "flag":
				if resp.StatusCode != 200 || string(out) != body {
					t.Fatalf("flag changed SSE: %s", out)
				}
			}
		})
	}
}
func TestModelSSEBlocksSplitToolArguments(t *testing.T) {
	p := responseProxy(t, filter.Config{Enabled: true, ScanResponses: true, ResponseRules: []filter.Rule{{Name: "dangerous_command", Pattern: `rm\s+-rf\s+/`, Action: "block"}}})
	body := sseEvent("response.function_call_arguments.delta", map[string]any{"type": "response.function_call_arguments.delta", "item_id": "tool", "delta": "{\"command\":\"rm -"}) + sseEvent("response.function_call_arguments.delta", map[string]any{"type": "response.function_call_arguments.delta", "item_id": "tool", "delta": "rf /\"}"}) + sseEvent("response.completed", map[string]any{"type": "response.completed", "response": map[string]any{}})
	resp := modelResponse(body, "text/event-stream")
	if err := p.scanResponse(resp); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 403 || strings.Contains(string(out), "function_call_arguments") {
		t.Fatalf("tool call leaked: %s", out)
	}
}
func TestResponseSchemaAndJSONRules(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","properties":{"answer":{"type":"string"}},"required":["answer"],"additionalProperties":false}`)
	cfg := filter.Config{Enabled: true, ScanResponses: true, ResponseSchema: schema, ResponseSchemaPath: "/output/0/content/0/text"}
	p := responseProxy(t, cfg)
	for _, tc := range []struct {
		answer string
		status int
	}{{`{"answer":"ok"}`, 200}, {`{"wrong":true}`, 403}} {
		value := map[string]any{"output": []any{map[string]any{"content": []any{map[string]any{"text": tc.answer}}}}}
		for _, stream := range []bool{false, true} {
			b, _ := json.Marshal(value)
			content := string(b)
			kind := "application/json"
			if stream {
				content = sseEvent("response.completed", map[string]any{"type": "response.completed", "response": value})
				kind = "text/event-stream"
			}
			resp := modelResponse(content, kind)
			if err := p.scanResponse(resp); err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != tc.status {
				t.Fatalf("answer %s stream=%t status=%d", tc.answer, stream, resp.StatusCode)
			}
		}
	}
	p = responseProxy(t, filter.Config{Enabled: true, ScanResponses: true, ResponseJSON: filter.JSONPolicy{RequireJSON: true, DenyFields: []string{"/private"}, Rules: []filter.JSONRule{{Name: "client", Path: "/answer", Pattern: "Acme", Action: "redact"}}}})
	resp := modelResponse(`{"answer":"Acme"}`, "application/json")
	if err := p.scanResponse(resp); err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(b), "Acme") || resp.StatusCode != 200 {
		t.Fatal(string(b))
	}
	resp = modelResponse(`{"private":"hidden"}`, "application/json")
	if err := p.scanResponse(resp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatal("forbidden response field allowed")
	}
}
func TestSSEFailureModes(t *testing.T) {
	p := responseProxy(t, filter.Config{Enabled: true, ScanResponses: true})
	for _, body := range []string{
		"data: {\"delta\":\"partial\"}\n\n",
		"data: {\"delta\":\"a\",\"delta\":\"b\"}\n\ndata: [DONE]\n\n",
		"data: [DONE]\n\ndata: {\"delta\":\"after\"}\n\n",
	} {
		resp := modelResponse(body, "text/event-stream")
		if err := p.scanResponse(resp); err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 403 {
			t.Fatalf("malformed stream allowed: %s", body)
		}
	}
}
func TestResponseGateBeforeDelivery(t *testing.T) {
	released := make(chan struct{})
	release := sync.OnceFunc(func() { close(released) })
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: {\"delta\":\"safe prefix\"}\n\n")
		w.(http.Flusher).Flush()
		<-released
		io.WriteString(w, "data: {\"delta\":\"FORBIDDEN\"}\n\ndata: [DONE]\n\n")
	}))
	defer upstream.Close()
	p, err := New(&policy.Resolved{PromptFilter: filter.Config{Enabled: true, ScanResponses: true, ResponseRules: []filter.Rule{{Name: "blocked", Pattern: "FORBIDDEN", Action: "block"}}}, KeyInject: []policy.KeyInjection{{Prefix: "/model", Upstream: upstream.URL}}}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseFilter()
	proxy := httptest.NewServer(p)
	defer proxy.Close()
	defer release()
	result := make(chan *http.Response, 1)
	go func() { resp, _ := proxy.Client().Get(proxy.URL + "/model"); result <- resp }()
	select {
	case resp := <-result:
		if resp != nil {
			resp.Body.Close()
		}
		t.Fatal("partial stream reached harness")
	case <-time.After(100 * time.Millisecond):
	}
	release()
	select {
	case resp := <-result:
		if resp == nil {
			t.Fatal("missing response")
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != 403 || strings.Contains(string(body), "safe prefix") || strings.Contains(string(body), "FORBIDDEN") {
			t.Fatalf("response leaked: %s", body)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("response never completed")
	}
}
func TestResponseTimeout(t *testing.T) {
	p := responseProxy(t, filter.Config{Enabled: true, ScanResponses: true, ResponseTimeoutSec: 1})
	read, write := io.Pipe()
	defer write.Close()
	resp := modelResponse("", "text/event-stream")
	resp.Body = read
	if err := p.scanResponse(resp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 403 {
		t.Fatal("timeout did not block")
	}
}

func TestSSEInterleavedChoices(t *testing.T) {
	p := responseProxy(t, filter.Config{Enabled: true, ScanResponses: true, ResponseRules: []filter.Rule{{Name: "email", Pattern: `[A-Za-z]+@[A-Za-z]+\.[A-Za-z]+`, Action: "redact"}}})
	event := func(index int, content string) string {
		return sseEvent("message", map[string]any{"choices": []any{map[string]any{"index": index, "delta": map[string]any{"content": content}}}})
	}
	body := event(0, "alice@") + event(1, "unrelated") + event(0, "example.com") + "data: [DONE]\n\n"
	resp := modelResponse(body, "text/event-stream")
	if err := p.scanResponse(resp); err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || strings.Contains(string(out), "alice@") || strings.Contains(string(out), "example.com") || !strings.Contains(string(out), "unrelated") {
		t.Fatalf("choice isolation: %s", out)
	}
}
