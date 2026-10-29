package proxy

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"guard/internal/filter"
	"guard/internal/policy"
)

func TestChunkedBudgetAndRedaction(t *testing.T) {
	var mu sync.Mutex
	var bodies, queries []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		queries = append(queries, r.URL.Query().Get("q"))
		mu.Unlock()
		fmt.Fprint(w, "ok")
	}))
	defer up.Close()
	p, err := New(&policy.Resolved{Limits: policy.Limits{MaxRequestBytes: 5}, KeyInject: []policy.KeyInjection{{Prefix: "/llm", Upstream: up.URL}}, PromptFilter: filter.Config{Enabled: true, Redact: []filter.Rule{{Name: "secret", Pattern: "sensitive", Action: "redact"}}}}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	defer p.CloseFilter()
	srv := httptest.NewServer(p)
	defer srv.Close()
	for i, tc := range []struct {
		body   string
		status int
	}{{"abc", 200}, {"xyz", 429}, {"de", 200}} {
		// NopCloser hides the reader's size, so net/http sends chunked encoding.
		req, _ := http.NewRequest("POST", srv.URL+"/llm/search?q=%73ensitive", io.NopCloser(strings.NewReader(tc.body)))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("request %d: status %d want %d", i, resp.StatusCode, tc.status)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || bodies[0] != "abc" || bodies[1] != "de" {
		t.Fatalf("upstream bodies %q", bodies)
	}
	for _, q := range queries {
		if q != "[REDACTED:secret]" {
			t.Fatalf("upstream query %q", q)
		}
	}
}

func TestBodyBufferLimits(t *testing.T) {
	p, err := New(&policy.Resolved{PromptFilter: filter.Config{Enabled: true, ScanResponses: true}}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "http://example.com", io.NopCloser(io.LimitReader(zeroReader{}, maxBufferedBody+100)))
	w := httptest.NewRecorder()
	if p.admit(w, req) || w.Code != 413 {
		t.Fatalf("oversized request admitted, status %d", w.Code)
	}
	resp := &http.Response{Header: make(http.Header), Body: io.NopCloser(io.LimitReader(zeroReader{}, maxBufferedBody+100))}
	if err := p.scanResponse(resp); err == nil {
		t.Fatal("oversized response admitted")
	}
	// SSE remains streamed rather than buffered.
	resp.Header.Set("Content-Type", "text/event-stream")
	if err := p.scanResponse(resp); err != nil {
		t.Fatal(err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) { clear(b); return len(b), nil }

func TestConcurrentByteBudget(t *testing.T) {
	l := newLimiter(0, 0, 10)
	var wg sync.WaitGroup
	var mu sync.Mutex
	accepted := 0
	for range 20 {
		wg.Go(func() {
			if ok, _ := l.admit(3); ok {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if accepted != 3 {
		t.Fatalf("admitted %d requests, want 3", accepted)
	}
}

func TestRouteRestrictions(t *testing.T) {
	hits := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		if r.Header.Get("Authorization") != "Bearer fixture-credential" {
			t.Error("wrong authorization")
		}
		fmt.Fprint(w, "ok")
	}))
	defer up.Close()
	t.Setenv("GUARD_FIXTURE_KEY", "fixture-credential")
	p, err := New(&policy.Resolved{KeyInject: []policy.KeyInjection{{Prefix: "/api", Upstream: up.URL, Env: "GUARD_FIXTURE_KEY", Header: "Authorization", HeaderPrefix: "Bearer ", Methods: []string{"POST"}, AllowPaths: []string{"/v1/responses"}, JSON: filter.JSONPolicy{RequireJSON: true, AllowModels: []string{"approved"}}}}, PromptFilter: filter.Config{Enabled: true}}, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path, method, body, encoding string
		status                       int
	}{
		{"/api/v1/responses", "POST", `{"model":"approved"}`, "", 200},
		{"/api/v1/responses-extra", "POST", `{"model":"approved"}`, "", 403},
		{"/api/v1/responses", "GET", `{"model":"approved"}`, "", 403},
		{"/api/v1/responses", "POST", `{"model":"other"}`, "", 403},
		{"/api/v1/responses", "POST", `broken`, "", 403},
		{"/api/v1/responses", "POST", `{"model":"approved"}`, "gzip", 403},
		{"/api/v1/responses", "POST", `{"model":"approved","text":"fixture-credential"}`, "", 403},
	} {
		req := httptest.NewRequest(tc.method, "http://localhost"+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Encoding", tc.encoding)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		if w.Code != tc.status {
			t.Errorf("%s %s: status %d want %d: %s", tc.method, tc.path, w.Code, tc.status, w.Body.String())
		}
	}
	if hits != 1 {
		t.Fatalf("unexpected requests reached upstream: %d", hits)
	}
	if p.allow["127.0.0.1"] {
		t.Fatal("injection upstream implicitly allowed for raw egress")
	}
}
