// Package proxy is guard's egress point. The sandbox lets the harness reach
// loopback only, so every outbound byte passes through here, where two things
// happen: (1) the destination is checked against an allowlist, and (2) for LLM
// APIs the auth header is injected from guard's own environment, so the secret
// never has to exist inside the sandbox.
package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"guard/internal/filter"
	"guard/internal/policy"
)

// Proxy is an HTTP server bound to loopback.
type Proxy struct {
	allow       map[string]bool // exact host allowlist for CONNECT
	routes      []route         // key-injection reverse routes
	filter      *filter.Filter  // content firewall on LLM traffic
	lim         *limiter        // rate / budget caps
	logger      *log.Logger
	ln          net.Listener
	srv         *http.Server
	mu          sync.Mutex
	denyCount   int
	filterCount int
	limitCount  int
}

// limiter enforces per-session request-count, rate (fixed 60s window) and
// cumulative-byte caps. A zero cap means that dimension is unlimited. It checks
// before consuming budget, so a rejected request does not count against it.
type limiter struct {
	mu          sync.Mutex
	maxReq      int
	ratePerMin  int
	maxBytes    int64
	reqCount    int
	byteCount   int64
	windowStart time.Time
	windowCount int
}

func newLimiter(maxReq, ratePerMin int, maxBytes int64) *limiter {
	return &limiter{maxReq: maxReq, ratePerMin: ratePerMin, maxBytes: maxBytes, windowStart: time.Now()}
}

// admit reports whether a request carrying nbytes of body may proceed.
func (l *limiter) admit(nbytes int64) (bool, string) {
	if l == nil {
		return true, ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.windowStart) >= time.Minute {
		l.windowStart = now
		l.windowCount = 0
	}
	if l.maxReq > 0 && l.reqCount+1 > l.maxReq {
		return false, "max_requests exceeded"
	}
	if l.ratePerMin > 0 && l.windowCount+1 > l.ratePerMin {
		return false, "rate_per_min exceeded"
	}
	if l.maxBytes > 0 && nbytes > 0 && l.byteCount+nbytes > l.maxBytes {
		return false, "max_request_bytes exceeded"
	}
	l.reqCount++
	l.windowCount++
	if nbytes > 0 {
		l.byteCount += nbytes
	}
	return true, ""
}

type route struct {
	prefix   string
	upstream *url.URL
	header   string
	value    string // resolved from guard's env at startup
	methods  map[string]bool
	paths    []string // allowed upstream path prefixes
	query    *queryPolicy
	rp       *httputil.ReverseProxy
}

// queryPolicy is the compiled per-parameter query filter.
type queryPolicy struct {
	allow      map[string]bool
	deny       map[string]bool
	maxLen     int
	paramRules []paramRule
}

type paramRule struct {
	param  string
	re     *regexp.Regexp
	action filter.Action
}

// allows reports whether a (method, upstream-path) pair is permitted by this
// route's request allowlist. An empty allowlist permits anything.
func (rt route) allows(method, upstreamPath string) bool {
	if len(rt.methods) > 0 && !rt.methods[strings.ToUpper(method)] {
		return false
	}
	if len(rt.paths) > 0 {
		ok := false
		for _, p := range rt.paths {
			if strings.HasPrefix(upstreamPath, p) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// New builds a proxy from the policy. Secrets are read from guard's env HERE,
// in the trusted parent, and captured in the closure — they are never placed in
// the child's environment.
func New(r *policy.Resolved, logger *log.Logger) (*Proxy, error) {
	f, err := filter.New(r.PromptFilter)
	if err != nil {
		return nil, err
	}
	p := &Proxy{allow: map[string]bool{}, filter: f, logger: logger}
	if r.Limits.MaxRequests > 0 || r.Limits.RatePerMin > 0 || r.Limits.MaxRequestBytes > 0 {
		p.lim = newLimiter(r.Limits.MaxRequests, r.Limits.RatePerMin, r.Limits.MaxRequestBytes)
	}
	for _, d := range r.AllowDomains {
		p.allow[strings.ToLower(d)] = true
	}
	for _, ki := range r.KeyInject {
		u, err := url.Parse(ki.Upstream)
		if err != nil {
			return nil, fmt.Errorf("key_injection upstream %q: %w", ki.Upstream, err)
		}
		val := os.Getenv(ki.Env)
		methods := map[string]bool{}
		for _, m := range ki.Methods {
			methods[strings.ToUpper(m)] = true
		}
		rt := route{prefix: ki.Prefix, upstream: u, header: ki.Header, value: val, methods: methods, paths: ki.AllowPaths}
		if ki.Query.Enabled() {
			qp := &queryPolicy{allow: map[string]bool{}, deny: map[string]bool{}, maxLen: ki.Query.MaxParamLen}
			for _, a := range ki.Query.AllowParams {
				qp.allow[a] = true
			}
			for _, d := range ki.Query.DenyParams {
				qp.deny[d] = true
			}
			for _, pr := range ki.Query.ParamRules {
				re, err := regexp.Compile(pr.Pattern)
				if err != nil {
					return nil, fmt.Errorf("query param_rule %q: %w", pr.Param, err)
				}
				qp.paramRules = append(qp.paramRules, paramRule{param: pr.Param, re: re, action: filter.ParseAction(pr.Action, filter.Block)})
			}
			rt.query = qp
		}
		up := u
		hdr := ki.Header
		prefix := ki.Prefix
		rt.rp = &httputil.ReverseProxy{
			Director: func(req *http.Request) {
				req.URL.Scheme = up.Scheme
				req.URL.Host = up.Host
				req.Host = up.Host
				req.URL.Path = strings.TrimPrefix(req.URL.Path, prefix)
				if val != "" {
					req.Header.Set(hdr, val)
				}
			},
			ModifyResponse: p.scanResponse,
		}
		p.routes = append(p.routes, rt)
		// The allowlist must also cover the upstream host for consistency.
		p.allow[strings.ToLower(hostOnly(u.Host))] = true
	}
	return p, nil
}

func hostOnly(h string) string {
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		return h[:i]
	}
	return h
}

// Start binds the proxy to 127.0.0.1:port (0 = auto) and begins serving.
// It returns the actual port.
func (p *Proxy) Start(port int) (int, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return 0, err
	}
	p.ln = ln
	p.srv = &http.Server{Handler: p}
	go func() {
		if err := p.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			p.logger.Printf("proxy serve error: %v", err)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// Close stops the proxy.
func (p *Proxy) Close() error {
	if p.srv != nil {
		return p.srv.Close()
	}
	return nil
}

// DenyCount reports how many requests were blocked (for the attack report).
func (p *Proxy) DenyCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.denyCount
}

func (p *Proxy) deny(w http.ResponseWriter, host, why string) {
	p.mu.Lock()
	p.denyCount++
	p.mu.Unlock()
	p.logger.Printf("DENY  %-40s %s", host, why)
	http.Error(w, "blocked by guard egress policy: "+why, http.StatusForbidden)
}

// admit applies the rate/budget limiter. Returns false (429 already written) if
// the request must be rejected.
func (p *Proxy) admit(w http.ResponseWriter, req *http.Request) bool {
	nbytes := req.ContentLength
	if nbytes < 0 {
		nbytes = 0
	}
	ok, why := p.lim.admit(nbytes)
	if ok {
		return true
	}
	p.mu.Lock()
	p.limitCount++
	p.mu.Unlock()
	p.logger.Printf("LIMIT %s %s  %s", req.Method, req.Host, why)
	http.Error(w, "throttled by guard limits: "+why, http.StatusTooManyRequests)
	return false
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// CONNECT = HTTPS tunnel. Check the host allowlist, then splice sockets.
	if req.Method == http.MethodConnect {
		host := hostOnly(req.Host)
		if !p.allow[strings.ToLower(host)] {
			p.deny(w, req.Host, "host not in allowlist")
			return
		}
		if !p.admit(w, req) {
			return
		}
		p.logger.Printf("ALLOW CONNECT %s", req.Host)
		p.tunnel(w, req)
		return
	}
	// Plain HTTP: either a key-injection route (path-prefixed) or a forward
	// proxy request to an allowlisted host.
	for _, rt := range p.routes {
		if strings.HasPrefix(req.URL.Path, rt.prefix) {
			upstreamPath := strings.TrimPrefix(req.URL.Path, rt.prefix)
			if !rt.allows(req.Method, upstreamPath) {
				p.mu.Lock()
				p.denyCount++
				p.mu.Unlock()
				p.logger.Printf("DENY  %s %s  request not permitted on route %s", req.Method, upstreamPath, rt.prefix)
				http.Error(w, "request not permitted by guard: "+req.Method+" "+upstreamPath, http.StatusForbidden)
				return
			}
			if !p.admit(w, req) {
				return // throttled by rate/budget limits
			}
			if !p.filterQuery(w, req, rt) {
				return // blocked by structured query policy
			}
			if !p.filterURL(w, req, rt.prefix) {
				return // blocked by the content firewall (URL/query)
			}
			if !p.filterRequest(w, req) {
				return // blocked by the content firewall (body)
			}
			p.logger.Printf("ALLOW inject %s %s -> %s", req.Method, upstreamPath, rt.upstream)
			rt.rp.ServeHTTP(w, req)
			return
		}
	}
	host := hostOnly(req.Host)
	if host == "" || !p.allow[strings.ToLower(host)] {
		p.deny(w, req.Host, "host not in allowlist")
		return
	}
	if !p.admit(w, req) {
		return
	}
	p.forward(w, req)
}

// LimitCount reports how many requests the rate/budget limiter rejected.
func (p *Proxy) LimitCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.limitCount
}

func (p *Proxy) tunnel(w http.ResponseWriter, req *http.Request) {
	dst, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
	hj, ok := w.(http.Hijacker)
	if !ok {
		dst.Close()
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	src, _, err := hj.Hijack()
	if err != nil {
		dst.Close()
		return
	}
	go func() { io.Copy(dst, src); dst.Close() }()
	go func() { io.Copy(src, dst); src.Close() }()
}

// filterRequest runs the outbound prompt through the content firewall. It
// returns false (and has already written the response) if the request was
// blocked. On allow/redact it replaces the body so the (possibly redacted)
// bytes are what actually get sent upstream.
func (p *Proxy) filterRequest(w http.ResponseWriter, req *http.Request) bool {
	if p.filter == nil || !p.filter.Enabled() || req.Body == nil {
		return true
	}
	body, err := io.ReadAll(req.Body)
	req.Body.Close()
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadGateway)
		return false
	}
	out, d := p.filter.Request(body)
	if len(d.Flagged) > 0 {
		// Flag = detected but the prompt was NOT changed or stopped.
		p.logger.Printf("FILTER FLAG request rules=%s (prompt forwarded unchanged)", strings.Join(d.Flagged, ","))
	}
	switch d.Action {
	case filter.Block:
		p.mu.Lock()
		p.filterCount++
		p.mu.Unlock()
		p.logger.Printf("FILTER BLOCK request rule=%s", d.Rule)
		http.Error(w, "blocked by guard prompt filter: "+d.Rule, http.StatusForbidden)
		return false
	case filter.Redact:
		p.mu.Lock()
		p.filterCount++
		p.mu.Unlock()
		// A redaction SILENTLY changed the user's prompt — say so loudly.
		p.logger.Printf("\x1b[33mFILTER REDACT request: your prompt was modified (%d span(s), rule=%s)\x1b[0m", d.Count, d.Rule)
	}
	req.Body = io.NopCloser(bytes.NewReader(out))
	req.ContentLength = int64(len(out))
	req.Header.Set("Content-Length", strconv.Itoa(len(out)))
	return true
}

// filterQuery enforces the structured per-parameter query policy for a route:
// which params may appear, their max length, and content rules scoped to a
// single param (e.g. the search term `q`). Returns false (403 written) on block.
func (p *Proxy) filterQuery(w http.ResponseWriter, req *http.Request, rt route) bool {
	if rt.query == nil {
		return true
	}
	qp := rt.query
	vals, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		p.queryBlock(w, "malformed query string")
		return false
	}
	changed := false
	for key, list := range vals {
		if qp.deny[key] {
			p.queryBlock(w, "parameter not allowed: "+key)
			return false
		}
		if len(qp.allow) > 0 && !qp.allow[key] {
			p.queryBlock(w, "unexpected parameter: "+key)
			return false
		}
		for i, v := range list {
			if qp.maxLen > 0 && len(v) > qp.maxLen {
				p.queryBlock(w, "parameter too long: "+key)
				return false
			}
			for _, pr := range qp.paramRules {
				if pr.param != key || !pr.re.MatchString(v) {
					continue
				}
				switch pr.action {
				case filter.Block:
					p.queryBlock(w, "forbidden value in parameter: "+key)
					return false
				case filter.Redact:
					list[i] = pr.re.ReplaceAllString(v, "[REDACTED]")
					changed = true
					p.logger.Printf("\x1b[33mFILTER REDACT query param=%s\x1b[0m", key)
				default: // flag
					p.logger.Printf("FILTER FLAG query param=%s (forwarded unchanged)", key)
				}
			}
		}
		vals[key] = list
	}
	if changed {
		req.URL.RawQuery = vals.Encode()
	}
	return true
}

func (p *Proxy) queryBlock(w http.ResponseWriter, why string) {
	p.mu.Lock()
	p.filterCount++
	p.mu.Unlock()
	p.logger.Printf("FILTER BLOCK query: %s", why)
	http.Error(w, "blocked by guard query policy: "+why, http.StatusForbidden)
}

// filterURL runs the request's path+query (where a harness's search terms live)
// through the content firewall before forwarding. Returns false (response
// already written) if the request was blocked.
func (p *Proxy) filterURL(w http.ResponseWriter, req *http.Request, prefix string) bool {
	if p.filter == nil || !p.filter.Enabled() {
		return true
	}
	upstreamPath := strings.TrimPrefix(req.URL.Path, prefix)
	newQuery, d := p.filter.URL(upstreamPath, req.URL.RawQuery)
	if len(d.Flagged) > 0 {
		p.logger.Printf("FILTER FLAG url rules=%s (query forwarded unchanged)", strings.Join(d.Flagged, ","))
	}
	switch d.Action {
	case filter.Block:
		p.mu.Lock()
		p.filterCount++
		p.mu.Unlock()
		p.logger.Printf("FILTER BLOCK url rule=%s path=%s", d.Rule, upstreamPath)
		http.Error(w, "blocked by guard request filter: "+d.Rule, http.StatusForbidden)
		return false
	case filter.Redact:
		p.mu.Lock()
		p.filterCount++
		p.mu.Unlock()
		p.logger.Printf("\x1b[33mFILTER REDACT url: query modified (rule=%s)\x1b[0m", d.Rule)
		req.URL.RawQuery = newQuery
	}
	return true
}

// scanResponse is the ReverseProxy ModifyResponse hook: it inspects model
// output and, on a blocking match, swaps the body for an error so injected
// instructions never reach the harness. Streaming responses (SSE) are passed
// through unscanned — buffering a stream would break token-by-token output.
func (p *Proxy) scanResponse(resp *http.Response) error {
	if p.filter == nil || !p.filter.ScanResponses() {
		return nil
	}
	if strings.Contains(resp.Header.Get("Content-Type"), "text/event-stream") {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	_, d := p.filter.Response(body)
	if len(d.Flagged) > 0 {
		p.logger.Printf("FILTER FLAG response rules=%s (output forwarded unchanged)", strings.Join(d.Flagged, ","))
	}
	if d.Action == filter.Block {
		p.mu.Lock()
		p.filterCount++
		p.mu.Unlock()
		p.logger.Printf("FILTER BLOCK response rule=%s", d.Rule)
		msg := []byte(`{"error":"guard prompt filter blocked model output: ` + d.Rule + `"}`)
		resp.Body = io.NopCloser(bytes.NewReader(msg))
		resp.ContentLength = int64(len(msg))
		resp.Header.Set("Content-Length", strconv.Itoa(len(msg)))
		resp.StatusCode = http.StatusForbidden
		resp.Status = "403 Forbidden"
		return nil
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return nil
}

// FilterCount reports how many requests/responses the content firewall acted on.
func (p *Proxy) FilterCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.filterCount
}

// CloseFilter releases the filter's audit log.
func (p *Proxy) CloseFilter() error {
	if p.filter != nil {
		return p.filter.Close()
	}
	return nil
}

func (p *Proxy) forward(w http.ResponseWriter, req *http.Request) {
	req.RequestURI = ""
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
