// Package proxy is guard's egress point. The sandbox lets the harness reach
// loopback only, so every outbound byte passes through here, where two things
// happen: (1) the destination is checked against an allowlist, and (2) for LLM
// APIs the auth header is injected from guard's own environment, so the secret
// never has to exist inside the sandbox.
package proxy

import (
	"bytes"
	"context"
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

	"guard/internal/credential"
	"guard/internal/filter"
	"guard/internal/injection"
	"guard/internal/policy"
)

// Hard buffering ceilings also apply in monitor mode and with filtering disabled.
const maxBufferedBody = 8 << 20

// Proxy is an HTTP server bound to loopback.
type Proxy struct {
	injection     *injection.Detector
	responseSlots chan struct{}
	mcp           http.Handler
	allow         map[string]bool // exact host allowlist for CONNECT
	routes        []route         // key-injection reverse routes
	filter        *filter.Filter  // content firewall on LLM traffic
	maxFilterBody int
	lim           *limiter // rate / budget caps
	logger        *log.Logger
	ln            net.Listener
	srv           *http.Server
	mu            sync.Mutex
	denyCount     int
	filterCount   int
	limitCount    int
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

type credentialHeadersKey struct{}

type route struct {
	auth     *credential.Provider
	prefix   string
	upstream *url.URL
	header   string
	value    string // resolved from guard's env at startup
	methods  map[string]bool
	paths    []string // allowed upstream path prefixes
	json     *filter.JSONFilter
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
			if upstreamPath == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(upstreamPath, p)) {
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
	p := &Proxy{responseSlots: make(chan struct{}, 4), allow: map[string]bool{}, filter: f, logger: logger, maxFilterBody: r.PromptFilter.MaxBodyBytes}
	success := false
	defer func() {
		if !success {
			p.injection.Close()
			f.Close()
		}
	}()
	if r.Limits.MaxRequests > 0 || r.Limits.RatePerMin > 0 || r.Limits.MaxRequestBytes > 0 {
		p.lim = newLimiter(r.Limits.MaxRequests, r.Limits.RatePerMin, r.Limits.MaxRequestBytes)
	}
	p.injection, err = injection.New(r.PromptInjection)
	if err != nil {
		return nil, err
	}
	if r.PromptInjection.Enabled {
		f.ProtectSecret(os.Getenv(r.PromptInjection.Defaults().TokenEnv))
	}
	for _, d := range r.AllowDomains {
		p.allow[strings.ToLower(d)] = true
	}
	for _, ki := range r.KeyInject {
		u, err := url.Parse(ki.Upstream)
		if err != nil {
			return nil, fmt.Errorf("key_injection upstream: %w", err)
		}
		if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			return nil, fmt.Errorf("key_injection upstream must be an http(s) origin without credentials, path or query")
		}
		if ki.Prefix == "" || !strings.HasPrefix(ki.Prefix, "/") || strings.HasSuffix(ki.Prefix, "/") {
			return nil, fmt.Errorf("route prefix must start with / and have no trailing /")
		}
		val := os.Getenv(ki.Env)
		if ki.Env != "" && val == "" {
			return nil, fmt.Errorf("required credential environment variable %s is empty", ki.Env)
		}
		if val != "" {
			f.ProtectSecret(val)
			val = ki.HeaderPrefix + val
		}
		jf, err := filter.NewJSON(ki.JSON)
		if err != nil {
			return nil, err
		}
		methods := map[string]bool{}
		for _, m := range ki.Methods {
			methods[strings.ToUpper(m)] = true
		}
		var provider *credential.Provider
		if ki.Auth.Type != "" {
			provider, err = credential.New(ki.Auth)
			if err != nil {
				return nil, err
			}
			secrets, err := provider.Secrets()
			if err != nil {
				return nil, err
			}
			for _, secret := range secrets {
				f.ProtectSecret(secret)
			}
		}
		rt := route{auth: provider, json: jf, prefix: ki.Prefix, upstream: u, header: ki.Header, value: val, methods: methods, paths: ki.AllowPaths}
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
				req.URL.RawPath = ""
				req.Header.Del("Authorization")
				req.Header.Del("Proxy-Authorization")
				req.Header.Del("ChatGPT-Account-ID")
				if hdr != "" {
					req.Header.Del(hdr)
				}
				if val != "" {
					req.Header.Set(hdr, val)
				}
				if p.filter.ScanResponses() {
					req.Header.Set("Accept-Encoding", "identity")
				}
				if headers, ok := req.Context().Value(credentialHeadersKey{}).(http.Header); ok {
					for k, v := range headers {
						req.Header[k] = append([]string(nil), v...)
					}
				}
			},
			ModifyResponse: p.scanResponse,
		}
		p.routes = append(p.routes, rt)

	}
	success = true
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
	p.srv = &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 60 * time.Second}
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
	var nbytes int64
	if req.Method != http.MethodConnect && req.Body != nil {
		// Count actual bytes, including chunked requests, before atomically
		// admitting them against the shared session budget.
		body, err := io.ReadAll(io.LimitReader(req.Body, maxBufferedBody+1))
		req.Body.Close()
		if err != nil {
			http.Error(w, "read body failed", http.StatusBadRequest)
			return false
		}
		if len(body) > maxBufferedBody {
			http.Error(w, "request body exceeds buffering limit", http.StatusRequestEntityTooLarge)
			return false
		}
		nbytes = int64(len(body))
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = nbytes
		req.TransferEncoding = nil
		req.Header.Del("Transfer-Encoding")
		req.Header.Del("Content-Length")
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

func (p *Proxy) SetMCP(h http.Handler) { p.mu.Lock(); defer p.mu.Unlock(); p.mcp = h }

func (p *Proxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if strings.HasPrefix(req.URL.Path, "/__guard/") {
		p.mu.Lock()
		h := p.mcp
		p.mu.Unlock()
		if h == nil {
			http.NotFound(w, req)
			return
		}
		h.ServeHTTP(w, req)
		return
	}
	if req.Header.Get("Upgrade") != "" {
		p.deny(w, req.Host, "protocol upgrades are disabled; use HTTP/SSE")
		return
	}
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
		if req.URL.Path == rt.prefix || strings.HasPrefix(req.URL.Path, rt.prefix+"/") {
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
			if !p.filterRequest(w, req, rt.json) {
				return // blocked by the content firewall (body)
			}
			if rt.auth != nil {
				headers, err := rt.auth.Headers(req.Context())
				if err != nil {
					p.logger.Printf("Codex authentication unavailable: %v", err)
					http.Error(w, "Codex authentication unavailable; log in outside guard", http.StatusServiceUnavailable)
					return
				}
				// Values are consumed by the reverse proxy only after filtering.
				req = req.WithContext(context.WithValue(req.Context(), credentialHeadersKey{}, headers))
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
func (p *Proxy) filterRequest(w http.ResponseWriter, req *http.Request, jf *filter.JSONFilter) bool {
	if encoding := req.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
		p.queryBlock(w, "encoded request bodies are not supported")
		return false
	}
	if req.Body == nil {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxBufferedBody+1))
	req.Body.Close()
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadGateway)
		return false
	}
	if len(body) > maxBufferedBody {
		http.Error(w, "request body exceeds buffering limit", http.StatusRequestEntityTooLarge)
		return false
	}
	var out []byte
	var d filter.Decision
	if jf != nil {
		out, d = jf.Request(body, p.filter)
	} else {
		out, d = p.filter.Request(body)
	}
	if p.maxFilterBody > 0 && len(body) > p.maxFilterBody {
		_, sizeDecision := p.filter.Request(body)
		if sizeDecision.Action == filter.Block {
			out, d = body, sizeDecision
		} else {
			d.Flagged = append(d.Flagged, sizeDecision.Flagged...)
		}
	}
	if d.Action != filter.Block {
		verdict := p.injection.Scan(req.Context(), "model_request", out)
		p.recordInjection("model_request", verdict)
		if verdict.Block {
			d = filter.Decision{Action: filter.Block, Rule: verdict.Rule}
		}
		if verdict.Flag {
			d.Flagged = append(d.Flagged, verdict.Rule)
		}
	}
	p.filter.Record("request-body", d)
	if err := p.filter.AuditError(); err != nil {
		p.logger.Printf("audit write failed: %v", err)
		http.Error(w, "guard audit log unavailable", http.StatusServiceUnavailable)
		return false
	}
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
					list[i] = pr.re.ReplaceAllString(list[i], "[REDACTED]")
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
	p.filter.Record("request-query", filter.Decision{Action: filter.Block, Rule: why})
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

// FilterCount reports how many requests/responses the content firewall acted on.
func (p *Proxy) FilterCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.filterCount
}

// CloseFilter releases the filter's audit log.
func (p *Proxy) CloseFilter() error {
	p.injection.Close()
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

func (p *Proxy) CredentialPaths() []string {
	var paths []string
	for _, rt := range p.routes {
		if rt.auth != nil {
			paths = append(paths, rt.auth.Home())
		}
	}
	return paths
}

func (p *Proxy) recordInjection(source string, v injection.Decision) {
	if v.Model == "" {
		return
	}
	d := filter.Decision{Action: filter.Allow, Rule: v.Rule}
	if v.Block {
		d.Action = filter.Block
	}
	if v.Flag {
		d.Flagged = []string{v.Rule}
	}
	p.filter.RecordDetail("prompt-injection:"+source, d, fmt.Sprintf("model=%s score=%.6f sha256=%s", v.Model, v.Score, v.Hash))
}
