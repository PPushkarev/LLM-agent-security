// Package filter is guard's content firewall. Because the sandbox can only
// reach the egress proxy, and the LLM key-injection route travels as plaintext
// HTTP over loopback, the proxy sees every prompt in the clear and can inspect
// it WITHOUT terminating TLS or installing a MITM certificate.
//
// It does three jobs on the bytes flowing to/from the model:
//   - BLOCK: refuse a request whose body carries a secret (the agent trying to
//     exfiltrate a key by pasting it into a prompt) or other forbidden content.
//   - REDACT: rewrite matched spans (emails, bearer tokens, known literals)
//     before the prompt leaves the machine.
//   - SCAN RESPONSES: flag/stop model output that carries injection payloads.
//
// Every decision is written to an append-only audit log that lives OUTSIDE the
// sandbox, so a compromised agent cannot erase the record of what it tried.
package filter

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Action is the outcome of inspecting a payload.
type Action int

const (
	Allow Action = iota
	Redact
	Block
)

func (a Action) String() string {
	switch a {
	case Block:
		return "BLOCK"
	case Redact:
		return "REDACT"
	default:
		return "ALLOW"
	}
}

// Rule is one named regular expression from the policy. Action overrides the
// default action for the list the rule sits in: "block" refuses the request,
// "redact" rewrites the matched span (a SILENT change to the user's prompt —
// opt-in only), and "flag" records the match but forwards the prompt UNCHANGED.
type Rule struct {
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
	Action  string `json:"action"` // "block" | "redact" | "flag"; optional
}

// Config is the prompt_filter section of a policy.
type Config struct {
	Enabled bool `json:"enabled"`
	// Mode: "enforce" (default) applies each rule's action; "monitor" never
	// blocks and never alters a prompt — it only logs what WOULD have happened,
	// so you can tune rules without silently changing anyone's prompt.
	Mode          string   `json:"mode"`
	MaxBodyBytes  int      `json:"max_body_bytes"`
	Block         []Rule   `json:"block"`          // default action: block
	Redact        []Rule   `json:"redact"`         // default action: redact (silent rewrite)
	LiteralRedact []string `json:"literal_redact"` // exact strings always scrubbed
	ScanResponses bool     `json:"scan_responses"`
	ResponseBlock []Rule   `json:"response_block"` // model output matching these is refused
	AuditLog      string   `json:"audit_log"`      // path (guard-writable, outside the sandbox)
}

func (c Config) monitor() bool { return strings.EqualFold(c.Mode, "monitor") }

// Decision records what happened to one payload.
type Decision struct {
	Action    Action
	Rule      string   // the rule that triggered a Block, or a summary for Redact
	Count     int      // number of redactions applied
	Flagged   []string // rules that matched but did not alter/stop the payload
	Monitored bool     // true when a would-block/would-redact was downgraded by monitor mode
}

type compiledRule struct {
	name   string
	re     *regexp.Regexp
	action Action // effective action for this rule
}

// Filter is the compiled, ready-to-use firewall.
type Filter struct {
	cfg       Config
	reqRules  []compiledRule // block + redact + flag rules, in order
	literals  []string
	respBlock []compiledRule
	mu        sync.Mutex
	auditFile *os.File
}

// ParseAction maps a policy action string to an Action ("flag" and anything
// unrecognized → Allow, i.e. detect-but-forward).
func ParseAction(s string, def Action) Action { return parseAction(s, def) }

func parseAction(s string, def Action) Action {
	switch strings.ToLower(s) {
	case "block":
		return Block
	case "redact":
		return Redact
	case "flag", "allow", "monitor":
		return Allow
	default:
		return def
	}
}

// Built-in block rules are always active when the filter is enabled. They catch
// the most damaging exfiltration regardless of what the policy lists.
var builtinBlock = []Rule{
	{Name: "pem_private_key", Pattern: `-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`},
	{Name: "aws_access_key", Pattern: `\bAKIA[0-9A-Z]{16}\b`},
	{Name: "anthropic_key", Pattern: `\bsk-ant-[A-Za-z0-9_-]{20,}\b`},
	{Name: "openai_key", Pattern: `\bsk-[A-Za-z0-9]{32,}\b`},
	{Name: "github_token", Pattern: `\bgh[pousr]_[A-Za-z0-9]{20,}\b`},
	{Name: "gcp_sa_key", Pattern: `"private_key_id"\s*:\s*"[0-9a-f]{20,}"`},
}

func compile(rules []Rule, def Action) ([]compiledRule, error) {
	var out []compiledRule
	for _, r := range rules {
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("filter rule %q: %w", r.Name, err)
		}
		out = append(out, compiledRule{name: r.Name, re: re, action: parseAction(r.Action, def)})
	}
	return out, nil
}

// New compiles a Config into a Filter. A disabled or zero Config yields a
// pass-through filter.
func New(cfg Config) (*Filter, error) {
	f := &Filter{cfg: cfg, literals: cfg.LiteralRedact}
	if !cfg.Enabled {
		return f, nil
	}
	// Request rules are evaluated in order; built-in secret detectors (always
	// block) come first, then policy block rules, then redact rules.
	blockRules, err := compile(append(append([]Rule{}, builtinBlock...), cfg.Block...), Block)
	if err != nil {
		return nil, err
	}
	redactRules, err := compile(cfg.Redact, Redact)
	if err != nil {
		return nil, err
	}
	f.reqRules = append(blockRules, redactRules...)
	if f.respBlock, err = compile(cfg.ResponseBlock, Block); err != nil {
		return nil, err
	}
	if cfg.AuditLog != "" {
		fh, err := os.OpenFile(cfg.AuditLog, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("open audit log: %w", err)
		}
		f.auditFile = fh
	}
	return f, nil
}

// Enabled reports whether inspection is active.
func (f *Filter) Enabled() bool { return f.cfg.Enabled }

// ScanResponses reports whether model output should be inspected.
func (f *Filter) ScanResponses() bool { return f.cfg.Enabled && f.cfg.ScanResponses }

func (f *Filter) audit(direction string, d Decision, extra string) {
	if f.auditFile == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	flags := ""
	if len(d.Flagged) > 0 {
		flags = strings.Join(d.Flagged, ",")
	}
	mode := "enforce"
	if d.Monitored {
		mode = "monitor"
	}
	fmt.Fprintf(f.auditFile, "%s\t%s\t%s\tmode=%s\trule=%s\tcount=%d\tflagged=%s\t%s\n",
		time.Now().UTC().Format(time.RFC3339), direction, d.Action, mode, d.Rule, d.Count, flags, extra)
}

// Request inspects an outbound prompt body. It returns the (possibly redacted)
// body and a decision. In "monitor" mode nothing is ever blocked or altered —
// the body comes back exactly as written, with would-be actions recorded in
// Decision.Flagged. A "redact" action is the ONLY thing that silently changes a
// prompt, so it is opt-in per rule and always reported in the decision.
func (f *Filter) Request(body []byte) ([]byte, Decision) {
	if !f.cfg.Enabled {
		return body, Decision{Action: Allow}
	}
	if f.cfg.MaxBodyBytes > 0 && len(body) > f.cfg.MaxBodyBytes {
		if f.cfg.monitor() {
			d := Decision{Action: Allow, Monitored: true, Flagged: []string{"would-block:max_body_bytes"}}
			f.audit("request", d, fmt.Sprintf("size=%d", len(body)))
			return body, d
		}
		d := Decision{Action: Block, Rule: "max_body_bytes"}
		f.audit("request", d, fmt.Sprintf("size=%d", len(body)))
		return body, d
	}
	return f.scan("request", body)
}

// URL inspects an outbound request's path+query — this is where a harness's
// search query lives (e.g. GET /search?q=...). The query is percent-decoded for
// matching so a pattern sees the human-readable text. It returns the
// (possibly-rewritten) raw query and a decision.
func (f *Filter) URL(rawPath, rawQuery string) (string, Decision) {
	if !f.cfg.Enabled || (rawPath == "" && rawQuery == "") {
		return rawQuery, Decision{Action: Allow}
	}
	decoded := rawQuery
	if q, err := url.QueryUnescape(rawQuery); err == nil {
		decoded = q
	}
	_, d := f.scan("request-url", []byte(rawPath+"?"+decoded))
	if d.Action == Redact {
		// Best-effort: rewrite matched spans in the raw query. Percent-encoded
		// values that only match after decoding are blocked rather than redacted.
		out, _ := f.applyRedactions([]byte(rawQuery), f.matchingRedactRules([]byte(decoded)))
		return string(out), d
	}
	return rawQuery, d
}

// scan is the shared rule-evaluation core used by both body and URL inspection.
func (f *Filter) scan(label string, data []byte) ([]byte, Decision) {
	mon := f.cfg.monitor()
	var flagged []string
	var redactRules []compiledRule
	for _, r := range f.reqRules {
		if !r.re.Match(data) {
			continue
		}
		switch r.action {
		case Block:
			if mon {
				flagged = append(flagged, "would-block:"+r.name)
				continue
			}
			d := Decision{Action: Block, Rule: r.name}
			f.audit(label, d, "secret/forbidden content")
			return data, d
		case Redact:
			if mon {
				flagged = append(flagged, "would-redact:"+r.name)
				continue
			}
			redactRules = append(redactRules, r)
		default: // Allow == flag: detect, record, forward unchanged
			flagged = append(flagged, r.name)
		}
	}

	out, count := data, 0
	if !mon {
		out, count = f.applyRedactions(data, redactRules)
	} else {
		flagged = append(flagged, f.wouldRedactLiterals(data)...)
	}

	d := Decision{Action: Allow, Flagged: flagged, Monitored: mon}
	if count > 0 {
		d.Action = Redact
		d.Count = count
		d.Rule = redactNames(redactRules)
	}
	f.audit(label, d, "")
	return out, d
}

func (f *Filter) matchingRedactRules(data []byte) []compiledRule {
	var out []compiledRule
	for _, r := range f.reqRules {
		if r.action == Redact && r.re.Match(data) {
			out = append(out, r)
		}
	}
	return out
}

// Response inspects model output. In monitor mode it never blocks; it records a
// would-block instead.
func (f *Filter) Response(body []byte) ([]byte, Decision) {
	if !f.ScanResponses() {
		return body, Decision{Action: Allow}
	}
	mon := f.cfg.monitor()
	for _, r := range f.respBlock {
		if r.re.Match(body) {
			if mon {
				d := Decision{Action: Allow, Monitored: true, Flagged: []string{"would-block:" + r.name}}
				f.audit("response", d, "injection/forbidden content in model output")
				return body, d
			}
			d := Decision{Action: Block, Rule: r.name}
			f.audit("response", d, "injection/forbidden content in model output")
			return body, d
		}
	}
	f.audit("response", Decision{Action: Allow}, "")
	return body, Decision{Action: Allow}
}

func (f *Filter) applyRedactions(body []byte, rules []compiledRule) ([]byte, int) {
	count := 0
	for _, lit := range f.literals {
		if lit == "" {
			continue
		}
		re := regexp.MustCompile(regexp.QuoteMeta(lit))
		body = re.ReplaceAllFunc(body, func(m []byte) []byte {
			count++
			return []byte("[REDACTED]")
		})
	}
	for _, r := range rules {
		body = r.re.ReplaceAllFunc(body, func(m []byte) []byte {
			count++
			return []byte("[REDACTED:" + r.name + "]")
		})
	}
	return body, count
}

func (f *Filter) wouldRedactLiterals(body []byte) []string {
	var out []string
	for _, lit := range f.literals {
		if lit != "" && regexp.MustCompile(regexp.QuoteMeta(lit)).Match(body) {
			out = append(out, "would-redact:literal")
		}
	}
	return out
}

func redactNames(rules []compiledRule) string {
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.name)
	}
	if len(names) == 0 {
		return "literal"
	}
	return strings.Join(names, ",")
}

// Close releases the audit log.
func (f *Filter) Close() error {
	if f.auditFile != nil {
		return f.auditFile.Close()
	}
	return nil
}
