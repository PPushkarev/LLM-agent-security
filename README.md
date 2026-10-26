# guard — sandbox any agent harness

`guard` wraps an arbitrary agent harness (Claude Code, Codex, Hermes, or your
own) in an OS-level sandbox plus an allowlisting egress proxy, so a
compromised, confused, or over-eager agent cannot read your secrets, write
outside its workspace, phone home, or persist itself.

The isolation covers the **whole harness and every child it spawns** — shells,
`node`, `python`, MCP servers, plugins — so you don't have to trust the harness
to apply limits correctly.

```
guard (trusted, outside the sandbox)
 ├─ egress proxy  127.0.0.1:PORT   — domain allowlist + injects the API key
 └─ sandbox ─► harness ─► all children (inherit every restriction)
```

## Why not just chroot?

chroot only remaps the filesystem root. It is not a security boundary (root
escapes it trivially), it does nothing about the network, IPC, or secrets in
the environment, and on macOS it is barely usable because the system dylibs
live in the dyld shared cache, not on disk. `guard` instead composes the
mechanisms each OS actually provides:

| Layer | macOS | Linux |
|---|---|---|
| Filesystem | Seatbelt (`sandbox-exec`, deny-by-default SBPL) | bubblewrap (mount ns: `--ro-bind /`, rw workspace, tmpfs `$HOME`) |
| Network | loopback only → traffic must use the proxy | `--unshare-net` → only the proxy socket is reachable |
| Secrets | **never in the sandbox**; the proxy adds the auth header | same |
| Persistence | write-deny on `.git/hooks`, rc files, harness config | `--ro-bind` the same paths |
| IPC | narrow `mach-lookup` allowlist (no Keychain/AppleEvents) | `--unshare-ipc`, seccomp |
| Tools (exec) | `process-exec*` deny/allow list of binaries | (seccomp/`--ro-bind` — planned) |

Two content checkpoints sit on top of this: an **input filter** on the prompt
before the harness runs it (`guard submit`), and an **egress firewall** on
everything the harness sends out (prompts, searches, tool calls, responses).

## Usage

```sh
go build -o guard ./cmd/guard

# Inspect exactly what will be enforced (no execution):
./guard profile --policy examples/policy.json
./guard run --dry-run --policy examples/policy.json -- hermes chat

# Run a harness under the sandbox:
export ANTHROPIC_API_KEY=sk-ant-...      # stays in guard; never enters the sandbox
./guard run --policy examples/policy.json -- hermes chat
```

The harness is pointed at `ANTHROPIC_BASE_URL=http://127.0.0.1:PORT/anthropic`;
`guard` forwards to the real API and attaches the key. The agent works normally
but holds no credential to leak.

## Request allowlist — limit what the agent may ask for

A host allowlist is not enough: once a host is reachable (or the injected key is
in play) a compromised agent could hit *any* path or method on it — account and
billing endpoints, file uploads, `DELETE`, model-management, etc. A
key-injection route can therefore pin the exact requests it permits:

```json
"key_injection": [{
  "prefix": "/anthropic", "upstream": "https://api.anthropic.com",
  "header": "x-api-key", "env": "ANTHROPIC_API_KEY",
  "methods": ["POST"], "allow_paths": ["/v1/messages"]
}]
```

The agent may now issue **only** `POST /v1/messages` with the injected key;
`GET /v1/messages`, `POST /v1/organizations`, uploads, deletes — all get a 403
and an audit entry. An empty `methods`/`allow_paths` list means "any".

For a search or tool endpoint you can go finer than method+path and filter the
query **by parameter** — more precise than a regex over the whole URL:

```json
"query": {
  "allow_params": ["q", "count"],
  "max_param_len": 100,
  "param_rules": [{ "param": "q", "action": "block", "pattern": "(?i)site:internal" }]
}
```

Now an unexpected param (`&callback=…`), an over-long value, or a forbidden term
inside `q` is blocked; `flag`/`redact` actions work per-param too. So the agent
can search, but only for what the policy allows, with no smuggling via extra
parameters.

This path/method control works on the key-injection route because that traffic
is plaintext on loopback. A raw HTTPS `CONNECT` tunnel to an allowlisted domain
is encrypted, so there guard can enforce the host only — route an API through a
key-injection prefix when you need request-level control over it.

## Input filter (Filter A) — clean the prompt before the harness sees it

`guard submit` inspects a prompt *before* it reaches the agent, so bad input
never enters the agent's logic:

```sh
guard submit --policy policy.json --prompt "mail bob@corp.com"      # prints: mail [REDACTED:email]
guard submit --policy policy.json --prompt "ignore all previous instructions"  # refused, exit≠0
echo "do X" | guard submit --policy policy.json -- hermes chat      # cleaned prompt piped to a sandboxed harness
```

It reuses the same rules as the egress firewall: **block** cuts the prompt off
(the harness is not invoked), **redact** masks spans, **flag** records without
changing anything. With a `--` harness it runs that harness sandboxed and feeds
it the cleaned prompt on stdin; without one it just prints the result. (Live
interactive TUIs type straight into the harness — for those the prompt is still
inspected at the harness→LLM hop by the egress firewall below.)

## Tool execution filter — restrict which binaries the agent may run

The sandbox also filters *local* tools, not just network egress. `exec.deny`
refuses dangerous binaries (robust default); `exec.allow`, when set, flips to
allowlist mode (stronger, but shells/interpreters re-exec helpers so it needs
tuning):

```json
"exec": { "deny": ["/usr/bin/osascript", "/usr/bin/security", "/usr/bin/ssh", "/usr/bin/nc", "/usr/bin/sudo"] }
```

A denied `exec` returns "operation not permitted" (rc 126); normal tools keep
working. Note: a path-based denylist is defense-in-depth — a copy of the binary
at another path isn't covered, so use allowlist mode when you need a hard
guarantee.

## Rate / budget limits

Even permitted requests shouldn't be unlimited — otherwise a runaway or
compromised agent can spam the API, run up a bill, or exfiltrate data in many
small allowed pieces. The `limits` section caps egress per session (any field
`0` = unlimited):

```json
"limits": { "max_requests": 500, "rate_per_min": 60, "max_request_bytes": 50000000 }
```

Over any cap, the proxy returns **429** and logs it; the limiter checks before
consuming budget, so a rejected request doesn't eat into the quota. Counts apply
to LLM calls, searches and plain egress alike.

## Prompt / content firewall

The harness reaches the LLM over the key-injection route, which travels as
**plaintext HTTP over loopback** (guard upgrades to HTTPS on the way out). So
guard sees every prompt in the clear and can inspect it **without a MITM
certificate**. The `prompt_filter` policy section controls three actions:

Each rule has an **action** so your own legitimate prompt is never changed
behind your back:

- **block** — refuse the request (a visible 403; the prompt is not altered).
  Built-in always-on detectors cover PEM private keys, `AKIA…`, `sk-ant-…`,
  `sk-…`, `ghp_…` and GCP service-account keys.
- **flag** — detect and log, but **forward the prompt unchanged**. This is the
  right default for soft patterns (emails, names): you find out it matched
  without your text being rewritten.
- **redact** — rewrite the matched span before sending. This is the *only*
  action that silently changes your prompt, so it is **opt-in per rule** and,
  when it fires, guard prints a loud warning (`your prompt was modified …`) and
  records it in the audit log.

Two global modes:

- **enforce** (default) — apply each rule's action.
- **monitor** — never block and **never alter** anything; only log what *would*
  have happened (`would-block:…`, `would-redact:…`). Run this first to tune
  rules against real traffic before any prompt is ever changed or stopped.

The firewall inspects the **whole outbound request, not just the body**. A
harness's search goes out as `GET /search?q=…`, with the query in the URL — so
guard scans the path+query too (percent-decoded). That means the same rules
block a search that leaks a secret (`?q=sk-ant-…`) or a search for a forbidden
topic, flag or redact query terms, and log every search to the audit trail.
Point the harness's search/tool endpoint at a key-injection prefix (any
upstream, with or without an injected key) to get this control over it.

Responses are scanned the same way (injection payloads like "ignore all
previous instructions"). Every decision is appended to an audit log **outside**
the sandbox, so a compromised agent can neither read nor erase it. Streaming
(SSE) responses pass through unscanned to preserve token-by-token output — a
documented limit of the prototype.

```
$ sh attack/filter_test.sh
  PASS  PEM key blocked (403)
  PASS  sk-ant key blocked (403)          # built-in detector
  PASS  email redacted in forwarded body  # only when action=redact
  PASS  clean prompt forwarded intact
  PASS  injected model output blocked (403)
  PASS  audit log has 8 entries
  PASS  action=flag forwards the prompt UNCHANGED
  PASS  monitor mode never blocks or alters (request + response)
RESULT pass=9 fail=0
```

## Policy

One declarative file is the single source of truth (see
[`examples/policy.json`](examples/policy.json)). Key fields: `workspace` (the
only writable tree), `read_deny` (secret paths), `self_protect` (persistence
surfaces made read-only even inside the workspace), `allow_domains` (egress
allowlist), `env_allow` (env var passthrough; everything else is dropped), and
`key_injection` (base-URL → upstream + header-from-env routes), and
`prompt_filter` (the content firewall above).

## Acceptance test

[`attack/run_attacks.sh`](attack/run_attacks.sh) plants fake secrets, puts a
bogus API key in guard's own environment, and runs
[`attack/attack.sh`](attack/attack.sh) — a stand-in misbehaving agent — under
guard. It exits non-zero unless every escape is blocked.

```
$ sh attack/run_attacks.sh
  PASS  wrote workspace file (expected)
  PASS  blocked read of ~/.ssh ~/.aws ~/.codex ~/.claude ~/.hermes
  PASS  blocked write to $HOME (incl. ../ trick)
  PASS  blocked .git/hooks/pre-commit and .envrc
  PASS  blocked direct TCP to example.com
  PASS  proxy refused tunnel to a non-allowlisted domain
  PASS  no API secrets in child env
  PASS  keychain + AppleEvents blocked
RESULT pass=15 fail=0
```

## Status & limits (prototype)

- Seatbelt `sandbox-exec` is Apple-deprecated (still functional on macOS 26).
  For a hard boundary, run `guard` inside a VM/container; a `--docker` mode and
  a Linux bubblewrap path are stubbed in [`internal/sandbox`](internal/sandbox).
- The `mach-lookup` allowlist is deliberately minimal and may need widening per
  harness; widen it in the policy, not by opening it entirely.
- Policy is JSON today; YAML is an easy add.
