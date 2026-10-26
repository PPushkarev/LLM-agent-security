# Technical guide

**English** · [Русский](usage.ru.md) · [Overview](../README.md)

`guard` is the CLI name for the Guard prototype. Its three commands are `profile`, `submit` and `run`. Run commands below from the repository root.

## Build and inspect

Requires Go 1.26+ as declared in [go.mod](../go.mod). macOS sandbox execution uses `/usr/bin/sandbox-exec`; Linux uses `bwrap` and remains experimental. Windows has no backend in this source tree.

```sh
go build -o guard ./cmd/guard
mkdir -p examples/ws
./guard profile --policy examples/policy.json
./guard run --dry-run --policy examples/policy.json -- /bin/echo "hello"
```

`profile` prints the generated OS policy. `--dry-run` starts the parent proxy, prepares the filter log, then prints the policy, child environment and command without launching the harness. It is not entirely side-effect free.

Paths in the policy are resolved against the current working directory; `self_protect` paths are resolved against the workspace. `~` expands to the current user's home. The workspace must already exist. JSON fields not recognized by the policy loader are rejected.

<a id="run-a-harness"></a>
## Run a harness

First review [the backend limitations](#limitations), the sample policy and the harness's own authentication requirements. Evaluate in a disposable environment. The following example uses macOS; `hermes` must already be installed and configured.

```sh
# Set ANTHROPIC_API_KEY in the parent shell using your normal secret workflow.
# Do not include credentials in env_allow.
./guard run --policy examples/policy.json -- hermes chat
```

`guard` passes the configured `env_allow` variables and adds proxy coordinates. For an Anthropic upstream it sets `ANTHROPIC_BASE_URL`; for an OpenAI upstream it sets `OPENAI_BASE_URL`. Every route also gets `GUARD_BASE_<PREFIX>` (for example, `GUARD_BASE_ANTHROPIC`).

The harness must actually honor those URLs and work with the chosen authentication setup. An SDK or harness may insist on its own API-key setting or config files. That compatibility needs separate evaluation. Do not pass real provider keys through the child environment to work around an integration issue.

### API routing and key injection

This fragment from the sample policy configures the parent proxy to add the key from `ANTHROPIC_API_KEY`:

```json
{
  "key_injection": [{
    "prefix": "/anthropic",
    "upstream": "https://api.anthropic.com",
    "header": "x-api-key",
    "env": "ANTHROPIC_API_KEY",
    "methods": ["POST"],
    "allow_paths": ["/v1/messages"]
  }]
}
```

The local route is `http://127.0.0.1:<port>/anthropic`; the proxy uses the configured upstream. Methods are checked against `methods`; `allow_paths` uses **prefix matching**, not exact-path matching. An empty methods or paths list leaves that dimension unrestricted. Configuring a route also adds its upstream host to the proxy's domain allowlist.

The parent reads the key at startup. It is kept out of the child environment only if you exclude it from `env_allow` and do not expose another readable credential source. A permitted API operation can still be invoked with the injected key.

### Query parameter policy

Add a `query` object to a configured route when controlling search or tool query parameters:

```json
{
  "query": {
    "allow_params": ["q", "count"],
    "max_param_len": 100,
    "param_rules": [
      {"param": "q", "action": "block", "pattern": "(?i)site:internal"}
    ]
  }
}
```

`deny_params` is also supported. Parameter values can be blocked, flagged or redacted. Structured query policy is separate from `prompt_filter`: its enforcement is not disabled by `prompt_filter.mode = "monitor"`.

## Input and content filters

`submit` checks a prompt before invoking a harness. Without a command after `--`, it prints the filtered text:

```sh
./guard submit --policy examples/policy.json --prompt "Summarize this file"
printf '%s\n' 'Summarize this file' | ./guard submit --policy examples/policy.json

# With a compatible harness, cleaned input is passed on stdin under the sandbox.
printf '%s\n' 'Summarize this file' | ./guard submit --policy examples/policy.json -- hermes chat
```

Interactive TUIs can take input directly; that input does not automatically pass through `submit`. Content inspection at the model API hop requires a configured reverse-proxy route.

| Rule action | Effect in enforce mode |
| --- | --- |
| `block` | Refuse the matching payload; `submit` exits non-zero; a blocked proxy request receives HTTP 403 |
| `flag` | Record the match and pass the text unchanged |
| `redact` | Replace matching spans; report the modification in logs |

`prompt_filter.enabled` activates filtering. Built-in regex detectors cover selected private-key headers and credential formats; they are not an exhaustive secret inventory. Custom `block`, `redact`, `literal_redact` and `response_block` rules extend the configuration. A rule in the `redact` list can explicitly use `"action": "flag"`, as the sample email rule does.

For an initial observation pass, change `prompt_filter.mode` to `"monitor"` in your local policy copy. Content filter rules then log would-be block/redact actions without altering the payload. This does **not** disable sandbox restrictions, route method/path/query policy or request limits.

`max_body_bytes` caps inspected request body size; `scan_responses` enables rules for eligible non-streaming responses. SSE responses bypass scanning. Content filtering applies to configured reverse-proxy routes, not to arbitrary HTTP forwarding or encrypted `CONNECT` payloads. URL query inspection includes percent-decoding for matching, but redaction should not be treated as a complete encoded-data scrubber.

## Policy reference

| Field | Meaning |
| --- | --- |
| `workspace` | Existing working tree permitted for writes |
| `writable` | Additional writable paths |
| `read_deny` | Paths excluded from otherwise broad filesystem reads |
| `self_protect` | Paths protected against writes even within a writable tree |
| `allow_domains` | Exact destination hosts allowed by the proxy |
| `env_allow` | Environment variable names copied into the child; all other inherited entries are dropped |
| `proxy_port` | Local proxy port; `0` asks the OS to choose |
| `key_injection` | Reverse-proxy prefixes, upstreams, auth injection and request policies |
| `prompt_filter` | Content rules, mode, response inspection and decision log |
| `exec` | macOS binary path allow/deny rules |
| `limits` | Per-session request count, rate and declared request-body byte caps |

### Tool execution controls

```json
{
  "exec": {
    "deny": ["/usr/bin/osascript", "/usr/bin/security", "/usr/bin/ssh", "/usr/bin/nc", "/usr/bin/sudo"],
    "allow": []
  }
}
```

macOS emits literal-path execution rules. A non-empty `allow` list selects allowlist mode and needs tuning for interpreter/helper processes. Denylists do not cover a copied binary at another path. Linux currently does not implement these per-binary rules.

### Session limits

```json
{
  "limits": {
    "max_requests": 500,
    "rate_per_min": 60,
    "max_request_bytes": 50000000
  }
}
```

Zero means unlimited for that field. Exceeding a cap returns HTTP 429. `rate_per_min` uses a fixed 60-second window. Despite its name, `max_request_bytes` is a cumulative cap based on declared request-body lengths, not a per-request cap. It does not account for unknown-length bodies or bytes inside CONNECT tunnels and does not enforce a token or monetary budget.

### Decision log

Set `prompt_filter.audit_log` to a parent-writable location outside every sandbox-writable path and add an appropriate `read_deny` entry if log confidentiality matters. Temporary directories can be writable by the sandbox too; placing a log outside the workspace alone does not guarantee protection.

The append-mode file contains filter decisions. Other proxy decisions are also written to process logs. This is not a tamper-proof audit service, complete tool-action trace or SIEM integration.

## Existing local test scripts

The repository includes acceptance and filter scripts:

```sh
sh attack/run_attacks.sh
sh attack/filter_test.sh
```

Use a disposable macOS test environment with Go, `curl`, Python 3 and `lsof`. Review scripts first: `run_attacks.sh` creates a fake key file under `~/.ssh`; `filter_test.sh` uses fixed port 8732 and attempts to kill its existing listener. Both create local test artifacts. These scripts assume macOS behavior and should not be presented as cross-platform certification. Results vary by host; no fixed pass count is promised here.

<a id="limitations"></a>
## Platform behavior and limitations

| Area | Current behavior |
| --- | --- |
| macOS | Seatbelt via `sandbox-exec`; availability and behavior must be checked on the target OS. The interface is deprecated. |
| Linux | bubblewrap namespace/mount setup exists, but there is no bridge from the isolated network namespace to the proxy on the parent loopback. HOME masking can also cover a workspace located beneath HOME. End-to-end harness connectivity needs further work. |
| Windows / Docker | No Windows backend or `--docker` execution mode is implemented. |
| Filesystem | Broad reads except `read_deny`; workspace plus configured writable paths and backend temporary/device exceptions for writes. Not a minimal filesystem view. |
| Local network | macOS permits localhost connections generally, including other local services. The profile does not restrict access to only the proxy listener. |
| HTTPS | CONNECT enforces destination host policy, not encrypted paths, bodies or headers. |
| Content rules | Regex-based; no complete prompt-injection, encoded-secret or semantic DLP guarantee. Streaming SSE responses are not scanned. |
| API policy | Path-prefix matching; no operation-level business authorization or human approval service. |
| Credentials | Proxy injection reduces child-environment exposure; it does not stop use of an allowed authenticated operation. Policy must exclude other credential sources. |
| Audit and usage | Filter decision log plus process logs; approximate request/body counters. No immutable evidence store or spend accounting. |

This is a prototype for evaluation. [Report vulnerabilities privately](../SECURITY.md), and [discuss enterprise requirements](enterprise.md) when you need a broader deployment scope.
