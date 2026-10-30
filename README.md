<p align="center">
  <img src="docs/assets/banner-en.png" alt="SpaceAI Guard — put boundaries around your AI agents" width="100%">
</p>

<p align="center"><strong>English</strong> · <a href="README.ru.md">Русский</a></p>

<h1 align="center">SpaceAI Guard</h1>
<p align="center"><strong>Put boundaries around your AI agents.</strong><br>OS sandboxing, controlled egress and content filtering for agent harnesses.</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-prototype-8B5CF6" alt="Status: prototype">
  <img src="https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go&amp;logoColor=white" alt="Go 1.26 or newer">
  <img src="https://img.shields.io/badge/macOS-Seatbelt-111827?logo=apple&amp;logoColor=white" alt="macOS Seatbelt backend">
  <img src="https://img.shields.io/badge/Linux-experimental-6B7280?logo=linux&amp;logoColor=white" alt="Linux backend: experimental">
</p>

<p align="center">
  <a href="#quick-start">Try locally</a> · <a href="docs/usage.md">Technical guide</a> ·
  <a href="https://spaceai.ru/form/">Request a demo</a> · <a href="https://spaceai.ru/">SpaceAI website</a>
</p>

An AI agent can run commands, read files and call external APIs. A mistake or malicious instruction can become a real action on your machine.

**SpaceAI Guard (`guard`) wraps the agent harness in an OS sandbox and applies a declarative policy to its environment and outbound API traffic.** Inspect the policy, filter a prompt, then evaluate a sandboxed session in a disposable environment.

This repository publishes a **focused prototype from the SpaceAI initiative**. SpaceAI's broader product is an enterprise control plane for AI agents: access, controlled execution, audit and risk management. See the [enterprise use cases](docs/enterprise.md) for that wider scope.

## What you can evaluate

| Control | Implementation | Practical value |
| --- | --- | --- |
| OS sandbox | macOS Seatbelt; Linux bubblewrap + isolated proxy bridge + seccomp | Apply boundaries to the harness and its child processes |
| Filesystem policy | Writable paths, denied reads and protected persistence paths | Reduce unwanted access and changes |
| Controlled egress | Domain allowlist and reverse-proxy routes | Make outbound destinations explicit |
| API key injection | Parent proxy adds a configured upstream auth header | Keep provider keys out of the child environment with a correctly configured policy |
| Request policy | HTTP methods, path prefixes and query rules on configured routes | Narrow the API operations the harness can request |
| Content filtering | Regex rules: `block`, `flag`, `redact`; monitoring mode | Inspect prompts and eligible API traffic against your rules |
| Usage limits & logs | Session request/rate/body-byte limits; filter decision log | Inspect activity and constrain request volume |

Read the [current boundaries](#current-boundaries) before treating these as security guarantees.

## Who this is for

- **Agent developers** evaluating external controls around command-running harnesses.
- **Platform and security teams** reviewing agent access to files, credentials and external APIs.
- **Integrators and B2B SaaS teams** preparing agent workflows for enterprise environments.

Claude Code, Codex, Hermes and custom CLI harnesses are example integration targets. Compatibility depends on each harness's authentication, configuration and networking behavior; this repository does not establish a tested compatibility matrix.

<a id="quick-start"></a>
## Quick start

Requires **Go 1.26+**. Input filtering needs no LLM account or sandboxed harness. Sandbox execution supports macOS with `sandbox-exec`, or Linux amd64/arm64 with bubblewrap, user namespaces and seccomp.

```sh
git clone https://github.com/SpaceAI-UAG/LLM-agent-security.git
cd LLM-agent-security
go build -o guard ./cmd/guard
mkdir -p examples/ws

# Inspect the OS policy without launching a harness.
./guard profile --policy examples/policy.json

# Filter a benign prompt locally. No provider API call is made.
./guard submit --policy examples/policy.json --prompt "Summarize the project README"
```

**Expected:** `profile` prints the OS policy; `submit` prints the clean prompt unchanged. To observe a block, run this command separately; it should exit with a non-zero status:

```sh
./guard submit --policy examples/policy.json --prompt "-----BEGIN OPENSSH PRIVATE KEY----- DEMO-ONLY"
```

This is a synthetic marker, not a real secret. The enabled filter detects the private-key header and rejects the prompt.

**Next:** review [the sample policy](examples/policy.json), then follow the [harness setup and API routing guide](docs/usage.md#run-a-harness) for key injection, monitor mode, tool controls, limits and local test scripts.

## Codex login and managed MCP

The current implementation adds `init`, `check`, `codex` and `mcp` commands,
ChatGPT subscription authentication through the trusted parent, structured JSON
filters, harness-independent MCP controls, and a `guardrails` policy section for
strict configuration, session time/output budgets and session audit. New policies
enable strict guardrails by default. The [current runtime guide
(Russian)](docs/runtime.ru.md) describes the full configuration and boundaries.

```sh
./guard init --workspace /absolute/path/to/project --output guard.json --auth chatgpt --model YOUR_MODEL_ID
./guard check --policy guard.json
./guard codex --policy guard.json
# Other clients must use the configured model proxy and managed MCP endpoints:
./guard run --policy guard.json -- /absolute/path/to/harness
```

Codex MCP configuration is generated automatically. Other MCP clients can consume
the per-launch `GUARD_MCP_CONFIG` connection file or configure a stdio server
with command `/absolute/path/to/guard` and arguments
`["mcp", "bridge", "--server", "NAME"]`, launched inside `guard run`.
The bridge must inherit `GUARD_MCP_CONFIG`. Backend credentials stay in the parent.

## How it works

| Component | Responsibility |
| --- | --- |
| `guard` parent process | Loads policy, holds configured provider credentials and starts the proxy |
| OS sandbox | Restricts the harness and its children according to the backend and policy |
| Egress proxy | Checks destinations; configured routes add method/path/query rules and auth headers |
| Content filter | Inspects submitted prompts and configured reverse-proxy traffic; optionally logs filter decisions |

Controls apply around the harness and its children. Managed MCP servers additionally use a parent-side gateway with per-tool permissions, argument/result filtering, approval requests, limits and audit. Clients connect through Streamable HTTP or the `guard mcp bridge --server NAME` stdio adapter; see the [current runtime guide (Russian)](docs/runtime.ru.md).

<a id="current-boundaries"></a>
## Current boundaries

- **Prototype:** use a disposable environment. No independent security audit or certification is claimed.
- **Backend differences:** macOS restricts network access to the guard proxy port. Linux uses a private network namespace and an inherited proxy bridge; host Unix sockets and namespace-changing syscalls are blocked. `exec.allow` additionally requires Landlock. Windows is unsupported.
- **Inspection scope:** configured reverse-proxy routes are inspected; encrypted HTTPS `CONNECT` payloads are not. With `scan_responses`, JSON and supported SSE model responses are buffered and checked before delivery. Regex rules do not provide complete prompt-injection or data-loss prevention.
- **Policy matters:** filesystem reads are broadly allowed except configured exclusions. Review writable paths, environment passthrough, local services and audit-log placement.

See [platform behavior and limitations](docs/usage.md#limitations) for details.

## Explore the project

| Start here | English | Русский |
| --- | --- | --- |
| Overview | [README](README.md) | [Обзор](README.ru.md) |
| Commands, configuration and limitations | [Technical guide](docs/usage.md) | [Техническое руководство](docs/usage.ru.md) |
| Enterprise use cases and partnership | [SpaceAI for teams](docs/enterprise.md) | [SpaceAI для компаний](docs/enterprise.ru.md) |
| Contributions and private security reports | [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) | [Участие](CONTRIBUTING.md#russian) · [Безопасность](SECURITY.md#russian) |

## Bring agent control into your company

**SpaceAI — a unified control layer for enterprise AI agents.** If your agents are starting to act in CRM, ERP, helpdesk or internal APIs, let's map the required access rules, approvals and audit evidence. These are broader SpaceAI deployment topics; the full enterprise platform is not included here.

- [Request a demo or discuss a pilot](https://spaceai.ru/form/)
- [Explore the SpaceAI platform](https://spaceai.ru/)
- [Discuss an integration or partnership](docs/enterprise.md#partners)
- [Telegram: @ran111s](https://t.me/ran111s) · [Email](mailto:r.galizyanov@spaceai.ru)

## Contribute and follow

Found a reproducible bug or a harness integration gap? [Open an issue](https://github.com/SpaceAI-UAG/LLM-agent-security/issues/new/choose) or read the [contribution guide](CONTRIBUTING.md). Use the [private reporting route](SECURITY.md) for vulnerabilities. Star the repository if this work is useful, or use GitHub Watch to follow changes.

**License:** no `LICENSE` file is currently published. Public source visibility does not by itself provide a reuse license. Contact the maintainers about usage and contribution terms.
