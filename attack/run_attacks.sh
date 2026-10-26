#!/bin/sh
# run_attacks.sh — acceptance harness. Builds guard, creates a throwaway
# workspace, plants fake secrets, exports a bogus API key into guard's own
# environment (to prove it does NOT leak into the sandbox), and runs attack.sh
# under guard. Exit 0 only if every escape was blocked.
set -eu
cd "$(dirname "$0")/.."

echo ">> building guard"
go build -o guard ./cmd/guard

ws="examples/ws"
mkdir -p "$ws"

# Plant fake secrets in HOME so read-denial is actually testable.
mkdir -p "$HOME/.ssh"
[ -f "$HOME/.ssh/guard_fake_key" ] || echo "FAKE-PRIVATE-KEY" > "$HOME/.ssh/guard_fake_key"

# A secret that lives in GUARD's env — the proxy may use it, the sandbox must not see it.
export ANTHROPIC_API_KEY="sk-ant-FAKE-should-never-reach-sandbox"
export GITHUB_TOKEN="ghp_FAKE-should-never-reach-sandbox"

echo ">> running attack suite under guard"
GUARD_WS="$PWD/$ws" ./guard run --policy examples/policy.json -- \
  /bin/sh -c "GUARD_WS='$PWD/$ws' /bin/sh attack/attack.sh"
