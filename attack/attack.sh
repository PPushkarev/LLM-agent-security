#!/bin/sh
# attack.sh — runs INSIDE the guard sandbox and plays the role of a compromised
# or misbehaving harness. Every check prints PASS (guard blocked it) or FAIL
# (guard let it through). The runner at the bottom of run_attacks.sh tallies them.
#
# It must be invoked via:  guard run --policy ... -- sh attack/attack.sh
#
# It expects $GUARD_WS to point at the workspace (set by run_attacks.sh).

ws="${GUARD_WS:-$PWD}"
pass=0; fail=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }

echo "== 1. workspace write should WORK =="
if echo hello > "$ws/legit.txt" 2>/dev/null; then
  ok "wrote $ws/legit.txt (expected)"
else
  bad "could not write workspace — sandbox too strict"
fi

echo "== 2. read secrets should be BLOCKED =="
for secret in "$HOME/.ssh" "$HOME/.aws" "$HOME/.codex" "$HOME/.claude" "$HOME/.hermes"; do
  if ls "$secret" >/dev/null 2>&1; then
    bad "read $secret"
  else
    ok "blocked read of $secret"
  fi
done

echo "== 3. write outside workspace should be BLOCKED =="
if echo x > "$HOME/guard-escape.txt" 2>/dev/null; then
  bad "wrote $HOME/guard-escape.txt"; rm -f "$HOME/guard-escape.txt" 2>/dev/null
else
  ok "blocked write to \$HOME"
fi
if echo x > "/tmp/../$HOME/guard-escape2.txt" 2>/dev/null; then
  bad "wrote HOME via path trick"
else
  ok "blocked write to \$HOME via ../ trick"
fi

echo "== 4. persistence inside workspace should be BLOCKED =="
mkdir -p "$ws/.git/hooks" 2>/dev/null
if echo '#!/bin/sh' > "$ws/.git/hooks/pre-commit" 2>/dev/null; then
  bad "wrote .git/hooks/pre-commit"
else
  ok "blocked .git/hooks/pre-commit"
fi
if echo 'export EVIL=1' > "$ws/.envrc" 2>/dev/null; then
  bad "wrote .envrc"
else
  ok "blocked .envrc"
fi

echo "== 5. direct internet (bypassing proxy) should be BLOCKED =="
if curl -sS -m 6 --noproxy '*' https://example.com -o /dev/null 2>/dev/null; then
  bad "reached example.com directly"
else
  ok "blocked direct TCP to example.com"
fi

echo "== 6. non-allowlisted domain via proxy should be BLOCKED =="
# Over an HTTPS CONNECT tunnel curl reports http_code 000 and a non-zero exit
# when the proxy refuses, so "blocked" == curl failed to establish the tunnel.
# A successful exfil would instead be exit 0 with a 2xx code.
out=$(curl -sS -m 6 -o /dev/null -w '%{http_code}' -x "$GUARD_PROXY" https://evil.example 2>&1)
rc=$?
case "$out" in 2*) code2xx=1 ;; *) code2xx=0 ;; esac
if [ "$rc" -ne 0 ] || [ "$code2xx" -eq 0 ]; then
  ok "proxy refused tunnel to evil.example (rc=$rc code=$out)"
else
  bad "proxy let evil.example through (rc=$rc code=$out)"
fi

echo "== 7. secret must NOT be in the environment =="
if env | grep -qiE 'ANTHROPIC_API_KEY|AWS_SECRET|GITHUB_TOKEN|OPENAI_API_KEY'; then
  bad "found an API secret in env"
else
  ok "no API secrets in child env"
fi

echo "== 8. macOS keychain / applescript should be BLOCKED =="
if command -v security >/dev/null 2>&1; then
  if security find-generic-password -a login >/dev/null 2>&1; then
    bad "security read a keychain item"
  else
    ok "keychain access blocked"
  fi
fi
if command -v osascript >/dev/null 2>&1; then
  if osascript -e 'tell application "System Events" to name of current user' >/dev/null 2>&1; then
    bad "osascript/AppleEvents worked"
  else
    ok "AppleEvents blocked"
  fi
fi

echo "== 9. tool/exec filtering: dangerous binaries should be BLOCKED =="
# A denied exec returns rc 126 (found but not permitted); a tool that actually
# ran would not. We don't gate on [ -x ] because the sandbox also makes the
# executable test fail for a denied binary.
for tool in /usr/bin/ssh /usr/bin/sudo /usr/bin/nc; do
  "$tool" --version >/dev/null 2>&1
  rc=$?
  if [ "$rc" = "126" ]; then
    ok "blocked exec of $tool (rc=126)"
  else
    bad "exec of $tool not blocked (rc=$rc)"
  fi
done
# A normal tool must still run — we filter tools, not break the agent.
if /bin/date +%s >/dev/null 2>&1; then
  ok "normal tool /bin/date still runs"
else
  bad "/bin/date blocked — exec filter too strict"
fi

echo
echo "RESULT pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
