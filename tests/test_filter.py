import subprocess, pytest

def submit(prompt):
    r = subprocess.run(["./guard", "submit", "--policy", "examples/policy.json", "--prompt", prompt],
                       capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr

@pytest.mark.parametrize("prompt", ["Summarize the README", "Привет, как дела?"])
def test_clean_passes(prompt):
    code, out = submit(prompt)
    assert code == 0 and prompt in out

@pytest.mark.parametrize("prompt", ["-----BEGIN OPENSSH PRIVATE KEY-----", "token xoxb-1234567890abc"])
def test_secret_blocked(prompt):
    code, out = submit(prompt)
    assert code == 1 and "BLOCKED" in out

def test_bearer_redacted():
    code, out = submit("Authorization: Bearer abcdefgh12345")
    assert code == 0 and "abcdefgh12345" not in out

@pytest.mark.xfail(reason="regex не ловит обфускацию — известное ограничение")
@pytest.mark.parametrize("prompt", ["x o x b-1234567890abc", "eG94Yi0xMjM0NTY3ODkwYWJj"])
def test_obfuscated_blocked(prompt):
    assert submit(prompt)[0] == 1