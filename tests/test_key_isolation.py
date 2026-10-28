# test_key_isolation.py — ключи провайдера не доходят до агента.
# Работает везде: использует `guard run --dry-run`, песочница не нужна.
#
# Чек-лист: граница доверия K-02 (агент не держит секрет) и E-04
# (секрет не утекает в окружение, которое увидит дочерний процесс).

import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUARD = ROOT / "guard"

POLICY = {
    "workspace": "./examples/ws",
    "read_deny": ["~/.ssh"],
    "allow_domains": ["api.anthropic.com"],
    "env_allow": ["PATH", "HOME", "USER"],
    "key_injection": [{
        "prefix": "/anthropic",
        "upstream": "https://api.anthropic.com",
        "header": "x-api-key",
        "env": "ANTHROPIC_API_KEY",
        "methods": ["POST"],
        "allow_paths": ["/v1/messages"],
    }],
    "prompt_filter": {"enabled": True, "mode": "enforce"},
    "limits": {},
}

SECRET_ANTHROPIC = "sk-ant-SECRET-should-never-leak"
SECRET_GITHUB = "ghp_SECRETTOKENshouldnotleak000000"


@pytest.fixture
def dry_run_env(tmp_path):
    import json
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(POLICY))

    def run():
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/root",
            "ANTHROPIC_API_KEY": SECRET_ANTHROPIC,
            "GITHUB_TOKEN": SECRET_GITHUB,
        }
        r = subprocess.run(
            [str(GUARD), "run", "--dry-run", "--policy", str(p),
             "--", "/bin/sh", "-c", "echo hi"],
            cwd=ROOT, env=env, capture_output=True, text=True,
        )
        return r.stdout + r.stderr
    return run


# === K-02 / E-04: секрет провайдера не виден дочернему процессу ==============
def test_provider_secret_absent_from_child_env(dry_run_env):
    out = dry_run_env()
    assert SECRET_ANTHROPIC not in out, "ключ Anthropic просочился в окружение агента"


# === E-04: прочие секреты из окружения guard тоже не проходят (default-deny) =
def test_unrelated_secret_scrubbed(dry_run_env):
    out = dry_run_env()
    assert SECRET_GITHUB not in out, "GITHUB_TOKEN должен быть вырезан (нет в env_allow)"


# === K-02: агенту подставляется адрес прокси, а не прямой доступ ==============
def test_base_url_points_at_proxy(dry_run_env):
    out = dry_run_env()
    assert "ANTHROPIC_BASE_URL=http://127.0.0.1:" in out
    assert "/anthropic" in out
    assert "HTTPS_PROXY=http://127.0.0.1:" in out
