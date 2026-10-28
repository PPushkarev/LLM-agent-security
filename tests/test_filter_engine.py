# test_filter_engine.py — поведение самого движка фильтра (не отдельных правил).
# Работает везде (`guard submit`).
#
# Чек-лист: порядок проверок и крайние случаи — block важнее redact,
# выключенный фильтр не защищает, маскирование считает спаны, literal_redact.

import json
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUARD = ROOT / "guard"
WS = ROOT / "examples" / "ws"


def _write(tmp_path, pf):
    cfg = {
        "workspace": str(WS),
        "read_deny": ["~/.ssh"],
        "allow_domains": ["api.anthropic.com"],
        "env_allow": ["PATH", "HOME"],
        "prompt_filter": pf,
        "limits": {},
    }
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(cfg))
    return str(p)


def sub(policy_path, prompt):
    r = subprocess.run([str(GUARD), "submit", "--policy", policy_path, "--prompt", prompt],
                       cwd=ROOT, capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


# === Выключенный фильтр не защищает ВООБЩЕ (важно задокументировать) =========
def test_disabled_filter_passes_secret(tmp_path):
    pol = _write(tmp_path, {"enabled": False})
    code, out, err = sub(pol, "AKIAIOSFODNN7EXAMPLE")
    assert code == 0, "выключенный фильтр ничего не блокирует"
    assert "AKIAIOSFODNN7EXAMPLE" in out, "и ничего не меняет"


# === block важнее redact: если в промте и секрет, и bearer — запрос отклонён =
def test_block_takes_precedence_over_redact(tmp_path):
    pol = _write(tmp_path, {
        "enabled": True,
        "redact": [{"name": "bearer_token",
                    "pattern": r"(?i)bearer\s+[A-Za-z0-9._-]{8,}", "action": "redact"}],
    })
    code, out, err = sub(pol, "Bearer abcdef123456 и ключ AKIAIOSFODNN7EXAMPLE")
    assert code == 1, "наличие секрета должно блокировать весь запрос"
    assert "BLOCKED" in err


# === Маскирование считает все спаны (count > 1) =============================
def test_redact_counts_multiple_spans(tmp_path):
    pol = _write(tmp_path, {
        "enabled": True,
        "redact": [{"name": "bearer_token",
                    "pattern": r"(?i)bearer\s+[A-Za-z0-9._-]{8,}", "action": "redact"}],
    })
    code, out, err = sub(pol, "Bearer tokenAAAAAAAA потом Bearer tokenBBBBBBBB")
    assert code == 0, err
    assert out.count("[REDACTED:bearer_token]") == 2
    assert "tokenAAAAAAAA" not in out and "tokenBBBBBBBB" not in out


# === literal_redact: точная строка всегда вырезается ========================
def test_literal_redact(tmp_path):
    pol = _write(tmp_path, {"enabled": True, "literal_redact": ["ACME-INTERNAL-CODENAME"]})
    code, out, err = sub(pol, "проект ACME-INTERNAL-CODENAME стартует завтра")
    assert code == 0, err
    assert "ACME-INTERNAL-CODENAME" not in out
    assert "[REDACTED]" in out


# === Пустой промт не ломает фильтр ==========================================
def test_empty_prompt(tmp_path):
    pol = _write(tmp_path, {"enabled": True})
    code, out, err = sub(pol, "")
    assert code == 0, err
