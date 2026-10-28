# conftest.py — общие фикстуры и хелперы для набора проверок guard.
#
# Набор построен по чек-листу L1 проекта: каждый тест в заголовке несёт ID
# строки чек-листа (A-10, C-06, D-03, E-04 и т.д.), к которой он относится.
# Проверяется не «ломается ли guard», а работает ли КАЖДАЯ заявленная защита:
# легальное проходит, запрещённое блокируется, маскируемое маскируется.

import json
import os
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUARD = ROOT / "guard"


@pytest.fixture(scope="session", autouse=True)
def built_guard():
    """Собрать guard один раз и гарантировать наличие рабочей папки."""
    if not GUARD.exists():
        subprocess.run(
            ["go", "build", "-buildvcs=false", "-o", "guard", "./cmd/guard"],
            cwd=ROOT, check=True,
        )
    (ROOT / "examples" / "ws").mkdir(parents=True, exist_ok=True)
    return GUARD


def _base_policy():
    """Базовая политика с теми же правилами, что в examples/policy.json."""
    return {
        "workspace": str(ROOT / "examples" / "ws"),
        "read_deny": ["~/.ssh"],
        "allow_domains": ["api.anthropic.com"],
        "env_allow": ["PATH", "HOME"],
        "prompt_filter": {
            "enabled": True,
            "mode": "enforce",
            "block": [
                {"name": "slack_token", "pattern": "xox[baprs]-[0-9A-Za-z-]{10,}"}
            ],
            "redact": [
                {"name": "email",
                 "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                 "action": "flag"},
                {"name": "bearer_token",
                 "pattern": r"(?i)bearer\s+[A-Za-z0-9._-]{8,}",
                 "action": "redact"},
            ],
            "scan_responses": True,
            "response_block": [
                {"name": "prompt_injection",
                 "pattern": r"(?i)ignore (all )?(your )?previous instructions"}
            ],
        },
        "limits": {},
    }


@pytest.fixture
def policy(tmp_path):
    """Фабрика политик. Переопределения верхнего уровня идут как есть;
    ключ prompt_filter мержится поверх базового."""
    def make(**over):
        cfg = _base_policy()
        pf = over.pop("prompt_filter", None)
        cfg.update(over)
        if pf is not None:
            cfg["prompt_filter"].update(pf)
        p = tmp_path / "policy.json"
        p.write_text(json.dumps(cfg))
        return str(p)
    return make


@pytest.fixture
def raw_policy(tmp_path):
    """Записать политику как сырой словарь (для тестов загрузки/ошибок)."""
    def make(cfg):
        p = tmp_path / "policy.json"
        p.write_text(json.dumps(cfg))
        return str(p)
    return make


@pytest.fixture
def sub():
    """Вызвать `guard submit`. Возвращает (код возврата, stdout, stderr).
    Без --prompt промт читается со stdin."""
    def run(policy_path, prompt=None, stdin=None):
        args = [str(GUARD), "submit", "--policy", policy_path]
        if prompt is not None:
            args += ["--prompt", prompt]
        r = subprocess.run(
            args, cwd=ROOT, input=stdin, capture_output=True, text=True
        )
        return r.returncode, r.stdout, r.stderr
    return run
