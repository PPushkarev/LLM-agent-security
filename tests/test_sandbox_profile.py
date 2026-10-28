# test_sandbox_profile.py — проверка профиля песочницы (`guard profile`) и
# default-deny окружения (`guard run --dry-run`). Оба команды НЕ запускают
# саму песочницу, поэтому работают где угодно — а проверяют именно границы,
# которые песочница наложит.
#
# Чек-лист: защита файловой системы и секретов (read_deny), рабочая папка,
# изоляция сети (K-03), запреты запуска (на Linux — известный пробел),
# default-deny окружения (E-04).

import json
import os
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUARD = ROOT / "guard"
WS = ROOT / "examples" / "ws"


def _policy(tmp_path, **extra):
    cfg = {
        "workspace": str(WS),
        "read_deny": ["~/.ssh", "~/.aws"],
        "self_protect": [".git/hooks", ".envrc"],
        "allow_domains": ["api.anthropic.com"],
        "env_allow": ["PATH", "HOME"],
        "exec": {"deny": ["/usr/bin/ssh", "/usr/bin/nc", "/usr/bin/sudo"]},
        "prompt_filter": {"enabled": True},
        "limits": {},
    }
    cfg.update(extra)
    p = tmp_path / "policy.json"
    p.write_text(json.dumps(cfg))
    return str(p)


def profile(policy_path):
    r = subprocess.run([str(GUARD), "profile", "--policy", policy_path],
                       cwd=ROOT, capture_output=True, text=True)
    # Профиль печатается с переносами («\\\n  ») по два аргумента на строку.
    # Нормализуем в одну строку, чтобы проверять по токенам аргументов.
    flat = " ".join(r.stdout.replace("\\", " ").split())
    return r.returncode, flat, r.stderr


# === FS: корень только на чтение, рабочая папка — на запись ==================
def test_root_readonly_workspace_writable(tmp_path):
    code, out, err = profile(_policy(tmp_path))
    assert code == 0, err
    assert "--ro-bind / /" in out, "корень должен монтироваться только на чтение"
    assert f"--bind {WS} {WS}" in out, "рабочая папка должна быть на запись"


# === Секреты: каталоги read_deny маскируются пустым tmpfs ====================
def test_read_deny_dirs_masked(tmp_path):
    code, out, err = profile(_policy(tmp_path))
    home = os.path.expanduser("~")
    assert f"--tmpfs {home}/.ssh" in out
    assert f"--tmpfs {home}/.aws" in out


# === Сеть: песочница отрезана от сети (только прокси на loopback) — K-03 =====
def test_network_unshared(tmp_path):
    code, out, err = profile(_policy(tmp_path))
    assert "--unshare-all" in out, "сеть должна быть отрезана (--unshare-all)"
    assert "--die-with-parent" in out


# === HOME — одноразовый tmpfs (персистентность через rc-файлы теряется) ======
def test_home_is_tmpfs(tmp_path):
    code, out, err = profile(_policy(tmp_path))
    home = os.path.expanduser("~")
    assert f"--tmpfs {home}" in out


# === self_protect защищает только СУЩЕСТВУЮЩИЙ путь (находка) ================
# Путь, которого ещё нет, просто пропускается: агент сможет его создать.
def test_self_protect_only_existing_paths(tmp_path):
    # .git/hooks и .envrc в рабочей папке не существуют → не попадут в профиль.
    code, out, err = profile(_policy(tmp_path))
    assert f"--ro-bind {WS}/.git/hooks" not in out, (
        "несуществующий self_protect путь в профиль не попадает — "
        "агент может его создать (задокументированный пробел)"
    )


# === Запрет запуска программ на Linux НЕ применяется (пробел по README) ======
@pytest.mark.xfail(reason="exec.deny не реализован в Linux-backend — заявлено в README",
                   strict=False)
def test_exec_deny_enforced(tmp_path):
    code, out, err = profile(_policy(tmp_path))
    # На macOS ssh/nc/sudo попали бы в профиль как deny; на Linux их там нет.
    assert "/usr/bin/ssh" in out, "exec.deny должен присутствовать в профиле"


# === Окружение: default-deny, только env_allow проходит к агенту (E-04) ======
def test_env_default_deny(tmp_path):
    pol = _policy(tmp_path)
    env = {"PATH": "/usr/bin:/bin", "HOME": "/root",
           "SECRET_FOO": "should-not-pass", "ANTHROPIC_API_KEY": "sk-ant-x"}
    r = subprocess.run(
        [str(GUARD), "run", "--dry-run", "--policy", pol, "--", "/bin/sh", "-c", "true"],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    out = r.stdout + r.stderr
    assert "SECRET_FOO" not in out, "переменная вне env_allow не должна проходить"
    assert "HOME=/root" in out, "разрешённая переменная должна проходить"
