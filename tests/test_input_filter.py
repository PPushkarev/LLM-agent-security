# test_input_filter.py — проверки фильтра входа guard (`guard submit`).
# Запускается где угодно: песочница и прокси не нужны.
#
# Колонка «чек-лист» в заголовках тестов — строка из нашего L1-чек-листа,
# к которой относится проверка. Все секреты синтетические (DEMO).

import pytest

# ---- синтетические секреты (не настоящие) --------------------------------
SECRETS = {
    "pem_private_key":  "-----BEGIN OPENSSH PRIVATE KEY----- DEMO-ONLY",
    "aws_access_key":   "AKIAIOSFODNN7EXAMPLE",            # канонический пример AWS
    "anthropic_key":    "sk-ant-DEMO00000000000000000000000",
    "openai_key":       "sk-" + "A" * 48,
    "github_token":     "ghp_" + "A" * 36,
    "gcp_sa_key":       '{"private_key_id":"a1b2c3d4e5f6a1b2c3d4"}',
}

CLEAN = [
    "Summarize the project README",
    "Привет, помоги разобраться с кодом на Python",
    "def add(a, b):\n    return a + b  # simple helper",
    "The API key lives in the vault — do not paste it into chat",
]


# === C-06 + C-16: секреты во входе блокируются ВНЕ модели (обычным кодом) ===
# C-06 — запрет секретов; C-16 — критичный запрет срабатывает вне модели,
# не полагаясь на то, послушается ли промт сама модель.
@pytest.mark.parametrize("rule,payload", list(SECRETS.items()), ids=list(SECRETS))
def test_c06_builtin_secret_blocked(sub, policy, rule, payload):
    code, out, err = sub(policy(), prompt=payload)
    assert code == 1, f"{rule}: ожидали блок, получили код {code}"
    assert "BLOCKED" in err
    assert out == "", "при блоке промт не должен печататься"


# === C-02: легальный ввод проходит без изменений (нет ложных срабатываний) ==
@pytest.mark.parametrize("text", CLEAN, ids=[c[:20] for c in CLEAN])
def test_c02_clean_passes_unchanged(sub, policy, text):
    code, out, err = sub(policy(), prompt=text)
    assert code == 0, err
    assert text.split("\n")[0] in out
    assert "BLOCKED" not in err


# === D-03: чувствительное маскируется до отправки (здесь — bearer-токен) =====
def test_d03_bearer_token_redacted(sub, policy):
    secret = "Authorization: Bearer abcdef123456TOKEN"
    code, out, err = sub(policy(), prompt=secret)
    assert code == 0, err
    assert "abcdef123456TOKEN" not in out, "токен должен быть вырезан"
    assert "[REDACTED:bearer_token]" in out
    assert "REDACT" in err


# === L-03 (вход): email детектируется, но правило flag → пропускается как есть
# Показывает разницу block / redact / flag и фиксирует, что email в этой
# политике только помечается, а не удаляется (осознанный выбор, не дефект).
def test_flag_email_detected_but_forwarded(sub, policy):
    code, out, err = sub(policy(), prompt="пиши на demo@example.com")
    assert code == 0, err
    assert "demo@example.com" in out, "flag не должен менять промт"
    assert "FLAG" in err and "email" in err


# === C-06 (политика): дополнительное block-правило из политики (slack) =======
def test_policy_block_rule_slack(sub, policy):
    code, out, err = sub(policy(), prompt="токен xoxb-1234567890abcdef")
    assert code == 1
    assert "slack_token" in err


# === A-10: ограничение размера входа =========================================
def test_a10_max_body_bytes(sub, policy):
    pol = policy(prompt_filter={"max_body_bytes": 64})
    code, out, err = sub(pol, prompt="A" * 500)
    assert code == 1, "слишком большой ввод должен блокироваться"
    assert "max_body_bytes" in err


# === F-02: режим monitor ничего не блокирует и не меняет, только логирует =====
# Аналог режима warn/off: защита включена «на слух», но промт идёт как есть.
def test_f02_monitor_never_alters(sub, policy):
    pol = policy(prompt_filter={"mode": "monitor"})
    code, out, err = sub(pol, prompt=SECRETS["aws_access_key"])
    assert code == 0, "monitor не должен блокировать"
    assert "AKIAIOSFODNN7EXAMPLE" in out, "monitor не должен менять промт"
    assert "BLOCKED" not in err


# === E-02 + E-04: аудит пишет РЕШЕНИЕ, но не сам секрет =======================
# E-04 — секрет удаляется до записи в аудит (должно работать).
# E-02 — восстановить исходный промт из аудита НЕЛЬЗЯ: guard пишет только
#        решения, не текст запроса. Тот же пробел, что мы отметили в L1.
def test_e04_audit_records_event_without_secret(sub, policy, tmp_path):
    log = tmp_path / "audit.log"
    pol = policy(prompt_filter={"audit_log": str(log)})
    secret = "токен xoxb-1234567890SECRET"
    code, _, _ = sub(pol, prompt=secret)
    assert code == 1
    data = log.read_text()
    assert "slack_token" in data, "событие должно быть записано"
    assert "xoxb-1234567890SECRET" not in data, "сам секрет в аудит попадать не должен (E-04)"


def test_e02_audit_does_not_store_prompt_text(sub, policy, tmp_path):
    log = tmp_path / "audit.log"
    pol = policy(prompt_filter={"audit_log": str(log)})
    sub(pol, prompt="совершенно безобидный уникальный текст QY27")
    data = log.read_text() if log.exists() else ""
    # Документируем пробел E-02: тела запроса в аудите нет.
    assert "QY27" not in data


# === F/конфиг: битая политика не проглатывается молча =========================
def test_bad_regex_rejected(sub, raw_policy, policy):
    import json
    base = json.loads(open(policy()).read())
    base["prompt_filter"]["block"] = [{"name": "bad", "pattern": "([unclosed"}]
    code, out, err = sub(raw_policy(base))
    assert code == 1
    assert "filter" in err.lower() or "rule" in err.lower()


def test_unknown_field_rejected(sub, raw_policy, policy):
    import json
    base = json.loads(open(policy()).read())
    base["totally_unknown_field"] = 123
    code, out, err = sub(raw_policy(base))
    assert code == 1
    assert "unknown field" in err.lower() or "parse" in err.lower()


# === A-04 / A-09 / C-15: устойчивость к обфускации — известное ограничение ====
# Регексный фильтр ловит явные шаблоны и, по документации самих авторов,
# не претендует на полную защиту от обфускации/инъекций. Эти кейсы помечены
# xfail: тест ЕСТЬ, но ожидаемо не проходит, что и фиксирует предел защиты.
# Реальный корпус обходов стоит гонять внешними инструментами (Garak, promptfoo),
# а не расширять руками.
@pytest.mark.xfail(reason="regex-фильтр не ловит обфускацию — заявленное ограничение проекта", strict=False)
@pytest.mark.parametrize("payload", [
    "x o x b-1234567890abcdef",          # разбито пробелами
    "eG94Yi0xMjM0NTY3ODkwYWJjZGVm",      # base64 того же токена
])
def test_c15_obfuscation_is_a_known_gap(sub, policy, payload):
    code, out, err = sub(policy(), prompt=payload)
    assert code == 1, "обфусцированный секрет НЕ блокируется (ожидаемый пробел)"
