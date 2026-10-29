# guard — независимое тестирование безопасности

Форк [SpaceAI-UAG/LLM-agent-security](https://github.com/SpaceAI-UAG/LLM-agent-security) с набором проверок безопасности **SpaceAI Guard (`guard`)**: автотесты, замеры, прогоны на Linux и macOS, найденные слабые места.

Исходный код guard принадлежит его авторам. В этом форке добавлены только тесты, workflow для macOS и этот README. Описание самого продукта — в [README авторов](https://github.com/SpaceAI-UAG/LLM-agent-security#readme).

| | |
|---|---|
| Проверенные версии guard | `46fa2d2` (исходная) и `3da71c3` / `346fc80` (MCP-шлюз и режим Codex, 29.10.2026) |
| Платформы | macOS (GitHub Actions, `macos-latest`) и Linux (Debian, контейнер Podman) |
| Статус | работа в процессе |

---

## Что такое guard

guard запускает ИИ-агента (Claude Code, Codex и т.п.) так, чтобы даже обманутый или ошибившийся агент не мог навредить за пределами разрешённого. **Агенту не доверяют**: ключи, правила и журналы хранятся снаружи, а агент работает в изолированной среде с контролируемыми выходами.

```
 ДОВЕРЕННАЯ ЗОНА (процесс guard)                НЕДОВЕРЕННАЯ ЗОНА (клетка)
 ┌───────────────────────────────────┐          ┌───────────────────────────┐
 │ политика guard.json               │          │ агент + всё, что он       │
 │ ключи и токены, журналы           │          │ запускает (shell, python, │
 │                                   │          │ npm, тесты)               │
 │ ПРОКСИ (один порт 127.0.0.1) ◄────┼── сеть ──┤                           │
 │  ├─ маршрут к модели → фильтр,    │  только  │ пишет: только рабочая     │
 │  │  + ключ → модель               │  сюда    │ папка (кроме self_protect)│
 │  ├─ allow_domains → сайты         │          │ читает: почти всё, кроме  │
 │  └─ /__guard → MCP-ШЛЮЗ           │          │ ключей и журналов         │
 │      → MCP-серверы                │          └───────────────────────────┘
 └───────────────────────────────────┘           стены — ядро ОС (Seatbelt)
```

**Три контрольные точки:**
1. **Клетка (Seatbelt на macOS)** — что агент делает на компьютере: файлы, программы, сеть.
2. **Прокси** — что агент отправляет в сеть: запросы к модели проверяются и дополняются ключом, сайты — только из `allow_domains`.
3. **MCP-шлюз** — что агент делает во внешних системах: белый список инструментов, проверка аргументов и результата, подтверждение человеком (`ask`).

**Платформы:** работает на macOS. На Linux с версии `3da71c3` запуск агента безопасно отклоняется («fails closed»): нет моста от изолированной сети к прокси. Windows не поддерживается. Проект — прототип без внешнего аудита (так заявлено авторами).

---

## Что проверялось

| Слой | Чем проверяли | Где |
|---|---|---|
| Фильтр промтов (`guard submit`) | наш pytest | Linux, macOS |
| Движок фильтра | наш pytest | Linux, macOS |
| Изоляция ключа и окружения агента | наш pytest (`--dry-run`) | macOS (на Linux новой версии неприменимо) |
| Охват типов секретов | `catch_rate.py` | Linux |
| Профиль песочницы | наш pytest (старый Linux), реальный профиль Seatbelt | Linux (старая версия), macOS |
| Песочница в работе | приёмочный тест авторов (`attack.sh`, 9 групп) | macOS |
| Прокси и фильтр (unit) | Go-тесты авторов | Linux, macOS |
| Безопасный отказ на Linux | прямые команды guard + файл-маркер | Linux |
| Архитектура, MCP-шлюз, проверка политики | чтение кода и документации | — |

**Не проверялось:** запуск настоящего агента (Claude Code / Codex) внутри guard, реальные вызовы MCP-инструментов и подтверждения, режим Codex.

---

## Состав форка

```
.github/workflows/guard-macos.yml   прогон на настоящем macOS (GitHub Actions)
tests/
  conftest.py                       общие фикстуры (сборка guard, политики, вызов submit)
  test_input_filter.py              фильтр промтов: секреты, маскирование, флаги, размер, monitor, аудит, политика
  test_filter_engine.py             движок фильтра: выключенный фильтр, приоритет block, литералы, пустой ввод
  test_key_isolation.py             ключ провайдера и посторонние секреты не попадают к агенту
  test_sandbox_profile.py           правила песочницы Linux — написаны под версию 46fa2d2, устарели (см. ниже)
  test_filter.py                    первый вариант тестов фильтра (дублирует test_input_filter.py)
  catch_rate.py                     замер доли пойманного на корпусе
  secrets.txt                       корпус-заглушка (обфускация)
  secret_types.txt                  корпус: 20 распространённых типов секретов (синтетические значения)
```

Все секреты в тестах и корпусах **синтетические**.

---

## Как запустить

### Linux (контейнер): фильтр, движок, замер охвата

```powershell
cd LLM-agent-security
podman run --rm -it -v "${PWD}:/src" -w /src docker.io/library/golang:1.26 bash
```

```bash
go build -buildvcs=false -o guard ./cmd/guard
apt-get update && apt-get install -y python3-pytest
mkdir -p examples/ws

go test ./...                                   # unit-тесты авторов
python3 -m pytest -v tests/test_input_filter.py tests/test_filter_engine.py

python3 tests/catch_rate.py --policy examples/policy.json --corpus tests/secret_types.txt
python3 tests/catch_rate.py --policy examples/policy.json --corpus tests/secret_types.txt --min-rate 0.8   # как порог для CI
```

`catch_rate.py` печатает только **номера** непойманных строк корпуса, а не их текст.

### macOS: GitHub Actions

На вкладке **Actions** → **guard-macos** → **Run workflow**. Workflow:
1. собирает guard и проверяет `sandbox-exec`;
2. печатает профиль Seatbelt для `examples/policy.json`;
3. запускает `test_input_filter.py`, `test_filter_engine.py`, `test_key_isolation.py`;
4. запускает `attack/run_attacks.sh` и `attack/filter_test.sh` (в версии `3da71c3` это Go-тесты авторов, включая `TestAttackAcceptance` — `attack.sh` в настоящей песочнице).

Шаги со скриптами авторов помечены `continue-on-error`, поэтому зелёный статус прогона не означает, что всё прошло: результат смотреть в логах шагов. Для публичного форка запуски на macOS бесплатны.

### Проверка безопасного отказа на Linux

```bash
export ANTHROPIC_API_KEY=sk-ant-FAKE-for-test   # без ключа run падает раньше, на проверке учётных данных
rm -f /tmp/harness_ran
./guard profile --policy examples/policy.json; echo "exit=$?"
./guard check   --policy examples/policy.json; echo "exit=$?"
./guard run --policy examples/policy.json -- /bin/sh -c 'touch /tmp/harness_ran'; echo "exit=$?"
ls /tmp/harness_ran     # файла быть не должно: агент не запускался
```

---

## Результаты

### macOS — версия `3da71c3`

| Проверка | Результат |
|---|---|
| Приёмочный тест авторов (`attack.sh` в песочнице) | ✅ 19 / 19 |
| `TestProxyPortIsolation`, `TestOfflineProfile` | ✅ |
| Go-тесты фильтра (URL, JSON) | ✅ все |
| Go-тесты прокси (лимиты, буферы, маршруты) | ✅ 4 / 4 |
| Наши тесты (фильтр, движок, изоляция ключа) | ✅ 27 passed, 2 xfailed |

Для версии `46fa2d2` приёмочный тест на macOS также дал 19 / 19.

### Linux — версия `3da71c3`

| Проверка | Результат |
|---|---|
| `go test ./...` | ✅ все пакеты `ok` |
| Наши тесты фильтра и движка | ✅ |
| `profile`, `check`, `run`, `run --dry-run` | отказ «Linux backend is not ready», агент не запускается (файл-маркер не создан) — **соответствует README** |
| `test_sandbox_profile.py` (5 тестов) и `test_base_url_points_at_proxy` | ❌ падают: проверяют поведение Linux-песочницы версии `46fa2d2`, которого больше нет |

### Замеры

| Корпус | Результат (обе версии) |
|---|---|
| `secret_types.txt` — 20 типов секретов | поймано **7 из 20 (35 %)** |
| `secrets.txt` — обфускация | поймано 1 из 3 |

Ловятся: AWS access key, GitHub classic PAT, Slack bot token (правило политики), OpenAI, Anthropic, PEM, GCP service account. Не ловятся, в том числе: AWS secret key, GitHub fine-grained PAT, GitLab PAT, Stripe, Google API key, npm, SendGrid, Twilio, Azure connection string, Google OAuth secret, Slack webhook, JWT, `password=`.

---

## Находки

Уровень подтверждения: **исполнение** — воспроизведено запуском; **профиль** — по профилю песочницы, который guard сгенерировал на целевой платформе; **код** — по чтению исходного кода.

### Актуальные (версия `3da71c3`, macOS)

| # | Находка | Подтверждение | Заявлено авторами |
|---|---|---|---|
| 1 | **Защита файлов автозапуска (`self_protect`) — только для путей из политики и только от корня рабочей папки.** Вложенные `.git/hooks` и файлы автозапуска не из списка не защищены. Агент может оставить файл, который позже выполнит доверенная программа вне песочницы (git, редактор, оболочка). Это основной класс обходов песочниц агентов, найденных в 2026 году | профиль | нет |
| 2 | Политика по умолчанию от `guard init` защищает меньше, чем пример: нет `.vscode`, `package.json`, скриптов сборки, CI-конфигов, `CLAUDE.md` и т.п. | код | нет |
| 3 | Встроенные детекторы ловят 7 из 20 распространённых типов секретов | исполнение | в общем виде («not an exhaustive inventory») |
| 4 | Ответ модели не проверяется встроенными детекторами секретов и ПДн, только правилами `response_block`; потоковые ответы (SSE) не проверяются вовсе | код | SSE — да |
| 5 | Белый список доменов проверяет имя хоста без учёта порта | код | нет |
| 6 | MCP-шлюз блокирует отдельный вызов, но не реагирует на повторные срабатывания (нет отключения инструмента или остановки сессии) | код | нет |
| 7 | Выключенный фильтр (`enabled: false`) не даёт защиты по секретам, без предупреждения | исполнение | — |
| 8 | Журнал аудита хранит решения, но не текст запроса — расследование ограничено | исполнение | да |
| 9 | После переписывания скриптов авторов автоматически больше не проверяются: блокировка вредного ответа модели, журнал и режим monitor через прокси | код тестов | — |

### Закрыты в версии `3da71c3`

| Было | Стало |
|---|---|
| На macOS агенту были доступны все локальные сервисы (`localhost:*`) | сеть только на порт прокси (подтверждено `TestProxyPortIsolation`) |
| Агент мог писать в общую `/private/tmp` | убрано, у сессии свой временный каталог |
| Адрес модели автоматически попадал в список сайтов | убрано, к модели — только через маршрут с проверками |
| Пути API сверялись по префиксу | точное совпадение |
| Linux: `self_protect` только для существующих путей, падение при отсутствии папки из `read_deny`, не работал `exec.deny` | Linux-backend отключён с безопасным отказом |
| Не было unit-тестов | добавлены Go-тесты (CI по-прежнему нет) |

---

## Рекомендации

1. Встроенный список файлов автозапуска и конфигурации (git-хуки, `.envrc`, настройки редакторов и агентов, конфиги MCP, скрипты пакетов и сборки, CI), защищённый **на любой глубине** рабочей папки.
2. Расширить встроенные детекторы секретов; проверять секреты и в ответах модели.
3. Учитывать порт в белом списке доменов.
4. Реакция на повторные срабатывания в MCP-шлюзе: перевод инструмента в `ask`, отключение сервера, остановка сессии.
5. Вернуть сквозные проверки прокси (вредный ответ модели, журнал, monitor) и добавить CI.
6. Для серверных сценариев — Linux-backend с мостом к прокси, затем вариант изоляции на gVisor или microVM.

---

## Ограничения этого тестирования

- Агента (Claude Code / Codex) внутри guard не запускали: роль агента играл shell-скрипт авторов.
- MCP-шлюз и режим Codex изучены по коду и документации, реальных вызовов не было.
- Находка 1 подтверждена профилем; попытка записи во вложенный путь не выполнялась.
- Обфускация и смысловые утечки не тестировались намеренно: это заявленное ограничение regex-фильтра. Для замера стоит использовать готовые корпуса (Garak, promptfoo) через `catch_rate.py`.
- `test_sandbox_profile.py` и `test_base_url_points_at_proxy` нужно переписать под новое поведение: на Linux — проверка безопасного отказа, на macOS — проверка профиля Seatbelt.

---

## Ссылки

- [README авторов guard](https://github.com/SpaceAI-UAG/LLM-agent-security#readme) и [ограничения платформ](https://github.com/SpaceAI-UAG/LLM-agent-security/blob/main/docs/usage.md#limitations)
- [Claude Code — sandboxing](https://code.claude.com/docs/en/sandboxing) — для сравнения подходов
- [NVIDIA — Practical security guidance for sandboxing agentic workflows](https://developer.nvidia.com/blog/practical-security-guidance-for-sandboxing-agentic-workflows-and-managing-execution-risk)
- [Simon Willison — The lethal trifecta for AI agents](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/)
- [Pillar Security: обходы песочниц агентов, 2026 (обзор)](https://codex.danielvaughan.com/2026/07/28/week-of-sandbox-escapes-pillar-security-codex-cli-cursor-gemini-docker-socket-git-hooks-defence/)

Уязвимости в самом guard авторы просят сообщать приватно — см. [`SECURITY.md`](SECURITY.md).
