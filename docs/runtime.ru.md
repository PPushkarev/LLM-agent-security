# guard — Codex в песочнице с фильтрацией данных

`guard` запускает Codex CLI под внешней OS-песочницей и проверяет запросы до
отправки в API. Codex и запущенные им инструменты не получают токены входа или
API-ключ: нужные заголовки добавляет доверенный прокси после проверки запроса.

**Рабочий backend: macOS / Seatbelt.** Сквозной тест запускает настоящий Codex,
выполняет shell-команду и проверяет фильтрацию через локальный Responses API.
Проверенная версия Codex CLI: **0.163.0**, нативный исполняемый файл.
Нужен Go **1.26+** для сборки.

Linux backend использует bubblewrap, отдельные user/PID/network/mount namespaces
и обязательный seccomp. Канал к proxy родителя передаётся через файловый дескриптор;
внутри namespace поднимается только loopback endpoint proxy. Поддерживаются
Linux amd64/arm64 с доступными user namespaces и seccomp. Для `exec.allow`
дополнительно требуется Landlock. Windows не поддерживается.

## Linux

Установи Go 1.26+ и bubblewrap. Например, на Debian/Ubuntu:

```sh
sudo apt-get update
sudo apt-get install bubblewrap
make build
./guard init --workspace /absolute/path/to/project --output guard.json --auth api --model YOUR_MODEL_ID
./guard check --policy guard.json
export OPENAI_API_KEY='your-api-key'
./guard run --policy guard.json -- /absolute/path/to/harness
# Для установленного нативного Codex также доступен адаптер:
./guard codex --policy guard.json
```

Для сборки отдельных статических бинарников обеих Linux-архитектур доступна
`make build-linux`: результаты находятся в `dist/guard-linux-amd64` и
`dist/guard-linux-arm64`. Bubblewrap всё равно нужен на целевой машине.

Для подписки ChatGPT используй `--auth chatgpt` и существующий вход Codex вместо
API-ключа. Нативный Codex должен быть установлен отдельно. Сквозная проверка с
настоящим Codex выполнена на macOS; на Linux проверены независимый harness,
фильтрующий proxy и локальные/удалённые MCP, без обращения к платной модели.

`guard check` проверяет policy и наличие bubblewrap; фактическая доступность
namespace/seccomp проверяется при запуске. Если дистрибутив, AppArmor или внешний
контейнер запрещает user namespaces, bubblewrap сообщит об ошибке. Guard не
переключается на запуск без песочницы. Запускать guard от root не требуется.

Linux сохраняет доступ к workspace под HOME. Writable mounts применяются до
`read_deny`, поэтому writable-каталог не раскрывает запрещённый секрет.
Создание Unix-сокетов (включая abstract sockets), ptrace, операции mount/setns,
BPF и io_uring блокируются обязательным seccomp. Это также ограничивает
инструменты, которым для работы нужны локальные Unix-сервисы.

`exec.deny` скрывает указанный бинарный файл, запрещая и его чтение. Как и на
macOS, запрет пути не охватывает заранее сделанную копию бинаря.
`exec.allow` использует Landlock; для динамических программ и скриптов нужно
явно разрешить ELF loader и интерпретаторы. Разрешённый интерпретатор всё ещё
может выполнять произвольный код в пределах остальных ограничений песочницы.

Для отсутствующих `self_protect`-путей внутри writable guard на время запуска
создаёт пустые файлы и необходимые родительские каталоги, затем монтирует файлы
read-only. Это резервирует запрещённые имена, сохраняя запись в остальной
workspace. После сессии созданные пустые placeholders удаляются; непустые файлы и файлы,
заменённые внешним процессом на другой inode, не удаляются. При аварийном завершении guard такие пустые
файлы могут остаться. Существующие защищённые файлы и каталоги сохраняются.

## Guardrails

Новая policy из `guard init` включает строгий режим и лимиты сессии. Для
существующей policy добавь секцию и задай отдельный журнал вне writable:

```json
{
  "guardrails": {
    "strict": true,
    "max_session_seconds": 3600,
    "max_output_bytes": 16777216,
    "audit_log": "/absolute/path/outside-workspace/session.guardrails.jsonl"
  }
}
```

Это фрагмент policy, а не полный конфигурационный файл. Родительский каталог
журнала должен существовать. Файл создаётся с правами 0600.

Строгий режим требует включённый `prompt_filter` в enforce-режиме и
`scan_responses: true`, отдельные
журналы сессии и контентного фильтра, положительные лимиты сессии/вывода и бюджеты
`limits.max_requests`/`limits.max_request_bytes`. Он запрещает `allow_domains`:
API нужно направлять через проверяемые `key_injection` routes с `require_json`,
разрешёнными методами и путями. MCP использует отдельный управляемый шлюз. Сырой egress локальных MCP через
`sandbox.allow_domains` в строгом режиме также запрещён.
Несогласованная policy отклоняется до запуска harness.

`max_session_seconds` ограничивает время исполнения harness, включая ожидание
MCP-подтверждения во время его работы. Подготовка credentials и запуск MCP до
старта harness в этот таймер не входят. `max_output_bytes` — общий бюджет
stdout/stderr harness и его дочерних процессов; prompts в stdin в него не входят.
Превышение завершает группу процессов и закрывает сетевые сервисы сессии. На
Linux PID namespace обеспечивает завершение процессов при остановке sandbox;
на macOS отсоединённый процесс, создавший собственную сессию, может пережить
остановку группы, сохраняя файловые и сетевые ограничения Seatbelt. Для строгого
контроля жизненного цикла таких процессов используй отдельную VM.

Интерактивные запуски используют PTY, сохраняя терминальный интерфейс harness
при проверке бюджета вывода. Журнал содержит `session_start`, `session_block`,
`session_end`, причину и число байтов, без текста вывода. Ошибки записи журнала
возвращаются как ошибки guard. Отдельные JSONL-журналы контентного фильтра и MCP
сохраняют решения на своих границах.

Guardrails здесь — детерминированные ограничения policy, regex и JSON Schema.
Семантическая оценка ответов модели, полнота обнаружения prompt injection и
запись каждого локального syscall не реализованы. SSE модели проверяется целиком до передачи harness, когда включён
`scan_responses`; результаты MCP проверяются после сборки целого tool result.
`strict` требует включённую проверку ответов модели. При отсутствии секции guardrails старые policy
сохраняют прежнее поведение; нулевые лимиты означают отсутствие ограничения.

Проверки:

```sh
make check
# На Linux с установленным bwrap: все тесты выполняются напрямую.
go test -race ./...
# На macOS: Linux-тесты в отдельном Docker-контейнере, тестовые процессы не root.
make test-linux
```

Привилегированный контейнер используется только как стенд для вложенных
namespaces, не как способ production-запуска guard. Скрипт передаёт в него
только скомпилированные тестовые бинарники.

## Правила для ответов модели

`prompt_filter.scan_responses: true` включает барьер проверки ответов: ни один
байт ответа, включая SSE tool calls, не передаётся harness до окончания проверки.
При блокировке клиент получает HTTP 403 и JSON с типом `guardrail_violation`,
именем правила и общим сообщением, без текста запрещённого ответа.

Пример фрагмента `prompt_filter` для дополнения существующей policy:

```json
{
  "enabled": true,
  "mode": "enforce",
  "scan_responses": true,
  "response_max_bytes": 8388608,
  "response_timeout_sec": 120,
  "response_rules": [
    {"name": "email", "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", "action": "redact"},
    {"name": "destructive_command", "pattern": "rm\\s+-rf\\s+/", "action": "block"},
    {"name": "ignore_instructions", "pattern": "(?i)ignore (all )?(previous|system) instructions", "action": "block"},
    {"name": "review_marker", "pattern": "REVIEW_REQUIRED", "action": "flag"}
  ],
  "response_json": {
    "deny_fields": ["/internal_debug"],
    "rules": [
      {"name": "private_client", "path": "/response/output/*/content/*/text", "pattern": "Acme", "action": "redact"}
    ]
  }
}
```

Regex проверяет декодированные строки JSON и поддерживает `block`, `redact`,
`flag`. Встроенные детекторы секретов и точных proxy credentials также активны
на ответах. JSON-аргументы tool calls, переданные внутри строки, проверяются
после декодирования вложенного JSON. JSON-ключи, в которых требуется redaction,
блокируют ответ целиком вместо изменения структуры протокола.

Для SSE собираются текстовые и argument delta-поля по идентификатору output,
choice/tool index и JSON-пути. Поэтому email или запрещённая команда, разбитые
между обычными delta-событиями одного output, не обходят проверку. При redaction
очищенный агрегат помещается в первый delta этого output, остальные очищаются;
итоговые done/completed-события проходят собственную проверку. Неполные и
невалидные потоки блокируются. Поддерживаются JSON-события с завершением
`response.completed` (Responses API), `[DONE]` (Chat Completions) или
`message_stop` (Anthropic). Другой формат требует отдельного адаптера.

`response_json` применяется к JSON-ответу или каждому SSE JSON-событию. Пути
зависят от протокола: `/output/...` в обычном Responses JSON и
`/response/output/...` в SSE-событии `response.completed`. Как и request JSON
policy, структурные запреты остаются обязательными в monitor-режиме;
мониторинг снимает блокировку и redaction только с обычных regex-правил.

Для задачи, где модель обязана возвращать JSON заданной структуры, можно
дополнительно задать schema и точный путь к тексту итогового ответа:

```json
{
  "response_schema_path": "/output/0/content/0/text",
  "response_schema": {
    "type": "object",
    "properties": {
      "status": {"type": "string", "enum": ["ok", "needs_review"]},
      "answer": {"type": "string", "maxLength": 2000}
    },
    "required": ["status", "answer"],
    "additionalProperties": false
  }
}
```

Это также поля внутри `prompt_filter`. При выборе строкового поля его содержимое
разбирается как JSON-документ. Пустой `response_schema_path` проверяет весь JSON
ответа. Для SSE схема применяется к полю `response` события `response.completed`,
так что указанный выше путь одинаков для обычного и SSE Responses API.
Schema проверяется до и после redaction. Внешние `$ref` не загружаются.
Для SSE других протоколов итоговая schema без адаптера блокирует ответ: нет
подтверждённого полного объекта для проверки. Schema заданного JSON-ответа также
отклонит промежуточный ответ с tool call, если нужного текстового поля ещё нет;
используй такую policy для задач с ожидаемым структурированным финальным ответом.

Проверка ограничена 8 МиБ и 120 секундами на ответ по умолчанию; можно уменьшить
размер и изменить время до 600 секунд. Одновременно буферизуются не более четырёх
ответов. Сжатые ответы без декодирования, превышение лимитов и ошибка аудита
закрывают передачу. При включённом барьере SSE теряет token-by-token вывод:
ответ появляется только после завершения upstream-генерации и проверки.
Это сознательная цена проверки полного ответа до исполнения действий агентом.

Регулярное выражение про `rm -rf` или prompt injection — пример правила,
а не семантическая гарантия: альтернативные команды, base64 и иные кодировки
требуют других ограничений. OS-песочница и разрешения MCP остаются обязательны.

## Быстрый запуск

```sh
go build -o guard ./cmd/guard

# Каталог с проектом, в котором будет работать Codex.
# --model — ID модели, доступной в твоём Codex/ChatGPT-аккаунте.
./guard init --workspace /absolute/path/to/project \
  --output guard.json --auth chatgpt --model YOUR_MODEL_ID

./guard check --policy guard.json

# Существующий вход используется только доверенным родителем:
codex login status

# Интерактивный Codex:
./guard codex --policy guard.json

# Одна задача без TUI:
./guard codex --policy guard.json -- exec 'Посмотри проект и объясни его структуру'
```

Рабочий каталог Codex — `workspace` из policy. Новая policy не перезаписывает
существующий файл. Генератор создаёт каталог workspace, если его ещё нет.
Относительные пути в policy разрешаются относительно текущего каталога shell;
`guard init` записывает абсолютный workspace.

По умолчанию используется **существующий вход Codex через подписку ChatGPT**.
Guard читает `auth.json` из родительского CODEX_HOME (по умолчанию `~/.codex`),
добавляет `Authorization` и `ChatGPT-Account-ID` после фильтрации и отправляет
запрос на Codex backend. Исходные credentials остаются вне sandbox.

Если входа ещё нет, выполни снаружи guard:

```sh
codex -c 'cli_auth_credentials_store="file"' login
```

При хранении входа только в системном keyring требуется сначала вход с файловым
хранилищем. Guard не извлекает credentials из Keychain. Обновление истекающего
access token выполняется доверенным helper-процессом `codex app-server` через
`account/read` с `refreshToken: true`; модельные задачи в helper не запускаются.
Если сессия отозвана, повтори `codex login` снаружи sandbox. Кеш перечитывается
перед запросами, поэтому обновление входа подхватывается без копирования токенов
в Codex внутри песочницы.

Для отдельного API-аккаунта доступен альтернативный режим:

```sh
./guard init --workspace /absolute/path/to/project \
  --output guard-api.json --auth api --model YOUR_API_MODEL_ID
export OPENAI_API_KEY='your-api-key'
./guard codex --policy guard-api.json
```

Доступность модели и лимиты подписки определяет твой аккаунт. Автоматические
тесты используют локальные серверы и фиктивные credentials.

По умолчанию новая policy:

- для подписки разрешает только `POST /backend-api/codex/responses` и `/backend-api/codex/responses/compact`;
- в API-режиме разрешает только `POST /v1/responses` и `/v1/responses/compact`;
- разрешает выбранную модель, если передан `--model`;
- блокирует обнаруженные секреты и маскирует email и международные телефоны;
- запрещает чтение типовых каталогов с секретами;
- ограничивает запись workspace и отдельными служебными каталогами сессии;
- запрещает прямой TCP-доступ, доступ к другим локальным портам и произвольным доменам;
- включает лимиты запросов и байтов;
- сохраняет аудит в `~/.guard/logs/`, вне workspace.

## Как устроен запуск

```text
guard — доверенный родитель, читает сессию ChatGPT или API-ключ
 ├─ HTTP-прокси на случайном localhost:PORT
 │   ├─ точный маршрут и HTTP-метод
 │   ├─ query-параметры, модель и JSON-поля
 │   ├─ поиск секретов / block / redact / flag
 │   └─ добавление auth-заголовков и запрос к Codex backend / API по HTTPS
 └─ Seatbelt → Codex → shell и остальные дочерние процессы
```

У Codex отдельные HOME, CODEX_HOME и TMPDIR. Пользовательские `auth.json`,
`config.toml`, плагины и MCP-конфигурация из реального CODEX_HOME не копируются.
В служебный каталог копируется только нативный исполняемый файл Codex; это
позволяет запускать установку, находящуюся внутри запрещённого `~/.codex`.
Для другого расположения укажи `codex.binary` в policy.

Внутренний sandbox Codex отключён (`sandbox_mode = "danger-full-access"`),
поскольку вложенный Seatbelt мешает запуску shell. **Внешняя песочница guard
при этом действует на весь Codex и всех его потомков.** Guard использует
отдельный custom provider с `supports_websockets = false`, чтобы запросы шли
через проверяемый HTTP, а ответы могли приходить по SSE.

Состояние Codex временное: при выходе сессия и служебные каталоги удаляются.
Изменения в workspace и audit log сохраняются. Возобновление сессии после выхода
пока не поддерживается. В выводе могут встречаться `DENY` для фоновых обращений
Codex к GitHub или ChatGPT — эти домены по умолчанию закрыты.

## Настройка фильтров

Открой созданный `guard.json`. После изменения проверь его командой
`./guard check --policy guard.json` и перезапусти сессию.
Горячая перезагрузка policy не реализована.

### Содержимое: block, redact, flag

Пример секции `prompt_filter`:

```json
{
  "enabled": true,
  "mode": "enforce",
  "max_body_bytes": 4194304,
  "block": [
    {"name": "internal_project", "pattern": "(?i)project[ -]orion", "action": "block"}
  ],
  "redact": [
    {"name": "email", "pattern": "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", "action": "redact"},
    {"name": "phone", "pattern": "\\+[0-9][0-9 ()-]{8,}[0-9]", "action": "redact"},
    {"name": "customer", "pattern": "(?i)Acme Corp", "action": "flag"}
  ],
  "literal_redact": ["CONFIDENTIAL-CUSTOMER-NAME"],
  "scan_responses": true,
  "audit_log": "/absolute/path/outside/workspace/audit.log"
}
```

- `block`: остановить запрос с `403`;
- `redact`: заменить совпадение на `[REDACTED:имя]`;
- `flag`: записать совпадение и передать данные без изменения.

Регулярные выражения используют синтаксис Go regexp / RE2, без lookbehind и
обратных ссылок. В JSON обратный слеш записывается как `\\`.

`mode: "monitor"` отключает блокировки и изменения **контентного фильтра**,
оставляя записи о предполагаемых действиях. Ограничения маршрутов, JSON-policy,
сети и ресурсов продолжают действовать. Не используй monitor для данных,
которые нельзя отправлять наружу.

В JSON-запросах проверяются декодированные строковые значения: запись
`alice\u0040example.com` также обнаруживается как email. Замены сохраняют
валидность JSON. Query-параметры проверяются после URL-декодирования. Если
маскирование затронуло бы путь URL, запрос блокируется вместо изменения маршрута.

### Модели, JSON-поля и отдельные значения

В нужном элементе массива `key_injection` настрой `json`:

```json
{
  "require_json": true,
  "allow_models": ["YOUR_MODEL_ID"],
  "deny_fields": ["/metadata/private", "/input/*/image_url"],
  "rules": [
    {
      "name": "customer_name",
      "path": "/input/*/content/*/text",
      "pattern": "(?i)Acme Corp",
      "action": "redact"
    },
    {
      "name": "external_tool",
      "path": "/tools/*/type",
      "pattern": "^(web_search|web_search_preview|file_search|mcp)$",
      "action": "block"
    }
  ]
}
```

Пути — JSON Pointer: `/` разделяет сегменты, `~1` обозначает `/` внутри имени,
`~0` — `~`. Отдельный сегмент `*` совпадает с одним ключом или индексом массива.
`deny_fields` запрещает наличие поля, даже если значение `null`.
Пустой `allow_models` разрешает любую модель на разрешённом endpoint.
Маскирование по JSON-правилу допускается только для строк; для других типов
запрос блокируется. JSON-policy применяется независимо от `prompt_filter.mode`.

Глобальный контентный фильтр проверяет все JSON-строки, включая сообщения,
результаты инструментов и аргументы tool calls. Сначала проверяются блокирующие
правила, затем выполняются замены. Если секрет уже прочитан локальным инструментом,
это не отменяет его обнаружения на следующем исходящем API-запросе. Для запрета
самого чтения файла добавь его абсолютный путь в `read_deny`.

### Методы, пути и query-параметры

```json
{
  "prefix": "/search",
  "upstream": "https://search.example.com",
  "methods": ["GET"],
  "allow_paths": ["/v1/search"],
  "query": {
    "allow_params": ["q", "count"],
    "deny_params": ["callback"],
    "max_param_len": 200,
    "param_rules": [
      {"param": "q", "pattern": "(?i)site:internal", "action": "block"}
    ]
  }
}
```

`allow_paths` проверяет точные пути. Путь, заканчивающийся `/`, разрешает всё
поддерево под этим префиксом. `/v1/responses` не разрешает `/v1/responses-extra`.
Пустые списки методов и путей означают отсутствие соответствующего ограничения.
Route prefix должен быть непустым и не должен пересекаться с другим route.
Для upstream указывается origin без path/query, а API-путь приходит от клиента.

Для подписки соответствующий route содержит:

```json
{
  "prefix": "/codex",
  "upstream": "https://chatgpt.com",
  "auth": {"type": "codex", "codex_home": "/absolute/path/to/.codex"},
  "methods": ["POST"],
  "allow_paths": ["/backend-api/codex/responses", "/backend-api/codex/responses/compact"],
  "json": {"require_json": true}
}
```

Пустой `codex_home` использует родительский CODEX_HOME или `~/.codex`.
Каталог credentials не может находиться в writable-путях; subscription auth
разрешён только для origin `https://chatgpt.com`. Route с таким auth не должен
одновременно содержать `env` и `header`. Поле `codex.route` верхнего уровня
должно совпадать с `prefix` выбранного route.

Для подстановки API-ключа используй `header`, `header_prefix` и `env`:

```json
{"header": "Authorization", "header_prefix": "Bearer ", "env": "OPENAI_API_KEY"}
```

Переменная с ключом не может одновременно находиться в `env_allow`.
Upstream маршрута автоматически не открывается для CONNECT или прямого HTTP.
Список `allow_domains` управляет таким доступом отдельно; в Codex-policy он пуст.

### Лимиты и файловая система

```json
{
  "limits": {
    "max_requests": 500,
    "rate_per_min": 60,
    "max_request_bytes": 52428800
  },
  "read_deny": ["~/.ssh", "~/.aws", "/absolute/path/to/project/.env"],
  "self_protect": [".git/hooks", ".git/config", ".envrc", ".codex"]
}
```

Нулевой лимит означает отсутствие соответствующего ограничения. Размеры — в
байтах. Для HTTP-запросов учитывается фактический размер тела, включая chunked.
Rate limit — фиксированное окно 60 секунд. Превышение бюджета возвращает `429`.
Жёсткий предел буферизации запроса и сканируемого ответа — 8 МиБ, в том числе
в monitor; слишком большой запрос получает `413`.

`self_protect` разрешается относительно workspace. Чтение остальных файлов
разрешено: это denylist-модель чтения, поэтому добавь свои секретные файлы явно.
Запись разрешена только в workspace, дополнительных `writable` и служебных
каталогах текущего запуска. Policy защищается от записи из sandbox.

Audit log не может находиться внутри writable-каталога, включая путь через
symlink. Родительский каталог журнала должен существовать; `guard init` создаёт
его. Ошибка записи журнала останавливает дальнейшую передачу проверяемого тела
запроса. Журнал содержит решения и имена правил, а не полные prompts.

## Контроль MCP

Секция `mcp` задаёт серверы и инструменты, которыми управляет guard. Личные
MCP-настройки из исходного CODEX_HOME не импортируются при `guard codex`. Harness подключается к
локальному шлюзу на том же порту, что и guard proxy. Сам шлюз подключается к
разрешённым серверам: по `stdio` для локальных процессов или по Streamable HTTP
для удалённых. Используется официальный Go MCP SDK, включая согласование
поддерживаемой версии протокола; старый отдельный SSE transport не поддерживается.

Указанный в policy сервер не получает автоматического разрешения на все tools.
Guard показывает только явно разрешённые инструменты и повторно проверяет
каждый вызов. Пустой список серверов отключает управляемые MCP. Неизвестный
инструмент, пустое действие или `deny` означают запрет.

### Локальный пример без сторонних сервисов

```sh
make build mcp-example

./guard init --workspace /absolute/path/to/project \
  --output guard.json --auth chatgpt --model YOUR_MODEL_ID \
  --mcp-example "$PWD/guard-mcp-example"

./guard check --policy guard.json
./guard codex --policy guard.json
```

Попроси Codex вызвать инструмент `echo` сервера `example` с текстом
`hello alice@example.com`. Пример использует действие `ask`: до подтверждения
сервер не получит вызов. В другом терминале:

```sh
./guard mcp pending --policy guard.json
./guard mcp approve --policy guard.json --id ID_ИЗ_СПИСКА

# Либо отклонить:
./guard mcp deny --policy guard.json --id ID_ИЗ_СПИСКА
```

Очередь показывает сервер, инструмент, отфильтрованные аргументы, идентификатор
сессии и срок действия запроса. Разрешение одноразовое и связано с точными
аргументами. При отмене, несовпадении digest или истечении срока вызов не
передаётся серверу. Очередь находится вне sandbox. HTTP endpoint для управления
подтверждениями отсутствует: эти действия выполняются отдельной CLI-командой
доверенного пользователя.

### Настройка сервера и инструментов

Пример секции в `guard.json` для удалённого сервера:

```json
{
  "mcp": {
    "servers": {
      "docs": {
        "url": "https://mcp.example.com/mcp",
        "bearer_env": "DOCS_MCP_TOKEN",
        "max_calls": 200,
        "rate_per_min": 30,
        "max_parallel": 2,
        "timeout_sec": 30,
        "approval_timeout_sec": 120,
        "max_request_bytes": 1048576,
        "max_response_bytes": 2097152,
        "tools": {
          "search": {
            "action": "allow",
            "schema": {
              "type": "object",
              "properties": {
                "repository": {"const": "my-org/my-project"},
                "query": {"type": "string", "maxLength": 200}
              },
              "required": ["repository", "query"],
              "additionalProperties": false
            },
            "arguments": {
              "deny_fields": ["/private"],
              "rules": [
                {"name": "internal_query", "path": "/query", "pattern": "(?i)confidential", "action": "block"}
              ]
            },
            "result": {
              "rules": [
                {"name": "internal_result", "path": "/content/*/text", "pattern": "INTERNAL-ONLY", "action": "block"}
              ]
            }
          },
          "create_note": {"action": "ask"},
          "delete_note": {"action": "deny"}
        }
      }
    }
  }
}
```

Имена tools и их параметры должны соответствовать конкретному MCP-серверу;
`docs`, `search` и поля в примере условные. Имена поддерживаемых tools проверяются
при запуске: если разрешённого инструмента нет, guard останавливает запуск.
JSON Schema из `schema` применяется дополнительно к схеме самого инструмента.
Аргументы проверяются после фильтрации и до передачи серверу. Внешние `$ref`
не загружаются. Каталог tools фиксируется на сессию, изменения серверного
каталога автоматически не открывают новые инструменты. Описания и annotations
сервера не используются как основание для разрешения; шлюз публикует своё
краткое описание каждого инструмента.

`arguments` и `result` используют JSON-пути и правила из раздела о JSON-фильтрах.
К обоим направлениям также применяется глобальный контентный фильтр
`prompt_filter`: проверяются секреты, выполняются `redact` и `flag`. Это отдельная
проверка MCP-результата до передачи harness; отдельный барьер SSE-ответов модели
управляется через `scan_responses`. Поля `response_block` и `scan_responses` относятся к фильтрации
ответов модели; MCP-специфические запреты результата задаются через `result`.

Удалённые credentials берутся из `bearer_env` в доверенном guard и не передаются
Codex. Redirect запрещён; автоматических повторов tool calls нет. Допускается
HTTPS, а для явного локального тестового endpoint — `http://127.0.0.1:PORT`
с `allow_http: true`. Браузерные Origin отклоняются, локальное соединение Codex
со шлюзом защищено отдельным токеном текущего запуска. OAuth/browser login
MCP-серверов пока не реализован: для них нужен заранее полученный bearer token.
Нельзя одновременно открыть hostname управляемого MCP в `allow_domains` агента:
такое сочетание позволило бы обходить шлюз прямым сетевым подключением.

### Изоляция локальных серверов

Вместо `url` укажи массив `command`. Локальный сервер запускается вне процесса
Codex, но под отдельным Seatbelt-профилем. По умолчанию доступны только необходимые
системные runtime-пути, сам executable и отдельные временные HOME/TMPDIR.
Чтение workspace, запись в него и сеть требуют отдельных разрешений:

```json
{
  "command": ["/absolute/path/to/server"],
  "env_allow": ["MY_SERVER_TOKEN"],
  "sandbox": {
    "read_allow": ["/absolute/path/to/project/docs"],
    "writable": [],
    "allow_domains": []
  },
  "tools": {"search_docs": {"action": "allow"}}
}
```

Дополнительные writable-пути должны находиться внутри writable-путей основной
policy. Каталоги учётных данных, audit и approvals остаются запрещены.
Локальный сервер получает только явно перечисленные переменные `env_allow`;
учётные данные модели передавать ему нельзя. Для Python/Node-сервера явно
разреши чтение файлов программы и её зависимостей. Не используй автоматический
`npx -y` download при запуске — установи и выбери сервер заранее.

Если серверу разрешена сеть через `sandbox.allow_domains`, она идёт через его
отдельный egress proxy. Для CONNECT виден hostname, но не содержимое TLS.
При передаче серверу токена и доступа к сети доверяй его коду и ограничивай
права самого токена. Для удалённых серверов guard проверяет вызов и результат,
но не контролирует их внутренние соединения и файловую систему.

### Аудит, лимиты и границы MCP-шлюза

По умолчанию журнал MCP находится в `<prompt_filter.audit_log>.mcp.jsonl`,
а очередь — в `<mcp.audit_log>.approvals/`. Их можно переопределить через
`mcp.audit_log` и `mcp.approval_dir`. Оба пути должны быть вне writable-каталогов.
Журнал — приватный JSONL: сессия, call ID, сервер, tool, решение, правило,
время, размер и hash аргументов/схемы. Сырые аргументы и ответы в журнал не
записываются. Ошибка записи журнала останавливает вызовы.

Нулевые MCP-лимиты выбирают безопасные defaults: 500 вызовов, 60 вызовов/мин,
один параллельный вызов, 60 секунд на сервер, 120 секунд на подтверждение,
1 МиБ аргументов и 2 МиБ результата. Максимальные значения: 32 параллельных
вызова, 600 секунд, 8 МиБ аргументов или результата. Transport дополнительно
ограничивает stdio frames и полные HTTP-ответы 16 МиБ. Разрешённые попытки
расходуют бюджет, включая запросы, которые затем отклонены пользователем.
После таймаута сервер отключается до перезапуска guard. Локальный процесс
и его process group завершаются при закрытии; таймаут или отмена не откатывают
уже совершённые удалённые операции.

Сейчас шлюз предоставляет tools. Resources, prompts, sampling, elicitation,
opaque multi-round-trip state и нетекстовые content blocks запрещены. Ответы
Streamable HTTP/SSE разбираются SDK, а финальный tool result проверяется целиком.
Legacy SSE и автоматическая OAuth-авторизация не поддерживаются.

Управляемые MCP работают и через `guard run`, и через `guard codex`. Для каждого
запуска guard создаёт приватный файл подключения и передаёт его путь дочернему
процессу в `GUARD_MCP_CONFIG`. Файл содержит объект `mcpServers`, где каждому
имени соответствуют `type: "http"`, `url` и `headers.Authorization`. Это адреса
локального шлюза и временный токен текущего запуска; credentials исходных
серверов остаются у родителя. Файл защищён от изменения в песочнице и удаляется
после завершения запуска. Codex получает настройки автоматически через адаптер.

Другой harness запускается обычной командой:

```sh
./guard run --policy guard.json -- /absolute/path/to/harness
```

Для harness с поддержкой Streamable HTTP перенеси адреса и заголовки из
`GUARD_MCP_CONFIG` в его MCP-конфигурацию при запуске. Единого механизма импорта
конфигурации для всех harness нет: сама переменная окружения не заставляет
произвольный клиент подключиться к шлюзу.

Для клиентов, которые подключают MCP через stdio, укажи сервер-мост в их
конфигурации (замени путь и `example` на имя из `mcp.servers`):

```json
{
  "mcpServers": {
    "example": {
      "command": "/absolute/path/to/guard",
      "args": ["mcp", "bridge", "--server", "example"]
    }
  }
}
```

Мост запускается самим harness **внутри `guard run`** и наследует
`GUARD_MCP_CONFIG`. Если клиент очищает окружение MCP-процессов, разреши передачу
этой переменной. Мост передаёт только tools через управляемый шлюз; его stdout
содержит исключительно MCP-протокол. Все вызовы проходят те же проверки,
подтверждения и аудит, что и при HTTP-подключении. Настраивай клиент на эти
подключения вместо прямых адресов исходных MCP-серверов.

Общая песочница и MCP-контроль не зависят от протокола LLM конкретного harness.
Подключение его модельного API к фильтрующему proxy настраивается отдельно;
готовый адаптер входа через подписку ChatGPT сейчас предназначен для Codex.
Шлюз контролирует свои endpoints и credentials.
Произвольная программа, запущенная агентом через shell, остаётся ограничена
основной OS-песочницей; семантический запрет tool не является запретом всех
эквивалентных действий через shell. Ограничивай файловые права и внешние
credentials также на уровне ОС и сервиса.

## Проверка и другие команды

```sh
# Проверка policy без обращения к API и без требования API-ключа:
./guard check --policy guard.json

# Профиль и окружение будущего запуска (нужен существующий вход / API-ключ):
./guard codex --policy guard.json --dry-run -- exec 'hello'

# Контентная проверка текста без запуска Codex:
printf 'mail alice@example.com' | ./guard submit --policy guard.json

# Другой harness; он должен использовать настроенный proxy/base URL:
./guard run --policy guard.json -- /absolute/path/to/harness

make check
```

`guard submit` проверяет текст контентным фильтром; JSON-policy маршрута
применяется на сетевом запросе. `guard profile` с `proxy_port: 0` печатает
offline-профиль без сетевого разрешения; фактический порт назначается при запуске.

`go test -race ./...` включает unit-тесты и интеграционные проверки локальных
HTTP-серверов. На macOS при наличии нативного `codex` также выполняется сквозной
тест: guard → Seatbelt → настоящий Codex → shell tool → guard proxy → тестовый
Responses/SSE API. Настоящие учётные данные для теста не нужны. Проверяются
API-key и ChatGPT-маршруты, account header и обновление тестового токена через RPC.

## Границы защиты

- Regex-фильтрация не является семантическим DLP: base64, изображения,
  шифрование, разделение секрета на несколько запросов и иные преобразования
  не распознаются автоматически. Байтовые лимиты не устраняют этот риск.
- При `scan_responses: true` SSE модели буферизуется и проверяется до передачи
  harness. При выключенной проверке ответ проходит без этого барьера. Regex и
  JSON Schema не дают семантической гарантии безопасности ответа.
- Если явно разрешить CONNECT, содержимое TLS-туннеля не проверяется и байты
  внутри туннеля не входят в `max_request_bytes`. Для фильтрации API используй
  key-injection routes и оставляй `allow_domains` пустым.
- Локальные действия инструментов контролирует OS-профиль; proxy проверяет
  сетевые запросы. Проверка аргументов tool calls в запросе к модели не является
  перехватом всех локальных системных вызовов.
- Seatbelt ограничивает процесс на хосте. Для отдельного ядра и более сильной
  границы изоляции нужна VM. Нативная установка Codex требуется для staging;
  npm-обёртку вместо исполняемого файла команда `guard codex` отклоняет.

Авторизация сверена с [официальным руководством по входу Codex](https://learn.chatgpt.com/docs/auth)
и [описанием проксирования ChatGPT credentials](https://learn.chatgpt.com/docs/enterprise/connect-to-a-gateway).
Параметры custom provider сверены с
[официальной документацией Codex](https://learn.chatgpt.com/docs/config-file/config-reference)
и [руководством по конфигурации провайдеров](https://learn.chatgpt.com/docs/config-file/config-advanced).
