# Repository presentation settings / Настройки оформления

These values accompany the bilingual README. Repository metadata and the social preview are configured separately from committed files.

Эти значения дополняют двуязычный README. Метаданные репозитория и социальное превью настраиваются отдельно от файлов в коммите.

## About

Open the gear next to **About** on the repository homepage. / Откройте шестерёнку рядом с **About** на главной странице репозитория.

**Description (recommended English default / основной вариант EN):**

```text
SpaceAI Guard: OS sandboxing, controlled egress and content filtering for AI agent harnesses. Inspect policies, protect credentials and evaluate agent boundaries.
```

**Russian alternative / вариант RU:**

```text
SpaceAI Guard — изоляция ИИ-агентов на уровне ОС, контроль исходящего трафика и фильтрация контента. Политики доступа, подстановка API-ключей и журнал решений фильтра.
```

GitHub has one About description field; use English there, with both languages in the README. / В About одно поле описания: используйте английский вариант, обе версии доступны в README.

**Website:** `https://spaceai.ru/`

**Topics:**

```text
ai-agent-security
agent-harness
sandbox
llm-security
ai-security
egress-proxy
prompt-injection
content-filtering
go
macos
bubblewrap
seatbelt
agent-governance
spaceai
llm-agents
```

## Social preview / Превью ссылки

In **Settings → General → Social preview**, upload [social-preview.png](assets/social-preview.png). It is 1280 × 640 px and uses the supplied SpaceAI UAG logo.

В **Settings → General → Social preview** загрузите [social-preview.png](assets/social-preview.png): 1280 × 640 px, с предоставленным логотипом SpaceAI UAG.

## Presentation files / Файлы оформления

| Purpose / Назначение | File / Файл |
| --- | --- |
| English repository landing page | [README.md](../README.md) |
| Русская главная страница | [README.ru.md](../README.ru.md) |
| Technical guide / Техническое руководство | [EN](usage.md) · [RU](usage.ru.md) |
| Enterprise and partners / Компании и партнёры | [EN](enterprise.md) · [RU](enterprise.ru.md) |
| Header images / Баннеры | [EN](assets/banner-en.png) · [RU](assets/banner-ru.png) |
| Editable vector layouts / Редактируемые макеты | [EN](assets/banner-en.svg) · [RU](assets/banner-ru.svg) · [Social](assets/social-preview.svg) |
| Original logo / Исходный логотип | [spaceai-logo.png](assets/spaceai-logo.png) |

## Licensing decision / Решение о лицензии

No license has been selected by this documentation change. Before promoting the repository as open source, the owners need to choose applicable license terms and publish a `LICENSE` file. Update the README license note and contribution terms at the same time.

В рамках оформления лицензия не выбиралась. Перед продвижением репозитория как open source владельцам нужно определить условия лицензирования и опубликовать `LICENSE`. Одновременно обновите примечание в README и условия участия.

## Language maintenance / Поддержка языков

When changing a feature claim, command, platform status, limitation or CTA, update its paired EN/RU page in the same pull request. The issue forms and community files accept both languages. Never add success badges for checks that do not exist.

При изменении функций, команд, статуса платформ, ограничений или ссылок обновляйте парную EN/RU-страницу в том же pull request. Формы issues и файлы сообщества принимают оба языка. Не добавляйте бейджи успешных проверок, которых нет.
