# Policy (`/etc/pam_certauth/policy.toml`)

`policy.toml` хранит правила одобрений для команд, выполняемых через
`pam-certauth execute`. Один файл — один экземпляр банкомата / АРМ.
Загружается на старте демона и при каждом вызове `execute`
(пересчитывается `sha256` и пишется в audit-событие).

Реализация: [`crates/pam_certauth_policy`](../crates/pam_certauth_policy/src/lib.rs).

## TOML-схема

```toml
# Значения по умолчанию для всех scope, у которых поле не задано.
[defaults]
m_of_n                   = 2          # u8, > 0
require_argv_pattern     = false      # требовать sidecar <work_order>.pattern
forbid_self_approval     = true       # подписавший не может быть исполнителем
require_timestamp_token  = false      # требовать RFC 3161 TSA (опт-ин)
audit_level              = "info"     # "info" | "notice" | "warning" | "critical"
pre_hooks                = []         # см. таблицу ниже
post_hooks               = []
timeout_seconds          = 600        # SIGTERM, +5s → SIGKILL, exit 124

# Точное совпадение scope.
[scope."bios.flash"]
m_of_n                   = 3
require_argv_pattern     = true
audit_level              = "critical"
post_hooks               = ["audit_critical"]
timeout_seconds          = 1800

# Wildcard — применяется ко всем scope с этим префиксом.
[scope."bios.*"]
m_of_n                   = 2
audit_level              = "warning"
```

### Поля `[defaults]` и `[scope."<name>"]`

| Поле                      | Тип          | Default            | Смысл |
|---------------------------|--------------|--------------------|-------|
| `m_of_n`                  | `u8`         | — (обяз.)          | Минимальное число валидных независимых подписей в CMS work order. `0` → reject. |
| `require_argv_pattern`    | `bool`       | `false`            | Если `true`, sidecar-файл `<work_order>.pattern` обязателен. |
| `forbid_self_approval`    | `bool`       | `true`             | Если `true`, ни одна подпись не должна происходить от того же SKI, что и `engineer_ski`. |
| `require_timestamp_token` | `bool`       | `false`            | Требовать RFC 3161 TSA в unsigned-attrs. **0.2.0:** валидация TSA не реализована; scope с `true` всегда отклоняется. |
| `audit_level`             | enum         | `"info"`           | Уровень audit-события (см. `operations.md`). |
| `pre_hooks`               | `[string]`   | `[]`               | Имена хуков, выполняемых до запуска команды. |
| `post_hooks`              | `[string]`   | `[]`               | Имена хуков после `wait()`. |
| `timeout_seconds`         | `u64`/null   | null               | Если задан — watchdog убивает процесс-группу. |

### Известные имена хуков

| Хук               | Когда зовётся        | Эффект |
|-------------------|----------------------|--------|
| `noop`            | pre / post           | Ничего. Для тестов. |
| `audit_critical`  | post                 | Эскалирует audit-уровень события до `critical`, ярлык `pam_certauth.execute.critical`. |

Любое имя, не входящее в этот список, — ошибка валидации.

## Precedence (порядок разрешения scope)

1. **Exact match** — `[scope."bios.flash"]` имеет приоритет.
2. **Wildcard match** — `[scope."bios.*"]` совпадает с `bios.flash`, `bios.erase` и т. д. При нескольких совпадающих wildcards побеждает **самый длинный префикс** (наиболее специфичный).
3. **`[defaults]`** — если ничего не нашлось.

Пример: для scope `bios.flash` при наличии всех трёх блоков победит
`[scope."bios.flash"]`. Для `bios.erase` — `[scope."bios.*"]`. Для
`net.firewall.reset` (если задан только `[scope."net.*"]`) — `net.*`.

## Merge с `[defaults]`

Конкретный scope **переопределяет только заданные поля**. Незаданные
поля наследуются из `[defaults]`. Это полезно, чтобы держать
`audit_level = "info"` для большинства scope, переопределяя только
особые.

## Примеры

### 1. Минимальный (тест / dev)

```toml
[defaults]
m_of_n = 1
forbid_self_approval = false

[scope."debug.*"]
audit_level = "info"
```

### 2. Банкомат (production)

```toml
[defaults]
m_of_n = 2
forbid_self_approval = true
audit_level = "notice"
timeout_seconds = 300

[scope."atm.cassette.replenish"]
m_of_n = 2
require_argv_pattern = true
audit_level = "warning"

[scope."atm.diag.*"]
m_of_n = 1            # diag — менее критичный
audit_level = "info"

[scope."bios.flash"]
m_of_n = 3
require_argv_pattern = true
audit_level = "critical"
post_hooks = ["audit_critical"]
timeout_seconds = 1800
```

### 3. Embedded-устройство (один scope)

```toml
[defaults]
m_of_n = 2
forbid_self_approval = true

[scope."device.fw.update"]
m_of_n = 2
require_argv_pattern = true
audit_level = "critical"
post_hooks = ["audit_critical"]
```

## Валидация

```bash
# Проверка синтаксиса и правил.
sudo pam-certauth policy validate --path=/etc/pam_certauth/policy.toml
# exit 0  → OK
# exit 2  → ошибка (m_of_n=0, неизвестный хук, синтаксис TOML…)
```

Падает на:

- `m_of_n = 0` в любом scope;
- scope без `m_of_n` и без `[defaults].m_of_n`;
- ссылка на неизвестный хук в `pre_hooks` / `post_hooks`;
- невалидный TOML, неизвестное поле.

## Инспекция

```bash
# Какое правило применится для конкретного scope?
sudo pam-certauth policy explain --scope=bios.flash
# выведет финальный merged ScopeRule
```

Полезно при отладке wildcard-precedence.

## Audit-drift detection

В каждое audit-событие `pam-certauth execute` пишет `policy_sha256` —
SHA-256 файла на момент чтения. Любая модификация `policy.toml`
гарантированно меняет хеш, что видно в journald. См.
`operations.md`.

## См. также

- [work-order.md](work-order.md) — как банк готовит CMS.
- [execute.md](execute.md) — CLI и sudoers.
- [x509-extensions.md](x509-extensions.md) — `pam_cert_scopes` и
  `approver_eku`.
- [configuration.md](configuration.md) — секция `[policy]` в
  `config.toml` указывает путь к policy.toml.
