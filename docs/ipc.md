# IPC v2 wire protocol

`pam_certauth` использует AF_UNIX socket для общения между:

- PAM cdylib (`libpam_certauth.so`) → демон (`pam-certauth`),
- CLI-subcommand `execute` → демон.

Транспорт описан в [architecture.md §10](architecture.md), здесь —
**только wire-сообщения** для протокола v2.

## Транспорт

- `AF_UNIX` SOCK_STREAM.
- Путь: `/run/pam_certauth/monitord.sock`.
- Права: `0660 root:pam-certauth`.
- Peer auth: `SO_PEERCRED`, требуется `uid == 0`.
- Кадрирование: NDJSON, `\n`-терминатор, max 64 KiB / frame.

## Версионирование

`PROTOCOL_VERSION = 2` (0.2.0).

- Первый кадр клиента — `Hello { protocol_version: 2 }`.
- Demон отвечает `HelloAck` или `Error { code: 1000 }` и закрывает
  соединение.
- Версия v1 (0.1.x) **не совместима** с v2 — payload `SessionOpen`
  расширен (см. ниже). Сервер 0.2.0 отказывает клиентам v1.

## Сообщения клиента (`ClientMessage`)

### `Hello`

```json
{"type":"hello","protocol_version":2,"agent":"libpam_certauth/0.2.0"}
```

### `SessionOpen`

```json
{
  "type": "session_open",
  "session_id": "1c5e8a90-3b6f-4a1d-9c2e-77f0b1c2d3e4",
  "pam_user": "alice",
  "pam_service": "sudo",
  "target": {"kind": "logind_session", "id": "12"},
  "usb_serial": "RUTOKEN-001",
  "host_id_hash": "ee0b...0f",
  "opened_at": 1735689600,
  "cert_cn": "Alice",
  "cert_serial": "01a2b3c4",
  "engineer_ski": "8f0e1d2c...",
  "engineer_cert_sha256": "a1b2c3...",
  "scopes": ["bios.flash", "atm.diag.dump"],
  "uid": 1001
}
```

Новые поля v2: `engineer_ski`, `engineer_cert_sha256`, `scopes`,
`uid`. Используются `pam-certauth execute` через
`GetActiveSessionByUid`.

### `SessionClose`

```json
{"type":"session_close","session_id":"...","closed_at":1735689700}
```

### `Ping`

```json
{"type":"ping"}
```

### `GetActiveSessionByUid` (новое в v2)

```json
{"type":"get_active_session_by_uid","uid":1001}
```

Используется `pam-certauth execute` сразу после `Hello`, чтобы
получить контекст активной сессии текущего оператора (его `scopes`,
`engineer_ski` и `usb_serial` для cross-check'а).

## Сообщения сервера (`ServerMessage`)

### `HelloAck`

```json
{"type":"hello_ack","server_version":"0.2.0","protocol_version":2}
```

### `Ack`

```json
{"type":"ack"}
```

### `Pong`

```json
{"type":"pong"}
```

### `ActiveSession`

Ответ на `GetActiveSessionByUid`:

```json
{
  "type": "active_session",
  "session_id": "1c5e...",
  "pam_user": "alice",
  "uid": 1001,
  "usb_serial": "RUTOKEN-001",
  "engineer_ski": "8f0e1d2c...",
  "engineer_cert_sha256": "a1b2c3...",
  "scopes": ["bios.flash", "atm.diag.dump"],
  "opened_at": 1735689600
}
```

Если нет активной сессии для этого uid → `Error { code: 1200 }`.

### `Error`

```json
{"type":"error","code":1000,"message":"protocol version mismatch"}
```

## Коды ошибок

| Код  | Имя                | Семантика                                                       |
|------|--------------------|-----------------------------------------------------------------|
| 1000 | PROTOCOL_MISMATCH  | Несовместимые версии. Соединение закрывается.                    |
| 1001 | DEVICE_GONE        | USB-устройство по `usb_serial` отсутствует.                      |
| 1003 | UNAUTHORIZED       | Peer не uid=0 (по `SO_PEERCRED`).                                |
| 1100 | BAD_REQUEST        | Невалидный кадр (нарушение схемы / overflow / NDJSON).           |
| 1200 | NO_ACTIVE_SESSION  | `GetActiveSessionByUid` — для uid нет открытой сессии.           |
| 1500 | INTERNAL           | Внутренняя ошибка демона.                                        |

## Таймауты initiator→ответ

| Сообщение             | Ожидаемый ответ              | Таймаут | Действие при timeout       |
|-----------------------|------------------------------|---------|----------------------------|
| `Hello`               | `HelloAck` / `Error`         | 2 сек   | разрыв                     |
| `SessionOpen`         | `Ack` / `Error`              | 2 сек   | по `monitor_fail_mode`     |
| `SessionClose`        | `Ack`                        | 1 сек   | log + продолжить           |
| `Ping`                | `Pong`                       | 1 сек   | log + продолжить           |
| `GetActiveSessionByUid` | `ActiveSession` / `Error`  | 2 сек   | `execute` отказывает (exit 2) |

## Version negotiation

При несовпадении протокола сервер отвечает `Error { code: 1000 }` и
закрывает соединение. Клиент должен fail-closed (cdylib → PAM_AUTH_ERR,
`execute` → exit 2).

## См. также

- [architecture.md §10](architecture.md) — описание транспорта.
- [execute.md](execute.md) — использует `GetActiveSessionByUid`.
