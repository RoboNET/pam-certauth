# `pam-certauth-execute`

Отдельный root-binary (0.2.4+; до этого был subcommand
`pam-certauth execute`) для запуска привилегированной операции
под защитой work order (M-of-N подписей). Запускается через sudo
от оператора, который уже прошёл PAM-аутентификацию с расширением
`pam_cert_scopes` и держит активную сессию (зарегистрированную в
monitord). Binary вынесен в отдельную crate
`pam_certauth_execute`, чтобы поверхность зависимостей
sudo target была минимальной — без zbus / udev / tokio-multi-thread.

## Synopsis

```text
pam-certauth-execute --scope=<name> --work-order=<path> [--retention-dir=DIR] \
                     -- <command> [args...]
```

Пример:

```bash
sudo pam-certauth-execute \
    --scope=bios.flash \
    --work-order=/tmp/wo.cms \
    -- flashrom -w /opt/fw/fw_v2.3.bin
```

## Algorithm (упрощённо)

1. `clap` парсит CLI.
2. Загружается `config.toml` и `policy.toml` (`policy_sha256` пишется в audit).
3. IPC → `GetActiveSessionByUid(uid)` к monitord. Если нет активной сессии — отказ.
4. Открыть `work-order` с `O_NOFOLLOW`; прочитать в буфер; пересчитать SHA-256 до и после (TOCTOU-guard).
5. CMS verify через `[approver_trust]`; собрать список SKI подписантов.
6. Проверить scope: `engineer_scopes` (из IPC) должен содержать `--scope`, и **каждый** подписант должен иметь этот scope в `pam_cert_scopes`.
7. Применить `policy.rule_for(scope)` — `m_of_n`, `forbid_self_approval`, `require_argv_pattern`, `require_timestamp_token`.
8. Canonicalize argv: запрет NUL/control bytes, запрет литерала `--` среди args.
9. Если `require_argv_pattern` — извлечь `argv_pattern` из **signed** `encapContentInfo.eContent` CMS (TOML payload), скомпилировать как glob, match'нуть полный canonical argv. Detached CMS отклоняется.
10. Audit-событие `pam_certauth.execute.start` (NDJSON в journald).
11. Запустить `pre_hooks` (статический enum).
12. `fork()` + setpgid → exec child под root.
13. Параллельно: forwarder сигналов (`SIGINT/TERM/HUP/QUIT/USR1/USR2/TSTP/CONT/WINCH` → pgrp).
14. Watchdog: если задан `timeout_seconds` — после таймаута SIGTERM, +5s SIGKILL, exit `124`.
15. `waitpid()`, exit code → собственный exit.
16. Audit-событие `pam_certauth.execute.done` с `exit_code`, `duration_ms`.
17. `post_hooks` (включая `audit_critical` — escalation на event-kind).
18. Сохранить CMS в retention-dir (`/var/lib/pam_certauth/work_orders/<sha256>.cms`).

## Exit codes

| Код           | Значение                                                           |
|---------------|--------------------------------------------------------------------|
| `0`           | Команда завершилась успешно (child exit 0).                        |
| `1`–`123`     | Reserved; child exit code (если совпал).                           |
| `124`         | Watchdog timeout (SIGTERM → 5s → SIGKILL).                         |
| `126`         | `fork`/`exec` не удался (бинарь не найден, ENOEXEC и т. п.).       |
| `<child>`     | Иной child exit code либо `128+signal`, если завершён сигналом.    |
| `2`           | Отказ политики, валидации CMS, отсутствует активная сессия и т. п. |

Источник: [`crates/pam_certauth_cli/src/execute/mod.rs`](../crates/pam_certauth_cli/src/execute/mod.rs)
константы `EXIT_DENIED`, `EXIT_SPAWN_FAILED`, и
`crates/pam_certauth_cli/src/execute/child.rs` константа
`TIMEOUT_EXIT_CODE = 124`.

## sudoers (рекомендованная конфигурация)

```text
# /etc/sudoers.d/pam-certauth-execute
Cmnd_Alias PAMCERTAUTH_EXEC = /usr/bin/pam-certauth-execute *

# Группа атм-инженеров может запускать execute без пароля
# (защита — сертификат + work order, не пароль).
%atm_engineers ALL=(root) NOPASSWD: PAMCERTAUTH_EXEC

Defaults!PAMCERTAUTH_EXEC env_reset, !requiretty, \
    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"
```

Группа `atm_engineers` обычно совпадает с группой, упомянутой в
`pam_cert_user_binding`. Сертификат уже фиксирует, какой UID может
исполнять; sudoers лишь даёт `pam-certauth-execute` запускаться от
root.

## Env scrub

`pam-certauth-execute` очищает env перед `exec` ребёнка, оставляя
whitelist:

- `PATH`, `LANG`, `LC_ALL`, `TERM`, `HOME`, `USER`, `LOGNAME`,
  `SHELL`.

Всё остальное (включая `LD_PRELOAD`, `LD_LIBRARY_PATH`, прокси-vars и
т. д.) **удаляется**.

## Signal forwarding

`execute` устанавливает себя в новую process group (`setpgid`) и
форвардит сигналы родителя на pgrp ребёнка:

| Получает родитель | Действие                              |
|-------------------|---------------------------------------|
| `SIGINT`          | → `kill(-pgrp, SIGINT)`               |
| `SIGTERM`         | → `kill(-pgrp, SIGTERM)`              |
| `SIGHUP`          | → `kill(-pgrp, SIGHUP)`               |
| `SIGQUIT`         | → `kill(-pgrp, SIGQUIT)`              |
| `SIGUSR1`/`USR2`  | → форвард                             |
| `SIGTSTP`/`CONT`  | → форвард (Ctrl-Z / fg)               |
| `SIGWINCH`        | → форвард (изменение размера терминала)|

Источник: [`crates/pam_certauth_cli/src/execute/child.rs`](../crates/pam_certauth_cli/src/execute/child.rs).

## Timeout semantics

Если в `policy.toml` для scope задан `timeout_seconds`:

1. Watchdog-тред просыпается через `timeout_seconds` секунд.
2. Если child ещё жив — отправляется `SIGTERM` на pgrp.
3. Ждёт `5` секунд.
4. Если жив — `SIGKILL` на pgrp.
5. Возвращается exit `124`.

Audit-событие `pam_certauth.execute.timeout` пишется отдельно.

## Argv pattern (внутри signed CMS payload)

Для scope с `require_argv_pattern = true` payload CMS (encapContent)
должен быть TOML с ключом `argv_pattern`:

```toml
argv_pattern = "flashrom -w /opt/fw/fw_v*.bin"
```

`execute` склеивает canonical argv через пробел и матчит как glob.
**Литерал `--` среди args отклоняется** на этапе canonicalize, до
матча, — это mitigates argv-smuggling в sudo.

> **0.2.1 breaking change:** до 0.2.0 `argv_pattern` лежал в
> unsigned-сайдкаре `<work_order>.cms.pattern`. Этот формат больше не
> поддерживается: любой локальный актор мог переписать сайдкар без
> инвалидации подписей одобряющих. Теперь паттерн читается из
> подписанного `encapContent`. См. `migration.md`.

## Примеры

### BIOS flash (m_of_n=3, argv_pattern, critical)

```bash
# Банк собирает CMS с embedded payload (argv_pattern внутри).
cat > payload.toml <<'EOF'
argv_pattern = "flashrom -w /opt/fw/fw_v*.bin"
EOF
openssl cms -sign -in payload.toml -signer alice.pem -inkey alice.key \
    -outform DER -binary -nodetach -out wo.cms
openssl cms -resign -inform DER -in wo.cms -signer bob.pem -inkey bob.key \
    -outform DER -binary -out wo.cms
openssl cms -resign -inform DER -in wo.cms -signer carol.pem -inkey carol.key \
    -outform DER -binary -out wo.cms

# Инженер вставляет токен, логинится по PAM (получает session).
# Затем:
sudo pam-certauth-execute \
    --scope=bios.flash \
    --work-order=/run/usb/wo.cms \
    -- flashrom -w /opt/fw/fw_v2.3.bin
```

### Diagnostic (m_of_n=1, info)

```bash
openssl cms -sign -in /dev/null -signer alice.pem -inkey alice.key \
    -outform DER -binary -out diag.cms
sudo pam-certauth-execute \
    --scope=atm.diag.dump \
    --work-order=/run/usb/diag.cms \
    -- /opt/atm/diag-dump.sh
```

## См. также

- [policy.md](policy.md) — правила.
- [work-order.md](work-order.md) — как банк готовит CMS.
- [x509-extensions.md](x509-extensions.md) — `pam_cert_scopes`,
  `approver_eku`.
- [operations.md](operations.md) — retention, journald, gc-timer.
