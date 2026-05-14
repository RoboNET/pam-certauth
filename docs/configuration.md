# Справочник конфигурации pam_certauth

Этот документ — справочник по основному конфигурационному файлу
`pam_certauth`:

- `/etc/pam_certauth/config.toml` — основная конфигурация модуля и
  демона `pam-certauth`.

Авторизация «какой пользователь на каком хосте» живёт в самом
сертификате — в X.509-расширениях `pam_cert_host_binding` и
`pam_cert_user_binding`. Когда расширение `pam_cert_user_binding`
присутствует на leaf-сертификате, оно полностью определяет, под каким
PAM-пользователем разрешено залогиниться, а массив `[[user_mapping]]`
из этого файла **игнорируется**. `[[user_mapping]]` оставлен в схеме
как legacy-fallback — он применяется только для тех сертификатов,
которые выпущены без расширения `pam_cert_user_binding`. См.
[docs/cert-issuance.md](cert-issuance.md).

Каждое поле описано в формате «тип → значение по умолчанию →
допустимые значения → влияние на поведение → security implication».
Все поля валидируются при загрузке через
`pam_certauth_core::config::ValidatedConfig::try_from`
(см. [`crates/pam_certauth_core/src/config/validated.rs`](../crates/pam_certauth_core/src/config/validated.rs)
и [`crates/pam_certauth_core/src/config/raw.rs`](../crates/pam_certauth_core/src/config/raw.rs)).
Несуществующие поля или неверные типы — ошибка загрузки → fail-closed.

> Все примеры используют тестовые данные (`alice@example.test`,
> `BANKOMAT-001`, `ca-test.example`). Никаких реальных CA, паролей
> или клиентских хостов в этом документе нет.

## Файл `/etc/pam_certauth/config.toml`

Полный поставочный пример лежит в
[`dist/config/config.toml.example`](../dist/config/config.toml.example).
Этот пример проверяется регрессионным тестом
`crates/pam_certauth_core/tests/dist_examples_parse.rs` — он гарантирует,
что пример действительно валидируется через `ValidatedConfig::try_from`.

### Глобальные параметры

| Поле                       | Тип                | Default     | Допустимые значения                                            | Влияние                                                       | Security implication                                                                 |
|----------------------------|--------------------|-------------|----------------------------------------------------------------|---------------------------------------------------------------|--------------------------------------------------------------------------------------|
| `crypto_backend`           | строка             | —           | `"openssl"`, `"pkcs11_native"`                                 | Какой бэкенд считает подписи и хеши.                          | `"openssl"` обязателен для ГОСТ через `gost-engine`.                                 |
| `mode`                     | строка             | —           | `"pkcs12"`, `"pkcs11"`                                         | Где живёт ключ пользователя.                                  | `"pkcs11"` — non-extractable ключ; `"pkcs12"` — программная защита.                  |
| `pkcs11_module`            | путь               | —           | абсолютный путь к `.so`                                        | Какой PKCS#11-модуль используется.                            | Обязателен в `mode = "pkcs11"`.                                                      |
| `pkcs11_token_label`       | строка             | `None`      | `≤ 64` байт без NUL                                            | Фильтр по `CKA_LABEL` токена.                                 | Защищает от случайного выбора чужого токена на машине.                               |
| `pkcs11_object_label`      | строка             | `None`      | `≤ 64` байт без NUL                                            | Фильтр по `CKA_LABEL` объекта (cert/privkey).                 | Аналогично, защита от выбора неправильного объекта.                                  |
| `pkcs11_max_pin_attempts`  | целое              | `3`         | `1..=5`                                                        | Сколько раз модуль предложит ввести PIN.                      | Слишком много → анти-paranoia; слишком мало → плохой UX.                             |
| `pkcs11_locking_mode`      | строка             | `"os"`      | `"os"`, `"mutex"`                                              | Стратегия блокировок PKCS#11.                                 | Зависит от поставляемого PKCS#11-модуля (см. документацию вендора).                  |
| `pkcs11_pin_prompt`        | строка             | `None`      | UTF-8                                                          | Текст приглашения PIN. По умолчанию — русское приглашение.    | Локализация UX, не безопасности.                                                     |
| `pkcs11_slot_wait_seconds` | целое              | `10`        | `0..=60`                                                       | Сколько секунд ждать вставки токена.                          | `0` — не ждать; UX vs. удобство.                                                     |
| `pkcs12_path_pattern`      | строка             | `None`      | путь с placeholder'ами                                         | Где искать `.p12` (поддерживает `${user}`).                   | Обязателен в `mode = "pkcs12"`.                                                      |
| `pkcs12_pin_prompt`        | строка             | `None`      | UTF-8                                                          | Текст приглашения для пароля `.p12`.                          | Локализация UX.                                                                      |
| `gost_engine_path`         | путь               | `None`      | абсолютный путь к `.so`                                        | Явный путь к `gost-engine`. По умолчанию — поиск по id.       | `None` — engine ищется через `OPENSSL_ENGINES`.                                      |
| `usb_wait_seconds`         | целое              | `10`        | `0..=300`                                                      | Сколько секунд ждать USB-носителя.                            | UX. На `0` — fail-fast.                                                              |
| `on_usb_removed`           | строка             | `"lock"`    | `"lock"`, `"logout"`, `"hook"`, `"shutdown"`                   | Действие при подтверждённом извлечении USB.                   | `"shutdown"` уместен для банкоматов; `"lock"` — для рабочих станций.                 |
| `usb_removed_grace_seconds`| целое              | `0`         | `0..=300`                                                      | Окно отмены: реинсерт того же серийника отменяет действие.    | Защищает от ложных срабатываний; на банкоматах ставить `0`.                          |
| `suspend_grace_seconds`    | целое              | `0`         | `0..=600`                                                      | Окно после resume, в котором USB-removal игнорируется.        | Хабы во время suspend часто шумят; `30` секунд — типовое значение.                   |
| `monitor_fail_mode`        | строка             | `"strict"`  | `"strict"`, `"permissive"`                                     | Что делать при недоступности `monitord`.                      | `"strict"` — fail-closed; `"permissive"` — терпимо к транзитным I/O ошибкам.         |

> **Авторизация (host + user) описана в самом сертификате через X.509
> v3 расширения** `pam_cert_host_binding` и `pam_cert_user_binding`.
> Этот файл содержит только trust + identity + monitor + hooks; см.
> [cert-issuance.md](cert-issuance.md) для выпуска сертификатов с
> нужными расширениями.

#### Значения `on_usb_removed`

| Значение     | Действие при подтверждённом извлечении USB                                                | Типовой сценарий                     |
|--------------|-------------------------------------------------------------------------------------------|--------------------------------------|
| `"lock"`     | `LockSession` через D-Bus к logind для **этой** сессии. Хост продолжает работать.          | Рабочая станция оператора.            |
| `"logout"`   | `TerminateSession` для **этой** сессии. Хост продолжает работать, остальные сессии целы. | Киоски, банкоматы (если хост не выключаем). |
| `"hook"`     | Запускается внешний исполняемый файл, заданный в `monitor.on_usb_removed_hook_path`.       | Сложные сценарии (audit + custom action). |
| `"shutdown"` | `PowerOff` через D-Bus к logind — выключение хоста.                                       | Банкоматы / выделенные АРМ.            |

При `"hook"` секция `[monitor]` должна содержать
`on_usb_removed_hook_path = "/абсолютный/путь"`. Валидатор отказывает
в загрузке конфига при `on_usb_removed = "hook"` без `hook_path`.

### Секция `[trust]`

| Поле                            | Тип        | Default | Допустимые значения                | Влияние                                                | Security implication                                              |
|---------------------------------|------------|---------|------------------------------------|--------------------------------------------------------|-------------------------------------------------------------------|
| `anchors`                       | список путей | —     | `≥ 1` PEM-файл                     | Корневые CA доверия.                                   | Корень доверия. Должны быть `0640 root:root`.                     |
| `intermediates`                 | список путей | `[]`  | PEM-файлы                          | Промежуточные CA (опционально).                        | Снимает нагрузку с поиска цепи.                                   |
| `max_chain_depth`               | целое      | `5`     | `1..=10`                           | Максимальная глубина X.509-цепи.                       | Анти-DoS.                                                         |
| `clock_skew_seconds`            | целое      | `60`    | `0..=600`                          | Допустимое отклонение часов при проверке `notBefore`/`notAfter`. | Слишком много — атакующий с устаревшим сертификатом.   |
| `allowed_signature_algorithms`  | список строк | `[]`  | OID или имена                      | Whitelist подписей. Пустой — без ограничения.          | Запрет SHA-1/MD5/слабых RSA. Production — обязательно.            |

Допустимые имена в `allowed_signature_algorithms` (см.
[`crates/pam_certauth_core/src/x509/mod.rs`](../crates/pam_certauth_core/src/x509/)):

- RSA: `"rsa-with-sha256"`, `"rsa-with-sha384"`, `"rsa-with-sha512"`
- ECDSA: `"ecdsa-with-sha256"`, `"ecdsa-with-sha384"`, `"ecdsa-with-sha512"`
- ГОСТ Р 34.10-2012-256: `"1.2.643.7.1.1.3.2"`
- ГОСТ Р 34.10-2012-512: `"1.2.643.7.1.1.3.3"`

### Секция `[trust.revocation]`

| Поле                       | Тип       | Default  | Допустимые значения                                       | Влияние                                                  | Security implication                                                  |
|----------------------------|-----------|----------|-----------------------------------------------------------|----------------------------------------------------------|------------------------------------------------------------------------|
| `mode`                     | строка    | `"none"` | `"none"`, `"crl"`, `"ocsp"`, `"crl_then_ocsp"`            | Какие источники отзыва используются.                     | `"none"` — отзыв не проверяется (НЕ для production).                  |
| `crl_paths`                | список путей | `[]` | PEM/DER-файлы                                             | Локальные CRL.                                           | Обязательны при `mode` содержит `crl`.                                |
| `ocsp_responder_url`       | строка    | `None`   | `http://...` или `https://...`                            | URL OCSP-ответчика.                                      | Обязателен при `mode` содержит `ocsp`.                                |
| `crl_max_age_hours`        | целое     | `0`      | `0..=720`                                                 | Максимальный возраст CRL до отказа.                      | `0` — не ограничивать; не рекомендуется.                              |
| `ocsp_timeout_seconds`     | целое     | `0`      | `0..=60`                                                  | Таймаут OCSP-запроса.                                    | `0` → системный default; рекомендуется `5..10`.                       |
| `ocsp_cache_ttl_seconds`   | целое     | `0`      | `0..=3600`                                                | TTL положительного OCSP-ответа в кэше.                   | Слишком много — отозванный сертификат продолжает работать.            |

> **Важно:** при недоступном OCSP в режиме `"ocsp"` модуль возвращает
> `PAM_AUTH_ERR` (fail-closed). Если контур офлайн, использовать
> `mode = "crl"` с регулярно обновляемым локальным CRL.

### Секция `[trust.pinning]`

| Поле                       | Тип       | Default  | Допустимые значения                | Влияние                                                | Security implication                                                  |
|----------------------------|-----------|----------|-------------------------------------|--------------------------------------------------------|------------------------------------------------------------------------|
| `enabled`                  | bool      | `false`  | `true`, `false`                    | Включает pinning по SPKI корневых CA.                   | Защита от компрометации УЦ.                                           |
| `allowed_root_spki_sha256` | список строк | `[]`  | 64-символьные lower-case hex       | Список разрешённых SPKI-хешей корней.                   | Любой корень не из списка отвергается.                                |

### Секция `[host_identity]`

| Поле                            | Тип        | Default          | Допустимые значения                                                       | Влияние                                                           | Security implication                                              |
|---------------------------------|------------|------------------|---------------------------------------------------------------------------|-------------------------------------------------------------------|--------------------------------------------------------------------|
| `sources`                       | список строк | —              | `"machine_id"`, `"dmi_board_serial"`, `"hostname"`, `"tpm_ek_pubhash"`, `"custom_command"` | Цепочка источников `host_id`. Первый непустой выигрывает.       | Чем стабильнее источник, тем сильнее host-binding.                |
| `fallback`                      | строка     | `"deny"`         | `"deny"`, `"warn"`, `"allow"`                                             | Что делать, если все источники пустые.                             | На production — только `"deny"`.                                  |
| `override`                      | строка     | `None`           | UTF-8, без перевода строк                                                 | Жёстко заданное значение `host_id` (для тестов).                  | НЕ использовать на production.                                    |
| `custom_command`                | путь       | `None`           | абсолютный путь к скрипту                                                 | Скрипт, печатающий `host_id` в stdout.                             | Скрипт исполняется от `root`. Должен быть `0750 root:root`.       |
| `custom_command_timeout_seconds`| целое      | `5`              | `1..=30`                                                                  | Таймаут на исполнение `custom_command`.                            | Анти-DoS.                                                         |

Реализация цепочки — в
[`crates/pam_certauth_core/src/host_identity/chain.rs`](../crates/pam_certauth_core/src/host_identity/chain.rs).
Поведение `fallback = "deny"` гарантирует fail-closed: если ни один
источник не дал значения, аутентификация не проходит.

### Секция `[[user_mapping]]` (legacy fallback)

> **Только для сертификатов без расширения `pam_cert_user_binding`.**
> Если на leaf-сертификате расширение `pam_cert_user_binding` присутствует,
> массив `[[user_mapping]]` **полностью игнорируется** — авторизацию
> определяет сам сертификат. На новые выпуски расширение должно
> проставляться всегда (mandatory-extension policy, см.
> [docs/threat-model.md §3.8](threat-model.md)).

Массив таблиц. Каждая запись — пара «PAM-пользователь → критерий
сертификата».

| Поле               | Тип    | Default | Допустимые значения              | Влияние                                                  | Security implication                                                |
|--------------------|--------|---------|-----------------------------------|----------------------------------------------------------|----------------------------------------------------------------------|
| `pam_user`         | строка | —       | UNIX-имя пользователя             | Какой UNIX-пользователь предъявляется PAM-стеку.         | Должен быть локальный аккаунт.                                       |
| `cert_subject_cn`  | строка | `None`  | значение `CN` из subject-DN       | Сопоставление по `CN`.                                   | Один из трёх критериев должен быть установлен.                       |
| `cert_san_email`   | строка | `None`  | RFC822-имя из SAN                  | Сопоставление по `subjectAltName`.                       | Точная строка, без regex.                                            |
| `cert_san_upn`     | строка | `None`  | UPN-имя из SAN OtherName           | Сопоставление по UPN (Microsoft AD).                     | Применимо для смешанных AD-сред.                                     |

> Ровно одно из `cert_subject_cn`/`cert_san_email`/`cert_san_upn` должно
> быть установлено в каждой записи. Невыполнение — ошибка валидации.

### Секция `[logging]`

| Поле                | Тип    | Default  | Допустимые значения                                       | Влияние                                                | Security implication                                                  |
|---------------------|--------|----------|-----------------------------------------------------------|--------------------------------------------------------|------------------------------------------------------------------------|
| `level`             | строка | —        | `"error"`, `"warn"`, `"info"`, `"debug"`, `"trace"`       | Уровень детализации журнала.                            | `"trace"` — отладка; не оставлять на production.                       |
| `syslog_facility`   | строка | —        | `"auth"`, `"authpriv"`, `"daemon"`, `"local0..7"`         | syslog-facility для журнала PAM-модуля.                | `"authpriv"` — лучшая практика для аутентификации.                     |
| `journald_priority` | bool   | `false`  | `true`, `false`                                           | Кодировать priority в journald-формате.                | Удобство, не безопасность.                                             |

> PIN-коды и пароли никогда не логируются. Полные DN сертификатов
> логируются на уровне `debug` и выше; на `info` и ниже — только CN.

### Секция `[[hooks]]`

Массив таблиц. Каждый хук — внешняя команда, исполняемая в стадии
жизненного цикла. Полная реализация — в
[`crates/pam_certauth_core/src/hooks/`](../crates/pam_certauth_core/src/hooks/).

| Поле               | Тип        | Default | Допустимые значения                                                                                  | Влияние                                                  | Security implication                                                                  |
|--------------------|------------|---------|-------------------------------------------------------------------------------------------------------|----------------------------------------------------------|----------------------------------------------------------------------------------------|
| `stage`            | строка     | —       | `"pre_auth"`, `"post_auth_success"`, `"post_auth_failure"`, `"session_open"`, `"session_close"`, `"usb_removed"` | На какой стадии жизненного цикла вызывается хук.         | Хуки исполняются с sandbox-ограничениями (см. [docs/threat-model.md](threat-model.md)). |
| `command`          | список строк | —    | `[ "/usr/bin/foo", "${pam_user}" ]`                                                                  | Аргументы. Поддерживаются placeholder'ы.                 | Argv injection невозможен — placeholder'ы подставляются как отдельные argv-элементы.   |
| `timeout_seconds`  | целое      | `10`    | `1..=60`                                                                                              | Таймаут исполнения.                                      | Хук убивается через `SIGKILL` по истечении.                                            |
| `on_failure`       | строка     | `None`  | `"deny"`, `"allow"`, `"log"`                                                                          | Что делать при ненулевом коде возврата хука.             | По умолчанию `"deny"` для `pre_auth`/`post_auth_*`; `"log"` для `usb_removed`.         |
| `run_as`           | строка     | `None`  | UNIX-имя                                                                                              | UID, под которым запускается хук.                        | По умолчанию — `root`. Снижение привилегий — лучшая практика.                          |
| `env`              | таблица    | `{}`    | строки `{ KEY = "${placeholder}" }`                                                                  | Переменные окружения, передаваемые хуку.                  | Whitelist `PATH`, `LANG`, `${pam_user}`, `${cert_cn}`, `${cert_serial}`, `${host_id}`. |

Допустимые placeholder'ы (см.
[`crates/pam_certauth_core/src/hooks/placeholder.rs`](../crates/pam_certauth_core/src/hooks/placeholder.rs)):

- `${pam_user}` — UNIX-пользователь.
- `${cert_cn}` — Common-Name сертификата.
- `${cert_serial}` — серийник сертификата (hex).
- `${host_id}` — вычисленный `host_id`.
- `${session_id}` — UUID PAM-сессии.

### Секция `[[trust_override]]`

Массив таблиц. Каждая запись — переопределение `[trust]` для
ограниченного набора `host_id`.

| Поле               | Тип        | Default | Допустимые значения        | Влияние                                                | Security implication                                                  |
|--------------------|------------|---------|-----------------------------|--------------------------------------------------------|------------------------------------------------------------------------|
| `when_host_id_in`  | список строк | —     | список `host_id`            | На каких машинах применять override.                    | Должен быть непустым.                                                  |
| `anchors`          | список путей | `[]`  | PEM-файлы                   | Какие корни доверия использовать вместо основных.       | Сужает доверие на конкретных машинах.                                  |
| `intermediates`    | список путей | `[]`  | PEM-файлы                   | Какие промежуточные использовать.                       | Аналогично.                                                            |

### Worked example: минимальная валидная конфигурация

```toml
crypto_backend = "openssl"
mode           = "pkcs12"
pkcs12_path_pattern = "/run/pam_certauth/usb/${user}.p12"

usb_wait_seconds         = 10
on_usb_removed           = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds    = 30
monitor_fail_mode        = "strict"

[trust]
anchors = ["/etc/pam_certauth/ca/bundle.pem"]

[trust.revocation]
mode = "none"

[host_identity]
sources  = ["machine_id", "hostname"]
fallback = "deny"

[[user_mapping]]
pam_user        = "alice"
cert_subject_cn = "Alice"

[logging]
level           = "info"
syslog_facility = "auth"
```

### Секция `[approver_trust]` (0.2.0)

Trust-материал для **подписантов CMS work order** (см.
[docs/work-order.md](work-order.md)). Структурно идентичен `[trust]`,
но trust-anchors разные — это разделение ролей: компрометация
инженерской CA не даёт подписывать work order'ы.

| Поле                            | Тип        | Default | Допустимые значения | Влияние                                                |
|---------------------------------|------------|---------|---------------------|--------------------------------------------------------|
| `anchors`                       | список путей | —     | `≥ 1` PEM-файл      | Корневые CA подписантов.                              |
| `intermediates`                 | список путей | `[]`  | PEM-файлы           | Промежуточные CA.                                      |
| `max_chain_depth`               | целое      | `5`     | `1..=10`            | Максимальная глубина X.509-цепи.                       |
| `clock_skew_seconds`            | целое      | `60`    | `0..=600`           | Допуск часов для `notBefore`/`notAfter`.               |
| `allowed_signature_algorithms`  | список строк | `[]`  | OID / имена         | Whitelist подписей CMS.                                |

`[approver_trust.revocation]` и `[approver_trust.pinning]`
поддерживаются с тем же форматом, что и `[trust.revocation]` /
`[trust.pinning]`.

Пример:

```toml
[approver_trust]
anchors = ["/etc/pam_certauth/ca/approver-bundle.pem"]

[approver_trust.revocation]
mode = "crl"
crl_paths = ["/etc/pam_certauth/ca/approver-crl.pem"]
crl_max_age_hours = 24
```

### Секция `[tsa_trust]` (0.2.0, deferred)

Trust-материал для RFC 3161 Time-Stamp Authority (для CMS unsigned
attribute `id-aa-timeStampToken`). Структурно идентичен `[trust]`.

> **0.2.0:** валидация TSA не реализована. Секция парсится, но не
> используется. Scope с `require_timestamp_token = true` будет
> отклонён до phase 2. Подробности — в
> [docs/threat-model.md](threat-model.md) и
> [docs/policy.md](policy.md).

### Секция `[policy]` (0.2.0)

Параметры применения policy.toml и проверки CMS.

| Поле                          | Тип    | Default       | Допустимые значения | Влияние                                                                            |
|-------------------------------|--------|---------------|---------------------|------------------------------------------------------------------------------------|
| `path`                        | путь   | —             | абсолютный путь     | Где лежит `policy.toml`. Перечитывается при каждом `execute`.                       |
| `require_approver_eku`        | bool   | `true`        | `true`/`false`      | Если `true`, каждый подписант должен содержать EKU `approver_eku`.                  |
| `signing_time_skew_seconds`   | целое  | `300`         | `0..=3600`          | Допуск часов для `signing-time` атрибута каждой `SignerInfo`.                       |
| `krl_poll_interval_seconds`   | целое  | `60`          | `5..=3600`          | Период обновления KRL/CRL для approver-trust.                                       |

Пример:

```toml
[policy]
path = "/etc/pam_certauth/policy.toml"
require_approver_eku = true
signing_time_skew_seconds = 300
krl_poll_interval_seconds = 60
```

См. [docs/policy.md](policy.md) для формата самого `policy.toml`.

### PAM-параметры `require_scope` / `scope_match` (0.2.0)

В строке PAM-модуля (например, `/etc/pam.d/sudo`):

```text
auth required pam_certauth.so \
    config=/etc/pam_certauth/config.toml \
    require_scope=bios.flash,atm.diag.dump \
    scope_match=any
```

| Параметр       | Default | Значения        | Смысл                                                              |
|----------------|---------|-----------------|--------------------------------------------------------------------|
| `require_scope`| —       | список через `,`| Минимум один (или все) из этих scope должен быть в `pam_cert_scopes`. |
| `scope_match`  | `any`   | `any` / `all`   | `any` — хотя бы один; `all` — все.                                  |

Не задан — фильтр выключен (legacy-логин по host/user-binding
работает как в 0.1.x).

## Авторизация в сертификате

Привязка сертификата к хостам и пользователям полностью описывается
двумя X.509 v3 расширениями leaf-сертификата:

- `pam_cert_host_binding` (OID `2.25.183976554325829274683049824615098`)
  — `SEQUENCE OF UTF8String`, каждая запись — либо `*`, либо
  `sha256:<HEX>`, либо «сырое» значение `machine_id` (тогда сравнение
  идёт через SHA-256 от строки).
- `pam_cert_user_binding` (OID `2.25.215438916728501023845629178354627`)
  — `SEQUENCE OF UTF8String`, каждая запись — либо `*`, либо точное
  имя PAM-пользователя.

Для авторизации сертификата на конкретном `host_id` / `pam_user`
требуется **хотя бы одна совпавшая запись в каждом** из расширений.
Отсутствие любого из расширений, повреждённое DER-кодирование или
полное отсутствие совпадений — отказ (`PAM_AUTH_ERR`).

Подробности и готовые рецепты `openssl.cnf` — в
[cert-issuance.md](cert-issuance.md).

## Типовые сценарии

### 3.1 Банкомат — оффлайн, без OCSP, USB обязателен

Свойства: машина в железной коробке, нет Интернета, ключ — на токене,
извлечение USB → немедленное завершение сессии (без grace).

```toml
crypto_backend = "openssl"
mode           = "pkcs11"
pkcs11_module  = "/usr/lib/librtpkcs11ecp.so"
pkcs11_max_pin_attempts = 3
pkcs11_slot_wait_seconds = 5

usb_wait_seconds         = 5
on_usb_removed           = "shutdown"   # банкомат — выключаемся
usb_removed_grace_seconds = 0           # без отмены
suspend_grace_seconds    = 0
monitor_fail_mode        = "strict"

[trust]
anchors = ["/etc/pam_certauth/ca/bankomat-ca.pem"]
allowed_signature_algorithms = [
    "1.2.643.7.1.1.3.2",   # ГОСТ-2012-256
]

[trust.revocation]
mode             = "crl"
crl_paths        = ["/etc/pam_certauth/crl/bankomat.crl"]
crl_max_age_hours = 72

[trust.pinning]
enabled = true
allowed_root_spki_sha256 = [
    "ee0bd4f3a3c8e21d4a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f"
]

[host_identity]
sources  = ["dmi_board_serial", "machine_id"]
fallback = "deny"

[[user_mapping]]
pam_user      = "operator"
cert_san_upn  = "operator@bankomat.example.test"

[logging]
level             = "warn"
syslog_facility   = "authpriv"
journald_priority = true
```

Обоснование выбора:

- `mode = "pkcs11"` + `librtpkcs11ecp.so`: ключ non-extractable.
- `on_usb_removed = "shutdown"`: банкомат не должен оставаться
  включённым с разлоченной сессией.
- `usb_removed_grace_seconds = 0`: на банкомате не может быть «вынул и
  передумал».
- `mode = "crl"` с `crl_max_age_hours = 72`: трое суток — компромисс
  между UX (CRL обновляется ежедневно) и безопасностью.
- `host_identity.sources = ["dmi_board_serial", ...]`: материнская
  плата привязана к корпусу, замена → новый `host_id` → требуется
  перевыпустить сертификат с новым значением в
  `pam_cert_host_binding`.
- `pinning.enabled = true`: компрометация УЦ не открывает все
  банкоматы автоматически.

### 3.2 Рабочая станция в защищённом контуре — online, OCSP, ГОСТ-токен

```toml
crypto_backend = "openssl"
mode           = "pkcs11"
pkcs11_module  = "/usr/lib/librtpkcs11ecp.so"
pkcs11_token_label = "STAFF"
pkcs11_max_pin_attempts = 3
pkcs11_slot_wait_seconds = 10

usb_wait_seconds         = 10
on_usb_removed           = "lock"
usb_removed_grace_seconds = 30
suspend_grace_seconds    = 60
monitor_fail_mode        = "strict"

[trust]
anchors = ["/etc/pam_certauth/ca/staff-ca.pem"]
intermediates = ["/etc/pam_certauth/ca/staff-int.pem"]
allowed_signature_algorithms = [
    "1.2.643.7.1.1.3.2",  # ГОСТ-2012-256
    "1.2.643.7.1.1.3.3",  # ГОСТ-2012-512
]

[trust.revocation]
mode               = "crl_then_ocsp"
crl_paths          = ["/etc/pam_certauth/crl/staff.crl"]
crl_max_age_hours  = 24
ocsp_responder_url = "http://ocsp.staff.example.test/"
ocsp_timeout_seconds = 5
ocsp_cache_ttl_seconds = 600

[host_identity]
sources  = ["machine_id", "hostname"]
fallback = "deny"

[[user_mapping]]
pam_user        = "staff"
cert_subject_cn = "Staff Operator"

[logging]
level             = "info"
syslog_facility   = "authpriv"
journald_priority = true

[[hooks]]
stage           = "post_auth_success"
command         = ["/usr/local/sbin/audit-login", "${pam_user}", "${cert_serial}"]
timeout_seconds = 5
on_failure      = "log"
run_as          = "audit"
```

Обоснование:

- `usb_removed_grace_seconds = 30`: пользователь может вытащить
  токен, чтобы что-то перевставить, и продолжить работу.
- `mode = "crl_then_ocsp"`: офлайн в случае недоступности OCSP
  по сети, но при восстановлении доступа — точная проверка.
- `[[hooks]]` для аудита: сторонняя система аудита получает событие
  «вход».

### 3.3 Тестовое окружение — `mode = "pkcs12"`, без OCSP

```toml
crypto_backend = "openssl"
mode           = "pkcs12"
pkcs12_path_pattern = "/run/pam_certauth/usb/${user}.p12"
pkcs12_pin_prompt   = "PKCS#12 password: "

usb_wait_seconds         = 5
on_usb_removed           = "lock"
usb_removed_grace_seconds = 5
suspend_grace_seconds    = 0
monitor_fail_mode        = "permissive"

[trust]
anchors = ["/etc/pam_certauth/ca/test-ca.pem"]

[trust.revocation]
mode = "none"

[host_identity]
sources  = ["hostname"]
fallback = "warn"

[[user_mapping]]
pam_user        = "alice"
cert_subject_cn = "Alice"

[logging]
level             = "debug"
syslog_facility   = "auth"
journald_priority = false
```

Обоснование:

- `mode = "pkcs12"`: чтобы не возиться с реальным токеном на тестах.
- `monitor_fail_mode = "permissive"`: monitord падает на dev-машинах
  чаще, чем на production.
- `level = "debug"`: всё видно, для отладки.
- `revocation.mode = "none"`: тесты не должны зависеть от внешних
  сервисов.

> **Эту конфигурацию нельзя использовать на production.** Маркер: в
> комментарии к файлу пишется `# TEST CONFIG — DO NOT DEPLOY`.

## Системная конфигурация (sudoers, PAM, группы)

Этот раздел описывает **обвязку на уровне ОС**, без которой
описанные выше параметры `config.toml` теряют смысл. Целевая модель
развёртывания на ATM — **нет аккаунтов с правом интерактивного
`sudo -i` / `sudo bash`**: инженер остаётся обычным UNIX-пользователем,
а единственный санкционированный путь к `root` — `pam-certauth execute`
с M-of-N CMS work order. Архитектурное обоснование и threat-model
анализ — см.
[install.md §2.7](install.md) и
[threat-model.md §1.2](threat-model.md).

### Группы и членство

Инженерские учётки обязаны принадлежать **только** служебной группе
`atm_engineers`. Любое членство в `sudo`, `wheel`, `admin` —
немедленный FAIL аудита (см. [operations.md §1.6](operations.md)).

```bash
# engineer-учётка:
sudo usermod -aG atm_engineers alice
# НЕ добавлять в sudo, wheel, admin.

# проверка инвариантов:
getent group sudo wheel admin
# → должно быть пусто или содержать только management-учётки
#   (recovery / Ansible service identity), но НЕ инженеров.
```

Проверка для конкретного инженера — `sudo -l -U alice` должна
показать **ровно одну** строку с `pam-certauth execute`.

### Файл `/etc/sudoers.d/pam-certauth`

Единственное разрешённое sudoers-правило для группы `atm_engineers`
— узкое правило на запуск `pam-certauth execute`. Никаких
`(ALL) ALL`, никаких `NOPASSWD: ALL`, никаких других команд для
этой группы.

```text
# /etc/sudoers.d/pam-certauth — поставляется пакетом, 0440 root:root
%atm_engineers ALL=(root) NOPASSWD: /usr/bin/pam-certauth execute *
```

Опционально — привязка по digest бинаря (дополнительная
целостностная защита поверх IMA/dm-verity, если sudo собран с
поддержкой `sha256:`-префикса):

```text
# с привязкой по digest бинаря (опционально):
%atm_engineers ALL=(root) NOPASSWD: sha256:<hex>... /usr/bin/pam-certauth execute *
```

Регулярный аудит на отсутствие broad-правил:

```bash
sudo grep -rE 'NOPASSWD:\s*ALL|\(ALL\)\s*ALL' /etc/sudoers /etc/sudoers.d/
# ожидание: либо пусто, либо строки, не относящиеся к atm_engineers.
```

### PAM-стек для инженерского входа

`pam_certauth` подключается в PAM-стеке точки входа, через которую
инженер логинится на ATM (обычно `/etc/pam.d/login` для локальной
консоли; `/etc/pam.d/sudo` — только если sudo-стек используется
для `pam-certauth execute`). Аутентификация — **только** через
сертификат на токене (`mode=pkcs11`); парольная строка
(`pam_unix.so`) из стека убирается.

```text
# /etc/pam.d/login (фрагмент для engineer-входа)
auth required pam_certauth.so \
    config=/etc/pam_certauth/config.toml \
    mode=pkcs11 \
    require_scope=login.shell
```

Параметр `require_scope=login.shell` обязывает leaf-сертификат
содержать scope `login.shell` в расширении `pam_cert_scopes` —
иначе PAM-стек отвергает попытку входа, даже если все остальные
проверки (host-binding, user-binding, revocation) прошли. Это
разделяет «можно войти на shell» и «можно подписать work order /
выполнить privileged команду» на уровне самого сертификата
(см. [policy.md](policy.md), [work-order.md](work-order.md)).

### GC-timer / retention

`pam-certauth-gc.timer` (см. [install.md §2.6](install.md)) — это
**системный** таймер, исполняющийся от `root` через
`systemd`. Он не зависит от sudoers-правил для `atm_engineers` и
не требует никаких дополнительных прав у инженерских учёток.
Параметры retention настраиваются в самом юните и в
`config.toml` (`[execute] retention_dir`, см.
[execute.md](execute.md)).

### Чек-лист инварианта (для аудита)

1. `getent group atm_engineers` — содержит инженеров.
2. `getent group sudo wheel admin` — НЕ содержит инженеров.
3. `/etc/sudoers.d/pam-certauth` — единственное правило для
   `atm_engineers`, форма `(root) NOPASSWD: /usr/bin/pam-certauth execute *`.
4. `grep -rE 'NOPASSWD:\s*ALL|\(ALL\)\s*ALL'` — пусто для
   `atm_engineers`.
5. `/etc/pam.d/login` (или соответствующая точка входа) — содержит
   `auth required pam_certauth.so ... mode=pkcs11 require_scope=login.shell`
   и **не** содержит `pam_unix.so` в `auth`-фазе.

См. [operations.md §1.6](operations.md) — скриптуемая версия
этой проверки.

## Дальнейшее чтение

- [docs/install.md](install.md) — пошаговая установка.
- [docs/architecture.md](architecture.md) — модель доверия и
  IPC-протокол.
- [docs/threat-model.md](threat-model.md) — каждое поле через призму
  угроз.
- [docs/operations.md](operations.md) — как менять конфиг на работающей
  машине без обрыва сессий.
