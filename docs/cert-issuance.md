# Выпуск сертификатов: host_binding и user_binding

## Введение

Авторизация «какой пользователь на каком хосте» закодирована в двух
X.509-расширениях leaf-сертификата, которые PAM-модуль проверяет на
этапе аутентификации:

- `pam_cert_host_binding`
- `pam_cert_user_binding`

Когда оба расширения присутствуют — они и только они определяют
область действия сертификата. Список `[[user_mapping]]` в
`config.toml` остался как **legacy fallback** для сертификатов,
выпущенных без расширения `pam_cert_user_binding`; на новые выпуски
расширения должны проставляться УЦ всегда (см. `docs/threat-model.md`,
mandatory-extension policy).

Этот документ описывает синтаксис расширений и приводит готовые рецепты
для `openssl.cnf`, по которым сертификат можно выпустить штатным
`openssl x509 -req`.

## OID-таблица

| Имя расширения | Дотированный OID | ASN.1 синтаксис |
|---|---|---|
| `pam_cert_host_binding` | `2.25.183976554325829274683049824615098` | `extnValue ::= SEQUENCE OF UTF8String` |
| `pam_cert_user_binding` | `2.25.215438916728501023845629178354627` | `extnValue ::= SEQUENCE OF UTF8String` |

OID размещены в нерегистрируемой ветке `2.25.<UUID>` (RFC 4530), что
гарантирует уникальность без обращения к внешнему реестру. Эти значения
зафиксированы в коде (`pam_certauth_core::x509::oids`) и являются частью
on-the-wire X.509-контракта — менять их нельзя.

## Семантика

Каждая запись `UTF8String` в `pam_cert_host_binding` интерпретируется
так:

| Запись | Значение |
|---|---|
| `*` | разрешено на любом хосте |
| `sha256:<HEX>` | разрешено только на хосте, чей `host_id_hash` совпадает с указанным шестидесятичетырёхсимвольным lowercase-hex (case-insensitive) |
| Любая другая UTF-8 строка | строка интерпретируется как «сырое» `machine_id` и сравнение идёт через SHA-256 от строки |

В `pam_cert_user_binding` запись либо `*` (любой PAM-пользователь), либо
точное имя пользователя (case-sensitive — Linux usernames регистрозависимы).

Для авторизации сертификата на конкретном хосте/пользователе нужна
**хотя бы одна совпавшая запись** в каждом из двух расширений.

## Сценарий 1 — рабочая станция: один хост, один пользователь

Рабочее место конкретного оператора. Сертификат можно использовать
только на машине с известным `machine_id` и только для конкретного
PAM-пользователя.

```ini
# openssl.cnf — фрагмент
[ user_exts ]
basicConstraints       = critical,CA:FALSE
keyUsage               = critical,digitalSignature
extendedKeyUsage       = clientAuth
subjectAltName         = email:ivanov@example.org

# Хост: SHA-256 от machine-id операторской АРМ
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:hb_one
# Пользователь: единственное имя
2.25.215438916728501023845629178354627 = ASN1:SEQUENCE:ub_one

[ hb_one ]
e0 = UTF8String:sha256:a1b2c3d4e5f6...64charsTotal...

[ ub_one ]
e0 = UTF8String:ivanov
```

Команда выпуска:

```sh
openssl req -new -key user.key -subj "/CN=Иванов" \
    -reqexts user_exts -config openssl.cnf -out user.csr
openssl x509 -req -in user.csr -CA int.pem -CAkey int.key \
    -CAcreateserial -days 365 -sha256 \
    -extfile openssl.cnf -extensions user_exts -out user.pem
```

## Сценарий 2 — оператор банкоматов: несколько хостов, один пользователь

```ini
[ hb_three_atms ]
e0 = UTF8String:sha256:1111111111111111111111111111111111111111111111111111111111111111
e1 = UTF8String:sha256:2222222222222222222222222222222222222222222222222222222222222222
e2 = UTF8String:sha256:3333333333333333333333333333333333333333333333333333333333333333

[ ub_operator ]
e0 = UTF8String:operator
```

## Сценарий 3 — мобильный администратор: любой хост, точный пользователь

```ini
[ hb_any ]
e0 = UTF8String:*

[ ub_admin ]
e0 = UTF8String:admin
```

`*` в host_binding позволяет сертификату работать на любой машине; в
user_binding по-прежнему остаётся жёсткое ограничение на имя
пользователя.

## Проверка выпущенного сертификата

```sh
openssl x509 -in user.pem -noout -text
```

В выводе должны присутствовать обе строки с дотированными OID:

```
2.25.183976554325829274683049824615098:
    0...sha256:a1b2c3d4...
2.25.215438916728501023845629178354627:
    0...ivanov
```

## Таблица проверки

| Запись | Совпадает с… |
|---|---|
| `*` | любым хостом / любым пользователем |
| `sha256:<HEX>` | хостом, чей `host_id_hash` равен `HEX` (без учёта регистра) |
| `<raw>` (host_binding) | хостом, чей `host_id_hash` равен `sha256(raw)` |
| `<name>` (user_binding) | PAM-пользователем с точным именем `<name>` |
| Расширение отсутствует | **отказ** (`HostExtensionMissing` / `UserExtensionMissing`) |
| Расширение пустое или DER-битое | **отказ** (`*ExtensionMalformed`) |
| Записи есть, но ни одна не совпала | **отказ** (`HostNotAllowed` / `UserNotAllowed`) |

См. также [`docs/configuration.md`](configuration.md).

## Расширение `MAX_INTEGRITY` (МКЦ Astra, 0.3.0+)

`MAX_INTEGRITY` — non-critical X.509 v3-расширение, кодирующее
максимальную метку целостности `(level, categories)`, до которой
сертификат может быть допущен на хосте Astra SE с включённым
strict-mode.

OID: `2.25.273824307386008814506455310913083078403`

Структура (DER):

```asn1
IntegrityLabel ::= SEQUENCE {
    level       INTEGER (-128..127),
    categories  BIT STRING DEFAULT ''B
}
```

Семантика на сервере:

- При `open_session` PAM-модуль выбирает эффективную метку как
  `intersect(cert, runtime_caps, fallback?)`.
- `cert_integrity = "required"` → сертификат без расширения отвергается.
- `cert_integrity = "optional"` → отсутствие расширения допускается;
  если задан `[mac.fallback_max_integrity]`, применяется он.
- `cert_integrity = "ignore"` → расширение игнорируется.

См. `docs/configuration.md` §«MAC integrity» и `docs/threat-model.md`
§«Privilege-escalation via MAC label».

Готовые шаблоны openssl.cnf для тестовых сертификатов:
`tests/fixtures/leaf-{l2-c01,l1-empty,no-ext,l3,malformed,l0-fullcats}.cnf`.
Генерация — `tests/fixtures/setup-mac-fixtures.sh`.

Пример строки в `openssl.cnf` для `level=2, categories={0}`:

```ini
2.25.273824307386008814506455310913083078403 = critical,DER:30:06:02:01:02:03:02:00:01
```

DER здесь — три TLV: `SEQUENCE`, `INTEGER 2`, `BIT STRING '01'B`.

