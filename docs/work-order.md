# Work Order (CMS SignedData)

«Work order» — это бинарный артефакт CMS SignedData (RFC 5652) с
**N независимыми подписями** одобряющих лиц. ATM/АРМ принимает его на
вход через `pam-certauth execute --work-order=<path>` и проверяет
перед выполнением команды.

## Модель

```
work_order.cms        — CMS SignedData (DER) с embedded TOML payload
```

Контент CMS (`encapContentInfo.eContent`) — TOML-файл, в котором (для
scope с `require_argv_pattern = true`) хранится ключ
`argv_pattern = "<glob>"`. Содержимое **signed** — любой модификации
выявит проверка подписи. Для scope без `require_argv_pattern`
допустимо как embedded (рекомендуется), так и detached (legacy
0.2.0).

> **0.2.1 breaking:** `argv_pattern` теперь читается из подписанного
> `encapContent`, а не из unsigned-сайдкара `<work_order>.cms.pattern`
> (как было в 0.2.0). Сайдкар-файлы игнорируются. Re-issue work order
> в embedded-режиме (`openssl cms -sign -nodetach`).

## Workflow банка (или удостоверяющего центра)

Ниже — bash-черновик. В реальном банке это, скорее всего,
веб-интерфейс с поэтапным сбором подписей.

### Шаг 1. Подготовить TOML payload

```bash
# Для scope с require_argv_pattern = true — обязательно argv_pattern.
cat > payload.toml <<'EOF'
argv_pattern = "flashrom -w /opt/fw/fw_v*.bin"
EOF
# Для остальных scope payload можно оставить пустым.
```

### Шаг 2. Первая подпись (Alice)

```bash
openssl cms -sign \
    -in payload.toml \
    -signer alice.pem \
    -inkey alice.key \
    -outform DER \
    -binary \
    -nodetach \
    -out partial.cms
```

> **Важно:** `-nodetach` обязателен. Без него `openssl cms -sign`
> производит detached CMS, и `argv_pattern` потеряется — для scope с
> `require_argv_pattern = true` верификация на ATM завершится denial
> с сообщением `argv_pattern missing from signed payload`.

### Шаг 3. Добавить подписи Bob и Carol

```bash
openssl cms -resign \
    -inform DER -in partial.cms \
    -signer bob.pem -inkey bob.key \
    -outform DER -binary \
    -out two_sigs.cms

openssl cms -resign \
    -inform DER -in two_sigs.cms \
    -signer carol.pem -inkey carol.key \
    -outform DER -binary \
    -out work_order.cms
```

`-resign` сохраняет embedded eContent из первого шага без
дополнительных флагов; `-content` нужен только для legacy detached
mode.

### Шаг 4. Передать оператору

```bash
scp work_order.cms atm-01:/tmp/
```

Никаких sidecar-файлов не передаётся — всё, что нужно ATM, лежит
внутри подписанного CMS.

## Required signed-attrs

Каждая `SignerInfo` обязана содержать:

| Attribute        | OID                     | Source                          |
|------------------|-------------------------|---------------------------------|
| `content-type`   | `1.2.840.113549.1.9.3`  | автоматически (`openssl cms`)   |
| `messageDigest`  | `1.2.840.113549.1.9.4`  | автоматически                   |
| `signing-time`   | `1.2.840.113549.1.9.5`  | автоматически                   |

`signing-time` валидируется против `now ± signing_time_skew_seconds`
(см. `configuration.md` → `[policy]`).

## Optional unsigned-attrs

| Attribute             | OID                          | Use case                            |
|-----------------------|------------------------------|-------------------------------------|
| `id-aa-timeStampToken`| `1.2.840.113549.1.9.16.2.14` | RFC 3161 TSA — для scope с `require_timestamp_token = true`. |

> **0.2.1+:** валидация TSA включена. Каждый `SignerInfo` для scope
> с `require_timestamp_token = true` ДОЛЖЕН нести
> `id-aa-timeStampToken` в `unsignedAttrs`. Внутренний `CMS` токена
> валидируется против `[tsa_trust]` (см. `configuration.md`). Без
> токена либо при отсутствии `[tsa_trust]` верификация падает с
> `CmsVerifyError::TimestampTokenMissing` /
> `CmsVerifyError::Verify(...)`.
>
> **0.2.1+:** жёсткая привязка
> `TSTInfo.messageImprint.hashedMessage == hash(signatureValue)`
> теперь enforced (SHA-256/384/512). Любое несовпадение → отказ с
> `CmsVerifyError::Verify("TST messageImprint does not match
> signature")`. Это закрывает риск переиспользования токена от
> скомпрометированного TSA для произвольного контента.

### Поток работы с TSA

1. После сбора всех подписей оператор извлекает байты `signatureValue`
   нужного `SignerInfo` и формирует RFC 3161 запрос:

   ```bash
   # signature_${i}.bin — байты подписи signer i, извлечённые
   # операторским скриптом (у openssl cms нет CLI-флага для этого).
   openssl ts -query -data signature_${i}.bin -sha256 -cert -out tsq.bin
   curl -H "Content-Type: application/timestamp-query" \
        --data-binary @tsq.bin https://tsa.example.com/ -o tsr.bin
   ```

2. `tsr.bin` — это `TimeStampToken` (вложенный CMS `SignedData` с
   `TSTInfo`). Он прикрепляется к `SignerInfo` подписи `i` как
   `unsignedAttr` с OID `1.2.840.113549.1.9.16.2.14`. У `openssl cms`
   нет CLI-команды для этой операции — требуется операторский скрипт
   (FFI к `CMS_unsigned_add1_attr_by_OBJ` либо прямая ASN.1 re-emit).

3. В `config.toml` банк регистрирует TSA как trust anchor:

   ```toml
   [tsa_trust]
   anchors = ["/etc/pam_certauth/tsa/tsa-ca.pem"]
   ```

4. На ATM `cms::verify` парсит `unsignedAttrs`, находит токен,
   валидирует TSA-цепочку.

## Validation matrix (что проверяет ATM)

| Проверка                                                                   | Источник                            |
|---------------------------------------------------------------------------|-------------------------------------|
| Структура CMS парсится                                                     | OpenSSL CMS                         |
| `SignerInfo.count >= rule.m_of_n`                                          | `policy.toml`                       |
| Каждый сертификат подписанта валиден против `[approver_trust]`             | `config.toml`                       |
| Каждый сертификат содержит EKU `approver_eku` (если `require_approver_eku`)| `[policy]` в `config.toml`          |
| Каждый сертификат содержит расширение `pam_cert_scopes` со scope          | `x509-extensions.md`                |
| `signing-time` в пределах `now ± signing_time_skew_seconds`                | `[policy]`                          |
| KRL/CRL/OCSP для каждого подписанта — не отозван                           | `[approver_trust.revocation]`       |
| Все SKI подписантов уникальны (нет дублей)                                 | hardcoded                           |
| Если `forbid_self_approval = true` → ни один SKI не равен `engineer_ski`   | `policy.toml` + IPC GetActiveSession |
| Если `require_argv_pattern = true` → CMS embedded и payload содержит `argv_pattern`  | `policy.toml`                       |
| Если `require_timestamp_token = true` → каждый `SignerInfo` содержит валидный RFC 3161 токен против `[tsa_trust]` | `policy.toml` + `[tsa_trust]` |
| `argv` соответствует `argv_pattern` (glob)                                 | execute.rs                          |
| Retention: после успешной валидации CMS сохраняется на 90 дней             | `gc_cmd`                            |

## Retention

После любого `execute` (allow / deny / error) ATM сохраняет копию CMS
в `/var/lib/pam_certauth/work_orders/<sha256>.cms`. Сборка мусора —
по `pam-certauth gc --retention-days=90` (триггер — systemd-timer,
см. `operations.md`).

## Инспекция

```bash
openssl cms -inform DER -in work_order.cms -cmsout -print | less
# Embedded режим — payload берётся изнутри CMS.
openssl cms -inform DER -in work_order.cms -verify \
    -CAfile approver_ca.pem -binary
```

## См. также

- [policy.md](policy.md) — какие правила применяются к CMS.
- [execute.md](execute.md) — как ATM принимает work order.
- [x509-extensions.md](x509-extensions.md) — формат сертификатов
  подписантов.
