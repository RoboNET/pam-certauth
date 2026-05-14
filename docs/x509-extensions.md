# X.509-расширения pam_certauth

Этот документ перечисляет все project-private X.509 v3-расширения,
которые `pam_certauth` парсит, проверяет и использует для авторизации.

Все OID выделены в RFC 4530 unregistered arc `2.25.<UUID>` и зашиты
в [`crates/pam_certauth_core/src/x509/oids.rs`](../crates/pam_certauth_core/src/x509/oids.rs).
**Менять их нельзя** — это on-the-wire-контракт.

## Таблица OID

| Имя расширения / EKU      | OID                                                  | Где встречается                          |
|---------------------------|------------------------------------------------------|------------------------------------------|
| `pam_cert_host_binding`   | `2.25.183976554325829274683049824615098`              | leaf-сертификат инженера                 |
| `pam_cert_user_binding`   | `2.25.215438916728501023845629178354627`              | leaf-сертификат инженера                 |
| `pam_cert_scopes`         | `2.25.148783702439522084104654664555598657967`        | leaf-сертификат инженера и подписанта    |
| `approver_eku`            | `2.25.164448633110302675590304402232871779284`        | EKU в leaf-сертификате подписанта        |
| `id-kp-clientAuth`        | `1.3.6.1.5.5.7.3.2`                                   | EKU: PAM/IPC auth для инженерского leaf и подписанта |
| `id-kp-emailProtection`   | `1.3.6.1.5.5.7.3.4`                                   | **Обязателен** в EKU подписанта (требование OpenSSL `CMS_verify`) |

## `pam_cert_host_binding` (0.1.0+)

ASN.1:

```asn1
PamCertHostBinding ::= SEQUENCE OF UTF8String
```

Каждая запись — host descriptor:

- `"*"` — wildcard, любая машина;
- `"sha256:<hex>"` — hex SHA-256 от `host_id`;
- raw `machine_id` (legacy).

Семантика: leaf принимается только если `host_id_hash` локальной
машины совпадает хотя бы с одной записью.

## `pam_cert_user_binding` (0.1.0+)

ASN.1: тот же `SEQUENCE OF UTF8String`. Записи:

- `"*"` — любой PAM-пользователь;
- точное имя пользователя.

Семантика: при наличии — единственный источник user-авторизации
(перекрывает `[[user_mapping]]`).

## `pam_cert_scopes` (0.2.0, новое)

ASN.1:

```asn1
PamCertScopes ::= SEQUENCE OF UTF8String
```

Каждая запись — имя scope, валидируется regex'ом:

```text
^[a-z][a-z0-9_.-]{0,127}$
```

либо точно `"*"` (wildcard — все scope).

Используется в двух ролях:

1. **На сертификате инженера** — определяет, какие `--scope`
   разрешено передавать в `pam-certauth execute`, и какие
   `require_scope` пройдут PAM-фильтр (см. ниже).
2. **На сертификате каждого подписанта** — должен включать scope из
   текущего work order. Иначе CMS verify падает.

Семантика match'а:

- exact match → допускается;
- `*` → допускается всё;
- иначе — отказ.

> **Wildcard subtree (например `bios.*` внутри сертификата)** —
> **не поддерживается** в 0.2.0. Только точное имя или `*`. Это
> избегает неожиданностей при ротации scope.

## `approver_eku` (0.2.0, новое)

Это **Extended Key Usage**-purpose (`2.5.29.37`), а не отдельное
расширение. OID помещается в `extendedKeyUsage`:

```asn1
ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
KeyPurposeId ::= OBJECT IDENTIFIER
```

Семантика: если в `[policy]` задано `require_approver_eku = true`
(см. `configuration.md`), каждый подписант work order **обязан**
иметь этот OID среди `extendedKeyUsage`. Иначе CMS verify падает.

Это разделение ролей: инженерский cert и approver cert могут жить
под одной CA-инфраструктурой, но не могут заменять друг друга — у
инженерского `approver_eku` отсутствует.

## OpenSSL: примеры выпуска

### Инженерский leaf со scopes

`engineer.ext` для `openssl x509 -req`:

```ini
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth

# pam_cert_host_binding: sha256:<hex>
2.25.183976554325829274683049824615098 = ASN1:SEQUENCE:host_bind
[host_bind]
e1 = UTF8String:sha256:ee0bd4f3a3c8e21d4a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f

# pam_cert_user_binding: alice
2.25.215438916728501023845629178354627 = ASN1:SEQUENCE:user_bind
[user_bind]
e1 = UTF8String:alice

# pam_cert_scopes: bios.flash, atm.diag.*
2.25.148783702439522084104654664555598657967 = ASN1:SEQUENCE:scopes
[scopes]
e1 = UTF8String:bios.flash
e2 = UTF8String:atm.diag.dump
```

### Approver leaf со scopes + EKU

```ini
basicConstraints = critical, CA:FALSE
keyUsage         = critical, digitalSignature
# clientAuth + emailProtection + наш approver_eku.
# emailProtection обязателен — без него OpenSSL CMS_verify падает с
# `unsuitable certificate purpose` даже при валидной цепочке.
extendedKeyUsage = clientAuth, emailProtection, 2.25.164448633110302675590304402232871779284

2.25.148783702439522084104654664555598657967 = ASN1:SEQUENCE:scopes
[scopes]
e1 = UTF8String:bios.flash
```

> Approver-сертификат **обычно не имеет** `pam_cert_user_binding` —
> он не предназначен для PAM-логина, только для подписи CMS.

> **`emailProtection` (`1.3.6.1.5.5.7.3.4`) обязателен** в EKU
> любого approver leaf, который будет использоваться как CMS signer.
> OpenSSL `CMS_verify` неявно требует этот KeyPurposeId; без него
> подписант отвергается с `unsuitable certificate purpose`. Это
> поведение проявилось на реальном Astra Linux 1.8.4 в E2E-сценарии
> `setup-mof-n-scenario.sh`. Подробнее — `cert-issuance.md` →
> «Approver cert EKU».

## См. также

- [cert-issuance.md](cert-issuance.md) — полный workflow выпуска.
- [work-order.md](work-order.md) — как подписант использует свой cert.
- [policy.md](policy.md) — как `require_approver_eku` влияет на проверку.
