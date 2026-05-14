# Changelog

## [0.3.0] — unreleased

### Added

- **MAC integrity (МКЦ) integration for Astra SE strict-mode.**
  Сессия теперь получает метку `(level, categories)`, выбранную как
  пересечение расширения `MAX_INTEGRITY` сертификата
  (OID `2.25.273824307386008814506455310913083078403`) с потолком
  рантайма от libpdp/libparsec. Новая секция `[mac]` в `config.toml`
  c полями `cert_integrity` (`required` / `optional` / `ignore`) и
  `fallback_max_integrity`.
- Feature-флаг `astra-mac` (включается на сборке для Astra SE);
  stub-бэкенд используется на не-Astra хостах и отвергает
  `cert_integrity = "required"` на этапе загрузки конфига.
- DER-кодек `IntegrityLabel` со строгим парсером и компонентным
  `strictly_below` для сравнения меток.
- Метки `pdpl-file :::iinh` накладываются на
  `/etc/pam_certauth/`, `/var/lib/pam_certauth/`,
  `/var/cache/pam_certauth/` через postinst при `astra-strictmode-control
  is-enabled`. `host_id` получает `chattr +i` после первой записи.
- Атомарная запись `sessions.json` теперь использует
  fd-based `fsetxattr` (irelax-лейбл накладывается до публикации
  имени файла, закрывает TOCTOU-окно).
- E2E-сценарии T1-T12 (`vagrant/scripts/test-mac.sh`) и
  perf-bench (`vagrant/scripts/bench-mac.sh`) для Astra VM.
- Документация: `docs/install.md`, `docs/cert-issuance.md`,
  `docs/configuration.md`, `docs/threat-model.md` пополнены секциями
  по МКЦ.

### Build

- `debian/control`: добавлен `Depends: libpdp3 (>= 3.11+ci97~)`.
  `libparsec-base3` пока остался в TODO build.rs/threat-model: на
  Astra SE 1.8.4 символ `parsec_capget` экспортируется из libpdp.so.3,
  но если downstream-сборка не сможет его разрешить — добавьте
  `libparsec-base3` в Depends и `cargo:rustc-link-lib=parsec-base`
  в `build.rs`.

## [0.2.1] — 2026-05-13

### Security

- RFC 3161 `TimeStampToken` теперь действительно проверяется, когда
  scope-policy выставляет `require_timestamp_token = true`. В 0.2.0
  флаг был silently no-op: CMS без TSA-токена принимался, что
  понижало гарантию spec §4 (row 4). Теперь `cms::verify` извлекает
  `unsignedAttrs[id-aa-timeStampToken]` каждого signer, парсит его
  как RFC 3161 `TimeStampToken` (вложенный CMS) и валидирует цепочку
  против `[tsa_trust]`-store. Отсутствие токена либо невалидная TSA
  chain → `CmsVerifyError::TimestampTokenMissing` /
  `CmsVerifyError::Verify`.
- RFC 3161 §2.4.1 `messageImprint` binding теперь enforced:
  `TSTInfo.messageImprint.hashedMessage` сравнивается с
  `hash(signature_bytes)` соответствующего `SignerInfo` (SHA-256/384/512).
  Без этой привязки скомпрометированный, но ещё не отозванный TSA
  ключ можно было использовать, чтобы выписать токен для произвольного
  контента. Несовпадение → `CmsVerifyError::Verify("TST messageImprint
  does not match signature")`. Неподдерживаемый hash-OID отклоняется.

### Fixed (post-0.2.0)

- `cms`: `signing-time` теперь сопоставляется с подписантом по
  `SubjectKeyIdentifier` (RFC 5652 v3) либо `issuerAndSerialNumber`
  (v1), а не по позиционному индексу. Раньше второй подписант в
  M-of-N мог попасть под чужой `signing-time` skew-check.
- `cms`: `argv_pattern` перенесён в подписанный
  `encapContentInfo.eContent` (см. breaking-changes ниже).
- `packaging`: `postinst` теперь включает `pam-certauth-gc.timer`
  и проставляет права `0750 root:root` на `/var/lib/pam_certauth/work_orders/`.
- `hooks`: docstring пути исправлен; `scope-match` dedup-логика
  стабилизирована; fail-closed для `host_id_hash`.
- `monitord`: запуск под non-root уже не падает на `gid_t` cast.

### Changed (breaking)

- `argv_pattern` теперь читается из подписанного
  `encapContentInfo.eContent` CMS (TOML payload), а не из
  unsigned-сайдкара `<work_order>.cms.pattern`. Сайдкар-формат был
  тампер-уязвим: любой локальный актор мог переписать паттерн без
  инвалидации подписей одобряющих. Все scope с
  `require_argv_pattern = true` требуют перевыпуска work order в
  embedded-режиме (`openssl cms -sign -nodetach`). См.
  [docs/migration.md](migration.md).
- `pam_certauth_core::cms::verify` теперь возвращает `VerifyResult`
  (`signers` + `encap_payload`) вместо `Vec<VerifiedSigner>`.
  Внутреннее API — callers внутри workspace обновлены.

## [0.2.0] — 2026-05-13

### Added

- X.509-расширение `pam_cert_scopes` объявляет список scope на
  сертификате инженера и подписанта.
- CMS-based M-of-N work order verification — новая subcommand
  `pam-certauth execute --scope=… --work-order=… -- <cmd>`.
- Новый крейт `pam_certauth_policy` с TOML-форматом
  `/etc/pam_certauth/policy.toml` (см. [docs/policy.md](policy.md)).
- Subcommands `pam-certauth policy validate|explain` и
  `pam-certauth gc --retention-days=N`.
- PAM-параметр `require_scope=...` с `scope_match=any|all` — фильтр
  по `pam_cert_scopes` на этапе логина.
- Audit-drift detection: каждое audit-событие пишет
  `policy_sha256` для отслеживания подмены `policy.toml`.
- Retention-store CMS-артефактов в
  `/var/lib/pam_certauth/work_orders/` с systemd-timer GC.
- Static hook framework с builtin `audit_critical`.

### Changed

- Бинарь `pam-certauth-monitord` переименован в `pam-certauth`
  (мульти-команда). Daemon-функция — `pam-certauth daemon`.
- IPC bump 1 → 2; payload `SessionOpen` теперь содержит
  `engineer_ski`, `engineer_cert_sha256`, `scopes`, `uid`.
  Новое сообщение `GetActiveSessionByUid` (для `execute`).
- Конфиг-схема расширена секциями `[approver_trust]`,
  `[tsa_trust]`, `[policy]`. Старые конфиги парсятся без правок.

### Known limitations

- RFC 3161 TSA валидация отложена; scope с
  `require_timestamp_token = true` отклоняется до phase 2.
- `argv_pattern` доставляется sidecar-файлом `<wo>.pattern`, не
  encapContent CMS (MVP-упрощение). **Закрыто в 0.2.1** — паттерн
  перенесён внутрь подписанного CMS.
- Подписывание `policy.toml` не реализовано; защита —
  root-containment + audit drift через `policy_sha256`.

### Migration

См. [docs/migration.md](migration.md).

## [0.1.1] — 2026-05-06

- Cert-binding extensions take precedence over the legacy
  `[[user_mapping]]` TOML list. `pam_cert_user_binding` /
  `pam_cert_host_binding` are the sole source of authorisation when
  present; `[[user_mapping]]` is consulted only for certificates
  without `pam_cert_user_binding`.
- PAM cdylib syslog backend wired into the `tracing` subscriber:
  every `error!` / `warn!` emitted from `libpam_certauth.so` lands
  in `/var/log/auth.log` (LOG_AUTH facility, ident `pam_certauth`,
  `pam_certauth[<pid>]:` prefix). Production diagnosis no longer
  blind.
- Three PAM-stack snippets shipped alongside the module:
  `/etc/pam.d/certauth` (2FA, default), `/etc/pam.d/certauth-optional`
  (phased rollout), `/etc/pam.d/certauth-only` (cert-only,
  lockout-strict). `integrate-pam.sh --mode=2fa|optional|cert-only`
  selects which one to wire in. The deprecated `--strict` /
  `--optional` flags still work as aliases.
- SysV init script (`/etc/init.d/pam-certauth`) shipped for
  hosts without systemd; adds `lsb-base` dependency to the `.deb`.
- Manpage `pam-certauth(8)` shipped.
- Docs: USBGuard interop, Astra ЗПС (DIGSIG) caveat, USB-lockout
  pre-deploy checklist, full `on_usb_removed` mode reference.

## [0.1.0] — 2026-05-05

Initial public release.

- PAM module for X.509 certificate authentication on Astra Linux SE 1.7+.
- USB token support: PKCS#11 (Rutoken/JaCarta/ESMART), PKCS#12 file.
- GOST cryptography (Р 34.10-2012, Р 34.11-2012) via openssl + gost-engine.
- Cert-driven authorisation: per-cert host_binding and user_binding X.509
  v3 extensions; no central ACL.
- Host-removal monitor daemon (pam-certauth) with udev + logind
  integration: lock/logout/shutdown on USB unplug.
- Configurable hook execution (pre_auth/post_auth_success/session_open/
  session_close) via fork+execve with full sandboxing.
- Debian package for Astra Linux SE.
