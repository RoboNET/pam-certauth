# Документация pam_certauth

Все документы — на русском языке (primary). Английская обзорная
страница доступна отдельно.

## Для администраторов

- [README.md](../README.md) — обзор проекта, быстрый старт.
- [docs/install.md](install.md) — пошаговая установка.
- [docs/configuration.md](configuration.md) — справочник по
  `config.toml`.
- [docs/cert-issuance.md](cert-issuance.md) — выпуск сертификатов с
  расширениями `pam_cert_host_binding` и `pam_cert_user_binding`.
- [docs/operations.md](operations.md) — runbook эксплуатации.
- [docs/migration.md](migration.md) — апгрейд 0.1.x → 0.2.0.

## Для scopes + M-of-N (0.2.0)

- [docs/policy.md](policy.md) — формат `policy.toml`, precedence,
  валидация.
- [docs/work-order.md](work-order.md) — как банк собирает CMS с
  N подписями (openssl-команды).
- [docs/execute.md](execute.md) — CLI `pam-certauth-execute`,
  exit-codes, sudoers, signal forwarding.
- [docs/x509-extensions.md](x509-extensions.md) — OID-таблица,
  `pam_cert_scopes`, `approver_eku`.
- [docs/ipc.md](ipc.md) — wire-протокол v2.

## Для безопасников

- [docs/threat-model.md](threat-model.md) — модель угроз с указанием
  evidence для каждого утверждения.
- [docs/architecture.md](architecture.md) — архитектура, IPC-протокол,
  fail-closed правила.

## Для разработчиков

- [docs/development.md](development.md) — гид контрибьютора.
- [docs/changelog.md](changelog.md) — история изменений.
- API-документация Rust: запустить `cargo doc --workspace --no-deps`
  локально; результат — в `target/doc/pam_certauth_core/index.html`.

## Что нового в 0.2.0

- X.509-расширение `pam_cert_scopes` + EKU `approver_eku`.
- `pam-certauth-execute` для M-of-N привилегированных операций под
  CMS work order.
- Крейт `pam_certauth_policy` и `/etc/pam_certauth/policy.toml`.
- Новые PAM-параметры `require_scope` / `scope_match`.
- Retention-store CMS-артефактов + GC timer.
- IPC bump до v2; payload `SessionOpen` расширен `scopes`, `uid`,
  `engineer_ski`, `engineer_cert_sha256`.

Подробности: [docs/changelog.md](changelog.md),
[docs/migration.md](migration.md).

## Что нового в 0.1.1

- Cert-driven авторизация: расширения `pam_cert_host_binding` /
  `pam_cert_user_binding` имеют приоритет над `[[user_mapping]]`;
  TOML-список оставлен как legacy fallback.
- Три эксплуатационных режима (`2fa` / `optional` / `cert-only`),
  переключаемых `integrate-pam.sh --mode=...`.
- syslog-backend для PAM-модуля: `tracing::error!` /
  `tracing::warn!` пишутся в `/var/log/auth.log` под `pam_certauth`.
- SysV-init скрипт `/etc/init.d/pam-certauth` — для хостов
  без systemd.
- Документированы `on_usb_removed`-режимы, USBGuard-interop и
  Astra ЗПС (DIGSIG) caveat.

## English documentation

- [README.md](../README.md) (primary, English)
