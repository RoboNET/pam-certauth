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

## English documentation

- [README.md](../README.md) (primary, English)
