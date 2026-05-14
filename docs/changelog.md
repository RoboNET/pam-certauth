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

### Removed

- Откат 0.2.x-набора `pam_cert_scopes` / CMS M-of-N work-order /
  approver-EKU / external policy TOML / `pam-certauth execute|policy|gc`.
  Бинарь оставляет только `pam-certauth daemon`. IPC v2 retains
  `engineer_ski` + `engineer_cert_sha256` (МКЦ-audit), `scopes`
  убран. Подробности см. в плане
  `docs/superpowers/plans/2026-05-14-strip-scopes-mofn.md`.

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
