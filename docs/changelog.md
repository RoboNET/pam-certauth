# Changelog

## [0.1.1] — 2026-01-25

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
- SysV init script (`/etc/init.d/pam-certauth-monitord`) shipped for
  hosts without systemd; adds `lsb-base` dependency to the `.deb`.
- Manpage `pam-certauth-monitord(8)` shipped.
- Docs: USBGuard interop, Astra ЗПС (DIGSIG) caveat, USB-lockout
  pre-deploy checklist, full `on_usb_removed` mode reference.

## [0.1.0] — 2026-01-17

Initial public release.

- PAM module for X.509 certificate authentication on Astra Linux SE 1.7+.
- USB token support: PKCS#11 (Rutoken/JaCarta/ESMART), PKCS#12 file.
- GOST cryptography (Р 34.10-2012, Р 34.11-2012) via openssl + gost-engine.
- Cert-driven authorisation: per-cert host_binding and user_binding X.509
  v3 extensions; no central ACL.
- Host-removal monitor daemon (pam-certauth-monitord) with udev + logind
  integration: lock/logout/shutdown on USB unplug.
- Configurable hook execution (pre_auth/post_auth_success/session_open/
  session_close) via fork+execve with full sandboxing.
- Debian package for Astra Linux SE.
