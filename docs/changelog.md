# Changelog

## [0.3.7] — 2026-04-04

### Critical

- **`[mac].runtime` runtime-переключатель Parsec backend.** Новое поле
  `[mac].runtime` (`required` | `auto` | `disabled`, default `auto`)
  разводит compile-time feature `astra-mac` от runtime-выбора backend'а.
  Боевой кейс: один `.deb` (собранный с `astra-mac`) ставится на
  банкоматы с МКЦ и без — поведение управляется через `config.toml`.
  - `disabled` — гарантированный `StubBackend`, никаких `pdp_*`
    вызовов даже на сборке с `astra-mac` (фиксирует событие
    `mac_runtime_disabled` в syslog).
  - `required` — fail-closed: если `parsec_strict_mode()` ядра вернул
    не «активно», аутентификация отклоняется с событием
    `mac_runtime_required` (вместо тихой деградации).
  - `auto` *(default)* — probe ядра на старте сессии; настоящий
    `ParsecBackend` при активном МКЦ, fallback на `StubBackend` с
    одноразовым `mac_runtime_fallback` (WARN) иначе.
  - Валидация: `disabled + cert_integrity=required` и `required` без
    `astra-mac` отвергаются на старте.
  - Снимает блокер на банкомате МКЦ: `pam_parsec_mac: Can't obtain
    required data` теперь решается выставлением `runtime = "disabled"`
    + удалением `pam_parsec_mac` из стека, а не пересборкой `.deb`.

### Диагностика

- `HostIdentityResolver::probe_all()` — публичный API, возвращающий
  одно `ProbeResult` на каждый сконфигурированный источник
  (`[host_identity].sources`) без влияния на политику выбора
  (`resolve()` остаётся first-working-wins). cdylib теперь на старте
  каждой auth-сессии логирует по строке INFO на источник в
  `pam_certauth.host_identity` (`probe ok` / `probe error` +
  `probe selected`). Источник истины для регистрации банкомата в
  реестре — этот лог; `sha256sum /etc/machine-id` вручную больше
  не нужен и даёт расхождение, если `[host_identity].sources`
  содержит не только `machine_id`.
- `ResolvedHostId::hash_prefix()` — первые 8 hex символов sha256 для
  on-screen диагностик. Сообщение `host_binding` mismatch на лок-скрине
  банкомата теперь показывает короткий `host_id=a1b2c3d4 (source=…)`
  вместо нечитаемых 64 hex. Полный hash остаётся в syslog.
- fly-dm greeter baseline: в начале `pam_sm_authenticate` модуль
  отправляет `PAM_TEXT_INFO` с короткой идентификацией машины
  («Этот банкомат: host_id=… (source=…)»). `fly-dm` показывает её
  в greeter UI при `greeter-show-messages = true` в
  `/etc/X11/fly-dm/fly-dmrc` — инженер у банкомата мгновенно сверяет
  hash с реестром, не заходя в shell.

### Документация

- `configuration.md` §«MAC integrity» — новая подсекция «Семантика
  `runtime`» с матрицей `runtime × cert_integrity × astra-mac`,
  таблица полей дополнена `runtime` и `warn_on_homedir_label_mismatch`.
- `install.md` §8.5 переписан под runtime-переключатель: один и тот же
  `.deb` для трёх сценариев (МКЦ выключен / включён / смешанный парк).
  Подсекция §8.5.1 — baseline для fly-dm greeter.
- `install.md` Troubleshooting — команда `journalctl … 'host_identity:
  probe'` теперь источник истины для регистрации банкомата.

### Внутреннее

- Новые audit-события `mac_runtime_fallback` (WARN) и
  `mac_runtime_disabled` (INFO) в target `mac.audit`.
- `MacRuntimeMode` (validated layer) и `RawMacRuntimeMode`
  (raw config) — pub re-exports через `pam_certauth_core::config::validated`
  и `::config::raw`.
- `build_backend(MacRuntimeMode)` в `pam_certauth::session` —
  единственная точка решения «Parsec vs Stub», вместо двух compile-time
  ветвей.

## [0.3.6] — 2026-04-04

### Диагностика

- `host_id` логируется при каждом `resolve()` с указанием `source`,
  `raw` и полного `host_id_hash` (target `pam_certauth.host_identity`).
  Fallback на `unknown` тоже логируется. **Регистрация банкомата в
  реестре теперь по факту resolved hash из syslog**, не ручное
  вычисление `sha256(/etc/machine-id)` — устраняет drift между скриптом
  выпуска cert'а и развёрнутыми `[host_identity].sources`.
- `PAM_TEXT_INFO` на экране при `host_binding` mismatch: показывает
  `host_id_hash` этой машины + тип источника + просьбу передать
  админу. Текст дублируется в syslog (`warn`).
- `PAM_TEXT_INFO` на экране при wrong .p12 PIN (`MAC verify`): если
  cert лежит в незашифрованном SafeBag (новый issuance-скрипт), модуль
  читает его без пароля и показывает host/user, для которых cert
  выпущен — инженер сразу видит «вставлена не та флешка». Для
  legacy-формата (cert тоже зашифрован) — обычное «пароль неверный».
- Per-candidate USB-iteration логирование на уровне `info`: mount
  succeeded → discovery → envelope parsed → chain validated → final
  outcome. Был «провал тишины» 14 секунд между «trying USB candidate»
  и concluding модулем; теперь каждый шаг видим в
  `journalctl -t pam_certauth`.

### Безопасность

- Fail-closed на неверный PIN: не перебираем USB-партиции (lock-test
  `wrong_pin_does_not_fall_back_to_next_partition`). Multi-partition
  fallback остаётся ограничен pre-password failures (ASN.1 envelope),
  иначе создаётся PIN-oracle / chain-probing по сменным носителям.
- Multi-source matching по `[host_identity].sources` намеренно НЕ
  делается (weakest-link bypass: атакующий с root спуфит самый
  писабельный источник → байпасит host-binding). Это зафиксировано в
  threat-model.md §4.10.

### Документация

- `install.md` — новая секция «Сертификат не принимается на банкомате»
  (чек-лист: host_id из syslog → сверка с реестром → перевыпуск или
  чтение cert plaintext из .p12). Обновлён раздел `host_binding
  mismatch` (cert в новом формате читается без PIN).
- `install.md` §8.5 — два сценария PAM-стека (с/без МКЦ PARSEC MAC)
  с явной инструкцией где `pam_parsec_mac.so` нужен, а где он завалит
  account-фазу с `Can't obtain required data`.
- `threat-model.md` §4.10 — multi-source iteration по host_identity
  явно отмечена как НЕ выполняемая по причине weakest-link bypass.

### Внутреннее

- Новый pub helper `pam_certauth_core::pkcs12::try_extract_cert_without_pin`
  — best-effort чтение leaf-cert из PKCS#12 без пароля. Возвращает
  `None` для legacy-формата. Используется wrong-PIN диагностикой.
- Новый pub метод `FlowIo::show_info(&str)` (default no-op) — путь
  доставки `PAM_TEXT_INFO` на экран. `RealFlowIo::with_pamh()`
  привязывает live PAM-handle для cdylib; тест-фейки остаются без
  изменений.

### Deferred (планируется к 0.3.7)

- `[mac].runtime = "auto" | "required" | "disabled"` — runtime-
  переключатель Parsec backend без пересборки (сейчас compile-time
  feature `astra-mac` решает однозначно). Боевой кейс: бинарь собран
  с `astra-mac`, но на конкретной машине МКЦ-ядро выключено — нужен
  fallback на StubBackend без пересборки .deb.
- `HostIdentityResolver::probe_all()` — вернёт значения всех
  сконфигурированных источников (а не только первого работающего)
  для startup-логирования и admin-troubleshooting'а.
- `host_id_hash_prefix` (первые 8 hex) в PAM_TEXT_INFO — полный
  64-char hash на экране нечитаем.
- Baseline-строка `«Этот банкомат: source=… hash_prefix=…»` для
  fly-dm greeter (до prompt'а PIN).

## [0.3.5] — 2026-04-04

### Fixed

- USB partition iteration теперь делает fallback на следующий раздел
  при ASN.1-ошибке парсинга PKCS#12 (т.е. «файл по нашему пути есть,
  но это не P12»). Раньше такая коллизия имён — типичная для
  USB-устройств с несколькими разделами и Apple-форматированных
  носителей — мгновенно роняла auth с
  `asn1_check_tlen: wrong tag, Type=PKCS12`, не пробуя оставшиеся
  партиции.

### Security

- Fallback срабатывает ТОЛЬКО на ASN.1-fail (pre-parse БЕЗ пароля).
  Ошибки MAC verify / decrypt / chain validation (всё, что требует
  пароля или валидации сертификата) остаются fail-closed без
  перебора — не создаёт PIN-oracle и не позволяет chain-probing по
  разделам.

### Added

- `pam_certauth_core::pkcs12::validate_p12_envelope(&[u8])` —
  pure-функция, проверяющая ASN.1-конверт PKCS#12 без обращения к
  паролю. Используется в `flow.rs::authenticate_pkcs12` как граница
  между «файл на USB не P12 → пробуем следующий раздел» и «файл —
  валидный P12, но не расшифровывается → fail-closed».
- `FlowError::P12Envelope` (мапится на `PAM_AUTHINFO_UNAVAIL` (9))
  для случая «ни одна партиция не дала валидного P12-конверта».

## [0.3.3] — unreleased

### Fixed

- `pkcs12_path_pattern` теперь реально применяется при discovery
  credentials с USB-носителя. До этого параметр декларировался в
  конфиге, но игнорировался — discovery всегда искал
  `<mountpoint>/certs/user.p12`. Default остался прежним
  (`certs/user.p12`) для backwards compat. Поддержан плейсхолдер
  `${user}`, добавлена защита от path-traversal в валидаторе
  (отклоняются абсолютные пути, пустая строка, сегменты `..` и `.`).

### Changed

- Снято требование `LABEL=PAMCERT` на партиции USB-носителя.
  `pam_certauth` теперь перебирает все партиции с FS из allowlist
  (`vfat`, `exfat`, `ext4`, `ntfs`) и останавливается на первой, где
  найден `.p12`. Реальная граница доверия — расшифровка `.p12`
  паролем пользователя и валидация цепочки сертификатов; label-фильтр
  ничего не добавлял к безопасности, только UX-friction.
- Удалена ошибка `UsbError::AmbiguousPartition` (несколько партиций с
  меткой `PAMCERT`) — она теряет смысл без обязательной метки.

### Added

- Новый конфиг-параметр `max_usb_partitions` (default `8`, range
  `1..=64`) ограничивает число перебираемых партиций. Анти-DoS guard
  против атакующего с физическим доступом, который мог бы подсунуть
  устройство с огромным числом разделов и заставить модуль крутить
  бесконечный цикл mount/umount.
- Новая ошибка `UsbError::TooManyPartitions { devnode, count, limit }`
  (fail-closed при превышении лимита).

### Migration

- Конфиги 0.3.2 совместимы как есть: `max_usb_partitions` опционален,
  default `8` достаточен для всех реалистичных USB-носителей.
- Раздел `LABEL=PAMCERT` продолжает работать, но метка больше не
  обязательна — можно оставить как есть или убрать на следующем
  переоформлении флешки.

## [0.3.2] — unreleased

### Added

- Поддержка USB-флешек с partition table: если на whole-device нет FS,
  pam_certauth ищет среди разделов один с label=PAMCERT и FS из allowlist.
  Несколько подходящих разделов → отказ (fail-closed). Обратная
  совместимость: установки с FS на whole-device работают как раньше.

## [0.3.0] — 2026-02-22

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
- Атомарная запись `sessions.json` теперь использует fd-based labeling
  через `pdp_set_fd` (метка накладывается до публикации имени файла,
  закрывает TOCTOU-окно). `irelax` через fd-API ядро не принимает
  (EINVAL) — relax-семантика для `sessions.json` обеспечивается
  `iinh`-наследованием от parent dir.
- E2E-сценарии T1-T12 (`vagrant/scripts/test-mac.sh`) и
  perf-bench (`vagrant/scripts/bench-mac.sh`) для Astra VM.
- Документация: `docs/install.md`, `docs/cert-issuance.md`,
  `docs/configuration.md`, `docs/threat-model.md` пополнены секциями
  по МКЦ.

### Build

- `debian/control`: добавлен `Recommends: libpdp3 (>= 3.11+ci97~)` и
  `libparsec-base3 (>= 3.11+ci97~)` (оба runtime-dep при сборке с
  `astra-mac`).
- **Linker fix:** `parsec_capget` оказался экспортируемым из
  `libparsec-base.so`, а не `libpdp.so` — Astra CI build падал с
  `undefined symbol: parsec_capget` (verified run 25903325006,
  2026-02-22). `build.rs` теперь emits и `-lpdp`, и `-lparsec-base`;
  extern-блок с `parsec_capget` помечен `#[link(name = "parsec-base")]`.
- **Linker fix:** `getmicnam` / `freemicent_r` живут в
  `libparsec-mic.so.3`, а не в `libpdp.so` (комментарий в `build.rs`,
  утверждавший обратное, исправлен). `build.rs` / `Dockerfile` теперь
  линкуют `-lparsec-mic`.

### Fixed

- **libpdp text-codec grammar.** Кодировщик `encode_label_text`
  раньше формировал строку `"0:0:cat:flags:level"` (пять сегментов,
  пятый = линейный ilevel) — это была устаревшая интерпретация
  заголовков. Реальное strict-mode-ядро Astra 1.8.4 принимает
  четырёхсегментную грамматику `level:ilevel:cat[:flags]`.
  Кодек переписан, e2e-применение метки на `sessions.json` теперь
  отображается `pdpl-file` как
  `Уровень_0:Сетевые_сервисы:Нет:0x0!`.
- **`pdp_set_fd` + `irelax` несовместимы.** Ядро возвращает EINVAL,
  если irelax передан через fd-based API. Демон теперь вызывает
  `set_fd_label(.., irelax=false)`. Path-based `pdp_set_path`
  irelax по-прежнему принимает (используется postinst через
  `pdpl-file`).
- **`getmicnam` возвращает library-private static memory** (per
  `man getmicnam` на Astra 1.8.4), а не heap-аллоцированную структуру.
  Прежний код звал `freemicent_r` на результат и падал в
  `pam_sm_open_session` с `free(): invalid pointer` → SIGABRT.
  Указатель больше не освобождается.
- **Daemon под `User=pamcertauth` (не root)** при опциональной
  активации МКЦ. Шипованный drop-in `mac-integrity.conf.example`
  использует `PAMName=pam-certauth` + парный PAM-стек
  `dist/pam.d/pam-certauth.example` (`pam_parsec_cap.so` +
  `pam_parsec_mac.so`) для подъёма ilevel=63 и `PARSEC_CAP_CHMAC` на
  процессе демона. Ранее обсуждавшийся `execaps -c 0x8 -- ...`-обход
  не используется — `execaps` сам требует `PARSEC_CAP_CAP` у
  запускающего процесса, которой у `pamcertauth` нет.
- **Sessions registry на tmpfs.** Переехал из
  `/var/lib/pam_certauth/sessions.json` (persistent) в
  `/run/pam_certauth/sessions.json` (volatile, `RuntimeDirectory=`).
  Снимает stale-state-after-reboot foot-gun и MAC-labelling churn на
  каталоге. `daemon.lock` и кэши остаются в `/var/lib/`.

### Removed

- Откат 0.2.x-набора `pam_cert_scopes` / CMS M-of-N work-order /
  approver-EKU / external policy TOML / `pam-certauth execute|policy|gc`.
  Бинарь оставляет только `pam-certauth daemon`. IPC v2 retains
  `engineer_ski` + `engineer_cert_sha256` (МКЦ-audit), `scopes`
  убран. Подробности см. в плане
  `docs/superpowers/plans/2026-02-21-strip-scopes-mofn.md`.

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
- SysV init script (`/etc/init.d/pam-certauth`) shipped for
  hosts without systemd; adds `lsb-base` dependency to the `.deb`.
- Manpage `pam-certauth(8)` shipped.
- Docs: USBGuard interop, Astra ЗПС (DIGSIG) caveat, USB-lockout
  pre-deploy checklist, full `on_usb_removed` mode reference.

## [0.1.0] — 2026-01-17

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
