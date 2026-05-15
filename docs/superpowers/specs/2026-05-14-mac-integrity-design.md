# Интеграция мандатного контроля целостности (МКЦ) Astra в pam_certauth

**Status:** Design (validated 2026-05-14)
**Target version:** pam_certauth 0.3.0
**Owner:** @michael443959

## Цель

Связать максимальный уровень НКЦ сессии с конкретным X.509-сертификатом
engineer-токена. Сертификат несёт расширение, задающее потолок целостности; при
открытии PAM-сессии pam_certauth выставляет процессу метку
`min(cert_max_integrity, user_МНКЦ)` через libparsec. Это даёт CA-управляемое
ограничение прав инженера для защищённых контуров (банкоматы, АРМ).

Не цели:
- Управление МРД (мандатной защитой конфиденциальности) — отдельный модуль parsec.
- Понижение/повышение integrity домашних каталогов (см. раздел 6).
- Replacement Astra-родного `pam_parsec_mac.so` — мы дополняем, не заменяем.

## 1. Семантика расширения

Сертификат несёт **потолок** (upper bound). Эффективная метка сессии вычисляется как:

```
effective.level      = min(cert.level, user_МНКЦ.level)
effective.categories = cert.categories ∩ user_МНКЦ.categories
```

Если `cert.categories` пустые — трактуем как "не ограничивать", т.е. пересечение
с полной маской → effective.categories = user_МНКЦ.categories.

Слово «минимальный» в исходной постановке означает «минимально достаточный для
роли», технически реализуется как upper bound. Это согласуется с паттерном
«слабее credential — слабее сессия».

**Несравнимость меток.** Метки МКЦ образуют частичный порядок: два label
могут быть несравнимы (например, `{level=2, categories=0b01}` и
`{level=2, categories=0b10}` — одинаковый level, непересекающиеся
categories). Для определения, действительно ли effective "ниже"
user_МНКЦ (а не просто несравним), используется метод
`IntegrityLabel::strictly_below(other)`:

```
strictly_below ⇔  (self.categories ⊆ other.categories)
                   ∧ ( self.level <  other.level
                       ∨ (self.level == other.level ∧ self.categories ≠ other.categories) )
```

Эта операция используется в orchestrator (см. §A) и в audit
`integrity_capped_below_user_mnkc`.

## 2. Формат X.509 extension

### 2.0 Trust boundary (VerifiedX509 newtype)

`extract_max_integrity` принимает **только** `&VerifiedX509`, не голый
`&X509`. `VerifiedX509(X509)` — приватный newtype в
`pam_certauth_core::x509`, конструктор `VerifiedX509::new` зовётся только
после успешной верификации chain/EKU/signature в основном flow. Это даёт
compile-time гарантию, что нельзя случайно прочитать MAX_INTEGRITY
extension из untrusted cert (например, leaf без подписи CA). Замапить из
`X509` без верификации можно только через `VerifiedX509::from_trusted_for_test`
(`#[cfg(test)]`, документировано «только для unit-тестов с self-signed
fixtures»).

### 2.1 OID

```
MAX_INTEGRITY_OID = 2.25.<UUID-int>
```

Arc `2.25.*` — UUID-derived OIDs (RFC 4530), не требуют IANA PEN. Тот же arc
что для `SCOPES_OID` и `APPROVER_EKU_OID` в плане
`scopes-and-m-of-n`. UUID сгенерировать при имплементации:

```bash
uuidgen | python3 -c 'import sys,uuid; print(uuid.UUID(sys.stdin.read().strip()).int)'
```

**Single-source-of-truth.** Константа хранится в одном мес—
`crates/pam_certauth_core/src/x509/oids.rs` — рядом с уже существующими
OID-константами. `openssl.cnf` шаблоны (`tests/fixtures/openssl-mac-*.cnf`)
генерируются `build.rs` / `xtask` подстановкой из той же константы; в репо
коммитятся `.cnf.in` шаблоны с плейсхолдером `@MAX_INTEGRITY_OID@`,
готовые `.cnf` — генерируются.

CI-страж против drift: pre-commit / CI шаг

```bash
! grep -RIn --exclude-dir=target -- '<MAX_OID>\|<TBD-uuid>\|2\.25\.<' . \
    --include='*.md' --include='*.rs' --include='*.cnf' --include='*.cnf.in'
```

— падает при появлении placeholder'а вне `docs/superpowers/`.

### 2.2 ASN.1 структура

```asn1
PamCertAuthMaxIntegrity ::= SEQUENCE {
    level       INTEGER (-128..127),
    categories  BIT STRING DEFAULT ''B   -- empty = "не ограничивать", до 64 бит
}
```

- `level` — **линейный уровень целостности** Astra 1.8 (`int8`,
  `-128..127`). Источник: official concepts Astra docs — линейный уровень
  целостности (`linear_ilev`, `PDP_ILINEAR_T = int8_t`) задаётся в **5-й**
  позиции `pdpl-file`-метки и отображается отрицательными значениями для
  untrusted процессов (sandbox), 0 — default, положительные — повышенный
  trust. Это НЕ тот же `level` что в МРД (`PDP_LEV_T = uint8_t` 0..255,
  конфиденциальность) — мы намеренно работаем только с integrity-осью.
- `categories` — **битовая маска неиерархических категорий целостности**,
  ширина **до 64 бит** (источник: pdp_common.h fetch 2026-05-14, `PDP_CAT_T
  = uint64_t`). Метки несравнимы если category-маски не совпадают побитово.
- Пустые `categories` означают «не ограничивать по категориям, использовать
  категории пользователя как есть».

**Bit-numbering convention (важно).** DER `BIT STRING` кодируется per X.690
§8.6: payload — массив байтов с MSB-first порядком, первый бит payload —
`bit 0` (старший разряд первого байта). Биту `n` категории соответствует
`bit n` в DER (т.е. `categories & (1<<n) != 0` ⇔ установлен n-й бит payload,
считая от MSB первого байта). Этот контракт обязателен для round-trip между
encode/decode и для DER-fallback в `openssl.cnf` (см. §2.4). Cross-encoding
test (Phase 1 Task 1.2) фиксирует это: round-trip `categories=0b11`
(bits 0,1) ⇔ `DER:03 02 00 03`. Полная маска `0xFFFFFFFFFFFFFFFF` (u64, T2)
кодируется как `DER:03 09 00 FF FF FF FF FF FF FF FF` (9 байт payload =
1 unused-bits prefix + 8 байт u64).

### 2.3 Critical flag

**Non-critical.** Critical extension заставил бы общие X.509-валидаторы
отвергать cert, если они не понимают OID; расширение специфично для
pam_certauth, остальным невидимо. Согласовано с существующими custom
extensions проекта.

### 2.4 Генерация в openssl.cnf

Основной способ — `ASN1:SEQUENCE`:

```ini
[ engineer_cert_v3 ]
# ... существующие extensions ...
2.25.<UUID> = ASN1:SEQUENCE:max_integrity

[ max_integrity ]
level      = INTEGER:2
categories = FORMAT:HEX,BITSTRING:03    # биты 0,1
```

Fallback (DER hex) для старых openssl, в которых `ASN1:SEQUENCE` барахлит:

```ini
2.25.<UUID> = DER:30:06:02:01:02:03:02:00:03
```

В `docs/cert-issuance.md` добавляется секция «MAX_INTEGRITY extension» с обоими
вариантами.

## 3. Поведение при отсутствии extension

Тернарная настройка в `policy.toml` (рядом с `require_approver_eku`, scopes
policy):

```toml
[mac]
# required — cert без extension отвергается (fail-closed).
# optional — cert без extension принимается; потолок = fallback (или unbounded).
# ignore   — extension не читается; pam_certauth не трогает НКЦ сессии.
cert_integrity = "optional"

# Применяется ТОЛЬКО при cert_integrity = "optional" + ext отсутствует.
# Пропущено → unbounded (только user МНКЦ ограничивает).
fallback_max_integrity = { level = 0, categories = "" }   # опционально
```

### Матрица поведения

| `cert_integrity` | ext present                       | ext absent                                |
|------------------|-----------------------------------|-------------------------------------------|
| `required`       | apply                             | **reject auth** (`cert_lacks_max_integrity_ext`) |
| `optional` (def) | apply                             | apply fallback (если задан) или unbounded |
| `ignore`         | not read                          | not read                                  |

Дефолт `optional` — для безопасной миграции: старые сертификаты продолжают
работать, новые получают cap. После полной ротации админ переводит в `required`.

## 4. API установки метки процесса

### 4.1 Backend

**libparsec через ручные FFI на text-API `pdpl_*` / `pdp_*`.** Реальная
shared library — **`libpdp`** (linker flag `-lpdp`). Это подтверждено
официальным demo Astra (`docs.astralinux.ru/.../szi/api/demo/label/`,
fetch 2026-05-14) — compile-команда демо: `gcc -o pdp_set_get_path
pdp_set_get_path.c -lpdp`. Backend pdp (МКЦ) — отдельная shared library
от `libparsec-mac` (МРД-confidentiality); мы линкуем только `-lpdp`.

**Backend строится на text-API**, а не на C struct layout
`parsec_mac_label_t`:

1. encode `IntegrityLabel { level, categories }` → text-форма
   `"0:0:<cat-hex>:<flags>:<linear_ilev>"` (формат `pdpl-file`-CLI,
   принимаемый `pdpl_get_from_text(3)`).
2. `pdpl_get_from_text(text)` → `*mut PDPL_T` (opaque).
3. `pdp_set_pid(0, label)` применяет метку на текущий процесс (или
   `pdp_set_fd(fd, label)` для §5.3.1). NB: `pdp_set_current` —
   **inline-обёртка** в `pdp.h` (`return pdp_set_pid(0, l);`), в `libpdp.so`
   как символ отсутствует — verified `nm -D /usr/lib/libpdp.so.3` на VM
   2026-05-14. Из Rust FFI вызываем **`pdp_set_pid(0, l)`** напрямую.
4. `pdpl_put(label)` освобождает opaque-структуру (RAII `Drop` на Rust
   newtype `Pdpl(*mut c_void)`).
5. для чтения — `pdp_get_pid(0)` / `pdp_get_lpath(path)` →
   `pdpl_get_text(label, 0)` → парсим обратно в `IntegrityLabel`,
   `free()` C-строку, `pdpl_put(label)`. Аналогично `pdp_get_current` —
   inline-обёртка над `pdp_get_pid(0)`.

Это **полностью устраняет зависимость от C struct ABI** (старый Appendix
C предполагал `#[repr(C)] parsec_mac_label_t` с угадываемым padding/alignment
— **больше не нужен**, прежняя «struct-layout blocking gate» закрыта
text-API контрактом). Сравнить с тем, как с этим API работает родная
утилита `pdpl-file` Astra — она зовёт ровно `pdpl_get_from_text` →
`pdp_set_path`.

Преимущества подхода:
- Тот же символьный путь, что у Astra-родной `pdpl-file` / `pdp-exec`.
- Никаких fork/exec в hot path PAM (мы linker-bound, не CLI-wrap).
- Корректный audit в Astra (вызов от нашего процесса).
- Текстовый API стабилен и документирован (concept-доки + headers).
- Build-time dep — пакет `libparsec-base` (или Astra-specific
  `libpdp-dev`) — изолируется feature flag `astra-mac` (раздел 7).

Прямой syscall и CLI-обёртки (`pdpl-file`, `pdp-exec`, `setpdpl`) отвергнуты:
syscall не имеет публичного API contract, CLI требует fork+exec в PAM hot path.

**Object-safety constraint.** `MacBackend` обязан оставаться object-safe
(`Box<dyn MacBackend>` используется в PAM entrypoint, см. Phase 5 Task 5.3).
Запрещены: `Self`-возврат не через `Box`, generic-методы, `impl Trait` в
сигнатурах trait-методов, `async fn`. Если в будущем потребуется generic
hot-path — оборачивать через отдельный non-object-safe sub-trait.

### 4.1.1 Доменные пользователи (NSS-resolved, FreeIPA-backed)

`get_user_mnkc(user)` под капотом зовёт `getmicnam(3)` / `getmicuid(3)` (см.
Appendix C). libparsec mic-db нативно поддерживает FreeIPA backend для МНКЦ:
domain user provisioned в FreeIPA с MIC-attribute → `getmicnam(name)`
возвращает корректный `mic_user` без какой-либо локальной записи в
`/etc/parsec/micdb`. Локальные пользователи берутся из `micdb` файла;
группы — из `/etc/parsec/micgrdb`. NSS-плагин Astra (sssd-bound) умеет
резолвить domain users прозрачно для нашего кода.

Это закрывает H4 ревью: FreeIPA-resolution — built-in feature libparsec,
никакой дополнительной интеграции не требуется.

Поведение при `getmicnam`/`getmicuid` возвращающем NULL (пользователь
неизвестен parsec):

| `cert_integrity` | Действие |
|------------------|----------|
| `required`       | fail-closed: `mac_apply_failed` reason=`user_mnkc_unknown`, PAM_SESSION_ERR |
| `optional`       | skip МКЦ: emit `mac_skipped` reason=`user_mnkc_unknown`, session продолжается |
| `ignore`         | unreachable (мы туда не входим) |

Test T8.5 (см. §8.2) фиксирует domain-user happy path и сценарий "user в
NSS, но без записи в mic db".

### 4.1.2 Открытые сессии при ротации CA

После ротации CA / отзыва сертификата pam_certauth НЕ переоценивает уже
открытые сессии — это статическая привязка cert→label на момент
`pam_sm_open_session`. Известное ограничение, дублируется в §10.

### 4.1.3 CertIdent (стандартизация audit fields)

Все audit events, относящиеся к сертификату, эмитятся с одинаковым набором
полей:

```rust
struct CertIdent {
    serial: String,       // hex, без префикса
    issuer: String,       // RFC 2253 DN
    cn: String,           // subject CN
    fingerprint: String,  // sha256 hex
}
```

Один builder `CertIdent::from(&VerifiedX509)` гарантирует один формат
во всех MAC-events (`mac_apply_failed`, `cert_lacks_max_integrity_ext`,
`cert_max_integrity_parse_failed`, `integrity_capped_below_user_mnkc`).

### 4.2 PAM hook

Установка метки происходит в **`pam_sm_open_session`** — точка совпадает с
поведением stock `pam_parsec_mac.so`. На этот момент процесс уже forked,
выставление метки распространится на будущий session leader (shell/desktop).

`pam_sm_setcred` не используется (YAGNI; при необходимости su-without-login
добавим позже под опциональный флаг).

**Label propagation via fork.** Метка процесса в Astra МКЦ наследуется
`fork(2)` и сохраняется через `exec(2)` (стандартная linux task-credentials
семантика). Поэтому установка метки в `pam_sm_open_session` (вызывается
парентом — sshd/login до `setuid`+`fork`+`exec shell`) автоматически
покрывает будущий shell и все его дочерние процессы. Это совпадает с тем,
что делает stock `pam_parsec_mac.so` — не требует дополнительных hook'ов
в `pam_sm_setcred` или `pam_sm_authenticate`.

### 4.3 Downgrade

Login/sshd на Astra имеют **`PARSEC_CAP_CHMAC` (bit 3)** в parsec
capabilities (file caps от пакета `parsec`). Этот cap разрешает менять
МКЦ-метку процессов и файлов. pam_certauth.so загружается в их адресное
пространство и наследует cap → downgrade процесса разрешён. Если cap
отсутствует — `pdp_set_pid` вернёт ненулевой rc (как правило `EPERM`),
обрабатывается через fail-closed `mac_apply_failed`.

Дополнительно при старте модуля делаем self-check через
`parsec_capget(0, &caps)` и проверяем `caps.cap_effective & (1<<3)
(PARSEC_CAP_CHMAC)`. Если бит не выставлен — emit audit warning
`mac_caps_missing` и продолжаем в degraded mode (любая попытка
`apply_session` всё равно завершится fail-closed на FFI-уровне). Бит
`PARSEC_CAP_IGNMACINT (13)` НЕ используется — мы не bypass'им integrity
check'и. `PARSEC_CAP_INHERIT_INTEGRITY (17)` относится к exec-наследованию
и нам не нужен (см. §4.2 — стандартная fork/exec семантика).

Если эффективный target превышает `user_МНКЦ` (например, ошибка в выпуске
cert), libparsec вернёт ненулевой код → fail-closed:

```
event=mac_apply_failed
target_level=N target_categories=...
user_mnkc_level=M user_mnkc_categories=...
parsec_rc=-1
parsec_error="..."
pam_user=... cert_cn=...
audit_level=CRITICAL
```

PAM возвращает `PAM_SESSION_ERR`, сессия не открывается.

**Не использовать `errno` после libparsec.** Только `int` return code
определён контрактом библиотеки; `errno` после её вызова не гарантируется.
Соответственно branch `if errno == libc::EPERM { Err(Eperm) }` в `ffi.rs`
заменён на trust только `rc`: любое `rc != 0` → `MacError::Parsec { rc }`.
Различия EPERM/EINVAL/... декодирует caller (orchestrator), если они
описаны в Appendix C.

**Почему `pdp_set_pid`, а не `pdp_set_pid_safe`.** `pdp_set_pid_safe`
отвергнут как primary API: внутренняя capability-recheck per-call (он
проверяет PARSEC_CAP_CHMAC на каждом вызове) дублирует наш self-check
`parsec_capget` при инициализации модуля (см. §4.1.2 / §C.5), увеличивая
overhead в hot path PAM без дополнительной защиты в нашей модели угроз
(модуль long-running, capabilities не меняются динамически). Если
`pdp_set_pid` показывает кросс-версионную хрупкость на CI (Astra 1.7 vs
1.8) — переключаемся на `_safe` как fallback. Phase 4 Task 4.0 содержит
probe-вызов `pdp_set_pid_safe(0, l)` без CHMAC cap (через
`setpriv --inh-caps=-CHMAC`), чтобы документировать поведение rc и
зафиксировать fallback path в Appendix C.

### 4.4 Capabilities

- File caps на сам `pam_certauth.so` **не выставляются** (caps на .so не
  работают).
- File caps на login/sshd/sudo/sddm **уже выставлены** пакетом `parsec`; мы
  наследуем.
- В `docs/install.md` секция «Prerequisites» документирует требование пакета
  `parsec-base` и проверку `getcap /usr/sbin/sshd`.
- Если caps отсутствуют (parsec не установлен) — libparsec вернёт EPERM →
  fail-closed с понятным audit-сообщением.

monitord не управляет НКЦ сессий, ему МКЦ-API не нужно. Единственная точка где
он трогает parsec — пометка собственного listening socket (раздел 5).

### 4.5 Runtime-предпосылки на Astra SE 1.8.4 (verified 2026-05-15)

Чтобы МКЦ-метка действительно применилась к `sessions.json` через
`pdp_set_fd`, на хосте должно быть выполнено всё нижеперечисленное.
Проверено e2e в strict-mode VM (Astra Linux SE 1.8.4):

1. **Strict-mode ядра.** `parsec.strict_mode=1` в kernel cmdline,
   проверяется через
   `cat /sys/module/parsec/parameters/strict_mode` → должно вернуть `Y`.
   Без strict-mode ядро принимает `pdp_set_fd`, но не пишет xattr на
   inode, и `pdpl-file` показывает default.

2. **PARSEC_CAP_CHMAC у daemon-процесса.** Демон не наследует caps от
   sshd/login (он long-running, запускается systemd как
   `User=pamcertauth`). Capability нужно явно выдать пользователю
   `pamcertauth` в parsec capdb:

   ```sh
   sudo /sbin/usercaps -m "+3" pamcertauth
   # = строка в /etc/parsec/capdb/<uid>:
   # pamcertauth:<linux_caps_hex>:<parsec_caps_hex_with_bit3>
   ```

   `+3` соответствует `PARSEC_CAP_CHMAC` (bit 3).

3. **Linux `CAP_MAC_ADMIN` у daemon-процесса.** systemd unit задаёт
   через `AmbientCapabilities=CAP_MAC_ADMIN` (и `CapabilityBoundingSet=`,
   включающий тот же cap). Без CAP_MAC_ADMIN ядро вернёт EPERM на
   попытке записать security.PDP xattr.

4. **`execaps`-обёртка для активации PARSEC caps в процессе демона.**
   Чтобы parsec capability из capdb фактически появилась в effective
   set процесса, `ExecStart=` юнита должен быть обёрнут в:

   ```
   ExecStart=/usr/sbin/execaps -c 0x8 -- /usr/sbin/pam-certauth-monitord ...
   ```

   `0x8 == (1<<3) == PARSEC_CAP_CHMAC`. Альтернатива — запускать демон
   через PAM-стек, в котором есть `pam_parsec` (это применяется к login
   sessions; для системных юнитов unsuitable). **Currently** production
   юнит запускает демон напрямую без execaps; чтобы развернуть МКЦ в
   проде, юнит нужно либо перевести на execaps-wrap, либо поднимать
   демон через parsec-aware login. Без этого `parsec_capget(0, &caps)`
   вернёт `cap_effective` без бита 3, self-check выдаст
   `mac_caps_missing` и весь fd-labeling провалится в fail-closed.

Пользовательская сторона:

5. **User ilevel ≥ требуемого `cert_max_integrity`.** Резолвится через
   `getmicnam(3)` из `libparsec-mic.so.3`. Назначается админом:

   ```sh
   sudo /sbin/pdpl-user --ilevel 63 <user>
   ```

   Если у пользователя ilevel ниже, чем уровень из сертификата,
   orchestrator делает `min()`-intersect и применяет именно МНКЦ
   пользователя (см. §6.4).

## 5. Файловая система

### 5.1 Карта меток

Имена флагов соответствуют реальному CLI `pdpl-file(1)` на Astra 1.8.4:
`iinh` — наследование integrity на dir; `irelax` — разрешить любой НКЦ при
создании/доступе на dir/file. Подтверждено через `man pdpl-file` на VM (см.
§5.2 синтаксис).

| Путь | Метка / флаги | Обоснование |
|------|---------------|-------------|
| `/etc/pam_certauth/` (dir + files) | `level=0`, `iinh` (= `PDPT_IINH = 0x80`) | Конфиг читается из любого НКЦ |
| `/var/lib/pam_certauth/` (dir) | `level=0`, `iinh \| irelax` (= `0x80 \| 0x20 = 0xA0`) | Новые файлы не наследуют |
| `/var/lib/pam_certauth/sessions.json` | `level=0`, **`irelax`** (= `PDPT_IRELAX = 0x20`) | Cross-level shared state; DAC `0600 root:root` |
| `/var/lib/pam_certauth/daemon.lock` | `level=0` | Стандартно |
| `/var/lib/pam_certauth/host_id` | `level=0`, `chattr +i` | Anti-tamper |
| `/run/pam_certauth/` | `level=0`, `iinh` | tmpfs, RuntimeDirectory= |
| `/run/pam_certauth/monitord.sock` | `level=0`, **`irelax`** | Cross-level connect от CLI |
| `/lib/security/pam_certauth.so` | default (`level=0`) | Загружается любым PAM stack |
| `/usr/bin/pam-certauth` | default | exec из любого user НКЦ |
| `/usr/sbin/pam-certauth-monitord` | default | systemd запускает на system default |

Никаких меток `level > 0` не выставляется — мы интегрируемся с Astra-инфрой, не
конкурируем с ней. Безопасность `sessions.json` и `monitord.sock` обеспечивается
DAC + audit, а не МКЦ — это shared system state аналогично `/var/log/wtmp`.

**Угроза `irelax + root`.** `irelax` на `sessions.json` означает: процесс
с UID 0 в любом НКЦ может писать в файл. Защита от подмены строится на
DAC (`0600 root:root`) + границе UID 0, а не на МКЦ. Если root скомпрометирован
— модель угроз pam_certauth не предусматривает защиту (см.
`docs/threat-model.md`). Документировать явно в Phase 11.

### 5.2 Postinst (debian/postinst, фрагмент)

**Синтаксис `pdpl-file` (Astra 1.8.4, проверено через `man pdpl-file` на VM):**

```
pdpl-file [OPTIONS]... [LEVEL][:INTEGRITY_CAT[:CONFIDENT_CAT[:EXTRA_FLAGS][:LINEAR_ILEV]]] FILE...
```

Дополнительные атрибуты МКЦ (`iinh`, `irelax`, `silev`, `ssi`) и МРД
(`ccnr`, `ehole`, `whole`) задаются в **4-й позиции метки**, через запятую.
Линейный уровень целостности (`-128..127`) — в **5-й позиции**.

- `-R, --recursive` — рекурсивно (НЕ `-r`! `-r` это `--reverse`).
- НЕТ `-l` и `-F`: метка задаётся позиционно одним аргументом.

Примеры из `man`:
- `pdpl-file 2:0:0:ccnr,irelax /tmp` — confidentiality=2, irelax+ccnr.
- `pdpl-file :::iinh:0 /tmp` — только iinh + linear integrity 0.
- `pdpl-file ::::-128 file.txt` — только linear integrity = -128.

Фрагмент `debian/postinst`:

```sh
#!/bin/sh
set -e

# Skip if parsec tools absent (non-Astra или базовый parsec не установлен)
if ! command -v pdpl-file >/dev/null 2>&1; then
    echo "pam-certauth: parsec tools not found, skipping MAC integrity setup"
    exit 0
fi

# Skip if strictmode disabled (exit-code based — не парсим вывод status)
if ! astra-strictmode-control is-enabled >/dev/null 2>&1; then
    echo "pam-certauth: strictmode disabled, skipping MAC integrity setup"
    exit 0
fi

# /etc/pam_certauth — iinh, level=0 (NO || true: ошибка должна провалить install)
pdpl-file :::iinh /etc/pam_certauth/
pdpl-file -R :::iinh /etc/pam_certauth/

# /var/lib/pam_certauth — iinh + sessions.json irelax
pdpl-file :::iinh /var/lib/pam_certauth/
if [ ! -e /var/lib/pam_certauth/sessions.json ]; then
    install -m 600 -o root -g root /dev/null /var/lib/pam_certauth/sessions.json
fi
pdpl-file :::irelax /var/lib/pam_certauth/sessions.json

# host_id — immutable после генерации
if [ -f /var/lib/pam_certauth/host_id ]; then
    pdpl-file 0:0 /var/lib/pam_certauth/host_id
    chattr +i /var/lib/pam_certauth/host_id 2>/dev/null || true
fi
```

`|| true` намеренно убран: маскировал реальные ошибки (бывший M3-finding).
Postinst должен валиться громко, если МКЦ-операции не прошли на машине, где
strictmode заявлен enabled. `chattr +i` оставлен с `|| true` — это
оптимизация анти-tamper, не критическая.

`/run/pam_certauth/` создаётся systemd через `RuntimeDirectory=pam_certauth` +
`tmpfiles.d` фрагмент `d /run/pam_certauth 0750 pamcertauth pamcertauth - -`.

### 5.3 Метка socket в коде daemon

В monitord перед атомарным rename `monitord.sock.tmp.$PID → monitord.sock`:

1. `bind` на `.tmp.$PID`.
2. `mac::set_file_label(path, IntegrityLabel { level: 0, categories: 0 }, flags: IRELAX)`.
3. `rename`.

### 5.3.2 Future: verify peer integrity на UDS

`pdp.h` экспортирует `PDPL_T* pdp_get_peer_label(int sockfd)` — позволяет
монитору после `accept(2)` прочитать integrity-метку peer-процесса CLI и
принять решение по policy (отвергать команды от слишком слабого peer'а).
В 0.3.0 не используется (out of scope), запланировано как Debug-уровневое
наблюдение `mac_socket_peer_label_check` (см. §9). Использование:
`pdp_get_peer_label(fd)` → `pdpl_get_text(...)` → log.

### 5.3.1 sessions.json — fd-based labeling, не path-based

**TOCTOU.** Path-based check `verify(path) → set_label(path)` уязвим:
между двумя вызовами файл могли подменить. Решение — `pdp_set_fd(fd, label)`,
сигнатура verified в pdp.h (docs.astralinux.ru/.../szi/api/headers/pdp/,
fetch 2026-05-14):

```c
int pdp_set_fd(int fd, const PDPL_T *l);
```

```rust
// Pseudocode для monitord.state::write_sessions_atomic():
let tmp = NamedTempFile::new_in("/var/lib/pam_certauth")?;  // O_CREAT|O_EXCL
let fd = tmp.as_raw_fd();
// NB: irelax=false на fd-based API. Ядро Astra 1.8.4 strict-mode
// возвращает EINVAL, если `irelax` передан через `pdp_set_fd` — флаг
// поддерживается только path-based API (`pdp_set_path`). Атрибут
// irelax наследуется через `iinh` на parent dir.
mac::set_fd_label(fd, IntegrityLabel { level: 0, categories: 0 }, /*irelax=*/false)?;
tmp.write_all(&serialized)?;
tmp.persist("/var/lib/pam_certauth/sessions.json")?;  // atomic rename
```

Этим закрывается TOCTOU: label выставлен на тот же inode, что будет
переименован, без окна между `open()` и `rename()`. Защита от ручной правки
админом остаётся через DAC + audit; parent dir (`/var/lib/pam_certauth/`)
имеет `iinh`, что гарантирует defaults для случайно созданных файлов.

**`pdp_set_fd` подтверждён в pdp.h** (см. Appendix C), → fd-based путь
реализуем напрямую через text-API: `pdpl_get_from_text("0:1:0")` →
`pdp_set_fd(fd, label)` → `pdpl_put`. Verified e2e на Astra Linux SE
1.8.4 strict-mode (2026-05-15): `pdpl-file` после persist печатает
`Уровень_0:Сетевые_сервисы:Нет:0x0!` (level=0, ilevel=1, без flags).

Compensating control при невозможности fd-labeling (если в каком-то
будущем рантайме функция вернёт `ENOSYS`): использовать
`O_NOFOLLOW | O_CLOEXEC` + parent directory с `iinh`-атрибутом — новый
inode наследует контейнерную метку и race-window сокращается до
write-to-rename. Основной защитный слой остаётся DAC `0600 root:root` +
parent dir `iinh`. Документировано в `docs/threat-model.md` как принятый
риск UID-0-trust.

## 6. Домашние каталоги

Подход — **document-only + audit warning** (вариант A). Кодовых изменений
mount/mkdir не делаем.

### Обоснование

- Primary use case (ATM): engineer не получает интерактивный shell, $HOME
  нерелевантен.
- Domain use case (АРМ): homedir уже создаёт stock `pam_mkhomedir.so` +
  `pam_parsec_mac.so` с правильной меткой по user МНКЦ.
- Реальная проблема — cert с потолком **ниже** user МНКЦ → session.level <
  homedir.level → process не сможет читать $HOME. Это **решается на уровне
  политики выпуска сертификатов**: админ выпускает cert с
  `max_integrity.level ≥ user_МНКЦ` для интерактивных логинов.

Per-session ramdisk homedir (вариант B) и label-aware mkdir (вариант C)
отложены под YAGNI — добавим если появится конкретный use case.

### Audit events

- `integrity_capped_below_user_mnkc` (Notice) — всегда когда `effective <
  user_МНКЦ` (штатное событие, не warning).
- `homedir_label_above_session_cap` (Warning) — только для интерактивных
  сервисов (`pam_service ∈ {login, sshd, sddm, gdm}`) и только если
  `getpdpl(/home/<user>).level > effective.level`. Без блокировки сессии.

Конфиг:

```toml
[mac]
warn_on_homedir_label_mismatch = true  # default
```

Stock `pam_mkhomedir.so` и `pam_parsec_mac.so` остаются в `/etc/pam.d/*` как
есть, pam_certauth их не дублирует и не вызывает.

`docs/install.md` получает раздел «Cert issuance policy for interactive use» с
рекомендацией `cert.level ≥ user_МНКЦ` для login/sshd сценариев.

## 7. Совместимость и сборка

### 7.1 Feature flag

Build-time feature `astra-mac` в `pam_certauth_core` (re-export в
`pam_certauth` и `pam_certauth_cli`):

```toml
# crates/pam_certauth_core/Cargo.toml
[features]
default = []
astra-mac = []   # links libparsec, enables real FFI
mac-tests = []   # in-process MacBackend mock для unit-тестов
```

- `default = []` — Debian dev box и CI собирают **без** libparsec. Весь
  МКЦ-код компилируется в stub (no-op `Ok(())`).
- `astra-mac` — линкуется с `libparsec`, активирует FFI. Включается при сборке
  deb-пакета под Astra: `cargo build --release --features astra-mac`.

Линковка через `build.rs`. Реальная shared library — `libpdp`,
подтверждена официальным demo Astra (compile-команда `gcc ... -lpdp`):

```rust
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "astra-mac")]
    {
        println!("cargo:rustc-link-lib=pdp");
    }
}
```

NB: предыдущие версии дизайна линковали `-lparsec-mic -lparsec-base` под
предположением о C-struct ABI `parsec_mac_label_t`. Это **отменено**:
text-API `pdpl_*` / `pdp_*` живёт в `libpdp`, и работа со struct не
требуется (см. §4.1 и Appendix C).  Verified на Astra VM (Phase 4
Task 4.0.5): `gcc -o /tmp/pdp_demo /tmp/pdp_set_get_path.c -lpdp`
успешно компилирует demo-пример из docs.astralinux.ru.

### 7.2 Runtime detection

При старте PAM модуля / daemon — `mac::probe()` → `MacRuntime`:

- `Active` — `parsec_strict_mode() == 1` / `parsec_mac_enabled() == 1`,
  libparsec работает.
- `Disabled` — strictmode выключен (`astra-strictmode-control disable`):
  `parsec_strict_mode() == 0`.
- `Unavailable` — stub-сборка или sentinel-возврат от libparsec.

**Когда `Unavailable` достижим в `astra-mac` сборке?**
При direct linking (`-lpdp`) отсутствующая `.so` вызовет crash рантайма
ещё до PAM entry → `Unavailable` под `astra-mac` **недостижим в нормальном
flow**. Единственная остаточная ветка — явный sentinel `< 0` от
`parsec_strict_mode` (контракт его не описывает, но мы маппим на
`Unavailable` defensively). `parsec_strict_mode` остаётся в `libparsec-base`,
поэтому при probe-only режиме можно отдельно линковать `-lparsec-base` —
либо положиться только на text-API `pdp_*` и трактовать любую FFI-ошибку
от `pdpl_get_from_text` как `Unavailable`. Финальный выбор — Phase 4 Task 4.0.

Если в будущем потребуется graceful-fallback при отсутствии libpdp под
`astra-mac` (рантайм Astra без parsec-base) — переключаться на `dlopen`-pattern
с `libloading` и lazy-resolve. Пока YAGNI: install.md описывает требование
`parsec-base` как hard prereq.

Под stub-сборкой `probe()` всегда возвращает `Unavailable`.

### 7.3 Взаимодействие feature × config × runtime

| Build feature | Runtime probe | `cert_integrity` | Поведение |
|---------------|---------------|------------------|-----------|
| astra-mac     | Active        | required/optional/ignore | Полный flow |
| astra-mac     | Disabled      | required         | fail-closed на auth, `mac_skipped reason=strictmode_disabled` |
| astra-mac     | Disabled      | optional/ignore  | МКЦ не применяется, session продолжается |
| astra-mac     | Unavailable   | any              | Warning при старте + как Disabled |
| stub (no feature) | Unavailable | required         | **fail-fast при load config**: "binary built without astra-mac but policy requires it" |
| stub          | Unavailable   | optional/ignore  | МКЦ no-op |

### 7.4 FFI: ручные сигнатуры, не bindgen, text-API

Модуль `crates/pam_certauth_core/src/mac/`:

```
mod.rs       — public API: IntegrityLabel, apply_session(), probe(), set_file_label()
label.rs     — IntegrityLabel { level: i8, categories: u64 }, encode/decode DER, encode/decode text
backend.rs   — trait MacBackend (для DI и unit-mocking через mockall)
ffi.rs       — extern "C" вызовы libpdp (только text-API), #[cfg(feature="astra-mac")]
stub.rs      — no-op impl, #[cfg(not(feature="astra-mac"))]
audit.rs     — events emitter (mac_apply_failed, integrity_capped_below_user_mnkc, ...)
```

bindgen отвергнут: тянет libclang в build env, ломает воспроизводимость на CI
без libparsec headers. Public surface libpdp text-API мал (~6 функций) —
ручные `extern "C"`, **никаких C-struct** для перехода через FFI границу
(`PDPL_T` — opaque, обёрнут в `Pdpl(*mut c_void)` с `Drop`). Это ≈40 строк
extern, легко аудитировать. Сборка с RUSTFLAGS не зависит от наличия
parsec-headers на CI.

Полный список FFI-сигнатур которые трогает 0.3.0:
- `pdp_set_pid`, `pdp_get_pid` (process integrity; `pdp_set_current` /
  `pdp_get_current` — inline-обёртки, не экспортируются).
- `pdp_set_fd`, `pdp_get_fd` (sessions.json fd-based labeling, §5.3.1).
- `pdp_set_path`, `pdp_get_lpath` (path-based для socket / homedir).
- `pdpl_get_from_text`, `pdpl_get_text`, `pdpl_put` (text codec + RAII).
- `pdp_get_peer_label` (future, §5.3.2 — линкуем но используем только в
  Debug-event при `cfg(feature = "mac-debug-peer-label")`).
- `getmicnam`, `freemicent_r` (user МНКЦ lookup, §4.1.1).
- `parsec_strict_mode`, `parsec_capget` (probe + self-check capabilities,
  §4.3 / §7.2). `parsec_capget` живёт в `libparsec-base.so` (verified
  Astra CI 2026-05-15, run 25903325006); `build.rs` линкует обе библиотеки
  (`-lpdp -lparsec-base`).

### 7.5 CI

- **Default Linux job**: `cargo build --workspace` (без features) + `cargo
  test --workspace --features mac-tests`. Прогоняется на Debian runner, не
  требует libparsec.
- **Astra deb build job**: `cargo build --release --features astra-mac` в
  контейнере с пакетом `libparsec-base` (предоставляет `libpdp.so`).
- **E2E on Astra VM**: ручной/cron, deb с `astra-mac` enabled.

## 8. Тестирование

### 8.1 Unit (Debian dev box, без VM)

- `label.rs`: round-trip encode/decode, пустые categories, граничные
  `level=-128`/`level=127`, categories до 64 бит (`0xFFFFFFFFFFFFFFFF`),
  malformed DER (fail-safe), `level=128` / `level<-128` (reject — выход за
  диапазон int8).
- `backend.rs` с `mockall`: все ветки матрицы 3.x и 7.3.
- `proptest`: алгебраические свойства intersection/min (commutativity,
  identity, idempotence). Генерация: `level in -128i8..=127`,
  `categories: u64` (`any::<u64>()`).
- Config parser: `[mac]` секция — все 3 значения trinary, fallback variants,
  fail на неизвестных значениях.
- Regression test (по образцу `rejects_legacy_*`): legacy field names
  (`require_mac`, `cert_mac_level` и т.п.) → parse error, чтобы они не вернулись.

### 8.2 Integration (Astra VM, `astra-mac` build)

| # | Сценарий | Ожидание |
|---|----------|----------|
| T1 | cert {level=2, cat=01b}, user_МНКЦ {3, 11b} | effective {2, 01b}; `getpdpl /proc/$SHELL` |
| T2 | cert {1, ∅}, user {3, 11b} | effective {1, 11b}; audit `integrity_capped_below_user_mnkc` Notice |
| T3 | cert {3, ∅}, user {1, ∅} | effective {1, ∅} (capped by user); не отказ |
| T4 | cert без ext, `required` | auth deny, `cert_lacks_max_integrity_ext` |
| T5 | cert без ext, `optional` + fallback {0, ∅} | effective {0, user_cats} |
| T6 | cert без ext, `ignore` | МКЦ не применяется, session = system default |
| T7 | malformed ext (truncated/level=64/wrong tag) | fail-closed `cert_max_integrity_parse_failed` |
| T8 | strictmode disabled, `astra-mac` build | runtime Disabled, audit `mac_skipped`, auth продолжается |
| T9 | homedir.level=2, cert capped to 1, sshd login | Warning `homedir_label_above_session_cap`, session создаётся, $HOME даёт EACCES |
| T10 | monitord socket label | `getpdpl /run/pam_certauth/monitord.sock` показывает irelax+level=0; CLI execute из engineer-сессии (level=1) **actually connects** (не только проверка флага) |
| T8.5 | Domain user через `getmicnam`/sssd: user_МНКЦ резолвится | T1-аналогичная семантика; T8.5b — user без mic-записи: `required` deny / `optional` skip |
| T11 | Concurrent sessions того же user, разные cert levels | session A opens с `level=2`, session B opens с `level=1`; обе живут параллельно, каждая со своим эффективным label (на свой PID); `sessions.json` содержит оба record |
| T12 | `engineer-cap-l0-fullcats.pem` (`categories=u64::MAX`) на VM с system-max категорий <64 | DER парсинг — OK; orchestrator эмиттит Notice `cert_max_integrity_categories_above_32bit`; libpdp при `pdpl_get_from_text("0:0:ffffffffffffffff:…")` возвращает rc≠0 → fail-closed `mac_apply_failed` с понятным сообщением (op=`pdpl_get_from_text`) |

Автоматизация — `vagrant/scripts/test-mac.sh` по образцу `test-negative.sh`.

### 8.3 Stub-сборка smoke (Debian)

- `cargo build --workspace` без features + unit suite — без `libparsec-dev`.
- Config `cert_integrity = "required"` + stub binary → fail-fast при load
  config (мок PAM stack).

### 8.4 Fixture generation

`tests/fixtures/setup-mac-fixtures.sh` (новый, по образцу
`setup-mof-n-scenario.sh`) выпускает:

- `engineer-cap-l2-c01.pem` — `{level=2, categories=BIT STRING 01}`
- `engineer-cap-l1-empty.pem` — `{level=1, categories=∅}`
- `engineer-no-mac-ext.pem` — без extension
- `engineer-mac-l3.pem` — `{level=3, categories=∅}` (для T3)
- `engineer-mac-malformed.pem` — truncated DER в ext (для T7)
- `engineer-cap-l0-fullcats.pem` — `{level=0, categories=BITSTRING:ffffffffffffffff}` —
  полная маска `u64::MAX` (все 64 бита). Используется в T12 для проверки
  поведения когда `categories >> 32 != 0`: парсер эмиттит Notice
  `cert_max_integrity_categories_above_32bit`, а на Astra-VM с категориями
  <64 libpdp вернёт rc≠0 при `pdpl_get_from_text` → fail-closed
  `mac_apply_failed` штатно.

`openssl.cnf` шаблоны для каждого варианта — основной `ASN1:SEQUENCE`,
fallback DER hex в комментариях.

## 9. Аудит events (полный список)

| Event | Level | Когда |
|-------|-------|-------|
| `mac_skipped` | Notice | runtime Disabled/Unavailable или `cert_integrity=ignore` |
| `integrity_capped_below_user_mnkc` | Notice | `effective < user_МНКЦ` (штатно) |
| `homedir_label_above_session_cap` | Warning | interactive PAM service + homedir.level > effective.level |
| `cert_lacks_max_integrity_ext` | Notice | `required` + ext absent → deny |
| `cert_max_integrity_parse_failed` | Warning | malformed DER в ext (rate-limited: см. ниже) |
| `mac_apply_failed` | **CRITICAL** | libparsec вернул error при `mac_set_proc` |
| `mac_socket_label_set` | Debug | daemon выставил irelax на socket |
| `mac_sessions_file_label_warning` | Warning | sessions.json без irelax при write |
| `mac_caps_missing` | Warning | self-check `parsec_capget` показал отсутствие `PARSEC_CAP_CHMAC` (bit 3) при старте модуля |
| `mac_socket_peer_label_check` | Debug | (future, §5.3.2) monitord прочитал peer integrity на UDS через `pdp_get_peer_label` |
| `cert_max_integrity_categories_above_32bit` | Notice | `IntegrityLabel.categories >> 32 != 0` — concept-доки описывают категории как 32 бита, libpdp может отвергнуть; warn без блокировки парсинга. Apply fail-closed произойдёт штатно через `mac_apply_failed`, если libpdp вернёт rc≠0 на text-формате (см. T12) |

Все события emit'ятся через существующий `tracing-journald` слой с префиксом
`F_` для structured fields (см. memory `reference_astra_e2e.md` §«Reading
journald audit events»).

**Rate-limit `cert_max_integrity_parse_failed`.** Один и тот же malformed
cert может в DoS-сценарии заспамить journal. Эмиттер использует
LRU-cache (`HashMap<fingerprint, last_emit_instant>`) и подавляет повторные
warning'и для того же fingerprint в окне 60s, заменяя их на единый счётчик
в первом emit'е следующего окна. Cache размер ≤ 256 записей (LRU).
Тот же подход применим к `cert_lacks_max_integrity_ext` если в production
он окажется шумным.

## 10. Известные ограничения

1. **Cert ниже user МНКЦ для interactive login ломает $HOME-доступ.**
   Документировано как admin policy — выпускать cert с `level ≥ user_МНКЦ`
   для интерактивных сценариев. Не блокируется в коде (warning only).
2. **Понижение user МНКЦ после выпуска cert.** Если user МНКЦ снижен админом
   (parsec user db edit), старые сертификаты с более высоким `max_integrity`
   продолжат работать корректно (min капит вниз). Обратное — повышение МНКЦ
   через cert — невозможно по дизайну.
3. **Replay внутри cert validity.** Унаследовано из основного дизайна
   (retry-on-failure, см. main design `docs/superpowers/specs/scopes-and-m-of-n.md`
   §Replay). Не специфично для МКЦ.
4. **Astra DIGSIG WAS_ALREADY_VERIFIED_AND_FAILED** — известная проблема для
   неподписанных Astra-ключом бинарей; не блокирует исполнение. Production
   install должен подписывать `pam-certauth` и `pam-certauth-monitord` через
   `digsig_verify --sign`. Подробности — см. основной design
   (`docs/superpowers/specs/<main>.md` §DIGSIG) и
   `docs/operations.md` §USBGuard/DIGSIG.
5. **Открытые сессии не переоцениваются при rotation CA/revocation
   сертификата.** pam_certauth применяет cert→label только в
   `pam_sm_open_session`. После revoke уже открытая shell-сессия инженера
   продолжает иметь старый effective integrity. Mitigation — short cert
   validity + admin завершает session явно (`pkill -KILL -u engineer`).
6. **`irelax` + UID 0 = подделка `sessions.json`/`monitord.sock`.**
   Защита от подмены root'ом не входит в модель угроз pam_certauth (см.
   `docs/threat-model.md` §Trust model). `irelax` — необходимое следствие
   cross-level shared state.

## 11. Roadmap (вне scope этого design'а)

- Per-session ramdisk homedir (вариант B из раздела 6) — если появится use
  case для cert-driven downgrade в interactive shell.
- Label-aware mkdir homedir (вариант C) — то же условие.
- Дополнительный hook в `pam_sm_setcred` — для su-without-login.
- Интеграция с МРД (конфиденциальность, а не целостность) — отдельный design.
- Cert max_integrity extension в approver-сертификатах (для capping execute
  scope, а не engineer session) — отдельный design.

## Приложения

### A. Псевдокод `pam_sm_open_session`

```rust
fn pam_sm_open_session(handle: PamHandle, _flags, _args) -> PamResult {
    let policy = load_policy()?;       // существующее
    let cert   = current_cert(handle)?; // из challenge-response state
    let user   = pam_user(handle)?;

    let cert_max = parse_max_integrity_ext(&cert)?;  // Option<IntegrityLabel>
    let user_mnkc = mac::get_user_mnkc(&user)?;       // libparsec lookup

    let effective = match (policy.mac.cert_integrity, cert_max) {
        (Ignore, _)          => { audit_notice(mac_skipped, reason="policy_ignore"); return Ok(()); }
        (Required, None)     => audit_deny(cert_lacks_ext); return Err(...),
        (Required, Some(c))  => intersect(c, user_mnkc),
        (Optional, Some(c))  => intersect(c, user_mnkc),
        (Optional, None)     => match policy.mac.fallback_max_integrity {
            Some(fb) => intersect(fb, user_mnkc),
            None     => user_mnkc,  // unbounded
        },
    };

    // Метки несравнимы в общем случае; используем componentwise strictly_below
    // (см. §1 «Несравнимость меток» + IntegrityLabel::strictly_below).
    if effective.strictly_below(&user_mnkc) {
        audit_notice(integrity_capped_below_user_mnkc, ...);
    }

    if policy.mac.warn_on_homedir_label_mismatch && is_interactive_service(handle) {
        if let Ok(home_label) = mac::get_file_label(&home_dir(&user)) {
            if home_label.level > effective.level {
                audit_warning(homedir_label_above_session_cap, ...);
            }
        }
    }

    mac::apply_session(effective).map_err(|e| {
        audit_critical(mac_apply_failed, target=effective, user_mnkc, errno=e);
        PamError::SessionErr
    })?;

    Ok(())
}
```

### B. Контрольный список перед merge

- [ ] OID UUID сгенерирован, закоммичен в `oids.rs` как single source of
  truth, `.cnf` фикстуры используют `@MAX_INTEGRITY_OID@`-substitution.
- [ ] `pdpl-file` синтаксис verified на Astra VM (позиционная метка
  `[lev][:icat[:ccat[:flags][:linear_ilev]]]`, флаги `iinh`/`irelax` в 4-й
  позиции, `-R` для рекурсии).
- [ ] **Appendix C (verified libpdp text-API)** заполнен с реальными
  сигнатурами + URL источника + датой fetch.
- [ ] **Phase 4 Task 4.0.5 (compile demo `-lpdp`)** на VM прошёл — это
  валидация рантайма перед FFI-кодом.
- [ ] **Phase 7 (sessions.json) использует fd-based labeling** через
  `pdp_set_fd` (см. §5.3.1, sig подтверждён в pdp.h).
- [ ] postinst протестирован idempotent (повторный install не ломает labels).
- [ ] T1–T11 + T8.5 проходят на Astra VM.
- [ ] master-code-reviewer прошёл (security/concurrency/audit completeness).
- [ ] `docs/install.md`, `docs/cert-issuance.md`, `docs/configuration.md`,
  `docs/threat-model.md`, `docs/changelog.md` обновлены.
- [ ] Perf-bench: 100 sequential logins, p95 МКЦ-overhead < 100 ms (см.
  Plan Phase 10 Task perf).

### C. Verified libpdp / libparsec API (МКЦ)

**Стратегия.** Работаем только через **text-API libpdp** — никаких C-struct
не пересекают FFI-границу. Это устраняет угадывание padding/alignment для
`parsec_mac_label_t` и закрывает прежний C3 ревью полностью (struct-layout
dependency removed by design).

**Источники (fetch 2026-05-14):**
- Demo (verified compile recipe `-lpdp`):
  https://docs.astralinux.ru/latest/szi/api/demo/label/
- `pdp.h`: https://docs.astralinux.ru/latest/szi/api/headers/pdp/
- `pdp_common.h`: https://docs.astralinux.ru/latest/szi/api/headers/pdp_common/
- `mic_db.h`: https://docs.astralinux.ru/latest/szi/api/headers/mic_db/
- `parsec_cap.h`: https://docs.astralinux.ru/latest/szi/api/headers/parsec_cap/
- `parsec_mac.h` (для contrast — МРД, не наш use case):
  https://docs.astralinux.ru/latest/szi/api/headers/parsec_mac/
- `parsec_integration.h`: https://docs.astralinux.ru/latest/szi/api/headers/parsec_integration/

#### C.1 Type definitions (pdp_common.h)

```c
typedef uint32_t PDP_ILEV_T;     /* full integrity level packed         */
typedef uint64_t PDP_CAT_T;      /* categories bitmask, до 64 бит        */
typedef uint16_t PDP_TYPE_T;     /* label type flags (PDPT_*)            */
typedef uint8_t  PDP_LEV_T;      /* confidentiality linear (МРД, 0..255) */
typedef int8_t   PDP_ILINEAR_T;  /* integrity linear, -128..127          */
typedef uint32_t PDP_CNT_SIZE_T; /* category size helper                 */
```

#### C.2 Opaque label types

```c
typedef struct PDP_LABEL_T  PDPL_T;    /* opaque label handle */
typedef struct PDP_M_LABEL_T PDPML_T;  /* opaque mutable label (advanced) */
```

Управление lifecycle — `pdpl_put(label)` (refcount drop). RAII в Rust:
`Pdpl(*mut c_void)` с `Drop { pdpl_put }`.

#### C.3 Flag constants (PDPT_*) — verified numeric values

```c
#define PDPT_CCNR    0x01  /* dir: разные labels ≤ own                    */
#define PDPT_RWHOLE  0x04  /* file: minimal classification (= PDPT_EHOLE) */
#define PDPT_EHOLE   0x04  /* alias of RWHOLE                              */
#define PDPT_WHOLE   0x08  /* file: write by lower-classification          */
#define PDPT_SILEV   0x10  /* file: execute with file's integrity          */
#define PDPT_IRELAX  0x20  /* dir: permits writes to higher-integrity      */
#define PDPT_SSI     0x40  /* file: denies read by lower-integrity         */
#define PDPT_IINH    0x80  /* dir: objects inherit integrity               */
```

Composition в `/var/lib/pam_certauth/` (см. §5.1) — `PDPT_IINH | PDPT_IRELAX
= 0x80 | 0x20 = 0xA0`.

PDPL_FMT_* константы для второго аргумента `pdpl_get_text(l, flags)`:
- `PDPL_FMT_FORCE`, `PDPL_FMT_TXT`, `PDPL_FMT_NO_FORCE` — точные numeric
  values в pdp_common.h, на webview странице не показаны. В FFI передаём
  `flags = 0` — это значение **подтверждено в официальном demo Astra**
  (см. §C.10: `pdpl_get_text(l, 0)`, корректно печатает label round-trip),
  и его достаточно для нашего use case (default text format). Точные
  numeric values для PDPL_FMT_* остаются open TODO — поднимаются через
  `gcc -E -dM <<<'#include <parsec/pdp_common.h>' 2>/dev/null | grep PDPL_FMT`
  только если в будущем потребуется кастомизация формата (force-format
  для специфичных случаев). В 0.3.0 — не блокер.

#### C.4 pdp.h API (полный, verified)

```c
/* lifecycle */
int       pdp_init(void);
int       pdp_release(void);

/* process labels */
PDPL_T*   pdp_get_pid(pid_t pid);
PDPL_T*   pdp_get_current(void);             /* inline = pdp_get_pid(0) */
int       pdp_set_pid(pid_t pid, const PDPL_T *l);
int       pdp_set_current(const PDPL_T *l);  /* inline = pdp_set_pid(0,l) */
int       pdp_set_pid_n(pid_t pid, const PDPL_T *l);
int       pdp_set_current_n(const PDPL_T *l);
int       pdp_set_pid_safe(pid_t pid, const PDPL_T *l);

/* file labels */
PDPL_T*   pdp_get_path(const char *path);
PDPL_T*   pdp_get_lpath(const char *path);   /* без разыменования symlink */
PDPL_T*   pdp_get_fd(int fd);
int       pdp_set_path(const char *path, const PDPL_T *l);
int       pdp_set_lpath(const char *path, const PDPL_T *l);
int       pdp_set_fd(int fd, const PDPL_T *l);
int       pdp_set_ehole(const char *path);
int       pdp_set_ehole_fd(int fd);

/* sockets */
PDPL_T*   pdp_get_peer_label(int sockfd);    /* peer на UDS — §5.3.2 */

/* system */
PDPL_T*   pdp_get_sys_max(void);             /* inline */
int       pdp_set_sys_max_path(const char *path);
int       pdp_set_sys_max_fd(int fd);
int       pdp_set_sys_max_ccnr_path(const char *path);
int       pdp_set_EQU_path(const char *path);
int       pdp_set_EQU_fd(int fd);

/* integrity levels */
PDP_ILEV_T pdp_get_current_ilev(void);
PDP_ILEV_T pdp_get_max_ilev(void);
int*       pdp_get_ilevs(int *count);

/* super-root check */
int        pdp_is_super_root(void);

/* text conversions */
PDPL_T*    pdpl_get_from_text(const char *text);
char*      pdpl_get_text(const PDPL_T *l, int flags);
int        pdp_ilev_from_text(const char *txt, PDP_ILEV_T *ilev);
char*      pdp_ilev_get_text(PDP_ILEV_T il, int flags);
int        pdp_cat_from_text(const char *txt, PDP_CAT_T *c);
char*      pdp_cat_get_text(PDP_CAT_T c, int flags);

/* binary */
void*      pdp2raw(const PDPL_T *l, size_t *size);

/* refcount */
void       pdpl_put(PDPL_T *l);
```

**Inline vs symbol.** `pdp_set_current`, `pdp_get_current`,
`pdp_get_sys_max`, `pdp_set_EQU_path`, `pdp_set_EQU_fd` — inline-обёртки в
`pdp.h`, символов в `libpdp.so` **нет**. Из Rust FFI вызываем напрямую
underlying не-inline функции (`pdp_set_pid(0, l)`, `pdp_get_pid(0)`, etc.).

#### C.5 parsec_cap.h (capabilities)

```c
typedef struct {
    parsec_cap_t cap_effective;
    parsec_cap_t cap_inheritable;
    parsec_cap_t cap_permitted;
} parsec_caps_t;

int parsec_capget(pid_t pid, parsec_caps_t *data);
int parsec_capset(pid_t pid, const parsec_caps_t *data);
```

**Link location (verified):** `parsec_capget` / `parsec_capset` экспортируются
из `libparsec-base.so` (НЕ из `libpdp.so`). Подтверждено на Astra CI
2026-05-15 (ubi18:latest container, run 25903325006): сборка с одним
`-lpdp` падает с `undefined symbol: parsec_capget`; `nm -D
/usr/lib/libparsec-base.so*` резолвит символ. Поэтому `build.rs` emits
обе директивы (`pdp` + `parsec-base`), а `ffi.rs` использует
`#[link(name = "parsec-base")]` для блока с `parsec_capget`. См.
закрытый TODO в §C.8.

Релевантные cap-биты (значения = номер бита):

```
PARSEC_CAP_CHMAC              = 3   /* менять MAC-метки процессов/файлов */
PARSEC_CAP_IGNMACINT          = 13  /* bypass integrity checks (НЕ используем) */
PARSEC_CAP_INHERIT_INTEGRITY  = 17  /* exec-наследование integrity (НЕ используем) */
```

Self-check на старте модуля (см. §4.3):
```rust
let mut caps: parsec_caps_t = unsafe { mem::zeroed() };
if unsafe { parsec_capget(0, &mut caps) } == 0 {
    if (caps.cap_effective & (1u64 << 3)) == 0 {
        audit_warning!(mac_caps_missing, "PARSEC_CAP_CHMAC not set");
    }
}
```

#### C.6 parsec_mac.h — contrast (МРД, НЕ наш use case)

Только для документации того, чего мы **не** трогаем:

```c
typedef uint8_t  parsec_lev_t;             /* конфиденциальность */
typedef uint64_t parsec_cat_t;
struct parsec_mac_t       { parsec_lev_t lev; parsec_cat_t cat; };
struct parsec_mac_label_t { parsec_mac_t mac; uint32_t type; };

int parsec_getmac(pid_t pid, parsec_mac_t *mac);
int parsec_setmac(pid_t pid, const parsec_mac_t *mac);
int parsec_statmac(const char *filename, parsec_mac_label_t *mac);
int parsec_chmac(const char *filename, const parsec_mac_label_t *mac);
int parsec_fstatmac(int fd, parsec_mac_label_t *mac);
int parsec_fchmac(int fd, const parsec_mac_label_t *mac);
int parsec_mac_enabled(void);
int parsec_strict_mode(void);
```

**Errno guarantee** (общий контракт всех parsec headers): «All documented
functions return 0 on success. Error handling uses standard errno.» — то
есть для **parsec_*** API `errno` определён. Для **pdp_*** API (text-API
libpdp) `errno` контрактом **НЕ описан** → `ffi.rs` обязан использовать
только `rc != 0`, см. §4.3.

`parsec_strict_mode()` / `parsec_mac_enabled()` мы используем как probe-функции
(§7.2).

#### C.7 Symbols verified on Astra VM (`nm -D /usr/lib/libpdp.so.3`)

Подтверждены (2026-05-14, Astra SE 1.8.4):

```
parsec_strict_mode, parsec_enabled, parsec_astramode,
pdp_set_path, pdp_get_lpath,
pdp_set_fd, pdp_get_fd,
pdp_set_pid, pdp_set_pid_n, pdp_set_pid_safe,
pdpl_get_from_text, pdpl_get_text, pdpl_put,
pdp_get_current_ilev
```

**Inline в `.h`, в `.so` отсутствуют** (вызывать underlying вместо них):
`pdp_set_current`, `pdp_get_current`, `pdp_get_sys_max`,
`pdp_set_EQU_path`, `pdp_set_EQU_fd`.

`parsec_capget` / `parsec_capset` — **resolved**: лежат в
`libparsec-base.so` (НЕ в `libpdp.so.3`). Verified on Astra CI
2026-05-15 (run 25903325006). См. §C.5 и закрытую строку в C.8.

#### C.8 Open TODOs (закрываются в Phase 4 Task 4.0 на VM)

| TODO | VM-команда | Контракт fallback |
|------|------------|-------------------|
| `PDPL_FMT_*` numeric values | требуется `libpdp-dev` на VM; либо: `echo '#include <parsec/pdp_common.h>' \| gcc -E -dM -xc - 2>/dev/null \| grep PDPL_FMT` | в `pdpl_get_text(l, 0)` передаём `0` (как в demo §C.10) — works in practice |
| Точный тип `mic_t` | `echo '#include <parsec/mic_db.h>\nint main(){return sizeof(mic_t);}' \| gcc -xc - -lpdp -o /tmp/mt && /tmp/mt; echo $?` | если ≠ 4 байт — расширить `MicUser.il` тип и saturate в `i8` |
| ~~Локация `parsec_capget` / `parsec_capset`~~ | **CLOSED 2026-05-15** (Astra CI run 25903325006): символ в `libparsec-base.so`. `build.rs` emits `cargo:rustc-link-lib=parsec-base`; `ffi.rs` использует `#[link(name = "parsec-base")]`. См. §C.5. | n/a |
| Точный тип `parsec_cap_t` | `echo '#include <parsec/parsec_cap.h>\nint main(){return sizeof(parsec_cap_t);}' \| gcc -xc - -o /tmp/pc && /tmp/pc; echo $?` | вероятно `uint64_t`; от типа зависит маска `1u64 << 3` |

Errno: docs возвращают только `int` rc для `pdp_*` API. `errno` after call
**НЕ описан в контракте** — `ffi.rs` обязан использовать только `rc`, см.
§4.3. Для `parsec_*` (cap, mac) — `errno` определён, но мы их используем
только для self-check, и там тоже опираемся на `rc`.

#### C.9 parsec_integration.h (НЕ используем в 0.3.0, future consideration)

**Status:** NOT USED in 0.3.0; reserved as future consideration (например,
если потребуется явное `parsec_suid` при cap-switch для PAM-сценариев с
nested setuid). В текущем дизайне `pam_sm_open_session` работает в
адресном пространстве sshd/login, которые уже выполнили `parsec_suid` сами.

Для справки — это auth-flow helpers Astra PAM, не наш use case:

```c
int parsec_chmac_ign(const char *filename);
int parsec_cur_caps_set(const linux_caps_t *lcaps, const parsec_caps_t *pcaps);
int parsec_fchmac_ign(int fd);
int parsec_suid(const linux_caps_t *lcaps, const parsec_caps_t *cmaps);
int parsec_sw_ugid_caps(uid_t uid, gid_t gid,
                         const linux_caps_t *lcaps,
                         const parsec_caps_t *pcaps);
```

#### C.10 Verified demo recipe (источник истины)

```c
// gcc -o pdp_set_get_path pdp_set_get_path.c -lpdp
#include <stdio.h>
#include <parsec/pdp.h>

int pdpl_file_set(char *label, char *path) {
    PDPL_T* l;
    int r;
    if (!path || !label) return 1;
    l = pdpl_get_from_text(label);
    if (!l) return 1;
    r = pdp_set_path(path, l);
    pdpl_put(l);
    return r;
}

int pdpl_file_get(char *path) {
    PDPL_T* l;
    char *pdpl_txt;
    if (!path) return 1;
    l = pdp_get_lpath(path);
    if (!l) return 1;
    pdpl_txt = pdpl_get_text(l, 0);
    pdpl_put(l);
    if (!pdpl_txt) return 1;
    printf("%s\n", pdpl_txt);
    free(pdpl_txt);
    return 0;
}
```

Этот demo:
- подтверждает linker flag **`-lpdp`** (одиночный);
- подтверждает RAII-протокол: `pdpl_get_from_text` ↔ `pdpl_put`;
- даёт reference на text-формат label (передаётся как C-строка).

**Text format string `pdpl_get_from_text`** (verified on Astra SE 1.8.4,
2026-05-15 — формат, который ранее в этом дизайн-доке указывался как
пятисегментный `conf:integ:cat:flags:linear`, был неверен; ядро
strict-mode принимает четырёхсегментную грамматику):

```
[level]:[ilevel]:[cat_hex][:flags]
```

- `level` — МАК-уровень (МРД-confidentiality); мы передаём `0`.
- `ilevel` — иерархический уровень целостности (он же «линейный»
  ilevel у pdpl-file). Это поле прямо отображается на наш
  `IntegrityLabel.level` (`i8`, `0..127` в нашем диапазоне).
- `cat_hex` — категории целостности, шестнадцатеричный (`0` если
  пусто, до 16 hex цифр для `u64`).
- `flags` — необязательное поле: `iinh,irelax,silev,ssi,ccnr,ehole,whole`
  через запятую. Мы используем `iinh` для каталогов через `pdp_set_path`;
  на fd-based API (`pdp_set_fd`) flags не передаются — ядро возвращает
  EINVAL при попытке передать `irelax` через fd. irelax-наследование
  для `sessions.json` обеспечивается `iinh`-атрибутом на parent dir
  (`/var/lib/pam_certauth/`).

Примеры (verified Astra 1.8.4):
- `"0:0:0"` — default, всё пусто.
- `"0:0:0:iinh"` — iinh flag для каталога (используется в postinst через
  `pdpl-file`/`pdp_set_path`).
- `"0:1:0"` — ilevel=1, без категорий, без flags — формат метки, которая
  применяется к `sessions.json` через `pdp_set_fd`. `pdpl-file` после
  этого отображает `Уровень_0:Сетевые_сервисы:Нет:0x0!`.
- `"0:127:ffffffffffffffff"` — максимальный ilevel + все 64 категории.

#### C.11 Verified function signatures (mic_db.h)

```c
struct mic_user {
    mic_t  il;     /* МНКЦ */
    char  *name;   /* heap-allocated */
};

struct mic_user *getmicnam(const char *name);  /* PRIMARY — NSS/FreeIPA-aware */
struct mic_user *getmicuid(uid_t uid);
void             freemicent_r(struct mic_user *res);
```

- `mic_t` — точное определение НЕ опубликовано в headers; из контекста
  доступно как unsigned int (вероятно `uint32_t`). Поскольку мы переводим
  значение **только в `IntegrityLabel.level` (`i8`)**, делаем
  `if mic_t > 127 { i8::MAX } else { mic_t as i8 }` либо явный reject в
  тестах. Финальный тип определяется Phase 4 Task 4.0 (`echo
  '#include <parsec/mic_db.h>...' | gcc ...` + sizeof check на VM).
- `getmicnam(NULL_returned)` → user отсутствует в mic-db / FreeIPA;
  caller решает по policy (§4.1.1).
- `freemicent_r` обязан вызываться на не-NULL результат (`Drop`).

#### C.12 Rust FFI surface (план реализации)

```rust
// crates/pam_certauth_core/src/mac/ffi.rs (under feature "astra-mac")
//
// ВСЕ функции подтверждены в docs.astralinux.ru + verified через
// `nm -D /usr/lib/libpdp.so.3` на Astra VM 2026-05-14 (см. C.7).
// Никаких C struct layout для PDPL_T — opaque (*mut c_void) + text-API.

use std::os::raw::{c_char, c_int, c_void};

#[link(name = "pdp")]
extern "C" {
    // process integrity (primary).  pdp_set_current/pdp_get_current —
    // inline-обёртки, в .so отсутствуют → вызываем pdp_set_pid(0,..).
    fn pdp_set_pid(pid: libc::pid_t, label: *const c_void) -> c_int;
    fn pdp_get_pid(pid: libc::pid_t) -> *mut c_void;

    // fd-based (sessions.json §5.3.1)
    fn pdp_set_fd(fd: c_int, label: *const c_void) -> c_int;
    fn pdp_get_fd(fd: c_int) -> *mut c_void;

    // path-based (helpers / read-only home label check / socket labeling)
    fn pdp_set_path(path: *const c_char, label: *const c_void) -> c_int;
    fn pdp_get_lpath(path: *const c_char) -> *mut c_void;

    // socket peer (future §5.3.2)
    fn pdp_get_peer_label(sockfd: c_int) -> *mut c_void;

    // text codec
    fn pdpl_get_from_text(text: *const c_char) -> *mut c_void;
    fn pdpl_get_text(l: *const c_void, flags: c_int) -> *mut c_char;
    fn pdpl_put(l: *mut c_void);

    // probe
    fn parsec_strict_mode() -> c_int;
    fn parsec_mac_enabled() -> c_int;

    // user МНКЦ lookup
    fn getmicnam(name: *const c_char) -> *mut MicUser;
    fn freemicent_r(res: *mut MicUser);
}

// parsec_capget — лежит в libparsec-base.so (Astra CI 2026-05-15,
// run 25903325006). build.rs emits `cargo:rustc-link-lib=parsec-base`.
#[link(name = "parsec-base")]
extern "C" {
    fn parsec_capget(pid: libc::pid_t, data: *mut ParsecCaps) -> c_int;
}

#[repr(C)]
pub struct MicUser {
    pub il: u32,                  // exact type sanity-checked in Phase 4 Task 4.0
    pub name: *mut c_char,
}

#[repr(C)]
pub struct ParsecCaps {
    pub cap_effective:   u64,     // parsec_cap_t — sanity-checked in Phase 4 Task 4.0
    pub cap_inheritable: u64,
    pub cap_permitted:   u64,
}

pub const PARSEC_CAP_CHMAC: u32 = 3;

/// RAII-обёртка над opaque pointer.  Drop вызывает pdpl_put.
pub struct Pdpl(*mut c_void);
impl Pdpl {
    pub fn from_text(s: &str) -> Result<Self, MacError> { /* CString + check NULL */ }
    pub fn to_text(&self) -> Result<String, MacError>   { /* pdpl_get_text + free */ }
    pub fn as_ptr(&self) -> *const c_void { self.0 }
}
impl Drop for Pdpl {
    fn drop(&mut self) { unsafe { if !self.0.is_null() { pdpl_put(self.0); } } }
}
```

#### C.13 IntegrityLabel ↔ text encoding helpers

```rust
fn encode_label_text(l: &IntegrityLabel, flags: &str) -> String {
    // libpdp text grammar: level:ilevel:cat_hex[:flags]
    //   level  — МАК-уровень, всегда 0 (МРД out of scope).
    //   ilevel — линейный уровень целостности (0..127); мапится напрямую
    //            на IntegrityLabel.level.
    //   cat    — до 16 hex цифр (u64).
    //   flags  — опционально; пустой суффикс не добавляем, иначе ядро
    //            может вернуть EINVAL на pdp_set_fd.
    if flags.is_empty() {
        format!("0:{}:{:x}", l.level, l.categories)
    } else {
        format!("0:{}:{:x}:{}", l.level, l.categories, flags)
    }
}

fn decode_label_text(s: &str) -> Result<IntegrityLabel, MacError> {
    // level:ilevel:cat_hex[:flags]
    let parts: Vec<&str> = s.splitn(4, ':').collect();
    let level = parts.get(1)
        .map(|s| s.parse::<i8>())
        .transpose()
        .map_err(|_| MacError::Parsec { rc: -1, op: "decode level" })?
        .unwrap_or(0);
    let categories = u64::from_str_radix(parts.get(2).unwrap_or(&"0"), 16)
        .map_err(|_| MacError::Parsec { rc: -1, op: "decode cat" })?;
    Ok(IntegrityLabel { level, categories })
}
```

