# Scopes + M-of-N policy-driven authorisation

**Status:** Design  
**Date:** 2026-05-12  
**Targets:** pam_certauth 0.2.0

## 1. Цели

Расширить `pam_certauth` с бинарной авторизации «cert валиден → доступ» до
per-action policy-driven авторизации с поддержкой multi-party approval (M-of-N)
для необратимых операций (BIOS flash, ротация ключей, стирание журналов).

### 1.1 Что входит

- X.509 extension `pam_cert_scopes` — список разрешённых scope'ов
  на серте.
- CMS-based work order (RFC 5652) — подписанный набором approver'ов
  артефакт «эта операция разрешена на этом хосте».
- `pam_certauth_policy` крейт — TOML-парсер `policy.toml` с правилами
  per-scope (`m_of_n`, `argv_pattern`, `audit_level`, hooks).
- `pam-certauth` как multi-command бинарь:
  - `pam-certauth daemon` — текущий monitord под subcommand;
  - `pam-certauth execute --scope=X --work-order=path -- cmd args...`
    — gated execution.
  - `pam-certauth policy validate|explain` — offline проверка.
  - `pam-certauth which --cmd="..."` — UX-подсказка (опционально, может
    приехать позже).
- Минимальный static-enum hook framework: `audit_critical`, `noop`.
- Audit через существующий `tracing` + journald.

### 1.2 Что НЕ входит (отложено)

- Live approver sessions / online approval — модель целиком офлайн,
  approvers подписывают CMS заранее.
- Network channel из ATM наружу в момент execute.
- TPM HMAC chain audit sink.
- Dynamic dlopen hook framework.
- inotify hot-reload policy.toml — рестарт daemon допустим.
- Полный набор CLI subcommands (`sessions list`, `audit tail`,
  `cert inspect`).

## 2. Архитектура

### 2.1 Roles

| Роль        | Где                | Что у неё |
| ----------- | ------------------ | --------- |
| engineer    | физически у ATM    | USB-токен с short-lived cert: `host_binding`, `user_binding`, `scopes`. Стандартный PAM-логин. |
| approver    | удалённо в банке   | свой персональный приватный ключ (PKCS#11 hardware-токен, PKCS#12 файл на ФС, network HSM или TPM-sealed) + short-lived cert: `host_binding`, `scopes`. **Подписывает work order CMS-подписью своим приватным ключом** — это даёт криптографическую non-repudiation: подпись принадлежит конкретному оператору, а не CA от его имени. Выбор формата хранения ключа — на стороне банка, проект не предписывает. |
| approver-CA | у банка            | выпускает оба типа certs на короткий срок (1-2 дня = окно работ). |

В пределах кода: engineer cert и approver cert технически одинаковы — оба
содержат `scopes`-ext, `host_binding`-ext. Различие = политика CA при
выпуске (кому какие certs выдаёт). Кто approver, кто engineer для конкретного
work order — определяется по факту использования: cert в CMS-подписи =
approver; cert в активной PAM-сессии = engineer.

### 2.2 Trust anchors

- **Engineer-CA** = существующая trust-секция (`[trust]` в config).
- **Approver-CA** = новая trust-секция `[approver_trust]`, та же
  структура (`anchors`, `pinning`).

**Trust-anchor separation enforced.** В коде проверяется, что цепочка
CMS signer cert'а **не** терминирует на anchor'е, перечисленном в
`[trust]`. Это исключает атаку «engineer попросил CA выпустить себе
approver-cert»: даже если фактически один и тот же CA, операционно
банк может разделить две иерархии (отдельный sub-CA для approver'ов),
либо использовать ту же hierarchy с обязательным **EKU OID**
различающим engineer-EKU и approver-EKU — verifier требует
approver-EKU в каждом signer cert'е (новый config-флаг
`require_approver_eku = true`, default true). Если банк настаивает на
общем anchor'е без EKU разделения — нужно явно установить
`require_approver_eku = false` (документировать как weakened-mode).

Verifier — переиспользует `openssl_verifier` из core. Цепочка signer cert →
approver trust anchor. Тот же KRL/CRL pull. Тот же SPKI pinning.

### 2.3 Time / revocation

Не вводим. Срок действия = validity всех certs в цепочке (engineer + N
approvers + signer certs внутри CMS). Все короткоживущие (1-2 дня), так что:

- payload work order **не содержит** `not_before/not_after`;
- CMS `signing-time` (RFC 5652 §11.3) каждой подписи проверяется
  попасть в validity cert'а подписанта;
- ATM проверяет `now() ∈ validity` всех certs;
- KRL/CRL pull продолжает работать как сейчас — окно работ короткое,
  но revocation на случай увольнения подрядчика mid-window нужен.

**Компрометация approver-токена mid-window.** Окно 2 дня — CMS-подпись
может быть сделана как в нормальный момент, так и после кражи токена.
Защита — KRL polling в monitord каждые `krl_poll_interval` секунд
(config, секция `[approver_trust]`, default 300s). В KRL попадает SKI
скомпрометированного cert'а; при execute ATM сверяет signer SKI
против свежего KRL и отбрасывает подпись. Acceptable exposure =
`krl_poll_interval`. Стандартная картина для KRL-based систем.

**Signing-time как unauthenticated wall clock.** `signing-time` —
self-attested timestamp на машине approver'а: если токен украден,
атакующий может установить системные часы на момент внутри validity и
подделать свежий `signing-time`. Cert validity не доказывает момент
подписи. Меры защиты:

- ATM проверяет `signing-time ∈ [now() - validity_max_age, now() +
  skew_max]` (по умолчанию `skew_max = 5 min`, `validity_max_age` =
  validity cert'а подписанта). Это ограничивает window forgery до
  validity cert'а — что уже close через KRL.
- Для scopes с `audit_level = "critical"` (опционально per-scope в
  policy.toml: `require_timestamp_token = true`) CMS должен содержать
  **RFC 3161 TSA TimeStampToken** как unsigned-attr поверх каждой
  подписи. ATM проверяет цепочку TSA через отдельный trust anchor
  (`[tsa_trust]` секция config'а). TimestampToken — independent
  third-party proof of signing-time.
- Без TSA — residual risk зафиксирован в `threat-model.md` как
  «stolen approver token within KRL polling window can forge fresh
  signing-time within cert validity».

## 3. X.509 extension: `pam_cert_scopes`

### 3.1 OID

Новый OID в arc `2.25.<UUID>`. Конкретное значение выделяется при
реализации, регистрируется в `crates/pam_certauth_core/src/x509/oids.rs`.

### 3.2 ASN.1 формат

```
pam_cert_scopes ::= SEQUENCE OF UTF8String
```

То же, что у `host_binding`/`user_binding`. Парсер — clone
`host_binding_ext.rs`.

### 3.3 Семантика scope-имени

- regex: `^[a-z][a-z0-9_.-]{0,127}$` (lowercase, dot-namespaced).
- Запрещены: пустые строки, дубликаты в одном extension, не-UTF8.
- Wildcard: `*` (все scopes), `bios.*` (prefix). Match — в policy
  engine, не в парсере (парсер хранит строку как есть).

### 3.4 Расширение `CertClaims`

```rust
pub struct CertClaims {
    // существующее: host, user, ...
    pub scopes: Vec<Scope>,  // empty если ext отсутствует
}

pub struct Scope(String);
```

Отсутствие `scopes`-ext не блокирует существующий PAM-флоу. Только
запросы с `--scope=X` в execute и `require_scope=X` в PAM config
требуют scope.

## 4. CMS work order

### 4.1 Формат

CMS SignedData (RFC 5652) с N detached or attached signatures.
Реализация через `openssl::cms::CmsContentInfo`.

### 4.2 Payload (signed content)

TOML, человекочитаемый. Approver глазами видит что подписывает. В
минимальном варианте payload почти пуст — все ограничения
зашиты в signer certs.

```toml
# опционально, требуется policy.toml для критичных scopes:
argv_pattern = "flashrom -w /opt/atm/fw/fw_v*.bin"        # glob, не regex
```

Если `argv_pattern` не требуется политикой — payload пустой TOML
документ. CMS-подпись over пустого payload остаётся валидной:
signed-attrs всё равно содержат `signing-time` и `messageDigest`,
обеспечивающие криптографическую привязку к моменту подписи.

**Минимализм payload намеренный**: host/scope/время извлекаются из
signer certs, не из payload. Это исключает противоречие «payload
говорит host=A, signer cert говорит host=B» — единственный источник
правды — signer certs.

**Replay-protection не вводится.** Cert validity = окно работ (1-2 дня),
в этом окне engineer может повторять команду столько раз сколько нужно.
Это **намеренное operational решение**: при сбое destructive операции
(прервался flash, неудачный rotate) engineer должен иметь право
повторить без нового round'а согласования с approvers. Approvers это
понимают на этапе подписи — они утверждают **scope на окне**, не
«одно конкретное выполнение». Защиту от злоупотребления внутри окна
обеспечивают: KRL polling (отзыв cert'а), audit на каждый запуск,
короткий validity window. Если для какого-то scope нужна single-use
семантика — это решается узким validity (E3-style, 30 минут), не
nonce в payload.

### 4.3 Что ATM верифицирует

1. CMS parse OK.
2. ≥ M подписей, где M из policy.toml для запрошенного scope.
3. Каждый signer cert:
   - цепочка верифицирована к approver trust anchor (через
     `openssl_verifier`);
   - цепочка **не терминирует** на engineer trust anchor (защита от
     shared-anchor cross-role attack, см. §2.2);
   - если `require_approver_eku = true` — содержит approver-EKU OID;
   - не в KRL/CRL;
   - `now() ∈ validity`;
   - `signing-time` (signed attr) ∈ `[now() - signer_validity_max_age,
     now() + skew_max]` (см. §2.3);
   - если scope требует `require_timestamp_token = true` —
     unsigned-attr TimeStampToken (RFC 3161) присутствует и валиден
     против `[tsa_trust]`;
   - содержит `scopes`-ext с запрошенным scope (или wildcard);
   - содержит `host_binding`-ext, матчит локальный `host_id_hash`.
4. Все signer certs имеют **разные** `SubjectKeyIdentifier` (=
   разные физические подписанты).
5. CMS подпись над payload математически валидна (`Cms::verify`).
6. Engineer (текущая PAM-сессия):
   - cert содержит `scopes`-ext с запрошенным scope;
   - cert содержит `host_binding`-ext, матчит локальный host_id_hash
     (это уже проверено PAM при логине; перепроверяется здесь как
     defence-in-depth).
7. `argv_pattern` (если в payload) — match против фактической cmd+argv.
   - Семантика: glob (`*`, `?`, `[abc]`, без regex) над **canonical
     full argv joined by single space**. `cmd[0]` пред-canonicalize
     через `realpath` чтобы исключить bypass через PATH lookup или
     symlinks. Аргументы shell-escape'уются перед join'ом, чтобы
     пробелы внутри отдельных аргументов не сливались.
   - Каждый argv element валидируется до match'а: запрещены NUL,
     control chars (`\x00-\x1f\x7f`), не-NFC unicode → отказ
     `InvalidArgv`. Защита от newline injection в audit / sudo arg
     smuggling.
   - В `argv_pattern` запрещён литерал `--` (защита от подделки
     sudo-arg boundary).
8. Если `policy.toml` для scope содержит `forbid_self_approval = true`
   (default), `SubjectKeyIdentifier` engineer'а текущей PAM-сессии не
   должен присутствовать среди SKI signer'ов CMS. Защита от
   «инженер сам себе подписал». Один физический человек может
   одновременно владеть и engineer-, и approver-cert'ами (CA
   выпускает разные certs на разные роли разных work orders), но
   на одной работе одновременно быть и тем и тем — запрещено
   политикой.

Любой fail → отказ + audit.

### 4.4 Replay-protection

Не вводится. См. п. 4.2 — replay внутри validity допустим
по operational соображениям. Защита обеспечивается узким validity
cert'ов + KRL polling + audit каждого запуска.

## 5. `pam_certauth_policy` крейт

### 5.1 Расположение

`crates/pam_certauth_policy/` — новый крейт, зависит только от `serde`,
`toml`, `thiserror`.

### 5.2 Формат `policy.toml`

```toml
[defaults]
m_of_n = 1
audit_level = "info"

[scope."bios.flash"]
m_of_n = 2
require_argv_pattern = true
forbid_self_approval = true
audit_level = "critical"
pre_hooks = ["audit_critical"]
timeout_seconds = 1800              # 30 min cap; default None = no cap

[scope."service.restart"]
m_of_n = 1
audit_level = "info"

[scope."routine.*"]
m_of_n = 1
audit_level = "info"
```

### 5.3 API

```rust
pub struct Policy {
    pub sha256: [u8; 32],   // hash исходного policy.toml
    /* остальные поля */
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self>;       // читает + hash от raw bytes
    pub fn validate(&self) -> Result<()>;           // semantic check
    pub fn rule_for(&self, scope: &str) -> ScopeRule;
    pub fn sha256(&self) -> &[u8; 32];              // для audit event drift detection
}

pub struct ScopeRule {
    pub m_of_n: u8,
    pub require_argv_pattern: bool,
    pub forbid_self_approval: bool,             // default true
    pub require_timestamp_token: bool,          // default false
    pub audit_level: AuditLevel,
    pub pre_hooks: Vec<String>,
    pub post_hooks: Vec<String>,
    pub timeout_seconds: Option<u64>,           // None = unlimited
}
```

`rule_for("bios.flash")` — сначала точное совпадение, потом
prefix-wildcard (`bios.*`), потом defaults. Поля `None` берутся из
менее специфичного правила.

### 5.4 Целостность policy.toml

Подпись policy.toml в MVP **не вводится**. Защита целостности
обеспечивается на operational уровне:

1. **Hardened ATM**: интерактивный root недоступен (no console
   login, ssh disabled или ограничен через PAM на cert-auth-only,
   нет `sudo bash`, AppArmor/SELinux profile блокирует запись в
   `/etc/pam_certauth/*` всем кроме package manager / Ansible).
2. **Scoped sudo**: единственная разрешённая инженеру команда —
   `pam-certauth execute *`. Не `vi`, не `cp`, не editor. Editing
   `/etc/pam_certauth/policy.toml` физически невозможно через legit
   PAM-flow.
3. **File permissions**: `/etc/pam_certauth/policy.toml` —
   `0644 root:root`, `/etc/pam_certauth/` директория `0755 root:root`.
4. **Audit drift detection**: SHA-256 raw bytes `policy.toml`
   сохраняется в `Policy::sha256` и пишется в каждый audit event
   как `policy_sha256`. SIEM наблюдает за изменением hash — любое
   изменение policy между deployments (Ansible push) детектируется
   немедленно по drift'у в audit.
5. **Immutable rootfs опционально**: для самых критичных deployments
   — `/etc` на overlayfs над read-only base; modifications требуют
   перезагрузку в специальный режим.

Подпись policy.toml + `policy_ca.pem` — отложено в phase 2 как
defense-in-depth для deployments где root containment недостаточен.
**Не блокер MVP.**

### 5.5 API подгрузки

## 6. `pam-certauth execute` CLI

### 6.1 Синопсис

```
pam-certauth execute --scope=<scope> --work-order=<path> -- <cmd> [args...]
```

Без `--scope` → explain mode: парсит cmd, ищет в опциональном
`[command_hint]` mapping'е, печатает «возможно нужен scope=X», не
запускает.

### 6.2 Поток выполнения

```
1. Парсинг CLI.
2. Connect IPC к monitord, получить текущую engineer-сессию по
   peercred. Включает: `session_id`, `engineer_ski`, `engineer_cert_der`,
   `scopes`, `host_id_hash`.
3. policy::load(/etc/pam_certauth/policy.toml).
4. rule = policy.rule_for(scope).
5. Open work_order файл с `O_NOFOLLOW | O_RDONLY`, прочитать целиком
   в `Vec<u8>` (cap 10 MB — DoS protection). Все последующие операции
   идут от этого буфера (TOCTOU-resistant): `cms_sha256` считается
   тут же от того же буфера.
6. cms::verify(buffer, approver_trust, engineer_trust, host_id_hash,
   scope, rule) → Vec<SignerInfo>. Проверяет все условия из §4.3 п.3
   включая EKU, signing-time skew, TSA если требуется.
7. Engineer cert claims: scopes contains scope? host матчит?
8. Если rule.forbid_self_approval — `engineer_ski` не среди signer SKI.
9. argv_pattern match если rule.require_argv_pattern (см. 4.3 п.7
   по семантике glob, canonical argv, NUL/control-char rejection).
10. audit::log(execute_start, ...).
11. hooks::run_pre(rule.pre_hooks).  // fail = abort, не запускать cmd.
12. Prepare child env (см. 6.3).
13. fork+execve cmd с args. Stdin/stdout/stderr пробрасываются.
14. wait или timeout (см. 6.3), exit_status.
15. audit::log(execute_done, exit_status).
16. hooks::run_post(rule.post_hooks, exit_status).
17. Возврат: exit code child'а (либо 124 при timeout).
```

При abort на любом из шагов 1-10 — audit `execute_denied(reason)`,
exit 2.

Concurrent executes одного engineer'а не сериализуются — допустимо
параллельно запускать execute в двух терминалах. Каждый запуск
независим; ordering responsibility лежит на caller.

### 6.3 Child process environment

```
env       Scrub до whitelist: {PATH, LANG, LC_*, TERM, HOME, USER,
          LOGNAME}. Сохраняются все переменные с префиксом
          PAM_CERTAUTH_* (interop с hooks). Прочее вычищается.
          PATH принудительно: "/usr/sbin:/usr/bin:/sbin:/bin".
cwd       Passthrough от engineer'а (sudo preserves через -E или
          policy). Approver argv_pattern может зашить абсолютные
          пути, если path-dependence важна.
stdin     Passthrough.
stdout    Passthrough.
stderr    Passthrough.
pgroup    Перед execve: `setpgid(child, child)` — child получает
          свою process group. Все forwarded сигналы идут на pgrp,
          не на одиночный pid (корректно обрабатывает шеллы и
          deep child trees).
signals   Forwarded в child pgrp: SIGINT, SIGTERM, SIGHUP, SIGQUIT,
          SIGUSR1, SIGUSR2, SIGTSTP, SIGCONT, SIGWINCH (последние
          три — для tty job-control и interactive children).
          execute ловит их через `signalfd` (или
          `tokio::signal::unix`), forwards через `kill(-pgrp, sig)`.
          SIGKILL и SIGSTOP — kernel-level, не ловятся.
          SIGCHLD — обрабатывается loop'ом `waitpid(-1, …,
          WNOHANG)` чтобы корректно ловить exit child'а и
          предотвращать зомби при concurrent executes (один
          execute может породить дополнительных детей через шелл —
          reaping должен быть аккуратный).
timeout   По умолчанию unlimited. Если rule.timeout_seconds задан:
          таймер запускается после execve. По истечении: SIGTERM в
          pgrp, через 5 секунд SIGKILL если ещё жив. Audit
          `execute_timeout`. Exit code 124 (POSIX coreutils
          convention для timeout).
```

### 6.4 Sudo integration

```
# /etc/sudoers.d/pam-certauth
ATM_ENGINEERS ALL=(root) NOPASSWD: /usr/bin/pam-certauth execute *
```

Учётка engineer = плейн user, ни в `wheel`, ни в `sudo`. Единственная
команда под sudo — `pam-certauth execute`. NOPASSWD — engineer уже
доказал владение USB+cert через PAM при логине (mode=pkcs11, пароля нет).

Никаких setuid-бинарей.

## 7. IPC расширения

### 7.1 Новые `ClientMessage`

```json
{"type": "get_active_session_by_uid", "uid": 1000}
```

Ответ:

```json
{
  "type": "active_session",
  "session_id": "...",
  "cert_cn": "Alice",
  "engineer_ski": "ab12cd34...",
  "engineer_cert_sha256": "deadbeef...",
  "scopes": ["bios.flash", "service.restart"],
  "host_id_hash": "ee0b..."
}
```

или

```json
{"type": "error", "code": 1200, "message": "no active session for uid"}
```

`engineer_ski` (hex-encoded SubjectKeyIdentifier) необходим для
`forbid_self_approval` check'а в §4.3 п.8. `engineer_cert_sha256`
— для audit cross-reference. monitord держит engineer cert DER в
registry с момента PAM `pam_sm_open_session` (через IPC SessionOpen
с расширенным payload — добавляется `engineer_ski` + `cert_der`).

### 7.2 Protocol version bump

`PROTOCOL_VERSION` → 2. monitord держит backward-compat с v1 для
старого PAM cdylib (graceful — старый клиент не шлёт новые сообщения).

## 8. PAM module

### 8.1 Новый параметр

```
auth required pam_certauth.so mode=pkcs11 require_scope=login.shell
auth required pam_certauth.so mode=pkcs11 require_scope=login.shell,admin scope_match=all
auth required pam_certauth.so mode=pkcs11 require_scope=login.shell,emergency scope_match=any
```

- `require_scope` — список через запятую (или единичное значение
  как short form).
- `scope_match=any` (default) — claims пересекаются с require_scope
  хотя бы одним элементом.
- `scope_match=all` — каждый элемент require_scope присутствует в
  claims.

Если задан — после успешной cert-валидации проверяется правило
match. Иначе — отказ с кодом `INSUFFICIENT_SCOPE`.

Эффект: можно ограничить PAM-цепочку «только серты со scope=login.shell
проходят логин на этом ATM», или «требуем admin AND login.shell»,
или «допускаем login.shell ИЛИ emergency для break-glass логина».

Без параметра — поведение совместимо со старым.

## 9. Audit (MVP)

Через существующий `tracing` + journald. **Все string-поля
санитизируются** (отказ от newline / control chars / non-UTF8) до
записи — защита от log injection через `cert_cn` или `argv`.
Используются **структурированные journald fields**, не
string-format, чтобы поля атомарны для SIEM:

```
event                 = "execute_start" | "execute_done" | "execute_denied" | "execute_timeout"
scope                 = "bios.flash"
engineer_cn           = "Alice"                  // sanitized
engineer_ski          = "ab12cd34..."             // hex
engineer_session_id   = "..."                     // UUID
policy_sha256         = "f0e1d2c3..."             // current policy.toml hash
work_order_cms_sha256 = "abc123..."               // хеш CMS DER, audit cross-reference
approvers             = ["sha256:abc...", "sha256:def..."]  // SKI hex
argv                  = ["flashrom", "-w", "fw.bin"]        // array, not string
audit_level           = "critical"
exit_code             = 0                         // в execute_done/timeout
denied_reason         = "..."                     // в execute_denied
```

`audit_critical` hook (static-built-in) дополнительно шлёт syslog с
priority `auth.crit` для интеграции с SIEM. Это эталонный пример hook
framework'а; полноценный dlopen — фаза 2.

## 10. Hooks (MVP)

Static enum:

```rust
pub enum BuiltinHook {
    Noop,
    AuditCritical,  // дублирует event в syslog auth.crit
}

impl BuiltinHook {
    pub fn run(&self, ctx: &HookContext) -> Result<()> { /* ... */ }
}
```

В policy.toml ссылается по имени:

```toml
pre_hooks = ["audit_critical"]
```

Неизвестное имя → policy::validate() возвращает error. Dynamic-загрузка
(`libloading`) — отложена.

## 11. Compatibility

- Старые серты без `scopes`-ext проходят PAM auth, если `require_scope`
  не задан. `execute` с такими сертами невозможен (нет scope claim → отказ).
- Старые конфиги без `policy.toml` → daemon стартует, `execute` отказывает
  с понятным сообщением «policy not configured».
- IPC v1 ↔ v2 — graceful, новые сообщения только в v2.

## 12. Crate layout

Новые крейты:

```
crates/
  pam_certauth_policy/          — TOML parser + rule resolver
```

Изменения в существующих:

```
crates/pam_certauth_core/src/
  x509/
    oids.rs                     — + SCOPES_OID
    scopes_ext.rs               — новый (clone host_binding_ext.rs)
  cms.rs                        — новый, work-order verify
  cert/                         — расширить CertClaims полем scopes
crates/pam_certauth_proto/src/
  client.rs, server.rs          — новые message variants
  version.rs                    — PROTOCOL_VERSION = 2
crates/pam_certauth_monitord/src/
  server.rs                     — handler для get_active_session_by_uid
  registry/                     — индекс by uid
  main.rs                       — clap subcommands (daemon, execute, policy validate)
```

**Single-binary repackaging.** Текущий бинарь `pam-certauth-monitord`
переименовывается в `pam-certauth` и становится multi-command'ным.
**Решение: обновляем systemd unit** (`ExecStart=/usr/bin/pam-certauth
daemon`), symlink **не делаем**. Argv[0]-based dispatch хрупкий
(сломаются clap subcommands при вызове через symlinked имя),
unit update — атомарная замена в одном пакете. Если в 0.3 кто-то
по привычке зовёт `pam-certauth-monitord`, печатаем error stub
с подсказкой на новое имя (короткий wrapper-script в debian
package, удаляется в 0.4).

Крейт `pam_certauth_monitord` стоит переименовать в `pam_certauth_cli`
или `pam_certauth_bin` для отражения новой роли. Это — рефакторинг-only
шаг, изолированный коммит до начала feature-work.

`pam-certauth execute` — subcommand этого бинаря, не отдельный крейт.
Логика — в `pam_certauth_core/src/execute.rs`.

## 13. Тестирование

### 13.1 Unit

- `scopes_ext::parse` — valid/invalid форматы, wildcard.
- `Policy::rule_for` — wildcard precedence, defaults merge.
- `Policy::load` — корректный hash от raw bytes, sha256 стабилен
  относительно конкретных bytes файла (BOM / trailing newline → разный hash).
- `cms::verify` — M-of-N матрица: M=1/2/3, разные SKI, дубль-SKI отказ,
  expired signer cert отказ, KRL revoked signer отказ, scope mismatch отказ,
  host mismatch отказ, payload tamper отказ, signing-time outside skew
  отказ, EKU missing отказ (когда required), shared-trust-anchor cross-role
  атака отказ.
- `argv_match` — glob корректность над canonical full argv: пробелы
  внутри отдельных аргументов, symlink-bypass через `realpath` для
  cmd[0], wildcard корнер-кейсы, NUL byte в argv element → reject,
  control chars → reject, non-NFC unicode → reject, литерал `--` в
  pattern → policy validate reject.
- `forbid_self_approval` — engineer SKI среди signer SKI → reject.
- `pam::require_scope` — list-parsing, scope_match=any/all семантика.
- `cms::verify` DoS guard — buffer > 10MB rejected до parse.
- `audit::sanitize` — newline/null/control в `cert_cn` или argv element
  не попадает в journald output.

### 13.2 Integration (in-process daemon)

- `execute` happy path с 2 fake-signed work orders.
- `execute` отказ при m_of_n=2 и одной подписи.
- `execute` отказ при одинаковом SKI двух подписантов.
- `execute` повтор внутри validity — оба запуска успешны, оба в audit.
- `execute` concurrent — два параллельных execute в одном engineer
  uid не сериализуются, оба завершаются с корректным exit code,
  без зомби (waitpid loop проверяется через `ps`/`/proc`).
- `execute` TOCTOU — modify work_order file между open и read
  (mock-based) — execute hash остаётся стабильным относительно
  буфера, не файла.
- `execute` timeout — child запускается, sleeps дольше
  timeout_seconds, получает SIGTERM, через 5s SIGKILL, exit 124.
- `execute` signal forwarding — execute получает SIGTERM, child
  получает SIGTERM на pgrp.
- `daemon` валидирует policy.toml semantically при старте; при
  syntax error / missing m_of_n / неизвестных hook'ах — exit non-zero,
  error в logs. execute последующий: «policy_loaded=false → exit 2
  с PolicyInvalid».
- IPC `get_active_session_by_uid` — корректный поиск, `engineer_ski`
  присутствует в ответе.

### 13.3 E2E (vagrant Astra/Debian box)

- Два soft-PKCS#12 approver token, один engineer PKCS#12.
- Скрипт: выпустить certs, сгенерить work order через `openssl cms -sign`
  дважды (от разных approvers), подключить engineer USB, залогиниться,
  запустить `pam-certauth execute --scope=test.scope --work-order=... -- /bin/echo ok`.
- Expected: success, audit-event в journald.
- Negative: только одна подпись → reject.
- **GOST E2E**: вариант с CMS signed через `gost-engine` для одного
  approver, RSA для другого. Mixed-alg должен работать (CMS-spec
  позволяет per-SignerInfo разные алгоритмы). Если `gost-engine` CMS
  sign не работает в Rust openssl bindings — задокументировать
  как known gap в `threat-model.md` и в `migration.md`, дождаться
  отдельной задачи.

### 13.4 Fuzz

- `cargo fuzz` target на CMS parser (через openssl Cms::from_der).
- `cargo fuzz` target на scopes_ext::parse.
- TOML policy parser.

## 14. Документация

В `docs/`:

- `x509-extensions.md` — добавить раздел `pam_cert_scopes` + approver-EKU OID.
- `policy.md` — новый файл, формат policy.toml + подпись + примеры.
- `work-order.md` — новый файл, как банк генерирует CMS, примеры
  `openssl cms -sign`, signed-attrs, TimeStampToken для critical scopes.
- `execute.md` — новый файл, CLI usage, sudoers пример, error codes,
  signal/timeout behavior, env scrub.
- `architecture.md` — добавить секции про CMS work order и execute flow,
  обновить компоненты-диаграмму.
- `configuration.md` — добавить секции `[approver_trust]`, `[policy]`,
  `[tsa_trust]`, `krl_poll_interval`, `policy_ca`, `require_approver_eku`.
- `operations.md` — добавить про work_order CMS retention, GC через
  systemd timer, journald audit query examples.
- `ipc.md` (или раздел в architecture.md) — новые v2 сообщения,
  version negotiation, error codes (1200 — no active session).
- `threat-model.md` — новые угрозы: компрометация approver mid-window,
  stolen approver token с forged signing-time, shared trust anchor
  cross-role атака, root-уровневая компрометация policy.toml, TOCTOU
  на work_order файле, log injection через cert_cn/argv. Для каждой —
  что closes / что residual.
- `migration.md` — как обновиться с 0.1.x: новые extension'ы, новые
  trust секции config'а, обновление systemd unit (rename binary),
  выпуск approver-cert'ов через банковский CA.

## 15. Open items (не блокеры дизайна, решаются в плане)

1. Точный OID для `pam_cert_scopes` — выделить новый UUID при
   реализации, документировать.
2. Формат signing-time проверки в CMS — какие attrs обязательны
   (`signing-time`), какие опциональны.
3. Audit identifier для cross-reference: использовать хеш CMS DER
   (после canonical-нормализации) или signer SKI + signing-time? Голос
   за хеш — стабильнее для banking SOC при пересылке артефактов.
4. Согласовать с банком-заказчиком: у каждого approver-оператора есть
   персональный приватный ключ (формат на усмотрение банка — PKCS#11
   hardware, PKCS#12 на encrypted FS, network HSM, TPM-sealed) и
   средства подписи CMS на рабочих станциях (openssl cms /
   банковская workflow-утилита-обёртка). Без этого non-repudiation в
   CMS-модели не работает.
5. Дизайн «non-repudiation rationale»: причина выбора CMS поверх
   Model D (N CA-выпущенных approval certs) — банк требует знать,
   **кто именно** из операторов утвердил доступ, с криптографической
   привязкой к ключу оператора, а не к CA-процессу.
6. Retention CMS-артефактов на ATM: чтобы `work_order_cms_sha256`
   в audit имел смысл при расследовании, либо ATM хранит копию CMS
   в `/var/lib/pam_certauth/work_orders/<hash>.cms` (срок ≥ retention
   policy банка), либо банковский SOC хранит исходники на стороне
   scheduling system. Голос за **первое** — ATM-локальная копия
   независима от внешних систем, объём пренебрежим (CMS обычно
   <10 KB), GC через systemd-timer по mtime.
7. Дизайн «no replay-protection rationale»: при сбое destructive
   операции (прерванный flash, повторный rotate ключей) engineer
   должен иметь право перезапустить без нового round'а согласования.
   Защита от злоупотребления внутри окна = узкий validity cert'а +
   KRL polling + audit. Если для конкретного scope нужна строгая
   single-use семантика — банк назначает короткий validity (30-60 мин
   вместо 2 дней) при выпуске approver-cert'ов.

## 16. Acceptance criteria

- Новый extension `pam_cert_scopes` парсится, валидируется, проброшен в
  `CertClaims`, документирован.
- `pam_certauth_policy` крейт работает с полным юнит-тестом.
- `pam-certauth execute` E2E проходит в vagrant с 2 approver токенами.
- PAM `require_scope` параметр работает.
- Старые серты и конфиги работают (back-compat).
- CI: unit + integration зелёные. E2E запускается через `vagrant up`.
- Документация обновлена.

## 17. Оценка

MVP (scope этого doc'а): 2-3 недели одному dev. Большая часть — CMS
verify (правильно обращаться с openssl Cms, проверять signed-attrs,
M-of-N подсчёт) и end-to-end test rig (выпуск certs + генерация
work order через openssl).
