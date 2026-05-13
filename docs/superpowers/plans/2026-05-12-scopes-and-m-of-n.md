# Scopes + M-of-N policy-driven authorisation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Расширить pam_certauth с бинарной cert-auth до per-action M-of-N policy-driven авторизации через CMS work order + policy.toml + новый `pam-certauth execute` subcommand.

**Architecture:** Per [spec](../specs/2026-05-12-scopes-and-m-of-n-design.md). Новая X.509 extension `pam_cert_scopes`. Новый крейт `pam_certauth_policy`. Новый модуль `cms` в core. Бинарь `pam-certauth-monitord` переименовывается в `pam-certauth` с clap subcommands (`daemon`, `execute`, `policy validate|explain`). PAM-модуль остаётся, добавляется параметр `require_scope` (list + match=any|all). monitord registry индексирует сессии по uid, IPC расширяется новым сообщением `get_active_session_by_uid` возвращающим engineer_ski/cert_sha256. Audit через journald structured fields с санитизацией. Без replay-protection (operational retry) и без policy.toml signing (root containment + audit drift).

**Tech Stack:** Rust 1.95, edition 2021, workspace. openssl 0.10 (X.509 + Cms), nix (signals, setpgid), tokio (signals/IPC), serde + toml, sha2, tracing + tracing-journald. clap derive для subcommands.

**Reference paths:**
- Spec: `docs/superpowers/specs/2026-05-12-scopes-and-m-of-n-design.md`
- Existing extensions: `crates/pam_certauth_core/src/x509/host_binding_ext.rs`, `user_binding_ext.rs`
- DER helpers: `crates/pam_certauth_core/src/x509/der_helpers.rs`
- OIDs: `crates/pam_certauth_core/src/x509/oids.rs`
- IPC proto: `crates/pam_certauth_proto/src/{client,server,version}.rs`
- monitord: `crates/pam_certauth_monitord/src/{main,server,registry}.rs`
- Workspace: `Cargo.toml`

**Conventions:**
- Каждый таск имеет файлы (Create / Modify / Test), пошагово TDD.
- Use `cargo test -p <crate>` для focused прогона.
- Use `cargo clippy --workspace --all-targets -- -D warnings` после каждого таска.
- Commit conventional commits: `feat(scope): …`, `test(scope): …`, `refactor(scope): …`, `docs(scope): …`.
- Coverage smoke: `cargo test --workspace` зелёный после каждого commit'а.

---

## Phase 0 — Pre-flight refactor (single binary)

### Task 0.1 — Rename monitord crate dir + Cargo.toml + bin name

**Files:**
- Modify: `Cargo.toml` (workspace member rename)
- Move: `crates/pam_certauth_monitord/` → `crates/pam_certauth_cli/`
- Modify: `crates/pam_certauth_cli/Cargo.toml` (package name, bin name)
- Modify: `debian/*.install`, `debian/*.service`, `debian/changelog`
- Modify: every `use pam_certauth_monitord::…` reference (test crates may use `test-support` feature)

- [ ] **Step 1: Grep all references**

```bash
rg "pam_certauth_monitord|pam-certauth-monitord" --type-add 'cargo:*.toml' -t rust -t cargo -t md --files-with-matches
```

Записать список файлов.

- [ ] **Step 2: Move directory**

```bash
git mv crates/pam_certauth_monitord crates/pam_certauth_cli
```

- [ ] **Step 3: Update workspace + crate manifest**

`Cargo.toml`:
```toml
members = [
    "crates/pam_certauth_core",
    "crates/pam_certauth_proto",
    "crates/pam_certauth",
    "crates/pam_certauth_cli",
]
```

`crates/pam_certauth_cli/Cargo.toml`:
```toml
[package]
name = "pam_certauth_cli"
# … остальное workspace-наследуется

[[bin]]
name = "pam-certauth"
path = "src/main.rs"
```

- [ ] **Step 4: Update systemd unit + debian files**

`debian/pam-certauth.service` (или существующий):
```ini
ExecStart=/usr/bin/pam-certauth daemon
```

`debian/pam-certauth-cli.install`:
```
target/release/pam-certauth usr/bin/
```

Удалить старый `pam-certauth-monitord.install` если был.

- [ ] **Step 5: Update sources referencing old crate**

В каждом `*.rs`, `*.toml`, `*.md`:
```
pam_certauth_monitord → pam_certauth_cli
pam-certauth-monitord → pam-certauth (с учётом контекста: бинарь vs subcommand)
```

В spec'е не править — это историчный документ.

- [ ] **Step 6: Build + test**

```bash
cargo build --workspace
cargo test --workspace
```

Все должны проходить (refactor-only).

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(cli): rename monitord crate to pam_certauth_cli with pam-certauth binary"
```

### Task 0.2 — Introduce clap subcommands skeleton

**Files:**
- Modify: `crates/pam_certauth_cli/Cargo.toml` (add clap)
- Modify: `crates/pam_certauth_cli/src/main.rs`
- Test: `crates/pam_certauth_cli/tests/cli_smoke.rs`

- [ ] **Step 1: Add clap dep**

`crates/pam_certauth_cli/Cargo.toml`:
```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
# … остальное
```

- [ ] **Step 2: Write failing test**

`crates/pam_certauth_cli/tests/cli_smoke.rs`:
```rust
use std::process::Command;

#[test]
fn binary_has_daemon_subcommand_help() {
    let out = Command::new(env!("CARGO_BIN_EXE_pam-certauth"))
        .args(["daemon", "--help"])
        .output()
        .expect("run pam-certauth daemon --help");
    assert!(out.status.success(), "daemon --help failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Run the monitor daemon"), "help text mismatch:\n{stdout}");
}
```

- [ ] **Step 3: Run — verify failure**

```bash
cargo test -p pam_certauth_cli cli_smoke
```

Expected: FAIL (no daemon subcommand).

- [ ] **Step 4: Implement subcommand skeleton**

`crates/pam_certauth_cli/src/main.rs`:
```rust
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "pam-certauth", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the monitor daemon (USB + IPC)
    Daemon,
    // Execute, Policy — добавятся в Phase 7 / Phase 8
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Daemon => run_daemon(),
    }
}

fn run_daemon() -> std::process::ExitCode {
    // Существующая логика main() из старого monitord уезжает сюда.
    // Импортировать через pub fn в lib.rs и звать здесь.
    pam_certauth_cli::daemon::run()
}
```

Перенести существующий контент `main.rs` в `src/daemon/mod.rs` с pub fn `run() -> ExitCode`. Создать `src/lib.rs` с `pub mod daemon;`.

- [ ] **Step 5: Run — verify pass**

```bash
cargo test -p pam_certauth_cli
cargo build --workspace
```

- [ ] **Step 6: Commit**

```bash
git commit -am "feat(cli): clap subcommand skeleton with daemon subcommand"
```

---

## Phase 1 — `pam_cert_scopes` X.509 extension + CertClaims

### Task 1.1 — Allocate OID + add parser stub

**Files:**
- Modify: `crates/pam_certauth_core/src/x509/oids.rs`
- Create: `crates/pam_certauth_core/src/x509/scopes_ext.rs`
- Modify: `crates/pam_certauth_core/src/x509/mod.rs`
- Test: `crates/pam_certauth_core/src/x509/scopes_ext.rs` (inline `#[cfg(test)]`)

- [ ] **Step 1: Pick OID — UUID v4**

Сгенерируй: `python3 -c 'import uuid; n=uuid.uuid4().int; print("2.25."+str(n))'`. Запиши в `oids.rs`:

```rust
/// OID of the `pam_cert_scopes` X.509 extension.
///
/// `extnValue ::= SEQUENCE OF UTF8String`, where each entry is a
/// scope name matching regex `^[a-z][a-z0-9_.-]{0,127}$` or the
/// wildcard `"*"`.
pub const SCOPES_OID: &str = "2.25.<GENERATED>";
```

(заменить `<GENERATED>` на реальное число)

- [ ] **Step 2: Write failing tests**

`crates/pam_certauth_core/src/x509/scopes_ext.rs`:
```rust
//! Parser for the `pam_cert_scopes` X.509 extension.
//!
//! ASN.1: `extnValue ::= SEQUENCE OF UTF8String`.

use super::der_helpers::{extract_extension_by_oid, parse_seq_of_utf8};
use super::oids::SCOPES_OID;
use openssl::x509::X509Ref;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Wildcard,             // "*"
    Exact(String),        // lowercase, dot-namespaced
}

#[derive(Debug, Error)]
pub enum ScopesExtError {
    #[error("extension missing")]
    Missing,
    #[error("extension malformed: {0}")]
    Malformed(String),
    #[error("extension has no entries")]
    Empty,
    #[error("invalid scope name {0:?}")]
    InvalidScope(String),
}

pub fn parse(_cert: &X509Ref) -> Result<Vec<Scope>, ScopesExtError> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::oids::SCOPES_OID;
    use crate::x509::test_utils::{build_cert, encode_seq_of_utf8};
    use crate::x509::oids::{HOST_BINDING_OID, USER_BINDING_OID};
}
```

Замени `todo!()` на `unimplemented!()` чтобы файл компилировался. Скопируй cert-building helpers (`encode_seq_of_utf8`, `build_cert`) из `host_binding.rs:206-258` в общий test-utils (`crates/pam_certauth_core/src/x509/test_utils.rs` под `#[cfg(test)]`). Зарегистрируй в `mod.rs`: `#[cfg(test)] pub(crate) mod test_utils;`.

Затем впиши пять unit-тестов в `mod tests`:

```rust
#[test]
fn parses_single_exact_scope() {
    let cert = build_cert(&[(SCOPES_OID, encode_seq_of_utf8(&["bios.flash"]))]);
    let scopes = parse(&cert).unwrap();
    assert_eq!(scopes, vec![Scope::Exact("bios.flash".into())]);
}

#[test]
fn parses_wildcard() {
    let cert = build_cert(&[(SCOPES_OID, encode_seq_of_utf8(&["*"]))]);
    let scopes = parse(&cert).unwrap();
    assert_eq!(scopes, vec![Scope::Wildcard]);
}

#[test]
fn rejects_invalid_scope_name() {
    let cert = build_cert(&[(SCOPES_OID, encode_seq_of_utf8(&["BAD UPPERCASE"]))]);
    let err = parse(&cert).unwrap_err();
    assert!(matches!(err, ScopesExtError::InvalidScope(_)));
}

#[test]
fn rejects_empty_extension() {
    let cert = build_cert(&[(SCOPES_OID, encode_seq_of_utf8(&[]))]);
    let err = parse(&cert).unwrap_err();
    assert!(matches!(err, ScopesExtError::Empty));
}

#[test]
fn returns_missing_when_absent() {
    let cert = build_cert(&[]);
    let err = parse(&cert).unwrap_err();
    assert!(matches!(err, ScopesExtError::Missing));
}
```

Зарегистрируй модуль: `crates/pam_certauth_core/src/x509/mod.rs`: `pub mod scopes_ext;`.

- [ ] **Step 3: Run — verify failure**

```bash
cargo test -p pam_certauth_core x509::scopes_ext
```

Expected: PANIC `unimplemented!` или compile error на `encode_seq_of_utf8`.

- [ ] **Step 4: Implement parser**

```rust
pub fn parse(cert: &X509Ref) -> Result<Vec<Scope>, ScopesExtError> {
    let der = cert
        .to_der()
        .map_err(|e| ScopesExtError::Malformed(format!("openssl: {e}")))?;

    let value = match extract_extension_by_oid(&der, SCOPES_OID) {
        Ok(Some(v)) => v,
        Ok(None) => return Err(ScopesExtError::Missing),
        Err(e) => return Err(ScopesExtError::Malformed(e.to_string())),
    };

    let strings = parse_seq_of_utf8(&value)
        .map_err(|e| ScopesExtError::Malformed(e.to_string()))?;

    if strings.is_empty() {
        return Err(ScopesExtError::Empty);
    }

    strings.into_iter().map(classify).collect()
}

fn classify(s: String) -> Result<Scope, ScopesExtError> {
    if s == "*" {
        return Ok(Scope::Wildcard);
    }
    if !is_valid_scope_name(&s) {
        return Err(ScopesExtError::InvalidScope(s));
    }
    Ok(Scope::Exact(s))
}

fn is_valid_scope_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 128 {
        return false;
    }
    let mut chars = s.bytes();
    let Some(first) = chars.next() else { return false; };
    if !first.is_ascii_lowercase() {
        return false;
    }
    chars.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}
```

- [ ] **Step 5: Run — verify pass**

```bash
cargo test -p pam_certauth_core x509::scopes_ext
cargo clippy -p pam_certauth_core -- -D warnings
```

- [ ] **Step 6: Commit**

```bash
git commit -am "feat(core): pam_cert_scopes X.509 extension parser"
```

### Task 1.2 — Scope matcher (wildcard precedence)

**Files:**
- Modify: `crates/pam_certauth_core/src/x509/scopes_ext.rs`

- [ ] **Step 1: Write failing tests**

В `scopes_ext.rs` добавь:
```rust
/// Returns true if `claimed` scopes contain `requested` (with wildcard semantics).
pub fn contains(claimed: &[Scope], requested: &str) -> bool {
    todo!()
}

#[cfg(test)]
mod matcher_tests {
    use super::*;

    #[test]
    fn wildcard_matches_anything() {
        assert!(contains(&[Scope::Wildcard], "bios.flash"));
    }

    #[test]
    fn prefix_wildcard_matches_subscope() {
        assert!(contains(&[Scope::Exact("bios.*".into())], "bios.flash"));
    }

    #[test]
    fn prefix_wildcard_does_not_match_other_namespace() {
        assert!(!contains(&[Scope::Exact("bios.*".into())], "service.restart"));
    }

    #[test]
    fn exact_match() {
        assert!(contains(&[Scope::Exact("bios.flash".into())], "bios.flash"));
    }

    #[test]
    fn missing_returns_false() {
        assert!(!contains(&[Scope::Exact("bios.flash".into())], "bios.erase"));
    }
}
```

- [ ] **Step 2: Run — fail**

- [ ] **Step 3: Implement**

```rust
pub fn contains(claimed: &[Scope], requested: &str) -> bool {
    for c in claimed {
        match c {
            Scope::Wildcard => return true,
            Scope::Exact(s) if s == requested => return true,
            Scope::Exact(s) if s.ends_with(".*") => {
                let prefix = &s[..s.len() - 1]; // включая '.'
                if requested.starts_with(prefix) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}
```

- [ ] **Step 4: Run — pass**

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(core): scope matcher with wildcard semantics"
```

### Task 1.3 — Extend `CertClaims` with scopes

**Files:**
- Modify: `crates/pam_certauth_core/src/host_binding.rs` (если `CertClaims` там) или искать через grep
- Modify: каждый caller, конструирующий CertClaims

- [ ] **Step 1: Locate CertClaims**

```bash
rg "struct CertClaims" crates/pam_certauth_core/src/
```

Если структура отсутствует — создать новый файл `crates/pam_certauth_core/src/cert_claims.rs`:

```rust
use crate::x509::scopes_ext::Scope;

#[derive(Debug, Clone)]
pub struct CertClaims {
    pub host_descriptors: Vec<crate::x509::host_binding_ext::HostDescriptor>,
    pub user_descriptors: Vec<crate::x509::user_binding_ext::UserDescriptor>,
    pub scopes: Vec<Scope>,                 // empty если ext отсутствует
    pub subject_key_identifier: String,     // hex
    pub cert_sha256: String,                // hex от X509 DER
}
```

Зарегистрировать `pub mod cert_claims;` в lib.rs.

- [ ] **Step 2: Helper `from_cert`**

```rust
impl CertClaims {
    pub fn from_cert(cert: &openssl::x509::X509Ref) -> Result<Self, Error> {
        let host = crate::x509::host_binding_ext::parse(cert)?;
        let user = crate::x509::user_binding_ext::parse(cert)?;
        let scopes = match crate::x509::scopes_ext::parse(cert) {
            Ok(v) => v,
            Err(crate::x509::scopes_ext::ScopesExtError::Missing) => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        let ski = subject_key_identifier_hex(cert)?;
        let cert_sha256 = sha256_hex_of_der(cert)?;
        Ok(Self { host_descriptors: host, user_descriptors: user, scopes,
                  subject_key_identifier: ski, cert_sha256 })
    }
}

fn subject_key_identifier_hex(cert: &openssl::x509::X509Ref) -> Result<String, Error> {
    // через openssl: cert.subject_key_id().map(|b| hex::encode(b.as_slice()))
    // openssl-rust 0.10 expose subject_key_id() как Option<&Asn1OctetStringRef>.
    let ski = cert
        .subject_key_id()
        .ok_or_else(|| Error::Malformed("cert missing SubjectKeyIdentifier".into()))?;
    Ok(hex::encode(ski.as_slice()))
}

fn sha256_hex_of_der(cert: &openssl::x509::X509Ref) -> Result<String, Error> {
    use sha2::{Digest, Sha256};
    let der = cert.to_der().map_err(|e| Error::Openssl(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(&der)))
}
```

Заведи минимальный `Error` enum (через thiserror) — конвертирует из существующих ошибок.

- [ ] **Step 3: Add `hex` dep**

`Cargo.toml` workspace:
```toml
hex = "0.4"
```

`crates/pam_certauth_core/Cargo.toml`:
```toml
hex = { workspace = true }
```

- [ ] **Step 4: Write test**

```rust
#[test]
fn from_cert_extracts_scopes_ski_and_sha256() {
    let cert = build_cert(&[
        (HOST_BINDING_OID, encode_seq_of_utf8(&["*"])),
        (USER_BINDING_OID, encode_seq_of_utf8(&["alice"])),
        (SCOPES_OID, encode_seq_of_utf8(&["bios.flash"])),
    ]);
    let claims = CertClaims::from_cert(&cert).unwrap();
    assert_eq!(claims.scopes, vec![Scope::Exact("bios.flash".into())]);
    assert_eq!(claims.subject_key_identifier.len(), 40); // 20 bytes hex
    assert_eq!(claims.cert_sha256.len(), 64);
}
```

- [ ] **Step 5: Run / fix / commit**

```bash
cargo test -p pam_certauth_core cert_claims
git commit -am "feat(core): CertClaims with scopes + SKI + cert_sha256"
```

---

## Phase 2 — `pam_certauth_policy` крейт

### Task 2.1 — Bootstrap crate + Cargo wiring

**Files:**
- Create: `crates/pam_certauth_policy/Cargo.toml`
- Create: `crates/pam_certauth_policy/src/lib.rs`
- Modify: workspace `Cargo.toml` (add member)

- [ ] **Step 1: Workspace member**

`Cargo.toml`:
```toml
members = [
    "crates/pam_certauth_core",
    "crates/pam_certauth_proto",
    "crates/pam_certauth",
    "crates/pam_certauth_cli",
    "crates/pam_certauth_policy",
]
```

- [ ] **Step 2: Crate Cargo.toml**

```toml
[package]
name = "pam_certauth_policy"
version.workspace = true
edition.workspace = true
rust-version.workspace = true
license.workspace = true
repository.workspace = true
authors.workspace = true
description = "Policy parser and rule resolver for pam_certauth."

[dependencies]
serde = { workspace = true }
toml = { workspace = true }
thiserror = { workspace = true }
sha2 = { workspace = true }
hex = { workspace = true }
```

- [ ] **Step 3: lib.rs skeleton**

```rust
//! Policy parser + rule resolver. See `docs/policy.md`.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("validation: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditLevel {
    Info,
    Notice,
    Warning,
    Critical,
}

impl Default for AuditLevel { fn default() -> Self { Self::Info } }

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawScopeRule {
    pub m_of_n: Option<u8>,
    pub require_argv_pattern: Option<bool>,
    pub forbid_self_approval: Option<bool>,
    pub require_timestamp_token: Option<bool>,
    pub audit_level: Option<AuditLevel>,
    #[serde(default)]
    pub pre_hooks: Vec<String>,
    #[serde(default)]
    pub post_hooks: Vec<String>,
    pub timeout_seconds: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RawPolicy {
    #[serde(default)]
    pub defaults: RawScopeRule,
    #[serde(default)]
    pub scope: HashMap<String, RawScopeRule>,
}

#[derive(Debug, Clone)]
pub struct Policy {
    raw: RawPolicy,
    sha256: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ScopeRule {
    pub m_of_n: u8,
    pub require_argv_pattern: bool,
    pub forbid_self_approval: bool,
    pub require_timestamp_token: bool,
    pub audit_level: AuditLevel,
    pub pre_hooks: Vec<String>,
    pub post_hooks: Vec<String>,
    pub timeout_seconds: Option<u64>,
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self, PolicyError> {
        let bytes = std::fs::read(path)?;
        let raw: RawPolicy = toml::from_slice(&bytes)?;
        let sha256 = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&bytes).into()
        };
        let p = Self { raw, sha256 };
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        // см. Task 2.3
        Ok(())
    }

    pub fn sha256(&self) -> &[u8; 32] { &self.sha256 }

    pub fn rule_for(&self, scope: &str) -> ScopeRule {
        // см. Task 2.4
        todo!()
    }
}
```

- [ ] **Step 4: Build**

```bash
cargo build -p pam_certauth_policy
```

- [ ] **Step 5: Commit**

```bash
git commit -am "feat(policy): bootstrap pam_certauth_policy crate"
```

### Task 2.2 — Hash stability test

**Files:**
- Test: `crates/pam_certauth_policy/tests/hash.rs`

- [ ] **Step 1: Write test**

```rust
use pam_certauth_policy::Policy;
use std::fs;
use std::path::PathBuf;

fn write_tmp(contents: &str) -> PathBuf {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("policy.toml");
    fs::write(&p, contents).unwrap();
    std::mem::forget(dir); // не удалять до конца теста
    p
}

#[test]
fn sha256_is_stable_across_loads() {
    let p1 = Policy::load(&write_tmp("[defaults]\nm_of_n = 1\n")).unwrap();
    let p2 = Policy::load(&write_tmp("[defaults]\nm_of_n = 1\n")).unwrap();
    assert_eq!(p1.sha256(), p2.sha256());
}

#[test]
fn sha256_changes_on_trailing_newline() {
    let p1 = Policy::load(&write_tmp("[defaults]\nm_of_n = 1")).unwrap();
    let p2 = Policy::load(&write_tmp("[defaults]\nm_of_n = 1\n")).unwrap();
    assert_ne!(p1.sha256(), p2.sha256());
}
```

Add `tempfile` to `[dev-dependencies]`.

- [ ] **Step 2: Run — pass (load is implemented already)**

```bash
cargo test -p pam_certauth_policy
```

- [ ] **Step 3: Commit**

```bash
git commit -am "test(policy): hash stability tests"
```

### Task 2.3 — `validate()` implementation

**Files:**
- Modify: `crates/pam_certauth_policy/src/lib.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod validate_tests {
    use super::*;
    use std::path::PathBuf;

    fn load(s: &str) -> Result<Policy, PolicyError> {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("policy.toml");
        std::fs::write(&p, s).unwrap();
        let r = Policy::load(&p);
        std::mem::forget(dir);
        r
    }

    #[test]
    fn rejects_zero_m_of_n() {
        let err = load("[scope.\"x\"]\nm_of_n = 0\n").unwrap_err();
        assert!(matches!(err, PolicyError::Validation(_)));
    }

    #[test]
    fn rejects_missing_m_of_n_after_defaults_unset() {
        let err = load("[scope.\"x\"]\n").unwrap_err();
        // нет m_of_n ни в defaults, ни в scope.x → fail
        assert!(matches!(err, PolicyError::Validation(_)));
    }

    #[test]
    fn rejects_unknown_hook_name() {
        let err = load("[defaults]\nm_of_n = 1\n[scope.\"x\"]\npre_hooks = [\"unknown\"]\n").unwrap_err();
        assert!(matches!(err, PolicyError::Validation(s) if s.contains("unknown")));
    }

    #[test]
    fn accepts_valid_policy() {
        let p = load("[defaults]\nm_of_n = 1\n[scope.\"bios.flash\"]\nm_of_n = 2\n").unwrap();
        assert_eq!(p.sha256().len(), 32);
    }
}
```

- [ ] **Step 2: Implement `validate()`**

```rust
const KNOWN_HOOKS: &[&str] = &["noop", "audit_critical"];

impl Policy {
    pub fn validate(&self) -> Result<(), PolicyError> {
        // m_of_n должно быть определено (в defaults или в scope)
        let default_m = self.raw.defaults.m_of_n;
        for (name, rule) in &self.raw.scope {
            let m = rule.m_of_n.or(default_m).ok_or_else(|| {
                PolicyError::Validation(format!(
                    "scope {name:?} has no m_of_n and defaults.m_of_n is unset"
                ))
            })?;
            if m == 0 {
                return Err(PolicyError::Validation(format!(
                    "scope {name:?} has m_of_n = 0"
                )));
            }
            for hook in rule.pre_hooks.iter().chain(rule.post_hooks.iter()) {
                if !KNOWN_HOOKS.contains(&hook.as_str()) {
                    return Err(PolicyError::Validation(format!(
                        "scope {name:?} references unknown hook {hook:?}"
                    )));
                }
            }
        }
        Ok(())
    }
}
```

- [ ] **Step 3: Run + fix + commit**

```bash
cargo test -p pam_certauth_policy
git commit -am "feat(policy): validate() catches zero m_of_n, missing m_of_n, unknown hooks"
```

### Task 2.4 — `rule_for()` with wildcard precedence

**Files:**
- Modify: `crates/pam_certauth_policy/src/lib.rs`

- [ ] **Step 1: Failing tests**

```rust
#[cfg(test)]
mod rule_for_tests {
    use super::*;

    fn load(s: &str) -> Policy { /* same helper */ }

    #[test]
    fn exact_match_wins_over_wildcard() {
        let p = load("\
[defaults]
m_of_n = 1
[scope.\"bios.*\"]
m_of_n = 3
[scope.\"bios.flash\"]
m_of_n = 2
");
        assert_eq!(p.rule_for("bios.flash").m_of_n, 2);
    }

    #[test]
    fn wildcard_falls_through() {
        let p = load("\
[defaults]
m_of_n = 1
[scope.\"bios.*\"]
m_of_n = 3
");
        assert_eq!(p.rule_for("bios.erase").m_of_n, 3);
    }

    #[test]
    fn defaults_used_when_nothing_matches() {
        let p = load("\
[defaults]
m_of_n = 1
audit_level = \"info\"
");
        let r = p.rule_for("random.thing");
        assert_eq!(r.m_of_n, 1);
        assert_eq!(r.audit_level, AuditLevel::Info);
    }

    #[test]
    fn forbid_self_approval_defaults_true() {
        let p = load("[defaults]\nm_of_n = 1\n");
        assert!(p.rule_for("any").forbid_self_approval);
    }
}
```

- [ ] **Step 2: Implement**

```rust
impl Policy {
    pub fn rule_for(&self, scope: &str) -> ScopeRule {
        // Поиск порядка: exact → prefix-wildcards (longest first) → defaults
        let mut candidate: Option<&RawScopeRule> = self.raw.scope.get(scope);
        if candidate.is_none() {
            let mut best: Option<(usize, &RawScopeRule)> = None;
            for (k, v) in &self.raw.scope {
                if let Some(prefix) = k.strip_suffix(".*") {
                    let prefix_with_dot = format!("{prefix}.");
                    if scope.starts_with(&prefix_with_dot) || scope == prefix {
                        let len = prefix.len();
                        if best.map_or(true, |(blen, _)| len > blen) {
                            best = Some((len, v));
                        }
                    }
                }
            }
            candidate = best.map(|(_, v)| v);
        }
        let merge = |field_from_specific: Option<_>, default: _| field_from_specific.unwrap_or(default);
        let d = &self.raw.defaults;
        let s = candidate.unwrap_or(d);
        ScopeRule {
            m_of_n: s.m_of_n.or(d.m_of_n).unwrap_or(1),
            require_argv_pattern: s.require_argv_pattern.or(d.require_argv_pattern).unwrap_or(false),
            forbid_self_approval: s.forbid_self_approval.or(d.forbid_self_approval).unwrap_or(true),
            require_timestamp_token: s.require_timestamp_token.or(d.require_timestamp_token).unwrap_or(false),
            audit_level: s.audit_level.or(d.audit_level).unwrap_or(AuditLevel::Info),
            pre_hooks: if !s.pre_hooks.is_empty() { s.pre_hooks.clone() } else { d.pre_hooks.clone() },
            post_hooks: if !s.post_hooks.is_empty() { s.post_hooks.clone() } else { d.post_hooks.clone() },
            timeout_seconds: s.timeout_seconds.or(d.timeout_seconds),
        }
    }
}
```

- [ ] **Step 3: Pass + commit**

```bash
cargo test -p pam_certauth_policy
git commit -am "feat(policy): rule_for() with wildcard precedence and defaults merge"
```

---

## Phase 3 — Config: `[approver_trust]`, `[tsa_trust]`, `[policy]`

### Task 3.1 — Add raw config sections

**Files:**
- Modify: `crates/pam_certauth_core/src/config/raw.rs`
- Modify: `crates/pam_certauth_core/src/config/validated.rs`

- [ ] **Step 1: Locate existing trust section**

```bash
rg "RawTrust" crates/pam_certauth_core/src/config/
```

- [ ] **Step 2: Add new raw fields**

`raw.rs` (после существующего `pub trust: RawTrust`):
```rust
#[serde(default)]
pub approver_trust: Option<RawTrust>,
#[serde(default)]
pub tsa_trust: Option<RawTrust>,
#[serde(default)]
pub policy: RawPolicySection,
```

```rust
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RawPolicySection {
    pub path: Option<PathBuf>,                  // default /etc/pam_certauth/policy.toml
    pub krl_poll_interval_seconds: Option<u64>, // default 300
    #[serde(default = "default_require_approver_eku")]
    pub require_approver_eku: bool,
    pub signing_time_skew_seconds: Option<u64>, // default 300
}

fn default_require_approver_eku() -> bool { true }
```

Validated layer (`validated.rs`) — параллельно: новые поля `approver_trust: Option<TrustSection>`, `tsa_trust: Option<TrustSection>`, `policy: PolicySection`.

- [ ] **Step 3: Write test for parsing**

`crates/pam_certauth_core/tests/config_approver_trust.rs`:
```rust
#[test]
fn config_with_approver_trust_parses() {
    let toml = r#"
[trust]
anchors = ["/etc/pam_certauth/ca.pem"]

[approver_trust]
anchors = ["/etc/pam_certauth/approver_ca.pem"]

[policy]
path = "/etc/pam_certauth/policy.toml"
krl_poll_interval_seconds = 300
"#;
    let raw: pam_certauth_core::config::raw::RawConfig = toml::from_str(toml).unwrap();
    assert!(raw.approver_trust.is_some());
    assert_eq!(raw.policy.krl_poll_interval_seconds, Some(300));
    assert!(raw.policy.require_approver_eku);
}
```

- [ ] **Step 4: Run + fix + commit**

```bash
cargo test -p pam_certauth_core config
git commit -am "feat(config): add approver_trust, tsa_trust, policy sections"
```

### Task 3.2 — Validated layer: load approver_trust anchors

**Files:**
- Modify: `crates/pam_certauth_core/src/config/validated.rs`

- [ ] **Step 1: Reuse validate_trust**

Существующая `validate_trust(&raw.trust)` уже валидирует pem-чтение. Звать её для approver_trust / tsa_trust если они присутствуют.

- [ ] **Step 2: Test**

```rust
#[test]
fn validated_approver_trust_loads_pem() {
    // подготовить tempdir с self-signed ca.pem, см. host_binding tests helpers
    // …
}
```

- [ ] **Step 3: Implement + commit**

```bash
git commit -am "feat(config): validate approver_trust + tsa_trust + policy sections"
```

---

## Phase 4 — CMS work order verifier

### Task 4.1 — Module skeleton + DoS guard

**Files:**
- Create: `crates/pam_certauth_core/src/cms.rs`
- Modify: `crates/pam_certauth_core/src/lib.rs`

- [ ] **Step 1: Skeleton**

```rust
//! CMS (RFC 5652) work order verifier for M-of-N approvals.
//!
//! See `docs/work-order.md` and spec §4.

use openssl::cms::{CmsContentInfo, CMSOptions};
use openssl::stack::Stack;
use openssl::x509::store::X509Store;
use openssl::x509::{X509, X509Ref};
use thiserror::Error;

const MAX_CMS_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum CmsVerifyError {
    #[error("cms too large: {0} bytes (cap {1})")]
    TooLarge(usize, usize),
    #[error("cms parse: {0}")]
    Parse(String),
    #[error("verify: {0}")]
    Verify(String),
    #[error("insufficient signatures: have {have} need {need}")]
    Insufficient { have: u8, need: u8 },
    #[error("duplicate signer SKI: {0}")]
    DuplicateSki(String),
    #[error("signer cert lacks scope {scope}")]
    ScopeMissing { scope: String },
    #[error("signer cert host mismatch")]
    HostMismatch,
    #[error("signer cert chain terminates at engineer trust anchor")]
    SharedTrustAnchor,
    #[error("signer cert lacks approver EKU")]
    EkuMissing,
    #[error("signing-time outside skew window")]
    SigningTimeOutOfWindow,
    #[error("timestamp token required but missing")]
    TimestampTokenMissing,
    #[error("openssl: {0}")]
    Openssl(String),
}

pub struct VerifyParams<'a> {
    pub approver_store: &'a X509Store,
    pub engineer_store: &'a X509Store,   // для shared-anchor detection
    pub host_id_hash: &'a str,
    pub scope: &'a str,
    pub m_of_n: u8,
    pub require_approver_eku: bool,
    pub require_timestamp_token: bool,
    pub signing_time_skew_seconds: u64,
    pub tsa_store: Option<&'a X509Store>,
}

#[derive(Debug, Clone)]
pub struct VerifiedSigner {
    pub subject_key_identifier: String,   // hex
    pub subject_cn: String,
    pub signing_time: chrono::DateTime<chrono::Utc>,
}

pub fn verify(buffer: &[u8], params: &VerifyParams) -> Result<Vec<VerifiedSigner>, CmsVerifyError> {
    if buffer.len() > MAX_CMS_BYTES {
        return Err(CmsVerifyError::TooLarge(buffer.len(), MAX_CMS_BYTES));
    }
    todo!()
}
```

Зарегистрировать в `lib.rs`: `pub mod cms;`. Добавить deps: `chrono = "0.4"` в workspace.

- [ ] **Step 2: Build + commit skeleton**

```bash
cargo build -p pam_certauth_core
git commit -am "feat(core): cms.rs skeleton + types"
```

### Task 4.2 — Test fixtures: generate signed CMS in tests

**Files:**
- Create: `crates/pam_certauth_core/tests/fixtures/cms_helpers.rs`

- [ ] **Step 1: Helper functions**

```rust
//! Test helpers for generating CMS SignedData from in-memory keys/certs.

use openssl::cms::{CmsContentInfo, CMSOptions};
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::X509;

pub struct Signer {
    pub cert: X509,
    pub key: PKey<Private>,
}

pub fn sign_cms_detached(payload: &[u8], signers: &[Signer]) -> Vec<u8> {
    // Сложный путь: openssl-rust CmsContentInfo::sign() поддерживает один signer.
    // Для multi-signer — нужно либо несколько вызовов с add_signer, либо
    // shell out to `openssl cms`. Goal: оба варианта проверить, выбрать один.
    // Если CmsContentInfo::sign не поддерживает add — fallback shell.
    todo!("see task 4.3")
}
```

- [ ] **Step 2: Verify openssl-rust binding for multi-signer**

```bash
rg "add_signer|CmsContentInfo" $(rustc --print sysroot)/lib/rustlib/src/rust 2>/dev/null
# или: cargo doc -p openssl --open и проверить.
```

Если `CmsContentInfo` Rust-API не имеет multi-signer добавления — использовать `process::Command::new("openssl")` shell-out в test-helper'е. Зафиксировать решение в `cms_helpers.rs` комментарием.

- [ ] **Step 3: Commit helper**

```bash
git commit -am "test(core): cms helpers for generating multi-signer fixtures"
```

### Task 4.3 — `cms::verify` implementation — happy path

**Files:**
- Modify: `crates/pam_certauth_core/src/cms.rs`
- Test: `crates/pam_certauth_core/tests/cms_happy.rs`

- [ ] **Step 1: Failing test**

```rust
use pam_certauth_core::cms::{verify, VerifyParams};
// fixture helpers — генерируют CA, approver certs со scopes-ext, host-ext, sign payload.

#[test]
fn verify_m2_n2_happy() {
    let (approver_store, signers) = make_approver_store_and_signers(
        2,
        &["bios.flash"],
        "host-hash-A",
    );
    let payload = b""; // пустой TOML
    let cms = sign_cms_detached(payload, &signers);
    let engineer_store = make_disjoint_engineer_store();
    let result = verify(&cms, &VerifyParams {
        approver_store: &approver_store,
        engineer_store: &engineer_store,
        host_id_hash: "host-hash-A",
        scope: "bios.flash",
        m_of_n: 2,
        require_approver_eku: false, // в первом тесте EKU не выпускаем
        require_timestamp_token: false,
        signing_time_skew_seconds: 300,
        tsa_store: None,
    });
    let signers = result.expect("verify ok");
    assert_eq!(signers.len(), 2);
    // SKI должны быть разные
    assert_ne!(signers[0].subject_key_identifier, signers[1].subject_key_identifier);
}
```

- [ ] **Step 2: Implement happy path**

```rust
pub fn verify(buffer: &[u8], params: &VerifyParams) -> Result<Vec<VerifiedSigner>, CmsVerifyError> {
    if buffer.len() > MAX_CMS_BYTES {
        return Err(CmsVerifyError::TooLarge(buffer.len(), MAX_CMS_BYTES));
    }
    let cms = CmsContentInfo::from_der(buffer)
        .map_err(|e| CmsVerifyError::Parse(e.to_string()))?;

    // Verify cryptographic correctness against approver_store
    let mut out_certs: Stack<X509> = Stack::new()
        .map_err(|e| CmsVerifyError::Openssl(e.to_string()))?;
    cms.verify(
        None,
        Some(params.approver_store),
        None,
        Some(&mut out_certs),
        CMSOptions::DETACHED | CMSOptions::BINARY,
    ).map_err(|e| CmsVerifyError::Verify(e.to_string()))?;

    let signer_certs: Vec<X509> = out_certs.iter().map(|r| r.to_owned()).collect();
    if (signer_certs.len() as u8) < params.m_of_n {
        return Err(CmsVerifyError::Insufficient {
            have: signer_certs.len() as u8, need: params.m_of_n,
        });
    }

    let mut seen_ski = std::collections::HashSet::new();
    let mut verified: Vec<VerifiedSigner> = Vec::new();
    for cert in &signer_certs {
        let ski = cert.subject_key_id()
            .ok_or_else(|| CmsVerifyError::Openssl("signer cert missing SKI".into()))?;
        let ski_hex = hex::encode(ski.as_slice());
        if !seen_ski.insert(ski_hex.clone()) {
            return Err(CmsVerifyError::DuplicateSki(ski_hex));
        }
        // … scope / host / EKU / shared-anchor / signing-time checks (см. Task 4.4-4.8)
        let cn = cert_cn(cert);
        verified.push(VerifiedSigner {
            subject_key_identifier: ski_hex,
            subject_cn: cn,
            signing_time: chrono::Utc::now(), // placeholder, заменить в task 4.7
        });
    }
    Ok(verified)
}

fn cert_cn(cert: &X509Ref) -> String {
    cert.subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().as_utf8().ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}
```

- [ ] **Step 3: Pass test + commit**

```bash
cargo test -p pam_certauth_core --test cms_happy
git commit -am "feat(core): cms::verify happy path with M-of-N + dedup SKI"
```

### Tasks 4.4 - 4.8 — Each verification check has its own task

Каждый следующий check — отдельный таск, TDD-цикл (failing test → implement → pass → commit). Список:

- [ ] **Task 4.4 — scope-ext check on each signer cert (test: `cms_scope_check.rs`)**

  Failing test: подписант без scope→ Err(ScopeMissing). Implement: parse scopes_ext, call contains(). Pass + commit.

- [ ] **Task 4.5 — host_binding-ext check (test: `cms_host_check.rs`)**

  Failing test: signer cert с host=B vs ATM=A → Err(HostMismatch). Implement: parse host_binding_ext, verify_host_binding. Pass + commit.

- [ ] **Task 4.6 — shared trust anchor cross-role rejection (test: `cms_shared_anchor.rs`)**

  Подписант, чья цепочка ведёт в engineer_store → Err(SharedTrustAnchor). Implement: вторая попытка verify против engineer_store; если ok → reject. Pass + commit.

- [ ] **Task 4.7 — signing-time skew check (test: `cms_signing_time.rs`)**

  Signed-attr `signing-time` извлекается через openssl `signed_attributes()`. Failing test: подделанный signing-time в +1 час (за пределами skew=300s) → Err. Implement extraction + comparison. Pass + commit.

- [ ] **Task 4.8 — approver EKU check (test: `cms_eku.rs`)**

  Allocate EKU OID (одного UUID-based), документировать в `oids.rs` как `APPROVER_EKU_OID`. Failing test: cert без EKU при require_approver_eku=true → Err(EkuMissing). Implement: parse extended_key_usage(), check OID present. Pass + commit.

- [ ] **Task 4.9 — TSA TimeStampToken support (test: `cms_tsa.rs`)**

  Failing test: require_timestamp_token=true, CMS без unsigned-attr TSA → Err. Implement: extract unsigned attr `id-aa-timeStampToken` (OID 1.2.840.113549.1.9.16.2.14), verify TSA через openssl Cms over tsa_store. Pass + commit.

  Если openssl-rust не имеет API для unsigned-attrs — задокументировать в spec'е как known gap, оставить enforce в logger (logs warning instead of reject). Создать issue.

---

## Phase 5 — IPC: `get_active_session_by_uid`, extended SessionOpen

### Task 5.1 — Proto messages

**Files:**
- Modify: `crates/pam_certauth_proto/src/{client,server,version}.rs`

- [ ] **Step 1: Bump PROTOCOL_VERSION**

```rust
// version.rs
pub const PROTOCOL_VERSION: u32 = 2;
```

- [ ] **Step 2: New ClientMessage variant**

```rust
// client.rs
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    // existing variants…
    GetActiveSessionByUid { uid: u32 },
    SessionOpen(SessionOpenPayload),   // обновлённый payload — см. ниже
    // …
}
```

В `SessionOpenPayload` добавить `engineer_ski: String`, `engineer_cert_sha256: String`, `scopes: Vec<String>` (опционально для совместимости — `#[serde(default)]`).

- [ ] **Step 3: New ServerMessage variant**

```rust
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    // existing…
    ActiveSession {
        session_id: String,
        cert_cn: String,
        engineer_ski: String,
        engineer_cert_sha256: String,
        scopes: Vec<String>,
        host_id_hash: String,
    },
    // …
}
```

- [ ] **Step 4: Error code 1200 = NO_ACTIVE_SESSION**

```rust
// server.rs error codes table
pub const NO_ACTIVE_SESSION: u32 = 1200;
```

Документировать в spec §10.6 (но spec уже фиксирован — добавить в `docs/architecture.md` или `docs/ipc.md` в Phase 12).

- [ ] **Step 5: Tests for serde roundtrip + version negotiation**

`crates/pam_certauth_proto/tests/v2_messages.rs`:
```rust
#[test]
fn get_active_session_by_uid_roundtrip() {
    let m = ClientMessage::GetActiveSessionByUid { uid: 1000 };
    let j = serde_json::to_string(&m).unwrap();
    assert!(j.contains("\"type\":\"get_active_session_by_uid\""));
    let back: ClientMessage = serde_json::from_str(&j).unwrap();
    assert!(matches!(back, ClientMessage::GetActiveSessionByUid { uid: 1000 }));
}

#[test]
fn active_session_serialises_with_engineer_ski() {
    let m = ServerMessage::ActiveSession {
        session_id: "id".into(), cert_cn: "Alice".into(),
        engineer_ski: "abcd".into(), engineer_cert_sha256: "1234".into(),
        scopes: vec!["bios.flash".into()], host_id_hash: "h".into(),
    };
    let j = serde_json::to_string(&m).unwrap();
    assert!(j.contains("engineer_ski"));
}
```

- [ ] **Step 6: Run + commit**

```bash
cargo test -p pam_certauth_proto
git commit -am "feat(proto): v2 messages — get_active_session_by_uid, engineer_ski in active_session and session_open"
```

### Task 5.2 — PAM cdylib emits engineer_ski + cert_sha256 in SessionOpen

**Files:**
- Modify: `crates/pam_certauth/src/pam.rs` (или где SessionOpen формируется)

- [ ] **Step 1: Find emission point**

```bash
rg "SessionOpen" crates/pam_certauth/src/
```

- [ ] **Step 2: Add SKI + sha256 to payload**

После cert-validation:
```rust
let claims = pam_certauth_core::cert_claims::CertClaims::from_cert(&cert)?;
let payload = SessionOpenPayload {
    // existing fields…
    engineer_ski: claims.subject_key_identifier,
    engineer_cert_sha256: claims.cert_sha256,
    scopes: claims.scopes.iter().map(|s| match s {
        Scope::Wildcard => "*".to_string(),
        Scope::Exact(s) => s.clone(),
    }).collect(),
};
```

- [ ] **Step 3: Existing PAM integration tests pass + commit**

```bash
cargo test -p pam_certauth
git commit -am "feat(pam): include engineer_ski + cert_sha256 + scopes in SessionOpen"
```

---

## Phase 6 — monitord registry by uid + handler

### Task 6.1 — Registry index by uid

**Files:**
- Modify: `crates/pam_certauth_cli/src/registry.rs` (или `registry/mod.rs`)

- [ ] **Step 1: Failing test**

```rust
#[test]
fn lookup_by_uid_returns_engineer_ski() {
    let mut reg = Registry::new();
    reg.insert_session(SessionRecord {
        uid: 1000,
        session_id: "s1".into(),
        engineer_ski: "abcd".into(),
        engineer_cert_sha256: "1234".into(),
        scopes: vec!["bios.flash".into()],
        host_id_hash: "h".into(),
        cert_cn: "Alice".into(),
        // …
    });
    let found = reg.find_by_uid(1000).expect("session present");
    assert_eq!(found.engineer_ski, "abcd");
}
```

- [ ] **Step 2: Implement**

Расширь существующий Registry struct полем `by_uid: HashMap<u32, SessionId>`. Обновлять при insert / remove. Добавь `find_by_uid(&self, uid: u32) -> Option<&SessionRecord>`.

- [ ] **Step 3: Run + commit**

```bash
cargo test -p pam_certauth_cli
git commit -am "feat(registry): index sessions by uid for active-session lookup"
```

### Task 6.2 — IPC handler `GetActiveSessionByUid`

**Files:**
- Modify: `crates/pam_certauth_cli/src/server.rs`

- [ ] **Step 1: Failing integration test**

`crates/pam_certauth_cli/tests/ipc_active_session.rs`:
```rust
#[tokio::test]
async fn get_active_session_returns_engineer_ski() {
    let (server, client) = in_process_server_pair().await;
    server.registry().insert_session(make_record(1000, "abcd")).await;

    let req = ClientMessage::GetActiveSessionByUid { uid: 1000 };
    let resp: ServerMessage = client.request(req).await.unwrap();
    match resp {
        ServerMessage::ActiveSession { engineer_ski, .. } => {
            assert_eq!(engineer_ski, "abcd");
        }
        other => panic!("unexpected: {other:?}"),
    }
}

#[tokio::test]
async fn get_active_session_no_match_returns_1200() {
    let (server, client) = in_process_server_pair().await;
    let req = ClientMessage::GetActiveSessionByUid { uid: 999 };
    let resp = client.request(req).await.unwrap();
    assert!(matches!(resp, ServerMessage::Error { code: 1200, .. }));
}
```

- [ ] **Step 2: Implement handler**

В match-арм для ClientMessage в `server.rs`:
```rust
ClientMessage::GetActiveSessionByUid { uid } => {
    match state.registry.find_by_uid(uid).await {
        Some(rec) => ServerMessage::ActiveSession {
            session_id: rec.session_id.clone(),
            cert_cn: rec.cert_cn.clone(),
            engineer_ski: rec.engineer_ski.clone(),
            engineer_cert_sha256: rec.engineer_cert_sha256.clone(),
            scopes: rec.scopes.clone(),
            host_id_hash: rec.host_id_hash.clone(),
        },
        None => ServerMessage::Error {
            code: NO_ACTIVE_SESSION,
            message: format!("no active session for uid {uid}"),
        },
    }
}
```

- [ ] **Step 3: Pass + commit**

```bash
cargo test -p pam_certauth_cli
git commit -am "feat(monitord): handle GetActiveSessionByUid + 1200 error"
```

---

## Phase 7 — `pam-certauth execute` subcommand

### Task 7.1 — CLI parse + IPC connect

**Files:**
- Modify: `crates/pam_certauth_cli/src/main.rs`
- Create: `crates/pam_certauth_cli/src/execute/mod.rs`
- Create: `crates/pam_certauth_cli/src/execute/cli.rs`

- [ ] **Step 1: CLI struct**

`execute/cli.rs`:
```rust
use clap::Args;
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct ExecuteArgs {
    /// Scope name (e.g. "bios.flash") — обязателен. Без него — explain mode.
    #[arg(long)]
    pub scope: Option<String>,

    /// Path to CMS work order file
    #[arg(long)]
    pub work_order: Option<PathBuf>,

    /// Command and args after `--`
    #[arg(last = true, required = true)]
    pub cmd: Vec<String>,
}
```

- [ ] **Step 2: Subcommand wiring**

`main.rs`:
```rust
enum Cmd {
    Daemon,
    Execute(execute::cli::ExecuteArgs),
}

// …
Cmd::Execute(args) => execute::run(args),
```

- [ ] **Step 3: Test: parse**

```rust
#[test]
fn parses_execute_with_scope_and_work_order_and_cmd() {
    use clap::Parser;
    let cli = super::Cli::parse_from([
        "pam-certauth", "execute",
        "--scope", "bios.flash",
        "--work-order", "/tmp/wo.cms",
        "--", "flashrom", "-w", "fw.bin",
    ]);
    let Cmd::Execute(args) = cli.cmd else { panic!() };
    assert_eq!(args.scope.as_deref(), Some("bios.flash"));
    assert_eq!(args.cmd, vec!["flashrom", "-w", "fw.bin"]);
}
```

- [ ] **Step 4: Commit**

```bash
git commit -am "feat(cli): execute subcommand argument parsing"
```

### Task 7.2 — Read work_order file with O_NOFOLLOW + size cap

**Files:**
- Create: `crates/pam_certauth_cli/src/execute/work_order.rs`

- [ ] **Step 1: Failing test**

```rust
#[test]
fn read_rejects_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.cms");
    std::fs::write(&real, b"hi").unwrap();
    let link = dir.path().join("link.cms");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let err = read_work_order(&link).unwrap_err();
    assert!(matches!(err, WorkOrderError::SymlinkRejected));
}

#[test]
fn read_caps_size() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("big.cms");
    let big = vec![0u8; 11 * 1024 * 1024];
    std::fs::write(&p, &big).unwrap();
    let err = read_work_order(&p).unwrap_err();
    assert!(matches!(err, WorkOrderError::TooLarge(_, _)));
}
```

- [ ] **Step 2: Implement**

```rust
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use thiserror::Error;

const MAX_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum WorkOrderError {
    #[error("symlink rejected")]
    SymlinkRejected,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("too large: {0} bytes (cap {1})")]
    TooLarge(usize, usize),
}

pub fn read_work_order(path: &Path) -> Result<Vec<u8>, WorkOrderError> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    opts.custom_flags(libc::O_NOFOLLOW);
    let mut f = match opts.open(path) {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(WorkOrderError::SymlinkRejected);
        }
        Err(e) => return Err(e.into()),
    };
    let meta = f.metadata()?;
    if meta.len() as usize > MAX_BYTES {
        return Err(WorkOrderError::TooLarge(meta.len() as usize, MAX_BYTES));
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    use std::io::Read;
    f.read_to_end(&mut buf)?;
    if buf.len() > MAX_BYTES {
        return Err(WorkOrderError::TooLarge(buf.len(), MAX_BYTES));
    }
    Ok(buf)
}

pub fn sha256_hex(buf: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(buf))
}
```

`libc` уже должен быть в зависимостях; иначе добавить.

- [ ] **Step 3: Pass + commit**

```bash
cargo test -p pam_certauth_cli execute::work_order
git commit -am "feat(execute): read work_order with O_NOFOLLOW and 10MB cap"
```

### Task 7.3 — argv sanitization + canonical join

**Files:**
- Create: `crates/pam_certauth_cli/src/execute/argv.rs`

- [ ] **Step 1: Failing tests**

```rust
#[test]
fn rejects_nul_byte() {
    let r = canonicalize_and_validate(&["flash\0rom".into()]);
    assert!(matches!(r, Err(ArgvError::InvalidByte)));
}

#[test]
fn rejects_control_char() {
    let r = canonicalize_and_validate(&["foo\nbar".into()]);
    assert!(r.is_err());
}

#[test]
fn joins_with_shell_escape() {
    let canonical = canonicalize_and_validate(&[
        "/bin/echo".into(), "hello world".into(), "x".into()
    ]).unwrap();
    assert_eq!(canonical.joined, "/bin/echo 'hello world' x");
}

#[test]
fn resolves_cmd0_to_realpath() {
    // /bin/sh → /usr/bin/sh on Astra usually
    let canonical = canonicalize_and_validate(&["sh".into()]).unwrap();
    assert!(canonical.joined.starts_with("/"));
}
```

- [ ] **Step 2: Implement**

```rust
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArgvError {
    #[error("argv element contains invalid byte (NUL/control)")]
    InvalidByte,
    #[error("non-NFC unicode in argv")]
    NonNfc,
    #[error("cmd[0] not found in PATH or invalid: {0}")]
    NotFound(String),
}

pub struct CanonicalArgv {
    pub argv0_resolved: PathBuf,
    pub joined: String,
}

pub fn canonicalize_and_validate(argv: &[String]) -> Result<CanonicalArgv, ArgvError> {
    if argv.is_empty() {
        return Err(ArgvError::NotFound("empty argv".into()));
    }
    for elem in argv {
        if elem.bytes().any(|b| b == 0 || b.is_ascii_control()) {
            return Err(ArgvError::InvalidByte);
        }
        if !is_nfc(elem) {
            return Err(ArgvError::NonNfc);
        }
    }
    let argv0 = resolve_in_path(&argv[0])?;
    let argv0_resolved = std::fs::canonicalize(&argv0)
        .map_err(|_| ArgvError::NotFound(argv[0].clone()))?;

    let mut parts: Vec<String> = Vec::with_capacity(argv.len());
    parts.push(argv0_resolved.to_string_lossy().to_string());
    for arg in &argv[1..] {
        parts.push(shell_escape(arg));
    }
    Ok(CanonicalArgv {
        argv0_resolved,
        joined: parts.join(" "),
    })
}

fn shell_escape(s: &str) -> String {
    if s.bytes().all(|b| matches!(b, b'a'..=b'z'|b'A'..=b'Z'|b'0'..=b'9'|b'_'|b'-'|b'/'|b'.'|b':')) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

fn resolve_in_path(cmd: &str) -> Result<PathBuf, ArgvError> {
    if cmd.contains('/') {
        return Ok(PathBuf::from(cmd));
    }
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/sbin:/usr/bin:/sbin:/bin".to_string());
    for dir in path.split(':') {
        let candidate = std::path::Path::new(dir).join(cmd);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(ArgvError::NotFound(cmd.to_string()))
}

fn is_nfc(s: &str) -> bool {
    use unicode_normalization::UnicodeNormalization;
    s.nfc().eq(s.chars())
}
```

Добавить `unicode-normalization` в workspace deps.

- [ ] **Step 3: Pass + commit**

```bash
cargo test -p pam_certauth_cli execute::argv
git commit -am "feat(execute): argv canonicalization with NFC + NUL/control rejection"
```

### Task 7.4 — Glob matcher for argv_pattern

**Files:**
- Create: `crates/pam_certauth_cli/src/execute/glob.rs`

- [ ] **Step 1: Failing tests**

```rust
#[test]
fn star_matches_any_chars() {
    assert!(glob_match("flash *.bin", "flash fw.bin"));
    assert!(!glob_match("flash *.bin", "flash fw.txt"));
}

#[test]
fn question_matches_single_char() {
    assert!(glob_match("v?", "v1"));
    assert!(!glob_match("v?", "vab"));
}

#[test]
fn bracket_class_matches_set() {
    assert!(glob_match("v[0-9]", "v3"));
}

#[test]
fn pattern_with_dashes_disallowed_in_validate() {
    let r = validate_pattern("foo -- bar");
    assert!(matches!(r, Err(GlobError::ContainsDoubleDash)));
}
```

- [ ] **Step 2: Implement**

Use existing `globset` или `wildmatch` crate. Add to workspace deps `wildmatch = "2"`.

```rust
use thiserror::Error;
use wildmatch::WildMatchPattern;

#[derive(Debug, Error)]
pub enum GlobError {
    #[error("pattern contains '--' literal which is forbidden")]
    ContainsDoubleDash,
}

pub fn validate_pattern(p: &str) -> Result<(), GlobError> {
    if p.split_whitespace().any(|tok| tok == "--") {
        return Err(GlobError::ContainsDoubleDash);
    }
    Ok(())
}

pub fn glob_match(pattern: &str, candidate: &str) -> bool {
    WildMatchPattern::<'*', '?'>::new(pattern).matches(candidate)
    // bracket classes — если wildmatch не поддерживает, расширить или использовать globset
}
```

Если bracket-classes требуются — взять `globset::Glob`. Adjust accordingly. Tests must reflect actual supported features.

- [ ] **Step 3: Pass + commit**

```bash
cargo test -p pam_certauth_cli execute::glob
git commit -am "feat(execute): glob matcher + double-dash rejection for argv_pattern"
```

### Task 7.5 — Child process spawn + env scrub + cwd

**Files:**
- Create: `crates/pam_certauth_cli/src/execute/child.rs`

- [ ] **Step 1: Failing test**

```rust
#[test]
fn env_is_scrubbed_to_whitelist() {
    std::env::set_var("EVIL", "should_be_gone");
    std::env::set_var("PAM_CERTAUTH_FOO", "kept");
    let env = build_child_env();
    assert!(!env.contains_key("EVIL"));
    assert_eq!(env.get("PAM_CERTAUTH_FOO").map(|s| s.as_str()), Some("kept"));
    assert_eq!(env.get("PATH").map(|s| s.as_str()), Some("/usr/sbin:/usr/bin:/sbin:/bin"));
}
```

- [ ] **Step 2: Implement**

```rust
use std::collections::HashMap;

pub fn build_child_env() -> HashMap<String, String> {
    const WHITELIST: &[&str] = &["LANG", "TERM", "HOME", "USER", "LOGNAME"];
    let mut env: HashMap<String, String> = HashMap::new();
    env.insert("PATH".into(), "/usr/sbin:/usr/bin:/sbin:/bin".into());
    for &k in WHITELIST {
        if let Ok(v) = std::env::var(k) {
            env.insert(k.into(), v);
        }
    }
    // LC_*
    for (k, v) in std::env::vars() {
        if k.starts_with("LC_") || k.starts_with("PAM_CERTAUTH_") {
            env.insert(k, v);
        }
    }
    env
}
```

- [ ] **Step 3: Pass + commit**

```bash
git commit -am "feat(execute): build_child_env with whitelist + PAM_CERTAUTH_* passthrough"
```

### Task 7.6 — Spawn with setpgid + signal forwarding + timeout

**Files:**
- Modify: `crates/pam_certauth_cli/src/execute/child.rs`

- [ ] **Step 1: Failing test (timeout)**

```rust
#[test]
fn timeout_sends_sigterm_then_sigkill() {
    let result = run_child_with_timeout(
        std::path::Path::new("/bin/sleep"),
        &["10".into()],
        std::collections::HashMap::new(),
        std::env::current_dir().unwrap(),
        Some(std::time::Duration::from_millis(500)),
    );
    assert_eq!(result.exit_code, 124);
}
```

- [ ] **Step 2: Implement spawn loop**

```rust
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

pub struct ChildResult {
    pub exit_code: i32,
}

pub fn run_child_with_timeout(
    argv0: &Path, args: &[String],
    env: std::collections::HashMap<String, String>,
    cwd: std::path::PathBuf,
    timeout: Option<Duration>,
) -> ChildResult {
    let mut cmd = Command::new(argv0);
    cmd.args(args).env_clear().envs(&env).current_dir(&cwd);
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0))
                .map_err(|e| std::io::Error::from_raw_os_error(e as i32))?;
            Ok(())
        });
    }
    let mut child = cmd.spawn().expect("spawn failed");
    let pid = Pid::from_raw(child.id() as i32);

    // Install signal forwarding (simplified: registers SIGINT/SIGTERM/...)
    let pgid_neg = Pid::from_raw(-(pid.as_raw()));
    let forward = setup_signal_forwarder(pgid_neg);

    let start = std::time::Instant::now();
    loop {
        match child.try_wait().expect("waitpid") {
            Some(status) => {
                forward.detach();
                let code = status.code().unwrap_or_else(|| {
                    // exit-by-signal: 128+signum
                    128 + status.signal().unwrap_or(0)
                });
                return ChildResult { exit_code: code };
            }
            None => {
                if let Some(t) = timeout {
                    if start.elapsed() >= t {
                        let _ = kill(pgid_neg, Signal::SIGTERM);
                        std::thread::sleep(Duration::from_secs(5));
                        let _ = kill(pgid_neg, Signal::SIGKILL);
                        let _ = child.wait();
                        forward.detach();
                        return ChildResult { exit_code: 124 };
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

struct SignalForwarder { /* state guard */ }
impl SignalForwarder { fn detach(self) {} }

fn setup_signal_forwarder(pgid: Pid) -> SignalForwarder {
    use signal_hook::consts::*;
    use signal_hook::iterator::Signals;
    let mut signals = Signals::new([
        SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2,
        SIGTSTP, SIGCONT, SIGWINCH,
    ]).expect("signals");
    std::thread::spawn(move || {
        for sig in signals.forever() {
            let _ = kill(pgid, Signal::try_from(sig).unwrap());
        }
    });
    SignalForwarder {}
}
```

Add `signal-hook = "0.3"` to workspace.

- [ ] **Step 3: Pass + commit**

```bash
cargo test -p pam_certauth_cli execute::child
git commit -am "feat(execute): spawn child with setpgid, signal forwarding, timeout"
```

### Task 7.7 — Audit emission via tracing-journald

**Files:**
- Create: `crates/pam_certauth_cli/src/execute/audit.rs`

- [ ] **Step 1: Sanitization helper**

```rust
pub fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\t')
        .collect()
}
```

- [ ] **Step 2: Emit events**

```rust
use tracing::{info, warn, error};

pub fn execute_start(ctx: &AuditCtx) {
    info!(
        target: "pam_certauth.execute",
        event = "execute_start",
        scope = %ctx.scope,
        engineer_cn = %sanitize(&ctx.engineer_cn),
        engineer_ski = %ctx.engineer_ski,
        engineer_session_id = %ctx.session_id,
        policy_sha256 = %ctx.policy_sha256_hex,
        work_order_cms_sha256 = %ctx.cms_sha256_hex,
        approvers = ?ctx.approver_skis,
        argv = ?ctx.argv,
        audit_level = ?ctx.audit_level,
        "execute starting"
    );
}

// execute_done, execute_denied, execute_timeout — аналогично.
```

- [ ] **Step 3: Tests via tracing-test capture**

Use `tracing-subscriber` test helper. Capture events, assert fields present.

- [ ] **Step 4: Commit**

```bash
git commit -am "feat(execute): structured audit events with sanitized strings"
```

### Task 7.8 — End-to-end execute orchestrator

**Files:**
- Modify: `crates/pam_certauth_cli/src/execute/mod.rs`

- [ ] **Step 1: Wire up all pieces**

```rust
pub fn run(args: ExecuteArgs) -> ExitCode {
    let Some(scope) = args.scope.as_deref() else {
        return explain_mode(&args);
    };
    let Some(wo_path) = args.work_order.as_deref() else {
        eprintln!("--work-order is required when --scope is given");
        return ExitCode::from(2);
    };

    let config = load_config()?;
    let policy = pam_certauth_policy::Policy::load(&config.policy.path)?;
    let rule = policy.rule_for(scope);

    let session = ipc::get_active_session()?;  // peercred → uid → IPC
    if !session_has_scope(&session, scope) {
        return audit_denied("engineer cert lacks scope", scope);
    }

    let buf = work_order::read_work_order(wo_path)?;
    let cms_sha = work_order::sha256_hex(&buf);

    let verify = pam_certauth_core::cms::verify(&buf, &cms::params(&config, &rule, &session))?;
    if rule.forbid_self_approval && verify.iter().any(|v| v.subject_key_identifier == session.engineer_ski) {
        return audit_denied("self-approval forbidden", scope);
    }

    let canonical = argv::canonicalize_and_validate(&args.cmd)?;
    if rule.require_argv_pattern {
        let pattern = extract_argv_pattern_from_payload(&buf)?;
        if !glob::glob_match(&pattern, &canonical.joined) {
            return audit_denied("argv_pattern mismatch", scope);
        }
    }

    audit::execute_start(&audit_ctx(scope, &policy, &session, &verify, &canonical, &cms_sha));

    let env = child::build_child_env();
    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("/"));
    let timeout = rule.timeout_seconds.map(std::time::Duration::from_secs);

    let result = child::run_child_with_timeout(&canonical.argv0_resolved, &args.cmd[1..], env, cwd, timeout);

    if result.exit_code == 124 {
        audit::execute_timeout(/* ctx */);
    } else {
        audit::execute_done(/* ctx */, result.exit_code);
    }
    ExitCode::from(result.exit_code as u8)
}
```

- [ ] **Step 2: Integration test happy path**

```rust
#[test]
fn execute_e2e_happy() {
    // setup tempdir with policy.toml, work order, mock monitord
    // run via cargo bin process — assert exit code 0
}
```

- [ ] **Step 3: Commit**

```bash
git commit -am "feat(execute): orchestrate full execute flow"
```

---

## Phase 8 — `pam-certauth policy` subcommand

### Task 8.1 — `policy validate` subcommand

**Files:**
- Create: `crates/pam_certauth_cli/src/policy_cmd/mod.rs`

- [ ] **Step 1: Test**

```rust
#[test]
fn policy_validate_returns_zero_on_valid() {
    let cli = Cli::parse_from(["pam-certauth", "policy", "validate", "--path=/tmp/valid.toml"]);
    // …
}

#[test]
fn policy_validate_returns_nonzero_on_invalid() { /* … */ }
```

- [ ] **Step 2: Implement + commit**

```bash
git commit -am "feat(cli): policy validate subcommand"
```

### Task 8.2 — `policy explain --scope=X` subcommand

**Files:**
- Modify: `crates/pam_certauth_cli/src/policy_cmd/mod.rs`

Печатает effective rule (после merge с defaults и wildcards) для указанного scope.

- [ ] **Implement + test + commit**

```bash
git commit -am "feat(cli): policy explain subcommand"
```

---

## Phase 9 — Hooks framework (static enum)

### Task 9.1 — BuiltinHook enum + dispatcher

**Files:**
- Create: `crates/pam_certauth_cli/src/hooks/mod.rs`

```rust
pub enum BuiltinHook { Noop, AuditCritical }

pub struct HookContext<'a> { /* scope, approvers, … */ }

impl BuiltinHook {
    pub fn from_name(s: &str) -> Option<Self> {
        match s { "noop" => Some(Self::Noop), "audit_critical" => Some(Self::AuditCritical), _ => None }
    }
    pub fn run(&self, ctx: &HookContext) -> Result<(), HookError> { /* … */ }
}
```

`audit_critical` — emits `syslog!(priority=Crit, "pam_certauth_critical scope=...")` через crate `syslog`.

- [ ] **TDD + commit**

```bash
git commit -am "feat(hooks): static enum framework with audit_critical builtin"
```

---

## Phase 10 — PAM `require_scope` list parameter

### Task 10.1 — Parse param list + match modes

**Files:**
- Modify: `crates/pam_certauth/src/pam.rs` (или где парсятся PAM args)

- [ ] **Step 1: Test**

```rust
#[test]
fn parses_require_scope_list_with_match_all() {
    let args = vec!["mode=pkcs11", "require_scope=login.shell,admin", "scope_match=all"];
    let parsed = parse_pam_args(&args);
    assert_eq!(parsed.required_scopes, vec!["login.shell", "admin"]);
    assert_eq!(parsed.scope_match, ScopeMatch::All);
}
```

- [ ] **Step 2: Implement parser + scope check**

После `verify_cert_scope` (host/user) — добавить:
```rust
if !parsed.required_scopes.is_empty() {
    let claims_scopes = parse_scopes_ext(&cert)?;
    let matches = match parsed.scope_match {
        ScopeMatch::Any => parsed.required_scopes.iter()
            .any(|s| scopes_contains(&claims_scopes, s)),
        ScopeMatch::All => parsed.required_scopes.iter()
            .all(|s| scopes_contains(&claims_scopes, s)),
    };
    if !matches {
        return PAM_AUTH_ERR;
    }
}
```

- [ ] **Step 3: Pass + commit**

```bash
git commit -am "feat(pam): require_scope list with scope_match=any|all"
```

---

## Phase 11 — CMS retention store + GC

### Task 11.1 — Persist CMS to /var/lib

**Files:**
- Modify: `crates/pam_certauth_cli/src/execute/mod.rs`
- Create: `crates/pam_certauth_cli/src/retention.rs`

При execute после успешной verify: запись CMS buffer'а в
`/var/lib/pam_certauth/work_orders/<cms_sha256>.cms` (mode 0640).

- [ ] **TDD + commit**

```bash
git commit -am "feat(execute): retain CMS artifact for forensics"
```

### Task 11.2 — GC systemd timer

**Files:**
- Create: `debian/pam-certauth-gc.timer`
- Create: `debian/pam-certauth-gc.service`
- Modify: existing debian install file

```ini
# pam-certauth-gc.timer
[Unit]
Description=GC for pam_certauth retained work orders

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```ini
# pam-certauth-gc.service
[Service]
Type=oneshot
ExecStart=/usr/bin/pam-certauth gc --retention-days=90
```

- [ ] **Implement `gc` subcommand + commit**

```bash
git commit -am "feat(cli): gc subcommand + systemd timer for work order retention"
```

---

## Phase 12 — Docs

### Task 12.1 — `docs/policy.md`

Полный формат policy.toml: all fields, examples — minimal/банк/embedded device, wildcard precedence, merge semantics, validation errors. Cross-link к spec.

### Task 12.2 — `docs/work-order.md`

Как банк формирует CMS: пример `openssl cms -sign -in payload.toml -signer alice.pem -inkey alice.key -nodetach -outform DER -binary -out partial.cms`, как добавляются дополнительные signer'ы (`openssl cms -resign`). Поля payload, signed-attrs обязательные (signing-time, messageDigest, content-type), unsigned TimeStampToken для critical scopes. Validation matrix — что ATM проверяет.

### Task 12.3 — `docs/execute.md`

CLI usage, sudoers пример, exit codes, env scrub, signal forwarding, timeout, examples.

### Task 12.4 — `docs/x509-extensions.md`

Добавить раздел `pam_cert_scopes` (OID, формат, regex, examples) + `approver_eku` OID.

### Task 12.5 — `docs/configuration.md`

Новые секции `[approver_trust]`, `[tsa_trust]`, `[policy]`. Default values. Required vs optional.

### Task 12.6 — `docs/architecture.md`

Обновить компоненты-диаграмму (новый pam_certauth_policy крейт, cms.rs модуль, execute subcommand). Добавить sequence diagram для `pam-certauth execute` flow.

### Task 12.7 — `docs/operations.md`

CMS retention dir, GC timer, journald query examples (`journalctl -u pam-certauth --output=json | jq 'select(.MESSAGE_ID == ...)'`).

### Task 12.8 — `docs/threat-model.md`

Добавить угрозы:
- Компрометация approver-токена mid-window → KRL polling, residual exposure
- Stolen approver token + forged signing-time → skew window, TSA для critical
- Shared trust anchor cross-role → enforced separation в коде
- Root-level policy.toml tampering → hardened ATM, audit drift detection, residual risk
- TOCTOU на work order файле → O_NOFOLLOW + buffer hash
- Log injection через cert_cn / argv → sanitize в audit emission

### Task 12.9 — `docs/migration.md`

С 0.1.x на 0.2.0: новые X.509 extensions (опциональны для PAM-only, обязательны для execute), новые config секции (`[approver_trust]`, `[policy]`), переименование бинаря (`pam-certauth-monitord` → `pam-certauth`), apt upgrade pre/post scripts, обратимая откатка через downgrade пакета.

### Task 12.10 — `docs/ipc.md`

Описать v2 wire protocol: новые messages, version negotiation, error codes table (1200 added).

Commit:
```bash
git commit -am "docs: refresh for scopes + M-of-N (policy, work-order, execute, x509, config, arch, ops, threat, migration, ipc)"
```

---

## Phase 13 — E2E vagrant test rig

### Task 13.1 — Vagrant box bootstrap script

**Files:**
- Modify: `vagrant/` existing setup
- Create: `vagrant/scripts/setup-mof-n-scenario.sh`

Скрипт:
1. Установить deb-пакет pam_certauth 0.2.0.
2. Сгенерить CA (engineer + approver hierarchies).
3. Выпустить engineer PKCS#12 со scopes-ext, host-binding, user-binding.
4. Выпустить 2 approver PKCS#12 со scopes-ext, host-binding, approver-EKU.
5. Сгенерить work order через `openssl cms -sign` дважды (two signers).
6. Установить `/etc/pam_certauth/policy.toml` с scope `test.scope` (m_of_n=2).
7. Скопировать work order на VM.

### Task 13.2 — Happy path test

```bash
# в скрипте vagrant up + ssh:
sudo pam-certauth daemon &
sudo su - testuser -c "pam-certauth execute --scope=test.scope --work-order=/tmp/wo.cms -- /bin/echo hello"
# expected: exit 0, "hello" в stdout, audit event в journald
```

### Task 13.3 — Negative cases

- Одна подпись → exit 2, denied event.
- forbid_self_approval + engineer SKI = signer → reject.
- Expired signer cert → reject.
- argv_pattern mismatch → reject.
- Wrong host_id_hash → reject.

### Task 13.4 — Optional GOST E2E variant

Если `gost-engine` доступен:
- 1 signer GOST, 1 signer RSA, mixed CMS.
- Если openssl-rust не поддерживает GOST CMS — задокументировать gap в migration.md, оставить как known limitation.

### Task 13.5 — CI hook

GitHub Actions: matrix job `e2e-mof-n` запускающий vagrant box smoke-test. Если стоимость CI слишком высока — оставить как nightly only.

Commit:
```bash
git commit -am "test(e2e): vagrant smoke-test for M-of-N happy + negative + optional GOST"
```

---

## Phase 14 — Final integration smoke

### Task 14.1 — Workspace lint + full test

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --features test-support
```

Все зелёные.

### Task 14.2 — Release prep

Bump version → 0.2.0 в workspace. `CHANGELOG.md` запись. README обновление.

Commit:
```bash
git commit -am "release: 0.2.0 with scopes + M-of-N approval"
```

---

## Spec coverage checklist

| Spec section | Plan tasks |
| ------------ | ---------- |
| §1.1 cели | весь plan |
| §3 scopes-ext | Phase 1 |
| §4 CMS verify | Phase 4 |
| §5 policy crate | Phase 2 |
| §2.2 trust separation | Phase 3, Phase 4 (Task 4.6) |
| §2.3 time/revocation | Phase 4 (Task 4.7) + KRL inherit existing |
| §6 execute CLI | Phase 7 |
| §7 IPC v2 | Phase 5, Phase 6 |
| §8 PAM require_scope | Phase 10 |
| §9 audit | Phase 7 (Task 7.7) |
| §10 hooks | Phase 9 |
| §11 compat | внутри каждого таска (back-compat assertions) |
| §12 crate layout | Phase 0 |
| §13 testing | каждая Phase, плюс Phase 13 |
| §14 docs | Phase 12 |

## Fuzz targets (deferred, не блокер MVP)

- `cargo fuzz` target на `cms::verify` — random byte input, must not panic.
- `cargo fuzz` target на `scopes_ext::parse` — same.
- `cargo fuzz` target на `Policy::load` TOML — same.

Размещаются в `fuzz/` crate (new). Запускаются в nightly CI.

---

**End of plan.**
