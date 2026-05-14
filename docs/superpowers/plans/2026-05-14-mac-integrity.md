# MAC Integrity (Astra МКЦ) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Связать максимальный уровень целостности Astra-сессии с расширением X.509 сертификата engineer-токена через libparsec FFI.

**Architecture:** В `pam_certauth_core` появляется модуль `mac/` с типом `IntegrityLabel`, парсером DER-расширения `MAX_INTEGRITY` (OID `2.25.<UUID>`), trait `MacBackend` и двумя реализациями (stub под `default`, FFI к libparsec под feature `astra-mac`). PAM hook `pam_sm_open_session` вычисляет `effective = intersect(cert_max, user_МНКЦ)` и применяет метку. Monitord помечает свой socket `irelax`. Конфигурация `[mac]` в `policy.toml` управляет поведением (`required` / `optional` / `ignore`).

**Tech Stack:** Rust 2021 (rust-version 1.95), `openssl` крейт для DER, `mockall` для backend, `tracing-journald` для audit, libparsec через ручные `extern "C"`. Сборка под Debian dev box проходит без libparsec (stub). E2E на Astra 1.8 VM через `ssh -p 2222 bfs_admin@127.0.0.1`.

**Pre-commit:** проект использует `.pre-commit-config.yaml` (`cargo fmt --check`, `cargo clippy -- -D warnings`). Каждый commit должен пройти эти хуки; при провале запускайте `cargo fmt --all`, исправляйте clippy и пересоздавайте commit (НЕ amend).

---

## Карта файлов

**Создаются:**
- `crates/pam_certauth_core/src/mac/mod.rs` — public API.
- `crates/pam_certauth_core/src/mac/label.rs` — `IntegrityLabel`, DER encode/decode.
- `crates/pam_certauth_core/src/mac/backend.rs` — trait `MacBackend` + `MacRuntime` enum.
- `crates/pam_certauth_core/src/mac/stub.rs` — no-op backend (без feature).
- `crates/pam_certauth_core/src/mac/ffi.rs` — libparsec extern "C" (под `astra-mac`).
- `crates/pam_certauth_core/src/mac/audit.rs` — emitters audit events.
- `crates/pam_certauth_core/src/x509/max_integrity_ext.rs` — извлечение и парсинг ext из cert.
- `crates/pam_certauth_core/build.rs` — `cargo:rustc-link-lib=parsec` под feature.
- `crates/pam_certauth_core/tests/mac_label_roundtrip.rs`
- `crates/pam_certauth_core/tests/mac_ext_parse.rs`
- `crates/pam_certauth_core/tests/mac_policy_config.rs`
- `crates/pam_certauth_core/tests/mac_backend_matrix.rs`
- `tests/fixtures/setup-mac-fixtures.sh`
- `tests/fixtures/openssl-mac-l2-c01.cnf`, `openssl-mac-l1-empty.cnf`, `openssl-mac-no-ext.cnf`, `openssl-mac-l3.cnf`, `openssl-mac-malformed.cnf`
- `vagrant/scripts/test-mac.sh`
- `debian/tmpfiles.d/pam-certauth.conf` (если не существует)

**Модифицируются:**
- `crates/pam_certauth_core/src/x509/oids.rs` — добавить `MAX_INTEGRITY_OID`.
- `crates/pam_certauth_core/src/x509/mod.rs` — export нового модуля.
- `crates/pam_certauth_core/src/lib.rs` — `pub mod mac;`.
- `crates/pam_certauth_core/Cargo.toml` — features `astra-mac`, `mac-tests`.
- `crates/pam_certauth_core/src/config/raw.rs` — `RawMacPolicy`.
- `crates/pam_certauth_core/src/config/validated.rs` — `MacPolicy`.
- `crates/pam_certauth/src/lib.rs` (или соответствующий PAM entry) — hook `pam_sm_open_session`.
- `crates/pam_certauth_monitord/src/server.rs` — атомарный rename socket + label.
- `crates/pam_certauth_monitord/src/state.rs` — verify irelax при write `sessions.json`.
- `debian/postinst` — фрагмент `pdpl-file`.
- `debian/pam-certauth-monitord.service` (или соответствующая unit) — `RuntimeDirectory=pam_certauth`.
- `docs/install.md`, `docs/cert-issuance.md`, `docs/configuration.md`, `docs/threat-model.md`, `docs/changelog.md`.

---

## Phase 0: Подготовка

### Task 0.1: Сгенерировать MAX_INTEGRITY UUID и закоммитить константу (single source of truth)

**Files:**
- Modify: `crates/pam_certauth_core/src/x509/oids.rs`
- Create: `tests/fixtures/openssl-mac-*.cnf.in` (см. Phase 9 — `.cnf.in` шаблоны
  с плейсхолдером `@MAX_INTEGRITY_OID@`, generated `.cnf` — gitignored)
- Modify: `.pre-commit-config.yaml` или CI workflow — добавить guard
  `! grep -RIn --exclude-dir=target -- '<MAX_OID>\|<TBD-uuid>\|2\.25\.<' . --include='*.md' --include='*.rs' --include='*.cnf' --include='*.cnf.in'`

- [ ] **Step 1: Сгенерировать UUID и преобразовать в OID 2.25.<int>**

```bash
python3 -c 'import uuid; u = uuid.uuid4(); print("UUID:", u); print("OID:", "2.25." + str(u.int))'
```

Сохранить вывод. Полученный OID — единственный источник истины: только в
`oids.rs::MAX_INTEGRITY_OID`. Не дублировать в `.md`/`.cnf` файлах.

- [ ] **Step 2: Добавить константу**

В `crates/pam_certauth_core/src/x509/oids.rs` после `USER_BINDING_OID` добавить:

```rust
/// OID of the `pam_cert_max_integrity` X.509 extension.
///
/// `extnValue ::= SEQUENCE { level INTEGER (0..63), categories BIT STRING DEFAULT ''B }`.
/// Marks the upper bound of Astra МКЦ integrity for the engineer session.
/// Non-critical. See `docs/superpowers/specs/2026-05-14-mac-integrity-design.md`.
pub const MAX_INTEGRITY_OID: &str = "<MAX_OID>";
```

- [ ] **Step 3: Verify build**

Run: `cargo build -p pam_certauth_core`
Expected: success.

- [ ] **Step 4: Commit**

```bash
git add crates/pam_certauth_core/src/x509/oids.rs
git commit -m "feat(mac): allocate MAX_INTEGRITY OID for Astra integrity extension"
```

### Task 0.2: Добавить cargo features astra-mac и mac-tests во все 3 крейта

**Files:**
- Modify: `crates/pam_certauth_core/Cargo.toml` (объявление features)
- Modify: `crates/pam_certauth/Cargo.toml` (re-export astra-mac, mac-tests)
- Modify: `crates/pam_certauth_monitord/Cargo.toml` (то же)
- Create: `crates/pam_certauth_core/build.rs`

`pam_certauth` и `pam_certauth_monitord` объявляют features прокидыванием
через workspace deps:

```toml
# crates/pam_certauth/Cargo.toml + crates/pam_certauth_monitord/Cargo.toml
[features]
default = []
astra-mac = ["pam_certauth_core/astra-mac"]
mac-tests = ["pam_certauth_core/mac-tests"]
```

Это обязательно, иначе сборка `cargo build -p pam_certauth --features astra-mac`
тихо включит только верхний слой без линковки FFI.

- [ ] **Step 1: Failing test**

Создать `crates/pam_certauth_core/tests/mac_feature_flags.rs`:

```rust
//! Verifies cargo features wire up as expected.

#[cfg(feature = "astra-mac")]
#[test]
fn astra_mac_feature_enabled() {
    // compile-only marker: ensures feature builds.
}

#[cfg(feature = "mac-tests")]
#[test]
fn mac_tests_feature_enabled() {}

#[test]
fn default_build_excludes_astra_mac() {
    #[cfg(feature = "astra-mac")]
    panic!("astra-mac must NOT be in default feature set");
}
```

- [ ] **Step 2: Run (expect default test to pass, features compile)**

Run: `cargo test -p pam_certauth_core --test mac_feature_flags`
Expected: `default_build_excludes_astra_mac` PASS. Two cfg-gated tests not built.

- [ ] **Step 3: Add features**

В `crates/pam_certauth_core/Cargo.toml` секция `[features]` дополнить:

```toml
# Links libparsec and enables real МКЦ FFI. Required for Astra deb build.
astra-mac = []
# Enables in-process MacBackend mock for unit tests on dev hosts without
# libparsec. Independent of astra-mac.
mac-tests = []
```

Создать `crates/pam_certauth_core/build.rs`:

```rust
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "astra-mac")]
    {
        // Реальная shared library — libpdp. Подтверждено demo-рецептом
        // в docs.astralinux.ru/.../szi/api/demo/label/ (compile-команда
        // `gcc -o pdp_set_get_path pdp_set_get_path.c -lpdp`).
        // Text-API (`pdpl_get_from_text`, `pdpl_put`, `pdp_set_pid`,
        // `pdp_set_fd`, `pdp_set_path`, `pdp_get_lpath`, `pdpl_get_text`,
        // `getmicnam`, `freemicent_r`) живёт в libpdp.so.
        // NB: `pdp_set_current` — inline-обёртка в pdp.h над `pdp_set_pid(0, l)`,
        // символа в .so нет — вызываем `pdp_set_pid` напрямую (spec §4.1).
        println!("cargo:rustc-link-lib=pdp");
    }
}
```

- [ ] **Step 4: Run all variants**

Run:
```
cargo build -p pam_certauth_core
cargo test -p pam_certauth_core --features mac-tests --test mac_feature_flags
```
Expected: both succeed.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_core/Cargo.toml crates/pam_certauth_core/build.rs crates/pam_certauth_core/tests/mac_feature_flags.rs
git commit -m "build(mac): add astra-mac and mac-tests cargo features"
```

---

## Phase 1: IntegrityLabel + DER

### Task 1.1: Тип IntegrityLabel и intersection

**Files:**
- Create: `crates/pam_certauth_core/src/mac/mod.rs`
- Create: `crates/pam_certauth_core/src/mac/label.rs`
- Modify: `crates/pam_certauth_core/src/lib.rs`

- [ ] **Step 1: Failing test** — `crates/pam_certauth_core/tests/mac_label_intersect.rs`:

```rust
use pam_certauth_core::mac::IntegrityLabel;

#[test]
fn intersect_takes_min_level_and_and_categories() {
    let a = IntegrityLabel { level: 2, categories: 0b0011_u64 };
    let b = IntegrityLabel { level: 3, categories: 0b0101_u64 };
    let r = a.intersect(&b);
    assert_eq!(r.level, 2);
    assert_eq!(r.categories, 0b0001_u64);
}

#[test]
fn empty_categories_means_unbounded() {
    let cert = IntegrityLabel { level: 5, categories: 0_u64 };
    let user = IntegrityLabel { level: 3, categories: 0b1111_u64 };
    // empty categories on cert = "no restriction" => user.categories preserved.
    let r = cert.intersect_cert_with_user(&user);
    assert_eq!(r.level, 3);
    assert_eq!(r.categories, 0b1111_u64);
}

#[test]
fn ordering_strict_less_when_level_or_cats_drop() {
    let lo = IntegrityLabel { level: 1, categories: 0b01_u64 };
    let hi = IntegrityLabel { level: 2, categories: 0b11_u64 };
    assert!(lo.strictly_below(&hi));
    assert!(!hi.strictly_below(&lo));
}

#[test]
fn full_u64_mask_roundtrips_through_intersect() {
    let cert = IntegrityLabel { level: 127, categories: u64::MAX };
    let user = IntegrityLabel { level: 5,   categories: u64::MAX };
    let r = cert.intersect(&user);
    assert_eq!(r.level, 5);
    assert_eq!(r.categories, u64::MAX);
}
```

- [ ] **Step 2: Run** — `cargo test -p pam_certauth_core --test mac_label_intersect`
Expected: compile error (module missing).

- [ ] **Step 3: Implement**

`crates/pam_certauth_core/src/mac/mod.rs`:

```rust
//! Mandatory Access Control (МКЦ) integration: types, traits, FFI/stub.
//!
//! See `docs/superpowers/specs/2026-05-14-mac-integrity-design.md`.

mod label;
pub mod audit;
pub mod backend;
#[cfg(feature = "astra-mac")]
mod ffi;
#[cfg(not(feature = "astra-mac"))]
mod stub;

pub use label::IntegrityLabel;
pub use backend::{MacBackend, MacRuntime, MacError};
```

`crates/pam_certauth_core/src/mac/label.rs`:

```rust
//! `IntegrityLabel` — Astra МКЦ integrity coordinate (linear level + categories).

/// Bound on Astra integrity.  Поля соответствуют официальной модели Astra:
/// линейный уровень целостности `linear_ilev` (int8, -128..=127) и
/// 64-битная маска категорий целостности (`PDP_CAT_T = uint64_t`,
/// pdp_common.h, fetch 2026-05-14).  Сериализуется в DER (§2.2 spec) и в
/// text-формат libpdp `"conf:integ:cat_hex:flags:linear"` (§C.4/C.10 spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntegrityLabel {
    /// Линейный уровень целостности (`PDP_ILINEAR_T` = int8).
    /// Отрицательные — untrusted (sandbox); 0 — default.
    pub level: i8,
    /// Битовая маска категорий целостности (до 64 бит).
    pub categories: u64,
}

impl IntegrityLabel {
    /// Maximum allowed level (int8 upper bound).
    pub const MAX_LEVEL: i8 = i8::MAX;
    /// Minimum allowed level (int8 lower bound, untrusted/sandbox).
    pub const MIN_LEVEL: i8 = i8::MIN;

    /// Plain set-intersection (treats empty categories literally as "no cats").
    #[must_use]
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            level: self.level.min(other.level),
            categories: self.categories & other.categories,
        }
    }

    /// Intersection where `self` is the cert bound and `other` is the user
    /// МНКЦ.  `self.categories == 0` is interpreted as "cert imposes no
    /// category restriction" so `other.categories` survives unchanged.  This
    /// is the cert-vs-user-МНКЦ axis, not symmetric — do not call with
    /// arguments swapped.
    #[must_use]
    pub fn intersect_cert_with_user(&self, other: &Self) -> Self {
        let cats = if self.categories == 0 {
            other.categories
        } else {
            self.categories & other.categories
        };
        Self {
            level: self.level.min(other.level),
            categories: cats,
        }
    }

    /// Strict componentwise less-than (level lower OR fewer categories).
    #[must_use]
    pub fn strictly_below(&self, other: &Self) -> bool {
        let cats_subset = (self.categories & other.categories) == self.categories;
        (self.level < other.level && cats_subset)
            || (self.level <= other.level && self.categories != other.categories && cats_subset)
    }
}
```

В `crates/pam_certauth_core/src/lib.rs` добавить `pub mod mac;`.

Создать пустые `audit.rs`, `backend.rs`, `stub.rs` файлы с заглушками (см. Phase 3):

```rust
// audit.rs
//! Placeholder; populated in Phase 5.
```

```rust
// backend.rs — заглушка для компиляции:
//! Placeholder backend types.
use thiserror::Error;
#[derive(Debug, Error)] #[error("placeholder")] pub struct MacError;
#[derive(Debug, Clone, Copy)] pub enum MacRuntime { Active, Disabled, Unavailable }
pub trait MacBackend: Send + Sync {}
```

```rust
// stub.rs
//! No-op MAC backend (default build).
```

- [ ] **Step 4: Run** — `cargo test -p pam_certauth_core --test mac_label_intersect`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_core/src/mac/ crates/pam_certauth_core/src/lib.rs crates/pam_certauth_core/tests/mac_label_intersect.rs
git commit -m "feat(mac): introduce IntegrityLabel with intersection semantics"
```

### Task 1.2: DER encode/decode для расширения

**Files:**
- Modify: `crates/pam_certauth_core/src/mac/label.rs`
- Create: `crates/pam_certauth_core/tests/mac_label_roundtrip.rs`

- [ ] **Step 1: Failing test**

`crates/pam_certauth_core/tests/mac_label_roundtrip.rs`:

```rust
use pam_certauth_core::mac::IntegrityLabel;

#[test]
fn roundtrip_basic() {
    let l = IntegrityLabel { level: 2, categories: 0b0011_u64 };
    let der = l.to_der().expect("encode");
    let back = IntegrityLabel::from_der(&der).expect("decode");
    assert_eq!(l, back);
}

#[test]
fn empty_categories_round_trip() {
    let l = IntegrityLabel { level: 1, categories: 0_u64 };
    let der = l.to_der().expect("encode");
    let back = IntegrityLabel::from_der(&der).expect("decode");
    assert_eq!(back.categories, 0);
}

#[test]
fn full_u64_categories_round_trip() {
    // u64::MAX → 9-byte BIT STRING payload (1 unused-bits prefix + 8 bytes).
    let l = IntegrityLabel { level: 0, categories: u64::MAX };
    let der = l.to_der().expect("encode");
    let back = IntegrityLabel::from_der(&der).expect("decode");
    assert_eq!(back, l);
}

#[test]
fn decode_boundary_levels_ok() {
    for level in [i8::MIN, -1, 0, 1, i8::MAX] {
        let l = IntegrityLabel { level, categories: u64::MAX };
        let der = l.to_der().expect("encode");
        let back = IntegrityLabel::from_der(&der).expect("decode");
        assert_eq!(back, l);
    }
}

#[test]
fn decode_malformed_fails_safe() {
    assert!(IntegrityLabel::from_der(&[]).is_err());
    assert!(IntegrityLabel::from_der(&[0x30, 0x80]).is_err());
    // sequence with INTEGER length > 1 byte where value cannot fit in i8
    // (e.g. 0x01 0x80 — 2-byte BER encoding for value 128 — out of i8 range).
    assert!(IntegrityLabel::from_der(&[0x30, 0x04, 0x02, 0x02, 0x00, 0x80]).is_err());
}
```

Property test добавить в тот же файл:

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn proptest_roundtrip(level in any::<i8>(), cats in any::<u64>()) {
        let l = IntegrityLabel { level, categories: cats };
        let der = l.to_der().unwrap();
        let back = IntegrityLabel::from_der(&der).unwrap();
        prop_assert_eq!(l, back);
    }
}
```

- [ ] **Step 2: Run** — expect failures (`to_der`/`from_der` missing).

- [ ] **Step 3: Implement** — добавить в `label.rs`:

```rust
use openssl::asn1::Asn1Integer;
use openssl::bn::BigNum;

/// Errors produced by DER (de)serialization of `IntegrityLabel`.
#[derive(Debug, thiserror::Error)]
pub enum LabelDerError {
    /// `level` не помещается в `i8`.
    #[error("level out of int8 range")]
    LevelOutOfRange,
    /// Malformed DER.
    #[error("malformed DER: {0}")]
    Malformed(&'static str),
    /// openssl backend error.
    #[error(transparent)]
    Openssl(#[from] openssl::error::ErrorStack),
}

impl IntegrityLabel {
    /// Encode as DER `SEQUENCE { level INTEGER, categories BIT STRING }`.
    ///
    /// `level` всегда помещается в один байт (диапазон int8); кодируется
    /// как DER INTEGER длины 1 (signed two's complement byte).
    ///
    /// # Errors
    /// `Openssl` для backend-сбоев.
    pub fn to_der(&self) -> Result<Vec<u8>, LabelDerError> {
        let mut inner = Vec::with_capacity(16);
        // INTEGER (level — signed int8, one byte two's-complement)
        inner.push(0x02);
        inner.push(0x01);
        inner.push(self.level as u8);
        // BIT STRING (categories, до 64 бит). Empty if zero.
        if self.categories == 0 {
            inner.push(0x03);
            inner.push(0x01);
            inner.push(0x00); // 0 unused bits, no payload
        } else {
            let bytes = self.categories.to_be_bytes(); // 8 bytes (u64)
            // strip leading zero bytes (min-length encoding); keep at least 1.
            let start = bytes.iter().position(|b| *b != 0).unwrap_or(7);
            let payload = &bytes[start..];
            inner.push(0x03);
            inner.push(u8::try_from(payload.len() + 1).map_err(|_| LabelDerError::Malformed("len"))?);
            inner.push(0x00); // unused bits
            inner.extend_from_slice(payload);
        }
        let mut out = Vec::with_capacity(inner.len() + 2);
        out.push(0x30);
        out.push(u8::try_from(inner.len()).map_err(|_| LabelDerError::Malformed("seq len"))?);
        out.extend_from_slice(&inner);
        Ok(out)
    }

    /// Decode a DER `SEQUENCE { level INTEGER, categories BIT STRING DEFAULT ''B }`.
    ///
    /// # Errors
    /// `Malformed` on bad tags/lengths, `LevelOutOfRange` if INTEGER не
    /// помещается в `i8`.
    pub fn from_der(der: &[u8]) -> Result<Self, LabelDerError> {
        if der.len() < 2 || der[0] != 0x30 {
            return Err(LabelDerError::Malformed("not a SEQUENCE"));
        }
        let seq_len = usize::from(der[1]);
        if 2 + seq_len > der.len() || der[1] & 0x80 != 0 {
            return Err(LabelDerError::Malformed("bad seq length"));
        }
        let body = &der[2..2 + seq_len];
        // INTEGER
        if body.len() < 3 || body[0] != 0x02 {
            return Err(LabelDerError::Malformed("missing INTEGER tag"));
        }
        let int_len = usize::from(body[1]);
        if int_len == 0 || 2 + int_len > body.len() {
            return Err(LabelDerError::Malformed("bad INTEGER length"));
        }
        let int_bytes = &body[2..2 + int_len];
        if int_bytes.len() != 1 {
            // INTEGER не помещается в один байт → не помещается в i8.
            return Err(LabelDerError::LevelOutOfRange);
        }
        let level = int_bytes[0] as i8;
        // BIT STRING (optional, default empty)
        let after_int = 2 + int_len;
        let categories = if after_int == body.len() {
            0u64
        } else {
            let bs = &body[after_int..];
            if bs.len() < 2 || bs[0] != 0x03 {
                return Err(LabelDerError::Malformed("missing BIT STRING tag"));
            }
            let bs_len = usize::from(bs[1]);
            if bs_len == 0 || 2 + bs_len > bs.len() {
                return Err(LabelDerError::Malformed("bad BIT STRING length"));
            }
            let payload = &bs[2..2 + bs_len];
            if payload.is_empty() {
                return Err(LabelDerError::Malformed("BIT STRING missing unused-bits byte"));
            }
            // payload[0] = unused bits
            let bits = &payload[1..];
            if bits.len() > 8 {
                return Err(LabelDerError::Malformed("categories > 64 bits"));
            }
            let mut buf = [0u8; 8];
            buf[8 - bits.len()..].copy_from_slice(bits);
            u64::from_be_bytes(buf)
        };
        Ok(Self { level, categories })
    }
}

```

`Asn1Integer`/`BigNum` импорты — НЕ нужны (encoder написан вручную), не
добавлять. Никакого `_force_openssl_dep`-shim'а.

**Categories u64 vs concept-доки 32 бита (N3).** Concept-доки Astra
описывают integrity categories как 32-bit маску, тогда как
`PDP_CAT_T = uint64_t` (pdp_common.h, verified Phase 4 Task 4.0). Чтобы
поведение было предсказуемым:

- В `from_der` **не** clamp'ить значение — сохраняем все 64 бита
  как есть в `IntegrityLabel.categories` (soft-clamp).
- Emit Notice-уровень audit event если `categories >> 32 != 0`.

**Phase ordering note.** `audit::emit_categories_above_32bit` живёт в
`crates/pam_certauth_core/src/mac/audit.rs`, который полноценно
заполняется только в Phase 5 Task 5.1. В Phase 1 (Task 1.2) ограничиваемся:
1) добавить TODO-комментарий в `from_der` с указанием, где будет emit;
2) задание fail-safe: парсер возвращает `Ok` (не Err), Notice — это
   диагностика, не ошибка валидации.
В Phase 5 Task 5.1 добавляется константа
`EVENT_CERT_MAX_INT_CATS_ABOVE_32BIT = "cert_max_integrity_categories_above_32bit"`
+ функция `emit_categories_above_32bit(categories: u64)`, и в `from_der`
ставится финальный вызов:

```rust
// в from_der, после успешного декода categories:
if categories >> 32 != 0 {
    crate::mac::audit::emit_categories_above_32bit(categories);
}
```
- На VM с system-max категорий <64, `pdpl_get_from_text("0:0:ffffffffffffffff:…")`
  вернёт NULL → `MacError::Parsec { op: "pdpl_get_from_text", rc: -1 }`
  → штатно поднимется как `mac_apply_failed`. Это покрывается T12 (E2E).

Test (добавить в тот же `mac_label_roundtrip.rs`):

```rust
#[test]
fn categories_above_32bit_round_trip_preserves_high_bits() {
    let l = IntegrityLabel { level: 0, categories: 0xFFFF_FFFF_FFFF_FFFF_u64 };
    let der = l.to_der().unwrap();
    let back = IntegrityLabel::from_der(&der).unwrap();
    assert_eq!(back.categories >> 32, 0xFFFF_FFFF_u64);
    assert_eq!(back, l);
}
```

- [ ] **Step 4: Run** — `cargo test -p pam_certauth_core --test mac_label_roundtrip`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_core/src/mac/label.rs crates/pam_certauth_core/tests/mac_label_roundtrip.rs
git commit -m "feat(mac): DER encode/decode for IntegrityLabel extension"
```

### Task 1.3: Извлечение MAX_INTEGRITY ext из сертификата

**Files:**
- Create: `crates/pam_certauth_core/src/x509/max_integrity_ext.rs`
- Modify: `crates/pam_certauth_core/src/x509/mod.rs`
- Create: `crates/pam_certauth_core/tests/mac_ext_parse.rs`

- [ ] **Step 1: Failing test**

```rust
use openssl::x509::X509;
use pam_certauth_core::mac::IntegrityLabel;
use pam_certauth_core::x509::max_integrity_ext::extract_max_integrity;

const PEM_WITH_EXT: &str = include_str!("fixtures/cert_with_mac_l2_c01.pem");
const PEM_NO_EXT:   &str = include_str!("fixtures/cert_without_mac.pem");
const PEM_MALFORMED: &str = include_str!("fixtures/cert_with_mac_malformed.pem");

#[test]
fn returns_label_when_ext_present() {
    let cert = X509::from_pem(PEM_WITH_EXT.as_bytes()).unwrap();
    let l = extract_max_integrity(&cert).unwrap();
    assert_eq!(l, Some(IntegrityLabel { level: 2, categories: 0b01 }));
}

#[test]
fn returns_none_when_ext_absent() {
    let cert = X509::from_pem(PEM_NO_EXT.as_bytes()).unwrap();
    assert_eq!(extract_max_integrity(&cert).unwrap(), None);
}

#[test]
fn malformed_ext_returns_err() {
    let cert = X509::from_pem(PEM_MALFORMED.as_bytes()).unwrap();
    assert!(extract_max_integrity(&cert).is_err());
}
```

Fixtures генерируются позже (Phase 9); пока создать минимальные plug-фикстуры через `openssl` команд (см. Phase 9 Task 9.1) и положить в `crates/pam_certauth_core/tests/fixtures/`. Если фикстуры ещё нет — пометить тест `#[ignore]` и вернуться после Phase 9. **Альтернатива:** сгенерировать сертификат внутри теста через `openssl` крейт — предпочтительно.

Заменить на in-test generation.  NOTE: openssl crate API ниже —
referential.  Точные имена (`X509Extension::new_from_der`, `Asn1OctetString::new_from_bytes`)
проверить через `cargo doc -p openssl` или https://docs.rs/openssl перед
commit (см. H8 ревью).  Альтернатива при отсутствии `new_from_der`:
`X509Extension::new(None, None, oid_str, "DER:...")` с hex-сериализацией
DER body.

VerifiedX509 newtype (spec §2.0): тест-fixtures создаются через
`VerifiedX509::from_trusted_for_test(x509)` — публичный конструктор
доступен только под `#[cfg(test)]`.

```rust
use openssl::asn1::Asn1Integer;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::{X509Builder, X509NameBuilder, X509Extension};
use pam_certauth_core::mac::IntegrityLabel;
use pam_certauth_core::x509::max_integrity_ext::extract_max_integrity;
use pam_certauth_core::x509::oids::MAX_INTEGRITY_OID;

fn build_cert(ext_der: Option<&[u8]>) -> openssl::x509::X509 {
    let rsa = Rsa::generate(2048).unwrap();
    let pkey = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "t").unwrap();
    let name = name.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let serial = BigNum::from_u32(1).unwrap();
    b.set_serial_number(&Asn1Integer::from_bn(&serial).unwrap()).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&pkey).unwrap();
    b.append_extension(BasicConstraints::new().critical().ca().build().unwrap()).unwrap();
    if let Some(der) = ext_der {
        // Wrap DER bytes inside OCTET STRING for X509Extension::new_from_der
        let ext = X509Extension::new_from_der(
            &openssl::asn1::Asn1Object::from_str(MAX_INTEGRITY_OID).unwrap(),
            false,
            &openssl::asn1::Asn1OctetString::new_from_bytes(der).unwrap(),
        ).unwrap();
        b.append_extension(ext).unwrap();
    }
    b.sign(&pkey, MessageDigest::sha256()).unwrap();
    b.build()
}

#[test]
fn returns_label_when_ext_present() {
    let der = IntegrityLabel { level: 2, categories: 0b01 }.to_der().unwrap();
    let cert = build_cert(Some(&der));
    assert_eq!(
        extract_max_integrity(&cert).unwrap(),
        Some(IntegrityLabel { level: 2, categories: 0b01 })
    );
}

#[test]
fn returns_none_when_ext_absent() {
    let cert = build_cert(None);
    assert!(extract_max_integrity(&cert).unwrap().is_none());
}

#[test]
fn malformed_ext_returns_err() {
    // Truncated SEQUENCE
    let bad = [0x30u8, 0x05, 0x02, 0x01, 0x02];
    let cert = build_cert(Some(&bad));
    assert!(extract_max_integrity(&cert).is_err());
}
```

(Если `X509Extension::new_from_der` API отличается — engineer должен проверить через `cargo doc --open openssl`; альтернатива `X509Extension::new` со строкой `ASN1:`.)

- [ ] **Step 2: Run** — `cargo test -p pam_certauth_core --test mac_ext_parse` (expect compile error: module missing).

- [ ] **Step 3: Implement** `crates/pam_certauth_core/src/x509/max_integrity_ext.rs`.

VerifiedX509 newtype (spec §2.0) — обязательный trust-boundary tunable.
Если `crates/pam_certauth_core/src/x509/mod.rs` ещё не содержит
`VerifiedX509`, добавить сейчас:

```rust
// in crates/pam_certauth_core/src/x509/mod.rs
/// Verified leaf certificate.  Constructed only after chain/EKU/signature
/// validation succeeded in the main authentication flow.
pub struct VerifiedX509(openssl::x509::X509);

impl VerifiedX509 {
    /// Production constructor — кодом call'ится только из verifier-pipeline,
    /// после успешной валидации.
    pub(crate) fn new(cert: openssl::x509::X509) -> Self { Self(cert) }
    /// Доступ к underlying X509 (read-only).
    pub fn as_x509(&self) -> &openssl::x509::X509 { &self.0 }
    /// Test-only escape hatch.  Использовать ТОЛЬКО в unit-тестах с
    /// self-signed fixtures.
    #[cfg(any(test, feature = "mac-tests"))]
    pub fn from_trusted_for_test(cert: openssl::x509::X509) -> Self { Self(cert) }
}
```

Затем `extract_max_integrity` принимает `&VerifiedX509`:

```rust
//! Extracts the `MAX_INTEGRITY` X.509 extension from a verified leaf
//! certificate.  Trust boundary: caller must already have validated the
//! chain — see `VerifiedX509`.

use crate::mac::IntegrityLabel;
use crate::mac::label::LabelDerError;
use super::oids::MAX_INTEGRITY_OID;
use super::VerifiedX509;

/// Errors returned from [`extract_max_integrity`].
#[derive(Debug, thiserror::Error)]
pub enum MaxIntegrityExtError {
    /// Extension present but DER body unparseable.
    #[error("parse: {0}")]
    Parse(#[from] LabelDerError),
    /// openssl backend error.
    #[error(transparent)]
    Openssl(#[from] openssl::error::ErrorStack),
}

/// Returns `Ok(Some(label))` if the cert carries a valid MAX_INTEGRITY
/// extension, `Ok(None)` if it is absent, or `Err` if present but malformed.
///
/// # Errors
/// See [`MaxIntegrityExtError`].
pub fn extract_max_integrity(cert: &VerifiedX509) -> Result<Option<IntegrityLabel>, MaxIntegrityExtError> {
    let target = openssl::asn1::Asn1Object::from_str(MAX_INTEGRITY_OID)?;
    let extensions = cert.as_x509().extensions()?;
    for ext in extensions {
        if ext.object().nid() == target.nid() || ext.object().to_string() == MAX_INTEGRITY_OID {
            let raw = ext.data().as_slice();
            let label = IntegrityLabel::from_der(raw)?;
            return Ok(Some(label));
        }
    }
    Ok(None)
}
```

Re-export в `x509/mod.rs`: `pub mod max_integrity_ext;`.

- [ ] **Step 4: Run** — `cargo test -p pam_certauth_core --test mac_ext_parse`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_core/src/x509/max_integrity_ext.rs crates/pam_certauth_core/src/x509/mod.rs crates/pam_certauth_core/tests/mac_ext_parse.rs
git commit -m "feat(mac): extract MAX_INTEGRITY extension from X.509 certs"
```

---

## Phase 2: Config [mac]

### Task 2.1: Парсинг секции [mac]

**Files:**
- Modify: `crates/pam_certauth_core/src/config/raw.rs`
- Modify: `crates/pam_certauth_core/src/config/validated.rs`
- Create: `crates/pam_certauth_core/tests/mac_policy_config.rs`

- [ ] **Step 1: Failing test**

```rust
use pam_certauth_core::config::{validated::ValidatedConfig, validated::CertIntegrityMode};

fn base_config() -> String {
    // Engineer must adapt this template to the minimal valid config of the
    // project; reuse existing helper from tests if available.
    std::fs::read_to_string("tests/fixtures/config_minimal.toml")
        .expect("minimal config fixture")
}

#[test]
fn mac_defaults_to_optional_without_fallback() {
    let cfg: ValidatedConfig = toml::from_str::<pam_certauth_core::config::raw::RawConfig>(&base_config())
        .unwrap()
        .try_into()
        .unwrap();
    assert!(matches!(cfg.mac.cert_integrity, CertIntegrityMode::Optional));
    assert!(cfg.mac.fallback_max_integrity.is_none());
    assert!(cfg.mac.warn_on_homedir_label_mismatch);
}

#[test]
fn parses_required_with_fallback() {
    let toml = format!(
        r#"{base}

[mac]
cert_integrity = "required"
warn_on_homedir_label_mismatch = false
[mac.fallback_max_integrity]
level = 0
categories = ""
"#,
        base = base_config()
    );
    let cfg: ValidatedConfig = toml::from_str::<pam_certauth_core::config::raw::RawConfig>(&toml)
        .unwrap()
        .try_into()
        .unwrap();
    assert!(matches!(cfg.mac.cert_integrity, CertIntegrityMode::Required));
    assert!(!cfg.mac.warn_on_homedir_label_mismatch);
}

#[test]
fn rejects_legacy_field_require_mac() {
    let toml = format!("{}\n[mac]\nrequire_mac = true\n", base_config());
    assert!(toml::from_str::<pam_certauth_core::config::raw::RawConfig>(&toml).is_err());
}

#[test]
fn rejects_legacy_field_cert_mac_level() {
    let toml = format!("{}\n[mac]\ncert_mac_level = 2\n", base_config());
    assert!(toml::from_str::<pam_certauth_core::config::raw::RawConfig>(&toml).is_err());
}

#[test]
fn rejects_invalid_trinary_value() {
    let toml = format!("{}\n[mac]\ncert_integrity = \"strict\"\n", base_config());
    assert!(toml::from_str::<pam_certauth_core::config::raw::RawConfig>(&toml).is_err());
}
```

Если фикстуры `config_minimal.toml` нет — создать копию текущего minimal sample из `tests/fixtures/`. Использовать `tests/fixtures/policy_minimal.toml` или эквивалент, который уже есть в репо. Engineer: проверить путём `ls crates/pam_certauth_core/tests/fixtures/`.

- [ ] **Step 2: Run** — compile error (нет `RawMacPolicy`).

- [ ] **Step 3: Implement**

В `raw.rs` (в самом конце):

```rust
/// Raw `[mac]` policy block. All fields optional with sane defaults so that
/// existing configs deserialize unchanged.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMacPolicy {
    /// Trinary: required | optional | ignore.
    #[serde(default)]
    pub cert_integrity: Option<RawCertIntegrityMode>,
    /// Fallback applied iff `cert_integrity=optional` AND ext absent.
    #[serde(default)]
    pub fallback_max_integrity: Option<RawIntegrityLabel>,
    /// Audit warning when interactive service hits homedir with higher label.
    #[serde(default)]
    pub warn_on_homedir_label_mismatch: Option<bool>,
}

/// Trinary cert-integrity gate.
#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RawCertIntegrityMode {
    /// Cert without ext is rejected.
    Required,
    /// Cert without ext is accepted; fallback or unbounded applies.
    Optional,
    /// Extension not consulted at all.
    Ignore,
}

/// TOML form of an integrity label. `categories` is a hex string (e.g. "03"
/// for bits 0,1) or `""` for empty.  `level` — int8 (`-128..=127`).
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawIntegrityLabel {
    /// -128..=127 (линейный уровень целостности).
    pub level: i8,
    /// Hex string (lower- or upper-case), до 8 hex-цифр (u32).
    /// Empty string = no categories.
    #[serde(default)]
    pub categories: String,
}
```

В `RawConfig` добавить:

```rust
    /// MAC integrity policy (`[mac]` section).
    #[serde(default)]
    pub mac: RawMacPolicy,
```

В `validated.rs` добавить:

```rust
/// Resolved MAC policy.
#[derive(Debug, Clone)]
pub struct MacPolicy {
    /// Required / Optional / Ignore.
    pub cert_integrity: CertIntegrityMode,
    /// Applied iff Optional + ext absent.
    pub fallback_max_integrity: Option<crate::mac::IntegrityLabel>,
    /// Emit warning on homedir label mismatch (interactive services only).
    pub warn_on_homedir_label_mismatch: bool,
}

/// Resolved trinary form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CertIntegrityMode {
    /// Reject cert without ext.
    Required,
    /// Accept; apply fallback or unbounded.
    Optional,
    /// Skip МКЦ entirely.
    Ignore,
}

impl Default for MacPolicy {
    fn default() -> Self {
        Self {
            cert_integrity: CertIntegrityMode::Optional,
            fallback_max_integrity: None,
            warn_on_homedir_label_mismatch: true,
        }
    }
}
```

И во `From<RawConfig>` или `TryFrom`:

```rust
let mac = MacPolicy {
    cert_integrity: match raw.mac.cert_integrity {
        Some(crate::config::raw::RawCertIntegrityMode::Required) => CertIntegrityMode::Required,
        Some(crate::config::raw::RawCertIntegrityMode::Ignore) => CertIntegrityMode::Ignore,
        _ => CertIntegrityMode::Optional,
    },
    fallback_max_integrity: raw.mac.fallback_max_integrity
        .as_ref()
        .map(|r| {
            let cats = if r.categories.is_empty() { 0u32 }
                else { u32::from_str_radix(&r.categories, 16)
                    .map_err(|e| ConfigError::InvalidValue(format!("[mac].fallback_max_integrity.categories: {e}")))? };
            // i8-валидация на этапе serde (`level: i8`); диапазон гарантирован
            Ok::<_, ConfigError>(crate::mac::IntegrityLabel { level: r.level, categories: cats })
        })
        .transpose()?,
    warn_on_homedir_label_mismatch: raw.mac.warn_on_homedir_label_mismatch.unwrap_or(true),
};
```

И поле `pub mac: MacPolicy` в `ValidatedConfig` (default через `MacPolicy::default()`).

- [ ] **Step 4: Run** — `cargo test -p pam_certauth_core --test mac_policy_config`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_core/src/config/ crates/pam_certauth_core/tests/mac_policy_config.rs
git commit -m "feat(mac): parse [mac] policy section with trinary cert_integrity"
```

---

## Phase 3: MacBackend trait, MacRuntime, stub

### Task 3.1: Trait + MacRuntime + stub impl

**Files:**
- Modify: `crates/pam_certauth_core/src/mac/backend.rs`
- Modify: `crates/pam_certauth_core/src/mac/stub.rs`
- Modify: `crates/pam_certauth_core/src/mac/mod.rs`
- Create: `crates/pam_certauth_core/tests/mac_backend_matrix.rs`

- [ ] **Step 1: Failing test**

```rust
#![cfg(feature = "mac-tests")]
use pam_certauth_core::mac::{IntegrityLabel, MacBackend, MacRuntime};
use pam_certauth_core::mac::backend::StubBackend;

#[test]
fn stub_probe_returns_unavailable() {
    let b = StubBackend::new();
    assert!(matches!(b.probe(), MacRuntime::Unavailable));
}

#[test]
fn stub_apply_is_noop_ok() {
    let b = StubBackend::new();
    let r = b.apply_session(IntegrityLabel { level: 1, categories: 0 });
    assert!(r.is_ok());
}

#[test]
fn stub_get_user_mnkc_returns_unbounded() {
    let b = StubBackend::new();
    let l = b.get_user_mnkc("alice").unwrap();
    assert_eq!(l.level, i8::MAX);
}
```

И mockall-based test для матрицы из spec 7.3:

```rust
#![cfg(feature = "mac-tests")]
use mockall::predicate::*;
use pam_certauth_core::mac::{IntegrityLabel, MacRuntime};
use pam_certauth_core::mac::backend::MockMacBackend;

#[test]
fn intersect_pipeline_calls_apply_with_capped_label() {
    let mut mock = MockMacBackend::new();
    mock.expect_probe().return_const(MacRuntime::Active);
    mock.expect_get_user_mnkc()
        .with(eq("alice"))
        .return_once(|_| Ok(IntegrityLabel { level: 3, categories: 0b11 }));
    mock.expect_apply_session()
        .with(eq(IntegrityLabel { level: 2, categories: 0b01 }))
        .return_once(|_| Ok(()));

    // Simulate orchestrator call shape (will live in pam_certauth crate later).
    let cert_max = IntegrityLabel { level: 2, categories: 0b01 };
    let user = mock.get_user_mnkc("alice").unwrap();
    let eff = cert_max.intersect(&user);
    mock.apply_session(eff).unwrap();
}
```

- [ ] **Step 2: Run** — `cargo test -p pam_certauth_core --features mac-tests --test mac_backend_matrix`
Expected: compile error (нет `MacBackend`, `StubBackend`, `MockMacBackend`).

- [ ] **Step 3: Implement**

`backend.rs` (полная замена):

```rust
//! `MacBackend` trait + runtime probe types.

use crate::mac::IntegrityLabel;

/// Errors returned by backend operations.
///
/// **Trust только `rc`** — `errno` после вызова libparsec НЕ описан в
/// контракте (см. spec §4.3, Appendix C).  Поэтому `MacError::Parsec`
/// несёт `(rc, op)` без errno.  Различения EPERM/EINVAL/... делает caller
/// по `rc` (если libparsec версии описывает соответствие).
///
/// **Полный список вариантов (compile-blocker для Task 4.1):**
/// FFI-layer (`ffi.rs`) использует `UserUnknown`, `CapMissing`,
/// `TextFormat` — они обязаны существовать к моменту реализации Task 4.1.
#[derive(Debug, thiserror::Error)]
pub enum MacError {
    /// libparsec/libpdp returned a non-zero status.
    #[error("parsec error: op={op} rc={rc}")]
    Parsec { op: &'static str, rc: i32 },
    /// User не найден в mic-db (см. spec §4.1.1).  Caller решает по
    /// policy: required → fail-closed, optional → skip.
    #[error("user unknown in mic db: {user}")]
    UserUnknown { user: String },
    /// libparsec or kernel reports MAC unavailable (probe-time).
    #[error("MAC subsystem unavailable")]
    Unavailable,
    /// I/O error during file label operations.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// libpdp text-format codec error (encode/decode).
    #[error("text format error: {0}")]
    TextFormat(String),
    /// Self-check показал отсутствие PARSEC_CAP_CHMAC (см. spec §4.3).
    #[error("missing CHMAC capability")]
    CapMissing,
}

/// Runtime state of Astra МКЦ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacRuntime {
    /// strictmode enabled, libparsec functional.
    Active,
    /// strictmode disabled via `astra-strictmode-control`.
    Disabled,
    /// libparsec absent or kernel without parsec LSM.
    Unavailable,
}

/// Abstraction over Astra МКЦ kernel API. Implemented by [`StubBackend`]
/// (default builds) and `ParsecBackend` (under `astra-mac`).
#[cfg_attr(feature = "mac-tests", mockall::automock)]
pub trait MacBackend: Send + Sync {
    /// One-shot runtime detection.
    fn probe(&self) -> MacRuntime;

    /// Look up the user's МНКЦ (upper bound).
    ///
    /// # Errors
    /// `Unavailable` on stub; `Parsec` on libparsec errors.
    fn get_user_mnkc(&self, user: &str) -> Result<IntegrityLabel, MacError>;

    /// Apply `label` to the current process.
    ///
    /// # Errors
    /// `Eperm` when label exceeds user МНКЦ; `Parsec` for other libparsec
    /// errors.
    fn apply_session(&self, label: IntegrityLabel) -> Result<(), MacError>;

    /// Read file integrity label (best effort).
    ///
    /// # Errors
    /// Returns `Io` if the path is unreadable, `Parsec` if libparsec rejects.
    fn get_file_label(&self, path: &std::path::Path) -> Result<IntegrityLabel, MacError>;

    /// Set file integrity label.
    ///
    /// # Errors
    /// See [`MacError`].
    fn set_file_label(
        &self,
        path: &std::path::Path,
        label: IntegrityLabel,
        irelax: bool,
    ) -> Result<(), MacError>;
}

/// Default no-op backend. `probe()` always returns `Unavailable`. Used in
/// stub builds and when caller wants a no-op for tests.
#[derive(Debug, Default)]
pub struct StubBackend;

impl StubBackend {
    /// Construct.
    #[must_use]
    pub fn new() -> Self { Self }
}

impl MacBackend for StubBackend {
    fn probe(&self) -> MacRuntime { MacRuntime::Unavailable }
    fn get_user_mnkc(&self, _user: &str) -> Result<IntegrityLabel, MacError> {
        Ok(IntegrityLabel { level: i8::MAX, categories: u64::MAX })
    }
    fn apply_session(&self, _label: IntegrityLabel) -> Result<(), MacError> { Ok(()) }
    fn get_file_label(&self, _p: &std::path::Path) -> Result<IntegrityLabel, MacError> {
        Ok(IntegrityLabel { level: 0, categories: 0 })
    }
    fn set_file_label(
        &self,
        _p: &std::path::Path,
        _label: IntegrityLabel,
        _irelax: bool,
    ) -> Result<(), MacError> {
        Ok(())
    }
}
```

Удалить старый placeholder в `stub.rs` (оставить пустым с doc-комментом) — реальный stub теперь `StubBackend` в `backend.rs`. Альтернативно — оставить `stub.rs` для FFI shim wiring под `cfg(not(feature="astra-mac"))`.

В `mod.rs` re-export:

```rust
pub use backend::{MacBackend, MacError, MacRuntime, StubBackend};
#[cfg(feature = "mac-tests")]
pub use backend::MockMacBackend;
```

Добавить `mockall` в `[dependencies]` (через `workspace = true`), а не `[dev-dependencies]`, но условно:

```toml
mockall = { workspace = true, optional = true }
```

И в `[features]`: `mac-tests = ["dep:mockall"]`.

- [ ] **Step 4: Run** —
```
cargo test -p pam_certauth_core --features mac-tests --test mac_backend_matrix
cargo build -p pam_certauth_core
```
Expected: both PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_core/src/mac/ crates/pam_certauth_core/Cargo.toml crates/pam_certauth_core/tests/mac_backend_matrix.rs
git commit -m "feat(mac): MacBackend trait, StubBackend, MacRuntime probe"
```

---

## Phase 4: libpdp FFI (под astra-mac, text-API)

Phase 4 — text-API на `libpdp`. Поскольку **никакие C-struct не пересекают
FFI**, прежняя «struct-layout blocking gate» закрыта дизайном: opaque
`PDPL_T *` обёрнут в RAII `Pdpl(*mut c_void)`, кодек делает
`IntegrityLabel ↔ text` в Rust. Перед Phase 4 на VM нужно лишь убедиться,
что demo из spec §C.1 компилируется и работает — это валидация рантайма.

### Task 4.0: Verify libpdp symbol presence on Astra VM

**Files:**
- Modify: `docs/superpowers/specs/2026-05-14-mac-integrity-design.md` —
  Appendix C §C.6 (записать verified values).

```bash
# Verified results on 2026-05-14 (Astra SE 1.8.4, libpdp.so.3):
#   parsec_strict_mode, parsec_enabled, parsec_astramode,
#   pdp_set_path, pdp_get_lpath, pdp_set_fd, pdp_get_fd,
#   pdp_set_pid, pdp_set_pid_n, pdp_set_pid_safe,
#   pdpl_get_from_text, pdpl_get_text, pdpl_put, pdp_get_current_ilev
# Inline в pdp.h, в .so отсутствуют (вызываем underlying):
#   pdp_set_current, pdp_get_current, pdp_get_sys_max, pdp_set_EQU_*

# 1. confirm libpdp + symbols (use pdp_set_pid, not pdp_set_current!)
ssh -p 2222 bfs_admin@127.0.0.1 \
    'nm -D /usr/lib/libpdp.so* 2>/dev/null | \
     grep -E "pdpl_get_from_text|pdpl_get_text|pdpl_put|pdp_set_pid|pdp_get_pid|pdp_set_fd|pdp_get_fd|pdp_set_path|pdp_get_lpath|pdp_get_peer_label|getmicnam|freemicent_r"'

# 2. confirm parsec_strict_mode + parsec_capget placement
ssh -p 2222 bfs_admin@127.0.0.1 \
    'for so in /usr/lib/libpdp.so* /usr/lib/libparsec-base.so* /usr/lib/libparsec-cap.so* /lib/libparsec-base.so*; do
         [ -e "$so" ] && echo "== $so =="
         [ -e "$so" ] && nm -D "$so" 2>/dev/null | grep -E "parsec_strict_mode|parsec_mac_enabled|parsec_capget|parsec_capset"
     done'

# 3. sanity-check mic_t width
ssh -p 2222 bfs_admin@127.0.0.1 \
    'echo "#include <stdio.h>
#include <parsec/mic_db.h>
int main(){printf(\"sizeof(mic_t)=%zu\\n\", sizeof(mic_t));return 0;}" \
     | gcc -xc - -lpdp -o /tmp/mt 2>&1 && /tmp/mt'

# 4. sanity-check parsec_cap_t width (для маски 1u64 << 3)
ssh -p 2222 bfs_admin@127.0.0.1 \
    'echo "#include <stdio.h>
#include <parsec/parsec_cap.h>
int main(){printf(\"sizeof(parsec_cap_t)=%zu\\n\", sizeof(parsec_cap_t));return 0;}" \
     | gcc -xc - -o /tmp/pc 2>&1 && /tmp/pc'

# 5. SEMANTIC PROBE: pdp_set_pid(0, l) must mean "current process",
#    not "process group". This is a BLOCKER for Task 4.1 — Rust FFI
#    code zовёт pdp_set_pid(0, ..) per spec §4.1; нужно эмпирически
#    убедиться, что rc == 0 и read-back через pdp_get_pid(getpid())
#    совпадает с установленной меткой.
ssh -p 2222 bfs_admin@127.0.0.1 'cat > /tmp/probe_pid0.c <<EOF
#include <stdio.h>
#include <unistd.h>
typedef struct PDPL PDPL_T;
extern PDPL_T* pdpl_get_from_text(const char *);
extern int     pdp_set_pid(int, const PDPL_T *);
extern PDPL_T* pdp_get_pid(int);
extern char*   pdpl_get_text(const PDPL_T *, int);
extern void    pdpl_put(PDPL_T *);
int main(void){
    PDPL_T *l = pdpl_get_from_text("0:0:0:");
    if (!l) return 1;
    int rc = pdp_set_pid(0, l);
    printf("set_pid(0) rc=%d\n", rc);
    pdpl_put(l);
    PDPL_T *cur = pdp_get_pid(getpid());
    if (cur) { char *t = pdpl_get_text(cur, 0); printf("current=%s\n", t ? t : "(null)"); pdpl_put(cur); }
    return 0;
}
EOF
gcc -o /tmp/probe_pid0 /tmp/probe_pid0.c -lpdp && sudo /tmp/probe_pid0'
# Expected: set_pid(0) rc=0, current="0:0:0:" — подтверждает 0 == self,
# а не "PG 0". ACCEPTANCE: Task 4.1 НЕ стартует, пока probe_pid0 не
# подтвердит rc=0 + read-back совпадает с установленным "0:0:0:".

# 5b. FALLBACK PROBE: pdp_set_pid_safe(0, l) поведение без CHMAC cap.
#    Зачем: spec §4.3 фиксирует _safe как fallback path; нужно
#    задокументировать, какой rc возвращается, если cap отсутствует.
ssh -p 2222 bfs_admin@127.0.0.1 \
    'cat > /tmp/probe_safe.c <<EOF
#include <stdio.h>
typedef struct PDPL PDPL_T;
extern PDPL_T* pdpl_get_from_text(const char *);
extern int     pdp_set_pid_safe(int, const PDPL_T *);
extern void    pdpl_put(PDPL_T *);
int main(void){
    PDPL_T *l = pdpl_get_from_text("0:0:0:");
    if (!l) return 2;
    int rc = pdp_set_pid_safe(0, l);
    printf("safe rc=%d\n", rc);
    pdpl_put(l);
    return 0;
}
EOF
gcc -o /tmp/probe_safe /tmp/probe_safe.c -lpdp && \
setpriv --inh-caps=-chmac /tmp/probe_safe 2>&1 || /tmp/probe_safe'
# Записать observed rc в spec Appendix C §C.7 как "fallback path: _safe
# returns rc=<N> without CHMAC". Не блокер для 4.1, но обязательно
# документируем (см. spec §4.3 — fallback rationale).

# 6. PARSEC_CAPGET LINK DECISION (BLOCKER for Task 4.2):
#    Определить, в каком .so живут parsec_capget/parsec_capset.
#    Если только в libpdp — оставляем единственный `cargo:rustc-link-lib=pdp`.
#    Если в libparsec-base — добавляем `-lparsec-base` в build.rs
#    + `Depends: libparsec-base3` в debian/control (Phase 8).
ssh -p 2222 bfs_admin@127.0.0.1 \
    'nm -D /usr/lib/libpdp.so* /lib/libparsec-base.so* /lib/libparsec-cap.so* 2>/dev/null | grep -E "parsec_capget|parsec_capset" | head'
# Записать decision в spec Appendix C §C.5 и в Plan Task 4.2 build.rs.
```

**Pre-flight: dpkg lock cleanup.** Background apt task на VM (см. 2026-05-14
diary) уже отпустила lock; перед запуском compile-steps быстро убедиться:

```bash
ssh -p 2222 bfs_admin@127.0.0.1 \
    'sudo fuser /var/lib/dpkg/lock-frontend 2>/dev/null; \
     sudo fuser /var/lib/apt/lists/lock 2>/dev/null; echo "locks clean"'
```

Если выводит PID — подождать завершения (apt после прерванного install
может занять минуту-другую). НЕ убивать процесс — это разрушит dpkg state.

Записать выводы в spec Appendix C §C.6.  Commit:

```bash
git add docs/superpowers/specs/2026-05-14-mac-integrity-design.md
git commit -m "docs(mac): verified libpdp symbols on Astra 1.8 VM"
```

### Task 4.0.5: Compile-test verified demo recipe on VM

**Goal:** убедиться что официальный demo из docs.astralinux.ru
действительно строится и работает на нашей VM до того, как мы начнём
писать Rust FFI. Если demo не компилируется — поднимать вопрос с
дистрибутивом раньше, чем потеряем время на FFI bindings.

```bash
ssh -p 2222 bfs_admin@127.0.0.1 'cat >/tmp/pdp_set_get_path.c <<'\''EOF'\''
// gcc -o pdp_set_get_path pdp_set_get_path.c -lpdp
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

int main(int argc, char **argv) {
    if (argc == 3) return pdpl_file_set(argv[1], argv[2]);
    if (argc == 2) return pdpl_file_get(argv[1]);
    fprintf(stderr, "usage: %s LABEL PATH | %s PATH\n", argv[0], argv[0]);
    return 2;
}
EOF
gcc -o /tmp/pdp_set_get_path /tmp/pdp_set_get_path.c -lpdp && \
echo "=== compile OK ===" && \
sudo touch /tmp/pdp_test_target && \
sudo /tmp/pdp_set_get_path "0:0:0::0" /tmp/pdp_test_target && \
/tmp/pdp_set_get_path /tmp/pdp_test_target'
```

Expected: команда печатает label (вида `0:0:0::0` или эквивалент с
дополнительными `default`-полями); exit code 0.

Если падает на этапе compile (`-lpdp not found`): убедиться что установлен
`libparsec-base` пакет (или Astra-specific `libpdp-dev`), и зафиксировать
в spec §C.6 / install.md.  Если падает в runtime — диагностировать через
`strace -e openat` (LSM-permission / strictmode не активен).

Commit (только если есть doc-обновления — иначе только заметка в
diary/CHANGELOG):

```bash
git add docs/install.md docs/superpowers/specs/2026-05-14-mac-integrity-design.md
git commit -m "docs(mac): verified libpdp demo recipe on Astra VM"
```

### Task 4.1: extern "C" сигнатуры (text-API)

**Files:**
- Modify: `crates/pam_certauth_core/src/mac/ffi.rs`

- [ ] **Step 1: Failing test** — `crates/pam_certauth_core/tests/mac_ffi_signatures.rs`:

```rust
#![cfg(feature = "astra-mac")]

/// Compile-only test: ensures FFI surface exists and links.
/// Real behaviour is verified on the Astra VM via test-mac.sh.
#[test]
fn ffi_symbols_link() {
    // touching the module forces linking
    let _ = pam_certauth_core::mac::ffi::probe_runtime();
}
```

- [ ] **Step 2: Run** — `cargo build -p pam_certauth_core --features astra-mac`
Expected: failure (no `ffi::probe_runtime`). Note: на dev box без libpdp эта команда падает на linker. Для CI без libpdp используйте `cargo check --features astra-mac` (linker не вызывается).

- [ ] **Step 3: Implement** `crates/pam_certauth_core/src/mac/ffi.rs`:

```rust
//! Hand-rolled libpdp text-API FFI. Linked only under `astra-mac`.
//!
//! Все сигнатуры verified в spec Appendix C (pdp.h, mic_db.h, demo).
//! **Никаких C-struct** не пересекают FFI-границу — opaque `PDPL_T *`
//! обёрнут в RAII `Pdpl`, метки кодируются текстом per spec §C.2.

#![allow(unsafe_code)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};
use std::path::Path;

use crate::mac::{IntegrityLabel, MacError, MacRuntime};

#[link(name = "pdp")]
extern "C" {
    // process integrity (PRIMARY для apply_session).
    // NB: `pdp_set_current` / `pdp_get_current` — inline-обёртки в pdp.h,
    //     в `libpdp.so.3` отсутствуют (verified 2026-05-14). Вызываем
    //     `pdp_set_pid(0, l)` напрямую.
    fn pdp_set_pid(pid: libc::pid_t, label: *const c_void) -> c_int;
    fn pdp_get_pid(pid: libc::pid_t) -> *mut c_void;

    // fd-based (§5.3.1 sessions.json TOCTOU)
    fn pdp_set_fd(fd: c_int, label: *const c_void) -> c_int;

    // path-based (file/dir labels — daemon socket setup, readonly home check)
    fn pdp_set_path(path: *const c_char, label: *const c_void) -> c_int;
    fn pdp_get_lpath(path: *const c_char) -> *mut c_void;

    // socket peer (future §5.3.2 — read peer integrity на UDS)
    fn pdp_get_peer_label(sockfd: c_int) -> *mut c_void;

    // text codec (cornerstone — IntegrityLabel ↔ PDPL_T идёт через текст)
    fn pdpl_get_from_text(text: *const c_char) -> *mut c_void;
    fn pdpl_get_text(l: *const c_void, flags: c_int) -> *mut c_char;
    fn pdpl_put(l: *mut c_void);

    // probes
    fn parsec_strict_mode() -> c_int;
    fn parsec_mac_enabled() -> c_int;

    // user МНКЦ lookup
    fn getmicnam(name: *const c_char) -> *mut MicUser;
    fn freemicent_r(res: *mut MicUser);
}

// parsec_capget: location verifies в Task 4.0 (libpdp.so.3 vs libparsec-base).
// Если только в libparsec-base — добавить `cargo:rustc-link-lib=parsec-base`
// в build.rs и сохранить второй extern блок ниже.
#[link(name = "pdp")]   // fallback link target: "parsec-base"
extern "C" {
    fn parsec_capget(pid: libc::pid_t, data: *mut ParsecCaps) -> c_int;
}

#[repr(C)]
pub struct MicUser {
    pub il: u32,
    pub name: *mut c_char,
}

/// `parsec_caps_t` per parsec_cap.h.  `parsec_cap_t` exact width
/// sanity-checked в Task 4.0 (вероятно `u64`).
#[repr(C)]
pub struct ParsecCaps {
    pub cap_effective:   u64,
    pub cap_inheritable: u64,
    pub cap_permitted:   u64,
}

/// PARSEC_CAP_CHMAC = bit 3 (parsec_cap.h).
pub const PARSEC_CAP_CHMAC: u32 = 3;

/// Type-safe МКЦ-флаги, передаваемые в text-форму label (spec §C.10).
/// Заменяет stringly-typed `flags: &str` — нельзя случайно опечататься
/// в `"ireelax"` и получить silent ignore от libpdp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McFlag {
    /// `irelax` — разрешить cross-level access (PDPT_IRELAX, dir/file).
    Irelax,
    /// `iinh` — наследование integrity на dir (PDPT_IINH).
    Iinh,
    /// `ccnr` — разные labels на dir entries (PDPT_CCNR).
    Ccnr,
    /// `ssi` — denies read by lower-integrity (PDPT_SSI).
    Ssi,
    /// `silev` — execute with file's integrity (PDPT_SILEV).
    Silev,
}

impl McFlag {
    /// Strict text-форма как принимает `pdpl_get_from_text`.
    fn as_str(self) -> &'static str {
        match self {
            Self::Irelax => "irelax",
            Self::Iinh   => "iinh",
            Self::Ccnr   => "ccnr",
            Self::Ssi    => "ssi",
            Self::Silev  => "silev",
        }
    }
}

/// RAII-обёртка над opaque PDPL_T pointer.  `Drop` вызывает `pdpl_put`.
pub struct Pdpl(*mut c_void);

impl Pdpl {
    /// Кодирует `IntegrityLabel` в text-формат и парсит libpdp'ом.
    ///
    /// `flags` — список МКЦ-флагов (см. `McFlag`); пустой slice если нет.
    /// Заменяет stringly-typed предыдущей версии — невозможно сделать
    /// опечатку, типобезопасно сериализуется в `iinh,irelax,...`.
    pub fn from_label(l: &IntegrityLabel, flags: &[McFlag]) -> Result<Self, MacError> {
        // conf_lev:integ_lev:cat_hex:flags:linear_ilev (per spec §C.2)
        let flags_str: String = flags
            .iter()
            .map(|f| f.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let text = format!("0:0:{:x}:{}:{}", l.categories, flags_str, l.level);
        let c = CString::new(text.clone())
            .map_err(|_| MacError::TextFormat(format!("label text contains NUL: {text:?}")))?;
        // SAFETY: c lives for the call; result is owned PDPL_T*.
        let ptr = unsafe { pdpl_get_from_text(c.as_ptr()) };
        if ptr.is_null() {
            // NULL → libpdp отвергло text (например, system-max категорий <64,
            // см. N3 / T12). Возвращаем Parsec rc=-1 — fail-closed штатно.
            return Err(MacError::Parsec { op: "pdpl_get_from_text", rc: -1 });
        }
        Ok(Self(ptr))
    }

    /// Декодирует opaque `PDPL_T *` обратно в text-форму через libpdp,
    /// потом парсит её как `IntegrityLabel`.
    pub fn to_label(&self) -> Result<IntegrityLabel, MacError> {
        // SAFETY: self.0 — valid opaque pointer; libpdp возвращает heap C-string.
        let raw = unsafe { pdpl_get_text(self.0, 0) };
        if raw.is_null() {
            return Err(MacError::Parsec { op: "pdpl_get_text", rc: -1 });
        }
        let cstr = unsafe { std::ffi::CStr::from_ptr(raw) };
        let s = cstr.to_string_lossy().into_owned();
        // SAFETY: pdpl_get_text возвращает malloc'ed buffer — freed via libc::free.
        unsafe { libc::free(raw as *mut c_void) };
        decode_label_text(&s)
    }

    pub fn as_ptr(&self) -> *const c_void { self.0 }
}

impl Drop for Pdpl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: ptr valid (constructed only via pdpl_get_from_text /
            // pdp_get_lpath / pdp_get_current).
            unsafe { pdpl_put(self.0) };
        }
    }
}

/// Parse text-форму label per spec §C.2: `conf:integ:cat_hex:flags:linear`.
/// Допускается trailing whitespace и **полностью отсутствующие** поля
/// (используем default 0). Но если поле **присутствует и не парсится**
/// (например, "zz" вместо hex) — возвращаем `MacError::TextFormat` (N9):
/// silent `unwrap_or(0)` маскировал бы ошибку и тихо понижал label.
fn decode_label_text(s: &str) -> Result<IntegrityLabel, MacError> {
    let s = s.trim();
    let parts: Vec<&str> = s.splitn(5, ':').collect();
    let categories = match parts.get(2) {
        None | Some(&"") => 0_u64,
        Some(hex) => u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .map_err(|e| MacError::TextFormat(format!(
                "decode cat hex {hex:?}: {e}"
            )))?,
    };
    let level = match parts.get(4) {
        None | Some(&"") => 0_i8,
        Some(lv) => lv.parse::<i8>()
            .map_err(|e| MacError::TextFormat(format!(
                "decode level {lv:?}: {e}"
            )))?,
    };
    Ok(IntegrityLabel { level, categories })
}

#[cfg(test)]
mod decode_label_text_tests {
    use super::*;
    #[test]
    fn err_on_bad_cat_hex() {
        // N9: "zz" — не парсится → Err, не silent 0.
        assert!(decode_label_text("0:0:zz:").is_err());
    }
    #[test]
    fn err_on_bad_level() {
        assert!(decode_label_text("0:0:0::not-an-int").is_err());
    }
    #[test]
    fn empty_fields_default_to_zero() {
        let l = decode_label_text("0:0::").unwrap();
        assert_eq!(l, IntegrityLabel { level: 0, categories: 0 });
    }
}

/// Probe libpdp/strictmode runtime.
#[must_use]
pub fn probe_runtime() -> MacRuntime {
    // SAFETY: parameterless FFI returning int.
    let strict = unsafe { parsec_strict_mode() };
    match strict {
        1 => MacRuntime::Active,
        0 => MacRuntime::Disabled,
        _ => MacRuntime::Unavailable,
    }
}

/// Применить метку к calling process через `pdp_set_pid(0, l)`.
///
/// NB: `pdp_set_current` — inline в `pdp.h` (`return pdp_set_pid(0, l);`),
/// в `libpdp.so` отсутствует как символ; ходим напрямую через `pdp_set_pid`.
///
/// **Не использовать `errno` после libpdp** — контракт описывает только
/// `int` rc; см. spec §4.3.
pub fn set_proc(label: IntegrityLabel) -> Result<(), MacError> {
    let p = Pdpl::from_label(&label, &[])?;
    // SAFETY: p.as_ptr() valid пока p жив (Drop в конце scope).
    let rc = unsafe { pdp_set_pid(0, p.as_ptr()) };
    if rc == 0 { Ok(()) } else { Err(MacError::Parsec { op: "pdp_set_pid(0, ..)", rc }) }
}

/// Self-check: cap_effective содержит PARSEC_CAP_CHMAC (bit 3).
/// Emit'ит `mac_caps_missing` audit warning если cap отсутствует.
/// Используется на инициализации модуля (spec §4.3).
pub fn check_chmac_capability() -> bool {
    use std::mem::MaybeUninit;
    let mut caps: MaybeUninit<ParsecCaps> = MaybeUninit::zeroed();
    // SAFETY: parsec_capget принимает out-ptr; pid=0 = self.
    let rc = unsafe { parsec_capget(0, caps.as_mut_ptr()) };
    if rc != 0 {
        return false;
    }
    // SAFETY: rc==0 ⇒ caps initialised by libparsec.
    let caps = unsafe { caps.assume_init() };
    (caps.cap_effective & (1u64 << PARSEC_CAP_CHMAC)) != 0
}

/// Look up user МНКЦ через `getmicnam` (NSS-aware, FreeIPA-backed).
pub fn get_user_mnkc(user: &str) -> Result<IntegrityLabel, MacError> {
    let c = CString::new(user)
        .map_err(|_| MacError::TextFormat("user CString contained NUL".into()))?;
    // SAFETY: c lives across the call.
    let raw = unsafe { getmicnam(c.as_ptr()) };
    if raw.is_null() {
        return Err(MacError::UserUnknown { user: user.to_string() });
    }
    // SAFETY: getmicnam возвращает heap-аллоцированный struct mic_user;
    // free через freemicent_r.
    let il = unsafe { (*raw).il };
    unsafe { freemicent_r(raw) };
    // saturate в i8 (см. spec §C.3 — exact mic_t width verifies в Task 4.0).
    let level = i8::try_from(il).unwrap_or(i8::MAX);
    Ok(IntegrityLabel { level, categories: 0_u64 })
}

/// Прочитать метку с пути (lstat-variant).
pub fn get_file_label(path: &Path) -> Result<IntegrityLabel, MacError> {
    let c = path_to_cstring(path)?;
    // SAFETY: c lives; result owned.
    let raw = unsafe { pdp_get_lpath(c.as_ptr()) };
    if raw.is_null() {
        return Err(MacError::Parsec { op: "pdp_get_lpath", rc: -1 });
    }
    let p = Pdpl(raw);
    p.to_label()
}

/// Установить метку на путь (path-variant). Для sessions.json — НЕ
/// использовать; см. `set_fd_label` (закрывает TOCTOU §5.3.1).
pub fn set_file_label(path: &Path, label: IntegrityLabel, irelax: bool) -> Result<(), MacError> {
    let c = path_to_cstring(path)?;
    let flags: &[McFlag] = if irelax { &[McFlag::Irelax] } else { &[] };
    let p = Pdpl::from_label(&label, flags)?;
    // SAFETY: c and p alive across the call.
    let rc = unsafe { pdp_set_path(c.as_ptr(), p.as_ptr()) };
    if rc == 0 { Ok(()) } else { Err(MacError::Parsec { op: "pdp_set_path", rc }) }
}

/// FD-based label — закрывает TOCTOU между open() и rename() при atomic
/// write sessions.json (spec §5.3.1).  `pdp_set_fd` sig подтверждена в pdp.h.
pub fn set_fd_label(fd: std::os::unix::io::RawFd, label: IntegrityLabel, irelax: bool) -> Result<(), MacError> {
    let flags: &[McFlag] = if irelax { &[McFlag::Irelax] } else { &[] };
    let p = Pdpl::from_label(&label, flags)?;
    // SAFETY: fd валиден (caller-owned); p alive across the call.
    let rc = unsafe { pdp_set_fd(fd, p.as_ptr()) };
    if rc == 0 { Ok(()) } else { Err(MacError::Parsec { op: "pdp_set_fd", rc }) }
}

fn path_to_cstring(p: &Path) -> Result<CString, MacError> {
    use std::os::unix::ffi::OsStrExt;
    CString::new(p.as_os_str().as_bytes())
        .map_err(|_| MacError::TextFormat(format!("path contained NUL: {}", p.display())))
}
```

**Note:** `MacError::Parsec` несёт `{ op: &'static str, rc: i32 }` — никакого
`errno` (порядок полей актуализирован Phase 3 Task 3.1 enum-блоком).
`MacError::UserUnknown { user }` — отдельный вариант для NULL-возврата от
`getmicnam` (см. spec §4.1.1); тащит имя пользователя для audit-лога.
`MacError::CapMissing` — emit при self-check (Task 4.2), не возникает в
hot path. Категории МНКЦ в первой реализации не
читаются (`getmicnam` возвращает только `il`); если позже потребуется
mic-cat support — расширить FFI отдельным API.

**libc dep:** добавить `libc = { workspace = true }` в
`crates/pam_certauth_core/Cargo.toml` для `libc::free` (used in
`Pdpl::to_label`). Альтернатива — extern `fn free(ptr: *mut c_void)` через
`#[link(name = "c")]`, но libc крейт уже в transitive deps.

Добавить `ParsecBackend` (для МКЦ через libpdp) в `backend.rs` (под cfg):

```rust
#[cfg(feature = "astra-mac")]
pub use crate::mac::ffi::probe_runtime as _;

#[cfg(feature = "astra-mac")]
#[derive(Debug, Default)]
pub struct ParsecBackend;

#[cfg(feature = "astra-mac")]
impl MacBackend for ParsecBackend {
    fn probe(&self) -> MacRuntime { crate::mac::ffi::probe_runtime() }
    fn get_user_mnkc(&self, user: &str) -> Result<IntegrityLabel, MacError> {
        crate::mac::ffi::get_user_mnkc(user)
    }
    fn apply_session(&self, label: IntegrityLabel) -> Result<(), MacError> {
        crate::mac::ffi::set_proc(label)
    }
    fn get_file_label(&self, p: &std::path::Path) -> Result<IntegrityLabel, MacError> {
        crate::mac::ffi::get_file_label(p)
    }
    fn set_file_label(&self, p: &std::path::Path, label: IntegrityLabel, irelax: bool) -> Result<(), MacError> {
        crate::mac::ffi::set_file_label(p, label, irelax)
    }
    fn set_fd_label(&self, fd: std::os::unix::io::RawFd, label: IntegrityLabel, irelax: bool) -> Result<(), MacError> {
        crate::mac::ffi::set_fd_label(fd, label, irelax)
    }
}
```

- [ ] **Step 4: Run**

Default build (stub):
```
cargo build -p pam_certauth_core
cargo test -p pam_certauth_core --features mac-tests
```
Expected: PASS.

FFI surface (no link):
```
cargo check -p pam_certauth_core --features astra-mac
```
Expected: PASS (compile only).

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_core/src/mac/ffi.rs crates/pam_certauth_core/src/mac/backend.rs crates/pam_certauth_core/tests/mac_ffi_signatures.rs
git commit -m "feat(mac): libparsec FFI bindings under astra-mac feature"
```

### Task 4.2: parsec_capget self-check at module init

**Goal:** на инициализации модуля проверить `cap_effective &
(1<<PARSEC_CAP_CHMAC)` через `parsec_capget(0, &caps)` (spec §4.3, §C.5).
Если cap отсутствует — эмиттим `mac_caps_missing` (Warning) и продолжаем в
degraded mode. Любая попытка `apply_session` всё равно завершится
fail-closed на FFI-уровне (libpdp вернёт ненулевой rc), но self-check даёт
ранний сигнал админу.

**Files:**
- Modify: `crates/pam_certauth_core/src/mac/ffi.rs` — экспортируем
  `check_chmac_capability()` (см. Task 4.1 sketch).
- Modify: `crates/pam_certauth_core/src/mac/backend.rs` — `ParsecBackend::new`
  вызывает self-check и эмиттит `audit::emit_caps_missing` если false.
- Modify: PAM entrypoint (Phase 6 Task 6.1) — конструировать `ParsecBackend`
  через `::new()` единожды per session (или per module load).

**Steps:**

```rust
// backend.rs (under feature = "astra-mac"):
#[cfg(feature = "astra-mac")]
impl ParsecBackend {
    pub fn new() -> Self {
        if !crate::mac::ffi::check_chmac_capability() {
            crate::mac::audit::emit_caps_missing(
                "parsec_capget showed PARSEC_CAP_CHMAC=0 in cap_effective"
            );
        }
        Self
    }
}
```

Test (compile-only, под `astra-mac`):

```rust
#![cfg(feature = "astra-mac")]
#[test]
fn parsec_backend_new_does_not_panic() {
    let _ = pam_certauth_core::mac::backend::ParsecBackend::new();
}
```

**Линковка parsec_capget (N2 — BLOCKER решение).** Phase 4 Task 4.0
probe #6 (`nm -D … | grep parsec_capget`) определяет финальное
решение. Два варианта:

A. **`parsec_capget` найден в `libpdp.so`** — оставляем единственный
   `cargo:rustc-link-lib=pdp` в `build.rs`. Без изменений в
   `debian/control`.

B. **`parsec_capget` найден в `libparsec-base.so`** — обязательно:
   1. В `build.rs` добавить второй link:

      ```rust
      #[cfg(feature = "astra-mac")]
      {
          println!("cargo:rustc-link-lib=pdp");
          println!("cargo:rustc-link-lib=parsec-base");
      }
      ```

   2. В `debian/control` (Phase 8 Task 8.0) Depends включает
      `libparsec-base3 (>= 3.11+ci97~)`.
   3. В spec Appendix C §C.5 зафиксировать "parsec_capget lives in
      libparsec-base.so" с датой verify.

ACCEPTANCE: Task 4.2 НЕ закрывается, пока probe #6 не выполнен и
build.rs не приведён в соответствие.

- [ ] **Commit**

```bash
git add crates/pam_certauth_core/src/mac/{ffi.rs,backend.rs} \
        crates/pam_certauth_core/build.rs \
        crates/pam_certauth_core/tests/mac_caps_selfcheck.rs
git commit -m "feat(mac): parsec_capget self-check warns on missing PARSEC_CAP_CHMAC"
```

---

## Phase 5: PAM hook pam_sm_open_session

### Task 5.1: Audit events emitter

**Files:**
- Modify: `crates/pam_certauth_core/src/mac/audit.rs`
- Modify: `crates/pam_certauth_core/src/x509/mod.rs` — добавить `CertIdent`
  builder (spec §4.1.3).

`CertIdent { serial, issuer, cn, fingerprint }` со `From<&VerifiedX509>`.
Все 4 cert-related MAC events (`mac_apply_failed`,
`cert_lacks_max_integrity_ext`, `cert_max_integrity_parse_failed`,
`integrity_capped_below_user_mnkc`) принимают `&CertIdent` и эмитят
`F_cert_serial`, `F_cert_issuer`, `F_cert_cn`, `F_cert_fpr` единообразно.

Rate-limit для `cert_max_integrity_parse_failed` (spec §9 «Rate-limit»):
LRU-cache по `fingerprint`, 60s окно, ≤256 записей.  Реализовать через
`once_cell::Lazy<Mutex<...>>` или `parking_lot::Mutex`.  Тест — emit
тот же fingerprint 3 раза подряд → один tracing-event (через
`tracing-test` или `tracing_subscriber::fmt::TestWriter`).

- [ ] **Step 1: Failing test** — `crates/pam_certauth_core/tests/mac_audit_events.rs`:

```rust
use pam_certauth_core::mac::audit;
use pam_certauth_core::mac::IntegrityLabel;

#[test]
fn event_names_are_stable_strings() {
    // Compile-time stability guard — these are part of audit contract.
    assert_eq!(audit::EVENT_MAC_APPLY_FAILED, "mac_apply_failed");
    assert_eq!(audit::EVENT_INTEGRITY_CAPPED, "integrity_capped_below_user_mnkc");
    assert_eq!(audit::EVENT_CERT_LACKS_EXT, "cert_lacks_max_integrity_ext");
    assert_eq!(audit::EVENT_MAC_SKIPPED, "mac_skipped");
    assert_eq!(audit::EVENT_HOMEDIR_LABEL_ABOVE, "homedir_label_above_session_cap");
    assert_eq!(audit::EVENT_CERT_EXT_PARSE_FAILED, "cert_max_integrity_parse_failed");
    assert_eq!(audit::EVENT_MAC_SOCKET_LABEL, "mac_socket_label_set");
    assert_eq!(audit::EVENT_MAC_SESSIONS_FILE_WARN, "mac_sessions_file_label_warning");
    assert_eq!(audit::EVENT_MAC_CAPS_MISSING, "mac_caps_missing");
    assert_eq!(audit::EVENT_MAC_SOCKET_PEER_LABEL, "mac_socket_peer_label_check");
    // N3
    assert_eq!(audit::EVENT_CERT_MAX_INT_CATS_ABOVE_32BIT, "cert_max_integrity_categories_above_32bit");
}

#[test]
fn capped_event_emits_without_panic() {
    use pam_certauth_core::x509::CertIdent;
    let cert_label = IntegrityLabel { level: 1, categories: 0_u64 };
    let user = IntegrityLabel { level: 3, categories: 0b11_u64 };
    let cid = CertIdent {
        serial: "AB12".into(), issuer: "CN=Test CA".into(),
        cn: "engineer".into(), fingerprint: "deadbeef".into(),
    };
    audit::emit_integrity_capped(&cert_label, &user, "alice", &cid);
}

#[test]
fn categories_above_32bit_event_emits() {
    audit::emit_categories_above_32bit(0xFFFF_FFFF_FFFF_FFFF);
}
```

- [ ] **Step 2: Run** — `cargo test -p pam_certauth_core --test mac_audit_events`
Expected: fail (нет констант).

- [ ] **Step 3: Implement** `mac/audit.rs`:

```rust
//! Audit emitters for МКЦ events. All events go through `tracing::event!`
//! with `F_*` structured fields; the system journald layer routes them.

use crate::mac::IntegrityLabel;
use crate::mac::backend::MacError;
use crate::x509::CertIdent;

pub const EVENT_MAC_APPLY_FAILED: &str = "mac_apply_failed";
pub const EVENT_INTEGRITY_CAPPED: &str = "integrity_capped_below_user_mnkc";
pub const EVENT_CERT_LACKS_EXT: &str = "cert_lacks_max_integrity_ext";
pub const EVENT_MAC_SKIPPED: &str = "mac_skipped";
pub const EVENT_HOMEDIR_LABEL_ABOVE: &str = "homedir_label_above_session_cap";
pub const EVENT_CERT_EXT_PARSE_FAILED: &str = "cert_max_integrity_parse_failed";
pub const EVENT_MAC_SOCKET_LABEL: &str = "mac_socket_label_set";
pub const EVENT_MAC_SESSIONS_FILE_WARN: &str = "mac_sessions_file_label_warning";
pub const EVENT_MAC_CAPS_MISSING: &str = "mac_caps_missing";
pub const EVENT_MAC_SOCKET_PEER_LABEL: &str = "mac_socket_peer_label_check";
/// N3: emitted when `IntegrityLabel.categories >> 32 != 0` (Notice).
pub const EVENT_CERT_MAX_INT_CATS_ABOVE_32BIT: &str = "cert_max_integrity_categories_above_32bit";

/// CRITICAL: libparsec refused to apply effective label.
/// N7: takes full `CertIdent`, emits unified F_cert_* fields.
pub fn emit_apply_failed(
    target: &IntegrityLabel,
    user_mnkc: &IntegrityLabel,
    user: &str,
    cert: &CertIdent,
    err: &MacError,
) {
    tracing::error!(
        event = EVENT_MAC_APPLY_FAILED,
        F_target_level = target.level,
        F_target_cats = target.categories,
        F_user_mnkc_level = user_mnkc.level,
        F_user_mnkc_cats = user_mnkc.categories,
        F_pam_user = user,
        F_cert_serial = %cert.serial,
        F_cert_issuer = %cert.issuer,
        F_cert_cn = %cert.cn,
        F_cert_fpr = %cert.fingerprint,
        F_error = %err,
        "mac apply failed"
    );
}

/// Notice: effective ⊏ user МНКЦ (strictly_below).  N7: CertIdent threaded.
pub fn emit_integrity_capped(
    effective: &IntegrityLabel,
    user_mnkc: &IntegrityLabel,
    user: &str,
    cert: &CertIdent,
) {
    tracing::info!(
        event = EVENT_INTEGRITY_CAPPED,
        F_effective_level = effective.level,
        F_effective_cats = effective.categories,
        F_user_mnkc_level = user_mnkc.level,
        F_user_mnkc_cats = user_mnkc.categories,
        F_pam_user = user,
        F_cert_serial = %cert.serial,
        F_cert_issuer = %cert.issuer,
        F_cert_cn = %cert.cn,
        F_cert_fpr = %cert.fingerprint,
        "integrity capped below user МНКЦ"
    );
}

/// Notice: cert without ext + required → deny.  N7: CertIdent threaded.
pub fn emit_cert_lacks_ext(user: &str, cert: &CertIdent) {
    tracing::info!(
        event = EVENT_CERT_LACKS_EXT,
        F_pam_user = user,
        F_cert_serial = %cert.serial,
        F_cert_issuer = %cert.issuer,
        F_cert_cn = %cert.cn,
        F_cert_fpr = %cert.fingerprint,
        "cert lacks MAX_INTEGRITY extension; required policy"
    );
}

/// Notice: categories маска > 32 бит (N3).  Concept-доки описывают 32-бит,
/// libpdp может отвергнуть при `pdpl_get_from_text` на VM с system-max <64.
pub fn emit_categories_above_32bit(categories: u64) {
    tracing::info!(
        event = EVENT_CERT_MAX_INT_CATS_ABOVE_32BIT,
        F_categories_hex = format!("{categories:016x}"),
        F_high32_hex = format!("{:08x}", categories >> 32),
        "cert categories exceed 32-bit width; libpdp may reject"
    );
}

/// Notice: МКЦ subsystem skipped (ignore mode or runtime unavailable).
pub fn emit_mac_skipped(reason: &str, user: &str) {
    tracing::info!(event = EVENT_MAC_SKIPPED, F_reason = reason, F_pam_user = user,
        "mac skipped");
}

/// Warning: interactive service hits homedir label above session cap.
pub fn emit_homedir_label_above(home_level: i8, session_cap: &IntegrityLabel, user: &str, service: &str) {
    tracing::warn!(
        event = EVENT_HOMEDIR_LABEL_ABOVE,
        F_home_level = home_level,
        F_session_level = session_cap.level,
        F_pam_user = user,
        F_pam_service = service,
        "homedir integrity label above session cap"
    );
}

/// Warning: cert ext present but malformed.  N7: CertIdent threaded.
pub fn emit_cert_ext_parse_failed(user: &str, cert: &CertIdent, err: &str) {
    tracing::warn!(
        event = EVENT_CERT_EXT_PARSE_FAILED,
        F_pam_user = user,
        F_cert_serial = %cert.serial,
        F_cert_issuer = %cert.issuer,
        F_cert_cn = %cert.cn,
        F_cert_fpr = %cert.fingerprint,
        F_error = err,
        "MAX_INTEGRITY ext parse failed"
    );
}

/// Debug: socket label was set.
pub fn emit_socket_label(path: &str) {
    tracing::debug!(event = EVENT_MAC_SOCKET_LABEL, F_path = path, "socket label set");
}

/// Warning: sessions.json lacks irelax at write time.
pub fn emit_sessions_file_warn(path: &str, err: Option<&str>) {
    tracing::warn!(event = EVENT_MAC_SESSIONS_FILE_WARN, F_path = path, F_error = err.unwrap_or("-"),
        "sessions.json missing irelax; attempting fixup");
}

/// Warning: self-check показал что PARSEC_CAP_CHMAC отсутствует в cap_effective.
/// Эмиттится один раз на инициализации модуля (spec §4.3).
pub fn emit_caps_missing(detail: &str) {
    tracing::warn!(event = EVENT_MAC_CAPS_MISSING, F_detail = detail,
        "PARSEC_CAP_CHMAC missing in cap_effective; apply_session will fail-closed");
}

/// Debug (future §5.3.2): monitord прочитал peer integrity на UDS.
pub fn emit_socket_peer_label(peer_pid: i32, peer_label: &str) {
    tracing::debug!(event = EVENT_MAC_SOCKET_PEER_LABEL, F_peer_pid = peer_pid,
        F_peer_label = peer_label, "socket peer integrity");
}
```

- [ ] **Step 4: Run** — `cargo test -p pam_certauth_core --test mac_audit_events`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_core/src/mac/audit.rs crates/pam_certauth_core/tests/mac_audit_events.rs
git commit -m "feat(mac): audit event emitters with F_-prefixed fields"
```

### Task 5.2: Orchestrator `apply_session_policy()` в core

**Files:**
- Create: `crates/pam_certauth_core/src/mac/orchestrator.rs`
- Modify: `crates/pam_certauth_core/src/mac/mod.rs`
- Create: `crates/pam_certauth_core/tests/mac_orchestrator.rs`

- [ ] **Step 1: Failing test**

```rust
#![cfg(feature = "mac-tests")]

use mockall::predicate::*;
use pam_certauth_core::config::validated::{CertIntegrityMode, MacPolicy};
use pam_certauth_core::mac::backend::MockMacBackend;
use pam_certauth_core::mac::orchestrator::{apply_session_policy, SessionContext, OutcomeKind};
use pam_certauth_core::mac::{IntegrityLabel, MacRuntime};

fn ctx() -> SessionContext {
    // N7: fake CertIdent — все 4 поля заполнены, чтобы тест мог
    // проверить, что emitted audit events содержат serial/issuer/cn/fpr.
    SessionContext {
        pam_user: "alice".into(),
        pam_service: "sshd".into(),
        cert_ident: pam_certauth_core::x509::CertIdent {
            serial: "AB12".into(),
            issuer: "CN=Test CA".into(),
            cn: "tok".into(),
            fingerprint: "deadbeef".into(),
        },
        home_dir: None,
    }
}

#[test]
fn required_with_cert_intersects_with_user_mnkc() {
    let mut m = MockMacBackend::new();
    m.expect_probe().return_const(MacRuntime::Active);
    m.expect_get_user_mnkc().return_once(|_| Ok(IntegrityLabel { level: 3, categories: 0b11_u64 }));
    m.expect_apply_session()
        .with(eq(IntegrityLabel { level: 2, categories: 0b01_u64 }))
        .return_once(|_| Ok(()));
    let pol = MacPolicy { cert_integrity: CertIntegrityMode::Required, ..MacPolicy::default() };
    let out = apply_session_policy(&m, &pol, Some(IntegrityLabel { level: 2, categories: 0b01_u64 }), &ctx()).unwrap();
    assert!(matches!(out.kind, OutcomeKind::Applied(_)));
}

#[test]
fn required_without_cert_denies() {
    let mut m = MockMacBackend::new();
    m.expect_probe().return_const(MacRuntime::Active);
    let pol = MacPolicy { cert_integrity: CertIntegrityMode::Required, ..MacPolicy::default() };
    let out = apply_session_policy(&m, &pol, None, &ctx()).unwrap_err();
    // M9: match на enum, не string-contains
    assert!(matches!(out,
        pam_certauth_core::mac::orchestrator::OrchestratorError::CertLacksExt));
}

#[test]
fn ignore_mode_skips_apply() {
    let mut m = MockMacBackend::new();
    m.expect_probe().return_const(MacRuntime::Active);
    let pol = MacPolicy { cert_integrity: CertIntegrityMode::Ignore, ..MacPolicy::default() };
    let out = apply_session_policy(&m, &pol, Some(IntegrityLabel { level: 2, categories: 0 }), &ctx()).unwrap();
    assert!(matches!(out.kind, OutcomeKind::Skipped(_)));
}

#[test]
fn optional_no_cert_no_fallback_uses_user_mnkc_unbounded() {
    let mut m = MockMacBackend::new();
    m.expect_probe().return_const(MacRuntime::Active);
    m.expect_get_user_mnkc().return_once(|_| Ok(IntegrityLabel { level: 3, categories: 0b11 }));
    m.expect_apply_session()
        .with(eq(IntegrityLabel { level: 3, categories: 0b11 }))
        .return_once(|_| Ok(()));
    let pol = MacPolicy { cert_integrity: CertIntegrityMode::Optional, ..MacPolicy::default() };
    let _ = apply_session_policy(&m, &pol, None, &ctx()).unwrap();
}

#[test]
fn runtime_disabled_with_required_denies() {
    let mut m = MockMacBackend::new();
    m.expect_probe().return_const(MacRuntime::Disabled);
    let pol = MacPolicy { cert_integrity: CertIntegrityMode::Required, ..MacPolicy::default() };
    assert!(apply_session_policy(&m, &pol, None, &ctx()).is_err());
}

#[test]
fn runtime_disabled_with_optional_skips() {
    let mut m = MockMacBackend::new();
    m.expect_probe().return_const(MacRuntime::Disabled);
    let pol = MacPolicy { cert_integrity: CertIntegrityMode::Optional, ..MacPolicy::default() };
    let out = apply_session_policy(&m, &pol, None, &ctx()).unwrap();
    assert!(matches!(out.kind, OutcomeKind::Skipped(_)));
}

#[test]
fn apply_eperm_returns_critical_error() {
    let mut m = MockMacBackend::new();
    m.expect_probe().return_const(MacRuntime::Active);
    m.expect_get_user_mnkc().return_once(|_| Ok(IntegrityLabel { level: 1, categories: 0 }));
    m.expect_apply_session()
        .return_once(|_| Err(pam_certauth_core::mac::MacError::Parsec { op: "mac_set_proc", rc: -1 }));
    let pol = MacPolicy { cert_integrity: CertIntegrityMode::Optional, ..MacPolicy::default() };
    let e = apply_session_policy(&m, &pol, Some(IntegrityLabel { level: 1, categories: 0 }), &ctx()).unwrap_err();
    // M9: enum match, не format!().contains()
    assert!(matches!(e,
        pam_certauth_core::mac::orchestrator::OrchestratorError::ApplyFailed(_)));
}
```

- [ ] **Step 2: Run** — fail (нет `orchestrator`).

**N7 — CertIdent wiring (explicit threading).** Orchestrator принимает
полный `CertIdent` внутри `SessionContext` и передаёт его в КАЖДЫЙ
`audit::emit_*` (а не голый `cert_cn`). Это гарантирует, что все 4
MAC-related события (`mac_apply_failed`, `cert_lacks_max_integrity_ext`,
`cert_max_integrity_parse_failed`, `integrity_capped_below_user_mnkc`)
выходят с одинаковым набором cert-полей (`F_cert_serial`,
`F_cert_issuer`, `F_cert_cn`, `F_cert_fpr`).

Сигнатура orchestrator (для ясности):

```rust
pub fn apply_session_policy<B: MacBackend + ?Sized>(
    backend: &B,
    policy: &MacPolicy,
    cert_max: Option<IntegrityLabel>,
    ctx: &SessionContext,                   // <-- содержит cert_ident
) -> Result<Outcome, OrchestratorError>;
```

`SessionContext { pam_user, pam_service, cert_ident, home_dir }` — единая
точка propagation. Тесты Task 5.2 строят fake
`CertIdent { serial: "AB12".into(), issuer: "CN=Test CA".into(),
cn: "engineer-cap-l2-c01".into(), fingerprint: "deadbeef".into() }` и
проверяют, что emitted audit-events содержат эти fields (через
`tracing-test`).

- [ ] **Step 3: Implement** `mac/orchestrator.rs`:

```rust
//! Orchestrator that turns `(MacPolicy, cert_max, user_МНКЦ)` into an apply
//! decision. Pure on top of `MacBackend` so it can be unit-tested with a
//! mock.

use crate::config::validated::{CertIntegrityMode, MacPolicy};
use crate::mac::audit;
use crate::mac::backend::{MacBackend, MacError};
use crate::mac::{IntegrityLabel, MacRuntime};

/// Per-session context required for orchestration + audit.
pub struct SessionContext {
    /// PAM user.
    pub pam_user: String,
    /// PAM service (login, sshd, sudo, ...).
    pub pam_service: String,
    /// Полные cert-identifying поля (spec §4.1.3) — обязательны для
    /// единообразного emit'а `mac_apply_failed`,
    /// `cert_lacks_max_integrity_ext`, `cert_max_integrity_parse_failed`,
    /// `integrity_capped_below_user_mnkc`. Build via
    /// `CertIdent::from(&VerifiedX509)` (Phase 5 Task 5.1).
    pub cert_ident: crate::x509::CertIdent,
    /// Optional homedir path for warn check.
    pub home_dir: Option<std::path::PathBuf>,
}

/// Outcome reported by [`apply_session_policy`].
#[derive(Debug)]
pub struct Outcome {
    /// Discriminated outcome variant.
    pub kind: OutcomeKind,
}

/// Outcome kind.
#[derive(Debug)]
pub enum OutcomeKind {
    /// Effective label applied.
    Applied(IntegrityLabel),
    /// МКЦ was skipped (with reason).
    Skipped(&'static str),
}

/// Error returned to PAM layer; stringified into PAM_SESSION_ERR.
#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    /// `cert_lacks_max_integrity_ext`.
    #[error("cert_lacks_max_integrity_ext")]
    CertLacksExt,
    /// `mac_apply_failed`.
    #[error("mac_apply_failed: {0}")]
    ApplyFailed(#[from] MacError),
    /// Required policy but strictmode disabled / runtime unavailable.
    #[error("mac_apply_failed: runtime {0:?}")]
    RuntimeRequired(MacRuntime),
}

fn is_interactive(service: &str) -> bool {
    matches!(service, "login" | "sshd" | "sddm" | "gdm")
}

/// Resolve & apply the effective label.
///
/// # Errors
/// See [`OrchestratorError`].
pub fn apply_session_policy<B: MacBackend + ?Sized>(
    backend: &B,
    policy: &MacPolicy,
    cert_max: Option<IntegrityLabel>,
    ctx: &SessionContext,
) -> Result<Outcome, OrchestratorError> {
    // Ignore mode short-circuits everything.
    if policy.cert_integrity == CertIntegrityMode::Ignore {
        audit::emit_mac_skipped("policy_ignore", &ctx.pam_user);
        return Ok(Outcome { kind: OutcomeKind::Skipped("policy_ignore") });
    }

    // Runtime probe.
    let runtime = backend.probe();
    match runtime {
        MacRuntime::Active => {}
        MacRuntime::Disabled => {
            if policy.cert_integrity == CertIntegrityMode::Required {
                return Err(OrchestratorError::RuntimeRequired(runtime));
            }
            audit::emit_mac_skipped("strictmode_disabled", &ctx.pam_user);
            return Ok(Outcome { kind: OutcomeKind::Skipped("strictmode_disabled") });
        }
        MacRuntime::Unavailable => {
            if policy.cert_integrity == CertIntegrityMode::Required {
                return Err(OrchestratorError::RuntimeRequired(runtime));
            }
            audit::emit_mac_skipped("runtime_unavailable", &ctx.pam_user);
            return Ok(Outcome { kind: OutcomeKind::Skipped("runtime_unavailable") });
        }
    }

    // Required + no cert ext → deny.
    if policy.cert_integrity == CertIntegrityMode::Required && cert_max.is_none() {
        // N7: emit с полным CertIdent, не только cn.
        audit::emit_cert_lacks_ext(&ctx.pam_user, &ctx.cert_ident);
        return Err(OrchestratorError::CertLacksExt);
    }

    let user_mnkc = backend.get_user_mnkc(&ctx.pam_user)?;

    let effective = match (cert_max, &policy.fallback_max_integrity) {
        (Some(c), _) => c.intersect_cert_with_user(&user_mnkc),
        (None, Some(fb)) => fb.intersect_cert_with_user(&user_mnkc),
        (None, None) => user_mnkc,
    };

    // N4: используем strictly_below — метки могут быть несравнимы,
    // плоское `<` по level некорректно.
    if effective.strictly_below(&user_mnkc) {
        audit::emit_integrity_capped(&effective, &user_mnkc, &ctx.pam_user, &ctx.cert_ident);
    }

    if policy.warn_on_homedir_label_mismatch && is_interactive(&ctx.pam_service) {
        if let Some(home) = &ctx.home_dir {
            if let Ok(home_label) = backend.get_file_label(home) {
                if home_label.level > effective.level {
                    audit::emit_homedir_label_above(home_label.level, &effective, &ctx.pam_user, &ctx.pam_service);
                }
            }
        }
    }

    backend.apply_session(effective).map_err(|e| {
        // N7: emit с полным CertIdent.
        audit::emit_apply_failed(&effective, &user_mnkc, &ctx.pam_user, &ctx.cert_ident, &e);
        OrchestratorError::ApplyFailed(e)
    })?;

    Ok(Outcome { kind: OutcomeKind::Applied(effective) })
}
```

В `mod.rs` добавить `pub mod orchestrator;`.

- [ ] **Step 4: Run** — `cargo test -p pam_certauth_core --features mac-tests --test mac_orchestrator`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_core/src/mac/orchestrator.rs crates/pam_certauth_core/src/mac/mod.rs crates/pam_certauth_core/tests/mac_orchestrator.rs
git commit -m "feat(mac): orchestrator deciding effective label from policy + runtime"
```

### Task 5.3: Wire orchestrator into pam_sm_open_session

**Files:**
- Modify: `crates/pam_certauth/src/lib.rs` (или соответствующий PAM entrypoint — engineer проверяет через `rg pam_sm_open_session crates/pam_certauth/`)

- [ ] **Step 1: Failing test** — integration harness тест в `crates/pam_certauth/tests/mac_open_session.rs`:

```rust
#![cfg(feature = "mac-tests")]
// Use existing test harness that fakes PamHandle and invokes pam_sm_open_session
// with a custom backend (DI via thread-local or context). If no such harness
// exists, add one minimal indirection: `pub fn open_session_with_backend(...)`.

#[test]
fn open_session_applies_effective_label() {
    use pam_certauth_core::mac::{IntegrityLabel, backend::MockMacBackend, MacRuntime};
    use mockall::predicate::*;

    let mut backend = MockMacBackend::new();
    backend.expect_probe().return_const(MacRuntime::Active);
    backend.expect_get_user_mnkc().return_once(|_| Ok(IntegrityLabel { level: 3, categories: 0b11 }));
    backend.expect_apply_session()
        .with(eq(IntegrityLabel { level: 2, categories: 0b01 }))
        .return_once(|_| Ok(()));

    let outcome = pam_certauth::test_only::run_open_session_pipeline(
        backend,
        Some(IntegrityLabel { level: 2, categories: 0b01 }),
        "alice", "sshd", "cn",
    ).unwrap();
    assert!(matches!(outcome.kind,
        pam_certauth_core::mac::orchestrator::OutcomeKind::Applied(_)));
}
```

- [ ] **Step 2: Run** — fail (нет `test_only::run_open_session_pipeline`).

- [ ] **Step 3: Implement**

В `crates/pam_certauth/src/lib.rs` (или новом submodule):

```rust
/// Exposed only under `mac-tests` for white-box pipeline testing.
#[cfg(feature = "mac-tests")]
pub mod test_only {
    use pam_certauth_core::config::validated::MacPolicy;
    use pam_certauth_core::mac::backend::MacBackend;
    use pam_certauth_core::mac::IntegrityLabel;
    use pam_certauth_core::mac::orchestrator::{
        apply_session_policy, Outcome, OrchestratorError, SessionContext,
    };

    /// Pure pipeline entrypoint usable from tests with a mock backend.
    ///
    /// # Errors
    /// Propagates [`OrchestratorError`].
    pub fn run_open_session_pipeline<B: MacBackend>(
        backend: B,
        cert_max: Option<IntegrityLabel>,
        user: &str,
        service: &str,
        cert_cn: &str,
    ) -> Result<Outcome, OrchestratorError> {
        let pol = MacPolicy::default();
        // N7: synthesise a CertIdent for white-box test entry; real flow
        // constructs it from VerifiedX509 in pam_sm_open_session.
        let cert_ident = pam_certauth_core::x509::CertIdent {
            serial:      "TEST-SERIAL".into(),
            issuer:      "CN=Test CA".into(),
            cn:          cert_cn.into(),
            fingerprint: "0".repeat(64),
        };
        let ctx = SessionContext {
            pam_user: user.into(),
            pam_service: service.into(),
            cert_ident,
            home_dir: None,
        };
        apply_session_policy(&backend, &pol, cert_max, &ctx)
    }
}
```

В реальном `pam_sm_open_session` (точный locator: `rg -n 'pam_sm_open_session' crates/pam_certauth/`):

```rust
// inside the existing pam_sm_open_session handler, AFTER cert validation,
// BEFORE returning PAM_SUCCESS:

// N7: build CertIdent once and reuse for every audit event below.
let cert_ident = pam_certauth_core::x509::CertIdent::from(&cert);

let cert_max = pam_certauth_core::x509::max_integrity_ext::extract_max_integrity(&cert)
    .map_err(|e| {
        pam_certauth_core::mac::audit::emit_cert_ext_parse_failed(
            &user, &cert_ident, &format!("{e}"));
        PamError::SessionErr
    })?;

let backend: Box<dyn pam_certauth_core::mac::backend::MacBackend> = {
    #[cfg(feature = "astra-mac")]
    { Box::new(pam_certauth_core::mac::backend::ParsecBackend::default()) }
    #[cfg(not(feature = "astra-mac"))]
    { Box::new(pam_certauth_core::mac::backend::StubBackend::default()) }
};

// L6: использовать getpwnam, не hardcode /home/{user} (домейн-юзера могут
// иметь $HOME из sssd с произвольным путём).
let home_dir = unsafe {
    let cuser = std::ffi::CString::new(user.as_str()).ok();
    cuser.and_then(|cu| {
        let pw = libc::getpwnam(cu.as_ptr());
        if pw.is_null() { None } else {
            let dir = (*pw).pw_dir;
            if dir.is_null() { None }
            else { Some(std::path::PathBuf::from(
                std::ffi::CStr::from_ptr(dir).to_string_lossy().into_owned())) }
        }
    })
};

let ctx = pam_certauth_core::mac::orchestrator::SessionContext {
    pam_user: user.clone(),
    pam_service: service.clone(),
    cert_ident: cert_ident.clone(),    // N7: full CertIdent, not bare cn
    home_dir,
};

pam_certauth_core::mac::orchestrator::apply_session_policy(
    backend.as_ref(),
    &config.mac,
    cert_max,
    &ctx,
).map_err(|_| PamError::SessionErr)?;
```

(Engineer адаптирует имена `cert`, `user`, `service`, `config` к фактическим в crate.)

Добавить feature-флаги в `crates/pam_certauth/Cargo.toml`:

```toml
[features]
default = []
astra-mac = ["pam_certauth_core/astra-mac"]
mac-tests = ["pam_certauth_core/mac-tests"]
```

- [ ] **Step 4: Run** — `cargo test -p pam_certauth --features mac-tests --test mac_open_session`
Expected: PASS. Также `cargo build -p pam_certauth` (default) и `cargo check -p pam_certauth --features astra-mac` (FFI surface).

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth/
git commit -m "feat(mac): wire orchestrator into pam_sm_open_session"
```

### Task 5.4: Stub-сборка fail-fast при cert_integrity=required

**Files:**
- Modify: `crates/pam_certauth_core/src/config/validated.rs`
- Create: `crates/pam_certauth_core/tests/mac_stub_fail_fast.rs`

- [ ] **Step 1: Failing test**

```rust
#[cfg(not(feature = "astra-mac"))]
#[test]
fn stub_build_rejects_required_policy_at_load() {
    let cfg_toml = include_str!("fixtures/policy_required_mac.toml");
    let raw: pam_certauth_core::config::raw::RawConfig = toml::from_str(cfg_toml).unwrap();
    let res: Result<pam_certauth_core::config::validated::ValidatedConfig, _> = raw.try_into();
    let err = res.unwrap_err().to_string();
    assert!(err.contains("astra-mac"), "expected build-flag hint, got: {err}");
}
```

(Создать fixture `policy_required_mac.toml` минимально валидным + `[mac]\ncert_integrity="required"\n`.)

- [ ] **Step 2: Run** — fail.

- [ ] **Step 3: Implement** — в `validated.rs` после построения `MacPolicy`:

```rust
#[cfg(not(feature = "astra-mac"))]
if matches!(mac.cert_integrity, CertIntegrityMode::Required) {
    return Err(ConfigError::InvalidValue(
        "[mac].cert_integrity = \"required\" but binary built without `astra-mac` feature".into(),
    ));
}
```

- [ ] **Step 4: Run** — PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_core/src/config/validated.rs crates/pam_certauth_core/tests/mac_stub_fail_fast.rs crates/pam_certauth_core/tests/fixtures/policy_required_mac.toml
git commit -m "feat(mac): stub build rejects cert_integrity=required at config load"
```

---

## Phase 6: Daemon socket labeling

### Task 6.1: Atomic rename + irelax на monitord.sock

**Files:**
- Modify: `crates/pam_certauth_monitord/src/server.rs`
- Modify: `crates/pam_certauth_monitord/Cargo.toml`
- Create: `crates/pam_certauth_monitord/tests/mac_socket_label.rs`

- [ ] **Step 1: Failing test**

```rust
#![cfg(feature = "mac-tests")]
use pam_certauth_core::mac::backend::MockMacBackend;
use pam_certauth_core::mac::IntegrityLabel;
use mockall::predicate::*;

#[test]
fn bind_calls_set_file_label_with_irelax_before_rename() {
    let tmp = tempfile::tempdir().unwrap();
    let final_path = tmp.path().join("monitord.sock");
    let mut mock = MockMacBackend::new();
    mock.expect_set_file_label()
        .withf(|p, l, irelax| {
            p.file_name().unwrap().to_string_lossy().contains(".tmp.")
                && l.level == 0 && *irelax
        })
        .return_once(|_, _, _| Ok(()));
    // call into helper
    pam_certauth_monitord::server::bind_with_label(&final_path, &mock).unwrap();
    assert!(final_path.exists());
}
```

- [ ] **Step 2: Run** — fail (нет `bind_with_label`).

- [ ] **Step 3: Implement** в `server.rs`:

```rust
/// Bind a Unix datagram/stream socket at `final_path` with МКЦ irelax label
/// applied atomically: bind on `.tmp.$PID`, label it, rename into place.
///
/// # Errors
/// Returns I/O error on bind/rename or `MacError` from `set_file_label`.
pub fn bind_with_label<B: pam_certauth_core::mac::backend::MacBackend>(
    final_path: &std::path::Path,
    backend: &B,
) -> std::io::Result<std::os::unix::net::UnixListener> {
    let tmp_name = format!(
        "{}.tmp.{}",
        final_path.display(),
        std::process::id()
    );
    let tmp_path = std::path::PathBuf::from(tmp_name);
    let _ = std::fs::remove_file(&tmp_path);
    let listener = std::os::unix::net::UnixListener::bind(&tmp_path)?;
    let label = pam_certauth_core::mac::IntegrityLabel { level: 0, categories: 0 };
    backend
        .set_file_label(&tmp_path, label, /*irelax=*/ true)
        .map_err(|e| std::io::Error::other(format!("set_file_label: {e}")))?;
    pam_certauth_core::mac::audit::emit_socket_label(&tmp_path.to_string_lossy());
    std::fs::rename(&tmp_path, final_path)?;
    Ok(listener)
}
```

Заменить существующий `UnixListener::bind(final_path)` call в `server.rs` на `bind_with_label(final_path, &backend)`, где `backend` — `ParsecBackend` под feature или `StubBackend` иначе.

Добавить в `Cargo.toml` daemon-crate:

```toml
[features]
default = []
astra-mac = ["pam_certauth_core/astra-mac"]
mac-tests = ["pam_certauth_core/mac-tests"]
```

- [ ] **Step 4: Run** — `cargo test -p pam_certauth_monitord --features mac-tests --test mac_socket_label`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_monitord/
git commit -m "feat(mac): atomic rename + irelax label on monitord.sock"
```

---

## Phase 7: sessions.json fd-based labeling (TOCTOU-safe)

### Task 7.1: write_sessions_atomic + fd-based set_label

**Закрывает C4 ревью.** Path-based `set_label(&path) → write_atomic(&path)`
оставляет окно TOCTOU.  Решение per spec §5.3.1 — labeling по fd на
ещё-не-видимом tempfile, дальше `persist()` (rename).

**Files:**
- Modify: `crates/pam_certauth_monitord/src/state.rs`
- Modify: `crates/pam_certauth_core/src/mac/backend.rs` — добавить
  `set_fd_label` в trait
- Create: `crates/pam_certauth_monitord/tests/mac_sessions_file.rs`

- [ ] **Step 0: Дополнить `MacBackend` trait методом `set_fd_label`**

В `backend.rs`:

```rust
/// FD-based label setter — закрывает TOCTOU при atomic write.  Spec §5.3.1.
///
/// # Errors
/// `Parsec` на non-zero rc; `Io` если fd невалиден.
fn set_fd_label(
    &self,
    fd: std::os::unix::io::RawFd,
    label: IntegrityLabel,
    irelax: bool,
) -> Result<(), MacError>;
```

StubBackend: `Ok(())`.  ParsecBackend под `astra-mac`: вызов
`crate::mac::ffi::set_fd_label(...)`.

- [ ] **Step 1: Failing test**

```rust
#![cfg(feature = "mac-tests")]
use pam_certauth_core::mac::backend::MockMacBackend;
use pam_certauth_core::mac::IntegrityLabel;
use mockall::predicate::*;

#[test]
fn write_atomic_labels_fd_before_rename() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("sessions.json");
    let mut m = MockMacBackend::new();
    m.expect_set_fd_label()
        .withf(|fd, l, irelax| *fd > 0 && l.level == 0 && *irelax)
        .return_once(|_, _, _| Ok(()));
    pam_certauth_monitord::state::write_sessions_atomic(&path, b"{}", &m).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"{}");
}
```

- [ ] **Step 2: Run** — fail.

- [ ] **Step 3: Implement** — заменить существующий path-based write на:

```rust
use std::io::Write;
use std::os::unix::io::AsRawFd;

/// Atomically write `sessions.json` with МКЦ irelax label set on the
/// inode BEFORE it becomes visible at `final_path` (closes TOCTOU per
/// spec §5.3.1).
pub fn write_sessions_atomic<B: pam_certauth_core::mac::backend::MacBackend>(
    final_path: &std::path::Path,
    bytes: &[u8],
    backend: &B,
) -> std::io::Result<()> {
    let parent = final_path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent dir")
    })?;
    // tempfile в той же fs => rename atomic
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    let fd = tmp.as_file().as_raw_fd();
    let label = pam_certauth_core::mac::IntegrityLabel { level: 0, categories: 0_u64 };
    if let Err(e) = backend.set_fd_label(fd, label, /*irelax=*/ true) {
        pam_certauth_core::mac::audit::emit_sessions_file_warn(
            &final_path.to_string_lossy(),
            Some(&format!("{e}")),
        );
        // продолжаем — best-effort; защита через DAC + parent dir iinh
    }
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(final_path).map_err(|e| e.error)?;
    Ok(())
}
```

Вызывать `write_sessions_atomic(&path, &serialized, &backend)?;` из всех
мест, которые ранее писали `sessions.json`.  Старый
`verify_or_fix_sessions_label` удалить — fd-based путь его поглощает.

- [ ] **Step 4: Run** — PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/pam_certauth_monitord/
git commit -m "feat(mac): best-effort irelax verify on sessions.json writes"
```

---

## Phase 8: Packaging

### Task 8.0: debian/control Depends (libpdp + conditional libparsec-base)

**Files:**
- Modify: `debian/control`

**Goal:** обеспечить runtime-зависимости пакета. `libpdp` обязателен;
`libparsec-base3` добавляется conditionally на основе результата
Phase 4 Task 4.0 probe #6 (parsec_capget link decision).

- [ ] **Step 1: Базовая зависимость на libpdp**

В `debian/control` для бинарного пакета `pam-certauth` в `Depends:` добавить:

```
Depends: ${shlibs:Depends}, ${misc:Depends},
         libpdp3 (>= 3.11+ci97~)
```

Минимальная версия `3.11+ci97~` — фактическая на Astra SE 1.8.4 VM
(verified `dpkg -l libpdp3` в Phase 4 Task 4.0). Tilde-suffix допускает
backport-варианты `3.11+ci97~bpo*`.

- [ ] **Step 2: Conditional libparsec-base3**

Если probe #6 (Task 4.0) показал, что `parsec_capget` живёт в
`libparsec-base.so` (а не в `libpdp.so`), добавить:

```
         libparsec-base3 (>= 3.11+ci97~)
```

В этом случае также добавить `cargo:rustc-link-lib=parsec-base` в
`crates/pam_certauth_core/build.rs` (см. Task 4.2 build.rs sketch ниже).
Если probe показал, что `parsec_capget` в `libpdp.so` — пропустить и
шаг 2 (Depends), и второй `link-lib` в build.rs.

- [ ] **Step 3: shlibs sanity check**

```bash
# В deb build env:
dpkg-shlibdeps -O debian/pam-certauth/usr/sbin/pam-certauth-monitord
```

Expected: вывод содержит `libpdp3` (и `libparsec-base3` если применимо).

- [ ] **Step 4: Commit**

```bash
git add debian/control
git commit -m "build(deb): pin libpdp3 + conditional libparsec-base3 runtime deps"
```

### Task 8.1: debian/postinst фрагмент

**Files:**
- Modify: `debian/postinst`
- Create: `debian/tmpfiles.d/pam-certauth.conf`
- Modify: `debian/pam-certauth.dirs` (если требуется)

- [ ] **Step 1: Verify current postinst** — engineer reads `debian/postinst` first.

- [ ] **Step 2: Append fragment** — добавить перед `exit 0`. Синтаксис
`pdpl-file` (Astra 1.8.4 verified man, see spec §5.2):
позиционная метка `[lev][:icat[:ccat[:flags][:linear_ilev]]]`, флаги МКЦ
`iinh`/`irelax` в 4-й позиции, `-R` рекурсия (НЕ `-r`).

```sh
# --- BEGIN Astra МКЦ integrity (pam_certauth 0.3.0) ---
# M2: check via exit code (is-enabled), не парсинг status output.
if command -v pdpl-file >/dev/null 2>&1 \
   && astra-strictmode-control is-enabled >/dev/null 2>&1; then
    # M3: NO || true — должны валить install если pdpl-file крашится
    # Flag numerics (pdp_common.h, verified 2026-05-14):
    #   PDPT_IINH   = 0x80   (dir inherit)
    #   PDPT_IRELAX = 0x20   (dir/file: allow cross-level)
    #   composition iinh+irelax = 0xA0
    pdpl-file :::iinh /etc/pam_certauth/                  # 0x80
    pdpl-file -R :::iinh /etc/pam_certauth/               # 0x80
    pdpl-file :::iinh,irelax /var/lib/pam_certauth/       # 0xA0
    if [ ! -e /var/lib/pam_certauth/sessions.json ]; then
        install -m 600 -o root -g root /dev/null /var/lib/pam_certauth/sessions.json
    fi
    pdpl-file :::irelax /var/lib/pam_certauth/sessions.json   # 0x20
    if [ -f /var/lib/pam_certauth/host_id ]; then
        pdpl-file 0:0 /var/lib/pam_certauth/host_id
        chattr +i /var/lib/pam_certauth/host_id 2>/dev/null || true
    fi
else
    echo "pam-certauth: parsec tools/strictmode not detected, skipping MAC integrity setup"
fi
# --- END Astra МКЦ integrity ---
```

Note: если `astra-strictmode-control is-enabled` не поддерживается на
target Astra версии, fallback — `astra-strictmode-control status 2>&1 |
grep -q '^enabled$'` с **якорной** регуляркой (а не `grep -qi enabled`,
который ложно матчится на `disabled`).

- [ ] **Step 3: tmpfiles.d**

`debian/tmpfiles.d/pam-certauth.conf`:

```
d /run/pam_certauth 0750 pamcertauth pamcertauth - -
```

И в `debian/install` (или `pam-certauth.install`) добавить строку:

```
debian/tmpfiles.d/pam-certauth.conf /usr/lib/tmpfiles.d/
```

- [ ] **Step 4: systemd unit**

В `debian/pam-certauth.pam-certauth-monitord.init` (если это шаблон systemd unit) либо в соответствующем `.service` файле добавить под `[Service]`:

```
RuntimeDirectory=pam_certauth
RuntimeDirectoryMode=0750
```

- [ ] **Step 5: Lint debian/postinst**

Run: `shellcheck debian/postinst`
Expected: no new warnings beyond pre-existing.

- [ ] **Step 6: Commit**

```bash
git add debian/postinst debian/tmpfiles.d/ debian/install debian/pam-certauth.pam-certauth-monitord.init
git commit -m "build(deb): postinst applies pdpl labels + tmpfiles.d + RuntimeDirectory"
```

---

## Phase 9: Fixture generation script

### Task 9.1: setup-mac-fixtures.sh + openssl.cnf шаблоны

**Files:**
- Create: `tests/fixtures/setup-mac-fixtures.sh`
- Create: `tests/fixtures/openssl-mac-l2-c01.cnf`
- Create: `tests/fixtures/openssl-mac-l1-empty.cnf`
- Create: `tests/fixtures/openssl-mac-no-ext.cnf`
- Create: `tests/fixtures/openssl-mac-l3.cnf`
- Create: `tests/fixtures/openssl-mac-malformed.cnf`
- Create: `tests/fixtures/openssl-mac-l0-fullcats.cnf` (N3: full u64 categories)

- [ ] **Step 1: Locate UUID и DER hex** — взять `<MAX_OID>` из Phase 0.

- [ ] **Step 2: Создать openssl.cnf шаблоны**

`tests/fixtures/openssl-mac-l2-c01.cnf` (engineer заменяет `<MAX_OID>` на реальный):

```ini
[ req ]
distinguished_name = req_dn
prompt = no
req_extensions = engineer_v3

[ req_dn ]
CN = engineer-cap-l2-c01

[ engineer_v3 ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,emailProtection
# fallback DER hex if ASN1:SEQUENCE breaks in legacy openssl:
# <MAX_OID> = DER:30:06:02:01:02:03:02:00:01
<MAX_OID> = ASN1:SEQUENCE:max_integrity

[ max_integrity ]
level      = INTEGER:2
categories = FORMAT:HEX,BITSTRING:01
```

`openssl-mac-l1-empty.cnf` — `level=1`, **no** `categories` line (defaults to empty BIT STRING). Альтернативно DER fallback `30:03:02:01:01`.

`openssl-mac-no-ext.cnf` — full cnf без MAX_INTEGRITY extension at all (для T4/T5/T6).

`openssl-mac-l3.cnf` — `level=3`, empty categories.

`openssl-mac-malformed.cnf` — DER fallback с truncated sequence:

```ini
<MAX_OID> = DER:30:02:02:01
```

`openssl-mac-l0-fullcats.cnf` — `level=0`, **полная маска u64** (для
T12, N3 — категории >32 бит):

```ini
[ req ]
distinguished_name = req_dn
prompt = no
req_extensions = engineer_v3

[ req_dn ]
CN = engineer-cap-l0-fullcats

[ engineer_v3 ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth,emailProtection
<MAX_OID> = ASN1:SEQUENCE:max_integrity

[ max_integrity ]
level      = INTEGER:0
categories = FORMAT:HEX,BITSTRING:ffffffffffffffff
```

- [ ] **Step 3: Script** `tests/fixtures/setup-mac-fixtures.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
CA_KEY="$DIR/ca.key.pem"
CA_CRT="$DIR/ca.crt.pem"

[ -f "$CA_KEY" ] || { echo "missing CA — run setup-ca first"; exit 1; }

gen() {
    local name="$1" cnf="$2"
    openssl req -new -newkey rsa:2048 -nodes \
        -keyout "$DIR/$name.key.pem" \
        -out    "$DIR/$name.csr.pem" \
        -config "$DIR/$cnf"
    openssl x509 -req \
        -in        "$DIR/$name.csr.pem" \
        -CA        "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
        -out       "$DIR/$name.crt.pem" \
        -days 365 -sha256 \
        -extfile   "$DIR/$cnf" -extensions engineer_v3
    rm -f "$DIR/$name.csr.pem"
}

gen engineer-cap-l2-c01    openssl-mac-l2-c01.cnf
gen engineer-cap-l1-empty  openssl-mac-l1-empty.cnf
gen engineer-no-mac-ext    openssl-mac-no-ext.cnf
gen engineer-mac-l3        openssl-mac-l3.cnf
gen engineer-mac-malformed openssl-mac-malformed.cnf
gen engineer-cap-l0-fullcats openssl-mac-l0-fullcats.cnf

echo "generated 6 MAC integrity fixtures in $DIR"
```

`chmod +x tests/fixtures/setup-mac-fixtures.sh`.

- [ ] **Step 4: Verify (smoke run на dev box)**

Run: `bash tests/fixtures/setup-mac-fixtures.sh && openssl x509 -in tests/fixtures/engineer-cap-l2-c01.crt.pem -noout -text | grep -A2 <MAX_OID>`
Expected: extension printed with proper hex.

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/setup-mac-fixtures.sh tests/fixtures/openssl-mac-*.cnf
git commit -m "test(fixtures): generator for 5 MAC integrity cert scenarios"
```

---

## Phase 10: E2E test script (Astra VM)

### Task 10.1: vagrant/scripts/test-mac.sh

**Files:**
- Create: `vagrant/scripts/test-mac.sh`

- [ ] **Step 1: Review baseline** — engineer прочитывает `vagrant/scripts/test-negative.sh` как шаблон.

- [ ] **Step 2: Implement** `vagrant/scripts/test-mac.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

SSH="ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null bfs_admin@127.0.0.1"
SCP="scp -P 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
FIX_DIR="$(cd "$(dirname "$0")/../../tests/fixtures" && pwd)"

journal_grep() { $SSH "sudo journalctl --since='1 min ago' -o cat | grep -F \"$1\""; }

# bring fixtures up to date
bash "$FIX_DIR/setup-mac-fixtures.sh"

# upload all certs + policy templates to VM
$SCP "$FIX_DIR"/engineer-*.crt.pem "$FIX_DIR"/engineer-*.key.pem bfs_admin@/tmp/

run_case() {
    local name="$1" policy_file="$2" cert="$3" expected_journal="$4" expected_pam="$5"
    echo "=== $name ==="
    $SSH "sudo cp /tmp/$policy_file /etc/pam_certauth/policy.toml"
    $SSH "sudo cp /tmp/$cert /etc/pam_certauth/test/cert.pem"
    set +e
    out=$($SSH "sudo PAM_TEST_USER=engineer pam-certauth-test open_session 2>&1")
    rc=$?
    set -e
    if [ "$expected_pam" = "success" ]; then
        [ $rc -eq 0 ] || { echo "$name: expected success, got rc=$rc; out=$out"; exit 1; }
    else
        [ $rc -ne 0 ] || { echo "$name: expected failure"; exit 1; }
    fi
    journal_grep "$expected_journal" || { echo "$name: missing audit '$expected_journal'"; exit 1; }
    echo "$name: OK"
}

# T1
run_case T1 policy-required.toml engineer-cap-l2-c01.crt.pem mac_apply_failed=NEVER success
# expected effective {2, 01b}; verify:
$SSH "sudo cat /proc/\$(pgrep -n bash)/attr/current" | tee /tmp/t1.label
grep -q "2:" /tmp/t1.label || { echo "T1 effective level mismatch"; exit 1; }

# T2
run_case T2 policy-required.toml engineer-cap-l1-empty.crt.pem integrity_capped_below_user_mnkc success
# T3
run_case T3 policy-required.toml engineer-mac-l3.crt.pem integrity_capped_below_user_mnkc success
# T4
run_case T4 policy-required.toml engineer-no-mac-ext.crt.pem cert_lacks_max_integrity_ext fail
# T5
run_case T5 policy-optional-fallback.toml engineer-no-mac-ext.crt.pem mac_apply_failed=NEVER success
# T6
run_case T6 policy-ignore.toml engineer-no-mac-ext.crt.pem mac_skipped success
# T7
run_case T7 policy-required.toml engineer-mac-malformed.crt.pem cert_max_integrity_parse_failed fail
# T8: strictmode off
$SSH "sudo astra-strictmode-control disable"
run_case T8 policy-optional.toml engineer-cap-l2-c01.crt.pem 'mac_skipped' success
$SSH "sudo astra-strictmode-control enable"
# T9: homedir mismatch
$SSH "sudo pdpl-file -l 3:0 /home/engineer"
run_case T9 policy-required.toml engineer-cap-l1-empty.crt.pem homedir_label_above_session_cap success
$SSH "sudo pdpl-file -l 0:0 /home/engineer"
# T10: socket label flag + actual cross-level connect (M6)
$SSH "getpdpl /run/pam_certauth/monitord.sock" | grep -q irelax \
    || { echo "T10: socket missing irelax"; exit 1; }
# Actually connect from a session running at integrity level 1:
$SSH "sudo -u engineer pdpl-shell --ilev 1 -- \
      socat -t1 - UNIX-CONNECT:/run/pam_certauth/monitord.sock <<<'PING' \
      | head -1" \
    | grep -q PONG \
    || { echo "T10: cross-level connect failed (irelax not honoured)"; exit 1; }

# T8.5: domain user resolution via getmicnam (требует sssd-bound VM или
# локальной mic-db record для test-user)
run_case T8.5  policy-required.toml  engineer-cap-l2-c01.crt.pem  integrity_capped_below_user_mnkc  success
# T8.5b: domain user without mic-db entry, required → deny
$SSH "sudo getent passwd unknown-mic-user || sudo useradd -M unknown-mic-user"
run_case T8.5b policy-required.toml  engineer-cap-l2-c01.crt.pem  mac_apply_failed  fail
$SSH "sudo userdel unknown-mic-user || true"

# T12 (N3): cert с full u64 categories на VM где system-max категорий <64.
# DER парсинг OK; orchestrator эмиттит Notice
# `cert_max_integrity_categories_above_32bit`; libpdp при
# pdpl_get_from_text("0:0:ffffffffffffffff:…") вернёт NULL → fail-closed
# `mac_apply_failed` с op=pdpl_get_from_text.
run_case T12 policy-required.toml engineer-cap-l0-fullcats.crt.pem mac_apply_failed fail
journal_grep "cert_max_integrity_categories_above_32bit" \
    || { echo "T12: missing Notice for categories above 32-bit"; exit 1; }

# T11: concurrent sessions, разные cert levels
$SSH "sudo cp /tmp/engineer-cap-l2-c01.crt.pem /etc/pam_certauth/test/cert.pem"
SESS_A=$($SSH "sudo PAM_TEST_USER=engineer pam-certauth-test open_session_bg 2>&1 | awk '/SESSION_ID/{print \$2}'")
$SSH "sudo cp /tmp/engineer-cap-l1-empty.crt.pem /etc/pam_certauth/test/cert.pem"
SESS_B=$($SSH "sudo PAM_TEST_USER=engineer pam-certauth-test open_session_bg 2>&1 | awk '/SESSION_ID/{print \$2}'")
$SSH "sudo jq --arg a $SESS_A --arg b $SESS_B '[.sessions[] | select(.id==\$a or .id==\$b)] | length' /var/lib/pam_certauth/sessions.json" \
    | grep -q '^2$' \
    || { echo "T11: sessions.json missing one of concurrent sessions"; exit 1; }
$SSH "sudo pam-certauth-test close_session $SESS_A; sudo pam-certauth-test close_session $SESS_B"

echo "ALL MAC E2E PASS"
```

### Task 10.2: Performance benchmark (H5)

**Files:**
- Create: `vagrant/scripts/bench-mac.sh`

**Goal:** убедиться что МКЦ-overhead на `pam_sm_open_session` ≤ p95 100 ms
для 100 последовательных логинов.

```bash
#!/usr/bin/env bash
set -euo pipefail
SSH="ssh -p 2222 ... bfs_admin@127.0.0.1"
# Baseline: pam-certauth без [mac]
$SSH "sudo cp /tmp/policy-ignore.toml /etc/pam_certauth/policy.toml"
BASE=$($SSH "for i in \$(seq 1 100); do
        /usr/bin/time -f '%e' sudo PAM_TEST_USER=engineer pam-certauth-test open_session >/dev/null 2>>/tmp/bench.log
    done
    awk '{a[NR]=\$1} END {asort(a); print a[int(NR*0.95)]}' /tmp/bench.log")
# Treatment: cert_integrity=required, реальный FFI
$SSH "sudo cp /tmp/policy-required.toml /etc/pam_certauth/policy.toml; rm -f /tmp/bench.log"
TREAT=$($SSH "for i in \$(seq 1 100); do
        /usr/bin/time -f '%e' sudo PAM_TEST_USER=engineer pam-certauth-test open_session >/dev/null 2>>/tmp/bench.log
    done
    awk '{a[NR]=\$1} END {asort(a); print a[int(NR*0.95)]}' /tmp/bench.log")
OVERHEAD=$(awk -v t=$TREAT -v b=$BASE 'BEGIN{print (t-b)*1000}')
echo "p95 overhead: ${OVERHEAD} ms (baseline ${BASE}s, treatment ${TREAT}s)"
awk -v o=$OVERHEAD 'BEGIN{exit (o<100)?0:1}' || { echo "FAIL: overhead > 100ms"; exit 1; }
```

Запускается опционально в CI nightly + перед release как gate.

`chmod +x vagrant/scripts/test-mac.sh`. Policy fixtures `policy-required.toml`, `policy-optional.toml`, `policy-optional-fallback.toml`, `policy-ignore.toml` engineer создаёт минимально валидными в `tests/fixtures/`.

- [ ] **Step 3: Run на VM** (manual)

```bash
bash vagrant/scripts/test-mac.sh
```
Expected: `ALL MAC E2E PASS`.

- [ ] **Step 4: Commit**

```bash
git add vagrant/scripts/test-mac.sh tests/fixtures/policy-*.toml
git commit -m "test(e2e): T1-T10 MAC integrity scenarios on Astra VM"
```

---

## Phase 11: Documentation

### Task 11.1: install.md, cert-issuance.md, configuration.md, threat-model.md, changelog.md

**Files:**
- Modify: `docs/install.md`
- Modify: `docs/cert-issuance.md`
- Modify: `docs/configuration.md`
- Modify: `docs/threat-model.md`
- Modify: `docs/changelog.md`

- [ ] **Step 1: install.md** — добавить раздел "Prerequisites: Astra МКЦ":

```markdown
## Prerequisites: Astra МКЦ integrity (optional)

Для интеграции с мандатным контролем целостности (МКЦ) Astra Linux требуется:

1. Установленный пакет `parsec-base` (предоставляет `libpdp.so`, `pdpl-file`,
   `astra-strictmode-control`).
2. Strictmode включён: `sudo astra-strictmode-control status` → `enabled`.
3. File capabilities на login binaries настроены пакетом `parsec` (проверить:
   `getcap /usr/sbin/sshd` должен показывать `CAP_PARSEC_ADMIN`).

Если parsec-base отсутствует или strictmode выключен, `pam_certauth.so` работает
без МКЦ (no-op). При `[mac].cert_integrity = "required"` сессия откроется
неуспешно — это намеренное fail-closed поведение.

### Cert issuance policy for interactive use

Для login/sshd/sddm выпускайте сертификаты с `max_integrity.level ≥ user_МНКЦ`,
иначе $HOME будет недоступен (см. `docs/threat-model.md` §Known limitations).
```

- [ ] **Step 2: cert-issuance.md** — добавить секцию "MAX_INTEGRITY extension":

```markdown
## MAX_INTEGRITY extension (опционально)

OID: `<MAX_OID>` (заменён в Phase 0).

ASN.1:

    PamCertAuthMaxIntegrity ::= SEQUENCE {
        level       INTEGER (-128..127),
        categories  BIT STRING DEFAULT ''B    -- до 64 бит (PDP_CAT_T = uint64_t)
    }

### Основной формат в openssl.cnf

```
<MAX_OID> = ASN1:SEQUENCE:max_integrity

[ max_integrity ]
level      = INTEGER:2
categories = FORMAT:HEX,BITSTRING:01
```

### Fallback DER hex (для старых openssl)

```
<MAX_OID> = DER:30:06:02:01:02:03:02:00:01
```

Пустые categories: либо опустить строку (default empty BIT STRING), либо
`DER:30:03:02:01:01`.

Семантика: cert несёт **потолок**; эффективный уровень сессии =
`min(cert, user_МНКЦ)`.
```

- [ ] **Step 3: configuration.md** — добавить раздел "[mac]":

```markdown
## [mac]

Управляет применением МКЦ при открытии PAM-сессии.

| Поле | Тип | Default | Описание |
|------|-----|---------|----------|
| `cert_integrity` | `"required" \| "optional" \| "ignore"` | `optional` | Trinary gate. |
| `fallback_max_integrity` | `{level, categories}` | unset | Применяется только при `optional` + ext отсутствует. |
| `warn_on_homedir_label_mismatch` | bool | `true` | Audit warning при interactive service + homedir.level > session.level. |

См. матрицу поведения в `docs/superpowers/specs/2026-05-14-mac-integrity-design.md` §3.

Пример:

```toml
[mac]
cert_integrity = "required"
warn_on_homedir_label_mismatch = true

[mac.fallback_max_integrity]
level = 0
categories = ""
```
```

- [ ] **Step 4: threat-model.md** — добавить:

```markdown
## МКЦ integrity (0.3.0)

Известные ограничения:

1. Cert с потолком ниже user_МНКЦ ломает доступ к $HOME для interactive login.
   Решается admin policy выпуска сертификатов. Не блокируется в коде (только
   warning `homedir_label_above_session_cap`).
2. После понижения user_МНКЦ старые cert с более высоким max_integrity
   корректно капятся вниз (intersect semantics).
3. Replay внутри cert validity — унаследовано от основного дизайна
   (см. main `scopes-and-m-of-n.md` §Replay).
4. Astra DIGSIG WAS_ALREADY_VERIFIED_AND_FAILED: подписать
   `pam-certauth(-monitord)` через `digsig_verify --sign` перед production
   установкой.
5. **Открытые сессии не re-evaluated при CA rotation / revocation.**
   pam_certauth применяет cert→label только в `pam_sm_open_session`.
   После revoke уже открытая shell-сессия продолжает работать со старым
   label.  Mitigation: short cert validity + admin завершает session явно
   (`pkill -KILL -u engineer`).
6. **`irelax` + UID 0 = ability to forge `sessions.json` / connect к
   socket из любого НКЦ.**  Защита от root-compromise — НЕ входит в нашу
   модель угроз.  `irelax` — необходимое следствие cross-level shared
   state (engineer level 1 должен мочь писать receipt'ы в lvl 0 daemon
   через socket).  Trust boundary — UID 0, не integrity.
```

- [ ] **Step 5: changelog.md** — добавить запись:

```markdown
## 0.3.0 (unreleased)

### Added

- Astra МКЦ integrity integration: extension `MAX_INTEGRITY` (OID `<MAX_OID>`),
  `[mac]` policy section, libpdp text-API FFI under `astra-mac` cargo feature.
- New audit events: `mac_apply_failed` (CRITICAL),
  `integrity_capped_below_user_mnkc`, `cert_lacks_max_integrity_ext`,
  `mac_skipped`, `homedir_label_above_session_cap`,
  `cert_max_integrity_parse_failed`, `mac_socket_label_set`,
  `mac_caps_missing` (self-check `parsec_capget` для `PARSEC_CAP_CHMAC`),
  `mac_socket_peer_label_check` (Debug, future §5.3.2),
  `mac_sessions_file_label_warning`.
- E2E test suite `vagrant/scripts/test-mac.sh` (T1–T10).

### Build

- Stub build (no `astra-mac`) compiles without libparsec; fails-fast at
  config load when `[mac].cert_integrity = "required"`.
```

- [ ] **Step 6: Commit**

```bash
git add docs/install.md docs/cert-issuance.md docs/configuration.md docs/threat-model.md docs/changelog.md
git commit -m "docs(mac): document МКЦ integration for 0.3.0"
```

---

## Phase 12: Review

### Task 12.1: master-code-reviewer + spec Appendix B checklist

- [ ] **Step 1: Run full local pipeline**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --features mac-tests -- -D warnings
cargo check --workspace --features astra-mac
cargo test --workspace
cargo test --workspace --features mac-tests
```
Expected: all green.

- [ ] **Step 2: Pre-commit dry-run**

```bash
pre-commit run --all-files
```
Expected: pass.

- [ ] **Step 3: Dispatch master-code-reviewer**

Запустить subagent `master-code-reviewer` с scope:
- `crates/pam_certauth_core/src/mac/`
- `crates/pam_certauth_core/src/x509/max_integrity_ext.rs`
- `crates/pam_certauth_core/src/config/{raw,validated}.rs` (diff)
- `crates/pam_certauth/src/lib.rs` (diff)
- `crates/pam_certauth_monitord/src/{server,state}.rs` (diff)
- `debian/postinst`
- `vagrant/scripts/test-mac.sh`

Critical/High findings — пофиксить отдельным commit'ом, повторить review.

- [ ] **Step 4: Walk Appendix B checklist из spec**

- [ ] OID UUID сгенерирован, single-source в `oids.rs`, CI-guard на
  плейсхолдеры (Phase 0.1).
- [ ] `pdpl-file` синтаксис verified (позиционная метка, флаги в 4-й
  позиции, `-R` рекурсия) — Phase 8.
- [ ] **Spec Appendix C (verified libpdp text-API) заполнен**, все
  `TODO: verify on VM` закрыты — Phase 4 Task 4.0 + 4.0.5.
- [ ] **C3 (struct layout) закрыт by design**: FFI работает через text-API,
  никакие C-структуры не пересекают границу (`PDPL_T` opaque +
  `Pdpl(*mut c_void)` RAII wrapper).
- [ ] `pdp_set_fd` подтверждена в pdp.h → fd-based labeling (Phase 7)
  реализуем без fallback.
- [ ] postinst idempotent + не использует `|| true` на критических шагах.
- [ ] T1–T11 + T8.5 + T10-actual-connect проходят на Astra VM.
- [ ] Performance benchmark p95 ≤ 100 ms (Phase 10 Task 10.2).
- [ ] master-code-reviewer прошёл.
- [ ] Все 5 doc-файлов обновлены (install/cert-issuance/configuration/
  threat-model/changelog).

- [ ] **Step 5: Tag 0.3.0**

```bash
git tag -a v0.3.0 -m "0.3.0: Astra МКЦ integrity integration"
```

(Push tag только после явного approval пользователя.)
