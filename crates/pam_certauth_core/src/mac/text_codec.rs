//! Pure-Rust text-format codec for Astra МКЦ labels.
//!
//! Encodes / decodes the `libpdp` text representation
//! `"conf:integ:cat_hex[:flags]"` (see spec §C.4 / §C.10, verified by a C
//! reproducer linking `-lpdp` on Astra 1.8.4 via `/usr/include/parsec/pdp.h`).
//! Confidentiality is field 0, integrity level is field 1, categories hex is
//! field 2, optional flags are field 3.  Kept feature-independent from the
//! FFI module (`crate::mac::ffi`) so the codec logic is testable on dev hosts
//! without `libpdp`.

// Codec is only invoked from `crate::mac::ffi`, which is itself gated behind
// the `astra-mac` cargo feature.  Without that feature these items have no
// non-test callers — silence dead-code lint to keep the default build clean.
#![cfg_attr(not(feature = "astra-mac"), allow(dead_code))]

use crate::mac::{IntegrityLabel, MacError};

/// libpdp text-API flags (see `pdp/pdp_common.h`).
///
/// Only `Irelax` is currently consumed by the FFI module; the remaining
/// variants are pre-declared to match the full libpdp text grammar and will
/// be wired up in later phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum McFlag {
    /// Allow integrity write-down (irelax).
    Irelax,
    /// Inheritable.
    Iinh,
    /// CCNR (no read from below).
    Ccnr,
    /// SSI.
    Ssi,
    /// Silev — strict integrity level enforcement.
    Silev,
}

impl McFlag {
    /// Single-character mnemonic used in libpdp text-encoded labels.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Irelax => "irelax",
            Self::Iinh => "iinh",
            Self::Ccnr => "ccnr",
            Self::Ssi => "ssi",
            Self::Silev => "silev",
        }
    }
}

/// Encode an [`IntegrityLabel`] into the libpdp text form
/// `"0:{ilevel}:{cat_hex}[:{flags}]"`.  Confidentiality (field 0) is always
/// zero — `pam_certauth` only cares about the integrity axis (field 1).
/// Categories hex occupies field 2; the optional flags field is emitted
/// only when `flags` is non-empty (so we never produce a stray trailing
/// `:` like `"0:1:0:"`).
pub(crate) fn encode_label_text(l: IntegrityLabel, flags: &[McFlag]) -> String {
    let base = format!("0:{}:{:x}", l.level, l.categories);
    if flags.is_empty() {
        base
    } else {
        let flag_str = flags
            .iter()
            .map(|f| McFlag::as_str(*f))
            .collect::<Vec<_>>()
            .join(",");
        format!("{base}:{flag_str}")
    }
}

/// Decode a libpdp text-format label `"conf:integ:cat_hex[:flags]"`.
///
/// Field 0 (confidentiality) is parsed but ignored — `pam_certauth` only
/// tracks the integrity axis. Field 1 is the integrity level (`i8`),
/// field 2 is categories hex (`u64`), optional field 3 carries flags
/// which are accepted for forward-compatibility but currently discarded
/// (the [`IntegrityLabel`] struct does not yet carry flag state).
/// Empty or missing trailing fields default to zero.
///
/// # Errors
/// Returns [`MacError::TextFormat`] if `integ` is non-empty but not a
/// valid `i8`, or if `cat_hex` is non-empty but not valid hex.
pub(crate) fn decode_label_text(s: &str) -> Result<IntegrityLabel, MacError> {
    let s = s.trim();
    let parts: Vec<&str> = s.splitn(4, ':').collect();
    let level = match parts.get(1) {
        None | Some(&"") => 0_i8,
        Some(lv) => lv
            .parse::<i8>()
            .map_err(|e| MacError::TextFormat(format!("bad level {lv:?}: {e}")))?,
    };
    let categories = match parts.get(2) {
        None | Some(&"") => 0_u64,
        Some(hex) => u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .map_err(|e| MacError::TextFormat(format!("bad cat hex {hex:?}: {e}")))?,
    };
    // Field 3 (flags) intentionally ignored — see doc comment.
    let _ = parts.get(3);
    Ok(IntegrityLabel { level, categories })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encode_roundtrip_default() {
        let l = IntegrityLabel {
            level: 3,
            categories: 0xab,
        };
        let s = encode_label_text(l, &[]);
        assert_eq!(s, "0:3:ab");
        let back = decode_label_text(&s).unwrap();
        assert_eq!(back, l);
    }

    #[test]
    fn encode_with_flags() {
        let l = IntegrityLabel {
            level: 1,
            categories: 0,
        };
        let s = encode_label_text(l, &[McFlag::Irelax, McFlag::Iinh]);
        assert_eq!(s, "0:1:0:irelax,iinh");
    }

    #[test]
    fn encode_integrity_level_one_no_flags() {
        // Regression: libpdp expects integrity level in field 1 with no
        // empty flags field appended.
        let l = IntegrityLabel {
            level: 1,
            categories: 0,
        };
        let s = encode_label_text(l, &[]);
        assert_eq!(s, "0:1:0");
        let back = decode_label_text(&s).unwrap();
        assert_eq!(back, l);
    }

    #[test]
    fn err_on_bad_cat_hex() {
        let r = decode_label_text("0:0:zz");
        assert!(matches!(r, Err(MacError::TextFormat(_))));
    }

    #[test]
    fn err_on_bad_level() {
        let r = decode_label_text("0:999:0");
        assert!(matches!(r, Err(MacError::TextFormat(_))));
    }

    #[test]
    fn empty_fields_default_to_zero() {
        let l = decode_label_text(":::").unwrap();
        assert_eq!(
            l,
            IntegrityLabel {
                level: 0,
                categories: 0
            }
        );
    }

    #[test]
    fn missing_trailing_fields_default_to_zero() {
        let l = decode_label_text("0:0:").unwrap();
        assert_eq!(
            l,
            IntegrityLabel {
                level: 0,
                categories: 0
            }
        );
    }

    #[test]
    fn too_few_fields_default_to_zero() {
        let l = decode_label_text("0:0").unwrap();
        assert_eq!(
            l,
            IntegrityLabel {
                level: 0,
                categories: 0
            }
        );
    }

    #[test]
    fn decode_ignores_flags_field() {
        // Flags field is accepted but discarded for now.
        let l = decode_label_text("0:1:0:irelax").unwrap();
        assert_eq!(
            l,
            IntegrityLabel {
                level: 1,
                categories: 0
            }
        );
    }

    #[test]
    fn mic_il_saturation_returns_max_i8() {
        // u32=200 → i8::try_from fails → MAX_I8=127 (restrictive, fail-safe).
        assert_eq!(i8::try_from(200_u32).unwrap_or(i8::MAX), 127);
        assert_eq!(i8::try_from(0_u32).unwrap(), 0);
        assert_eq!(i8::try_from(127_u32).unwrap(), 127);
    }

    #[test]
    fn negative_level_round_trips() {
        let l = IntegrityLabel {
            level: -5,
            categories: 0,
        };
        let s = encode_label_text(l, &[]);
        let back = decode_label_text(&s).unwrap();
        assert_eq!(back, l);
    }
}
