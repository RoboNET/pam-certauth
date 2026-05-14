//! Pure-Rust text-format codec for Astra МКЦ labels.
//!
//! Encodes / decodes the `libpdp` text representation
//! `"conf:integ:cat_hex:flags:linear"` (see spec §C.4 / §C.10).  Kept feature-
//! independent from the FFI module (`crate::mac::ffi`) so the codec logic is
//! testable on dev hosts without `libpdp`.

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
/// `"0:0:{cat_hex}:{flags}:{level}"`.  Confidentiality fields are always
/// zero — `pam_certauth` only cares about the integrity axis.
pub(crate) fn encode_label_text(l: IntegrityLabel, flags: &[McFlag]) -> String {
    let mut flag_str = String::new();
    for (i, f) in flags.iter().enumerate() {
        if i != 0 {
            flag_str.push(',');
        }
        flag_str.push_str(f.as_str());
    }
    format!("0:0:{:x}:{}:{}", l.categories, flag_str, l.level)
}

/// Decode a libpdp text-format label `"conf:integ:cat_hex:flags:linear"`.
///
/// Empty `conf`/`integ` fields default to zero.  Bad hex or out-of-range
/// linear levels return [`MacError::TextFormat`].
///
/// # Errors
/// Returns [`MacError::TextFormat`] if the input does not split into exactly
/// five colon-separated fields, if `cat_hex` is not valid hex, or if `linear`
/// is not a valid `i8`.
pub(crate) fn decode_label_text(s: &str) -> Result<IntegrityLabel, MacError> {
    let parts: Vec<&str> = s.splitn(5, ':').collect();
    if parts.len() != 5 {
        return Err(MacError::TextFormat(format!(
            "expected 5 colon-separated fields, got {}",
            parts.len()
        )));
    }
    let cat_hex = parts[2];
    let categories = if cat_hex.is_empty() {
        0u64
    } else {
        u64::from_str_radix(cat_hex, 16)
            .map_err(|e| MacError::TextFormat(format!("bad cat hex {cat_hex:?}: {e}")))?
    };
    let linear = parts[4];
    let level = if linear.is_empty() {
        0i8
    } else {
        linear
            .parse::<i8>()
            .map_err(|e| MacError::TextFormat(format!("bad level {linear:?}: {e}")))?
    };
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
        assert_eq!(s, "0:0:ab::3");
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
        assert_eq!(s, "0:0:0:irelax,iinh:1");
    }

    #[test]
    fn err_on_bad_cat_hex() {
        let r = decode_label_text("0:0:zz::0");
        assert!(matches!(r, Err(MacError::TextFormat(_))));
    }

    #[test]
    fn err_on_bad_level() {
        let r = decode_label_text("0:0:0::999");
        assert!(matches!(r, Err(MacError::TextFormat(_))));
    }

    #[test]
    fn empty_fields_default_to_zero() {
        let l = decode_label_text("::::").unwrap();
        assert_eq!(
            l,
            IntegrityLabel {
                level: 0,
                categories: 0
            }
        );
    }

    #[test]
    fn err_on_too_few_fields() {
        let r = decode_label_text("0:0:0");
        assert!(matches!(r, Err(MacError::TextFormat(_))));
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
