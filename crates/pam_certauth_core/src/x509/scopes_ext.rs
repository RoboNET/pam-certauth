//! Parser for the `pam_cert_scopes` X.509 extension.
//!
//! ASN.1: `extnValue ::= SEQUENCE OF UTF8String`.
//!
//! Each entry is either:
//! - `"*"`                — wildcard, matches any scope;
//! - `^[a-z][a-z0-9_.-]{0,127}$` — an exact, lowercase, dot-namespaced scope.

use super::der_helpers::{extract_extension_by_oid, parse_seq_of_utf8};
use super::oids::SCOPES_OID;
use openssl::x509::X509Ref;
use thiserror::Error;

/// One scope entry from the `pam_cert_scopes` extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// `"*"` — matches any scope.
    Wildcard,
    /// Exact scope name (lowercase, dot-namespaced).
    Exact(String),
}

/// Errors produced while parsing the `pam_cert_scopes` extension.
#[derive(Debug, Error)]
pub enum ScopesExtError {
    /// The extension is not present in the certificate.
    #[error("extension missing")]
    Missing,
    /// The extension is present but its DER content is invalid.
    #[error("extension malformed: {0}")]
    Malformed(String),
    /// The extension is present but contains zero entries.
    #[error("extension has no entries")]
    Empty,
    /// One of the entries is not a wildcard and not a valid scope name.
    #[error("invalid scope name {0:?}")]
    InvalidScope(String),
}

/// Parses the `pam_cert_scopes` extension from `cert`.
///
/// # Errors
///
/// - [`ScopesExtError::Missing`]      — the extension is not in the cert.
/// - [`ScopesExtError::Empty`]        — present but `SEQUENCE OF UTF8String`
///   is empty.
/// - [`ScopesExtError::Malformed`]    — DER decoding failed.
/// - [`ScopesExtError::InvalidScope`] — an entry is neither `"*"` nor a
///   valid scope name per the regex above.
pub fn parse(cert: &X509Ref) -> Result<Vec<Scope>, ScopesExtError> {
    let der = cert
        .to_der()
        .map_err(|e| ScopesExtError::Malformed(format!("openssl: {e}")))?;

    let value = match extract_extension_by_oid(&der, SCOPES_OID) {
        Ok(Some(v)) => v,
        Ok(None) => return Err(ScopesExtError::Missing),
        Err(e) => return Err(ScopesExtError::Malformed(e.to_string())),
    };

    let strings =
        parse_seq_of_utf8(&value).map_err(|e| ScopesExtError::Malformed(e.to_string()))?;

    if strings.is_empty() {
        return Err(ScopesExtError::Empty);
    }

    strings.into_iter().map(classify).collect()
}

/// Returns true if any of the raw-string `claimed` scopes match `requested`.
///
/// Identical wildcard semantics to [`contains`] but accepts string slices
/// directly — convenient for call sites (PAM module, execute runner) that
/// store the engineer's scopes as plain strings out of `ActiveSessionReply`
/// or PAM args, without first round-tripping through [`Scope`].
///
/// - `"*"` matches anything.
/// - `"bios.*"` matches `"bios.flash"`, `"bios.erase"`, etc — but **not**
///   plain `"bios"`.
/// - any other entry must match `requested` exactly.
#[must_use]
pub fn matches_strings(claimed: &[String], requested: &str) -> bool {
    for c in claimed {
        if c == "*" {
            return true;
        }
        if c == requested {
            return true;
        }
        if let Some(prefix) = c.strip_suffix(".*") {
            let with_dot = format!("{prefix}.");
            if requested.starts_with(&with_dot) {
                return true;
            }
        }
    }
    false
}

/// Returns true if `claimed` scopes contain `requested` (with wildcard semantics).
///
/// - `Scope::Wildcard` matches anything.
/// - `Scope::Exact("bios.*")` matches `"bios.flash"`, `"bios.erase"`, etc.
/// - `Scope::Exact("bios.flash")` matches only `"bios.flash"`.
pub fn contains(claimed: &[Scope], requested: &str) -> bool {
    for c in claimed {
        match c {
            Scope::Wildcard => return true,
            Scope::Exact(s) if s == requested => return true,
            Scope::Exact(s) if s.ends_with(".*") => {
                // "bios.*" → prefix = "bios.", matches "bios.flash", "bios.erase",
                // but does not match plain "bios" (without dot).
                let prefix = &s[..s.len() - 1]; // includes trailing '.'
                if requested.starts_with(prefix) && requested.len() > prefix.len() {
                    return true;
                }
            }
            Scope::Exact(_) => {}
        }
    }
    false
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
    let mut bytes = s.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !first.is_ascii_lowercase() {
        return false;
    }
    bytes.all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'-'))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::x509::oids::SCOPES_OID;
    use crate::x509::test_utils::{build_cert, encode_seq_of_utf8};

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
    fn parses_multiple_scopes_in_order() {
        let cert = build_cert(&[(
            SCOPES_OID,
            encode_seq_of_utf8(&["bios.flash", "net.admin", "*"]),
        )]);
        let scopes = parse(&cert).unwrap();
        assert_eq!(
            scopes,
            vec![
                Scope::Exact("bios.flash".into()),
                Scope::Exact("net.admin".into()),
                Scope::Wildcard,
            ]
        );
    }

    #[test]
    fn rejects_invalid_scope_name() {
        let cert = build_cert(&[(SCOPES_OID, encode_seq_of_utf8(&["BAD UPPERCASE"]))]);
        let err = parse(&cert).unwrap_err();
        assert!(matches!(err, ScopesExtError::InvalidScope(_)));
    }

    #[test]
    fn rejects_scope_starting_with_digit() {
        let cert = build_cert(&[(SCOPES_OID, encode_seq_of_utf8(&["1bad"]))]);
        let err = parse(&cert).unwrap_err();
        assert!(matches!(err, ScopesExtError::InvalidScope(_)));
    }

    #[test]
    fn rejects_empty_extension() {
        // parse_seq_of_utf8 returns Ok(empty) for an empty SEQUENCE,
        // which classify() turns into ScopesExtError::Empty.
        let cert = build_cert(&[(SCOPES_OID, encode_seq_of_utf8(&[]))]);
        let err = parse(&cert).unwrap_err();
        assert!(matches!(
            err,
            ScopesExtError::Empty | ScopesExtError::Malformed(_)
        ));
    }

    #[test]
    fn returns_missing_when_absent() {
        let cert = build_cert(&[]);
        let err = parse(&cert).unwrap_err();
        assert!(matches!(err, ScopesExtError::Missing));
    }
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

    #[test]
    fn empty_claimed_returns_false() {
        assert!(!contains(&[], "bios.flash"));
    }

    #[test]
    fn prefix_wildcard_does_not_match_root_alone() {
        // "bios.*" should not match plain "bios" (without dot).
        assert!(!contains(&[Scope::Exact("bios.*".into())], "bios"));
    }
}
