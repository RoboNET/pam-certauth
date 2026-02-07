//! Parser for `pam_certauth.so` module arguments.
//!
//! The cdylib's `pam_sm_*` entries collect raw `key=value` strings off the
//! C `argv` pointer; the parser here turns that into a typed
//! [`ParsedPamArgs`] struct that the auth flow consumes. New top-level
//! arguments live here so the C boundary keeps a single source of truth
//! for shape + defaults.
//!
//! Currently understood top-level arguments:
//!
//! - `config=<path>`              — override the config TOML path.
//! - `require_scope=<a,b,c>`      — list of scope names the engineer cert
//!   must claim (per `pam_cert_scopes`). Empty / absent disables the check.
//! - `scope_match=any|all`        — match mode for `require_scope`.
//!   Defaults to `any`. Unknown values fall back to `any`.
//!
//! Unrecognised `key=value` pairs are kept in [`ParsedPamArgs::extra`] so
//! later phases can extend the surface without breaking older builds.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Match policy for the `require_scope` list parameter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScopeMatch {
    /// At least one scope in `required_scopes` must be claimed by the
    /// engineer cert. This is the default to match the typical
    /// "user must hold AT LEAST one of these roles" semantics.
    #[default]
    Any,
    /// Every scope in `required_scopes` must be claimed by the engineer
    /// cert.
    All,
}

/// Typed projection of the raw PAM arg vector.
#[derive(Debug, Clone, Default)]
pub struct ParsedPamArgs {
    /// Optional path override for the config TOML.
    pub config_path: Option<PathBuf>,
    /// Scopes the engineer cert must claim. Empty disables the check.
    pub required_scopes: Vec<String>,
    /// Match mode for [`Self::required_scopes`].
    pub scope_match: ScopeMatch,
    /// Any `key=value` we did not recognise; available for diagnostic
    /// logging / forward compatibility tests.
    pub extra: BTreeMap<String, String>,
}

/// Parse a slice of `key=value` strings into a [`ParsedPamArgs`].
///
/// Whitespace around comma-separated `require_scope` entries is trimmed.
/// Empty entries (e.g. `require_scope=,,`) are filtered out so a trailing
/// comma does not silently inject an empty scope name.
#[must_use]
pub fn parse_pam_args(args: &[&str]) -> ParsedPamArgs {
    let mut out = ParsedPamArgs::default();
    for raw in args {
        let Some((k, v)) = raw.split_once('=') else {
            continue;
        };
        match k {
            "config" => out.config_path = Some(PathBuf::from(v)),
            "require_scope" => {
                out.required_scopes = v
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .collect();
            }
            "scope_match" => {
                out.scope_match = match v {
                    "all" => ScopeMatch::All,
                    // Anything else (including the literal "any") maps to
                    // Any. We could log a warning for typos in future.
                    _ => ScopeMatch::Any,
                };
            }
            _ => {
                out.extra.insert(k.to_string(), v.to_string());
            }
        }
    }
    out
}

/// Decide whether the engineer's claimed scopes satisfy the configured
/// `require_scope` list under the chosen [`ScopeMatch`] mode.
///
/// `claimed` is the list of scope strings returned by
/// `pam_certauth_core::x509::scopes_ext::parse` (already normalised to
/// `"*"` / `"bios.*"` / `"bios.flash"` shape).
#[must_use]
pub fn satisfies_required_scopes(
    claimed: &[String],
    required: &[String],
    mode: ScopeMatch,
) -> bool {
    if required.is_empty() {
        return true;
    }
    // Delegate to the single source of truth for scope-match semantics
    // shared with the execute runner (cli crate).
    let check_one = |req: &String| {
        pam_certauth_core::x509::scopes_ext::matches_strings(claimed, req)
    };
    match mode {
        ScopeMatch::Any => required.iter().any(check_one),
        ScopeMatch::All => required.iter().all(check_one),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_require_scope_list_with_match_all() {
        let args = vec!["mode=pkcs11", "require_scope=login.shell,admin", "scope_match=all"];
        let parsed = parse_pam_args(&args);
        assert_eq!(parsed.required_scopes, vec!["login.shell", "admin"]);
        assert_eq!(parsed.scope_match, ScopeMatch::All);
    }

    #[test]
    fn default_scope_match_is_any() {
        let parsed = parse_pam_args(&["require_scope=a,b"]);
        assert_eq!(parsed.scope_match, ScopeMatch::Any);
    }

    #[test]
    fn scope_match_unknown_falls_back_to_any() {
        let parsed = parse_pam_args(&["require_scope=a", "scope_match=garbage"]);
        assert_eq!(parsed.scope_match, ScopeMatch::Any);
    }

    #[test]
    fn require_scope_trims_and_drops_empty() {
        let parsed = parse_pam_args(&["require_scope= a , ,b , "]);
        assert_eq!(parsed.required_scopes, vec!["a", "b"]);
    }

    #[test]
    fn config_path_parsed() {
        let parsed = parse_pam_args(&["config=/tmp/c.toml"]);
        assert_eq!(parsed.config_path.as_deref().map(std::path::Path::to_str), Some(Some("/tmp/c.toml")));
    }

    #[test]
    fn unknown_keys_go_to_extra() {
        let parsed = parse_pam_args(&["foo=bar", "baz=qux"]);
        assert_eq!(parsed.extra.get("foo").map(String::as_str), Some("bar"));
        assert_eq!(parsed.extra.get("baz").map(String::as_str), Some("qux"));
    }

    #[test]
    fn satisfies_any_matches_when_one_claim_present() {
        let claimed = vec!["login.shell".to_string()];
        let req = vec!["login.shell".to_string(), "admin".to_string()];
        assert!(satisfies_required_scopes(&claimed, &req, ScopeMatch::Any));
    }

    #[test]
    fn satisfies_all_rejects_when_missing_one() {
        let claimed = vec!["login.shell".to_string()];
        let req = vec!["login.shell".to_string(), "admin".to_string()];
        assert!(!satisfies_required_scopes(&claimed, &req, ScopeMatch::All));
    }

    #[test]
    fn satisfies_with_wildcard_claim() {
        let claimed = vec!["*".to_string()];
        let req = vec!["whatever".to_string()];
        assert!(satisfies_required_scopes(&claimed, &req, ScopeMatch::All));
    }

    #[test]
    fn satisfies_with_prefix_wildcard_claim() {
        let claimed = vec!["bios.*".to_string()];
        let req = vec!["bios.flash".to_string()];
        assert!(satisfies_required_scopes(&claimed, &req, ScopeMatch::Any));
        let req_no = vec!["bios".to_string()];
        assert!(!satisfies_required_scopes(&claimed, &req_no, ScopeMatch::Any));
    }

    #[test]
    fn empty_required_list_passes() {
        assert!(satisfies_required_scopes(&[], &[], ScopeMatch::All));
        assert!(satisfies_required_scopes(
            &["a".to_string()],
            &[],
            ScopeMatch::All
        ));
    }
}
