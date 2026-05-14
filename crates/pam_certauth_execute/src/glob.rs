//! Glob matcher used for `argv_pattern` policy rules.
//!
//! Backed by the [`wildmatch`] crate. We deliberately support only the simple
//! `*` (any sequence) and `?` (single char) wildcards — POSIX bracket-classes
//! like `[0-9]` are intentionally **not** supported to keep policy semantics
//! easy to reason about. If richer matching is needed in the future the
//! implementation can be swapped for `globset` without changing the public
//! API.

use thiserror::Error;
use wildmatch::WildMatchPattern;

/// Errors returned by [`validate_pattern`].
#[derive(Debug, Error)]
pub enum GlobError {
    /// Pattern contains a `--` token, which is reserved for argv separation.
    #[error("pattern contains '--' literal which is forbidden")]
    ContainsDoubleDash,
}

/// Verify that an `argv_pattern` is well-formed.
pub fn validate_pattern(p: &str) -> Result<(), GlobError> {
    if p.split_whitespace().any(|tok| tok == "--") {
        return Err(GlobError::ContainsDoubleDash);
    }
    Ok(())
}

/// Match `candidate` against a wildcard `pattern`.
///
/// Supports `*` (any sequence including empty) and `?` (exactly one char).
pub fn glob_match(pattern: &str, candidate: &str) -> bool {
    WildMatchPattern::<'*', '?'>::new(pattern).matches(candidate)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
    fn pattern_with_dashes_disallowed_in_validate() {
        let r = validate_pattern("foo -- bar");
        assert!(matches!(r, Err(GlobError::ContainsDoubleDash)));
    }

    #[test]
    fn plain_pattern_validates() {
        assert!(validate_pattern("flashrom -w *.bin").is_ok());
    }

    #[test]
    fn exact_match() {
        assert!(glob_match("hello", "hello"));
        assert!(!glob_match("hello", "world"));
    }
}
