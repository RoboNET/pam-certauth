//! argv sanitisation, NFC validation, and canonicalisation of `argv[0]`.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Errors returned by [`canonicalize_and_validate`].
#[derive(Debug, Error)]
pub enum ArgvError {
    /// argv element contains NUL or an ASCII control byte.
    #[error("argv element contains invalid byte (NUL/control)")]
    InvalidByte,
    /// argv element is not in Unicode NFC form.
    #[error("non-NFC unicode in argv")]
    NonNfc,
    /// `argv[0]` could not be resolved on disk.
    #[error("cmd[0] not found in PATH or invalid: {0}")]
    NotFound(String),
}

/// Canonical view of an argv vector.
#[derive(Debug, Clone)]
pub struct CanonicalArgv {
    /// Realpath of `argv[0]`.
    pub argv0_resolved: PathBuf,
    /// Shell-escaped joined argv for audit / policy matching.
    pub joined: String,
}

/// Validate every argv element and resolve `argv[0]` to its realpath.
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
    let argv0_resolved =
        std::fs::canonicalize(&argv0).map_err(|_| ArgvError::NotFound(argv[0].clone()))?;

    let mut parts: Vec<String> = Vec::with_capacity(argv.len());
    parts.push(argv0_resolved.to_string_lossy().into_owned());
    for arg in &argv[1..] {
        parts.push(shell_escape(arg));
    }
    Ok(CanonicalArgv {
        argv0_resolved,
        joined: parts.join(" "),
    })
}

fn shell_escape(s: &str) -> String {
    if !s.is_empty()
        && s.bytes().all(|b| {
            matches!(b,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'-' | b'/' | b'.' | b':')
        })
    {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

fn resolve_in_path(cmd: &str) -> Result<PathBuf, ArgvError> {
    if cmd.contains('/') {
        return Ok(PathBuf::from(cmd));
    }
    let path =
        std::env::var("PATH").unwrap_or_else(|_| "/usr/sbin:/usr/bin:/sbin:/bin".to_string());
    for dir in path.split(':') {
        let candidate = Path::new(dir).join(cmd);
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_nul_byte() {
        let r = canonicalize_and_validate(&["flash\0rom".into()]);
        assert!(matches!(r, Err(ArgvError::InvalidByte)));
    }

    #[test]
    fn rejects_control_char() {
        let r = canonicalize_and_validate(&["foo\nbar".into()]);
        assert!(matches!(r, Err(ArgvError::InvalidByte)));
    }

    #[test]
    fn rejects_non_nfc() {
        // U+00E9 (NFC) vs U+0065 U+0301 (NFD). The NFD sequence is rejected.
        let nfd = "e\u{0301}".to_string();
        let r = canonicalize_and_validate(&[nfd]);
        assert!(matches!(r, Err(ArgvError::NonNfc)));
    }

    #[test]
    fn joins_with_shell_escape() {
        let canonical = canonicalize_and_validate(&[
            "/bin/echo".into(),
            "hello world".into(),
            "x".into(),
        ])
        .expect("canonicalize");
        // /bin/echo may resolve to /usr/bin/echo on some distros.
        assert!(canonical.joined.ends_with(" 'hello world' x"));
    }

    #[test]
    fn resolves_cmd0_to_realpath() {
        let canonical = canonicalize_and_validate(&["sh".into()]).expect("sh");
        assert!(canonical.argv0_resolved.is_absolute());
        assert!(canonical.joined.starts_with('/'));
    }

    #[test]
    fn rejects_missing_cmd() {
        let r = canonicalize_and_validate(&["/nonexistent/binary".into()]);
        assert!(matches!(r, Err(ArgvError::NotFound(_))));
    }
}
