//! Policy parser + rule resolver. See `docs/policy.md`.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

const KNOWN_HOOKS: &[&str] = &["noop", "audit_critical"];

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("utf8: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("validation: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuditLevel {
    #[default]
    Info,
    Notice,
    Warning,
    Critical,
}

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
        let text = std::str::from_utf8(&bytes)?;
        let raw: RawPolicy = toml::from_str(text)?;
        let sha256 = {
            use sha2::{Digest, Sha256};
            Sha256::digest(&bytes).into()
        };
        let p = Self { raw, sha256 };
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        // m_of_n должно быть определено (в defaults или в scope)
        let default_m = self.raw.defaults.m_of_n;
        if let Some(0) = default_m {
            return Err(PolicyError::Validation(
                "defaults.m_of_n must be >= 1 (got 0)".into(),
            ));
        }
        // Defaults hooks must reference known hooks too.
        for hook in self
            .raw
            .defaults
            .pre_hooks
            .iter()
            .chain(self.raw.defaults.post_hooks.iter())
        {
            if !KNOWN_HOOKS.contains(&hook.as_str()) {
                return Err(PolicyError::Validation(format!(
                    "defaults references unknown hook {hook:?}"
                )));
            }
        }
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

    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

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
                        if best.is_none_or(|(blen, _)| len > blen) {
                            best = Some((len, v));
                        }
                    }
                }
            }
            candidate = best.map(|(_, v)| v);
        }
        let d = &self.raw.defaults;
        let s = candidate.unwrap_or(d);
        ScopeRule {
            m_of_n: s.m_of_n.or(d.m_of_n).unwrap_or(1),
            require_argv_pattern: s.require_argv_pattern.or(d.require_argv_pattern).unwrap_or(false),
            forbid_self_approval: s.forbid_self_approval.or(d.forbid_self_approval).unwrap_or(true),
            require_timestamp_token: s.require_timestamp_token.or(d.require_timestamp_token).unwrap_or(false),
            audit_level: s.audit_level.or(d.audit_level).unwrap_or(AuditLevel::Info),
            pre_hooks: if !s.pre_hooks.is_empty() {
                s.pre_hooks.clone()
            } else {
                d.pre_hooks.clone()
            },
            post_hooks: if !s.post_hooks.is_empty() {
                s.post_hooks.clone()
            } else {
                d.post_hooks.clone()
            },
            timeout_seconds: s.timeout_seconds.or(d.timeout_seconds),
        }
    }
}

#[cfg(test)]
mod rule_for_tests {
    use super::*;

    fn load(s: &str) -> Policy {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("policy.toml");
        std::fs::write(&p, s).unwrap();
        let pol = Policy::load(&p).unwrap();
        std::mem::forget(dir);
        pol
    }

    #[test]
    fn exact_match_wins_over_wildcard() {
        let p = load(
            "[defaults]\nm_of_n = 1\n[scope.\"bios.*\"]\nm_of_n = 3\n[scope.\"bios.flash\"]\nm_of_n = 2\n",
        );
        assert_eq!(p.rule_for("bios.flash").m_of_n, 2);
    }

    #[test]
    fn wildcard_falls_through() {
        let p = load("[defaults]\nm_of_n = 1\n[scope.\"bios.*\"]\nm_of_n = 3\n");
        assert_eq!(p.rule_for("bios.erase").m_of_n, 3);
    }

    #[test]
    fn defaults_used_when_nothing_matches() {
        let p = load("[defaults]\nm_of_n = 1\naudit_level = \"info\"\n");
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

#[cfg(test)]
mod validate_tests {
    use super::*;

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
    fn rejects_zero_default_m_of_n() {
        let err = load("[defaults]\nm_of_n = 0\n").unwrap_err();
        assert!(matches!(err, PolicyError::Validation(_)));
    }

    #[test]
    fn rejects_missing_m_of_n_after_defaults_unset() {
        let err = load("[scope.\"x\"]\n").unwrap_err();
        assert!(matches!(err, PolicyError::Validation(_)));
    }

    #[test]
    fn rejects_unknown_hook_name() {
        let err = load("[defaults]\nm_of_n = 1\n[scope.\"x\"]\npre_hooks = [\"unknown\"]\n")
            .unwrap_err();
        assert!(matches!(err, PolicyError::Validation(s) if s.contains("unknown")));
    }

    #[test]
    fn rejects_unknown_hook_name_in_defaults() {
        let err = load("[defaults]\nm_of_n = 1\npre_hooks = [\"unknown_default\"]\n")
            .unwrap_err();
        assert!(matches!(err, PolicyError::Validation(s) if s.contains("unknown_default")));
    }

    #[test]
    fn accepts_valid_policy() {
        let p = load("[defaults]\nm_of_n = 1\n[scope.\"bios.flash\"]\nm_of_n = 2\n").unwrap();
        assert_eq!(p.sha256().len(), 32);
    }
}
