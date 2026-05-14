//! Static hook framework for `pam-certauth execute`.
//!
//! MVP: only built-in hooks; no fork/exec, no dynamic plugins. The
//! [`Policy`](pam_certauth_policy::Policy) validator already restricts
//! `pre_hooks` / `post_hooks` values to [`KNOWN_HOOKS`] so dispatch here
//! cannot encounter an unknown name unless someone routes around the
//! validator (we still return an explicit error in that case).

use thiserror::Error;

/// Built-in hook implementations recognised by the dispatcher.
///
/// Keep this in lock-step with `KNOWN_HOOKS` in `pam_certauth_policy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuiltinHook {
    /// No-op; useful for explicit "hook is configured but does nothing"
    /// markers in test/sample policy files.
    Noop,
    /// Emits a `tracing::warn!` audit line marking the scope action as
    /// critical. Replaces the future syslog(Crit) sink described in the
    /// spec — same channel, lower dependency surface.
    AuditCritical,
}

/// Phase a hook is invoked in. Determines failure handling: pre-hook errors
/// abort execution, post-hook errors are logged and swallowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookPhase {
    /// Runs before the child is spawned; failure denies execution.
    Pre,
    /// Runs after the child exits; failure is logged but ignored.
    Post,
}

/// Per-invocation context handed to every hook.
#[derive(Debug)]
pub struct HookContext<'a> {
    /// Which phase the dispatcher is in.
    pub phase: HookPhase,
    /// Scope being executed.
    pub scope: &'a str,
    /// Engineer common name (from the active session); may be empty in
    /// pre-flight denials.
    pub engineer_cn: &'a str,
    /// Canonicalised argv (argv0 is the resolved binary path).
    pub argv: &'a [String],
    /// Child exit code; `None` during the pre-phase.
    pub exit_code: Option<i32>,
}

/// Errors that can be returned by hook resolution / execution.
#[derive(Debug, Error)]
pub enum HookError {
    /// The hook name is not one of [`BuiltinHook`]'s variants.
    #[error("unknown hook: {0}")]
    Unknown(String),
    /// A built-in hook returned an error.
    #[error("hook {0} failed: {1}")]
    Failed(String, String),
}

impl BuiltinHook {
    /// Resolve a hook by configured name.
    ///
    /// # Errors
    ///
    /// Returns [`HookError::Unknown`] if `s` is not a recognised hook name.
    pub fn from_name(s: &str) -> Result<Self, HookError> {
        match s {
            "noop" => Ok(Self::Noop),
            "audit_critical" => Ok(Self::AuditCritical),
            other => Err(HookError::Unknown(other.to_string())),
        }
    }

    /// Run the hook against `ctx`.
    ///
    /// # Errors
    ///
    /// Currently neither built-in hook can fail at runtime; the return
    /// type stays `Result` so future hooks can surface failures.
    pub fn run(&self, ctx: &HookContext<'_>) -> Result<(), HookError> {
        match self {
            Self::Noop => Ok(()),
            Self::AuditCritical => {
                let phase = match ctx.phase {
                    HookPhase::Pre => "pre",
                    HookPhase::Post => "post",
                };
                tracing::warn!(
                    target: "pam_certauth.execute.critical",
                    scope = %ctx.scope,
                    engineer_cn = %ctx.engineer_cn,
                    phase = %phase,
                    exit_code = ?ctx.exit_code,
                    "critical scope action"
                );
                Ok(())
            }
        }
    }
}

/// Run a sequence of named hooks in order against `ctx`.
///
/// In [`HookPhase::Pre`] the first hook *execution* error aborts and is
/// returned to the caller (which denies the execute). In
/// [`HookPhase::Post`] hook execution errors are logged at `warn!` and
/// the remaining hooks still run.
///
/// **Exception:** [`HookError::Unknown`] from
/// [`BuiltinHook::from_name`] propagates in *both* phases. An unknown
/// hook name indicates configuration drift between the policy file and
/// the binary — not a runtime failure of the hook itself — and silently
/// skipping it would let a misnamed hook quietly disappear from the
/// audit trail. Callers must surface this as a deny so the operator
/// fixes the policy.
///
/// # Errors
///
/// * Any [`HookError::Unknown`] from name resolution (both phases).
/// * The first hook *execution* error encountered when in
///   [`HookPhase::Pre`].
pub fn run_hooks(hook_names: &[String], ctx: &HookContext<'_>) -> Result<(), HookError> {
    for name in hook_names {
        let hook = BuiltinHook::from_name(name)?;
        match (ctx.phase, hook.run(ctx)) {
            (HookPhase::Pre, Err(e)) => return Err(e),
            (HookPhase::Post, Err(e)) => {
                tracing::warn!(
                    target: "pam_certauth.execute.hooks",
                    hook = %name,
                    error = %e,
                    "post-hook failed but continuing"
                );
            }
            (_, Ok(())) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn ctx(phase: HookPhase, argv: &[String]) -> HookContext<'_> {
        HookContext {
            phase,
            scope: "bios.flash",
            engineer_cn: "Alice",
            argv,
            exit_code: None,
        }
    }

    #[test]
    fn from_name_resolves_known_hooks() {
        assert_eq!(BuiltinHook::from_name("noop").unwrap(), BuiltinHook::Noop);
        assert_eq!(
            BuiltinHook::from_name("audit_critical").unwrap(),
            BuiltinHook::AuditCritical
        );
    }

    #[test]
    fn from_name_rejects_unknown() {
        let err = BuiltinHook::from_name("garbage").unwrap_err();
        assert!(matches!(err, HookError::Unknown(s) if s == "garbage"));
    }

    #[test]
    fn noop_run_succeeds() {
        let argv: Vec<String> = vec![];
        BuiltinHook::Noop.run(&ctx(HookPhase::Pre, &argv)).unwrap();
    }

    #[test]
    fn audit_critical_run_succeeds_pre_and_post() {
        let argv: Vec<String> = vec!["/bin/true".into()];
        BuiltinHook::AuditCritical
            .run(&ctx(HookPhase::Pre, &argv))
            .unwrap();
        let mut c = ctx(HookPhase::Post, &argv);
        c.exit_code = Some(0);
        BuiltinHook::AuditCritical.run(&c).unwrap();
    }

    #[test]
    fn run_hooks_dispatches_in_order() {
        let argv: Vec<String> = vec![];
        let names: Vec<String> = vec!["noop".into(), "audit_critical".into()];
        run_hooks(&names, &ctx(HookPhase::Pre, &argv)).unwrap();
    }

    #[test]
    fn run_hooks_pre_phase_aborts_on_unknown() {
        let argv: Vec<String> = vec![];
        let names: Vec<String> = vec!["noop".into(), "garbage".into()];
        let err = run_hooks(&names, &ctx(HookPhase::Pre, &argv)).unwrap_err();
        assert!(matches!(err, HookError::Unknown(_)));
    }

    #[test]
    fn run_hooks_post_phase_logs_but_continues_on_unknown() {
        // Post phase: unknown name still returns Err from from_name(),
        // but the dispatcher must surface it because resolution itself
        // failed (we never reach the swallow path).
        let argv: Vec<String> = vec![];
        let names: Vec<String> = vec!["garbage".into()];
        let err = run_hooks(&names, &ctx(HookPhase::Post, &argv)).unwrap_err();
        assert!(matches!(err, HookError::Unknown(_)));
    }
}
