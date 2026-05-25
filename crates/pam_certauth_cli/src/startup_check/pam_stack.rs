//! PAM stack ordering check.
//!
//! Astra SE 1.8.x ships `pam_parsec_mac.so` in the `auth` phase of every
//! interactive service (login, fly-dm, sshd, …). Our integrate-pam.sh adds
//! `@include certauth-only` (or `certauth-optional`) whose Felix block uses
//! `success=done` to short-circuit on a successful certificate auth.
//!
//! If our include lands BEFORE `auth required pam_parsec_mac.so`, the
//! short-circuit jumps over `pam_parsec_mac` and its later `account`-phase
//! companion fails with "Can't obtain required data", denying login on an
//! otherwise correct setup.
//!
//! This check scans the well-known PAM service files and warns whenever the
//! ordering invariant is violated. It does NOT auto-repair — admins keep
//! the autonomy to override — but it surfaces the regression on every
//! daemon start so a stray edit doesn't sit unnoticed.

use std::path::Path;

use super::{StartupCheckRecord, StartupCheckReport};

/// Standard Astra services we scan. Missing files are silently skipped —
/// e.g. `fly-dm-np` only exists on некоторых конфигурациях.
const STANDARD_SERVICES: &[&str] = &["login", "fly-dm", "fly-dm-np", "sshd", "sudo", "su"];

/// Run the PAM stack ordering check.
pub fn check(pam_d_root: &Path, report: &mut StartupCheckReport) {
    for svc in STANDARD_SERVICES {
        let path = pam_d_root.join(svc);
        if !path.exists() {
            continue;
        }
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                report.push(StartupCheckRecord::warn(
                    "pam_stack_read_failed",
                    format!(
                        "PAM service {path}: read failed ({e})",
                        path = path.display()
                    ),
                ));
                continue;
            }
        };
        evaluate_service(&path, &text, report);
    }
}

/// Inspect a single PAM service file. Public for unit tests that want to
/// drive arbitrary content without round-tripping through the filesystem.
pub fn evaluate_service(path: &Path, text: &str, report: &mut StartupCheckReport) {
    let mut include_line: Option<usize> = None;
    let mut parsec_line: Option<usize> = None;

    for (idx, raw) in text.lines().enumerate() {
        let line = raw.trim_start();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if is_certauth_include(line) {
            include_line.get_or_insert(idx);
        } else if is_auth_parsec_mac(line) {
            parsec_line.get_or_insert(idx);
        }
    }

    match (include_line, parsec_line) {
        (Some(inc), Some(par)) if inc < par => {
            report.push(StartupCheckRecord::error(
                "pam_stack_misorder",
                format!(
                    "PAM stack misorder in {path}: @include certauth-* (line {inc}) appears \
                     BEFORE 'auth required pam_parsec_mac.so' (line {par}). On Astra SE the \
                     success=done jump will skip pam_parsec_mac and account-phase will fail \
                     'Can't obtain required data'. Run: \
                     sudo /usr/share/pam-certauth/integrate-pam.sh --unintegrate {path} && \
                     sudo /usr/share/pam-certauth/integrate-pam.sh --mode=<your-mode> {path}",
                    path = path.display(),
                    inc = inc + 1,
                    par = par + 1,
                ),
            ));
        }
        (Some(_), Some(_)) => {
            report.push(StartupCheckRecord::info(
                "pam_stack_ok",
                format!(
                    "PAM stack {path}: @include certauth-* correctly placed after \
                     pam_parsec_mac",
                    path = path.display()
                ),
            ));
        }
        // Either include missing (service not integrated) or pam_parsec_mac
        // missing (host without МКЦ). Both are common; no log noise.
        _ => {}
    }
}

fn is_certauth_include(line: &str) -> bool {
    // Matches `@include certauth`, `@include certauth-only`,
    // `@include certauth-optional` with arbitrary surrounding whitespace.
    let mut it = line.split_whitespace();
    let Some(first) = it.next() else { return false };
    if first != "@include" {
        return false;
    }
    let Some(name) = it.next() else { return false };
    if it.next().is_some() {
        return false;
    }
    matches!(name, "certauth" | "certauth-only" | "certauth-optional")
}

fn is_auth_parsec_mac(line: &str) -> bool {
    // Matches lines whose first token is `auth` and which mention
    // `pam_parsec_mac.so` anywhere in the rest of the line. We are
    // intentionally lenient on the control field (could be `required`,
    // `requisite`, or a substack expression on customized stacks).
    let mut it = line.split_whitespace();
    let Some(phase) = it.next() else { return false };
    if phase != "auth" {
        return false;
    }
    line.contains("pam_parsec_mac.so")
}
