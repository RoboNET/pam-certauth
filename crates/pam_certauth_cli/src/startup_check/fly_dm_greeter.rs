//! fly-dm greeter-show-messages check (informational).
//!
//! pam_certauth surfaces PAM_TEXT_INFO ("Этот банкомат: host_id=...",
//! p12_wrong_pin_diagnostic) on the lock screen via io.show_info().
//! fly-dm only forwards PAM_TEXT_INFO to the greeter UI when
//! `greeter-show-messages = true` is set under `[greeter]` in
//! /etc/X11/fly-dm/fly-dmrc. This check reports the state.
//!
//! Severity: Info only (never errors, never warns). Silent skip when the
//! fly-dmrc file does not exist (sshd-only hosts, server stands).

use std::path::{Path, PathBuf};

use super::{StartupCheckRecord, StartupCheckReport};

/// Outcome of parsing `/etc/X11/fly-dm/fly-dmrc` for the
/// `greeter-show-messages` flag in the `[greeter]` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreeterMessagesState {
    /// `greeter-show-messages = true` (or `yes`/`1`) — PAM_TEXT_INFO is
    /// forwarded to the greeter UI.
    Enabled,
    /// Option is present but explicitly set to a false-like value
    /// (`false`/`no`/`0`) — PAM_TEXT_INFO will NOT appear on the lock screen.
    DisabledExplicit,
    /// Option is not present (either the `[greeter]` section is absent or
    /// the option is omitted within it). fly-dm defaults to off, so PAM
    /// info-messages will not be shown.
    Missing,
}

/// Pure parser for fly-dmrc content. Exposed for unit tests.
///
/// Logic:
/// * locate the `[greeter]` section (section name is case-insensitive,
///   surrounding whitespace ignored);
/// * within that section (until the next `[...]` header or EOF), match
///   `greeter-show-messages\s*=\s*(value)` (key case-insensitive);
/// * `true`/`yes`/`1` (case-insensitive) → `Enabled`;
/// * `false`/`no`/`0` (case-insensitive) → `DisabledExplicit`;
/// * any other value or no match → `Missing`.
#[must_use]
pub fn evaluate_fly_dmrc(text: &str) -> GreeterMessagesState {
    let mut in_greeter = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(stripped) = line.strip_prefix('[') {
            if let Some(name) = stripped.strip_suffix(']') {
                in_greeter = name.trim().eq_ignore_ascii_case("greeter");
            } else {
                in_greeter = false;
            }
            continue;
        }
        if !in_greeter {
            continue;
        }
        let Some(eq_idx) = line.find('=') else {
            continue;
        };
        let key = line[..eq_idx].trim();
        if !key.eq_ignore_ascii_case("greeter-show-messages") {
            continue;
        }
        let value = line[eq_idx + 1..].trim();
        // strip trailing inline comment if any
        let value = value
            .split_once('#')
            .map_or(value, |(v, _)| v.trim_end());
        let value = value
            .split_once(';')
            .map_or(value, |(v, _)| v.trim_end());
        let value = value.trim();
        if value.eq_ignore_ascii_case("true")
            || value.eq_ignore_ascii_case("yes")
            || value == "1"
        {
            return GreeterMessagesState::Enabled;
        }
        if value.eq_ignore_ascii_case("false")
            || value.eq_ignore_ascii_case("no")
            || value == "0"
        {
            return GreeterMessagesState::DisabledExplicit;
        }
        // unrecognised value — treat as missing/default
        return GreeterMessagesState::Missing;
    }
    GreeterMessagesState::Missing
}

/// Report whether fly-dm is configured to forward PAM_TEXT_INFO to the
/// greeter UI. Always Info severity; silent skip when fly-dmrc is absent.
pub fn check(fs_root: Option<&Path>, report: &mut StartupCheckReport) {
    let root = fs_root.map_or_else(|| PathBuf::from("/"), PathBuf::from);
    let path = root.join("etc/X11/fly-dm/fly-dmrc");

    if !path.exists() {
        // sshd-only host / server stand — nothing to say.
        return;
    }

    let text = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) => {
            report.push(StartupCheckRecord::info(
                "fly_dm_greeter_read_failed",
                format!(
                    "fly-dm greeter config {path} present but unreadable ({e}); \
                     cannot determine whether PAM_TEXT_INFO will appear on the lock screen",
                    path = path.display()
                ),
            ));
            return;
        }
    };

    match evaluate_fly_dmrc(&text) {
        GreeterMessagesState::Enabled => report.push(StartupCheckRecord::info(
            "fly_dm_greeter_messages_on",
            "fly-dm greeter-show-messages=true — PAM info-messages will appear on the lock screen",
        )),
        GreeterMessagesState::DisabledExplicit => report.push(StartupCheckRecord::info(
            "fly_dm_greeter_messages_off",
            "fly-dm greeter-show-messages set to false in /etc/X11/fly-dm/fly-dmrc — \
             PAM_TEXT_INFO from pam_certauth (host_id banner, p12 wrong-pin diagnostic) \
             will NOT appear on the lock screen. Fix: set greeter-show-messages = true \
             under [greeter] (see docs/install.md §8.5.1) or re-run integrate-pam.sh \
             on /etc/pam.d/fly-dm",
        )),
        GreeterMessagesState::Missing => report.push(StartupCheckRecord::info(
            "fly_dm_greeter_messages_default",
            "fly-dm greeter-show-messages not set in /etc/X11/fly-dm/fly-dmrc — \
             defaults to off; PAM_TEXT_INFO from pam_certauth will NOT appear on \
             the lock screen. Fix: same as above",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup_check::{StartupCheckReport, StartupCheckSeverity};
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn evaluate_enabled_simple() {
        let txt = "[greeter]\ngreeter-show-messages = true\n";
        assert_eq!(evaluate_fly_dmrc(txt), GreeterMessagesState::Enabled);
    }

    #[test]
    fn evaluate_enabled_yes_case_insensitive() {
        let txt = "[Greeter]\nGreeter-Show-Messages=Yes\n";
        assert_eq!(evaluate_fly_dmrc(txt), GreeterMessagesState::Enabled);
    }

    #[test]
    fn evaluate_enabled_one() {
        let txt = "[greeter]\ngreeter-show-messages=1\n";
        assert_eq!(evaluate_fly_dmrc(txt), GreeterMessagesState::Enabled);
    }

    #[test]
    fn evaluate_enabled_true_mixed_case() {
        let txt = "[greeter]\ngreeter-show-messages = True\n";
        assert_eq!(evaluate_fly_dmrc(txt), GreeterMessagesState::Enabled);
    }

    #[test]
    fn evaluate_disabled_explicit() {
        let txt = "[greeter]\ngreeter-show-messages = false\n";
        assert_eq!(
            evaluate_fly_dmrc(txt),
            GreeterMessagesState::DisabledExplicit
        );
    }

    #[test]
    fn evaluate_disabled_no() {
        let txt = "[greeter]\ngreeter-show-messages=no\n";
        assert_eq!(
            evaluate_fly_dmrc(txt),
            GreeterMessagesState::DisabledExplicit
        );
    }

    #[test]
    fn evaluate_missing_other_section_only() {
        let txt = "[other]\ngreeter-show-messages = true\n";
        assert_eq!(evaluate_fly_dmrc(txt), GreeterMessagesState::Missing);
    }

    #[test]
    fn evaluate_missing_empty_file() {
        assert_eq!(evaluate_fly_dmrc(""), GreeterMessagesState::Missing);
    }

    #[test]
    fn evaluate_missing_greeter_section_without_option() {
        let txt = "[greeter]\nfoo = bar\n[daemon]\nbaz=qux\n";
        assert_eq!(evaluate_fly_dmrc(txt), GreeterMessagesState::Missing);
    }

    #[test]
    fn evaluate_only_matches_inside_greeter_section() {
        // Option appears in [daemon], then [greeter] has nothing relevant.
        let txt = "[daemon]\ngreeter-show-messages = true\n[greeter]\nfoo = bar\n";
        assert_eq!(evaluate_fly_dmrc(txt), GreeterMessagesState::Missing);
    }

    #[test]
    fn check_silent_skip_when_file_missing() {
        let tmp = tempdir().expect("tempdir");
        let mut report = StartupCheckReport::default();
        check(Some(tmp.path()), &mut report);
        assert_eq!(report.records.len(), 0);
    }

    #[test]
    fn check_emits_info_when_enabled() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path().join("etc/X11/fly-dm");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(dir.join("fly-dmrc"), "[greeter]\ngreeter-show-messages = true\n")
            .expect("write");
        let mut report = StartupCheckReport::default();
        check(Some(tmp.path()), &mut report);
        assert_eq!(report.records.len(), 1);
        let rec = &report.records[0];
        assert_eq!(rec.severity, StartupCheckSeverity::Info);
        assert_eq!(rec.check, "fly_dm_greeter_messages_on");
    }

    #[test]
    fn check_emits_info_when_disabled() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path().join("etc/X11/fly-dm");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(dir.join("fly-dmrc"), "[greeter]\ngreeter-show-messages = false\n")
            .expect("write");
        let mut report = StartupCheckReport::default();
        check(Some(tmp.path()), &mut report);
        assert_eq!(report.records.len(), 1);
        let rec = &report.records[0];
        assert_eq!(rec.severity, StartupCheckSeverity::Info);
        assert_eq!(rec.check, "fly_dm_greeter_messages_off");
    }

    #[test]
    fn check_emits_info_when_missing_option() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path().join("etc/X11/fly-dm");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(dir.join("fly-dmrc"), "[daemon]\nfoo = bar\n").expect("write");
        let mut report = StartupCheckReport::default();
        check(Some(tmp.path()), &mut report);
        assert_eq!(report.records.len(), 1);
        let rec = &report.records[0];
        assert_eq!(rec.severity, StartupCheckSeverity::Info);
        assert_eq!(rec.check, "fly_dm_greeter_messages_default");
    }

    #[cfg(unix)]
    #[test]
    fn check_emits_read_failed_when_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        // Skip when running as root — root bypasses mode 0 reads.
        if rustix::process::geteuid().is_root() {
            return;
        }
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path().join("etc/X11/fly-dm");
        fs::create_dir_all(&dir).expect("mkdir");
        let p = dir.join("fly-dmrc");
        fs::write(&p, "[greeter]\ngreeter-show-messages = true\n").expect("write");
        let mut perms = fs::metadata(&p).expect("meta").permissions();
        perms.set_mode(0o000);
        fs::set_permissions(&p, perms).expect("chmod");

        let mut report = StartupCheckReport::default();
        check(Some(tmp.path()), &mut report);

        // restore so tempdir can clean up
        let mut perms = fs::metadata(&p).expect("meta").permissions();
        perms.set_mode(0o644);
        let _ = fs::set_permissions(&p, perms);

        assert_eq!(report.records.len(), 1);
        let rec = &report.records[0];
        assert_eq!(rec.severity, StartupCheckSeverity::Info);
        assert_eq!(rec.check, "fly_dm_greeter_read_failed");
    }
}
