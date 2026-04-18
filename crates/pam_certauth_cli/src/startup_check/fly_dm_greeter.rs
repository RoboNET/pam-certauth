//! fly-dm GreetString.desktop check (informational).
//!
//! On modern Astra (fly-qdm 2.15+), the legacy KDM-style
//! `greeter-show-messages` option in `/etc/X11/fly-dm/fly-dmrc` is NOT
//! parsed. The actual point where banner text is injected into the login
//! screen header is `/etc/X11/fly-dm/override/GreetString.desktop`:
//! fly-dm reads `Name=` and `Name[<locale>]=` from the `[Desktop Entry]`
//! section and substitutes `%n` (hostname), `%h` (host+domain), `%d`
//! (display) into the greeter header.
//!
//! `pam-certauth update-greeter` (separate subcommand) writes the ATM
//! `host_id=<id>` into one or more `Name[...]` keys so the identifier is
//! visible on the lock screen. This startup check reports whether that has
//! been done.
//!
//! Severity: Info only (never errors, never warns). Silent skip when
//! `/etc/X11/fly-dm/` does not exist (server stands, sshd-only hosts).

use std::path::{Path, PathBuf};

use super::{StartupCheckRecord, StartupCheckReport};

/// Outcome of parsing `/etc/X11/fly-dm/override/GreetString.desktop`
/// for the presence of an injected `host_id=` token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GreetStringState {
    /// At least one `Name` / `Name[<locale>]` value in `[Desktop Entry]`
    /// contains the substring `host_id=` — `pam-certauth update-greeter`
    /// has already injected the ATM identifier.
    Customized,
    /// The file is present (or has a `[Desktop Entry]` section) but no
    /// `Name*` value contains `host_id=` — still using the stock greeter
    /// string.
    Default,
}

/// Pure parser for GreetString.desktop content. Exposed for unit tests.
///
/// Logic:
/// * locate the `[Desktop Entry]` section (case-sensitive, the standard
///   spelling for .desktop files);
/// * within that section (until the next `[...]` header or EOF), collect
///   every key whose name starts with `Name` (covers `Name`, `Name[ru]`,
///   `Name[en_US]`, `Name[tt]`, etc.);
/// * if any of those values contains the substring `host_id=`
///   (case-sensitive — looser matching would yield false positives) →
///   `Customized`;
/// * otherwise (including: no `[Desktop Entry]` section, no `Name*` keys,
///   empty file) → `Default`.
#[must_use]
pub fn evaluate_greet_string_desktop(text: &str) -> GreetStringState {
    let mut in_desktop_entry = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(stripped) = line.strip_prefix('[') {
            if let Some(name) = stripped.strip_suffix(']') {
                in_desktop_entry = name.trim() == "Desktop Entry";
            } else {
                in_desktop_entry = false;
            }
            continue;
        }
        if !in_desktop_entry {
            continue;
        }
        let Some(eq_idx) = line.find('=') else {
            continue;
        };
        let key = line[..eq_idx].trim();
        // Accept Name, Name[ru], Name[en_US], Name[tt], …
        if !(key == "Name" || (key.starts_with("Name[") && key.ends_with(']'))) {
            continue;
        }
        let value = &line[eq_idx + 1..];
        if value.contains("host_id=") {
            return GreetStringState::Customized;
        }
    }
    GreetStringState::Default
}

/// Report whether fly-dm's greeter banner has been customized with the
/// ATM `host_id`. Always Info severity; silent skip when fly-dm is not
/// installed at all.
pub fn check(fs_root: Option<&Path>, report: &mut StartupCheckReport) {
    let root = fs_root.map_or_else(|| PathBuf::from("/"), PathBuf::from);
    let fly_dm_root = root.join("etc/X11/fly-dm");

    if !fly_dm_root.exists() {
        // sshd-only host / server stand — fly-dm is not installed.
        return;
    }

    let greet_path = fly_dm_root.join("override/GreetString.desktop");

    if !greet_path.exists() {
        report.push(StartupCheckRecord::info(
            "fly_dm_greeter_override_missing",
            format!(
                "fly-dm installed but {path} absent — \
                 `pam-certauth update-greeter` will create it",
                path = greet_path.display()
            ),
        ));
        return;
    }

    let text = match std::fs::read_to_string(&greet_path) {
        Ok(t) => t,
        Err(e) => {
            report.push(StartupCheckRecord::info(
                "fly_dm_greeter_read_failed",
                format!(
                    "fly-dm greeter override {path} present but unreadable ({e}); \
                     cannot determine whether the ATM host_id is on the lock screen",
                    path = greet_path.display()
                ),
            ));
            return;
        }
    };

    match evaluate_greet_string_desktop(&text) {
        GreetStringState::Customized => report.push(StartupCheckRecord::info(
            "fly_dm_greeter_greet_string_customized",
            "fly-dm GreetString.desktop contains host_id — \
             banner will be visible on lock screen",
        )),
        GreetStringState::Default => report.push(StartupCheckRecord::info(
            "fly_dm_greeter_greet_string_default",
            "fly-dm GreetString.desktop present but lacks host_id — \
             run `pam-certauth update-greeter` to inject the ATM identifier \
             into the login screen banner",
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
    fn evaluate_customized_single_locale() {
        let txt = "[Desktop Entry]\n\
                   Name=Welcome to %n\n\
                   Name[ru]=Банкомат %n host_id=abc12345\n";
        assert_eq!(
            evaluate_greet_string_desktop(txt),
            GreetStringState::Customized
        );
    }

    #[test]
    fn evaluate_customized_default_name_only() {
        let txt = "[Desktop Entry]\nName=ATM host_id=xyz\n";
        assert_eq!(
            evaluate_greet_string_desktop(txt),
            GreetStringState::Customized
        );
    }

    #[test]
    fn evaluate_default_stock_template() {
        let txt = "[Desktop Entry]\n\
                   Name=Welcome to %n\n\
                   Name[ru]=Добро пожаловать в %n\n\
                   Name[tt]=Монда рәхим итегез: %n\n";
        assert_eq!(
            evaluate_greet_string_desktop(txt),
            GreetStringState::Default
        );
    }

    #[test]
    fn evaluate_default_empty_file() {
        assert_eq!(evaluate_greet_string_desktop(""), GreetStringState::Default);
    }

    #[test]
    fn evaluate_default_no_section() {
        let txt = "Name=Foo host_id=bar\n";
        assert_eq!(
            evaluate_greet_string_desktop(txt),
            GreetStringState::Default
        );
    }

    #[test]
    fn evaluate_default_other_section_with_host_id() {
        // host_id appears in [Other], but [Desktop Entry] is stock.
        let txt = "[Other]\nName=foo host_id=zzz\n\
                   [Desktop Entry]\nName=Welcome to %n\n";
        assert_eq!(
            evaluate_greet_string_desktop(txt),
            GreetStringState::Default
        );
    }

    #[test]
    fn evaluate_customized_multi_locale_one_customized() {
        let txt = "[Desktop Entry]\n\
                   Name=Welcome to %n\n\
                   Name[ru]=Добро пожаловать в %n\n\
                   Name[en_US]=ATM %n host_id=node42\n\
                   Name[tt]=Монда рәхим итегез: %n\n";
        assert_eq!(
            evaluate_greet_string_desktop(txt),
            GreetStringState::Customized
        );
    }

    #[test]
    fn evaluate_default_section_without_name_keys() {
        let txt = "[Desktop Entry]\nType=Application\nComment=foo\n";
        assert_eq!(
            evaluate_greet_string_desktop(txt),
            GreetStringState::Default
        );
    }

    #[test]
    fn check_silent_skip_when_no_fly_dm_root() {
        let tmp = tempdir().expect("tempdir");
        let mut report = StartupCheckReport::default();
        check(Some(tmp.path()), &mut report);
        assert_eq!(report.records.len(), 0);
    }

    #[test]
    fn check_emits_info_when_override_missing() {
        let tmp = tempdir().expect("tempdir");
        // fly-dm root exists but override/ subdir + file do not.
        fs::create_dir_all(tmp.path().join("etc/X11/fly-dm")).expect("mkdir");
        let mut report = StartupCheckReport::default();
        check(Some(tmp.path()), &mut report);
        assert_eq!(report.records.len(), 1);
        let rec = &report.records[0];
        assert_eq!(rec.severity, StartupCheckSeverity::Info);
        assert_eq!(rec.check, "fly_dm_greeter_override_missing");
    }

    #[test]
    fn check_emits_info_when_customized() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path().join("etc/X11/fly-dm/override");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(
            dir.join("GreetString.desktop"),
            "[Desktop Entry]\nName[ru]=Банкомат %n host_id=abc12345\n",
        )
        .expect("write");
        let mut report = StartupCheckReport::default();
        check(Some(tmp.path()), &mut report);
        assert_eq!(report.records.len(), 1);
        let rec = &report.records[0];
        assert_eq!(rec.severity, StartupCheckSeverity::Info);
        assert_eq!(rec.check, "fly_dm_greeter_greet_string_customized");
    }

    #[test]
    fn check_emits_info_when_default() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path().join("etc/X11/fly-dm/override");
        fs::create_dir_all(&dir).expect("mkdir");
        fs::write(
            dir.join("GreetString.desktop"),
            "[Desktop Entry]\n\
             Name=Welcome to %n\n\
             Name[ru]=Добро пожаловать в %n\n",
        )
        .expect("write");
        let mut report = StartupCheckReport::default();
        check(Some(tmp.path()), &mut report);
        assert_eq!(report.records.len(), 1);
        let rec = &report.records[0];
        assert_eq!(rec.severity, StartupCheckSeverity::Info);
        assert_eq!(rec.check, "fly_dm_greeter_greet_string_default");
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
        let dir = tmp.path().join("etc/X11/fly-dm/override");
        fs::create_dir_all(&dir).expect("mkdir");
        let p = dir.join("GreetString.desktop");
        fs::write(&p, "[Desktop Entry]\nName=Welcome to %n\n").expect("write");
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
