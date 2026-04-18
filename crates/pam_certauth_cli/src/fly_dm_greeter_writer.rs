//! Writes `/etc/X11/fly-dm/override/GreetString.desktop` with the resolved
//! host identity so the ATM identifier appears in the fly-dm login-screen
//! banner. Astra-specific. Opt-in via
//! `[fly_dm_greeter].update_greet_string = true`.
//!
//! Pure-render path is exposed via [`render`] for unit tests; the FS-touching
//! work lives in [`update`], which is invoked once per daemon start in
//! `crate::daemon`. Failures are intentionally non-fatal — see the call site
//! for the rationale.
//!
//! Template placeholders:
//! * `{host_id_short}` → first 8 hex chars of `ResolvedHostId::hash_hex`.
//! * `{source}` → snake_case Display of `HostIdSourceKind`
//!   (e.g. `dmi_board_serial`).
//!
//! `.desktop` placeholders `%n`, `%h`, `%d` are NOT touched here — fly-dm
//! itself substitutes them at render time.

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use pam_certauth_core::config::validated::FlyDmGreeterSection;
use pam_certauth_core::host_identity::ResolvedHostId;

/// Outcome of a single [`update`] invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    /// `update_greet_string = false` — no FS work attempted.
    Disabled,
    /// fly-dm is not installed (`/etc/X11/fly-dm/` missing) — silent skip
    /// so the same package keeps working on sshd-only / server hosts.
    NoFlyDm,
    /// File was (re)written. `backed_up = true` iff a `.orig` sibling was
    /// just created (first run on a previously-stock host).
    Wrote {
        /// True iff this call created the `.orig` backup.
        backed_up: bool,
    },
    /// Target file already had the desired contents byte-for-byte — no
    /// rewrite, no backup touched.
    Unchanged,
}

/// Errors from [`update`]. Daemon log-and-continues on any of these.
#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    /// I/O error against a concrete path.
    #[error("io error on {path}: {source}")]
    Io {
        /// Path involved (best effort).
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: io::Error,
    },
}

impl WriterError {
    fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

/// Render the `.desktop` file content (without touching the FS).
///
/// Substitutes `{host_id_short}` and `{source}` in each configured
/// template. Always emits `[Desktop Entry]`, `Name=`, `Name[ru]=`. Emits
/// `Name[tt]=` only when [`FlyDmGreeterSection::template_tt`] is `Some`.
#[must_use]
pub fn render(cfg: &FlyDmGreeterSection, resolved: &ResolvedHostId) -> String {
    let host_id_short = resolved.hash_prefix();
    let source = resolved.source_kind.to_string();
    let sub = |t: &str| -> String {
        t.replace("{host_id_short}", host_id_short)
            .replace("{source}", &source)
    };
    let mut out = String::with_capacity(256);
    out.push_str("[Desktop Entry]\n");
    let _ = writeln!(out, "Name={}", sub(&cfg.template_en));
    let _ = writeln!(out, "Name[ru]={}", sub(&cfg.template_ru));
    if let Some(tt) = cfg.template_tt.as_deref() {
        let _ = writeln!(out, "Name[tt]={}", sub(tt));
    }
    out
}

/// Write the `.desktop` file according to `cfg`, returning a status.
///
/// Semantics:
/// 1. `update_greet_string = false` → [`UpdateOutcome::Disabled`] (no FS).
/// 2. fly-dm absent (no `/etc/X11/fly-dm/` next to the override) →
///    [`UpdateOutcome::NoFlyDm`].
/// 3. Otherwise create the override dir if needed, render the desired
///    content, compare against the existing file:
///    * Identical → [`UpdateOutcome::Unchanged`].
///    * Differs / file missing → atomic rewrite via
///      `<override_path>.tmp.<pid>` + `rename`. If the target existed and
///      no `.orig` sibling is present yet, copy the previous content to
///      `<override_path>.orig` first (preserving the user's stock file
///      exactly once).
pub fn update(
    cfg: &FlyDmGreeterSection,
    resolved: &ResolvedHostId,
) -> Result<UpdateOutcome, WriterError> {
    if !cfg.update_greet_string {
        return Ok(UpdateOutcome::Disabled);
    }
    let target = &cfg.override_path;
    let override_dir = target
        .parent()
        .ok_or_else(|| WriterError::io(target.clone(), io::Error::new(
            io::ErrorKind::InvalidInput,
            "override_path has no parent directory",
        )))?;
    // The override dir's parent is the fly-dm root (e.g. /etc/X11/fly-dm).
    // If neither the override dir nor the fly-dm root exists, fly-dm isn't
    // installed → silent skip.
    let fly_dm_root = override_dir.parent();
    if !override_dir.exists() && !fly_dm_root.is_some_and(Path::exists) {
        return Ok(UpdateOutcome::NoFlyDm);
    }
    if !override_dir.exists() {
        fs::create_dir_all(override_dir)
            .map_err(|e| WriterError::io(override_dir.to_path_buf(), e))?;
    }

    let rendered = render(cfg, resolved);

    let existing = match fs::read_to_string(target) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(WriterError::io(target.clone(), e)),
    };

    if existing.as_deref() == Some(rendered.as_str()) {
        return Ok(UpdateOutcome::Unchanged);
    }

    // Preserve user's pre-existing file as `.orig` exactly once. We never
    // overwrite an existing `.orig`: that file is the operator's last copy
    // of whatever shipped on the host.
    let orig_path = {
        let mut p = target.clone().into_os_string();
        p.push(".orig");
        PathBuf::from(p)
    };
    let mut backed_up = false;
    if let Some(prev) = existing.as_deref() {
        if !orig_path.exists() {
            // Use atomic rename of a sibling tmp so a crash mid-write doesn't
            // leave a half-written .orig.
            let tmp_orig = tmp_path(&orig_path);
            fs::write(&tmp_orig, prev).map_err(|e| WriterError::io(tmp_orig.clone(), e))?;
            fs::rename(&tmp_orig, &orig_path)
                .map_err(|e| WriterError::io(orig_path.clone(), e))?;
            backed_up = true;
        }
    }

    let tmp = tmp_path(target);
    fs::write(&tmp, &rendered).map_err(|e| WriterError::io(tmp.clone(), e))?;
    // Best-effort mode 0644 on the temp file (rename preserves the temp's
    // perms, not the target's). Failure here is non-fatal: the file will
    // still be there with whatever default umask granted.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644));
    }
    fs::rename(&tmp, target).map_err(|e| WriterError::io(target.clone(), e))?;

    Ok(UpdateOutcome::Wrote { backed_up })
}

fn tmp_path(target: &Path) -> PathBuf {
    let pid = std::process::id();
    let mut p = target.to_path_buf().into_os_string();
    p.push(format!(".tmp.{pid}"));
    PathBuf::from(p)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use pam_certauth_core::host_identity::HostIdSourceKind;
    use tempfile::tempdir;

    fn fixture_resolved(kind: HostIdSourceKind, hash_hex: &str) -> ResolvedHostId {
        ResolvedHostId {
            source_kind: kind,
            raw: "raw-value".to_string(),
            normalized: "raw-value".to_string(),
            hash_hex: hash_hex.to_string(),
        }
    }

    fn cfg_with(target: PathBuf, enabled: bool, with_tt: bool) -> FlyDmGreeterSection {
        FlyDmGreeterSection {
            update_greet_string: enabled,
            override_path: target,
            template_en: "ATM %n host_id={host_id_short} ({source})".to_string(),
            template_ru: "Банкомат %n host_id={host_id_short} ({source})".to_string(),
            template_tt: if with_tt {
                Some("Банкомат %n host_id={host_id_short}".to_string())
            } else {
                None
            },
        }
    }

    #[test]
    fn render_substitutes_placeholders_for_dmi_board_serial() {
        let cfg = cfg_with(PathBuf::from("/tmp/unused"), true, true);
        let r = fixture_resolved(HostIdSourceKind::DmiBoardSerial, "abc12345deadbeef");
        let out = render(&cfg, &r);
        assert!(out.contains("Name=ATM %n host_id=abc12345 (dmi_board_serial)\n"));
        assert!(out.contains("Name[ru]=Банкомат %n host_id=abc12345 (dmi_board_serial)\n"));
        assert!(out.contains("Name[tt]=Банкомат %n host_id=abc12345\n"));
        assert!(out.starts_with("[Desktop Entry]\n"));
    }

    #[test]
    fn render_substitutes_for_machine_id_source() {
        let cfg = cfg_with(PathBuf::from("/tmp/unused"), true, false);
        let r = fixture_resolved(HostIdSourceKind::MachineId, "0011223344");
        let out = render(&cfg, &r);
        assert!(out.contains("(machine_id)"));
        assert!(out.contains("host_id=00112233"));
    }

    #[test]
    fn render_omits_name_tt_when_template_tt_is_none() {
        let cfg = cfg_with(PathBuf::from("/tmp/unused"), true, false);
        let r = fixture_resolved(HostIdSourceKind::Hostname, "abcdefgh");
        let out = render(&cfg, &r);
        assert!(!out.contains("Name[tt]="));
        assert!(out.contains("Name[ru]="));
    }

    #[test]
    fn update_disabled_returns_disabled_and_does_not_write() {
        let tmp = tempdir().expect("tempdir");
        // Point at a path inside an existing fly-dm tree so NoFlyDm doesn't
        // pre-empt the disabled check.
        fs::create_dir_all(tmp.path().join("etc/X11/fly-dm/override")).expect("mkdir");
        let target = tmp.path().join("etc/X11/fly-dm/override/GreetString.desktop");
        let cfg = cfg_with(target.clone(), false, true);
        let r = fixture_resolved(HostIdSourceKind::Hostname, "abcdefgh");
        let outcome = update(&cfg, &r).expect("ok");
        assert_eq!(outcome, UpdateOutcome::Disabled);
        assert!(!target.exists());
    }

    #[test]
    fn update_no_fly_dm_when_root_missing() {
        let tmp = tempdir().expect("tempdir");
        // No /etc/X11/fly-dm tree at all.
        let target = tmp.path().join("etc/X11/fly-dm/override/GreetString.desktop");
        let cfg = cfg_with(target.clone(), true, true);
        let r = fixture_resolved(HostIdSourceKind::Hostname, "abcdefgh");
        let outcome = update(&cfg, &r).expect("ok");
        assert_eq!(outcome, UpdateOutcome::NoFlyDm);
        assert!(!target.exists());
    }

    #[test]
    fn update_first_run_creates_file_without_backup_when_no_prior_file() {
        let tmp = tempdir().expect("tempdir");
        fs::create_dir_all(tmp.path().join("etc/X11/fly-dm/override")).expect("mkdir");
        let target = tmp.path().join("etc/X11/fly-dm/override/GreetString.desktop");
        let cfg = cfg_with(target.clone(), true, true);
        let r = fixture_resolved(HostIdSourceKind::DmiBoardSerial, "abc12345deadbeef");
        let outcome = update(&cfg, &r).expect("ok");
        // No prior file → no .orig backup created.
        assert_eq!(outcome, UpdateOutcome::Wrote { backed_up: false });
        let body = fs::read_to_string(&target).expect("read");
        assert!(body.contains("host_id=abc12345"));
        let orig = target.with_extension("desktop.orig");
        assert!(!orig.exists());
    }

    #[test]
    fn update_first_run_backs_up_existing_stock_file() {
        let tmp = tempdir().expect("tempdir");
        fs::create_dir_all(tmp.path().join("etc/X11/fly-dm/override")).expect("mkdir");
        let target = tmp.path().join("etc/X11/fly-dm/override/GreetString.desktop");
        let stock = "[Desktop Entry]\nName=Welcome to %n\n";
        fs::write(&target, stock).expect("seed");
        let cfg = cfg_with(target.clone(), true, true);
        let r = fixture_resolved(HostIdSourceKind::DmiBoardSerial, "abc12345deadbeef");
        let outcome = update(&cfg, &r).expect("ok");
        assert_eq!(outcome, UpdateOutcome::Wrote { backed_up: true });
        let body = fs::read_to_string(&target).expect("read");
        assert!(body.contains("host_id=abc12345"));
        let orig_path = {
            let mut p = target.clone().into_os_string();
            p.push(".orig");
            PathBuf::from(p)
        };
        let orig_body = fs::read_to_string(&orig_path).expect("read orig");
        assert_eq!(orig_body, stock);
    }

    #[test]
    fn update_second_run_with_identical_content_is_unchanged() {
        let tmp = tempdir().expect("tempdir");
        fs::create_dir_all(tmp.path().join("etc/X11/fly-dm/override")).expect("mkdir");
        let target = tmp.path().join("etc/X11/fly-dm/override/GreetString.desktop");
        let cfg = cfg_with(target.clone(), true, true);
        let r = fixture_resolved(HostIdSourceKind::DmiBoardSerial, "abc12345deadbeef");
        let _ = update(&cfg, &r).expect("first");
        let outcome = update(&cfg, &r).expect("second");
        assert_eq!(outcome, UpdateOutcome::Unchanged);
    }

    #[test]
    fn update_second_run_with_new_host_id_rewrites_but_keeps_orig() {
        let tmp = tempdir().expect("tempdir");
        fs::create_dir_all(tmp.path().join("etc/X11/fly-dm/override")).expect("mkdir");
        let target = tmp.path().join("etc/X11/fly-dm/override/GreetString.desktop");
        let stock = "[Desktop Entry]\nName=Welcome to %n\n";
        fs::write(&target, stock).expect("seed");
        let cfg = cfg_with(target.clone(), true, true);

        let r1 = fixture_resolved(HostIdSourceKind::DmiBoardSerial, "abc12345deadbeef");
        let o1 = update(&cfg, &r1).expect("first");
        assert_eq!(o1, UpdateOutcome::Wrote { backed_up: true });

        let r2 = fixture_resolved(HostIdSourceKind::DmiBoardSerial, "ffffffffdeadbeef");
        let o2 = update(&cfg, &r2).expect("second");
        assert_eq!(o2, UpdateOutcome::Wrote { backed_up: false });

        let body = fs::read_to_string(&target).expect("read");
        assert!(body.contains("host_id=ffffffff"));
        let orig_path = {
            let mut p = target.clone().into_os_string();
            p.push(".orig");
            PathBuf::from(p)
        };
        // .orig must still be the very first stock content, not r1's render.
        let orig_body = fs::read_to_string(&orig_path).expect("read orig");
        assert_eq!(orig_body, stock);
    }
}
