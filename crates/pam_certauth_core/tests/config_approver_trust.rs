//! Tests for the new [approver_trust], [tsa_trust], and [policy]
//! sections at the raw-config layer (spec §2.2, §2.3, §5.4).
#![allow(missing_docs)]
#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::doc_markdown)]

use std::path::PathBuf;

use pam_certauth_core::config::raw::RawConfig;
use pam_certauth_core::config::ValidatedConfig;

/// Minimal-but-complete TOML satisfying all required raw-config fields
/// other than the section under test.  Kept here (rather than in a
/// fixture file) so the test stays hermetic.
fn base_config() -> &'static str {
    r#"
crypto_backend = "openssl"
mode = "pkcs12"
pkcs12_path_pattern = "/tmp/p.p12"
pkcs12_pin_prompt = "PIN: "

[host_identity]
sources = ["machine_id"]

[logging]
level = "info"
syslog_facility = "auth"
"#
}

#[test]
fn config_with_approver_trust_parses() {
    let mut toml = String::from(base_config());
    toml.push_str(
        r#"
[trust]
anchors = ["/etc/pam_certauth/ca.pem"]

[approver_trust]
anchors = ["/etc/pam_certauth/approver_ca.pem"]

[policy]
path = "/etc/pam_certauth/policy.toml"
krl_poll_interval_seconds = 300
"#,
    );
    let raw: RawConfig = toml::from_str(&toml).expect("parse");
    assert!(raw.approver_trust.is_some());
    assert!(raw.tsa_trust.is_none());
    assert_eq!(raw.policy.krl_poll_interval_seconds, Some(300));
    assert!(raw.policy.require_approver_eku);
    assert_eq!(
        raw.policy.path.as_deref(),
        Some(std::path::Path::new("/etc/pam_certauth/policy.toml"))
    );
}

#[test]
fn config_with_tsa_trust_parses() {
    let mut toml = String::from(base_config());
    toml.push_str(
        r#"
[trust]
anchors = ["/etc/pam_certauth/ca.pem"]

[tsa_trust]
anchors = ["/etc/pam_certauth/tsa_ca.pem"]
"#,
    );
    let raw: RawConfig = toml::from_str(&toml).expect("parse");
    assert!(raw.tsa_trust.is_some());
    assert!(raw.approver_trust.is_none());
}

#[test]
fn config_without_new_sections_still_parses() {
    let mut toml = String::from(base_config());
    toml.push_str(
        r#"
[trust]
anchors = ["/etc/pam_certauth/ca.pem"]
"#,
    );
    let raw: RawConfig = toml::from_str(&toml).expect("parse");
    assert!(raw.approver_trust.is_none());
    assert!(raw.tsa_trust.is_none());
    // [policy] missing entirely → default RawPolicySection.
    assert!(raw.policy.require_approver_eku);
    assert!(raw.policy.path.is_none());
    assert!(raw.policy.krl_poll_interval_seconds.is_none());
    assert!(raw.policy.signing_time_skew_seconds.is_none());
}

/// Minimal self-signed-ish PEM blob accepted by `validate_pem` (only the
/// BEGIN marker is sniffed).
const FAKE_PEM: &str = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";

fn write_pem(dir: &std::path::Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, FAKE_PEM).expect("write pem");
    p
}

/// Build a fully-validating TOML (real PEM anchor) from the base config
/// plus an extra section block.
fn with_anchor_and_extra(anchor: &std::path::Path, extra: &str) -> String {
    use std::fmt::Write as _;
    let mut s = String::from(base_config());
    let _ = write!(
        &mut s,
        "\n[trust]\nanchors = [{:?}]\n",
        anchor.to_string_lossy()
    );
    s.push_str(extra);
    s
}

#[test]
fn validated_policy_section_has_defaults() {
    let dir = tempfile::tempdir().expect("tempdir");
    let anchor = write_pem(dir.path(), "ca.pem");
    let toml_str = with_anchor_and_extra(&anchor, "");
    let raw: RawConfig = toml::from_str(&toml_str).expect("parse");
    let validated = ValidatedConfig::try_from(&raw).expect("validate");
    assert_eq!(
        validated.policy.path,
        PathBuf::from("/etc/pam_certauth/policy.toml")
    );
    assert_eq!(validated.policy.krl_poll_interval.as_secs(), 300);
    assert!(validated.policy.require_approver_eku);
    assert_eq!(validated.policy.signing_time_skew.as_secs(), 300);
    assert!(validated.approver_trust.is_none());
    assert!(validated.tsa_trust.is_none());
}

#[test]
fn validated_approver_and_tsa_trust_are_validated() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = write_pem(dir.path(), "ca.pem");
    let approver_ca = write_pem(dir.path(), "approver_ca.pem");
    let tsa_ca = write_pem(dir.path(), "tsa_ca.pem");
    let extra = format!(
        "\n[approver_trust]\nanchors = [{:?}]\n\n[tsa_trust]\nanchors = [{:?}]\n",
        approver_ca.to_string_lossy(),
        tsa_ca.to_string_lossy()
    );
    let toml_str = with_anchor_and_extra(&ca, &extra);
    let raw: RawConfig = toml::from_str(&toml_str).expect("parse");
    let validated = ValidatedConfig::try_from(&raw).expect("validate");
    let approver = validated.approver_trust.expect("approver_trust present");
    assert_eq!(approver.anchors, vec![approver_ca]);
    let tsa = validated.tsa_trust.expect("tsa_trust present");
    assert_eq!(tsa.anchors, vec![tsa_ca]);
}

#[test]
fn validated_policy_rejects_zero_krl_interval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = write_pem(dir.path(), "ca.pem");
    let extra = "\n[policy]\nkrl_poll_interval_seconds = 0\n";
    let toml_str = with_anchor_and_extra(&ca, extra);
    let raw: RawConfig = toml::from_str(&toml_str).expect("parse");
    let err = ValidatedConfig::try_from(&raw).expect_err("zero interval rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("krl_poll_interval_seconds"),
        "unexpected error: {msg}"
    );
}

#[test]
fn validated_policy_rejects_relative_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ca = write_pem(dir.path(), "ca.pem");
    let extra = "\n[policy]\npath = \"relative/policy.toml\"\n";
    let toml_str = with_anchor_and_extra(&ca, extra);
    let raw: RawConfig = toml::from_str(&toml_str).expect("parse");
    let err = ValidatedConfig::try_from(&raw).expect_err("relative path rejected");
    let msg = format!("{err}");
    assert!(msg.contains("policy.path"), "unexpected error: {msg}");
}

#[test]
fn policy_require_approver_eku_can_be_disabled() {
    let mut toml = String::from(base_config());
    toml.push_str(
        r#"
[trust]
anchors = ["/etc/pam_certauth/ca.pem"]

[policy]
require_approver_eku = false
signing_time_skew_seconds = 60
"#,
    );
    let raw: RawConfig = toml::from_str(&toml).expect("parse");
    assert!(!raw.policy.require_approver_eku);
    assert_eq!(raw.policy.signing_time_skew_seconds, Some(60));
}

/// Regression: setup-mof-n-scenario.sh (pre-PR#3) used field names that
/// don't exist in the schema. These TOML snippets MUST be rejected, not
/// silently parsed. Catches future drift between docs/scripts and the
/// validator.
#[test]
fn rejects_legacy_setup_logging_journald_bool() {
    // The legacy setup-mof-n script wrote `journald = true` / `syslog = false`
    // under [logging]; the real schema demands level / syslog_facility /
    // journald_priority.  Build TOML with the bad fields and check parse fails.
    let toml = r#"
crypto_backend = "openssl"
mode = "pkcs12"
pkcs12_path_pattern = "/tmp/p.p12"
pkcs12_pin_prompt = "PIN: "

[host_identity]
sources = ["machine_id"]

[logging]
journald = true
syslog = false

[trust]
anchors = ["/etc/pam_certauth/ca.pem"]
"#;
    let err = toml::from_str::<RawConfig>(toml).unwrap_err().to_string();
    assert!(
        err.contains("journald") || err.contains("unknown field"),
        "expected unknown field error mentioning journald, got: {err}"
    );
}

#[test]
fn rejects_legacy_monitor_ipc_socket_path() {
    let toml = format!(
        "{}\n[trust]\nanchors = [\"/etc/pam_certauth/ca.pem\"]\n[monitor]\nipc_socket_path = \"/run/x.sock\"\n",
        base_config()
    );
    let err = toml::from_str::<RawConfig>(&toml).unwrap_err().to_string();
    assert!(
        err.contains("ipc_socket_path") || err.contains("unknown field"),
        "expected unknown field error mentioning ipc_socket_path, got: {err}"
    );
}

#[test]
fn rejects_legacy_policy_forbid_self_approval_field() {
    let toml = format!(
        "{}\n[trust]\nanchors = [\"/etc/pam_certauth/ca.pem\"]\n[policy]\nforbid_self_approval = true\n",
        base_config()
    );
    let err = toml::from_str::<RawConfig>(&toml).unwrap_err().to_string();
    assert!(
        err.contains("forbid_self_approval") || err.contains("unknown field"),
        "expected unknown field error mentioning forbid_self_approval, got: {err}"
    );
}

#[test]
fn rejects_legacy_policy_retention_days_field() {
    let toml = format!(
        "{}\n[trust]\nanchors = [\"/etc/pam_certauth/ca.pem\"]\n[policy]\nretention_days = 7\n",
        base_config()
    );
    let err = toml::from_str::<RawConfig>(&toml).unwrap_err().to_string();
    assert!(
        err.contains("retention_days") || err.contains("unknown field"),
        "expected unknown field error mentioning retention_days, got: {err}"
    );
}
