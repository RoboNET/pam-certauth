//! Raw serde config.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Raw config.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    /// Crypto backend.
    pub crypto_backend: RawCryptoBackend,
    /// Mode.
    pub mode: RawMode,
    /// PKCS#11 module.
    pub pkcs11_module: Option<PathBuf>,
    /// Optional `CKA_LABEL` filter for the token.
    #[serde(default)]
    pub pkcs11_token_label: Option<String>,
    /// Optional `CKA_LABEL` filter for the on-token certificate /
    /// private-key object.  When `None`, the first end-entity cert is
    /// used.  Validated to be ≤ 64 chars and contain no NUL bytes.
    #[serde(default)]
    pub pkcs11_object_label: Option<String>,
    /// Maximum number of PIN attempts before bailing.  Defaults to 3.
    #[serde(default = "default_pkcs11_max_pin_attempts")]
    pub pkcs11_max_pin_attempts: u32,
    /// PKCS#11 locking mode.
    #[serde(default)]
    pub pkcs11_locking_mode: RawPkcs11LockingMode,
    /// Prompt string for the token PIN (Russian by default).
    #[serde(default)]
    pub pkcs11_pin_prompt: Option<String>,
    /// Maximum time `wait_for_token` will block waiting for the user
    /// to insert the token, in seconds.  Defaults to 10.
    #[serde(default = "default_pkcs11_slot_wait_seconds")]
    pub pkcs11_slot_wait_seconds: u32,
    /// PKCS#12 path pattern.
    pub pkcs12_path_pattern: Option<String>,
    /// PIN prompt.
    pub pkcs12_pin_prompt: Option<String>,
    /// Optional path to the gost-engine `.so` file.
    ///
    /// When `None`, the engine is resolved by id `"gost"` from the system's
    /// default engine search path.  When `Some`, it must point to a readable
    /// file (validated in [`crate::config::ValidatedConfig`]).
    #[serde(default)]
    pub gost_engine_path: Option<PathBuf>,
    /// USB wait seconds.
    #[serde(default = "default_usb_wait_seconds")]
    pub usb_wait_seconds: u64,
    /// USB removal action.
    #[serde(default)]
    pub on_usb_removed: RawOnUsbRemoved,
    /// USB removed grace.
    #[serde(default)]
    pub usb_removed_grace_seconds: u64,
    /// Suspend grace.
    #[serde(default)]
    pub suspend_grace_seconds: u64,
    /// Monitor failure mode (top-level, deprecated in favour of `[monitor].fail_mode`
    /// but still honoured for backwards compatibility when the new section is
    /// absent).
    #[serde(default)]
    pub monitor_fail_mode: RawMonitorFailMode,
    /// Monitor IPC section (socket path, timeout, fail mode). Optional —
    /// when absent, the validated config falls back to defaults plus the
    /// top-level `monitor_fail_mode`.
    #[serde(default)]
    pub monitor: RawMonitor,
    /// Trust.
    pub trust: RawTrust,
    /// Optional approver-CA trust section (m-of-n approver chains).
    /// Same shape as [`RawTrust`]; when absent the validated layer
    /// resolves it to `None`.
    #[serde(default)]
    pub approver_trust: Option<RawTrust>,
    /// Optional TSA trust section for RFC 3161 `TimestampToken`
    /// verification.  Same shape as [`RawTrust`]; when absent the
    /// validated layer resolves it to `None`.
    #[serde(default)]
    pub tsa_trust: Option<RawTrust>,
    /// Policy section: external policy file path and runtime knobs.
    #[serde(default)]
    pub policy: RawPolicySection,
    /// Trust overrides.
    #[serde(default)]
    pub trust_override: Vec<RawTrustOverride>,
    /// Host identity.
    pub host_identity: RawHostIdentity,
    /// User mappings.
    #[serde(default)]
    pub user_mapping: Vec<RawUserMapping>,
    /// Logging.
    pub logging: RawLogging,
    /// Hooks.
    #[serde(default)]
    pub hooks: Vec<RawHook>,
}

const fn default_usb_wait_seconds() -> u64 {
    10
}

const fn default_pkcs11_max_pin_attempts() -> u32 {
    3
}

const fn default_pkcs11_slot_wait_seconds() -> u32 {
    10
}

/// PKCS#11 locking mode (raw).  Mirrors
/// [`crate::token::pkcs11::LockingMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RawPkcs11LockingMode {
    /// Native OS thread locking (`CKF_OS_LOCKING_OK`).  Default.
    #[default]
    Os,
    /// User-space mutex serialization.
    Mutex,
}

/// Raw crypto backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawCryptoBackend {
    /// OpenSSL.
    Openssl,
    /// Native PKCS#11.
    Pkcs11Native,
}

/// Raw mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RawMode {
    /// PKCS#12.
    Pkcs12,
    /// PKCS#11.
    Pkcs11,
}

/// Raw removal action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RawOnUsbRemoved {
    /// Lock.
    #[default]
    Lock,
    /// Logout.
    Logout,
    /// Hook.
    Hook,
    /// Shutdown.
    Shutdown,
}

/// Raw monitor fail mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RawMonitorFailMode {
    /// Strict.
    #[default]
    Strict,
    /// Permissive.
    Permissive,
}

/// Raw `[monitor]` section. All fields are optional so an empty section
/// (or no section at all) yields validator defaults.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawMonitor {
    /// Path to the monitord Unix socket. Default
    /// `/run/pam_certauth/monitord.sock`.
    #[serde(default)]
    pub socket_path: Option<PathBuf>,
    /// Per-RPC connect+IO timeout in milliseconds. Default 2000.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Per-section fail mode override. When `None`, the validated config
    /// falls back to the top-level `monitor_fail_mode`.
    #[serde(default)]
    pub fail_mode: Option<String>,
    /// Path to the persisted session-registry JSON. Default
    /// `/var/lib/pam_certauth/sessions.json`. Read by `pam-certauth`.
    #[serde(default)]
    pub state_file_path: Option<PathBuf>,
    /// Action to take when the bound USB token is removed past the
    /// configured grace window. Default `lock`. Mirrors
    /// [`RawOnUsbRemoved`].
    #[serde(default)]
    pub on_usb_removed: Option<RawOnUsbRemoved>,
    /// Grace window between USB removal event and the configured action.
    /// Default 5 s.
    #[serde(default)]
    pub usb_removed_grace_seconds: Option<u64>,
    /// Suspend-grace window: removals within this many seconds after a
    /// resume are ignored. Default 30 s.
    #[serde(default)]
    pub suspend_grace_seconds: Option<u64>,
    /// Absolute path to the hook executable invoked when
    /// `on_usb_removed = "hook"`. Required only in `hook` mode.
    #[serde(default)]
    pub on_usb_removed_hook_path: Option<PathBuf>,
    /// Per-connection idle timeout in seconds (server-side IPC). Default 30.
    #[serde(default)]
    pub idle_timeout_seconds: Option<u64>,
    /// Maximum number of concurrent client connections accepted by the
    /// monitord IPC server. Default 64.
    #[serde(default)]
    pub max_concurrent_connections: Option<u32>,
}

/// Trust section.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTrust {
    /// Anchors.
    pub anchors: Vec<PathBuf>,
    /// Intermediates.
    #[serde(default)]
    pub intermediates: Vec<PathBuf>,
    /// Max chain depth.
    #[serde(default = "default_max_chain_depth")]
    pub max_chain_depth: u32,
    /// Clock skew.
    #[serde(default)]
    pub clock_skew_seconds: u64,
    /// Signature algorithms.
    #[serde(default)]
    pub allowed_signature_algorithms: Vec<String>,
    /// Revocation.
    #[serde(default)]
    pub revocation: RawRevocation,
    /// Pinning.
    #[serde(default)]
    pub pinning: RawPinning,
}

const fn default_max_chain_depth() -> u32 {
    5
}

/// Revocation section.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRevocation {
    /// Mode.
    #[serde(default)]
    pub mode: RawRevocationMode,
    /// CRL paths.
    #[serde(default)]
    pub crl_paths: Vec<PathBuf>,
    /// OCSP URL.
    #[serde(default)]
    pub ocsp_responder_url: Option<String>,
    /// CRL max age.
    #[serde(default)]
    pub crl_max_age_hours: u64,
    /// OCSP timeout.
    #[serde(default)]
    pub ocsp_timeout_seconds: u64,
    /// OCSP cache TTL.
    #[serde(default)]
    pub ocsp_cache_ttl_seconds: u64,
}

impl Default for RawRevocation {
    fn default() -> Self {
        Self {
            mode: RawRevocationMode::None,
            crl_paths: Vec::new(),
            ocsp_responder_url: None,
            crl_max_age_hours: 0,
            ocsp_timeout_seconds: 0,
            ocsp_cache_ttl_seconds: 0,
        }
    }
}

/// Raw revocation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RawRevocationMode {
    /// None.
    #[default]
    None,
    /// CRL.
    Crl,
    /// OCSP.
    Ocsp,
    /// CRL then OCSP.
    CrlThenOcsp,
}

/// Pinning section.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPinning {
    /// Enabled.
    #[serde(default)]
    pub enabled: bool,
    /// Allowed root SPKI hashes.
    #[serde(default)]
    pub allowed_root_spki_sha256: Vec<String>,
}

/// Trust override.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawTrustOverride {
    /// Host ids.
    pub when_host_id_in: Vec<String>,
    /// Anchors.
    #[serde(default)]
    pub anchors: Vec<PathBuf>,
    /// Intermediates.
    #[serde(default)]
    pub intermediates: Vec<PathBuf>,
}

/// Host identity section.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHostIdentity {
    /// Sources.
    pub sources: Vec<String>,
    /// Fallback.
    #[serde(default)]
    pub fallback: RawHostIdFallback,
    /// Override value.
    #[serde(default, rename = "override")]
    pub override_value: Option<String>,
    /// Custom command.
    #[serde(default)]
    pub custom_command: Option<PathBuf>,
    /// Custom command timeout.
    #[serde(default = "default_custom_command_timeout")]
    pub custom_command_timeout_seconds: u64,
}

const fn default_custom_command_timeout() -> u64 {
    5
}

/// Host id fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RawHostIdFallback {
    /// Deny.
    #[default]
    Deny,
    /// Warn.
    Warn,
    /// Allow.
    Allow,
}

/// User mapping.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawUserMapping {
    /// PAM user.
    pub pam_user: String,
    /// Subject CN.
    #[serde(default)]
    pub cert_subject_cn: Option<String>,
    /// SAN email.
    #[serde(default)]
    pub cert_san_email: Option<String>,
    /// SAN UPN.
    #[serde(default)]
    pub cert_san_upn: Option<String>,
}

/// Logging section.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawLogging {
    /// Level.
    pub level: String,
    /// Facility.
    pub syslog_facility: String,
    /// Journald priority.
    #[serde(default)]
    pub journald_priority: bool,
}

/// Hook.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawHook {
    /// Stage.
    pub stage: crate::hooks::HookStage,
    /// Command.
    pub command: Vec<String>,
    /// Timeout.
    #[serde(default = "default_hook_timeout")]
    pub timeout_seconds: u64,
    /// Failure mode.
    #[serde(default)]
    pub on_failure: Option<String>,
    /// Run as.
    #[serde(default)]
    pub run_as: Option<String>,
    /// Env templates.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

const fn default_hook_timeout() -> u64 {
    10
}

/// Raw `[policy]` section.  All fields optional; the validated layer
/// applies defaults per spec §5.4.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawPolicySection {
    /// Path to the external policy TOML.  Default
    /// `/etc/pam_certauth/policy.toml` (applied in validated layer).
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// How often to re-poll the KRL for changes (seconds).  Default 300.
    #[serde(default)]
    pub krl_poll_interval_seconds: Option<u64>,
    /// Whether approver certificates must carry the approver-EKU.
    /// Default `true`.
    #[serde(default = "default_require_approver_eku")]
    pub require_approver_eku: bool,
    /// Allowed skew between approval signing time and verification
    /// time (seconds).  Default 300.
    ///
    /// **No-op since 0.2.2** — the signing-time skew enforcement was
    /// dropped (cert validity is the authoritative time bound; see
    /// `docs/work-order.md`).  Field retained so existing
    /// `config.toml` files continue to parse without errors.
    #[serde(default)]
    pub signing_time_skew_seconds: Option<u64>,
}

impl Default for RawPolicySection {
    fn default() -> Self {
        Self {
            path: None,
            krl_poll_interval_seconds: None,
            require_approver_eku: default_require_approver_eku(),
            signing_time_skew_seconds: None,
        }
    }
}

const fn default_require_approver_eku() -> bool {
    true
}
