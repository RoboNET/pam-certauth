//! Host identity resolver chain.

use std::fmt::Write as _;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::config::validated::{HostIdFallback, HostIdentitySection};
use crate::error::HostIdentityError;
use crate::host_identity::{
    CustomCommandSource, DmiBoardSerialSource, DmiSystemSerialSource, DmiSystemUuidSource,
    HostIdSource, HostIdSourceKind, HostnameSource, MachineIdSource,
};

/// Resolved host id.
#[derive(Debug, Clone)]
pub struct ResolvedHostId {
    /// Source kind.
    pub source_kind: HostIdSourceKind,
    /// Raw value.
    pub raw: String,
    /// Normalized value.
    pub normalized: String,
    /// SHA-256 hex.
    pub hash_hex: String,
}

/// Resolver.
pub struct HostIdentityResolver {
    sources: Vec<Box<dyn HostIdSource>>,
    fallback: HostIdFallback,
    fs_root: PathBuf,
}

impl HostIdentityResolver {
    /// Build from validated config.
    pub fn from_validated(cfg: &HostIdentitySection, fs_root: PathBuf) -> Self {
        let mut sources: Vec<Box<dyn HostIdSource>> = Vec::new();
        for kind in &cfg.sources {
            match kind {
                HostIdSourceKind::MachineId => sources.push(Box::new(MachineIdSource)),
                HostIdSourceKind::DmiBoardSerial => sources.push(Box::new(DmiBoardSerialSource)),
                HostIdSourceKind::DmiSystemUuid => sources.push(Box::new(DmiSystemUuidSource)),
                HostIdSourceKind::DmiSystemSerial => sources.push(Box::new(DmiSystemSerialSource)),
                HostIdSourceKind::Hostname => sources.push(Box::new(HostnameSource)),
                HostIdSourceKind::CustomCommand => {
                    if let Some(cmd) = &cfg.custom_command {
                        sources.push(Box::new(CustomCommandSource::new(
                            cmd.clone(),
                            cfg.custom_command_timeout,
                        )));
                    }
                }
                HostIdSourceKind::Override => {}
            }
        }
        Self {
            sources,
            fallback: cfg.fallback,
            fs_root,
        }
    }

    /// Resolve the first working source.
    pub fn resolve(&self) -> Result<ResolvedHostId, HostIdentityError> {
        let mut attempts = Vec::new();
        for source in &self.sources {
            match source.fetch(&self.fs_root) {
                Ok(raw) => {
                    let normalized = normalize_host_id(&raw);
                    if normalized.is_empty() {
                        attempts.push((source.kind(), "empty after normalization".to_string()));
                        continue;
                    }
                    return Ok(resolved(source.kind(), raw, normalized));
                }
                Err(e) => attempts.push((source.kind(), e.to_string())),
            }
        }
        match self.fallback {
            HostIdFallback::Deny => Err(HostIdentityError::AllSourcesFailed { attempts }),
            HostIdFallback::Warn | HostIdFallback::Allow => Ok(resolved(
                HostIdSourceKind::Override,
                "unknown".to_string(),
                "unknown".to_string(),
            )),
        }
    }
}

/// Normalize a host id.
pub fn normalize_host_id(input: &str) -> String {
    input
        .trim()
        .chars()
        .filter(|c| *c != ':' && *c != ' ')
        .flat_map(char::to_lowercase)
        .collect()
}

fn resolved(source_kind: HostIdSourceKind, raw: String, normalized: String) -> ResolvedHostId {
    let hash = Sha256::digest(normalized.as_bytes());
    let mut hash_hex = String::with_capacity(64);
    for byte in hash {
        let _ = write!(hash_hex, "{byte:02x}");
    }
    ResolvedHostId {
        source_kind,
        raw,
        normalized,
        hash_hex,
    }
}
