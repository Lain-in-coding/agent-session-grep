use std::num::{NonZeroU32, NonZeroU64};

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use crate::{LauncherError, Result};

pub const LAUNCHER_PROTOCOL: u32 = 1;
pub const BUILD_TARGET: &str = env!("ASG_LAUNCHER_TARGET");
pub const CURRENT_SCHEMA: &str = "asg.current/v1";
pub const RELEASE_SCHEMA: &str = "asg.version/v1";
pub const MAX_METADATA_BYTES: usize = 8192;
pub const APP_NAME: &str = if cfg!(windows) {
    "agent-session-grep.exe"
} else {
    "agent-session-grep"
};

/// Package-owned metadata. Deserialize with `parse` to enforce v1 bounds.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentPointer {
    pub schema: String,
    pub generation: NonZeroU64,
    pub version: String,
    pub dir: String,
    pub app: String,
    pub app_sha256: String,
    pub launcher_protocol: u32,
    pub activated_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseMetadata {
    pub schema: String,
    pub version: String,
    pub target: String,
    pub source_commit: String,
    pub app_sha256: String,
    pub catalog_schema: NonZeroU32,
    pub control_schema: NonZeroU32,
    pub launcher_protocol_min: NonZeroU32,
    pub launcher_protocol_max: NonZeroU32,
    pub built_at: String,
}

impl CurrentPointer {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let invalid = LauncherError::PointerInvalid;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(invalid);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid)?;
        if value.schema != CURRENT_SCHEMA
            || !valid_version(&value.version)
            || !lower_hex(&value.app_sha256, 64)
            || value.app != APP_NAME
            || !valid_utc(&value.activated_at)
        {
            return Err(invalid);
        }
        let leaf = format!("{}-{}", value.version, &value.app_sha256[..12]);
        if leaf.len() > 64 || value.dir != format!("versions/{leaf}") {
            return Err(invalid);
        }
        if value.launcher_protocol != LAUNCHER_PROTOCOL {
            return Err(LauncherError::UpdateRequired);
        }
        Ok(value)
    }
}

impl ReleaseMetadata {
    pub fn parse(bytes: &[u8], pointer: &CurrentPointer) -> Result<Self> {
        let invalid = LauncherError::ReleaseInvalid;
        if bytes.len() > MAX_METADATA_BYTES {
            return Err(invalid);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| invalid)?;
        if value.schema != RELEASE_SCHEMA
            || !valid_version(&value.version)
            || value.version != pointer.version
            || !lower_hex(&value.app_sha256, 64)
            || !lower_hex(&value.source_commit, 40)
            || !valid_utc(&value.built_at)
            || value.launcher_protocol_min > value.launcher_protocol_max
        {
            return Err(invalid);
        }
        if value.target != BUILD_TARGET {
            return Err(LauncherError::TargetMismatch);
        }
        if !(value.launcher_protocol_min.get()..=value.launcher_protocol_max.get())
            .contains(&LAUNCHER_PROTOCOL)
        {
            return Err(LauncherError::UpdateRequired);
        }
        if value.app_sha256 != pointer.app_sha256 {
            return Err(LauncherError::IntegrityFailed);
        }
        Ok(value)
    }
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 51
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+-".contains(&b))
        && semver::Version::parse(value).is_ok()
}

fn lower_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_utc(value: &str) -> bool {
    (20..=35).contains(&value.len())
        && (value.ends_with('Z') || value.ends_with("+00:00"))
        && OffsetDateTime::parse(value, &Rfc3339).is_ok_and(|time| time.offset() == UtcOffset::UTC)
}
