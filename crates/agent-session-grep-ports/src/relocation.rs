//! Explicit installation relocation contracts.
//!
//! The application and protocol layers exchange only bounded, opaque values
//! from this module.  Filesystem roots and provider-native identifiers stay in
//! the adapter boundary; callers receive counts, generation numbers and an
//! opaque plan token instead.

use serde::{Deserialize, Serialize};

/// Default compatibility lifetime for a retired installation location.
pub const DEFAULT_ALIAS_TTL_DAYS: u32 = 90;
/// Smallest accepted retired-location lifetime.
pub const MIN_ALIAS_TTL_DAYS: u32 = 1;
/// Largest accepted retired-location lifetime.
pub const MAX_ALIAS_TTL_DAYS: u32 = 365;
/// Opaque relocation plans are deliberately short lived.
pub const PLAN_TTL_MS: i64 = 15 * 60 * 1000;
/// Maximum encoded relocation plan length, checked before decoding.
pub const MAX_PLAN_TOKEN_BYTES: usize = 2048;

/// Validate the user-facing alias retention policy before any storage access.
pub fn validate_alias_ttl_days(days: u32) -> Result<(), &'static str> {
    if (MIN_ALIAS_TTL_DAYS..=MAX_ALIAS_TTL_DAYS).contains(&days) {
        Ok(())
    } else {
        Err("alias TTL must be between 1 and 365 days")
    }
}

/// Result state for a relocation request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelocationStatus {
    /// A read-only preview was produced.
    Planned,
    /// The mapping was committed.
    Applied,
    /// The requested mapping already exists and no generation was advanced.
    Unchanged,
}

impl RelocationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Applied => "applied",
            Self::Unchanged => "unchanged",
        }
    }
}

/// Bounded relocation result shared by adapters and protocol renderers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelocationResult {
    pub status: RelocationStatus,
    /// Opaque plan token.  It contains no reversible root or transcript data.
    pub plan: Option<String>,
    pub source_count: u64,
    pub session_count: u64,
    pub installation_count: u64,
    pub namespace_count: u64,
    pub generation: u64,
    pub previous_generation: u64,
    pub alias_ttl_days: u32,
}
