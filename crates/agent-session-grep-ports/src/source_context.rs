//! Private publication context. Lifecycle metadata never enriches original text.
//! Values grant no filesystem admission or policy permission by themselves.

use crate::{
    PortError, PortResult, SearchProvider,
    control::{CanonicalLocator, ControlId},
    managed::{RevisionRef, SelectionProof, SourceBinding},
};
use agent_session_grep_domain::{IdKind, StableId};
use std::fmt;

pub const MAX_SOURCE_DEPENDENCIES: usize = 16;
pub const MAX_AUTHORITY_KEYS: usize = 65_536;
pub const MAX_CONTEXT_BYTES: usize = 256 * 1024;
pub const MAX_NATIVE_ID_BYTES: usize = 64 * 1024;
pub const MAX_CONTEXT_LOCATOR_BYTES: usize = 8 * 1024;

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid source publication context".into())
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct NativeSessionId(String);
impl NativeSessionId {
    pub fn parse(value: &str) -> PortResult<Self> {
        if value.is_empty()
            || value.len() > MAX_NATIVE_ID_BYTES
            || value.chars().any(char::is_control)
            || value.trim() != value
        {
            return Err(invalid());
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for NativeSessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeSessionId([private])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct StateDigest(String);
impl StateDigest {
    pub fn parse(value: &str) -> PortResult<Self> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        Ok(Self(value.into()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl fmt::Debug for StateDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StateDigest([private])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleState {
    ActiveLocal,
    SoftDeleted,
    CloudUnavailable,
    OrphanUnknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnresolvedDependency {
    NotSelected,
    Missing,
    Incomplete,
    Unsupported,
    Changed,
    Withdrawn,
}

/// An exact complete metadata receipt, separately admitted from the transcript.
/// The state digest binds semantic native-session/state, not the whole DB hash.
#[derive(Clone, PartialEq, Eq)]
pub struct MetadataDependencyProof {
    pub binding: SourceBinding,
    pub receipt: RevisionRef,
    pub selection: SelectionProof,
    pub state: LifecycleState,
    pub state_digest: StateDigest,
}
impl fmt::Debug for MetadataDependencyProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MetadataDependencyProof([private])")
    }
}
#[derive(Clone, PartialEq, Eq)]
pub enum DependencyResolution {
    Resolved(Box<MetadataDependencyProof>),
    Unresolved(UnresolvedDependency),
}
impl fmt::Debug for DependencyResolution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DependencyResolution([private])")
    }
}
/// All entries are required for lifecycle currentness. No optional/implicit
/// empty resolution. Metadata fields are never copied into corpus projections.
#[derive(Clone, PartialEq, Eq)]
pub struct SourceDependency {
    pub native_session: NativeSessionId,
    pub resolution: DependencyResolution,
}
impl fmt::Debug for SourceDependency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceDependency([private])")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SourceAuthorityKey {
    pub provider: SearchProvider,
    /// Physical provider surface identity supplied by verified layout admission;
    /// overlapping selections share it, independent installations do not.
    pub surface_id: ControlId,
    pub surface_root: CanonicalLocator,
    pub surface_identity: ControlId,
    pub native_session: NativeSessionId,
    pub session_id: StableId,
}
impl fmt::Debug for SourceAuthorityKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceAuthorityKey([private])")
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct SourceAuthorityPrior {
    pub binding: SourceBinding,
    pub receipt: RevisionRef,
    pub transition_id: ControlId,
}
impl fmt::Debug for SourceAuthorityPrior {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceAuthorityPrior([private])")
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct SourceAuthorityTransition {
    pub key: SourceAuthorityKey,
    /// None is initialization only; an existing row requires its exact preimage.
    pub expected_prior: Option<SourceAuthorityPrior>,
}
impl fmt::Debug for SourceAuthorityTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourceAuthorityTransition([private])")
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
pub struct SourcePublicationContext {
    pub dependencies: Vec<SourceDependency>,
    pub authority: Option<SourceAuthorityTransition>,
}
impl fmt::Debug for SourcePublicationContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SourcePublicationContext([private])")
    }
}
impl SourcePublicationContext {
    pub fn is_empty(&self) -> bool {
        self.dependencies.is_empty() && self.authority.is_none()
    }
    pub fn validate(&self) -> PortResult<()> {
        if self.dependencies.len() > MAX_SOURCE_DEPENDENCIES {
            return Err(invalid());
        }
        let mut ids = std::collections::BTreeSet::new();
        for dep in &self.dependencies {
            if !ids.insert(dep.native_session.as_str()) {
                return Err(invalid());
            }
            if let DependencyResolution::Resolved(proof) = &dep.resolution {
                validate_binding(&proof.binding)?;
                validate_receipt(&proof.receipt)?;
                ControlId::parse(&proof.selection.selection_id)?;
                ControlId::parse(&proof.selection.root_identity)?;
                if proof.selection.selection_revision < 1 {
                    return Err(invalid());
                }
            }
        }
        if let Some(transition) = &self.authority {
            let key = &transition.key;
            if key.surface_root.as_str().len() > MAX_CONTEXT_LOCATOR_BYTES
                || key.session_id.kind() != IdKind::Session
            {
                return Err(invalid());
            }
            if let Some(prior) = &transition.expected_prior {
                validate_binding(&prior.binding)?;
                validate_receipt(&prior.receipt)?;
                if prior.binding.provider != key.provider {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}
fn validate_binding(binding: &SourceBinding) -> PortResult<()> {
    if binding.source_path.len() > MAX_CONTEXT_LOCATOR_BYTES {
        return Err(invalid());
    }
    CanonicalLocator::parse(&binding.source_path)?;
    ControlId::parse(&binding.root_identity)?;
    if let Some(ns) = &binding.namespace_id {
        ControlId::parse(ns)?;
    }
    Ok(())
}
fn validate_receipt(receipt: &RevisionRef) -> PortResult<()> {
    if !receipt.published
        || receipt.cycle_seq < 1
        || receipt.started_control_seq < 1
        || receipt.policy_epoch < 0
        || receipt.observed_at_ms < 0
        || receipt.committed_generation.is_none_or(|v| v < 0)
        || receipt.digest.is_empty()
        || receipt.digest.len() > 256
        || receipt.digest.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    ControlId::parse(&receipt.worker_boot_id)?;
    ControlId::parse(&receipt.catalog_incarnation)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_and_required_unknown_are_distinct() {
        let empty = SourcePublicationContext::default();
        assert!(empty.is_empty());
        empty.validate().unwrap();
        let context = SourcePublicationContext {
            dependencies: vec![SourceDependency {
                native_session: NativeSessionId::parse("synthetic-session").unwrap(),
                resolution: DependencyResolution::Unresolved(UnresolvedDependency::NotSelected),
            }],
            authority: None,
        };
        assert!(!context.is_empty());
        context.validate().unwrap();
        let too_many = SourcePublicationContext {
            dependencies: vec![context.dependencies[0].clone(); 17],
            authority: None,
        };
        assert!(too_many.validate().is_err());
    }
    #[test]
    fn native_and_digest_values_are_bounded_and_debug_redacted() {
        assert!(NativeSessionId::parse("").is_err());
        assert!(NativeSessionId::parse("\nprivate").is_err());
        assert!(NativeSessionId::parse(&"x".repeat(MAX_NATIVE_ID_BYTES + 1)).is_err());
        let native = NativeSessionId::parse("private-native").unwrap();
        assert!(!format!("{native:?}").contains("private-native"));
        assert!(StateDigest::parse(&"g".repeat(64)).is_err());
        assert!(StateDigest::parse(&"a".repeat(64)).is_ok());
    }
}
