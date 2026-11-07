//! Closed, pure state and proof records. Decoding never grants filesystem or SQL
//! authority. Runtime publication, full successor dispatch and native admission
//! remain separate from these byte/relationship checks.

use super::{
    AdmissionV2, MAX_COUNTER, RecordError, Result, TransitionMode, id, lower_hex, require,
    root_token, sha256,
};
use serde::{
    Deserialize, Deserializer, Serialize,
    de::{DeserializeOwned, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use std::{collections::BTreeSet, fmt};

#[path = "update_schema_transition_records.rs"]
pub mod records;
use records::{
    Component, ComponentIntent, ComponentReadback, ComponentReceipt, Coverage, RollbackIntent,
    RollbackPlan,
};

const STATE_SCHEMA: &str = "asg.update-state/v2";
const PROOF_LIMIT: usize = 8192;

fn nullable<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

// Serde's internally tagged unit visitor ignores payload fields, including with
// deny_unknown_fields. Decode an empty struct to enforce the closed payload.
fn closed_unit<'de, D>(deserializer: D) -> std::result::Result<(), D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}

    Empty::deserialize(deserializer).map(|_| ())
}

// Unlike AdmissionV2, state has one fixed array. Every other value still rejects
// serde's sequence representation of structs and repeated object/enum keys.
struct Shape(bool);
impl<'de> DeserializeSeed<'de> for Shape {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> std::result::Result<(), D::Error> {
        struct ShapeVisitor(bool);
        impl<'de> Visitor<'de> for ShapeVisitor {
            type Value = ();
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a closed state field")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> std::result::Result<(), M::Error> {
                let mut keys = BTreeSet::new();
                while let Some(key) = map.next_key::<String>()? {
                    if !keys.insert(key.clone()) {
                        return Err(serde::de::Error::custom("duplicate state field"));
                    }
                    if matches!(
                        key.as_str(),
                        "slot"
                            | "mode"
                            | "desired_updates"
                            | "state"
                            | "path_kind"
                            | "role"
                            | "disposition"
                            | "restore_pair"
                            | "code"
                            | "effect"
                            | "result"
                            | "resume"
                    ) {
                        map.next_value::<Option<String>>()?;
                    } else {
                        map.next_value_seed(Shape(key == "slots"))?;
                    }
                }
                Ok(())
            }
            fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> std::result::Result<(), S::Error> {
                if !self.0 {
                    return Err(serde::de::Error::custom("unexpected state array"));
                }
                for _ in 0..16 {
                    if seq.next_element::<super::ObjectShape>()?.is_none() {
                        return Err(serde::de::Error::custom("missing metadata slot"));
                    }
                }
                if seq.next_element::<super::ObjectShape>()?.is_some() {
                    return Err(serde::de::Error::custom("extra metadata slot"));
                }
                Ok(())
            }
            fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
                Ok(())
            }
            fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
                Ok(())
            }
            fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
                Ok(())
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
                Ok(())
            }
        }
        deserializer.deserialize_any(ShapeVisitor(self.0))
    }
}

fn digest(value: &str) -> Result<()> {
    require(lower_hex(value, 64))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordSlot {
    Coverage,
    CatalogIntent,
    ControlIntent,
    CatalogReceipt,
    ControlReceipt,
    CatalogCommitReadback,
    ControlCommitReadback,
    ForwardPairReadback,
    RollbackPairReadback,
    SelfCheck,
    RollbackIntent,
    RollbackPlan,
}

impl RecordSlot {
    /// Fixed basename under the admitted U. This supplies no filesystem authority.
    pub fn filename(self) -> &'static str {
        match self {
            Self::Coverage => "coverage.json",
            Self::CatalogIntent => "catalog-intent.json",
            Self::ControlIntent => "control-intent.json",
            Self::CatalogReceipt => "catalog-receipt.json",
            Self::ControlReceipt => "control-receipt.json",
            Self::CatalogCommitReadback => "catalog-commit-readback.json",
            Self::ControlCommitReadback => "control-commit-readback.json",
            Self::ForwardPairReadback => "forward-pair-readback.json",
            Self::RollbackPairReadback => "rollback-pair-readback.json",
            Self::SelfCheck => "self-check.json",
            Self::RollbackIntent => "rollback-intent.json",
            Self::RollbackPlan => "rollback-plan.json",
        }
    }

    fn limit(self) -> u64 {
        if self == Self::Coverage {
            256 * 1024
        } else {
            PROOF_LIMIT as u64
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordRef {
    slot: RecordSlot,
    size_bytes: u64,
    sha256: String,
}

impl RecordRef {
    fn validate(&self, slot: RecordSlot) -> Result<()> {
        require(self.slot == slot && (1..=slot.limit()).contains(&self.size_bytes))?;
        digest(&self.sha256)
    }

    fn matches(&self, record: &ProofRecord) -> bool {
        self.slot == record.slot
            && self.size_bytes == record.raw.len() as u64
            && self.sha256 == sha256(&record.raw)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum FileIdentity {
    Unix { device: u64, inode: u64 },
    Windows { volume: u64, file_id: String },
}

impl FileIdentity {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Unix { .. } => Ok(()),
            Self::Windows { file_id, .. } => require(lower_hex(file_id, 32)),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileStamp {
    identity: FileIdentity,
    size_bytes: u64,
    blake3: String,
}

impl FileStamp {
    fn validate(&self) -> Result<()> {
        self.identity.validate()?;
        require((1..=MAX_COUNTER).contains(&self.size_bytes))?;
        digest(&self.blake3)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogIdentity {
    installation_id: String,
    incarnation: String,
    schema: u32,
    generation: u64,
    destructive_epoch: u64,
}

impl CatalogIdentity {
    fn validate(&self, admission: &AdmissionV2, schema: u32) -> Result<()> {
        id(&self.incarnation)?;
        require(
            self.installation_id == admission.record.installation_id
                && self.schema == schema
                && self.generation <= MAX_COUNTER
                && self.destructive_epoch <= MAX_COUNTER,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Desired {
    Running,
    Paused,
    Stopped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FenceState {
    Idle,
    Updating,
    Recovering,
    Uninstalling,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fence {
    state: FenceState,
    #[serde(deserialize_with = "nullable")]
    owner: Option<String>,
    #[serde(deserialize_with = "nullable")]
    phase: Option<String>,
}

impl Fence {
    fn validate(&self) -> Result<()> {
        if self.state == FenceState::Idle {
            return require(self.owner.is_none() && self.phase.is_none());
        }
        id(self.owner.as_deref().ok_or(RecordError::Invalid)?)?;
        require(matches!(
            self.phase.as_deref(),
            Some(
                "downloaded"
                    | "verified"
                    | "quiescing"
                    | "backed_up"
                    | "staged"
                    | "migrated"
                    | "switched"
                    | "self_checked"
                    | "complete"
                    | "failed"
                    | "rollback_pending"
                    | "reconciling"
                    | "rolled_back"
                    | "attention"
            )
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlCheckpoint {
    installation_id: String,
    schema: u32,
    control_seq: u64,
    policy_epoch: u64,
    next_cycle_seq: u64,
    #[serde(deserialize_with = "nullable")]
    catalog_incarnation: Option<String>,
    restart_request_seq: u64,
    desired_updates: Desired,
    autostart_enabled: bool,
    supervisor_failed: bool,
    maintenance: Fence,
    authority_blake3: String,
    inventory_blake3: String,
    runtime_blake3: String,
}

impl ControlCheckpoint {
    fn same_restore_policy(&self, before: &Self) -> bool {
        self.authority_blake3 == before.authority_blake3
            && self.policy_epoch == before.policy_epoch
            && self.desired_updates == before.desired_updates
            && self.autostart_enabled == before.autostart_enabled
            && self.restart_request_seq == before.restart_request_seq
    }

    /// A later observation may advance policy, but cannot reuse an older
    /// sequence or give the same sequence contradictory policy fields.
    fn follows_checkpoint(&self, before: &Self) -> Result<()> {
        require(
            self.installation_id == before.installation_id
                && self.catalog_incarnation == before.catalog_incarnation
                && self.control_seq >= before.control_seq
                && self.policy_epoch >= before.policy_epoch
                && self.next_cycle_seq >= before.next_cycle_seq
                && self.restart_request_seq >= before.restart_request_seq
                && (self.control_seq != before.control_seq || self.same_restore_policy(before)),
        )
    }

    fn validate(&self, admission: &AdmissionV2, schema: u32) -> Result<()> {
        require(
            self.installation_id == admission.record.installation_id
                && self.schema == schema
                && self.policy_epoch <= self.control_seq
                && [
                    self.control_seq,
                    self.next_cycle_seq,
                    self.restart_request_seq,
                ]
                .into_iter()
                .all(|value| value <= MAX_COUNTER),
        )?;
        if let Some(incarnation) = &self.catalog_incarnation {
            id(incarnation)?;
        }
        self.maintenance.validate()?;
        require(
            self.maintenance.state == FenceState::Idle
                || (matches!(
                    self.maintenance.state,
                    FenceState::Updating | FenceState::Recovering
                ) && self.maintenance.owner.as_deref()
                    == Some(admission.record.owner_nonce.as_str())),
        )?;
        for value in [
            &self.authority_blake3,
            &self.inventory_blake3,
            &self.runtime_blake3,
        ] {
            digest(value)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Quiesced {
    catalog: CatalogIdentity,
    control: ControlCheckpoint,
    coverage_sha256: String,
    coverage_count: u64,
    catalog_file: FileStamp,
    control_file: FileStamp,
}

impl Quiesced {
    fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        self.catalog.validate(admission, 22)?;
        self.control.validate(admission, 2)?;
        require(
            self.catalog.incarnation == admission.record.checkpoint.catalog_incarnation
                && self.catalog.generation >= admission.record.checkpoint.catalog_generation
                && self.control.control_seq >= admission.record.checkpoint.control_seq
                && self.control.policy_epoch >= admission.record.checkpoint.policy_epoch
                && self.control.catalog_incarnation.as_deref()
                    == Some(self.catalog.incarnation.as_str())
                && self.coverage_count <= MAX_COUNTER,
        )?;
        digest(&self.coverage_sha256)?;
        self.catalog_file.validate()?;
        self.control_file.validate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Disposition {
    Restorable,
    Quarantined,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ImageState {
    #[serde(deserialize_with = "closed_unit")]
    Registered,
    OwnedIncomplete {
        identity: FileIdentity,
    },
    Complete {
        stamp: FileStamp,
    },
    Adopted {
        stamp: FileStamp,
        receipt_sha256: String,
        disposition: Disposition,
    },
    Reclaimed {
        identity: FileIdentity,
        #[serde(deserialize_with = "nullable")]
        stamp: Option<FileStamp>,
    },
    DeleteIntent {
        identity: FileIdentity,
        #[serde(deserialize_with = "nullable")]
        stamp: Option<FileStamp>,
    },
    #[serde(deserialize_with = "closed_unit")]
    Deleted,
    #[serde(deserialize_with = "closed_unit")]
    Absent,
}

impl ImageState {
    fn stamp(&self) -> Option<&FileStamp> {
        match self {
            Self::Complete { stamp } | Self::Adopted { stamp, .. } => Some(stamp),
            Self::Reclaimed { stamp, .. } | Self::DeleteIntent { stamp, .. } => stamp.as_ref(),
            _ => None,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::Registered | Self::Deleted | Self::Absent => Ok(()),
            Self::OwnedIncomplete { identity } => identity.validate(),
            Self::Complete { stamp } => stamp.validate(),
            Self::Adopted {
                stamp,
                receipt_sha256,
                ..
            } => {
                stamp.validate()?;
                digest(receipt_sha256)
            }
            Self::Reclaimed { identity, stamp } | Self::DeleteIntent { identity, stamp } => {
                identity.validate()?;
                if let Some(stamp) = stamp {
                    stamp.validate()?;
                    require(&stamp.identity == identity)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ParentState {
    #[serde(deserialize_with = "closed_unit")]
    AbsentUnderBoundRoot,
    Owned {
        identity: FileIdentity,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ManifestState {
    #[serde(deserialize_with = "closed_unit")]
    Absent,
    OwnedIncomplete {
        identity: FileIdentity,
    },
    Complete {
        stamp: FileStamp,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum SidecarState {
    #[serde(deserialize_with = "closed_unit")]
    Absent,
    Owned {
        identity: FileIdentity,
    },
    DeleteIntent {
        identity: FileIdentity,
    },
    #[serde(deserialize_with = "closed_unit")]
    Deleted,
}

impl SidecarState {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Owned { identity } | Self::DeleteIntent { identity } => identity.validate(),
            Self::Absent | Self::Deleted => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sidecars {
    wal: SidecarState,
    shm: SidecarState,
    journal: SidecarState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ImageRole {
    CatalogPreimage,
    ControlPreimage,
    CatalogSide,
    ControlSide,
    CatalogDisplaced,
    ControlDisplaced,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageSlot {
    role: ImageRole,
    artifact_id: String,
    root_binding: String,
    relative_locator: String,
    #[serde(deserialize_with = "nullable")]
    coverage_ref: Option<RecordRef>,
    parent: ParentState,
    image: ImageState,
    manifest: ManifestState,
    sidecars: Sidecars,
}

impl ImageSlot {
    fn clean(&self) -> bool {
        matches!(self.image, ImageState::Absent | ImageState::Deleted)
            && matches!(self.manifest, ManifestState::Absent)
            && [
                &self.sidecars.wal,
                &self.sidecars.shm,
                &self.sidecars.journal,
            ]
            .into_iter()
            .all(|slot| matches!(slot, SidecarState::Absent | SidecarState::Deleted))
    }

    fn validate(&self, admission: &AdmissionV2, role: ImageRole) -> Result<()> {
        require(self.role == role && self.root_binding == admission.record.control_root.identity)?;
        id(&self.artifact_id)?;
        if let Some(reference) = &self.coverage_ref {
            reference.validate(RecordSlot::Coverage)?;
        } else {
            require(
                matches!(
                    role,
                    ImageRole::CatalogPreimage | ImageRole::ControlPreimage
                ) && matches!(
                    self.image,
                    ImageState::Registered
                        | ImageState::OwnedIncomplete { .. }
                        | ImageState::Reclaimed { stamp: None, .. }
                        | ImageState::DeleteIntent { stamp: None, .. }
                        | ImageState::Deleted
                        | ImageState::Absent
                ) && !matches!(self.manifest, ManifestState::Complete { .. }),
            )?;
        }
        let suffix = &admission.record.update_id["update_".len()..];
        let catalog = format!("transition_catalog_{suffix}");
        let control = format!("transition_control_{suffix}");
        let recovery = format!("transition_recovery_{suffix}");
        let catalog_side = format!("transition-catalog-{suffix}.db");
        let control_side = format!("transition-control-{suffix}.db");
        let expected = match role {
            ImageRole::CatalogPreimage => {
                require(self.artifact_id == catalog)?;
                format!("backups/{catalog}/catalog.db")
            }
            ImageRole::ControlPreimage => {
                require(self.artifact_id == control)?;
                format!("backups/{control}/control.db")
            }
            ImageRole::CatalogSide => catalog_side,
            ImageRole::ControlSide => control_side,
            ImageRole::CatalogDisplaced | ImageRole::ControlDisplaced => {
                let (preimage, side, prefix, name) = if role == ImageRole::CatalogDisplaced {
                    (catalog, catalog_side, "restore_prior_", "catalog.db")
                } else {
                    (
                        control,
                        control_side,
                        "transition_control_prior_",
                        "control.db",
                    )
                };
                let key = format!("{preimage}:{recovery}:{side}:displaced");
                let hash = blake3::hash(key.as_bytes()).to_hex();
                let expected_id = format!("{prefix}{}", &hash[..32]);
                require(self.artifact_id == expected_id)?;
                format!("backups/{expected_id}/{name}")
            }
        };
        require(self.relative_locator == expected)?;
        if let ParentState::Owned { identity } = &self.parent {
            identity.validate()?;
        } else {
            require(
                matches!(self.image, ImageState::Registered | ImageState::Absent)
                    && matches!(self.manifest, ManifestState::Absent)
                    && matches!(self.sidecars.wal, SidecarState::Absent)
                    && matches!(self.sidecars.shm, SidecarState::Absent)
                    && matches!(self.sidecars.journal, SidecarState::Absent),
            )?;
        }
        self.image.validate()?;
        match &self.manifest {
            ManifestState::Absent => {}
            ManifestState::OwnedIncomplete { identity } => identity.validate()?,
            ManifestState::Complete { stamp } => stamp.validate()?,
        }
        if matches!(
            role,
            ImageRole::CatalogPreimage | ImageRole::ControlPreimage
        ) && matches!(
            self.image,
            ImageState::Complete { .. } | ImageState::Adopted { .. }
        ) {
            require(matches!(self.manifest, ManifestState::Complete { .. }))?;
        }
        self.sidecars.wal.validate()?;
        self.sidecars.shm.validate()?;
        self.sidecars.journal.validate()?;
        require(super::encode(self)?.len() <= 2048)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preimages {
    catalog: ImageSlot,
    control: ImageSlot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum StageProgress {
    #[serde(deserialize_with = "closed_unit")]
    Unstarted,
    Intent {
        inventory_sha256: String,
    },
    Extracted {
        inventory_sha256: String,
    },
    PublishIntent {
        inventory_sha256: String,
    },
    Published {
        inventory_sha256: String,
        final_root_binding: String,
    },
}

impl StageProgress {
    fn validate(&self) -> Result<()> {
        match self {
            Self::Unstarted => Ok(()),
            Self::Intent { inventory_sha256 }
            | Self::Extracted { inventory_sha256 }
            | Self::PublishIntent { inventory_sha256 } => digest(inventory_sha256),
            Self::Published {
                inventory_sha256,
                final_root_binding,
            } => {
                root_token(final_root_binding)?;
                digest(inventory_sha256)
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ComponentProgress {
    #[serde(deserialize_with = "closed_unit")]
    Unstarted,
    Intent {
        record: RecordRef,
    },
    Committed {
        intent: RecordRef,
        receipt: RecordRef,
        readback: RecordRef,
    },
    NotApplied {
        intent: RecordRef,
        readback: RecordRef,
    },
}

impl ComponentProgress {
    fn intent(&self) -> Option<&RecordRef> {
        match self {
            Self::Intent { record } => Some(record),
            Self::Committed { intent, .. } | Self::NotApplied { intent, .. } => Some(intent),
            Self::Unstarted => None,
        }
    }

    fn validate(&self, catalog: bool) -> Result<()> {
        let (intent_slot, receipt_slot) = if catalog {
            (RecordSlot::CatalogIntent, RecordSlot::CatalogReceipt)
        } else {
            (RecordSlot::ControlIntent, RecordSlot::ControlReceipt)
        };
        match self {
            Self::Unstarted => Ok(()),
            Self::Intent { record } => record.validate(intent_slot),
            Self::Committed {
                intent,
                receipt,
                readback,
            } => {
                intent.validate(intent_slot)?;
                receipt.validate(receipt_slot)?;
                readback.validate(if catalog {
                    RecordSlot::CatalogCommitReadback
                } else {
                    RecordSlot::ControlCommitReadback
                })
            }
            Self::NotApplied { intent, readback } => {
                intent.validate(intent_slot)?;
                readback.validate(if catalog {
                    RecordSlot::CatalogCommitReadback
                } else {
                    RecordSlot::ControlCommitReadback
                })
            }
        }
    }

    fn receipt(&self) -> Option<&RecordRef> {
        match self {
            Self::Committed { receipt, .. } => Some(receipt),
            _ => None,
        }
    }

    fn readback(&self) -> Option<&RecordRef> {
        match self {
            Self::Committed { readback, .. } | Self::NotApplied { readback, .. } => Some(readback),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImageDigest {
    size_bytes: u64,
    sha256: String,
}

impl ImageDigest {
    fn validate(&self) -> Result<()> {
        require(self.size_bytes <= 1024 * 1024)?;
        digest(&self.sha256)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum BeforeImage {
    #[serde(deserialize_with = "closed_unit")]
    Absent,
    ImageDigest {
        size_bytes: u64,
        sha256: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum MetadataSlot {
    #[serde(deserialize_with = "closed_unit")]
    Untouched,
    Prepared {
        before: BeforeImage,
        after: ImageDigest,
    },
    PublishIntent {
        before: BeforeImage,
        after: ImageDigest,
    },
    Applied {
        before: BeforeImage,
        after: ImageDigest,
    },
    RestoreIntent {
        before: BeforeImage,
        after: ImageDigest,
    },
    Restored {
        before: BeforeImage,
        after: ImageDigest,
    },
}

impl MetadataSlot {
    fn validate(&self) -> Result<()> {
        let (before, after) = match self {
            Self::Untouched => return Ok(()),
            Self::Prepared { before, after }
            | Self::PublishIntent { before, after }
            | Self::Applied { before, after }
            | Self::RestoreIntent { before, after }
            | Self::Restored { before, after } => (before, after),
        };
        if let BeforeImage::ImageDigest { size_bytes, sha256 } = before {
            require(*size_bytes <= 1024 * 1024)?;
            digest(sha256)?;
        }
        after.validate()?;
        require(super::encode(self)?.len() <= 512)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataLedger {
    slots: [MetadataSlot; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PlainPhase {
    Verified,
    Quiescing,
    BackedUp,
    Staged,
    Catalog23Control2,
    Catalog23Control3,
    Migrated,
    Switched,
    SelfChecked,
    Opening,
    Complete,
    ReclaimPrepared,
    ReclaimCommitted,
    CatalogRestored,
    ControlRestored,
    CleanupPending,
    CleanupComplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum PhaseV2 {
    #[serde(deserialize_with = "closed_unit")]
    Verified,
    #[serde(deserialize_with = "closed_unit")]
    Quiescing,
    #[serde(deserialize_with = "closed_unit")]
    BackedUp,
    #[serde(deserialize_with = "closed_unit")]
    Staged,
    #[serde(deserialize_with = "closed_unit")]
    Catalog23Control2,
    #[serde(deserialize_with = "closed_unit")]
    Catalog23Control3,
    #[serde(deserialize_with = "closed_unit")]
    Migrated,
    #[serde(deserialize_with = "closed_unit")]
    Switched,
    #[serde(deserialize_with = "closed_unit")]
    SelfChecked,
    #[serde(deserialize_with = "closed_unit")]
    Opening,
    #[serde(deserialize_with = "closed_unit")]
    Complete,
    #[serde(deserialize_with = "closed_unit")]
    ReclaimPrepared,
    #[serde(deserialize_with = "closed_unit")]
    ReclaimCommitted,
    #[serde(deserialize_with = "closed_unit")]
    CatalogRestored,
    #[serde(deserialize_with = "closed_unit")]
    ControlRestored,
    #[serde(deserialize_with = "closed_unit")]
    CleanupPending,
    #[serde(deserialize_with = "closed_unit")]
    CleanupComplete,
    Attention {
        resume: PlainPhase,
        failed_seq: u64,
    },
}

impl PhaseV2 {
    fn plain(&self) -> PlainPhase {
        match self {
            Self::Verified => PlainPhase::Verified,
            Self::Quiescing => PlainPhase::Quiescing,
            Self::BackedUp => PlainPhase::BackedUp,
            Self::Staged => PlainPhase::Staged,
            Self::Catalog23Control2 => PlainPhase::Catalog23Control2,
            Self::Catalog23Control3 => PlainPhase::Catalog23Control3,
            Self::Migrated => PlainPhase::Migrated,
            Self::Switched => PlainPhase::Switched,
            Self::SelfChecked => PlainPhase::SelfChecked,
            Self::Opening => PlainPhase::Opening,
            Self::Complete => PlainPhase::Complete,
            Self::ReclaimPrepared => PlainPhase::ReclaimPrepared,
            Self::ReclaimCommitted => PlainPhase::ReclaimCommitted,
            Self::CatalogRestored => PlainPhase::CatalogRestored,
            Self::ControlRestored => PlainPhase::ControlRestored,
            Self::CleanupPending => PlainPhase::CleanupPending,
            Self::CleanupComplete => PlainPhase::CleanupComplete,
            Self::Attention { resume, .. } => *resume,
        }
    }
}

impl PlainPhase {
    fn next(self) -> Option<Self> {
        Some(match self {
            Self::Verified => Self::Quiescing,
            Self::Quiescing => Self::BackedUp,
            Self::BackedUp => Self::Staged,
            Self::Staged => Self::Catalog23Control2,
            Self::Catalog23Control2 => Self::Catalog23Control3,
            Self::Catalog23Control3 => Self::Migrated,
            Self::Migrated => Self::Switched,
            Self::Switched => Self::SelfChecked,
            Self::SelfChecked => Self::Opening,
            Self::Opening => Self::Complete,
            Self::ReclaimPrepared => Self::ReclaimCommitted,
            Self::ReclaimCommitted => Self::CatalogRestored,
            Self::CatalogRestored => Self::ControlRestored,
            Self::ControlRestored => Self::CleanupPending,
            Self::CleanupPending => Self::CleanupComplete,
            Self::Complete | Self::CleanupComplete => return None,
        })
    }

    fn pre_open(self) -> bool {
        matches!(
            self,
            Self::Verified
                | Self::Quiescing
                | Self::BackedUp
                | Self::Staged
                | Self::Catalog23Control2
                | Self::Catalog23Control3
                | Self::Migrated
                | Self::Switched
                | Self::SelfChecked
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenIntent {
    seq: u64,
    self_check_sha256: String,
    forward_pair_readback_sha256: String,
    new_pointer_generation: u64,
    final_app_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RestorePair {
    Required,
    NotNeeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalRole {
    CatalogRestoreJournal,
    ControlRestoreJournal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnedRecordState {
    Registered,
    Owned,
    Complete,
    DeleteIntent,
    Deleted,
    Absent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedRecordSlot {
    role: JournalRole,
    path_kind: JournalRole,
    #[serde(deserialize_with = "nullable")]
    identity: Option<FileIdentity>,
    size_bytes: u64,
    #[serde(deserialize_with = "nullable")]
    blake3: Option<String>,
    state: OwnedRecordState,
}

impl OwnedRecordSlot {
    fn validate(&self, role: JournalRole) -> Result<()> {
        require(
            self.role == role && self.path_kind == role && self.size_bytes <= 64 * 1024 * 1024,
        )?;
        if let Some(identity) = &self.identity {
            identity.validate()?;
        }
        if let Some(hash) = &self.blake3 {
            digest(hash)?;
        }
        if matches!(
            self.state,
            OwnedRecordState::Owned | OwnedRecordState::Complete | OwnedRecordState::DeleteIntent
        ) {
            require(self.identity.is_some())?;
        }
        if self.state == OwnedRecordState::Complete {
            require(self.blake3.is_some())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackProgress {
    #[serde(deserialize_with = "nullable")]
    plan: Option<RecordRef>,
    #[serde(deserialize_with = "nullable")]
    intent: Option<RecordRef>,
    restore_pair: RestorePair,
    #[serde(deserialize_with = "nullable")]
    recovery_incarnation: Option<String>,
    authority_checkpoint: ControlCheckpoint,
    #[serde(deserialize_with = "nullable")]
    catalog_side: Option<ImageSlot>,
    #[serde(deserialize_with = "nullable")]
    control_side: Option<ImageSlot>,
    #[serde(deserialize_with = "nullable")]
    catalog_displaced: Option<ImageSlot>,
    #[serde(deserialize_with = "nullable")]
    control_displaced: Option<ImageSlot>,
    #[serde(deserialize_with = "nullable")]
    catalog_restore_journal: Option<OwnedRecordSlot>,
    #[serde(deserialize_with = "nullable")]
    control_restore_journal: Option<OwnedRecordSlot>,
    #[serde(deserialize_with = "nullable")]
    rollback_pair_readback: Option<RecordRef>,
    #[serde(deserialize_with = "nullable")]
    finalizer: Option<RecordRef>,
}

impl RollbackProgress {
    fn preparation_complete(&self) -> bool {
        self.restore_pair == RestorePair::Required
            && self.plan.is_some()
            && [&self.catalog_side, &self.control_side]
                .into_iter()
                .all(|slot| {
                    slot.as_ref().is_some_and(|image| {
                        matches!(image.parent, ParentState::Owned { .. })
                            && matches!(image.image, ImageState::Complete { .. })
                            && matches!(image.manifest, ManifestState::Absent)
                            && [
                                &image.sidecars.wal,
                                &image.sidecars.shm,
                                &image.sidecars.journal,
                            ]
                            .into_iter()
                            .all(|sidecar| matches!(sidecar, SidecarState::Owned { .. }))
                    })
                })
            && [&self.catalog_displaced, &self.control_displaced]
                .into_iter()
                .all(|slot| {
                    slot.as_ref().is_some_and(|image| {
                        matches!(image.parent, ParentState::Owned { .. })
                            && matches!(image.image, ImageState::Registered | ImageState::Absent)
                            && matches!(image.manifest, ManifestState::Complete { .. })
                            && [
                                &image.sidecars.wal,
                                &image.sidecars.shm,
                                &image.sidecars.journal,
                            ]
                            .into_iter()
                            .all(|sidecar| matches!(sidecar, SidecarState::Absent))
                    })
                })
            && [&self.catalog_restore_journal, &self.control_restore_journal]
                .into_iter()
                .all(|slot| {
                    slot.as_ref().is_some_and(|journal| {
                        journal.state == OwnedRecordState::Complete
                            && journal.identity.is_some()
                            && journal.size_bytes > 0
                            && journal.blake3.is_some()
                    })
                })
    }

    fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        if let Some(plan) = &self.plan {
            plan.validate(RecordSlot::RollbackPlan)?;
        }
        if let Some(intent) = &self.intent {
            intent.validate(RecordSlot::RollbackIntent)?;
        }
        self.authority_checkpoint
            .validate(admission, self.authority_checkpoint.schema)?;
        require(matches!(self.authority_checkpoint.schema, 2 | 3))?;
        if let Some(record) = &self.rollback_pair_readback {
            record.validate(RecordSlot::RollbackPairReadback)?;
        }
        require(self.finalizer.is_none())?;
        let images = [
            (&self.catalog_side, ImageRole::CatalogSide),
            (&self.control_side, ImageRole::ControlSide),
            (&self.catalog_displaced, ImageRole::CatalogDisplaced),
            (&self.control_displaced, ImageRole::ControlDisplaced),
        ];
        if self.restore_pair == RestorePair::NotNeeded {
            require(
                self.recovery_incarnation.is_none()
                    && self.plan.is_none()
                    && self.intent.is_some()
                    && self.authority_checkpoint.schema == 2
                    && images.iter().all(|(slot, _)| slot.is_none())
                    && self.catalog_restore_journal.is_none()
                    && self.control_restore_journal.is_none(),
            )?;
            return Ok(());
        }
        require(self.plan.is_some())?;
        let suffix = &admission.record.update_id["update_".len()..];
        require(
            self.recovery_incarnation.as_deref()
                == Some(format!("transition_recovery_{suffix}").as_str()),
        )?;
        for (slot, role) in images {
            slot.as_ref()
                .ok_or(RecordError::Invalid)?
                .validate(admission, role)?;
        }
        self.catalog_restore_journal
            .as_ref()
            .ok_or(RecordError::Invalid)?
            .validate(JournalRole::CatalogRestoreJournal)?;
        self.control_restore_journal
            .as_ref()
            .ok_or(RecordError::Invalid)?
            .validate(JournalRole::ControlRestoreJournal)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EffectKind {
    StageExtract,
    StagePublish,
    FenceSet,
    PreimageCreate,
    RollbackBindParent,
    RollbackCreateEmpty,
    RollbackWriteContent,
    ComponentCommit,
    MetadataPublish,
    MetadataRestore,
    PairRestore,
    OwnedDelete,
    FenceClear,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordDigest {
    size_bytes: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum BeforeRecord {
    #[serde(deserialize_with = "closed_unit")]
    Absent,
    RecordDigest {
        size_bytes: u64,
        sha256: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingEffect {
    kind: EffectKind,
    slot: String,
    intent_seq: u64,
    expected_before: BeforeRecord,
    expected_after: RecordDigest,
}

impl PendingEffect {
    fn validate(&self, seq: u64) -> Result<()> {
        let valid_slot = match self.kind {
            EffectKind::StageExtract | EffectKind::StagePublish => self.slot == "stage",
            EffectKind::FenceSet | EffectKind::FenceClear => self.slot == "control",
            EffectKind::PreimageCreate => {
                matches!(self.slot.as_str(), "catalog_preimage" | "control_preimage")
            }
            EffectKind::RollbackBindParent
            | EffectKind::RollbackCreateEmpty
            | EffectKind::RollbackWriteContent => records::PreparationSlot::parse(&self.slot)
                .is_some_and(|slot| slot.permits(self.kind)),
            EffectKind::ComponentCommit => matches!(self.slot.as_str(), "catalog" | "control"),
            EffectKind::MetadataPublish | EffectKind::MetadataRestore => matches!(
                self.slot.as_str(),
                "package_manifest"
                    | "package_receipt"
                    | "release_manifest"
                    | "checksums"
                    | "current"
                    | "installer_sh"
                    | "installer_powershell"
                    | "install_guide"
                    | "readme"
                    | "changelog"
                    | "license_mit"
                    | "license_apache"
                    | "notice"
                    | "security"
                    | "dependencies_json"
                    | "dependencies_csv"
            ),
            EffectKind::PairRestore => matches!(self.slot.as_str(), "catalog" | "control"),
            EffectKind::OwnedDelete => matches!(
                self.slot.as_str(),
                "catalog_preimage"
                    | "control_preimage"
                    | "catalog_side"
                    | "control_side"
                    | "catalog_displaced"
                    | "control_displaced"
                    | "catalog_restore_journal"
                    | "control_restore_journal"
            ),
        };
        require(
            valid_slot
                && (1..=seq).contains(&self.intent_seq)
                && self.expected_after.size_bytes <= 64 * 1024,
        )?;
        digest(&self.expected_after.sha256)?;
        if let BeforeRecord::RecordDigest { size_bytes, sha256 } = &self.expected_before {
            require(*size_bytes <= 64 * 1024)?;
            digest(sha256)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FailureCode {
    Deadline,
    Busy,
    ControlDrainPending,
    InputChanged,
    IdentityChanged,
    SchemaMismatch,
    PolicyChanged,
    PublicationUnknown,
    CleanupPending,
    RestartFailed,
    Io,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureRecord {
    at_seq: u64,
    code: FailureCode,
    #[serde(deserialize_with = "nullable")]
    effect: Option<EffectKind>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateRecord {
    schema: String,
    mode: TransitionMode,
    update_id: String,
    owner_nonce: String,
    prefix_binding: String,
    control_binding: String,
    admission_sha256: String,
    seq: u64,
    #[serde(deserialize_with = "nullable")]
    predecessor_sha256: Option<String>,
    phase: PhaseV2,
    #[serde(deserialize_with = "nullable")]
    quiesced: Option<Quiesced>,
    preimages: Preimages,
    stage: StageProgress,
    catalog_component: ComponentProgress,
    control_component: ComponentProgress,
    metadata: MetadataLedger,
    #[serde(deserialize_with = "nullable")]
    forward_pair_readback: Option<RecordRef>,
    #[serde(deserialize_with = "nullable")]
    self_check: Option<RecordRef>,
    #[serde(deserialize_with = "nullable")]
    requests_open_intent: Option<OpenIntent>,
    #[serde(deserialize_with = "nullable")]
    rollback: Option<RollbackProgress>,
    #[serde(deserialize_with = "nullable")]
    pending: Option<PendingEffect>,
    #[serde(deserialize_with = "nullable")]
    last_failure: Option<FailureRecord>,
}

impl StateRecord {
    fn images(&self) -> [Option<&ImageSlot>; 6] {
        let rollback = self.rollback.as_ref();
        [
            Some(&self.preimages.catalog),
            Some(&self.preimages.control),
            rollback.and_then(|r| r.catalog_side.as_ref()),
            rollback.and_then(|r| r.control_side.as_ref()),
            rollback.and_then(|r| r.catalog_displaced.as_ref()),
            rollback.and_then(|r| r.control_displaced.as_ref()),
        ]
    }

    fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        admission.record.validate()?;
        require(
            self.schema == STATE_SCHEMA
                && self.mode == admission.record.mode
                && self.update_id == admission.record.update_id
                && self.owner_nonce == admission.record.owner_nonce
                && self.prefix_binding == admission.record.prefix.identity
                && self.control_binding == admission.record.control_root.identity
                && self.admission_sha256 == sha256(admission.raw_bytes())
                && (1..=10000).contains(&self.seq)
                && (self.seq == 1) == self.predecessor_sha256.is_none(),
        )?;
        if self.seq == 1 {
            require(self.phase == PhaseV2::Verified)?;
        }
        if let Some(hash) = &self.predecessor_sha256 {
            digest(hash)?;
        }
        if let Some(checkpoint) = &self.quiesced {
            checkpoint.validate(admission)?;
        }
        self.preimages
            .catalog
            .validate(admission, ImageRole::CatalogPreimage)?;
        self.preimages
            .control
            .validate(admission, ImageRole::ControlPreimage)?;
        let before_coverage = self.quiesced.is_none()
            && matches!(self.stage, StageProgress::Unstarted)
            && matches!(self.catalog_component, ComponentProgress::Unstarted)
            && matches!(self.control_component, ComponentProgress::Unstarted)
            && self.forward_pair_readback.is_none()
            && self.self_check.is_none()
            && self.requests_open_intent.is_none()
            && self
                .metadata
                .slots
                .iter()
                .all(|slot| matches!(slot, MetadataSlot::Untouched))
            && (matches!(
                self.phase.plain(),
                PlainPhase::Verified | PlainPhase::Quiescing
            ) || self
                .rollback
                .as_ref()
                .is_some_and(|r| r.restore_pair == RestorePair::NotNeeded));
        let mut recorded_coverage = None;
        for image in self.images().into_iter().flatten() {
            if let Some(reference) = &image.coverage_ref {
                if let Some(previous) = recorded_coverage {
                    require(reference == previous)?;
                }
                recorded_coverage = Some(reference);
                if let Some(checkpoint) = &self.quiesced {
                    require(reference.sha256 == checkpoint.coverage_sha256)?;
                }
            } else {
                require(before_coverage)?;
            }
        }
        self.stage.validate()?;
        self.catalog_component.validate(true)?;
        self.control_component.validate(false)?;
        if self.control_component.receipt().is_some() {
            require(self.catalog_component.receipt().is_some())?;
        }
        for slot in &self.metadata.slots {
            slot.validate()?;
        }
        if let Some(record) = &self.forward_pair_readback {
            record.validate(RecordSlot::ForwardPairReadback)?;
            require(
                self.catalog_component.receipt().is_some()
                    && self.control_component.receipt().is_some(),
            )?;
        }
        if let Some(record) = &self.self_check {
            record.validate(RecordSlot::SelfCheck)?;
            require(self.forward_pair_readback.is_some())?;
        }
        if let Some(intent) = &self.requests_open_intent {
            let check = self.self_check.as_ref().ok_or(RecordError::Invalid)?;
            let pair = self
                .forward_pair_readback
                .as_ref()
                .ok_or(RecordError::Invalid)?;
            require(
                (1..=self.seq).contains(&intent.seq)
                    && intent.self_check_sha256 == check.sha256
                    && intent.forward_pair_readback_sha256 == pair.sha256
                    && intent.new_pointer_generation == admission.record.new_pointer_generation
                    && intent.final_app_sha256 == admission.record.new.app_sha256
                    && self.rollback.is_none(),
            )?;
        }
        if let Some(rollback) = &self.rollback {
            require(self.requests_open_intent.is_none())?;
            rollback.validate(admission)?;
            require(
                rollback.intent.is_some()
                    || (rollback.restore_pair == RestorePair::Required
                        && self.phase.plain() == PlainPhase::ReclaimPrepared),
            )?;
            if rollback.restore_pair == RestorePair::NotNeeded {
                require(
                    self.catalog_component.receipt().is_none()
                        && matches!(self.control_component, ComponentProgress::Unstarted),
                )?;
            } else if matches!(
                self.phase.plain(),
                PlainPhase::ReclaimPrepared | PlainPhase::ReclaimCommitted
            ) {
                for image in [&rollback.catalog_displaced, &rollback.control_displaced] {
                    require(image.as_ref().is_some_and(|image| {
                        matches!(image.image, ImageState::Registered | ImageState::Absent)
                            && [
                                &image.sidecars.wal,
                                &image.sidecars.shm,
                                &image.sidecars.journal,
                            ]
                            .into_iter()
                            .all(|sidecar| matches!(sidecar, SidecarState::Absent))
                    }))?;
                }
                if rollback.intent.is_some() {
                    require(rollback.preparation_complete())?;
                }
            }
        }
        if let Some(pending) = &self.pending {
            pending.validate(self.seq)?;
        }
        if let Some(failure) = &self.last_failure {
            require((1..=self.seq).contains(&failure.at_seq))?;
        }
        if let PhaseV2::Attention { failed_seq, .. } = &self.phase {
            require((1..=self.seq).contains(failed_seq))?;
        }
        let phase = self.phase.plain();
        for (component, entry_phase) in [
            (&self.catalog_component, PlainPhase::Staged),
            (&self.control_component, PlainPhase::Catalog23Control2),
        ] {
            if matches!(component, ComponentProgress::NotApplied { .. }) {
                require(self.rollback.is_some() || phase == entry_phase)?;
            }
        }
        let forward_rank = match phase {
            PlainPhase::Verified => Some(0),
            PlainPhase::Quiescing => Some(1),
            PlainPhase::BackedUp => Some(2),
            PlainPhase::Staged => Some(3),
            PlainPhase::Catalog23Control2 => Some(4),
            PlainPhase::Catalog23Control3 => Some(5),
            PlainPhase::Migrated => Some(6),
            PlainPhase::Switched => Some(7),
            PlainPhase::SelfChecked => Some(8),
            PlainPhase::Opening => Some(9),
            PlainPhase::Complete => Some(10),
            _ => None,
        };
        if let Some(rank) = forward_rank {
            require(self.rollback.is_none())?;
            if self.seq == 1 {
                require(
                    rank == 0
                        && self.quiesced.is_none()
                        && self.pending.is_none()
                        && self.last_failure.is_none()
                        && matches!(self.stage, StageProgress::Unstarted)
                        && matches!(
                            self.preimages.catalog.image,
                            ImageState::Registered | ImageState::Absent
                        )
                        && matches!(
                            self.preimages.control.image,
                            ImageState::Registered | ImageState::Absent
                        ),
                )?;
            }
            if rank < 3 {
                require(matches!(
                    self.catalog_component,
                    ComponentProgress::Unstarted
                ))?;
            }
            if rank < 4 {
                require(self.catalog_component.receipt().is_none())?;
            }
            if rank < 2 {
                require(matches!(self.stage, StageProgress::Unstarted))?;
            }
            if rank < 4 {
                require(matches!(
                    self.control_component,
                    ComponentProgress::Unstarted
                ))?;
            }
            if rank < 5 {
                require(self.control_component.receipt().is_none())?;
            }
            if rank < 5 {
                require(self.forward_pair_readback.is_none())?;
            }
            if rank < 6 {
                require(
                    self.metadata
                        .slots
                        .iter()
                        .all(|slot| matches!(slot, MetadataSlot::Untouched)),
                )?;
            }
            if rank < 7 {
                require(self.self_check.is_none())?;
            }
            if rank < 8 {
                require(self.requests_open_intent.is_none())?;
            }
            if rank < 6 {
                require(self.catalog_component.receipt().is_none() || self.quiesced.is_some())?;
            }
            if rank >= 2 {
                require(self.quiesced.is_some())?;
            }
            if (2..=4).contains(&rank) {
                require(
                    matches!(self.preimages.catalog.image, ImageState::Complete { .. })
                        && matches!(self.preimages.control.image, ImageState::Complete { .. }),
                )?;
            }
            if rank >= 3 {
                require(matches!(self.stage, StageProgress::Published { .. }))?;
            }
            if rank >= 4 {
                require(self.catalog_component.receipt().is_some())?;
            }
            if rank >= 5 {
                require(self.control_component.receipt().is_some())?;
            }
            if rank >= 6 {
                require(self.forward_pair_readback.is_some())?;
            }
            if rank >= 7 {
                require(
                    self.metadata
                        .slots
                        .iter()
                        .all(|slot| matches!(slot, MetadataSlot::Applied { .. })),
                )?;
            }
            if rank >= 8 {
                require(self.self_check.is_some())?;
            }
            if rank >= 9 {
                require(self.requests_open_intent.is_some())?;
            }
            if rank == 10 {
                require(self.pending.is_none() && self.last_failure.is_none())?;
            }
        } else {
            require(self.rollback.is_some() && self.requests_open_intent.is_none())?;
            if matches!(
                phase,
                PlainPhase::ControlRestored
                    | PlainPhase::CleanupPending
                    | PlainPhase::CleanupComplete
            ) {
                require(
                    self.rollback
                        .as_ref()
                        .is_some_and(|r| r.rollback_pair_readback.is_some()),
                )?;
            }
        }
        Ok(())
    }
}

const METADATA_ORDER: [usize; 16] = [0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 4];
const METADATA_KEYS: [&str; 16] = [
    "package_manifest",
    "package_receipt",
    "release_manifest",
    "checksums",
    "current",
    "installer_sh",
    "installer_powershell",
    "install_guide",
    "readme",
    "changelog",
    "license_mit",
    "license_apache",
    "notice",
    "security",
    "dependencies_json",
    "dependencies_csv",
];
const IMAGE_KEYS: [&str; 6] = [
    "catalog_preimage",
    "control_preimage",
    "catalog_side",
    "control_side",
    "catalog_displaced",
    "control_displaced",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Change {
    Coverage,
    Quiesced,
    Image(usize),
    Stage,
    Component(Component),
    Metadata(usize),
    ForwardReadback,
    SelfCheck,
    Open,
    Rollback,
    RollbackIntent,
    RollbackReadback,
    Journal(usize),
}

impl ImageState {
    fn follows(&self, before: &Self, phase: PlainPhase) -> Result<()> {
        if self == before {
            return Ok(());
        }
        let allowed = match (before, self) {
            (Self::Absent, Self::Registered) => phase == PlainPhase::Quiescing,
            (Self::Registered, Self::OwnedIncomplete { .. }) => matches!(
                phase,
                PlainPhase::Quiescing | PlainPhase::ReclaimPrepared | PlainPhase::ReclaimCommitted
            ),
            (Self::Registered, Self::Complete { .. }) => matches!(
                phase,
                PlainPhase::ReclaimCommitted | PlainPhase::CatalogRestored
            ),
            (Self::OwnedIncomplete { identity }, Self::Complete { stamp }) => {
                identity == &stamp.identity
                    && matches!(
                        phase,
                        PlainPhase::Quiescing
                            | PlainPhase::ReclaimPrepared
                            | PlainPhase::ReclaimCommitted
                            | PlainPhase::CatalogRestored
                    )
            }
            (Self::Complete { stamp }, Self::Adopted { stamp: next, .. }) => {
                stamp == next && phase == PlainPhase::Catalog23Control2
            }
            (
                Self::OwnedIncomplete { identity },
                Self::Reclaimed {
                    identity: next,
                    stamp: None,
                },
            ) => identity == next && phase == PlainPhase::ReclaimPrepared,
            (
                Self::Complete { stamp } | Self::Adopted { stamp, .. },
                Self::Reclaimed {
                    identity,
                    stamp: Some(next),
                },
            ) => {
                stamp == next && identity == &stamp.identity && phase == PlainPhase::ReclaimPrepared
            }
            (Self::Registered, Self::Absent) => phase == PlainPhase::CleanupPending,
            (
                Self::OwnedIncomplete { identity },
                Self::DeleteIntent {
                    identity: next,
                    stamp: None,
                },
            ) => identity == next && phase == PlainPhase::CleanupPending,
            (
                Self::Reclaimed { identity, stamp },
                Self::DeleteIntent {
                    identity: next,
                    stamp: after,
                },
            ) => identity == next && stamp == after && phase == PlainPhase::CleanupPending,
            (
                Self::Complete { stamp },
                Self::DeleteIntent {
                    identity,
                    stamp: Some(after),
                },
            ) => {
                phase == PlainPhase::CleanupPending && stamp == after && identity == &stamp.identity
            }
            (
                Self::Adopted {
                    stamp,
                    disposition: Disposition::Quarantined,
                    ..
                },
                Self::DeleteIntent {
                    identity,
                    stamp: Some(after),
                },
            ) => {
                stamp == after
                    && identity == &stamp.identity
                    && matches!(
                        phase,
                        PlainPhase::Migrated | PlainPhase::Switched | PlainPhase::SelfChecked
                    )
            }
            (Self::DeleteIntent { .. }, Self::Deleted) => matches!(
                phase,
                PlainPhase::CleanupPending
                    | PlainPhase::Migrated
                    | PlainPhase::Switched
                    | PlainPhase::SelfChecked
            ),
            // A prepared replacement becomes the installed file. Its old side
            // name can be absent only at the recorded pair exchange boundary.
            (Self::Complete { .. }, Self::Absent) => matches!(
                phase,
                PlainPhase::ReclaimCommitted | PlainPhase::CatalogRestored
            ),
            _ => false,
        };
        require(allowed)
    }
}

impl SidecarState {
    fn follows(&self, before: &Self, cleanup: bool) -> bool {
        self == before
            || match (before, self) {
                (Self::Absent, Self::Owned { .. }) => !cleanup,
                (Self::Owned { identity }, Self::DeleteIntent { identity: next }) => {
                    identity == next
                }
                (Self::DeleteIntent { .. }, Self::Deleted) => true,
                _ => false,
            }
    }
}

impl ImageSlot {
    fn follows(&self, before: &Self, phase: PlainPhase) -> Result<()> {
        require(
            self.role == before.role
                && self.artifact_id == before.artifact_id
                && self.root_binding == before.root_binding
                && self.relative_locator == before.relative_locator
                && self.coverage_ref == before.coverage_ref,
        )?;
        let mut changes = 0;
        if self.parent != before.parent {
            require(
                matches!(
                    (&before.parent, &self.parent),
                    (ParentState::AbsentUnderBoundRoot, ParentState::Owned { .. })
                ) && matches!(phase, PlainPhase::Quiescing | PlainPhase::ReclaimPrepared),
            )?;
            changes += 1;
        }
        if self.image != before.image {
            if matches!(before.image, ImageState::Registered)
                && matches!(self.image, ImageState::Complete { .. })
            {
                require(matches!(
                    (self.role, phase),
                    (ImageRole::CatalogDisplaced, PlainPhase::ReclaimCommitted)
                        | (ImageRole::ControlDisplaced, PlainPhase::CatalogRestored)
                ))?;
            }
            if matches!(before.image, ImageState::Complete { .. })
                && matches!(self.image, ImageState::Absent)
            {
                require(matches!(
                    (self.role, phase),
                    (ImageRole::CatalogSide, PlainPhase::ReclaimCommitted)
                        | (ImageRole::ControlSide, PlainPhase::CatalogRestored)
                ))?;
            }
            if matches!(before.image, ImageState::Complete { .. })
                && matches!(self.image, ImageState::DeleteIntent { .. })
            {
                require(matches!(
                    self.role,
                    ImageRole::CatalogDisplaced
                        | ImageRole::ControlDisplaced
                        | ImageRole::CatalogSide
                        | ImageRole::ControlSide
                ))?;
            }
            self.image.follows(&before.image, phase)?;
            changes += 1;
        }
        if self.manifest != before.manifest {
            let valid = match (&before.manifest, &self.manifest) {
                (ManifestState::Absent, ManifestState::OwnedIncomplete { .. }) => matches!(
                    phase,
                    PlainPhase::Quiescing
                        | PlainPhase::ReclaimPrepared
                        | PlainPhase::ReclaimCommitted
                ),
                (
                    ManifestState::OwnedIncomplete { identity },
                    ManifestState::Complete { stamp },
                ) => identity == &stamp.identity,
                (
                    ManifestState::OwnedIncomplete { .. } | ManifestState::Complete { .. },
                    ManifestState::Absent,
                ) => {
                    matches!(
                        self.image,
                        ImageState::DeleteIntent { .. } | ImageState::Deleted | ImageState::Absent
                    )
                }
                _ => false,
            };
            require(valid)?;
            changes += 1;
        }
        let cleanup = matches!(phase, PlainPhase::CleanupPending | PlainPhase::SelfChecked);
        for (old, new) in [
            (&before.sidecars.wal, &self.sidecars.wal),
            (&before.sidecars.shm, &self.sidecars.shm),
            (&before.sidecars.journal, &self.sidecars.journal),
        ] {
            if old != new {
                require(new.follows(old, cleanup))?;
                changes += 1;
            }
        }
        require(changes == 1)
    }
}

impl StageProgress {
    fn follows(&self, before: &Self) -> bool {
        match (before, self) {
            (Self::Unstarted, Self::Intent { .. }) => true,
            (
                Self::Intent {
                    inventory_sha256: a,
                },
                Self::Extracted {
                    inventory_sha256: b,
                },
            )
            | (
                Self::Extracted {
                    inventory_sha256: a,
                },
                Self::PublishIntent {
                    inventory_sha256: b,
                },
            )
            | (
                Self::PublishIntent {
                    inventory_sha256: a,
                },
                Self::Published {
                    inventory_sha256: b,
                    ..
                },
            ) => a == b,
            _ => false,
        }
    }
}

impl ComponentProgress {
    fn follows(&self, before: &Self) -> bool {
        match (before, self) {
            (Self::Unstarted, Self::Intent { .. }) => true,
            (
                Self::Intent { record },
                Self::Committed { intent, .. } | Self::NotApplied { intent, .. },
            ) => record == intent,
            _ => false,
        }
    }
}

impl MetadataSlot {
    fn images(&self) -> Option<(&BeforeImage, &ImageDigest)> {
        match self {
            Self::Untouched => None,
            Self::Prepared { before, after }
            | Self::PublishIntent { before, after }
            | Self::Applied { before, after }
            | Self::RestoreIntent { before, after }
            | Self::Restored { before, after } => Some((before, after)),
        }
    }

    fn follows(&self, before: &Self, rollback: bool) -> bool {
        let allowed = if rollback {
            matches!(
                (before, self),
                (
                    Self::Prepared { .. } | Self::PublishIntent { .. } | Self::Applied { .. },
                    Self::RestoreIntent { .. }
                ) | (Self::RestoreIntent { .. }, Self::Restored { .. })
            )
        } else {
            matches!(
                (before, self),
                (Self::Untouched, Self::Prepared { .. })
                    | (Self::Prepared { .. }, Self::PublishIntent { .. })
                    | (Self::PublishIntent { .. }, Self::Applied { .. })
            )
        };
        allowed && (before.images().is_none() || before.images() == self.images())
    }
}

impl OwnedRecordSlot {
    fn follows(&self, before: &Self) -> bool {
        if self.role != before.role || self.path_kind != before.path_kind {
            return false;
        }
        let same_identity = before.identity.is_none() || self.identity == before.identity;
        let same_bytes = before.blake3.is_none()
            || (self.blake3 == before.blake3 && self.size_bytes == before.size_bytes);
        same_identity
            && same_bytes
            && matches!(
                (before.state, self.state),
                (
                    OwnedRecordState::Registered,
                    OwnedRecordState::Owned | OwnedRecordState::Absent
                ) | (
                    OwnedRecordState::Owned,
                    OwnedRecordState::Complete | OwnedRecordState::DeleteIntent
                ) | (OwnedRecordState::Complete, OwnedRecordState::DeleteIntent)
                    | (OwnedRecordState::DeleteIntent, OwnedRecordState::Deleted)
            )
    }
}

impl StateRecord {
    fn same_progress(&self, before: &Self) -> bool {
        let mut comparable = self.clone();
        comparable.seq = before.seq;
        comparable.predecessor_sha256 = before.predecessor_sha256.clone();
        comparable.phase = before.phase.clone();
        comparable.pending = before.pending.clone();
        comparable.last_failure = before.last_failure.clone();
        comparable == *before
    }

    fn successor(&self, before: &Self) -> Result<()> {
        let from = before.phase.plain();
        let to = self.phase.plain();
        if let PhaseV2::Attention { resume, failed_seq } = &self.phase {
            let failure = self.last_failure.as_ref().ok_or(RecordError::Invalid)?;
            return require(
                *resume == from
                    && *failed_seq == before.seq
                    && failure.at_seq == before.seq
                    && failure.effect == before.pending.as_ref().map(|p| p.kind)
                    && self.same_progress(before)
                    && self.pending == before.pending
                    && !matches!(from, PlainPhase::Complete | PlainPhase::CleanupComplete),
            );
        }
        if matches!(before.phase, PhaseV2::Attention { .. }) && to == from {
            return require(
                self.same_progress(before)
                    && self.pending == before.pending
                    && self.last_failure.is_none(),
            );
        }
        let reclaim = to == PlainPhase::ReclaimPrepared && from.pre_open();
        require(!matches!(before.phase, PhaseV2::Attention { .. }) || reclaim)?;
        require(to == from || from.next() == Some(to) || reclaim)?;
        require(!matches!(
            from,
            PlainPhase::Complete | PlainPhase::CleanupComplete
        ))?;
        if reclaim {
            require(
                before.requests_open_intent.is_none()
                    && self.requests_open_intent.is_none()
                    && before.rollback.is_none()
                    && self.rollback.is_some()
                    && before.pending.is_none(),
            )?;
            if let Some(rollback) = &self.rollback {
                require(match rollback.restore_pair {
                    RestorePair::Required => rollback.plan.is_some() && rollback.intent.is_none(),
                    RestorePair::NotNeeded => rollback.plan.is_none() && rollback.intent.is_some(),
                })?;
                for image in [
                    rollback.catalog_side.as_ref(),
                    rollback.control_side.as_ref(),
                    rollback.catalog_displaced.as_ref(),
                    rollback.control_displaced.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    require(
                        matches!(image.parent, ParentState::AbsentUnderBoundRoot)
                            && matches!(image.image, ImageState::Registered | ImageState::Absent)
                            && matches!(image.manifest, ManifestState::Absent)
                            && [
                                &image.sidecars.wal,
                                &image.sidecars.shm,
                                &image.sidecars.journal,
                            ]
                            .into_iter()
                            .all(|state| matches!(state, SidecarState::Absent)),
                    )?;
                }
                for record in [
                    rollback.catalog_restore_journal.as_ref(),
                    rollback.control_restore_journal.as_ref(),
                ]
                .into_iter()
                .flatten()
                {
                    require(
                        matches!(
                            record.state,
                            OwnedRecordState::Registered | OwnedRecordState::Absent
                        ) && record.identity.is_none()
                            && record.blake3.is_none()
                            && record.size_bytes == 0,
                    )?;
                }
            }
        }
        let changes = self.progress_changes(before)?;
        self.check_change_phase(before, &changes)?;
        self.check_pending(before, &changes)?;
        let failure_changed = self.last_failure != before.last_failure;
        if failure_changed {
            if let Some(failure) = &self.last_failure {
                require(
                    failure.at_seq == before.seq
                        && failure.effect == before.pending.as_ref().map(|p| p.kind)
                        && self.same_progress(before)
                        && self.pending == before.pending
                        && to == from,
                )?;
            } else {
                require(before.last_failure.is_some())?;
            }
        }
        require(
            !changes.is_empty()
                || self.phase != before.phase
                || self.pending != before.pending
                || failure_changed,
        )?;
        if to != from {
            self.check_phase_boundary(before, &changes)?;
        }
        Ok(())
    }

    fn progress_changes(&self, before: &Self) -> Result<Vec<Change>> {
        let mut changes = Vec::new();
        let mut comparable = self.clone();
        comparable.seq = before.seq;
        comparable.predecessor_sha256 = before.predecessor_sha256.clone();
        comparable.phase = before.phase.clone();
        comparable.pending = before.pending.clone();
        comparable.last_failure = before.last_failure.clone();
        if self.quiesced != before.quiesced {
            require(before.quiesced.is_none() && self.quiesced.is_some())?;
            comparable.quiesced = before.quiesced.clone();
            changes.push(Change::Quiesced);
        }
        let mut coverage_changed = false;
        for (index, (old, new)) in before.images().into_iter().zip(self.images()).enumerate() {
            let (Some(old), Some(new)) = (old, new) else {
                continue;
            };
            if old.coverage_ref != new.coverage_ref {
                require(old.coverage_ref.is_none() && new.coverage_ref.is_some())?;
                coverage_changed = true;
            }
            let mut without_coverage = new.clone();
            without_coverage.coverage_ref = old.coverage_ref.clone();
            if &without_coverage != old {
                without_coverage.follows(old, before.phase.plain())?;
                changes.push(Change::Image(index));
            }
        }
        if coverage_changed {
            changes.push(Change::Coverage);
        }
        comparable.preimages = before.preimages.clone();
        if self.stage != before.stage {
            require(self.stage.follows(&before.stage))?;
            comparable.stage = before.stage.clone();
            changes.push(Change::Stage);
        }
        for (component, old, new) in [
            (
                Component::Catalog,
                &before.catalog_component,
                &self.catalog_component,
            ),
            (
                Component::Control,
                &before.control_component,
                &self.control_component,
            ),
        ] {
            if old != new {
                require(new.follows(old))?;
                changes.push(Change::Component(component));
            }
        }
        comparable.catalog_component = before.catalog_component.clone();
        comparable.control_component = before.control_component.clone();
        for (index, (old, new)) in before
            .metadata
            .slots
            .iter()
            .zip(&self.metadata.slots)
            .enumerate()
        {
            if old != new {
                require(new.follows(old, self.rollback.is_some()))?;
                changes.push(Change::Metadata(index));
            }
        }
        comparable.metadata = before.metadata.clone();
        for (old, new, kind) in [
            (
                &before.forward_pair_readback,
                &self.forward_pair_readback,
                Change::ForwardReadback,
            ),
            (&before.self_check, &self.self_check, Change::SelfCheck),
        ] {
            if old != new {
                require(old.is_none() && new.is_some())?;
                changes.push(kind);
            }
        }
        comparable.forward_pair_readback = before.forward_pair_readback.clone();
        comparable.self_check = before.self_check.clone();
        if self.requests_open_intent != before.requests_open_intent {
            require(
                before.requests_open_intent.is_none()
                    && self
                        .requests_open_intent
                        .as_ref()
                        .is_some_and(|intent| intent.seq == self.seq),
            )?;
            changes.push(Change::Open);
        }
        comparable.requests_open_intent = before.requests_open_intent.clone();
        match (&before.rollback, &self.rollback) {
            (None, Some(_)) => changes.push(Change::Rollback),
            (Some(old), Some(new)) => {
                let mut fixed = new.clone();
                if old.intent != new.intent {
                    require(
                        old.intent.is_none()
                            && new.intent.is_some()
                            && old.restore_pair == RestorePair::Required,
                    )?;
                    fixed.intent = old.intent.clone();
                    changes.push(Change::RollbackIntent);
                }
                fixed.catalog_side = old.catalog_side.clone();
                fixed.control_side = old.control_side.clone();
                fixed.catalog_displaced = old.catalog_displaced.clone();
                fixed.control_displaced = old.control_displaced.clone();
                for (old, new, index) in [
                    (
                        &old.catalog_restore_journal,
                        &new.catalog_restore_journal,
                        0,
                    ),
                    (
                        &old.control_restore_journal,
                        &new.control_restore_journal,
                        1,
                    ),
                ] {
                    if old != new {
                        require(
                            old.as_ref()
                                .zip(new.as_ref())
                                .is_some_and(|(a, b)| b.follows(a)),
                        )?;
                        changes.push(Change::Journal(index));
                    }
                }
                fixed.catalog_restore_journal = old.catalog_restore_journal.clone();
                fixed.control_restore_journal = old.control_restore_journal.clone();
                if old.rollback_pair_readback != new.rollback_pair_readback {
                    require(
                        old.rollback_pair_readback.is_none()
                            && new.rollback_pair_readback.is_some(),
                    )?;
                    changes.push(Change::RollbackReadback);
                }
                fixed.rollback_pair_readback = old.rollback_pair_readback.clone();
                fixed.finalizer = old.finalizer.clone();
                require(&fixed == old)?;
                for (old, new) in before.images().into_iter().zip(self.images()).skip(2) {
                    require(old.is_some() == new.is_some())?;
                }
            }
            (Some(_), None) => return Err(RecordError::Invalid),
            (None, None) => {}
        }
        comparable.rollback = before.rollback.clone();
        require(comparable == *before)?;
        Ok(changes)
    }

    fn check_change_phase(&self, before: &Self, changes: &[Change]) -> Result<()> {
        let phase = before.phase.plain();
        let adopting = changes.contains(&Change::Component(Component::Control))
            && self.control_component.receipt().is_some();
        let reclaiming = phase == PlainPhase::ReclaimPrepared
            && self.phase.plain() == PlainPhase::ReclaimCommitted;
        let pair_group = before.pending.as_ref().is_some_and(|pending| {
            pending.kind == EffectKind::PairRestore
                && changes.iter().all(|change| pending.targets(*change))
        });
        let grouped = pair_group
            || (changes
                .iter()
                .all(|change| matches!(change, Change::Quiesced | Change::Coverage))
                && changes.contains(&Change::Quiesced))
            || ((adopting || reclaiming)
                && changes.iter().all(|change| {
                    matches!(
                        change,
                        Change::Component(Component::Control) | Change::Image(0 | 1)
                    )
                }));
        require(changes.len() <= 1 || grouped)?;
        for change in changes {
            require(match *change {
                Change::Quiesced | Change::Coverage => {
                    matches!(phase, PlainPhase::Verified | PlainPhase::Quiescing)
                }
                Change::Stage => phase == PlainPhase::BackedUp,
                Change::Component(Component::Catalog) => phase == PlainPhase::Staged,
                Change::Component(Component::Control) => phase == PlainPhase::Catalog23Control2,
                Change::Metadata(index) => {
                    let rollback = self.rollback.is_some();
                    let next = if rollback {
                        METADATA_ORDER.iter().rev().copied().find(|i| {
                            !matches!(
                                before.metadata.slots[*i],
                                MetadataSlot::Untouched | MetadataSlot::Restored { .. }
                            )
                        })
                    } else {
                        METADATA_ORDER.iter().copied().find(|i| {
                            !matches!(before.metadata.slots[*i], MetadataSlot::Applied { .. })
                        })
                    };
                    next == Some(index)
                        && phase
                            == if rollback {
                                PlainPhase::CleanupPending
                            } else {
                                PlainPhase::Migrated
                            }
                }
                Change::ForwardReadback => {
                    phase == PlainPhase::Catalog23Control3
                        && self.phase.plain() == PlainPhase::Migrated
                }
                Change::SelfCheck => {
                    phase == PlainPhase::Switched && self.phase.plain() == PlainPhase::SelfChecked
                }
                Change::Open => {
                    phase == PlainPhase::SelfChecked && self.phase.plain() == PlainPhase::Opening
                }
                Change::Rollback => phase.pre_open(),
                Change::RollbackIntent => {
                    phase == PlainPhase::ReclaimPrepared
                        && self.phase.plain() == PlainPhase::ReclaimPrepared
                        && before.pending.is_none()
                        && self.pending.is_none()
                        && self
                            .rollback
                            .as_ref()
                            .is_some_and(RollbackProgress::preparation_complete)
                }
                Change::RollbackReadback => phase == PlainPhase::CatalogRestored,
                Change::Journal(_) => matches!(
                    phase,
                    PlainPhase::ReclaimPrepared
                        | PlainPhase::ReclaimCommitted
                        | PlainPhase::CatalogRestored
                        | PlainPhase::CleanupPending
                ),
                Change::Image(index) => {
                    let new = self.images()[index].ok_or(RecordError::Invalid)?;
                    let old = before.images()[index].ok_or(RecordError::Invalid)?;
                    if matches!(old.image, ImageState::Registered)
                        && matches!(new.image, ImageState::Complete { .. })
                    {
                        let (slot, boundary) = match new.role {
                            ImageRole::CatalogDisplaced => ("catalog", PlainPhase::CatalogRestored),
                            ImageRole::ControlDisplaced => ("control", PlainPhase::ControlRestored),
                            _ => return Err(RecordError::Invalid),
                        };
                        require(
                            self.phase.plain() == boundary
                                && before.pending.as_ref().is_some_and(|p| {
                                    p.kind == EffectKind::PairRestore && p.slot == slot
                                }),
                        )?;
                    }
                    if matches!(old.image, ImageState::Complete { .. })
                        && matches!(new.image, ImageState::Absent)
                    {
                        let (slot, boundary) = match new.role {
                            ImageRole::CatalogSide => ("catalog", PlainPhase::CatalogRestored),
                            ImageRole::ControlSide => ("control", PlainPhase::ControlRestored),
                            _ => return Err(RecordError::Invalid),
                        };
                        require(
                            self.phase.plain() == boundary
                                && before.pending.as_ref().is_some_and(|pending| {
                                    pending.kind == EffectKind::PairRestore && pending.slot == slot
                                }),
                        )?;
                    }
                    if new.image == old.image {
                        require(matches!(
                            phase,
                            PlainPhase::Quiescing
                                | PlainPhase::ReclaimPrepared
                                | PlainPhase::ReclaimCommitted
                                | PlainPhase::CatalogRestored
                                | PlainPhase::CleanupPending
                                | PlainPhase::Migrated
                                | PlainPhase::Switched
                                | PlainPhase::SelfChecked
                        ))?;
                        continue;
                    }
                    match &new.image {
                        ImageState::Adopted { .. } => adopting,
                        ImageState::Reclaimed { .. } => reclaiming,
                        _ => matches!(
                            phase,
                            PlainPhase::Quiescing
                                | PlainPhase::ReclaimPrepared
                                | PlainPhase::ReclaimCommitted
                                | PlainPhase::CatalogRestored
                                | PlainPhase::CleanupPending
                                | PlainPhase::Migrated
                                | PlainPhase::Switched
                                | PlainPhase::SelfChecked
                        ),
                    }
                }
            })?;
        }
        Ok(())
    }

    fn check_pending(&self, before: &Self, changes: &[Change]) -> Result<()> {
        match (&before.pending, &self.pending) {
            (None, Some(next)) => {
                require(next.intent_seq == self.seq && before.last_failure.is_none())?;
                require(changes.is_empty())?;
                self.effect_allowed(next)?;
            }
            (Some(old), Some(new)) => {
                require(old == new && changes.is_empty() && self.phase == before.phase)?;
            }
            (Some(old), None) => {
                before.effect_allowed(old)?;
                require(
                    !changes.is_empty()
                        || match old.kind {
                            EffectKind::FenceClear => self.phase.plain() == PlainPhase::Complete,
                            EffectKind::PairRestore => {
                                self.phase.plain() != before.phase.plain()
                                    && self
                                        .rollback
                                        .as_ref()
                                        .is_some_and(|r| r.restore_pair == RestorePair::NotNeeded)
                            }
                            _ => false,
                        },
                )?;
                require(
                    changes.iter().all(|change| old.targets(*change))
                        && (self.phase.plain() == before.phase.plain()
                            || before.phase.plain().next() == Some(self.phase.plain())),
                )?;
            }
            (None, None) => {
                require(changes.iter().all(|change| match *change {
                    Change::Stage => matches!(
                        self.stage,
                        StageProgress::Intent { .. } | StageProgress::PublishIntent { .. }
                    ),
                    Change::Component(component) => matches!(
                        if component == Component::Catalog {
                            &self.catalog_component
                        } else {
                            &self.control_component
                        },
                        ComponentProgress::Intent { .. }
                    ),
                    Change::Metadata(index) => matches!(
                        self.metadata.slots[index],
                        MetadataSlot::Prepared { .. }
                            | MetadataSlot::PublishIntent { .. }
                            | MetadataSlot::RestoreIntent { .. }
                    ),
                    Change::Image(index) => {
                        index < 2
                            && self.images()[index].is_some_and(|image| {
                                matches!(image.image, ImageState::Registered)
                                    || (before.phase.plain() == PlainPhase::ReclaimPrepared
                                        && self.phase.plain() == PlainPhase::ReclaimCommitted
                                        && matches!(image.image, ImageState::Reclaimed { .. }))
                            })
                    }
                    Change::Journal(_) => false,
                    _ => true,
                }))?;
            }
        }
        Ok(())
    }

    fn effect_allowed(&self, pending: &PendingEffect) -> Result<()> {
        let phase = self.phase.plain();
        require(match pending.kind {
            EffectKind::FenceSet => phase == PlainPhase::Quiescing && self.quiesced.is_none(),
            EffectKind::StageExtract => {
                phase == PlainPhase::BackedUp && matches!(self.stage, StageProgress::Intent { .. })
            }
            EffectKind::StagePublish => {
                phase == PlainPhase::BackedUp
                    && matches!(self.stage, StageProgress::PublishIntent { .. })
            }
            EffectKind::PreimageCreate => {
                phase == PlainPhase::Quiescing
                    && self.quiesced.is_some()
                    && [&self.preimages.catalog, &self.preimages.control]
                        .into_iter()
                        .all(|image| !matches!(image.image, ImageState::Absent))
            }
            EffectKind::RollbackBindParent
            | EffectKind::RollbackCreateEmpty
            | EffectKind::RollbackWriteContent => {
                phase == PlainPhase::ReclaimPrepared
                    && self.rollback.as_ref().is_some_and(|r| {
                        r.restore_pair == RestorePair::Required
                            && r.plan.is_some()
                            && r.intent.is_none()
                    })
                    && records::PreparationSlot::parse(&pending.slot)
                        .is_some_and(|slot| slot.permits(pending.kind))
            }
            EffectKind::ComponentCommit => match pending.slot.as_str() {
                "catalog" => {
                    phase == PlainPhase::Staged
                        && matches!(self.catalog_component, ComponentProgress::Intent { .. })
                }
                "control" => {
                    phase == PlainPhase::Catalog23Control2
                        && matches!(self.control_component, ComponentProgress::Intent { .. })
                }
                _ => false,
            },
            EffectKind::MetadataPublish | EffectKind::MetadataRestore => {
                let index = METADATA_KEYS
                    .iter()
                    .position(|key| *key == pending.slot)
                    .ok_or(RecordError::Invalid)?;
                match pending.kind {
                    EffectKind::MetadataPublish => {
                        phase == PlainPhase::Migrated
                            && matches!(
                                self.metadata.slots[index],
                                MetadataSlot::PublishIntent { .. }
                            )
                    }
                    _ => {
                        phase == PlainPhase::CleanupPending
                            && matches!(
                                self.metadata.slots[index],
                                MetadataSlot::RestoreIntent { .. }
                            )
                    }
                }
            }
            EffectKind::PairRestore => {
                self.rollback.as_ref().is_some_and(|r| r.intent.is_some())
                    && ((phase == PlainPhase::ReclaimCommitted && pending.slot == "catalog")
                        || (phase == PlainPhase::CatalogRestored && pending.slot == "control"))
            }
            EffectKind::OwnedDelete => matches!(
                phase,
                PlainPhase::CleanupPending
                    | PlainPhase::Migrated
                    | PlainPhase::Switched
                    | PlainPhase::SelfChecked
            ),
            EffectKind::FenceClear => phase == PlainPhase::Opening,
        })
    }

    fn check_phase_boundary(&self, before: &Self, changes: &[Change]) -> Result<()> {
        let to = self.phase.plain();
        require(match to {
            PlainPhase::Quiescing => self
                .pending
                .as_ref()
                .is_some_and(|p| p.kind == EffectKind::FenceSet),
            PlainPhase::BackedUp => {
                self.pending.is_none()
                    && self.quiesced.is_some()
                    && [&self.preimages.catalog, &self.preimages.control]
                        .into_iter()
                        .all(|image| {
                            matches!(image.image, ImageState::Complete { .. })
                                && matches!(image.manifest, ManifestState::Complete { .. })
                        })
            }
            PlainPhase::Staged => {
                self.pending.is_none() && matches!(self.stage, StageProgress::Published { .. })
            }
            PlainPhase::Catalog23Control2 => {
                self.pending.is_none()
                    && self.catalog_component.receipt().is_some()
                    && changes.contains(&Change::Component(Component::Catalog))
            }
            PlainPhase::Catalog23Control3 => {
                self.pending.is_none()
                    && self.control_component.receipt().is_some()
                    && changes.contains(&Change::Component(Component::Control))
                    && [&self.preimages.catalog, &self.preimages.control]
                        .into_iter()
                        .all(|image| matches!(image.image, ImageState::Adopted { .. }))
            }
            PlainPhase::Migrated => self.pending.is_none() && changes == [Change::ForwardReadback],
            PlainPhase::Switched => {
                self.pending.is_none()
                    && self
                        .metadata
                        .slots
                        .iter()
                        .all(|slot| matches!(slot, MetadataSlot::Applied { .. }))
            }
            PlainPhase::SelfChecked => self.pending.is_none() && changes == [Change::SelfCheck],
            PlainPhase::Opening => {
                self.pending.is_none()
                    && changes == [Change::Open]
                    && self.images().into_iter().flatten().all(|image| {
                        matches!(
                            image.image,
                            ImageState::Adopted {
                                disposition: Disposition::Restorable,
                                ..
                            }
                        ) || image.clean()
                    })
            }
            PlainPhase::Complete => {
                self.pending.is_none()
                    && self.last_failure.is_none()
                    && before
                        .pending
                        .as_ref()
                        .is_some_and(|p| p.kind == EffectKind::FenceClear)
            }
            PlainPhase::ReclaimPrepared => changes == [Change::Rollback] && self.pending.is_none(),
            PlainPhase::ReclaimCommitted => {
                self.rollback.as_ref().is_some_and(|r| r.intent.is_some())
                    && changes
                        .iter()
                        .all(|change| matches!(change, Change::Image(0 | 1)))
                    && self.pending.is_none()
                    && [&self.preimages.catalog, &self.preimages.control]
                        .into_iter()
                        .all(|image| {
                            matches!(
                                image.image,
                                ImageState::Registered
                                    | ImageState::Absent
                                    | ImageState::Deleted
                                    | ImageState::Reclaimed { .. }
                            )
                        })
            }
            PlainPhase::CatalogRestored => {
                self.pending.is_none()
                    && before
                        .pending
                        .as_ref()
                        .is_some_and(|p| p.kind == EffectKind::PairRestore && p.slot == "catalog")
                    && self.rollback.as_ref().is_some_and(|r| {
                        r.restore_pair == RestorePair::NotNeeded
                            || r.catalog_side
                                .as_ref()
                                .is_some_and(|image| matches!(image.image, ImageState::Absent))
                    })
            }
            PlainPhase::ControlRestored => {
                self.pending.is_none()
                    && self
                        .rollback
                        .as_ref()
                        .is_some_and(|r| r.rollback_pair_readback.is_some())
                    && before
                        .pending
                        .as_ref()
                        .is_some_and(|p| p.kind == EffectKind::PairRestore && p.slot == "control")
                    && self.rollback.as_ref().is_some_and(|r| {
                        r.restore_pair == RestorePair::NotNeeded
                            || r.control_side
                                .as_ref()
                                .is_some_and(|image| matches!(image.image, ImageState::Absent))
                    })
            }
            PlainPhase::CleanupPending => self.pending.is_none(),
            PlainPhase::CleanupComplete => {
                self.pending.is_none()
                    && self.images().into_iter().flatten().all(ImageSlot::clean)
                    && self.metadata.slots.iter().all(|slot| {
                        matches!(
                            slot,
                            MetadataSlot::Untouched | MetadataSlot::Restored { .. }
                        )
                    })
                    && self.rollback.as_ref().is_some_and(|r| {
                        [
                            r.catalog_restore_journal.as_ref(),
                            r.control_restore_journal.as_ref(),
                        ]
                        .into_iter()
                        .flatten()
                        .all(|record| {
                            matches!(
                                record.state,
                                OwnedRecordState::Absent | OwnedRecordState::Deleted
                            )
                        })
                    })
            }
            PlainPhase::Verified => false,
        })
    }
}

impl PendingEffect {
    fn targets(&self, change: Change) -> bool {
        match change {
            Change::Stage => matches!(
                self.kind,
                EffectKind::StageExtract | EffectKind::StagePublish
            ),
            Change::Component(component) => {
                self.kind == EffectKind::ComponentCommit
                    && self.slot
                        == if component == Component::Catalog {
                            "catalog"
                        } else {
                            "control"
                        }
            }
            Change::Metadata(index) => {
                matches!(
                    self.kind,
                    EffectKind::MetadataPublish | EffectKind::MetadataRestore
                ) && self.slot == METADATA_KEYS[index]
            }
            Change::Image(index) => {
                (matches!(
                    self.kind,
                    EffectKind::PreimageCreate | EffectKind::OwnedDelete
                ) && self.slot == IMAGE_KEYS[index])
                    || (matches!(
                        self.kind,
                        EffectKind::RollbackBindParent
                            | EffectKind::RollbackCreateEmpty
                            | EffectKind::RollbackWriteContent
                    ) && records::PreparationSlot::parse(&self.slot)
                        .is_some_and(|slot| slot.target() == Change::Image(index)))
                    || (self.kind == EffectKind::ComponentCommit
                        && self.slot == "control"
                        && index < 2)
                    || (self.kind == EffectKind::PairRestore
                        && ((self.slot == "catalog" && matches!(index, 2 | 4))
                            || (self.slot == "control" && matches!(index, 3 | 5))))
            }
            Change::Journal(index) => {
                (matches!(
                    self.kind,
                    EffectKind::RollbackCreateEmpty | EffectKind::RollbackWriteContent
                ) && records::PreparationSlot::parse(&self.slot)
                    .is_some_and(|slot| slot.target() == Change::Journal(index)))
                    || (self.kind == EffectKind::OwnedDelete
                        && self.slot
                            == if index == 0 {
                                "catalog_restore_journal"
                            } else {
                                "control_restore_journal"
                            })
                    || (self.kind == EffectKind::PairRestore
                        && self.slot == if index == 0 { "catalog" } else { "control" })
            }
            Change::Quiesced | Change::Coverage => self.kind == EffectKind::FenceSet,
            Change::RollbackReadback => {
                self.kind == EffectKind::PairRestore && self.slot == "control"
            }
            _ => false,
        }
    }
}

/// A decoded state is a bounded record, never a publication/executor capability.
#[derive(Debug)]
pub struct StateV2 {
    record: StateRecord,
    raw: Vec<u8>,
}

/// Already decoded byte evidence. These borrowed records are not native guards.
#[derive(Clone, Copy)]
pub struct RecordSet<'a> {
    pub proofs: &'a [ProofRecord],
    pub manifests: &'a [records::PreimageManifest],
}

/// An effect ACK supplies the exact typed readback bytes named by pending.
/// The future executor is responsible for obtaining them under retained pins.
pub struct SuccessorEvidence<'a> {
    pub previous: RecordSet<'a>,
    pub current: RecordSet<'a>,
    pub effect_readback: Option<&'a [u8]>,
}

fn find_record<'a>(
    proofs: &'a [ProofRecord],
    reference: &RecordRef,
    used: &mut BTreeSet<u8>,
) -> Result<&'a ProofRecord> {
    let proof = proofs
        .iter()
        .find(|proof| reference.matches(proof))
        .ok_or(RecordError::Invalid)?;
    used.insert(proof.slot as u8);
    Ok(proof)
}

impl StateV2 {
    /// Canonical first state. Only the native initializer may publish it after
    /// its immutable admission and final refusal guard are durably bound.
    pub(super) fn initial(admission: &AdmissionV2) -> Result<Self> {
        admission.record.validate()?;
        let suffix = &admission.record.update_id["update_".len()..];
        let image = |role, component: &str, name: &str| {
            let artifact_id = format!("transition_{component}_{suffix}");
            ImageSlot {
                role,
                relative_locator: format!("backups/{artifact_id}/{name}"),
                artifact_id,
                root_binding: admission.record.control_root.identity.clone(),
                coverage_ref: None,
                parent: ParentState::AbsentUnderBoundRoot,
                image: ImageState::Absent,
                manifest: ManifestState::Absent,
                sidecars: Sidecars {
                    wal: SidecarState::Absent,
                    shm: SidecarState::Absent,
                    journal: SidecarState::Absent,
                },
            }
        };
        let record = StateRecord {
            schema: STATE_SCHEMA.into(),
            mode: admission.record.mode,
            update_id: admission.record.update_id.clone(),
            owner_nonce: admission.record.owner_nonce.clone(),
            prefix_binding: admission.record.prefix.identity.clone(),
            control_binding: admission.record.control_root.identity.clone(),
            admission_sha256: sha256(admission.raw_bytes()),
            seq: 1,
            predecessor_sha256: None,
            phase: PhaseV2::Verified,
            quiesced: None,
            preimages: Preimages {
                catalog: image(ImageRole::CatalogPreimage, "catalog", "catalog.db"),
                control: image(ImageRole::ControlPreimage, "control", "control.db"),
            },
            stage: StageProgress::Unstarted,
            catalog_component: ComponentProgress::Unstarted,
            control_component: ComponentProgress::Unstarted,
            metadata: MetadataLedger {
                slots: std::array::from_fn(|_| MetadataSlot::Untouched),
            },
            forward_pair_readback: None,
            self_check: None,
            requests_open_intent: None,
            rollback: None,
            pending: None,
            last_failure: None,
        };
        record.validate(admission)?;
        let raw = super::encode(&record)?;
        Ok(Self { record, raw })
    }

    pub fn decode(bytes: &[u8], admission: &AdmissionV2) -> Result<Self> {
        super::bounded(bytes)?;
        let mut deserializer = serde_json::Deserializer::from_slice(bytes);
        Shape(false)
            .deserialize(&mut deserializer)
            .map_err(|_| RecordError::Invalid)?;
        deserializer.end().map_err(|_| RecordError::Invalid)?;
        let record: StateRecord =
            serde_json::from_slice(bytes).map_err(|_| RecordError::Invalid)?;
        record.validate(admission)?;
        Ok(Self {
            record,
            raw: bytes.to_vec(),
        })
    }

    pub fn encode(&self, admission: &AdmissionV2) -> Result<Vec<u8>> {
        self.record.validate(admission)?;
        super::encode(&self.record)
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Validate one closed record successor. Runtime still owes native admission
    /// and exact effect readback; use validate_successor for retained payloads too.
    pub fn validate_chain(&self, previous: &Self, admission: &AdmissionV2) -> Result<()> {
        self.record.validate(admission)?;
        previous.record.validate(admission)?;
        require(
            previous.record.seq.checked_add(1) == Some(self.record.seq)
                && self.record.predecessor_sha256.as_deref()
                    == Some(sha256(&previous.raw).as_str())
                && previous.record.phase.plain() != PlainPhase::Complete,
        )?;
        for (before, after) in previous
            .record
            .images()
            .into_iter()
            .zip(self.record.images())
        {
            if let Some(reference) = before.and_then(|image| image.coverage_ref.as_ref()) {
                require(after.and_then(|image| image.coverage_ref.as_ref()) == Some(reference))?;
            }
        }
        if let Some(intent) = &previous.record.requests_open_intent {
            require(
                self.record.requests_open_intent.as_ref() == Some(intent)
                    && self.record.rollback.is_none(),
            )?;
        }
        self.record.successor(&previous.record)
    }

    /// Check actual supplied proof bytes against the state references. This
    /// checks the acyclic readback/SelfCheck chain, not live component commits.
    pub fn validate_proofs(&self, proofs: &[ProofRecord], admission: &AdmissionV2) -> Result<()> {
        require(proofs.len() <= 3)?;
        self.validate_readbacks(&proofs.iter().collect::<Vec<_>>(), admission)
    }

    fn validate_readbacks(&self, proofs: &[&ProofRecord], admission: &AdmissionV2) -> Result<()> {
        self.record.validate(admission)?;
        require(proofs.len() <= 3)?;
        let mut seen = BTreeSet::new();
        for proof in proofs {
            require(seen.insert(proof.slot as u8))?;
            proof.payload.validate(admission)?;
        }
        let find = |reference: &RecordRef| -> Result<&ProofRecord> {
            proofs
                .iter()
                .copied()
                .find(|proof| reference.matches(proof))
                .ok_or(RecordError::Invalid)
        };
        if let Some(reference) = &self.record.forward_pair_readback {
            let proof = find(reference)?;
            let ProofPayload::Forward(pair) = &proof.payload else {
                return Err(RecordError::Invalid);
            };
            let catalog = self
                .record
                .catalog_component
                .receipt()
                .ok_or(RecordError::Invalid)?;
            let control = self
                .record
                .control_component
                .receipt()
                .ok_or(RecordError::Invalid)?;
            require(
                pair.catalog_receipt_sha256 == catalog.sha256
                    && pair.control_receipt_sha256 == control.sha256,
            )?;
            let before = self.record.quiesced.as_ref().ok_or(RecordError::Invalid)?;
            require(
                pair.catalog_identity.incarnation == before.catalog.incarnation
                    && pair.catalog_identity.generation == before.catalog.generation
                    && pair.catalog_identity.destructive_epoch == before.catalog.destructive_epoch
                    && pair.catalog.identity == before.catalog_file.identity
                    && pair.control.identity == before.control_file.identity,
            )?;
            pair.control_checkpoint
                .follows_checkpoint(&before.control)?;
        }
        if let Some(reference) = &self.record.self_check {
            let proof = find(reference)?;
            let ProofPayload::SelfCheck(check) = &proof.payload else {
                return Err(RecordError::Invalid);
            };
            let forward = self
                .record
                .forward_pair_readback
                .as_ref()
                .ok_or(RecordError::Invalid)?;
            let ProofPayload::Forward(pair) = &find(forward)?.payload else {
                return Err(RecordError::Invalid);
            };
            require(
                check.forward_pair_readback_sha256 == forward.sha256
                    && check.catalog_receipt_sha256 == pair.catalog_receipt_sha256
                    && check.control_receipt_sha256 == pair.control_receipt_sha256
                    && check.catalog_identity == pair.catalog_identity,
            )?;
            check
                .control_checkpoint
                .follows_checkpoint(&pair.control_checkpoint)?;
            let StageProgress::Published {
                inventory_sha256, ..
            } = &self.record.stage
            else {
                return Err(RecordError::Invalid);
            };
            let after = match &self.record.metadata.slots[4] {
                MetadataSlot::Applied { after, .. } => after,
                MetadataSlot::RestoreIntent { after, .. }
                | MetadataSlot::Restored { after, .. }
                    if self.record.rollback.is_some() =>
                {
                    after
                }
                _ => return Err(RecordError::Invalid),
            };
            require(
                check.final_package_inventory_sha256 == *inventory_sha256
                    && check.new_pointer_sha256 == after.sha256,
            )?;
        }
        if let Some(rollback) = &self.record.rollback
            && let Some(reference) = &rollback.rollback_pair_readback
        {
            let ProofPayload::Rollback(pair) = &find(reference)?.payload else {
                return Err(RecordError::Invalid);
            };
            require(
                rollback
                    .intent
                    .as_ref()
                    .is_some_and(|intent| pair.rollback_intent_sha256 == intent.sha256)
                    && pair.restore_pair == rollback.restore_pair,
            )?;
            if pair.restore_pair == RestorePair::NotNeeded {
                if let Some(before) = &self.record.quiesced {
                    require(
                        pair.catalog_identity == before.catalog
                            && pair.catalog.identity == before.catalog_file.identity
                            && pair.control.identity == before.control_file.identity,
                    )?;
                } else {
                    require(
                        pair.catalog_identity.generation
                            == admission.record.checkpoint.catalog_generation,
                    )?;
                }
            }
        }
        let expected = usize::from(self.record.forward_pair_readback.is_some())
            + usize::from(self.record.self_check.is_some())
            + usize::from(
                self.record
                    .rollback
                    .as_ref()
                    .is_some_and(|r| r.rollback_pair_readback.is_some()),
            );
        require(proofs.len() == expected)
    }

    /// Validate every retained referenced payload, including preimage manifests.
    /// Bytes establish relations only; the executor must retain actual native pins.
    pub fn validate_records(
        &self,
        proofs: &[ProofRecord],
        manifests: &[records::PreimageManifest],
        admission: &AdmissionV2,
    ) -> Result<()> {
        self.record.validate(admission)?;
        require(proofs.len() <= 12 && manifests.len() <= 2)?;
        let mut slots = BTreeSet::new();
        for proof in proofs {
            require(slots.insert(proof.slot as u8))?;
            proof.payload.validate(admission)?;
        }
        let mut used = BTreeSet::new();
        let readbacks: Vec<_> = proofs
            .iter()
            .filter(|proof| {
                matches!(
                    proof.slot,
                    RecordSlot::ForwardPairReadback
                        | RecordSlot::RollbackPairReadback
                        | RecordSlot::SelfCheck
                )
            })
            .collect();
        self.validate_readbacks(&readbacks, admission)?;
        for proof in &readbacks {
            used.insert(proof.slot as u8);
        }
        let mut coverage = None;
        for image in self.record.images().into_iter().flatten() {
            if let Some(reference) = &image.coverage_ref {
                let proof = find_record(proofs, reference, &mut used)?;
                let ProofPayload::Coverage(value) = &proof.payload else {
                    return Err(RecordError::Invalid);
                };
                if let Some(checkpoint) = &self.record.quiesced {
                    require(
                        reference.sha256 == checkpoint.coverage_sha256
                            && value.source_ids.len() as u64 == checkpoint.coverage_count,
                    )?;
                }
                coverage = Some(proof);
            }
        }
        let mut manifest_components = BTreeSet::new();
        for manifest in manifests {
            require(manifest_components.insert(manifest.component as u8))?;
            let image = match manifest.component {
                Component::Catalog => &self.record.preimages.catalog,
                Component::Control => &self.record.preimages.control,
            };
            manifest.validate_binding(
                image,
                coverage.ok_or(RecordError::Invalid)?,
                self.record.quiesced.as_ref(),
                admission,
            )?;
        }
        for (component, progress) in [
            (Component::Catalog, &self.record.catalog_component),
            (Component::Control, &self.record.control_component),
        ] {
            let Some(reference) = progress.intent() else {
                continue;
            };
            let proof = find_record(proofs, reference, &mut used)?;
            let ProofPayload::ComponentIntent(intent) = &proof.payload else {
                return Err(RecordError::Invalid);
            };
            require(intent.component == component && intent.intent_seq <= self.record.seq)?;
            intent
                .catalog_preimage
                .matches_image(&self.record.preimages.catalog)?;
            intent
                .control_preimage
                .matches_image(&self.record.preimages.control)?;
            for (role, preimage) in [
                (Component::Catalog, &intent.catalog_preimage),
                (Component::Control, &intent.control_preimage),
            ] {
                let manifest = manifests
                    .iter()
                    .find(|m| m.component == role)
                    .ok_or(RecordError::Invalid)?;
                manifest.matches_preimage(preimage)?;
            }
            let quiesced = self.record.quiesced.as_ref().ok_or(RecordError::Invalid)?;
            match &intent.before {
                records::ComponentSnapshot::Catalog(snapshot) => {
                    require(snapshot.identity == quiesced.catalog)?;
                }
                records::ComponentSnapshot::Control(snapshot) => {
                    snapshot.checkpoint.follows_checkpoint(&quiesced.control)?;
                    let catalog = self
                        .record
                        .catalog_component
                        .receipt()
                        .ok_or(RecordError::Invalid)?;
                    require(
                        intent.catalog_receipt_sha256.as_deref() == Some(catalog.sha256.as_str()),
                    )?;
                    let catalog_readback = find_record(
                        proofs,
                        self.record
                            .catalog_component
                            .readback()
                            .ok_or(RecordError::Invalid)?,
                        &mut used,
                    )?;
                    let ProofPayload::ComponentReadback(catalog_readback) =
                        &catalog_readback.payload
                    else {
                        return Err(RecordError::Invalid);
                    };
                    snapshot
                        .checkpoint
                        .follows_checkpoint(&catalog_readback.control_checkpoint)?;
                }
            }
            let readback = if let Some(reference) = progress.readback() {
                let readback_proof = find_record(proofs, reference, &mut used)?;
                let ProofPayload::ComponentReadback(readback) = &readback_proof.payload else {
                    return Err(RecordError::Invalid);
                };
                let catalog_intent_proof = find_record(
                    proofs,
                    self.record
                        .catalog_component
                        .intent()
                        .ok_or(RecordError::Invalid)?,
                    &mut used,
                )?;
                let ProofPayload::ComponentIntent(catalog_intent) = &catalog_intent_proof.payload
                else {
                    return Err(RecordError::Invalid);
                };
                let records::ComponentSnapshot::Catalog(catalog_snapshot) = &catalog_intent.before
                else {
                    return Err(RecordError::Invalid);
                };
                require(readback.pending_state.seq < self.record.seq)?;
                readback.matches_component(
                    intent,
                    proof.raw_bytes(),
                    progress,
                    if component == Component::Catalog {
                        progress.receipt()
                    } else {
                        self.record.catalog_component.receipt()
                    },
                    catalog_snapshot,
                    quiesced,
                )?;
                Some(readback.as_ref())
            } else {
                None
            };
            if let Some(receipt) = progress.receipt() {
                let receipt_proof = find_record(proofs, receipt, &mut used)?;
                let ProofPayload::ComponentReceipt(value) = &receipt_proof.payload else {
                    return Err(RecordError::Invalid);
                };
                value.matches_intent(intent, proof.raw_bytes())?;
                if component == Component::Control {
                    let live = &readback.ok_or(RecordError::Invalid)?.control_checkpoint;
                    let records::ComponentSnapshot::Control(before) = &intent.before else {
                        return Err(RecordError::Invalid);
                    };
                    let old = &quiesced.control;
                    let restorable =
                        before.checkpoint.same_restore_policy(old) && live.same_restore_policy(old);
                    let expected = if restorable {
                        Disposition::Restorable
                    } else {
                        Disposition::Quarantined
                    };
                    for image in [
                        &self.record.preimages.catalog,
                        &self.record.preimages.control,
                    ] {
                        if let ImageState::Adopted {
                            receipt_sha256,
                            disposition,
                            ..
                        } = &image.image
                        {
                            require(receipt_sha256 == &receipt.sha256 && *disposition == expected)?;
                        }
                    }
                }
                if let Some(reference) = &self.record.forward_pair_readback {
                    let forward = find_record(proofs, reference, &mut used)?;
                    let ProofPayload::Forward(pair) = &forward.payload else {
                        return Err(RecordError::Invalid);
                    };
                    match &intent.expected_after {
                        records::ComponentSnapshot::Catalog(after) => {
                            require(pair.catalog_identity == after.identity)?;
                        }
                        records::ComponentSnapshot::Control(after) => {
                            pair.control_checkpoint
                                .follows_checkpoint(&after.checkpoint)?;
                        }
                    }
                    pair.control_checkpoint.follows_checkpoint(
                        &readback.ok_or(RecordError::Invalid)?.control_checkpoint,
                    )?;
                }
                if let Some(reference) = &self.record.self_check {
                    let check = find_record(proofs, reference, &mut used)?;
                    let ProofPayload::SelfCheck(check) = &check.payload else {
                        return Err(RecordError::Invalid);
                    };
                    check.control_checkpoint.follows_checkpoint(
                        &readback.ok_or(RecordError::Invalid)?.control_checkpoint,
                    )?;
                }
            }
        }
        if let Some(rollback) = &self.record.rollback {
            let plan = if let Some(reference) = &rollback.plan {
                let proof = find_record(proofs, reference, &mut used)?;
                let ProofPayload::RollbackPlan(plan) = &proof.payload else {
                    return Err(RecordError::Invalid);
                };
                require(
                    rollback.restore_pair == RestorePair::Required
                        && rollback.recovery_incarnation.as_deref()
                            == Some(plan.recovery_incarnation.as_str())
                        && rollback.authority_checkpoint == plan.compatible_control_checkpoint,
                )?;
                Some((plan.as_ref(), proof.raw_bytes()))
            } else {
                None
            };
            let intent = if let Some(reference) = &rollback.intent {
                let proof = find_record(proofs, reference, &mut used)?;
                let ProofPayload::RollbackIntent(intent) = &proof.payload else {
                    return Err(RecordError::Invalid);
                };
                require(
                    intent.restore_pair == rollback.restore_pair
                        && intent.recovery_incarnation == rollback.recovery_incarnation
                        && intent.compatible_control_checkpoint == rollback.authority_checkpoint,
                )?;
                if let Some((plan, raw)) = plan {
                    intent.matches_plan(plan, raw)?;
                }
                Some(intent.as_ref())
            } else {
                None
            };
            if rollback.restore_pair == RestorePair::Required {
                let (plan, _) = plan.ok_or(RecordError::Invalid)?;
                let quiesced = self.record.quiesced.as_ref().ok_or(RecordError::Invalid)?;
                let catalog_receipt = self
                    .record
                    .catalog_component
                    .receipt()
                    .ok_or(RecordError::Invalid)?;
                let catalog_proof = find_record(proofs, catalog_receipt, &mut used)?;
                let ProofPayload::ComponentReceipt(catalog_receipt) = &catalog_proof.payload else {
                    return Err(RecordError::Invalid);
                };
                let live = &plan.live_pair_before;
                let mut expected_catalog = quiesced.catalog.clone();
                expected_catalog.schema = catalog_receipt.pair_after.catalog;
                let control_after = if let Some(reference) = self.record.control_component.receipt()
                {
                    let receipt_proof = find_record(proofs, reference, &mut used)?;
                    let ProofPayload::ComponentReceipt(receipt) = &receipt_proof.payload else {
                        return Err(RecordError::Invalid);
                    };
                    let intent_proof = find_record(
                        proofs,
                        self.record
                            .control_component
                            .intent()
                            .ok_or(RecordError::Invalid)?,
                        &mut used,
                    )?;
                    let ProofPayload::ComponentIntent(control_intent) = &intent_proof.payload
                    else {
                        return Err(RecordError::Invalid);
                    };
                    let records::ComponentSnapshot::Control(after) = &control_intent.expected_after
                    else {
                        return Err(RecordError::Invalid);
                    };
                    require(live.control_checkpoint.schema == receipt.pair_after.control)?;
                    &after.checkpoint
                } else {
                    require(live.control_checkpoint.schema == catalog_receipt.pair_after.control)?;
                    &quiesced.control
                };
                require(
                    live.catalog_identity == expected_catalog
                        && live.catalog.identity == quiesced.catalog_file.identity
                        && live.control.identity == quiesced.control_file.identity
                        && live.control_checkpoint.catalog_incarnation
                            == Some(expected_catalog.incarnation)
                        && live.control_checkpoint.control_seq >= control_after.control_seq
                        && live.control_checkpoint.policy_epoch >= control_after.policy_epoch
                        && live.control_checkpoint.next_cycle_seq >= control_after.next_cycle_seq,
                )?;
                for retained in proofs {
                    let checkpoint = match &retained.payload {
                        ProofPayload::ComponentReadback(readback) => {
                            Some(&readback.control_checkpoint)
                        }
                        ProofPayload::Forward(readback) => Some(&readback.control_checkpoint),
                        ProofPayload::SelfCheck(check) => Some(&check.control_checkpoint),
                        _ => None,
                    };
                    if let Some(checkpoint) = checkpoint {
                        live.control_checkpoint.follows_checkpoint(checkpoint)?;
                    }
                }
                require(
                    plan.compatible_control_checkpoint.authority_blake3
                        == quiesced.control.authority_blake3
                        && plan.compatible_control_checkpoint.desired_updates
                            == quiesced.control.desired_updates
                        && plan.compatible_control_checkpoint.restart_request_seq
                            == quiesced.control.restart_request_seq,
                )?;
                require(
                    plan.compatible_control_checkpoint.policy_epoch
                        == quiesced.control.policy_epoch
                        && plan.compatible_control_checkpoint.autostart_enabled
                            == quiesced.control.autostart_enabled,
                )?;
                plan.preimage_refs
                    .catalog
                    .as_ref()
                    .ok_or(RecordError::Invalid)?
                    .matches_image(&self.record.preimages.catalog)?;
                plan.preimage_refs
                    .control
                    .as_ref()
                    .ok_or(RecordError::Invalid)?
                    .matches_image(&self.record.preimages.control)?;
                for (component, descriptor) in [
                    (Component::Catalog, plan.preimage_refs.catalog.as_ref()),
                    (Component::Control, plan.preimage_refs.control.as_ref()),
                ] {
                    manifests
                        .iter()
                        .find(|m| m.component == component)
                        .ok_or(RecordError::Invalid)?
                        .matches_preimage(descriptor.ok_or(RecordError::Invalid)?)?;
                }
                if let Some(intent) = intent {
                    let prepared = intent
                        .prepared_pair_after
                        .as_ref()
                        .ok_or(RecordError::Invalid)?;
                    for (image, expected) in [
                        (&rollback.catalog_side, &prepared.catalog),
                        (&rollback.control_side, &prepared.control),
                        (
                            &rollback.catalog_displaced,
                            &intent.live_pair_before.catalog,
                        ),
                        (
                            &rollback.control_displaced,
                            &intent.live_pair_before.control,
                        ),
                    ] {
                        if let Some(stamp) = image.as_ref().and_then(|image| image.image.stamp()) {
                            require(stamp == expected)?;
                        }
                    }
                } else {
                    require(rollback.rollback_pair_readback.is_none())?;
                }
            } else {
                require(plan.is_none())?;
                let live = &intent.ok_or(RecordError::Invalid)?.live_pair_before;
                if let Some(quiesced) = &self.record.quiesced {
                    require(
                        live.catalog_identity == quiesced.catalog
                            && live.catalog.identity == quiesced.catalog_file.identity
                            && live.control.identity == quiesced.control_file.identity,
                    )?;
                    live.control_checkpoint
                        .follows_checkpoint(&quiesced.control)?;
                }
                if let Some(reference) = self.record.catalog_component.readback() {
                    let proof = find_record(proofs, reference, &mut used)?;
                    let ProofPayload::ComponentReadback(readback) = &proof.payload else {
                        return Err(RecordError::Invalid);
                    };
                    require(
                        live.catalog_identity == readback.catalog_identity
                            && live.catalog.identity == readback.catalog_file
                            && live.control.identity == readback.control_file,
                    )?;
                    live.control_checkpoint
                        .follows_checkpoint(&readback.control_checkpoint)?;
                }
            }
            if let Some(reference) = &rollback.rollback_pair_readback {
                let intent = intent.ok_or(RecordError::Invalid)?;
                let readback = find_record(proofs, reference, &mut used)?;
                let ProofPayload::Rollback(pair) = &readback.payload else {
                    return Err(RecordError::Invalid);
                };
                let expected = intent
                    .prepared_pair_after
                    .as_ref()
                    .unwrap_or(&intent.live_pair_before);
                require(
                    pair.catalog == expected.catalog
                        && pair.control == expected.control
                        && pair.catalog_identity == expected.catalog_identity
                        && pair.control_checkpoint == expected.control_checkpoint
                        && pair.owned_inventory_blake3 == intent.owned_inventory_blake3,
                )?;
            }
            for descriptor in intent
                .into_iter()
                .flat_map(|intent| {
                    [
                        intent.preimage_refs.catalog.as_ref(),
                        intent.preimage_refs.control.as_ref(),
                    ]
                })
                .flatten()
            {
                let component = if descriptor.kind == records::PreimageKind::CatalogBackup {
                    Component::Catalog
                } else {
                    Component::Control
                };
                manifests
                    .iter()
                    .find(|manifest| manifest.component == component)
                    .ok_or(RecordError::Invalid)?
                    .matches_preimage(descriptor)?;
            }
        }
        for (component, image) in [
            (Component::Catalog, &self.record.preimages.catalog),
            (Component::Control, &self.record.preimages.control),
        ] {
            if image.image.stamp().is_some()
                || matches!(image.manifest, ManifestState::Complete { .. })
            {
                require(manifest_components.contains(&(component as u8)))?;
            }
        }
        require(used.len() == proofs.len())
    }

    fn effect_projection(
        &self,
        effect: &PendingEffect,
        proofs: &[ProofRecord],
    ) -> Result<Option<Vec<u8>>> {
        fn encoded<T: Serialize>(value: &T) -> Result<Option<Vec<u8>>> {
            Ok(Some(super::encode(value)?))
        }
        let raw = |reference: &RecordRef| -> Result<Option<Vec<u8>>> {
            let proof = proofs
                .iter()
                .find(|proof| reference.matches(proof))
                .ok_or(RecordError::Invalid)?;
            Ok(Some(proof.raw_bytes().to_vec()))
        };
        match effect.kind {
            EffectKind::StageExtract | EffectKind::StagePublish => encoded(&self.record.stage),
            EffectKind::FenceSet => match &self.record.quiesced {
                Some(checkpoint) => encoded(&checkpoint.control),
                None => Ok(None),
            },
            EffectKind::FenceClear => {
                let reference = self
                    .record
                    .self_check
                    .as_ref()
                    .ok_or(RecordError::Invalid)?;
                let proof = proofs
                    .iter()
                    .find(|proof| reference.matches(proof))
                    .ok_or(RecordError::Invalid)?;
                let ProofPayload::SelfCheck(check) = &proof.payload else {
                    return Err(RecordError::Invalid);
                };
                encoded(&check.control_checkpoint)
            }
            EffectKind::PreimageCreate | EffectKind::OwnedDelete => {
                if let Some(index) = IMAGE_KEYS.iter().position(|key| *key == effect.slot) {
                    let image = self.record.images()[index].ok_or(RecordError::Invalid)?;
                    encoded(image)
                } else {
                    let rollback = self.record.rollback.as_ref().ok_or(RecordError::Invalid)?;
                    let record = if effect.slot == "catalog_restore_journal" {
                        rollback.catalog_restore_journal.as_ref()
                    } else {
                        rollback.control_restore_journal.as_ref()
                    };
                    encoded(record.ok_or(RecordError::Invalid)?)
                }
            }
            EffectKind::RollbackBindParent
            | EffectKind::RollbackCreateEmpty
            | EffectKind::RollbackWriteContent => {
                let slot =
                    records::PreparationSlot::parse(&effect.slot).ok_or(RecordError::Invalid)?;
                match slot.target() {
                    Change::Image(index) => {
                        encoded(self.record.images()[index].ok_or(RecordError::Invalid)?)
                    }
                    Change::Journal(index) => {
                        let r = self.record.rollback.as_ref().ok_or(RecordError::Invalid)?;
                        encoded(
                            if index == 0 {
                                r.catalog_restore_journal.as_ref()
                            } else {
                                r.control_restore_journal.as_ref()
                            }
                            .ok_or(RecordError::Invalid)?,
                        )
                    }
                    _ => Err(RecordError::Invalid),
                }
            }
            EffectKind::ComponentCommit => {
                let progress = if effect.slot == "catalog" {
                    &self.record.catalog_component
                } else {
                    &self.record.control_component
                };
                raw(progress.intent().ok_or(RecordError::Invalid)?)
            }
            EffectKind::MetadataPublish | EffectKind::MetadataRestore => {
                let index = METADATA_KEYS
                    .iter()
                    .position(|key| *key == effect.slot)
                    .ok_or(RecordError::Invalid)?;
                encoded(&self.record.metadata.slots[index])
            }
            EffectKind::PairRestore => raw(self
                .record
                .rollback
                .as_ref()
                .ok_or(RecordError::Invalid)?
                .intent
                .as_ref()
                .ok_or(RecordError::Invalid)?),
        }
    }

    fn bind_pending_effect(
        &self,
        previous: &Self,
        evidence: &SuccessorEvidence<'_>,
        admission: &AdmissionV2,
    ) -> Result<()> {
        let effect = previous
            .record
            .pending
            .as_ref()
            .or(self.record.pending.as_ref());
        let Some(effect) = effect else {
            return require(evidence.effect_readback.is_none());
        };
        if self.record.pending.is_some() {
            require(evidence.effect_readback.is_none())?;
        }
        if matches!(
            effect.kind,
            EffectKind::RollbackBindParent
                | EffectKind::RollbackCreateEmpty
                | EffectKind::RollbackWriteContent
        ) {
            let plan_ref = previous
                .record
                .rollback
                .as_ref()
                .and_then(|r| r.plan.as_ref())
                .ok_or(RecordError::Invalid)?;
            let proof = evidence
                .previous
                .proofs
                .iter()
                .find(|p| plan_ref.matches(p))
                .ok_or(RecordError::Invalid)?;
            let ProofPayload::RollbackPlan(plan) = &proof.payload else {
                return Err(RecordError::Invalid);
            };
            let projection = records::preparation_projection(
                previous,
                effect,
                plan,
                proof.raw_bytes(),
                admission,
            )?;
            require(
                effect.expected_after.size_bytes == projection.len() as u64
                    && effect.expected_after.sha256 == sha256(&projection),
            )?;
            let owner = previous
                .effect_projection(effect, evidence.previous.proofs)?
                .ok_or(RecordError::Invalid)?;
            require(
                effect.expected_before
                    == BeforeRecord::RecordDigest {
                        size_bytes: owner.len() as u64,
                        sha256: sha256(&owner),
                    },
            )?;
            if previous.record.pending.is_some() && self.record.pending.is_none() {
                return records::validate_preparation_readback(
                    previous,
                    self,
                    effect,
                    &projection,
                    evidence.effect_readback.ok_or(RecordError::Invalid)?,
                    admission,
                );
            }
            return Ok(());
        }
        if effect.kind == EffectKind::ComponentCommit
            && previous.record.pending.is_some()
            && self.record.pending.is_none()
        {
            let projection = previous
                .effect_projection(effect, evidence.previous.proofs)?
                .ok_or(RecordError::Invalid)?;
            require(
                effect.expected_before
                    == BeforeRecord::RecordDigest {
                        size_bytes: projection.len() as u64,
                        sha256: sha256(&projection),
                    }
                    && effect.expected_after.size_bytes == projection.len() as u64
                    && effect.expected_after.sha256 == sha256(&projection),
            )?;
            let component = if effect.slot == "catalog" {
                Component::Catalog
            } else {
                Component::Control
            };
            let progress = if component == Component::Catalog {
                &self.record.catalog_component
            } else {
                &self.record.control_component
            };
            let reference = progress.readback().ok_or(RecordError::Invalid)?;
            let proof = evidence
                .current
                .proofs
                .iter()
                .find(|p| reference.matches(p))
                .ok_or(RecordError::Invalid)?;
            let ProofPayload::ComponentReadback(readback) = &proof.payload else {
                return Err(RecordError::Invalid);
            };
            readback.pending_state.matches(previous)?;
            return require(
                readback.component == component
                    && evidence.effect_readback == Some(proof.raw_bytes()),
            );
        }
        if previous.record.pending.is_none() {
            let raw = previous.effect_projection(effect, evidence.previous.proofs)?;
            let expected = match raw {
                Some(raw) => BeforeRecord::RecordDigest {
                    size_bytes: raw.len() as u64,
                    sha256: sha256(&raw),
                },
                None => BeforeRecord::Absent,
            };
            require(effect.expected_before == expected)?;
            if matches!(
                effect.kind,
                EffectKind::ComponentCommit | EffectKind::PairRestore
            ) {
                let raw = self
                    .effect_projection(effect, evidence.current.proofs)?
                    .ok_or(RecordError::Invalid)?;
                require(
                    effect.expected_after.size_bytes == raw.len() as u64
                        && effect.expected_after.sha256 == sha256(&raw),
                )?;
            }
        } else if self.record.pending.is_none() {
            let raw = self
                .effect_projection(effect, evidence.current.proofs)?
                .ok_or(RecordError::Invalid)?;
            let observed = evidence.effect_readback.ok_or(RecordError::Invalid)?;
            require(
                effect.expected_after.size_bytes == observed.len() as u64
                    && effect.expected_after.sha256 == sha256(observed),
            )?;
            if effect.kind == EffectKind::FenceClear {
                let current: ControlCheckpoint = canonical(observed)?;
                current.validate(admission, 3)?;
                let before: ControlCheckpoint = canonical(&raw)?;
                require(current.maintenance.state == FenceState::Idle)?;
                current.follows_checkpoint(&before)?;
            } else {
                require(observed == raw)?;
            }
        }
        Ok(())
    }

    /// Full pure admission for one successor and its retained record set.
    pub fn validate_successor(
        &self,
        previous: &Self,
        evidence: SuccessorEvidence<'_>,
        admission: &AdmissionV2,
    ) -> Result<()> {
        self.validate_chain(previous, admission)?;
        previous.validate_records(
            evidence.previous.proofs,
            evidence.previous.manifests,
            admission,
        )?;
        self.validate_records(
            evidence.current.proofs,
            evidence.current.manifests,
            admission,
        )?;
        for (component, before, after) in [
            (
                Component::Catalog,
                &previous.record.catalog_component,
                &self.record.catalog_component,
            ),
            (
                Component::Control,
                &previous.record.control_component,
                &self.record.control_component,
            ),
        ] {
            if before.intent().is_none()
                && let Some(reference) = after.intent()
            {
                let proof = evidence
                    .current
                    .proofs
                    .iter()
                    .find(|proof| reference.matches(proof))
                    .ok_or(RecordError::Invalid)?;
                let ProofPayload::ComponentIntent(intent) = &proof.payload else {
                    return Err(RecordError::Invalid);
                };
                require(intent.component == component && intent.intent_seq == self.record.seq)?;
            }
        }
        for old in evidence.previous.proofs {
            require(
                evidence
                    .current
                    .proofs
                    .iter()
                    .any(|new| new.slot == old.slot && new.raw == old.raw),
            )?;
        }
        for old in evidence.previous.manifests {
            require(
                evidence.current.manifests.iter().any(|new| {
                    new.component == old.component && new.raw_bytes() == old.raw_bytes()
                }),
            )?;
        }
        if previous
            .record
            .rollback
            .as_ref()
            .and_then(|r| r.intent.as_ref())
            .is_none()
            && let Some(rollback) = &self.record.rollback
            && rollback.restore_pair == RestorePair::Required
            && let Some(reference) = &rollback.intent
        {
            let proof = evidence
                .current
                .proofs
                .iter()
                .find(|p| reference.matches(p))
                .ok_or(RecordError::Invalid)?;
            let ProofPayload::RollbackIntent(intent) = &proof.payload else {
                return Err(RecordError::Invalid);
            };
            let prepared = intent
                .prepared_pair_after
                .as_ref()
                .ok_or(RecordError::Invalid)?;
            require(
                rollback.preparation_complete()
                    && rollback.catalog_side.as_ref().and_then(|i| i.image.stamp())
                        == Some(&prepared.catalog)
                    && rollback.control_side.as_ref().and_then(|i| i.image.stamp())
                        == Some(&prepared.control),
            )?;
        }
        self.bind_pending_effect(previous, &evidence, admission)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RowCounts {
    grants: u64,
    receipts: u64,
    heads: u64,
    proofs: u64,
}

impl RowCounts {
    fn empty(&self) -> bool {
        [self.grants, self.receipts, self.heads, self.proofs] == [0; 4]
    }
}

// Fields are intentionally repeated rather than flattened: deny_unknown_fields
// must apply to every complete on-disk object, with fixed canonical field order.
macro_rules! proof_record {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $name {
            schema: String,
            mode: TransitionMode,
            update_id: String,
            owner_nonce: String,
            admission_sha256: String,
            $($field: $ty,)*
        }
        impl $name {
            fn context(&self, admission: &AdmissionV2, schema: &str) -> Result<()> {
                require(self.schema == schema && self.mode == admission.record.mode
                    && self.update_id == admission.record.update_id
                    && self.owner_nonce == admission.record.owner_nonce
                    && self.admission_sha256 == sha256(admission.raw_bytes()))
            }
        }
    };
}

proof_record!(ForwardReadback {
    catalog_receipt_sha256: String,
    control_receipt_sha256: String,
    catalog: FileStamp,
    control: FileStamp,
    catalog_identity: CatalogIdentity,
    control_checkpoint: ControlCheckpoint,
    repository_row_counts: RowCounts,
    owned_inventory_blake3: String
});
proof_record!(RollbackReadback {
    rollback_intent_sha256: String,
    restore_pair: RestorePair,
    catalog: FileStamp,
    control: FileStamp,
    catalog_identity: CatalogIdentity,
    control_checkpoint: ControlCheckpoint,
    owned_inventory_blake3: String
});
proof_record!(SelfCheckPayload {
    forward_pair_readback_sha256: String,
    catalog_receipt_sha256: String,
    control_receipt_sha256: String,
    final_package_inventory_sha256: String,
    new_pointer_sha256: String,
    catalog_identity: CatalogIdentity,
    control_checkpoint: ControlCheckpoint,
    result: CheckResult
});

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CheckResult {
    Passed,
}

#[derive(Debug)]
enum ProofPayload {
    Forward(ForwardReadback),
    Rollback(RollbackReadback),
    SelfCheck(SelfCheckPayload),
    ComponentIntent(Box<ComponentIntent>),
    ComponentReceipt(Box<ComponentReceipt>),
    ComponentReadback(Box<ComponentReadback>),
    RollbackIntent(Box<RollbackIntent>),
    RollbackPlan(Box<RollbackPlan>),
    Coverage(Coverage),
}

impl ProofPayload {
    fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        admission.record.validate()?;
        let (catalog, control) = match self {
            Self::ComponentIntent(record) => return record.validate(admission),
            Self::ComponentReceipt(record) => return record.validate(admission),
            Self::ComponentReadback(record) => return record.validate(admission),
            Self::RollbackIntent(record) => return record.validate(admission),
            Self::RollbackPlan(record) => return record.validate(admission),
            Self::Coverage(record) => return record.validate(admission),
            Self::Forward(record) => {
                record.context(admission, "asg.schema-transition-forward-pair-readback/v1")?;
                record.catalog.validate()?;
                record.control.validate()?;
                record.catalog_identity.validate(admission, 23)?;
                record.control_checkpoint.validate(admission, 3)?;
                digest(&record.catalog_receipt_sha256)?;
                digest(&record.control_receipt_sha256)?;
                digest(&record.owned_inventory_blake3)?;
                let counts = &record.repository_row_counts;
                require([counts.grants, counts.receipts, counts.heads, counts.proofs] == [0; 4])?;
                (&record.catalog_identity, &record.control_checkpoint)
            }
            Self::Rollback(record) => {
                record.context(admission, "asg.schema-transition-rollback-pair-readback/v1")?;
                record.catalog.validate()?;
                record.control.validate()?;
                record.catalog_identity.validate(admission, 22)?;
                record.control_checkpoint.validate(admission, 2)?;
                digest(&record.rollback_intent_sha256)?;
                digest(&record.owned_inventory_blake3)?;
                let expected = match record.restore_pair {
                    RestorePair::Required => format!(
                        "transition_recovery_{}",
                        &admission.record.update_id["update_".len()..]
                    ),
                    RestorePair::NotNeeded => {
                        admission.record.checkpoint.catalog_incarnation.clone()
                    }
                };
                require(record.catalog_identity.incarnation == expected)?;
                (&record.catalog_identity, &record.control_checkpoint)
            }
            Self::SelfCheck(record) => {
                record.context(admission, "asg.schema-transition-self-check/v1")?;
                record.catalog_identity.validate(admission, 23)?;
                record.control_checkpoint.validate(admission, 3)?;
                for hash in [
                    &record.forward_pair_readback_sha256,
                    &record.catalog_receipt_sha256,
                    &record.control_receipt_sha256,
                    &record.final_package_inventory_sha256,
                    &record.new_pointer_sha256,
                ] {
                    digest(hash)?;
                }
                (&record.catalog_identity, &record.control_checkpoint)
            }
        };
        require(
            control.catalog_incarnation.as_deref() == Some(catalog.incarnation.as_str())
                && control.control_seq >= admission.record.checkpoint.control_seq
                && control.policy_epoch >= admission.record.checkpoint.policy_epoch
                && catalog.generation >= admission.record.checkpoint.catalog_generation,
        )
    }
}

/// Canonical forward/rollback/SelfCheck bytes. Unsupported slots are refused;
/// component, coverage and finalizer publication belong to later gated slices.
#[derive(Debug)]
pub struct ProofRecord {
    slot: RecordSlot,
    payload: ProofPayload,
    raw: Vec<u8>,
}

fn canonical<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    require(!bytes.is_empty())?;
    if bytes.len() > PROOF_LIMIT {
        return Err(RecordError::TooLarge);
    }
    let record: T = super::decode(bytes)?;
    require(super::encode(&record)? == bytes)?;
    Ok(record)
}

impl ProofRecord {
    pub fn decode(slot: RecordSlot, bytes: &[u8], admission: &AdmissionV2) -> Result<Self> {
        let payload = match slot {
            RecordSlot::ForwardPairReadback => ProofPayload::Forward(canonical(bytes)?),
            RecordSlot::RollbackPairReadback => ProofPayload::Rollback(canonical(bytes)?),
            RecordSlot::SelfCheck => ProofPayload::SelfCheck(canonical(bytes)?),
            RecordSlot::CatalogIntent | RecordSlot::ControlIntent => {
                let record: ComponentIntent = canonical(bytes)?;
                require(slot == record.component.intent_slot())?;
                ProofPayload::ComponentIntent(Box::new(record))
            }
            RecordSlot::CatalogReceipt | RecordSlot::ControlReceipt => {
                let record: ComponentReceipt = canonical(bytes)?;
                require(slot == record.component.receipt_slot())?;
                ProofPayload::ComponentReceipt(Box::new(record))
            }
            RecordSlot::RollbackIntent => ProofPayload::RollbackIntent(Box::new(canonical(bytes)?)),
            RecordSlot::RollbackPlan => ProofPayload::RollbackPlan(Box::new(canonical(bytes)?)),
            RecordSlot::CatalogCommitReadback | RecordSlot::ControlCommitReadback => {
                let record: ComponentReadback = canonical(bytes)?;
                require(record.component.readback_slot() == slot)?;
                ProofPayload::ComponentReadback(Box::new(record))
            }
            RecordSlot::Coverage => ProofPayload::Coverage(records::canonical_list_record(bytes)?),
        };
        payload.validate(admission)?;
        Ok(Self {
            slot,
            payload,
            raw: bytes.to_vec(),
        })
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn reference_bytes(&self) -> Result<Vec<u8>> {
        super::encode(&RecordRef {
            slot: self.slot,
            size_bytes: self.raw.len() as u64,
            sha256: sha256(&self.raw),
        })
    }
}

#[cfg(test)]
#[path = "update_schema_transition_state_tests.rs"]
mod tests;
