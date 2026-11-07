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
    ForwardPairReadback,
    RollbackPairReadback,
    SelfCheck,
    RollbackIntent,
    Finalizer,
}

impl RecordSlot {
    /// Fixed basename only. Finalizer is rooted at C; the other records are
    /// rooted at the admitted U. This method supplies no filesystem authority.
    pub fn filename(self) -> &'static str {
        match self {
            Self::Coverage => "coverage.json",
            Self::CatalogIntent => "catalog-intent.json",
            Self::ControlIntent => "control-intent.json",
            Self::CatalogReceipt => "catalog-receipt.json",
            Self::ControlReceipt => "control-receipt.json",
            Self::ForwardPairReadback => "forward-pair-readback.json",
            Self::RollbackPairReadback => "rollback-pair-readback.json",
            Self::SelfCheck => "self-check.json",
            Self::RollbackIntent => "rollback-intent.json",
            Self::Finalizer => "schema-transition-finalize.json",
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
    },
}

impl ComponentProgress {
    fn validate(&self, catalog: bool) -> Result<()> {
        let (intent_slot, receipt_slot) = if catalog {
            (RecordSlot::CatalogIntent, RecordSlot::CatalogReceipt)
        } else {
            (RecordSlot::ControlIntent, RecordSlot::ControlReceipt)
        };
        match self {
            Self::Unstarted => Ok(()),
            Self::Intent { record } => record.validate(intent_slot),
            Self::Committed { intent, receipt } => {
                intent.validate(intent_slot)?;
                receipt.validate(receipt_slot)
            }
        }
    }

    fn receipt(&self) -> Option<&RecordRef> {
        match self {
            Self::Committed { receipt, .. } => Some(receipt),
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
    FinalizingOldLayout,
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
    #[serde(deserialize_with = "closed_unit")]
    FinalizingOldLayout,
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
            Self::FinalizingOldLayout => PlainPhase::FinalizingOldLayout,
            Self::Attention { resume, .. } => *resume,
        }
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
    intent: RecordRef,
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
    fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        self.intent.validate(RecordSlot::RollbackIntent)?;
        self.authority_checkpoint
            .validate(admission, self.authority_checkpoint.schema)?;
        require(matches!(self.authority_checkpoint.schema, 2 | 3))?;
        if let Some(record) = &self.rollback_pair_readback {
            record.validate(RecordSlot::RollbackPairReadback)?;
        }
        if let Some(record) = &self.finalizer {
            record.validate(RecordSlot::Finalizer)?;
        }
        let images = [
            (&self.catalog_side, ImageRole::CatalogSide),
            (&self.control_side, ImageRole::ControlSide),
            (&self.catalog_displaced, ImageRole::CatalogDisplaced),
            (&self.control_displaced, ImageRole::ControlDisplaced),
        ];
        if self.restore_pair == RestorePair::NotNeeded {
            require(
                self.recovery_incarnation.is_none()
                    && self.authority_checkpoint.schema == 2
                    && images.iter().all(|(slot, _)| slot.is_none())
                    && self.catalog_restore_journal.is_none()
                    && self.control_restore_journal.is_none(),
            )?;
            return Ok(());
        }
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
    ComponentCommit,
    MetadataPublish,
    MetadataRestore,
    PairRestore,
    OwnedDelete,
    FenceClear,
    OldLayoutFinalize,
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
            EffectKind::OldLayoutFinalize => self.slot == "finalizer",
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
            if rollback.restore_pair == RestorePair::NotNeeded {
                require(
                    self.catalog_component.receipt().is_none()
                        && self.control_component.receipt().is_none(),
                )?;
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
                    | PlainPhase::FinalizingOldLayout
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

/// A decoded state is a bounded record, never a publication/executor capability.
#[derive(Debug)]
pub struct StateV2 {
    record: StateRecord,
    raw: Vec<u8>,
}

impl StateV2 {
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

    /// The chain/open-intent guard is necessary but not a full successor or
    /// publication admission. Native effect and substep dispatch remain gated.
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
        Ok(())
    }

    /// Check actual supplied proof bytes against the state references. This
    /// checks the acyclic readback/SelfCheck chain, not live component commits.
    pub fn validate_proofs(&self, proofs: &[ProofRecord], admission: &AdmissionV2) -> Result<()> {
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
                    && pair.control.identity == before.control_file.identity
                    && pair.control_checkpoint.control_seq >= before.control.control_seq
                    && pair.control_checkpoint.policy_epoch >= before.control.policy_epoch,
            )?;
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
                    && check.catalog_identity == pair.catalog_identity
                    && check.control_checkpoint.control_seq >= pair.control_checkpoint.control_seq
                    && check.control_checkpoint.policy_epoch
                        >= pair.control_checkpoint.policy_epoch,
            )?;
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
                pair.rollback_intent_sha256 == rollback.intent.sha256
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
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RowCounts {
    grants: u64,
    receipts: u64,
    heads: u64,
    proofs: u64,
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
}

impl ProofPayload {
    fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        admission.record.validate()?;
        let (catalog, control) = match self {
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
            _ => return Err(RecordError::Invalid),
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
