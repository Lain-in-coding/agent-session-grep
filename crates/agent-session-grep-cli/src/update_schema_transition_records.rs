//! Bounded transition payloads. These compare records, not live capabilities.

use super::*;
use crate::update_state::VersionIdentity;

pub(super) const MANIFEST_LIMIT: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Catalog,
    Control,
}

impl Component {
    pub(super) fn intent_slot(self) -> RecordSlot {
        match self {
            Self::Catalog => RecordSlot::CatalogIntent,
            Self::Control => RecordSlot::ControlIntent,
        }
    }

    pub(super) fn receipt_slot(self) -> RecordSlot {
        match self {
            Self::Catalog => RecordSlot::CatalogReceipt,
            Self::Control => RecordSlot::ControlReceipt,
        }
    }

    pub(super) fn readback_slot(self) -> RecordSlot {
        match self {
            Self::Catalog => RecordSlot::CatalogCommitReadback,
            Self::Control => RecordSlot::ControlCommitReadback,
        }
    }
}

macro_rules! payload {
    ($name:ident { $($(#[$attr:meta])* $field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields)]
        pub(super) struct $name {
            pub(super) schema: String,
            pub(super) mode: TransitionMode,
            pub(super) update_id: String,
            pub(super) owner_nonce: String,
            pub(super) admission_sha256: String,
            $($(#[$attr])* pub(super) $field: $ty,)*
        }
        impl $name {
            fn context(&self, admission: &AdmissionV2, schema: &str) -> Result<()> {
                require(self.schema == schema
                    && self.mode == admission.record.mode
                    && self.update_id == admission.record.update_id
                    && self.owner_nonce == admission.record.owner_nonce
                    && self.admission_sha256 == sha256(admission.raw_bytes()))
            }
        }
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SchemaPair {
    pub(super) catalog: u32,
    pub(super) control: u32,
}

impl SchemaPair {
    fn before(component: Component) -> Self {
        Self {
            catalog: if component == Component::Catalog {
                22
            } else {
                23
            },
            control: 2,
        }
    }

    fn after(component: Component) -> Self {
        Self {
            catalog: 23,
            control: if component == Component::Catalog {
                2
            } else {
                3
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreimageKind {
    CatalogBackup,
    SchemaTransitionControlPreimage,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreimageRef {
    pub(super) id: String,
    pub(super) kind: PreimageKind,
    pub(super) relative_locator: String,
    pub(super) manifest_sha256: String,
    pub(super) db_blake3: String,
    pub(super) size_bytes: u64,
    pub(super) coverage_sha256: String,
}

impl PreimageRef {
    pub(super) fn validate(&self, component: Component, admission: &AdmissionV2) -> Result<()> {
        let suffix = &admission.record.update_id["update_".len()..];
        let (kind, id, file) = match component {
            Component::Catalog => (
                PreimageKind::CatalogBackup,
                format!("transition_catalog_{suffix}"),
                "catalog.db",
            ),
            Component::Control => (
                PreimageKind::SchemaTransitionControlPreimage,
                format!("transition_control_{suffix}"),
                "control.db",
            ),
        };
        require(self.kind == kind && self.id == id)?;
        require(self.relative_locator == format!("backups/{id}/{file}"))?;
        require((1..=MAX_COUNTER).contains(&self.size_bytes))?;
        digest(&self.manifest_sha256)?;
        digest(&self.db_blake3)?;
        digest(&self.coverage_sha256)
    }

    pub(super) fn matches_image(&self, image: &ImageSlot) -> Result<()> {
        require(self.id == image.artifact_id && self.relative_locator == image.relative_locator)?;
        require(
            image
                .coverage_ref
                .as_ref()
                .is_some_and(|r| r.sha256 == self.coverage_sha256),
        )?;
        if let Some(stamp) = image.image.stamp() {
            require(stamp.blake3 == self.db_blake3 && stamp.size_bytes == self.size_bytes)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogSnapshot {
    pub(super) identity: CatalogIdentity,
    pub(super) active_generation: u64,
    pub(super) destructive_epoch: u64,
    pub(super) preserved_rows_blake3: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlSnapshot {
    pub(super) checkpoint: ControlCheckpoint,
    #[serde(deserialize_with = "nullable")]
    pub(super) adoption_sha256: Option<String>,
}

// The containing component selects the exact closed shape. There is no second
// wire tag and no fallback between catalog and control snapshots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum ComponentSnapshot {
    Catalog(Box<CatalogSnapshot>),
    Control(Box<ControlSnapshot>),
}

impl ComponentSnapshot {
    fn validate(&self, component: Component, after: bool, admission: &AdmissionV2) -> Result<()> {
        match (component, self) {
            (Component::Catalog, Self::Catalog(snapshot)) => {
                snapshot
                    .identity
                    .validate(admission, if after { 23 } else { 22 })?;
                require(
                    snapshot.active_generation == snapshot.identity.generation
                        && snapshot.destructive_epoch == snapshot.identity.destructive_epoch,
                )?;
                digest(&snapshot.preserved_rows_blake3)
            }
            (Component::Control, Self::Control(snapshot)) => {
                snapshot
                    .checkpoint
                    .validate(admission, if after { 3 } else { 2 })?;
                if after {
                    digest(
                        snapshot
                            .adoption_sha256
                            .as_deref()
                            .ok_or(RecordError::Invalid)?,
                    )
                } else {
                    require(snapshot.adoption_sha256.is_none())
                }
            }
            _ => Err(RecordError::Invalid),
        }
    }

    pub(super) fn commitment(&self) -> Result<String> {
        let mut hash = blake3::Hasher::new();
        self.write_commitment(|bytes| {
            hash.update(bytes);
        })?;
        Ok(hash.finalize().to_hex().to_string())
    }

    pub(super) fn write_commitment(&self, mut write: impl FnMut(&[u8])) -> Result<()> {
        write(match self {
            Self::Catalog(_) => b"asg.transition.catalog-component-snapshot/v1\0",
            Self::Control(_) => b"asg.transition.control-component-snapshot/v1\0",
        });
        write(&0_u16.to_le_bytes());
        write(&1_u64.to_le_bytes());
        match self {
            Self::Catalog(value) => {
                text(&mut write, &value.identity.installation_id)?;
                text(&mut write, &value.identity.incarnation)?;
                integer(&mut write, u64::from(value.identity.schema))?;
                integer(&mut write, value.active_generation)?;
                integer(&mut write, value.destructive_epoch)?;
                text(&mut write, &value.preserved_rows_blake3)?;
            }
            Self::Control(value) => {
                let checkpoint = &value.checkpoint;
                text(&mut write, &checkpoint.installation_id)?;
                integer(&mut write, u64::from(checkpoint.schema))?;
                integer(&mut write, checkpoint.control_seq)?;
                integer(&mut write, checkpoint.policy_epoch)?;
                integer(&mut write, checkpoint.next_cycle_seq)?;
                nullable_text(&mut write, checkpoint.catalog_incarnation.as_deref())?;
                integer(&mut write, checkpoint.restart_request_seq)?;
                text(
                    &mut write,
                    match checkpoint.desired_updates {
                        Desired::Running => "running",
                        Desired::Paused => "paused",
                        Desired::Stopped => "stopped",
                    },
                )?;
                integer(&mut write, u64::from(checkpoint.autostart_enabled))?;
                integer(&mut write, u64::from(checkpoint.supervisor_failed))?;
                text(
                    &mut write,
                    match checkpoint.maintenance.state {
                        FenceState::Idle => "idle",
                        FenceState::Updating => "updating",
                        FenceState::Recovering => "recovering",
                        FenceState::Uninstalling => "uninstalling",
                    },
                )?;
                nullable_text(&mut write, checkpoint.maintenance.owner.as_deref())?;
                nullable_text(&mut write, checkpoint.maintenance.phase.as_deref())?;
                text(&mut write, &checkpoint.authority_blake3)?;
                text(&mut write, &checkpoint.inventory_blake3)?;
                text(&mut write, &checkpoint.runtime_blake3)?;
                nullable_text(&mut write, value.adoption_sha256.as_deref())?;
            }
        }
        Ok(())
    }
}

fn integer(write: &mut impl FnMut(&[u8]), value: u64) -> Result<()> {
    let value = i64::try_from(value).map_err(|_| RecordError::Invalid)?;
    write(&[1]);
    write(&value.to_le_bytes());
    Ok(())
}

pub(super) fn text(write: &mut impl FnMut(&[u8]), value: &str) -> Result<()> {
    let size = u32::try_from(value.len()).map_err(|_| RecordError::TooLarge)?;
    write(&[2]);
    write(&size.to_le_bytes());
    write(value.as_bytes());
    Ok(())
}

fn nullable_text(write: &mut impl FnMut(&[u8]), value: Option<&str>) -> Result<()> {
    if let Some(value) = value {
        text(write, value)
    } else {
        write(&[0]);
        Ok(())
    }
}

payload!(ComponentIntent {
    component: Component,
    intent_seq: u64,
    pair_before: SchemaPair,
    pair_after: SchemaPair,
    installation_id: String,
    prefix_binding: String,
    control_binding: String,
    before: ComponentSnapshot,
    expected_after: ComponentSnapshot,
    catalog_preimage: PreimageRef,
    control_preimage: PreimageRef,
    #[serde(deserialize_with = "nullable")]
    catalog_receipt_sha256: Option<String>,
    #[serde(deserialize_with = "nullable")]
    adoption_sha256: Option<String>,
});

impl ComponentIntent {
    pub(super) fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        self.context(admission, "asg.schema-transition-component-intent/v1")?;
        component_context(
            self.component,
            (&self.pair_before, &self.pair_after),
            (
                &self.installation_id,
                &self.prefix_binding,
                &self.control_binding,
            ),
            (&self.catalog_receipt_sha256, &self.adoption_sha256),
            admission,
        )?;
        require((1..=10000).contains(&self.intent_seq))?;
        self.catalog_preimage
            .validate(Component::Catalog, admission)?;
        self.control_preimage
            .validate(Component::Control, admission)?;
        require(self.catalog_preimage.coverage_sha256 == self.control_preimage.coverage_sha256)?;
        self.before.validate(self.component, false, admission)?;
        self.expected_after
            .validate(self.component, true, admission)?;
        match (&self.before, &self.expected_after) {
            (ComponentSnapshot::Catalog(before), ComponentSnapshot::Catalog(after)) => {
                let mut expected = before.clone();
                expected.identity.schema = 23;
                require(after == &expected)
            }
            (ComponentSnapshot::Control(before), ComponentSnapshot::Control(after)) => {
                let old = &before.checkpoint;
                let new = &after.checkpoint;
                require(
                    old.control_seq.checked_add(1) == Some(new.control_seq)
                        && old.installation_id == new.installation_id
                        && old.policy_epoch == new.policy_epoch
                        && old.next_cycle_seq == new.next_cycle_seq
                        && old.catalog_incarnation == new.catalog_incarnation
                        && old.restart_request_seq == new.restart_request_seq
                        && old.desired_updates == new.desired_updates
                        && old.autostart_enabled == new.autostart_enabled
                        && old.supervisor_failed == new.supervisor_failed
                        && old.maintenance == new.maintenance
                        && old.authority_blake3 == new.authority_blake3
                        && after.adoption_sha256 == self.adoption_sha256,
                )
            }
            _ => Err(RecordError::Invalid),
        }
    }
}

fn component_context(
    component: Component,
    pair: (&SchemaPair, &SchemaPair),
    identity: (&str, &str, &str),
    dependencies: (&Option<String>, &Option<String>),
    admission: &AdmissionV2,
) -> Result<()> {
    let (pair_before, pair_after) = pair;
    let (installation, prefix, control) = identity;
    let (catalog_receipt, adoption) = dependencies;
    require(
        *pair_before == SchemaPair::before(component)
            && *pair_after == SchemaPair::after(component)
            && installation == admission.record.installation_id
            && prefix == admission.record.prefix.identity
            && control == admission.record.control_root.identity,
    )?;
    match component {
        Component::Catalog => require(catalog_receipt.is_none() && adoption.is_none()),
        Component::Control => {
            digest(catalog_receipt.as_deref().ok_or(RecordError::Invalid)?)?;
            digest(adoption.as_deref().ok_or(RecordError::Invalid)?)
        }
    }
}

payload!(ComponentReceipt {
    component: Component,
    intent_sha256: String,
    pair_before: SchemaPair,
    pair_after: SchemaPair,
    installation_id: String,
    prefix_binding: String,
    control_binding: String,
    before_blake3: String,
    after_blake3: String,
    catalog_preimage_manifest_sha256: String,
    control_preimage_manifest_sha256: String,
    #[serde(deserialize_with = "nullable")]
    catalog_receipt_sha256: Option<String>,
    #[serde(deserialize_with = "nullable")]
    adoption_sha256: Option<String>,
    repository_row_counts: RowCounts,
});

impl ComponentReceipt {
    pub(super) fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        self.context(admission, "asg.schema-transition-component-receipt/v1")?;
        component_context(
            self.component,
            (&self.pair_before, &self.pair_after),
            (
                &self.installation_id,
                &self.prefix_binding,
                &self.control_binding,
            ),
            (&self.catalog_receipt_sha256, &self.adoption_sha256),
            admission,
        )?;
        for value in [
            &self.intent_sha256,
            &self.before_blake3,
            &self.after_blake3,
            &self.catalog_preimage_manifest_sha256,
            &self.control_preimage_manifest_sha256,
        ] {
            digest(value)?;
        }
        require(self.repository_row_counts.empty())
    }

    pub(super) fn matches_intent(&self, intent: &ComponentIntent, raw: &[u8]) -> Result<()> {
        require(
            self.component == intent.component
                && self.intent_sha256 == sha256(raw)
                && self.pair_before == intent.pair_before
                && self.pair_after == intent.pair_after
                && self.before_blake3 == intent.before.commitment()?
                && self.after_blake3 == intent.expected_after.commitment()?
                && self.catalog_preimage_manifest_sha256 == intent.catalog_preimage.manifest_sha256
                && self.control_preimage_manifest_sha256 == intent.control_preimage.manifest_sha256
                && self.catalog_receipt_sha256 == intent.catalog_receipt_sha256
                && self.adoption_sha256 == intent.adoption_sha256,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PendingStateRef {
    pub(super) seq: u64,
    pub(super) size_bytes: u64,
    pub(super) sha256: String,
}

impl PendingStateRef {
    fn validate(&self) -> Result<()> {
        require((1..=10000).contains(&self.seq) && (1..=65536).contains(&self.size_bytes))?;
        digest(&self.sha256)
    }

    pub(super) fn matches(&self, state: &StateV2) -> Result<()> {
        require(
            self.seq == state.record.seq
                && self.size_bytes == state.raw_bytes().len() as u64
                && self.sha256 == sha256(state.raw_bytes()),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum ComponentMarker {
    #[serde(deserialize_with = "closed_unit")]
    ColumnAbsent,
    Receipt {
        record: RecordRef,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum AdoptionReadback {
    #[serde(deserialize_with = "closed_unit")]
    NotCommitted,
    Committed {
        sha256: String,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ComponentOutcome {
    Before,
    After,
}

payload!(ComponentReadback {
    component: Component,
    pending_state: PendingStateRef,
    intent_sha256: String,
    pair: SchemaPair,
    catalog_file: FileIdentity,
    control_file: FileIdentity,
    catalog_identity: CatalogIdentity,
    control_checkpoint: ControlCheckpoint,
    catalog_preserved_rows_blake3: String,
    catalog_marker: ComponentMarker,
    control_marker: ComponentMarker,
    adoption: AdoptionReadback,
    #[serde(deserialize_with = "nullable")]
    repository_row_counts: Option<RowCounts>,
});

impl ComponentReadback {
    pub(super) fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        self.context(admission, "asg.schema-transition-component-readback/v1")?;
        self.pending_state.validate()?;
        digest(&self.intent_sha256)?;
        self.catalog_file.validate()?;
        self.control_file.validate()?;
        self.catalog_identity
            .validate(admission, self.pair.catalog)?;
        self.control_checkpoint
            .validate(admission, self.pair.control)?;
        digest(&self.catalog_preserved_rows_blake3)?;
        require(
            self.control_checkpoint.catalog_incarnation.as_deref()
                == Some(self.catalog_identity.incarnation.as_str()),
        )?;
        for (marker, slot) in [
            (&self.catalog_marker, RecordSlot::CatalogReceipt),
            (&self.control_marker, RecordSlot::ControlReceipt),
        ] {
            if let ComponentMarker::Receipt { record } = marker {
                record.validate(slot)?;
            }
        }
        if let AdoptionReadback::Committed { sha256 } = &self.adoption {
            digest(sha256)?;
        }
        self.outcome().map(|_| ())
    }

    pub(super) fn outcome(&self) -> Result<ComponentOutcome> {
        let outcome = match (
            self.component,
            self.pair.catalog,
            self.pair.control,
            &self.catalog_marker,
            &self.control_marker,
            &self.adoption,
        ) {
            (
                Component::Catalog,
                22,
                2,
                ComponentMarker::ColumnAbsent,
                ComponentMarker::ColumnAbsent,
                AdoptionReadback::NotCommitted,
            ) => {
                require(self.repository_row_counts.is_none())?;
                ComponentOutcome::Before
            }
            (
                Component::Catalog,
                23,
                2,
                ComponentMarker::Receipt { .. },
                ComponentMarker::ColumnAbsent,
                AdoptionReadback::NotCommitted,
            ) => {
                require(
                    self.repository_row_counts
                        .as_ref()
                        .is_some_and(RowCounts::empty),
                )?;
                ComponentOutcome::After
            }
            (
                Component::Control,
                23,
                2,
                ComponentMarker::Receipt { .. },
                ComponentMarker::ColumnAbsent,
                AdoptionReadback::NotCommitted,
            ) => {
                require(
                    self.repository_row_counts
                        .as_ref()
                        .is_some_and(RowCounts::empty),
                )?;
                ComponentOutcome::Before
            }
            (
                Component::Control,
                23,
                3,
                ComponentMarker::Receipt { .. },
                ComponentMarker::Receipt { .. },
                AdoptionReadback::Committed { .. },
            ) => {
                require(
                    self.repository_row_counts
                        .as_ref()
                        .is_some_and(RowCounts::empty),
                )?;
                ComponentOutcome::After
            }
            _ => return Err(RecordError::Invalid),
        };
        Ok(outcome)
    }

    pub(super) fn matches_component(
        &self,
        intent: &ComponentIntent,
        intent_raw: &[u8],
        progress: &ComponentProgress,
        catalog_receipt: Option<&RecordRef>,
        catalog_snapshot: &CatalogSnapshot,
        quiesced: &Quiesced,
    ) -> Result<()> {
        require(
            self.component == intent.component
                && self.intent_sha256 == sha256(intent_raw)
                && self.pending_state.seq >= intent.intent_seq
                && self.catalog_file == quiesced.catalog_file.identity
                && self.control_file == quiesced.control_file.identity
                && self.catalog_preserved_rows_blake3 == catalog_snapshot.preserved_rows_blake3,
        )?;
        let mut expected_catalog = catalog_snapshot.identity.clone();
        expected_catalog.schema = self.pair.catalog;
        require(self.catalog_identity == expected_catalog)?;
        let outcome = self.outcome()?;
        require(
            (outcome == ComponentOutcome::Before)
                == matches!(progress, ComponentProgress::NotApplied { .. }),
        )?;
        match (&self.catalog_marker, catalog_receipt) {
            (ComponentMarker::ColumnAbsent, None) => {}
            (ComponentMarker::Receipt { record }, Some(expected)) => require(record == expected)?,
            _ => return Err(RecordError::Invalid),
        }
        match (&self.control_marker, intent.component, progress.receipt()) {
            (ComponentMarker::ColumnAbsent, Component::Catalog, _) => {}
            (ComponentMarker::ColumnAbsent, Component::Control, None) => {}
            (ComponentMarker::Receipt { record }, Component::Control, Some(expected)) => {
                require(record == expected)?;
            }
            _ => return Err(RecordError::Invalid),
        }
        if let AdoptionReadback::Committed { sha256 } = &self.adoption {
            require(intent.adoption_sha256.as_deref() == Some(sha256.as_str()))?;
        }
        let floor = match if outcome == ComponentOutcome::After {
            &intent.expected_after
        } else {
            &intent.before
        } {
            ComponentSnapshot::Control(snapshot) => &snapshot.checkpoint,
            ComponentSnapshot::Catalog(_) => &quiesced.control,
        };
        self.control_checkpoint.follows_checkpoint(floor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PairSnapshot {
    pub(super) catalog: FileStamp,
    pub(super) control: FileStamp,
    pub(super) catalog_identity: CatalogIdentity,
    pub(super) control_checkpoint: ControlCheckpoint,
}

impl PairSnapshot {
    fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        self.catalog.validate()?;
        self.control.validate()?;
        let pair = (self.catalog_identity.schema, self.control_checkpoint.schema);
        require(matches!(pair, (22, 2) | (23, 2) | (23, 3)))?;
        self.catalog_identity.validate(admission, pair.0)?;
        self.control_checkpoint.validate(admission, pair.1)?;
        require(
            self.control_checkpoint.catalog_incarnation.as_deref()
                == Some(self.catalog_identity.incarnation.as_str()),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreimageRefs {
    #[serde(deserialize_with = "nullable")]
    pub(super) catalog: Option<PreimageRef>,
    #[serde(deserialize_with = "nullable")]
    pub(super) control: Option<PreimageRef>,
}

payload!(RollbackPlan {
    restore_pair: RestorePair,
    #[serde(rename = "R")]
    recovery_incarnation: String,
    preimage_refs: PreimageRefs,
    live_pair_before: PairSnapshot,
    compatible_control_checkpoint: ControlCheckpoint,
});

impl RollbackPlan {
    pub(super) fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        self.context(admission, "asg.schema-transition-rollback-plan/v1")?;
        require(
            self.restore_pair == RestorePair::Required
                && self.recovery_incarnation
                    == format!(
                        "transition_recovery_{}",
                        &admission.record.update_id["update_".len()..]
                    ),
        )?;
        self.preimage_refs
            .catalog
            .as_ref()
            .ok_or(RecordError::Invalid)?
            .validate(Component::Catalog, admission)?;
        self.preimage_refs
            .control
            .as_ref()
            .ok_or(RecordError::Invalid)?
            .validate(Component::Control, admission)?;
        self.live_pair_before.validate(admission)?;
        require(self.compatible_control_checkpoint == self.live_pair_before.control_checkpoint)
    }
}

payload!(RollbackIntent {
    #[serde(deserialize_with = "nullable")]
    rollback_plan_sha256: Option<String>,
    restore_pair: RestorePair,
    #[serde(rename = "R", deserialize_with = "nullable")]
    recovery_incarnation: Option<String>,
    preimage_refs: PreimageRefs,
    live_pair_before: PairSnapshot,
    #[serde(deserialize_with = "nullable")]
    prepared_pair_after: Option<PairSnapshot>,
    compatible_control_checkpoint: ControlCheckpoint,
    owned_inventory_blake3: String,
});

impl RollbackIntent {
    pub(super) fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        self.context(admission, "asg.schema-transition-rollback/v1")?;
        self.live_pair_before.validate(admission)?;
        self.compatible_control_checkpoint
            .validate(admission, self.compatible_control_checkpoint.schema)?;
        require(self.compatible_control_checkpoint == self.live_pair_before.control_checkpoint)?;
        digest(&self.owned_inventory_blake3)?;
        match self.restore_pair {
            RestorePair::NotNeeded => require(
                self.rollback_plan_sha256.is_none()
                    && self.recovery_incarnation.is_none()
                    && self.preimage_refs.catalog.is_none()
                    && self.preimage_refs.control.is_none()
                    && self.prepared_pair_after.is_none()
                    && self.live_pair_before.catalog_identity.schema == 22
                    && self.live_pair_before.control_checkpoint.schema == 2
                    && self.live_pair_before.catalog_identity.incarnation
                        == admission.record.checkpoint.catalog_incarnation,
            ),
            RestorePair::Required => {
                digest(
                    self.rollback_plan_sha256
                        .as_deref()
                        .ok_or(RecordError::Invalid)?,
                )?;
                let recovery = format!(
                    "transition_recovery_{}",
                    &admission.record.update_id["update_".len()..]
                );
                require(self.recovery_incarnation.as_deref() == Some(recovery.as_str()))?;
                self.preimage_refs
                    .catalog
                    .as_ref()
                    .ok_or(RecordError::Invalid)?
                    .validate(Component::Catalog, admission)?;
                self.preimage_refs
                    .control
                    .as_ref()
                    .ok_or(RecordError::Invalid)?
                    .validate(Component::Control, admission)?;
                let after = self
                    .prepared_pair_after
                    .as_ref()
                    .ok_or(RecordError::Invalid)?;
                after.validate(admission)?;
                let before = &self.live_pair_before.control_checkpoint;
                let next = &after.control_checkpoint;
                require(
                    after.catalog_identity.schema == 22
                        && next.schema == 2
                        && after.catalog_identity.incarnation == recovery
                        && after.catalog_identity.generation
                            == self.live_pair_before.catalog_identity.generation
                        && self
                            .live_pair_before
                            .catalog_identity
                            .destructive_epoch
                            .checked_add(1)
                            == Some(after.catalog_identity.destructive_epoch)
                        && next.control_seq > before.control_seq
                        && next.policy_epoch == before.policy_epoch
                        && next.desired_updates == before.desired_updates
                        && next.autostart_enabled == before.autostart_enabled
                        && next.restart_request_seq == before.restart_request_seq
                        && next.authority_blake3 == before.authority_blake3
                        && next.maintenance.owner == before.maintenance.owner,
                )
            }
        }
    }

    pub(super) fn matches_plan(&self, plan: &RollbackPlan, raw: &[u8]) -> Result<()> {
        require(
            self.restore_pair == RestorePair::Required
                && self.rollback_plan_sha256.as_deref() == Some(sha256(raw).as_str())
                && self.recovery_incarnation.as_deref() == Some(plan.recovery_incarnation.as_str())
                && self.preimage_refs == plan.preimage_refs
                && self.live_pair_before == plan.live_pair_before
                && self.compatible_control_checkpoint == plan.compatible_control_checkpoint,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PreparationSlot {
    CatalogSideParent,
    ControlSideParent,
    CatalogDisplacedParent,
    ControlDisplacedParent,
    CatalogSideDb,
    ControlSideDb,
    CatalogDisplacedManifest,
    ControlDisplacedManifest,
    CatalogRestoreJournal,
    ControlRestoreJournal,
    CatalogSideWal,
    CatalogSideShm,
    CatalogSideJournal,
    ControlSideWal,
    ControlSideShm,
    ControlSideJournal,
}

impl PreparationSlot {
    pub(super) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "catalog_side_parent" => Self::CatalogSideParent,
            "control_side_parent" => Self::ControlSideParent,
            "catalog_displaced_parent" => Self::CatalogDisplacedParent,
            "control_displaced_parent" => Self::ControlDisplacedParent,
            "catalog_side_db" => Self::CatalogSideDb,
            "control_side_db" => Self::ControlSideDb,
            "catalog_displaced_manifest" => Self::CatalogDisplacedManifest,
            "control_displaced_manifest" => Self::ControlDisplacedManifest,
            "catalog_restore_journal" => Self::CatalogRestoreJournal,
            "control_restore_journal" => Self::ControlRestoreJournal,
            "catalog_side_wal" => Self::CatalogSideWal,
            "catalog_side_shm" => Self::CatalogSideShm,
            "catalog_side_journal" => Self::CatalogSideJournal,
            "control_side_wal" => Self::ControlSideWal,
            "control_side_shm" => Self::ControlSideShm,
            "control_side_journal" => Self::ControlSideJournal,
            _ => return None,
        })
    }

    pub(super) fn permits(self, kind: EffectKind) -> bool {
        match kind {
            EffectKind::RollbackBindParent => {
                matches!(self, Self::CatalogSideParent | Self::ControlSideParent)
            }
            EffectKind::RollbackCreateEmpty => {
                !matches!(self, Self::CatalogSideParent | Self::ControlSideParent)
            }
            EffectKind::RollbackWriteContent => matches!(
                self,
                Self::CatalogSideDb
                    | Self::ControlSideDb
                    | Self::CatalogDisplacedManifest
                    | Self::ControlDisplacedManifest
                    | Self::CatalogRestoreJournal
                    | Self::ControlRestoreJournal
            ),
            _ => false,
        }
    }

    pub(super) fn target(self) -> Change {
        match self {
            Self::CatalogSideParent
            | Self::CatalogSideDb
            | Self::CatalogSideWal
            | Self::CatalogSideShm
            | Self::CatalogSideJournal => Change::Image(2),
            Self::ControlSideParent
            | Self::ControlSideDb
            | Self::ControlSideWal
            | Self::ControlSideShm
            | Self::ControlSideJournal => Change::Image(3),
            Self::CatalogDisplacedParent | Self::CatalogDisplacedManifest => Change::Image(4),
            Self::ControlDisplacedParent | Self::ControlDisplacedManifest => Change::Image(5),
            Self::CatalogRestoreJournal => Change::Journal(0),
            Self::ControlRestoreJournal => Change::Journal(1),
        }
    }

    fn component(self) -> Component {
        match self.target() {
            Change::Image(2 | 4) | Change::Journal(0) => Component::Catalog,
            _ => Component::Control,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PreparationInput {
    #[serde(deserialize_with = "closed_unit")]
    None,
    CatalogSide {
        preimage: PreimageRef,
        #[serde(rename = "R")]
        recovery: String,
    },
    ControlSide {
        preimage: PreimageRef,
        #[serde(rename = "R")]
        recovery: String,
        compatible_control_checkpoint: Box<ControlCheckpoint>,
    },
    Manifest {
        component: Component,
        live_file: FileStamp,
    },
    RestoreJournal {
        component: Component,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PreparationPostcondition {
    #[serde(deserialize_with = "closed_unit")]
    BoundParent,
    #[serde(deserialize_with = "closed_unit")]
    EmptyDirectory,
    #[serde(deserialize_with = "closed_unit")]
    EmptyRegular,
    #[serde(deserialize_with = "closed_unit")]
    VerifiedContent,
}

payload!(RollbackPreparation {
    rollback_plan_sha256: String,
    intent_seq: u64,
    kind: EffectKind,
    slot: PreparationSlot,
    owner_before: RecordDigest,
    input: PreparationInput,
    postcondition: PreparationPostcondition,
});

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum PreparationObservation {
    BoundParent {
        identity: FileIdentity,
    },
    EmptyDirectory {
        identity: FileIdentity,
        entry_count: u64,
    },
    EmptyRegular {
        identity: FileIdentity,
        size_bytes: u64,
    },
    VerifiedContent {
        stamp: FileStamp,
    },
}

// These object shapes are disjoint and the closed slot selects the required one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum PreparationOwner {
    Image(Box<ImageSlot>),
    Journal(OwnedRecordSlot),
}

impl PreparationOwner {
    fn from_state(state: &StateV2, slot: PreparationSlot) -> Result<Self> {
        match slot.target() {
            Change::Image(index) => Ok(Self::Image(Box::new(
                state.record.images()[index]
                    .ok_or(RecordError::Invalid)?
                    .clone(),
            ))),
            Change::Journal(index) => {
                let rollback = state.record.rollback.as_ref().ok_or(RecordError::Invalid)?;
                Ok(Self::Journal(
                    if index == 0 {
                        rollback.catalog_restore_journal.as_ref()
                    } else {
                        rollback.control_restore_journal.as_ref()
                    }
                    .ok_or(RecordError::Invalid)?
                    .clone(),
                ))
            }
            _ => Err(RecordError::Invalid),
        }
    }
}

fn preparation_before(
    owner: &PreparationOwner,
    slot: PreparationSlot,
    kind: EffectKind,
) -> Result<()> {
    let allowed = match (owner, slot, kind) {
        (
            PreparationOwner::Image(image),
            PreparationSlot::CatalogSideParent | PreparationSlot::ControlSideParent,
            EffectKind::RollbackBindParent,
        )
        | (
            PreparationOwner::Image(image),
            PreparationSlot::CatalogDisplacedParent | PreparationSlot::ControlDisplacedParent,
            EffectKind::RollbackCreateEmpty,
        ) => matches!(image.parent, ParentState::AbsentUnderBoundRoot),
        (PreparationOwner::Image(image), slot, EffectKind::RollbackCreateEmpty) => {
            matches!(image.parent, ParentState::Owned { .. })
                && match slot {
                    PreparationSlot::CatalogSideDb | PreparationSlot::ControlSideDb => {
                        matches!(image.image, ImageState::Registered)
                    }
                    PreparationSlot::CatalogDisplacedManifest
                    | PreparationSlot::ControlDisplacedManifest => {
                        matches!(image.manifest, ManifestState::Absent)
                    }
                    _ => {
                        let mut image = image.as_ref().clone();
                        preparation_sidecar(&mut image, slot)
                            .is_some_and(|s| matches!(s, SidecarState::Absent))
                    }
                }
        }
        (PreparationOwner::Journal(journal), _, EffectKind::RollbackCreateEmpty) => {
            journal.state == OwnedRecordState::Registered
                && journal.identity.is_none()
                && journal.size_bytes == 0
                && journal.blake3.is_none()
        }
        (PreparationOwner::Image(image), slot, EffectKind::RollbackWriteContent) => {
            matches!(image.parent, ParentState::Owned { .. })
                && match slot {
                    PreparationSlot::CatalogSideDb | PreparationSlot::ControlSideDb => {
                        matches!(image.image, ImageState::OwnedIncomplete { .. })
                            && [
                                &image.sidecars.wal,
                                &image.sidecars.shm,
                                &image.sidecars.journal,
                            ]
                            .into_iter()
                            .all(|s| matches!(s, SidecarState::Owned { .. }))
                    }
                    PreparationSlot::CatalogDisplacedManifest
                    | PreparationSlot::ControlDisplacedManifest => {
                        matches!(image.manifest, ManifestState::OwnedIncomplete { .. })
                    }
                    _ => false,
                }
        }
        (PreparationOwner::Journal(journal), _, EffectKind::RollbackWriteContent) => {
            journal.state == OwnedRecordState::Owned && journal.identity.is_some()
        }
        _ => false,
    };
    require(allowed)
}

payload!(PreparationReadback {
    pending_state: PendingStateRef,
    preparation_sha256: String,
    observed: PreparationObservation,
    owner_after: PreparationOwner,
});

pub(super) fn preparation_projection(
    state: &StateV2,
    effect: &PendingEffect,
    plan: &RollbackPlan,
    plan_raw: &[u8],
    admission: &AdmissionV2,
) -> Result<Vec<u8>> {
    let slot = PreparationSlot::parse(&effect.slot).ok_or(RecordError::Invalid)?;
    require(slot.permits(effect.kind))?;
    let owner = PreparationOwner::from_state(state, slot)?;
    preparation_before(&owner, slot, effect.kind)?;
    let owner_bytes = super::super::encode(&owner)?;
    let before = RecordDigest {
        size_bytes: owner_bytes.len() as u64,
        sha256: sha256(&owner_bytes),
    };
    let (input, postcondition) = match effect.kind {
        EffectKind::RollbackBindParent => (
            PreparationInput::None,
            PreparationPostcondition::BoundParent,
        ),
        EffectKind::RollbackCreateEmpty => (
            PreparationInput::None,
            if matches!(
                slot,
                PreparationSlot::CatalogDisplacedParent | PreparationSlot::ControlDisplacedParent
            ) {
                PreparationPostcondition::EmptyDirectory
            } else {
                PreparationPostcondition::EmptyRegular
            },
        ),
        EffectKind::RollbackWriteContent => {
            let input = match slot {
                PreparationSlot::CatalogSideDb => PreparationInput::CatalogSide {
                    preimage: plan
                        .preimage_refs
                        .catalog
                        .clone()
                        .ok_or(RecordError::Invalid)?,
                    recovery: plan.recovery_incarnation.clone(),
                },
                PreparationSlot::ControlSideDb => PreparationInput::ControlSide {
                    preimage: plan
                        .preimage_refs
                        .control
                        .clone()
                        .ok_or(RecordError::Invalid)?,
                    recovery: plan.recovery_incarnation.clone(),
                    compatible_control_checkpoint: Box::new(
                        plan.compatible_control_checkpoint.clone(),
                    ),
                },
                PreparationSlot::CatalogDisplacedManifest
                | PreparationSlot::ControlDisplacedManifest => PreparationInput::Manifest {
                    component: slot.component(),
                    live_file: if slot.component() == Component::Catalog {
                        plan.live_pair_before.catalog.clone()
                    } else {
                        plan.live_pair_before.control.clone()
                    },
                },
                PreparationSlot::CatalogRestoreJournal | PreparationSlot::ControlRestoreJournal => {
                    PreparationInput::RestoreJournal {
                        component: slot.component(),
                    }
                }
                _ => return Err(RecordError::Invalid),
            };
            (input, PreparationPostcondition::VerifiedContent)
        }
        _ => return Err(RecordError::Invalid),
    };
    let projection = RollbackPreparation {
        schema: "asg.schema-transition-rollback-preparation/v1".into(),
        mode: admission.record.mode,
        update_id: admission.record.update_id.clone(),
        owner_nonce: admission.record.owner_nonce.clone(),
        admission_sha256: sha256(admission.raw_bytes()),
        rollback_plan_sha256: sha256(plan_raw),
        intent_seq: effect.intent_seq,
        kind: effect.kind,
        slot,
        owner_before: before,
        input,
        postcondition,
    };
    projection.context(admission, "asg.schema-transition-rollback-preparation/v1")?;
    let bytes = super::super::encode(&projection)?;
    require(bytes.len() <= PROOF_LIMIT)?;
    Ok(bytes)
}

pub(super) fn validate_preparation_readback(
    previous: &StateV2,
    next: &StateV2,
    effect: &PendingEffect,
    projection: &[u8],
    raw: &[u8],
    admission: &AdmissionV2,
) -> Result<()> {
    let plan: RollbackPreparation = canonical(projection)?;
    let readback: PreparationReadback = canonical(raw)?;
    readback.context(
        admission,
        "asg.schema-transition-rollback-preparation-readback/v1",
    )?;
    readback.pending_state.matches(previous)?;
    require(
        readback.preparation_sha256 == sha256(projection)
            && effect.expected_after.sha256 == readback.preparation_sha256
            && effect.expected_after.size_bytes == projection.len() as u64,
    )?;
    let before = PreparationOwner::from_state(previous, plan.slot)?;
    let after = PreparationOwner::from_state(next, plan.slot)?;
    require(readback.owner_after == after)?;
    let mut expected = before.clone();
    match (
        &mut expected,
        plan.slot,
        &readback.observed,
        plan.postcondition,
    ) {
        (
            PreparationOwner::Image(image),
            PreparationSlot::CatalogSideParent | PreparationSlot::ControlSideParent,
            PreparationObservation::BoundParent { identity },
            PreparationPostcondition::BoundParent,
        )
        | (
            PreparationOwner::Image(image),
            PreparationSlot::CatalogDisplacedParent | PreparationSlot::ControlDisplacedParent,
            PreparationObservation::EmptyDirectory {
                identity,
                entry_count: 0,
            },
            PreparationPostcondition::EmptyDirectory,
        ) => {
            require(matches!(image.parent, ParentState::AbsentUnderBoundRoot))?;
            identity.validate()?;
            image.parent = ParentState::Owned {
                identity: identity.clone(),
            };
        }
        (
            PreparationOwner::Image(image),
            slot,
            PreparationObservation::EmptyRegular {
                identity,
                size_bytes: 0,
            },
            PreparationPostcondition::EmptyRegular,
        ) => {
            require(matches!(image.parent, ParentState::Owned { .. }))?;
            identity.validate()?;
            match slot {
                PreparationSlot::CatalogSideDb | PreparationSlot::ControlSideDb => {
                    require(matches!(image.image, ImageState::Registered))?;
                    image.image = ImageState::OwnedIncomplete {
                        identity: identity.clone(),
                    };
                }
                PreparationSlot::CatalogDisplacedManifest
                | PreparationSlot::ControlDisplacedManifest => {
                    require(matches!(image.manifest, ManifestState::Absent))?;
                    image.manifest = ManifestState::OwnedIncomplete {
                        identity: identity.clone(),
                    };
                }
                _ => {
                    let sidecar = preparation_sidecar(image, slot).ok_or(RecordError::Invalid)?;
                    require(matches!(sidecar, SidecarState::Absent))?;
                    *sidecar = SidecarState::Owned {
                        identity: identity.clone(),
                    };
                }
            }
        }
        (
            PreparationOwner::Journal(journal),
            _,
            PreparationObservation::EmptyRegular {
                identity,
                size_bytes: 0,
            },
            PreparationPostcondition::EmptyRegular,
        ) => {
            require(
                journal.state == OwnedRecordState::Registered
                    && journal.identity.is_none()
                    && journal.size_bytes == 0
                    && journal.blake3.is_none(),
            )?;
            identity.validate()?;
            journal.state = OwnedRecordState::Owned;
            journal.identity = Some(identity.clone());
        }
        (
            PreparationOwner::Image(image),
            slot,
            PreparationObservation::VerifiedContent { stamp },
            PreparationPostcondition::VerifiedContent,
        ) => {
            stamp.validate()?;
            if matches!(
                slot,
                PreparationSlot::CatalogSideDb | PreparationSlot::ControlSideDb
            ) {
                require(
                    matches!(&image.image, ImageState::OwnedIncomplete { identity } if identity == &stamp.identity),
                )?;
                // The supported backend must hold every possibly writable sidecar.
                require(
                    [
                        &image.sidecars.wal,
                        &image.sidecars.shm,
                        &image.sidecars.journal,
                    ]
                    .into_iter()
                    .all(|s| matches!(s, SidecarState::Owned { .. })),
                )?;
                image.image = ImageState::Complete {
                    stamp: stamp.clone(),
                };
            } else {
                require(
                    matches!(
                        slot,
                        PreparationSlot::CatalogDisplacedManifest
                            | PreparationSlot::ControlDisplacedManifest
                    ) && matches!(&image.manifest, ManifestState::OwnedIncomplete { identity } if identity == &stamp.identity),
                )?;
                image.manifest = ManifestState::Complete {
                    stamp: stamp.clone(),
                };
            }
        }
        (
            PreparationOwner::Journal(journal),
            _,
            PreparationObservation::VerifiedContent { stamp },
            PreparationPostcondition::VerifiedContent,
        ) => {
            stamp.validate()?;
            require(
                journal.state == OwnedRecordState::Owned
                    && journal.identity.as_ref() == Some(&stamp.identity)
                    && stamp.size_bytes <= 64 * 1024 * 1024,
            )?;
            journal.state = OwnedRecordState::Complete;
            journal.size_bytes = stamp.size_bytes;
            journal.blake3 = Some(stamp.blake3.clone());
        }
        _ => return Err(RecordError::Invalid),
    }
    require(expected == after)
}

fn preparation_sidecar(image: &mut ImageSlot, slot: PreparationSlot) -> Option<&mut SidecarState> {
    match slot {
        PreparationSlot::CatalogSideWal | PreparationSlot::ControlSideWal => {
            Some(&mut image.sidecars.wal)
        }
        PreparationSlot::CatalogSideShm | PreparationSlot::ControlSideShm => {
            Some(&mut image.sidecars.shm)
        }
        PreparationSlot::CatalogSideJournal | PreparationSlot::ControlSideJournal => {
            Some(&mut image.sidecars.journal)
        }
        _ => None,
    }
}

payload!(Coverage {
    source_ids: Vec<String>,
});

impl Coverage {
    pub(super) fn validate(&self, admission: &AdmissionV2) -> Result<()> {
        self.context(admission, "asg.schema-transition-coverage/v1")?;
        source_ids(&self.source_ids)
    }
}

fn source_ids(values: &[String]) -> Result<()> {
    let mut previous: Option<&str> = None;
    for value in values {
        id(value)?;
        require(previous.is_none_or(|before| before < value.as_str()))?;
        previous = Some(value);
    }
    Ok(())
}

// Only these bounded records admit source_ids arrays. All objects still reject
// duplicate keys, and arrays cannot substitute for any object representation.
pub(super) fn canonical_list_record<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    require(!bytes.is_empty())?;
    if bytes.len() > MANIFEST_LIMIT {
        return Err(RecordError::TooLarge);
    }
    struct ListShape(bool);
    impl<'de> Visitor<'de> for ListShape {
        type Value = ();
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a bounded manifest field")
        }
        fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> std::result::Result<(), M::Error> {
            let mut keys = BTreeSet::new();
            while let Some(key) = map.next_key::<String>()? {
                let list = key == "source_ids";
                if !keys.insert(key) {
                    return Err(serde::de::Error::custom("duplicate manifest field"));
                }
                map.next_value_seed(ListShape(list))?;
            }
            Ok(())
        }
        fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> std::result::Result<(), S::Error> {
            if !self.0 {
                return Err(serde::de::Error::custom("unexpected manifest array"));
            }
            while seq.next_element::<String>()?.is_some() {}
            Ok(())
        }
        fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
            Ok(())
        }
        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
            Ok(())
        }
    }
    impl<'de> DeserializeSeed<'de> for ListShape {
        type Value = ();
        fn deserialize<D: Deserializer<'de>>(self, d: D) -> std::result::Result<(), D::Error> {
            d.deserialize_any(self)
        }
    }
    let mut d = serde_json::Deserializer::from_slice(bytes);
    ListShape(false)
        .deserialize(&mut d)
        .map_err(|_| RecordError::Invalid)?;
    d.end().map_err(|_| RecordError::Invalid)?;
    let value: T = serde_json::from_slice(bytes).map_err(|_| RecordError::Invalid)?;
    require(serde_json::to_vec(&value).map_err(|_| RecordError::Invalid)? == bytes)?;
    Ok(value)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CatalogManifest {
    schema: String,
    backup_id: String,
    purpose: String,
    installation_id: String,
    catalog_incarnation: String,
    catalog_generation: u64,
    schema_version: u32,
    digest: String,
    size_bytes: u64,
    source_ids: Vec<String>,
    created_at_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlManifest {
    schema: String,
    backup_id: String,
    purpose: String,
    update_id: String,
    owner_nonce: String,
    installation_id: String,
    control_root_binding: String,
    catalog_root_binding: String,
    control_schema: u32,
    control_checkpoint: ControlCheckpoint,
    catalog_incarnation: String,
    catalog_generation: u64,
    digest_blake3: String,
    size_bytes: u64,
    source_ids: Vec<String>,
    coverage_sha256: String,
    created_at_ms: i64,
}

#[derive(Debug)]
enum ManifestPayload {
    Catalog(Box<CatalogManifest>),
    Control(Box<ControlManifest>),
}

/// An independently decoded manifest is byte evidence only, not a backup pin.
#[derive(Debug)]
pub struct PreimageManifest {
    pub(super) component: Component,
    payload: ManifestPayload,
    raw: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum FinalOldLayout {
    #[serde(deserialize_with = "closed_unit")]
    Absent,
    TerminalV1 {
        update_id: String,
        state_size_bytes: u64,
        state_sha256: String,
        run_binding: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalFile {
    size_bytes: u64,
    sha256: String,
    file_identity: FileIdentity,
}

impl FinalFile {
    fn validate(&self) -> Result<()> {
        require((1..=64 * 1024).contains(&self.size_bytes))?;
        digest(&self.sha256)?;
        self.file_identity.validate()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalResiduals {
    admission: FinalFile,
    initial_state: FinalFile,
    active_state: FinalFile,
    guard: FinalFile,
    #[serde(deserialize_with = "nullable")]
    prior_state: Option<FinalFile>,
    update_directory: FileIdentity,
    run_directory: FileIdentity,
    #[serde(deserialize_with = "nullable")]
    prior_directory: Option<FileIdentity>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalCatalog {
    schema: u32,
    incarnation: String,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum FinalStep {
    Prepared,
    LayoutInstalled,
    FenceCleared,
    Complete,
}

impl FinalStep {
    fn seq(self) -> u64 {
        match self {
            Self::Prepared => 1,
            Self::LayoutInstalled => 2,
            Self::FenceCleared => 3,
            Self::Complete => 4,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FinalizerPayload {
    schema: String,
    mode: TransitionMode,
    update_id: String,
    owner_nonce: String,
    prefix_binding: String,
    control_binding: String,
    installation_id: String,
    final_executor: VersionIdentity,
    old_executor: VersionIdentity,
    old_pointer_generation: u64,
    old_layout: FinalOldLayout,
    expected_catalog: FinalCatalog,
    expected_control_schema: u32,
    cleanup_receipt_sha256: String,
    guard_sha256: String,
    active_state_sha256: String,
    residuals: FinalResiduals,
    step: FinalStep,
    step_seq: u64,
    #[serde(deserialize_with = "nullable")]
    predecessor_sha256: Option<String>,
}

impl FinalizerPayload {
    pub(super) fn validate(&self) -> Result<()> {
        require(self.schema == "asg.schema-transition-finalizer/v1")?;
        super::super::fresh_id(&self.update_id, "update_")?;
        super::super::fresh_id(&self.owner_nonce, "update_owner_")?;
        root_token(&self.prefix_binding)?;
        root_token(&self.control_binding)?;
        id(&self.installation_id)?;
        super::super::version(&self.old_executor, (22, 2))?;
        super::super::version(&self.final_executor, (23, 3))?;
        require((1..=MAX_COUNTER).contains(&self.old_pointer_generation))?;
        require(self.expected_catalog.schema == 22 && self.expected_control_schema == 2)?;
        id(&self.expected_catalog.incarnation)?;
        require(self.expected_catalog.generation <= MAX_COUNTER)?;
        for digest_value in [
            &self.cleanup_receipt_sha256,
            &self.guard_sha256,
            &self.active_state_sha256,
        ] {
            digest(digest_value)?;
        }
        for file in [
            &self.residuals.admission,
            &self.residuals.initial_state,
            &self.residuals.active_state,
            &self.residuals.guard,
        ] {
            file.validate()?;
        }
        self.residuals.update_directory.validate()?;
        self.residuals.run_directory.validate()?;
        require(
            self.residuals.guard.sha256 == self.guard_sha256
                && self.residuals.active_state.sha256 == self.active_state_sha256,
        )?;
        match &self.old_layout {
            FinalOldLayout::Absent => require(
                self.old_pointer_generation == 1
                    && self.residuals.prior_state.is_none()
                    && self.residuals.prior_directory.is_none(),
            )?,
            FinalOldLayout::TerminalV1 {
                update_id,
                state_size_bytes,
                state_sha256,
                run_binding,
            } => {
                id(update_id)?;
                root_token(run_binding)?;
                let prior = self
                    .residuals
                    .prior_state
                    .as_ref()
                    .ok_or(RecordError::Invalid)?;
                prior.validate()?;
                self.residuals
                    .prior_directory
                    .as_ref()
                    .ok_or(RecordError::Invalid)?
                    .validate()?;
                require(prior.size_bytes == *state_size_bytes && prior.sha256 == *state_sha256)?;
            }
        }
        require(
            self.step_seq == self.step.seq()
                && (self.step_seq == 1) == self.predecessor_sha256.is_none(),
        )?;
        if let Some(previous) = &self.predecessor_sha256 {
            digest(previous)?;
        }
        Ok(())
    }

    pub(super) fn context(&self, admission: &AdmissionV2) -> Result<()> {
        self.validate()?;
        require(
            self.mode == admission.record.mode
                && self.update_id == admission.record.update_id
                && self.owner_nonce == admission.record.owner_nonce
                && self.prefix_binding == admission.record.prefix.identity
                && self.control_binding == admission.record.control_root.identity
                && self.installation_id == admission.record.installation_id
                && self.final_executor == admission.record.new
                && self.old_executor == admission.record.old
                && self.old_pointer_generation == admission.record.old_pointer_generation
                && self.residuals.admission.sha256 == sha256(admission.raw_bytes())
                && self.residuals.admission.size_bytes == admission.raw_bytes().len() as u64,
        )?;
        match (&self.old_layout, &admission.record.old_layout) {
            (FinalOldLayout::Absent, super::super::OldJournalLayout::Absent { .. }) => Ok(()),
            (
                FinalOldLayout::TerminalV1 {
                    update_id,
                    state_size_bytes,
                    state_sha256,
                    run_binding,
                },
                super::super::OldJournalLayout::TerminalV1 {
                    update_id: expected_id,
                    state_size_bytes: expected_size,
                    state_sha256: expected_hash,
                    run_identity,
                },
            ) => require(
                update_id == expected_id
                    && state_size_bytes == expected_size
                    && state_sha256 == expected_hash
                    && run_binding == run_identity,
            ),
            _ => Err(RecordError::Invalid),
        }
    }

    pub(super) fn matches_cleanup(&self, cleanup: &StateV2) -> Result<()> {
        require(
            cleanup.record.phase.plain() == PlainPhase::CleanupComplete
                && self.step == FinalStep::Prepared
                && self.cleanup_receipt_sha256 == sha256(cleanup.raw_bytes())
                && self.active_state_sha256 == self.cleanup_receipt_sha256,
        )?;
        let rollback = cleanup
            .record
            .rollback
            .as_ref()
            .ok_or(RecordError::Invalid)?;
        require(
            rollback.rollback_pair_readback.is_some()
                && cleanup.record.pending.is_none()
                && rollback.finalizer.is_none()
                && self.residuals.active_state.size_bytes == cleanup.raw_bytes().len() as u64
                && cleanup
                    .record
                    .images()
                    .into_iter()
                    .flatten()
                    .all(ImageSlot::clean)
                && cleanup.record.metadata.slots.iter().all(|slot| {
                    matches!(
                        slot,
                        MetadataSlot::Untouched | MetadataSlot::Restored { .. }
                    )
                }),
        )
    }
}

/// Pure handoff only. C remains the active state; no StateV2 ACK is published.
pub fn validate_finalizer_handoff(
    cleanup: &StateV2,
    prepared: &FinalizerRecord,
    admission: &AdmissionV2,
) -> Result<()> {
    cleanup.record.validate(admission)?;
    prepared.payload.context(admission)?;
    prepared.payload.matches_cleanup(cleanup)?;
    let rollback = cleanup
        .record
        .rollback
        .as_ref()
        .ok_or(RecordError::Invalid)?;
    let incarnation = match rollback.restore_pair {
        RestorePair::Required => rollback
            .recovery_incarnation
            .as_ref()
            .ok_or(RecordError::Invalid)?,
        RestorePair::NotNeeded => &admission.record.checkpoint.catalog_incarnation,
    };
    let generation = cleanup
        .record
        .quiesced
        .as_ref()
        .map_or(admission.record.checkpoint.catalog_generation, |q| {
            q.catalog.generation
        });
    require(
        prepared.payload.expected_catalog.incarnation == *incarnation
            && prepared.payload.expected_catalog.generation == generation
            && [
                rollback.catalog_restore_journal.as_ref(),
                rollback.control_restore_journal.as_ref(),
            ]
            .into_iter()
            .flatten()
            .all(|r| {
                matches!(
                    r.state,
                    OwnedRecordState::Absent | OwnedRecordState::Deleted
                )
            }),
    )
}

/// Independent C-root finalizer decoding never requires deleted U/state files.
#[derive(Debug)]
pub struct FinalizerRecord {
    payload: FinalizerPayload,
    raw: Vec<u8>,
}

impl FinalizerRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let payload: FinalizerPayload = canonical(bytes)?;
        payload.validate()?;
        Ok(Self {
            payload,
            raw: bytes.to_vec(),
        })
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn validate_chain(&self, previous: &Self) -> Result<()> {
        self.payload.validate()?;
        previous.payload.validate()?;
        require(
            previous.payload.step_seq.checked_add(1) == Some(self.payload.step_seq)
                && self.payload.predecessor_sha256.as_deref()
                    == Some(sha256(previous.raw_bytes()).as_str()),
        )?;
        let mut expected = previous.payload.clone();
        expected.step = self.payload.step;
        expected.step_seq = self.payload.step_seq;
        expected.predecessor_sha256 = self.payload.predecessor_sha256.clone();
        require(self.payload == expected)
    }
}

impl PreimageManifest {
    pub fn decode(component: Component, bytes: &[u8], admission: &AdmissionV2) -> Result<Self> {
        let payload = match component {
            Component::Catalog => ManifestPayload::Catalog(Box::new(canonical_list_record(bytes)?)),
            Component::Control => ManifestPayload::Control(Box::new(canonical_list_record(bytes)?)),
        };
        let manifest = Self {
            component,
            payload,
            raw: bytes.to_vec(),
        };
        manifest.validate_context(admission)?;
        Ok(manifest)
    }

    fn validate_context(&self, admission: &AdmissionV2) -> Result<()> {
        let suffix = &admission.record.update_id["update_".len()..];
        match &self.payload {
            ManifestPayload::Catalog(value) => {
                require(
                    self.component == Component::Catalog
                        && value.schema == "asg.catalog-backup/v1"
                        && value.backup_id == format!("transition_catalog_{suffix}")
                        && value.purpose == "beta_rollback"
                        && value.installation_id == admission.record.installation_id
                        && value.catalog_incarnation
                            == admission.record.checkpoint.catalog_incarnation
                        && value.catalog_generation
                            >= admission.record.checkpoint.catalog_generation
                        && value.schema_version == 22
                        && value.created_at_ms >= 0,
                )?;
                source_ids(&value.source_ids)?;
                digest(&value.digest)?;
                require((1..=MAX_COUNTER).contains(&value.size_bytes))?;
            }
            ManifestPayload::Control(value) => {
                require(
                    self.component == Component::Control
                        && value.schema == "asg.schema-transition-control-preimage/v1"
                        && value.backup_id == format!("transition_control_{suffix}")
                        && value.purpose == "schema_transition_rollback"
                        && value.update_id == admission.record.update_id
                        && value.owner_nonce == admission.record.owner_nonce
                        && value.installation_id == admission.record.installation_id
                        && value.control_root_binding == admission.record.control_root.identity
                        && value.catalog_root_binding == admission.record.control_root.identity
                        && value.control_schema == 2
                        && value.catalog_incarnation
                            == admission.record.checkpoint.catalog_incarnation
                        && value.catalog_generation
                            >= admission.record.checkpoint.catalog_generation
                        && value.created_at_ms >= 0,
                )?;
                value.control_checkpoint.validate(admission, 2)?;
                source_ids(&value.source_ids)?;
                digest(&value.digest_blake3)?;
                digest(&value.coverage_sha256)?;
                require((1..=MAX_COUNTER).contains(&value.size_bytes))?;
            }
        }
        Ok(())
    }

    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub(super) fn matches_preimage(&self, reference: &PreimageRef) -> Result<()> {
        let (id, size, db_digest) = match &self.payload {
            ManifestPayload::Catalog(value) => (&value.backup_id, value.size_bytes, &value.digest),
            ManifestPayload::Control(value) => {
                (&value.backup_id, value.size_bytes, &value.digest_blake3)
            }
        };
        require(
            reference.id == *id
                && reference.size_bytes == size
                && reference.db_blake3 == *db_digest
                && reference.manifest_sha256 == sha256(self.raw_bytes()),
        )
    }

    pub(super) fn validate_binding(
        &self,
        image: &ImageSlot,
        coverage: &ProofRecord,
        checkpoint: Option<&Quiesced>,
        admission: &AdmissionV2,
    ) -> Result<()> {
        self.validate_context(admission)?;
        let (role, backup_id) = match &self.payload {
            ManifestPayload::Catalog(value) => (ImageRole::CatalogPreimage, &value.backup_id),
            ManifestPayload::Control(value) => (ImageRole::ControlPreimage, &value.backup_id),
        };
        require(image.role == role && &image.artifact_id == backup_id)?;
        let ProofPayload::Coverage(covered) = &coverage.payload else {
            return Err(RecordError::Invalid);
        };
        let (digest, size, ids, generation, incarnation) = match &self.payload {
            ManifestPayload::Catalog(m) => (
                &m.digest,
                m.size_bytes,
                &m.source_ids,
                m.catalog_generation,
                &m.catalog_incarnation,
            ),
            ManifestPayload::Control(m) => {
                require(m.coverage_sha256 == sha256(coverage.raw_bytes()))?;
                if let Some(checkpoint) = checkpoint {
                    require(m.control_checkpoint == checkpoint.control)?;
                }
                (
                    &m.digest_blake3,
                    m.size_bytes,
                    &m.source_ids,
                    m.catalog_generation,
                    &m.catalog_incarnation,
                )
            }
        };
        if let Some(checkpoint) = checkpoint {
            require(
                generation == checkpoint.catalog.generation
                    && incarnation == &checkpoint.catalog.incarnation,
            )?;
        }
        match self.component {
            Component::Control => require(ids == &covered.source_ids)?,
            Component::Catalog => require(
                ids.iter()
                    .all(|id| covered.source_ids.binary_search(id).is_ok()),
            )?,
        }
        if let Some(stamp) = image.image.stamp() {
            require(&stamp.blake3 == digest && stamp.size_bytes == size)?;
        }
        if let ManifestState::Complete { stamp } = &image.manifest {
            require(
                stamp.size_bytes == self.raw.len() as u64
                    && stamp.blake3 == blake3::hash(&self.raw).to_hex().as_str(),
            )?;
        }
        Ok(())
    }
}
