use super::*;
use agent_session_grep_adapters_sqlite::SCHEMA_VERSION;
use agent_session_grep_ports::PortError;
use std::time::Duration;
use tempfile::TempDir;

// Historical journal metadata is retained independently of the current catalog.
const HISTORICAL_CATALOG_SCHEMA: u32 = 20;
fn current_catalog_schema() -> u32 {
    u32::try_from(SCHEMA_VERSION).expect("current adapter schema must fit release metadata")
}

fn end() -> Instant {
    Instant::now() + Duration::from_secs(10)
}
fn identity(version: &str, digest: &str) -> VersionIdentity {
    VersionIdentity {
        version: version.into(),
        target: agent_session_grep_launcher::metadata::BUILD_TARGET.into(),
        source_commit: "a".repeat(40),
        relative_dir: format!("versions/{version}-{}", &digest[..12]),
        app_sha256: digest.into(),
        catalog_schema: current_catalog_schema(),
        control_schema: 1,
        launcher_protocol: 1,
    }
}
fn state(catalog: PathBuf) -> State {
    State::new(UpdateStart {
        update_id: ControlId::parse("update_one").unwrap(),
        owner: ControlId::parse("nonce_one").unwrap(),
        old: identity("0.2.0-beta.1", &"a".repeat(64)),
        new: identity("0.2.0-beta.2", &"b".repeat(64)),
        archive_sha256: "c".repeat(64),
        manifest_sha256: "d".repeat(64),
        old_pointer_generation: 7,
        stable_launcher_sha256: "f".repeat(64),
        catalog,
        checkpoint: Checkpoint {
            installation_id: "installation_one".into(),
            policy_epoch: 3,
            control_seq: 6,
            desired_updates: "paused".into(),
            catalog_incarnation: "catalog_one".into(),
            catalog_generation: 14,
            catalog_schema: current_catalog_schema(),
        },
    })
    .unwrap()
}
fn historical_state(catalog: PathBuf) -> State {
    let mut historical = state(catalog);
    historical.old.catalog_schema = HISTORICAL_CATALOG_SCHEMA;
    historical.new.catalog_schema = HISTORICAL_CATALOG_SCHEMA;
    historical.checkpoint.catalog_schema = HISTORICAL_CATALOG_SCHEMA;
    historical.validate().unwrap();
    historical
}
struct Fixture {
    prefix: PathBuf,
    catalog: PathBuf,
    lock: ExclusiveGuard,
    // The installation lock must close before Windows temp cleanup.
    _temp: TempDir,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        let prefix = temp.path().join("owned-install");
        platform::create_private_directory(&prefix).unwrap();
        let catalog = temp.path().join("private-catalog.db");
        let lock = acquire_installation_lock(&prefix, end()).unwrap();
        Self {
            _temp: temp,
            prefix,
            catalog,
            lock,
        }
    }
    fn journal(&self) -> Journal<'_> {
        Journal::create(&self.prefix, &self.lock, state(self.catalog.clone()), end()).unwrap()
    }
}
#[test]
fn durable_state_reopens_with_same_physical_lock() {
    let f = Fixture::new();
    let mut j = f.journal();
    j.transition(Phase::Quiescing, end()).unwrap();
    let seq = j.state.seq;
    drop(j);
    let j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    assert_eq!(j.state.phase, Phase::Quiescing);
    assert_eq!(j.state.seq, seq);
    assert_eq!(j.state.checkpoint.desired_updates, "paused");
}
#[test]
fn terminal_phase_cannot_be_marked_without_verified_effects() {
    let f = Fixture::new();
    let mut j = f.journal();
    assert!(j.transition(Phase::Complete, end()).is_err());
    assert_eq!(j.state.phase, Phase::Verified);
    assert!(j.poisoned());
    drop(j);
    let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    j.transition(Phase::Quiescing, end()).unwrap();
    assert!(j.transition(Phase::BackedUp, end()).is_err());
    assert!(j.poisoned());
}
#[test]
fn wrong_root_or_lock_domain_cannot_open_journal() {
    let f = Fixture::new();
    let other = f._temp.path().join("other");
    platform::create_private_directory(&other).unwrap();
    let lock = ExclusiveGuard::try_acquire(
        &other,
        LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap()),
    )
    .unwrap();
    assert!(Journal::create(&f.prefix, &lock, state(f.catalog.clone()), end()).is_err());
    let lock_end = end();
    let lock = loop {
        match ExclusiveGuard::try_acquire(&f.prefix, LockKind::PolicyOwner) {
            Ok(lock) => break lock,
            Err(PortError::WriterBusy(_)) if Instant::now() < lock_end => {
                std::thread::yield_now();
            }
            Err(error) => panic!("synthetic policy lock failed: {error:?}"),
        }
    };
    assert!(Journal::create(&f.prefix, &lock, state(f.catalog.clone()), end()).is_err());
}
#[test]
fn expired_budget_creates_no_journal_directory() {
    let f = Fixture::new();
    assert!(Journal::create(&f.prefix, &f.lock, state(f.catalog.clone()), Instant::now()).is_err());
    assert!(!f.prefix.join("update").exists());
}
#[test]
fn metadata_replace_retains_hashed_original_and_recovers() {
    let f = Fixture::new();
    write_new(&f.prefix.join("current.json"), b"old-pointer").unwrap();
    let mut j = f.journal();
    j.replace_metadata(MetadataFile::Current, b"new-pointer", end())
        .unwrap();
    assert_eq!(
        read(&f.prefix.join("current.json"), 128).unwrap().unwrap(),
        b"new-pointer"
    );
    drop(j);
    let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    j.restore_metadata(end()).unwrap();
    assert_eq!(
        read(&f.prefix.join("current.json"), 128).unwrap().unwrap(),
        b"old-pointer"
    );
}
#[test]
fn independent_edit_is_preserved_by_rollback() {
    let f = Fixture::new();
    write_new(&f.prefix.join("current.json"), b"old").unwrap();
    let mut j = f.journal();
    j.replace_metadata(MetadataFile::Current, b"new", end())
        .unwrap();
    fs::write(f.prefix.join("current.json"), b"owner-edited").unwrap();
    assert!(j.restore_metadata(end()).is_err());
    assert_eq!(
        fs::read(f.prefix.join("current.json")).unwrap(),
        b"owner-edited"
    );
}
#[test]
fn unacknowledged_effect_is_reconciled_by_hash_without_second_mutation() {
    let f = Fixture::new();
    write_new(&f.prefix.join("current.json"), b"old").unwrap();
    let mut j = f.journal();
    let artifact = format!("{}-current", j.state.seq);
    j.state.pending = Some(Replacement {
        file: MetadataFile::Current,
        before_sha256: Some(hash(b"old")),
        after_sha256: hash(b"new"),
        artifact: artifact.clone(),
    });
    j.save(end()).unwrap();
    write_new(&j.run_root().join(format!("{artifact}.before")), b"old").unwrap();
    write_new(&j.run_root().join(format!("{artifact}.new")), b"new").unwrap();
    publish(
        &f.prefix.join("current.json"),
        &j.run_root().join(format!("{artifact}.new")),
        &j.run_root().join(format!("{artifact}.displaced")),
    )
    .unwrap();
    let effect_identity =
        platform::identity(&platform::open_file(&f.prefix.join("current.json")).unwrap()).unwrap();
    drop(j);
    let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    j.reconcile_metadata(end()).unwrap();
    assert_eq!(
        platform::identity(&platform::open_file(&f.prefix.join("current.json")).unwrap()).unwrap(),
        effect_identity
    );
    assert!(j.state.pending.is_none());
    assert_eq!(j.state.effects.len(), 1);
}
#[test]
fn verified_intent_before_images_can_cancel_without_target_changes() {
    let f = Fixture::new();
    write_new(&f.prefix.join("current.json"), b"old").unwrap();
    let mut j = f.journal();
    j.state.pending = Some(Replacement {
        file: MetadataFile::Current,
        before_sha256: Some(hash(b"old")),
        after_sha256: hash(b"new"),
        artifact: format!("{}-current", j.state.seq),
    });
    j.save(end()).unwrap();
    drop(j);
    let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    j.reconcile_metadata(end()).unwrap();
    assert!(j.state.pending.is_none());
    assert!(j.state.effects.is_empty());
    assert_eq!(fs::read(f.prefix.join("current.json")).unwrap(), b"old");
}
#[test]
fn next_state_intent_promotes_only_consistent_one_step_sequence() {
    let f = Fixture::new();
    let j = f.journal();
    let mut next = j.state.clone();
    next.seq += 1;
    next.phase = Phase::Quiescing;
    write_new(
        &j.root.join("state.next.json"),
        &serde_json::to_vec(&next).unwrap(),
    )
    .unwrap();
    drop(j);
    let j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    assert_eq!(j.state.phase, Phase::Quiescing);
    assert!(!j.root.join("state.next.json").exists());
}
#[test]
fn corrupt_or_conflicting_state_slot_fails_closed() {
    let f = Fixture::new();
    let j = f.journal();
    write_new(&j.root.join("state.next.json"), b"broken").unwrap();
    drop(j);
    assert!(Journal::open(&f.prefix, &f.lock, end()).is_err());
    assert_eq!(
        fs::read(f.prefix.join("update/state.next.json")).unwrap(),
        b"broken"
    );
}
#[test]
fn changed_prefix_binding_and_unknown_fields_are_rejected() {
    let f = Fixture::new();
    let j = f.journal();
    let mut state = j.state.clone();
    state.prefix_binding = "other_root".into();
    fs::write(
        j.root.join("state.json"),
        serde_json::to_vec(&state).unwrap(),
    )
    .unwrap();
    drop(j);
    assert!(Journal::open(&f.prefix, &f.lock, end()).is_err());
    let mut value = serde_json::to_value(state).unwrap();
    value["unknown"] = true.into();
    assert!(serde_json::from_value::<State>(value).is_err());
}
#[test]
fn backup_and_effect_locators_cannot_escape_owned_run() {
    let f = Fixture::new();
    let mut state = state(f.catalog.clone());
    state.backup = Some(BackupReference {
        id: "backup".into(),
        relative_locator: "../source-history".into(),
        digest: "e".repeat(64),
        size_bytes: 1,
        catalog_incarnation: "catalog_one".into(),
        catalog_generation: 14,
        schema: state.checkpoint.catalog_schema,
    });
    assert!(state.validate().is_err());
}
#[cfg(unix)]
#[test]
fn linked_state_is_never_followed() {
    use std::os::unix::fs::symlink;
    let f = Fixture::new();
    let j = f.journal();
    let external = f._temp.path().join("external");
    fs::write(&external, b"private external").unwrap();
    fs::remove_file(j.root.join("state.json")).unwrap();
    symlink(&external, j.root.join("state.json")).unwrap();
    drop(j);
    assert!(Journal::open(&f.prefix, &f.lock, end()).is_err());
    assert_eq!(fs::read(external).unwrap(), b"private external");
}

fn inject(point: Fault) {
    INJECTED_FAULT.with(|slot| {
        assert!(slot.get().is_none());
        slot.set(Some(point));
    });
}
fn set_quiesced(j: &mut Journal<'_>) {
    let mut checkpoint = j.state.checkpoint.clone();
    checkpoint.catalog_generation += 2;
    checkpoint.control_seq += 1;
    j.state.quiesced_checkpoint = Some(checkpoint);
    j.save(end()).unwrap();
}
fn backup_for(checkpoint: &Checkpoint) -> BackupReference {
    BackupReference {
        id: "backup_one".into(),
        relative_locator: "backups/backup_one/catalog.db".into(),
        digest: "e".repeat(64),
        size_bytes: 10,
        catalog_incarnation: checkpoint.catalog_incarnation.clone(),
        catalog_generation: checkpoint.catalog_generation,
        schema: checkpoint.catalog_schema,
    }
}
fn replace_intent(j: &mut Journal<'_>, before: &[u8], after: &[u8]) -> Replacement {
    let intent = Replacement {
        file: MetadataFile::Current,
        before_sha256: Some(hash(before)),
        after_sha256: hash(after),
        artifact: format!("{}-current", j.state.seq),
    };
    j.state.pending = Some(intent.clone());
    j.save(end()).unwrap();
    write_new(
        &j.run_root().join(format!("{}.before", intent.artifact)),
        before,
    )
    .unwrap();
    write_new(
        &j.run_root().join(format!("{}.new", intent.artifact)),
        after,
    )
    .unwrap();
    intent
}

#[test]
fn save_deadline_failure_stops_reuse_without_advancing_durable_sequence() {
    let f = Fixture::new();
    let mut j = f.journal();
    let durable = fs::read(j.root.join("state.json")).unwrap();
    j.state.error_code = Some("retry_needed".into());
    let error = j.save(Instant::now()).unwrap_err();
    assert_eq!(error.0.code, CanonicalCode::WriterBusy);
    assert!(j.poisoned());
    assert_eq!(j.state.seq, 1);
    assert_eq!(j.state.error_code, None);
    assert_eq!(fs::read(j.root.join("state.json")).unwrap(), durable);
    assert!(j.transition(Phase::Quiescing, end()).is_err());
    assert!(
        j.replace_metadata(MetadataFile::Current, b"never-published", end())
            .is_err()
    );
    assert!(!f.prefix.join("current.json").exists());
    drop(j);
    let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    j.transition(Phase::Quiescing, end()).unwrap();
    assert_eq!(j.state.seq, 2);
}

#[test]
fn failed_write_new_preserves_conflicting_slot_and_stops_reuse() {
    let f = Fixture::new();
    let mut j = f.journal();
    let before = fs::read(j.root.join("state.json")).unwrap();
    write_new(&j.root.join("state.next.json"), b"unrelated").unwrap();
    assert!(j.transition(Phase::Quiescing, end()).is_err());
    assert!(j.poisoned());
    assert_eq!(fs::read(j.root.join("state.json")).unwrap(), before);
    assert_eq!(
        fs::read(j.root.join("state.next.json")).unwrap(),
        b"unrelated"
    );
    assert!(j.reconcile_metadata(end()).is_err());
}

#[test]
fn interrupted_save_requires_reopen_even_if_publication_already_happened() {
    for point in [Fault::StateIntent, Fault::StatePublished] {
        let f = Fixture::new();
        let mut j = f.journal();
        inject(point);
        assert!(j.transition(Phase::Quiescing, end()).is_err());
        assert!(j.poisoned());
        assert_eq!(j.state.phase, Phase::Verified);
        assert_eq!(j.state.seq, 1);
        assert!(j.save(end()).is_err());
        drop(j);
        let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
        assert_eq!(j.state.phase, Phase::Quiescing);
        assert_eq!(j.state.seq, 2);
        assert!(!j.poisoned());
        for path in state_paths(&j.root).iter().skip(1) {
            assert!(!path.exists());
        }
        j.save(end()).unwrap();
        assert_eq!(j.state.seq, 3);
    }
}

#[test]
fn adjacent_sequence_cannot_replace_immutable_identity_or_skip_phase() {
    for changed in 0..10 {
        let f = Fixture::new();
        let j = f.journal();
        let current = fs::read(j.root.join("state.json")).unwrap();
        let mut next = j.state.clone();
        next.seq += 1;
        match changed {
            0 => next.checkpoint.installation_id = "different_installation".into(),
            1 => next.checkpoint.control_seq += 1,
            2 => next.checkpoint.catalog_generation += 1,
            3 => next.checkpoint.catalog_incarnation = "different_catalog".into(),
            4 => next.checkpoint.desired_updates = "running".into(),
            5 => next.catalog = f._temp.path().join("different.db"),
            6 => next.archive_sha256 = "a".repeat(64),
            7 => next.new.source_commit = "b".repeat(40),
            8 => next.stable_launcher_sha256 = "b".repeat(64),
            _ => next.phase = Phase::Attention,
        }
        next.validate().unwrap();
        let bytes = serde_json::to_vec(&next).unwrap();
        write_new(&j.root.join("state.next.json"), &bytes).unwrap();
        let root = j.root.clone();
        drop(j);
        assert!(
            Journal::open(&f.prefix, &f.lock, end()).is_err(),
            "case {changed}"
        );
        assert_eq!(fs::read(root.join("state.json")).unwrap(), current);
        assert_eq!(fs::read(root.join("state.next.json")).unwrap(), bytes);
    }
}

#[test]
fn save_does_not_allow_initial_checkpoint_changes_or_caller_sequence_override() {
    for change_sequence in [false, true] {
        let f = Fixture::new();
        let mut j = f.journal();
        let bytes = fs::read(j.root.join("state.json")).unwrap();
        if change_sequence {
            j.state.seq += 1;
        } else {
            j.state.checkpoint.catalog_generation += 1;
        }
        assert!(j.save(end()).is_err());
        assert!(j.poisoned());
        assert_eq!(fs::read(j.root.join("state.json")).unwrap(), bytes);
        assert!(!j.root.join("state.next.json").exists());
    }
}

#[test]
fn quiesced_checkpoint_is_once_only_monotonic_and_binds_backup() {
    let f = Fixture::new();
    let mut j = f.journal();
    let initial = j.state.checkpoint.clone();
    assert!(j.state.quiesced_checkpoint.is_none());
    j.transition(Phase::Quiescing, end()).unwrap();
    set_quiesced(&mut j);
    let checkpoint = j.state.quiesced_checkpoint.clone().unwrap();
    assert_eq!(j.state.checkpoint, initial);
    assert!(checkpoint.catalog_generation > initial.catalog_generation);
    j.state.backup = Some(backup_for(&checkpoint));
    j.transition(Phase::BackedUp, end()).unwrap();
    drop(j);
    let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    assert_eq!(j.state.quiesced_checkpoint.as_ref(), Some(&checkpoint));
    let bytes = fs::read(j.root.join("state.json")).unwrap();
    j.state
        .quiesced_checkpoint
        .as_mut()
        .unwrap()
        .catalog_generation += 1;
    j.state.backup.as_mut().unwrap().catalog_generation += 1;
    assert!(j.save(end()).is_err());
    assert_eq!(fs::read(j.root.join("state.json")).unwrap(), bytes);
    assert_eq!(j.state.quiesced_checkpoint, Some(checkpoint));
}

#[test]
fn invalid_quiesced_identity_counters_and_backup_mismatch_fail_before_write() {
    for changed in 0..8 {
        let f = Fixture::new();
        let mut j = f.journal();
        j.transition(Phase::Quiescing, end()).unwrap();
        let bytes = fs::read(j.root.join("state.json")).unwrap();
        let mut checkpoint = j.state.checkpoint.clone();
        match changed {
            0 => checkpoint.installation_id = "other_installation".into(),
            1 => checkpoint.catalog_incarnation = "other_catalog".into(),
            2 => checkpoint.catalog_schema += 1,
            3 => checkpoint.catalog_generation -= 1,
            4 => checkpoint.control_seq -= 1,
            5 => checkpoint.policy_epoch -= 1,
            6 => checkpoint.control_seq = u64::MAX,
            _ => checkpoint.desired_updates = "unknown".into(),
        }
        j.state.quiesced_checkpoint = Some(checkpoint);
        assert!(j.save(end()).is_err(), "case {changed}");
        assert_eq!(fs::read(j.root.join("state.json")).unwrap(), bytes);
    }
    let f = Fixture::new();
    let mut j = f.journal();
    j.transition(Phase::Quiescing, end()).unwrap();
    set_quiesced(&mut j);
    let bytes = fs::read(j.root.join("state.json")).unwrap();
    let mut backup = backup_for(j.state.quiesced_checkpoint.as_ref().unwrap());
    backup.catalog_generation -= 1;
    j.state.backup = Some(backup);
    assert!(j.transition(Phase::BackedUp, end()).is_err());
    assert_eq!(fs::read(j.root.join("state.json")).unwrap(), bytes);
}

#[test]
fn backward_compatible_options_are_defaulted_but_post_backup_requires_checkpoint() {
    let f = Fixture::new();
    let j = Journal::create(
        &f.prefix,
        &f.lock,
        historical_state(f.catalog.clone()),
        end(),
    )
    .unwrap();
    let mut value = serde_json::to_value(&j.state).unwrap();
    value.as_object_mut().unwrap().remove("quiesced_checkpoint");
    value
        .as_object_mut()
        .unwrap()
        .remove("native_binding_sha256");
    let old: State = serde_json::from_value(value).unwrap();
    old.validate().unwrap();
    assert!(old.quiesced_checkpoint.is_none());
    assert!(old.native_binding_sha256.is_none());
    assert_eq!(old.old.catalog_schema, HISTORICAL_CATALOG_SCHEMA);
    assert_eq!(old.new.catalog_schema, HISTORICAL_CATALOG_SCHEMA);
    assert_eq!(old.checkpoint.catalog_schema, HISTORICAL_CATALOG_SCHEMA);
    let mut progressed = old;
    progressed.phase = Phase::BackedUp;
    progressed.backup = Some(backup_for(&progressed.checkpoint));
    assert!(progressed.validate().is_err());
}

#[test]
fn historical_journal_schema_and_checkpoint_survive_reopen_without_rekeying() {
    let f = Fixture::new();
    let mut j = Journal::create(
        &f.prefix,
        &f.lock,
        historical_state(f.catalog.clone()),
        end(),
    )
    .unwrap();
    let initial = j.state.checkpoint.clone();
    j.transition(Phase::Quiescing, end()).unwrap();
    set_quiesced(&mut j);
    j.state.backup = Some(backup_for(j.state.quiesced_checkpoint.as_ref().unwrap()));
    j.transition(Phase::BackedUp, end()).unwrap();
    let expected = j.state.clone();
    drop(j);
    let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    assert_eq!(j.state, expected);
    assert_eq!(j.state.checkpoint, initial);
    assert_eq!(
        j.state.backup.as_ref().unwrap().schema,
        HISTORICAL_CATALOG_SCHEMA
    );
    let durable = fs::read(j.root.join("state.json")).unwrap();
    // Even a consistent schema substitution is a change to immutable identity.
    j.state.old.catalog_schema = current_catalog_schema();
    j.state.new.catalog_schema = current_catalog_schema();
    j.state.checkpoint.catalog_schema = current_catalog_schema();
    j.state.quiesced_checkpoint.as_mut().unwrap().catalog_schema = current_catalog_schema();
    j.state.backup.as_mut().unwrap().schema = current_catalog_schema();
    j.state.validate().unwrap();
    assert!(j.save(end()).is_err());
    assert!(j.poisoned());
    assert_eq!(j.state, expected);
    assert_eq!(fs::read(j.root.join("state.json")).unwrap(), durable);
}
#[test]
fn native_digest_is_bound_once_in_verified_and_never_binds_unconfirmed_file() {
    let f = Fixture::new();
    let j = f.journal();
    write_new(&j.run_root().join("native-binding.json"), b"bounded-intent").unwrap();
    drop(j);
    let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    assert!(j.state.native_binding_sha256.is_none());
    j.state.native_binding_sha256 = Some(hash(b"bounded-intent"));
    j.save(end()).unwrap();
    let bytes = fs::read(j.root.join("state.json")).unwrap();
    j.state.native_binding_sha256 = Some("a".repeat(64));
    assert!(j.save(end()).is_err());
    assert_eq!(fs::read(j.root.join("state.json")).unwrap(), bytes);
    drop(j);
    let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    j.state.native_binding_sha256 = None;
    assert!(j.save(end()).is_err());
    drop(j);
    let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    j.transition(Phase::Quiescing, end()).unwrap();
    j.transition(Phase::Failed, end()).unwrap();
    assert!(j.state.native_binding_sha256.is_some());
    assert!(j.save(end()).is_err());
}

#[test]
fn digest_cannot_be_first_bound_after_effect_and_malformed_digest_is_rejected() {
    let f = Fixture::new();
    let mut j = f.journal();
    j.replace_metadata(MetadataFile::Current, b"owned", end())
        .unwrap();
    j.state.native_binding_sha256 = Some(hash(b"intent"));
    assert!(j.save(end()).is_err());
    let mut malformed = state(f.catalog.clone());
    malformed.native_binding_sha256 = Some("A".repeat(64));
    assert!(malformed.validate().is_err());
}

#[test]
fn interrupted_reconcile_reuses_validated_reconcile_and_old_slots() {
    for point in [Fault::ReconcileIntent, Fault::ReconcilePublished] {
        let f = Fixture::new();
        let j = f.journal();
        let mut next = j.state.clone();
        next.seq += 1;
        next.phase = Phase::Quiescing;
        write_new(
            &j.root.join("state.next.json"),
            &serde_json::to_vec(&next).unwrap(),
        )
        .unwrap();
        drop(j);
        inject(point);
        assert!(Journal::open(&f.prefix, &f.lock, end()).is_err());
        let j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
        assert_eq!(j.state, next);
        for path in state_paths(&j.root).iter().skip(1) {
            assert!(!path.exists());
        }
    }
}

#[test]
fn corrupt_reconcile_slot_is_not_ignored_or_deleted() {
    let f = Fixture::new();
    let j = f.journal();
    write_new(&j.root.join("state.reconcile.json"), b"unverified").unwrap();
    let current = fs::read(j.root.join("state.json")).unwrap();
    drop(j);
    assert!(Journal::open(&f.prefix, &f.lock, end()).is_err());
    assert_eq!(
        fs::read(f.prefix.join("update/state.json")).unwrap(),
        current
    );
    assert_eq!(
        fs::read(f.prefix.join("update/state.reconcile.json")).unwrap(),
        b"unverified"
    );
}

#[test]
fn interrupted_terminal_archive_finishes_without_resurrecting_previous_phase() {
    for point in [
        Fault::ArchiveIntent,
        Fault::ArchivePublished,
        Fault::ArchiveCleaned,
    ] {
        let f = Fixture::new();
        let mut j = f.journal();
        j.transition(Phase::Failed, end()).unwrap();
        let terminal = j.state.clone();
        let archive = j.run_root().join("completed-state.json");
        drop(j);
        inject(point);
        assert!(Journal::archive_terminal(&f.prefix, &f.lock, end()).is_err());
        Journal::archive_terminal(&f.prefix, &f.lock, end()).unwrap();
        let actual: State = serde_json::from_slice(&fs::read(&archive).unwrap()).unwrap();
        assert_eq!(actual, terminal);
        assert!(!f.prefix.join("update/state.json").exists());
        assert!(!f.prefix.join("update/state.archive.json").exists());
        let mut next = state(f.catalog.clone());
        next.update_id = "update_two".into();
        let next = Journal::create(&f.prefix, &f.lock, next, end()).unwrap();
        assert_eq!(next.state.phase, Phase::Verified);
    }
}

#[test]
fn supersede_recovery_always_exposes_one_complete_update_journal() {
    for point in [
        Fault::SupersedeIntentStaged,
        Fault::SupersedeIntent,
        Fault::SupersedeStaged,
        Fault::SupersedePublished,
        Fault::SupersedeArchiveStaged,
        Fault::SupersedeArchived,
        Fault::SupersedeCleaned,
    ] {
        let f = Fixture::new();
        let mut j = f.journal();
        j.transition(Phase::Failed, end()).unwrap();
        let terminal = j.state.clone();
        drop(j);

        let mut next = state(f.catalog.clone());
        next.update_id = "update_two".into();
        inject(point);
        assert!(Journal::create_after_terminal(&f.prefix, &f.lock, next, end()).is_err());

        let j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
        let published = matches!(
            point,
            Fault::SupersedePublished
                | Fault::SupersedeArchiveStaged
                | Fault::SupersedeArchived
                | Fault::SupersedeCleaned
        );
        if published {
            assert_eq!(j.state.update_id, "update_two");
            assert_eq!(j.state.phase, Phase::Verified);
            assert!(
                j.root
                    .join(&terminal.update_id)
                    .join("completed-state.json")
                    .exists()
            );
        } else {
            assert_eq!(j.state, terminal);
            assert!(!j.root.join("update_two").exists());
        }
        assert!(!j.root.join("state.supersede.json").exists());
        assert!(!j.root.join("state.supersede.intent.next.json").exists());
        assert!(!j.root.join("state.supersede.next.json").exists());
        assert!(!j.root.join("state.supersede.displaced.json").exists());
        assert!(
            !j.root
                .join(&terminal.update_id)
                .join("completed-state.next.json")
                .exists()
        );
    }
}

#[test]
fn supersede_recovery_handles_exchange_left_in_the_next_slot() {
    let f = Fixture::new();
    let mut j = f.journal();
    j.transition(Phase::Failed, end()).unwrap();
    let terminal = j.state.clone();
    let old_bytes = serde_json::to_vec(&terminal).unwrap();
    let root = j.root.clone();
    let current = root.join("state.json");
    drop(j);

    let mut next = state(f.catalog.clone());
    next.update_id = "update_two".into();
    next.seq = 1;
    next.prefix_binding = f.lock.root_identity().control_id().as_str().into();
    next.validate().unwrap();
    let new_bytes = serde_json::to_vec(&next).unwrap();
    let intent = SupersedeIntent {
        schema: SUPERSEDE_SCHEMA.into(),
        old_update_id: terminal.update_id.clone(),
        new_update_id: next.update_id.clone(),
        old_sha256: hash(&old_bytes),
        new_sha256: hash(&new_bytes),
        old_bytes_hex: bytes_hex(&old_bytes),
        new_bytes_hex: bytes_hex(&new_bytes),
    };
    write_new(
        &supersede_intent_path(&root),
        &serde_json::to_vec(&intent).unwrap(),
    )
    .unwrap();
    platform::create_private_directory(&root.join(&next.update_id)).unwrap();
    write_new(&supersede_next_path(&root), &new_bytes).unwrap();
    let displaced = supersede_displaced_path(&root);
    publish(&current, &supersede_next_path(&root), &displaced).unwrap();

    // Unix exchange is complete once `state.json` is new. A process may stop
    // before the exchanged old image is moved from `next` to `displaced`.
    remove_matching(&displaced, &old_bytes, MAX_STATE).unwrap();
    write_new(&supersede_next_path(&root), &old_bytes).unwrap();

    let j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    assert_eq!(j.state.update_id, "update_two");
    assert_eq!(j.state.phase, Phase::Verified);
    assert_eq!(
        read(
            &supersede_archive_path(&j.root.join(&terminal.update_id)),
            MAX_STATE
        )
        .unwrap()
        .unwrap(),
        old_bytes
    );
    assert!(!supersede_intent_path(&root).exists());
    assert!(!supersede_next_path(&root).exists());
    assert!(!displaced.exists());
}

#[test]
fn supersede_preflight_preserves_a_conflicting_old_archive() {
    let f = Fixture::new();
    let mut j = f.journal();
    j.transition(Phase::Failed, end()).unwrap();
    let terminal = j.state.clone();
    let current = read(&j.root.join("state.json"), MAX_STATE)
        .unwrap()
        .unwrap();
    let archive = supersede_archive_path(&j.run_root());
    write_new(&archive, b"unrelated archive").unwrap();
    drop(j);

    let mut next = state(f.catalog.clone());
    next.update_id = "update_two".into();
    assert!(Journal::create_after_terminal(&f.prefix, &f.lock, next, end()).is_err());
    assert_eq!(
        read(&f.prefix.join("update/state.json"), MAX_STATE)
            .unwrap()
            .unwrap(),
        current
    );
    assert_eq!(fs::read(archive).unwrap(), b"unrelated archive");
    assert!(!f.prefix.join("update/update_two").exists());
    let j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    assert_eq!(j.state, terminal);
}

#[test]
fn create_reconciles_archive_after_terminal_name_was_already_moved() {
    let f = Fixture::new();
    let mut j = f.journal();
    j.transition(Phase::Failed, end()).unwrap();
    let archive = j.run_root().join("completed-state.json");
    drop(j);
    inject(Fault::ArchivePublished);
    assert!(Journal::archive_terminal(&f.prefix, &f.lock, end()).is_err());
    let mut next = state(f.catalog.clone());
    next.update_id = "update_two".into();
    let j = Journal::create(&f.prefix, &f.lock, next, end()).unwrap();
    assert_eq!(j.state.update_id, "update_two");
    assert!(archive.exists());
    assert!(!j.root.join("state.archive.json").exists());
}

#[test]
fn terminal_archive_preserves_conflicting_existing_archive() {
    let f = Fixture::new();
    let mut j = f.journal();
    j.transition(Phase::Failed, end()).unwrap();
    let archive = j.run_root().join("completed-state.json");
    write_new(&archive, b"unrelated archive").unwrap();
    drop(j);
    assert!(Journal::archive_terminal(&f.prefix, &f.lock, end()).is_err());
    assert_eq!(fs::read(archive).unwrap(), b"unrelated archive");
    assert!(f.prefix.join("update/state.json").exists());
}

#[test]
fn published_metadata_ack_failure_reopens_without_replacing_target_twice() {
    let f = Fixture::new();
    write_new(&f.prefix.join("current.json"), b"old").unwrap();
    let mut j = f.journal();
    inject(Fault::MetadataPublished);
    assert!(
        j.replace_metadata(MetadataFile::Current, b"new", end())
            .is_err()
    );
    assert!(j.poisoned());
    assert!(j.state.pending.is_some());
    let identity =
        platform::identity(&platform::open_file(&f.prefix.join("current.json")).unwrap()).unwrap();
    assert!(j.restore_metadata(end()).is_err());
    drop(j);
    let mut j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    j.reconcile_metadata(end()).unwrap();
    assert_eq!(
        platform::identity(&platform::open_file(&f.prefix.join("current.json")).unwrap()).unwrap(),
        identity
    );
    assert_eq!(j.state.effects.len(), 1);
    assert!(j.state.pending.is_none());
}

#[test]
fn displaced_third_image_is_preserved_before_and_after_publication() {
    for published in [false, true] {
        let f = Fixture::new();
        write_new(&f.prefix.join("current.json"), b"old").unwrap();
        let mut j = f.journal();
        let intent = replace_intent(&mut j, b"old", b"new");
        let displaced = j.run_root().join(format!("{}.displaced", intent.artifact));
        if published {
            publish(
                &f.prefix.join("current.json"),
                &j.run_root().join(format!("{}.new", intent.artifact)),
                &displaced,
            )
            .unwrap();
            fs::write(&displaced, b"third image").unwrap();
        } else {
            write_new(&displaced, b"third image").unwrap();
        }
        let target = fs::read(f.prefix.join("current.json")).unwrap();
        let durable = fs::read(j.root.join("state.json")).unwrap();
        assert!(j.reconcile_metadata(end()).is_err());
        assert!(j.poisoned());
        assert_eq!(fs::read(&displaced).unwrap(), b"third image");
        assert_eq!(fs::read(f.prefix.join("current.json")).unwrap(), target);
        assert_eq!(fs::read(j.root.join("state.json")).unwrap(), durable);
    }
}

#[test]
fn equal_metadata_images_and_repeated_restore_keep_original_hash_chain() {
    let f = Fixture::new();
    write_new(&f.prefix.join("current.json"), b"original").unwrap();
    let mut j = f.journal();
    j.replace_metadata(MetadataFile::Current, b"original", end())
        .unwrap();
    j.replace_metadata(MetadataFile::Current, b"updated", end())
        .unwrap();
    j.restore_metadata(end()).unwrap();
    let count = j.state.effects.len();
    j.restore_metadata(end()).unwrap();
    assert_eq!(j.state.effects.len(), count);
    assert_eq!(
        fs::read(f.prefix.join("current.json")).unwrap(),
        b"original"
    );
    assert_eq!(
        j.replacements().unwrap()[0].1.as_deref(),
        Some(b"original".as_slice())
    );
    drop(j);
    let j = Journal::open(&f.prefix, &f.lock, end()).unwrap();
    assert_eq!(j.state.effects.len(), count);
}
