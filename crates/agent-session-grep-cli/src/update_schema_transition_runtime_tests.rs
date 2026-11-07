use super::*;
use crate::update_schema_transition::{
    ADMISSION_SCHEMA, GUARD_SCHEMA, MODE,
    state::records::{Component, PreimageManifest},
    tests::admission_value,
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, ffi::OsString, fs, time::Duration};

// All evidence is synthetic. These tests exercise the production native
// publication receiver; they do not stand in for real package/channel or SQL
// admission, old-executable refusal, or schema activation.
struct Fixture {
    prefix_lock: ExclusiveGuard,
    control_lock: ExclusiveGuard,
    owner_lock: ExclusiveGuard,
    prefix: PathBuf,
    control: PathBuf,
    run: PathBuf,
    invocation: Invocation,
    admission: AdmissionV2,
    initial: Vec<u8>,
    end: Instant,
    _temp: tempfile::TempDir,
}

#[derive(Debug, PartialEq, Eq)]
enum InventoryEntry {
    Directory {
        identity: (u64, u128),
    },
    HeldLock {
        identity: (u64, u128),
        size: u64,
        modified: std::time::SystemTime,
        readonly: bool,
    },
    File(Vec<u8>),
}

fn private(path: &Path) {
    assert!(platform::create_private_directory(path).unwrap());
}

fn write(path: &Path, raw: &[u8]) {
    let mut file = platform::create_file(path).unwrap();
    file.write_all(raw).unwrap();
    file.sync_all().unwrap();
}

fn initial(admission: &AdmissionV2) -> StateV2 {
    let image = |control: bool| {
        let suffix = &admission.record.update_id["update_".len()..];
        let (role, id, name) = if control {
            (
                "control_preimage",
                format!("transition_control_{suffix}"),
                "control.db",
            )
        } else {
            (
                "catalog_preimage",
                format!("transition_catalog_{suffix}"),
                "catalog.db",
            )
        };
        json!({
            "role":role,"artifact_id":id,"root_binding":admission.record.control_root.identity,
            "relative_locator":format!("backups/{id}/{name}"),"coverage_ref":null,
            "parent":{"kind":"absent_under_bound_root"},"image":{"kind":"absent"},
            "manifest":{"kind":"absent"},
            "sidecars":{"wal":{"kind":"absent"},"shm":{"kind":"absent"},"journal":{"kind":"absent"}}
        })
    };
    let value = json!({
        "schema":"asg.update-state/v2","mode":MODE,
        "update_id":admission.record.update_id,"owner_nonce":admission.record.owner_nonce,
        "prefix_binding":admission.record.prefix.identity,
        "control_binding":admission.record.control_root.identity,
        "admission_sha256":sha256(admission.raw_bytes()),
        "seq":1,"predecessor_sha256":null,"phase":{"kind":"verified"},"quiesced":null,
        "preimages":{"catalog":image(false),"control":image(true)},"stage":{"kind":"unstarted"},
        "catalog_component":{"kind":"unstarted"},"control_component":{"kind":"unstarted"},
        "metadata":{"slots":vec![json!({"kind":"untouched"});16]},
        "forward_pair_readback":null,"self_check":null,"requests_open_intent":null,
        "rollback":null,"pending":null,"last_failure":null
    });
    canonical(&value, admission)
}

fn canonical(value: &Value, admission: &AdmissionV2) -> StateV2 {
    let state = StateV2::decode(&serde_json::to_vec(value).unwrap(), admission).unwrap();
    StateV2::decode(&state.encode(admission).unwrap(), admission).unwrap()
}

impl Fixture {
    fn new() -> Self {
        let end = Instant::now() + Duration::from_secs(30);
        let temp = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(temp.path()).unwrap();
        let prefix = root.join("install");
        let control = root.join("data");
        let incoming = root.join("incoming");
        for path in [&prefix, &control, &incoming] {
            private(path);
        }
        let prefix_lock = ExclusiveGuard::try_acquire(
            &prefix,
            LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap()),
        )
        .unwrap();
        let control_lock = ExclusiveGuard::try_acquire(&control, LockKind::ControlHandles).unwrap();
        let owner_lock = ExclusiveGuard::try_acquire(&control, LockKind::PolicyOwner).unwrap();
        let mut admission = admission_value(&root);
        admission["schema"] = json!(ADMISSION_SCHEMA);
        admission["prefix"]["identity"] = json!(prefix_lock.root_identity().control_id().as_str());
        admission["control_root"]["identity"] =
            json!(control_lock.root_identity().control_id().as_str());
        admission["incoming_root"]["identity"] =
            json!(RootIdentity::read(&incoming).unwrap().control_id().as_str());
        let admission = AdmissionV2::decode(&serde_json::to_vec(&admission).unwrap()).unwrap();
        let admission = AdmissionV2::decode(&admission.encode().unwrap()).unwrap();
        let initial = initial(&admission).raw_bytes().to_vec();
        let update = prefix.join("update");
        let run = update.join(&admission.record.update_id);
        private(&update);
        private(&run);
        write(&run.join("admission.json"), admission.raw_bytes());
        write(&run.join("state.initial.json"), &initial);
        let guard = json!({
            "schema":GUARD_SCHEMA,"mode":MODE,"update_id":admission.record.update_id,
            "owner_nonce":admission.record.owner_nonce,
            "prefix_binding":admission.record.prefix.identity,
            "admission_sha256":sha256(admission.raw_bytes()),
            "initial_state_sha256":sha256(&initial)
        });
        write(&update.join(GUARD), &serde_json::to_vec(&guard).unwrap());
        write(&update.join(ACTIVE), &initial);
        // Sentinels are never opened by the publication receiver.
        write(&control.join("catalog.db"), b"synthetic catalog unchanged");
        write(&control.join("control.db"), b"synthetic control unchanged");
        let invocation = Invocation::parse(&[
            OsString::from("__asg-schema-transition"),
            "--mode".into(),
            MODE.into(),
            "--action".into(),
            "continue".into(),
            "--install-prefix".into(),
            prefix.as_os_str().to_owned(),
            "--control-root".into(),
            control.as_os_str().to_owned(),
            "--db".into(),
            control.join("catalog.db").into_os_string(),
            "--update-id".into(),
            admission.record.update_id.clone().into(),
        ])
        .unwrap();
        Self {
            prefix_lock,
            control_lock,
            owner_lock,
            prefix,
            control,
            run,
            invocation,
            admission,
            initial,
            end,
            _temp: temp,
        }
    }

    fn locks(&self) -> JournalLocks<'_> {
        JournalLocks::new(&self.prefix_lock, &self.control_lock, &self.owner_lock).unwrap()
    }

    fn open(&self) -> Journal<'_> {
        self.invocation
            .open_bound_journal(self.locks(), self.end)
            .unwrap()
    }

    fn states(&self) -> (StateV2, StateV2) {
        let before = StateV2::decode(&self.initial, &self.admission).unwrap();
        let mut after: Value = serde_json::from_slice(before.raw_bytes()).unwrap();
        after["seq"] = json!(2);
        after["predecessor_sha256"] = json!(sha256(before.raw_bytes()));
        after["phase"] = json!({"kind":"attention","resume":"verified","failed_seq":1});
        after["last_failure"] = json!({"at_seq":1,"code":"io","effect":null});
        (before, canonical(&after, &self.admission))
    }

    fn inventory(&self) -> BTreeMap<PathBuf, InventoryEntry> {
        fn visit(
            path: &Path,
            held_locks: &[PathBuf; 3],
            files: &mut BTreeMap<PathBuf, InventoryEntry>,
        ) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                let metadata = fs::symlink_metadata(&path).unwrap();
                assert!(!metadata.file_type().is_symlink());
                let observed = if metadata.is_dir() {
                    let file = platform::directory(&path).unwrap();
                    let native = identity(&file).unwrap();
                    visit(&path, held_locks, files);
                    InventoryEntry::Directory {
                        identity: (native.volume, native.file),
                    }
                } else {
                    assert!(metadata.is_file());
                    if held_locks.contains(&path) {
                        // Only these three actual held rendezvous leafs have
                        // unreadable byte ranges on Windows. Opening a handle
                        // for identity/metadata neither reads nor unlocks them.
                        let file = platform::open_file(&path).unwrap();
                        let native = identity(&file).unwrap();
                        let metadata = file.metadata().unwrap();
                        assert!(metadata.is_file());
                        InventoryEntry::HeldLock {
                            identity: (native.volume, native.file),
                            size: metadata.len(),
                            modified: metadata.modified().unwrap(),
                            readonly: metadata.permissions().readonly(),
                        }
                    } else {
                        // All other files, including other .lock names and
                        // every DB/WAL/journal/proof, remain exact byte oracles.
                        InventoryEntry::File(fs::read(&path).unwrap())
                    }
                };
                assert!(files.insert(path, observed).is_none());
            }
        }
        assert_eq!(
            self.prefix_lock.kind(),
            &LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap())
        );
        assert_eq!(self.control_lock.kind(), &LockKind::ControlHandles);
        assert_eq!(self.owner_lock.kind(), &LockKind::PolicyOwner);
        // LockKind::filename hex-encodes MaintenanceJob's exact UTF-8 key.
        // RootDirectory::open_lock places all three leafs directly under root.
        let held_locks = [
            self.prefix
                .join("maintenance-job-696e7374616c6c6174696f6e2d757064617465.lock"),
            self.control.join("control-handles.lock"),
            self.control.join("policy-owner.lock"),
        ];
        let mut files = BTreeMap::new();
        visit(&self.prefix, &held_locks, &mut files);
        visit(&self.control, &held_locks, &mut files);
        for path in held_locks {
            assert!(matches!(
                files.get(&path),
                Some(InventoryEntry::HeldLock { .. })
            ));
        }
        self.prefix_lock.validate_current(&self.prefix).unwrap();
        self.control_lock.validate_current(&self.control).unwrap();
        self.owner_lock.validate_current(&self.control).unwrap();
        files
    }
}

fn no_records() -> SuccessorEvidence<'static> {
    SuccessorEvidence {
        previous: RecordSet {
            proofs: &[],
            manifests: &[],
        },
        current: RecordSet {
            proofs: &[],
            manifests: &[],
        },
        effect_readback: None,
    }
}

fn coverage_next(f: &Fixture, before: &StateV2) -> (StateV2, ProofRecord) {
    // Literal struct-field wire order from the independent closed contract.
    let raw = format!(
        "{{\"schema\":\"asg.schema-transition-coverage/v1\",\"mode\":\"{MODE}\",\
        \"update_id\":\"{}\",\"owner_nonce\":\"{}\",\"admission_sha256\":\"{}\",\
        \"source_ids\":[\"source_a\",\"source_b\"]}}",
        f.admission.record.update_id,
        f.admission.record.owner_nonce,
        sha256(f.admission.raw_bytes()),
    );
    let proof = ProofRecord::decode(RecordSlot::Coverage, raw.as_bytes(), &f.admission).unwrap();
    let reference: Value = serde_json::from_slice(&proof.reference_bytes().unwrap()).unwrap();
    let mut next: Value = serde_json::from_slice(before.raw_bytes()).unwrap();
    next["seq"] = json!(2);
    next["predecessor_sha256"] = json!(sha256(before.raw_bytes()));
    next["preimages"]["catalog"]["coverage_ref"] = reference.clone();
    next["preimages"]["control"]["coverage_ref"] = reference;
    (canonical(&next, &f.admission), proof)
}

fn wire(fields: &[(&str, String)]) -> String {
    format!(
        "{{{}}}",
        fields
            .iter()
            .map(|(key, raw)| format!("{}:{raw}", serde_json::to_string(key).unwrap()))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn quoted(value: impl serde::Serialize) -> String {
    serde_json::to_string(&value).unwrap()
}

fn identity_wire(file: &File) -> String {
    let native = identity(file).unwrap();
    if cfg!(windows) {
        use std::fmt::Write;
        let mut file_id = String::with_capacity(32);
        for byte in native.file.to_le_bytes() {
            write!(&mut file_id, "{byte:02x}").unwrap();
        }
        wire(&[
            ("kind", quoted("windows")),
            ("volume", native.volume.to_string()),
            ("file_id", quoted(file_id)),
        ])
    } else {
        wire(&[
            ("kind", quoted("unix")),
            ("device", native.volume.to_string()),
            ("inode", native.file.to_string()),
        ])
    }
}

fn stamp_wire(path: &Path) -> String {
    let file = platform::open_file(path).unwrap();
    let bytes = fs::read(path).unwrap();
    wire(&[
        ("identity", identity_wire(&file)),
        ("size_bytes", bytes.len().to_string()),
        ("blake3", quoted(blake3::hash(&bytes).to_hex().to_string())),
    ])
}

fn checkpoint_wire(f: &Fixture) -> String {
    wire(&[
        (
            "installation_id",
            quoted(&f.admission.record.installation_id),
        ),
        ("schema", "2".into()),
        ("control_seq", "8".into()),
        ("policy_epoch", "3".into()),
        ("next_cycle_seq", "5".into()),
        ("catalog_incarnation", quoted("catalog_fixture")),
        ("restart_request_seq", "1".into()),
        ("desired_updates", quoted("paused")),
        ("autostart_enabled", "false".into()),
        ("supervisor_failed", "false".into()),
        (
            "maintenance",
            wire(&[
                ("state", quoted("updating")),
                ("owner", quoted(&f.admission.record.owner_nonce)),
                ("phase", quoted("self_checked")),
            ]),
        ),
        ("authority_blake3", quoted("3".repeat(64))),
        ("inventory_blake3", quoted("4".repeat(64))),
        ("runtime_blake3", quoted("5".repeat(64))),
    ])
}

fn record_wire(f: &Fixture, schema: &str, fields: Vec<(&str, String)>) -> Vec<u8> {
    let mut header = vec![
        ("schema", quoted(schema)),
        ("mode", quoted(MODE)),
        ("update_id", quoted(&f.admission.record.update_id)),
        ("owner_nonce", quoted(&f.admission.record.owner_nonce)),
        ("admission_sha256", quoted(sha256(f.admission.raw_bytes()))),
    ];
    header.extend(fields);
    wire(&header).into_bytes()
}

struct ManifestDeletion {
    before: StateV2,
    pending: StateV2,
    after: StateV2,
    proofs: Vec<ProofRecord>,
    manifests: Vec<PreimageManifest>,
    readback: Vec<u8>,
    path: PathBuf,
    original: Vec<u8>,
}

impl ManifestDeletion {
    fn new(f: &Fixture, component: Component) -> Self {
        let initial = StateV2::decode(&f.initial, &f.admission).unwrap();
        let (_, coverage) = coverage_next(f, &initial);
        let coverage_ref = String::from_utf8(coverage.reference_bytes().unwrap()).unwrap();
        let catalog_identity = wire(&[
            (
                "installation_id",
                quoted(&f.admission.record.installation_id),
            ),
            ("incarnation", quoted("catalog_fixture")),
            ("schema", "22".into()),
            ("generation", "14".into()),
            ("destructive_epoch", "2".into()),
        ]);
        let catalog_stamp = stamp_wire(&f.control.join("catalog.db"));
        let control_stamp = stamp_wire(&f.control.join("control.db"));
        let checkpoint = checkpoint_wire(f);
        let intent = record_wire(
            f,
            "asg.schema-transition-rollback/v1",
            vec![
                ("rollback_plan_sha256", "null".into()),
                ("restore_pair", quoted("not_needed")),
                ("R", "null".into()),
                (
                    "preimage_refs",
                    "{\"catalog\":null,\"control\":null}".into(),
                ),
                (
                    "live_pair_before",
                    wire(&[
                        ("catalog", catalog_stamp.clone()),
                        ("control", control_stamp.clone()),
                        ("catalog_identity", catalog_identity.clone()),
                        ("control_checkpoint", checkpoint.clone()),
                    ]),
                ),
                ("prepared_pair_after", "null".into()),
                ("compatible_control_checkpoint", checkpoint.clone()),
                ("owned_inventory_blake3", quoted("4".repeat(64))),
            ],
        );
        let intent =
            ProofRecord::decode(RecordSlot::RollbackIntent, &intent, &f.admission).unwrap();
        let pair = record_wire(
            f,
            "asg.schema-transition-rollback-pair-readback/v1",
            vec![
                ("rollback_intent_sha256", quoted(sha256(intent.raw_bytes()))),
                ("restore_pair", quoted("not_needed")),
                ("catalog", catalog_stamp),
                ("control", control_stamp),
                ("catalog_identity", catalog_identity),
                ("control_checkpoint", checkpoint.clone()),
                ("owned_inventory_blake3", quoted("4".repeat(64))),
            ],
        );
        let pair =
            ProofRecord::decode(RecordSlot::RollbackPairReadback, &pair, &f.admission).unwrap();
        let role = if component == Component::Catalog {
            "catalog"
        } else {
            "control"
        };
        let suffix = &f.admission.record.update_id["update_".len()..];
        let artifact = format!("transition_{role}_{suffix}");
        let backups = f.control.join("backups");
        private(&backups);
        let parent = backups.join(&artifact);
        private(&parent);
        let db = parent.join(format!("{role}.db"));
        write(&db, b"synthetic owned preimage");
        let db_stamp = stamp_wire(&db);
        let db_identity = identity_wire(&platform::open_file(&db).unwrap());
        let db_bytes = fs::read(&db).unwrap();
        let mut manifest = vec![
            (
                "schema",
                quoted(if component == Component::Catalog {
                    "asg.catalog-backup/v1"
                } else {
                    "asg.schema-transition-control-preimage/v1"
                }),
            ),
            ("backup_id", quoted(&artifact)),
            (
                "purpose",
                quoted(if component == Component::Catalog {
                    "beta_rollback"
                } else {
                    "schema_transition_rollback"
                }),
            ),
        ];
        if component == Component::Control {
            manifest.extend([
                ("update_id", quoted(&f.admission.record.update_id)),
                ("owner_nonce", quoted(&f.admission.record.owner_nonce)),
            ]);
        }
        manifest.push((
            "installation_id",
            quoted(&f.admission.record.installation_id),
        ));
        if component == Component::Control {
            manifest.extend([
                (
                    "control_root_binding",
                    quoted(&f.admission.record.control_root.identity),
                ),
                (
                    "catalog_root_binding",
                    quoted(&f.admission.record.control_root.identity),
                ),
                ("control_schema", "2".into()),
                ("control_checkpoint", checkpoint.clone()),
            ]);
        }
        manifest.extend([
            ("catalog_incarnation", quoted("catalog_fixture")),
            ("catalog_generation", "14".into()),
        ]);
        if component == Component::Catalog {
            manifest.push(("schema_version", "22".into()));
        }
        manifest.extend([
            (
                if component == Component::Catalog {
                    "digest"
                } else {
                    "digest_blake3"
                },
                quoted(blake3::hash(&db_bytes).to_hex().to_string()),
            ),
            ("size_bytes", db_bytes.len().to_string()),
            (
                "source_ids",
                if component == Component::Catalog {
                    "[\"source_a\"]".into()
                } else {
                    "[\"source_a\",\"source_b\"]".into()
                },
            ),
        ]);
        if component == Component::Control {
            manifest.push(("coverage_sha256", quoted(sha256(coverage.raw_bytes()))));
        }
        manifest.push(("created_at_ms", "1".into()));
        let original = wire(&manifest).into_bytes();
        let decoded = PreimageManifest::decode(component, &original, &f.admission).unwrap();
        let path = parent.join("manifest.json");
        write(&path, &original);
        let parent_identity = identity_wire(&platform::directory(&parent).unwrap());
        let image = |manifest| {
            wire(&[
            ("role", quoted(format!("{role}_preimage"))), ("artifact_id", quoted(&artifact)),
            ("root_binding", quoted(&f.admission.record.control_root.identity)),
            ("relative_locator", quoted(format!("backups/{artifact}/{role}.db"))),
            ("coverage_ref", coverage_ref.clone()),
            ("parent", wire(&[("kind", quoted("owned")), ("identity", parent_identity.clone())])),
            ("image", wire(&[
                ("kind", quoted("delete_intent")), ("identity", db_identity.clone()), ("stamp", db_stamp.clone()),
            ])),
            ("manifest", manifest),
            ("sidecars", "{\"wal\":{\"kind\":\"absent\"},\"shm\":{\"kind\":\"absent\"},\"journal\":{\"kind\":\"absent\"}}".into()),
        ])
        };
        let before_image = image(wire(&[
            ("kind", quoted("complete")),
            ("stamp", stamp_wire(&path)),
        ]));
        let after_image = image("{\"kind\":\"absent\"}".into());
        let mut before: Value = serde_json::from_slice(&f.initial).unwrap();
        before["seq"] = json!(10);
        before["predecessor_sha256"] = json!("a".repeat(64));
        before["phase"] = json!({"kind":"cleanup_pending"});
        for key in ["catalog", "control"] {
            before["preimages"][key]["coverage_ref"] = serde_json::from_str(&coverage_ref).unwrap();
        }
        before["preimages"][role] = serde_json::from_str(&before_image).unwrap();
        before["rollback"] = json!({
            "plan":null,"intent":serde_json::from_slice::<Value>(&intent.reference_bytes().unwrap()).unwrap(),
            "restore_pair":"not_needed","recovery_incarnation":null,
            "authority_checkpoint":serde_json::from_str::<Value>(&checkpoint).unwrap(),
            "catalog_side":null,"control_side":null,"catalog_displaced":null,"control_displaced":null,
            "catalog_restore_journal":null,"control_restore_journal":null,
            "rollback_pair_readback":serde_json::from_slice::<Value>(&pair.reference_bytes().unwrap()).unwrap(),
            "finalizer":null,
        });
        let before = canonical(&before, &f.admission);
        let mut pending: Value = serde_json::from_slice(before.raw_bytes()).unwrap();
        pending["seq"] = json!(11);
        pending["predecessor_sha256"] = json!(sha256(before.raw_bytes()));
        pending["pending"] = json!({
            "kind":"owned_delete","slot":format!("{role}_preimage"),"intent_seq":11,
            "expected_before":{"kind":"record_digest","size_bytes":before_image.len(),"sha256":sha256(before_image.as_bytes())},
            "expected_after":{"size_bytes":after_image.len(),"sha256":sha256(after_image.as_bytes())},
        });
        let pending = canonical(&pending, &f.admission);
        let mut after: Value = serde_json::from_slice(pending.raw_bytes()).unwrap();
        after["seq"] = json!(12);
        after["predecessor_sha256"] = json!(sha256(pending.raw_bytes()));
        after["pending"] = Value::Null;
        after["preimages"][role] = serde_json::from_str(&after_image).unwrap();
        let after = canonical(&after, &f.admission);
        let proofs = vec![coverage, intent, pair];
        let manifests = vec![decoded];
        let records = RecordSet {
            proofs: &proofs,
            manifests: &manifests,
        };
        pending
            .validate_successor(
                &before,
                SuccessorEvidence {
                    previous: records,
                    current: records,
                    effect_readback: None,
                },
                &f.admission,
            )
            .unwrap();
        after
            .validate_successor(
                &pending,
                SuccessorEvidence {
                    previous: records,
                    current: records,
                    effect_readback: Some(after_image.as_bytes()),
                },
                &f.admission,
            )
            .unwrap();
        for proof in &proofs {
            write(
                &f.run.join(proof_key(proof).unwrap().filename()),
                proof.raw_bytes(),
            );
        }
        fs::write(f.prefix.join("update").join(ACTIVE), before.raw_bytes()).unwrap();
        Self {
            before,
            pending,
            after,
            proofs,
            manifests,
            readback: after_image.into_bytes(),
            path,
            original,
        }
    }

    fn evidence(&self, ack: bool) -> SuccessorEvidence<'_> {
        let records = RecordSet {
            proofs: &self.proofs,
            manifests: &self.manifests,
        };
        SuccessorEvidence {
            previous: records,
            current: records,
            effect_readback: ack.then_some(self.readback.as_slice()),
        }
    }
}

struct FaultReset;
impl Drop for FaultReset {
    fn drop(&mut self) {
        FAILURE.with(|slot| slot.set(None));
        UNWIND.with(|slot| slot.set(None));
    }
}

#[test]
fn native_publication_replaces_only_active_and_exact_ack_is_idempotent() {
    let f = Fixture::new();
    let (before, after) = f.states();
    let mut expected = f.inventory();
    expected.insert(
        f.prefix.join("update").join(ACTIVE),
        InventoryEntry::File(after.raw_bytes().to_vec()),
    );
    let mut journal = f.open();
    assert_eq!(journal.current().unwrap().raw_bytes(), before.raw_bytes());
    assert_eq!(journal.admission().raw_bytes(), f.admission.raw_bytes());
    assert_eq!(
        journal.publish(&before, &after, no_records()),
        Ok(Publication::Published)
    );
    assert_eq!(f.inventory(), expected);
    assert_eq!(
        journal.publish(&before, &after, no_records()),
        Ok(Publication::ReadBack)
    );
    assert_eq!(f.inventory(), expected);
    assert_eq!(journal.reconcile(no_records()), Ok(None));
}

#[test]
fn native_publication_immutable_proof_precedes_state_and_survives_lost_ack() {
    let f = Fixture::new();
    let before = StateV2::decode(&f.initial, &f.admission).unwrap();
    let (next, proof) = coverage_next(&f, &before);
    let current = [proof];
    let evidence = || SuccessorEvidence {
        previous: RecordSet {
            proofs: &[],
            manifests: &[],
        },
        current: RecordSet {
            proofs: &current,
            manifests: &[],
        },
        effect_readback: None,
    };
    let mut expected = f.inventory();
    expected.insert(
        f.run.join("coverage.json"),
        InventoryEntry::File(current[0].raw_bytes().to_vec()),
    );
    let _reset = FaultReset;
    let mut journal = f.open();
    FAILURE.with(|slot| slot.set(Some(Fault::ProofFlushed)));
    assert_eq!(
        journal.publish(&before, &next, evidence()),
        Err(PublicationError::Io)
    );
    assert_eq!(f.inventory(), expected);
    assert!(!f.run.join(CANDIDATE).exists());
    drop(journal);
    let mut resumed = f.open();
    assert_eq!(
        resumed.publish(&before, &next, evidence()),
        Ok(Publication::Published)
    );
    expected.insert(
        f.prefix.join("update").join(ACTIVE),
        InventoryEntry::File(next.raw_bytes().to_vec()),
    );
    assert_eq!(f.inventory(), expected);
    assert_eq!(
        resumed.publish(&before, &next, evidence()),
        Ok(Publication::ReadBack)
    );
    assert_eq!(f.inventory(), expected);
}

#[test]
fn native_publication_complete_unflushed_proof_is_reflushed_before_candidate() {
    let _reset = FaultReset;
    let f = Fixture::new();
    let before = StateV2::decode(&f.initial, &f.admission).unwrap();
    let (next, proof) = coverage_next(&f, &before);
    let proofs = [proof];
    let evidence = || SuccessorEvidence {
        previous: RecordSet {
            proofs: &[],
            manifests: &[],
        },
        current: RecordSet {
            proofs: &proofs,
            manifests: &[],
        },
        effect_readback: None,
    };
    let mut journal = f.open();
    FAILURE.with(|slot| slot.set(Some(Fault::ProofWritten)));
    assert_eq!(
        journal.publish(&before, &next, evidence()),
        Err(PublicationError::Io)
    );
    assert_eq!(
        fs::read(f.run.join("coverage.json")).unwrap(),
        proofs[0].raw_bytes()
    );
    assert!(!f.run.join(CANDIDATE).exists());
    drop(journal);
    let retained = f.inventory();
    let mut resumed = f.open();
    FAILURE.with(|slot| slot.set(Some(Fault::RetainedProofFlushed)));
    assert_eq!(
        resumed.publish(&before, &next, evidence()),
        Err(PublicationError::Io)
    );
    assert!(
        FAILURE.with(|slot| slot.get().is_none()),
        "retained proof flush was bypassed"
    );
    assert_eq!(f.inventory(), retained);
    drop(resumed);
    let mut resumed = f.open();
    assert_eq!(resumed.end, f.end);
    assert_eq!(
        resumed.publish(&before, &next, evidence()),
        Ok(Publication::Published)
    );
}

#[test]
fn native_publication_complete_unflushed_candidate_is_reflushed_before_exchange() {
    let _reset = FaultReset;
    let f = Fixture::new();
    let (before, after) = f.states();
    let mut journal = f.open();
    FAILURE.with(|slot| slot.set(Some(Fault::CandidateWritten)));
    assert_eq!(
        journal.publish(&before, &after, no_records()),
        Err(PublicationError::Io)
    );
    assert_eq!(fs::read(f.run.join(CANDIDATE)).unwrap(), after.raw_bytes());
    assert_eq!(
        fs::read(f.prefix.join("update").join(ACTIVE)).unwrap(),
        before.raw_bytes()
    );
    drop(journal);
    let retained = f.inventory();
    let mut resumed = f.open();
    FAILURE.with(|slot| slot.set(Some(Fault::RetainedCandidateFlushed)));
    assert_eq!(resumed.reconcile(no_records()), Err(PublicationError::Io));
    assert!(
        FAILURE.with(|slot| slot.get().is_none()),
        "retained candidate flush was bypassed"
    );
    assert_eq!(f.inventory(), retained);
    drop(resumed);
    let mut resumed = f.open();
    assert_eq!(resumed.end, f.end);
    assert_eq!(
        resumed.reconcile(no_records()),
        Ok(Some(Publication::Published))
    );
}

#[test]
fn native_publication_entry_and_read_errors_poison_even_after_bytes_are_restored() {
    for operation in ["current", "publish", "reconcile"] {
        let f = Fixture::new();
        let (before, after) = f.states();
        let mut journal = f.open();
        let path = f.prefix.join("update").join(GUARD);
        let raw = fs::read(&path).unwrap();
        fs::write(&path, b"changed immutable guard").unwrap();
        let failed = match operation {
            "current" => journal.current().map(|_| ()),
            "publish" => journal.publish(&before, &after, no_records()).map(|_| ()),
            _ => journal.reconcile(no_records()).map(|_| ()),
        };
        assert!(failed.is_err());
        fs::write(&path, raw).unwrap();
        assert!(matches!(journal.current(), Err(PublicationError::Poisoned)));
        assert_eq!(
            journal.publish(&before, &after, no_records()),
            Err(PublicationError::Poisoned)
        );
        assert_eq!(
            journal.reconcile(no_records()),
            Err(PublicationError::Poisoned)
        );
        drop(journal);
        assert_eq!(f.open().current().unwrap().raw_bytes(), before.raw_bytes());
    }
    let f = Fixture::new();
    let mut journal = f.open();
    let path = f.prefix.join("update").join(ACTIVE);
    fs::write(&path, b"invalid active JSON").unwrap();
    assert!(journal.current().is_err());
    fs::write(&path, &f.initial).unwrap();
    assert_eq!(
        journal.reconcile(no_records()),
        Err(PublicationError::Poisoned)
    );
    drop(journal);
    assert_eq!(f.open().current().unwrap().raw_bytes(), f.initial);
}

#[test]
fn native_publication_entry_and_current_unwind_poison_receiver() {
    for point in [Fault::ReceiverCheck, Fault::CurrentRead] {
        let _reset = FaultReset;
        let f = Fixture::new();
        let journal = f.open();
        UNWIND.with(|slot| slot.set(Some(point)));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| journal.current())).is_err()
        );
        assert!(UNWIND.with(|slot| slot.get().is_none()));
        assert!(matches!(journal.current(), Err(PublicationError::Poisoned)));
        drop(journal);
        assert_eq!(f.open().current().unwrap().raw_bytes(), f.initial);
    }
}

#[cfg(windows)]
#[test]
fn native_publication_metadata_pin_survives_replace_without_data_access_or_inheritance() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};
    let f = Fixture::new();
    let (before, after) = f.states();
    let journal = f.open();
    let staged = journal
        .run
        .write_new(CANDIDATE, after.raw_bytes(), f.end)
        .unwrap();
    journal.run.matches(CANDIDATE, &staged, f.end).unwrap();
    let mut metadata = native::metadata_pin(&journal.run, CANDIDATE).unwrap();
    assert!(identity(&metadata).unwrap() == staged.identity);
    let mut flags = 0;
    // SAFETY: query flags on this live borrowed handle, without inheriting it.
    assert_ne!(
        unsafe { GetHandleInformation(metadata.as_raw_handle(), &mut flags) },
        0
    );
    assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
    let mut byte = [0];
    assert!(
        metadata.read(&mut byte).is_err(),
        "metadata pin has no data-read permission"
    );
    let old = journal
        .update
        .required(ACTIVE, MAX_RECORD_BYTES, f.end)
        .unwrap();
    let refused =
        native::replace(&journal.update, ACTIVE, &journal.run, CANDIDATE, DISPLACED).unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(32));
    assert_eq!(
        fs::read(f.prefix.join("update").join(ACTIVE)).unwrap(),
        before.raw_bytes()
    );
    let expected = staged.identity;
    drop(staged);
    native::replace(&journal.update, ACTIVE, &journal.run, CANDIDATE, DISPLACED).unwrap();
    let installed = journal
        .update
        .required(ACTIVE, MAX_RECORD_BYTES, f.end)
        .unwrap();
    assert!(installed.identity == expected && identity(&metadata).unwrap() == expected);
    assert_eq!(installed.raw, after.raw_bytes());
    journal.flush_active(&installed).unwrap();
    journal.update.sync(f.end).unwrap();
    journal.run.sync(f.end).unwrap();
    assert!(identity(&metadata).unwrap() == expected);
    assert_eq!(old.raw, before.raw_bytes());
}

#[test]
fn native_publication_missing_active_recovers_only_exact_retained_pair() {
    let _reset = FaultReset;
    let f = Fixture::new();
    let (before, after) = f.states();
    let mut expected = f.inventory();
    expected.insert(
        f.prefix.join("update").join(ACTIVE),
        InventoryEntry::File(after.raw_bytes().to_vec()),
    );
    let mut journal = f.open();
    FAILURE.with(|slot| slot.set(Some(Fault::ActiveDisplaced)));
    assert_eq!(
        journal.publish(&before, &after, no_records()),
        Err(PublicationError::Io)
    );
    assert!(FAILURE.with(|slot| slot.get().is_none()));
    assert!(!f.prefix.join("update").join(ACTIVE).exists());
    assert_eq!(fs::read(f.run.join(DISPLACED)).unwrap(), before.raw_bytes());
    assert_eq!(fs::read(f.run.join(CANDIDATE)).unwrap(), after.raw_bytes());
    drop(journal);
    let retained = f.inventory();
    let mut resumed = f.open();
    assert_eq!(
        f.inventory(),
        retained,
        "opening partial replace cannot mutate it"
    );
    assert_eq!(resumed.end, f.end);
    assert_eq!(
        resumed.reconcile(no_records()),
        Ok(Some(Publication::Published))
    );
    assert_eq!(f.inventory(), expected);
}

#[test]
fn native_publication_missing_active_rejects_bad_chain_missing_image_and_foreign_active() {
    for case in [
        "bad_chain",
        "missing_candidate",
        "missing_displaced",
        "occupied_previous",
        "foreign_active",
    ] {
        let _reset = FaultReset;
        let f = Fixture::new();
        let (before, after) = f.states();
        let mut journal = f.open();
        FAILURE.with(|slot| slot.set(Some(Fault::ActiveDisplaced)));
        assert_eq!(
            journal.publish(&before, &after, no_records()),
            Err(PublicationError::Io)
        );
        assert!(FAILURE.with(|slot| slot.get().is_none()));
        drop(journal);
        match case {
            "bad_chain" => {
                let mut value: Value = serde_json::from_slice(after.raw_bytes()).unwrap();
                value["predecessor_sha256"] = json!("e".repeat(64));
                fs::write(
                    f.run.join(CANDIDATE),
                    canonical(&value, &f.admission).raw_bytes(),
                )
                .unwrap();
            }
            "missing_candidate" => fs::remove_file(f.run.join(CANDIDATE)).unwrap(),
            "missing_displaced" => fs::remove_file(f.run.join(DISPLACED)).unwrap(),
            "occupied_previous" => write(&f.prefix.join("update").join(ACTIVE), &f.initial),
            _ => {
                let foreign = Fixture::new();
                write(&f.prefix.join("update").join(ACTIVE), &foreign.initial);
            }
        }
        let retained = f.inventory();
        match f.invocation.open_bound_journal(f.locks(), f.end) {
            Ok(mut resumed) => assert!(resumed.reconcile(no_records()).is_err()),
            Err(_) => assert_ne!(case, "occupied_previous"),
        }
        assert_eq!(f.inventory(), retained, "{case}");
    }
}

#[test]
fn native_publication_manifest_delete_ack_and_lost_ack_keep_historical_payloads() {
    for component in [Component::Catalog, Component::Control] {
        for point in [Fault::CandidateFlushed, Fault::Exchanged] {
            let _reset = FaultReset;
            let f = Fixture::new();
            let deletion = ManifestDeletion::new(&f, component);
            let mut journal = f.open();
            assert_eq!(
                journal.publish(
                    &deletion.before,
                    &deletion.pending,
                    deletion.evidence(false)
                ),
                Ok(Publication::Published)
            );
            let pending_inventory = f.inventory();
            assert!(
                journal
                    .publish(&deletion.pending, &deletion.after, deletion.evidence(true))
                    .is_err(),
                "physical manifest still exists, so its deletion cannot be acknowledged"
            );
            assert_eq!(f.inventory(), pending_inventory);
            drop(journal);
            fs::remove_file(&deletion.path).unwrap();
            let mut expected = f.inventory();
            let mut journal = f.open();
            assert_eq!(
                journal.current().unwrap().raw_bytes(),
                deletion.pending.raw_bytes()
            );
            assert!(
                journal.reconcile(deletion.evidence(false)).is_err(),
                "pending observation must not acknowledge a deleted manifest by itself"
            );
            assert_eq!(f.inventory(), expected);
            drop(journal);
            let mut journal = f.open();
            FAILURE.with(|slot| slot.set(Some(point)));
            assert_eq!(
                journal.publish(&deletion.pending, &deletion.after, deletion.evidence(true)),
                Err(PublicationError::Io)
            );
            assert!(FAILURE.with(|slot| slot.get().is_none()));
            assert!(!deletion.path.exists());
            drop(journal);
            let mut resumed = f.open();
            assert!(matches!(
                resumed.reconcile(deletion.evidence(true)),
                Ok(Some(_))
            ));
            expected.insert(
                f.prefix.join("update").join(ACTIVE),
                InventoryEntry::File(deletion.after.raw_bytes().to_vec()),
            );
            assert_eq!(f.inventory(), expected);
            assert_eq!(resumed.reconcile(deletion.evidence(false)), Ok(None));
            assert!(!deletion.path.exists());
            assert_eq!(deletion.manifests[0].raw_bytes(), deletion.original);
        }
    }
}

#[test]
fn native_publication_manifest_absence_requires_pending_exact_readback_and_stays_absent() {
    let f = Fixture::new();
    let deletion = ManifestDeletion::new(&f, Component::Catalog);
    let replacement = deletion.path.with_file_name("manifest.replacement.test");
    write(&replacement, &deletion.original);
    let original_identity = identity(&platform::open_file(&deletion.path).unwrap()).unwrap();
    let replacement_identity = identity(&platform::open_file(&replacement).unwrap()).unwrap();
    assert!(original_identity != replacement_identity);
    fs::remove_file(&deletion.path).unwrap();
    let retained = f.inventory();
    let mut journal = f.open();
    assert!(
        journal
            .publish(
                &deletion.before,
                &deletion.pending,
                deletion.evidence(false)
            )
            .is_err()
    );
    assert_eq!(f.inventory(), retained);
    drop(journal);
    // The replacement was allocated while the original still existed, so the
    // negative does not depend on whether a filesystem reuses deleted IDs.
    fs::rename(&replacement, &deletion.path).unwrap();
    let retained = f.inventory();
    let mut journal = f.open();
    assert!(
        journal
            .publish(
                &deletion.before,
                &deletion.pending,
                deletion.evidence(false)
            )
            .is_err()
    );
    assert_eq!(f.inventory(), retained);

    let f = Fixture::new();
    let deletion = ManifestDeletion::new(&f, Component::Control);
    let mut journal = f.open();
    journal
        .publish(
            &deletion.before,
            &deletion.pending,
            deletion.evidence(false),
        )
        .unwrap();
    fs::remove_file(&deletion.path).unwrap();
    let retained = f.inventory();
    assert!(
        journal
            .publish(&deletion.pending, &deletion.after, deletion.evidence(false))
            .is_err()
    );
    assert_eq!(f.inventory(), retained);
    drop(journal);
    let mut resumed = f.open();
    resumed
        .publish(&deletion.pending, &deletion.after, deletion.evidence(true))
        .unwrap();
    write(&deletion.path, &deletion.original);
    let retained = f.inventory();
    assert!(resumed.reconcile(deletion.evidence(false)).is_err());
    assert_eq!(f.inventory(), retained);
}

#[test]
fn native_publication_foreign_or_partial_proof_is_not_rewritten() {
    for raw in [b"{".as_slice(), b"unrelated proof".as_slice()] {
        let f = Fixture::new();
        let before = StateV2::decode(&f.initial, &f.admission).unwrap();
        let (next, proof) = coverage_next(&f, &before);
        write(&f.run.join("coverage.json"), raw);
        let retained = f.inventory();
        let proofs = [proof];
        let mut journal = f.open();
        assert!(
            journal
                .publish(
                    &before,
                    &next,
                    SuccessorEvidence {
                        previous: RecordSet {
                            proofs: &[],
                            manifests: &[]
                        },
                        current: RecordSet {
                            proofs: &proofs,
                            manifests: &[]
                        },
                        effect_readback: None,
                    }
                )
                .is_err()
        );
        assert_eq!(f.inventory(), retained);
        assert!(!f.run.join(CANDIDATE).exists());
    }
}

#[test]
fn native_publication_unreferenced_proof_is_preserved_and_refuses_advancement() {
    let f = Fixture::new();
    let (before, after) = f.states();
    write(
        &f.run.join("control-intent.json"),
        b"foreign unreferenced record",
    );
    let retained = f.inventory();
    let mut journal = f.open();
    assert!(journal.publish(&before, &after, no_records()).is_err());
    assert_eq!(f.inventory(), retained);
}

#[test]
fn native_publication_existing_candidate_cannot_recreate_its_missing_proof() {
    let f = Fixture::new();
    let before = StateV2::decode(&f.initial, &f.admission).unwrap();
    let (next, proof) = coverage_next(&f, &before);
    write(&f.run.join(CANDIDATE), next.raw_bytes());
    let retained = f.inventory();
    let proofs = [proof];
    let mut journal = f.open();
    assert!(
        journal
            .publish(
                &before,
                &next,
                SuccessorEvidence {
                    previous: RecordSet {
                        proofs: &[],
                        manifests: &[]
                    },
                    current: RecordSet {
                        proofs: &proofs,
                        manifests: &[]
                    },
                    effect_readback: None,
                }
            )
            .is_err()
    );
    assert_eq!(f.inventory(), retained);
    assert!(!f.run.join("coverage.json").exists());
}

#[test]
fn native_publication_expired_reentry_preserves_candidate_and_original_end() {
    let f = Fixture::new();
    let (before, after) = f.states();
    write(&f.run.join(CANDIDATE), after.raw_bytes());
    let retained = f.inventory();
    let mut journal = f.open();
    journal.end = Instant::now();
    assert_eq!(
        journal.reconcile(no_records()),
        Err(PublicationError::Deadline)
    );
    assert_eq!(f.inventory(), retained);
    assert_eq!(
        fs::read(f.prefix.join("update").join(ACTIVE)).unwrap(),
        before.raw_bytes()
    );
}

#[test]
fn native_publication_retains_all_three_native_exclusions() {
    let f = Fixture::new();
    let (before, after) = f.states();
    let mut journal = f.open();
    assert_eq!(
        journal.publish(&before, &after, no_records()),
        Ok(Publication::Published)
    );
    let busy = |root: &Path, kind| {
        assert!(matches!(
            ExclusiveGuard::try_acquire(root, kind),
            Err(agent_session_grep_ports::PortError::WriterBusy(_))
        ));
    };
    busy(
        &f.prefix,
        LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap()),
    );
    busy(&f.control, LockKind::ControlHandles);
    busy(&f.control, LockKind::PolicyOwner);
}

#[test]
fn native_publication_finalizer_receipt_has_priority_over_active_state() {
    let f = Fixture::new();
    write(
        &f.control.join("schema-transition-finalize.json"),
        b"retained finalizer",
    );
    let retained = f.inventory();
    assert!(f.invocation.open_bound_journal(f.locks(), f.end).is_err());
    assert_eq!(f.inventory(), retained);
}

#[test]
fn native_publication_unwind_poison_retains_candidate_for_exact_reentry() {
    let _reset = FaultReset;
    let f = Fixture::new();
    let (before, after) = f.states();
    let mut journal = f.open();
    UNWIND.with(|slot| slot.set(Some(Fault::CandidateFlushed)));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            journal.publish(&before, &after, no_records())
        }))
        .is_err()
    );
    let retained = f.inventory();
    assert_eq!(
        journal.publish(&before, &after, no_records()),
        Err(PublicationError::Poisoned)
    );
    assert_eq!(f.inventory(), retained);
    drop(journal);
    let mut resumed = f.open();
    assert_eq!(
        resumed.reconcile(no_records()),
        Ok(Some(Publication::Published))
    );
    assert_eq!(resumed.current().unwrap().raw_bytes(), after.raw_bytes());
}

#[test]
fn native_publication_fault_boundaries_reenter_exact_slots_with_original_end() {
    let mut points = vec![Fault::CandidateFlushed, Fault::Exchanged, Fault::ReadBack];
    if cfg!(unix) {
        points.push(Fault::DisplacedStored);
    }
    for point in points {
        let _reset = FaultReset;
        let f = Fixture::new();
        let (before, after) = f.states();
        let mut expected = f.inventory();
        expected.insert(
            f.prefix.join("update").join(ACTIVE),
            InventoryEntry::File(after.raw_bytes().to_vec()),
        );
        let mut journal = f.open();
        FAILURE.with(|slot| slot.set(Some(point)));
        assert_eq!(
            journal.publish(&before, &after, no_records()),
            Err(PublicationError::Io)
        );
        let retained = f.inventory();
        assert_eq!(
            journal.publish(&before, &after, no_records()),
            Err(PublicationError::Poisoned)
        );
        assert_eq!(f.inventory(), retained);
        drop(journal);
        let mut resumed = f.open();
        assert_eq!(resumed.end, f.end);
        assert!(matches!(resumed.reconcile(no_records()), Ok(Some(_))));
        assert_eq!(f.inventory(), expected);
        assert_eq!(resumed.current().unwrap().raw_bytes(), after.raw_bytes());
    }
}

#[test]
fn native_publication_conflicting_candidate_displaced_and_legacy_slots_preserve_all_bytes() {
    for (name, root_level) in [
        (CANDIDATE, false),
        (DISPLACED, false),
        (RECONCILE, false),
        ("state.next.json", true),
    ] {
        let f = Fixture::new();
        let path = if root_level {
            f.prefix.join("update").join(name)
        } else {
            f.run.join(name)
        };
        write(&path, b"unrelated retained bytes");
        let before = f.inventory();
        let (old, new) = f.states();
        match f.invocation.open_bound_journal(f.locks(), f.end) {
            Ok(mut journal) => assert!(journal.publish(&old, &new, no_records()).is_err()),
            Err(_) => assert!(name == RECONCILE || root_level),
        }
        assert_eq!(f.inventory(), before);
    }
}

#[test]
fn native_publication_rejects_bad_successor_and_foreign_admission_before_staging() {
    let f = Fixture::new();
    let (before, _) = f.states();
    let mut bad: Value = serde_json::from_slice(before.raw_bytes()).unwrap();
    bad["seq"] = json!(2);
    bad["predecessor_sha256"] = json!(sha256(before.raw_bytes()));
    let noop = canonical(&bad, &f.admission);
    let retained = f.inventory();
    let mut journal = f.open();
    assert!(journal.publish(&before, &noop, no_records()).is_err());
    assert_eq!(f.inventory(), retained);
    drop(journal);
    let other = Fixture::new();
    let (foreign_before, foreign_after) = other.states();
    let mut journal = f.open();
    assert!(
        journal
            .publish(&foreign_before, &foreign_after, no_records())
            .is_err()
    );
    assert_eq!(f.inventory(), retained);
}

#[test]
fn native_publication_wrong_lock_kind_root_and_expired_end_have_zero_effects() {
    let f = Fixture::new();
    let other = Fixture::new();
    let retained = f.inventory();
    assert!(JournalLocks::new(&f.owner_lock, &f.control_lock, &f.prefix_lock).is_err());
    assert!(JournalLocks::new(&f.prefix_lock, &other.control_lock, &f.owner_lock).is_err());
    let foreign = JournalLocks::new(&other.prefix_lock, &f.control_lock, &f.owner_lock).unwrap();
    assert!(f.invocation.open_bound_journal(foreign, f.end).is_err());
    assert!(matches!(
        f.invocation.open_bound_journal(f.locks(), Instant::now()),
        Err(PublicationError::Deadline)
    ));
    let (before, after) = f.states();
    let mut journal = f.open();
    journal.end = Instant::now();
    assert_eq!(
        journal.publish(&before, &after, no_records()),
        Err(PublicationError::Deadline)
    );
    assert_eq!(f.inventory(), retained);
}

#[test]
fn native_publication_retained_guard_rejects_same_bytes_on_a_different_file() {
    let f = Fixture::new();
    let (before, after) = f.states();
    let mut journal = f.open();
    let update = f.prefix.join("update");
    let raw = fs::read(update.join(GUARD)).unwrap();
    let replacement = "guard-replacement.test";
    write(&update.join(replacement), &raw);
    // Use the actual native replacement while the receiver retains the original
    // file pin. Same content alone must not make the replacement authoritative.
    native::replace(
        &journal.update,
        GUARD,
        &journal.update,
        replacement,
        "guard-old.test",
    )
    .unwrap();
    let retained = f.inventory();
    assert_eq!(
        journal.publish(&before, &after, no_records()),
        Err(PublicationError::Changed)
    );
    assert_eq!(f.inventory(), retained);
}

#[test]
fn native_publication_unknown_or_missing_guard_never_recreates_authority() {
    for missing in [true, false] {
        let f = Fixture::new();
        let guard = f.prefix.join("update").join(GUARD);
        if missing {
            fs::remove_file(&guard).unwrap();
        } else {
            fs::write(&guard, b"{\"schema\":\"unknown\"}").unwrap();
        }
        let retained = f.inventory();
        assert!(f.invocation.open_bound_journal(f.locks(), f.end).is_err());
        assert_eq!(f.inventory(), retained);
    }
}

#[cfg(unix)]
#[test]
fn native_publication_root_replacement_refuses_before_writing_either_directory() {
    let f = Fixture::new();
    let (before, after) = f.states();
    let mut journal = f.open();
    let moved = f.prefix.with_file_name("original-install");
    fs::rename(&f.prefix, &moved).unwrap();
    private(&f.prefix);
    let original_active = fs::read(moved.join("update").join(ACTIVE)).unwrap();
    assert!(journal.publish(&before, &after, no_records()).is_err());
    assert_eq!(
        fs::read(moved.join("update").join(ACTIVE)).unwrap(),
        original_active
    );
    assert!(fs::read_dir(&f.prefix).unwrap().next().is_none());
}

fn before_initialization(terminal: bool) -> (Fixture, Option<Vec<u8>>) {
    let mut f = Fixture::new();
    write(
        &f.prefix.join("current.json"),
        b"synthetic pointer untouched",
    );
    // Remove only exact files created by this synthetic fixture, with no held
    // journal receiver. Neither production initialization nor recovery deletes U.
    for name in ["admission.json", "state.initial.json"] {
        fs::remove_file(f.run.join(name)).unwrap();
    }
    let update = f.prefix.join("update");
    for name in [ACTIVE, GUARD] {
        fs::remove_file(update.join(name)).unwrap();
    }
    fs::remove_dir(&f.run).unwrap();
    let old = if terminal {
        let prior = update.join("update_prior");
        private(&prior);
        write(&prior.join("retained-metadata"), b"old immutable metadata");
        let mut record = f.admission.record.clone();
        let mut state = crate::update_state::State::new(crate::update_state::UpdateStart {
            update_id: agent_session_grep_ports::control::ControlId::parse("update_prior").unwrap(),
            owner: agent_session_grep_ports::control::ControlId::parse("owner_prior").unwrap(),
            old: record.old.clone(),
            new: record.old.clone(),
            archive_sha256: "d".repeat(64),
            manifest_sha256: "e".repeat(64),
            old_pointer_generation: 1,
            stable_launcher_sha256: record.stable_launcher_sha256.clone(),
            catalog: record.catalog.clone(),
            checkpoint: record.checkpoint.clone(),
        })
        .unwrap();
        state.prefix_binding = record.prefix.identity.clone();
        state.phase = crate::update_state::Phase::Failed;
        state.validate().unwrap();
        let raw = serde_json::to_vec(&state).unwrap();
        record.old_layout = OldJournalLayout::TerminalV1 {
            update_id: "update_prior".into(),
            state_sha256: sha256(&raw),
            state_size_bytes: raw.len() as u64,
            run_identity: RootIdentity::read(&prior)
                .unwrap()
                .control_id()
                .as_str()
                .into(),
        };
        f.admission = AdmissionV2::decode(&serde_json::to_vec(&record).unwrap()).unwrap();
        f.initial = initial(&f.admission).raw_bytes().to_vec();
        write(&update.join(ACTIVE), &raw);
        Some(raw)
    } else {
        fs::remove_dir(update).unwrap();
        None
    };
    (f, old)
}

fn prepare_invocation(f: &Fixture) -> Invocation {
    let record = &f.admission.record;
    Invocation {
        prefix: f.prefix.clone(),
        control_root: f.control.clone(),
        catalog: record.catalog.clone(),
        action: InternalAction::Prepare {
            source: record.incoming_root.path.clone(),
            archive: record.bundle.archive_path.clone(),
            manifest: record.bundle.manifest_path.clone(),
            checksums: record.bundle.checksums_path.clone(),
        },
    }
}

#[test]
fn native_initialization_publishes_guard_before_exact_initial_and_is_idempotent() {
    for terminal in [false, true] {
        let (f, old) = before_initialization(terminal);
        let before = f.inventory();
        let request = prepare_invocation(&f);
        assert_eq!(
            StateV2::initial(&f.admission).unwrap().raw_bytes(),
            f.initial
        );
        assert_eq!(
            request.initialize_bound_journal(&f.admission, f.locks(), f.end),
            Ok(Publication::Published)
        );
        assert_eq!(f.open().current().unwrap().raw_bytes(), f.initial);
        if let Some(raw) = old {
            assert_eq!(fs::read(f.run.join("prior/state.v1.raw")).unwrap(), raw);
        }
        let published = f.inventory();
        for (path, value) in before {
            if path != f.prefix.join("update").join(ACTIVE) {
                assert_eq!(published.get(&path), Some(&value));
            }
        }
        assert_eq!(
            request.initialize_bound_journal(&f.admission, f.locks(), f.end),
            Ok(Publication::ReadBack)
        );
        assert_eq!(f.inventory(), published);
        assert!(!f.run.join(CANDIDATE).exists());
        assert!(!f.run.join(DISPLACED).exists());
    }
}

#[test]
fn native_initialization_recovers_each_fixed_publication_without_replacing_old_run() {
    for terminal in [false, true] {
        for point in [
            Fault::InitialAdmission,
            Fault::InitialState,
            Fault::InitialGuardReady,
            Fault::InitialGuardPublished,
            Fault::InitialCandidate,
            Fault::InitialActive,
        ] {
            let _reset = FaultReset;
            let (f, old) = before_initialization(terminal);
            let request = prepare_invocation(&f);
            FAILURE.with(|slot| slot.set(Some(point)));
            assert_eq!(
                request.initialize_bound_journal(&f.admission, f.locks(), f.end),
                Err(PublicationError::Io)
            );
            assert!(FAILURE.with(|slot| slot.get().is_none()));
            let update = f.prefix.join("update");
            if matches!(
                point,
                Fault::InitialAdmission | Fault::InitialState | Fault::InitialGuardReady
            ) {
                assert!(!update.join(GUARD).exists());
                assert_eq!(fs::read(update.join(ACTIVE)).ok(), old);
                assert!(!f.run.join(CANDIDATE).exists());
            } else {
                assert!(update.join(GUARD).is_file());
            }
            let result = request
                .initialize_bound_journal(&f.admission, f.locks(), f.end)
                .unwrap();
            assert_eq!(
                result,
                if point == Fault::InitialActive {
                    Publication::ReadBack
                } else {
                    Publication::Published
                }
            );
            assert_eq!(f.open().current().unwrap().raw_bytes(), f.initial);
            assert_eq!(
                fs::read(f.control.join("catalog.db")).unwrap(),
                b"synthetic catalog unchanged"
            );
            assert_eq!(
                fs::read(f.control.join("control.db")).unwrap(),
                b"synthetic control unchanged"
            );
        }
    }
}

#[test]
fn native_initialization_refuses_foreign_partial_and_unbound_existing_records() {
    for case in 0..5 {
        let _reset = FaultReset;
        let (f, _) = before_initialization(false);
        let request = prepare_invocation(&f);
        if case == 0 {
            private(&f.prefix.join("update"));
            private(&f.run);
        } else {
            FAILURE.with(|slot| slot.set(Some(Fault::InitialGuardReady)));
            assert_eq!(
                request.initialize_bound_journal(&f.admission, f.locks(), f.end),
                Err(PublicationError::Io)
            );
            match case {
                1 => fs::write(f.run.join("admission.json"), b"{").unwrap(),
                2 => fs::write(f.run.join("state.initial.json"), b"{}").unwrap(),
                3 => write(&f.run.join("foreign-record"), b"preserved"),
                _ => write(&f.prefix.join("update").join(GUARD), b"foreign guard"),
            }
        }
        let before = f.inventory();
        assert!(
            request
                .initialize_bound_journal(&f.admission, f.locks(), f.end)
                .is_err()
        );
        assert_eq!(f.inventory(), before);
    }
}

#[test]
fn native_initialization_expired_end_and_wrong_action_preserve_absence() {
    let (f, _) = before_initialization(false);
    let before = f.inventory();
    assert_eq!(
        prepare_invocation(&f).initialize_bound_journal(
            &f.admission,
            f.locks(),
            Instant::now() - Duration::from_millis(1)
        ),
        Err(PublicationError::Deadline)
    );
    assert_eq!(
        f.invocation
            .initialize_bound_journal(&f.admission, f.locks(), f.end),
        Err(PublicationError::Changed)
    );
    assert_eq!(f.inventory(), before);
}

#[test]
fn native_initialization_changed_old_state_and_finalizer_refuse_without_new_effects() {
    for finalizer in [false, true] {
        let (f, _) = before_initialization(true);
        if finalizer {
            write(
                &f.control.join("schema-transition-finalize.json"),
                b"pending finalizer",
            );
        } else {
            fs::write(f.prefix.join("update").join(ACTIVE), b"foreign current").unwrap();
        }
        let before = f.inventory();
        assert!(
            prepare_invocation(&f)
                .initialize_bound_journal(&f.admission, f.locks(), f.end)
                .is_err()
        );
        assert_eq!(f.inventory(), before);
        assert!(!f.run.exists());
    }
}

#[test]
fn native_initialization_missing_initial_after_final_guard_never_recreates_it() {
    let _reset = FaultReset;
    let (f, _) = before_initialization(false);
    let request = prepare_invocation(&f);
    FAILURE.with(|slot| slot.set(Some(Fault::InitialGuardPublished)));
    assert_eq!(
        request.initialize_bound_journal(&f.admission, f.locks(), f.end),
        Err(PublicationError::Io)
    );
    fs::remove_file(f.run.join("state.initial.json")).unwrap();
    let before = f.inventory();
    assert!(
        request
            .initialize_bound_journal(&f.admission, f.locks(), f.end)
            .is_err()
    );
    assert_eq!(f.inventory(), before);
}

#[test]
fn native_initialization_retains_exclusions_and_preserves_an_earlier_end() {
    let (f, _) = before_initialization(false);
    let scope = SqliteControlStore::create(
        &f._temp.path().join("scope"),
        &agent_session_grep_ports::control::ControlId::parse("scope-fixture").unwrap(),
        agent_session_grep_ports::control::DesiredUpdates::Paused,
    )
    .unwrap();
    let before = f.inventory();
    let expired = Instant::now() - Duration::from_millis(1);
    let result = scope.with_runtime_deadline(expired, || {
        prepare_invocation(&f)
            .initialize_bound_journal(&f.admission, f.locks(), f.end)
            .map_err(|_| agent_session_grep_ports::PortError::DeadlineExceeded("expired".into()))
    });
    assert!(result.is_err());
    assert_eq!(f.inventory(), before);
    assert_eq!(SqliteControlStore::effective_runtime_deadline(f.end), f.end);
    prepare_invocation(&f)
        .initialize_bound_journal(&f.admission, f.locks(), f.end)
        .unwrap();
    for (root, kind) in [
        (
            &f.prefix,
            LockKind::MaintenanceJob(JobLockKey::parse("installation-update").unwrap()),
        ),
        (&f.control, LockKind::ControlHandles),
        (&f.control, LockKind::PolicyOwner),
    ] {
        assert!(matches!(
            ExclusiveGuard::try_acquire(root, kind),
            Err(agent_session_grep_ports::PortError::WriterBusy(_))
        ));
    }
}

#[test]
fn native_initialization_missing_active_requires_exact_initial_and_old_pair() {
    for foreign in [false, true] {
        let _reset = FaultReset;
        let (f, old) = before_initialization(true);
        let request = prepare_invocation(&f);
        FAILURE.with(|slot| slot.set(Some(Fault::InitialCandidate)));
        assert_eq!(
            request.initialize_bound_journal(&f.admission, f.locks(), f.end),
            Err(PublicationError::Io)
        );
        let update = f.prefix.join("update");
        platform::move_new(&update.join(ACTIVE), &f.run.join(DISPLACED)).unwrap();
        if foreign {
            write(&update.join(ACTIVE), b"foreign active preserved");
            let before = f.inventory();
            assert!(
                request
                    .initialize_bound_journal(&f.admission, f.locks(), f.end)
                    .is_err()
            );
            assert_eq!(f.inventory(), before);
        } else {
            assert_eq!(
                request.initialize_bound_journal(&f.admission, f.locks(), f.end),
                Ok(Publication::Published)
            );
            assert_eq!(f.open().current().unwrap().raw_bytes(), f.initial);
            assert_eq!(
                fs::read(f.run.join("prior/state.v1.raw")).unwrap(),
                old.unwrap()
            );
            assert!(!f.run.join(DISPLACED).exists());
        }
        assert_eq!(
            fs::read(f.prefix.join("current.json")).unwrap(),
            b"synthetic pointer untouched"
        );
    }
}
