//! Original-deadline, finite runtime inventory and exact control1 -> control2
//! regressions. All roots and SQL rows are synthetic; no source is read or changed.
use agent_session_grep_adapters_sqlite::{
    SqliteControlStore,
    control::{CONTROL_SCHEMA_VERSION, MAX_RUNTIME_REFERENCES, MAX_RUNTIME_RELATIONS},
    managed_locks::{ExclusiveGuard, LockKind},
};
use agent_session_grep_ports::{PortError, PortResult, SearchProvider, control::*};
use rusqlite::{Connection, params};
use std::{
    cell::Cell,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

fn id(value: &str) -> ControlId {
    ControlId::parse(value).unwrap()
}
fn number(value: usize) -> i64 {
    i64::try_from(value).unwrap()
}
fn bounded<T>(control: &SqliteControlStore, operation: impl FnOnce() -> PortResult<T>) -> T {
    control
        .with_runtime_deadline(Instant::now() + Duration::from_secs(10), operation)
        .unwrap()
}
fn assert_capacity<T>(result: PortResult<T>) {
    // Capacity is a terminal refusal: a genuine overage must not masquerade
    // as contention that callers retry forever.
    assert!(matches!(result, Err(PortError::Backend(reason))
        if reason == "control runtime dependency capacity exceeded"));
}
fn assert_corrupt<T>(result: PortResult<T>) {
    assert!(matches!(result, Err(PortError::SchemaIncompatible(_))));
}
fn raw(root: &Path) -> Connection {
    Connection::open(SqliteControlStore::path(root)).unwrap()
}
fn version(conn: &Connection) -> i64 {
    conn.query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap()
}
fn indexes(conn: &Connection) -> Vec<String> {
    let mut statement = conn
        .prepare("SELECT name FROM sqlite_schema WHERE type='index' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}
fn make_v1(conn: &Connection) {
    conn.execute_batch(
        "BEGIN IMMEDIATE;
        DROP INDEX cycles_runtime_state;
        DROP INDEX barriers_runtime_state;
        DROP INDEX barriers_runtime_admission;
        UPDATE control_meta SET schema_version=1;
        PRAGMA user_version=1;
        COMMIT;",
    )
    .unwrap();
}

struct Fixture {
    root: PathBuf,
    control: SqliteControlStore,
    _background: ExclusiveGuard,
    selection: SelectionRevision,
    // Connections and OS guards must close before Windows temp cleanup.
    _temp: tempfile::TempDir,
}
impl Fixture {
    fn new() -> Self {
        let temp = agent_session_grep_testkit::tempdir().unwrap();
        // Synthetic initialization has one bounded end. The runtime deadline
        // tests below start their own clocks after this scope has been restored;
        // a slow setup read must not exhaust an implicit 250 ms fallback.
        let setup_end = Instant::now() + Duration::from_secs(30);
        let root = temp.path().join("private");
        let selected_root = temp.path().join("synthetic-selected");
        std::fs::create_dir(&selected_root).unwrap();
        let control = SqliteControlStore::create_with_deadline(
            &root,
            &id("synthetic-installation"),
            DesiredUpdates::Running,
            setup_end,
        )
        .unwrap();
        let (selected, background) = control
            .with_runtime_deadline(setup_end, || {
                let selected = control.add_selection(
                    ControlSeq::new(0).unwrap(),
                    SelectionRequest {
                        region: ScopeRegion {
                            provider: SearchProvider::Codex,
                            locator: CanonicalLocator::from_path(&selected_root)?,
                            kind: RootKind::Root,
                        },
                        root_identity: Some(id("synthetic-root")),
                        now_ms: 1,
                    },
                )?;
                let lock_end = setup_end.min(Instant::now() + Duration::from_secs(1));
                let background = loop {
                    match ExclusiveGuard::try_acquire(&root, LockKind::Background) {
                        Ok(guard) => break guard,
                        Err(PortError::WriterBusy(_)) if Instant::now() < lock_end => {
                            std::thread::yield_now()
                        }
                        Err(error) => return Err(error),
                    }
                };
                {
                    let worker = control.bind_worker(&background, id("synthetic-boot"))?;
                    control.register_worker(
                        selected.control_seq,
                        &worker,
                        std::process::id(),
                        2,
                    )?;
                }
                Ok((selected, background))
            })
            .unwrap();
        let selection = SelectionRevision {
            selection_id: selected.value.id,
            revision: selected.value.revision,
            root_identity: id("synthetic-root"),
        };
        Self {
            _temp: temp,
            root,
            control,
            _background: background,
            selection,
        }
    }
    fn seq(&self) -> ControlSeq {
        bounded(&self.control, || self.control.status())
            .policy
            .control_seq
    }
    fn seed_cycles(&self, count: usize, live: bool, selections: &[SelectionRevision]) {
        let mut conn = raw(&self.root);
        let tx = conn.transaction().unwrap();
        let policy = bounded(&self.control, || self.control.status()).policy;
        for n in 1..=count {
            tx.execute(
                "INSERT INTO cycles VALUES(?1,'synthetic-boot',?2,?3,?4,NULL,NULL,?5)",
                params![
                    number(n),
                    policy.policy_epoch.get(),
                    if live { "queued" } else { "aborted" },
                    policy.control_seq.get(),
                    if live { None } else { Some(3_i64) }
                ],
            )
            .unwrap();
            for selected in selections {
                tx.execute(
                    "INSERT INTO cycle_selections VALUES(?1,?2,?3,0,?4,0,0,0,NULL)",
                    params![
                        number(n),
                        selected.selection_id.as_str(),
                        selected.revision.get(),
                        selected.root_identity.as_str()
                    ],
                )
                .unwrap();
            }
        }
        tx.execute(
            "UPDATE control_meta SET next_cycle_seq=?1",
            [number(count + 1)],
        )
        .unwrap();
        tx.commit().unwrap();
    }
}

#[test]
fn current_indexes_cover_live_lookup_and_ordered_barrier_tail() {
    let f = Fixture::new();
    let conn = raw(&f.root);
    assert_eq!(version(&conn), CONTROL_SCHEMA_VERSION);
    assert_eq!(
        indexes(&conn),
        [
            "barriers_runtime_admission",
            "barriers_runtime_state",
            "cycles_runtime_state"
        ]
    );
    for (query, index) in [
        (
            "SELECT cycle_seq FROM cycles WHERE state IN ('queued','observing')",
            "cycles_runtime_state",
        ),
        (
            "SELECT barrier_id FROM barriers WHERE state='pending'",
            "barriers_runtime_state",
        ),
        (
            "SELECT barrier_id FROM barriers ORDER BY admission_control_seq DESC,barrier_id LIMIT 64",
            "barriers_runtime_admission",
        ),
    ] {
        let mut statement = conn
            .prepare(&format!("EXPLAIN QUERY PLAN {query}"))
            .unwrap();
        let plan: Vec<String> = statement
            .query_map([], |row| row.get(3))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert!(
            plan.iter().any(|step| step.contains(index)),
            "missing index: {plan:?}"
        );
        assert!(
            !plan.iter().any(|step| step.contains("TEMP B-TREE")),
            "temporary sort: {plan:?}"
        );
    }
}

#[test]
fn v1_read_is_unchanged_and_write_upgrade_preserves_policy_and_old_tokens() {
    let f = Fixture::new();
    // Seed and policy changes prepare the old schema fixture. End this scope
    // before the read-only and writable opens start their original budgets.
    let preparation_end = Instant::now() + Duration::from_secs(10);
    let probe_end = preparation_end + Duration::from_secs(10);
    let (mut seed_calls, mut revoke_calls, mut pause_calls) = (0, 0, 0);
    let mut prepare = || {
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe_end),
            preparation_end
        );
        seed_calls += 1;
        f.seed_cycles(80, false, std::slice::from_ref(&f.selection));
        let initial = f.control.status()?;
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe_end),
            preparation_end
        );
        revoke_calls += 1;
        let denied = f.control.revoke_selection(
            initial.policy.control_seq,
            &f.selection.selection_id,
            None,
            4,
        )?;
        assert!(denied.changed);
        assert_eq!(
            denied.control_seq.get(),
            initial.policy.control_seq.get() + 1
        );
        assert_eq!(
            denied.policy_epoch.get(),
            initial.policy.policy_epoch.get() + 1
        );
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe_end),
            preparation_end
        );
        pause_calls += 1;
        let paused = f
            .control
            .set_desired_updates(denied.control_seq, DesiredUpdates::Paused)?;
        assert!(paused.changed);
        assert_eq!(paused.control_seq.get(), denied.control_seq.get() + 1);
        assert_eq!(paused.policy_epoch, denied.policy_epoch);
        let before = f.control.status()?;
        let old = f.control.cycle(CycleSeq::new(1).unwrap())?;
        assert_eq!(before.desired_updates, DesiredUpdates::Paused);
        assert_eq!(before.policy.control_seq, paused.control_seq);
        assert_eq!(before.policy.policy_epoch, paused.policy_epoch);
        assert_eq!(before.policy.revocations, [denied.value.intent]);
        assert_eq!(f.control.purge_jobs()?, [denied.value.purge_job]);
        assert_eq!(
            SqliteControlStore::effective_runtime_deadline(probe_end),
            preparation_end
        );
        Ok::<_, PortError>((before, old))
    };
    let (before, old) = f
        .control
        .with_runtime_deadline(preparation_end, &mut prepare)
        .unwrap();
    assert_eq!((seed_calls, revoke_calls, pause_calls), (1, 1, 1));
    assert_eq!(
        SqliteControlStore::effective_runtime_deadline(probe_end),
        probe_end
    );
    let conn = raw(&f.root);
    make_v1(&conn);
    let read = SqliteControlStore::open_current_read_only_with_deadline(
        &f.root,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(bounded(&read, || read.status()), before);
    assert_eq!(version(&conn), 1);
    assert!(indexes(&conn).is_empty());
    let write = SqliteControlStore::open_existing_writable_with_deadline(
        &f.root,
        &id("synthetic-installation"),
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(version(&conn), CONTROL_SCHEMA_VERSION);
    assert_eq!(indexes(&conn).len(), 3);
    assert_eq!(bounded(&write, || write.status()), before);
    assert_eq!(
        bounded(&write, || write.cycle(CycleSeq::new(1).unwrap())),
        old
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM cycles", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        80
    );
}

#[test]
fn migration_checks_installation_and_rolls_back_on_original_deadline_contention() {
    let f = Fixture::new();
    let conn = raw(&f.root);
    make_v1(&conn);
    let before = bounded(&f.control, || f.control.status());
    assert_corrupt(SqliteControlStore::open_existing_writable_with_deadline(
        &f.root,
        &id("other-installation"),
        Instant::now() + Duration::from_secs(1),
    ));
    assert_eq!(version(&conn), 1);
    assert!(indexes(&conn).is_empty());
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let result = SqliteControlStore::open_existing_writable_with_deadline(
        &f.root,
        &id("synthetic-installation"),
        Instant::now() + Duration::from_millis(25),
    );
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(version(&conn), 1);
    assert!(indexes(&conn).is_empty());
    assert_eq!(bounded(&f.control, || f.control.status()), before);
    let write = SqliteControlStore::open_existing_writable_with_deadline(
        &f.root,
        &id("synthetic-installation"),
        Instant::now() + Duration::from_secs(1),
    )
    .unwrap();
    assert_eq!(bounded(&write, || write.status()), before);
}

#[test]
fn schema_allowlist_rejects_unknown_version_missing_or_extra_index() {
    for sql in [
        "PRAGMA user_version=3; UPDATE control_meta SET schema_version=3",
        "DROP INDEX cycles_runtime_state",
        "CREATE INDEX unowned_runtime_index ON cycles(policy_epoch)",
        "DROP INDEX cycles_runtime_state; CREATE INDEX cycles_runtime_state ON cycles(cycle_seq,state)",
    ] {
        let f = Fixture::new();
        raw(&f.root).execute_batch(sql).unwrap();
        assert_corrupt(SqliteControlStore::open_current_read_only(&f.root));
        assert_corrupt(SqliteControlStore::open_current_writable(&f.root));
    }
}

#[test]
fn expired_admission_and_scope_do_not_execute_or_create_artifacts() {
    let temp = agent_session_grep_testkit::tempdir().unwrap();
    let root = temp.path().join("missing");
    for result in [
        SqliteControlStore::open_current_read_only_with_deadline(&root, Instant::now()),
        SqliteControlStore::open_existing_writable_with_deadline(
            &root,
            &id("synthetic-installation"),
            Instant::now(),
        ),
    ] {
        assert!(matches!(result, Err(PortError::WriterBusy(_))));
    }
    assert!(!root.exists());
    assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    let f = Fixture::new();
    let ran = Cell::new(false);
    let result = f.control.with_runtime_deadline(Instant::now(), || {
        ran.set(true);
        f.control.status()
    });
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
    assert!(!ran.get());
    bounded(&f.control, || f.control.status());
}

#[test]
fn nested_later_deadline_cannot_extend_real_sqlite_writer_wait() {
    let f = Fixture::new();
    let before = bounded(&f.control, || f.control.status());
    let conn = raw(&f.root);
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let started = Instant::now();
    let deadline = started + Duration::from_millis(30);
    let result = f.control.with_runtime_deadline(deadline, || {
        f.control
            .with_runtime_deadline(started + Duration::from_secs(2), || {
                f.control
                    .set_desired_updates(before.policy.control_seq, DesiredUpdates::Paused)
            })
    });
    assert!(matches!(result, Err(PortError::WriterBusy(_))));
    // This distinguishes the original 30ms budget from a renewed 250ms busy
    // allowance. It is a synthetic cancellation regression, not a latency gate.
    assert!(started.elapsed() < Duration::from_millis(200));
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(bounded(&f.control, || f.control.status()), before);
    bounded(&f.control, || {
        f.control
            .set_desired_updates(before.policy.control_seq, DesiredUpdates::Paused)
    });
}

#[test]
fn live_cycle_capacity_is_checked_before_decode_without_dropping_rows() {
    let f = Fixture::new();
    f.seed_cycles(
        MAX_RUNTIME_REFERENCES + 1,
        true,
        std::slice::from_ref(&f.selection),
    );
    let conn = raw(&f.root);
    let before: (i64, i64) = conn
        .query_row(
            "SELECT control_seq,next_cycle_seq FROM control_meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_capacity(
        f.control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(2), || {
                f.control.background_status()
            }),
    );
    assert_capacity(f.control.with_runtime_deadline(
        Instant::now() + Duration::from_secs(2),
        || {
            f.control.queue_cycle(
                ControlSeq::new(before.0).unwrap(),
                vec![f.selection.clone()],
            )
        },
    ));
    assert_eq!(
        conn.query_row("SELECT count(*) FROM cycles", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        number(MAX_RUNTIME_REFERENCES + 1)
    );
    assert_eq!(
        conn.query_row(
            "SELECT control_seq,next_cycle_seq FROM control_meta",
            [],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        )
        .unwrap(),
        before
    );
}

#[test]
fn staged_live_cycle_boundary_accepts_all_proof_but_refuses_a_new_cycle() {
    let f = Fixture::new();
    f.seed_cycles(
        MAX_RUNTIME_REFERENCES,
        true,
        std::slice::from_ref(&f.selection),
    );
    let selected_root = f._temp.path().join("second-selected");
    std::fs::create_dir(&selected_root).unwrap();
    // Add the second selection without scanning an intentionally large runtime.
    // The inserted row uses the actual typed identity and current policy values.
    let conn = raw(&f.root);
    conn.execute("INSERT INTO selections VALUES('second-selection','codex',?1,'root','second-root',1,1,1,NULL)",
        [CanonicalLocator::from_path(&selected_root).unwrap().as_str()]).unwrap();
    let second = SelectionRevision {
        selection_id: id("second-selection"),
        revision: ControlSeq::new(1).unwrap(),
        root_identity: id("second-root"),
    };
    let runtime = bounded(&f.control, || f.control.background_status());
    assert_eq!(
        runtime.next_cycle_seq.get(),
        number(MAX_RUNTIME_REFERENCES + 1)
    );
    let before = f.seq();
    assert_capacity(
        f.control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(10), || {
                f.control.queue_cycle(before, vec![second])
            }),
    );
    assert_eq!(f.seq(), before);
    assert_eq!(
        bounded(&f.control, || f.control.cycle(CycleSeq::new(1).unwrap()))
            .token
            .cycle_seq
            .get(),
        1
    );
}

#[test]
fn source_dependency_union_has_a_front_capacity_bound() {
    let f = Fixture::new();
    f.seed_cycles(
        MAX_RUNTIME_REFERENCES + 1,
        false,
        std::slice::from_ref(&f.selection),
    );
    let mut conn = raw(&f.root);
    let tx = conn.transaction().unwrap();
    for source in 0..=(MAX_RUNTIME_REFERENCES / 2) {
        tx.execute("INSERT INTO source_updates(source_id,provider_id,last_attempt_at_ms,last_observed_cycle,indexed_revision,receipt_cycle,catalog_incarnation,catalog_generation,coverage,update_state,backfill_state)
            VALUES(?1,'codex',3,?2,?3,?4,'synthetic-catalog',1,'complete','idle','complete')",
            params![format!("synthetic-source-{source}"), number(source * 2 + 1), format!("synthetic-revision-{source}"), number((source * 2 + 2).min(MAX_RUNTIME_REFERENCES + 1))]).unwrap();
    }
    tx.execute(
        "UPDATE control_meta SET catalog_incarnation='synthetic-catalog'",
        [],
    )
    .unwrap();
    tx.commit().unwrap();
    assert_capacity(
        f.control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(2), || {
                f.control.background_status()
            }),
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM source_updates", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        number(MAX_RUNTIME_REFERENCES / 2 + 1)
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM cycles", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        number(MAX_RUNTIME_REFERENCES + 1)
    );
}

#[test]
fn relation_capacity_is_checked_before_building_typed_vectors() {
    let f = Fixture::new();
    f.seed_cycles(1, true, &[]);
    let mut conn = raw(&f.root);
    let tx = conn.transaction().unwrap();
    // Deliberately unknown selection references must not be decoded or hidden
    // as a partial list when the front inventory itself exceeds capacity.
    for n in 0..=MAX_RUNTIME_RELATIONS {
        tx.execute(
            "INSERT INTO cycle_selections VALUES(1,?1,1,0,'synthetic-root',0,0,0,NULL)",
            [format!("synthetic-selection-{n}")],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    assert_capacity(
        f.control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(2), || {
                f.control.background_status()
            }),
    );
    assert_eq!(
        conn.query_row("SELECT count(*) FROM cycle_selections", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        number(MAX_RUNTIME_RELATIONS + 1)
    );
}

#[test]
fn pending_barrier_inventory_and_new_admission_refuse_capacity_without_mutation() {
    let f = Fixture::new();
    f.seed_cycles(1, true, std::slice::from_ref(&f.selection));
    let mut conn = raw(&f.root);
    let tx = conn.transaction().unwrap();
    let policy = bounded(&f.control, || f.control.status()).policy;
    let before = policy.control_seq;
    for n in 0..=MAX_RUNTIME_REFERENCES {
        let barrier = format!("synthetic-barrier-{n:05}");
        tx.execute(
            "INSERT INTO barriers VALUES(?1,?2,?3,1,'pending',1000,3,NULL,NULL,NULL)",
            params![barrier, policy.policy_epoch.get(), before.get()],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO barrier_selections VALUES(?1,?2,?3)",
            params![
                barrier,
                f.selection.selection_id.as_str(),
                f.selection.revision.get()
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    assert_capacity(
        f.control
            .with_runtime_deadline(Instant::now() + Duration::from_secs(2), || {
                f.control.background_status()
            }),
    );
    assert_capacity(f.control.with_runtime_deadline(
        Instant::now() + Duration::from_secs(2),
        || {
            f.control.admit_latest(
                before,
                LatestRequest {
                    selections: vec![f.selection.clone()],
                    max_wait_ms: 1000,
                    now_ms: 4,
                },
            )
        },
    ));
    let count: i64 = conn
        .query_row("SELECT count(*) FROM barriers", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, number(MAX_RUNTIME_REFERENCES + 1));
    conn.execute(
        "DELETE FROM barrier_selections WHERE barrier_id='synthetic-barrier-16384'",
        [],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM barriers WHERE barrier_id='synthetic-barrier-16384'",
        [],
    )
    .unwrap();
    assert!(
        bounded(&f.control, || f.control.background_status())
            .worker
            .boot_id
            .is_some()
    );
    assert_capacity(f.control.with_runtime_deadline(
        Instant::now() + Duration::from_secs(10),
        || {
            f.control.admit_latest(
                before,
                LatestRequest {
                    selections: vec![f.selection.clone()],
                    max_wait_ms: 1000,
                    now_ms: 4,
                },
            )
        },
    ));
    let after: (i64, i64) = conn
        .query_row(
            "SELECT control_seq,next_cycle_seq FROM control_meta",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(after, (before.get(), 2));
    assert_eq!(
        conn.query_row("SELECT count(*) FROM barriers", [], |row| row
            .get::<_, i64>(0))
            .unwrap(),
        number(MAX_RUNTIME_REFERENCES)
    );
}

#[test]
fn source_row_and_policy_inventory_capacity_refuse_before_typed_decode() {
    for table in ["source_updates", "selections"] {
        let f = Fixture::new();
        let mut conn = raw(&f.root);
        let tx = conn.transaction().unwrap();
        for n in 0..=MAX_RUNTIME_REFERENCES {
            if table == "source_updates" {
                tx.execute("INSERT INTO source_updates(source_id,provider_id,coverage,update_state,backfill_state)
                    VALUES(?1,'codex','empty','offline','pending')", [format!("synthetic-source-{n}")]).unwrap();
            } else {
                tx.execute("INSERT INTO selections VALUES(?1,'codex','/synthetic/unknown','root','synthetic-root',1,1,1,NULL)",
                    [format!("synthetic-selection-{n}")]).unwrap();
            }
        }
        tx.commit().unwrap();
        assert_capacity(f.control.with_runtime_deadline(
            Instant::now() + Duration::from_secs(2),
            || {
                if table == "source_updates" {
                    f.control.read_policy(RequestIntersection::Selected)
                } else {
                    f.control.status().map(|status| status.policy)
                }
            },
        ));
        assert!(
            conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row
                .get::<_, i64>(0))
                .unwrap()
                > number(MAX_RUNTIME_REFERENCES)
        );
    }
}

#[test]
#[ignore = "raw timing microbenchmark; run explicitly in release mode"]
fn policy_admission_skips_runtime_decode_timing() {
    const SOURCES: usize = 4_000;
    let f = Fixture::new();
    let mut conn = raw(&f.root);
    let tx = conn.transaction().unwrap();
    for n in 0..SOURCES {
        tx.execute(
            "INSERT INTO source_updates(source_id,provider_id,coverage,update_state,backfill_state)
             VALUES(?1,'codex','empty','offline','pending')",
            [format!("synthetic-source-{n}")],
        )
        .unwrap();
    }
    tx.commit().unwrap();

    let mut policy_ms = Vec::new();
    let mut status_ms = Vec::new();
    for _ in 0..4 {
        let start = Instant::now();
        f.control
            .read_policy(RequestIntersection::Selected)
            .unwrap();
        policy_ms.push(start.elapsed().as_secs_f64() * 1000.0);

        let start = Instant::now();
        f.control.status().unwrap();
        status_ms.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    eprintln!("sources={SOURCES} read_policy_ms={policy_ms:?} status_ms={status_ms:?}");
}
