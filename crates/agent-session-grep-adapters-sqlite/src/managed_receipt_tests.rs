//! Real SQLite receipt/publication regressions with wholly synthetic metadata.
//! Use the crate's actual private modules so discovery's source-context checks
//! share the production implementation without expanding the public API.

use crate::{
    SCHEMA_VERSION, SourceBatch,
    managed::{
        create_schema, finalize_publications_in_tx, initialize_catalog_in_tx, publish_source_in_tx,
    },
    managed_discovery, managed_receipt,
};
use agent_session_grep_ports::{
    PortError, SearchProvider,
    managed::{
        DiscoveryObservation, DiscoverySource, ObservationState, RevisionId, RevisionRef,
        SelectionProof, SourceBinding, SourceId, SourceObservation,
    },
};
use rusqlite::{Connection, params, types::Value};

fn schema() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys=ON; CREATE TABLE store_metadata(singleton INTEGER PRIMARY KEY,active_generation INTEGER NOT NULL,projection_contract_version INTEGER NOT NULL DEFAULT 0,managed_mode INTEGER NOT NULL DEFAULT 0,destructive_epoch INTEGER NOT NULL DEFAULT 0); INSERT INTO store_metadata VALUES(1,0,0,0,0); BEGIN IMMEDIATE;").unwrap();
    create_schema(&conn).unwrap();
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)
        .unwrap();
    initialize_catalog_in_tx(&conn, "synthetic-installation", "synthetic-incarnation", 1).unwrap();
    conn.execute_batch("COMMIT").unwrap();
    conn
}
fn observation(source: &str, cycle: i64, state: ObservationState) -> SourceObservation {
    SourceObservation {
        binding: SourceBinding {
            source_id: SourceId::parse(source).unwrap(),
            source_path: format!("synthetic-source-{source}"),
            provider: SearchProvider::Codex,
            namespace_id: None,
            root_identity: "synthetic-root".into(),
        },
        revision_id: RevisionId::parse(&format!("receipt-{source}-{cycle}")).unwrap(),
        revision_digest: format!("fingerprint-{source}-{cycle}"),
        parser_version: 1,
        state,
        cycle_seq: cycle,
        worker_boot_id: "synthetic-boot".into(),
        catalog_incarnation: "synthetic-incarnation".into(),
        policy_epoch: 1,
        started_control_seq: 10 + cycle,
        observed_at_ms: cycle * 10,
        committed_at_ms: cycle * 10 + 1,
        selections: vec![SelectionProof {
            selection_id: "synthetic-selection".into(),
            selection_revision: 1,
            root_identity: "synthetic-root".into(),
        }],
        repositories: vec![],
    }
}
fn publish(conn: &Connection, source: &str, cycle: i64, state: ObservationState) -> RevisionRef {
    let observation = observation(source, cycle, state);
    // A fully observed empty source is legitimate, including confirmed deletion.
    // The actual publisher still writes its content fingerprint and origin id.
    let batch = SourceBatch {
        source_path: observation.binding.source_path.clone(),
        entries: vec![],
        placements: vec![],
        edges: vec![],
        activities: vec![],
        usage_events: vec![],
        relation_complete: true,
        len_bytes: Some(0),
        fingerprint: Some(observation.revision_digest.clone()),
        provider_id: Some("codex".into()),
        resume_claims: vec![],
    };
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let generation: i64 = conn
        .query_row(
            "SELECT active_generation FROM store_metadata WHERE singleton=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let mut publication = publish_source_in_tx(conn, &batch, &observation, generation + 1).unwrap();
    conn.execute(
        "UPDATE store_metadata SET active_generation=?1 WHERE singleton=1",
        [publication.required_generation],
    )
    .unwrap();
    finalize_publications_in_tx(conn, std::slice::from_mut(&mut publication)).unwrap();
    conn.execute_batch("COMMIT").unwrap();
    publication.receipt
}
fn discovery(cycle: i64, sources: Vec<DiscoverySource>) -> DiscoveryObservation {
    DiscoveryObservation {
        cycle_seq: cycle,
        worker_boot_id: "synthetic-boot".into(),
        catalog_incarnation: "synthetic-incarnation".into(),
        policy_epoch: 1,
        started_control_seq: 10 + cycle,
        selection: SelectionProof {
            selection_id: "synthetic-selection".into(),
            selection_revision: 1,
            root_identity: "synthetic-root".into(),
        },
        sources,
        complete: true,
    }
}
fn discovered(source: &str, revision: &RevisionRef) -> DiscoverySource {
    DiscoverySource {
        source_id: SourceId::parse(source).unwrap(),
        revision_id: revision.revision_id.clone(),
    }
}
fn try_discovery(conn: &Connection, input: &DiscoveryObservation) -> Result<(), PortError> {
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    let result = managed_discovery::publish_in_tx(conn, input);
    conn.execute_batch(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })
        .unwrap();
    result
}
fn state(conn: &Connection) -> Vec<Vec<Vec<Value>>> {
    [
        "source_bindings",
        "source_heads",
        "source_revision_receipts",
        "receipt_selection_claims",
        "source_scope_claims",
        "discovery_receipts",
        "discovery_sources",
    ]
    .into_iter()
    .map(|table| {
        let mut statement = conn
            .prepare(&format!("SELECT * FROM {table} ORDER BY 1,2"))
            .unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| {
                (0..columns)
                    .map(|column| row.get(column))
                    .collect::<rusqlite::Result<Vec<Value>>>()
            })
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    })
    .collect()
}
fn assert_corrupt(result: Result<RevisionRef, PortError>) {
    assert!(
        matches!(result, Err(PortError::SchemaIncompatible(_))),
        "malformed persisted receipt must fail closed"
    );
}

#[test]
fn real_published_noop_and_all_unpublished_shapes_decode_without_mutation() {
    let conn = schema();
    let first = publish(&conn, "source-a", 1, ObservationState::Complete);
    let second = publish(&conn, "source-a", 2, ObservationState::Complete);
    let states = [
        ObservationState::Incomplete,
        ObservationState::Unstable,
        ObservationState::RewritePending,
        ObservationState::DeletionPending,
    ];
    let held: Vec<_> = states
        .into_iter()
        .enumerate()
        .map(|(index, state)| publish(&conn, "source-a", index as i64 + 3, state))
        .collect();
    let initial_partial = publish(&conn, "source-b", 1, ObservationState::Incomplete);
    let before = state(&conn);
    for expected in std::iter::once(&first)
        .chain(std::iter::once(&second))
        .chain(held.iter())
    {
        assert_eq!(
            managed_receipt::read_checked(&conn, expected.revision_id.as_str(), Some("source-a"))
                .unwrap(),
            *expected
        );
    }
    assert_eq!(
        managed_receipt::read_checked(
            &conn,
            initial_partial.revision_id.as_str(),
            Some("source-b")
        )
        .unwrap(),
        initial_partial
    );
    assert_eq!(
        state(&conn),
        before,
        "decoder must not repair receipt/source/head state"
    );
    let origin: String = conn
        .query_row(
            "SELECT content_revision_id FROM source_revision_receipts WHERE revision_id=?1",
            [second.revision_id.as_str()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        origin,
        first.revision_id.as_str(),
        "unchanged publication retains the actual earlier content receipt"
    );
}

#[test]
fn historical_incarnation_is_structural_metadata_and_never_current_discovery() {
    let conn = schema();
    let expected = publish(&conn, "source-a", 1, ObservationState::Complete);
    conn.execute(
        "UPDATE catalog_meta SET catalog_incarnation='rotated-incarnation' WHERE singleton=1",
        [],
    )
    .unwrap();
    let before = state(&conn);
    assert_eq!(
        managed_receipt::read_checked(&conn, expected.revision_id.as_str(), Some("source-a"))
            .unwrap(),
        expected
    );
    assert_eq!(state(&conn), before);
    let mut current = discovery(1, vec![discovered("source-a", &expected)]);
    current.catalog_incarnation = "rotated-incarnation".into();
    assert!(matches!(
        try_discovery(&conn, &current),
        Err(PortError::InvalidRequest(_))
    ));
    assert_eq!(
        state(&conn),
        before,
        "no current receipt may be forged from a historical origin"
    );
}

#[test]
fn source_head_pointer_to_another_receipt_is_not_its_owners_proof() {
    let conn = schema();
    let a = publish(&conn, "source-a", 1, ObservationState::Complete);
    let _b = publish(&conn, "source-b", 1, ObservationState::Complete);
    conn.execute("UPDATE source_heads SET latest_receipt_id=?1,last_attempt_id=?1 WHERE source_id='source-b'", [a.revision_id.as_str()]).unwrap();
    let pointer: String = conn
        .query_row(
            "SELECT latest_receipt_id FROM source_heads WHERE source_id='source-b'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let before = state(&conn);
    assert_corrupt(managed_receipt::read_checked(
        &conn,
        &pointer,
        Some("source-b"),
    ));
    assert_eq!(
        managed_receipt::read_checked(&conn, &pointer, Some("source-a")).unwrap(),
        a
    );
    assert_corrupt(managed_receipt::read_checked(
        &conn,
        &pointer,
        Some("missing-source"),
    ));
    assert!(
        try_discovery(
            &conn,
            &discovery(
                1,
                vec![DiscoverySource {
                    source_id: SourceId::parse("source-b").unwrap(),
                    revision_id: a.revision_id.clone()
                }]
            )
        )
        .is_err()
    );
    assert_eq!(state(&conn), before);
}

#[test]
fn schema_valid_malformed_published_metadata_is_rejected_by_decoder_and_publication() {
    for assignment in [
        "parser_version=0",
        "parser_version=-1",
        "parser_version=4294967296",
        "parser_version='not-an-integer'",
        "cycle_seq=0",
        "cycle_seq=-1",
        "started_control_seq=0",
        "started_control_seq=-1",
        "policy_epoch=-1",
        "observed_at_ms=-1",
        "committed_at_ms=-1",
        "committed_generation=-1",
        "worker_boot_id=''",
        "worker_boot_id='synthetic-invalid/id'",
        "catalog_incarnation=''",
        "catalog_incarnation='synthetic-invalid/id'",
        "revision_digest=''",
        "revision_digest=char(10)",
        "revision_digest=printf('%0300d',0)",
        "content_revision_id=NULL",
        "content_revision_id='missing-receipt'",
        "content_revision_id='synthetic-invalid/id'",
        "content_set_digest=NULL",
        "content_set_digest='bad-digest'",
        "content_set_digest=upper(content_set_digest)",
        "reason='incomplete'",
    ] {
        let conn = schema();
        let receipt = publish(&conn, "source-a", 1, ObservationState::Complete);
        conn.execute(
            &format!("UPDATE source_revision_receipts SET {assignment} WHERE revision_id=?1"),
            [receipt.revision_id.as_str()],
        )
        .unwrap();
        let before = state(&conn);
        assert_corrupt(managed_receipt::read_checked(
            &conn,
            receipt.revision_id.as_str(),
            Some("source-a"),
        ));
        assert!(
            matches!(
                try_discovery(&conn, &discovery(1, vec![discovered("source-a", &receipt)])),
                Err(PortError::SchemaIncompatible(_))
            ),
            "invalid metadata must never reach complete discovery: {assignment}"
        );
        assert_eq!(
            state(&conn),
            before,
            "refusal must not mutate source/discovery: {assignment}"
        );
    }
}

#[test]
fn unpublished_attempt_shape_and_retained_content_are_checked() {
    for assignment in [
        "parser_version=0",
        "cycle_seq=0",
        "started_control_seq=0",
        "observed_at_ms=-1",
        "policy_epoch=-1",
        "worker_boot_id=''",
        "catalog_incarnation=''",
        "revision_digest=''",
        "reason=NULL",
        "reason=''",
        "reason='guessed-failure'",
        "committed_generation=0",
        "committed_at_ms=1",
        "content_set_digest=printf('%064d',0)",
        "content_revision_id='missing-receipt'",
        "content_revision_id=revision_id",
    ] {
        let conn = schema();
        publish(&conn, "source-a", 1, ObservationState::Complete);
        let attempt = publish(&conn, "source-a", 2, ObservationState::RewritePending);
        conn.execute(
            &format!("UPDATE source_revision_receipts SET {assignment} WHERE revision_id=?1"),
            [attempt.revision_id.as_str()],
        )
        .unwrap();
        let before = state(&conn);
        assert_corrupt(managed_receipt::read_checked(
            &conn,
            attempt.revision_id.as_str(),
            Some("source-a"),
        ));
        assert!(
            try_discovery(&conn, &discovery(2, vec![discovered("source-a", &attempt)])).is_err()
        );
        assert_eq!(
            state(&conn),
            before,
            "bad unpublished attempt must remain unchanged: {assignment}"
        );
    }
}

#[test]
fn content_origin_must_be_same_source_published_and_earlier() {
    let conn = schema();
    let first = publish(&conn, "source-a", 1, ObservationState::Complete);
    let latest = publish(&conn, "source-a", 2, ObservationState::Complete);
    let other = publish(&conn, "source-b", 1, ObservationState::Complete);
    conn.execute(
        "UPDATE source_revision_receipts SET content_revision_id=?1 WHERE revision_id=?2",
        params![other.revision_id.as_str(), latest.revision_id.as_str()],
    )
    .unwrap();
    assert_corrupt(managed_receipt::read_checked(
        &conn,
        latest.revision_id.as_str(),
        Some("source-a"),
    ));
    conn.execute(
        "UPDATE source_revision_receipts SET content_revision_id=?1 WHERE revision_id=?2",
        params![first.revision_id.as_str(), latest.revision_id.as_str()],
    )
    .unwrap();
    conn.execute(
        "UPDATE source_revision_receipts SET content_set_digest=?1 WHERE revision_id=?2",
        params!["0".repeat(64), latest.revision_id.as_str()],
    )
    .unwrap();
    assert_corrupt(managed_receipt::read_checked(
        &conn,
        latest.revision_id.as_str(),
        Some("source-a"),
    ));
    let attempt = publish(&conn, "source-a", 3, ObservationState::Incomplete);
    conn.execute(
        "UPDATE source_revision_receipts SET content_revision_id=?1 WHERE revision_id=?2",
        params![attempt.revision_id.as_str(), latest.revision_id.as_str()],
    )
    .unwrap();
    assert_corrupt(managed_receipt::read_checked(
        &conn,
        latest.revision_id.as_str(),
        Some("source-a"),
    ));
}

#[test]
fn every_source_is_checked_before_complete_discovery_is_promoted() {
    let conn = schema();
    let a = publish(&conn, "source-a", 1, ObservationState::Complete);
    let b = publish(&conn, "source-b", 1, ObservationState::Complete);
    let mut begin = discovery(1, vec![]);
    begin.complete = false;
    try_discovery(&conn, &begin).unwrap();
    conn.execute(
        "UPDATE source_revision_receipts SET parser_version=0 WHERE revision_id=?1",
        [b.revision_id.as_str()],
    )
    .unwrap();
    let before = state(&conn);
    let complete = discovery(
        1,
        vec![discovered("source-a", &a), discovered("source-b", &b)],
    );
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(managed_discovery::publish_in_tx(&conn, &complete).is_err());
    assert_eq!(
        state(&conn),
        before,
        "a later invalid source must leave no writes even before caller rollback"
    );
    conn.execute_batch("ROLLBACK").unwrap();
    let stored_complete: i64 = conn
        .query_row(
            "SELECT complete FROM discovery_receipts WHERE cycle_seq=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_complete, 0);
    conn.execute(
        "UPDATE source_revision_receipts SET parser_version=1 WHERE revision_id=?1",
        [b.revision_id.as_str()],
    )
    .unwrap();
    try_discovery(&conn, &complete).unwrap();
    let count: i64 = conn
        .query_row(
            "SELECT count(*) FROM discovery_sources WHERE cycle_seq=1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(count, 2);
    let committed = state(&conn);
    try_discovery(&conn, &complete).unwrap();
    assert_eq!(
        state(&conn),
        committed,
        "identical completed publication is idempotent"
    );
}

#[test]
fn missing_invalid_and_orphaned_receipts_fail_with_content_free_errors() {
    let conn = schema();
    let receipt = publish(&conn, "source-a", 1, ObservationState::Complete);
    let error =
        managed_receipt::read_checked(&conn, "missing-receipt", Some("source-a")).unwrap_err();
    assert!(!error.to_string().contains("missing-receipt"));
    assert!(matches!(
        managed_receipt::read_checked(&conn, "private-invalid/ref", None),
        Err(PortError::InvalidRequest(_))
    ));
    assert!(matches!(
        managed_receipt::read_checked(
            &conn,
            receipt.revision_id.as_str(),
            Some("private-invalid/source")
        ),
        Err(PortError::InvalidRequest(_))
    ));
    conn.execute_batch(
        "PRAGMA foreign_keys=OFF; DELETE FROM source_bindings WHERE source_id='source-a'",
    )
    .unwrap();
    let before = state(&conn);
    assert_corrupt(managed_receipt::read_checked(
        &conn,
        receipt.revision_id.as_str(),
        Some("source-a"),
    ));
    assert_eq!(state(&conn), before);
}

#[test]
fn wall_clock_backwards_and_valid_append_shape_do_not_invent_current_proof() {
    let conn = schema();
    let mut expected = publish(&conn, "source-a", 1, ObservationState::Complete);
    conn.execute("UPDATE source_revision_receipts SET completeness='append',observed_at_ms=10,committed_at_ms=1 WHERE revision_id=?1", [expected.revision_id.as_str()]).unwrap();
    expected.observed_at_ms = 10;
    assert_eq!(
        managed_receipt::read_checked(&conn, expected.revision_id.as_str(), Some("source-a"))
            .unwrap(),
        expected
    );
}

#[test]
fn retained_content_cannot_have_a_generation_later_than_its_published_observation() {
    let conn = schema();
    let first = publish(&conn, "source-a", 1, ObservationState::Complete);
    let latest = publish(&conn, "source-a", 2, ObservationState::Complete);
    let later_generation = latest.committed_generation.unwrap() + 1;
    conn.execute(
        "UPDATE store_metadata SET active_generation=?1 WHERE singleton=1",
        [later_generation],
    )
    .unwrap();
    conn.execute(
        "UPDATE source_revision_receipts SET committed_generation=?1 WHERE revision_id=?2",
        params![later_generation, first.revision_id.as_str()],
    )
    .unwrap();
    let before = state(&conn);
    assert_corrupt(managed_receipt::read_checked(
        &conn,
        latest.revision_id.as_str(),
        Some("source-a"),
    ));
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        managed_discovery::publish_in_tx(
            &conn,
            &discovery(2, vec![discovered("source-a", &latest)])
        ),
        Err(PortError::SchemaIncompatible(_))
    ));
    assert_eq!(state(&conn), before);
    conn.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn bounded_text_digest_and_earlier_content_survive_boot_and_parser_changes() {
    let conn = schema();
    let first = publish(&conn, "source-a", 1, ObservationState::Complete);
    let mut current = publish(&conn, "source-a", 2, ObservationState::Complete);
    conn.execute(
        "UPDATE source_revision_receipts SET revision_digest='full-fingerprint',parser_version=4294967295,worker_boot_id='next-boot',cycle_seq=1 WHERE revision_id=?1",
        [current.revision_id.as_str()],
    )
    .unwrap();
    current.digest = "full-fingerprint".into();
    current.worker_boot_id = "next-boot".into();
    current.cycle_seq = 1;
    let before = state(&conn);
    assert_eq!(
        managed_receipt::read_checked(&conn, current.revision_id.as_str(), Some("source-a"))
            .unwrap(),
        current
    );
    assert_eq!(
        managed_receipt::read_checked(&conn, first.revision_id.as_str(), Some("source-a")).unwrap(),
        first
    );
    assert_eq!(state(&conn), before);
    let mut current_discovery = discovery(1, vec![discovered("source-a", &current)]);
    current_discovery.worker_boot_id = current.worker_boot_id;
    current_discovery.started_control_seq = current.started_control_seq;
    try_discovery(&conn, &current_discovery).unwrap();
}
