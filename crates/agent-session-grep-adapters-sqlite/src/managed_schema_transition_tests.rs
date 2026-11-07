use super::*;
use crate::managed_schema_transition::ddl;
use rusqlite::{Connection, params};

fn hash_stats(rows: &[Vec<u8>], present: bool) -> Result<[u8; 32]> {
    let mut hash = CatalogCommitment::new();
    for table in &TABLES {
        let is_stats = table.ordinal == 65;
        hash.begin_table(
            table.ordinal,
            !table.optional || (is_stats && present),
            if is_stats { rows.len() as u64 } else { 0 },
        )?;
        if is_stats {
            for row in rows {
                hash.push_row(&decode_cells(row, table.columns.len())?)?;
            }
        }
        hash.end_table()?;
    }
    hash.finish()
}

#[test]
fn statistics_numeric_ties_use_typed_bytes_and_preserve_duplicates() {
    let db = Connection::open_in_memory().unwrap();
    // No affinity on the last column: this is the raw scalar source consumed
    // by the projection, so SQLite must retain INTEGER and REAL separately.
    db.execute_batch("CREATE TABLE sample(tbl,idx,value);")
        .unwrap();
    let mut commitments = Vec::new();
    for reverse in [false, true] {
        db.execute("DELETE FROM sample", []).unwrap();
        if reverse {
            db.execute_batch("INSERT INTO sample VALUES('t','i',1.0),('t','i',1);")
                .unwrap();
        } else {
            db.execute_batch("INSERT INTO sample VALUES('t','i',1),('t','i',1.0);")
                .unwrap();
        }
        let mut statement = db
            .prepare("SELECT tbl,idx,value,typeof(value) FROM sample ORDER BY tbl,idx,value")
            .unwrap();
        let mut query = statement.query([]).unwrap();
        let mut bytes = Vec::new();
        let mut kinds = Vec::new();
        while let Some(row) = query.next().unwrap() {
            let cell = match row.get_ref(2).unwrap() {
                rusqlite::types::ValueRef::Integer(value) => Cell::Integer(value),
                rusqlite::types::ValueRef::Real(value) => Cell::Real(value),
                _ => panic!("fixture lost its numeric storage class"),
            };
            kinds.push(row.get::<_, String>(3).unwrap());
            let mut encoded = Vec::new();
            encode_row(&[Cell::Text(b"t"), Cell::Text(b"i"), cell], &mut encoded).unwrap();
            bytes.push(encoded);
        }
        kinds.sort();
        assert_eq!(kinds, ["integer", "real"]);
        assert_ne!(bytes[0], bytes[1]);
        bytes.sort_by(|a, b| compare_rows(65, a, b).unwrap());
        commitments.push(hash_stats(&bytes, true).unwrap());
        assert_ne!(
            hash_stats(&[bytes[0].clone(), bytes[0].clone()], true).unwrap(),
            commitments[0]
        );
        let mut duplicate = bytes.clone();
        duplicate.insert(0, bytes[0].clone());
        assert_ne!(hash_stats(&duplicate, true).unwrap(), commitments[0]);
        bytes.reverse();
        assert_eq!(hash_stats(&bytes, true), Err(CommitmentError::Unordered));
    }
    assert_eq!(commitments[0], commitments[1]);
    assert_ne!(
        hash_stats(&[], true).unwrap(),
        hash_stats(&[], false).unwrap()
    );
}

#[test]
fn streaming_commitment_refuses_omissions_types_order_and_poisoned_reuse() {
    assert!(CatalogCommitment::new().finish().is_err());
    let mut hash = CatalogCommitment::new();
    assert!(hash.begin_table(2, true, 0).is_err());
    assert!(hash.begin_table(1, true, 0).is_err());
    let mut hash = CatalogCommitment::new();
    hash.begin_table(1, true, 1).unwrap();
    assert!(
        hash.push_row(&[Cell::Text(b"id"), Cell::Text(b"wrong")])
            .is_err()
    );
    assert!(hash.end_table().is_err());
    let mut hash = CatalogCommitment::new();
    hash.begin_table(1, true, 1).unwrap();
    assert!(hash.end_table().is_err());
    let mut hash = CatalogCommitment::new();
    hash.begin_table(1, true, 2).unwrap();
    hash.push_row(&[Cell::Text(b"z"), Cell::Blob(b"payload")])
        .unwrap();
    assert_eq!(
        hash.push_row(&[Cell::Text(b"a"), Cell::Blob(b"payload")]),
        Err(CommitmentError::Unordered)
    );
}

#[test]
fn fixed_projection_is_complete_and_preserves_fts_and_numeric_boundaries() {
    assert_eq!(TABLES.len(), 66);
    for (index, table) in TABLES.iter().enumerate() {
        assert_eq!(usize::from(table.ordinal), index + 1);
        assert_eq!(table.storage.len(), table.columns.len());
        assert!(
            table
                .order
                .iter()
                .all(|column| *column < table.columns.len())
        );
        assert_eq!(table.optional, index >= 64);
    }
    assert_eq!(
        TABLES[24].columns,
        [
            "singleton",
            "installation_id",
            "catalog_incarnation",
            "created_at_ms"
        ]
    );
    assert_eq!(TABLES[46].name, "fts_data");
    assert_eq!(TABLES[63].name, "session_metadata_fts_config");
    assert_eq!(
        integer_real(9_007_199_254_740_993, 9_007_199_254_740_992.0),
        Ordering::Greater
    );
    assert_eq!(
        integer_real(i64::MAX, 9_223_372_036_854_775_808.0),
        Ordering::Less
    );
    let mut bytes = Vec::new();
    encode_row(&[Cell::Integer(1), Cell::Real(1.0)], &mut bytes).unwrap();
    assert_eq!(bytes[0], 1);
    assert_eq!(bytes[9], 4);
    assert!(encode_row(&[Cell::Real(f64::NAN)], &mut bytes).is_err());
}

fn read_fixture_commitment(db: &Connection) -> [u8; 32] {
    let mut hash = CatalogCommitment::new();
    for table in &TABLES {
        let present: bool = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name=?1)",
                [table.name],
                |row| row.get(0),
            )
            .unwrap();
        if !present {
            hash.begin_table(table.ordinal, false, 0).unwrap();
            hash.end_table().unwrap();
            continue;
        }
        let count: i64 = db
            .query_row(&format!("SELECT count(*) FROM {}", table.name), [], |row| {
                row.get(0)
            })
            .unwrap();
        let count = u64::try_from(count).expect("SQL row count must be nonnegative");
        // The real fresh catalog has no optional statistics. Their raw numeric
        // ties are tested separately above.
        assert!(!table.optional);
        let keys: Vec<_> = table
            .order
            .iter()
            .map(|index| table.columns[*index])
            .collect();
        let mut statement = db
            .prepare(&format!(
                "SELECT {} FROM {} ORDER BY {}",
                table.columns.join(","),
                table.name,
                keys.join(","),
            ))
            .unwrap();
        let mut query = statement.query([]).unwrap();
        hash.begin_table(table.ordinal, true, count).unwrap();
        while let Some(row) = query.next().unwrap() {
            let cells: Vec<_> = (0..table.columns.len())
                .map(|column| match row.get_ref(column).unwrap() {
                    rusqlite::types::ValueRef::Null => Cell::Null,
                    rusqlite::types::ValueRef::Integer(value) => Cell::Integer(value),
                    rusqlite::types::ValueRef::Real(value) => Cell::Real(value),
                    rusqlite::types::ValueRef::Text(value) => Cell::Text(value),
                    rusqlite::types::ValueRef::Blob(value) => Cell::Blob(value),
                })
                .collect();
            hash.push_row(&cells).unwrap();
        }
        hash.end_table().unwrap();
    }
    hash.finish().unwrap()
}

#[test]
fn production_catalog_columns_and_actual_fts_shadows_are_committed() {
    let db = Connection::open_in_memory().unwrap();
    crate::SqliteStore::init(&db).unwrap();
    db.execute(
        "INSERT INTO catalog_meta(singleton,installation_id,catalog_incarnation,created_at_ms)
         VALUES(1,'installation','incarnation',1)",
        [],
    )
    .unwrap();
    let original = read_fixture_commitment(&db);
    db.execute(
        "INSERT INTO fts(id,text) VALUES('synthetic','original evidence')",
        [],
    )
    .unwrap();
    let with_fts = read_fixture_commitment(&db);
    assert_ne!(original, with_fts);
    db.execute(
        "INSERT INTO catalog(id,payload) VALUES('synthetic',?1)",
        [b"raw original".as_slice()],
    )
    .unwrap();
    assert_ne!(with_fts, read_fixture_commitment(&db));
    db.execute_batch(ddl::CATALOG_TABLES).unwrap();
    db.execute_batch(ddl::CATALOG_RECEIPT_COLUMN).unwrap();
    let before_marker = read_fixture_commitment(&db);
    assert_eq!(
        db.execute(
            "UPDATE catalog_meta SET repository_transition_receipt=X'7b7d'",
            []
        )
        .unwrap(),
        1
    );
    assert_eq!(before_marker, read_fixture_commitment(&db));
}

fn proof_db() -> Connection {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch(
        "PRAGMA foreign_keys=ON;
         CREATE TABLE source_bindings(source_id TEXT PRIMARY KEY);
         CREATE TABLE source_revision_receipts(revision_id TEXT PRIMARY KEY);
         INSERT INTO source_bindings VALUES('source');
         INSERT INTO source_revision_receipts VALUES('revision');",
    )
    .unwrap();
    db.execute_batch(ddl::CATALOG_TABLES).unwrap();
    db
}

#[test]
fn repository_anchor_matrix_keeps_real_negative_unit_variants() {
    let db = proof_db();
    let mut ordinal = 0;
    for (resolution, anchor, start, end, allowed) in [
        ("missing", None, None, None, true),
        ("missing", Some("repository"), Some(0), Some(1), false),
        ("resolved", None, None, None, false),
        ("resolved", Some("repository"), Some(0), Some(1), true),
        ("ambiguous", None, None, None, true),
        ("unusable", None, None, None, true),
        ("ambiguous", Some("repository"), Some(0), Some(1), true),
        ("unusable", Some("repository"), None, Some(1), false),
        ("unusable", None, Some(0), Some(1), false),
        ("resolved", Some("repository"), Some(1), Some(1), false),
        ("resolved", Some("cwd_pair"), Some(0), Some(1), false),
    ] {
        ordinal += 1;
        let result = db.execute(
            "INSERT INTO source_repository_proofs
             (proof_id,source_id,source_revision_id,session_id,proof_ordinal,origin,resolution,
              source_snapshot_blake3,anchor_kind,anchor_start,anchor_end,repo_slug)
             VALUES(?1,'source','revision','ses_v1_fixture',?2,'transcript',?3,zeroblob(32),?4,?5,?6,?7)",
            params![format!("proof_{ordinal}"), ordinal, resolution, anchor, start, end,
                (resolution == "resolved").then_some("example/owner/repo")],
        );
        assert_eq!(
            result.is_ok(),
            allowed,
            "{resolution} {anchor:?} {start:?} {end:?}"
        );
    }
    for anchor in [None, Some("repository"), Some("cwd_pair")] {
        ordinal += 1;
        let result = db.execute(
            "INSERT INTO source_repository_proofs
             (proof_id,source_id,source_revision_id,session_id,proof_ordinal,origin,resolution,
              source_snapshot_blake3,anchor_kind,anchor_start,anchor_end,grant_id,authorization_revision)
             VALUES(?1,'source','revision','ses_v1_fixture',?2,'metadata','denied',zeroblob(32),?3,0,1,'grant',1)",
            params![format!("proof_{ordinal}"), ordinal, anchor],
        );
        assert_eq!(result.is_ok(), anchor == Some("cwd_pair"));
    }
}

#[test]
fn inert_ddl_creates_only_four_tables_and_keeps_meta_receipt_boundaries() {
    let db = proof_db();
    db.execute_batch(
        "CREATE TABLE catalog_meta(singleton INTEGER PRIMARY KEY);
         CREATE TABLE control_meta(singleton INTEGER PRIMARY KEY);
         INSERT INTO catalog_meta VALUES(1); INSERT INTO control_meta VALUES(1);",
    )
    .unwrap();
    db.execute_batch(ddl::CONTROL_TABLES).unwrap();
    db.execute_batch(ddl::CATALOG_RECEIPT_COLUMN).unwrap();
    db.execute_batch(ddl::CONTROL_RECEIPT_COLUMN).unwrap();
    let count: i64 = db.query_row(
        "SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN
         ('repository_metadata_grants','repository_metadata_receipts','repository_metadata_heads','source_repository_proofs')",
        [], |row| row.get(0),
    ).unwrap();
    assert_eq!(count, 4);
    assert!(
        db.execute(
            "UPDATE catalog_meta SET repository_transition_receipt=zeroblob(8193)",
            []
        )
        .is_err()
    );
    assert!(db.execute_batch(ddl::CATALOG_TABLES).is_err());
    assert!(db.execute_batch(ddl::CONTROL_TABLES).is_err());
    // Constants deliberately do not activate either schema version.
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |row| row.get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(crate::SCHEMA_VERSION, 22);
    assert_eq!(crate::control::CONTROL_SCHEMA_VERSION, 2);
}
