//! Completed discovery receipts, published with their exact source observations.
use agent_session_grep_ports::{
    PortError, PortResult,
    managed::{DiscoveryObservation, DiscoverySource},
};
use rusqlite::{Connection, OptionalExtension, params};

type StoredDiscovery = (i64, String, i64, i64, String, String, String, bool);

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid discovery receipt".into())
}
fn sql(_: rusqlite::Error) -> PortError {
    PortError::SchemaIncompatible("discovery receipt storage is unavailable".into())
}

pub(crate) fn source_set_digest(sources: &[DiscoverySource]) -> PortResult<String> {
    let mut sorted: Vec<_> = sources.iter().collect();
    sorted.sort_by(|a, b| a.source_id.cmp(&b.source_id));
    if sorted.windows(2).any(|s| s[0].source_id == s[1].source_id) {
        return Err(invalid());
    }
    let mut hash = blake3::Hasher::new();
    hash.update(b"asg-discovery-source-set-v1");
    for source in sorted {
        for field in [source.source_id.as_str(), source.revision_id.as_str()] {
            hash.update(&(field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
    }
    Ok(hash.finalize().to_hex().to_string())
}

#[cfg(test)]
pub(crate) fn publish_in_tx(
    conn: &Connection,
    observation: &DiscoveryObservation,
) -> PortResult<()> {
    publish_with_deadline_in_tx(
        conn,
        observation,
        None,
        std::time::Instant::now() + std::time::Duration::from_secs(10),
    )
}
pub(crate) fn publish_with_deadline_in_tx(
    conn: &Connection,
    observation: &DiscoveryObservation,
    policy: Option<&agent_session_grep_ports::control::ReadPolicy>,
    deadline: std::time::Instant,
) -> PortResult<()> {
    let check = || {
        if std::time::Instant::now() >= deadline {
            Err(PortError::WriterBusy(
                "discovery receipt deadline reached".into(),
            ))
        } else {
            Ok(())
        }
    };
    check()?;
    if conn.is_autocommit()
        || (!observation.complete && !observation.sources.is_empty())
        || observation.cycle_seq < 1
        || observation.policy_epoch < 0
        || observation.started_control_seq < 1
        || observation.selection.selection_revision < 1
    {
        return Err(invalid());
    }
    let generation: i64 = conn
        .query_row(
            "SELECT active_generation FROM store_metadata WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let digest = source_set_digest(&observation.sources)?;
    for source in &observation.sources {
        check()?;
        let receipt = crate::managed_receipt::read_checked(
            conn,
            source.revision_id.as_str(),
            Some(source.source_id.as_str()),
        )?;
        if !crate::managed_source_context::receipt_context_current(
            conn,
            source.revision_id.as_str(),
            policy,
            deadline,
        )? {
            return Err(invalid());
        }
        // Structural/source validation precedes the current-cycle predicate.
        // A well-formed historical receipt is readable metadata, but it cannot
        // publish a different incarnation/cycle's completed discovery proof.
        if !receipt.published
            || receipt.cycle_seq != observation.cycle_seq
            || receipt.worker_boot_id != observation.worker_boot_id
            || receipt.policy_epoch != observation.policy_epoch
            || receipt.started_control_seq != observation.started_control_seq
            || receipt.catalog_incarnation != observation.catalog_incarnation
            || receipt
                .committed_generation
                .is_none_or(|value| value > generation)
        {
            return Err(invalid());
        }
        let valid:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM source_revision_receipts r JOIN source_heads h USING(source_id) JOIN receipt_selection_claims c USING(revision_id) WHERE r.source_id=?1 AND r.revision_id=?2 AND r.published=1 AND r.cycle_seq=?3 AND r.worker_boot_id=?4 AND r.policy_epoch=?5 AND r.started_control_seq=?6 AND r.catalog_incarnation=?7 AND c.selection_id=?8 AND c.selection_revision=?9 AND c.root_identity=?10 AND h.latest_receipt_id=r.revision_id AND h.last_attempt_id=r.revision_id AND r.committed_generation<=?11)",params![source.source_id.as_str(),source.revision_id.as_str(),observation.cycle_seq,observation.worker_boot_id,observation.policy_epoch,observation.started_control_seq,observation.catalog_incarnation,observation.selection.selection_id,observation.selection.selection_revision,observation.selection.root_identity,generation],|r|r.get(0)).map_err(sql)?;
        if !valid {
            return Err(invalid());
        }
    }
    check()?;
    let existing:Option<StoredDiscovery>=conn.query_row("SELECT selection_revision,worker_boot_id,policy_epoch,started_control_seq,catalog_incarnation,root_identity,source_set_digest,complete FROM discovery_receipts WHERE cycle_seq=?1 AND selection_id=?2",params![observation.cycle_seq,observation.selection.selection_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))).optional().map_err(sql)?;
    if let Some(prior) = existing {
        let identity = (
            observation.selection.selection_revision,
            observation.worker_boot_id.clone(),
            observation.policy_epoch,
            observation.started_control_seq,
            observation.catalog_incarnation.clone(),
            observation.selection.root_identity.clone(),
            prior.6.clone(),
            prior.7,
        );
        if prior != identity {
            return Err(invalid());
        }
        // Only an incomplete attempt may become complete. Its provisional set
        // must be empty; a completed receipt is immutable, even on retry.
        if !prior.7 && observation.complete {
            let empty = source_set_digest(&[])?;
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM discovery_sources WHERE cycle_seq=?1 AND selection_id=?2",
                    params![observation.cycle_seq, observation.selection.selection_id],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            if prior.6 != empty || count != 0 {
                return Err(invalid());
            }
            conn.execute("UPDATE discovery_receipts SET source_set_digest=?3,complete=1,committed_generation=?4 WHERE cycle_seq=?1 AND selection_id=?2 AND complete=0",
                params![observation.cycle_seq,observation.selection.selection_id,digest,generation]).map_err(sql)?;
            insert_sources(conn, observation)?;
            return check();
        }
        if prior.7 != observation.complete || prior.6 != digest {
            return Err(invalid());
        }
        let mut stmt=conn.prepare("SELECT source_id,revision_id FROM discovery_sources WHERE cycle_seq=?1 AND selection_id=?2 ORDER BY source_id").map_err(sql)?;
        let stored = stmt
            .query_map(
                params![observation.cycle_seq, observation.selection.selection_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)),
            )
            .map_err(sql)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql)?;
        let mut expected: Vec<_> = observation
            .sources
            .iter()
            .map(|s| {
                (
                    s.source_id.as_str().to_string(),
                    s.revision_id.as_str().to_string(),
                )
            })
            .collect();
        expected.sort();
        return if stored == expected {
            check()
        } else {
            Err(invalid())
        };
    }
    conn.execute(
        "INSERT INTO discovery_receipts VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        params![
            observation.cycle_seq,
            observation.selection.selection_id,
            observation.selection.selection_revision,
            observation.worker_boot_id,
            observation.policy_epoch,
            observation.started_control_seq,
            observation.catalog_incarnation,
            observation.selection.root_identity,
            digest,
            observation.complete,
            generation
        ],
    )
    .map_err(sql)?;
    insert_sources(conn, observation)?;
    check()
}

fn insert_sources(conn: &Connection, observation: &DiscoveryObservation) -> PortResult<()> {
    for source in &observation.sources {
        conn.execute(
            "INSERT INTO discovery_sources VALUES(?1,?2,?3,?4)",
            params![
                observation.cycle_seq,
                observation.selection.selection_id,
                source.source_id.as_str(),
                source.revision_id.as_str()
            ],
        )
        .map_err(sql)?;
    }
    Ok(())
}
