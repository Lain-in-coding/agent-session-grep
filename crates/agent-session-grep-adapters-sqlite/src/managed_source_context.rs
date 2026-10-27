//! Source dependencies and provider-surface authority in the caller's catalog transaction.
//! No source I/O, control mutation, outer COMMIT, or legacy merged-content fallback.
use crate::{SourceBatch, managed, managed_receipt};
use agent_session_grep_ports::{
    PortError, PortResult, SearchProvider,
    control::{CanonicalLocator, ControlId, ReadPolicy, RequestIntersection},
    managed::{
        Publication, RevisionId, RevisionRef, SelectionProof, SourceBinding, SourceObservation,
    },
    source_context::*,
};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use std::{collections::BTreeSet, time::Instant};

fn invalid() -> PortError {
    PortError::InvalidRequest("invalid managed source context operation".into())
}
fn corrupt() -> PortError {
    PortError::SchemaIncompatible("managed source context is unavailable or invalid".into())
}
fn stale() -> PortError {
    PortError::GenerationMismatch("managed source context changed".into())
}
fn busy() -> PortError {
    PortError::WriterBusy("managed source context exceeded its deadline or bounds".into())
}
fn sql(error: rusqlite::Error) -> PortError {
    match error.sqlite_error_code() {
        Some(
            rusqlite::ErrorCode::DatabaseBusy
            | rusqlite::ErrorCode::DatabaseLocked
            | rusqlite::ErrorCode::OperationInterrupted,
        ) => busy(),
        _ => corrupt(),
    }
}
fn time(deadline: Instant) -> PortResult<()> {
    if Instant::now() >= deadline {
        Err(busy())
    } else {
        Ok(())
    }
}
fn tx(conn: &Connection) -> PortResult<()> {
    let fk: bool = conn
        .pragma_query_value(None, "foreign_keys", |r| r.get(0))
        .map_err(sql)?;
    if conn.is_autocommit() || !fk {
        Err(invalid())
    } else {
        Ok(())
    }
}
fn hash(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

const SCHEMA: &str = r"
CREATE TABLE source_publication_contexts(
 revision_id TEXT PRIMARY KEY REFERENCES source_revision_receipts(revision_id) ON DELETE CASCADE,
 source_id TEXT NOT NULL REFERENCES source_bindings(source_id),
 manifest BLOB NOT NULL CHECK(length(manifest)<=262144), context_digest TEXT NOT NULL CHECK(length(context_digest)=64),
 dependency_count INTEGER NOT NULL CHECK(dependency_count BETWEEN 0 AND 16), authority_id TEXT);
CREATE INDEX source_context_owner ON source_publication_contexts(source_id,revision_id);
CREATE TABLE source_dependencies(
 owner_revision_id TEXT NOT NULL REFERENCES source_publication_contexts(revision_id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 15),
 metadata_source_id TEXT REFERENCES source_bindings(source_id),
 metadata_revision_id TEXT REFERENCES source_revision_receipts(revision_id),
 resolution TEXT NOT NULL CHECK(resolution IN ('resolved','unresolved','withdrawn')),
 PRIMARY KEY(owner_revision_id,ordinal),
 CHECK((metadata_source_id IS NULL)=(metadata_revision_id IS NULL)),
 CHECK((resolution='resolved')=(metadata_revision_id IS NOT NULL)));
CREATE INDEX source_dependency_receipt ON source_dependencies(metadata_revision_id);
CREATE TABLE source_context_heads(
 source_id TEXT PRIMARY KEY REFERENCES source_bindings(source_id),
 revision_id TEXT NOT NULL REFERENCES source_publication_contexts(revision_id));
CREATE TABLE source_authorities(
 authority_id TEXT PRIMARY KEY, key_manifest BLOB NOT NULL CHECK(length(key_manifest)<=73728),
 active_source_id TEXT NOT NULL UNIQUE REFERENCES source_bindings(source_id),
 active_revision_id TEXT NOT NULL REFERENCES source_revision_receipts(revision_id),
 transition_id TEXT NOT NULL REFERENCES source_authority_transitions(transition_id));
CREATE TABLE source_authority_transitions(
 transition_id TEXT PRIMARY KEY, authority_id TEXT NOT NULL REFERENCES source_authorities(authority_id) DEFERRABLE INITIALLY DEFERRED,
 prior_transition_id TEXT REFERENCES source_authority_transitions(transition_id),
 old_source_id TEXT REFERENCES source_bindings(source_id), old_revision_id TEXT REFERENCES source_revision_receipts(revision_id),
 new_source_id TEXT NOT NULL REFERENCES source_bindings(source_id), new_revision_id TEXT NOT NULL REFERENCES source_revision_receipts(revision_id),
 kind TEXT NOT NULL CHECK(kind IN ('activation','switch','purge_checkpoint')),
 CHECK((old_source_id IS NULL)=(old_revision_id IS NULL)),
 CHECK((old_source_id IS NULL)=(prior_transition_id IS NULL)));
CREATE INDEX source_authority_old_receipt ON source_authority_transitions(old_revision_id);
CREATE INDEX source_authority_new_receipt ON source_authority_transitions(new_revision_id);
CREATE TRIGGER source_authority_transition_immutable BEFORE UPDATE ON source_authority_transitions BEGIN SELECT RAISE(ABORT,'immutable source transition'); END;
CREATE TABLE source_authority_members(
 source_id TEXT PRIMARY KEY REFERENCES source_bindings(source_id),
 authority_id TEXT NOT NULL REFERENCES source_authorities(authority_id),
 state TEXT NOT NULL CHECK(state IN ('active','superseded')),
 transition_id TEXT NOT NULL REFERENCES source_authority_transitions(transition_id));
CREATE INDEX source_authority_members_key ON source_authority_members(authority_id,state);
CREATE TABLE source_authority_tombstones(source_id TEXT PRIMARY KEY REFERENCES source_bindings(source_id),authority_id TEXT NOT NULL CHECK(length(authority_id)=64),revoked_epoch INTEGER NOT NULL CHECK(revoked_epoch>=0));
CREATE TRIGGER source_publication_context_immutable BEFORE UPDATE ON source_publication_contexts BEGIN SELECT RAISE(ABORT,'immutable source context'); END;
";

/// Additive v21->v22 schema body. Caller sets user_version in the same tx.
/// No source context/authority/dependency proof is backfilled.
pub fn create_schema(conn: &Connection) -> PortResult<()> {
    tx(conn)?;
    let present: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name IN ('source_publication_contexts','source_dependencies','source_context_heads','source_authorities','source_authority_transitions','source_authority_members','source_authority_tombstones','source_context_owner','source_dependency_receipt','source_authority_old_receipt','source_authority_new_receipt','source_authority_members_key','source_authority_transition_immutable','source_publication_context_immutable')",
        [], |r| r.get(0),
    ).map_err(sql)?;
    if present == 0 {
        conn.execute_batch(SCHEMA).map_err(sql)?;
    }
    // An interrupted/unknown schema is diagnosable; never fill in missing
    // objects or silently adopt a table that merely shares the first name.
    validate_schema(conn)
}

pub(crate) fn validate_schema(conn: &Connection) -> PortResult<()> {
    for (table, columns) in [
        (
            "source_publication_contexts",
            "revision_id,source_id,manifest,context_digest,dependency_count,authority_id",
        ),
        (
            "source_dependencies",
            "owner_revision_id,ordinal,metadata_source_id,metadata_revision_id,resolution",
        ),
        ("source_context_heads", "source_id,revision_id"),
        (
            "source_authorities",
            "authority_id,key_manifest,active_source_id,active_revision_id,transition_id",
        ),
        (
            "source_authority_transitions",
            "transition_id,authority_id,prior_transition_id,old_source_id,old_revision_id,new_source_id,new_revision_id,kind",
        ),
        (
            "source_authority_members",
            "source_id,authority_id,state,transition_id",
        ),
        (
            "source_authority_tombstones",
            "source_id,authority_id,revoked_epoch",
        ),
    ] {
        let statement = conn
            .prepare(&format!("SELECT * FROM {table} LIMIT 0"))
            .map_err(sql)?;
        if statement.column_names().join(",") != columns {
            return Err(corrupt());
        }
        schema_object_matches(conn, table, "TABLE", ");")?;
    }
    for (name, kind) in [
        ("source_context_owner", "index"),
        ("source_dependency_receipt", "index"),
        ("source_authority_old_receipt", "index"),
        ("source_authority_new_receipt", "index"),
        ("source_authority_members_key", "index"),
        ("source_authority_transition_immutable", "trigger"),
        ("source_publication_context_immutable", "trigger"),
    ] {
        let found: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name=?1 AND type=?2)",
                params![name, kind],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if !found {
            return Err(corrupt());
        }
        schema_object_matches(
            conn,
            name,
            if kind == "trigger" {
                "TRIGGER"
            } else {
                "INDEX"
            },
            if kind == "trigger" { "END;" } else { ";" },
        )?;
    }
    Ok(())
}
fn schema_object_matches(
    conn: &Connection,
    name: &str,
    kind: &str,
    ending: &str,
) -> PortResult<()> {
    let marker = format!("CREATE {kind} {name}");
    let start = SCHEMA.find(&marker).ok_or_else(corrupt)?;
    let length = SCHEMA[start..].find(ending).ok_or_else(corrupt)? + ending.len();
    let expected = SCHEMA[start..start + length].trim_end_matches(';');
    let actual: String = conn
        .query_row("SELECT sql FROM sqlite_schema WHERE name=?1", [name], |r| {
            r.get(0)
        })
        .map_err(sql)?;
    let normalize = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalize(&actual) != normalize(expected) {
        return Err(corrupt());
    }
    Ok(())
}
fn has_schema(conn: &Connection) -> PortResult<bool> {
    let present: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='source_publication_contexts')",[],|r|r.get(0)).map_err(sql)?;
    if !present {
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(sql)?;
        if version >= 22 {
            return Err(corrupt());
        }
    }
    Ok(present)
}

fn binding_wire(b: &SourceBinding) -> Value {
    json!([
        b.source_id.as_str(),
        b.source_path,
        b.provider.as_str(),
        b.namespace_id,
        b.root_identity
    ])
}
fn receipt_wire(r: &RevisionRef) -> Value {
    json!([
        r.revision_id.as_str(),
        r.digest,
        r.observed_at_ms,
        r.cycle_seq,
        r.worker_boot_id,
        r.catalog_incarnation,
        r.policy_epoch,
        r.started_control_seq,
        r.committed_generation,
        r.published
    ])
}
fn selection_wire(s: &SelectionProof) -> Value {
    json!([s.selection_id, s.selection_revision, s.root_identity])
}
fn state_wire(s: LifecycleState) -> &'static str {
    match s {
        LifecycleState::ActiveLocal => "active_local",
        LifecycleState::SoftDeleted => "soft_deleted",
        LifecycleState::CloudUnavailable => "cloud_unavailable",
        LifecycleState::OrphanUnknown => "orphan_unknown",
    }
}
fn unresolved_wire(s: UnresolvedDependency) -> &'static str {
    match s {
        UnresolvedDependency::NotSelected => "not_selected",
        UnresolvedDependency::Missing => "missing",
        UnresolvedDependency::Incomplete => "incomplete",
        UnresolvedDependency::Unsupported => "unsupported",
        UnresolvedDependency::Changed => "changed",
        UnresolvedDependency::Withdrawn => "withdrawn",
    }
}
fn key_wire(k: &SourceAuthorityKey) -> Value {
    json!([
        k.provider.as_str(),
        k.surface_id.as_str(),
        k.surface_root.as_str(),
        k.surface_identity.as_str(),
        k.native_session.as_str(),
        k.session_id
    ])
}
fn context_wire(c: &SourcePublicationContext) -> Value {
    json!([
        "asg.source-context/v1",
        c.dependencies
            .iter()
            .map(|d| {
                let r = match &d.resolution {
                    DependencyResolution::Resolved(p) => json!([
                        "resolved",
                        binding_wire(&p.binding),
                        receipt_wire(&p.receipt),
                        selection_wire(&p.selection),
                        state_wire(p.state),
                        p.state_digest.as_str()
                    ]),
                    DependencyResolution::Unresolved(r) => {
                        json!(["unresolved", unresolved_wire(*r)])
                    }
                };
                json!([d.native_session.as_str(), r])
            })
            .collect::<Vec<_>>(),
        c.authority.as_ref().map(|a| json!([
            key_wire(&a.key),
            a.expected_prior.as_ref().map(|p| json!([
                binding_wire(&p.binding),
                receipt_wire(&p.receipt),
                p.transition_id.as_str()
            ]))
        ]))
    ])
}
/// Deterministic, bounded private manifest bytes. Include these exact bytes in
/// BOTH preview and durable outbox manifest. Nothing is serialized to wire output.
pub fn context_manifest(context: &SourcePublicationContext) -> PortResult<Vec<u8>> {
    context.validate()?;
    let bytes = serde_json::to_vec(&context_wire(context)).map_err(|_| invalid())?;
    if bytes.len() > MAX_CONTEXT_BYTES {
        Err(invalid())
    } else {
        Ok(bytes)
    }
}
fn array(v: &Value, n: usize) -> PortResult<&[Value]> {
    let a = v.as_array().ok_or_else(corrupt)?;
    if a.len() != n { Err(corrupt()) } else { Ok(a) }
}
fn text(v: &Value) -> PortResult<&str> {
    v.as_str().ok_or_else(corrupt)
}
fn number(v: &Value) -> PortResult<i64> {
    v.as_i64().ok_or_else(corrupt)
}
fn provider(v: &Value) -> PortResult<SearchProvider> {
    let s = text(v)?;
    SearchProvider::parse(s)
        .filter(|p| p.as_str() == s)
        .ok_or_else(corrupt)
}
fn binding_from(v: &Value) -> PortResult<SourceBinding> {
    let a = array(v, 5)?;
    Ok(SourceBinding {
        source_id: agent_session_grep_ports::managed::SourceId::parse(text(&a[0])?)
            .map_err(|_| corrupt())?,
        source_path: text(&a[1])?.into(),
        provider: provider(&a[2])?,
        namespace_id: if a[3].is_null() {
            None
        } else {
            Some(text(&a[3])?.into())
        },
        root_identity: text(&a[4])?.into(),
    })
}
fn receipt_from(v: &Value) -> PortResult<RevisionRef> {
    let a = array(v, 10)?;
    Ok(RevisionRef {
        revision_id: RevisionId::parse(text(&a[0])?).map_err(|_| corrupt())?,
        digest: text(&a[1])?.into(),
        observed_at_ms: number(&a[2])?,
        cycle_seq: number(&a[3])?,
        worker_boot_id: text(&a[4])?.into(),
        catalog_incarnation: text(&a[5])?.into(),
        policy_epoch: number(&a[6])?,
        started_control_seq: number(&a[7])?,
        committed_generation: if a[8].is_null() {
            None
        } else {
            Some(number(&a[8])?)
        },
        published: a[9].as_bool().ok_or_else(corrupt)?,
    })
}
fn key_from(v: &Value) -> PortResult<SourceAuthorityKey> {
    let a = array(v, 6)?;
    Ok(SourceAuthorityKey {
        provider: provider(&a[0])?,
        surface_id: ControlId::parse(text(&a[1])?).map_err(|_| corrupt())?,
        surface_root: CanonicalLocator::parse(text(&a[2])?).map_err(|_| corrupt())?,
        surface_identity: ControlId::parse(text(&a[3])?).map_err(|_| corrupt())?,
        native_session: NativeSessionId::parse(text(&a[4])?).map_err(|_| corrupt())?,
        session_id: serde_json::from_value(a[5].clone()).map_err(|_| corrupt())?,
    })
}
fn context_from(bytes: &[u8]) -> PortResult<SourcePublicationContext> {
    if bytes.len() > MAX_CONTEXT_BYTES {
        return Err(corrupt());
    }
    let v: Value = serde_json::from_slice(bytes).map_err(|_| corrupt())?;
    let a = array(&v, 3)?;
    if text(&a[0])? != "asg.source-context/v1" {
        return Err(corrupt());
    }
    let deps = a[1].as_array().ok_or_else(corrupt)?;
    if deps.len() > MAX_SOURCE_DEPENDENCIES {
        return Err(corrupt());
    }
    let mut dependencies = Vec::with_capacity(deps.len());
    for d in deps {
        let d = array(d, 2)?;
        let r = d[1].as_array().ok_or_else(corrupt)?;
        let resolution = match r.first().map(text).transpose()?.ok_or_else(corrupt)? {
            "resolved" => {
                let r = array(&d[1], 6)?;
                let s = array(&r[3], 3)?;
                let state = match text(&r[4])? {
                    "active_local" => LifecycleState::ActiveLocal,
                    "soft_deleted" => LifecycleState::SoftDeleted,
                    "cloud_unavailable" => LifecycleState::CloudUnavailable,
                    "orphan_unknown" => LifecycleState::OrphanUnknown,
                    _ => return Err(corrupt()),
                };
                DependencyResolution::Resolved(Box::new(MetadataDependencyProof {
                    binding: binding_from(&r[1])?,
                    receipt: receipt_from(&r[2])?,
                    selection: SelectionProof {
                        selection_id: text(&s[0])?.into(),
                        selection_revision: number(&s[1])?,
                        root_identity: text(&s[2])?.into(),
                    },
                    state,
                    state_digest: StateDigest::parse(text(&r[5])?).map_err(|_| corrupt())?,
                }))
            }
            "unresolved" => {
                let r = array(&d[1], 2)?;
                DependencyResolution::Unresolved(match text(&r[1])? {
                    "not_selected" => UnresolvedDependency::NotSelected,
                    "missing" => UnresolvedDependency::Missing,
                    "incomplete" => UnresolvedDependency::Incomplete,
                    "unsupported" => UnresolvedDependency::Unsupported,
                    "changed" => UnresolvedDependency::Changed,
                    "withdrawn" => UnresolvedDependency::Withdrawn,
                    _ => return Err(corrupt()),
                })
            }
            _ => return Err(corrupt()),
        };
        dependencies.push(SourceDependency {
            native_session: NativeSessionId::parse(text(&d[0])?).map_err(|_| corrupt())?,
            resolution,
        });
    }
    let authority = if a[2].is_null() {
        None
    } else {
        let r = array(&a[2], 2)?;
        Some(SourceAuthorityTransition {
            key: key_from(&r[0])?,
            expected_prior: if r[1].is_null() {
                None
            } else {
                let p = array(&r[1], 3)?;
                Some(SourceAuthorityPrior {
                    binding: binding_from(&p[0])?,
                    receipt: receipt_from(&p[1])?,
                    transition_id: ControlId::parse(text(&p[2])?).map_err(|_| corrupt())?,
                })
            },
        })
    };
    let context = SourcePublicationContext {
        dependencies,
        authority,
    };
    context.validate().map_err(|_| corrupt())?;
    if context_wire(&context) != v {
        return Err(corrupt());
    }
    Ok(context)
}
fn load_context(conn: &Connection, revision: &str) -> PortResult<Option<SourcePublicationContext>> {
    let len: Option<i64> = conn
        .query_row(
            "SELECT length(manifest) FROM source_publication_contexts WHERE revision_id=?1",
            [revision],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    let Some(len) = len else { return Ok(None) };
    if !(1..=MAX_CONTEXT_BYTES as i64).contains(&len) {
        return Err(corrupt());
    }
    let (bytes,digest,count,owner,authority):(Vec<u8>,String,i64,String,Option<String>)=conn.query_row("SELECT manifest,context_digest,dependency_count,source_id,authority_id FROM source_publication_contexts WHERE revision_id=?1",[revision],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(sql)?;
    let mut context = context_from(&bytes)?;
    let owner_receipt = managed_receipt::read_checked(conn, revision, Some(&owner))?;
    if hash(&bytes) != digest
        || count != context.dependencies.len() as i64
        || authority
            != context
                .authority
                .as_ref()
                .map(|a| authority_id(&a.key))
                .transpose()?
    {
        return Err(corrupt());
    }
    let mut stmt=conn.prepare("SELECT ordinal,metadata_source_id,metadata_revision_id,resolution FROM source_dependencies WHERE owner_revision_id=?1 ORDER BY ordinal").map_err(sql)?;
    let mut rows = stmt.query([revision]).map_err(sql)?;
    let mut index = 0;
    while let Some(row) = rows.next().map_err(sql)? {
        let dep = context.dependencies.get_mut(index).ok_or_else(corrupt)?;
        let edge_state: String = row.get(3).map_err(sql)?;
        if edge_state == "withdrawn" {
            if !matches!(dep.resolution, DependencyResolution::Resolved(_))
                || row.get::<_, Option<String>>(1).map_err(sql)?.is_some()
                || row.get::<_, Option<String>>(2).map_err(sql)?.is_some()
                || row.get::<_, i64>(0).map_err(sql)? != index as i64
            {
                return Err(corrupt());
            }
            dep.resolution = DependencyResolution::Unresolved(UnresolvedDependency::Withdrawn);
            index += 1;
            continue;
        }
        if !matches!(edge_state.as_str(), "resolved" | "unresolved") {
            return Err(corrupt());
        }
        let (source, receipt) = match &dep.resolution {
            DependencyResolution::Resolved(p) => {
                verify_binding(conn, &p.binding)?;
                if managed_receipt::read_checked(
                    conn,
                    p.receipt.revision_id.as_str(),
                    Some(p.binding.source_id.as_str()),
                )? != p.receipt
                {
                    return Err(corrupt());
                }
                let same_cycle = p.receipt.cycle_seq == owner_receipt.cycle_seq
                    && p.receipt.worker_boot_id == owner_receipt.worker_boot_id
                    && p.receipt.catalog_incarnation == owner_receipt.catalog_incarnation
                    && p.receipt.policy_epoch == owner_receipt.policy_epoch
                    && p.receipt.started_control_seq == owner_receipt.started_control_seq;
                let selection:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM receipt_selection_claims WHERE revision_id=?1 AND selection_id=?2 AND selection_revision=?3 AND root_identity=?4)",params![p.receipt.revision_id.as_str(),p.selection.selection_id,p.selection.selection_revision,p.selection.root_identity],|r|r.get(0)).map_err(sql)?;
                let metadata_empty:bool=conn.query_row("SELECT NOT EXISTS(SELECT 1 FROM source_projections WHERE revision_id=?1 UNION ALL SELECT 1 FROM source_occurrences WHERE revision_id=?1 UNION ALL SELECT 1 FROM source_entity_projections WHERE revision_id=?1 UNION ALL SELECT 1 FROM source_session_projections WHERE revision_id=?1)",[p.receipt.revision_id.as_str()],|r|r.get(0)).map_err(sql)?;
                let owner_binding = stored_binding(conn, &owner)?;
                if !same_cycle
                    || !selection
                    || !metadata_empty
                    || p.binding.source_id.as_str() == owner
                    || p.binding.provider.as_str() != "workbuddy"
                    || owner_binding.provider != p.binding.provider
                {
                    return Err(corrupt());
                }
                (
                    Some(p.binding.source_id.as_str()),
                    Some(p.receipt.revision_id.as_str()),
                )
            }
            DependencyResolution::Unresolved(_) => (None, None),
        };
        if (edge_state == "resolved") != source.is_some()
            || row.get::<_, i64>(0).map_err(sql)? != index as i64
            || row.get::<_, Option<String>>(1).map_err(sql)?.as_deref() != source
            || row.get::<_, Option<String>>(2).map_err(sql)?.as_deref() != receipt
        {
            return Err(corrupt());
        }
        index += 1;
    }
    if index != context.dependencies.len() {
        return Err(corrupt());
    }
    Ok(Some(context))
}
fn verify_binding(conn: &Connection, b: &SourceBinding) -> PortResult<()> {
    let stored:Option<(String,String,Option<String>,String)>=conn.query_row("SELECT source_path,provider_id,namespace_id,root_identity FROM source_bindings WHERE source_id=?1",[b.source_id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(sql)?;
    if stored
        != Some((
            b.source_path.clone(),
            b.provider.as_str().into(),
            b.namespace_id.clone(),
            b.root_identity.clone(),
        ))
    {
        Err(corrupt())
    } else {
        Ok(())
    }
}
fn stored_binding(conn: &Connection, source: &str) -> PortResult<SourceBinding> {
    let (path,wire,namespace,root):(String,String,Option<String>,String) = conn.query_row("SELECT source_path,provider_id,namespace_id,root_identity FROM source_bindings WHERE source_id=?1",[source],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(sql)?;
    let binding = SourceBinding {
        source_id: agent_session_grep_ports::managed::SourceId::parse(source)
            .map_err(|_| corrupt())?,
        source_path: path,
        provider: SearchProvider::parse(&wire)
            .filter(|p| p.as_str() == wire)
            .ok_or_else(corrupt)?,
        namespace_id: namespace,
        root_identity: root,
    };
    CanonicalLocator::parse(&binding.source_path).map_err(|_| corrupt())?;
    ControlId::parse(&binding.root_identity).map_err(|_| corrupt())?;
    Ok(binding)
}
fn authority_id(key: &SourceAuthorityKey) -> PortResult<String> {
    Ok(hash(
        &serde_json::to_vec(&key_wire(key)).map_err(|_| invalid())?,
    ))
}
fn selected_permission(policy: &ReadPolicy, b: &SourceBinding) -> PortResult<bool> {
    let mut p = policy.clone();
    p.request_intersection = RequestIntersection::Selected;
    let locator = CanonicalLocator::parse(&b.source_path).map_err(|_| corrupt())?;
    let source = ControlId::parse(b.source_id.as_str()).map_err(|_| corrupt())?;
    Ok(p.allows_source(b.provider, &locator, &source))
}
fn selection_allowed(
    policy: &ReadPolicy,
    b: &SourceBinding,
    s: &SelectionProof,
) -> PortResult<bool> {
    let locator = CanonicalLocator::parse(&b.source_path).map_err(|_| corrupt())?;
    Ok(policy.selections.iter().any(|c| {
        c.enabled
            && c.id.as_str() == s.selection_id
            && c.revision.get() == s.selection_revision
            && c.root_identity
                .as_ref()
                .is_some_and(|r| r.as_str() == s.root_identity)
            && c.region.matches(b.provider, &locator)
    }) && selected_permission(policy, b)?)
}

/// Compatibility guard for old callers: empty context cannot discard required
/// lifecycle dependencies or resurrect a superseded authority member.
pub(crate) fn legacy_publication_allowed(conn: &Connection, source: &str) -> PortResult<()> {
    if !has_schema(conn)? {
        return Ok(());
    }
    let retired: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM source_authority_tombstones WHERE source_id=?1)",
            [source],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if retired {
        return Err(invalid());
    }
    let member: Option<String> = conn
        .query_row(
            "SELECT state FROM source_authority_members WHERE source_id=?1",
            [source],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    if member.is_some() {
        return Err(invalid());
    }
    let revision: Option<String> = conn
        .query_row(
            "SELECT revision_id FROM source_context_heads WHERE source_id=?1",
            [source],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    if let Some(revision) = revision {
        let c = load_context(conn, &revision)?.ok_or_else(corrupt)?;
        if !c.is_empty() {
            return Err(invalid());
        }
    }
    Ok(())
}
fn verify_observation_policy(
    conn: &Connection,
    o: &SourceObservation,
    policy: &ReadPolicy,
) -> PortResult<()> {
    let installation: String = conn
        .query_row(
            "SELECT installation_id FROM catalog_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if installation != policy.installation_id.as_str()
        || policy.policy_epoch.get() != o.policy_epoch
        || policy.control_seq.get() < o.started_control_seq
        || policy.emission_blocked()
        || !selected_permission(policy, &o.binding)?
    {
        return Err(stale());
    }
    for s in &o.selections {
        if !selection_allowed(policy, &o.binding, s)? {
            return Err(stale());
        }
    }
    Ok(())
}
fn dependency_valid(
    conn: &Connection,
    dep: &SourceDependency,
    o: &SourceObservation,
    policy: &ReadPolicy,
) -> PortResult<()> {
    let DependencyResolution::Resolved(p) = &dep.resolution else {
        return Ok(());
    };
    verify_binding(conn, &p.binding)?;
    if p.binding.provider.as_str() != "workbuddy"
        || o.binding.provider != p.binding.provider
        || p.binding.source_id == o.binding.source_id
    {
        return Err(invalid());
    }
    if managed_receipt::read_checked(
        conn,
        p.receipt.revision_id.as_str(),
        Some(p.binding.source_id.as_str()),
    )? != p.receipt
    {
        return Err(stale());
    }
    if p.receipt.cycle_seq != o.cycle_seq
        || p.receipt.worker_boot_id != o.worker_boot_id
        || p.receipt.catalog_incarnation != o.catalog_incarnation
        || p.receipt.policy_epoch != o.policy_epoch
        || p.receipt.started_control_seq != o.started_control_seq
        || !selection_allowed(policy, &p.binding, &p.selection)?
    {
        return Err(stale());
    }
    let claim:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM receipt_selection_claims c JOIN source_heads h ON h.source_id=?1 WHERE c.revision_id=?2 AND c.selection_id=?3 AND c.selection_revision=?4 AND c.root_identity=?5 AND h.latest_receipt_id=c.revision_id AND h.last_attempt_id=c.revision_id AND h.update_state='current')",params![p.binding.source_id.as_str(),p.receipt.revision_id.as_str(),p.selection.selection_id,p.selection.selection_revision,p.selection.root_identity],|r|r.get(0)).map_err(sql)?;
    let metadata_empty:bool=conn.query_row("SELECT NOT EXISTS(SELECT 1 FROM source_projections WHERE source_id=?1 UNION ALL SELECT 1 FROM source_occurrences WHERE source_id=?1 UNION ALL SELECT 1 FROM source_entity_projections WHERE source_id=?1 UNION ALL SELECT 1 FROM source_session_projections WHERE source_id=?1)",[p.binding.source_id.as_str()],|r|r.get(0)).map_err(sql)?;
    if !claim || !metadata_empty {
        return Err(invalid());
    }
    Ok(())
}
fn semantic_bytes(c: &SourcePublicationContext) -> PortResult<Vec<u8>> {
    serde_json::to_vec(&json!([
        c.dependencies
            .iter()
            .map(|d| json!([
                d.native_session.as_str(),
                match &d.resolution {
                    DependencyResolution::Resolved(p) =>
                        json!(["resolved", state_wire(p.state), p.state_digest.as_str()]),
                    DependencyResolution::Unresolved(r) =>
                        json!(["unresolved", unresolved_wire(*r)]),
                }
            ]))
            .collect::<Vec<_>>(),
        c.authority.as_ref().map(|a| key_wire(&a.key))
    ]))
    .map_err(|_| invalid())
}
struct AuthorityTransition {
    authority: String,
    prior: Option<String>,
    old: Option<String>,
    old_revision: Option<RevisionRef>,
    new: String,
    new_revision: RevisionRef,
}
fn transition_checked(conn: &Connection, transition: &str) -> PortResult<AuthorityTransition> {
    ControlId::parse(transition).map_err(|_| corrupt())?;
    let (authority,prior,old,old_revision,new,new_revision,kind):(String,Option<String>,Option<String>,Option<String>,String,String,String)=conn.query_row("SELECT authority_id,prior_transition_id,old_source_id,old_revision_id,new_source_id,new_revision_id,kind FROM source_authority_transitions WHERE transition_id=?1",[transition],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).map_err(sql)?;
    StateDigest::parse(&authority).map_err(|_| corrupt())?;
    if old.is_some() != old_revision.is_some()
        || old.is_some() != prior.is_some()
        || !matches!(kind.as_str(), "activation" | "switch" | "purge_checkpoint")
        || (kind == "switch") != old.is_some()
        || prior.as_deref() == Some(transition)
    {
        return Err(corrupt());
    }
    let new_revision = managed_receipt::read_checked(conn, &new_revision, Some(&new))?;
    if !new_revision.published {
        return Err(corrupt());
    }
    let old_revision = old_revision
        .as_deref()
        .map(|r| managed_receipt::read_checked(conn, r, old.as_deref()))
        .transpose()?;
    if let (Some(old_source), Some(old_receipt), Some(prior_id)) = (&old, &old_revision, &prior) {
        if old_source == &new || !old_receipt.published {
            return Err(corrupt());
        }
        let (previous_authority,previous_new,previous_revision):(String,String,String)=conn.query_row("SELECT authority_id,new_source_id,new_revision_id FROM source_authority_transitions WHERE transition_id=?1",[prior_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(sql)?;
        if previous_authority != authority || previous_new != *old_source {
            return Err(corrupt());
        }
        let previous = managed_receipt::read_checked(conn, &previous_revision, Some(old_source))?;
        let ordered:bool=conn.query_row("SELECT p.revision_seq<=o.revision_seq FROM source_revision_receipts p,source_revision_receipts o WHERE p.revision_id=?1 AND o.revision_id=?2",params![previous.revision_id.as_str(),old_receipt.revision_id.as_str()],|r|r.get(0)).map_err(sql)?;
        if !previous.published || !ordered || old_receipt.cycle_seq > new_revision.cycle_seq {
            return Err(corrupt());
        }
    }
    Ok(AuthorityTransition {
        authority,
        prior,
        old,
        old_revision,
        new,
        new_revision,
    })
}
fn authority_binding_matches(binding: &SourceBinding, key: &SourceAuthorityKey) -> PortResult<()> {
    if binding.provider != key.provider
        || binding.namespace_id.is_none()
        || !key
            .surface_root
            .contains(&CanonicalLocator::parse(&binding.source_path).map_err(|_| corrupt())?)
    {
        return Err(corrupt());
    }
    Ok(())
}
struct Authority {
    key: SourceAuthorityKey,
    source: String,
    revision: RevisionRef,
    transition: String,
}
fn load_authority(conn: &Connection, id: &str) -> PortResult<Option<Authority>> {
    let len: Option<i64> = conn
        .query_row(
            "SELECT length(key_manifest) FROM source_authorities WHERE authority_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    let Some(len) = len else { return Ok(None) };
    if !(1..=73_728).contains(&len) {
        return Err(corrupt());
    }
    let (bytes,source,revision,transition):(Vec<u8>,String,String,String)=conn.query_row("SELECT key_manifest,active_source_id,active_revision_id,transition_id FROM source_authorities WHERE authority_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(sql)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| corrupt())?;
    let key = key_from(&value)?;
    if key_wire(&key) != value || authority_id(&key)? != id {
        return Err(corrupt());
    }
    SourcePublicationContext {
        dependencies: Vec::new(),
        authority: Some(SourceAuthorityTransition {
            key: key.clone(),
            expected_prior: None,
        }),
    }
    .validate()
    .map_err(|_| corrupt())?;
    let revision = managed_receipt::read_checked(conn, &revision, Some(&source))?;
    if !revision.published {
        return Err(corrupt());
    }
    let binding = stored_binding(conn, &source)?;
    authority_binding_matches(&binding, &key)?;
    let tr = transition_checked(conn, &transition)?;
    if tr.authority != id || tr.new != source {
        return Err(corrupt());
    }
    let ordered:bool=conn.query_row("SELECT t.revision_seq<=a.revision_seq FROM source_revision_receipts t,source_revision_receipts a WHERE t.revision_id=?1 AND a.revision_id=?2",params![tr.new_revision.revision_id.as_str(),revision.revision_id.as_str()],|r|r.get(0)).map_err(sql)?;
    if !ordered {
        return Err(corrupt());
    }
    let active:Option<(String,String)>=conn.query_row("SELECT source_id,transition_id FROM source_authority_members WHERE authority_id=?1 AND state='active'",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(sql)?;
    let active_count:i64=conn.query_row("SELECT COUNT(*) FROM source_authority_members WHERE authority_id=?1 AND state='active'",[id],|r|r.get(0)).map_err(sql)?;
    if active_count != 1 || active != Some((source.clone(), transition.clone())) {
        return Err(corrupt());
    }
    if let Some(old) = tr.old {
        let previous = stored_binding(conn, &old)?;
        authority_binding_matches(&previous, &key)?;
        if previous.namespace_id != binding.namespace_id {
            return Err(corrupt());
        }
    }
    Ok(Some(Authority {
        key,
        source,
        revision,
        transition,
    }))
}
fn authority_preimage(
    conn: &Connection,
    a: &SourceAuthorityTransition,
    o: &SourceObservation,
    policy: &ReadPolicy,
    batch: &SourceBatch,
) -> PortResult<Option<Authority>> {
    let id = authority_id(&a.key)?;
    let old = load_authority(conn, &id)?;
    if old.is_none() {
        let retired: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM source_authority_tombstones WHERE authority_id=?1)",
                [&id],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if retired {
            return Err(stale());
        }
    }
    if a.key.provider != o.binding.provider
        || !a
            .key
            .surface_root
            .contains(&CanonicalLocator::parse(&o.binding.source_path)?)
        || o.binding.namespace_id.is_none()
    {
        return Err(invalid());
    }
    match (&old, &a.expected_prior) {
        (None, None) => {}
        (Some(old), Some(p)) => {
            verify_binding(conn, &p.binding)?;
            if old.key != a.key
                || old.source != p.binding.source_id.as_str()
                || old.revision != p.receipt
                || old.transition != p.transition_id.as_str()
                || p.binding.namespace_id != o.binding.namespace_id
                || !a
                    .key
                    .surface_root
                    .contains(&CanonicalLocator::parse(&p.binding.source_path)?)
                || !selected_permission(policy, &p.binding)?
            {
                return Err(stale());
            }
        }
        _ => return Err(stale()),
    }
    // The caller's verified native/session pairing must already be present in
    // staged canonical resume facts. Never infer it from a basename or locator.
    let native = batch.resume_claims.iter().any(|c| {
        c.provider_id == a.key.provider.as_str()
            && c.session_id == a.key.session_id.as_str()
            && c.provider_session_id_state == "resolved"
            && c.provider_session_id.as_deref() == Some(a.key.native_session.as_str())
    });
    if !native && !(batch.entries.is_empty() && old.is_some()) {
        return Err(invalid());
    }
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM source_authorities", [], |r| r.get(0))
        .map_err(sql)?;
    if old.is_none() && count >= MAX_AUTHORITY_KEYS as i64 {
        return Err(busy());
    }
    let owned: Option<String> = conn
        .query_row(
            "SELECT authority_id FROM source_authority_members WHERE source_id=?1",
            [o.binding.source_id.as_str()],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    if owned.is_some_and(|owned| owned != id) {
        return Err(stale());
    }
    Ok(old)
}
fn persist_context(
    conn: &Connection,
    o: &SourceObservation,
    c: &SourcePublicationContext,
    bytes: &[u8],
    published: bool,
) -> PortResult<()> {
    let authority = c
        .authority
        .as_ref()
        .map(|a| authority_id(&a.key))
        .transpose()?;
    conn.execute(
        "INSERT INTO source_publication_contexts VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            o.revision_id.as_str(),
            o.binding.source_id.as_str(),
            bytes,
            hash(bytes),
            c.dependencies.len() as i64,
            authority
        ],
    )
    .map_err(sql)?;
    for (i, d) in c.dependencies.iter().enumerate() {
        let (source, receipt) = match &d.resolution {
            DependencyResolution::Resolved(p) => (
                Some(p.binding.source_id.as_str()),
                Some(p.receipt.revision_id.as_str()),
            ),
            DependencyResolution::Unresolved(_) => (None, None),
        };
        conn.execute(
            "INSERT INTO source_dependencies VALUES(?1,?2,?3,?4,?5)",
            params![
                o.revision_id.as_str(),
                i as i64,
                source,
                receipt,
                if source.is_some() {
                    "resolved"
                } else {
                    "unresolved"
                }
            ],
        )
        .map_err(sql)?;
    }
    if published {
        conn.execute("INSERT INTO source_context_heads VALUES(?1,?2) ON CONFLICT(source_id) DO UPDATE SET revision_id=excluded.revision_id",params![o.binding.source_id.as_str(),o.revision_id.as_str()]).map_err(sql)?;
    }
    Ok(())
}
fn apply_authority(
    conn: &Connection,
    o: &SourceObservation,
    a: &SourceAuthorityTransition,
    old: Option<&Authority>,
) -> PortResult<bool> {
    let id = authority_id(&a.key)?;
    let source = o.binding.source_id.as_str();
    if old.is_some_and(|p| p.source == source) {
        let old = old.ok_or_else(corrupt)?;
        let updated=conn.execute("UPDATE source_authorities SET active_revision_id=?2 WHERE authority_id=?1 AND active_source_id=?3 AND active_revision_id=?4 AND transition_id=?5",params![id,o.revision_id.as_str(),source,old.revision.revision_id.as_str(),old.transition]).map_err(sql)?;
        if updated != 1 {
            return Err(stale());
        }
        return Ok(false);
    }
    let transition = format!(
        "transition-{}",
        hash(format!("{id}:{}", o.revision_id.as_str()).as_bytes())
    );
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM source_authority_transitions",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if count >= MAX_AUTHORITY_KEYS as i64 {
        return Err(busy());
    }
    conn.execute(
        "INSERT INTO source_authority_transitions VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            transition,
            id,
            old.map(|p| p.transition.as_str()),
            old.map(|p| p.source.as_str()),
            old.map(|p| p.revision.revision_id.as_str()),
            source,
            o.revision_id.as_str(),
            if old.is_some() {
                "switch"
            } else {
                "activation"
            }
        ],
    )
    .map_err(sql)?;
    if let Some(old) = old {
        let n=conn.execute("UPDATE source_authorities SET active_source_id=?2,active_revision_id=?3,transition_id=?4 WHERE authority_id=?1 AND active_source_id=?5 AND active_revision_id=?6 AND transition_id=?7",params![id,source,o.revision_id.as_str(),transition,old.source,old.revision.revision_id.as_str(),old.transition]).map_err(sql)?;
        if n != 1 {
            return Err(stale());
        }
        conn.execute("UPDATE source_authority_members SET state='superseded',transition_id=?2 WHERE authority_id=?1 AND state='active'",params![id,transition]).map_err(sql)?;
        conn.execute(
            "DELETE FROM source_scope_claims WHERE source_id=?1",
            [&old.source],
        )
        .map_err(sql)?;
        conn.execute(
            "UPDATE source_heads SET update_state='deferred' WHERE source_id=?1",
            [&old.source],
        )
        .map_err(sql)?;
    } else {
        let key = serde_json::to_vec(&key_wire(&a.key)).map_err(|_| invalid())?;
        conn.execute(
            "INSERT INTO source_authorities VALUES(?1,?2,?3,?4,?5)",
            params![id, key, source, o.revision_id.as_str(), transition],
        )
        .map_err(sql)?;
    }
    conn.execute(
        "DELETE FROM source_authority_tombstones WHERE source_id=?1 AND authority_id=?2",
        params![source, id],
    )
    .map_err(sql)?;
    conn.execute("INSERT INTO source_authority_members VALUES(?1,?2,'active',?3) ON CONFLICT(source_id) DO UPDATE SET state='active',transition_id=excluded.transition_id WHERE source_authority_members.authority_id=excluded.authority_id",params![source,id,transition]).map_err(sql)?;
    Ok(old.is_some())
}

/// Validates separately admitted receipts, publishes original content/context,
/// and applies authority CAS/retirement in ONE nested savepoint. The caller
/// owns worker/control authority, original deadline and the outer outbox/CAS tx.
pub fn publish_source_with_context_in_tx(
    conn: &Connection,
    batch: &SourceBatch,
    o: &SourceObservation,
    c: &SourcePublicationContext,
    policy: &ReadPolicy,
    target: i64,
    deadline: Instant,
) -> PortResult<Publication> {
    tx(conn)?;
    time(deadline)?;
    let bytes = context_manifest(c)?;
    if !has_schema(conn)? {
        return Err(corrupt());
    }
    verify_observation_policy(conn, o, policy)?;
    let old_revision: Option<String> = conn
        .query_row(
            "SELECT revision_id FROM source_context_heads WHERE source_id=?1",
            [o.binding.source_id.as_str()],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    let prior = old_revision
        .as_deref()
        .map(|r| {
            managed_receipt::read_checked(conn, r, Some(o.binding.source_id.as_str()))?;
            load_context(conn, r)?.ok_or_else(corrupt)
        })
        .transpose()?;
    if let Some(prior) = &prior {
        let old_ids: BTreeSet<_> = prior
            .dependencies
            .iter()
            .map(|d| d.native_session.as_str())
            .collect();
        let new_ids: BTreeSet<_> = c
            .dependencies
            .iter()
            .map(|d| d.native_session.as_str())
            .collect();
        if !old_ids.is_subset(&new_ids) || (prior.authority.is_some() && c.authority.is_none()) {
            return Err(invalid());
        }
    }
    for d in &c.dependencies {
        time(deadline)?;
        dependency_valid(conn, d, o, policy)?;
        if let DependencyResolution::Resolved(p) = &d.resolution {
            let native = batch.resume_claims.iter().any(|r| {
                r.provider_id == "workbuddy"
                    && r.provider_session_id_state == "resolved"
                    && r.provider_session_id.as_deref() == Some(d.native_session.as_str())
            });
            if !native && !(batch.entries.is_empty() && p.state == LifecycleState::SoftDeleted) {
                return Err(invalid());
            }
        }
    }
    let old = c
        .authority
        .as_ref()
        .map(|a| authority_preimage(conn, a, o, policy, batch))
        .transpose()?
        .flatten();
    if c.authority.is_none() {
        let member: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM source_authority_members WHERE source_id=?1 UNION ALL SELECT 1 FROM source_authority_tombstones WHERE source_id=?1)",
                [o.binding.source_id.as_str()],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if member {
            return Err(invalid());
        }
    }
    let semantics = semantic_bytes(c)?;
    let semantic_change = prior
        .as_ref()
        .map(semantic_bytes)
        .transpose()?
        .is_some_and(|p| semantics != p);
    conn.execute_batch("SAVEPOINT asg_source_context;")
        .map_err(sql)?;
    let result = (|| {
        let mut p = managed::publish_source_uncontextualized_in_tx(conn, batch, o, target)?;
        persist_context(conn, o, c, &bytes, p.receipt.published)?;
        let switch = if p.receipt.published {
            if let Some(a) = &c.authority {
                apply_authority(conn, o, a, old.as_ref())?
            } else {
                false
            }
        } else {
            false
        };
        if p.receipt.published && (switch || semantic_change) {
            let base: i64 = conn
                .query_row(
                    "SELECT active_generation FROM store_metadata WHERE singleton=1",
                    [],
                    |r| r.get(0),
                )
                .map_err(sql)?;
            if target != base.checked_add(1).ok_or_else(invalid)? {
                return Err(stale());
            }
            p.content_changed = true;
            p.required_generation = target;
            if switch && !p.destructive {
                let epoch: i64 = conn
                    .query_row(
                        "SELECT destructive_epoch FROM store_metadata WHERE singleton=1",
                        [],
                        |r| r.get(0),
                    )
                    .map_err(sql)?;
                let next = epoch.checked_add(1).ok_or_else(invalid)?;
                let n=conn.execute("UPDATE store_metadata SET destructive_epoch=?2 WHERE singleton=1 AND destructive_epoch=?1",params![epoch,next]).map_err(sql)?;
                if n != 1 {
                    return Err(stale());
                }
                p.destructive = true;
                p.destructive_epoch = next;
            }
        }
        time(deadline)?;
        Ok(p)
    })();
    match result {
        Ok(p) => {
            if let Err(e) = conn.execute_batch("RELEASE asg_source_context;") {
                conn.execute_batch("ROLLBACK TO asg_source_context; RELEASE asg_source_context;")
                    .map_err(sql)?;
                return Err(sql(e));
            }
            Ok(p)
        }
        Err(e) => {
            conn.execute_batch("ROLLBACK TO asg_source_context; RELEASE asg_source_context;")
                .map_err(sql)?;
            Err(e)
        }
    }
}

/// Returns false only for a verified superseded source. Corrupt/missing graph
/// dependencies are errors. Currentness never controls permission to old text.
pub fn source_read_eligible(conn: &Connection, source: &str) -> PortResult<bool> {
    if !has_schema(conn)? {
        return Ok(true);
    }
    let retired: Option<(String, i64)> = conn
        .query_row(
            "SELECT authority_id,revoked_epoch FROM source_authority_tombstones WHERE source_id=?1",
            [source],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    if let Some((id, epoch)) = retired {
        StateDigest::parse(&id).map_err(|_| corrupt())?;
        if epoch < 0 {
            return Err(corrupt());
        }
        return Ok(false);
    }
    let head: Option<String> = conn
        .query_row(
            "SELECT revision_id FROM source_context_heads WHERE source_id=?1",
            [source],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    if let Some(revision) = head {
        managed_receipt::read_checked(conn, &revision, Some(source))?;
        let latest: Option<String> = conn
            .query_row(
                "SELECT latest_receipt_id FROM source_heads WHERE source_id=?1",
                [source],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if latest.as_deref() != Some(revision.as_str()) {
            return Err(corrupt());
        }
        load_context(conn, &revision)?.ok_or_else(corrupt)?;
    } else {
        let contextual:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM source_publication_contexts c JOIN source_heads h ON h.latest_receipt_id=c.revision_id WHERE h.source_id=?1)",[source],|r|r.get(0)).map_err(sql)?;
        if contextual {
            return Err(corrupt());
        }
    }
    let row:Option<(String,String,String)>=conn.query_row("SELECT authority_id,state,transition_id FROM source_authority_members WHERE source_id=?1",[source],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(sql)?;
    let Some((id, state, transition)) = row else {
        let orphan: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM source_authorities WHERE active_source_id=?1)",
                [source],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if orphan {
            return Err(corrupt());
        }
        return Ok(true);
    };
    let authority = load_authority(conn, &id)?.ok_or_else(corrupt)?;
    let tr = transition_checked(conn, &transition)?;
    if tr.authority != id {
        return Err(corrupt());
    }
    let binding = stored_binding(conn, source)?;
    authority_binding_matches(&binding, &authority.key)?;
    let active_binding = stored_binding(conn, &authority.source)?;
    if binding.namespace_id != active_binding.namespace_id {
        return Err(corrupt());
    }
    match state.as_str() {
        "active"
            if authority.source == source
                && tr.new == source
                && authority.transition == transition =>
        {
            Ok(true)
        }
        "superseded" if authority.source != source && tr.old.as_deref() == Some(source) => {
            Ok(false)
        }
        _ => Err(corrupt()),
    }
}
/// A typed proof's complete/current status, checked against metadata latest head
/// and current Selected policy. Ordinary content uses source_read_eligible only.
pub fn receipt_context_current(
    conn: &Connection,
    revision: &str,
    policy: Option<&ReadPolicy>,
    deadline: Instant,
) -> PortResult<bool> {
    time(deadline)?;
    if !has_schema(conn)? {
        return Ok(true);
    }
    let owner = managed_receipt::read_checked(conn, revision, None)?;
    let source: String = conn
        .query_row(
            "SELECT source_id FROM source_revision_receipts WHERE revision_id=?1",
            [revision],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let incarnation: String = conn
        .query_row(
            "SELECT catalog_incarnation FROM catalog_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let current: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM source_heads WHERE source_id=?1 AND latest_receipt_id=?2 AND last_attempt_id=?2 AND update_state='current')", params![source,revision], |r|r.get(0)).map_err(sql)?;
    if !owner.published
        || owner.catalog_incarnation != incarnation
        || !current
        || !source_read_eligible(conn, &source)?
    {
        return Ok(false);
    }
    if let Some(policy) = policy {
        let binding = stored_binding(conn, &source)?;
        if owner.policy_epoch != policy.policy_epoch.get()
            || !selected_permission(policy, &binding)?
        {
            return Ok(false);
        }
        let mut statement = conn.prepare("SELECT selection_id,selection_revision,root_identity FROM receipt_selection_claims WHERE revision_id=?1").map_err(sql)?;
        let mut rows = statement.query([revision]).map_err(sql)?;
        let mut permitted = false;
        while let Some(row) = rows.next().map_err(sql)? {
            time(deadline)?;
            let selection = SelectionProof {
                selection_id: row.get(0).map_err(sql)?,
                selection_revision: row.get(1).map_err(sql)?,
                root_identity: row.get(2).map_err(sql)?,
            };
            if selection_allowed(policy, &binding, &selection)? {
                permitted = true;
            }
        }
        if !permitted {
            return Ok(false);
        }
    }
    let Some(c) = load_context(conn, revision)? else {
        return Ok(true);
    };
    if let Some(a) = &c.authority {
        let row = load_authority(conn, &authority_id(&a.key)?)?.ok_or_else(corrupt)?;
        if row.source != source || row.revision != owner {
            return Ok(false);
        }
    }
    for d in &c.dependencies {
        time(deadline)?;
        let DependencyResolution::Resolved(p) = &d.resolution else {
            return Ok(false);
        };
        if matches!(
            p.state,
            LifecycleState::CloudUnavailable | LifecycleState::OrphanUnknown
        ) {
            return Ok(false);
        }
        if p.receipt.cycle_seq != owner.cycle_seq
            || p.receipt.worker_boot_id != owner.worker_boot_id
            || p.receipt.policy_epoch != owner.policy_epoch
            || p.receipt.catalog_incarnation != owner.catalog_incarnation
            || p.receipt.started_control_seq != owner.started_control_seq
        {
            return Err(corrupt());
        }
        let current:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM source_heads WHERE source_id=?1 AND latest_receipt_id=?2 AND last_attempt_id=?2 AND update_state='current')",params![p.binding.source_id.as_str(),p.receipt.revision_id.as_str()],|r|r.get(0)).map_err(sql)?;
        if !current {
            return Ok(false);
        }
        if let Some(policy) = policy
            && (policy.policy_epoch.get() != p.receipt.policy_epoch
                || !selection_allowed(policy, &p.binding, &p.selection)?)
        {
            return Ok(false);
        }
    }
    Ok(true)
}
/// Bounded read-only prior lookup. Returns the authority row's exact checked
/// active receipt/transition, including a retained old-cycle receipt. It never
/// substitutes a source-head observation or requires old physical source I/O.
pub fn authority_prior(
    conn: &Connection,
    key: &SourceAuthorityKey,
    policy: &ReadPolicy,
    deadline: Instant,
) -> PortResult<Option<SourceAuthorityPrior>> {
    time(deadline)?;
    SourcePublicationContext {
        dependencies: Vec::new(),
        authority: Some(SourceAuthorityTransition {
            key: key.clone(),
            expected_prior: None,
        }),
    }
    .validate()?;
    let Some(a) = load_authority(conn, &authority_id(key)?)? else {
        return Ok(None);
    };
    if a.key != *key {
        return Err(corrupt());
    }
    let (path,wire,ns,root):(String,String,Option<String>,String)=conn.query_row("SELECT source_path,provider_id,namespace_id,root_identity FROM source_bindings WHERE source_id=?1",[&a.source],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(sql)?;
    let provider = SearchProvider::parse(&wire)
        .filter(|p| p.as_str() == wire)
        .ok_or_else(corrupt)?;
    let binding = SourceBinding {
        source_id: agent_session_grep_ports::managed::SourceId::parse(&a.source)
            .map_err(|_| corrupt())?,
        source_path: path,
        provider,
        namespace_id: ns,
        root_identity: root,
    };
    if !selected_permission(policy, &binding)? {
        return Err(stale());
    }
    time(deadline)?;
    Ok(Some(SourceAuthorityPrior {
        binding,
        receipt: a.revision,
        transition_id: ControlId::parse(&a.transition).map_err(|_| corrupt())?,
    }))
}

/// Validate the complete bounded context/authority graph and return exact
/// receipt roots for GC. Missing/unknown links cannot mean an empty graph.
///
/// With `retained_contexts_only`, publication contexts are validated only when
/// their owner receipt is already in `temp.history_keep_receipts`: an obsolete
/// context neither counts toward the live inventory bound nor pins its
/// metadata dependency. Retention validates each obsolete context before it
/// joins a bounded deletion batch. Authority roots and transitions are always
/// validated and retained completely.
pub(crate) fn history_roots(
    conn: &Connection,
    max: usize,
    deadline: Instant,
    retained_contexts_only: bool,
) -> PortResult<Vec<RevisionId>> {
    time(deadline)?;
    if !has_schema(conn)? {
        return Ok(Vec::new());
    }
    let context_count: i64 = if retained_contexts_only {
        conn.query_row(
            "SELECT COUNT(*) FROM source_publication_contexts c JOIN temp.history_keep_receipts k ON k.revision_id=c.revision_id",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?
    } else {
        conn.query_row(
            "SELECT COUNT(*) FROM source_publication_contexts",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?
    };
    let authority_count: i64 = conn
        .query_row(
            "SELECT (SELECT COUNT(*) FROM source_authorities)+(SELECT COUNT(*) FROM source_authority_transitions)",
            [],
            |r| r.get(0),
        )
        .map_err(sql)?;
    let count = context_count
        .checked_add(authority_count)
        .ok_or_else(corrupt)?;
    let side_count:i64=conn.query_row("SELECT (SELECT COUNT(*) FROM source_context_heads)+(SELECT COUNT(*) FROM source_authority_members)+(SELECT COUNT(*) FROM source_authority_tombstones)",[],|r|r.get(0)).map_err(sql)?;
    if count < 0
        || count as usize > max
        || side_count < 0
        || side_count as usize > max.saturating_mul(3)
    {
        return Err(busy());
    }
    let orphan:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM source_dependencies d LEFT JOIN source_publication_contexts c ON c.revision_id=d.owner_revision_id WHERE c.revision_id IS NULL)",[],|r|r.get(0)).map_err(sql)?;
    if orphan {
        return Err(corrupt());
    }
    let mut roots = BTreeSet::new();
    let context_query = if retained_contexts_only {
        "SELECT c.revision_id FROM source_publication_contexts c
         JOIN temp.history_keep_receipts k ON k.revision_id=c.revision_id
         ORDER BY c.revision_id"
    } else {
        "SELECT revision_id FROM source_publication_contexts ORDER BY revision_id"
    };
    let mut stmt = conn.prepare(context_query).map_err(sql)?;
    let mut rows = stmt.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let revision: String = row.get(0).map_err(sql)?;
        let context = load_context(conn, &revision)?.ok_or_else(corrupt)?;
        // A full inventory pins every context edge. Retention mode reaches
        // here only for live owners; obsolete owners are validated separately
        // and retired before their dependency receipts can become deletable.
        for dependency in context.dependencies {
            if let DependencyResolution::Resolved(proof) = dependency.resolution {
                roots.insert(proof.receipt.revision_id);
                if roots.len() > max {
                    return Err(busy());
                }
            }
        }
    }
    drop(rows);
    drop(stmt);
    let mut stmt = conn
        .prepare("SELECT source_id,revision_id FROM source_context_heads ORDER BY source_id")
        .map_err(sql)?;
    let mut rows = stmt.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let source: String = row.get(0).map_err(sql)?;
        let revision: String = row.get(1).map_err(sql)?;
        managed_receipt::read_checked(conn, &revision, Some(&source))?;
        load_context(conn, &revision)?.ok_or_else(corrupt)?;
        roots.insert(RevisionId::parse(&revision).map_err(|_| corrupt())?);
    }
    drop(rows);
    drop(stmt);
    let mut stmt = conn
        .prepare("SELECT authority_id FROM source_authorities ORDER BY authority_id")
        .map_err(sql)?;
    let mut rows = stmt.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let id: String = row.get(0).map_err(sql)?;
        let a = load_authority(conn, &id)?.ok_or_else(corrupt)?;
        roots.insert(a.revision.revision_id);
    }
    drop(rows);
    drop(stmt);
    let mut stmt = conn
        .prepare("SELECT transition_id FROM source_authority_transitions ORDER BY transition_id")
        .map_err(sql)?;
    let mut rows = stmt.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let id: String = row.get(0).map_err(sql)?;
        let transition = transition_checked(conn, &id)?;
        let authority = load_authority(conn, &transition.authority)?.ok_or_else(corrupt)?;
        let new_binding = stored_binding(conn, &transition.new)?;
        authority_binding_matches(&new_binding, &authority.key)?;
        let active_binding = stored_binding(conn, &authority.source)?;
        if new_binding.namespace_id != active_binding.namespace_id {
            return Err(corrupt());
        }
        roots.insert(transition.new_revision.revision_id);
        if let (Some(old), Some(revision), Some(_prior)) =
            (transition.old, transition.old_revision, transition.prior)
        {
            let old_binding = stored_binding(conn, &old)?;
            authority_binding_matches(&old_binding, &authority.key)?;
            if old_binding.namespace_id != active_binding.namespace_id {
                return Err(corrupt());
            }
            roots.insert(revision.revision_id);
        }
        if roots.len() > max {
            return Err(busy());
        }
    }
    drop(rows);
    drop(stmt);
    let mut stmt = conn
        .prepare("SELECT source_id FROM source_authority_members ORDER BY source_id")
        .map_err(sql)?;
    let mut rows = stmt.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        source_read_eligible(conn, &row.get::<_, String>(0).map_err(sql)?)?;
    }
    drop(rows);
    drop(stmt);
    let mut stmt = conn
        .prepare("SELECT source_id,authority_id,revoked_epoch FROM source_authority_tombstones")
        .map_err(sql)?;
    let mut rows = stmt.query([]).map_err(sql)?;
    while let Some(row) = rows.next().map_err(sql)? {
        time(deadline)?;
        let source: String = row.get(0).map_err(sql)?;
        let id: String = row.get(1).map_err(sql)?;
        let epoch: i64 = row.get(2).map_err(sql)?;
        StateDigest::parse(&id).map_err(|_| corrupt())?;
        stored_binding(conn, &source)?;
        if epoch < 0 {
            return Err(corrupt());
        }
        let member: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM source_authority_members WHERE source_id=?1)",
                [source],
                |r| r.get(0),
            )
            .map_err(sql)?;
        if member {
            return Err(corrupt());
        }
    }
    let closure = dependency_closure(
        conn,
        &roots.iter().cloned().collect::<Vec<_>>(),
        max,
        deadline,
    )?;
    Ok(closure)
}

/// Validate one obsolete publication context immediately before retention
/// cascades it with its owner receipt. Old rows are not exempt from checks.
pub(crate) fn verify_context_for_retirement(
    conn: &Connection,
    revision: &str,
    source: &str,
) -> PortResult<()> {
    managed_receipt::read_checked(conn, revision, Some(source))?;
    load_context(conn, revision)?.ok_or_else(corrupt)?;
    Ok(())
}

pub(crate) fn dependency_closure(
    conn: &Connection,
    seeds: &[RevisionId],
    max: usize,
    deadline: Instant,
) -> PortResult<Vec<RevisionId>> {
    let mut keep: BTreeSet<_> = seeds.iter().cloned().collect();
    let mut queue: Vec<_> = keep.iter().cloned().collect();
    let mut index = 0;
    while index < queue.len() {
        time(deadline)?;
        if keep.len() > max {
            return Err(busy());
        }
        if let Some(c) = load_context(conn, queue[index].as_str())? {
            for d in c.dependencies {
                if let DependencyResolution::Resolved(p) = d.resolution
                    && keep.insert(p.receipt.revision_id.clone())
                {
                    queue.push(p.receipt.revision_id.clone());
                }
            }
        }
        index += 1;
    }
    Ok(keep.into_iter().collect())
}

/// Return private typed prior context for an independently permitted receipt.
/// This never authorizes reuse of old metadata or grants currentness.
pub fn publication_context(
    conn: &Connection,
    receipt: &RevisionRef,
    policy: &ReadPolicy,
    deadline: Instant,
) -> PortResult<SourcePublicationContext> {
    time(deadline)?;
    let actual = managed_receipt::read_checked(conn, receipt.revision_id.as_str(), None)?;
    if actual != *receipt {
        return Err(stale());
    }
    let (source,path,wire,ns,root):(String,String,String,Option<String>,String)=conn.query_row("SELECT b.source_id,b.source_path,b.provider_id,b.namespace_id,b.root_identity FROM source_revision_receipts r JOIN source_bindings b USING(source_id) WHERE r.revision_id=?1",[receipt.revision_id.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(sql)?;
    let provider = SearchProvider::parse(&wire)
        .filter(|p| p.as_str() == wire)
        .ok_or_else(corrupt)?;
    let binding = SourceBinding {
        source_id: agent_session_grep_ports::managed::SourceId::parse(&source)
            .map_err(|_| corrupt())?,
        source_path: path,
        provider,
        namespace_id: ns,
        root_identity: root,
    };
    if !selected_permission(policy, &binding)? {
        return Err(stale());
    }
    let c = load_context(conn, receipt.revision_id.as_str())?.unwrap_or_default();
    time(deadline)?;
    Ok(c)
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextPurgeCounts {
    pub dependencies_withdrawn: u64,
    pub contexts_removed: u64,
    pub authority_groups_checkpointed: u64,
}
/// Unlink revoked metadata receipts before the caller removes them, preserving
/// independently allowed transcript bodies. Authority purge checkpoints retire
/// disposable historical receipt edges while preserving exact active authority
/// and permanent no-default-resurrection tombstones. No source content is read.
pub fn purge_sources_in_tx(
    conn: &Connection,
    sources: &[agent_session_grep_ports::managed::SourceId],
    policy: &ReadPolicy,
    deadline: Instant,
) -> PortResult<ContextPurgeCounts> {
    tx(conn)?;
    time(deadline)?;
    if sources.len() > MAX_AUTHORITY_KEYS {
        return Err(busy());
    }
    let unique: BTreeSet<_> = sources.iter().map(|s| s.as_str()).collect();
    if unique.len() != sources.len() {
        return Err(invalid());
    }
    for source in sources {
        let (path,wire,ns,root):(String,String,Option<String>,String)=conn.query_row("SELECT source_path,provider_id,namespace_id,root_identity FROM source_bindings WHERE source_id=?1",[source.as_str()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(sql)?;
        let provider = SearchProvider::parse(&wire)
            .filter(|p| p.as_str() == wire)
            .ok_or_else(corrupt)?;
        if selected_permission(
            policy,
            &SourceBinding {
                source_id: source.clone(),
                source_path: path,
                provider,
                namespace_id: ns,
                root_identity: root,
            },
        )? {
            return Err(stale());
        }
    }
    history_roots(conn, MAX_AUTHORITY_KEYS, deadline, false)?;
    conn.execute_batch("SAVEPOINT asg_context_purge;")
        .map_err(sql)?;
    let result = (|| {
        let mut out = ContextPurgeCounts::default();
        let mut groups = BTreeSet::new();
        for source in sources {
            time(deadline)?;
            let mut stmt=conn.prepare("SELECT DISTINCT authority_id FROM source_authority_members WHERE source_id=?1 UNION SELECT authority_id FROM source_authority_transitions WHERE old_source_id=?1 OR new_source_id=?1").map_err(sql)?;
            let ids = stmt
                .query_map([source.as_str()], |r| r.get::<_, String>(0))
                .map_err(sql)?;
            for id in ids {
                groups.insert(id.map_err(sql)?);
            }
            drop(stmt);
            out.dependencies_withdrawn+=conn.execute("UPDATE source_dependencies SET metadata_source_id=NULL,metadata_revision_id=NULL,resolution='withdrawn' WHERE metadata_source_id=?1",[source.as_str()]).map_err(sql)? as u64;
            conn.execute(
                "DELETE FROM source_context_heads WHERE source_id=?1",
                [source.as_str()],
            )
            .map_err(sql)?;
            out.contexts_removed += conn
                .execute(
                    "DELETE FROM source_publication_contexts WHERE source_id=?1",
                    [source.as_str()],
                )
                .map_err(sql)? as u64;
        }
        for id in groups {
            time(deadline)?;
            let a = load_authority(conn, &id)?.ok_or_else(corrupt)?;
            let active_revoked = unique.contains(a.source.as_str());
            let mut members = conn
                .prepare("SELECT source_id FROM source_authority_members WHERE authority_id=?1")
                .map_err(sql)?;
            let member_rows = members
                .query_map([&id], |r| r.get::<_, String>(0))
                .map_err(sql)?;
            for source in member_rows {
                let source = source.map_err(sql)?;
                if source != a.source || active_revoked {
                    conn.execute("INSERT INTO source_authority_tombstones VALUES(?1,?2,?3) ON CONFLICT(source_id) DO UPDATE SET revoked_epoch=excluded.revoked_epoch WHERE source_authority_tombstones.authority_id=excluded.authority_id",params![source,id,policy.policy_epoch.get()]).map_err(sql)?;
                }
            }
            drop(members);
            // Remove live cyclic FK roots before retiring the immutable history. Both
            // occur in this same savepoint; no reader sees an authority gap.
            conn.execute(
                "DELETE FROM source_authority_members WHERE authority_id=?1",
                [&id],
            )
            .map_err(sql)?;
            conn.execute(
                "DELETE FROM source_authorities WHERE authority_id=?1",
                [&id],
            )
            .map_err(sql)?;
            conn.execute(
                "DELETE FROM source_authority_transitions WHERE authority_id=?1",
                [&id],
            )
            .map_err(sql)?;
            if !active_revoked {
                let checkpoint = format!(
                    "checkpoint-{}",
                    hash(
                        format!(
                            "{id}:{}:{}",
                            a.revision.revision_id.as_str(),
                            policy.policy_epoch.get()
                        )
                        .as_bytes()
                    )
                );
                conn.execute("INSERT INTO source_authority_transitions VALUES(?1,?2,NULL,NULL,NULL,?3,?4,'purge_checkpoint')",params![checkpoint,id,a.source,a.revision.revision_id.as_str()]).map_err(sql)?;
                let key = serde_json::to_vec(&key_wire(&a.key)).map_err(|_| invalid())?;
                conn.execute(
                    "INSERT INTO source_authorities VALUES(?1,?2,?3,?4,?5)",
                    params![
                        id,
                        key,
                        a.source,
                        a.revision.revision_id.as_str(),
                        checkpoint
                    ],
                )
                .map_err(sql)?;
                conn.execute(
                    "INSERT INTO source_authority_members VALUES(?1,?2,'active',?3)",
                    params![a.source, id, checkpoint],
                )
                .map_err(sql)?;
            }
            out.authority_groups_checkpointed += 1;
        }
        time(deadline)?;
        Ok(out)
    })();
    match result {
        Ok(out) => {
            conn.execute_batch("RELEASE asg_context_purge;")
                .map_err(sql)?;
            Ok(out)
        }
        Err(e) => {
            conn.execute_batch("ROLLBACK TO asg_context_purge; RELEASE asg_context_purge;")
                .map_err(sql)?;
            Err(e)
        }
    }
}
