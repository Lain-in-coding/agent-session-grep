# Runbook: v5 → v6 store migration (canonical Source/Session/Span foundation)

Scope: data roots created before schema v6 (`PRAGMA user_version < 6`).

## What v6 changes

- `source_membership` gains a nullable `document_id` column. Legacy rows keep
  `NULL` — the pre-v6 store had no document attribution and none is invented.
- New ingests persist three entity kinds per source into the catalog:
  messages (`msg_v1_*`), one session (`ses_v1_*`), and one content-addressed
  document (`doc_v1_*`). Container entities never enter the FTS table; only
  messages are search hits.
- New message payloads carry `session` (wire id reference) and `span`
  (byte offsets into the verified source snapshot, end exclusive).

## Migration behavior

- Opening a v5 store with a v6 binary migrates in a single transaction
  (idempotent, gated by `PRAGMA user_version`). On failure the transaction
  rolls back and the store remains v5-readable by the old binary.
- Opening a v6 store with an older binary is refused
  (`schema_incompatible`) — no silent downgrade.

## Legacy-row semantics (explicit absence, not fabrication)

Messages ingested before v6 have no `session`, no `span`, and their
membership rows have `NULL document_id`. `show` reports these fields as
`null`. This is honest missing data.

**To obtain full fidelity (session/document entities + spans) for legacy
sources, re-ingest them** (`sync <files...>`): identity is stable (native ids
survive re-ingest; reconstructed ids are deterministic), so re-ingest upserts
in place, adds the container entities, and enriches message payloads. If the
source bytes changed since the original ingest, the content-addressed
document id reflects the current bytes — the old document row (if any)
retires via the normal tombstone rules.

## Rebuild interaction

`index rebuild` preserves identity stability tiers via the `fts_ids` sidecar
(fallback `from_wire` → `Unstable`, documented catalog-key constraint) and
keeps container entities out of FTS. Spans live inside catalog payloads and
are untouched by rebuild.
