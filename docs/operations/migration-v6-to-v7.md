# Runbook: v6 -> v7 store migration (relational message placement)

Scope: data roots at schema v6 (`PRAGMA user_version = 6`).

## What v7 changes

- Stable Message content remains in `catalog`; session, document, span,
  ordinal, sidechain, and parent facts move to explicit placement and edge
  relations.
- New source manifests track entity membership, placement claims, relation
  completeness, and relation changes in the durable outbox.
- Context assembly reads the typed relation graph. Compatibility aliases in
  Message and Session JSON remain readable projections, not graph authority.

## Before upgrading

1. Stop every agent-session-grep process that can write the data root.
2. Back up the SQLite database and any adjacent `-wal` and `-shm` files as one
   consistent set.
3. Record the v6 binary version so the backup can be inspected with the same
   binary if rollback is required.

Do not copy only the main database while a writer is active.

## Migration behavior

- The first v7 open migrates v6 in one transaction. Relation tables, indexes,
  outbox manifest columns, and `PRAGMA user_version = 7` commit or roll back
  together.
- Migration preserves existing catalog, FTS, identity-sidecar, and source
  membership rows. It does not infer placements, edges, source claims, or
  relation-complete markers from compatibility aliases.
- `get`, `show`, and `list` remain readable immediately after migration.
- `context` remains disabled with `schema_incompatible` and a bounded
  re-ingest-required action until every known contributing source has completed
  a zero-skipped v7 scan.
- An older binary refuses a v7 store. There is no in-place downgrade.

## Complete the upgrade

Use the v7 release binary to re-ingest every source that contributed to the
catalog. A complete source scan must report `skipped: 0`; otherwise the source
remains relation-incomplete, no missing-record tombstones are inferred, and
context stays disabled.

For a single source:

```text
agent-session-grep --db <catalog.db> --robot ingest <source.jsonl>
```

For a known source set:

```text
agent-session-grep --db <catalog.db> --robot sync <source.jsonl>...
```

The re-ingest upserts stable entities, writes source-placement claims and
relations, and regenerates compatibility aliases from complete relational
facts. Shared Messages remain one catalog entity while retaining distinct
per-session placements, parents, documents, and spans. When two sources
project the same stable message with different content, `text` is exempt
from conflict authority — it is a content projection, not a stable identity
field, and a resumed/forked session copy may legitimately carry a different
number of content blocks. The merged payload deterministically keeps the
longer text projection so no retrieved content is lost, and FTS is
reprojected from `searchable_text` of the merged payload so the search
index reflects the single merged fact.

## Verify

1. Confirm each ingest/sync response is successful and reports `skipped: 0`.
2. Run `status` and confirm placement and source-placement-claim counts are
   nonzero for a nonempty corpus.
3. Run `get`, `show`, and `list` to confirm legacy catalog reads still work.
4. Run `context <session-id>` for representative sessions. It must succeed only
   after all known contributors are relation-complete.
5. Run `index rebuild`, then repeat `status` and representative context reads.
   Rebuild must not change relation counts or context results.

## Failure and rollback

- If migration fails, do not retry with an older binary against a partially
  copied file. The transactional migration leaves the original v6 schema and
  version intact; investigate the reported catalog error first.
- If rollback is required after a successful migration, stop all writers and
  restore the complete v6 backup set. Do not edit `user_version`, drop v7
  tables, or attempt a reverse migration.
- A failed or incomplete re-ingest is not a reason to restore the database:
  fix the source/provider error and rerun the complete source set. Context
  remains disabled rather than fabricating graph completeness.
