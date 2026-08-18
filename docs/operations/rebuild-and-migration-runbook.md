# Rebuild and migration runbook

Scope: operator procedures for an existing agent-session-grep data root — schema
upgrades, full index rebuild, store reconstruction, write-contention
recovery, and the generation/cursor semantics behind them.

Every command below exists in the current CLI; examples use `--robot` so the
output is the JSON envelope, not the human rendering. Paths are placeholders.

## Command reference

| Command | Writes? | Purpose |
|---|---|---|
| `agent-session-grep --robot doctor --db <path>` | no | Report store schema, generation, and interrupted-batch count. |
| `agent-session-grep --robot --db <path> sync <file>...` | yes | Atomically ingest the listed sources; no new generation when content is unchanged. |
| `agent-session-grep --robot --db <path> ingest <file>` | yes | Ingest one source file. |
| `agent-session-grep --robot --db <path> index rebuild` | yes | Reproject the FTS index from the catalog. |
| `agent-session-grep --robot --db <path> status` | no | Report catalog entity count and active generation. |
| `agent-session-grep --robot --db <path> search <query>` | no | Full-text search over the current generation. |

Error and exit-code mapping: usage or cursor errors exit `2`, not-found `4`,
source I/O and source-changed `5`, catalog errors and `writer_busy` `6`,
provider errors `7`, `schema_incompatible` `9` (as is a cursor whose
generation no longer matches), internal errors `70`, and a truncated but
usable result exits `10`. The envelope's `error.code` is the stable spelling.

## Reading doctor

```
agent-session-grep --robot doctor --db C:/data/example.db
```

`data.db` is `"ok"` when the store opens, or `"not-checked"` when no `--db`
was given. `data.schema` is the store schema version, `data.generation` is
the active generation, and `data.interrupted_batches` counts durable-intent
rows still marked `building`. The last one is the signal to act on:

- `0` — nothing to do.
- Greater than `0` — a writer crashed or was killed before activation. The
  aborted intents have no catalog or FTS effect. The next write open
  converges them automatically; run any write command, or `ingest` a single
  source if nothing new needs syncing, then check `doctor` again and expect
  `interrupted_batches: 0`.

If `doctor` fails instead of reporting, the error envelope names the reason —
most usefully `schema_incompatible` when the store is newer than the binary.

## Procedure 1: Schema upgrade

There is no manual upgrade command. Opening an older store with a newer
binary migrates it in a single transaction gated by `PRAGMA user_version`;
on failure the transaction rolls back and the old binary can still read the
store. `SCHEMA_VERSION` is currently 12, and v8 through v12 are the current
additive steps (v8 resume-claims, v9 source-scan provider id, v10 semantic
vector sidecar, v11 session-metadata search projection, v12 tool-activity
projection). They run stepwise on first open; the v7 → v12 chain is specified
in this runbook's procedures below and in the store source
(`crates/agent-session-grep-adapters-sqlite/src/lib.rs`, the
`migrate_v7_to_v8` … `migrate_v11_to_v12` steps), not restated here. The
v5 → v6 (`migration-v5-to-v6.md`) and v6 → v7 (`migration-v6-to-v7.md`) steps
are historical by design; stores at v5 or v6 migrate stepwise to the current
version on first open by the current binary.

Operational sequence:

1. Note the pre-state: `agent-session-grep --robot doctor --db <path>`.
2. Keep a copy of the data root before first open if it matters. There is no
   production snapshot or bundle API today (`CB-PROD-SNAPSHOT-API-001` is
   `not_implemented`); the WAL-aware feasibility spike shows why copying the
   main database file alone while a writer is live is unsafe.
3. Run the new binary against the store: `agent-session-grep --robot doctor --db <path>`.
4. Confirm `data.schema` is the new version and `data.db` is `"ok"`.
5. Re-ingest sources (`sync`) to lift legacy rows to current fidelity.
   Migration never fabricates data; rows created before v6 have no session or
   span attribution until re-ingested. `context` remains disabled with
   `schema_incompatible` and a bounded re-ingest-required action until every
   known contributing source has completed a zero-skipped v7 scan
   (relation-complete); see `migration-v6-to-v7.md`.

The reverse direction is refused: an older binary opening a newer store gets
`schema_incompatible` (exit 9), not a silent downgrade.

## Procedure 2: Full FTS rebuild

Rebuild when the FTS index is damaged or suspect and the catalog is
trustworthy. The catalog is the authority; the index is a projection of it.

```
agent-session-grep --robot --db C:/data/example.db index rebuild
```

The result reports `data.reindexed` (messages written back into FTS) and
`data.generation` (the new active generation). What a rebuild does:

- Clears the FTS tables and reprojects from every catalog entity. Only
  messages enter FTS; session and document entities stay out, matching the
  commit path, so search hit counts do not change meaning after a rebuild.
- Runs as one durable batch: intent is journaled first, then clear,
  reprojection, generation advance, and activation commit in a single
  transaction. A crash mid-rebuild leaves the store at the previous
  generation, and the intent shows up as `interrupted_batches` until the next
  write open.
- Preserves identity tiers via the `fts_ids` sidecar (fallback to parsing the
  wire id, with the documented catalog-key constraint; see
  `migration-v5-to-v6.md`).
- Deletes FTS rows through the `fts_ids.fts_rowid` sidecar column rather than
  by matching FTS content columns. The sidecar maps each message's wire id to
  its FTS rowid, turning the per-row clear/reproject delete from a
  content-column scan into a rowid lookup (O(1)); this is what makes rebuilds
  on large stores fast. `fts_rowid` is part of the `fts_ids` sidecar
  (introduced at schema v3): new catalogs carry the column from the v3 DDL,
  and catalogs created before it existed gain it via `ensure_fts_ids_rowid`
  on their next open, with `user_version` unchanged.

A rebuild **advances the generation**, which invalidates outstanding cursors.
It does not rewrite catalog payloads, so evidence spans inside payloads are
untouched.

Verify afterwards:

```
agent-session-grep --robot --db C:/data/example.db status
agent-session-grep --robot --db C:/data/example.db search "<known term>"
```

Compare `catalog_count` against the pre-rebuild value and confirm the known
term still hits. `status` does not include a per-kind breakdown — a gap to
be aware of when verifying.

## Procedure 3: Store reconstruction by re-ingest

When the store itself is untrusted or you need full current-schema fidelity
on legacy rows, rebuild the data root from the sources. Sources are the
ground truth and ingestion is read-only against them.

```
agent-session-grep --robot --db C:/data/example-new.db sync <file1.jsonl> <file2.jsonl>
```

Semantics that make this safe to reason about:

- Identity is deterministic. Message ids prefer the provider-native id; the
  fallback (path plus sequence) and the content-addressed document ids are
  reproducible for the same bytes. Re-ingesting the same source upserts in
  place instead of duplicating.
- `sync` is all-or-nothing across its file list: every source is staged
  first, then one durable batch commits. A failure partway leaves the store
  at its previous generation. Files that moved out of a re-scanned source
  become tombstones.
- A `sync` whose content matches what is already committed is a no-op: no new
  generation, and `data.committed` is `0` while `data.unchanged` reports the
  message count. Rerunning a reconstruction command is therefore cheap and
  safe to repeat.
- Content-addressed document identity means changed bytes get a new document
  id rather than a false match against the old one.

## Procedure 4: Writer-lease contention and interrupted batches

Each data root allows exactly one writer, enforced by an OS-level lock on
`writer.lock` in the store directory. Readers (`search`, `get`, `show`,
`list`, `context`, `status`, `doctor`) do not take it.

**`writer_busy` (exit 6).** Another process holds the lease. The lease is an
OS lock, so it cannot outlive the holder: a crashed or killed writer releases
it. Retry the command (`writer_busy` is `retryable: true`); if it persists,
find the process actually writing to that data root. Do not delete
`writer.lock` by hand — it is not a stale-flag scheme, and deleting a file a
live process holds locked does not unlock anything.

**`interrupted_batches > 0` in `doctor`.** A writer died between journaling
its intent and activating it. Because apply and activation commit in one
transaction, the interruption is always side-effect-free for the catalog and
FTS. The next write open (`sync`, `ingest`, `index rebuild`) marks the
stranded intents aborted automatically. Do not delete rows from
`index_batches` directly.

**`source_changed` (exit 5).** The transcript file was modified between its
capture and the post-stage verification. Nothing committed. Retry once the
source is stable; it is marked retryable for the same reason.

## Procedure 5: Generation and cursor semantics

Every committed write batch advances the store's generation by one. The
current value is in the `data.generation` field of `status`, `search`,
`list`, and `context` responses, and in `doctor --db`.

Pagination cursors (from `page.next_cursor` in `search` and `list`) are
self-contained tokens that record the generation they were issued against,
an expiry, and the query and sort they belong to. Continuing with
`--cursor <token>` checks, in order, token integrity, contract version,
expiry, then generation. Failure modes:

- `cursor_invalid` (exit 2): the token is malformed or bound to a different
  query. Re-run without `--cursor` to start a fresh page set.
- `cursor_expired` (exit 2): the TTL has passed (15 minutes by default).
  Re-run without a cursor.
- `generation_mismatch` (exit 9): a write — any `sync` or `ingest` that
  committed, or an `index rebuild` — advanced the generation after the cursor
  was issued. The error's `details` carries both `cursor_generation` and
  `active_generation`. Restart the sequence from the first page; the data you
  were reading may have changed, which is exactly why the cursor refuses.
- `schema_incompatible` (exit 9) can also come from a cursor minted by a
  different protocol contract major, with `details` naming both versions.

No-op syncs do not advance the generation, so rerunning an unchanged `sync`
does not invalidate cursors. Everything else that commits does, including
rebuilds.

## Storage-model limits

- There is one store per data root: the catalog table plus its FTS index in
  one SQLite database. Backup means a consistent copy of the whole data root
  while no writer is live; a production snapshot API does not exist yet.
- Deleting the store file and re-ingesting is a supported recovery path
  because identity is derived from content (procedure 3), not from the
  store's internal state.
- This runbook assumes the current single-binary CLI. It does not cover
  upgrading between protocol contract majors.
