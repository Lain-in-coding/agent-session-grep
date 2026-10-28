# Rebuild and migration runbook

Scope: operator procedures for an existing agent-session-grep data root — schema
upgrades, managed program-update reconciliation, full index rebuild, store
reconstruction, write-contention recovery, and the generation/cursor semantics
behind them. Managed recovery retains current permission/pause policy; the
legacy reconstruction procedures below do not reset that policy.

Commands below follow the current source CLI; inspect the newly built verified
candidate's `--help` before use, since older artifacts can lack update commands.
Examples use `--robot` for JSON envelopes. Paths are placeholders.

## Command reference

| Command | Writes? | Purpose |
|---|---|---|
| `agent-session-grep --robot doctor --db <path>` | no | Report store schema, generation, and interrupted-batch count. |
| `agent-session-grep --robot --db <path> sync <file>...` | yes | Atomically ingest the listed sources; no new generation when content is unchanged. |
| `agent-session-grep --robot --db <path> ingest <file>` | yes | Ingest one source file. |
| `agent-session-grep --robot --db <path> index rebuild` | yes | Reproject the FTS index from the catalog. |
| `agent-session-grep --robot --db <path> status` | no | Report catalog entity count and active generation. |
| `agent-session-grep --robot --db <path> search <query>` | no catalog write | Full-text search over the permitted catalog snapshot. |
| `asg --robot update check [--channel beta\|stable]` | public metadata transport | Explicit bounded release check; no archive download or program replacement. |
| `asg --robot --db <path> update apply --from <archive>` | yes | Verified offline current catalog22/control2 managed program update. |
| `asg --robot --db <path> update status` | journal reconciliation only | Inspect the retained update journal; no catalog recovery or worker start. |
| `asg --robot --db <path> update recover` | yes | Reconcile the recorded update under installation/catalog ownership. |
| `asg --robot --db <path> background status` | control observation | Distinguish desired ingestion intent from worker liveness; not a freshness proof. |

Error and exit-code mapping: usage or cursor errors exit `2`, not-found `4`,
source I/O and source-changed `5`, catalog errors and `writer_busy` `6`,
provider errors `7`, `schema_incompatible` `9` (as is a cursor whose
generation no longer matches), internal errors `70`, and a truncated but
usable result exits `10`. `update_recovery_required` also exits `10`, with
`retryable: false`; it asks for explicit recorded-update reconciliation rather
than blind retry. The envelope's `error.code` is the stable spelling.

## Managed program update and interrupted recovery

These commands require a verified installed managed candidate and its existing
managed catalog. Legacy adoption and schema-changing catalog migration are
separate from an executable program update.
`update check` uses only a hash-verified versioned helper for public HTTPS
metadata, while `update apply --from` validates a local archive, its sibling
manifest and `SHA256SUMS` without network access. See
[Install and upgrade](INSTALL-AND-UPGRADE.md#developer-candidate-user-triggered-program-update)
for the helper whitelist and exact package checks.

The current apply path supports a strictly newer SemVer on the same native
target only when the installed and candidate programs and the managed catalog
all use catalog22/control2. The first public managed package uses22/2; no
catalog21/control2 managed program has shipped. Schema-changing pairs are
refused before maintenance or catalog mutation. Ordinary managed opens also
refuse older schema rather than migrating during a read or sync.

The internal maintenance seam still supports the additive managed catalog
migration and exact schema restore under its own ownership and transaction
contracts. It can run canonical catalog21-to22 units after an exact owned21
backup is verified, and it can restore that exact21 image for coordinated
recovery. It preserves generation, incarnation, namespace and current control
policy without changing policy or granting current source proof. This is not an
old-program executor handoff, and the public `update` command does not expose
that schema-changing path.

For an interrupted update:

1. Keep the prefix's private update journal, versions, receipt, owned backups and
   current control intact. Use the same `--db <path>` and, when needed,
   `--install-prefix <prefix>` used by apply.
2. Run `asg --robot --db <path> update status`. It inspects the retained journal
   and may reconcile interrupted journal-file publication under the real lock.
   A fresh install with no journal has no idle-status response yet. Inspect
   `phase` and `error_code`; an inspection of terminal `failed`/`rolled_back`
   is not a successful upgrade. A recorded `restart_failed` state is a failed
   forward self-check, not a reason to repeat it. Nonterminal state returns
   partial (exit 10).
3. Run `asg --robot --db <path> update recover`. It verifies the selected
   catalog and installation identity, owns the maintenance fence, drains
   cooperating catalog handles and reconciles recorded metadata effects. A
   verified switched candidate may finish forward, except a recorded
   `restart_failed` self-check, which uses the rollback path. For the supported
   public catalog22/control2 program path, rollback rotates the catalog
   incarnation and restores old metadata. A recorded schema-changing pair is
   refused rather than treated as an executable old-program handoff; the
   internal exact21 restore seam remains separately owned. A busy live owner or
   changed or unverified identity is a reason to stop and resolve the reported
   failure, never to delete a lock/fence or overwrite metadata by hand.
4. Recheck `update status`, both command versions and `background status`.
   Forward completion starts the verified next-version supervisor only for
   running intent, using the owned native registration or a hidden detached
   launch when login startup is disabled. It rechecks current pause/stop;
   `restart_failed` while still running leaves a recoverable partial state and
   explicit recover selects rollback. Rollback also restarts the verified old
   supervisor only for current running intent; restart failure remains partial
   and recoverable. A second successful recover does not rotate the catalog or
   increment the destructive epoch again. `background start` preserves intent;
   `background resume` explicitly changes paused/stopped intent to running.
5. Run a permitted evidence read with `--latest` to obtain a new post-request
   observation. Update status always reports `freshness: unknown`; package
   identity, a heartbeat and catalog generation cannot establish source coverage.
   Update journals replacement/recovery of its proven owned native supervisor
   registration without adopting unowned entries or enabling autostart. Inspect
   explicit selected-host setup if registration or host loading needs repair;
   update does not restart host processes or verify their loaded MCP image.

Recovery never copies an older `control.db` over the current one or clears a
revoke/pause to make rollback possible. Rollback reconciliation invalidates old
progress, barriers, pending rewrite/deletion confirmations and continuation
proofs. The initial checkpoint stays immutable; a separate post-drain checkpoint
binds
backup to the actual drained catalog/control identity. Failed candidate process
exit or incorrect active pointer generation rejects self-check even when other
identity fields match. The current equal-schema path retains the live catalog
and reconciles metadata; it is not a general catalog backup-restore interface. The verified
WAL-aware catalog backup excludes control and provider histories. Generic
schema-changing restore and legacy-to-managed migration remain separate work.
Setup history selection still uses `sources add` separately. Public background
autostart enable/disable, managed uninstall/default purge and keep-data are not
yet implemented.

The worker writes an incomplete discovery receipt before source I/O and only
finalizes the exact current-cycle source set after complete verification.
Confirmed absence participates in that set; failed discovery cannot resurrect
an older complete receipt. Empty, malformed and unstable rewrites retain the
last verified evidence and leave latest partial. Valid nonempty complete
rewrites, including shrinking JSONL, and deletion require two qualifying cycles
at least five monotonic seconds apart. Restart or changed proof/policy/root
restarts confirmation; offline/unreadable roots are never deletion proof.
This is a correctness grace window, not a measured update-latency claim.

## Legacy catalog procedures

The procedures below describe the unmanaged write-open migration, merged
catalog and stateless cursor path. Managed commands enforce selected scopes and
pause, use per-source receipts and fail closed on missing/corrupt control.
Managed index rebuild does not bypass an update fence or regrant a source.
Do not delete/recreate a managed catalog, restore control or run an old unscoped
binary to apply the legacy procedures.

## Reading doctor

```
agent-session-grep --robot doctor --db <path>
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

`data.index_projection_stale` is the second signal to act on. It compares the
store's `index_projection_version` (what wrote the FTS tokens currently on
disk) against `index_projection_expected` (what this binary's query side
produces). `false` is healthy. `true` means the two token streams are not
comparable, so search refuses instead of returning a wrong hit set — see
"Index-projection upgrades" below. Without `--db` the expected value is still
reported (a build fact) while the store-side fields are `null`, never guessed.

If `doctor` fails instead of reporting, the error envelope names the reason —
most usefully `schema_incompatible` when the store schema differs from the
binary's supported version, whether older or newer. `doctor` is read-only and
does not perform an upgrade.

For a managed catalog with a sibling `control.db`, `doctor` returns
`managed: true` instead. It runs the managed control/admission path, reports a
bounded catalog check plus `snapshot.generation`,
`snapshot.destructive_epoch` and `snapshot.policy_epoch`, and sets
`diagnostics_complete: false`. The legacy `schema`, `interrupted_batches` and
index-projection fields do not describe this response. A successful managed
doctor does not prove selected-source freshness or host/model acceptance.

## Procedure 1: Schema upgrade

For an unmanaged catalog, schema migration occurs on write open rather than
through a dedicated schema-migration command. Managed program updates use the
separate `update` commands above and currently refuse schema changes. Read-only
opens (`doctor`, search, MCP) require the supported schema and never migrate an
older catalog. An
explicit write path such as `index rebuild`, `sync`, or `ingest` takes the
writer lease and migrates before its own operation. It may also refresh stale
index projections; choose and authorize that write deliberately.

`SCHEMA_VERSION` is currently 22. The additive steps include v8 resume claims,
v9 source-scan provider id, v10 semantic vectors, v11 session-metadata search,
v12 tool activity, v13 session titles, v14 parser version, v15 token usage,
v16 repo identity, v17 index-projection version, v18 installation/relocation
records, v19 journal-compaction records, v20 managed catalog/source
projections, v21 retained exact-receipt lineage for verified recovery, and v22
source-publication context with its dependency and atomic provider-source
authority records. The v21 table is empty when migrated; neither v21 nor v22
backfills observations, permission or currentness proof. Migration adds their
schema; it does not select histories or complete managed setup. `PRAGMA
user_version` gates the steps in
`crates/agent-session-grep-adapters-sqlite/src/lib.rs`
(`migrate_v7_to_v8` through `migrate_v19_to_v20`); the additive managed tail
through v22 is completed by `migrate_managed_in_transaction` in that file. The
v17 → v18 implementation is in
`crates/agent-session-grep-adapters-sqlite/src/relocation.rs`.
The v5 → v6 (`migration-v5-to-v6.md`) and v6 → v7 (`migration-v6-to-v7.md`)
records remain historical; those stores upgrade on an explicit write open.

Transaction boundaries are migration units, not the entire upgrade chain:
legacy v1–v6 changes share one transaction, and v6 → v7 and subsequent steps
have their own transactions. A failed unit rolls back its changes, but earlier
committed units can remain. Do not assume failure restores the original
schema or guarantees old-binary readability; retain the pre-upgrade backup.

Operational sequence:

1. Record the binary version/commit and the pre-state with a compatible old
   binary's `agent-session-grep --robot doctor --db <path>`. A new binary can
   instead return `schema_incompatible`; that read is not an upgrade.
2. Stop writers and retain a verified consistent copy of the data root before
   any write open. The WAL-aware feasibility spike explains why copying only
   the main database file while a writer is live is unsafe; preserve committed
   WAL state in the backup rather than assuming the main file is sufficient.
3. Run the explicitly chosen write with the new binary:
   `agent-session-grep --robot --db <path> index rebuild`. Check its exit code;
   stop and inspect on failure rather than assuming the whole chain rolled back.
4. Run `agent-session-grep --robot doctor --db <path>` again. This read-only
   verification must report `data.schema: 22` and `data.db: "ok"`.
5. Re-ingest sources (`sync`) to lift legacy rows to current fidelity.
   Migration never fabricates data; rows created before v6 have no session or
   span attribution until re-ingested. `context` remains disabled with
   `schema_incompatible` and a bounded re-ingest-required action until every
   known contributing source has completed a zero-skipped v7 scan
   (relation-complete); see `migration-v6-to-v7.md`.

The reverse direction is refused: an older binary opening a newer store gets
`schema_incompatible` (exit 9), not a silent downgrade.

## Parser-semantic upgrades trigger targeted backfill, not rebuild

`sync`'s "unchanged" judgment is not only `(len_bytes, fingerprint)`: it also
compares the stored `source_scans.parser_version` against the binary's
`PARSER_SEMANTIC_VERSION` constant (borrowed from Recall's parser-version
incremental sync). When a release changes parsing semantics — anything that
changes what a provider parse produces for the same bytes, such as noise
filtering rules or a new transcript shape — the constant is bumped. Sources
whose bytes are unchanged but whose stored parser version is behind are then
re-parsed once on the next `sync` (targeted backfill: parse + commit, which
writes the current version back into `source_scans`), instead of keeping
stale parsed content until a manual `index rebuild` or until the source file
happens to change. No full rebuild is required.

Operational facts:

- The schema v14 migration adds `parser_version INTEGER NOT NULL DEFAULT 0`
  to `source_scans`. Existing rows default to `0`, which never equals the
  current constant (≥ 1), so the first `sync` after the upgrade automatically
  backfills every previously scanned source.
- Each backfilled source commits once and advances the generation (cursors
  are invalidated as for any commit); afterwards the source is current again
  and subsequent syncs are no-ops.
- A sync that re-parses sources for this reason reports it through the
  warnings channel with a `parser semantics upgraded (stored parser_version
  …, current …)` diagnostic per source. Truncated-tail sources are still
  retained (not re-parsed) until the file is complete.

## Index-projection upgrades reproject, and never return wrong results

`PARSER_SEMANTIC_VERSION` covers one axis: what a provider parse produces
from the same source bytes. A second, orthogonal axis is what the store
*projects* out of the authoritative catalog into the search index —
the FTS token stream and the derived per-session projections. Changing that
projection (the CJK tokenizer, the `MESSAGE_FTS_MAX_CHARS` retention cap, the
`searchable_text` rule, which fields `session_fts` carries, the
`session_titles` derivation chain, or the `session_repo_slugs` slug rule)
makes every row already on disk incomparable with what the query side now
produces. Indexing and querying must apply the *same* transform.

This is versioned by `INDEX_PROJECTION_VERSION` and persisted as the
store-level `store_metadata.index_projection_version` (schema v17). It is
deliberately a whole-store singleton, not a per-source column like
`source_scans.parser_version`: one reprojection rewrites every row, so a
per-source record has no self-consistent value in a partially migrated store.

The following projection-version behavior assumes a current-schema catalog;
a schema mismatch itself refuses the read open, as described above.

What happens on a mismatch:

- **Write opens self-heal.** Any write path (`sync`, `ingest`, `index`)
  reprojects from the catalog before doing its own work, and **no re-parse is
  needed** because catalog payloads are authoritative for content. That
  advances the generation once (cursors are invalidated, as for any commit) and
  stamps the current version.
- **Self-heal covers every projection except one.** `session_repo_slugs` is
  the only projection that cannot be rebuilt from the catalog: a slug exists
  only as a live probe of the local git checkout, by design, since no absolute
  path is ever stored. Self-heal runs inside the write open, before the
  composition root can inject the resolver, so it deliberately preserves those
  rows instead of emptying and re-deriving them — otherwise one self-heal
  would delete the whole repo dimension and stamp the version current in the
  same transaction, leaving `search --repo` at zero hits with nothing to
  report the loss. Consequence to plan for: a change to the **slug derivation
  rule** is converged only by an explicit `index rebuild`, which re-probes git.
  A version bump alone converges the FTS token stream, `session_titles`, and
  the display projections; it does not re-derive slugs.
- **Read paths fail closed.** A read-only open holds no writer lease and must
  not write, so FTS queries return `schema_incompatible` (exit 9) with the
  exact remedy in the message instead of matching old tokens against new query
  tokens. `list`, `get`, and `status` keep working: they read the catalog,
  which is unaffected.
- **`doctor` reports it** through `index_projection_version`,
  `index_projection_expected`, and `index_projection_stale`.

Manual remedy, when you would rather not wait for the next write command:

```
agent-session-grep --robot --db C:/data/example.db index rebuild
```

Operational facts:

- The v17 migration stamps honestly from an observable fact rather than from
  the old schema version: a store whose `fts` and `session_fts` are both empty
  has no old tokens and is stamped current (a fresh data root never reports
  stale and never churns a rebuild on first open); a store with projection
  rows keeps the `0` sentinel, which never equals the current constant (≥ 1).
- Only a whole-store reprojection stamps the version. The incremental commit
  path deliberately does not: it only rewrites the batch's own rows, so
  claiming store-wide currency there would re-hide exactly this defect.
- Why this matters concretely: the 2026-08-27 dogfooding run found a real
  170,468-entity library built by an older binary where MCP `search_sessions`
  returned **0 hits** for Chinese queries (`配置备份`, `备份`) while ASCII
  queries (`clippy`) scored and matched normally — a silently wrong result
  set, not an error. The stored tokens were pure CJK bigrams; the binary had
  moved to unigram + bigram.
- Measured cost on that library (1.5 GB store, release build, local NVMe):
  the v15 → v17 migration plus `doctor` took **0.19 s**; one whole-store
  reprojection of all 170,468 entities took **≈140 s**. Budget roughly two
  minutes of extra time on the first write command after this upgrade for a
  library of that size, and expect one generation advance. Read paths refuse
  rather than triggering that work implicitly — a two-minute stall inside a
  search would be its own defect.

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
  on a write open, with that repair itself leaving `user_version` unchanged.

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
agent-session-grep --robot --db <new-unmanaged-catalog> sync <file1.jsonl> <file2.jsonl>
```

Semantics that make this safe to reason about:

- Identity: Message ids prefer the provider-native id. The no-native fallback
  is path-free (provider + variant + document ID + sequence), and is marked
  `Unstable`: parser/filter changes can shift sequence values, so there is
  no cross-parser stability guarantee. Document IDs are content-addressed
  within their provider/variant.
- `sync` commits eligible staged sources in a single durable batch. Only a
  `source_changed` detected during final post-stage verification is deferred,
  with that source's previously indexed data preserved; other eligible sources
  may still commit (see Procedure 4). Earlier capture/reopen failures, including
  `source_changed`, abort `sync` before the batch commit. This does not promise
  that every file-list member commits or that all failure classes behave alike;
  inspect the exit status, `deferred` count, and bounded diagnostics.
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

**`source_changed` (exit 5 when returned as an error).** A source changed
while being read. Only a change detected during final post-stage verification
is **deferred** by `sync`: that source is dropped from the commit batch,
reported through a per-source diagnostic and the `deferred` count, and its
previously indexed content is left untouched. Other eligible sources may still
commit together; this is not a promise to commit every input.

Earlier capture/reopen failures, including `source_changed`, still
abort `sync` before the batch commit. Other error classes are not automatically
deferred either. Inspect the actual exit status and `deferred` count; re-run
once the source is no longer being written. `ingest` of a single source still
returns exit 5 for `source_changed`, rather than using the batch deferral path.

**`catalog_error` (exit 6) that `doctor` cannot explain.** The masked message
("database internal error") covers two different situations: the store failed
to open or read, and the store *opened fine* but refused a write because it
would have broken an invariant. Run `doctor --db <path>` first. If `doctor`
reports a healthy store, it is the second case; rerun the same command with
`ASG_DEBUG_ERRORS=1` to print the masked reason on stderr (it never enters the
stdout envelope).

The refusal seen on real data is `message has conflicting projections across
sources (stable field \`role\` differs)`. Message identity adopts the provider's
native id, so one entity can be contributed by more than one file; a *stable*
field that disagrees between two contributions means the two files describe the
same identity differently, and the store refuses rather than pick a winner.
The case to expect is a store written by an **older parser**: re-parsing the
same bytes today can produce a different stable projection than the row already
on disk, and the merge then has no authority to choose. Verified on a 170k-entity
library built by an older binary: every `sync` failed this way, while a full
`sync --discover` of the same 1,888 sources into a *fresh* `--db` succeeded
(336,563 messages, exit 0). Sources are authoritative and re-ingest is cheap
relative to the value, so the remedy is to rebuild rather than to patch rows:

```
agent-session-grep --db <new-unmanaged-catalog> sync --discover
```

Compare `status` on both stores, then swap the new file in and keep the old one
until you are satisfied. An `index rebuild` does **not** help here: it reprojects
the catalog it already has and never re-parses a source.

## Procedure 5: Generation and cursor semantics

These stateless cursor rules describe the unmanaged path. Managed continuation
proofs are also bound to policy, catalog incarnation and destructive change;
append generation alone is not proof of invalidation or freshness. Recovery
invalidates those proofs. Inspect the current managed tool capability report
before assuming a cursor is supported.

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

- Unmanaged catalog and FTS facts occupy one SQLite database. Managed mode also
  has separate policy/control, continuation and owned-artifact state. A managed
  catalog backup is WAL-aware and does not back up or restore control.
- Unmanaged reconstruction by re-ingest has the identity limits in procedure 3.
  Managed identity/namespace and permission state are not recreated by deleting
  a database; recovery requires their verified ownership records.
- The current managed update path coordinates the stable launcher and immutable
  application/supervisor/helper versions for equal schemas. Schema-changing and
  protocol-major upgrades, native four-target recovery and actual host-loaded
  acceptance remain unverified; a local synthetic pass is not those receipts.
