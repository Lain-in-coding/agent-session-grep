# Journal maintenance

Journal maintenance aggregates the detailed recovery manifests of confirmed,
terminal indexing batches, then reclaims SQLite storage. It does **not** delete
provider transcripts or catalog messages. Aggregating old journal detail is
irreversible without the maintenance-before-state backup; it is not a search
quality or search-speed upgrade.

## Preview and submit

Use the same catalog on every command. Omit `--db` to use the normal platform
catalog. Global flags such as `--robot`, `--request-id`, and `--db` belong before
`journal`, just as they do for other commands.

```text
asg --db <catalog> journal preview
asg --db <catalog> journal submit --plan <token-from-preview>
asg --db <catalog> journal status <job-id>
```

Preview reports the selected batch count, estimated journal-detail savings and
a confirmation token. It does not enqueue work or start a worker. Review the
irreversible effect before submitting. Estimates of logical detail savings
are **not** estimates of the exact database-file reduction.

Submission rechecks the token and saves the job durably before acknowledging
it. **Accepted means queued, not completed.** If starting the worker fails, the
job remains saved; start the worker explicitly after resolving the problem.
Submitting the same accepted token is idempotent.

If the candidate set changes before submission, preview again. After successful
submission, new batches are excluded. If a selected batch changes before its
compaction, the task requires a new review; retry never silently selects a new
set of rows.

## Online execution and write budget

The worker is started on demand, survives the submitting CLI process, and
installs no operating-system service or scheduled task. While automatically
retryable work exists it remains alive and retries contention. No further CLI
request is required when an existing lock is eventually released.

Search and other read-only commands never start it. Successful write commands
can wake an existing, unpaused queue after releasing their writer lease. After
a crash or machine restart, an explicit worker start, submit/retry, or an
eligible write invocation is needed to wake the saved queue again.

A maintenance attempt takes the normal exclusive writer lease. Existing
read-only services need not be closed in advance, but a long read transaction
can delay WAL truncation. New write requests may receive `writer_busy` while
maintenance holds the lease.

The default writer-lease budget is **30 seconds per acquisition**. It is a soft
budget: SQLite work and backup steps check for interruption, but filesystem I/O
cannot always be interrupted immediately. The worker never silently increases
the budget. Three budget-exhausted attempts without durable stage progress
require attention rather than retrying an oversized operation forever.

```text
asg --db <catalog> journal retry <job-id> --max-write-seconds 120
```

This explicitly permits a longer write interruption; it is not a guarantee that
a large database will finish within that time. Contention retries use delays of
1, 2, 5, 15, 30 and then at most 60 seconds. Jobs also need enough free disk for
a verified backup, VACUUM working space and WAL growth; SQLite can require up to
twice the database size in additional working space for VACUUM alone.

## Status, pause, cancellation and retry

```text
asg --db <catalog> journal status
asg --db <catalog> journal worker stop
asg --db <catalog> journal worker start
asg --db <catalog> journal cancel <job-id>
asg --db <catalog> journal retry <job-id>
```

- `status` reads queue state without opening or migrating the catalog. Without
  a job ID it lists jobs for the selected catalog and the root worker state.
- `worker stop` persistently pauses maintenance for the whole data-root and
  requests interruption at a safe point; it does not delete jobs. Automatic
  wakes do not clear that pause. `worker start` explicitly resumes it.
- `cancel` stops uncommitted work and later stages. It does **not** undo a
  committed journal compaction. Check `logical_compaction_committed` in status;
  `null` means a crash left the result pending read-only reconciliation, not
  that nothing committed. Once durable cleanup has started, cancellation is
  closed (`cancellation_closed: true`): the backup may already be deleted, so
  the job must finish/retry cleanup rather than promise backup retention.
- `retry` retains the original target and selection and resumes unfinished
  stages. A `needs_review` job requires a new preview and submission instead.

| State | Meaning / next action |
|---|---|
| `queued` | Durably accepted and awaiting execution. |
| `running` | A worker is processing or reconciling the job. |
| `deferred` | A temporary condition prevented progress; retry is automatic unless paused. |
| `needs_review` | The target or selected rows no longer match the authorization. Preview again. |
| `needs_attention` | Address the reported resource, budget or cleanup condition, then retry. |
| `completed` | Compaction, physical maintenance, validation and required backup cleanup succeeded. |
| `failed` | Inspect the bounded reason; no success is implied. |
| `cancelled` | Remaining work was stopped; already committed work is not reversed. |

Status distinguishes job state from phase. A successful VACUUM followed by a
busy checkpoint resumes at checkpoint rather than routinely repeating VACUUM.
After an ambiguous crash boundary a safe physical step may repeat; committed
logical compaction is reconciled through its catalog audit record.

## Backups and disk accounting

The queue is independent of the catalog, under `.maintenance` in the existing
writer-lease data-root. Each job binds a canonical catalog target, so changing
`--db` later cannot redirect previously accepted work. Queue and backup files
are private operational data; do not publish them.

Each job creates and verifies one owned maintenance-before-state backup before
compaction. It reuses that backup across attempts. **The backup does not include
legitimate writes made after it was captured.** Never restore it automatically
over a live catalog; restoration could discard newer messages or indexing work.

On success the worker closes and removes its own temporary backup after
verification. On failure or cancellation a verified backup is retained.
Cleanup failure is not completion: retry resumes cleanup rather than
recompacting the database. Never delete another job's retained backup to make
space. Manual recovery should be performed only after stopping writers and
preserving the current catalog; retained backups are evidence, not permission
to overwrite newer state.

Results separate logical detail bytes, catalog-file bytes, WAL/SHM, queue and
owned backup footprint. Job measurements can start after the queue was created
and while SQLite has SHM open; they are not necessarily the same interval as
measuring the entire directory before submission and after completion. Process
peak memory is a lifetime high-water mark, not incremental memory for one job;
zero means unavailable on platforms without a supported measurement. A no-reduction result is reported honestly; zero free
pages alone is not proof that VACUUM cannot compact partially occupied pages.
Concurrent writes can affect observed disk usage, so compare the measurement
points rather than interpreting every difference as maintenance savings.

Catalog schema remains v19. Missing, incompatible or replaced targets are not
created, migrated or silently substituted by maintenance. Existing read-only
services and the Robot envelope remain compatible.
