# Provider Adapter Contributor Guide

This guide is the community entry point for adding or changing a provider adapter. It complements the [Provider Adapter Contract](architecture/RFC-0002-provider-adapter-contract.md), the [fixture redaction policy](security/FIXTURE-REDACTION-POLICY.md), and the [provider maturity matrix](product/PROVIDER-MATURITY-MATRIX.md).

> **Never upload, paste, or commit a real transcript.** Do not include secrets, credentials, provider databases, hostnames, identities, or absolute personal paths in an issue, pull request, fixture, test, log, or diagnostic. Build a minimal synthetic fixture with invented content instead.

RFC-0002 is currently Draft. The in-tree Rust contract is authoritative for code: discovery and snapshotting are owned by the surrounding application ports, while `ProviderAdapter` currently exposes metadata, `probe`, and `parse`. The planned community boundary is a versioned external process; describing an adapter proposal does not imply that arbitrary dynamic plugins are already loadable.

## 1. Keep provider logic behind the adapter boundary

An adapter translates one provider variant into canonical events. It must not implement catalog storage, search, UI, release behavior, or source mutation.

The current minimum Rust contract is:

```rust
pub trait ProviderAdapter: Send + Sync {
    fn provider_id(&self) -> &str;
    fn manifest(&self) -> AdapterManifest;
    fn probe(&self, bytes: &[u8]) -> Result<ProbeResult, ProviderError>;
    fn parse(
        &self,
        bytes: &[u8],
        sink: &mut dyn CanonicalEventSink,
    ) -> Result<ParseReport, ProviderError>;
}
```

Use domain and port types. Provider-specific filesystem, SQLite, or JSON details stay inside the provider crate and its discovery implementation.

## 2. Declare the manifest before claiming support

Every implemented Rust adapter must return `AdapterManifest` from `manifest()`. Use the authoritative capability matrix through `manifest_for`; do not duplicate maturity or capability values in entry points.

The current in-tree manifest contains:

| Field | Requirement |
|---|---|
| `provider_id` | Stable canonical identifier, such as `example-agent` |
| `supported_variants` | Explicit, versioned format identifiers; never use one catch-all variant for incompatible formats |
| `maturity` | Current evidence-backed state, not a roadmap target |
| `capabilities` | The authoritative per-field capability row |
| `fixture_revision` | Revision from a fixture `PROVENANCE.md`, or `None` when no reviewed revision exists |
| `last_certified_targets` | Named successful certification targets only; local runs or configured workflows do not count |
| `known_limitations` | Concise user-visible gaps and unsupported cases |

A community external-process proposal must also declare its protocol/schema version and review metadata for:

- provider id and supported variant range;
- candidate source roots and how users authorize them;
- capabilities and current maturity;
- adapter and fixture license/provenance;
- network permission (`none` by default), including purpose and data boundary if requested;
- the read-only source guarantee.

Do not place a real user root, credential, or machine-specific path in a manifest. Roots must be portable declarations or user-supplied configuration. The exact external-process wire schema remains versioned contract work; do not invent an incompatible runtime protocol in a provider pull request.

Capability values are `native`, `derived`, `partial`, `unsupported`, or `unknown`. Use `unknown` until evidence exists. A new adapter starts at **Experimental** by default. Code existing is not promotion evidence.

## 3. Probe conservatively

`probe` identifies a supported variant without mutating the source.

- Return a stable `variant_id` and one of `Confirmed`, `High`, `Low`, or `Ambiguous`.
- Record only bounded, privacy-safe evidence about structural discriminators.
- Unknown or mixed incompatible variants must be `Ambiguous` or an `AmbiguousVariant` error. Never silently parse them as a nearby known format.
- Additive unknown fields may be ignored only when the variant contract permits it; count or diagnose them without copying source content.
- Malformed or adversarial input must return a typed error, not panic.

Probe tests must include positive, negative, ambiguous, truncated, and unknown-field samples.

## 4. Parse through `CanonicalEventSink`

`parse` streams canonical messages to `CanonicalEventSink::emit_message`. Do not build an unbounded in-memory transcript.

Each `MessageEvent` carries:

- a successful-message sequence number;
- provider-native message and parent ids when they actually exist;
- role and normalized searchable text;
- a provider timestamp only when it is stable and authoritative;
- the sidechain flag;
- an optional source span.

Do not fabricate native ids, parent edges, timestamps, or session metadata. Missing data stays missing. The sink owns canonical role/id mapping and source-local staging; the adapter must not write directly to storage.

Return a truthful `ParseReport`: `committed`, `skipped`, bounded diagnostics, durable session id when present, and any provider session observation. Recoverable record failures increment `skipped`; a structural failure rolls back the source staging instead of exposing partial canonical state.

## 5. Preserve source-span evidence

`MessageEvent.span` is `Option<(u64, u64)>` in **verified snapshot bytes**:

- `start` is inclusive and `end` is exclusive;
- for JSONL, exclude the line terminator;
- offsets must bound the exact source record used for the event;
- multi-byte Unicode must be measured in bytes, not characters;
- use `None` when no contiguous span can be attributed; never fabricate precision.

Golden and end-to-end tests must prove the span round-trips to the expected synthetic source bytes. If a row-oriented source cannot provide a file-byte span, document the limitation and set the capability honestly.

## 6. Enforce read-only snapshots and checksums

Provider histories are untrusted, privacy-sensitive, read-only sources.

- Open files and provider databases read-only. Never write, delete, move, prune, lock, vacuum, migrate, or repair upstream data during discovery, probe, or parse.
- Parse only the captured snapshot range. Recheck source identity, length, modification state, and content fingerprint before commit.
- Treat the content fingerprint as authoritative. Length and modification time are fast-path hints and cannot detect an equal-length replacement by themselves.
- If the source changes during parsing, discard staging and report `source_changed_during_read`; do not commit a mixed-time snapshot.
- Add a before/after checksum assertion. Use the shared read-only test helper where available, and ensure diagnostics never reveal source paths or bytes.

SQLite providers must use a read-only connection and must not execute schema changes or cleanup queries against the provider database.

## 7. Make incremental and tombstone behavior explicit

When an adapter claims incremental support, test all of these cases:

1. first sync commits the expected canonical events;
2. an unchanged resync is idempotent;
3. an append adds only new memberships without changing stable identities;
4. a successful source shrink removes only memberships no longer present;
5. a successfully parsed empty source creates the expected whole-source tombstones;
6. a malformed, ambiguous, incomplete, unavailable, or changed source preserves the last good catalog state.

Failure is not evidence of deletion. Provider discovery or parse failure must be isolated to that provider and must not abort successful increments from other providers. Missing-source and root-level tombstones are valid only after a complete successful scan proves absence; never infer them from permission errors, partial roots, unsupported layouts, or parse failures.

## 8. Supply synthetic fixtures and reproducible tests

Prefer small hand-authored fixtures with invented beacon text. Every fixture set must include `PROVENANCE.md` that records:

- whether it is synthetic or irreversibly redacted;
- the generator or hand-construction procedure;
- `fixture_revision` and supported variant;
- confirmation that it contains no real transcript, secret, identity, hostname, or personal path;
- fixture and generator license/provenance.

Never copy fixtures from another project, even when that project is open source, unless repository policy has explicitly accepted the provenance. Provider format research is evidence for structure, not permission to copy user data.

Required test layers:

- **probe tests** for confirmed, rejected, and ambiguous variants;
- **golden tests** that lock fixture bytes and compare the complete canonical output, report, identities, threading, and spans;
- **deterministic property tests** for malformed records, unknown fields, Unicode, large/bounded fields, ordering, duplicate mirrors, and no-panic behavior;
- **read-only tests** with pre/post checksums;
- **incremental end-to-end tests** for idempotence, append, shrink, empty source, and failure-preserves-old-data behavior when claimed;
- **search/context smoke tests** proving emitted canonical events remain usable through the shared application path.

A parser-only unit test is not enough evidence for a maturity promotion.

## 9. Maturity is evidence-based

New adapters and new variants default to `Experimental`. Keep the capability matrix and manifest aligned with the facts.

Promotion requires independent review and evidence appropriate to the level:

- **Experimental:** conservative probe, small synthetic parse fixture, explicit limitations.
- **Beta:** main-path fixtures, golden/property/contract tests, read-only checksum evidence, incremental and tombstone coverage, source spans, and the claimed canonical capability path.
- **GA/Certified:** historical and mixed variants, unknown-field policy, crash recovery, rollback evidence, performance evidence, named successful target runs, and owner/approver promotion decisions.

Do not fill `last_certified_targets`, update public claims, or raise maturity based only on a local green run.

## 10. License, network, and privacy review

In-tree contributions must be compatible with the repository's `MIT OR Apache-2.0` licensing. Declare the license and provenance for adapter code, generated artifacts, and fixtures; update required notices for accepted third-party reuse. Follow the repository reuse audit. Restricted-party material and fixtures with uncertain provenance require clean-room treatment and must not be copied.

Provider adapters are **offline and network-denied by default**:

- no telemetry, uploads, crash reports, update checks, or remote format detection;
- no provider credentials in configuration or tests;
- any requested network permission must be explicit in the contribution manifest, narrowly scoped, justified, reviewable, and user-confirmed;
- offline operation must fail clearly without changing source or catalog state.

A network-enabled adapter proposal needs a separate trust-boundary review. Do not add an implicit fallback from local parsing to a remote API.

## 11. Pull request checklist

Before opening a pull request:

1. Read [CONTRIBUTING.md](../CONTRIBUTING.md) and use the repository pull request template.
2. Add or update the manifest and authoritative capability row.
3. Add synthetic fixtures, `PROVENANCE.md`, golden/property/read-only tests, and incremental tests as applicable.
4. Update provider limitations, maturity documentation, and user-facing docs without overstating support.
5. Run:

   ```text
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```

6. Recheck the entire diff for real transcripts, secrets, credentials, identities, hostnames, and personal paths.

If a real transcript is necessary to investigate locally, keep it outside the repository and do not attach it to an issue or pull request. Reduce the behavior to a synthetic fixture before sharing.
