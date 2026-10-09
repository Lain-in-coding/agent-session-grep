# Pull request

Keep changes focused and privacy-safe. Follow `CONTRIBUTING.md`.
Title: `type(scope): subject`, at most 50 Unicode code points in total.
Allowed types: feat, fix, docs, refactor, test, chore, ci, perf.
Scope is required. Use English for the title and core why; Chinese may
supplement. Keep body lines at most 72 code points. Replace every prompt
below; unchanged placeholders or checked boxes are not a rationale.

> Never paste real transcripts, secrets, copied provider databases, or
> private personal paths/hostnames. Use synthetic or irreversibly
> redacted fixtures with provenance, and runtime-generated synthetic
> test values, not hardcoded token-shaped examples. Genuine
> author/committer metadata, human co-author credit, and required
> license attribution are retained.

## Why and scope

<Describe why this change is needed and which contract it addresses.>
<Describe the change, its boundaries, and the related issue if any.>

## Risks and rollback

<Describe risks, limitations, and the newly reviewed rollback approach.>

## Validation

<Describe commands, results, tested base/head SHAs, and check links.>
<Describe metadata_sha256 and the reviewed merge message/identity.>
<Describe anything not run or blocked; do not present it as success.>

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Applicable helper/feature tests and Markdown/YAML checks ran.
- [ ] Governance tests used the verified native-platform archive via
      `GOVERNANCE_TEST_ARCHIVE`; missing input fails, not skips.
- [ ] All introduced commits pass metadata checks, not just the PR
      title.
- [ ] Mandatory checks actually succeeded for the current candidate SHA.

## Provider adapter evidence (when applicable)

- [ ] Fixtures are synthetic or irreversibly redacted, not real
      sessions.
- [ ] Provenance records generator, revision, and license
      (`PROVENANCE.md`).
- [ ] Golden/property tests cover valid, malformed, unknown-field,
      Unicode, and boundary cases.
- [ ] Read-only behavior and source-span expectations are tested.
- [ ] Incremental, resync, failure, and tombstone cases have coverage
      where supported.
- [ ] `ProviderAdapter::manifest()` matches the capability matrix.
- [ ] Maturity is evidence-based; new adapters start as `Experimental`.
- [ ] For planned external-process proposals only, manifests declare
      provider/variant, roots, capabilities, maturity, license, and
      network permission; this is not an implemented plugin API.

## Privacy and security

- [ ] Separate path/privacy and credential gates covered the exact tree
      and all introduced commits/blobs/messages, even later-deleted
      data, plus PR metadata and the proposed merge message.
- [ ] No real sessions, secrets, private paths/hostnames, or unrelated
      personal data entered code, fixtures, docs, logs, commits, or this
      PR.
- [ ] Only reviewed safe diagnostics are shared; no raw scanner output.
- [ ] No scanner allowlist widening, inline allow, or baseline
      suppression.
- [ ] Sources remain read-only; no scan-time mutation, upload,
      telemetry, or unrequested network access was added.

## License and documentation

- [ ] Code/fixtures have compatible license and provenance; third-party
      reuse was reviewed and restricted-party material was not copied.
- [ ] Genuine authors, human co-authors, already-authorized bots, and
      required copyright/license notices are preserved. Attribution does
      not grant write/merge authority; no invented AI credit or adverts.
- [ ] Behavior, capability/maturity claims, and limitations are
      documented.
- [ ] Relevant README, CONTRIBUTING, protocol, security, and provider
      matrix links are updated.

## Human acceptance and merge

<Describe the owner's explicit acceptance record for this PR/head SHA.>

- [ ] Human review covered English wording, meaningful why, atomicity,
      genuine attribution, risks, and verification; syntax/Git cannot
      prove these, and one owner email cannot replace the checks.
- [ ] The owner explicitly accepted this PR at its current SHA after
      actual mandatory check success. This also applies to owner PRs.
- [ ] No new commit or material PR metadata edit has invalidated that
      acceptance; otherwise refresh checks and obtain fresh acceptance.
- [ ] The proposed ordinary merge preserves atomic commits and authors.
      Its scoped English header and why body pass the same 50/72 rules;
      default merge text, hidden skip directives, and fixups are no
      escape.

This is a solo-maintainer exception, not two-person review. Do not
invent reviewers or a GitHub self-APPROVED review. Task approval is not
merge approval. AI cannot autonomously approve/merge or waive gates.
Local tests and candidate workflow files do not prove trusted hosted
enforcement; bootstrap needs explicit review of a frozen checker
revision and actual runs/settings evidence. Missing or unavailable
checks are not success.
