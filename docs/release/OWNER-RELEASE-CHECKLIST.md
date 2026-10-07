# Owner release checklist — agent-session-grep

This checklist preserves the useful verification steps from the historical
2026-08-29 / 2026-10-06 development checklist without treating its local checks,
old repository runs, visibility, or tag inventory as canonical evidence.
The canonical repository is
[Lain-in-coding/agent-session-grep](https://github.com/Lain-in-coding/agent-session-grep).
It already has a `0.1.0` release. Do not recreate that tag or replace its assets.

No action below is authorized merely by this document. Actual merges, tags,
release publication, visibility, signing credentials, and platform settings
require separate owner authorization for the specific candidate.

## 1. Verify the current candidate

Record the canonical repository identity, branch, full tested SHA, toolchain,
commands, UTC times, exit status, and actual hosted job/artifact links.

- Run fmt, clippy, workspace tests, and the explicit `semantic-candle` suite.
- Verify both command names (`agent-session-grep` and `asg`) share the CLI
  implementation in `crates/agent-session-grep-cli/src/lib.rs` and agree on
  `--version`, `--help`, and environment-only `doctor` results.
- Run dependency policy and advisory checks. A failed advisory-database fetch
  is not an advisory pass; record it as unavailable and do not waive the gate.
- Run the public privacy profile and credential/metadata checks against the
  exact candidate. A historical zero-findings report is not current evidence;
  immutable import snapshots and history need their own explicit review.
- Repeat install, first run, in-place upgrade, uninstall, and second uninstall
  using [the installation runbook](../operations/INSTALL-AND-UPGRADE.md).
  A synthetic successor version tests replacement mechanics, not compatibility
  with another released version. Local Windows evidence is not hosted
  cross-platform or clean-machine certification.

## 2. Obtain real CI and non-publishing artifact evidence

Use [the evidence matrix](../operations/core-beta-evidence-matrix.md) to
separate `locally_verified`, `ci_configured_only`, and `ci_verified`.
No previous repository run certifies this canonical SHA.

`release-verify.yml` exercises the locked/no-default-features/target-bound
build, synthetic release smoke, packaging, manifests, and `SHA256SUMS` without
publishing. Its unsigned Actions artifacts expire after 30 days and are not
release assets. The imported verification matrix currently covers three OS
families; the publishing definition covers four architecture targets. That
coverage difference and the pending CI/release-integrity work must be resolved
before claiming full release readiness. Record skipped, failed, cancelled,
missing, and not-started checks as non-success, not proof by YAML presence.

## 3. Review governance and provider evidence

- Review each ADR's actual status individually; do not mass-convert Proposed
  documents to Accepted. ADR-0010 (provider maturity rollback) requires owner
  acceptance before any Beta promotion. The two ADR-0009 documents have
  different subjects and statuses; use their full filenames.
- Re-evaluate the [go/no-go template](go-no-go.template.md) for the current
  candidate. The dated 2026-08-16 record remains a historical draft.
- Review [REUSE](../operations/REUSE-LICENSE-AUDIT.md), real attribution,
  `NOTICE`, and the dependency inventory. The generated JSON/CSV report is not
  a complete SPDX SBOM or legal clearance; do not defer a mandatory review just
  to call the release ready.
- Resolve owner decisions in [the threat model](../security/THREAT-MODEL.md),
  including path-privacy semantics and network-filesystem policy.
- Provider promotion requires the per-row evidence in
  [the readiness ledger](../product/PROVIDER-BETA-READINESS.md), named
  cross-target results, accepted rollback policy, and an explicit owner
  decision. Derived resume previews are not executed native-resume evidence.
  Keep the capability source, matrix, ledger, and drift tests in agreement;
  code existence and this reconciliation imply no promotion.

## 4. Semantic, signing, and distribution boundaries

The default build remains lexical/bigram-hash; the optional local Candle E5
path needs a verified offline bundle and appropriately scoped measurements.
Follow [the existing model-bundle runbook](../operations/SEMANTIC-MODEL-BUNDLE.md)
and preserve its historical evidence rather than relabeling it as a fresh run.
Neither installer smoke nor a synthetic gate establishes semantic quality.

Unsigned and unnotarized builds must remain labeled as such. Signing,
notarization, package-manager channels, and credentials are separate
owner-controlled work; never request or publish credentials in this checklist.

## 5. Any future publication

Stop until the owner approves the specific new version, candidate SHA,
release notes, provenance, checks, and action. Do not run an old `v0.1.0` tag
recipe, silently overwrite assets, change visibility, or bypass unavailable
hosted prerequisites. The existing publication workflow still requires the
planned integrity review; its presence is not permission to execute it.

After a separately authorized publication, verify the actual tag, source SHA,
asset hashes, manifests, and release identity. Preserve the existing release
and attribution; corrections use a newly reviewed version rather than
rewritten history or replaced assets.
