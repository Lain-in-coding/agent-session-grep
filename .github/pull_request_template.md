# Pull request

Thanks for contributing to `agent-session-grep`. Keep this change focused and privacy-safe.

> **Privacy boundary:** Never paste or commit a real transcript, secret, credential, absolute personal path, provider database content, or copied fixture. Use synthetic or irreversibly redacted data and safe diagnostics only.

## Summary

- What changed and why?
- Which issue, contract, or capability does this address?

## Validation

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Markdown/YAML or other format-specific validation was run when applicable.

## Provider adapter evidence (when applicable)

- [ ] Fixtures are synthetic or irreversibly redacted; no real transcript was used.
- [ ] Fixture provenance is documented (`PROVENANCE.md`, generator, revision, and license).
- [ ] Golden and property tests cover valid, malformed, unknown-field, Unicode, and boundary cases.
- [ ] Read-only behavior and source-span expectations are tested.
- [ ] Incremental, resync, failure, and tombstone behavior are covered where supported.
- [ ] `ProviderAdapter::manifest()` is updated and matches the capability matrix.
- [ ] Current maturity remains evidence-based; new adapters default to `Experimental`.
- [ ] Any external-process manifest declares provider/variant, roots, capabilities, maturity, license, and network permission.

## Privacy and security

- [ ] No real transcript, secret, credential, hostname, identity, or personal path is present in code, fixtures, docs, logs, or this PR.
- [ ] Sources remain read-only; no scan-time mutation, upload, telemetry, or unrequested network access was added.
- [ ] Diagnostics and examples are safe to share and do not expose source content.

## License and documentation

- [ ] New code and fixtures have a compatible license/provenance; third-party reuse was reviewed, and restricted-party material was not copied.
- [ ] User-facing behavior, capability/maturity claims, and limitations are documented.
- [ ] Relevant README, CONTRIBUTING, protocol, security, or provider-matrix links are updated.
