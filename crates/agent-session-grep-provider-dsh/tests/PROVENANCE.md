# DeepSeek Harness synthetic fixture provenance

Fixture revision: 1.

All records, identifiers, task/snapshot content and compressed frames in these
Rust tests are constructed in memory. No private profile, live transcript,
upstream fixture or third-party parser is read or copied into the tests.

Structural facts come from official deepseek-ai/deepseek-harness commit
`1517a4dbca0a2789ff1d41ba439600f8547d23fa`:

- `docs/session-format-status.md` and `docs/persistence-schema.json`;
- `packages/core/session/src/types.ts` and its public persistence catalog;
- `packages/llm/llm/src/message.ts` and `types.ts`;
- `packages/session/session-persistence-jsonl/README.md`.

The local implementation uses Rust's standard zstd decoder, with explicit
record, cumulative-output, captured-input and decoder-window limits. Complete
user/assistant records are historical transcript evidence; replacements do not
pretend to replay the current model surface. Unknown required records refuse;
unknown explicitly ignorable records remain only in the original source bytes.

These tests do not establish real host loading, highest-generation discovery,
private-corpus coverage, deletion semantics or native multi-platform acceptance.
