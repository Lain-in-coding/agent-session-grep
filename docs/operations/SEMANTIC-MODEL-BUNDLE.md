# Semantic model bundle (offline import)

The optional `semantic-candle` feature loads a **local** multilingual-e5-small
bundle. Default builds do **not** enable this feature and continue to use the
honest `bigram-hash-v1` fuzzy-lexical vectorizer.

## Bundle layout

```text
<bundle>/
  config.json
  tokenizer.json
  model.safetensors
  MODEL-MANIFEST.json
```

`MODEL-MANIFEST.json` example:

```json
{
  "model_id": "intfloat-multilingual-e5-small@614241f6-candle-f32-meanpool-l2-qpass-v1",
  "dimension": 384,
  "license": "MIT (intfloat/multilingual-e5-small model weights)",
  "files": [
    { "name": "config.json", "sha256": "<hex>", "size_bytes": 0 },
    { "name": "tokenizer.json", "sha256": "<hex>", "size_bytes": 0 },
    { "name": "model.safetensors", "sha256": "<hex>", "size_bytes": 0 }
  ]
}
```

The `model_id` is part of the storage contract. Changing pooling, prefixes,
precision, truncation, or weights **must** change the id so old vectors stay
inert under `message_vec.model_id` scoping.

## Import (never downloads)

Build a semantic-capable binary:

```text
cargo build --release --features semantic-candle -p agent-session-grep-cli --locked
```

The feature build works offline (`--offline`) against the locked dependency
graph. Import a verified local bundle:

```text
asg model import --dir <bundle>
asg model status
asg --db <path> index embeddings
asg --db <path> search "query" --mode semantic
```

Import verifies every declared SHA-256, then atomically publishes under
`{cache}/models/<sanitized-model-id>/` from `config paths`. Search/sync/index
paths never open a network socket; missing weights fall back to bigram-hash
with the existing explicit warning / `lexical_fallback` behavior.

### Building MODEL-MANIFEST.json from real weight files

The manifest must record the real per-file SHA-256 digests. A stdlib-Python
snippet generates it without extra tooling:

```python
import hashlib, json, pathlib

dir = pathlib.Path(".")  # directory holding the three weight files
files = {}
for name in ("config.json", "tokenizer.json", "model.safetensors"):
    data = pathlib.Path(dir, name).read_bytes()
    files[name] = {
        "name": name,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": len(data),
    }
manifest = {
    "model_id": "intfloat-multilingual-e5-small@614241f6-candle-f32-meanpool-l2-qpass-v1",
    "dimension": 384,
    "license": "MIT (intfloat/multilingual-e5-small model weights)",
    "files": [files[name] for name in ("config.json", "tokenizer.json", "model.safetensors")],
}
pathlib.Path(dir, "MODEL-MANIFEST.json").write_text(json.dumps(manifest, indent=2))
```

`asg model import --dir <bundle>` re-computes the digests independently and
refuses the publish on any mismatch; it never trusts a manifest that does not
match the bytes on disk.

## Benchmark gate (`scripts/evidence/semantic_benchmark.py`)

Frozen semantic recall gate. Standard library only; never reads provider data
roots. Generates a deterministic synthetic corpus (paraphrase topics with
ground-truth markers + distractors, no real transcripts) and measures, per
retrieval mode (`lexical` / `semantic` / `hybrid`):

- recall@k against ground truth (`--k`, default 10),
- p50/p95 whole-process search latency.

```text
python scripts/evidence/semantic_benchmark.py run --profile smoke
python scripts/evidence/semantic_benchmark.py validate-report scripts/evidence/out/semantic-benchmark-smoke.json
```

The harness builds the release CLI with `--features semantic-candle` itself
(or accepts `--binary`) and gates on `asg model status`:

- **Bundle present and verified** -> runs sync, `index embeddings`, and the
  search loop; emits `semantic-benchmark-<profile>.json` (status
  `locally_verified`) under `scripts/evidence/out/` (gitignored) and exits 0.
- **Bundle absent** -> emits a `model_not_imported` manifest and exits 2. It
  refuses to fabricate semantic numbers.
- **`index embeddings` fell back to bigram-hash** (e.g. weights present but
  not loadable) -> the emitted report fails validation; bigram-hash-backed
  vectors are never certified as semantic evidence.

Corpus design: each topic has 2 anchor messages sharing the query term
(lexical finds them) and 2 paraphrase messages sharing no token with the query
(only a semantic model can find them). The smoke profile (4 topics) therefore
expects lexical recall@k 0.5 and, with a real model, semantic/hybrid recall@k
1.0. A sanity run on the bigram-hash fallback backend measured lexical 0.5 /
bigram-backed vector modes 0.75 — those numbers are corpus mechanics, not
semantic evidence.

## Verification status (2026-08-18)

**Real multilingual-e5-small inference HAS been verified in this
environment.** The pinned weights (`model.safetensors`, 470,641,600 bytes,
SHA-256 `1a55775f53449dac10a2bcbc312469fac40b96d53198c407081a831f81c98477`)
were obtained out of band (via the public HF mirror), hash-verified against the
pinned digest recorded in the model-options research, imported with
`asg model import --dir <bundle>` into the platform model cache, and exercised
end to end with a `--features semantic-candle` release binary:

- `asg model status` reports `feature: semantic-candle`, `present: true`,
  `verified: true`.
- `asg --db <path> index embeddings` builds real 384-dim E5 vectors (the
  report's `model_labeling.is_real_embedding_model` is `true` and the backend
  is the pinned Candle model id, not `bigram-hash-v1`).
- `scripts/evidence/semantic_benchmark.py run --profile gate-real` produced a
  validating report: semantic recall@k tracked at/below lexical on the frozen
  corpus with zero fallback queries; semantic p50/p95 latency per query was on
  the order of seconds for one-shot CLI processes because each invocation pays
  the ~470MB model load — long-lived entry points (MCP/TUI/serve) amortize
  this via the in-process `load_cached` model cache. The amortized latency is
  verified by `scripts/evidence/semantic_mcp_latency.py`, which keeps the
  encoder resident in an `asg mcp` process and issues 10 `search_sessions`
  calls with `mode: "semantic"`: p50 16.6 ms / p95 21.0 ms per query (real
  Candle E5 inference, not the lexical fallback), versus the ~3 s one-shot
  CLI path. `gate.promotion_claim`
  remains `none`, `lexical_stays_default` remains `true`, `maturity` stays
  `beta`, and thresholds remain pending: this run records real evidence but
  does not promote anything.
- Fail-closed behavior: with a hash-valid but unloadable bundle present,
  `index embeddings` falls back to `bigram-hash` with the explicit warning,
  and the benchmark harness refuses to certify the resulting numbers.
- Import/verify/round-trip logic is covered by 16 hermetic unit tests
  (`crates/agent-session-grep-application/src/candle_embedding.rs`), including
  SHA-256 known vectors, size/digest tampering, missing declared files,
  conflicting publishes, staging hygiene, and model-id/dimension rejection.
- The benchmark harness has a 22-case hermetic unittest suite
  (`scripts/evidence/test_semantic_benchmark.py`) with a 200-session frozen
  corpus and 100 gold-labeled queries.

Generated reports land under `scripts/evidence/out/` (gitignored); the frozen
corpus/manifest under `scripts/evidence/fixtures/semantic/` is committed and
protected by determinism tests.

## What is still deferred

- Official weight packaging / redistribution decision (license notice in
  release materials — the weights themselves remain user-imported).
- Freezing recall/latency thresholds from the real-model run into the frozen
  manifest (`state: pending` stays until the owner freezes them).
- Default-on semantic in release binaries (explicitly not planned for 0.1.0).
