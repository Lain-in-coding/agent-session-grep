#!/usr/bin/env python3
"""Frozen semantic/hybrid retrieval benchmark for agent-session-grep.

The benchmark has three parts:

- A deterministic, seeded synthetic corpus (~2000 messages, ~200 sessions)
  mixing CJK Chinese prose, English prose, and code snippets, with planted
  near-duplicate and paraphrase pairs so semantic recall has gold labels.
- A frozen query manifest (~100 queries in zh/en/code) whose gold message ids
  come from the generator's own plant bookkeeping.
- A runner that ingests the frozen corpus into a temp catalog, builds the
  vector index via `index embeddings`, runs lexical/semantic/hybrid queries
  with `--mode`, and reports recall@k (k=5/10/20) per mode plus p50/p95
  query latency into `scripts/evidence/out/` (gitignored).

Honesty contract: when the vector backend is the default bigram-hash
vectorizer (fuzzy lexical similarity, NOT a semantic model), semantic/hybrid
measurements are labeled `model=bigram-hash-v1` and `threshold_pending=true`
and can never license promotion. If a real Candle E5 bundle has been imported
(`asg model status` reports a verified semantic-candle bundle), the runner
records real measurements but still claims no promotion: thresholds stay
pending until they are deliberately frozen in the manifest.

The corpus is synthetic: every template and snippet is hand-authored inside
this file. No real transcript content, paths, or identities are copied.

Uses only the Python standard library. Determinism: the generator consumes
`random.Random(SEED)` draws in a fixed call order; the same seed produces
byte-identical corpus files and manifest (asserted by the unit tests, which
also verify the committed fixtures still equal the generator output).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# Reuse the frozen helpers from the core harness so every evidence report in
# this repo shares the same measurement plumbing.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from core_beta_benchmark import (  # noqa: E402
    cli,
    command_text,
    parse_frame,
    rounded_summary,
    run_process,
    sha256_file,
    tree_hash,
)


def normalized_tree_hash(paths: Iterable[Path], root: Path) -> str:
    """CRLF-normalized fixture hash.

    Git's Windows checkout may rewrite the committed corpus line endings, so
    hashing raw bytes makes the frozen manifest platform-dependent. The frozen
    contract is the logical content; both the generator and the verifier hash
    CRLF-normalized bytes so the same manifest validates on LF and CRLF
    checkouts alike.
    """
    digest = hashlib.sha256()
    for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(relative)
        digest.update(b"\0")
        digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
        digest.update(b"\0")
    return digest.hexdigest()

SCHEMA_VERSION = "agent-session-grep.semantic-benchmark-report/v1"
MANIFEST_SCHEMA_VERSION = "agent-session-grep.semantic-benchmark-manifest/v1"

# Frozen generator parameters. Changing any of these changes the corpus and
# therefore the benchmark contract; bump corpus_version in that case.
SEED = 20260815
CORPUS_VERSION = "1"
N_SESSIONS = 200
MESSAGES_PER_SESSION = 10
N_DUPLICATE_PAIRS = 40
N_PARAPHRASE_PAIRS = 40
K_VALUES = (5, 10, 20)
MODES = ("lexical", "semantic", "hybrid")
QUERY_CATEGORIES = frozenset({"zh", "en", "code"})
BIGRAM_HASH_MODEL_ID = "bigram-hash-v1"

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "semantic"
MANIFEST_PATH = FIXTURE_DIR / "manifest.json"
CORPUS_DIR = FIXTURE_DIR / "corpus" / "claude"

# ---------------------------------------------------------------------------
# Content library (hand-authored, synthetic).
# ---------------------------------------------------------------------------

# Generic sentence templates: slots {t} (topic token), {x}, {y} (topic terms).
ZH_TEMPLATES = (
    "{t} 的{x}问题，多半是{y}没有对齐导致的，先对一下日志时间线。",
    "排查{t}的{x}时，建议把{y}相关的开关全部关掉再逐个打开。",
    "我怀疑{t}这次{x}回归是{y}变更引入的，回滚到上一个 tag 试试。",
    "{t} 的{x}和{y}是两套机制，混在一起讨论容易跑偏。",
    "线上{x}告警收敛之后，{t} 的{y}指标才慢慢恢复正常。",
    "看{t}的源码，{x}入口在{y}模块里，跟进链路比较长。",
    "用{t}压测的时候，{x}吞吐上不去，瓶颈反而在{y}序列化。",
    "{t} 升级之后{x}行为变了，{y}的兼容性需要单独补测试。",
    "文档里写的是{t}的{x}走异步，实际上{y}还是同步阻塞的。",
    "把{t}的{x}采样率调低之后，{y}的延迟抖动就消失了。",
)

EN_TEMPLATES = (
    "the {x} regression in {t} points back to the {y} change from the last sprint",
    "when debugging {x} in {t}, start from the {y} logs and walk the call chain",
    "{t} treats {x} and {y} as separate mechanisms, and mixing them muddles the design",
    "under load, {t} keeps {x} latency flat while {y} becomes the real bottleneck",
    "the runbook for {x} in {t} says to drain {y} before restarting the daemon",
    "a {x} misconfiguration in {t} usually surfaces as {y} churn in the metrics",
    "profiling {t} showed that {x} spends most cycles inside {y} serialization",
    "the {x} contract in {t} changed, so {y} consumers need a compatibility shim",
    "a stale {x} entry in {t} can shadow {y} for minutes unless the ttl is low",
    "the {x} path in {t} is async on paper, but {y} still blocks the caller",
)

# Query surface forms. The store matches FTS tokens with AND semantics (CJK
# runs are bigrammed identically on the index and query sides), so EVERY token
# of every query must appear verbatim in the gold messages — a filler word the
# gold does not contain would silently zero the query.
#
# Near-duplicate queries use the topic token + the two planted terms, which
# both members share verbatim. Secondary duplicate queries add one filler that
# is fixed by the template the pair was built from: a genuinely different
# surface that is still lexically reachable through both members.
ZH_TEMPLATE_FILLERS = (
    "日志时间线",
    "开关",
    "回归",
    "两套机制",
    "告警",
    "源码",
    "序列化",
    "兼容性",
    "同步阻塞",
    "采样率",
)

EN_TEMPLATE_FILLERS = (
    "regression sprint",
    "debugging logs",
    "mechanisms design",
    "load bottleneck",
    "runbook daemon",
    "misconfiguration churn",
    "profiling cycles",
    "contract shim",
    "stale ttl",
    "async caller",
)


def duplicate_query(topic: dict[str, Any], pair_index: int, wrapper_offset: int) -> tuple[str, str]:
    """Primary/secondary query for a duplicate pair. Returns (query, category).

    Every query token appears verbatim in both members of the pair.
    """
    if pair_index < 20:
        code = topic["code"]
        query = code["query"] if wrapper_offset == 0 else code["secondary"]
        return query, "code"
    if pair_index < 30:
        lang, terms, fillers = "zh", topic["zh"], ZH_TEMPLATE_FILLERS
    else:
        lang, terms, fillers = "en", topic["en"], EN_TEMPLATE_FILLERS
    template_index = pair_index % 10
    x = terms[pair_index % len(terms)]
    y = terms[(pair_index + 3) % len(terms)]
    query = f"{topic['token']} {x} {y}"
    if wrapper_offset != 0:
        query += " " + fillers[template_index]
    return query, lang


def paraphrase_query(pair: dict[str, Any], use_b_terms: bool) -> tuple[str, str]:
    """Query for a paraphrase pair. Returns (query, category).

    Primary queries are the two planted terms of member a; secondary queries
    are member b's terms. The topic token and any filler are deliberately
    absent: the paraphrase member contains none of the query terms, so only
    semantic similarity (or a fuzzy vectorizer) can recover it.
    """
    if use_b_terms:
        return f"{pair['terms_b'][0]} {pair['terms_b'][1]}", pair["lang_b"]
    return f"{pair['terms_a'][0]} {pair['terms_a'][1]}", pair["lang_a"]

# Near-duplicate tails: member B of a duplicate pair is member A plus one of
# these, so the pair is near-identical but never byte-identical.
DUP_SUFFIX = {
    "zh": "（详见运维手册。）",
    "en": " See the runbook for details.",
}

CODE_SUFFIX = {
    "rust": "// see the runbook before touching this",
    "py": "# see the runbook before touching this",
    "sql": "-- see the runbook before touching this",
    "toml": "# see the runbook before touching this",
    "yaml": "# see the runbook before touching this",
}

# Generic code snippets for BASELINE code messages. They reuse topic tokens
# and English terms but never the identifiers of the topic's showcase snippet,
# so near-duplicate code queries (token + snippet identifier, AND semantics)
# match ONLY the two planted members — never a wall of identical baseline
# copies competing for the top-k slots.
CODE_TEMPLATES = (
    "# {t} tuning notes for {x} and {y}\n{t}_tune = dict(kind=\"{x}\", detail=\"{y}\")",
    "// {t} checklist: verify {x} before touching {y}\npub fn {t}_audit() -> bool {{\n    check(\"{x}\");\n    check(\"{y}\")\n}}",
    "-- {t} migration notes: {x}, {y}\nSELECT '{t}' AS service, '{x}' AS scope, '{y}' AS note;",
    "# {t} config for {x} and {y}\n[{t}]\nenabled = true\nscope = \"{x}\"\nnote = \"{y}\"",
    "steps:\n  - name: {t}-baseline\n    run: {t} run --scope {x} --note {y}",
    "{{\n  \"{t}\": {{\n    \"scope\": \"{x}\",\n    \"note\": \"{y}\"\n  }}\n}}",
    "def {t}_baseline():\n    return (\"{x}\", \"{y}\")",
    "CREATE TABLE IF NOT EXISTS {t}_notes (\n  id INTEGER PRIMARY KEY,\n  scope TEXT NOT NULL DEFAULT '{x}',\n  note TEXT NOT NULL DEFAULT '{y}'\n);",
)

# Topic library: 20 invented product domains. Every topic carries a unique
# nonsense token, six Chinese term phrases, six English term phrases, and one
# code snippet whose identifiers repeat the token, so code queries can target
# it. Terms are ordinary technical vocabulary — only the tokens are invented.
TOPICS = (
    {
        "token": "ferroflux",
        "zh": ["缓存一致性", "失效消息", "时间戳排序", "重放", "集群节点", "竞态条件"],
        "en": ["cache coherence", "invalidation messages", "timestamp ordering", "replay", "mesh nodes", "race condition"],
        "code": {
            "kind": "rust",
            "text": (
                "// ferroflux epoch-based invalidation\n"
                "pub struct FerrofluxCache {\n"
                "    entries: Vec<Entry>,\n"
                "    epoch: u64,\n"
                "}\n"
                "\n"
                "pub fn invalidate_stale(&mut self) -> Vec<Entry> {\n"
                "    self.entries.retain(|e| e.epoch < self.epoch);\n"
                "    self.entries.clone()\n"
                "}"
            ),
            "query": "ferroflux invalidate_stale",
            "secondary": "FerrofluxCache epoch invalidation",
        },
    },
    {
        "token": "nebulamail",
        "zh": ["邮件队列", "消费者阻塞", "积压", "投递重试", "幂等键", "慢查询"],
        "en": ["mail queue", "consumer blocking", "backlog", "delivery retries", "idempotency keys", "slow query"],
        "code": {
            "kind": "py",
            "text": (
                "# nebulamail worker loop\n"
                "def drain_queue(client, batch_size=64):\n"
                "    while True:\n"
                "        batch = client.recv_many(batch_size)\n"
                "        if not batch:\n"
                "            break\n"
                "        for msg in batch:\n"
                "            if not deliver(msg):\n"
                "                client.nack(msg.id, requeue=True)"
            ),
            "query": "nebulamail drain_queue",
            "secondary": "nebulamail recv_many nack",
        },
    },
    {
        "token": "quantleap",
        "zh": ["定时任务", "触发窗口", "错过补偿", "分片", "时区偏移", "锁竞争"],
        "en": ["cron jobs", "trigger window", "missed-run catch-up", "sharding", "timezone offset", "lock contention"],
        "code": {
            "kind": "sql",
            "text": (
                "CREATE TABLE quantleap_jobs (\n"
                "  id TEXT PRIMARY KEY,\n"
                "  cron TEXT NOT NULL,\n"
                "  next_run_ms INTEGER NOT NULL,\n"
                "  last_status TEXT DEFAULT 'idle'\n"
                ");\n"
                "CREATE INDEX idx_quantleap_next ON quantleap_jobs(next_run_ms);"
            ),
            "query": "quantleap_jobs next_run_ms",
            "secondary": "quantleap_jobs cron last_status",
        },
    },
    {
        "token": "velocipod",
        "zh": ["迁移脚本", "校验和", "锁超时", "回滚计划", "排序执行", "断点续跑"],
        "en": ["migration scripts", "checksums", "lock timeout", "rollback plan", "ordered execution", "resume from checkpoint"],
        "code": {
            "kind": "toml",
            "text": (
                "[migrations]\n"
                'directory = "db/migrations"\n'
                'table = "velocipod_schema"\n'
                "lock_timeout_ms = 5000\n"
                'checksums = "sha256"'
            ),
            "query": "velocipod migrations checksums",
            "secondary": "velocipod_schema lock_timeout_ms checksums",
        },
    },
    {
        "token": "spriggan",
        "zh": ["流水线", "缓存命中率", "失败重试", "工件上传", "并发作业", "超时熔断"],
        "en": ["pipeline", "cache hit rate", "failure retries", "artifact upload", "parallel jobs", "timeout breaker"],
        "code": {
            "kind": "yaml",
            "text": (
                "steps:\n"
                "  - name: spriggan-lint\n"
                "    run: spriggan run --pipeline lint\n"
                "  - name: spriggan-test\n"
                "    run: spriggan run --pipeline test --workers 4"
            ),
            "query": "spriggan pipeline lint",
            "secondary": "spriggan-lint spriggan-test workers",
        },
    },
    {
        "token": "lumenbox",
        "zh": ["指标聚合", "采样丢失", "时间窗口", "高基数标签", "下采样", "存储压缩"],
        "en": ["metric aggregation", "sample loss", "time windows", "high-cardinality labels", "downsampling", "storage compaction"],
        "code": {
            "kind": "rust",
            "text": (
                "// lumenbox metric aggregation\n"
                "pub fn aggregate_window(buckets: &mut Vec<Bucket>, window_ms: u64) -> f64 {\n"
                "    let cutoff = now_ms().saturating_sub(window_ms);\n"
                "    buckets.retain(|b| b.started_ms >= cutoff);\n"
                "    buckets.iter().map(|b| b.value).sum()\n"
                "}"
            ),
            "query": "lumenbox aggregate_window",
            "secondary": "lumenbox aggregate_window saturating_sub",
        },
    },
    {
        "token": "driftwood",
        "zh": ["日志采集", "断点续传", "背压", "轮转检测", "网络闪断", "重复投递"],
        "en": ["log collection", "resume after restart", "backpressure", "rotation detection", "network flaps", "duplicate delivery"],
        "code": {
            "kind": "py",
            "text": (
                "# driftwood shipper tail\n"
                "def tail_and_ship(path, cursor):\n"
                '    with open(path, "rb") as handle:\n'
                "        handle.seek(cursor)\n"
                "        chunk = handle.read()\n"
                "    if chunk:\n"
                "        ship(rotated=True, payload=chunk)\n"
                "    return cursor + len(chunk)"
            ),
            "query": "driftwood tail_and_ship",
            "secondary": "driftwood tail_and_ship rotated",
        },
    },
    {
        "token": "kestrelwing",
        "zh": ["限流窗口", "令牌桶", "突发容忍", "滑动窗口", "拒绝策略", "抖动"],
        "en": ["rate limit window", "token bucket", "burst tolerance", "sliding window", "rejection policy", "jitter"],
        "code": {
            "kind": "rust",
            "text": (
                "// kestrelwing token bucket\n"
                "pub fn allow_burst(state: &mut BucketState, now_ms: u64, cost: u32) -> bool {\n"
                "    state.refill(now_ms);\n"
                "    if state.tokens >= cost {\n"
                "        state.tokens -= cost;\n"
                "        true\n"
                "    } else {\n"
                "        false\n"
                "    }\n"
                "}"
            ),
            "query": "kestrelwing allow_burst",
            "secondary": "kestrelwing BucketState refill",
        },
    },
    {
        "token": "mossgate",
        "zh": ["灰度发布", "规则求值", "回退开关", "采样分流", "版本兼容", "审计日志"],
        "en": ["gradual rollout", "rule evaluation", "kill switch", "sampling split", "version compatibility", "audit trail"],
        "code": {
            "kind": "json",
            "text": (
                "{\n"
                '  "rollout": {\n'
                '    "flag": "mossgate_new_ui",\n'
                '    "percentage": 5,\n'
                '    "kill_switch": false,\n'
                '    "rules": [{"attr": "region", "op": "eq", "value": "staging"}]\n'
                "  }\n"
                "}"
            ),
            "query": "mossgate rollout kill_switch",
            "secondary": "mossgate_new_ui rollout percentage",
        },
    },
    {
        "token": "embertide",
        "zh": ["重试队列", "退避策略", "死信", "最大尝试次数", "消息过期", "手动重投"],
        "en": ["retry queue", "backoff policy", "dead letter", "max attempts", "message expiry", "manual redrive"],
        "code": {
            "kind": "sql",
            "text": (
                "CREATE TABLE embertide_jobs (\n"
                "  id TEXT PRIMARY KEY,\n"
                "  attempts INTEGER NOT NULL DEFAULT 0,\n"
                "  backoff_ms INTEGER NOT NULL,\n"
                "  dead_lettered INTEGER NOT NULL DEFAULT 0\n"
                ");"
            ),
            "query": "embertide_jobs attempts",
            "secondary": "embertide_jobs backoff_ms dead_lettered",
        },
    },
    {
        "token": "oakshield",
        "zh": ["密钥轮换", "版本共存", "吊销", "访问审计", "派生密钥", "轮换窗口"],
        "en": ["secret rotation", "dual versions", "revocation", "access audit", "derived keys", "rotation window"],
        "code": {
            "kind": "py",
            "text": (
                "# oakshield rotation\n"
                "def rotate_secret(vault, name):\n"
                '    old = vault.read(name, version="current")\n'
                "    new = derive_next(old)\n"
                '    vault.write(name, new, version="next")\n'
                '    vault.activate(name, "next")\n'
                "    return new"
            ),
            "query": "oakshield rotate_secret",
            "secondary": "oakshield rotate_secret activate",
        },
    },
    {
        "token": "riverstone",
        "zh": ["配置热更新", "监听文件", "校验失败", "原子切换", "灰度生效", "版本号"],
        "en": ["hot reload", "file watch", "validation failure", "atomic swap", "staged rollout", "revision number"],
        "code": {
            "kind": "rust",
            "text": (
                "// riverstone hot reload\n"
                "pub fn reload_config(path: &Path) -> Result<Config, ReloadError> {\n"
                "    let raw = fs::read_to_string(path)?;\n"
                "    let parsed: Config = toml::from_str(&raw)?;\n"
                "    validate(&parsed)?;\n"
                "    Ok(parsed)\n"
                "}"
            ),
            "query": "riverstone reload_config",
            "secondary": "riverstone reload_config ReloadError",
        },
    },
    {
        "token": "hollowspire",
        "zh": ["代理缓存", "缓存键", "条件请求", "失效批量", "命中率", "压缩存储"],
        "en": ["proxy cache", "cache keys", "conditional requests", "batch invalidation", "hit ratio", "compressed storage"],
        "code": {
            "kind": "py",
            "text": (
                "# hollowspire proxy cache keys\n"
                "def cache_key(method, path, accept_encoding):\n"
                '    base = f"{method} {path}"\n'
                "    if accept_encoding:\n"
                '        base += f"|{accept_encoding}"\n'
                "    return sha256(base.encode()).hexdigest()"
            ),
            "query": "hollowspire cache_key",
            "secondary": "hollowspire cache_key hexdigest",
        },
    },
    {
        "token": "frostfern",
        "zh": ["快照备份", "增量差异", "保留策略", "一致性检查", "恢复演练", "上传分块"],
        "en": ["snapshot backup", "incremental diff", "retention policy", "integrity check", "restore drill", "chunked upload"],
        "code": {
            "kind": "toml",
            "text": (
                "# frostfern snapshot policy\n"
                "[snapshots]\n"
                "interval_hours = 6\n"
                "retention = { daily = 14, weekly = 8 }\n"
                'integrity_check = "on_restore"\n'
                "upload_chunk_mb = 8"
            ),
            "query": "frostfern snapshots retention",
            "secondary": "frostfern snapshots integrity_check",
        },
    },
    {
        "token": "cloudberry",
        "zh": ["幂等键", "过期清理", "冲突检测", "结果缓存", "并发写入", "锁租约"],
        "en": ["idempotency keys", "expiry sweep", "conflict detection", "result cache", "concurrent writes", "lease lock"],
        "code": {
            "kind": "json",
            "text": (
                "{\n"
                '  "idempotency": {\n'
                '    "key_prefix": "cloudberry_idem",\n'
                '    "ttl_seconds": 86400,\n'
                '    "conflict_policy": "reject",\n'
                '    "store": "inmemory"\n'
                "  }\n"
                "}"
            ),
            "query": "cloudberry idempotency ttl_seconds",
            "secondary": "cloudberry_idem ttl_seconds conflict_policy",
        },
    },
    {
        "token": "thornhive",
        "zh": ["发布订阅", "主题路由", "订阅匹配", "背压", "持久化顺序", "心跳超时"],
        "en": ["publish subscribe", "topic routing", "subscription matching", "backpressure", "durable ordering", "heartbeat timeout"],
        "code": {
            "kind": "yaml",
            "text": (
                "topics:\n"
                "  - name: thornhive.events\n"
                "    routing: round-robin\n"
                "    ack_timeout_ms: 30000\n"
                "    max_inflight: 256"
            ),
            "query": "thornhive topics routing",
            "secondary": "thornhive.events ack_timeout_ms max_inflight",
        },
    },
    {
        "token": "pebblepath",
        "zh": ["链路追踪", "跨度采样", "上下文传播", "日志关联", "尾延迟", "染色标记"],
        "en": ["distributed tracing", "span sampling", "context propagation", "log correlation", "tail latency", "taint tag"],
        "code": {
            "kind": "rust",
            "text": (
                "// pebblepath tracing middleware\n"
                "pub fn trace_span(name: &str, parent: Option<SpanId>) -> Span {\n"
                "    let span = Span::child_of(parent, name);\n"
                '    span.tag("sampled", true);\n'
                "    span\n"
                "}"
            ),
            "query": "pebblepath trace_span",
            "secondary": "pebblepath trace_span SpanId",
        },
    },
    {
        "token": "sunforged",
        "zh": ["模式校验", "错误定位", "引用解析", "缓存编译", "严格模式", "自定义格式"],
        "en": ["schema validation", "error locations", "reference resolution", "compiled cache", "strict mode", "custom formats"],
        "code": {
            "kind": "py",
            "text": (
                "# sunforged validator\n"
                "def validate_schema(document, schema):\n"
                "    compiled = compile_schema(schema)\n"
                "    errors = compiled.iter_errors(document)\n"
                '    return [{"path": list(e.path), "message": e.message} for e in errors]'
            ),
            "query": "sunforged validate_schema",
            "secondary": "sunforged validate_schema iter_errors",
        },
    },
    {
        "token": "wispthread",
        "zh": ["优雅停机", "连接排空", "信号处理", "超时强制", "状态落盘", "健康检查摘除"],
        "en": ["graceful shutdown", "connection drain", "signal handling", "forced timeout", "state flush", "health-check deregistration"],
        "code": {
            "kind": "rust",
            "text": (
                "// wispthread graceful shutdown\n"
                "pub fn drain_connections(listener: &TcpListener, budget_ms: u64) -> usize {\n"
                "    let mut drained = 0;\n"
                "    while let Ok((stream, _)) = listener.accept() {\n"
                "        stream.set_read_timeout(Some(std::time::Duration::from_millis(budget_ms))).ok();\n"
                "        drained += 1;\n"
                "    }\n"
                "    drained\n"
                "}"
            ),
            "query": "wispthread drain_connections",
            "secondary": "wispthread drain_connections TcpListener",
        },
    },
    {
        "token": "gildedown",
        "zh": ["排版规则", "链接检查", "断行策略", "忽略规则", "自动修复", "配置继承"],
        "en": ["lint rules", "link checks", "line breaking", "ignore patterns", "auto fix", "config inheritance"],
        "code": {
            "kind": "yaml",
            "text": (
                "# gildedown lint config\n"
                "rules:\n"
                "  line_break: soft\n"
                "  link_check: true\n"
                "  ignore:\n"
                '    - "docs/legacy/**"\n'
                "autofix: true"
            ),
            "query": "gildedown rules line_break",
            "secondary": "gildedown rules line_break link_check",
        },
    },
)

# Hand-authored paraphrase pairs: member `a` and member `b` express the same
# fact in different wording. `terms_a` appear verbatim in `a` (and never in
# `b`), `terms_b` appear verbatim in `b`. Queries built from `terms_a` are
# lexically reachable only through member `a`; recovering `b` requires
# semantic similarity. Cross-language pairs make the gap measurable: a zh
# query shares no token at all with the English paraphrase.
PARAPHRASE_PAIRS = (
    {
        "a": "ferroflux 的失效消息乱序时，先把时间戳排序打开再重放，竞态条件会少很多。",
        "b": "stale invalidation notices reach the replicas out of order; enabling monotonic ordering before replay removes most of the races.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["失效消息", "时间戳排序"],
        "terms_b": ["invalidation notices", "monotonic ordering"],
    },
    {
        "a": "nebulamail 队列积压是因为消费者阻塞在慢查询上，投递重试反而加重了负担。",
        "b": "the worker pool stalls on a slow database call, so the pending mail pile grows and every redelivery attempt makes it worse.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["队列积压", "投递重试"],
        "terms_b": ["worker pool", "redelivery attempt"],
    },
    {
        "a": "quantleap 错过触发窗口的任务靠补偿逻辑补齐，时区偏移会导致补偿重复。",
        "b": "jobs that skip their scheduled slot are backfilled afterwards, and a wrong offset makes the backfill fire the same job twice.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["触发窗口", "时区偏移"],
        "terms_b": ["scheduled slot", "backfill"],
    },
    {
        "a": "velocipod 迁移脚本按校验和判断是否执行过，锁超时会导致部分表被跳过。",
        "b": "migrations are tracked by digest, and when the advisory lock times out a few tables silently never get applied.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["迁移脚本", "锁超时"],
        "terms_b": ["digest", "advisory lock"],
    },
    {
        "a": "spriggan 的流水线失败重试没有上限，缓存命中率掉到零时并发作业会互相踩踏。",
        "b": "the pipeline retries forever, and once the cache warms down to zero the parallel jobs start colliding with each other.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["失败重试", "并发作业"],
        "terms_b": ["retries forever", "parallel jobs"],
    },
    {
        "a": "lumenbox 的指标聚合在高基数标签下会采样丢失，下采样之后波形完全失真。",
        "b": "with very distinct label sets the aggregator drops observations, and after decimation the plotted series no longer looks like the real one.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["指标聚合", "采样丢失"],
        "terms_b": ["aggregator", "decimation"],
    },
    {
        "a": "driftwood 日志采集遇到网络闪断会重复投递，靠断点续传去重。",
        "b": "when the link flaps the shipper sends the same lines again, and the receiver de-duplicates by the persisted offset.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["日志采集", "重复投递"],
        "terms_b": ["shipper", "persisted offset"],
    },
    {
        "a": "kestrelwing 的滑动窗口把突发容忍调得太高，拒绝策略基本失效。",
        "b": "with the moving window allowing huge bursts, the drop policy almost never kicks in.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["滑动窗口", "拒绝策略"],
        "terms_b": ["moving window", "drop policy"],
    },
    {
        "a": "mossgate 灰度发布期间规则求值变慢，回退开关也打不开。",
        "b": "during the staged rollout flag evaluation gets slow and the emergency shutoff refuses to engage.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["灰度发布", "回退开关"],
        "terms_b": ["staged rollout", "emergency shutoff"],
    },
    {
        "a": "embertide 重试队列里死信堆积，退避策略把最大尝试次数耗尽了。",
        "b": "undeliverable entries pile up in the retry store because the backoff schedule burns through every allowed attempt.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["重试队列", "最大尝试次数"],
        "terms_b": ["retry store", "allowed attempt"],
    },
    {
        "a": "oakshield 密钥轮换失败时版本共存会出问题，吊销列表没同步。",
        "b": "when rotation does not finish, the old and new credentials coexist while the revocation list lags behind.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["密钥轮换", "吊销"],
        "terms_b": ["rotation", "revocation list"],
    },
    {
        "a": "riverstone 配置热更新校验失败时，原子切换保证旧配置仍然生效。",
        "b": "if the new file fails validation, the live swap is skipped and the previous settings keep serving traffic.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["配置热更新", "原子切换"],
        "terms_b": ["validation", "live swap"],
    },
    {
        "a": "hollowspire 的代理缓存命中率下降，条件请求和缓存键不一致。",
        "b": "the proxy hit ratio dropped because the conditional request headers no longer line up with the computed key.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["代理缓存", "缓存键"],
        "terms_b": ["hit ratio", "computed key"],
    },
    {
        "a": "frostfern 快照备份的增量差异计算错误，保留策略把最近备份删掉了。",
        "b": "the incremental diff came out wrong, and the cleanup rules removed the newest snapshot instead of the oldest.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["快照备份", "保留策略"],
        "terms_b": ["incremental diff", "cleanup rules"],
    },
    {
        "a": "cloudberry 幂等键过期清理太激进，冲突检测把正常请求也拦了。",
        "b": "the idempotency sweep evicts keys too early, so the duplicate guard starts rejecting healthy calls.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["幂等键", "冲突检测"],
        "terms_b": ["idempotency sweep", "duplicate guard"],
    },
    {
        "a": "thornhive 发布订阅的订阅匹配漏了通配符，主题路由把消息投错分区。",
        "b": "the subscription matcher ignores the wildcard pattern, so the broker routes events into the wrong partition.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["发布订阅", "主题路由"],
        "terms_b": ["subscription matcher", "broker routes"],
    },
    {
        "a": "pebblepath 链路追踪的跨度采样在入口丢失，日志关联就断了。",
        "b": "the span decision never propagates from the edge, so the correlation ids inside the logs stop lining up.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["链路追踪", "日志关联"],
        "terms_b": ["span decision", "correlation ids"],
    },
    {
        "a": "sunforged 模式校验的错误定位不准，引用解析把循环引用放行了。",
        "b": "validation points at the wrong node, and the resolver lets circular refs through without complaining.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["模式校验", "引用解析"],
        "terms_b": ["validation", "resolver"],
    },
    {
        "a": "wispthread 优雅停机时连接排空超时，信号处理把状态落盘跳过了。",
        "b": "during shutdown the drain deadline expires early, and the handler skips persisting the in-memory state.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["优雅停机", "连接排空"],
        "terms_b": ["shutdown", "drain deadline"],
    },
    {
        "a": "gildedown 的排版规则和断行策略冲突，自动修复把表格改坏了。",
        "b": "the style rules disagree with the wrapping policy, and the auto-fixer mangles the markdown tables.",
        "lang_a": "zh", "lang_b": "en",
        "terms_a": ["排版规则", "自动修复"],
        "terms_b": ["style rules", "auto-fixer"],
    },
    {
        "a": "ferroflux 缓存一致性主要靠失效消息广播，节点间时间戳排序不一致就会重放错乱。",
        "b": "集群里每个副本的过期通告靠广播同步，一旦各机器记录的先后次序对不上，回放就会把旧值盖回来。",
        "lang_a": "zh", "lang_b": "zh",
        "terms_a": ["缓存一致性", "失效消息"],
        "terms_b": ["过期通告", "先后次序"],
    },
    {
        "a": "nebulamail 的幂等键没有覆盖重试路径，投递重试会重复发信。",
        "b": "重发路径上没有去重标记，网络超时后用户会收到两封一样的邮件。",
        "lang_a": "zh", "lang_b": "zh",
        "terms_a": ["幂等键", "投递重试"],
        "terms_b": ["去重标记", "网络超时"],
    },
    {
        "a": "quantleap 的锁竞争导致错过补偿延迟，定时任务全部挤在同一秒。",
        "b": "抢锁太频繁会让补跑逻辑排队，所有计划任务最后都堆在同一个时刻启动。",
        "lang_a": "zh", "lang_b": "zh",
        "terms_a": ["锁竞争", "错过补偿"],
        "terms_b": ["抢锁", "补跑逻辑"],
    },
    {
        "a": "velocipod 的排序执行依赖校验和，断点续跑从错误的迁移开始。",
        "b": "脚本按摘要值排队，恢复运行的时候起点选错了，中间几步被重复应用。",
        "lang_a": "zh", "lang_b": "zh",
        "terms_a": ["排序执行", "断点续跑"],
        "terms_b": ["摘要值", "恢复运行"],
    },
    {
        "a": "spriggan 的工件上传失败后失败重试会重新跑整条流水线。",
        "b": "产物推送一旦报错，重试机制会把整个构建流程从头再来一遍。",
        "lang_a": "zh", "lang_b": "zh",
        "terms_a": ["工件上传", "失败重试"],
        "terms_b": ["产物推送", "重试机制"],
    },
    {
        "a": "lumenbox 的存储压缩在高基数标签上开销很大，时间窗口也越推越慢。",
        "b": "维度组合太多的时候，压缩模块的耗时直线上升，滚动区间随之变卡。",
        "lang_a": "zh", "lang_b": "zh",
        "terms_a": ["存储压缩", "时间窗口"],
        "terms_b": ["压缩模块", "滚动区间"],
    },
    {
        "a": "driftwood 的轮转检测漏了软链场景，背压把采集端拖垮了。",
        "b": "日志文件用符号链接切换时识别不到，上游推得太快直接把收集进程压垮。",
        "lang_a": "zh", "lang_b": "zh",
        "terms_a": ["轮转检测", "背压"],
        "terms_b": ["符号链接", "收集进程"],
    },
    {
        "a": "kestrelwing 的令牌桶在抖动场景下突发容忍算错，限流窗口形同虚设。",
        "b": "延迟忽高忽低的时候，令牌补充量算多了，整个限速区间基本拦不住流量。",
        "lang_a": "zh", "lang_b": "zh",
        "terms_a": ["令牌桶", "限流窗口"],
        "terms_b": ["令牌补充量", "限速区间"],
    },
    {
        "a": "mossgate 的审计日志没有记录采样分流，灰度发布无法回查。",
        "b": "分流决策没写进留痕记录，上线过程出了问题也没法追溯当时的分组。",
        "lang_a": "zh", "lang_b": "zh",
        "terms_a": ["审计日志", "灰度发布"],
        "terms_b": ["留痕记录", "分组"],
    },
    {
        "a": "embertide 的消息过期策略把死信也清了，手动重投拿不到原文。",
        "b": "过期清理把投递失败的消息一并删掉，运维想重新投递时内容已经没了。",
        "lang_a": "zh", "lang_b": "zh",
        "terms_a": ["消息过期", "手动重投"],
        "terms_b": ["过期清理", "重新投递"],
    },
    {
        "a": "oakshield rotation ran with dual versions active, and the access audit missed the revoke step.",
        "b": "both credential versions stayed live during the rollover, and the audit trail never recorded the deactivation.",
        "lang_a": "en", "lang_b": "en",
        "terms_a": ["access audit", "revoke"],
        "terms_b": ["audit trail", "deactivation"],
    },
    {
        "a": "riverstone hot reload watched the wrong file, so the atomic swap kept shipping stale config.",
        "b": "the watcher pointed at an old path, and every live replacement still carried the outdated settings.",
        "lang_a": "en", "lang_b": "en",
        "terms_a": ["hot reload", "atomic swap"],
        "terms_b": ["watcher", "live replacement"],
    },
    {
        "a": "hollowspire batch invalidation missed the conditional requests, so the cache hit ratio kept sliding.",
        "b": "the purge only covered a subset of entries, and clients kept revalidating the same stale objects.",
        "lang_a": "en", "lang_b": "en",
        "terms_a": ["batch invalidation", "cache hit ratio"],
        "terms_b": ["purge", "revalidating"],
    },
    {
        "a": "frostfern restore drills found the incremental diff corrupt, and the integrity check passed anyway.",
        "b": "the recovery rehearsal hit a bad delta, yet the verification step reported the archive as healthy.",
        "lang_a": "en", "lang_b": "en",
        "terms_a": ["restore drills", "integrity check"],
        "terms_b": ["recovery rehearsal", "verification step"],
    },
    {
        "a": "cloudberry concurrent writes raced the expiry sweep, and the conflict detection let one overwrite the other.",
        "b": "two writers hit the same key while the cleanup ran, and the guard failed to stop the second one.",
        "lang_a": "en", "lang_b": "en",
        "terms_a": ["concurrent writes", "conflict detection"],
        "terms_b": ["cleanup", "guard"],
    },
    {
        "a": "thornhive subscription matching ignored the heartbeat timeout, so durable ordering dropped the slow client.",
        "b": "the pattern matcher skipped the liveness check, and the ordered stream evicted the lagging consumer.",
        "lang_a": "en", "lang_b": "en",
        "terms_a": ["subscription matching", "durable ordering"],
        "terms_b": ["pattern matcher", "ordered stream"],
    },
    {
        "a": "pebblepath tail latency grew when span sampling dropped the context propagation field.",
        "b": "the slowest requests got slower once the sampling logic stopped forwarding the trace header.",
        "lang_a": "en", "lang_b": "en",
        "terms_a": ["tail latency", "context propagation"],
        "terms_b": ["sampling logic", "trace header"],
    },
    {
        "a": "sunforged strict mode turned off, and the reference resolution began swallowing custom formats.",
        "b": "with the loose settings enabled, the resolver started ignoring the bespoke schemas.",
        "lang_a": "en", "lang_b": "en",
        "terms_a": ["strict mode", "reference resolution"],
        "terms_b": ["loose settings", "resolver"],
    },
    {
        "a": "wispthread signal handling missed the health-check deregistration, so the graceful shutdown hung.",
        "b": "the handler skipped unregistering from the load balancer, and the drain waited forever.",
        "lang_a": "en", "lang_b": "en",
        "terms_a": ["signal handling", "graceful shutdown"],
        "terms_b": ["handler", "drain"],
    },
    {
        "a": "gildedown line breaking fought the config inheritance, and the lint rules flagged every table.",
        "b": "the wrapping options conflicted with the parent preset, so the checker complained about all grids.",
        "lang_a": "en", "lang_b": "en",
        "terms_a": ["line breaking", "lint rules"],
        "terms_b": ["wrapping options", "checker"],
    },
)

# ---------------------------------------------------------------------------
# Deterministic generator.
# ---------------------------------------------------------------------------

def message_uuid(message_index: int) -> str:
    """Wire-id source uuid for global message index 1..2000."""
    return f"00000000-0000-4000-8000-{message_index:012d}"


def wire_message_id(message_index: int) -> str:
    return f"msg_v1_{message_uuid(message_index)}"


def timestamp_for(session: int, position: int) -> str:
    """Deterministic timestamp: 2026-03-01T09:00:00.000Z + 3s per message."""
    total = (session * MESSAGES_PER_SESSION + position) * 3
    second = total % 60
    minute = (total // 60) % 60
    hour = (total // 3600) % 24 + 9
    day = total // 86400 + 1
    return f"2026-03-{day:02d}T{hour:02d}:{minute:02d}:{second:02d}.000Z"


def allocate_plant_slots(rng: random.Random) -> list[tuple[tuple[int, int], tuple[int, int]]]:
    """Pick 2 slots in 2 distinct sessions for each plant, deterministically."""
    order = [
        (session, position)
        for session in range(N_SESSIONS)
        for position in range(MESSAGES_PER_SESSION)
    ]
    rng.shuffle(order)
    used: set[tuple[int, int]] = set()
    pairs: list[tuple[tuple[int, int], tuple[int, int]]] = []
    for _ in range(N_DUPLICATE_PAIRS + N_PARAPHRASE_PAIRS):
        first: tuple[int, int] | None = None
        second: tuple[int, int] | None = None
        for slot in order:
            if slot in used:
                continue
            if first is None:
                first = slot
                used.add(slot)
                continue
            if slot[0] != first[0]:
                second = slot
                used.add(slot)
                break
        if first is None or second is None:
            raise RuntimeError("slot pool too small for the plant allocation")
        pairs.append((first, second))
    return pairs


def duplicate_plant_texts(topic: dict[str, Any], pair_index: int) -> tuple[str, str, str]:
    """Build the two near-identical member texts for a duplicate pair.

    Returns (text_a, text_b, language). Member b is member a plus a fixed
    suffix, so the pair is near-duplicate but never byte-identical.
    """
    if pair_index < 20:
        snippet = topic["code"]["text"].rstrip("\n")
        if topic["code"]["kind"] == "json":
            body = snippet[: snippet.rfind("}")]
            text_b = body.rstrip() + ',\n  "note": "pinned by the runbook"\n}'
        else:
            text_b = snippet + "\n" + CODE_SUFFIX[topic["code"]["kind"]]
        return snippet, text_b, "code"
    if pair_index < 30:
        lang = "zh"
        terms = topic["zh"]
        templates = ZH_TEMPLATES
        suffix = DUP_SUFFIX["zh"]
    else:
        lang = "en"
        terms = topic["en"]
        templates = EN_TEMPLATES
        suffix = DUP_SUFFIX["en"]
    x = terms[pair_index % len(terms)]
    y = terms[(pair_index + 3) % len(terms)]
    text_a = templates[pair_index % len(templates)].format(t=topic["token"], x=x, y=y)
    return text_a, text_a + suffix, lang


def generate_corpus(output_dir: Path) -> dict[str, Any]:
    """Materialize the deterministic corpus and frozen manifest under output_dir.

    Returns the manifest dict. Same seed + same generator = byte-identical
    output (asserted by the unit tests). The manifest carries no timestamps.
    """
    rng = random.Random(SEED)
    slots = allocate_plant_slots(rng)

    plants: list[dict[str, Any]] = []
    plants_by_slot: dict[tuple[int, int], tuple[int, str, str, str]] = {}
    slot_pairs = slots[:N_DUPLICATE_PAIRS]
    for index, (slot_a, slot_b) in enumerate(slot_pairs):
        topic = TOPICS[index % len(TOPICS)]
        text_a, text_b, lang = duplicate_plant_texts(topic, index)
        plant_id = f"dup-{index + 1:03d}"
        plants.append(
            {
                "plant_id": plant_id,
                "kind": "near_duplicate",
                "topic": topic["token"],
                "languages": [lang, lang],
                "slots": [list(slot_a), list(slot_b)],
                "message_ids": [
                    wire_message_id(slot_a[0] * MESSAGES_PER_SESSION + slot_a[1] + 1),
                    wire_message_id(slot_b[0] * MESSAGES_PER_SESSION + slot_b[1] + 1),
                ],
            }
        )
        plants_by_slot[slot_a] = (index, plant_id, text_a, lang)
        plants_by_slot[slot_b] = (index, plant_id, text_b, lang)
    for index, (slot_a, slot_b) in enumerate(slots[N_DUPLICATE_PAIRS:]):
        pair = PARAPHRASE_PAIRS[index % len(PARAPHRASE_PAIRS)]
        plant_id = f"par-{index + 1:03d}"
        plants.append(
            {
                "plant_id": plant_id,
                "kind": "paraphrase",
                "topic": None,
                "languages": [pair["lang_a"], pair["lang_b"]],
                "slots": [list(slot_a), list(slot_b)],
                "message_ids": [
                    wire_message_id(slot_a[0] * MESSAGES_PER_SESSION + slot_a[1] + 1),
                    wire_message_id(slot_b[0] * MESSAGES_PER_SESSION + slot_b[1] + 1),
                ],
            }
        )
        plants_by_slot[slot_a] = (index, plant_id, pair["a"], pair["lang_a"])
        plants_by_slot[slot_b] = (index, plant_id, pair["b"], pair["lang_b"])

    language_counts = {"zh": 0, "en": 0, "code": 0}

    def note_language(lang: str) -> None:
        language_counts[lang] += 1

    def baseline_text(session: int, position: int) -> tuple[str, str]:
        """One baseline message; rng draws happen in message order."""
        topic = TOPICS[session % len(TOPICS)]
        draw = rng.randrange(100)
        if draw < 45:
            lang = "zh"
            terms = topic["zh"]
            templates = ZH_TEMPLATES
        elif draw < 80:
            lang = "en"
            terms = topic["en"]
            templates = EN_TEMPLATES
        else:
            terms = topic["en"]
            x = terms[rng.randrange(len(terms))]
            y = terms[rng.randrange(len(terms))]
            template = CODE_TEMPLATES[rng.randrange(len(CODE_TEMPLATES))]
            return template.format(t=topic["token"], x=x, y=y), "code"
        x = terms[rng.randrange(len(terms))]
        y = terms[rng.randrange(len(terms))]
        text = templates[rng.randrange(len(templates))].format(t=topic["token"], x=x, y=y)
        return text, lang

    # Write corpus. One file per session (the Claude provider contract is one
    # session per file; all messages in a file share the same sessionId).
    corpus_dir = output_dir / "corpus" / "claude"
    shutil.rmtree(corpus_dir.parent, ignore_errors=True)
    corpus_dir.mkdir(parents=True)
    for session in range(N_SESSIONS):
        session_id = f"semcorp-s{session + 1:04d}"
        path = corpus_dir / f"{session_id}.jsonl"
        lines: list[str] = []
        previous_uuid: str | None = None
        for position in range(MESSAGES_PER_SESSION):
            message_index = session * MESSAGES_PER_SESSION + position + 1
            uuid = message_uuid(message_index)
            role = "user" if position % 2 == 0 else "assistant"
            slot = (session, position)
            planted = plants_by_slot.get(slot)
            if planted is not None:
                _, _, text, lang = planted
            else:
                text, lang = baseline_text(session, position)
            note_language(lang)
            record: dict[str, Any] = {
                "type": role,
                "uuid": uuid,
                "parentUuid": previous_uuid,
                "sessionId": session_id,
                "timestamp": timestamp_for(session, position),
            }
            if role == "assistant" and position == 7:
                record["isSidechain"] = True
            # Every 25th baseline message uses content blocks so the parser
            # path for block content stays exercised by the corpus.
            if planted is None and message_index % 25 == 0:
                content: Any = [{"type": "text", "text": text}]
            else:
                content = text
            record["message"] = {"role": role, "content": content}
            lines.append(json.dumps(record, ensure_ascii=False, separators=(",", ":")))
            previous_uuid = uuid
        path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

    corpus_files = sorted(corpus_dir.glob("*.jsonl"))
    if len(corpus_files) != N_SESSIONS:
        raise RuntimeError(f"expected {N_SESSIONS} corpus files, wrote {len(corpus_files)}")

    # Query manifest: primary query per plant, plus a second query for every
    # fourth plant (80 + 20 = 100 queries). Gold ids come from plant
    # bookkeeping only.
    queries: list[dict[str, Any]] = []
    for plant_index, plant in enumerate(plants):
        if plant["kind"] == "near_duplicate":
            topic_index = plant_index
            topic = TOPICS[topic_index % len(TOPICS)]
            query, category = duplicate_query(topic, topic_index, 0)
        else:
            pair = PARAPHRASE_PAIRS[plant_index % len(PARAPHRASE_PAIRS)]
            query, category = paraphrase_query(pair, use_b_terms=False)
        queries.append(
            {
                "id": f"semq-{len(queries) + 1:04d}",
                "query": query,
                "category": category,
                "gold_message_ids": plant["message_ids"],
                "gold_session_ids": [
                    f"semcorp-s{plant['slots'][0][0] + 1:04d}",
                    f"semcorp-s{plant['slots'][1][0] + 1:04d}",
                ],
                "plant_id": plant["plant_id"],
                "gold_derivation": "generator_plant_bookkeeping",
            }
        )
        if plant_index % 4 == 0:
            if plant["kind"] == "near_duplicate":
                topic_index = plant_index
                topic = TOPICS[topic_index % len(TOPICS)]
                query, category = duplicate_query(topic, topic_index, 1)
            else:
                pair = PARAPHRASE_PAIRS[plant_index % len(PARAPHRASE_PAIRS)]
                query, category = paraphrase_query(pair, use_b_terms=True)
            queries.append(
                {
                    "id": f"semq-{len(queries) + 1:04d}",
                    "query": query,
                    "category": category,
                    "gold_message_ids": plant["message_ids"],
                    "gold_session_ids": [
                        f"semcorp-s{plant['slots'][0][0] + 1:04d}",
                        f"semcorp-s{plant['slots'][1][0] + 1:04d}",
                    ],
                    "plant_id": plant["plant_id"],
                    "gold_derivation": "generator_plant_bookkeeping",
                }
            )

    manifest: dict[str, Any] = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "corpus_version": CORPUS_VERSION,
        "seed": SEED,
        "generator": "scripts/evidence/semantic_benchmark.py",
        "provenance": {
            "kind": "deterministic_synthetic",
            "contains_real_transcripts": False,
            "templates": (
                "all content is hand-authored inside scripts/evidence/semantic_benchmark.py; "
                "no provider transcript content, paths, or identities are copied"
            ),
        },
        "corpus": {
            "provider": "claude-code",
            "session_count": N_SESSIONS,
            "message_count": N_SESSIONS * MESSAGES_PER_SESSION,
            "language_mix": language_counts,
            "planted": {
                "near_duplicate_pairs": N_DUPLICATE_PAIRS,
                "paraphrase_pairs": N_PARAPHRASE_PAIRS,
            },
            "fixture_hash": normalized_tree_hash(corpus_files, corpus_dir),
            "hash_algorithm": "sha256",
        },
        "plants": plants,
        "queries": queries,
        "benchmark_contract": {
            "modes": list(MODES),
            "k_values": list(K_VALUES),
            "latency_percentiles": ["p50", "p95"],
            "thresholds": {
                "state": "pending",
                "note": (
                    "recall/latency thresholds are frozen only after a benchmark run "
                    "against a real imported embedding model; runs under the bigram-hash "
                    "vectorizer can never set thresholds"
                ),
            },
            "repeat_counts": {
                "state": "pending",
                "planned": 3,
                "note": (
                    "frozen together with the thresholds once a real-model run is "
                    "recorded; the runner reports the repeat count it actually used"
                ),
            },
        },
    }

    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return manifest

# ---------------------------------------------------------------------------
# Shared helpers.
# ---------------------------------------------------------------------------

def distinctive_tokens(text: str) -> set[str]:
    """Distinctive lexical units as the store's FTS5 unicode61 tokenizer sees
    them: ASCII runs split on underscores (underscore is not a token
    character), ASCII case-folded, plus CJK bigrams from the index-side
    transform. Short tokens (<3 chars) are dropped on both sides."""
    tokens: set[str] = set()
    for run in re.findall(r"[A-Za-z0-9_]+", text):
        tokens.update(piece.lower() for piece in run.split("_") if len(piece) >= 3)
    for word in re.findall(r"[一-鿿]{2,}", text):
        tokens.update(word[i : i + 2] for i in range(len(word) - 1))
    return tokens


def corpus_message_texts(corpus_dir: Path) -> dict[str, str]:
    """Parse the corpus back to {wire_id: plain text} for gold verification."""
    mapping: dict[str, str] = {}
    for path in sorted(corpus_dir.glob("*.jsonl")):
        for line in path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            content = record["message"]["content"]
            if isinstance(content, str):
                text = content
            else:
                text = "\n".join(
                    block.get("text", "")
                    for block in content
                    if isinstance(block, dict) and block.get("type") == "text"
                )
            mapping[f"msg_v1_{record['uuid']}"] = text
    return mapping


def recall_at_k(hit_ids: list[str], gold_ids: list[str], k: int) -> float:
    """Recall@k of ordered hit ids against the gold id set."""
    if k <= 0:
        raise ValueError("k must be positive")
    gold = set(gold_ids)
    if not gold:
        raise ValueError("gold ids must not be empty")
    return len(set(hit_ids[:k]) & gold) / len(gold)


def label_model(
    embeddings_data: dict[str, Any], model_status_data: dict[str, Any]
) -> dict[str, Any]:
    """Honest model labeling. A semantic/hybrid number must never pretend to
    come from a real embedding model when the backend is the bigram hash, and
    even a real bundle never licenses promotion by itself."""
    real_bundle = (
        model_status_data.get("feature") == "semantic-candle"
        and model_status_data.get("present") is True
        and model_status_data.get("verified") is True
    )
    if real_bundle:
        return {
            "model": embeddings_data.get("model_id"),
            "is_real_embedding_model": True,
            "threshold_pending": True,
            "promotion_claim": "none",
            "maturity": "beta",
            "note": (
                "a verified local Candle E5 bundle was imported; real measurements "
                "were recorded, but thresholds stay pending and no promotion is "
                "claimed from this run alone"
            ),
        }
    return {
        "model": BIGRAM_HASH_MODEL_ID,
        "is_real_embedding_model": False,
        "threshold_pending": True,
        "promotion_claim": "none",
        "maturity": "beta",
        "note": (
            "the vector backend is the bigram-hash vectorizer (fuzzy lexical "
            "similarity, not a semantic model); semantic/hybrid recall is "
            "informational and can never gate promotion"
        ),
    }


def load_manifest() -> dict[str, Any]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    validate_manifest_obj(manifest, MANIFEST_PATH)
    return manifest


def corpus_files() -> list[Path]:
    return sorted(CORPUS_DIR.glob("*.jsonl"))


def validate_manifest_obj(manifest: dict[str, Any], source: Path) -> dict[str, Any]:
    """Validate the frozen manifest's structural invariants."""
    if manifest.get("schema_version") != MANIFEST_SCHEMA_VERSION:
        raise ValueError(f"{source}: unsupported schema_version {manifest.get('schema_version')!r}")
    if manifest.get("corpus_version") != CORPUS_VERSION:
        raise ValueError(f"{source}: unexpected corpus_version {manifest.get('corpus_version')!r}")
    if manifest.get("seed") != SEED:
        raise ValueError(f"{source}: seed drifted from the generator constant")
    provenance = manifest.get("provenance", {})
    if provenance.get("kind") != "deterministic_synthetic":
        raise ValueError(f"{source}: provenance kind must be deterministic_synthetic")
    if provenance.get("contains_real_transcripts", True) is not False:
        raise ValueError(f"{source}: corpus provenance must be synthetic")
    corpus = manifest.get("corpus", {})
    if corpus.get("session_count") != N_SESSIONS:
        raise ValueError(f"{source}: session_count must be {N_SESSIONS}")
    if corpus.get("message_count") != N_SESSIONS * MESSAGES_PER_SESSION:
        raise ValueError(f"{source}: message_count must be {N_SESSIONS * MESSAGES_PER_SESSION}")
    mix = corpus.get("language_mix", {})
    if sum(mix.values()) != corpus["message_count"]:
        raise ValueError(f"{source}: language_mix does not sum to message_count")
    if set(mix) != {"zh", "en", "code"}:
        raise ValueError(f"{source}: language_mix keys must be zh/en/code")
    planted = corpus.get("planted", {})
    if planted.get("near_duplicate_pairs") != N_DUPLICATE_PAIRS:
        raise ValueError(f"{source}: near_duplicate_pairs count drifted")
    if planted.get("paraphrase_pairs") != N_PARAPHRASE_PAIRS:
        raise ValueError(f"{source}: paraphrase_pairs count drifted")
    fixture_hash = corpus.get("fixture_hash", "")
    if not isinstance(fixture_hash, str) or len(fixture_hash) != 64 or any(
        char not in "0123456789abcdef" for char in fixture_hash
    ):
        raise ValueError(f"{source}: fixture_hash must be a lowercase SHA-256 digest")
    plants = manifest.get("plants")
    if not isinstance(plants, list) or len(plants) != N_DUPLICATE_PAIRS + N_PARAPHRASE_PAIRS:
        raise ValueError(f"{source}: plant bookkeeping count drifted")
    used_ids: set[str] = set()
    for plant in plants:
        ids = plant.get("message_ids")
        if not isinstance(ids, list) or len(ids) != 2:
            raise ValueError(f"{source}: plant {plant.get('plant_id')} must carry 2 message ids")
        if ids[0] == ids[1]:
            raise ValueError(f"{source}: plant {plant.get('plant_id')} members must differ")
        for mid in ids:
            if mid in used_ids:
                raise ValueError(f"{source}: message id {mid} reused across plants")
            used_ids.add(mid)
        sessions = plant.get("slots") or []
        if len(sessions) != 2 or sessions[0][0] == sessions[1][0]:
            raise ValueError(f"{source}: plant {plant.get('plant_id')} members must live in distinct sessions")
    queries = manifest.get("queries")
    if not isinstance(queries, list) or not queries:
        raise ValueError(f"{source}: query manifest must be non-empty")
    plant_ids = {plant["plant_id"] for plant in plants}
    for query in queries:
        if query.get("category") not in QUERY_CATEGORIES:
            raise ValueError(f"{source}: query {query.get('id')} has unknown category")
        if query.get("plant_id") not in plant_ids:
            raise ValueError(f"{source}: query {query.get('id')} references an unknown plant")
        gold = query.get("gold_message_ids")
        if not isinstance(gold, list) or not gold or not all(isinstance(i, str) for i in gold):
            raise ValueError(f"{source}: query {query.get('id')} must carry gold message ids")
        if set(gold) & used_ids != set(gold):
            raise ValueError(f"{source}: query {query.get('id')} gold ids are not plant messages")
        if query.get("gold_derivation") != "generator_plant_bookkeeping":
            raise ValueError(f"{source}: query {query.get('id')} gold labels must come from plant bookkeeping")
    contract = manifest.get("benchmark_contract", {})
    if contract.get("thresholds", {}).get("state") != "pending":
        raise ValueError(f"{source}: thresholds must stay pending in the frozen manifest")
    if contract.get("repeat_counts", {}).get("state") != "pending":
        raise ValueError(f"{source}: repeat counts must stay pending in the frozen manifest")
    if contract.get("modes") != list(MODES) or contract.get("k_values") != list(K_VALUES):
        raise ValueError(f"{source}: benchmark contract modes/k_values drifted")
    return manifest


def validate_manifest_file(path: Path) -> dict[str, Any]:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    validated = validate_manifest_obj(manifest, path)
    print(f"valid {MANIFEST_SCHEMA_VERSION} manifest: {path}")
    return validated


# ---------------------------------------------------------------------------
# Runner.
# ---------------------------------------------------------------------------

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def resolve_binary(workspace: Path, args: argparse.Namespace) -> Path:
    if args.binary:
        binary = Path(args.binary).expanduser().resolve()
    else:
        build = subprocess.run(
            [args.cargo, "build", "--locked", "--release", "-p", "agent-session-grep-cli"],
            cwd=workspace,
            check=False,
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            hint = (
                "\ncargo build failed. If a running agent-session-grep (e.g. an MCP"
                "\nserver) holds target/release/agent-session-grep.exe locked on"
                "\nWindows, build into an isolated target dir or pass --binary with"
                "\na prebuilt release binary."
            )
            raise RuntimeError(
                f"cargo build --locked --release failed (exit {build.returncode}):"
                f"\n{build.stdout.strip()}\n{build.stderr.strip()}{hint}"
            )
        name = "agent-session-grep.exe" if platform.system().lower() == "windows" else "agent-session-grep"
        binary = workspace / "target" / "release" / name
    if not binary.is_file():
        raise FileNotFoundError(f"release CLI binary not found: {binary}")
    return binary


def environment_block() -> dict[str, Any]:
    return {
        "os": platform.system().lower(),
        "os_release": platform.release(),
        "machine": platform.machine() or "not_recorded",
        "processor": platform.processor() or "not_recorded",
        "logical_cpu_count": os.cpu_count(),
        "python_version": platform.python_version(),
    }


def directory_size(paths: list[Path]) -> int:
    return sum(path.stat().st_size for path in paths if path.is_file())


def run_queries(
    binary: Path,
    workspace: Path,
    db: Path,
    manifest: dict[str, Any],
    mode: str,
    repeat: int,
) -> tuple[dict[str, float], list[dict[str, Any]], list[dict[str, Any]]]:
    """Run every manifest query in one retrieval mode.

    Returns (mean_recall_by_k, per_query_detail, raw_samples). Recall is taken
    from the first repetition; every repetition contributes a latency sample.
    """
    per_query: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []
    per_k: dict[int, list[float]] = {k: [] for k in K_VALUES}
    for entry in manifest["queries"]:
        gold = entry["gold_message_ids"]
        recalls: dict[str, float] = {}
        hit_ids: list[str] = []
        effective_mode = "not_recorded"
        for rep in range(repeat):
            result = cli(
                binary,
                workspace,
                db,
                "search",
                entry["query"],
                "--mode",
                mode,
                "--max-items",
                str(max(K_VALUES)),
            )
            samples.append(result)
            if rep != 0:
                continue
            frame = result["frame"]
            hits = frame["data"].get("hits", [])
            hit_ids = [hit.get("id", "") for hit in hits]
            effective_mode = str(frame["data"].get("retrieval_mode", "not_recorded"))
            for k in K_VALUES:
                value = recall_at_k(hit_ids, gold, k)
                recalls[f"recall_at_{k}"] = round(value, 6)
                per_k[k].append(value)
        per_query.append(
            {
                "query_id": entry["id"],
                "query": entry["query"],
                "category": entry["category"],
                "requested_mode": mode,
                "effective_mode": effective_mode,
                "fell_back": effective_mode != mode,
                "gold_count": len(gold),
                "recalls": recalls,
                "hit_ids": hit_ids[: max(K_VALUES)],
                "warnings": len(result["frame"].get("warnings", [])),
            }
        )
    means = {f"recall_at_{k}": round(sum(per_k[k]) / len(per_k[k]), 6) for k in K_VALUES}
    detail = sorted(per_query, key=lambda item: item["query_id"])
    return means, detail, samples


def run_benchmark(args: argparse.Namespace) -> Path:
    workspace = Path(args.workspace).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest()
    files = corpus_files()
    if len(files) != N_SESSIONS:
        raise RuntimeError(f"committed corpus holds {len(files)} files, expected {N_SESSIONS}")
    fixture_hash = normalized_tree_hash(files, CORPUS_DIR)
    if fixture_hash != manifest["corpus"]["fixture_hash"]:
        raise RuntimeError(
            "committed corpus does not match the frozen manifest fixture_hash; "
            "re-run `semantic_benchmark.py generate` if the corpus was regenerated"
        )
    binary = resolve_binary(workspace, args)
    commit = command_text(["git", "rev-parse", "HEAD"], workspace) or "not_recorded"

    with tempfile.TemporaryDirectory(prefix="agent-session-grep-semantic-") as temp_name:
        scratch = Path(temp_name)
        db = scratch / "semantic.db"

        sync_result = cli(binary, workspace, db, "sync", *(str(path) for path in files))
        sync_data = sync_result["frame"]["data"]
        emitted = int(sync_data.get("emitted", 0))
        skipped = int(sync_data.get("skipped", 0))
        if emitted != manifest["corpus"]["message_count"] or skipped != 0:
            raise RuntimeError(
                f"corpus did not fully ingest: emitted={emitted} skipped={skipped} "
                f"(expected {manifest['corpus']['message_count']} emitted, 0 skipped)"
            )
        after_sync_bytes = directory_size(list(scratch.glob("semantic.db*")))

        embeddings_result = cli(binary, workspace, db, "index", "embeddings")
        embeddings_data = embeddings_result["frame"]["data"]
        after_embeddings_bytes = directory_size(list(scratch.glob("semantic.db*")))

        model_status_data = cli(binary, workspace, db, "model", "status")["frame"]["data"]
        labeling = label_model(embeddings_data, model_status_data)
        # Belt-and-braces: the embeddings frame itself reports the backend; the
        # labeling must agree with it.
        if embeddings_data.get("backend") == "bigram-hash":
            if labeling["is_real_embedding_model"] or labeling["model"] != BIGRAM_HASH_MODEL_ID:
                raise RuntimeError("embeddings backend is bigram-hash but labeling claims otherwise")

        recall_by_mode: dict[str, Any] = {}
        latency_by_mode: dict[str, Any] = {}
        per_query_detail: dict[str, list[dict[str, Any]]] = {}
        for mode in MODES:
            means, detail, samples = run_queries(
                binary, workspace, db, manifest, mode, args.repeat
            )
            recall_by_mode[mode] = means
            recall_by_mode[mode]["query_count"] = len(manifest["queries"])
            recall_by_mode[mode]["fell_back_query_count"] = sum(1 for q in detail if q["fell_back"])
            recall_by_mode[mode]["fell_back_repetitions"] = sum(
                1 for sample in samples
                if sample["frame"]["data"].get("retrieval_mode", "not_recorded") != mode
            )
            summary = rounded_summary([float(sample["duration_ms"]) for sample in samples])
            latency_by_mode[mode] = {
                "p50": summary["p50"],
                "p95": summary["p95"],
                "count": summary["count"],
            }
            per_query_detail[mode] = detail

        lexical_mean = recall_by_mode["lexical"][f"recall_at_{max(K_VALUES)}"]
        if lexical_mean < 0.5:
            raise RuntimeError(
                f"lexical recall@{max(K_VALUES)} is {lexical_mean} (< 0.5); the corpus/query "
                "pairing is broken — gold messages are not lexically reachable"
            )

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "profile": args.profile,
        "commit": commit,
        "environment": environment_block(),
        "manifest": {
            "path": str(MANIFEST_PATH.relative_to(Path(__file__).resolve().parents[2])).replace("\\", "/"),
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "corpus_version": manifest["corpus_version"],
            "seed": manifest["seed"],
            "fixture_hash": manifest["corpus"]["fixture_hash"],
            "verified_against_committed_corpus": True,
        },
        "corpus": {
            "kind": "deterministic_synthetic_labeled",
            "contains_real_transcripts": False,
            "session_count": manifest["corpus"]["session_count"],
            "message_count": manifest["corpus"]["message_count"],
            "planted": manifest["corpus"]["planted"],
            "query_count": len(manifest["queries"]),
        },
        "binary": {
            "hash_algorithm": "sha256",
            "binary_hash": sha256_file(binary),
            "provenance": (
                "caller_supplied_prebuilt"
                if args.binary
                else "built_by_harness_from_workspace"
            ),
        },
        "catalog": {
            "sync": {
                "sources": sync_data.get("sources"),
                "emitted": emitted,
                "skipped": skipped,
                "duration_ms": sync_result["duration_ms"],
            },
            "embeddings": embeddings_data,
            "embeddings_index_duration_ms": embeddings_result["duration_ms"],
            "embeddings_warnings": embeddings_result["frame"].get("warnings", []),
            "model_status": model_status_data,
        },
        "model_labeling": labeling,
        "recall": {
            "k_values": list(K_VALUES),
            "per_mode": recall_by_mode,
            "per_query": per_query_detail,
        },
        "latency_p50_p95_ms": latency_by_mode,
        "index_size": {
            "catalog_bytes_after_sync": after_sync_bytes,
            "catalog_bytes_after_embeddings": after_embeddings_bytes,
            "vector_projection_delta_bytes": after_embeddings_bytes - after_sync_bytes,
        },
        "thresholds": {
            "state": "pending",
            "note": manifest["benchmark_contract"]["thresholds"]["note"],
        },
        "repeat_counts": {
            "state": "pending",
            "used_in_this_run": args.repeat,
            "note": manifest["benchmark_contract"]["repeat_counts"]["note"],
        },
        "gate": {
            "promotion_claim": "none",
            "lexical_stays_default": True,
            "maturity": "beta",
        },
        "limitations": [
            "The corpus and query manifest are deterministic and synthetic; recall numbers are only comparable across runs that pin the same manifest.",
            "With the default build the semantic backend is the bigram-hash vectorizer (fuzzy lexical similarity, not a semantic model); semantic/hybrid recall is informational.",
            "Latency is measured per CLI invocation (process spawn included); p50/p95 use nearest-rank percentiles.",
            "Vector-index disk footprint is approximated by the catalog byte delta after `index embeddings`; a dedicated per-table size probe is not exposed by the CLI.",
            "Thresholds and frozen repeat counts stay pending until a real embedding-model run is recorded; this report alone can never promote semantic retrieval.",
        ],
    }

    report_path = output_dir / f"semantic-benchmark-{args.profile}.json"
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    validate_report(report_path)
    print(report_path)
    return report_path

def validate_report(path: Path) -> dict[str, Any]:
    """Validate a report against the frozen manifest contract and the honesty
    invariants: no promotion claim, thresholds always pending, and the
    bigram-hash backend is never mislabeled as a real model."""
    report = json.loads(path.read_text(encoding="utf-8"))
    if report.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version: {report.get('schema_version')!r}")
    commit = report.get("commit", "")
    if not isinstance(commit, str) or len(commit) != 40 or any(
        char not in "0123456789abcdef" for char in commit
    ):
        raise ValueError("commit must be a full lowercase Git SHA")
    if report.get("corpus", {}).get("contains_real_transcripts") is not False:
        raise ValueError("corpus.contains_real_transcripts must be false")
    binary = report.get("binary", {})
    binary_hash = binary.get("binary_hash", "")
    if not isinstance(binary_hash, str) or len(binary_hash) != 64 or any(
        char not in "0123456789abcdef" for char in binary_hash
    ):
        raise ValueError("binary.binary_hash must be a lowercase SHA-256 digest")
    if binary.get("provenance") not in {"built_by_harness_from_workspace", "caller_supplied_prebuilt"}:
        raise ValueError("binary.provenance is not recognized")
    manifest = load_manifest()
    pinned = report.get("manifest", {})
    if pinned.get("fixture_hash") != manifest["corpus"]["fixture_hash"]:
        raise ValueError("report pins a fixture_hash that differs from the frozen manifest")
    if pinned.get("corpus_version") != manifest["corpus_version"] or pinned.get("seed") != manifest["seed"]:
        raise ValueError("report pins a corpus_version/seed that differs from the frozen manifest")
    if pinned.get("verified_against_committed_corpus") is not True:
        raise ValueError("report must verify the committed corpus before measuring")

    labeling = report.get("model_labeling", {})
    if labeling.get("threshold_pending") is not True:
        raise ValueError("model_labeling.threshold_pending must stay true until thresholds are frozen")
    if labeling.get("promotion_claim") != "none":
        raise ValueError("model_labeling.promotion_claim must be 'none'")
    if labeling.get("maturity") != "beta":
        raise ValueError("model_labeling.maturity must stay 'beta'")
    model_status = report.get("catalog", {}).get("model_status", {})
    real_bundle = (
        model_status.get("feature") == "semantic-candle"
        and model_status.get("present") is True
        and model_status.get("verified") is True
    )
    if labeling.get("is_real_embedding_model") is not real_bundle:
        raise ValueError("model_labeling.is_real_embedding_model contradicts the recorded model status")
    embeddings = report.get("catalog", {}).get("embeddings", {})
    if embeddings.get("backend") == "bigram-hash":
        if labeling.get("model") != BIGRAM_HASH_MODEL_ID or labeling.get("is_real_embedding_model") is not False:
            raise ValueError("bigram-hash backend must be labeled model=bigram-hash-v1 and never as a real model")
    if real_bundle and labeling.get("model") != embeddings.get("model_id"):
        raise ValueError("real-bundle labeling must carry the embeddings model id")

    gate = report.get("gate", {})
    if gate.get("promotion_claim") != "none" or gate.get("lexical_stays_default") is not True:
        raise ValueError("gate must claim no promotion and keep lexical default")
    if gate.get("maturity") != "beta":
        raise ValueError("gate.maturity must stay beta until thresholds are frozen")
    if report.get("thresholds", {}).get("state") != "pending":
        raise ValueError("thresholds must remain pending in reports")
    repeat = report.get("repeat_counts", {})
    if repeat.get("state") != "pending" or not isinstance(repeat.get("used_in_this_run"), int) or repeat["used_in_this_run"] < 1:
        raise ValueError("repeat_counts must stay pending and record a positive used count")

    recall = report.get("recall", {})
    if recall.get("k_values") != list(K_VALUES):
        raise ValueError("recall.k_values drifted from the benchmark contract")
    per_mode = recall.get("per_mode", {})
    if set(per_mode) != set(MODES):
        raise ValueError("recall.per_mode must cover lexical/semantic/hybrid")
    query_count = len(manifest["queries"])
    for mode in MODES:
        entry = per_mode[mode]
        if entry.get("query_count") != query_count:
            raise ValueError(f"{mode}: query_count does not match the frozen manifest")
        for k in K_VALUES:
            value = entry.get(f"recall_at_{k}")
            if not isinstance(value, (int, float)) or not 0.0 <= value <= 1.0:
                raise ValueError(f"{mode}.recall_at_{k} must be a ratio in [0, 1]")
    latency = report.get("latency_p50_p95_ms", {})
    if set(latency) != set(MODES):
        raise ValueError("latency_p50_p95_ms must cover lexical/semantic/hybrid")
    for mode in MODES:
        entry = latency[mode]
        if entry.get("count") != query_count * repeat["used_in_this_run"]:
            raise ValueError(f"{mode}: latency sample count does not match queries x repeat")
        if not isinstance(entry.get("p50"), (int, float)) or not isinstance(entry.get("p95"), (int, float)):
            raise ValueError(f"{mode}: p50/p95 must be numeric")
    per_query = recall.get("per_query", {})
    if set(per_query) != set(MODES):
        raise ValueError("recall.per_query must cover lexical/semantic/hybrid")
    expected_query_ids = {entry["id"] for entry in manifest["queries"]}
    for mode in MODES:
        details = per_query[mode]
        if len(details) != query_count:
            raise ValueError(f"{mode}: per-query detail count does not match the manifest")
        if {detail.get("query_id") for detail in details} != expected_query_ids:
            raise ValueError(f"{mode}: per-query detail ids do not match the manifest")
        for detail in details:
            if detail.get("requested_mode") != mode:
                raise ValueError(f"{mode}: per-query detail carries a mismatched requested_mode")
            for k in K_VALUES:
                value = detail.get("recalls", {}).get(f"recall_at_{k}")
                if not isinstance(value, (int, float)) or not 0.0 <= value <= 1.0:
                    raise ValueError(f"{mode}: per-query recall_at_{k} must be a ratio in [0, 1]")
            if not isinstance(detail.get("hit_ids"), list):
                raise ValueError(f"{mode}: per-query detail must carry ordered hit ids")
    print(f"valid {SCHEMA_VERSION} report: {path}")
    return report


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[2]
    result = argparse.ArgumentParser(description=__doc__)
    sub = result.add_subparsers(dest="command", required=True)

    generate = sub.add_parser(
        "generate",
        help="deterministically materialize the frozen corpus + manifest",
    )
    generate.add_argument("--output-dir", default=str(FIXTURE_DIR))

    run = sub.add_parser(
        "run",
        help="ingest the frozen corpus, run lexical/semantic/hybrid queries, emit the report",
    )
    run.add_argument("--profile", default="semantic", help="profile name used in the report filename")
    run.add_argument("--workspace", default=str(root))
    run.add_argument("--output-dir", default=str(root / "scripts" / "evidence" / "out"))
    run.add_argument("--binary", help="explicit prebuilt release CLI; otherwise cargo build --release is run")
    run.add_argument("--cargo", default="cargo")
    run.add_argument("--repeat", type=positive_int, default=1, help="query repetitions per mode for latency sampling")

    validate_manifest = sub.add_parser("validate-manifest", help="validate a frozen manifest file")
    validate_manifest.add_argument("manifest")

    validate = sub.add_parser("validate-report", help="validate a report against the frozen contract")
    validate.add_argument("report")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "generate":
            manifest = generate_corpus(Path(args.output_dir).expanduser().resolve())
            validate_manifest_obj(manifest, Path(args.output_dir).expanduser().resolve() / "manifest.json")
            print(Path(args.output_dir).expanduser().resolve() / "manifest.json")
        elif args.command == "run":
            run_benchmark(args)
        elif args.command == "validate-manifest":
            validate_manifest_file(Path(args.manifest).expanduser().resolve())
        else:
            validate_report(Path(args.report).expanduser().resolve())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())





