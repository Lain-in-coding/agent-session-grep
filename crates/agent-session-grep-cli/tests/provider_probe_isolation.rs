//! Cross-provider probe isolation: every golden fixture must be claimed by
//! exactly one adapter at the top confidence rank.
//!
//! `select_and_stage_source` (see `agent-session-grep-application`) ranks probe
//! results and **refuses the whole source** when two different variants tie at
//! the top rank ("ambiguous provider selection"). A second adapter that answers
//! `Confirmed` on another provider's bytes therefore does not merely add noise —
//! it makes those sources unindexable. That regression has happened twice
//! (pi ↔ openclaw, qoder ↔ codex) and nothing pinned it afterwards.
//!
//! This suite feeds each provider's pinned golden fixture to **every** adapter's
//! probe and asserts the owner wins outright, with one explicitly enumerated
//! exception: pi and openclaw transcripts are the *same* v3 session JSONL, so
//! the tie is real and is resolved by the canonical discovery root rather than
//! by content (see `stage_with_source`'s `provider_hint` documentation and the
//! `provider-openclaw` module docs). Enumerating it here means a *new* tie fails
//! loudly instead of silently joining a known one.

use agent_session_grep_ports::{Confidence, ProviderAdapter};
use agent_session_grep_provider_aider::AiderAdapter;
use agent_session_grep_provider_antigravity::AntigravityAdapter;
use agent_session_grep_provider_claude::ClaudeCodeAdapter;
use agent_session_grep_provider_cline::ClineAdapter;
use agent_session_grep_provider_codebuddy::CodeBuddyAdapter;
use agent_session_grep_provider_codex::CodexAdapter;
use agent_session_grep_provider_cursor::CursorAdapter;
use agent_session_grep_provider_grok::GrokBuildAdapter;
use agent_session_grep_provider_hermes::OpenHermesAdapter;
use agent_session_grep_provider_kimi::KimiCodeAdapter;
use agent_session_grep_provider_openclaw::OpenClawAdapter;
use agent_session_grep_provider_opencode::OpenCodeAdapter;
use agent_session_grep_provider_pi::PiAdapter;
use agent_session_grep_provider_qoder::QoderAdapter;

/// `(owning provider_id, fixture label, fixture bytes)` for every pinned golden
/// fixture in the workspace, including the per-provider extra fixtures.
const GOLDEN_FIXTURES: &[(&str, &str, &[u8])] = &[
    (
        "aider",
        "basic.md",
        include_bytes!("../../agent-session-grep-provider-aider/tests/golden/basic.md"),
    ),
    (
        "antigravity",
        "basic.jsonl",
        include_bytes!("../../agent-session-grep-provider-antigravity/tests/golden/basic.jsonl"),
    ),
    (
        "claude-code",
        "basic.jsonl",
        include_bytes!("../../agent-session-grep-provider-claude/tests/golden/basic.jsonl"),
    ),
    (
        "claude-code",
        "thinking.jsonl",
        include_bytes!("../../agent-session-grep-provider-claude/tests/golden/thinking.jsonl"),
    ),
    (
        "cline",
        "basic.json",
        include_bytes!("../../agent-session-grep-provider-cline/tests/golden/basic.json"),
    ),
    (
        "codex",
        "basic.jsonl",
        include_bytes!("../../agent-session-grep-provider-codex/tests/golden/basic.jsonl"),
    ),
    (
        "cursor",
        "basic.db",
        include_bytes!("../../agent-session-grep-provider-cursor/tests/golden/basic.db"),
    ),
    (
        "cursor",
        "disk-kv.db",
        include_bytes!("../../agent-session-grep-provider-cursor/tests/golden/disk-kv.db"),
    ),
    (
        "cursor",
        "disk-kv-shuffled.db",
        include_bytes!("../../agent-session-grep-provider-cursor/tests/golden/disk-kv-shuffled.db"),
    ),
    (
        "grok-build",
        "basic.jsonl",
        include_bytes!("../../agent-session-grep-provider-grok/tests/golden/basic.jsonl"),
    ),
    (
        "hermes",
        "basic.json",
        include_bytes!("../../agent-session-grep-provider-hermes/tests/golden/basic.json"),
    ),
    (
        "hermes",
        "state.db",
        include_bytes!("../../agent-session-grep-provider-hermes/tests/golden/state.db"),
    ),
    (
        "kimi-code",
        "basic.jsonl",
        include_bytes!("../../agent-session-grep-provider-kimi/tests/golden/basic.jsonl"),
    ),
    (
        "openclaw",
        "basic.jsonl",
        include_bytes!("../../agent-session-grep-provider-openclaw/tests/golden/basic.jsonl"),
    ),
    (
        "opencode",
        "basic.db",
        include_bytes!("../../agent-session-grep-provider-opencode/tests/golden/basic.db"),
    ),
    (
        "pi",
        "basic.jsonl",
        include_bytes!("../../agent-session-grep-provider-pi/tests/golden/basic.jsonl"),
    ),
    (
        "pi",
        "v3-branched.jsonl",
        include_bytes!("../../agent-session-grep-provider-pi/tests/golden/v3-branched.jsonl"),
    ),
    (
        "pi",
        "thinking.jsonl",
        include_bytes!("../../agent-session-grep-provider-pi/tests/golden/thinking.jsonl"),
    ),
    (
        "qoder",
        "basic.jsonl",
        include_bytes!("../../agent-session-grep-provider-qoder/tests/golden/basic.jsonl"),
    ),
    (
        "tencent-codebuddy",
        "basic.jsonl",
        include_bytes!("../../agent-session-grep-provider-codebuddy/tests/golden/basic.jsonl"),
    ),
];

/// The one documented, root-resolved tie. Both adapters read the same v3 session
/// JSONL shape (`{type:session,…}` header + `{type:message,message:{role,content}}`)
/// and there is no discriminating bit in the bytes, so each answers `Confirmed`
/// on the other's fixture. `stage_with_source` narrows the candidate set by the
/// canonical discovery root before probing, which is why real `~/.pi` and
/// `~/.openclaw` sources still index.
///
/// Anything not listed here is a new defect: it makes the affected sources fail
/// `select_and_stage_source` with "ambiguous provider selection".
const ROOT_RESOLVED_TIES: &[(&str, &str)] = &[("pi", "openclaw")];

fn adapters() -> Vec<Box<dyn ProviderAdapter>> {
    vec![
        Box::new(ClaudeCodeAdapter::new()),
        Box::new(AiderAdapter::new()),
        Box::new(CodexAdapter::new()),
        Box::new(GrokBuildAdapter::new()),
        Box::new(PiAdapter::new()),
        Box::new(QoderAdapter::new()),
        Box::new(KimiCodeAdapter::new()),
        Box::new(OpenClawAdapter::new()),
        Box::new(OpenCodeAdapter::new()),
        Box::new(CodeBuddyAdapter::new()),
        Box::new(ClineAdapter::new()),
        Box::new(AntigravityAdapter::new()),
        Box::new(OpenHermesAdapter::new()),
        Box::new(CursorAdapter::new()),
    ]
}

/// Same ranking as `select_and_stage_source`: `Ambiguous` does not compete.
fn rank(confidence: Confidence) -> Option<u8> {
    match confidence {
        Confidence::Confirmed => Some(3),
        Confidence::High => Some(2),
        Confidence::Low => Some(1),
        Confidence::Ambiguous => None,
    }
}

fn tie_is_documented(left: &str, right: &str) -> bool {
    ROOT_RESOLVED_TIES
        .iter()
        .any(|(a, b)| (*a == left && *b == right) || (*a == right && *b == left))
}

#[test]
fn golden_fixture_table_covers_every_implemented_provider() {
    // A provider missing from the table would silently skip its own row below.
    for adapter in adapters() {
        let id = adapter.provider_id();
        assert!(
            GOLDEN_FIXTURES.iter().any(|(owner, _, _)| *owner == id),
            "{id}: GOLDEN_FIXTURES 缺少该 provider 的 golden fixture"
        );
    }
}

#[test]
fn every_golden_fixture_is_claimed_by_its_own_adapter() {
    for (owner, label, bytes) in GOLDEN_FIXTURES {
        let claimed = adapters()
            .iter()
            .filter(|adapter| adapter.provider_id() == *owner)
            .any(|adapter| adapter.probe(bytes).is_ok());
        assert!(
            claimed,
            "{owner}/{label}: 自己的 golden fixture 必须被自己的 probe 认领"
        );
    }
}

#[test]
fn no_undocumented_probe_tie_at_the_top_confidence_rank() {
    for (owner, label, bytes) in GOLDEN_FIXTURES {
        // (provider_id, variant_id) of every adapter that competes at the top rank.
        let mut best: Option<u8> = None;
        let mut top: Vec<(String, String)> = Vec::new();
        for adapter in adapters() {
            let Ok(probe) = adapter.probe(bytes) else {
                continue;
            };
            let Some(r) = rank(probe.confidence) else {
                continue;
            };
            match best {
                Some(current) if r < current => continue,
                Some(current) if r > current => {
                    best = Some(r);
                    top.clear();
                }
                Some(_) => {}
                None => best = Some(r),
            }
            top.push((adapter.provider_id().to_string(), probe.variant_id.clone()));
        }

        assert!(
            best.is_some(),
            "{owner}/{label}: 没有任何 adapter 给出可竞争的置信度"
        );
        // Distinct variant ids at the top rank are what `select_and_stage_source`
        // treats as a tie; one adapter answering twice cannot happen here.
        let mut variants: Vec<&str> = top.iter().map(|(_, v)| v.as_str()).collect();
        variants.sort_unstable();
        variants.dedup();
        if variants.len() == 1 {
            assert_eq!(
                top[0].0, *owner,
                "{owner}/{label}: 顶档唯一认领者必须是 fixture 自己的 provider，实际 {top:?}"
            );
            continue;
        }

        // More than one variant at the top rank: only the enumerated,
        // root-resolved pair is allowed, and the owner must be part of it.
        let ids: Vec<&str> = top.iter().map(|(id, _)| id.as_str()).collect();
        assert_eq!(
            ids.len(),
            2,
            "{owner}/{label}: 顶档出现 {} 个竞争者，超出任何已记录的 tie：{top:?}",
            ids.len()
        );
        assert!(
            tie_is_documented(ids[0], ids[1]),
            "{owner}/{label}: 未记录的 probe tie（{} ↔ {}）——这会让该源在 \
             select_and_stage_source 被整源拒绝（ambiguous provider selection）。\
             要么收紧其中一方的 probe 正信号，要么在 ROOT_RESOLVED_TIES 里连同 \
             根消解证据一起登记。实际：{top:?}",
            ids[0],
            ids[1]
        );
        assert!(
            ids.contains(owner),
            "{owner}/{label}: 顶档竞争者里没有 fixture 自己的 provider：{top:?}"
        );
    }
}
