//! Deterministic, placement-aware context selection over one validated Session
//! graph. The module is pure and performs no I/O.

use crate::{
    DomainError, DomainResult, Message, MessageEdge, MessagePlacement, SessionContextGraph,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

/// Session context selection policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextPolicy {
    Mainline,
    Full,
}

/// A selected contextual branch in root-to-leaf order.
#[derive(Debug, PartialEq)]
pub struct BranchSelection<'a> {
    pub leaf: &'a MessagePlacement,
    pub placements: Vec<&'a MessagePlacement>,
}

/// Select the deterministic contextual mainline.
///
/// Non-sidechain placements form the candidate graph. When every placement is
/// sidechain, all placements are candidates rather than inventing a mainline.
/// Parent Message IDs resolve within that candidate graph. Multiple matches are
/// accepted only when exactly one is in the child's source document.
///
/// Parent resolution is lazy: only the selected branch's parent chain is
/// resolved. An ambiguous parent on a candidate that is *not* part of the
/// selected branch (e.g. a fork/retry child pointing at a parent that only
/// exists in other documents) never fails the selection.
pub fn select_mainline(graph: &SessionContextGraph) -> DomainResult<Option<BranchSelection<'_>>> {
    graph.validate()?;

    let messages = messages_by_id(graph);
    // 每条消息的时间戳只解析一次;比较时读 map(逐跳重复解析是 O(n²) 热点)。
    let instants = instants_by_id(&messages);
    let edges: BTreeMap<&str, &MessageEdge> = graph
        .edges
        .iter()
        .map(|edge| (edge.child_placement_id.as_str(), edge))
        .collect();

    let all_placements: Vec<&MessagePlacement> = graph.placements.iter().collect();
    // 每条消息的全部出现按图内顺序索引一次;父解析从逐跳扫描全部出现降为
    // 一次 map 查找(候选图很大时逐跳扫描是 O(n²) 热点)。
    let placements_by_message = placements_by_message(&all_placements);
    let mut candidates: Vec<&MessagePlacement> = all_placements
        .iter()
        .copied()
        .filter(|placement| !placement.is_sidechain)
        .collect();
    if candidates.is_empty() {
        candidates.extend(all_placements.iter().copied());
    }
    if candidates.is_empty() {
        return Ok(None);
    }

    // A message referenced as a parent by any candidate's edge is internal to
    // the mainline graph: none of its occurrences are leaves, even when the
    // resolved parent happens to pick a different occurrence. Real transcripts
    // carry the same native message in several documents (cross-file copies),
    // so a stale occurrence of an internal message must not win the leaf
    // selection over the child that actually points at it.
    let parent_message_ids: BTreeSet<&str> = candidates
        .iter()
        .filter_map(|candidate| {
            edges
                .get(candidate.id.as_str())
                .map(|edge| edge.parent_message_id.as_str())
        })
        .collect();
    let leaves: Vec<&MessagePlacement> = candidates
        .iter()
        .copied()
        .filter(|candidate| !parent_message_ids.contains(candidate.message_id.as_str()))
        .collect();

    // Leaf copies that carry an out-edge are the ones that continue the
    // chain; an edgeless copy of the same message is a stale duplicate and
    // must not win by document-id ordering (which is content-hash-derived
    // and arbitrary). Prefer the edged leaves when any exist.
    let leaf = {
        let edged: Vec<&MessagePlacement> = leaves
            .iter()
            .copied()
            .filter(|placement| edges.contains_key(placement.id.as_str()))
            .collect();
        if !edged.is_empty() {
            edged
                .into_iter()
                .max_by(|left, right| compare_placements(left, right, &messages, &instants))
        } else {
            leaves
                .into_iter()
                .max_by(|left, right| compare_placements(left, right, &messages, &instants))
        }
    }
    .or_else(|| {
        candidates
            .iter()
            .copied()
            .max_by(|left, right| compare_placements(left, right, &messages, &instants))
    });
    let Some(leaf) = leaf else {
        return Ok(None);
    };

    let mut placements = vec![leaf];
    let mut visited = BTreeSet::new();
    visited.insert(leaf.id.as_str());
    let mut current = leaf;
    // 沿选中分支惰性解析父链:不在分支上的候选即使父解析歧义也不阻塞
    // 整条 mainline(如 fork/retry 子消息指向只存在于其他文档的父)。
    while let Some(parent) = resolve_parent(current, &placements_by_message, &edges)? {
        if !visited.insert(parent.id.as_str()) {
            break;
        }
        placements.push(parent);
        current = parent;
    }
    placements.reverse();

    Ok(Some(BranchSelection { leaf, placements }))
}

/// Return every placement in deterministic contextual order.
pub fn select_full(graph: &SessionContextGraph) -> DomainResult<Vec<&MessagePlacement>> {
    graph.validate()?;
    let messages = messages_by_id(graph);
    let instants = instants_by_id(&messages);
    let mut placements: Vec<&MessagePlacement> = graph.placements.iter().collect();
    placements.sort_by(|left, right| compare_placements(left, right, &messages, &instants));
    Ok(placements)
}

fn messages_by_id(graph: &SessionContextGraph) -> BTreeMap<&str, &Message> {
    graph
        .messages
        .iter()
        .map(|message| (message.id.as_str(), message))
        .collect()
}

/// 每条消息的解析后时间戳(秒 + 纳秒),每消息只解析一次。缺失或不可解析均为
/// `None`;不可解析时比较回退原始字节序,与逐次解析的语义一致。
fn instants_by_id<'a>(
    messages: &'a BTreeMap<&'a str, &'a Message>,
) -> BTreeMap<&'a str, Option<Instant>> {
    messages
        .iter()
        .map(|(id, message)| (*id, message.timestamp.as_deref().and_then(parse_instant)))
        .collect()
}

/// 每条消息的全部出现,按图内出现顺序索引。
fn placements_by_message<'a>(
    placements: &[&'a MessagePlacement],
) -> BTreeMap<&'a str, Vec<&'a MessagePlacement>> {
    let mut index: BTreeMap<&str, Vec<&MessagePlacement>> = BTreeMap::new();
    for placement in placements {
        index
            .entry(placement.message_id.as_str())
            .or_default()
            .push(*placement);
    }
    index
}

fn resolve_parent<'a>(
    child: &'a MessagePlacement,
    placements_by_message: &BTreeMap<&str, Vec<&'a MessagePlacement>>,
    edges: &BTreeMap<&str, &MessageEdge>,
) -> DomainResult<Option<&'a MessagePlacement>> {
    let Some(edge) = edges.get(child.id.as_str()) else {
        return Ok(None);
    };

    let matching: &[&'a MessagePlacement] = placements_by_message
        .get(edge.parent_message_id.as_str())
        .map_or(&[][..], |placements| placements.as_slice());
    match matching {
        [] => Ok(None),
        [parent] => Ok(Some(*parent)),
        _ => {
            let same_document: Vec<&MessagePlacement> = matching
                .iter()
                .copied()
                .filter(|placement| {
                    placement.source_document_id.as_str() == child.source_document_id.as_str()
                })
                .collect();
            match same_document.as_slice() {
                [parent] => Ok(Some(*parent)),
                _ => Err(DomainError::AmbiguousGraph(format!(
                    "child placement {} has multiple possible parents",
                    child.id
                ))),
            }
        }
    }
}

/// An ISO-8601 instant as (seconds since the Unix epoch, nanoseconds).
type Instant = (i64, u32);

/// Parse an ISO-8601 timestamp into a UTC instant.
///
/// Accepts `YYYY-MM-DD[T ]HH:MM:SS[.fraction][Z|±HH:MM|±HHMM]`. Returns `None`
/// for anything that does not parse (callers fall back to byte comparison).
fn parse_instant(value: &str) -> Option<Instant> {
    let value = value.trim();
    let (date, time) = value.split_once(['T', ' '])?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() {
        return None;
    }

    let (time, offset_minutes) = split_zone(time);
    let (hms, fraction) = time.rsplit_once('.').unwrap_or((time, ""));
    let mut hms_parts = hms.split(':');
    let hour: u32 = hms_parts.next()?.parse().ok()?;
    let minute: u32 = hms_parts.next()?.parse().ok()?;
    let second: u32 = hms_parts.next()?.parse().ok()?;
    if hms_parts.next().is_some() || hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    // Fractional seconds at nanosecond precision; a shorter fraction is
    // zero-padded, so `0.5` and `0.500000000` compare equal. Digits beyond
    // nine are ignored (sub-nanosecond).
    let mut nanos: u64 = 0;
    for digit in fraction.bytes().take(9) {
        if !digit.is_ascii_digit() {
            return None;
        }
        nanos = nanos * 10 + u64::from(digit - b'0');
    }
    for _ in fraction.len()..9 {
        nanos *= 10;
    }

    let days = days_from_civil(year, month, day)?;
    // 超大年份会溢出 i64 秒：checked 算术，溢出即 None（与"anything that
    // does not parse"契约一致），绝不 panic 或静默 wrap。
    let seconds = days
        .checked_mul(86400)?
        .checked_add(i64::from(hour).checked_mul(3600)?)?
        .checked_add(i64::from(minute).checked_mul(60)?)?
        .checked_add(i64::from(second))?
        .checked_sub(i64::from(offset_minutes).checked_mul(60)?)?;
    Some((seconds, nanos as u32))
}

/// Strip a trailing timezone marker and return the UTC offset in minutes.
///
/// Handles `Z` (zero), `±HH:MM` and `±HHMM`; a missing zone is treated as UTC.
fn split_zone(time: &str) -> (&str, i32) {
    if let Some(without) = time.strip_suffix('Z') {
        return (without, 0);
    }
    let parse_offset = |sign: u8, hours: &str, minutes: &str| -> Option<i32> {
        let magnitude = hours.parse::<i32>().ok()? * 60 + minutes.parse::<i32>().ok()?;
        Some(if sign == b'-' { -magnitude } else { magnitude })
    };
    // 字节窗口必须落在 char 边界上，否则非 ASCII 时间戳会 panic。失败返回
    // (time, 0)，调用方最终回退字节比较（None 语义由 parse_instant 保证）。
    if time.len() >= 6 && time.is_char_boundary(time.len() - 6) {
        let suffix = &time[time.len() - 6..];
        let bytes = suffix.as_bytes();
        if (bytes[0] == b'+' || bytes[0] == b'-')
            && bytes[3] == b':'
            && let Some(offset) = parse_offset(bytes[0], &suffix[1..3], &suffix[4..6])
        {
            return (&time[..time.len() - 6], offset);
        }
    }
    if time.len() >= 5 && time.is_char_boundary(time.len() - 5) {
        let suffix = &time[time.len() - 5..];
        let bytes = suffix.as_bytes();
        if (bytes[0] == b'+' || bytes[0] == b'-')
            && suffix[1..].bytes().all(|b| b.is_ascii_digit())
            && let Some(offset) = parse_offset(bytes[0], &suffix[1..3], &suffix[3..5])
        {
            return (&time[..time.len() - 5], offset);
        }
    }
    (time, 0)
}

/// Days since 1970-01-01 for a proleptic Gregorian date
/// (Howard Hinnant's `days_from_civil`), so offsets that cross month/year
/// boundaries still compare correctly.
fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let shifted_month = (month + 9) % 12;
    let day_of_year = ((153 * shifted_month + 2) / 5 + day - 1) as i64;
    let day_of_era = year_of_era
        .checked_mul(365)?
        .checked_add(year_of_era / 4)?
        .checked_sub(year_of_era / 100)?
        .checked_add(day_of_year)?;
    let days = era
        .checked_mul(146097)?
        .checked_add(day_of_era)?
        .checked_sub(719468)?;
    Some(days)
}

/// 比较两个出现:先按消息时间戳(预解析 map,每消息解析一次),缺失排在
/// 有值之前;时间戳相同时按文档 id → 源内序号 → 出现 id 的字节序决胜。
///
/// 时间戳值都在 `instants` 里预解析过;两个都能解析则按 UTC 瞬时比较,
/// 任一不可解析则回退原始字节比较(与逐次解析的 `cmp_timestamps` 一致)。
fn compare_placements(
    left: &MessagePlacement,
    right: &MessagePlacement,
    messages: &BTreeMap<&str, &Message>,
    instants: &BTreeMap<&str, Option<Instant>>,
) -> Ordering {
    let left_raw = messages
        .get(left.message_id.as_str())
        .and_then(|message| message.timestamp.as_deref());
    let right_raw = messages
        .get(right.message_id.as_str())
        .and_then(|message| message.timestamp.as_deref());

    match (left_raw, right_raw) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left_raw), Some(right_raw)) => {
            let left_instant = instants.get(left.message_id.as_str()).copied().flatten();
            let right_instant = instants.get(right.message_id.as_str()).copied().flatten();
            match (left_instant, right_instant) {
                (Some(left_instant), Some(right_instant)) => left_instant.cmp(&right_instant),
                _ => left_raw.as_bytes().cmp(right_raw.as_bytes()),
            }
        }
    }
    .then_with(|| {
        left.source_document_id
            .as_str()
            .as_bytes()
            .cmp(right.source_document_id.as_str().as_bytes())
    })
    .then_with(|| left.source_ordinal.cmp(&right.source_ordinal))
    .then_with(|| {
        left.id
            .as_str()
            .as_bytes()
            .cmp(right.id.as_str().as_bytes())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IdKind, MessageRelation, PlacementId, Role, SourceDocument, Stability, StableId};

    fn id(kind: IdKind, tag: &str) -> StableId {
        StableId::derive(kind, Stability::Reconstructed, &[tag.as_bytes()])
    }

    fn message(tag: &str, timestamp: Option<&str>) -> Message {
        Message {
            id: id(IdKind::Message, tag),
            role: Role::User,
            text: tag.to_string(),
            timestamp: timestamp.map(str::to_string),
        }
    }

    fn document(tag: &str) -> SourceDocument {
        SourceDocument {
            id: id(IdKind::Document, tag),
            provider_id: "test-provider".into(),
            variant_id: "test-provider/v1".into(),
            fingerprint: format!("fingerprint-{tag}"),
            len: 1024,
        }
    }

    fn placement(
        session_id: &StableId,
        document_id: &StableId,
        message_id: &StableId,
        source_ordinal: u32,
        is_sidechain: bool,
    ) -> MessagePlacement {
        MessagePlacement::new(
            session_id.clone(),
            document_id.clone(),
            message_id.clone(),
            source_ordinal,
            is_sidechain,
            None,
        )
    }

    fn edge(child: &MessagePlacement, parent: &Message) -> MessageEdge {
        MessageEdge {
            child_placement_id: child.id.clone(),
            parent_message_id: parent.id.clone(),
            parent_native_id: None,
            relation: MessageRelation::Reply,
        }
    }

    fn graph(
        session_id: StableId,
        messages: Vec<Message>,
        source_documents: Vec<SourceDocument>,
        placements: Vec<MessagePlacement>,
        edges: Vec<MessageEdge>,
    ) -> SessionContextGraph {
        SessionContextGraph {
            session_id,
            messages,
            source_documents,
            placements,
            edges,
        }
    }

    fn ordinals(placements: &[&MessagePlacement]) -> Vec<u32> {
        placements
            .iter()
            .map(|placement| placement.source_ordinal)
            .collect()
    }

    // ===== pre-change reference implementation (property-test oracle) =====
    //
    // The production path pre-parses timestamps into a map and resolves parents
    // through a per-message placement index; this copy preserves the original
    // per-comparison parse + per-hop scan semantics to prove the selection is
    // byte-for-byte identical on generated graphs.

    /// Compare two timestamps in ISO-8601 form.
    ///
    /// Raw byte comparison reverses order when the two values disagree about the
    /// fractional-second digits (`"00:04:00Z"` vs `"00:04:00.123Z"`: `'Z'` (0x5A)
    /// sorts after `'.'` (0x2E) even though `.123Z` is later), and when one carries
    /// a numeric timezone offset (`"00:04:00+08:00"` sorts after `"00:04:00Z"`
    /// though it is eight hours *earlier*). Providers emit both shapes, so each
    /// value is parsed into a UTC instant (seconds since the epoch + nanoseconds)
    /// before comparison: `±HH:MM` / `±HHMM` offsets are applied, fractions keep
    /// full nanosecond precision (shorter fractions are zero-padded to nine
    /// digits), and a missing zone is treated as UTC. Unparseable values fall back
    /// to a deterministic raw byte comparison. The parser allocates nothing.
    fn cmp_timestamps(left: &str, right: &str) -> std::cmp::Ordering {
        match (parse_instant(left), parse_instant(right)) {
            (Some(a), Some(b)) => a.cmp(&b),
            _ => left.as_bytes().cmp(right.as_bytes()),
        }
    }

    fn compare_placements_reference(
        left: &MessagePlacement,
        right: &MessagePlacement,
        messages: &BTreeMap<&str, &Message>,
    ) -> Ordering {
        let left_timestamp = messages
            .get(left.message_id.as_str())
            .and_then(|message| message.timestamp.as_deref());
        let right_timestamp = messages
            .get(right.message_id.as_str())
            .and_then(|message| message.timestamp.as_deref());

        match (left_timestamp, right_timestamp) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(left), Some(right)) => cmp_timestamps(left, right),
        }
        .then_with(|| {
            left.source_document_id
                .as_str()
                .as_bytes()
                .cmp(right.source_document_id.as_str().as_bytes())
        })
        .then_with(|| left.source_ordinal.cmp(&right.source_ordinal))
        .then_with(|| {
            left.id
                .as_str()
                .as_bytes()
                .cmp(right.id.as_str().as_bytes())
        })
    }

    fn resolve_parent_reference<'a>(
        child: &'a MessagePlacement,
        candidates: &[&'a MessagePlacement],
        edges: &BTreeMap<&str, &MessageEdge>,
    ) -> DomainResult<Option<&'a MessagePlacement>> {
        let Some(edge) = edges.get(child.id.as_str()) else {
            return Ok(None);
        };

        let matching: Vec<&MessagePlacement> = candidates
            .iter()
            .copied()
            .filter(|placement| placement.message_id.as_str() == edge.parent_message_id.as_str())
            .collect();
        match matching.as_slice() {
            [] => Ok(None),
            [parent] => Ok(Some(*parent)),
            _ => {
                let same_document: Vec<&MessagePlacement> = matching
                    .into_iter()
                    .filter(|placement| {
                        placement.source_document_id.as_str() == child.source_document_id.as_str()
                    })
                    .collect();
                match same_document.as_slice() {
                    [parent] => Ok(Some(*parent)),
                    _ => Err(DomainError::AmbiguousGraph(format!(
                        "child placement {} has multiple possible parents",
                        child.id
                    ))),
                }
            }
        }
    }

    fn select_mainline_reference(
        graph: &SessionContextGraph,
    ) -> DomainResult<Option<BranchSelection<'_>>> {
        graph.validate()?;

        let messages = messages_by_id(graph);
        let edges: BTreeMap<&str, &MessageEdge> = graph
            .edges
            .iter()
            .map(|edge| (edge.child_placement_id.as_str(), edge))
            .collect();

        let all_placements: Vec<&MessagePlacement> = graph.placements.iter().collect();
        let mut candidates: Vec<&MessagePlacement> = all_placements
            .iter()
            .copied()
            .filter(|placement| !placement.is_sidechain)
            .collect();
        if candidates.is_empty() {
            candidates.extend(all_placements.iter().copied());
        }
        if candidates.is_empty() {
            return Ok(None);
        }

        let parent_message_ids: BTreeSet<&str> = candidates
            .iter()
            .filter_map(|candidate| {
                edges
                    .get(candidate.id.as_str())
                    .map(|edge| edge.parent_message_id.as_str())
            })
            .collect();
        let leaves: Vec<&MessagePlacement> = candidates
            .iter()
            .copied()
            .filter(|candidate| !parent_message_ids.contains(candidate.message_id.as_str()))
            .collect();

        let leaf = {
            let edged: Vec<&MessagePlacement> = leaves
                .iter()
                .copied()
                .filter(|placement| edges.contains_key(placement.id.as_str()))
                .collect();
            if !edged.is_empty() {
                edged
                    .into_iter()
                    .max_by(|left, right| compare_placements_reference(left, right, &messages))
            } else {
                leaves
                    .into_iter()
                    .max_by(|left, right| compare_placements_reference(left, right, &messages))
            }
        }
        .or_else(|| {
            candidates
                .iter()
                .copied()
                .max_by(|left, right| compare_placements_reference(left, right, &messages))
        });
        let Some(leaf) = leaf else {
            return Ok(None);
        };

        let mut placements = vec![leaf];
        let mut visited = BTreeSet::new();
        visited.insert(leaf.id.as_str());
        let mut current = leaf;
        while let Some(parent) = resolve_parent_reference(current, &all_placements, &edges)? {
            if !visited.insert(parent.id.as_str()) {
                break;
            }
            placements.push(parent);
            current = parent;
        }
        placements.reverse();

        Ok(Some(BranchSelection { leaf, placements }))
    }

    /// 确定性 LCG,用于随机图生成(无外部依赖)。
    struct Lcg(u64);

    impl Lcg {
        fn new(seed: u64) -> Self {
            Lcg(seed)
        }

        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    fn random_graph(
        rng: &mut Lcg,
        session: &StableId,
        message_count: u64,
        target_placement_count: u64,
    ) -> SessionContextGraph {
        let timestamps: [Option<&str>; 9] = [
            None,
            Some("2026-01-01T00:04:00Z"),
            Some("2026-01-01T00:04:00.123Z"),
            Some("2026-01-01T00:04:00+08:00"),
            Some("2026-01-01T00:04:00-05:00"),
            Some("2026-01-01T00:04:00.123456789Z"),
            Some("2026-01-01T00:04:00"),
            Some("2026-13-40T99:99:99Z"),
            Some("not-a-timestamp"),
        ];
        let mut messages = Vec::new();
        for index in 0..message_count {
            let timestamp = timestamps[rng.below(timestamps.len() as u64) as usize];
            messages.push(message(&format!("m{index}"), timestamp));
        }
        let document_count = 1 + rng.below(3);
        let documents: Vec<SourceDocument> = (0..document_count)
            .map(|index| document(&format!("d{index}")))
            .collect();

        // 出现坐标(session, doc, message, ordinal)必须唯一;碰撞则重试。
        let mut placements = Vec::new();
        let mut coordinates = BTreeSet::new();
        let mut attempts = 0u64;
        while placements.len() < target_placement_count as usize
            && attempts < target_placement_count * 32
        {
            attempts += 1;
            let document = &documents[rng.below(document_count) as usize];
            let message = &messages[rng.below(message_count) as usize];
            let ordinal = rng.below(8) as u32;
            let coordinate = (
                document.id.as_str().to_string(),
                message.id.as_str().to_string(),
                ordinal,
            );
            if !coordinates.insert(coordinate) {
                continue;
            }
            let is_sidechain = rng.below(4) == 0;
            placements.push(placement(
                session,
                &document.id,
                &message.id,
                ordinal,
                is_sidechain,
            ));
        }

        // 约 2/3 的出现带一条出边;父消息一半取自图内(可能无出现 → 孤儿父),
        // 一半是图外消息 id(跨文档/会话的孤儿父)。
        let mut edges = Vec::new();
        for child in &placements {
            if rng.below(3) == 0 {
                continue;
            }
            let parent = if rng.below(2) == 0 {
                messages[rng.below(message_count) as usize].id.clone()
            } else {
                let orphan = format!("orphan-{}", rng.below(4096));
                StableId::derive(IdKind::Message, Stability::Unstable, &[orphan.as_bytes()])
            };
            edges.push(MessageEdge {
                child_placement_id: child.id.clone(),
                parent_message_id: parent,
                parent_native_id: None,
                relation: MessageRelation::Reply,
            });
        }

        graph(session.clone(), messages, documents, placements, edges)
    }

    fn selection_outcome(
        branch: &Option<BranchSelection<'_>>,
    ) -> Option<(PlacementId, Vec<PlacementId>)> {
        branch.as_ref().map(|branch| {
            (
                branch.leaf.id.clone(),
                branch
                    .placements
                    .iter()
                    .map(|placement| placement.id.clone())
                    .collect(),
            )
        })
    }

    #[test]
    fn select_mainline_matches_pre_change_reference_on_random_graphs() {
        // R2/R3 行为保真:主链选择(叶子 + 完整分支)与改前逐跳扫描/逐次解析
        // 的实现完全一致。生成图覆盖跨文档重复消息(叉/歧义)、孤儿父、
        // sidechain、不可解析时间戳与各种时区/小数形态。
        let session = id(IdKind::Session, "property-session");
        let mut rng = Lcg::new(0x9e37_79b9_7f4a_7c15);
        for iteration in 0..400 {
            let graph = random_graph(&mut rng, &session, 6, 12);
            let before_result = select_mainline_reference(&graph);
            let after_result = select_mainline(&graph);
            let before = before_result.as_ref().map(selection_outcome);
            let after = after_result.as_ref().map(selection_outcome);
            assert_eq!(after, before, "iteration {iteration}");
        }
    }

    #[test]
    fn edged_child_copy_wins_over_edgeless_copy_as_leaf() {
        // Major-2 regression: message C appears in documents d1 and d2; the d1
        // copy has an out-edge to M (chain continues), the d2 copy is edgeless.
        // All timestamps are None, so compare_placements would tie-break on
        // document id (content-hash, arbitrary). The edged copy must win.
        let session = id(IdKind::Session, "session");
        let doc_1 = document("doc-1");
        let doc_2 = document("doc-2");
        let m = message("m", None);
        let c = message("c", None);
        let m_id = m.id.clone();
        let c_id = c.id.clone();
        let m_d1 = placement(&session, &doc_1.id, &m_id, 0, false);
        let c_d1 = placement(&session, &doc_1.id, &c_id, 1, false);
        let c_d2 = placement(&session, &doc_2.id, &c_id, 0, false);
        let c_d1_id = c_d1.id.clone();
        let m_d1_id = m_d1.id.clone();
        let edge_cd1_m = edge(&c_d1, &m);
        let graph = graph(
            session,
            vec![m, c],
            vec![doc_1, doc_2],
            vec![m_d1, c_d1, c_d2],
            vec![edge_cd1_m],
        );
        let branch = select_mainline(&graph).unwrap().unwrap();
        assert_eq!(
            branch
                .placements
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>(),
            vec![m_d1_id.as_str(), c_d1_id.as_str()],
            "the edged d1 copy must form the mainline, not the edgeless d2 copy"
        );
        assert_eq!(branch.leaf.id, c_d1_id);
    }

    #[test]
    fn stale_occurrence_of_internal_message_is_not_a_leaf() {
        // BLOCKER-1 regression: the same message M appears in documents A and
        // B; child C in document B has an edge to M. M is internal to the
        // graph, so the stale occurrence M_a must not be chosen as the leaf
        // over C. All timestamps are None, so ordering alone cannot save us:
        // the message-level exclusion must.
        let session = id(IdKind::Session, "session");
        let doc_a = document("doc-a");
        let doc_b = document("doc-b");
        let m = message("m", None);
        let c = message("c", None);
        let m_id = m.id.clone();
        let c_id = c.id.clone();
        let m_a = placement(&session, &doc_a.id, &m_id, 0, false);
        let m_b = placement(&session, &doc_b.id, &m_id, 0, false);
        let c_b = placement(&session, &doc_b.id, &c_id, 1, false);
        let m_b_id = m_b.id.clone();
        let c_b_id = c_b.id.clone();
        let edge_cb_m = edge(&c_b, &m);
        let graph = graph(
            session,
            vec![m, c],
            vec![doc_a, doc_b],
            vec![m_a, m_b, c_b],
            vec![edge_cb_m],
        );
        let branch = select_mainline(&graph).unwrap().unwrap();
        assert_eq!(
            branch
                .placements
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>(),
            vec![m_b_id.as_str(), c_b_id.as_str()],
            "mainline must run through the document-B occurrence of M"
        );
        assert_eq!(branch.leaf.id, c_b_id);
    }

    #[test]
    fn ambiguous_off_branch_parent_does_not_fail_selection() {
        // Major-1 regression: message P appears in documents A and B; document
        // C's fork/retry child X points at P, which is not resolvable from C
        // (neither A nor B is C). The mainline runs through the other chain,
        // so the off-branch ambiguity must not fail the whole selection.
        let session = id(IdKind::Session, "session");
        let doc_a = document("doc-a");
        let doc_b = document("doc-b");
        let doc_c = document("doc-c");
        let p = message("p", None);
        let r = message("r", None);
        let x = message("x", None);
        let m = message("m", None);
        let p_a = placement(&session, &doc_a.id, &p.id, 0, false);
        let p_b = placement(&session, &doc_b.id, &p.id, 0, false);
        let r_c = placement(&session, &doc_c.id, &r.id, 0, false);
        let x_c = placement(&session, &doc_c.id, &x.id, 1, false);
        let m_c = placement(&session, &doc_c.id, &m.id, 2, false);
        let graph = graph(
            session,
            vec![p.clone(), r.clone(), x, m],
            vec![doc_a, doc_b, doc_c],
            vec![p_a, p_b, r_c.clone(), x_c.clone(), m_c.clone()],
            vec![edge(&x_c, &p), edge(&m_c, &r)],
        );

        let selected = select_mainline(&graph).unwrap().unwrap();
        assert_eq!(selected.leaf.id, m_c.id);
        assert_eq!(
            selected
                .placements
                .iter()
                .map(|p| p.id.as_str())
                .collect::<Vec<_>>(),
            vec![r_c.id.as_str(), m_c.id.as_str()]
        );
    }

    #[test]
    fn timestamp_cmp_normalizes_fractional_digits() {
        assert_eq!(
            cmp_timestamps("2026-01-01T00:04:00Z", "2026-01-01T00:04:00.123Z"),
            Ordering::Less
        );
        assert_eq!(
            cmp_timestamps("2026-01-01T00:04:00.123Z", "2026-01-01T00:04:00Z"),
            Ordering::Greater
        );
        assert_eq!(
            cmp_timestamps("2026-01-01T00:04:00.5Z", "2026-01-01T00:04:00.500000Z"),
            Ordering::Equal
        );
        assert_eq!(
            cmp_timestamps("2026-01-01T00:04:01Z", "2026-01-01T00:04:00.999Z"),
            Ordering::Greater
        );
    }

    #[test]
    fn timestamp_cmp_normalizes_common_timezone_offsets() {
        // 数值时区比同字面 Z 晚/早:00:04+08:00 即前一日 16:04Z。
        assert_eq!(
            cmp_timestamps("2026-01-01T00:04:00+08:00", "2026-01-01T00:04:00Z"),
            Ordering::Less
        );
        assert_eq!(
            cmp_timestamps("2026-01-01T00:04:00+08:00", "2025-12-31T16:04:00Z"),
            Ordering::Equal
        );
        // ±HHMM(无冒号)与 ±HH:MM 等价。
        assert_eq!(
            cmp_timestamps("2026-01-01T00:04:00+0800", "2025-12-31T16:04:00Z"),
            Ordering::Equal
        );
        // 负偏移归一为 UTC。
        assert_eq!(
            cmp_timestamps("2026-01-01T00:04:00-05:00", "2026-01-01T05:04:00Z"),
            Ordering::Equal
        );
        // 跨日借位。
        assert_eq!(
            cmp_timestamps("2026-01-01T01:00:00+02:00", "2025-12-31T23:30:00Z"),
            Ordering::Less
        );
        // 无时区标记按 UTC 处理,与带 Z 的等价。
        assert_eq!(
            cmp_timestamps("2026-01-01T00:04:00", "2026-01-01T00:04:00Z"),
            Ordering::Equal
        );
    }

    #[test]
    fn timestamp_cmp_keeps_full_fractional_precision() {
        // 6 位截断会把更晚的纳秒值误判为相等:保留完整纳秒精度。
        assert_eq!(
            cmp_timestamps(
                "2026-01-01T00:00:00.123456789Z",
                "2026-01-01T00:00:00.123456Z"
            ),
            Ordering::Greater
        );
        assert_eq!(
            cmp_timestamps(
                "2026-01-01T00:00:00.123456Z",
                "2026-01-01T00:00:00.123456000Z"
            ),
            Ordering::Equal
        );
        assert_eq!(
            cmp_timestamps("2026-01-01T00:00:00.000000001Z", "2026-01-01T00:00:00Z"),
            Ordering::Greater
        );
    }

    #[test]
    fn linear_chain_returns_root_to_leaf_placements() {
        let session = id(IdKind::Session, "session");
        let document = document("document");
        let root = message("root", Some("2026-07-28T00:00:00Z"));
        let middle = message("middle", Some("2026-07-28T00:00:01Z"));
        let leaf = message("leaf", Some("2026-07-28T00:00:02Z"));
        let root_placement = placement(&session, &document.id, &root.id, 0, false);
        let middle_placement = placement(&session, &document.id, &middle.id, 1, false);
        let leaf_placement = placement(&session, &document.id, &leaf.id, 2, false);
        let graph = graph(
            session,
            vec![root.clone(), middle.clone(), leaf],
            vec![document],
            vec![
                root_placement,
                middle_placement.clone(),
                leaf_placement.clone(),
            ],
            vec![
                edge(&middle_placement, &root),
                edge(&leaf_placement, &middle),
            ],
        );

        let selected = select_mainline(&graph).unwrap().unwrap();
        assert_eq!(selected.leaf.id, leaf_placement.id);
        assert_eq!(ordinals(&selected.placements), vec![0, 1, 2]);
    }

    #[test]
    fn divergent_contextual_parents_select_per_session() {
        let parent_a = message("parent-a", None);
        let parent_b = message("parent-b", None);
        let shared_child = message("shared-child", None);

        let session_a = id(IdKind::Session, "session-a");
        let document_a = document("document-a");
        let parent_a_placement = placement(&session_a, &document_a.id, &parent_a.id, 0, false);
        let child_a_placement = placement(&session_a, &document_a.id, &shared_child.id, 1, false);
        let graph_a = graph(
            session_a,
            vec![parent_a.clone(), shared_child.clone()],
            vec![document_a],
            vec![parent_a_placement.clone(), child_a_placement.clone()],
            vec![edge(&child_a_placement, &parent_a)],
        );

        let session_b = id(IdKind::Session, "session-b");
        let document_b = document("document-b");
        let parent_b_placement = placement(&session_b, &document_b.id, &parent_b.id, 0, false);
        let child_b_placement = placement(&session_b, &document_b.id, &shared_child.id, 1, false);
        let graph_b = graph(
            session_b,
            vec![parent_b.clone(), shared_child],
            vec![document_b],
            vec![parent_b_placement.clone(), child_b_placement.clone()],
            vec![edge(&child_b_placement, &parent_b)],
        );

        let selected_a = select_mainline(&graph_a).unwrap().unwrap();
        let selected_b = select_mainline(&graph_b).unwrap().unwrap();
        assert_eq!(selected_a.placements[0].message_id, parent_a.id);
        assert_eq!(selected_b.placements[0].message_id, parent_b.id);
        assert_ne!(selected_a.leaf.id, selected_b.leaf.id);
    }

    #[test]
    fn same_document_parent_disambiguates_repeated_message() {
        let session = id(IdKind::Session, "session");
        let document_a = document("a");
        let document_b = document("b");
        let parent = message("parent", None);
        let child = message("child", Some("2026-07-28T00:00:00Z"));
        let parent_a = placement(&session, &document_a.id, &parent.id, 0, false);
        let parent_b = placement(&session, &document_b.id, &parent.id, 0, false);
        let child_b = placement(&session, &document_b.id, &child.id, 1, false);
        let graph = graph(
            session,
            vec![parent.clone(), child],
            vec![document_a, document_b],
            vec![parent_a, parent_b.clone(), child_b.clone()],
            vec![edge(&child_b, &parent)],
        );

        let selected = select_mainline(&graph).unwrap().unwrap();
        assert_eq!(selected.leaf.id, child_b.id);
        assert_eq!(selected.placements[0].id, parent_b.id);
        assert_eq!(selected.placements.len(), 2);
    }

    #[test]
    fn same_document_parent_resolution_considers_sidechain_placements() {
        let session = id(IdKind::Session, "session");
        let document_a = document("a");
        let document_b = document("b");
        let root = message("root", Some("2026-07-28T00:00:00Z"));
        let parent = message("parent", Some("2026-07-28T00:00:01Z"));
        let child = message("child", Some("2026-07-28T00:00:02Z"));
        let root_b = placement(&session, &document_b.id, &root.id, 0, false);
        let parent_a = placement(&session, &document_a.id, &parent.id, 0, false);
        let parent_b = placement(&session, &document_b.id, &parent.id, 1, true);
        let child_b = placement(&session, &document_b.id, &child.id, 2, false);
        let graph = graph(
            session,
            vec![root.clone(), parent.clone(), child],
            vec![document_a, document_b],
            vec![root_b.clone(), parent_a, parent_b.clone(), child_b.clone()],
            vec![edge(&parent_b, &root), edge(&child_b, &parent)],
        );

        let selected = select_mainline(&graph).unwrap().unwrap();
        assert_eq!(selected.leaf.id, child_b.id);
        assert_eq!(
            selected
                .placements
                .iter()
                .map(|placement| placement.id.clone())
                .collect::<Vec<_>>(),
            vec![root_b.id, parent_b.id, child_b.id]
        );
    }

    #[test]
    fn unresolved_repeated_parent_is_explicitly_ambiguous() {
        let session = id(IdKind::Session, "session");
        let document_a = document("a");
        let document_b = document("b");
        let document_c = document("c");
        let parent = message("parent", None);
        let child = message("child", None);
        let parent_a = placement(&session, &document_a.id, &parent.id, 0, false);
        let parent_b = placement(&session, &document_b.id, &parent.id, 0, false);
        let child_c = placement(&session, &document_c.id, &child.id, 0, false);
        let graph = graph(
            session,
            vec![parent.clone(), child],
            vec![document_a, document_b, document_c],
            vec![parent_a, parent_b, child_c.clone()],
            vec![edge(&child_c, &parent)],
        );

        let error = select_mainline(&graph).unwrap_err();
        assert_eq!(error.code(), "ambiguous_graph");
    }

    #[test]
    fn orphan_parent_stops_walk_without_invalidating_graph() {
        let session = id(IdKind::Session, "session");
        let document = document("document");
        let child = message("child", None);
        let orphan = message("orphan", None);
        let child_placement = placement(&session, &document.id, &child.id, 0, false);
        let graph = graph(
            session,
            vec![child],
            vec![document],
            vec![child_placement.clone()],
            vec![edge(&child_placement, &orphan)],
        );

        let selected = select_mainline(&graph).unwrap().unwrap();
        assert_eq!(selected.leaf.id, child_placement.id);
        assert_eq!(selected.placements, vec![&child_placement]);
    }

    #[test]
    fn cycles_have_deterministic_fallback_and_terminate() {
        let session = id(IdKind::Session, "session");
        let document = document("document");
        let a = message("a", None);
        let b = message("b", None);
        let a_placement = placement(&session, &document.id, &a.id, 0, false);
        let b_placement = placement(&session, &document.id, &b.id, 1, false);
        let graph = graph(
            session,
            vec![a.clone(), b.clone()],
            vec![document],
            vec![a_placement.clone(), b_placement.clone()],
            vec![edge(&a_placement, &b), edge(&b_placement, &a)],
        );

        let selected = select_mainline(&graph).unwrap().unwrap();
        assert_eq!(selected.leaf.id, b_placement.id);
        assert_eq!(ordinals(&selected.placements), vec![0, 1]);
    }

    #[test]
    fn sidechains_are_excluded_and_all_sidechains_fall_back_honestly() {
        let session = id(IdKind::Session, "session");
        let document = document("document");
        let root = message("root", None);
        let main = message("main", None);
        let side = message("side", Some("2026-07-28T00:00:00Z"));
        let root_placement = placement(&session, &document.id, &root.id, 0, false);
        let main_placement = placement(&session, &document.id, &main.id, 1, false);
        let side_placement = placement(&session, &document.id, &side.id, 2, true);
        let mixed = graph(
            session.clone(),
            vec![root.clone(), main.clone(), side.clone()],
            vec![document.clone()],
            vec![
                root_placement.clone(),
                main_placement.clone(),
                side_placement.clone(),
            ],
            vec![edge(&main_placement, &root), edge(&side_placement, &main)],
        );

        let selected = select_mainline(&mixed).unwrap().unwrap();
        assert_eq!(selected.leaf.id, main_placement.id);
        assert_eq!(ordinals(&selected.placements), vec![0, 1]);
        assert_eq!(select_full(&mixed).unwrap().len(), 3);

        let side_root = placement(&session, &document.id, &root.id, 0, true);
        let side_leaf = placement(&session, &document.id, &side.id, 1, true);
        let all_sidechain = graph(
            session,
            vec![root.clone(), side],
            vec![document],
            vec![side_root.clone(), side_leaf.clone()],
            vec![edge(&side_leaf, &root)],
        );
        let selected = select_mainline(&all_sidechain).unwrap().unwrap();
        assert_eq!(selected.leaf.id, side_leaf.id);
        assert_eq!(ordinals(&selected.placements), vec![0, 1]);
    }

    #[test]
    fn true_leaf_wins_even_when_missing_timestamp_sorts_first() {
        let session = id(IdKind::Session, "session");
        let document = document("document");
        let internal = message("internal", Some("9999-12-31T23:59:59Z"));
        let leaf = message("leaf", None);
        let internal_placement = placement(&session, &document.id, &internal.id, 99, false);
        let leaf_placement = placement(&session, &document.id, &leaf.id, 0, false);
        let graph = graph(
            session,
            vec![internal.clone(), leaf],
            vec![document],
            vec![internal_placement.clone(), leaf_placement.clone()],
            vec![edge(&leaf_placement, &internal)],
        );

        let full = select_full(&graph).unwrap();
        assert_eq!(full[0].id, leaf_placement.id);
        assert_eq!(full[1].id, internal_placement.id);

        let selected = select_mainline(&graph).unwrap().unwrap();
        assert_eq!(selected.leaf.id, leaf_placement.id);
        assert_eq!(
            selected.placements,
            vec![&internal_placement, &leaf_placement]
        );
    }

    #[test]
    fn full_order_is_timestamp_document_ordinal_then_placement_id() {
        let session = id(IdKind::Session, "session");
        let mut document_a = document("a");
        document_a.id = StableId::native(IdKind::Document, "a");
        let mut document_b = document("b");
        document_b.id = StableId::native(IdKind::Document, "b");
        let missing_a_1 = message("missing-a-1", None);
        let missing_a_3 = message("missing-a-3", None);
        let missing_b = message("missing-b", None);
        let earlier = message("earlier", Some("2025-01-01T00:00:00Z"));
        let later = message("later", Some("2026-01-01T00:00:00Z"));
        let p_missing_a_1 = placement(&session, &document_a.id, &missing_a_1.id, 1, false);
        let p_missing_a_3 = placement(&session, &document_a.id, &missing_a_3.id, 3, false);
        let p_missing_b = placement(&session, &document_b.id, &missing_b.id, 0, false);
        let p_earlier = placement(&session, &document_b.id, &earlier.id, 1, false);
        let p_later = placement(&session, &document_a.id, &later.id, 2, false);
        let graph = graph(
            session,
            vec![later, missing_b, missing_a_3, earlier, missing_a_1],
            vec![document_b, document_a],
            vec![
                p_later.clone(),
                p_missing_b.clone(),
                p_missing_a_3.clone(),
                p_earlier.clone(),
                p_missing_a_1.clone(),
            ],
            Vec::new(),
        );

        let selected = select_full(&graph).unwrap();
        assert_eq!(
            selected
                .iter()
                .map(|placement| placement.id.clone())
                .collect::<Vec<PlacementId>>(),
            vec![
                p_missing_a_1.id,
                p_missing_a_3.id,
                p_missing_b.id,
                p_earlier.id,
                p_later.id,
            ]
        );
    }

    #[test]
    fn empty_graph_returns_empty_selections() {
        let graph = graph(
            id(IdKind::Session, "session"),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );
        assert!(select_mainline(&graph).unwrap().is_none());
        assert!(select_full(&graph).unwrap().is_empty());
    }

    #[test]
    fn selector_rejects_invalid_graph_before_selection() {
        let session = id(IdKind::Session, "session");
        let document = document("document");
        let message = message("message", None);
        let mut invalid = placement(&session, &document.id, &message.id, 0, false);
        invalid.id = PlacementId::derive(&session, &document.id, &message.id, 1);
        let graph = graph(
            session,
            vec![message],
            vec![document],
            vec![invalid],
            Vec::new(),
        );

        assert_eq!(
            select_mainline(&graph).unwrap_err().code(),
            "invariant_violation"
        );
        assert_eq!(
            select_full(&graph).unwrap_err().code(),
            "invariant_violation"
        );
    }

    #[test]
    fn context_policy_serde_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&ContextPolicy::Mainline).unwrap(),
            "\"mainline\""
        );
        assert_eq!(
            serde_json::from_str::<ContextPolicy>("\"full\"").unwrap(),
            ContextPolicy::Full
        );
    }
}
