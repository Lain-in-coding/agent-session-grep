//! Typed stable identifiers (RFC-0001).
//!
//! Every entity in the Canonical Model carries a *typed* stable id. Ids are
//! opaque strings with a versioned type prefix so that a raw id string alone
//! is self-describing and mistyping one id for another is a compile error.
//!
//! # Identity vs location
//!
//! A stable id encodes an entity's *identity* — what it is — and never its
//! *location* — where the bytes currently live on disk. Locations move
//! (files get renamed, data roots migrate); identity must survive that. The
//! hash inputs below are deliberately restricted to intrinsic, relocation-
//! invariant facts.
//!
//! # Stability tiers
//!
//! Not every provider gives us a durable native id. We record how much to
//! trust an id's stability via [`Stability`]:
//!
//! * [`Stability::Native`] — the provider emitted a durable id we adopt verbatim.
//! * [`Stability::Reconstructed`] — we derived a deterministic id from intrinsic
//!   content the provider *does* guarantee (e.g. a session's first-message
//!   timestamp + provider tag). Stable across re-ingest of the same source.
//! * [`Stability::Unstable`] — best-effort id derived from facts that may shift
//!   between runs. Callers must not persist cross-run references to these.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The versioned type tag that prefixes every stable id string.
///
/// The `_v1_` infix is a format version: if the hashing scheme for a kind ever
/// changes, we bump to `_v2_` and both can coexist during migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IdKind {
    /// A discovered source (a provider's on-disk history location).
    Source,
    /// A single history document within a source.
    Document,
    /// A conversation/session reconstructed from one or more documents.
    Session,
    /// A single message (turn) within a session.
    Message,
}

impl IdKind {
    /// The stable, wire-visible prefix for this kind, including the trailing `_`.
    pub const fn prefix(self) -> &'static str {
        match self {
            IdKind::Source => "src_v1_",
            IdKind::Document => "doc_v1_",
            IdKind::Session => "ses_v1_",
            IdKind::Message => "msg_v1_",
        }
    }
}

impl fmt::Display for IdKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            IdKind::Source => "source",
            IdKind::Document => "document",
            IdKind::Session => "session",
            IdKind::Message => "message",
        })
    }
}

/// How much an id's stability can be trusted across re-ingest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Stability {
    /// Adopted verbatim from a durable provider-native id.
    Native,
    /// Deterministically derived from intrinsic content; stable across re-ingest.
    Reconstructed,
    /// Best-effort; may shift between runs. Do not persist cross-run references.
    Unstable,
}

/// The identity namespace that scopes a provider-native Session id.
///
/// Two providers can independently emit the same native Session id string, and
/// two installations of the same provider (e.g. two machines ingesting their
/// own history) can as well. Canonical Session identity therefore namespaces
/// the native id by both facts — see [`StableId::native_session_scoped`] — so
/// equal native ids from different providers or installations can never
/// collide in a merged catalog.
///
/// Both fields must be *relocation-invariant*: stable across re-ingest of the
/// same provider installation, and distinct between different installations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionIdentityNamespace<'a> {
    /// The stable provider tag (e.g. `"claude-code"`).
    pub provider_id: &'a str,
    /// A stable identifier for the provider installation.
    pub installation_namespace: &'a str,
}

/// A typed, opaque, stable identifier.
///
/// The wire form is `<prefix><hex-blake3-digest>` for derived ids, or
/// `<prefix><adopted>` for native ids where `<adopted>` is a sanitized copy of
/// the provider's own id. Construct via [`StableId::native`] or
/// [`StableId::derive`]; never hand-assemble the string.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StableId {
    kind: IdKind,
    stability: Stability,
    /// Full wire string, prefix included.
    value: String,
}

/// Length (in hex chars) of the truncated BLAKE3 digest used in derived ids.
///
/// 32 hex chars = 128 bits. Collision-resistant far beyond the id population we
/// will ever hold, while keeping ids short enough to eyeball in logs.
const DIGEST_HEX_LEN: usize = 32;
const PLACEMENT_ID_PREFIX: &str = "plc_v1_";

/// Maximum length (in chars) of the adopted suffix of a native id.
///
/// Provider-native ids are trusted-but-unbounded strings; an extreme value
/// would pollute logs and JSON responses. Every known provider id is far
/// shorter (Claude Code uuids are 36 chars, Codex session ids shorter), so
/// the clamp never truncates a legitimate id and the lossless round-trip
/// contract holds for all real inputs.
const NATIVE_SUFFIX_MAX_CHARS: usize = 256;

impl StableId {
    /// Adopt a provider-native id verbatim (tier [`Stability::Native`]).
    ///
    /// For provider-native *Session* ids, use
    /// [`StableId::native_session_scoped`] instead: canonical Session identity
    /// must be namespaced by provider and installation
    /// ([`SessionIdentityNamespace`]) or equal native ids from different
    /// providers/installations collide. This constructor keeps its original
    /// semantics for every other kind (e.g. message native ids).
    ///
    /// The raw id is sanitized (trimmed, control characters stripped, suffix
    /// clamped to [`NATIVE_SUFFIX_MAX_CHARS`]) so that hostile or pathological
    /// ids cannot break logs or JSON output; within those bounds the id is
    /// preserved so that round-tripping back to the provider is lossless.
    pub fn native(kind: IdKind, raw: &str) -> Self {
        let sanitized: String = raw
            .trim()
            .chars()
            .filter(|c| !c.is_control())
            .take(NATIVE_SUFFIX_MAX_CHARS)
            .collect();
        StableId {
            kind,
            stability: Stability::Native,
            value: format!("{}{sanitized}", kind.prefix()),
        }
    }

    /// Derive a deterministic id by hashing intrinsic identity facts.
    ///
    /// `facts` are hashed in order with an unambiguous length-prefixed framing
    /// so that `["a", "bc"]` and `["ab", "c"]` never collide. Pass only
    /// relocation-invariant inputs (never absolute paths, mtimes, or run-local
    /// counters) or the resulting id will not be reproducible.
    ///
    /// `stability` should be [`Stability::Reconstructed`] when every fact is
    /// provider-guaranteed, or [`Stability::Unstable`] otherwise.
    pub fn derive(kind: IdKind, stability: Stability, facts: &[&[u8]]) -> Self {
        let mut hasher = blake3::Hasher::new();
        // Domain-separate by kind so identical facts under different kinds
        // never produce the same digest.
        hasher.update(kind.prefix().as_bytes());
        for fact in facts {
            hasher.update(&(fact.len() as u64).to_le_bytes());
            hasher.update(fact);
        }
        let digest = hasher.finalize();
        let hex = digest.to_hex();
        let truncated = &hex.as_str()[..DIGEST_HEX_LEN];
        StableId {
            kind,
            stability,
            value: format!("{}{truncated}", kind.prefix()),
        }
    }

    /// Canonical id for a Session whose provider emitted a durable native id.
    ///
    /// Canonical identity is the digest of
    /// `(provider_id, installation_namespace, native_session_id)`, hashed with
    /// the same length-prefixed framing as [`StableId::derive`] and the usual
    /// Session domain separation. The wire string keeps the ordinary
    /// [`IdKind::Session`] prefix — `ses_v1_` + digest — so the namespace does
    /// not introduce a new prefix or format.
    ///
    /// Because the namespace facts are *hashed*, the resulting id contains
    /// neither the native id nor the namespace in recoverable form. **Never**
    /// attempt to recover a provider-native id by stripping the `ses_v1_`
    /// prefix — that transform is lossy and unreliable, and no reverse
    /// derivation path exists. Callers that need the native id must carry it
    /// alongside the canonical id.
    ///
    /// The id is tier [`Stability::Native`]: every input fact is durable and
    /// provider-guaranteed, so the derivation is as stable as the native id
    /// itself.
    pub fn native_session_scoped(
        namespace: &SessionIdentityNamespace<'_>,
        native_session_id: &str,
    ) -> Self {
        Self::derive(
            IdKind::Session,
            Stability::Native,
            &[
                namespace.provider_id.as_bytes(),
                namespace.installation_namespace.as_bytes(),
                native_session_id.as_bytes(),
            ],
        )
    }

    /// The entity kind this id names.
    pub fn kind(&self) -> IdKind {
        self.kind
    }

    /// The stability tier of this id.
    pub fn stability(&self) -> Stability {
        self.stability
    }

    /// The full wire string, prefix included.
    pub fn as_str(&self) -> &str {
        &self.value
    }

    /// Reconstruct an id from a wire string received from outside (e.g. a CLI
    /// argument or an API caller echoing back an id we emitted).
    ///
    /// The `kind` is recovered from the versioned prefix. Stability is *not*
    /// encoded on the wire, so a reconstructed id is always [`Stability::Unstable`]:
    /// we cannot prove how the original was derived. This is honest — callers
    /// must not persist cross-run references built from a wire round-trip.
    ///
    /// Catalog lookups key on [`StableId::as_str`], which is preserved exactly,
    /// so a wire round-trip resolves the same stored entity regardless of the
    /// stability tier. Returns `None` if no known prefix matches, or if only a
    /// bare prefix is given (an empty adopted suffix is not a valid id —
    /// [`StableId::validate`] rejects it the same way).
    pub fn from_wire(wire: &str) -> Option<Self> {
        for kind in [
            IdKind::Source,
            IdKind::Document,
            IdKind::Session,
            IdKind::Message,
        ] {
            if let Some(suffix) = wire.strip_prefix(kind.prefix()) {
                if suffix.is_empty() {
                    return None;
                }
                return Some(StableId {
                    kind,
                    stability: Stability::Unstable,
                    value: wire.to_string(),
                });
            }
        }
        None
    }

    /// Verify the wire value is consistent with the declared kind.
    ///
    /// A `StableId` deserialized from untrusted JSON could pair an arbitrary
    /// kind with a mismatched value (e.g. kind `Message` but value
    /// `"ses_v1_..."`); nothing else in the codebase would catch that because
    /// entity validation only inspects `kind()`. Rejects empty adopted values
    /// too, so all-messages-with-empty-native-ids cannot collide on one id.
    pub fn validate(&self) -> bool {
        !self.value.is_empty()
            && self.value.starts_with(self.kind.prefix())
            && !self.value[self.kind.prefix().len()..].is_empty()
    }
}

impl fmt::Display for StableId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.value)
    }
}

/// A deterministic identity for one contextual occurrence of a Message.
///
/// A placement is not a canonical entity and therefore does not use
/// [`StableId`] or a stability tier. Its identity is derived only from logical,
/// path-independent context: session, source document, message, and the
/// source-local ordinal.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PlacementId(String);

impl PlacementId {
    /// Derive the occurrence identity from relocation-invariant context.
    pub fn derive(
        session_id: &StableId,
        source_document_id: &StableId,
        message_id: &StableId,
        source_ordinal: u32,
    ) -> Self {
        let ordinal = source_ordinal.to_le_bytes();
        let facts = [
            session_id.as_str().as_bytes(),
            source_document_id.as_str().as_bytes(),
            message_id.as_str().as_bytes(),
            ordinal.as_slice(),
        ];
        let mut hasher = blake3::Hasher::new();
        hasher.update(PLACEMENT_ID_PREFIX.as_bytes());
        for fact in facts {
            hasher.update(&(fact.len() as u64).to_le_bytes());
            hasher.update(fact);
        }
        let digest = hasher.finalize();
        let hex = digest.to_hex();
        Self(format!(
            "{PLACEMENT_ID_PREFIX}{}",
            &hex.as_str()[..DIGEST_HEX_LEN]
        ))
    }

    /// Reconstruct a placement id from its wire representation.
    pub fn from_wire(wire: &str) -> Option<Self> {
        let digest = wire.strip_prefix(PLACEMENT_ID_PREFIX)?;
        if digest.len() == DIGEST_HEX_LEN && digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Some(Self(wire.to_string()))
        } else {
            None
        }
    }

    /// The full wire string, including the versioned `plc_v1_` prefix.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PlacementId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_preserves_and_prefixes() {
        let id = StableId::native(IdKind::Source, "  claude-code  ");
        assert_eq!(id.as_str(), "src_v1_claude-code");
        assert_eq!(id.kind(), IdKind::Source);
        assert_eq!(id.stability(), Stability::Native);
    }

    #[test]
    fn native_strips_control_characters_and_clamps_oversized_suffixes() {
        // 控制字符(换行/DEL/BEL)会破坏日志与 JSON,必须剥离。
        let control = StableId::native(IdKind::Message, "ab\nc\u{7f}d\u{0007}e");
        assert_eq!(control.as_str(), "msg_v1_abcde");
        assert!(control.validate());

        // 超长 native id 截断到上限;已知 provider id 都远短于此。
        let oversized = StableId::native(IdKind::Message, &"x".repeat(300));
        assert_eq!(
            oversized.as_str().len(),
            "msg_v1_".len() + NATIVE_SUFFIX_MAX_CHARS
        );
        assert!(oversized.validate());
    }

    #[test]
    fn scoped_session_native_ids_namespace_by_provider_and_installation() {
        let ns = SessionIdentityNamespace {
            provider_id: "claude-code",
            installation_namespace: "install-a",
        };
        let other_provider = SessionIdentityNamespace {
            provider_id: "codex",
            installation_namespace: "install-a",
        };
        let other_install = SessionIdentityNamespace {
            provider_id: "claude-code",
            installation_namespace: "install-b",
        };

        let base = StableId::native_session_scoped(&ns, "session-123");

        // 同 native id + 不同 provider → 不同 canonical session id。
        assert_ne!(
            base,
            StableId::native_session_scoped(&other_provider, "session-123")
        );
        // 同 provider + 不同 installation → 不同 canonical session id。
        assert_ne!(
            base,
            StableId::native_session_scoped(&other_install, "session-123")
        );

        // wire 前缀仍是 ses_v1_;类型、稳定性、digest 长度均正确。
        assert!(base.as_str().starts_with("ses_v1_"));
        assert_eq!(base.as_str().len(), "ses_v1_".len() + DIGEST_HEX_LEN);
        assert_eq!(base.kind(), IdKind::Session);
        assert_eq!(base.stability(), Stability::Native);
        assert!(base.validate());

        // 命名空间与 native id 被哈希吸收,不是 verbatim 采纳的
        // `ses_v1_session-123` 形态。
        assert_ne!(base.as_str(), "ses_v1_session-123");
        // 且均不可从 wire 反推(digest 只含 0-9a-f)。
        assert!(!base.as_str().contains("session-123"));
        assert!(!base.as_str().contains("claude-code"));
        assert!(!base.as_str().contains("install-a"));
    }

    #[test]
    fn scoped_session_native_ids_are_deterministic() {
        let ns = SessionIdentityNamespace {
            provider_id: "claude-code",
            installation_namespace: "install-a",
        };
        let a = StableId::native_session_scoped(&ns, "session-123");
        let b = StableId::native_session_scoped(&ns, "session-123");
        // 同 provider + installation + native id → 确定性一致。
        assert_eq!(a, b);
        // 同命名空间下不同 native id → 不同 id。
        assert_ne!(a, StableId::native_session_scoped(&ns, "session-124"));
    }

    #[test]
    fn scoped_session_native_id_wire_roundtrip() {
        let ns = SessionIdentityNamespace {
            provider_id: "claude-code",
            installation_namespace: "install-a",
        };
        let original = StableId::native_session_scoped(&ns, "session-123");
        let reparsed = StableId::from_wire(original.as_str()).unwrap();
        // Value(catalog 查找键)原样保留,kind 从前缀恢复。
        assert_eq!(reparsed.as_str(), original.as_str());
        assert_eq!(reparsed.kind(), IdKind::Session);
        // Stability 不在 wire 上。
        assert_eq!(reparsed.stability(), Stability::Unstable);
    }

    #[test]
    fn derive_is_deterministic() {
        let a = StableId::derive(
            IdKind::Session,
            Stability::Reconstructed,
            &[b"claude", b"2026-07-21T00:00:00Z"],
        );
        let b = StableId::derive(
            IdKind::Session,
            Stability::Reconstructed,
            &[b"claude", b"2026-07-21T00:00:00Z"],
        );
        assert_eq!(a, b);
        assert!(a.as_str().starts_with("ses_v1_"));
    }

    #[test]
    fn framing_prevents_boundary_collision() {
        let a = StableId::derive(IdKind::Message, Stability::Reconstructed, &[b"a", b"bc"]);
        let b = StableId::derive(IdKind::Message, Stability::Reconstructed, &[b"ab", b"c"]);
        assert_ne!(a, b);
    }

    #[test]
    fn kind_domain_separation() {
        let s = StableId::derive(IdKind::Session, Stability::Reconstructed, &[b"x"]);
        let m = StableId::derive(IdKind::Message, Stability::Reconstructed, &[b"x"]);
        assert_ne!(s.as_str()[7..].to_string(), m.as_str()[7..].to_string());
    }

    #[test]
    fn derived_digest_length() {
        let id = StableId::derive(IdKind::Document, Stability::Reconstructed, &[b"doc"]);
        assert_eq!(id.as_str().len(), "doc_v1_".len() + DIGEST_HEX_LEN);
    }

    #[test]
    fn from_wire_roundtrips_kind_and_value() {
        let original = StableId::derive(IdKind::Message, Stability::Reconstructed, &[b"a", b"b"]);
        let reparsed = StableId::from_wire(original.as_str()).unwrap();
        // Value (the catalog lookup key) is preserved exactly, so the round-trip
        // resolves the same stored entity.
        assert_eq!(reparsed.as_str(), original.as_str());
        assert_eq!(reparsed.kind(), IdKind::Message);
        // Stability is not on the wire; a reconstructed id is always Unstable.
        assert_eq!(reparsed.stability(), Stability::Unstable);
    }

    #[test]
    fn from_wire_rejects_unknown_prefix() {
        assert!(StableId::from_wire("bogus_v1_deadbeef").is_none());
        assert!(StableId::from_wire("").is_none());
    }

    #[test]
    fn from_wire_rejects_bare_prefix_with_empty_suffix() {
        // 裸前缀不是合法 id——与 validate() 的结论一致(空 adopted 后缀)。
        assert!(StableId::from_wire("msg_v1_").is_none());
        assert!(StableId::from_wire("ses_v1_").is_none());
        assert!(StableId::from_wire("doc_v1_").is_none());
        assert!(StableId::from_wire("src_v1_").is_none());
        // 非空后缀(含 native 形态)仍可反解。
        assert!(StableId::from_wire("msg_v1_legacy").is_some());
    }

    #[test]
    fn placement_id_is_deterministic_and_path_independent() {
        let session = StableId::derive(IdKind::Session, Stability::Reconstructed, &[b"session"]);
        let document = StableId::derive(
            IdKind::Document,
            Stability::Reconstructed,
            &[b"document-bytes"],
        );
        let message = StableId::native(IdKind::Message, "native-message");

        let at_original_path = PlacementId::derive(&session, &document, &message, 7);
        let after_source_move = PlacementId::derive(&session, &document, &message, 7);

        assert_eq!(at_original_path, after_source_move);
        assert!(at_original_path.as_str().starts_with("plc_v1_"));
        assert_eq!(
            at_original_path.as_str().len(),
            PLACEMENT_ID_PREFIX.len() + DIGEST_HEX_LEN
        );
    }

    #[test]
    fn placement_id_changes_with_each_identity_component() {
        let session = StableId::derive(IdKind::Session, Stability::Reconstructed, &[b"session"]);
        let other_session = StableId::derive(
            IdKind::Session,
            Stability::Reconstructed,
            &[b"other-session"],
        );
        let document = StableId::derive(IdKind::Document, Stability::Reconstructed, &[b"document"]);
        let other_document = StableId::derive(
            IdKind::Document,
            Stability::Reconstructed,
            &[b"other-document"],
        );
        let message = StableId::native(IdKind::Message, "message");
        let other_message = StableId::native(IdKind::Message, "other-message");
        let base = PlacementId::derive(&session, &document, &message, 1);

        assert_ne!(
            base,
            PlacementId::derive(&other_session, &document, &message, 1)
        );
        assert_ne!(
            base,
            PlacementId::derive(&session, &other_document, &message, 1)
        );
        assert_ne!(
            base,
            PlacementId::derive(&session, &document, &other_message, 1)
        );
        assert_ne!(base, PlacementId::derive(&session, &document, &message, 2));
    }

    #[test]
    fn placement_id_wire_roundtrip_is_strict() {
        let session = StableId::native(IdKind::Session, "session");
        let document = StableId::native(IdKind::Document, "document");
        let message = StableId::native(IdKind::Message, "message");
        let original = PlacementId::derive(&session, &document, &message, 0);

        assert_eq!(
            PlacementId::from_wire(original.as_str()).as_ref(),
            Some(&original)
        );
        assert!(PlacementId::from_wire("plc_v1_short").is_none());
        assert!(PlacementId::from_wire("plc_v1_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
        assert!(PlacementId::from_wire("msg_v1_00000000000000000000000000000000").is_none());
    }

    // ------------------------------------------------------------------
    // Provider-scoped identity migration plan (schema v13, deferred):
    // test-local mirrors of the proposed `ses_v2_` derivation,
    // namespace-key normalization, and TTL alias resolution.
    // Production code is deliberately untouched — `native_session_scoped`
    // keeps emitting `ses_v1_` until the migration lands. These pure
    // functions pin the plan's determinism/reversibility properties
    // before any schema or wire change ships.
    // ------------------------------------------------------------------

    /// Proposed `ses_v2_` scoped-session wire prefix — the format bump that
    /// `IdKind` documents: a changed hashing scheme bumps `_v1_` → `_v2_`
    /// and both coexist during migration.
    const SESSION_V2_PREFIX: &str = "ses_v2_";

    /// Proposed v2 derivation: digest of
    /// `(provider_id, installation_namespace_key, native_session_id)`,
    /// domain-separated by the `ses_v2_` prefix and length-prefix framed
    /// exactly like [`StableId::derive`]. The prefix doubles as the domain
    /// separator, so identical facts can never produce a v1 digest.
    fn session_v2_wire(
        provider_id: &str,
        installation_namespace_key: &str,
        native_session_id: &str,
    ) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(SESSION_V2_PREFIX.as_bytes());
        for fact in [
            provider_id.as_bytes(),
            installation_namespace_key.as_bytes(),
            native_session_id.as_bytes(),
        ] {
            hasher.update(&(fact.len() as u64).to_le_bytes());
            hasher.update(fact);
        }
        let hex = hasher.finalize().to_hex();
        format!("{SESSION_V2_PREFIX}{}", &hex.as_str()[..DIGEST_HEX_LEN])
    }

    /// Proposed registry-key derivation: composition-root rule (last
    /// provider data-root marker) plus the Windows path-case normalization
    /// the migration adds (`windows` lowercases the whole key; non-Windows
    /// keeps the spelling). Production `installation_namespace` in
    /// `crates/agent-session-grep-cli/src/main.rs` lacks the normalization
    /// today — that is the known debt this mirror fixes ahead of time.
    fn namespace_key(path: &str, provider_id: &str, windows: bool) -> String {
        let folded = path.replace('\\', "/");
        let normalized = if windows {
            folded.to_ascii_lowercase()
        } else {
            folded
        };
        let marker = match provider_id {
            "claude-code" => ".claude",
            "codex" => ".codex",
            _ => "",
        };
        let segments: Vec<&str> = normalized.split('/').filter(|s| !s.is_empty()).collect();
        let root = if !marker.is_empty()
            && let Some(index) = segments.iter().rposition(|s| *s == marker)
        {
            segments[..=index].join("/")
        } else {
            match segments.split_last() {
                Some((_, parent)) if !parent.is_empty() => parent.join("/"),
                _ => ".".to_string(),
            }
        };
        format!("{provider_id}:{root}")
    }

    /// What alias resolution decided for a legacy `ses_v1_*` wire id.
    #[derive(Debug, PartialEq, Eq)]
    enum LegacyResolution {
        /// No rewrite exists: the legacy id stays the lookup key.
        KeepLegacy(String),
        /// Exactly one live alias: resolve the legacy id to this wire id.
        Rewritten(String),
        /// Multiple distinct live targets: fail closed, disclose nothing.
        Conflict,
    }

    /// Proposed `id_alias` row as read back from storage.
    struct AliasRow {
        new_id: String,
        expires_at_ms: u64,
    }

    /// Proposed resolution of a legacy id against its alias rows at `now`.
    ///
    /// Deterministic and total:
    /// - no live rows → `KeepLegacy` (legacy ids stay valid/searchable);
    /// - exactly one live distinct target → `Rewritten`;
    /// - identity rows (`new_id == old_id`) mark "not yet rewritten" →
    ///   `KeepLegacy`;
    /// - two or more live distinct targets → `Conflict` (never pick by
    ///   path, order, or value);
    /// - expiry is `now >= expires_at_ms` (half-open; the boundary is
    ///   expired), and expired rows are filtered before conflict detection.
    fn resolve_legacy(legacy: &str, rows: &[AliasRow], now_ms: u64) -> LegacyResolution {
        let mut live: Vec<&str> = rows
            .iter()
            .filter(|row| now_ms < row.expires_at_ms)
            .map(|row| row.new_id.as_str())
            .collect();
        live.sort_unstable();
        live.dedup();
        match live.as_slice() {
            [] => LegacyResolution::KeepLegacy(legacy.to_string()),
            [only] if *only == legacy => LegacyResolution::KeepLegacy(legacy.to_string()),
            [only] => LegacyResolution::Rewritten((*only).to_string()),
            _ => LegacyResolution::Conflict,
        }
    }

    /// Proposed extension of [`StableId::from_wire`]: recover the kind
    /// version from the `ses_v2_` prefix and preserve the value exactly
    /// (catalog lookups key on the preserved wire string).
    fn session_v2_from_wire(wire: &str) -> Option<&str> {
        wire.strip_prefix(SESSION_V2_PREFIX)
            .filter(|suffix| !suffix.is_empty())
    }

    #[test]
    fn v2_scoped_wire_is_deterministic_and_namespaced() {
        let key = "claude-code:c:/profiles/one/.claude";
        let a = session_v2_wire("claude-code", key, "session-123");
        let b = session_v2_wire("claude-code", key, "session-123");
        assert_eq!(a, b);

        // 任一身份轴变化 → 不同 id;digest 只含 hex。
        assert_ne!(a, session_v2_wire("codex", key, "session-123"));
        assert_ne!(
            a,
            session_v2_wire(
                "claude-code",
                "claude-code:d:/profiles/two/.claude",
                "session-123"
            )
        );
        assert_ne!(a, session_v2_wire("claude-code", key, "session-124"));
        assert!(a.starts_with(SESSION_V2_PREFIX));
        assert_eq!(a.len(), SESSION_V2_PREFIX.len() + DIGEST_HEX_LEN);
        assert!(
            a[SESSION_V2_PREFIX.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        );
    }

    #[test]
    fn v2_scoped_wire_never_collides_with_v1_for_identical_facts() {
        let key = "claude-code:c:/profiles/one/.claude";
        let v1 = StableId::native_session_scoped(
            &SessionIdentityNamespace {
                provider_id: "claude-code",
                installation_namespace: key,
            },
            "session-123",
        );
        let v2 = session_v2_wire("claude-code", key, "session-123");
        // 前缀 bump 即域分隔:相同事实在 v1/v2 方案下得到不同 digest。
        assert_ne!(v1.as_str(), v2);
        assert!(v1.as_str().starts_with("ses_v1_"));
        assert!(v2.starts_with("ses_v2_"));
    }

    #[test]
    fn v2_scoped_wire_hides_namespace_and_native_id() {
        let wire = session_v2_wire(
            "claude-code",
            "claude-code:c:/profiles/one/.claude",
            "session-123",
        );
        // 与 v1 契约一致:无反向派生路径——wire 不携带 provider、命名空间
        // 或 native id 的任何可恢复成分。
        assert!(!wire.contains("claude-code"));
        assert!(!wire.contains("profiles"));
        assert!(!wire.contains("session-123"));
    }

    #[test]
    fn v2_scoped_wire_roundtrip_preserves_value() {
        let wire = session_v2_wire("claude-code", "claude-code:c:/profiles/one/.claude", "s");
        let parsed = session_v2_from_wire(&wire).unwrap();
        // wire 自描述:前缀恢复 kind 版本,值原样保留(catalog 查找键不漂移)。
        assert_eq!(format!("{SESSION_V2_PREFIX}{parsed}"), wire);
        assert_eq!(parsed.len(), DIGEST_HEX_LEN);
        // 裸前缀不合法——与 v1 的 from_wire 判定一致。
        assert!(session_v2_from_wire("ses_v2_").is_none());
    }

    #[test]
    fn namespace_key_windows_case_variants_collapse() {
        let key = namespace_key(
            "C:/profiles/one/.claude/projects/a.jsonl",
            "claude-code",
            true,
        );
        // 同一安装的 case/分隔符变体 → 同一 key(NTFS 大小写不敏感)。
        assert_eq!(
            key,
            namespace_key(
                "c:\\profiles\\one\\.claude\\projects\\a.jsonl",
                "claude-code",
                true
            )
        );
        // 不同根 → 不同 key。
        assert_ne!(
            key,
            namespace_key(
                "D:/profiles/two/.claude/projects/a.jsonl",
                "claude-code",
                true
            )
        );
        // provider marker 区分安装。
        assert_ne!(
            key,
            namespace_key("C:/profiles/one/.codex/sessions/a.jsonl", "codex", true)
        );
        assert_eq!(key, "claude-code:c:/profiles/one/.claude");
    }

    #[test]
    fn namespace_key_is_deterministic_per_platform_flag() {
        let path = "C:/profiles/one/.claude/projects/a.jsonl";
        assert_eq!(
            namespace_key(path, "claude-code", true),
            namespace_key(path, "claude-code", true)
        );
        // 非 Windows 保留原拼写,分隔符仍归一。
        assert_eq!(
            namespace_key(path, "claude-code", false),
            "claude-code:C:/profiles/one/.claude"
        );
    }

    #[test]
    fn namespace_key_fallback_uses_parent_directory_boundary() {
        // 不在已知数据根下的源:以共同父目录为未知安装边界
        // (与组合根规则一致)。
        assert_eq!(
            namespace_key("C:/fixtures/head.jsonl", "synthetic", false),
            "synthetic:C:/fixtures"
        );
    }

    #[test]
    fn alias_resolution_is_deterministic_and_total() {
        let old = "ses_v1_legacy";
        let new = "ses_v2_00000000000000000000000000000000";
        let now = 1_000;

        // 无别名行 → 旧 id 保持有效(共存)。
        assert_eq!(
            resolve_legacy(old, &[], now),
            LegacyResolution::KeepLegacy(old.into())
        );
        // 单一未过期行 → 重写目标,且重复解析一致(确定性)。
        let rows = [AliasRow {
            new_id: new.into(),
            expires_at_ms: now + 500,
        }];
        assert_eq!(
            resolve_legacy(old, &rows, now),
            LegacyResolution::Rewritten(new.into())
        );
        assert_eq!(
            resolve_legacy(old, &rows, now),
            resolve_legacy(old, &rows, now)
        );
        // 同一目标的重复行 → 去重后仍唯一,不误判冲突。
        let dupes = [
            AliasRow {
                new_id: new.into(),
                expires_at_ms: now + 500,
            },
            AliasRow {
                new_id: new.into(),
                expires_at_ms: now + 900,
            },
        ];
        assert_eq!(
            resolve_legacy(old, &dupes, now),
            LegacyResolution::Rewritten(new.into())
        );
    }

    #[test]
    fn alias_resolution_ttl_boundary_is_half_open() {
        let old = "ses_v1_legacy";
        let new = "ses_v2_00000000000000000000000000000000";
        let rows = [AliasRow {
            new_id: new.into(),
            expires_at_ms: 1_000,
        }];
        // 恰在过期时刻 → 已过期(半开区间)→ 回退旧 id。
        assert_eq!(
            resolve_legacy(old, &rows, 1_000),
            LegacyResolution::KeepLegacy(old.into())
        );
        assert_eq!(
            resolve_legacy(old, &rows, 999),
            LegacyResolution::Rewritten(new.into())
        );
    }

    #[test]
    fn alias_resolution_identity_marker_means_not_rewritten() {
        // 设计契约:不可解析根(legacy 绝对路径)保持 ses_v1_*,写 identity
        // 行(old→old)+ 短 TTL 作为"待重写"标记。
        let old = "ses_v1_legacy";
        let rows = [AliasRow {
            new_id: old.into(),
            expires_at_ms: 1_000,
        }];
        assert_eq!(
            resolve_legacy(old, &rows, 900),
            LegacyResolution::KeepLegacy(old.into())
        );
    }

    #[test]
    fn alias_resolution_conflicting_targets_fail_closed() {
        // 多-ID 分裂:旧 id 解析到多个不同 v2 目标 → Conflict,绝不按路径/
        // 顺序/值猜选,不披露冲突值。
        let old = "ses_v1_legacy";
        let rows = [
            AliasRow {
                new_id: "ses_v2_00000000000000000000000000000000".into(),
                expires_at_ms: 2_000,
            },
            AliasRow {
                new_id: "ses_v2_11111111111111111111111111111111".into(),
                expires_at_ms: 2_000,
            },
        ];
        assert_eq!(
            resolve_legacy(old, &rows, 1_000),
            LegacyResolution::Conflict
        );
        // 其中一个过期 → 只剩一个 live 目标 → 不再冲突(过期行先滤除)。
        let one_expired = [
            AliasRow {
                new_id: "ses_v2_00000000000000000000000000000000".into(),
                expires_at_ms: 900,
            },
            AliasRow {
                new_id: "ses_v2_11111111111111111111111111111111".into(),
                expires_at_ms: 2_000,
            },
        ];
        assert_eq!(
            resolve_legacy(old, &one_expired, 1_000),
            LegacyResolution::Rewritten("ses_v2_11111111111111111111111111111111".into())
        );
    }

    #[test]
    fn alias_mapping_is_one_directional_by_design() {
        // 可逆性仅存在于 wire round-trip;alias 有意单向(old→new):新 id 是
        // digest,不可能恢复旧 native id。
        let old = "ses_v1_legacy-session";
        let new = session_v2_wire(
            "claude-code",
            "claude-code:c:/profiles/one/.claude",
            "legacy-session",
        );
        let rows = [AliasRow {
            new_id: new.clone(),
            expires_at_ms: 2_000,
        }];
        assert_eq!(
            resolve_legacy(old, &rows, 1_000),
            LegacyResolution::Rewritten(new.clone())
        );
        assert!(!new.contains("legacy"));
    }

    #[test]
    fn placement_rederivation_after_session_rewrite_is_deterministic() {
        // 计划关键发现:PlacementId 哈希会话 wire,会话 id 从 ses_v1_ 改写为
        // ses_v2_ 后,每个 placement id 都必须机械重派生。重派生是
        // (session, document, message, ordinal) 的纯函数——确定性。
        let document = StableId::native(IdKind::Document, "document");
        let message = StableId::native(IdKind::Message, "message");
        let v1 = StableId::native(IdKind::Session, "legacy-session");
        let v2 = session_v2_wire(
            "claude-code",
            "claude-code:c:/profiles/one/.claude",
            "legacy-session",
        );
        let v2_id = StableId {
            kind: IdKind::Session,
            stability: Stability::Native,
            value: v2,
        };

        let before = PlacementId::derive(&v1, &document, &message, 3);
        let after = PlacementId::derive(&v2_id, &document, &message, 3);
        assert_ne!(before, after);
        assert_eq!(after, PlacementId::derive(&v2_id, &document, &message, 3));
    }
}
