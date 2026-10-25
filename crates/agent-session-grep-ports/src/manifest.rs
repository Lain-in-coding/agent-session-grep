//! Structured provider adapter declarations required by RFC-0002 §6.

use crate::capability::{ProviderCapability, ProviderCapabilityMatrix, ProviderMaturity};

/// How an adapter consumes a provider source in production (RFC-0002 §7 bounded
/// ingestion). The manifest declares the mode so limits are honest and machine
/// readable instead of an implicit implementation detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamingSupport {
    /// The source is parsed incrementally by record, including decoded records
    /// from bounded compressed streams. `max_record_size` bounds record buffers;
    /// compressed-input, decoded-total and decoder-window limits remain explicit
    /// adapter limitations rather than a claim of whole-source buffering.
    RecordStream,
    /// The format requires a complete payload (whole-document JSON, Markdown,
    /// SQLite); production reads are hard-capped by `max_source_size`.
    BoundedWholeSource,
}

/// Maximum one-line/record allocation for streaming text adapters (8 MiB).
pub const STREAM_RECORD_MAX_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum complete JSON-family (JSON array / JSONL fallback) or Markdown
/// source accepted by whole-document adapters (32 MiB).
pub const JSON_FAMILY_MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum SQLite source copied through the bounded whole-source path (128 MiB).
pub const SQLITE_MAX_SOURCE_BYTES: u64 = 128 * 1024 * 1024;
/// ZCode logical graph images have a separate 256 MiB source ceiling. This does
/// not widen the generic SQLite snapshot or any other provider's accepted input.
pub const ZCODE_MAX_SOURCE_BYTES: u64 = 256 * 1024 * 1024;

/// Machine-readable metadata for one implemented provider adapter.
///
/// The capability row, provider id, current maturity, and current variant are
/// projected from [`ProviderCapabilityMatrix::current`] by [`manifest_for`].
/// Adapters supply only evidence that is not part of the capability matrix.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AdapterManifest {
    /// Canonical provider id.
    pub provider_id: String,
    /// Variants supported by this adapter implementation.
    pub supported_variants: Vec<String>,
    /// Current evidence-backed maturity, independent from target maturity.
    pub maturity: ProviderMaturity,
    /// Authoritative per-field capability row for this provider.
    pub capabilities: ProviderCapability,
    /// Revision supplied by an adapter from its synthetic/golden fixture
    /// provenance, if one exists. Registration never invents this evidence.
    pub fixture_revision: Option<u32>,
    /// Named targets from successful certification workflow runs.
    pub last_certified_targets: Vec<String>,
    /// Concise, user-relevant limits of the current adapter implementation.
    pub known_limitations: Vec<String>,
    /// Production source-consumption mode for the supported variant.
    pub streaming_support: StreamingSupport,
    /// Maximum accepted source size when the format requires whole-source
    /// parsing (`BoundedWholeSource`). `None` means total size is not the
    /// memory bound (record streaming).
    pub max_source_size: Option<u64>,
    /// Maximum in-memory record/line size for streaming text variants
    /// (`RecordStream`). `None` for whole-source adapters.
    pub max_record_size: Option<u64>,
}

/// Classify each implemented adapter by its source format. This is the single
/// source of truth for the manifest's streaming/limit fields; adapters must not
/// override the mode per-instance (the format is a property of the provider).
fn source_consumption(provider_id: &str) -> (StreamingSupport, Option<u64>, Option<u64>) {
    match provider_id {
        // Whole-document JSON arrays (cline api-conversation-history, hermes
        // session JSON) and Markdown (aider chat history): the parser needs the
        // complete document, so production reads carry an honest hard cap.
        "cline" | "hermes" | "aider" => (
            StreamingSupport::BoundedWholeSource,
            Some(JSON_FAMILY_MAX_SOURCE_BYTES),
            None,
        ),
        // SQLite databases (opencode.db, cursor vscdb) are buffered whole and
        // parsed read-only; the copy is hard-capped rather than unbounded.
        "opencode" | "cursor" => (
            StreamingSupport::BoundedWholeSource,
            Some(SQLITE_MAX_SOURCE_BYTES),
            None,
        ),
        // ZCode's separately bounded session/message/part graph does not widen
        // the generic SQLite source path.
        "zcode" => (
            StreamingSupport::BoundedWholeSource,
            Some(ZCODE_MAX_SOURCE_BYTES),
            None,
        ),
        // WorkBuddy JSONL and DSH decoded v4 records stream just as JSONL does;
        // DSH additionally declares input/decoded/window bounds in limitations.
        _ => (
            StreamingSupport::RecordStream,
            None,
            Some(STREAM_RECORD_MAX_BYTES),
        ),
    }
}

/// Build an adapter manifest from the authoritative capability matrix row.
///
/// This intentionally has no unknown-provider fallback: every implemented
/// adapter must have an explicit matrix row before it can expose a manifest.
pub fn manifest_for(
    provider_id: &str,
    fixture_revision: Option<u32>,
    known_limitations: &[&str],
) -> AdapterManifest {
    let capabilities = ProviderCapabilityMatrix::current()
        .providers
        .into_iter()
        .find(|capability| capability.provider_id == provider_id)
        .unwrap_or_else(|| panic!("provider `{provider_id}` has no capability matrix entry"));
    let supported_variants = if capabilities.variant_id.is_empty() {
        Vec::new()
    } else {
        vec![capabilities.variant_id.clone()]
    };
    let (streaming_support, max_source_size, max_record_size) =
        source_consumption(&capabilities.provider_id);

    AdapterManifest {
        provider_id: capabilities.provider_id.clone(),
        supported_variants,
        maturity: capabilities.maturity,
        capabilities,
        fixture_revision,
        last_certified_targets: Vec::new(),
        known_limitations: known_limitations
            .iter()
            .map(|limitation| (*limitation).to_string())
            .collect(),
        streaming_support,
        max_source_size,
        max_record_size,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IMPLEMENTED_PROVIDERS: [&str; 17] = [
        "claude-code",
        "codex",
        "grok-build",
        "antigravity",
        "opencode",
        "pi",
        "hermes",
        "cursor",
        "kimi-code",
        "openclaw",
        "qoder",
        "tencent-codebuddy",
        "cline",
        "aider",
        "workbuddy",
        "zcode",
        "deepseek-harness",
    ];

    #[test]
    fn implemented_manifests_match_authoritative_capability_rows() {
        let matrix = ProviderCapabilityMatrix::current();
        let registered: std::collections::BTreeSet<_> = matrix
            .providers
            .iter()
            .filter(|row| row.maturity != ProviderMaturity::Unsupported)
            .map(|row| row.provider_id.as_str())
            .collect();
        assert_eq!(
            registered,
            IMPLEMENTED_PROVIDERS.into_iter().collect(),
            "manifest tests must cover every implemented matrix row"
        );

        for provider_id in IMPLEMENTED_PROVIDERS {
            let manifest = manifest_for(provider_id, None, &[]);
            let capability = matrix
                .find(provider_id)
                .unwrap_or_else(|| panic!("missing matrix row for {provider_id}"));

            assert_eq!(manifest.provider_id, capability.provider_id);
            assert_eq!(
                manifest.supported_variants.as_slice(),
                std::slice::from_ref(&capability.variant_id)
            );
            assert_eq!(manifest.maturity, capability.maturity);
            assert_eq!(&manifest.capabilities, capability);
            assert_eq!(manifest.maturity, ProviderMaturity::Experimental);
            assert!(manifest.last_certified_targets.is_empty());
            // Every implemented adapter declares a bounded ingestion mode and
            // exactly one matching limit (record cap for streaming, source cap
            // for whole-source formats) — RFC-0002 §7 honesty, never unbounded.
            match manifest.streaming_support {
                StreamingSupport::RecordStream => {
                    assert!(
                        manifest.max_record_size.is_some() && manifest.max_source_size.is_none(),
                        "{provider_id}: record stream must declare max_record_size only"
                    );
                }
                StreamingSupport::BoundedWholeSource => {
                    assert!(
                        manifest.max_source_size.is_some() && manifest.max_record_size.is_none(),
                        "{provider_id}: whole source must declare max_source_size only"
                    );
                }
            }
        }
    }

    #[test]
    fn source_consumption_classifies_formats_honestly() {
        // JSONL transcripts stream records; whole-document JSON/Markdown/SQLite
        // carry an explicit hard cap. This is the release-blocking RFC-0002 §7
        // honesty contract: no adapter may silently claim streaming while its
        // parser needs the complete source.
        for provider_id in IMPLEMENTED_PROVIDERS {
            let manifest = manifest_for(provider_id, None, &[]);
            let line_based = matches!(
                provider_id,
                "claude-code"
                    | "codex"
                    | "grok-build"
                    | "antigravity"
                    | "pi"
                    | "kimi-code"
                    | "openclaw"
                    | "qoder"
                    | "tencent-codebuddy"
                    | "workbuddy"
                    | "deepseek-harness"
            );
            assert_eq!(
                manifest.streaming_support,
                if line_based {
                    StreamingSupport::RecordStream
                } else {
                    StreamingSupport::BoundedWholeSource
                },
                "{provider_id}"
            );
        }
    }

    #[test]
    fn fixture_revision_is_never_inferred_from_provider_registration() {
        // The actual adapter's revision is checked with its provenance by the
        // CLI matrix suite. Ports cannot fabricate one from a provider name.
        for provider_id in IMPLEMENTED_PROVIDERS {
            let manifest = manifest_for(provider_id, None, &[]);
            assert_eq!(manifest.fixture_revision, None, "{provider_id}");
        }
    }

    #[test]
    fn zcode_source_limit_does_not_widen_generic_sqlite_or_record_streams() {
        assert_eq!(SQLITE_MAX_SOURCE_BYTES, 128 * 1024 * 1024);
        assert_eq!(ZCODE_MAX_SOURCE_BYTES, 256 * 1024 * 1024);
        for (id, limit) in [
            ("opencode", SQLITE_MAX_SOURCE_BYTES),
            ("cursor", SQLITE_MAX_SOURCE_BYTES),
            ("zcode", ZCODE_MAX_SOURCE_BYTES),
        ] {
            let manifest = manifest_for(id, None, &[]);
            assert_eq!(
                manifest.streaming_support,
                StreamingSupport::BoundedWholeSource
            );
            assert_eq!(manifest.max_source_size, Some(limit), "{id}");
            assert_eq!(manifest.max_record_size, None, "{id}");
        }
        for id in ["workbuddy", "deepseek-harness"] {
            let manifest = manifest_for(id, None, &[]);
            assert_eq!(manifest.streaming_support, StreamingSupport::RecordStream);
            assert_eq!(manifest.max_source_size, None, "{id}");
            assert_eq!(
                manifest.max_record_size,
                Some(STREAM_RECORD_MAX_BYTES),
                "{id}"
            );
        }
    }

    #[test]
    fn json_serialization_contains_every_rfc_field() {
        let manifest = manifest_for(
            "claude-code",
            Some(1),
            &["tool activity extraction is partial"],
        );
        let json = serde_json::to_value(&manifest).expect("manifest must serialize");

        for field in [
            "provider_id",
            "supported_variants",
            "maturity",
            "capabilities",
            "fixture_revision",
            "last_certified_targets",
            "known_limitations",
            "streaming_support",
            "max_source_size",
            "max_record_size",
        ] {
            assert!(json.get(field).is_some(), "missing JSON field `{field}`");
        }

        let round_trip: AdapterManifest =
            serde_json::from_value(json).expect("manifest must deserialize");
        assert_eq!(round_trip, manifest);
    }
}
