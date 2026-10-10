//! Pure policy for explicit installation relocation.
//!
//! Callers supply catalog facts and time. This module performs no filesystem
//! access, storage writes or clock reads. A plan is a bounded freshness check,
//! not an authentication credential; its claims contain only digests and scalars.

use agent_session_grep_ports::relocation::{
    MAX_PLAN_TOKEN_BYTES, PLAN_TTL_MS, validate_alias_ttl_days,
};
use agent_session_grep_ports::{PortError, PortResult};
use serde::{Deserialize, Serialize};

use crate::cursor::{base64url_decode, base64url_encode};

/// Version of the relocation plan wire contract, independent of cursor tokens.
pub const PLAN_FORMAT_VERSION: u32 = 1;
const PLAN_DIGEST_DOMAIN: &[u8] = b"asg-relocation-plan-v1\0";
const DIGEST_HEX_LEN: usize = 64;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const MAX_PATH_BYTES: usize = 128 * 1024;

/// Verified relocation facts. Private roots, namespace seeds and native IDs
/// must be bound through `mapping_digest`, never carried in the token itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanClaims {
    pub version: u32,
    pub schema_version: u32,
    pub generation: u64,
    pub mapping_digest: String,
    pub alias_ttl_days: u32,
    pub issued_at_ms: i64,
    pub expires_at_ms: i64,
}

/// Issue a plan for a complete adapter-computed mapping digest. That digest
/// must cover normalized roots, provider, ownership and source fingerprints.
pub fn issue_plan(
    schema_version: u32,
    generation: u64,
    mapping_digest: &str,
    alias_ttl_days: u32,
    now_ms: i64,
) -> PortResult<String> {
    validate_plan_inputs(schema_version, mapping_digest, alias_ttl_days)?;
    let expires_at_ms = now_ms
        .checked_add(PLAN_TTL_MS)
        .ok_or_else(|| invalid("relocation plan expiry is outside the supported time range"))?;
    let claims = PlanClaims {
        version: PLAN_FORMAT_VERSION,
        schema_version,
        generation,
        mapping_digest: mapping_digest.to_owned(),
        alias_ttl_days,
        issued_at_ms: now_ms,
        expires_at_ms,
    };
    let payload = serde_json::to_vec(&claims)
        .map_err(|_| PortError::Backend("relocation plan could not be encoded".into()))?;
    Ok(format!(
        "{}.{}",
        base64url_encode(&payload),
        integrity_digest(&payload)
    ))
}

/// Verify integrity and lifetime before comparing catalog facts. Generation
/// changes have their own error even when they also change the mapping digest.
/// Every failure is explicit; callers must not silently create a new plan.
pub fn verify_plan(
    token: &str,
    schema_version: u32,
    generation: u64,
    mapping_digest: &str,
    alias_ttl_days: u32,
    now_ms: i64,
) -> PortResult<PlanClaims> {
    validate_plan_inputs(schema_version, mapping_digest, alias_ttl_days)?;
    let claims = decode_plan(token, now_ms)?;
    if claims.schema_version != schema_version {
        return Err(invalid(
            "relocation plan targets a different schema; preview again",
        ));
    }
    if claims.generation != generation {
        return Err(PortError::GenerationMismatch(
            "catalog changed after relocation preview; preview again".into(),
        ));
    }
    if claims.mapping_digest != mapping_digest || claims.alias_ttl_days != alias_ttl_days {
        return Err(invalid(
            "relocation plan does not match this request; preview again",
        ));
    }
    Ok(claims)
}

/// Verify the bounded token, its scalar contract, integrity and injected-clock
/// lifetime before reading catalog facts. Callers must still check all bindings
/// with `verify_plan`, or validate an exact committed receipt for a replay.
pub fn decode_plan(token: &str, now_ms: i64) -> PortResult<PlanClaims> {
    if token.len() > MAX_PLAN_TOKEN_BYTES {
        return Err(invalid("relocation plan exceeds the supported size"));
    }
    let (encoded, digest) = token
        .split_once('.')
        .ok_or_else(|| invalid("relocation plan has an invalid encoding"))?;
    if !is_digest(digest) {
        return Err(invalid("relocation plan has an invalid integrity digest"));
    }
    let payload = base64url_decode(encoded)
        .ok_or_else(|| invalid("relocation plan has an invalid encoding"))?;
    if base64url_encode(&payload) != encoded || integrity_digest(&payload) != digest {
        return Err(invalid("relocation plan integrity check failed"));
    }
    let claims: PlanClaims = serde_json::from_slice(&payload)
        .map_err(|_| invalid("relocation plan contains invalid claims"))?;
    if claims.version != PLAN_FORMAT_VERSION {
        return Err(invalid(
            "relocation plan version is unsupported; preview again",
        ));
    }
    if claims.issued_at_ms.checked_add(PLAN_TTL_MS) != Some(claims.expires_at_ms)
        || now_ms < claims.issued_at_ms
        || now_ms >= claims.expires_at_ms
    {
        return Err(invalid(
            "relocation plan is outside its validity period; preview again",
        ));
    }
    validate_plan_inputs(
        claims.schema_version,
        &claims.mapping_digest,
        claims.alias_ttl_days,
    )?;
    Ok(claims)
}

/// Calculate alias expiry from the same injected clock used for the operation.
/// Expiry concerns retired locations only, never canonical entity identities.
pub fn alias_expiry_ms(now_ms: i64, alias_ttl_days: u32) -> PortResult<i64> {
    validate_alias_ttl_days(alias_ttl_days).map_err(invalid)?;
    now_ms
        .checked_add(i64::from(alias_ttl_days) * DAY_MS)
        .ok_or_else(|| invalid("relocation alias expiry is outside the supported time range"))
}

fn validate_plan_inputs(
    schema_version: u32,
    mapping_digest: &str,
    alias_ttl_days: u32,
) -> PortResult<()> {
    validate_alias_ttl_days(alias_ttl_days).map_err(invalid)?;
    if schema_version == 0 || !is_digest(mapping_digest) {
        return Err(invalid(
            "relocation plan requires a valid schema and mapping digest",
        ));
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == DIGEST_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn integrity_digest(payload: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(PLAN_DIGEST_DOMAIN);
    hasher.update(payload);
    hasher.finalize().to_hex().to_string()
}

fn invalid(message: &'static str) -> PortError {
    PortError::InvalidRequest(message.into())
}

/// Exact pre-registry namespace derivation. Do not normalize its input or
/// output: historical case, marker lookup and separator handling are identity.
pub fn legacy_installation_namespace(path: &str, provider_id: &str) -> String {
    let marker = installation_marker(provider_id);
    let segments: Vec<&str> = path.split(['/', '\\']).filter(|s| !s.is_empty()).collect();
    if !marker.is_empty()
        && let Some(index) = segments.iter().rposition(|s| *s == marker)
    {
        return format!("{provider_id}:{}", segments[..=index].join("/"));
    }
    let parent = match segments.split_last() {
        Some((_, parent)) if !parent.is_empty() => parent.join("/"),
        _ => ".".to_string(),
    };
    format!("{provider_id}:{parent}")
}

fn installation_marker(provider_id: &str) -> &'static str {
    match provider_id {
        "claude-code" => ".claude",
        "codex" => ".codex",
        _ => "",
    }
}

/// Return a lexical comparison key using the recorded syntax, independent of
/// this host. Windows keys fold ASCII case and separators; Unicode is unchanged.
/// The adapter separately requires a host-local destination and verifies files.
pub fn normalize_absolute_path(path: &str) -> PortResult<String> {
    Ok(AbsolutePath::parse(path)?.key())
}

/// Component-aware containment, including an equal root. A directory named
/// `sessions-old` is not contained in a directory named `sessions`.
pub fn path_is_within(path: &str, root: &str) -> PortResult<bool> {
    Ok(AbsolutePath::parse(path)?.is_within(&AbsolutePath::parse(root)?))
}

/// Reject strict ancestor overlap. Equal normalized roots remain eligible for
/// the adapter's ownership-checked no-op result.
pub fn validate_root_mapping(from: &str, to: &str) -> PortResult<()> {
    validate_mapping(&AbsolutePath::parse(from)?, &AbsolutePath::parse(to)?)
}

/// Map a source under its recorded old root to a new root. Preserve the source
/// suffix's component spelling, including Unicode and ASCII case.
pub fn remap_source_path(source: &str, from: &str, to: &str) -> PortResult<String> {
    let source = AbsolutePath::parse(source)?;
    let from = AbsolutePath::parse(from)?;
    let mut to = AbsolutePath::parse(to)?;
    validate_mapping(&from, &to)?;
    if !source.is_within(&from) {
        return Err(invalid("relocation source is outside the selected root"));
    }
    for component in &source.components[from.components.len()..] {
        validate_component(component, to.is_windows())?;
        to.components.push(component.clone());
    }
    let mapped = to.locator(false);
    if mapped.len() > MAX_PATH_BYTES {
        return Err(invalid("relocation path exceeds the supported size"));
    }
    Ok(mapped)
}

/// Locate a source's installation boundary without reading the filesystem.
/// Marker lookup keeps the exact historical spelling; otherwise use its parent.
/// Returned locators preserve component case and Unicode, not namespace seeds.
pub fn installation_root(path: &str, provider_id: &str) -> PortResult<String> {
    let mut path = AbsolutePath::parse(path)?;
    if path.components.is_empty() {
        return Err(invalid("installation root requires a source path"));
    }
    let marker = installation_marker(provider_id);
    let end = path
        .components
        .iter()
        .rposition(|component| !marker.is_empty() && component == marker)
        .map_or(path.components.len() - 1, |index| index + 1);
    path.components.truncate(end);
    Ok(path.locator(false))
}

#[derive(Debug)]
enum Anchor {
    Posix,
    Drive(String),
    Unc { server: String, share: String },
}

#[derive(Debug)]
struct AbsolutePath {
    anchor: Anchor,
    components: Vec<String>,
    verbatim: bool,
}

impl AbsolutePath {
    fn parse(path: &str) -> PortResult<Self> {
        if path.is_empty() || path.len() > MAX_PATH_BYTES || path.chars().any(char::is_control) {
            return Err(invalid(
                "relocation path is empty, too long or contains control characters",
            ));
        }
        if let Some(rest) = path.strip_prefix(r"\\?\") {
            if rest.contains('/') {
                return Err(invalid("relocation verbatim path has ambiguous separators"));
            }
            if rest
                .get(..4)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(r"UNC\"))
            {
                return Self::unc(&rest[4..], true);
            }
            return Self::drive(rest, true);
        }
        let bytes = path.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Self::drive(path, false);
        }
        if bytes.len() >= 2 && is_separator(bytes[0]) && is_separator(bytes[1]) {
            return Self::unc(&path[2..], false);
        }
        if let Some(rest) = path.strip_prefix('/') {
            return Ok(Self {
                anchor: Anchor::Posix,
                components: parse_components(rest, false)?,
                verbatim: false,
            });
        }
        Err(invalid("relocation requires an unambiguous absolute path"))
    }

    fn drive(path: &str, verbatim: bool) -> PortResult<Self> {
        let bytes = path.as_bytes();
        if bytes.len() < 3
            || !bytes[0].is_ascii_alphabetic()
            || bytes[1] != b':'
            || !is_separator(bytes[2])
        {
            return Err(invalid("relocation requires an absolute drive path"));
        }
        Ok(Self {
            anchor: Anchor::Drive(path[..2].to_owned()),
            components: parse_components(&path[3..], true)?,
            verbatim,
        })
    }

    fn unc(path: &str, verbatim: bool) -> PortResult<Self> {
        if path
            .as_bytes()
            .first()
            .is_some_and(|byte| is_separator(*byte))
        {
            return Err(invalid("relocation UNC path has an ambiguous root"));
        }
        let mut components = parse_components(path, true)?.into_iter();
        let server = components
            .next()
            .ok_or_else(|| invalid("relocation UNC path requires a server and share"))?;
        let share = components
            .next()
            .ok_or_else(|| invalid("relocation UNC path requires a server and share"))?;
        Ok(Self {
            anchor: Anchor::Unc { server, share },
            components: components.collect(),
            verbatim,
        })
    }

    fn is_windows(&self) -> bool {
        !matches!(self.anchor, Anchor::Posix)
    }

    fn is_within(&self, root: &Self) -> bool {
        let same_anchor = match (&self.anchor, &root.anchor) {
            (Anchor::Posix, Anchor::Posix) => true,
            (Anchor::Drive(left), Anchor::Drive(right)) => left.eq_ignore_ascii_case(right),
            (
                Anchor::Unc {
                    server: left_server,
                    share: left_share,
                },
                Anchor::Unc {
                    server: right_server,
                    share: right_share,
                },
            ) => {
                left_server.eq_ignore_ascii_case(right_server)
                    && left_share.eq_ignore_ascii_case(right_share)
            }
            _ => false,
        };
        same_anchor
            && self.components.len() >= root.components.len()
            && self
                .components
                .iter()
                .zip(&root.components)
                .all(|(left, right)| {
                    if self.is_windows() {
                        left.eq_ignore_ascii_case(right)
                    } else {
                        left == right
                    }
                })
    }

    fn key(&self) -> String {
        let mut key = self.locator(true);
        if self.is_windows() {
            key.make_ascii_lowercase();
        }
        key
    }

    fn locator(&self, comparison: bool) -> String {
        let verbatim = self.verbatim && !comparison;
        let separator = if verbatim { '\\' } else { '/' };
        let mut locator = match &self.anchor {
            Anchor::Posix => "/".to_owned(),
            Anchor::Drive(drive) if verbatim => format!(r"\\?\{drive}\"),
            Anchor::Drive(drive) => format!("{drive}/"),
            Anchor::Unc { server, share } if verbatim => format!(r"\\?\UNC\{server}\{share}"),
            Anchor::Unc { server, share } => format!("//{server}/{share}"),
        };
        for component in &self.components {
            if !locator.ends_with(separator) {
                locator.push(separator);
            }
            locator.push_str(component);
        }
        locator
    }
}

fn is_separator(byte: u8) -> bool {
    byte == b'/' || byte == b'\\'
}

fn parse_components(path: &str, windows: bool) -> PortResult<Vec<String>> {
    path.split(|character| character == '/' || (windows && character == '\\'))
        .filter(|component| !component.is_empty())
        .map(|component| {
            validate_component(component, windows)?;
            Ok(component.to_owned())
        })
        .collect()
}

fn validate_component(component: &str, windows: bool) -> PortResult<()> {
    if component == "." || component == ".." {
        return Err(invalid("relocation path cannot contain dot components"));
    }
    if windows
        && (component.ends_with('.')
            || component.ends_with(' ')
            || component.chars().any(|character| {
                matches!(
                    character,
                    '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'
                )
            }))
    {
        return Err(invalid(
            "relocation Windows path contains an ambiguous component",
        ));
    }
    Ok(())
}

fn validate_mapping(from: &AbsolutePath, to: &AbsolutePath) -> PortResult<()> {
    if from.components.len() != to.components.len() && (from.is_within(to) || to.is_within(from)) {
        return Err(invalid("relocation roots cannot have an ancestor overlap"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_session_grep_ports::relocation::DEFAULT_ALIAS_TTL_DAYS;

    const NOW: i64 = 1_000_000;
    const SCHEMA: u32 = 18;
    const GENERATION: u64 = 7;

    fn digest() -> String {
        blake3::hash(b"synthetic relocation ownership and source fingerprints")
            .to_hex()
            .to_string()
    }

    fn plan() -> String {
        issue_plan(SCHEMA, GENERATION, &digest(), DEFAULT_ALIAS_TTL_DAYS, NOW).unwrap()
    }

    fn verify(token: &str, now_ms: i64) -> PortResult<PlanClaims> {
        verify_plan(
            token,
            SCHEMA,
            GENERATION,
            &digest(),
            DEFAULT_ALIAS_TTL_DAYS,
            now_ms,
        )
    }

    fn encode_value(value: &serde_json::Value) -> String {
        let payload = serde_json::to_vec(value).unwrap();
        format!(
            "{}.{}",
            base64url_encode(&payload),
            integrity_digest(&payload)
        )
    }

    fn plan_value() -> serde_json::Value {
        serde_json::to_value(decode_plan(&plan(), NOW).unwrap()).unwrap()
    }

    #[test]
    fn plan_round_trip_binds_catalog_mapping_retention_and_injected_time() {
        let token = plan();
        assert_eq!(token, plan());
        assert!(token.len() < MAX_PLAN_TOKEN_BYTES);
        assert_eq!(
            verify(&token, NOW).unwrap(),
            PlanClaims {
                version: PLAN_FORMAT_VERSION,
                schema_version: SCHEMA,
                generation: GENERATION,
                mapping_digest: digest(),
                alias_ttl_days: DEFAULT_ALIAS_TTL_DAYS,
                issued_at_ms: NOW,
                expires_at_ms: NOW + PLAN_TTL_MS,
            }
        );
    }

    #[test]
    fn plan_payload_contains_only_bounded_scalar_and_digest_fields() {
        let value = plan_value();
        let object = value.as_object().unwrap();
        let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "alias_ttl_days",
                "expires_at_ms",
                "generation",
                "issued_at_ms",
                "mapping_digest",
                "schema_version",
                "version",
            ]
        );
        assert!(object.iter().all(|(key, value)| {
            if key == "mapping_digest" {
                value.as_str().is_some_and(is_digest)
            } else {
                value.is_number()
            }
        }));
        let private_input = "C:/PrivateFixture/installation/native-session";
        let error = issue_plan(SCHEMA, GENERATION, private_input, 90, NOW).unwrap_err();
        assert!(!error.to_string().contains(private_input));
        assert!(matches!(error, PortError::InvalidRequest(_)));
    }

    #[test]
    fn tampered_payload_and_digest_are_rejected() {
        let token = plan();
        let (payload, checksum) = token.split_once('.').unwrap();
        let changed_payload = format!("A{}.{checksum}", &payload[1..]);
        assert!(matches!(
            verify(&changed_payload, NOW),
            Err(PortError::InvalidRequest(_))
        ));
        let changed_checksum = format!("{payload}.{}0", &checksum[..checksum.len() - 1]);
        let changed_checksum = if changed_checksum == token {
            format!("{payload}.{}1", &checksum[..checksum.len() - 1])
        } else {
            changed_checksum
        };
        assert!(matches!(
            verify(&changed_checksum, NOW),
            Err(PortError::InvalidRequest(_))
        ));
    }

    #[test]
    fn plan_expiry_boundary_and_future_issue_time_fail_explicitly() {
        assert!(verify(&plan(), NOW + PLAN_TTL_MS - 1).is_ok());
        for time in [NOW - 1, NOW + PLAN_TTL_MS, NOW + PLAN_TTL_MS + 1] {
            assert!(matches!(
                verify(&plan(), time),
                Err(PortError::InvalidRequest(_))
            ));
        }
        let mut value = plan_value();
        value["expires_at_ms"] = (NOW + PLAN_TTL_MS + 1).into();
        assert!(matches!(
            decode_plan(&encode_value(&value), NOW),
            Err(PortError::InvalidRequest(_))
        ));
    }

    #[test]
    fn generation_mismatch_is_distinct_and_precedes_mapping_mismatch() {
        let other_mapping = blake3::hash(b"changed mapping").to_hex().to_string();
        let result = verify_plan(&plan(), SCHEMA, GENERATION + 1, &other_mapping, 90, NOW);
        assert!(matches!(result, Err(PortError::GenerationMismatch(_))));
        // Receipt verification can inspect a valid plan before comparing the
        // current generation, but still has to validate its committed bindings.
        assert_eq!(decode_plan(&plan(), NOW).unwrap().generation, GENERATION);
    }

    #[test]
    fn changed_schema_mapping_or_retention_never_silently_replans() {
        let token = plan();
        let other_digest = blake3::hash(b"another installation").to_hex().to_string();
        for (schema, mapping, days) in [
            (SCHEMA + 1, digest(), 90),
            (SCHEMA, other_digest, 90),
            (SCHEMA, digest(), 91),
        ] {
            assert!(matches!(
                verify_plan(&token, schema, GENERATION, &mapping, days, NOW),
                Err(PortError::InvalidRequest(_))
            ));
        }
    }

    #[test]
    fn self_consistent_but_unsupported_claims_are_rejected() {
        for (field, replacement) in [
            ("version", serde_json::json!(2)),
            ("schema_version", serde_json::json!(0)),
            ("alias_ttl_days", serde_json::json!(366)),
            ("mapping_digest", serde_json::json!("private-fixture")),
            ("unexpected_root", serde_json::json!("/private-fixture")),
        ] {
            let mut value = plan_value();
            value[field] = replacement;
            let error = decode_plan(&encode_value(&value), NOW).unwrap_err();
            assert!(matches!(error, PortError::InvalidRequest(_)));
            assert!(!error.to_string().contains("private-fixture"));
        }
        assert!(matches!(
            decode_plan(&encode_value(&serde_json::json!([])), NOW),
            Err(PortError::InvalidRequest(_))
        ));
    }

    #[test]
    fn malformed_oversized_or_noncanonical_encodings_are_rejected() {
        for token in ["", "abc", ".", "e30.=", "e30.bad", "not-a-plan"] {
            assert!(matches!(
                decode_plan(token, NOW),
                Err(PortError::InvalidRequest(_))
            ));
        }
        let oversized = "a".repeat(MAX_PLAN_TOKEN_BYTES + 1);
        assert!(matches!(
            decode_plan(&oversized, NOW),
            Err(PortError::InvalidRequest(_))
        ));
        // e30 and e31 both decode to {}, but only e30 has zero unused bits.
        let noncanonical = format!("e31.{}", integrity_digest(b"{}"));
        let error = decode_plan(&noncanonical, NOW).unwrap_err();
        assert!(error.to_string().contains("integrity check failed"));
        // A cursor's domain-separated checksum cannot authorize a relocation.
        let token = crate::cursor::issue(&crate::cursor::CursorClaims {
            contract_major: crate::cursor::SUPPORTED_CONTRACT_MAJOR,
            generation: GENERATION,
            issued_at_ms: NOW,
            expires_at_ms: NOW + PLAN_TTL_MS,
            query_digest: digest(),
            sort_digest: "wire_id_asc".into(),
            result_set: None,
            offset: 0,
        });
        assert!(matches!(
            decode_plan(token.as_str(), NOW),
            Err(PortError::InvalidRequest(_))
        ));
    }

    #[test]
    fn retention_limits_and_clock_overflow_are_checked() {
        for days in [1, DEFAULT_ALIAS_TTL_DAYS, 365] {
            assert_eq!(
                alias_expiry_ms(NOW, days).unwrap(),
                NOW + i64::from(days) * DAY_MS
            );
            assert!(issue_plan(SCHEMA, GENERATION, &digest(), days, NOW).is_ok());
        }
        for days in [0, 366, u32::MAX] {
            assert!(matches!(
                alias_expiry_ms(NOW, days),
                Err(PortError::InvalidRequest(_))
            ));
            assert!(matches!(
                issue_plan(SCHEMA, GENERATION, &digest(), days, NOW),
                Err(PortError::InvalidRequest(_))
            ));
        }
        assert!(issue_plan(SCHEMA, GENERATION, &digest(), 90, i64::MAX).is_err());
        assert!(alias_expiry_ms(i64::MAX, 1).is_err());
        assert_eq!(
            decode_plan(
                &issue_plan(SCHEMA, GENERATION, &digest(), 90, i64::MIN).unwrap(),
                i64::MIN
            )
            .unwrap()
            .expires_at_ms,
            i64::MIN + PLAN_TTL_MS
        );
    }

    #[test]
    fn mapping_digest_requires_full_lowercase_hex() {
        for mapping in [
            "a".repeat(63),
            "a".repeat(65),
            "g".repeat(64),
            "A".repeat(64),
        ] {
            assert!(matches!(
                issue_plan(SCHEMA, GENERATION, &mapping, 90, NOW),
                Err(PortError::InvalidRequest(_))
            ));
        }
    }

    #[test]
    fn windows_keys_fold_ascii_case_and_separators_without_unicode_changes() {
        assert_eq!(
            normalize_absolute_path(r"C:\Archive\会话\É\").unwrap(),
            "c:/archive/会话/É"
        );
        assert_eq!(
            normalize_absolute_path("c:/ARCHIVE//会话/É").unwrap(),
            "c:/archive/会话/É"
        );
        assert_ne!(
            normalize_absolute_path("C:/É").unwrap(),
            normalize_absolute_path("c:/é").unwrap()
        );
        assert_ne!(
            normalize_absolute_path("C:/é").unwrap(),
            normalize_absolute_path("C:/e\u{301}").unwrap()
        );
        assert_eq!(normalize_absolute_path("C:/").unwrap(), "c:/");
    }

    #[test]
    fn posix_paths_preserve_case_and_literal_backslashes() {
        assert_eq!(
            normalize_absolute_path("/Archive//会话/").unwrap(),
            "/Archive/会话"
        );
        assert_ne!(
            normalize_absolute_path("/Archive").unwrap(),
            normalize_absolute_path("/archive").unwrap()
        );
        assert_eq!(
            normalize_absolute_path(r"/Archive/a\b").unwrap(),
            r"/Archive/a\b"
        );
        assert_eq!(normalize_absolute_path("/").unwrap(), "/");
    }

    #[test]
    fn unc_and_unambiguous_verbatim_paths_share_comparison_keys() {
        for path in [
            r"\\Server\Share\Data",
            "//server/SHARE/data",
            r"\\?\UNC\Server\Share\Data",
        ] {
            assert_eq!(
                normalize_absolute_path(path).unwrap(),
                "//server/share/data"
            );
        }
        assert_eq!(
            normalize_absolute_path(r"\\?\C:\Archive\Logs").unwrap(),
            "c:/archive/logs"
        );
        assert_eq!(
            remap_source_path(r"C:\Old\会话\Log.jsonl", "C:/old", r"\\?\D:\New").unwrap(),
            r"\\?\D:\New\会话\Log.jsonl"
        );
        assert!(!path_is_within("//server/other/data", "//server/share").unwrap());
    }

    #[test]
    fn relative_and_ambiguous_paths_fail_without_echoing_private_input() {
        for path in [
            "",
            "fixture/relative",
            "C:fixture",
            r"\fixture",
            "/fixture/./logs",
            "/fixture/../logs",
            r"C:\fixture\..\logs",
            "C:/fixture./logs",
            "C:/fixture /logs",
            "C:/fixture:stream",
            "//server",
            "///fixture/logs",
            r"\\.\fixture\logs",
            r"\\?\C:\fixture/logs",
            "C:/fixture\0/logs",
        ] {
            let error = normalize_absolute_path(path).unwrap_err();
            assert!(matches!(error, PortError::InvalidRequest(_)), "{path:?}");
            assert!(!error.to_string().contains("fixture"), "{error}");
            assert!(error.to_string().len() < 160);
        }
        assert!(normalize_absolute_path(&format!("/{}", "a".repeat(MAX_PATH_BYTES))).is_err());
    }

    #[test]
    fn containment_matches_components_and_recorded_flavor() {
        for (path, root) in [
            ("C:/Archive/Log.jsonl", r"c:\archive"),
            ("/archive/data", "/archive"),
            ("/archive", "/archive/"),
            ("C:/Archive", "c:/"),
            ("/archive", "/"),
        ] {
            assert!(path_is_within(path, root).unwrap(), "{path} under {root}");
        }
        for (path, root) in [
            ("C:/Archive-other/log", "c:/archive"),
            ("/archive2/data", "/archive"),
            ("/Archive/data", "/archive"),
            ("D:/archive/data", "C:/archive"),
            ("C:/archive/data", "/archive"),
        ] {
            assert!(!path_is_within(path, root).unwrap(), "{path} under {root}");
        }
    }

    #[test]
    fn strict_ancestor_overlap_is_refused_in_both_directions() {
        for (from, to) in [
            ("C:/Archive", "c:/archive/new"),
            ("/new/old", "/new"),
            ("C:/", "C:/Archive"),
            ("/", "/Archive"),
        ] {
            assert!(matches!(
                validate_root_mapping(from, to),
                Err(PortError::InvalidRequest(_))
            ));
            assert!(matches!(
                validate_root_mapping(to, from),
                Err(PortError::InvalidRequest(_))
            ));
        }
        for (from, to) in [
            (r"C:\Archive\", "c:/archive"),
            ("/archive", "/archive/"),
            ("/archive", "/archive-other"),
            ("C:/archive", "D:/archive"),
        ] {
            assert!(validate_root_mapping(from, to).is_ok());
        }
    }

    #[test]
    fn remapping_preserves_suffix_case_unicode_and_source_boundaries() {
        assert_eq!(
            remap_source_path(r"C:\Old\数据\KeepCase.JSONL", "c:/old", "D:/New").unwrap(),
            "D:/New/数据/KeepCase.JSONL"
        );
        assert_eq!(
            remap_source_path("/old/数据/KeepCase.JSONL", "/old", "D:/New").unwrap(),
            "D:/New/数据/KeepCase.JSONL"
        );
        assert_eq!(remap_source_path("/old", "/old", "/new").unwrap(), "/new");
        assert!(remap_source_path("/old-other/log", "/old", "/new").is_err());
        assert!(remap_source_path("/old/log", "/old", "/old/new").is_err());
        for source in [r"/old/a\b", "/old/a:b", "/old/a."] {
            assert!(remap_source_path(source, "/old", "C:/New").is_err());
        }
    }

    #[test]
    fn reverse_remapping_is_an_explicit_new_mapping() {
        let original = "C:/Original/项目/Session.jsonl";
        let relocated = remap_source_path(original, "C:/Original", "D:/Moved").unwrap();
        assert_eq!(
            remap_source_path(&relocated, "D:/Moved", "C:/Original").unwrap(),
            original
        );
        assert!(remap_source_path(&relocated, "C:/Original", "D:/Moved").is_err());
    }

    #[test]
    fn legacy_namespace_matches_the_original_cli_strings_exactly() {
        for (path, provider, expected) in [
            (
                r"C:\Archive\.claude\projects\log.jsonl",
                "claude-code",
                "claude-code:C:/Archive/.claude",
            ),
            (
                r"C:\Archive\.CLAUDE\projects\log.jsonl",
                "claude-code",
                "claude-code:C:/Archive/.CLAUDE/projects",
            ),
            (
                "/data/.codex/a/.codex/log.jsonl",
                "codex",
                "codex:data/.codex/a/.codex",
            ),
            ("//data///group/log.jsonl", "cursor", "cursor:data/group"),
            (
                r"\\Server\Share\.claude\log.jsonl",
                "claude-code",
                "claude-code:Server/Share/.claude",
            ),
            (
                r"\\?\C:\Archive\.claude\log.jsonl",
                "claude-code",
                "claude-code:?/C:/Archive/.claude",
            ),
            ("", "codex", "codex:."),
            ("log.jsonl", "codex", "codex:."),
            ("one/two", "codex", "codex:one"),
            (
                "/Data/.claude/x/log.jsonl",
                "claude",
                "claude:Data/.claude/x",
            ),
        ] {
            assert_eq!(legacy_installation_namespace(path, provider), expected);
        }
    }

    #[test]
    fn namespace_seeds_remain_distinct_when_windows_locations_compare_equal() {
        let left = "C:/Archive/.claude/log.jsonl";
        let right = "c:/archive/.claude/log.jsonl";
        assert_eq!(
            normalize_absolute_path(left).unwrap(),
            normalize_absolute_path(right).unwrap()
        );
        assert_ne!(
            legacy_installation_namespace(left, "claude-code"),
            legacy_installation_namespace(right, "claude-code")
        );
    }

    #[test]
    fn installation_root_preserves_spelling_and_legacy_group_boundaries() {
        for (source, provider, expected) in [
            (
                r"C:\Archive\.claude\projects\log.jsonl",
                "claude-code",
                "C:/Archive/.claude",
            ),
            (
                "/Data/.codex/a/.codex/log.jsonl",
                "codex",
                "/Data/.codex/a/.codex",
            ),
            (
                "/Data/Cursor/Workspace/db.sqlite",
                "cursor",
                "/Data/Cursor/Workspace",
            ),
            (
                r"C:\Archive\.CLAUDE\projects\log.jsonl",
                "claude-code",
                "C:/Archive/.CLAUDE/projects",
            ),
            ("/log.jsonl", "cursor", "/"),
            ("C:/log.jsonl", "cursor", "C:/"),
        ] {
            assert_eq!(installation_root(source, provider).unwrap(), expected);
        }
        assert!(installation_root("/", "codex").is_err());
    }
}
