//! CursorToken：自包含、防篡改的分页令牌（CONTRACT-cli-robot-mcp-draft §7 无状态保留模型）。
//!
//! 线格式：`base64url_no_pad(claims JSON) + "." + hex16(blake3("as-cursor-v1" || claims JSON))`。
//! v1 采用无密钥完整性摘要（防篡改、不防伪造）：本地单用户面没有密钥管理设施，
//! 摘要域前缀自带版本（`as-cursor-v1`），将来替换有密钥方案时线形状不变（design §0 偏差 1）。
//!
//! 系统不登记活动 Cursor；令牌自包含 generation、过期时刻与查询/排序摘要。
//! 任何校验失败都显式报错并指示调用方重新发起查询——绝不静默回到第一页。
//! 本模块不读系统时钟：当前时间一律经 [`CursorExpectations::now_ms`] 注入，保证可测。

/// 当前实现支持的合同 major 版本。
pub const SUPPORTED_CONTRACT_MAJOR: u32 = 1;

/// 默认 Cursor 存活时长（毫秒）：15 分钟；调用方据此计算 [`CursorClaims::expires_at_ms`]。
pub const DEFAULT_TTL_MS: i64 = 15 * 60 * 1000;

/// 完整性摘要的域前缀：把摘要绑定到 cursor v1 用途，防跨用途复用；换签名方案时递增版本。
const DIGEST_DOMAIN: &[u8] = b"as-cursor-v1";

/// 摘要长度：blake3 hex 的前 16 位（8 字节）。
const DIGEST_HEX_LEN: usize = 16;

/// Cursor 载荷声明：自包含续读所需的全部状态（CONTRACT §7）。
///
/// `query_digest` / `sort_digest` 把令牌绑定到发行时的查询与排序方案；
/// [`verify`] 对不一致者显式拒绝——换了查询或排序的旧令牌绝不静默复用。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CursorClaims {
    /// 发行时的合同 major；与 [`SUPPORTED_CONTRACT_MAJOR`] 不等即拒绝。
    pub contract_major: u32,
    /// 发行时的活动 generation；数据换代后旧令牌失效（无状态保留模型）。
    pub generation: u64,
    /// 发行时刻（Unix 毫秒）。
    pub issued_at_ms: i64,
    /// 过期时刻（Unix 毫秒）；`now_ms >= expires_at_ms` 即过期。
    pub expires_at_ms: i64,
    /// 规范化查询串的摘要（见 [`digest_query`]；规范化是调用方义务）。
    pub query_digest: String,
    /// 排序方案标识：用例内常量（如 `"wire_id_asc"` / `"score_desc"`）或其摘要，
    /// [`verify`] 只做等值比较。
    pub sort_digest: String,
    /// 结果集判别器（resume-protocol-prerequisites R2）：同一排序标识下不同
    /// 结果序列（如 `list` 全部实体 vs `list_sessions` 仅会话）不得互换续读。
    /// 旧令牌（serde default）为 `None`，与期望带判别器时 fail closed。
    #[serde(default)]
    pub result_set: Option<String>,
    /// 钉住排序内的续读偏移。
    pub offset: u64,
}

/// 不透明分页令牌。唯一合法产地是 [`issue`]；前端只把它当字符串透传。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorToken(String);

impl CursorToken {
    /// 线格式字符串视图（放进 envelope 的 `page.next_cursor`）。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 取回线格式字符串所有权。
    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for CursorToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// [`verify`] 的期望上下文：时间与当前查询状态全部由调用方注入，本模块零环境读取。
#[derive(Debug, Clone)]
pub struct CursorExpectations {
    /// 当前时刻（Unix 毫秒）。
    pub now_ms: i64,
    /// 当前活动 generation。
    pub active_generation: u64,
    /// 本次请求查询串的摘要（与发行侧同一算法，见 [`digest_query`]）。
    pub query_digest: String,
    /// 本次请求的排序方案标识。
    pub sort_digest: String,
    /// 本次请求的结果集判别器；`None` 表示该用例不区分结果集。
    pub result_set: Option<String>,
}

/// Cursor 校验错误。每条消息都指示调用方去掉 cursor 重新发起查询——
/// 静默从第一页继续是合同明令禁止的行为（CONTRACT §7）。
#[derive(Debug, thiserror::Error)]
pub enum CursorError {
    /// 结构损坏 / base64 或 JSON 非法 / 摘要不符 / 跨查询、跨排序复用。
    #[error("invalid cursor ({0}); discard it and re-run the query without a cursor")]
    Invalid(String),
    /// 已到达或超过 `expires_at_ms`。
    #[error("cursor expired ({0}); re-run the query without a cursor to start fresh")]
    Expired(String),
    /// 令牌 generation 与当前活动 generation 不一致（数据已换代）。
    #[error(
        "cursor generation {cursor} is no longer active (current {active}); \
         re-run the query without a cursor to page over the latest data"
    )]
    GenerationMismatch {
        /// 令牌内记录的 generation。
        cursor: u64,
        /// 当前活动 generation。
        active: u64,
    },
    /// 令牌合同 major 与本实现不兼容。
    #[error(
        "cursor contract major {cursor} is not supported (supported: {supported}); \
         re-run the query without a cursor"
    )]
    ContractMismatch {
        /// 令牌内记录的合同 major。
        cursor: u32,
        /// 本实现支持的合同 major。
        supported: u32,
    },
}

/// 发行令牌：序列化 claims 并附加完整性摘要。
///
/// 不做语义校验——claims 内容（TTL、offset、各摘要）由调用方负责构造。
pub fn issue(claims: &CursorClaims) -> CursorToken {
    let json = serde_json::to_vec(claims).expect("cursor claims serialize to JSON infallibly");
    let digest = integrity_digest(&json);
    CursorToken(format!("{}.{digest}", base64url_encode(&json)))
}

/// 校验令牌并取回 claims。
///
/// 检查顺序：结构 → 完整性摘要 → JSON → 合同 major → 过期 → generation → 查询/排序绑定。
/// 摘要先于一切语义检查：先确认载荷未被篡改，再信任其内容。
pub fn verify(token: &str, expect: &CursorExpectations) -> Result<CursorClaims, CursorError> {
    let Some((payload, digest)) = token.split_once('.') else {
        return Err(CursorError::Invalid("missing digest separator".into()));
    };
    let json = base64url_decode(payload)
        .ok_or_else(|| CursorError::Invalid("payload is not valid base64url".into()))?;
    if digest != integrity_digest(&json) {
        return Err(CursorError::Invalid(
            "integrity digest mismatch (token corrupted or tampered)".into(),
        ));
    }
    let claims: CursorClaims = serde_json::from_slice(&json)
        .map_err(|e| CursorError::Invalid(format!("claims JSON malformed: {e}")))?;
    if claims.contract_major != SUPPORTED_CONTRACT_MAJOR {
        return Err(CursorError::ContractMismatch {
            cursor: claims.contract_major,
            supported: SUPPORTED_CONTRACT_MAJOR,
        });
    }
    if expect.now_ms >= claims.expires_at_ms {
        return Err(CursorError::Expired(format!(
            "expired at {} (now {})",
            claims.expires_at_ms, expect.now_ms
        )));
    }
    if claims.generation != expect.active_generation {
        return Err(CursorError::GenerationMismatch {
            cursor: claims.generation,
            active: expect.active_generation,
        });
    }
    if claims.query_digest != expect.query_digest {
        return Err(CursorError::Invalid(
            "cursor was issued for a different query".into(),
        ));
    }
    if claims.sort_digest != expect.sort_digest {
        return Err(CursorError::Invalid(
            "cursor was issued for a different sort order".into(),
        ));
    }
    if let Some(expected_set) = expect.result_set.as_deref()
        && claims.result_set.as_deref() != Some(expected_set)
    {
        return Err(CursorError::Invalid(
            "cursor was issued for a different result set".into(),
        ));
    }
    Ok(claims)
}

/// 计算查询串的 blake3 摘要（前 16 位 hex），供调用方填充 [`CursorClaims::query_digest`]
/// 与 [`CursorExpectations::query_digest`]。按字节原样哈希；规范化（trim 等）是调用方义务。
pub fn digest_query(s: &str) -> String {
    let hex = blake3::hash(s.as_bytes()).to_hex();
    hex.as_str()[..DIGEST_HEX_LEN].to_string()
}

/// 域前缀完整性摘要：`hex16(blake3("as-cursor-v1" || payload))`。
fn integrity_digest(payload: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(payload);
    let hex = hasher.finalize().to_hex();
    hex.as_str()[..DIGEST_HEX_LEN].to_string()
}

// ---- 本地 base64url（RFC 4648 §5，无填充）----
// 只服务 cursor 线格式；自足实现约 40 行，不为此引入通用编码依赖。

const B64_URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url 编码，无 `=` 填充。
fn base64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(chunk.get(1).copied().unwrap_or(0)) << 8)
            | u32::from(chunk.get(2).copied().unwrap_or(0));
        out.push(B64_URL_ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(B64_URL_ALPHABET[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(B64_URL_ALPHABET[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(B64_URL_ALPHABET[(n as usize) & 0x3f] as char);
        }
    }
    out
}

/// base64url 解码；非法字符、`=` 填充或非法长度（`len % 4 == 1`）返回 `None`。
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    fn sextet(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for &c in chunk {
            n = (n << 6) | sextet(c)?;
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]),
            3 => out.extend_from_slice(&[(n >> 10) as u8, (n >> 2) as u8]),
            2 => out.push((n >> 4) as u8),
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> CursorClaims {
        CursorClaims {
            contract_major: SUPPORTED_CONTRACT_MAJOR,
            generation: 7,
            issued_at_ms: 1_000,
            expires_at_ms: 1_000 + DEFAULT_TTL_MS,
            query_digest: digest_query("hello world"),
            sort_digest: "score_desc".into(),
            result_set: None,
            offset: 40,
        }
    }

    fn expectations() -> CursorExpectations {
        CursorExpectations {
            now_ms: 2_000,
            active_generation: 7,
            query_digest: digest_query("hello world"),
            sort_digest: "score_desc".into(),
            result_set: None,
        }
    }

    #[test]
    fn round_trip_returns_identical_claims() {
        let token = issue(&claims());
        let got = verify(token.as_str(), &expectations()).unwrap();
        assert_eq!(got, claims());
    }

    #[test]
    fn issue_is_deterministic() {
        assert_eq!(issue(&claims()), issue(&claims()));
    }

    #[test]
    fn token_wire_shape_is_payload_dot_hex16() {
        let token = issue(&claims()).into_string();
        let (payload, digest) = token.split_once('.').unwrap();
        assert!(!payload.is_empty());
        assert!(!payload.contains('='));
        assert_eq!(digest.len(), DIGEST_HEX_LEN);
        assert!(digest.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn tampered_payload_is_invalid() {
        let token = issue(&claims()).into_string();
        let (payload, digest) = token.split_once('.').unwrap();
        // 改动 payload 首字符（仍是合法 base64 字符）→ 解码字节变化 → 摘要不符。
        let mut chars: Vec<char> = payload.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered = format!("{}.{digest}", chars.into_iter().collect::<String>());
        let err = verify(&tampered, &expectations()).unwrap_err();
        assert!(matches!(err, CursorError::Invalid(_)), "{err}");
        assert!(err.to_string().contains("digest mismatch"), "{err}");
    }

    #[test]
    fn tampered_digest_is_invalid() {
        let token = issue(&claims()).into_string();
        let (payload, digest) = token.split_once('.').unwrap();
        let last = digest.chars().last().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        let tampered = format!("{payload}.{}{flipped}", &digest[..DIGEST_HEX_LEN - 1]);
        assert!(matches!(
            verify(&tampered, &expectations()),
            Err(CursorError::Invalid(_))
        ));
    }

    #[test]
    fn wrong_query_digest_is_invalid() {
        let token = issue(&claims());
        let mut e = expectations();
        e.query_digest = digest_query("another query");
        let err = verify(token.as_str(), &e).unwrap_err();
        assert!(matches!(err, CursorError::Invalid(_)), "{err}");
        assert!(err.to_string().contains("different query"), "{err}");
    }

    #[test]
    fn wrong_sort_digest_is_invalid() {
        let token = issue(&claims());
        let mut e = expectations();
        e.sort_digest = "wire_id_asc".into();
        let err = verify(token.as_str(), &e).unwrap_err();
        assert!(matches!(err, CursorError::Invalid(_)), "{err}");
        assert!(err.to_string().contains("different sort"), "{err}");
    }

    #[test]
    fn expired_at_and_after_boundary() {
        let token = issue(&claims());
        // 闭边界：now == expires 即过期（now >= expires）。
        let mut e = expectations();
        e.now_ms = claims().expires_at_ms;
        assert!(matches!(
            verify(token.as_str(), &e),
            Err(CursorError::Expired(_))
        ));
        e.now_ms = claims().expires_at_ms + 1;
        assert!(matches!(
            verify(token.as_str(), &e),
            Err(CursorError::Expired(_))
        ));
    }

    #[test]
    fn generation_mismatch_reports_both_sides() {
        let token = issue(&claims());
        let mut e = expectations();
        e.active_generation = 8;
        let err = verify(token.as_str(), &e).unwrap_err();
        assert!(
            matches!(
                err,
                CursorError::GenerationMismatch {
                    cursor: 7,
                    active: 8
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn contract_major_mismatch_is_rejected() {
        let mut c = claims();
        c.contract_major = SUPPORTED_CONTRACT_MAJOR + 1;
        let token = issue(&c);
        let err = verify(token.as_str(), &expectations()).unwrap_err();
        assert!(
            matches!(
                err,
                CursorError::ContractMismatch {
                    cursor: 2,
                    supported: SUPPORTED_CONTRACT_MAJOR
                }
            ),
            "{err}"
        );
    }

    #[test]
    fn garbage_tokens_are_invalid() {
        let cases = [
            "",
            "no-dot",
            "..",
            "a.b.c",
            "%%%.0123456789abcdef",
            "e30.zzzz",
            "有非ASCII.0123456789abcdef",
        ];
        for garbage in cases {
            assert!(
                matches!(
                    verify(garbage, &expectations()),
                    Err(CursorError::Invalid(_))
                ),
                "token: {garbage:?}"
            );
        }
    }

    #[test]
    fn error_messages_instruct_fresh_rerun() {
        // 合同要求：任何 cursor 错误都指示调用方重新发查询，绝不静默回第一页。
        let errors = [
            CursorError::Invalid("x".into()),
            CursorError::Expired("x".into()),
            CursorError::GenerationMismatch {
                cursor: 1,
                active: 2,
            },
            CursorError::ContractMismatch {
                cursor: 2,
                supported: 1,
            },
        ];
        for err in errors {
            assert!(err.to_string().contains("re-run the query"), "{err}");
        }
    }

    #[test]
    fn digest_query_is_deterministic_16_hex() {
        let d = digest_query("q");
        assert_eq!(d.len(), DIGEST_HEX_LEN);
        assert!(d.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(d, digest_query("q"));
        assert_ne!(d, digest_query("q2"));
    }

    #[test]
    fn base64url_round_trips_all_lengths_and_non_ascii() {
        let cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0],
            vec![0, 1],
            vec![0, 1, 2],
            "你好，世界 🚀 café".as_bytes().to_vec(),
            (0u8..=255).collect(),
        ];
        for case in cases {
            let encoded = base64url_encode(&case);
            assert!(!encoded.contains('='), "no padding: {encoded}");
            assert!(
                encoded
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
                "url-safe alphabet only: {encoded}"
            );
            assert_eq!(base64url_decode(&encoded).unwrap(), case);
        }
    }

    #[test]
    fn base64url_rejects_bad_input() {
        // len % 4 == 1 是任何无填充 base64 的非法长度。
        assert!(base64url_decode("abcde").is_none());
        // 标准 base64 字符 '+' / '/' 与 '=' 填充都不属于 url 无填充字母表。
        assert!(base64url_decode("ab+d").is_none());
        assert!(base64url_decode("ab/d").is_none());
        assert!(base64url_decode("ab=d").is_none());
        assert!(base64url_decode("有").is_none());
    }
}
