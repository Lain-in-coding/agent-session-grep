//! Loopback HTTP server for `asg serve` (#7).
//!
//! Minimal loopback HTTP/1.1 server built on std::net::TcpListener — no
//! heavy framework dependency (hyper/axum), keeping the supply chain lean.
//! Binds to 127.0.0.1 by default; random token authenticates each session.
//!
//! Security:
//! - Default: loopback only (127.0.0.1) + random token + Host/Origin check
//! - Explicit LAN mode: requires token + audit log
//! - All output goes through the cross-boundary redactor (ADR-0009)
//!
//! The server is the single backend; the Web UI is a protocol client over
//! the same Application ADT / Robot contract.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agent_session_grep_adapters_sqlite::SqliteStore;
use agent_session_grep_application::{ContextLevel, ResponseBudget};
use agent_session_grep_domain::ContextPolicy;
use agent_session_grep_ports::{SearchFacets, SearchFilters, SearchProvider, SidechainFacet};

const READ_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const WORKER_COUNT: usize = 4;
const QUEUE_CAPACITY: usize = 8;
const MAX_REQUEST_LINE_BYTES: usize = 8 * 1024;
const MAX_HEADER_BYTES: usize = 64 * 1024;
const MAX_HEADER_COUNT: usize = 100;
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// 常量时间字节比较（无新依赖）：逐字节 XOR 累计，长度不等也照常遍历
/// 短者全程，避免 early-return 时序差异。
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    left.len() == right.len() && diff == 0
}

/// A random bearer token generated for each `asg serve` session.
/// Clients must send it in the `Authorization: Bearer <token>` header.
pub struct ServeSession {
    token: String,
    address: String,
}

impl ServeSession {
    /// Bind a loopback listener on a random port and generate a session token.
    pub fn bind_loopback(port: u16) -> std::io::Result<Self> {
        let address = format!("127.0.0.1:{port}");
        // The listener is bound in run(); here we just prepare token/address.
        let token = generate_token();
        Ok(Self { token, address })
    }

    /// The bearer token clients must send.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The bound address.
    pub fn address(&self) -> &str {
        &self.address
    }
}

/// Run the loopback HTTP server until interrupted.
///
/// Network reads and writes run in a fixed-size worker pool; routing runs on
/// one dedicated thread because `SqliteStore` deliberately owns a non-`Sync`
/// SQLite connection. A slow query therefore parks only that router thread —
/// accepts keep running while a slow or non-reading client can occupy at most
/// one bounded worker slot.
pub fn run(
    session: &ServeSession,
    store: &SqliteStore,
) -> Result<crate::protocol::Outcome, crate::CliError> {
    let listener = TcpListener::bind(session.address())
        .map_err(|e| crate::CliError::usage(format!("serve: bind failed: {e}")))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| crate::CliError::usage(format!("serve: local address unavailable: {e}")))?;
    // Token goes in the URL **fragment**, not the query string. A fragment is
    // never sent to the server, so it cannot land in a request log, an access
    // log, or a `Referer` header on any later navigation — whereas
    // `?token=<secret>` reaches every one of those. The page reads it from
    // `location.hash` and sends it as `Authorization: Bearer`, then strips it
    // from the visible URL so it does not persist in browser history.
    // Idea from cc-sessions-viewer's `web-server-mode.md` (no LICENSE file in
    // that repository — spec-level idea only, no code borrowed).
    eprintln!(
        "asg serve: open http://{local_addr}/#token={}",
        session.token()
    );
    eprintln!("asg serve: loopback-only; LAN mode is capability_not_supported");
    serve_listener(listener, session.token(), store, ServerLimits::production())
        .map_err(|e| crate::CliError::usage(format!("serve: listener failed: {e}")))?;
    Ok(crate::protocol::Outcome::Success)
}

#[derive(Clone, Copy)]
struct ServerLimits {
    read_timeout: Duration,
    write_timeout: Duration,
    stop_after: Option<usize>,
}

impl ServerLimits {
    const fn production() -> Self {
        Self {
            read_timeout: READ_TIMEOUT,
            write_timeout: WRITE_TIMEOUT,
            stop_after: None,
        }
    }
}

enum WorkerEvent {
    Parsed {
        request: std::io::Result<HttpRequest>,
        reply: SyncSender<HttpResponse>,
    },
    Completed,
}

fn serve_listener(
    listener: TcpListener,
    token: &str,
    store: &SqliteStore,
    limits: ServerLimits,
) -> std::io::Result<()> {
    listener.set_nonblocking(true)?;
    let (work_tx, work_rx) = mpsc::sync_channel::<TcpStream>(QUEUE_CAPACITY);
    let work_rx = Arc::new(Mutex::new(work_rx));
    let (event_tx, event_rx) = mpsc::channel::<WorkerEvent>();

    std::thread::scope(|scope| {
        for _ in 0..WORKER_COUNT {
            let work_rx = Arc::clone(&work_rx);
            let event_tx = event_tx.clone();
            scope.spawn(move || worker_loop(work_rx, event_tx, limits));
        }
        drop(event_tx);

        // The accept loop only touches the listener, the work queue sender and
        // the completed counter — none of them `!Sync` — so it runs on its own
        // scoped thread and a slow query routed below can never stall accepts.
        // After the stop budget is reached it returns and releases the work
        // queue, letting the workers drain what is already staged and exit.
        let completed_counter = Arc::new(AtomicUsize::new(0));
        let accept_thread = {
            let completed_counter = Arc::clone(&completed_counter);
            scope.spawn(move || {
                let mut accepted = 0usize;
                loop {
                    if limits.stop_after.is_some_and(|max| accepted >= max) {
                        return Ok(());
                    }
                    loop {
                        let in_flight =
                            accepted.saturating_sub(completed_counter.load(Ordering::Relaxed));
                        if in_flight < WORKER_COUNT + QUEUE_CAPACITY {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    match listener.accept() {
                        Ok((stream, _peer)) => match work_tx.send(stream) {
                            Ok(()) => accepted += 1,
                            Err(_) => return Ok(()),
                        },
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => return Err(error),
                    }
                }
            })
        };

        // Routing runs on the store-owning thread (`SqliteStore` is `!Sync`)
        // directly in this event loop: one slow query parks it, but the accept
        // thread above keeps admitting and staging connections. Worker
        // completion is shared with the accept thread through the atomic
        // counter above.
        let mut completed = 0usize;
        loop {
            if limits.stop_after.is_some_and(|max| completed >= max) {
                break;
            }
            match event_rx.recv_timeout(Duration::from_millis(5)) {
                Ok(WorkerEvent::Parsed { request, reply }) => match request {
                    Ok(request) => {
                        let response = route_response(&request, token, store);
                        let _ = reply.send(response);
                    }
                    Err(error) => {
                        let response = if matches!(
                            error.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) {
                            fixed_error(408, "request_timeout", "request timed out")
                        } else {
                            fixed_error(400, "invalid_request", "malformed HTTP request")
                        };
                        let _ = reply.send(response);
                    }
                },
                Ok(WorkerEvent::Completed) => {
                    completed += 1;
                    completed_counter.store(completed, Ordering::Relaxed);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        accept_thread
            .join()
            .expect("serve accept thread panicked")?;
        Ok(())
    })
}

fn worker_loop(
    work_rx: Arc<Mutex<mpsc::Receiver<TcpStream>>>,
    event_tx: mpsc::Sender<WorkerEvent>,
    limits: ServerLimits,
) {
    loop {
        let stream = {
            let receiver = match work_rx.lock() {
                Ok(receiver) => receiver,
                Err(_) => return,
            };
            match receiver.recv() {
                Ok(stream) => stream,
                Err(_) => return,
            }
        };
        let mut stream = stream;
        // Windows 的 `accept` 会继承 listener 的非阻塞属性（`set_nonblocking(true)`
        // 在 serve_listener 里是为了让 accept 轮询不阻塞事件循环）。不显式还原为
        // 阻塞，SO_RCVTIMEO/SO_SNDTIMEO 就整体失效：请求字节晚到几百微秒即
        // WouldBlock → 立刻回 408（实测 140 次合法请求误判 2 次），而半关闭的
        // 客户端还会被随后的 RST 抹掉已经收到的响应（0 字节 + ConnectionAborted）。
        let _ = stream.set_nonblocking(false);
        let _ = stream.set_read_timeout(Some(limits.read_timeout));
        let _ = stream.set_write_timeout(Some(limits.write_timeout));
        let request = parse_request(&mut stream);
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        if event_tx
            .send(WorkerEvent::Parsed {
                request,
                reply: reply_tx,
            })
            .is_err()
        {
            return;
        }
        let Ok(response) = reply_rx.recv() else {
            return;
        };
        let _ = stream.write_all(&response.to_bytes());
        let _ = stream.flush();
        if event_tx.send(WorkerEvent::Completed).is_err() {
            return;
        }
    }
}

/// Route one request on the router thread, surviving a handler panic.
///
/// `dispatch` unwinds on internal bugs; with the router on its own thread a
/// panic would otherwise kill routing for the rest of the server's lifetime
/// and hang every later request. One fixed 500 per failing request is the
/// honest failure; the panic payload is never echoed (it may quote transcript
/// content).
fn route_response(request: &HttpRequest, token: &str, store: &SqliteStore) -> HttpResponse {
    let result = catch_unwind(AssertUnwindSafe(|| route_request(request, token, store)));
    match result {
        Ok(response) => response,
        Err(_) => fixed_error(500, "internal", "request handler failed"),
    }
}

/// A parsed HTTP request (minimal subset; the server accepts one request per
/// connection and always closes it after the response).
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    #[allow(dead_code)] // v1 首发的危险动作全部停在预览；body 留给未来经 CSRF/确认的 POST。
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// Get a header value (case-insensitive lookup).
    pub fn header(&self, name: &str) -> Option<&str> {
        let mut matches = self
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case(name));
        let value = matches.next().map(|(_, value)| value.as_str())?;
        if matches.next().is_some() {
            None
        } else {
            Some(value)
        }
    }

    /// Check the Authorization header against a token.
    ///
    /// 常量时间比较：即便 loopback-only 且 token 为 CSPRNG，也不给任何
    /// 时序侧信道（audit 建议的 one-line hardening）。
    pub fn check_token(&self, expected: &str) -> bool {
        if let Some(auth) = self.header("authorization")
            && let Some(token) = auth.strip_prefix("Bearer ")
        {
            return constant_time_eq(token.as_bytes(), expected.as_bytes());
        }
        false
    }

    /// Check the Host header is loopback (security: prevent DNS rebinding).
    pub fn check_host_loopback(&self) -> bool {
        loopback_host(self.header("host"))
    }

    /// A cross-origin browser fetch must never enter the API. Same-origin
    /// requests made by the embedded UI carry no Origin header; a present
    /// Origin must exactly match the loopback Host authority (Q27).
    pub fn check_origin_loopback(&self) -> bool {
        let mut origins = self
            .headers
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("origin"))
            .map(|(_, value)| value.as_str());
        let Some(origin) = origins.next() else {
            return true;
        };
        // 重复 Origin 不是"没有 Origin"：`header` 对重复取值返回 None，沿用它会
        // 把两个 Origin 头当成同源放行（fail open）。在场即校验，歧义即拒绝。
        if origins.next().is_some() {
            return false;
        }
        let Some((scheme, authority)) = parse_http_origin(origin) else {
            return false;
        };
        let Some(host) = self.header("host") else {
            return false;
        };
        (scheme == "http" || scheme == "https")
            && loopback_host(Some(host))
            && authority.eq_ignore_ascii_case(host.trim())
    }

    pub fn check_csrf_token(&self, expected: &str) -> bool {
        self.header("x-csrf-token") == Some(expected)
    }

    /// Fail closed on reverse-proxy hints: a direct loopback client has no
    /// forwarding headers (agentsview hasForwardingHeader, idea-level port).
    pub fn check_direct_client(&self) -> bool {
        !self
            .headers
            .iter()
            .any(|(name, _)| is_forwarding_header(name))
    }

    fn query_pairs(&self) -> Result<Vec<(String, String)>, HttpResponse> {
        let Some((_, query)) = self.path.split_once('?') else {
            return Ok(Vec::new());
        };
        if query.is_empty() {
            return Ok(Vec::new());
        }
        query
            .split('&')
            .map(|pair| {
                let Some((key, value)) = pair.split_once('=') else {
                    return Err(fixed_error(
                        400,
                        "invalid_request",
                        "invalid query parameter encoding",
                    ));
                };
                match (percent_decode(key), percent_decode(value)) {
                    (Some(key), Some(value)) => Ok((key, value)),
                    _ => Err(fixed_error(
                        400,
                        "invalid_request",
                        "invalid query parameter encoding",
                    )),
                }
            })
            .collect()
    }
}

fn percent_decode(value: &str) -> Option<String> {
    let mut output = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => output.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let high = (bytes[index + 1] as char).to_digit(16)?;
                let low = (bytes[index + 2] as char).to_digit(16)?;
                output.push((high * 16 + low) as u8);
                index += 2;
            }
            b'%' => return None,
            byte if byte.is_ascii_control() => return None,
            byte => output.push(byte),
        }
        index += 1;
    }
    let value = String::from_utf8(output).ok()?;
    // A raw control byte is rejected above, but `%0A` would otherwise decode
    // into one. No request parameter has a legitimate control-character use,
    // and accepting some here while the search validator rejects others made
    // the failure depend on the parameter name.
    (!value.chars().any(char::is_control)).then_some(value)
}

fn loopback_host(host: Option<&str>) -> bool {
    let Some(host) = host else {
        return false;
    };
    let host = host.trim();
    let (name, port) = if let Some(rest) = host.strip_prefix('[') {
        let Some((name, tail)) = rest.split_once(']') else {
            return false;
        };
        let port = if tail.is_empty() {
            None
        } else if let Some(port) = tail.strip_prefix(':') {
            Some(port)
        } else {
            return false;
        };
        (name, port)
    } else if host.matches(':').count() > 1 {
        (host, None)
    } else if let Some((name, port)) = host.rsplit_once(':') {
        (name, Some(port))
    } else {
        (host, None)
    };
    if port.is_some_and(|port| port.parse::<u16>().is_err()) {
        return false;
    }
    name.eq_ignore_ascii_case("localhost") || name == "127.0.0.1" || name == "::1"
}

fn parse_http_origin(origin: &str) -> Option<(String, String)> {
    let (scheme, authority) = origin.split_once("://")?;
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
    {
        None
    } else {
        Some((scheme.to_ascii_lowercase(), authority.to_string()))
    }
}

fn is_forwarding_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("forwarded")
        || name.eq_ignore_ascii_case("x-forwarded-for")
        || name.eq_ignore_ascii_case("x-forwarded-host")
        || name.eq_ignore_ascii_case("x-real-ip")
}

/// A minimal HTTP response.
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
    pub content_type: &'static str,
    pub headers: Vec<(&'static str, &'static str)>,
}

impl HttpResponse {
    pub fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            body: body.to_string(),
            content_type: "application/json; charset=utf-8",
            headers: Vec::new(),
        }
    }

    pub fn text(status: u16, body: &str, content_type: &'static str) -> Self {
        Self {
            status,
            body: body.to_string(),
            content_type,
            // `to_bytes` emits X-Content-Type-Options for every response; a
            // second value here made text responses send the header twice.
            headers: Vec::new(),
        }
    }

    /// Serialize to HTTP/1.1 response bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let status_text = match self.status {
            200 => "OK",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            408 => "Request Timeout",
            409 => "Conflict",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            503 => "Service Unavailable",
            _ => "Unknown",
        };
        let mut header = format!(
            "HTTP/1.1 {self_status} {status_text}\r\nContent-Type: {ct}\r\nContent-Length: {len}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\n",
            self_status = self.status,
            ct = self.content_type,
            len = self.body.len()
        );
        for (name, value) in &self.headers {
            header.push_str(name);
            header.push_str(": ");
            header.push_str(value);
            header.push_str("\r\n");
        }
        header.push_str("\r\n");
        let mut bytes = header.into_bytes();
        bytes.extend_from_slice(self.body.as_bytes());
        bytes
    }
}

fn json_error(status: u16, code: &str, message: &str) -> HttpResponse {
    HttpResponse::json(
        status,
        &serde_json::json!({
            "error": {
                "code": code,
                "message": message,
            }
        })
        .to_string(),
    )
}

fn fixed_error(status: u16, code: &str, message: &str) -> HttpResponse {
    json_error(status, code, message)
}

/// Parse a minimal HTTP request from a TCP stream.
///
/// Header and body reads are explicitly bounded: the header section may not
/// exceed `MAX_HEADER_BYTES`, at most `MAX_HEADER_COUNT` lines are accepted,
/// and a request body may not exceed `MAX_BODY_BYTES`. Combined with the
/// socket read deadline, this keeps a slow client from holding a worker.
pub fn parse_request(stream: &mut TcpStream) -> std::io::Result<HttpRequest> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    let request_line_len =
        read_bounded_line(&mut reader, &mut request_line, MAX_REQUEST_LINE_BYTES)?;
    if request_line_len == 0 {
        return Err(invalid_data("empty request"));
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() != 3 || !parts[2].starts_with("HTTP/1.") {
        return Err(invalid_data("malformed request line"));
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();
    if !path.starts_with('/') {
        return Err(invalid_data("origin-form request target required"));
    }

    let mut headers = Vec::new();
    let mut header_bytes = 0usize;
    loop {
        let mut line = String::new();
        let n = read_bounded_line(&mut reader, &mut line, MAX_HEADER_BYTES - header_bytes)?;
        header_bytes += n;
        if n == 0 || line.trim().is_empty() {
            break;
        }
        // 计数放在"确认这一行是 header"之后：守卫在循环开头时，终止空行也要占
        // 一次迭代，于是恰好 MAX_HEADER_COUNT 条 header 的合法请求被判 400
        // （实际上限只有 99）。上限的含义是"接受这么多条 header"。
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(invalid_data("too many request headers"));
        }
        let Some(idx) = line.find(':') else {
            return Err(invalid_data("malformed request header"));
        };
        let key = line[..idx].trim().to_string();
        let val = line[idx + 1..].trim().to_string();
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(invalid_data("malformed request header name"));
        }
        headers.push((key, val));
    }

    if headers
        .iter()
        .any(|(key, _)| key.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(invalid_data("transfer encoding is not supported"));
    }
    let content_lengths = headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    if content_lengths.len() > 1 {
        return Err(invalid_data("duplicate content length"));
    }

    // Read body if Content-Length is present. v1 routes do not consume a body,
    // but parse it (bounded) so the transport contract stays explicit.
    let mut body = Vec::new();
    if let Some(value) = content_lengths.first() {
        let cl = value
            .parse::<usize>()
            .map_err(|_| invalid_data("invalid content length"))?;
        if cl > MAX_BODY_BYTES {
            return Err(invalid_data("request body too large"));
        }
        body.resize(cl, 0);
        reader.read_exact(&mut body)?;
    }

    Ok(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

fn read_bounded_line(
    reader: &mut BufReader<&mut TcpStream>,
    line: &mut String,
    remaining: usize,
) -> std::io::Result<usize> {
    if remaining == 0 {
        return Err(invalid_data("request headers too large"));
    }
    let read = (&mut *reader).take(remaining as u64 + 1).read_line(line)?;
    if read > remaining {
        return Err(invalid_data("request headers too large"));
    }
    Ok(read)
}

fn invalid_data(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// Generate a random 32-char hex token for session authentication.
///
/// Uses the platform CSPRNG via getrandom; the token guards loopback API
/// access, so it must not be predictable from the clock (LCG + timestamp
/// was not).
fn generate_token() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("CSPRNG must be available on serve host");
    let mut hex = String::with_capacity(32);
    for byte in bytes {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// The embedded Web UI HTML (single-page app, no external dependencies).
const WEB_UI_HTML: &str = include_str!("web/index.html");

/// Strip a query string from a request path for route matching.
fn path_only(path: &str) -> &str {
    path.split_once('?').map(|(p, _)| p).unwrap_or(path)
}

/// Route an HTTP request to the appropriate response, backed by the
/// Application ADT over the same SqliteStore used by CLI/MCP/Robot.
///
/// All JSON responses pass through the cross-boundary redactor (ADR-0009):
/// Web 是跨边界输出,secret 模式一律脱敏(与 Robot/MCP/Handoff 同规则)。
pub fn route_request(req: &HttpRequest, token: &str, store: &SqliteStore) -> HttpResponse {
    // The order deliberately reveals no token validity to a non-loopback Host
    // or Origin. Every rejection has a fixed, path-free, secret-free body.
    if !req.check_host_loopback() {
        return fixed_error(403, "forbidden_host", "loopback Host required");
    }
    if !req.check_origin_loopback() {
        return fixed_error(403, "forbidden_origin", "loopback Origin required");
    }
    if !req.check_direct_client() {
        return fixed_error(
            403,
            "forbidden_proxy",
            "direct loopback connection required",
        );
    }
    // The UI page itself is static HTML with no secrets and no data; it may be
    // fetched without a token so the fragment-based flow can boot at all — a
    // fragment is never sent to the server, so the page-load request carries
    // no credential by design. The query string is never a credential: it
    // reaches access logs and `Referer` headers, which is exactly why the
    // printed URL uses a fragment. Every data route below requires the bearer.
    let is_ui_page = req.method == "GET" && path_only(req.path.as_str()) == "/";
    if !is_ui_page && !req.check_token(token) {
        return fixed_error(401, "unauthorized", "valid bearer token required");
    }

    // No mutation is in the first public Web surface. POST can therefore never
    // accidentally turn a preview into execution; clients receive an explicit
    // capability result instead of a misleading 404 or silent fallback.
    if req.method == "POST" {
        if req.header("origin").is_none() || !req.check_origin_loopback() {
            return fixed_error(403, "forbidden_origin", "same-origin POST required");
        }
        if !req.check_csrf_token(token) {
            return fixed_error(403, "forbidden_csrf", "CSRF token required");
        }
        audit_unsupported_action(path_only(req.path.as_str()));
        return fixed_error(
            501,
            "capability_not_supported",
            "HTTP mutation and execution are not supported; use preview endpoints",
        );
    }
    if req.method != "GET" {
        return fixed_error(400, "invalid_request", "GET requests only");
    }

    let path = path_only(req.path.as_str());
    if path == "/" {
        let mut response = HttpResponse::text(200, WEB_UI_HTML, "text/html; charset=utf-8");
        response.headers.push((
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'none'",
        ));
        return response;
    }
    match path {
        "/health" | "/api/status" => match WebParams::parse(req, &[], &[]) {
            Ok(_) => execute(
                "status",
                crate::read_commands::status(store).map(with_web_capabilities),
            ),
            Err(response) => response,
        },
        "/api/providers" => match WebParams::parse(req, &[], &[]) {
            Ok(_) => redacted_json(
                200,
                serde_json::json!({
                    "command": "providers",
                    "outcome": "success",
                    "data": crate::provider_matrix_data(),
                    "page": { "next_cursor": null, "has_more": false },
                    "warnings": [],
                }),
            ),
            Err(response) => response,
        },
        "/api/search" | "/api/projection/search" => web_search(req, store),
        "/api/context" => web_context(req, store),
        "/api/handoff" => web_handoff(req, store),
        "/api/show" => web_show(req, store, None),
        "/api/resume" => web_resume(req, store, None),
        _ => {
            if let Some(id) = path.strip_prefix("/api/show/") {
                web_show(req, store, Some(id))
            } else if let Some(session_id) = path.strip_prefix("/api/resume/") {
                web_resume(req, store, Some(session_id))
            } else {
                fixed_error(404, "not_found", "HTTP route not found")
            }
        }
    }
}

const WEB_SEARCH_PARAMETERS: &[&str] = &[
    "q",
    "mode",
    "limit",
    "max_bytes",
    "cursor",
    "provider",
    "since",
    "until",
    "repo",
    "include_system",
    "group_by_session",
    "sidechain",
    "tool_kind",
    "tool_name",
];

const WEB_CONTEXT_PARAMETERS: &[&str] =
    &["session", "policy", "level", "max_messages", "max_bytes"];
const WEB_HANDOFF_PARAMETERS: &[&str] = &[
    "q",
    "provider",
    "repo",
    "since",
    "until",
    "max_evidence",
    "max_tokens",
    "max_bytes",
];

/// Decode and validate one route's query string exactly once. Every data route
/// declares its parameter vocabulary; an unknown, repeated scalar, empty or
/// malformed value is rejected instead of being silently ignored. The page
/// route (`/`) is deliberately not passed through here: its query string is
/// inert and the fragment-based bootstrap must keep working.
struct WebParams {
    pairs: Vec<(String, String)>,
}

impl WebParams {
    fn parse(
        req: &HttpRequest,
        allowed: &[&str],
        repeatable: &[&str],
    ) -> Result<Self, HttpResponse> {
        let pairs = req.query_pairs()?;
        let mut seen = std::collections::BTreeMap::<&str, &str>::new();
        for (name, value) in &pairs {
            if !allowed.contains(&name.as_str()) {
                return Err(fixed_error(
                    400,
                    "invalid_request",
                    "unknown query parameter",
                ));
            }
            if !repeatable.contains(&name.as_str()) && seen.insert(name, value).is_some() {
                return Err(fixed_error(
                    400,
                    "invalid_request",
                    &format!("repeated query parameter: {name}"),
                ));
            }
            if value.trim().is_empty() {
                return Err(fixed_error(
                    400,
                    "invalid_request",
                    &format!("empty query parameter: {name}"),
                ));
            }
        }
        Ok(Self { pairs })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn required(&self, name: &str) -> Result<&str, HttpResponse> {
        self.get(name).ok_or_else(|| {
            fixed_error(400, "invalid_request", &format!("missing {name} parameter"))
        })
    }

    fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.pairs
            .iter()
            .filter(move |(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn opt_usize(&self, name: &str) -> Result<Option<usize>, HttpResponse> {
        self.get(name)
            .map(|value| {
                value.parse::<usize>().map_err(|_| {
                    fixed_error(400, "invalid_request", &format!("invalid {name} parameter"))
                })
            })
            .transpose()
    }

    fn opt_bool(&self, name: &str) -> Result<bool, HttpResponse> {
        match self.get(name) {
            None | Some("false") => Ok(false),
            Some("true") => Ok(true),
            Some(_) => Err(fixed_error(
                400,
                "invalid_request",
                &format!("invalid {name} parameter"),
            )),
        }
    }
}

fn execute(
    command: &'static str,
    result: Result<crate::read_commands::Rendered, crate::CliError>,
) -> HttpResponse {
    match result {
        Ok((outcome, data, page, warnings)) => {
            let outcome = match outcome {
                crate::protocol::Outcome::Success => "success",
                crate::protocol::Outcome::Partial => "partial",
            };
            redacted_json(
                200,
                serde_json::json!({
                    "command": command,
                    "outcome": outcome,
                    "data": data,
                    "page": {
                        "next_cursor": page.next_cursor,
                        "has_more": page.has_more,
                    },
                    "warnings": warnings,
                }),
            )
        }
        Err(error) => protocol_error(error.0),
    }
}

/// Attach the Web capability block to the rendered status projection before
/// the envelope is built, so the response is assembled and redacted once.
fn with_web_capabilities(
    (outcome, mut data, page, warnings): crate::read_commands::Rendered,
) -> crate::read_commands::Rendered {
    if let Some(data) = data.as_object_mut() {
        data.insert(
            "web_capabilities".into(),
            serde_json::json!({
                "search_parameters": WEB_SEARCH_PARAMETERS,
                "repeated_parameters": ["provider"],
                "provider_values": agent_session_grep_ports::capability::search_provider_filter_values(),
                "retrieval_modes": ["lexical", "semantic", "hybrid"],
                "limit_sets_max_items": true,
                "mutation_and_execution": false,
            }),
        );
    }
    (outcome, data, page, warnings)
}

fn search_command(req: &HttpRequest) -> Result<crate::read_commands::SearchCommand, HttpResponse> {
    let params = WebParams::parse(req, WEB_SEARCH_PARAMETERS, &["provider"])?;
    let query = params.required("q")?.trim();
    let mode = match params.get("mode") {
        None => agent_session_grep_ports::RetrievalMode::Lexical,
        Some(value) => match crate::read_commands::retrieval_mode(value) {
            Some(mode) => mode,
            None => {
                return Err(fixed_error(
                    400,
                    "invalid_request",
                    "invalid mode parameter",
                ));
            }
        },
    };
    let sidechain = match params.get("sidechain") {
        None => SidechainFacet::Include,
        Some(value) => match crate::read_commands::sidechain_facet(value) {
            Some(facet) => facet,
            None => {
                return Err(fixed_error(
                    400,
                    "invalid_request",
                    "invalid sidechain parameter",
                ));
            }
        },
    };
    let include_system = params.opt_bool("include_system")?;
    let group_by_session = params.opt_bool("group_by_session")?;
    let max_items = params.opt_usize("limit")?;
    let max_bytes = params.opt_usize("max_bytes")?;
    let mut filters = SearchFilters::default();
    // Only the clock used to resolve compact relative durations is captured.
    let now_ms = crate::app_clock_ms();
    for value in params.values("provider") {
        let Some(provider) = SearchProvider::parse(value) else {
            return Err(fixed_error(
                400,
                "invalid_request",
                &format!(
                    "invalid provider parameter; expected {}",
                    crate::provider_value_hint()
                ),
            ));
        };
        filters.providers.push(provider);
    }
    filters.since = parse_time_param(&params, "since", now_ms)?;
    filters.until = parse_time_param(&params, "until", now_ms)?;
    filters.repo = params.get("repo").map(str::to_string);
    let tool_kind = params.get("tool_kind").map(str::to_string);
    if let Some(kind) = tool_kind.as_deref()
        && !crate::read_commands::valid_tool_kind(kind)
    {
        return Err(fixed_error(
            400,
            "invalid_request",
            "invalid tool_kind parameter",
        ));
    }
    let facets = SearchFacets {
        sidechain,
        tool_kind,
        tool_name: params.get("tool_name").map(str::to_string),
    };
    let mut budget = ResponseBudget::default();
    if let Some(value) = max_items {
        budget.max_items = value;
    }
    if let Some(value) = max_bytes {
        budget.max_response_bytes = value;
    }
    Ok(crate::read_commands::SearchCommand {
        query: query.to_string(),
        filters,
        facets,
        limit: max_items.unwrap_or(crate::read_commands::DEFAULT_SEARCH_LIMIT),
        cursor: params.get("cursor").map(str::to_string),
        budget,
        include_system,
        group_by_session,
        mode,
        attach_session_rows: false,
    })
}

fn web_search(req: &HttpRequest, store: &SqliteStore) -> HttpResponse {
    let command = match search_command(req) {
        Ok(command) => command,
        Err(response) => return response,
    };
    execute("search", crate::read_commands::search(store, command))
}

fn parse_time_param(
    params: &WebParams,
    name: &str,
    now_ms: i64,
) -> Result<Option<agent_session_grep_ports::SearchInstant>, HttpResponse> {
    let Some(value) = params.get(name) else {
        return Ok(None);
    };
    agent_session_grep_application::parse_search_instant(value)
        .or_else(|| agent_session_grep_application::parse_relative_search_instant(value, now_ms))
        .map(Some)
        .ok_or_else(|| fixed_error(400, "invalid_request", &format!("invalid {name} parameter")))
}

fn web_context(req: &HttpRequest, store: &SqliteStore) -> HttpResponse {
    let params = match WebParams::parse(req, WEB_CONTEXT_PARAMETERS, &[]) {
        Ok(params) => params,
        Err(response) => return response,
    };
    let session = match params.required("session") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let policy = match params.get("policy") {
        None => ContextPolicy::Mainline,
        Some(value) => match crate::read_commands::context_policy(value) {
            Some(policy) => policy,
            None => {
                return fixed_error(400, "invalid_request", "invalid policy parameter");
            }
        },
    };
    let level = match params.get("level") {
        None => ContextLevel::Raw,
        Some(value) => match crate::read_commands::context_level(value) {
            Some(level) => level,
            None => {
                return fixed_error(400, "invalid_request", "invalid level parameter");
            }
        },
    };
    let max_messages = match params.opt_usize("max_messages") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let max_bytes = match params.opt_usize("max_bytes") {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(session_id) = agent_session_grep_domain::StableId::from_wire(session)
        .filter(|id| id.kind() == agent_session_grep_domain::IdKind::Session)
    else {
        return fixed_error(400, "invalid_request", "invalid session parameter");
    };
    let mut budget = ResponseBudget::default();
    if let Some(value) = max_messages {
        budget.max_messages = value;
    }
    if let Some(value) = max_bytes {
        budget.max_response_bytes = value;
    }
    execute(
        "context",
        crate::read_commands::context(
            store,
            crate::read_commands::ContextCommand {
                session_id,
                policy,
                level,
                budget,
            },
        ),
    )
}

fn web_handoff(req: &HttpRequest, store: &SqliteStore) -> HttpResponse {
    let params = match WebParams::parse(req, WEB_HANDOFF_PARAMETERS, &["provider"]) {
        Ok(params) => params,
        Err(response) => return response,
    };
    let query = match params.required("q") {
        Ok(query) => query.trim(),
        Err(response) => return response,
    };
    let now_ms = crate::app_clock_ms();
    let mut filters = SearchFilters::default();
    for value in params.values("provider") {
        let Some(provider) = SearchProvider::parse(value) else {
            return fixed_error(
                400,
                "invalid_request",
                &format!(
                    "invalid provider parameter; expected {}",
                    crate::provider_value_hint()
                ),
            );
        };
        filters.providers.push(provider);
    }
    filters.since = match parse_time_param(&params, "since", now_ms) {
        Ok(value) => value,
        Err(response) => return response,
    };
    filters.until = match parse_time_param(&params, "until", now_ms) {
        Ok(value) => value,
        Err(response) => return response,
    };
    filters.repo = params.get("repo").map(str::to_string);
    let max_evidence = match params.opt_usize("max_evidence") {
        Ok(value) => value.unwrap_or(crate::read_commands::DEFAULT_HANDOFF_EVIDENCE),
        Err(response) => return response,
    };
    let max_tokens = match params.opt_usize("max_tokens") {
        Ok(value) => value.unwrap_or(crate::read_commands::DEFAULT_HANDOFF_TOKENS),
        Err(response) => return response,
    };
    let max_bytes = match params.opt_usize("max_bytes") {
        Ok(value) => value.unwrap_or(crate::read_commands::DEFAULT_HANDOFF_BYTES),
        Err(response) => return response,
    };
    execute(
        "handoff",
        crate::read_commands::handoff(
            store,
            crate::read_commands::HandoffCommand {
                query: query.to_string(),
                filters,
                search_limit: crate::read_commands::DEFAULT_HANDOFF_SEARCH_LIMIT,
                max_evidence,
                max_tokens,
                max_bytes,
            },
        ),
    )
}

fn web_show(req: &HttpRequest, store: &SqliteStore, path_id: Option<&str>) -> HttpResponse {
    let id = match path_id {
        Some(id) => {
            if let Err(response) = WebParams::parse(req, &[], &[]) {
                return response;
            }
            id.to_string()
        }
        None => {
            let params = match WebParams::parse(req, &["id"], &[]) {
                Ok(params) => params,
                Err(response) => return response,
            };
            let Ok(id) = params.required("id") else {
                return fixed_error(400, "invalid_request", "missing id parameter");
            };
            id.to_string()
        }
    };
    let Some(id) = agent_session_grep_domain::StableId::from_wire(&id) else {
        return fixed_error(400, "invalid_request", "invalid id parameter");
    };
    execute("show", crate::read_commands::show(store, id))
}

fn web_resume(req: &HttpRequest, store: &SqliteStore, path_session: Option<&str>) -> HttpResponse {
    let session = match path_session {
        Some(session) => {
            if let Err(response) = WebParams::parse(req, &[], &[]) {
                return response;
            }
            session.to_string()
        }
        None => {
            let params = match WebParams::parse(req, &["session"], &[]) {
                Ok(params) => params,
                Err(response) => return response,
            };
            let Ok(session) = params.required("session") else {
                return fixed_error(400, "invalid_request", "missing session parameter");
            };
            session.to_string()
        }
    };
    let Some(session_id) = agent_session_grep_domain::StableId::from_wire(&session)
        .filter(|id| id.kind() == agent_session_grep_domain::IdKind::Session)
    else {
        return fixed_error(400, "invalid_request", "invalid session parameter");
    };
    // GET is a pure preview: no first-run acknowledgement marker and no
    // execution. `resume --yes` is a CLI-only capability.
    match crate::read_commands::resume_preview(store, session_id) {
        Ok((data, _preview)) => redacted_json(
            200,
            serde_json::json!({
                "command": "resume",
                "outcome": "success",
                "data": data,
                "page": { "next_cursor": null, "has_more": false },
                "warnings": [],
            }),
        ),
        Err(error) => protocol_error(error.0),
    }
}

fn audit_unsupported_action(path: &str) {
    let action = match path {
        "/api/resume" => "resume",
        "/api/handoff" => "handoff",
        "/api/provider/start" => "provider_start",
        _ => "unknown",
    };
    // Fixed vocabulary only: never log request headers, token, body, query,
    // filesystem paths, provider-native IDs, or transcript content.
    eprintln!(
        "asg serve audit: action={action} outcome=capability_not_supported secret_fields=omitted"
    );
}

fn protocol_error(error: crate::protocol::ProtocolError) -> HttpResponse {
    let status = match error.code {
        crate::protocol::CanonicalCode::InvalidRequest
        | crate::protocol::CanonicalCode::CursorInvalid
        | crate::protocol::CanonicalCode::CursorExpired => 400,
        crate::protocol::CanonicalCode::NotFound => 404,
        crate::protocol::CanonicalCode::GenerationMismatch
        | crate::protocol::CanonicalCode::SchemaIncompatible => 409,
        _ => 500,
    };
    let message = match error.code {
        crate::protocol::CanonicalCode::InvalidRequest => "invalid HTTP API request",
        crate::protocol::CanonicalCode::NotFound => "requested entity not found",
        crate::protocol::CanonicalCode::CursorInvalid => "cursor is invalid",
        crate::protocol::CanonicalCode::CursorExpired => "cursor is expired",
        crate::protocol::CanonicalCode::GenerationMismatch => "catalog generation changed",
        crate::protocol::CanonicalCode::SchemaIncompatible => "catalog schema is incompatible",
        crate::protocol::CanonicalCode::WriterBusy => "catalog writer is busy",
        crate::protocol::CanonicalCode::DeadlineExceeded => "request deadline exceeded",
        crate::protocol::CanonicalCode::SourceChanged => "source changed during operation",
        crate::protocol::CanonicalCode::SourceIo => "source I/O failed",
        crate::protocol::CanonicalCode::SnapshotFailed => "source snapshot failed",
        crate::protocol::CanonicalCode::CatalogError => "catalog operation failed",
        crate::protocol::CanonicalCode::ProviderError => "provider operation failed",
        crate::protocol::CanonicalCode::CapabilityNotSupported => {
            "capability not supported in this mode"
        }
        crate::protocol::CanonicalCode::UpdateRecoveryRequired => {
            "program update recovery is required"
        }
        crate::protocol::CanonicalCode::Internal => "internal operation failed",
    };
    redacted_json(
        status,
        serde_json::json!({
            "error": {
                "code": error.code.as_str(),
                "message": message,
                "retryable": error.code.retryable(),
                "details": error.details,
            }
        }),
    )
}

/// Serialize a JSON value through the cross-boundary redactor (ADR-0009).
fn redacted_json(status: u16, value: serde_json::Value) -> HttpResponse {
    let (redacted, _status) = crate::redaction::redact_value(value);
    HttpResponse::json(status, &redacted.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Shutdown, SocketAddr};
    use std::sync::{Arc, Barrier};

    const TEST_TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn request(method: &str, path: &str, headers: Vec<(String, String)>) -> HttpRequest {
        HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            headers,
            body: Vec::new(),
        }
    }

    fn authorized(method: &str, path: &str) -> HttpRequest {
        request(
            method,
            path,
            vec![
                ("Authorization".into(), format!("Bearer {TEST_TOKEN}")),
                ("Host".into(), "127.0.0.1:8080".into()),
            ],
        )
    }

    fn start_test_server(
        connection_count: usize,
        read_timeout: Duration,
    ) -> (SocketAddr, String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let address = listener.local_addr().expect("test listener address");
        let token = TEST_TOKEN.to_string();
        let server_token = token.clone();
        let handle = std::thread::spawn(move || {
            let store = SqliteStore::open_in_memory().expect("in-memory store");
            serve_listener(
                listener,
                &server_token,
                &store,
                ServerLimits {
                    read_timeout,
                    write_timeout: Duration::from_secs(2),
                    stop_after: Some(connection_count),
                },
            )
            .expect("test server");
        });
        (address, token, handle)
    }

    fn raw_http(address: SocketAddr, request: &str) -> String {
        let mut stream = TcpStream::connect(address).expect("connect test server");
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("set client timeout");
        stream.write_all(request.as_bytes()).expect("write request");
        stream.shutdown(Shutdown::Write).expect("finish request");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        response
    }

    fn get_request(address: SocketAddr, token: &str, path: &str) -> String {
        format!("GET {path} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\n\r\n")
    }

    #[test]
    fn generate_token_is_csprng_shaped_and_unique() {
        let first = generate_token();
        let second = generate_token();
        assert_eq!(first.len(), 32);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn host_origin_token_and_proxy_guards_are_strict() {
        let valid = authorized("GET", "/api/status");
        assert!(valid.check_host_loopback());
        assert!(valid.check_origin_loopback());
        assert!(valid.check_direct_client());
        assert!(valid.check_token(TEST_TOKEN));

        let ipv6 = request(
            "GET",
            "/api/status",
            vec![("Host".into(), "[::1]:8080".into())],
        );
        assert!(ipv6.check_host_loopback());

        let bad_port = request(
            "GET",
            "/api/status",
            vec![("Host".into(), "localhost:not-a-port".into())],
        );
        assert!(!bad_port.check_host_loopback());

        let wrong_origin = request(
            "GET",
            "/api/status",
            vec![
                ("Host".into(), "127.0.0.1:8080".into()),
                ("Origin".into(), "http://127.0.0.1:8081".into()),
            ],
        );
        assert!(!wrong_origin.check_origin_loopback());

        let proxied = request(
            "GET",
            "/api/status",
            vec![("X-Forwarded-For".into(), "127.0.0.1".into())],
        );
        assert!(!proxied.check_direct_client());
    }

    /// `header` returns `None` for a duplicated value, and a *missing* Origin is
    /// deliberately treated as same-origin — so reusing it here let two Origin
    /// headers walk through the cross-origin gate: one bad Origin answered 403,
    /// the same bad Origin sent twice answered 200. Ambiguity must fail closed,
    /// the way a duplicated Host and Authorization already do.
    #[test]
    fn duplicate_origin_header_cannot_bypass_the_cross_origin_guard() {
        let store = SqliteStore::open_in_memory().expect("store");
        let mut duplicated = authorized("GET", "/api/status");
        duplicated
            .headers
            .push(("Origin".into(), "http://evil.test".into()));
        duplicated
            .headers
            .push(("Origin".into(), "http://evil.test".into()));
        assert!(!duplicated.check_origin_loopback());
        let response = route_request(&duplicated, TEST_TOKEN, &store);
        assert_eq!(response.status, 403, "{}", response.body);
        assert!(
            response.body.contains("forbidden_origin"),
            "{}",
            response.body
        );
    }

    #[test]
    fn percent_decode_handles_unicode_and_rejects_bad_escape() {
        assert_eq!(percent_decode("hello+world"), Some("hello world".into()));
        assert_eq!(percent_decode("%E9%85%8D%E7%BD%AE"), Some("配置".into()));
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%0A"), None);
        assert_eq!(percent_decode("%"), None);
        assert_eq!(percent_decode("%A"), None);
    }

    #[test]
    fn routes_require_auth_and_preserve_bootstrap_only_for_the_page() {
        let store = SqliteStore::open_in_memory().expect("store");
        let no_token = request(
            "GET",
            "/api/status",
            vec![("Host".into(), "127.0.0.1:8080".into())],
        );
        assert_eq!(route_request(&no_token, TEST_TOKEN, &store).status, 401);

        let bad_host = request(
            "GET",
            "/api/status",
            vec![
                ("Authorization".into(), format!("Bearer {TEST_TOKEN}")),
                ("Host".into(), "example.test".into()),
            ],
        );
        assert_eq!(route_request(&bad_host, TEST_TOKEN, &store).status, 403);

        // A query string is never a credential: the page is served for
        // `/?token=…` because it is the static UI route, but the token there
        // is inert (the UI reads only the fragment), and
        // `/api/status?token=…` stays unauthorized like any other data route.
        let query_token_page = request(
            "GET",
            &format!("/?token={TEST_TOKEN}"),
            vec![("Host".into(), "127.0.0.1:8080".into())],
        );
        let response = route_request(&query_token_page, TEST_TOKEN, &store);
        assert_eq!(response.status, 200);
        assert!(response.body.contains("data-shell=\"asg-web\""));

        let api_query_token = request(
            "GET",
            &format!("/api/status?token={TEST_TOKEN}"),
            vec![("Host".into(), "127.0.0.1:8080".into())],
        );
        assert_eq!(
            route_request(&api_query_token, TEST_TOKEN, &store).status,
            401
        );

        // The fragment-based flow loads the page with NO credential at all —
        // a fragment is never sent to the server, so `GET /` arrives bare.
        // The static page must still load (the UI reads the token from
        // `location.hash` and puts it in the Authorization header itself);
        // data routes must not.
        let bare_page = request("GET", "/", vec![("Host".into(), "127.0.0.1:8080".into())]);
        let response = route_request(&bare_page, TEST_TOKEN, &store);
        assert_eq!(response.status, 200);
        assert!(response.body.contains("data-shell=\"asg-web\""));
    }

    #[test]
    fn core_preview_routes_use_the_shared_dispatch_contract() {
        let store = SqliteStore::open_in_memory().expect("store");
        for path in [
            "/api/status",
            "/api/providers",
            "/api/search?q=needle&mode=lexical&limit=20",
            "/api/search?q=needle&repo=github.com/synthetic-owner/synthetic-repo",
            "/api/handoff?q=needle",
        ] {
            let response = route_request(&authorized("GET", path), TEST_TOKEN, &store);
            assert_eq!(response.status, 200, "{path}: {}", response.body);
            let body: serde_json::Value = serde_json::from_str(&response.body).expect("JSON");
            assert!(body.get("data").is_some());
            assert_eq!(body.get("outcome"), Some(&serde_json::json!("success")));
        }

        let invalid = route_request(
            &authorized("GET", "/api/show?id=C%3A%2FUsers%2Falice%2Fsecret.jsonl"),
            TEST_TOKEN,
            &store,
        );
        assert_eq!(invalid.status, 400);
        assert!(!invalid.body.contains("C:/Users"));
        assert!(!invalid.body.contains("secret.jsonl"));
    }

    /// Once a request is typed, a value equal to a CLI flag cannot influence
    /// parsing. The old argv bridge rejected `q=--repo`; now it is search text
    /// and `repo` remains an independent filter, the same way MCP treats it.
    #[test]
    fn flag_named_values_are_literal_data_not_reparsed_argv() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let store = SqliteStore::open_in_memory().unwrap();
        let source = dir.path().join("flag-value.jsonl");
        std::fs::write(
            &source,
            r#"{"params":{"update":{"sessionUpdate":"user_message_chunk","content":"literal --repo evidence"},"_meta":{"promptIndex":0}}}"#,
        )
        .unwrap();
        crate::ingest_file(&store, source.to_str().unwrap()).unwrap();

        let response = route_request(
            &authorized("GET", "/api/search?q=--repo"),
            TEST_TOKEN,
            &store,
        );
        assert_eq!(response.status, 200, "{}", response.body);
        let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(body["data"]["hits"].as_array().unwrap().len(), 1, "{body}");
        assert_eq!(body["data"]["hits"][0]["text"], "literal --repo evidence");

        for path in [
            "/api/search?q=needle&mode=-x",
            "/api/projection/search?q=--cursor&cursor=needle",
            "/api/show?id=--yes",
            "/api/show/--yes",
            "/api/resume?session=--yes",
            "/api/resume/--yes",
        ] {
            let response = route_request(&authorized("GET", path), TEST_TOKEN, &store);
            assert_eq!(response.status, 400, "{path}: {}", response.body);
        }
    }

    #[test]
    fn web_and_cli_search_build_the_same_typed_request() {
        let request = authorized(
            "GET",
            "/api/search?q=needle&mode=hybrid&limit=5&max_bytes=4096&provider=claude&provider=grok-build&sidechain=subagent_only&tool_kind=command&tool_name=Bash&repo=github.com/synthetic-owner/synthetic-repo&include_system=true&group_by_session=true",
        );
        let web = search_command(&request).unwrap_or_else(|response| panic!("{}", response.body));
        let argv = [
            "search",
            "needle",
            "--mode",
            "hybrid",
            "--max-items",
            "5",
            "--max-bytes",
            "4096",
            "--provider",
            "claude",
            "--provider",
            "grok-build",
            "--subagent-only",
            "--tool-kind",
            "command",
            "--tool-name",
            "Bash",
            "--repo",
            "github.com/synthetic-owner/synthetic-repo",
            "--include-system",
            "--group-by-session",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        let cli = crate::search_command_from_args(&argv, crate::protocol::OutputMode::Json)
            .expect("CLI search command");
        assert_eq!(web.query, cli.query);
        assert_eq!(web.filters, cli.filters);
        assert_eq!(web.facets, cli.facets);
        assert_eq!(web.limit, cli.limit);
        assert_eq!(web.cursor, cli.cursor);
        assert_eq!(web.budget, cli.budget);
        assert_eq!(web.include_system, cli.include_system);
        assert_eq!(web.group_by_session, cli.group_by_session);
        assert_eq!(web.mode, cli.mode);
    }

    #[test]
    fn every_data_route_rejects_unknown_duplicate_empty_or_invalid_parameters() {
        let store = SqliteStore::open_in_memory().expect("store");
        for path in [
            "/health?unexpected=true",
            "/api/status?unexpected=true",
            "/api/providers?unexpected=true",
            "/api/search?q=x&unexpected=true",
            "/api/context?session=x&unexpected=true",
            "/api/handoff?q=x&unexpected=true",
            "/api/show?id=x&unexpected=true",
            "/api/resume?session=x&unexpected=true",
            "/api/search?q=x&mode=lexical&mode=semantic",
            "/api/context?session=x&session=y",
            "/api/handoff?q=x&q=y",
            "/api/show?id=x&id=y",
            "/api/resume?session=x&session=y",
            "/api/search?q=x&max_bytes=",
            "/api/context?session=x&policy=",
            "/api/handoff?q=",
            "/api/show?id=",
            "/api/resume?session=",
            "/api/search?q=x&tool_name=%0A",
            "/api/search?q=x&&mode=lexical",
            "/api/search?q=x&mode",
            "/api/search?q=x&provider=",
            "/api/status?a&",
        ] {
            let response = route_request(&authorized("GET", path), TEST_TOKEN, &store);
            assert_eq!(response.status, 400, "{path}: {}", response.body);
            assert!(
                response.body.contains("invalid_request"),
                "{path}: {}",
                response.body
            );
        }

        // An empty query string is equivalent to no query string.
        assert_eq!(
            route_request(&authorized("GET", "/api/status?"), TEST_TOKEN, &store,).status,
            200
        );
    }

    #[test]
    fn handoff_applies_repeated_provider_values() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let store = SqliteStore::open_in_memory().unwrap();
        let source = dir.path().join("handoff-providers.jsonl");
        std::fs::write(
            &source,
            r#"{"params":{"update":{"sessionUpdate":"user_message_chunk","content":"provider union needle"},"_meta":{"promptIndex":0}}}"#,
        )
        .unwrap();
        crate::ingest_file(&store, source.to_str().unwrap()).unwrap();
        let response = route_request(
            &authorized(
                "GET",
                "/api/handoff?q=needle&provider=claude&provider=grok-build",
            ),
            TEST_TOKEN,
            &store,
        );
        assert_eq!(response.status, 200, "{}", response.body);
        let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();
        assert_eq!(
            body["data"]["query"]["filters"]["providers"],
            serde_json::json!(["claude-code", "grok-build"]),
            "{body}"
        );
        assert!(
            body["data"]["evidence"]
                .as_array()
                .is_some_and(|items| !items.is_empty()),
            "{body}"
        );

        // Repo is a Web parity parameter: a non-matching scope must exclude
        // evidence in handoff exactly as it does in search.
        let scoped = route_request(
            &authorized("GET", "/api/handoff?q=needle&repo=synthetic/repo"),
            TEST_TOKEN,
            &store,
        );
        assert_eq!(scoped.status, 200, "{}", scoped.body);
        let body: serde_json::Value = serde_json::from_str(&scoped.body).unwrap();
        assert_eq!(body["data"]["matched_sessions"], serde_json::json!([]));
        assert_eq!(body["data"]["evidence"], serde_json::json!([]));
    }

    #[test]
    fn resume_preview_is_read_only_and_never_acknowledges_the_first_run_marker() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let db = dir.path().join("data.db");
        let store = SqliteStore::open_for_write(db.to_str().unwrap()).expect("store");
        let source = dir.path().join("resume.jsonl");
        let marker = dir
            .path()
            .join(agent_session_grep_application::resume::RESUME_PREVIEW_ACK_FILE);
        std::fs::write(
            &source,
            r#"{"type":"user","uuid":"c0000000-0000-4000-8000-000000000001","parentUuid":null,"sessionId":"ccdd1234-5678-4abc-8def-001122334455","cwd":null,"timestamp":"2026-07-26T01:00:00.000Z","message":{"role":"user","content":"resume preview"}}"#,
        )
        .unwrap();
        crate::ingest_file(&store, source.to_str().unwrap()).unwrap();
        let (_, data, _, _) = crate::read_commands::search(
            &store,
            crate::read_commands::SearchCommand {
                query: "resume preview".into(),
                filters: SearchFilters::default(),
                facets: SearchFacets::default(),
                limit: 1,
                cursor: None,
                budget: ResponseBudget::default(),
                include_system: true,
                group_by_session: false,
                mode: agent_session_grep_ports::RetrievalMode::Lexical,
                attach_session_rows: false,
            },
        )
        .unwrap();
        let session_wire = data["hits"][0]["session_id"]
            .as_str()
            .expect("fixture session")
            .to_string();

        assert!(!marker.exists());
        let first = route_request(
            &authorized("GET", &format!("/api/resume?session={session_wire}")),
            TEST_TOKEN,
            &store,
        );
        assert_eq!(first.status, 200, "{}", first.body);
        let body: serde_json::Value = serde_json::from_str(&first.body).unwrap();
        assert_eq!(body["data"]["available"], true, "{body}");
        assert_eq!(body["data"]["executed"], false, "{body}");
        assert!(
            body["data"]["command"]
                .as_str()
                .is_some_and(|command| command.contains("--resume")),
            "{body}"
        );
        assert!(
            !marker.exists(),
            "a Web GET must not acknowledge the CLI execution gate"
        );

        let second = route_request(
            &authorized("GET", &format!("/api/resume?session={session_wire}")),
            TEST_TOKEN,
            &store,
        );
        assert_eq!(second.status, 200, "{}", second.body);
        assert!(!marker.exists(), "repeated previews stay side-effect free");
    }

    #[test]
    fn web_search_applies_provider_union_and_reports_its_capabilities() {
        let dir = agent_session_grep_testkit::tempdir().unwrap();
        let store = SqliteStore::open_in_memory().unwrap();
        let source = dir.path().join("grok.jsonl");
        std::fs::write(&source, r#"{"params":{"update":{"sessionUpdate":"user_message_chunk","content":"needle web"},"_meta":{"promptIndex":0}}}"#).unwrap();
        crate::ingest_file(&store, source.to_str().unwrap()).unwrap();
        crate::build_embeddings(&store).unwrap();
        for mode in ["lexical", "semantic", "hybrid"] {
            let response = route_request(
                &authorized(
                    "GET",
                    &format!(
                        "/api/search?q=needle&provider=claude&provider=grok-build&mode={mode}&max_bytes=4096&sidechain=main_only"
                    ),
                ),
                TEST_TOKEN,
                &store,
            );
            assert_eq!(response.status, 200, "{}", response.body);
            let body: serde_json::Value = serde_json::from_str(&response.body).unwrap();
            assert_eq!(body["data"]["retrieval_mode"], mode);
            assert_eq!(body["data"]["hits"].as_array().unwrap().len(), 1, "{body}");
            assert_eq!(body["data"]["hits"][0]["text"], "needle web");
        }
        let status = route_request(&authorized("GET", "/api/status"), TEST_TOKEN, &store);
        let body: serde_json::Value = serde_json::from_str(&status.body).unwrap();
        assert_eq!(
            body["data"]["web_capabilities"]["search_parameters"],
            serde_json::json!(WEB_SEARCH_PARAMETERS)
        );
        assert_eq!(
            body["data"]["web_capabilities"]["mutation_and_execution"],
            false
        );
    }

    #[test]
    fn post_requires_origin_and_csrf_then_reports_unsupported() {
        let store = SqliteStore::open_in_memory().expect("store");
        let missing_origin = authorized("POST", "/api/resume");
        assert_eq!(
            route_request(&missing_origin, TEST_TOKEN, &store).status,
            403
        );

        let mut valid_guard = authorized("POST", "/api/resume");
        valid_guard
            .headers
            .push(("Origin".into(), "http://127.0.0.1:8080".into()));
        assert_eq!(route_request(&valid_guard, TEST_TOKEN, &store).status, 403);
        valid_guard
            .headers
            .push(("X-CSRF-Token".into(), TEST_TOKEN.into()));
        let response = route_request(&valid_guard, TEST_TOKEN, &store);
        assert_eq!(response.status, 501);
        assert!(response.body.contains("capability_not_supported"));
    }

    #[test]
    fn http_response_emits_security_and_length_headers() {
        let resp = HttpResponse::json(200, r#"{"ok":true}"#);
        let text = String::from_utf8(resp.to_bytes()).expect("HTTP bytes");
        assert!(text.starts_with("HTTP/1.1 200 OK"));
        assert!(text.contains("Content-Type: application/json; charset=utf-8"));
        assert!(text.contains("X-Content-Type-Options: nosniff"));
        assert!(text.contains("Referrer-Policy: no-referrer"));
        assert!(text.contains(r#"{"ok":true}"#));
    }

    #[test]
    fn integration_rejects_bad_token_host_and_origin() {
        let (address, token, server) = start_test_server(4, Duration::from_secs(2));
        let bad_token = raw_http(
            address,
            &format!(
                "GET /api/status HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer wrong\r\n\r\n"
            ),
        );
        assert!(bad_token.starts_with("HTTP/1.1 401"));

        let bad_host = raw_http(
            address,
            &format!(
                "GET /api/status HTTP/1.1\r\nHost: evil.test\r\nAuthorization: Bearer {token}\r\n\r\n"
            ),
        );
        assert!(bad_host.starts_with("HTTP/1.1 403"));

        let bad_origin = raw_http(
            address,
            &format!(
                "GET /api/status HTTP/1.1\r\nHost: {address}\r\nOrigin: http://127.0.0.1:9\r\nAuthorization: Bearer {token}\r\n\r\n"
            ),
        );
        assert!(bad_origin.starts_with("HTTP/1.1 403"));

        let ok = raw_http(address, &get_request(address, &token, "/api/status"));
        assert!(ok.starts_with("HTTP/1.1 200"));
        server.join().expect("server join");
    }

    /// Windows' `accept` hands back a socket that inherited the listener's
    /// non-blocking flag (`set_nonblocking(true)` is what keeps the accept poll
    /// off the event loop). Without restoring blocking mode the read deadline is
    /// inert: a request whose bytes land a moment after `accept` makes
    /// `parse_request` return `WouldBlock`, which the server reports as 408 — 2
    /// of 140 valid requests were answered that way against the real catalog,
    /// and a half-closing client lost the response entirely to the RST that
    /// followed. Delay the request past any accept-time read to pin it.
    #[test]
    fn integration_delayed_request_is_served_not_timed_out() {
        let (address, token, server) = start_test_server(1, Duration::from_secs(5));
        let mut stream = TcpStream::connect(address).expect("connect test server");
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("set client timeout");
        std::thread::sleep(Duration::from_millis(200));
        stream
            .write_all(get_request(address, &token, "/api/status").as_bytes())
            .expect("write request");
        stream.shutdown(Shutdown::Write).expect("finish request");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        server.join().expect("server join");
    }

    /// The limit means "this many headers are accepted": counting at the top of
    /// the loop spent one iteration on the terminating blank line, so a
    /// well-formed request carrying exactly `MAX_HEADER_COUNT` headers was
    /// rejected 400 and the real ceiling was 99. Pin both sides of the boundary.
    #[test]
    fn integration_accepts_exactly_max_header_count_headers() {
        let (address, token, server) = start_test_server(2, Duration::from_secs(3));
        let required = format!("Host: {address}\r\nAuthorization: Bearer {token}\r\n");
        let pad = |count: usize| {
            (0..count)
                .map(|index| format!("X-Pad-{index}: v\r\n"))
                .collect::<String>()
        };
        let at_limit = raw_http(
            address,
            &format!(
                "GET /api/status HTTP/1.1\r\n{required}{}\r\n",
                pad(MAX_HEADER_COUNT - 2)
            ),
        );
        assert!(at_limit.starts_with("HTTP/1.1 200"), "{at_limit}");
        let over_limit = raw_http(
            address,
            &format!(
                "GET /api/status HTTP/1.1\r\n{required}{}\r\n",
                pad(MAX_HEADER_COUNT - 1)
            ),
        );
        assert!(over_limit.starts_with("HTTP/1.1 400"), "{over_limit}");
        server.join().expect("server join");
    }

    /// Slowloris isolation is a **structural** property, not a latency budget.
    /// The read timeout here is long enough that the parked connection provably
    /// cannot be reaped first, so a 200 can only mean the fast request was
    /// served alongside it; a server that serialised would stall past
    /// `raw_http`'s own client read timeout and fail loudly. An absolute
    /// wall-clock assertion instead measured how loaded the host was — it
    /// flaked in a full `--workspace` run while passing in isolation.
    #[test]
    fn integration_slowloris_does_not_block_a_fast_get() {
        let (address, token, server) = start_test_server(2, Duration::from_secs(30));
        let mut slow = TcpStream::connect(address).expect("connect slow client");
        slow.write_all(b"GET /api/status HTTP/1.1\r\nHost:")
            .expect("write partial request");

        let fast = raw_http(address, &get_request(address, &token, "/api/status"));
        assert!(fast.starts_with("HTTP/1.1 200"), "{fast}");

        // Release the parked connection so the second slot completes and
        // `stop_after` is reached without waiting out the 30s read timeout.
        drop(slow);
        server.join().expect("server join");
    }

    /// The reaping half of the same guard, with no timing assertion: a client
    /// that never finishes its headers is answered 408 once the server's own
    /// read timeout expires, whenever that happens to be.
    #[test]
    fn integration_stalled_headers_are_answered_408() {
        let (address, _token, server) = start_test_server(1, Duration::from_millis(300));
        let mut slow = TcpStream::connect(address).expect("connect slow client");
        slow.set_read_timeout(Some(Duration::from_secs(10)))
            .expect("slow read timeout");
        slow.write_all(b"GET /api/status HTTP/1.1\r\nHost:")
            .expect("write partial request");

        let mut slow_response = String::new();
        slow.read_to_string(&mut slow_response)
            .expect("read timeout response");
        assert!(slow_response.starts_with("HTTP/1.1 408"), "{slow_response}");
        server.join().expect("server join");
    }

    #[test]
    fn integration_concurrent_gets_complete_on_bounded_pool() {
        const CLIENTS: usize = 8;
        let (address, token, server) = start_test_server(CLIENTS, Duration::from_secs(2));
        let barrier = Arc::new(Barrier::new(CLIENTS));
        let clients = (0..CLIENTS)
            .map(|_| {
                let barrier = Arc::clone(&barrier);
                let token = token.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    raw_http(address, &get_request(address, &token, "/api/status"))
                })
            })
            .collect::<Vec<_>>();
        for client in clients {
            let response = client.join().expect("client join");
            assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        }
        server.join().expect("server join");
    }

    #[test]
    fn integration_unsupported_post_echoes_no_secret_or_path() {
        let (address, token, server) = start_test_server(1, Duration::from_secs(2));
        let body =
            r#"{"token":"ghp_example_secret_value","path":"C:/Users/alice/transcript.jsonl"}"#;
        let request = format!(
            "POST /api/resume HTTP/1.1\r\nHost: {address}\r\nOrigin: http://{address}\r\nAuthorization: Bearer {token}\r\nX-CSRF-Token: {token}\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = raw_http(address, &request);
        assert!(response.starts_with("HTTP/1.1 501"));
        assert!(response.contains("capability_not_supported"));
        assert!(!response.contains("ghp_example"));
        assert!(!response.contains("C:/Users"));
        assert!(!response.contains(&token));
        server.join().expect("server join");
    }

    #[test]
    fn embedded_ui_is_offline_and_uses_safe_dom_projection() {
        assert!(!WEB_UI_HTML.contains("http://"));
        assert!(!WEB_UI_HTML.contains("https://"));
        assert!(!WEB_UI_HTML.contains("innerHTML"));
        for endpoint in [
            "/api/status",
            "/api/providers",
            "/api/search",
            "/api/show",
            "/api/context",
            "/api/handoff",
            "/api/resume",
        ] {
            assert!(WEB_UI_HTML.contains(endpoint), "missing {endpoint}");
        }
    }

    /// The UI hides regions with the `hidden` attribute, but `[hidden]` is only
    /// a UA-stylesheet `display: none`: any author `display` rule on the same
    /// element wins and the region stays visible. `.gate` sets `display: grid`
    /// and `.shell` sets `display: flex`, so without an author-level
    /// `[hidden] { display: none !important }` the token gate and the app shell
    /// render on top of each other and the gate's button looks dead. Pin both
    /// the rule and every element that depends on it.
    #[test]
    fn embedded_ui_enforces_the_hidden_attribute_over_author_display_rules() {
        assert!(
            WEB_UI_HTML.contains("[hidden] { display: none !important; }"),
            "author-level [hidden] override is required: `.gate`/`.shell` set display"
        );
        for id in [
            "gate",
            "shell",
            "contextPanel",
            "detailEmpty",
            "previewOutput",
        ] {
            assert!(
                WEB_UI_HTML.contains(&format!("id=\"{id}\"")),
                "missing element #{id} that the hidden-attribute contract covers"
            );
        }
    }

    /// Every `data-i18n` key the markup asks for must exist in **both**
    /// dictionaries, or the toggle silently blanks that control (an empty
    /// button is indistinguishable from a broken one). Both directions are
    /// checked: a key added to the markup without a translation, and a key
    /// present in one language only.
    #[test]
    fn embedded_ui_translates_every_referenced_i18n_key() {
        let keys: Vec<&str> = WEB_UI_HTML
            .match_indices("data-i18n=\"")
            .map(|(index, marker)| {
                let rest = &WEB_UI_HTML[index + marker.len()..];
                &rest[..rest.find('"').expect("unterminated data-i18n value")]
            })
            .collect();
        assert!(keys.len() >= 10, "expected the markup to use i18n keys");

        let zh_start = WEB_UI_HTML.find("  zh: {").expect("zh dictionary");
        let en_start = WEB_UI_HTML.find("  en: {").expect("en dictionary");
        assert!(zh_start < en_start, "dictionary order assumption changed");
        let zh = &WEB_UI_HTML[zh_start..en_start];
        let en_end = WEB_UI_HTML[en_start..]
            .find("\n};")
            .expect("dictionary terminator");
        let en = &WEB_UI_HTML[en_start..en_start + en_end];

        for key in keys {
            assert!(zh.contains(&format!("{key}:")), "zh missing i18n key {key}");
            assert!(en.contains(&format!("{key}:")), "en missing i18n key {key}");
        }
    }

    /// The source text between `anchor` and the first following `terminator`.
    /// Pins a behaviour to the handler that has to implement it: a bare
    /// whole-file `contains` passes when the required call sits anywhere at all,
    /// which is how a defect in one handler hides behind another's code.
    fn ui_slice(anchor: &str, terminator: &str) -> &'static str {
        let start = WEB_UI_HTML
            .find(anchor)
            .unwrap_or_else(|| panic!("web UI no longer contains `{anchor}`"));
        let rest = &WEB_UI_HTML[start..];
        let end = rest
            .find(terminator)
            .unwrap_or_else(|| panic!("`{anchor}` is not terminated by `{terminator}`"));
        &rest[..end + terminator.len()]
    }

    /// A URL that differs from the current one only in its fragment is a
    /// same-document navigation: the script does not re-run. So pasting the
    /// fresh `#token=…` line into the tab that is already open — exactly what
    /// the gate's rejection text instructs after serve rotates the token — left
    /// the gate sitting there unchanged, with the dead token still in storage.
    /// The fragment read has to be reachable again from `hashchange`.
    #[test]
    fn embedded_ui_reads_the_token_again_when_only_the_fragment_changes() {
        assert!(
            WEB_UI_HTML.contains("function readUrlToken()"),
            "the fragment read must be a function, not inline boot-only code"
        );
        let handler = ui_slice("window.addEventListener('hashchange'", "\n});");
        assert!(
            handler.contains("readUrlToken()"),
            "hashchange must re-read the fragment: {handler}"
        );
        assert!(
            handler.contains("acceptToken("),
            "a token found on hashchange must authenticate: {handler}"
        );
    }

    /// A preview belongs to the session it was opened from. `closeContext` hid
    /// it but `loadContext` did not, so opening session B while session A's
    /// resume preview was on screen left A's `--resume` command under B's
    /// header — a command that resumes the wrong session if copied.
    #[test]
    fn embedded_ui_scopes_the_preview_pane_to_the_open_session() {
        let load_context = ui_slice("async function loadContext(", "\n}");
        assert!(
            load_context.contains("previewOutput"),
            "opening a session must reset the preview pane: {load_context}"
        );
        assert!(
            load_context.contains("hidden = true"),
            "the preview pane must be hidden, not just emptied: {load_context}"
        );
    }

    /// `applyI18n()` only rewrites `[data-i18n]` markup and the select options.
    /// Everything else on screen came from `t()` at render time, so the toggle
    /// used to leave the status line, every hit card's session line, the session
    /// title and each `show` button in the previous language — an English UI
    /// reading "已连接 · 第 4 代 · 38 条记录". The toggle must re-run those
    /// renderers.
    #[test]
    fn embedded_ui_rerenders_dynamic_strings_when_the_language_changes() {
        let toggle = ui_slice("getElementById('langToggle').addEventListener", "\n});");
        for call in ["applyI18n()", "renderHits(", "loadContext(", "init()"] {
            assert!(
                toggle.contains(call),
                "language toggle must re-render via `{call}`: {toggle}"
            );
        }
    }

    /// The counter beside the "Hits" heading reported the last page's length,
    /// not what is on screen: paging 2 at a time through 18 hits left it reading
    /// "lexical · 2" under an 18-row list.
    #[test]
    fn embedded_ui_counts_every_loaded_page_in_the_hit_meta() {
        let meta = ui_slice("async function doSearch(", "\n}");
        assert!(
            meta.contains("lastHits.length"),
            "the hit meta must count all loaded pages: {meta}"
        );
    }

    /// Closing the context reset `activeHit` but left the `.active` class on the
    /// card, so the sidebar kept showing a selected hit with nothing open.
    #[test]
    fn embedded_ui_clears_the_hit_highlight_when_the_context_closes() {
        let close = ui_slice("function closeContext()", "\n}");
        assert!(
            close.contains("classList.remove('active')"),
            "closing the context must drop the hit highlight: {close}"
        );
    }

    /// `white-space: pre-wrap` breaks at soft opportunities only, and transcript
    /// text is full of runs with none (absolute paths, URLs, base64, hashes). A
    /// single 400-character run measured 3233px inside a 990px pane, giving the
    /// message list a horizontal scrollbar. Both text surfaces need a break rule.
    #[test]
    fn embedded_ui_wraps_unbreakable_runs_in_message_and_preview_text() {
        for anchor in [".msg-body {", "pre.preview {"] {
            let rule = ui_slice(anchor, "}");
            assert!(
                rule.contains("white-space: pre-wrap") && rule.contains("overflow-wrap:"),
                "`{anchor}` wraps pre-formatted text and needs overflow-wrap: {rule}"
            );
        }
    }

    /// `frame-ancestors` is defined to be ignored in a meta-delivered policy and
    /// the browser logs a CSP error for it on every page load. The directive is
    /// only real on the HTTP response, so the meta tag must not carry it while
    /// the served header still must.
    #[test]
    fn embedded_ui_meta_csp_omits_the_directive_only_a_header_can_carry() {
        let meta = ui_slice("<meta http-equiv=\"Content-Security-Policy\"", ">");
        assert!(
            !meta.contains("frame-ancestors"),
            "meta CSP must not declare frame-ancestors: {meta}"
        );

        let store = SqliteStore::open_in_memory().expect("store");
        let page = route_request(&authorized("GET", "/"), TEST_TOKEN, &store);
        let csp = page
            .headers
            .iter()
            .find(|(name, _)| *name == "Content-Security-Policy")
            .map(|(_, value)| *value)
            .expect("the UI page must send a CSP header");
        assert!(
            csp.contains("frame-ancestors 'none'"),
            "the header keeps the framing protection the meta tag cannot: {csp}"
        );
    }

    /// With no icon declared the browser probes `/favicon.ico` on its own. That
    /// path is not the UI page, so it needs a bearer token the probe never
    /// carries — a 401 in the console on every load. An inline `data:` icon
    /// stops the request; `img-src ... data:` already permits it.
    #[test]
    fn embedded_ui_declares_an_inline_icon_so_no_favicon_probe_is_made() {
        assert!(
            WEB_UI_HTML.contains("rel=\"icon\"") && WEB_UI_HTML.contains("href=\"data:"),
            "the page must declare an inline icon"
        );
    }

    /// A credential the server refused must not be replayed: keeping it made
    /// every later load paint the authenticated shell, wait out a `/health`
    /// round-trip, and only then fall back to the gate.
    #[test]
    fn embedded_ui_forgets_a_rejected_token() {
        let show_gate = ui_slice("function showGate(", "\n}");
        assert!(
            show_gate.contains("removeItem(TOKEN_KEY)"),
            "a rejected token must be dropped from storage: {show_gate}"
        );
    }

    #[test]
    fn embedded_ui_bytes_input_matches_the_server_budget_floor() {
        let ui = WEB_UI_HTML;
        let tag_start = ui.find("<input id=\"maxBytes\"").expect("maxBytes input");
        let tag_end = ui[tag_start..]
            .find('>')
            .map(|end| tag_start + end)
            .unwrap();
        let tag = &ui[tag_start..=tag_end];
        let minimum = format!(
            "min=\"{}\"",
            agent_session_grep_application::budget::MIN_RESPONSE_BYTES
        );
        assert!(tag.contains(&minimum), "{tag}");
    }

    /// `.ctl-row label` sets `flex: none` and beats `.ctl-row > *` on
    /// specificity, so the filter controls could not shrink to the 248px
    /// sidebar: they needed 308px and the page-size input was cut in half at the
    /// sidebar edge. The row must be allowed to wrap.
    #[test]
    fn embedded_ui_lets_the_filter_row_wrap_inside_the_sidebar() {
        let rule = ui_slice(".ctl-row {", "}");
        assert!(
            rule.contains("flex-wrap: wrap"),
            "unshrinkable filter labels overflow the sidebar without wrapping: {rule}"
        );
    }

    #[test]
    fn serve_session_generates_token_and_loopback_address() {
        let session = ServeSession::bind_loopback(0).expect("session");
        assert_eq!(session.token().len(), 32);
        assert_eq!(session.address(), "127.0.0.1:0");
    }

    /// Slow queries run on the dedicated router thread, so accepts keep
    /// completing while one route is parked: after the slow request has been
    /// submitted, a fast GET must still be answered. Before the router thread,
    /// routing ran on the listener thread and this request would have stalled
    /// behind the parked route until the client's own timeout.
    #[test]
    fn integration_slow_route_does_not_block_accepts() {
        let (address, token, server) = start_test_server(2, Duration::from_secs(5));
        let mut parked = TcpStream::connect(address).expect("connect parked client");
        parked
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("parked read timeout");
        parked
            .write_all(get_request(address, &token, "/api/search?q=needle").as_bytes())
            .expect("submit parked request");
        parked
            .shutdown(Shutdown::Write)
            .expect("finish parked request");

        let fast = raw_http(address, &get_request(address, &token, "/health"));
        assert!(fast.starts_with("HTTP/1.1 200"), "{fast}");

        // The parked route completes on the router thread once the fast
        // response is out, so `stop_after` is reached without waiting out the
        // server's read timeout.
        let mut parked_response = String::new();
        parked
            .read_to_string(&mut parked_response)
            .expect("read parked response");
        assert!(
            parked_response.starts_with("HTTP/1.1 200"),
            "{parked_response}"
        );
        drop(parked);
        server.join().expect("server join");
    }

    /// Text responses must emit X-Content-Type-Options exactly once: the
    /// builder also pushed it, so `to_bytes` sent a duplicate header (Info).
    #[test]
    fn text_response_emits_nosniff_exactly_once() {
        let response = HttpResponse::text(200, "body", "text/html; charset=utf-8");
        let bytes = String::from_utf8(response.to_bytes()).expect("HTTP bytes");
        assert_eq!(
            bytes.matches("X-Content-Type-Options:").count(),
            1,
            "{bytes}"
        );
    }
}
