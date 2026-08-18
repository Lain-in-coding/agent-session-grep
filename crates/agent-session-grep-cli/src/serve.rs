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
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use agent_session_grep_adapters_sqlite::SqliteStore;

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
/// Network reads and writes run in a fixed-size worker pool. The Application
/// ADT stays on the listener thread because `SqliteStore` deliberately owns a
/// non-`Sync` SQLite connection; parsed requests are routed serially while a
/// slow or non-reading client can occupy at most one bounded worker slot.
pub fn run(
    session: &ServeSession,
    db: &str,
    offline: bool,
    store: &SqliteStore,
) -> Result<crate::protocol::Outcome, crate::CliError> {
    let listener = TcpListener::bind(session.address())
        .map_err(|e| crate::CliError::usage(format!("serve: bind failed: {e}")))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| crate::CliError::usage(format!("serve: local address unavailable: {e}")))?;
    eprintln!(
        "asg serve: open http://{local_addr}/?token={}",
        session.token()
    );
    eprintln!("asg serve: loopback-only; LAN mode is capability_not_supported");
    serve_listener(
        listener,
        session.token(),
        db,
        offline,
        store,
        ServerLimits::production(),
    )
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
    db: &str,
    offline: bool,
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

        let mut accepted = 0usize;
        let mut completed = 0usize;
        loop {
            let accepting = limits.stop_after.is_none_or(|max| accepted < max);
            let in_flight = accepted.saturating_sub(completed);
            if accepting && in_flight < WORKER_COUNT + QUEUE_CAPACITY {
                match listener.accept() {
                    Ok((stream, _peer)) => match work_tx.try_send(stream) {
                        Ok(()) => accepted += 1,
                        Err(TrySendError::Full(_)) => {}
                        Err(TrySendError::Disconnected(_)) => {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::BrokenPipe,
                                "HTTP worker pool stopped",
                            ));
                        }
                    },
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
            }

            match event_rx.recv_timeout(Duration::from_millis(5)) {
                Ok(event) => handle_worker_event(event, token, db, offline, store, &mut completed),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
            while let Ok(event) = event_rx.try_recv() {
                handle_worker_event(event, token, db, offline, store, &mut completed);
            }

            if limits.stop_after.is_some_and(|max| completed >= max) {
                break;
            }
        }
        drop(work_tx);
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

fn handle_worker_event(
    event: WorkerEvent,
    token: &str,
    db: &str,
    offline: bool,
    store: &SqliteStore,
    completed: &mut usize,
) {
    match event {
        WorkerEvent::Parsed { request, reply } => {
            let response = match request {
                Ok(request) => route_request(&request, token, db, offline, store),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) =>
                {
                    fixed_error(408, "request_timeout", "request timed out")
                }
                Err(_) => fixed_error(400, "invalid_request", "malformed HTTP request"),
            };
            let _ = reply.send(response);
        }
        WorkerEvent::Completed => *completed += 1,
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
        let Some(origin) = self.header("origin") else {
            return true;
        };
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

    /// Extract a query-string parameter from the request path (percent-
    /// decoding is minimal: '+' as space; other escapes passed through).
    pub fn query_param(&self, name: &str) -> Option<String> {
        let (_, query) = self.path.split_once('?')?;
        for pair in query.split('&') {
            let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
            if percent_decode(raw_key).as_deref() == Some(name) {
                return percent_decode(raw_value);
            }
        }
        None
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
    String::from_utf8(output).ok()
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
            headers: vec![("X-Content-Type-Options", "nosniff")],
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
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(invalid_data("too many request headers"));
        }
        let mut line = String::new();
        let n = read_bounded_line(&mut reader, &mut line, MAX_HEADER_BYTES - header_bytes)?;
        header_bytes += n;
        if n == 0 || line.trim().is_empty() {
            break;
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
pub fn route_request(
    req: &HttpRequest,
    token: &str,
    db: &str,
    offline: bool,
    store: &SqliteStore,
) -> HttpResponse {
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
    let bootstrap_token =
        path_only(req.path.as_str()) == "/" && req.query_param("token").as_deref() == Some(token);
    if !req.check_token(token) && !bootstrap_token {
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

    let mut args = match request_args(req) {
        Ok(args) => args,
        Err(response) => return response,
    };
    let path = path_only(req.path.as_str());
    if path == "/" {
        let mut response = HttpResponse::text(200, WEB_UI_HTML, "text/html; charset=utf-8");
        response.headers.push((
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'; object-src 'none'; frame-ancestors 'none'",
        ));
        return response;
    }
    if path == "/health" {
        args = vec!["status".to_string()];
    }
    if path == "/api/providers" {
        // 与其它 Web 路由共用同一 envelope（command/outcome/data/page/warnings），
        // 客户端无需为单一路由特判响应形状（audit P1-6）。
        return redacted_json(
            200,
            serde_json::json!({
                "command": "providers",
                "outcome": "success",
                "data": crate::provider_matrix_data(),
                "page": { "next_cursor": null, "has_more": false },
                "warnings": [],
            }),
        );
    }
    if let Some(id) = path.strip_prefix("/api/show/") {
        args = vec!["show".to_string(), id.to_string()];
    } else if path == "/api/show" {
        let Some(id) = req.query_param("id").filter(|value| !value.is_empty()) else {
            return fixed_error(400, "invalid_request", "missing id parameter");
        };
        args = vec!["show".to_string(), id];
    }
    if let Some(session_id) = path.strip_prefix("/api/resume/") {
        args = vec!["resume".to_string(), session_id.to_string()];
    } else if path == "/api/resume" {
        let Some(session_id) = req.query_param("session").filter(|value| !value.is_empty()) else {
            return fixed_error(400, "invalid_request", "missing session parameter");
        };
        args = vec!["resume".to_string(), session_id];
    }
    if !matches!(
        path,
        "/health"
            | "/api/status"
            | "/api/search"
            | "/api/projection/search"
            | "/api/context"
            | "/api/handoff"
            | "/api/providers"
            | "/api/show"
            | "/api/resume"
    ) && !path.starts_with("/api/show/")
        && !path.starts_with("/api/resume/")
    {
        return fixed_error(404, "not_found", "HTTP route not found");
    }

    match crate::dispatch(
        store,
        db,
        &args,
        crate::protocol::OutputMode::Json,
        None,
        offline,
    ) {
        Ok((command, outcome, data, page, warnings)) => {
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

fn request_args(req: &HttpRequest) -> Result<Vec<String>, HttpResponse> {
    let path = path_only(req.path.as_str());
    let value = |name: &str| req.query_param(name).filter(|value| !value.is_empty());
    match path {
        "/" | "/health" | "/api/providers" => Ok(Vec::new()),
        "/api/status" => Ok(vec!["status".to_string()]),
        "/api/search" | "/api/projection/search" => {
            let Some(query) = value("q") else {
                return Err(fixed_error(400, "invalid_request", "missing q parameter"));
            };
            let mut args = vec!["search".to_string(), query];
            append_value_flag(&mut args, "--mode", value("mode"));
            append_value_flag(&mut args, "--max-items", value("limit"));
            append_value_flag(&mut args, "--cursor", value("cursor"));
            append_value_flag(&mut args, "--provider", value("provider"));
            append_value_flag(&mut args, "--since", value("since"));
            append_value_flag(&mut args, "--until", value("until"));
            if value("include_system").as_deref() == Some("true") {
                args.push("--include-system".to_string());
            }
            if value("group_by_session").as_deref() == Some("true") {
                args.push("--group-by-session".to_string());
            }
            Ok(args)
        }
        "/api/context" => {
            let Some(session) = value("session") else {
                return Err(fixed_error(
                    400,
                    "invalid_request",
                    "missing session parameter",
                ));
            };
            let mut args = vec!["context".to_string(), session];
            append_value_flag(&mut args, "--policy", value("policy"));
            append_value_flag(&mut args, "--level", value("level"));
            append_value_flag(&mut args, "--max-messages", value("max_messages"));
            Ok(args)
        }
        "/api/handoff" => {
            let Some(query) = value("q") else {
                return Err(fixed_error(400, "invalid_request", "missing q parameter"));
            };
            let mut args = vec!["handoff".to_string(), query];
            append_value_flag(&mut args, "--provider", value("provider"));
            append_value_flag(&mut args, "--since", value("since"));
            append_value_flag(&mut args, "--until", value("until"));
            append_value_flag(&mut args, "--max-evidence", value("max_evidence"));
            Ok(args)
        }
        _ => Ok(Vec::new()),
    }
}

fn append_value_flag(args: &mut Vec<String>, flag: &str, value: Option<String>) {
    if let Some(value) = value {
        args.push(flag.to_string());
        args.push(value);
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
        crate::protocol::CanonicalCode::SourceChanged => "source changed during operation",
        crate::protocol::CanonicalCode::SourceIo => "source I/O failed",
        crate::protocol::CanonicalCode::SnapshotFailed => "source snapshot failed",
        crate::protocol::CanonicalCode::CatalogError => "catalog operation failed",
        crate::protocol::CanonicalCode::ProviderError => "provider operation failed",
        crate::protocol::CanonicalCode::CapabilityNotSupported => {
            "capability not supported in this mode"
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
    use std::time::Instant;

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
                "test.db",
                false,
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

    #[test]
    fn percent_decode_handles_unicode_and_rejects_bad_escape() {
        assert_eq!(percent_decode("hello+world"), Some("hello world".into()));
        assert_eq!(percent_decode("%E9%85%8D%E7%BD%AE"), Some("配置".into()));
        assert_eq!(percent_decode("%zz"), None);
    }

    #[test]
    fn routes_require_auth_and_preserve_bootstrap_only_for_the_page() {
        let store = SqliteStore::open_in_memory().expect("store");
        let no_token = request(
            "GET",
            "/api/status",
            vec![("Host".into(), "127.0.0.1:8080".into())],
        );
        assert_eq!(
            route_request(&no_token, TEST_TOKEN, "test.db", false, &store).status,
            401
        );

        let bad_host = request(
            "GET",
            "/api/status",
            vec![
                ("Authorization".into(), format!("Bearer {TEST_TOKEN}")),
                ("Host".into(), "example.test".into()),
            ],
        );
        assert_eq!(
            route_request(&bad_host, TEST_TOKEN, "test.db", false, &store).status,
            403
        );

        let bootstrap = request(
            "GET",
            &format!("/?token={TEST_TOKEN}"),
            vec![("Host".into(), "127.0.0.1:8080".into())],
        );
        let response = route_request(&bootstrap, TEST_TOKEN, "test.db", false, &store);
        assert_eq!(response.status, 200);
        assert!(response.body.contains("local session observatory"));

        let api_query_token = request(
            "GET",
            &format!("/api/status?token={TEST_TOKEN}"),
            vec![("Host".into(), "127.0.0.1:8080".into())],
        );
        assert_eq!(
            route_request(&api_query_token, TEST_TOKEN, "test.db", false, &store).status,
            401
        );
    }

    #[test]
    fn core_preview_routes_use_the_shared_dispatch_contract() {
        let store = SqliteStore::open_in_memory().expect("store");
        for path in [
            "/api/status",
            "/api/providers",
            "/api/search?q=needle&mode=lexical&limit=20",
            "/api/handoff?q=needle",
        ] {
            let response = route_request(
                &authorized("GET", path),
                TEST_TOKEN,
                "test.db",
                false,
                &store,
            );
            assert_eq!(response.status, 200, "{path}: {}", response.body);
            let body: serde_json::Value = serde_json::from_str(&response.body).expect("JSON");
            assert!(body.get("data").is_some());
            assert_eq!(body.get("outcome"), Some(&serde_json::json!("success")));
        }

        let invalid = route_request(
            &authorized("GET", "/api/show?id=C%3A%2FUsers%2Falice%2Fsecret.jsonl"),
            TEST_TOKEN,
            "test.db",
            false,
            &store,
        );
        assert_eq!(invalid.status, 400);
        assert!(!invalid.body.contains("C:/Users"));
        assert!(!invalid.body.contains("secret.jsonl"));
    }

    #[test]
    fn post_requires_origin_and_csrf_then_reports_unsupported() {
        let store = SqliteStore::open_in_memory().expect("store");
        let missing_origin = authorized("POST", "/api/resume");
        assert_eq!(
            route_request(&missing_origin, TEST_TOKEN, "test.db", false, &store).status,
            403
        );

        let mut valid_guard = authorized("POST", "/api/resume");
        valid_guard
            .headers
            .push(("Origin".into(), "http://127.0.0.1:8080".into()));
        assert_eq!(
            route_request(&valid_guard, TEST_TOKEN, "test.db", false, &store).status,
            403
        );
        valid_guard
            .headers
            .push(("X-CSRF-Token".into(), TEST_TOKEN.into()));
        let response = route_request(&valid_guard, TEST_TOKEN, "test.db", false, &store);
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

    #[test]
    fn integration_slowloris_does_not_block_a_fast_get() {
        let (address, token, server) = start_test_server(2, Duration::from_millis(300));
        let mut slow = TcpStream::connect(address).expect("connect slow client");
        slow.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("slow read timeout");
        slow.write_all(b"GET /api/status HTTP/1.1\r\nHost:")
            .expect("write partial request");

        let started = Instant::now();
        let fast = raw_http(address, &get_request(address, &token, "/api/status"));
        assert!(fast.starts_with("HTTP/1.1 200"));
        assert!(started.elapsed() < Duration::from_millis(250));

        let mut slow_response = String::new();
        slow.read_to_string(&mut slow_response)
            .expect("read timeout response");
        assert!(slow_response.starts_with("HTTP/1.1 408"));
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
            "/health",
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

    #[test]
    fn serve_session_generates_token_and_loopback_address() {
        let session = ServeSession::bind_loopback(0).expect("session");
        assert_eq!(session.token().len(), 32);
        assert_eq!(session.address(), "127.0.0.1:0");
    }
}
