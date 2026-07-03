//! NeuralSync Secure Channel — Stream cipher + ECDH key exchange
//! Protocol: XOR with PRNG-derived keystream (deterministic per-message)
//! Key: Build-derived fallback → ECDH per-session forward-secret key
//! Format: hex(enc_key[4] ++ xor(payload, keystream))

use std::sync::OnceLock;

fn shared_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();


    KEY.get_or_init(|| {
        let seed_hex = env!("OBS_BUILD_SEED");
        let seed_bytes = seed_hex.as_bytes();
        let mut val: u32 = 0;
        let mut i = 2;
        while i < seed_bytes.len() {
            let b = seed_bytes[i];
            let digit = if b.is_ascii_digit() { b - b'0' }
                else if (b'A'..=b'F').contains(&b) { b - b'A' + 10 }
                else if (b'a'..=b'f').contains(&b) { b - b'a' + 10 }
                else { 0 };
            val = (val << 4) | digit as u32;
            i += 1;
        }

        let mut key = [0u8; 32];
        let mut state = val;
        for chunk in key.chunks_mut(4) {
            state = state.wrapping_mul(0x9E3779B9).wrapping_add(0x6A09E667);
            state ^= state >> 16;
            state = state.wrapping_mul(0x85EBCA6B);
            state ^= state >> 13;
            state = state.wrapping_mul(0xC2B2AE35);
            state ^= state >> 16;
            let bytes = state.to_le_bytes();
            for (i, b) in bytes.iter().enumerate() {
                if i < chunk.len() {
                    chunk[i] = *b;
                }
            }
        }
        key
    })
}

pub fn build_key() -> &'static [u8; 32] {
    shared_key()
}

fn keystream(key: &[u8; 32], enc_key: u32, len: usize) -> Vec<u8> {
    let mut ks = Vec::with_capacity(len);
    let mut state = [0u32; 8];
    for (i, chunk) in key.chunks(4).enumerate() {
        state[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    state[7] ^= enc_key;

    let mut block = 0u32;
    let mut pos   = 0;
    while ks.len() < len {
        block = block
            .wrapping_add(state[pos % 8])
            .wrapping_mul(0x6c62272e)
            .rotate_right(13)
            ^ enc_key
            ^ (pos as u32).wrapping_mul(0x9e3779b9);
        pos += 1;
        let bytes = block.to_le_bytes();
        for b in bytes {
            if ks.len() < len { ks.push(b); }
        }
    }
    ks
}

pub fn encrypt_with(data: &[u8], enc_key: u32, key: &[u8; 32]) -> String {
    let ks = keystream(key, enc_key, data.len());
    let mut enc = Vec::with_capacity(4 + data.len());
    enc.extend_from_slice(&enc_key.to_le_bytes());
    for (d, k) in data.iter().zip(ks.iter()) {
        enc.push(d ^ k);
    }
    hex::encode(&enc)
}

pub fn decrypt_with(hex_str: &str, key: &[u8; 32]) -> Option<Vec<u8>> {
    if hex_str.len() < 8 || !hex_str.len().is_multiple_of(2) { return None; }
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() < 4 { return None; }
    let enc_key = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let ciphertext = &bytes[4..];
    let ks = keystream(key, enc_key, ciphertext.len());
    let plain: Vec<u8> = ciphertext.iter().zip(ks.iter()).map(|(c, k)| c ^ k).collect();
    Some(plain)
}

pub fn encrypt(data: &[u8], enc_key: u32) -> String {
    encrypt_with(data, enc_key, shared_key())
}

pub fn decrypt(hex_str: &str) -> Option<Vec<u8>> {
    decrypt_with(hex_str, shared_key())
}

pub fn encrypt_json_with(json: &str, enc_key: u32, key: &[u8; 32]) -> String {
    encrypt_with(json.as_bytes(), enc_key, key)
}

pub fn decrypt_json_with(hex_str: &str, key: &[u8; 32]) -> Option<String> {
    let plain = decrypt_with(hex_str, key)?;
    String::from_utf8(plain).ok()
}

pub fn encrypt_json(json: &str, enc_key: u32) -> String {
    encrypt_json_with(json, enc_key, shared_key())
}

pub fn decrypt_json(hex_str: &str) -> Option<String> {
    decrypt_json_with(hex_str, shared_key())
}

pub const SECURE_ENVELOPE_VERSION: u64 = 1;
pub const SECURE_ENVELOPE_TTL_MS: u64 = 120_000;
pub const SECURE_ENVELOPE_MAX_PLAINTEXT: usize = 1_048_576;

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn new_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static CTR: AtomicU64 = AtomicU64::new(0);
    let t = now_ms();
    let c = CTR.fetch_add(1, Ordering::Relaxed);
    hex::encode(t.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(c).to_le_bytes())
}

pub fn encrypt_envelope_json_with(json: &str, enc_key: u32, key: &[u8; 32]) -> Option<String> {
    encrypt_envelope_json_with_ts(json, enc_key, key, now_ms(), &new_nonce())
}

pub fn encrypt_envelope_json_with_ts(json: &str, enc_key: u32, key: &[u8; 32], timestamp_ms: u64, nonce: &str) -> Option<String> {
    if json.len() > SECURE_ENVELOPE_MAX_PLAINTEXT || nonce.is_empty() || nonce.len() > 128 {
        return None;
    }
    let ciphertext = encrypt_json_with(json, enc_key, key);
    Some(serde_json::json!({
        "v": SECURE_ENVELOPE_VERSION,
        "ts": timestamp_ms,
        "n": nonce,
        "ct": ciphertext,
    }).to_string())
}

pub fn decrypt_envelope_json_with(envelope: &str, key: &[u8; 32]) -> Option<String> {
    decrypt_envelope_json_with_now(envelope, key, now_ms())
}

pub fn decrypt_envelope_json_with_now(envelope: &str, key: &[u8; 32], now: u64) -> Option<String> {
    if envelope.len() > SECURE_ENVELOPE_MAX_PLAINTEXT * 3 {
        return None;
    }
    let v: serde_json::Value = serde_json::from_str(envelope).ok()?;
    if v.get("v")?.as_u64()? != SECURE_ENVELOPE_VERSION {
        return None;
    }
    let ts = v.get("ts")?.as_u64()?;
    if now.saturating_sub(ts) > SECURE_ENVELOPE_TTL_MS || ts > now.saturating_add(SECURE_ENVELOPE_TTL_MS) {
        return None;
    }
    let nonce = v.get("n")?.as_str()?;
    if nonce.is_empty() || nonce.len() > 128 {
        return None;
    }
    let ct = v.get("ct")?.as_str()?;
    let plain = decrypt_json_with(ct, key)?;
    if plain.len() > SECURE_ENVELOPE_MAX_PLAINTEXT {
        return None;
    }
    Some(plain)
}
pub fn new_enc_key() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    t ^ 0xDEADBEEF
}

pub fn looks_encrypted(s: &str) -> bool {
    s.len() >= 10
        && s.len().is_multiple_of(2)
        && s.as_bytes()[0] != b'['
        && s.as_bytes()[0] != b'{'
        && s.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn ecdh_generate() -> (x25519_dalek::EphemeralSecret, [u8; 32]) {
    let secret = x25519_dalek::EphemeralSecret::random();
    let public = x25519_dalek::PublicKey::from(&secret);
    (secret, *public.as_bytes())
}

pub fn ecdh_derive(secret: x25519_dalek::EphemeralSecret, peer_public_bytes: &[u8; 32]) -> [u8; 32] {
    let peer_public = x25519_dalek::PublicKey::from(*peer_public_bytes);
    let shared = secret.diffie_hellman(&peer_public);
    let raw = shared.as_bytes();

    let mut key = [0u8; 32];
    let mut state = u64::from_le_bytes([
        raw[0], raw[1], raw[2], raw[3],
        raw[4], raw[5], raw[6], raw[7],
    ]);
    let salt = u64::from_le_bytes([
        raw[8], raw[9], raw[10], raw[11],
        raw[12], raw[13], raw[14], raw[15],
    ]);
    state ^= salt;

    for chunk in key.chunks_mut(8) {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        let bytes = z.to_le_bytes();
        for (i, b) in bytes.iter().enumerate() {
            if i < chunk.len() {
                chunk[i] = *b;
            }
        }
    }
    key
}

pub struct Cipher;

impl Default for Cipher {
    fn default() -> Self { Self::new() }
}

impl Cipher {
    pub fn new() -> Self { Cipher }

    pub fn encrypt_msg(&self, data: &[u8]) -> String {
        encrypt(data, new_enc_key())
    }

    pub fn decrypt_msg(&self, hex_str: &str) -> Option<Vec<u8>> {
        decrypt(hex_str)
    }

    pub fn encrypt_json_msg(&self, json: &str) -> String {
        encrypt_json(json, new_enc_key())
    }

    pub fn decrypt_json_msg(&self, hex_str: &str) -> Option<String> {
        decrypt_json(hex_str)
    }

    pub fn is_encrypted(&self, s: &str) -> bool {
        looks_encrypted(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_key_json_roundtrip() {
        let payload = r#"{"method":"login","params":["worker","x"]}"#;
        let encrypted = encrypt_json(payload, 0x1234_5678);
        assert_ne!(encrypted, payload);
        assert!(looks_encrypted(&encrypted));
        let decrypted = decrypt_json(&encrypted).expect("decrypt build-key payload");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn explicit_session_key_roundtrip() {
        let key = [0x42u8; 32];
        let payload = r#"[1,"submit",{"nonce":"abcdef","result":"012345"}]"#;
        let encrypted = encrypt_json_with(payload, 0xA5A5_5A5A, &key);
        let decrypted = decrypt_json_with(&encrypted, &key).expect("decrypt session payload");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn ecdh_peers_derive_same_session_key() {
        let (alice_secret, alice_pub) = ecdh_generate();
        let (bob_secret, bob_pub) = ecdh_generate();

        let alice_key = ecdh_derive(alice_secret, &bob_pub);
        let bob_key = ecdh_derive(bob_secret, &alice_pub);

        assert_eq!(alice_key, bob_key);
        assert_ne!(alice_key, [0u8; 32]);

        let payload = "session-test";
        let encrypted = encrypt_json_with(payload, 0x0102_0304, &alice_key);
        let decrypted = decrypt_json_with(&encrypted, &bob_key).expect("decrypt ecdh payload");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn rejects_malformed_hex_payloads() {
        assert_eq!(decrypt_json_with("", &[0u8; 32]), None);
        assert_eq!(decrypt_json_with("abc", &[0u8; 32]), None);
        assert_eq!(decrypt_json_with("zzzzzzzzzz", &[0u8; 32]), None);
        assert_eq!(decrypt_json_with("001122", &[0u8; 32]), None);
    }

    #[test]
    fn empty_payload_roundtrip() {
        let key = [0x11u8; 32];
        let encrypted = encrypt_json_with("", 0xFEED_FACE, &key);
        let decrypted = decrypt_json_with(&encrypted, &key).expect("decrypt empty payload");
        assert_eq!(decrypted, "");
    }

    #[test]
    fn unicode_payload_roundtrip() {
        let key = [0x7Au8; 32];
        let payload = r#"{"msg":"xin chào","symbols":"Δλ✓","items":[1,2,3]}"#;
        let encrypted = encrypt_json_with(payload, 0x0BAD_F00D, &key);
        let decrypted = decrypt_json_with(&encrypted, &key).expect("decrypt unicode payload");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn large_payload_roundtrip() {
        let key = [0xA7u8; 32];
        let payload = "x".repeat(64 * 1024);
        let encrypted = encrypt_json_with(&payload, 0xCAFE_BABE, &key);
        let decrypted = decrypt_json_with(&encrypted, &key).expect("decrypt large payload");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn wrong_key_does_not_recover_plaintext() {
        let key_a = [0x21u8; 32];
        let key_b = [0x22u8; 32];
        let payload = "wrong-key-test";
        let encrypted = encrypt_json_with(payload, 0x1020_3040, &key_a);
        let decrypted = decrypt_json_with(&encrypted, &key_b);
        assert_ne!(decrypted.as_deref(), Some(payload));
    }

    #[test]
    fn deterministic_randomized_roundtrips() {
        let mut state = 0xD1CE_CAFE_u32;
        for size in [0usize, 1, 2, 3, 7, 31, 128, 1024, 4096] {
            let mut key = [0u8; 32];
            for byte in &mut key {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                *byte = (state >> 24) as u8;
            }

            let mut payload = Vec::with_capacity(size);
            for _ in 0..size {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                payload.push(b'a' + ((state >> 24) % 26) as u8);
            }
            let payload = String::from_utf8(payload).expect("ascii payload");
            let encrypted = encrypt_json_with(&payload, state, &key);
            let decrypted = decrypt_json_with(&encrypted, &key).expect("decrypt randomized payload");
            assert_eq!(decrypted, payload);
        }
    }

    #[test]
    fn secure_envelope_roundtrip() {
        let key = [0x5Au8; 32];
        let payload = r#"{"op":"sync","value":42}"#;
        let envelope = encrypt_envelope_json_with_ts(payload, 0x7788_9900, &key, 1_000_000, "nonce-1")
            .expect("create envelope");
        let decrypted = decrypt_envelope_json_with_now(&envelope, &key, 1_000_500)
            .expect("decrypt envelope");
        assert_eq!(decrypted, payload);
    }

    #[test]
    fn secure_envelope_rejects_expired_replay() {
        let key = [0x6Bu8; 32];
        let payload = "replay-test";
        let envelope = encrypt_envelope_json_with_ts(payload, 0x0101_0101, &key, 1_000, "nonce-2")
            .expect("create envelope");
        assert_eq!(decrypt_envelope_json_with_now(&envelope, &key, 1_000 + SECURE_ENVELOPE_TTL_MS + 1), None);
    }

    #[test]
    fn secure_envelope_rejects_malformed_schema() {
        let key = [0x7Cu8; 32];
        assert_eq!(decrypt_envelope_json_with_now("{}", &key, 1_000), None);
        assert_eq!(decrypt_envelope_json_with_now(r#"{"v":2,"ts":1000,"n":"x","ct":"00"}"#, &key, 1_000), None);
        assert_eq!(decrypt_envelope_json_with_now(r#"{"v":1,"ts":1000,"n":"","ct":"00"}"#, &key, 1_000), None);
    }

    #[test]
    fn secure_envelope_rejects_oversized_plaintext() {
        let key = [0x8Du8; 32];
        let payload = "x".repeat(SECURE_ENVELOPE_MAX_PLAINTEXT + 1);
        assert_eq!(encrypt_envelope_json_with_ts(&payload, 0x0202_0202, &key, 1_000, "nonce-3"), None);
    }
}

#[cfg(target_os = "linux")]
pub fn resolve_via_doh(_domain: &str) -> Option<String> {
    use std::net::TcpStream;
    use std::io::{Read, Write};

    let doh_servers = vec![
        ("1.1.1.1", "cloudflare-dns.com"),
        ("8.8.8.8", "dns.google"),
        ("9.9.9.9", "dns.quad9.net"),
    ];

    for (ip, host) in doh_servers {
        let path = format!("/dns-query?name={}&type=A", _domain);
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n",
            path, host
        );
        if let Ok(tcp) = TcpStream::connect((ip as &str, 443)) {
            let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(4)));
            let connector = match native_tls::TlsConnector::new() {
                Ok(c) => c,
                Err(_) => continue,
            };
            if let Ok(mut stream) = connector.connect(host, tcp) {
                let _ = stream.write_all(req.as_bytes());
                let mut response = Vec::new();
                let mut buf = [0u8; 1024];
                while let Ok(n) = stream.read(&mut buf) {
                    if n == 0 { break; }
                    response.extend_from_slice(&buf[..n]);
                }
                let resp_str = String::from_utf8_lossy(&response);
                if let Some(body_start) = resp_str.find("\r\n\r\n") {
                    let body = &resp_str[body_start + 4..];
                    if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(body) {
                        if let Some(answers) = json_val.get("Answer").and_then(|a| a.as_array()) {
                            for answer in answers {
                                if answer.get("type").and_then(|t| t.as_u64()) == Some(1) {
                                    if let Some(ip_str) = answer.get("data").and_then(|d| d.as_str()) {
                                        return Some(ip_str.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "linux"))]
pub fn resolve_via_doh(_domain: &str) -> Option<String> { None }
