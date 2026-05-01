//! Request authentication per §5.3.
//!
//! Signed requests carry these headers:
//!
//! ```text
//! LeVCS-Key:       ed25519:<base64 public key>
//! LeVCS-Timestamp: <Unix microseconds>
//! LeVCS-Nonce:     <16 random bytes, base64>
//! LeVCS-Signature: ed25519:<base64 signature>
//! ```
//!
//! The signature is computed over the canonical request string:
//!
//! ```text
//! <HTTP method>\n
//! <request path including query string>\n
//! <timestamp>\n
//! <nonce>\n
//! <BLAKE3 hash of request body, hex-encoded>
//! ```

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use thiserror::Error;

use levcs_identity::keys::{PublicKey, SecretKey};

pub const NONCE_TTL_SECS: i64 = 600;
pub const DEFAULT_CLOCK_SKEW: i64 = 5 * 60; // 5 minutes

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("missing header: {0}")]
    MissingHeader(&'static str),

    #[error("invalid header value for {name}: {detail}")]
    InvalidHeader { name: &'static str, detail: String },

    #[error("timestamp out of allowed window: {0} seconds skew")]
    Skew(i64),

    #[error("replay detected: nonce already seen")]
    Replay,

    #[error("signature verify failed: {0}")]
    BadSignature(String),

    #[error("identity error: {0}")]
    Identity(#[from] levcs_identity::IdentityError),

    #[error("base64 decode: {0}")]
    Base64(String),

    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
}

#[derive(Clone, Debug)]
pub struct AuthHeaders {
    pub key: PublicKey,
    pub timestamp_micros: i64,
    pub nonce: [u8; 16],
    pub signature: [u8; 64],
}

#[derive(Clone, Debug)]
pub struct AuthRequest<'a> {
    pub method: &'a str,
    pub path_with_query: &'a str,
    pub body: &'a [u8],
}

pub fn build_canonical(req: &AuthRequest, timestamp_micros: i64, nonce_b64: &str) -> String {
    let body_hash = hex::encode(blake3::hash(req.body).as_bytes());
    format!(
        "{}\n{}\n{}\n{}\n{}",
        req.method, req.path_with_query, timestamp_micros, nonce_b64, body_hash
    )
}

/// Sign a request, returning the four header values.
pub fn sign_request(
    sk: &SecretKey,
    req: &AuthRequest,
) -> Result<(String, String, String, String), AuthError> {
    let mut nonce = [0u8; 16];
    getrandom_bytes(&mut nonce)?;
    let timestamp = current_micros();
    let nonce_b64 = B64.encode(nonce);
    let canonical = build_canonical(req, timestamp, &nonce_b64);
    let sig = sk.sign(canonical.as_bytes());
    Ok((
        sk.public().to_levcs(),
        timestamp.to_string(),
        nonce_b64,
        format!("ed25519:{}", B64.encode(sig)),
    ))
}

/// Verify the four headers of an authenticated request, given the request's
/// method/path/body. Returns the verified `AuthHeaders` on success.
pub fn verify_request(
    req: &AuthRequest,
    key_header: &str,
    timestamp_header: &str,
    nonce_header: &str,
    signature_header: &str,
    now_micros: i64,
    skew_seconds: i64,
) -> Result<AuthHeaders, AuthError> {
    let pk = PublicKey::parse_levcs(key_header).map_err(AuthError::Identity)?;
    let timestamp_micros: i64 = timestamp_header
        .parse()
        .map_err(|e: std::num::ParseIntError| AuthError::InvalidHeader {
            name: "LeVCS-Timestamp",
            detail: e.to_string(),
        })?;
    let skew = (now_micros - timestamp_micros) / 1_000_000;
    if skew.abs() > skew_seconds {
        return Err(AuthError::Skew(skew));
    }
    let nonce_bytes = B64
        .decode(nonce_header.as_bytes())
        .map_err(|e| AuthError::Base64(e.to_string()))?;
    if nonce_bytes.len() != 16 {
        return Err(AuthError::InvalidHeader {
            name: "LeVCS-Nonce",
            detail: format!("expected 16 bytes, got {}", nonce_bytes.len()),
        });
    }
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&nonce_bytes);

    let sig_b64 = signature_header
        .strip_prefix("ed25519:")
        .ok_or(AuthError::InvalidHeader {
            name: "LeVCS-Signature",
            detail: "missing ed25519: prefix".into(),
        })?;
    let sig_bytes = B64
        .decode(sig_b64.as_bytes())
        .map_err(|e| AuthError::Base64(e.to_string()))?;
    if sig_bytes.len() != 64 {
        return Err(AuthError::InvalidHeader {
            name: "LeVCS-Signature",
            detail: format!("expected 64 bytes, got {}", sig_bytes.len()),
        });
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&sig_bytes);

    let canonical = build_canonical(req, timestamp_micros, nonce_header);
    pk.verify(canonical.as_bytes(), &sig)
        .map_err(|e| AuthError::BadSignature(e.to_string()))?;

    Ok(AuthHeaders {
        key: pk,
        timestamp_micros,
        nonce,
        signature: sig,
    })
}

fn getrandom_bytes(buf: &mut [u8]) -> Result<(), AuthError> {
    getrandom::getrandom(buf)
        .map_err(|e| AuthError::InvalidHeader { name: "LeVCS-Nonce", detail: e.to_string() })
}

pub fn current_micros() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = SecretKey::generate();
        let body = b"{\"updates\":[]}";
        let req = AuthRequest {
            method: "POST",
            path_with_query: "/levcs/v1/repos/abc/push",
            body,
        };
        let (key, ts, nonce, sig) = sign_request(&sk, &req).unwrap();
        let now = current_micros();
        let h = verify_request(&req, &key, &ts, &nonce, &sig, now, DEFAULT_CLOCK_SKEW).unwrap();
        assert_eq!(h.key, sk.public());
    }

    #[test]
    fn tampered_body_fails() {
        let sk = SecretKey::generate();
        let body = b"{\"updates\":[]}";
        let req = AuthRequest {
            method: "POST",
            path_with_query: "/levcs/v1/repos/abc/push",
            body,
        };
        let (key, ts, nonce, sig) = sign_request(&sk, &req).unwrap();
        let req2 = AuthRequest { method: "POST", path_with_query: "/levcs/v1/repos/abc/push", body: b"bogus" };
        let now = current_micros();
        assert!(verify_request(&req2, &key, &ts, &nonce, &sig, now, DEFAULT_CLOCK_SKEW).is_err());
    }
}
