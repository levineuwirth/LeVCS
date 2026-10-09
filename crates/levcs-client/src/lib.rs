//! Client-side instance interaction. Wraps `reqwest::blocking::Client` with
//! request signing per §5.3 and provides typed methods for the §5.2
//! endpoints.

use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use reqwest::blocking::Client as Http;
use reqwest::header::HeaderMap;
use thiserror::Error;

use levcs_core::ObjectId;
use levcs_identity::keys::SecretKey;
use levcs_protocol::auth::{sign_request, AuthRequest};
use levcs_protocol::pack::{DEFAULT_MAX_OBJECT_BYTES, DEFAULT_MAX_TOTAL_BYTES};
use levcs_protocol::wire::{InfoResponse, InstanceInfo, RefList};
use levcs_protocol::{Pack, PushLimits, PushManifest};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    #[error("server returned {status}: {body}")]
    Server { status: u16, body: String },

    #[error("auth: {0}")]
    Auth(String),

    #[error("decode: {0}")]
    Decode(String),
}

#[derive(Clone)]
pub struct Client {
    base: String,
    http: Http,
    user_agent: String,
    /// Signs every read of a repository, so that a private one can be read
    /// by its members. Without a key, reads are anonymous.
    reader: Option<Arc<SecretKey>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base", &self.base)
            .field("reader", &self.reader.as_ref().map(|k| k.public()))
            .finish()
    }
}

impl Client {
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            http: Http::builder()
                .timeout(Duration::from_secs(60))
                .build()
                .expect("build reqwest client"),
            user_agent: "levcs-client/0.1.0".into(),
            reader: None,
        }
    }

    /// Sign reads of repositories with `sk`. An instance serves a private
    /// repository only to members of its current authority, and answers
    /// anyone else as if it did not exist.
    pub fn with_reader(mut self, sk: Arc<SecretKey>) -> Self {
        self.reader = Some(sk);
        self
    }

    /// GET `path` (`/repos/<id>/...`, the form the instance verifies a
    /// signature over), signed if this client has a reader key.
    fn get(&self, path: &str) -> Result<reqwest::blocking::Response, ClientError> {
        let mut req = self
            .http
            .get(format!("{}{path}", self.base))
            .header("user-agent", &self.user_agent);
        if let Some(sk) = &self.reader {
            let signed = AuthRequest {
                method: "GET",
                path_with_query: path,
                body: b"",
            };
            let (key, ts, nonce, sig) =
                sign_request(sk, &signed).map_err(|e| ClientError::Auth(e.to_string()))?;
            req = req
                .header("LeVCS-Key", key)
                .header("LeVCS-Timestamp", ts)
                .header("LeVCS-Nonce", nonce)
                .header("LeVCS-Signature", sig);
        }
        check(req.send()?)
    }

    pub fn instance_info(&self) -> Result<InstanceInfo, ClientError> {
        let url = format!("{}/instance/info", self.base);
        let res = self
            .http
            .get(&url)
            .header("user-agent", &self.user_agent)
            .send()?;
        json_within(check(res)?)
    }

    pub fn repo_info(&self, repo_id: &str) -> Result<InfoResponse, ClientError> {
        json_within(self.get(&format!("/repos/{repo_id}/info"))?)
    }

    pub fn refs(&self, repo_id: &str) -> Result<RefList, ClientError> {
        json_within(self.get(&format!("/repos/{repo_id}/refs"))?)
    }

    pub fn get_object(&self, repo_id: &str, id: ObjectId) -> Result<Vec<u8>, ClientError> {
        let res = self.get(&format!("/repos/{repo_id}/objects/{}", id.to_hex()))?;
        body_within(res, DEFAULT_MAX_OBJECT_BYTES as u64)
    }

    pub fn get_pack(
        &self,
        repo_id: &str,
        have: &[ObjectId],
        want: &[ObjectId],
    ) -> Result<Pack, ClientError> {
        let have_q: Vec<String> = have.iter().map(|h| h.to_hex()).collect();
        let want_q: Vec<String> = want.iter().map(|h| h.to_hex()).collect();
        let path = format!(
            "/repos/{repo_id}/pack?have={}&want={}",
            have_q.join(","),
            want_q.join(",")
        );
        let bytes = body_within(self.get(&path)?, DEFAULT_MAX_TOTAL_BYTES as u64)?;
        Pack::decode(&bytes).map_err(|e| ClientError::Decode(e.to_string()))
    }

    pub fn push(
        &self,
        sk: &SecretKey,
        repo_id: &str,
        pack: &Pack,
        manifest: &PushManifest,
    ) -> Result<(), ClientError> {
        // Body: pack bytes followed by 4 bytes manifest length, manifest JSON,
        // then manifest signature (64 bytes).
        let pack_bytes = pack.encode();
        let manifest_json =
            serde_json::to_vec(manifest).map_err(|e| ClientError::Decode(e.to_string()))?;
        let mut body = Vec::with_capacity(pack_bytes.len() + 4 + manifest_json.len() + 64);
        body.extend_from_slice(&pack_bytes);
        body.extend_from_slice(&(manifest_json.len() as u32).to_le_bytes());
        body.extend_from_slice(&manifest_json);
        // Sign the manifest separately so the instance can verify it.
        let manifest_sig = sk.sign(&manifest_json);
        body.extend_from_slice(&manifest_sig);

        let path = format!("/repos/{repo_id}/push");
        let req = AuthRequest {
            method: "POST",
            path_with_query: &path,
            body: &body,
        };
        let (key, ts, nonce, sig) =
            sign_request(sk, &req).map_err(|e| ClientError::Auth(e.to_string()))?;

        let mut headers = HeaderMap::new();
        headers.insert("LeVCS-Key", key.parse().unwrap());
        headers.insert("LeVCS-Timestamp", ts.parse().unwrap());
        headers.insert("LeVCS-Nonce", nonce.parse().unwrap());
        headers.insert("LeVCS-Signature", sig.parse().unwrap());
        headers.insert("Content-Type", "application/octet-stream".parse().unwrap());
        // Useful for clients to advertise the public key that signed the manifest:
        headers.insert(
            "LeVCS-Manifest-Signature",
            B64.encode(manifest_sig).parse().unwrap(),
        );

        let url = format!("{}{}", self.base, path);
        let res = self.http.post(&url).headers(headers).body(body).send()?;
        check(res)?;
        Ok(())
    }

    pub fn init(
        &self,
        sk: &SecretKey,
        repo_id: &str,
        authority_object: &[u8],
    ) -> Result<(), ClientError> {
        let path = format!("/repos/{repo_id}/init");
        let req = AuthRequest {
            method: "POST",
            path_with_query: &path,
            body: authority_object,
        };
        let (key, ts, nonce, sig) =
            sign_request(sk, &req).map_err(|e| ClientError::Auth(e.to_string()))?;
        let mut headers = HeaderMap::new();
        headers.insert("LeVCS-Key", key.parse().unwrap());
        headers.insert("LeVCS-Timestamp", ts.parse().unwrap());
        headers.insert("LeVCS-Nonce", nonce.parse().unwrap());
        headers.insert("LeVCS-Signature", sig.parse().unwrap());
        headers.insert("Content-Type", "application/octet-stream".parse().unwrap());
        let url = format!("{}{}", self.base, path);
        let res = self
            .http
            .post(&url)
            .headers(headers)
            .body(authority_object.to_vec())
            .send()?;
        check(res)?;
        Ok(())
    }
}

/// What a push would send: its objects, their decoded bytes together and
/// the largest one, and its request body's length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PushSize {
    pub objects: u64,
    pub decoded: u64,
    pub largest: u64,
    pub body: u64,
    /// Refs it updates.
    pub updates: u64,
}

impl PushSize {
    /// Measure the push of `pack` with `manifest`, as `Client::push` would
    /// send it.
    pub fn of(pack: &Pack, manifest: &PushManifest) -> Result<Self, ClientError> {
        let json = serde_json::to_vec(manifest).map_err(|e| ClientError::Decode(e.to_string()))?;
        Ok(PushSize {
            objects: pack.entries.len() as u64,
            decoded: pack.entries.iter().map(|e| e.bytes.len() as u64).sum(),
            largest: pack
                .entries
                .iter()
                .map(|e| e.bytes.len() as u64)
                .max()
                .unwrap_or(0),
            body: (pack.encode().len() + 4 + json.len() + 64) as u64,
            updates: manifest.updates.len() as u64,
        })
    }

    /// The first of `limits` this push would pass, said as a refusal.
    pub fn over(&self, limits: &PushLimits) -> Option<String> {
        let checks = [
            ("a request body", self.body, limits.max_push_bytes, "bytes"),
            ("objects", self.objects, limits.max_pack_objects, "objects"),
            (
                "decoded objects",
                self.decoded,
                limits.max_pack_bytes,
                "bytes",
            ),
            ("one object", self.largest, limits.max_object_bytes, "bytes"),
            (
                "ref updates",
                self.updates,
                limits.max_ref_updates.unwrap_or(u64::MAX),
                "updates",
            ),
        ];
        checks
            .into_iter()
            .find(|(_, size, max, _)| size > max)
            .map(|(what, size, max, unit)| {
                format!("this push is {size} {unit} of {what}; the instance takes at most {max}")
            })
    }
}

/// A JSON answer (info, refs) is read up to this many bytes.
const MAX_JSON_BYTES: u64 = 16 << 20;

/// The body of `res`, if it is at most `max` bytes: refused from its
/// declared length when it has one, and never read past `max`. Bodies were
/// read whole, and a pack's decoding budget applied only after its body had
/// been buffered, however large.
fn body_within(res: reqwest::blocking::Response, max: u64) -> Result<Vec<u8>, ClientError> {
    use std::io::Read;
    let too_large = || ClientError::Decode(format!("response larger than {max} bytes"));
    if res.content_length().is_some_and(|n| n > max) {
        return Err(too_large());
    }
    let mut buf = Vec::new();
    res.take(max.saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|e| ClientError::Decode(e.to_string()))?;
    if buf.len() as u64 > max {
        return Err(too_large());
    }
    Ok(buf)
}

fn json_within<T: serde::de::DeserializeOwned>(
    res: reqwest::blocking::Response,
) -> Result<T, ClientError> {
    serde_json::from_slice(&body_within(res, MAX_JSON_BYTES)?)
        .map_err(|e| ClientError::Decode(e.to_string()))
}

/// An error answer's body is read up to this many bytes: enough for any
/// message. It was read whole, past every other limit.
const MAX_ERROR_BYTES: u64 = 64 << 10;

fn check(res: reqwest::blocking::Response) -> Result<reqwest::blocking::Response, ClientError> {
    use std::io::Read;
    if res.status().is_success() {
        return Ok(res);
    }
    let status = res.status().as_u16();
    let mut buf = Vec::new();
    let _ = res
        .take(MAX_ERROR_BYTES.saturating_add(1))
        .read_to_end(&mut buf);
    let cut = buf.len() as u64 > MAX_ERROR_BYTES;
    buf.truncate(MAX_ERROR_BYTES as usize);
    let mut body = String::from_utf8_lossy(&buf).into_owned();
    if cut {
        body.push_str(" ... (cut off)");
    }
    Err(ClientError::Server { status, body })
}
