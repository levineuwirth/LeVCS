//! Client-side instance interaction. Wraps `reqwest::blocking::Client` with
//! request signing per §5.3 and provides typed methods for the §5.2
//! endpoints.

use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use reqwest::blocking::Client as Http;
use reqwest::header::HeaderMap;
use thiserror::Error;

use levcs_core::ObjectId;
use levcs_identity::keys::SecretKey;
use levcs_protocol::auth::{sign_request, AuthRequest};
use levcs_protocol::wire::{InfoResponse, InstanceInfo, RefList};
use levcs_protocol::{Pack, PushManifest};

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

#[derive(Clone, Debug)]
pub struct Client {
    base: String,
    http: Http,
    user_agent: String,
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
        }
    }

    pub fn instance_info(&self) -> Result<InstanceInfo, ClientError> {
        let url = format!("{}/instance/info", self.base);
        let res = self
            .http
            .get(&url)
            .header("user-agent", &self.user_agent)
            .send()?;
        check(res)?.json::<InstanceInfo>().map_err(Into::into)
    }

    pub fn repo_info(&self, repo_id: &str) -> Result<InfoResponse, ClientError> {
        let url = format!("{}/repos/{repo_id}/info", self.base);
        let res = self
            .http
            .get(&url)
            .header("user-agent", &self.user_agent)
            .send()?;
        check(res)?.json::<InfoResponse>().map_err(Into::into)
    }

    pub fn refs(&self, repo_id: &str) -> Result<RefList, ClientError> {
        let url = format!("{}/repos/{repo_id}/refs", self.base);
        let res = self
            .http
            .get(&url)
            .header("user-agent", &self.user_agent)
            .send()?;
        check(res)?.json::<RefList>().map_err(Into::into)
    }

    pub fn get_object(&self, repo_id: &str, id: ObjectId) -> Result<Vec<u8>, ClientError> {
        let url = format!("{}/repos/{repo_id}/objects/{}", self.base, id.to_hex());
        let res = self
            .http
            .get(&url)
            .header("user-agent", &self.user_agent)
            .send()?;
        let res = check(res)?;
        Ok(res.bytes()?.to_vec())
    }

    pub fn get_pack(
        &self,
        repo_id: &str,
        have: &[ObjectId],
        want: &[ObjectId],
    ) -> Result<Pack, ClientError> {
        let have_q: Vec<String> = have.iter().map(|h| h.to_hex()).collect();
        let want_q: Vec<String> = want.iter().map(|h| h.to_hex()).collect();
        let url = format!(
            "{}/repos/{repo_id}/pack?have={}&want={}",
            self.base,
            have_q.join(","),
            want_q.join(",")
        );
        let res = self
            .http
            .get(&url)
            .header("user-agent", &self.user_agent)
            .send()?;
        let bytes = check(res)?.bytes()?;
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

fn check(res: reqwest::blocking::Response) -> Result<reqwest::blocking::Response, ClientError> {
    if res.status().is_success() {
        Ok(res)
    } else {
        let status = res.status().as_u16();
        let body = res.text().unwrap_or_default();
        Err(ClientError::Server { status, body })
    }
}
