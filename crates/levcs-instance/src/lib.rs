//! Instance HTTP server.
//!
//! Hosts repositories under a configured root directory. Each repository
//! lives at `<root>/<repo_id_hex>/` with the standard `.levcs/` layout.
//!
//! Implements the §5.2 endpoint surface:
//!
//! ```text
//! GET  /levcs/v1/repos/{repo_id}/info
//! GET  /levcs/v1/repos/{repo_id}/objects/{hash}
//! GET  /levcs/v1/repos/{repo_id}/pack?have=...&want=...
//! POST /levcs/v1/repos/{repo_id}/push
//! GET  /levcs/v1/repos/{repo_id}/refs
//! POST /levcs/v1/repos/{repo_id}/init
//! GET  /levcs/v1/instance/info
//! GET  /levcs/v1/instance/peers
//! ```

pub mod mirror;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};

use levcs_core::object::ObjectType;
use levcs_core::{Commit, EntryType, ObjectId, ObjectStore, Tree};
use levcs_identity::authority::AuthorityBody;
use levcs_identity::keys::PublicKey;
use levcs_identity::verify::{
    verify_authority_chain, verify_genesis, ObjectSource as VerifySource,
};
use levcs_merge::engine::check_handler_allowed;
use levcs_merge::record::MergeRecord;
use levcs_protocol::auth::{verify_request, AuthRequest, DEFAULT_CLOCK_SKEW, NONCE_TTL_SECS};
use levcs_protocol::wire::{InfoResponse, InstanceInfo, RefList};
use levcs_protocol::Pack;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct InstanceConfig {
    pub root: PathBuf,
    #[serde(default)]
    pub storage_mode: String, // full, release, metadata
    #[serde(default)]
    pub federation_peers: Vec<String>,
    #[serde(default)]
    pub allowed_handlers: Vec<String>,
    /// Per-repository mirror declarations (§5.6). A repo whose `repo_id`
    /// matches one of these entries is treated as a mirror of `source` —
    /// served read-only to clients (unless `writeback` is true) and kept
    /// fresh by `sync_mirror`.
    #[serde(default)]
    pub mirrors: Vec<MirrorConfig>,
    /// Keys that may create repositories here, as `levcs key show` prints
    /// them (`ed25519:<hex>`). None by default: an instance that names no
    /// creator accepts no new repository. Any owner of a genesis used to be
    /// able to create one.
    #[serde(default)]
    pub creators: Vec<String>,
}

/// A hosted repository's id: exactly 64 lowercase hex characters. It is the
/// only thing ever joined onto the instance's root. The id used to be joined
/// as the request gave it, percent-decoded, so `/repos/%2F<path>/info` read
/// a repository anywhere on the host (audit C3).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RepoId(String);

impl RepoId {
    pub fn parse(s: &str) -> Option<Self> {
        let hex = s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        hex.then(|| RepoId(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for RepoId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Per-repository mirror configuration (§5.6).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MirrorConfig {
    pub repo_id: String,
    /// Base URL of the source instance, including the `/levcs/v1` path.
    pub source: String,
    /// Replication mode: "full" mirrors every reachable object;
    /// "release" mirrors only release objects, their trees and blobs,
    /// and the authority chain (skipping inter-release commits) per §4.3.
    #[serde(default = "default_mirror_mode")]
    pub mode: String,
    /// Polling cadence as a duration string (e.g. "5m", "30s"). Used by
    /// the optional background poller; standalone `sync_mirror` calls do
    /// not consult this field.
    #[serde(default)]
    pub poll_interval: String,
    /// When true, this mirror accepts client pushes and forwards them to
    /// `source`. When false (the default), client pushes are rejected.
    /// §5.6 leaves the proxy mechanism implementation-defined; the wire
    /// behavior — read-only by default — is the part we must enforce.
    #[serde(default)]
    pub writeback: bool,
}

fn default_mirror_mode() -> String {
    "full".into()
}

impl InstanceConfig {
    /// Look up a mirror declaration for `repo_id`. Returns `None` for
    /// repositories the instance is authoritative for.
    pub fn mirror_for(&self, repo_id: &RepoId) -> Option<&MirrorConfig> {
        self.mirrors.iter().find(|m| m.repo_id == repo_id.as_str())
    }

    /// Where `repo` lives.
    pub fn repo_dir(&self, repo: &RepoId) -> PathBuf {
        self.root.join(repo.as_str())
    }

    /// What the configuration names that is not what it should be: a
    /// creator that is not a key, a mirror whose repository is not named by
    /// its id. The binary refuses to start over any of it; where these are
    /// used, an entry that does not parse authorizes and reaches nothing.
    pub fn validate(&self) -> Result<(), String> {
        let mut bad = Vec::new();
        for c in &self.creators {
            if PublicKey::parse_levcs(c).is_err() {
                bad.push(format!(
                    "creators: {c:?} is not a key (expected ed25519:<64 hex digits>)"
                ));
            }
        }
        for m in &self.mirrors {
            if RepoId::parse(&m.repo_id).is_none() {
                bad.push(format!(
                    "mirrors: repo_id {:?} is not 64 lowercase hex characters",
                    m.repo_id
                ));
            }
        }
        if bad.is_empty() {
            Ok(())
        } else {
            Err(bad.join("\n"))
        }
    }

    /// Resolve the storage mode (§4.3). Empty / unset / "full" all
    /// mean full replication; the spec only enumerates three valid
    /// values, so anything else is treated as full and warned about
    /// at instance startup. Used by the push handler to gate which
    /// reference namespaces accept updates.
    pub fn storage_mode(&self) -> StorageMode {
        match self.storage_mode.as_str() {
            "release" => StorageMode::Release,
            "metadata" => StorageMode::Metadata,
            _ => StorageMode::Full,
        }
    }
}

/// One of the three modes from §4.3.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StorageMode {
    /// Full replication — accepts every push.
    Full,
    /// Releases + their trees + reachable blobs + authority chain.
    /// Rejects pushes that update branches; only `refs/releases/*`
    /// updates are accepted.
    Release,
    /// Authority objects, release headers, signed references only.
    /// Rejects all pushes — metadata-mode instances are typically
    /// populated by mirroring rather than direct push.
    Metadata,
}

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<InstanceConfig>,
    pub nonce_cache: Arc<Mutex<NonceCache>>,
    pub repo_locks: Arc<RwLock<HashMap<RepoId, Arc<tokio::sync::RwLock<()>>>>>,
    /// `config.creators`, parsed. An entry that does not parse is left out,
    /// and so authorizes no one.
    creators: Arc<HashSet<PublicKey>>,
}

impl AppState {
    pub fn new(config: InstanceConfig) -> Self {
        let creators = config
            .creators
            .iter()
            .filter_map(|c| PublicKey::parse_levcs(c).ok())
            .collect();
        Self {
            config: Arc::new(config),
            nonce_cache: Arc::new(Mutex::new(NonceCache::default())),
            repo_locks: Arc::new(RwLock::new(HashMap::new())),
            creators: Arc::new(creators),
        }
    }

    pub fn repo_dir(&self, repo: &RepoId) -> PathBuf {
        self.config.repo_dir(repo)
    }

    pub fn store(&self, repo: &RepoId) -> ObjectStore {
        ObjectStore::new(self.repo_dir(repo).join(".levcs/objects"))
    }

    /// `repo`'s lock. Every writer of its refs holds it exclusively, from
    /// reading the state it decides against to its last ref write. Every
    /// read holds it shared, from deciding who may read to its answer, so
    /// that a read sees a push wholly before or wholly after. Reads used to
    /// take no lock: one could decide by an authority a push had moved
    /// `current` to and not yet committed.
    pub fn repo_lock(&self, repo: &RepoId) -> Arc<tokio::sync::RwLock<()>> {
        let mut map = self.repo_locks.write().unwrap();
        map.entry(repo.clone())
            .or_insert_with(|| Arc::new(tokio::sync::RwLock::new(())))
            .clone()
    }
}

/// Replay-protection cache for §5.3 request nonces.
///
/// `verify_request` already rejects timestamps outside ±`DEFAULT_CLOCK_SKEW`,
/// so a nonce only needs to be remembered while its parent timestamp is
/// still within the skew window — anything older is rejected for skew
/// before the cache is even consulted. We use `NONCE_TTL_SECS` (the
/// protocol-level constant) as the retention horizon, which is wider than
/// the skew window so that a small clock difference between client and
/// server can't open a replay window between the two checks.
///
/// The earlier implementation was a `HashSet` that called `clear()` once
/// it grew past a count cap. That was a real replay vulnerability: an
/// attacker who captured a recent signed request could replay it the
/// instant the cache wiped, regardless of how long the original was
/// supposed to remain "seen." The TTL approach below is bounded in
/// memory by the rate of accepted requests times the TTL — at typical
/// federation load that's a few thousand entries, kilobytes of state.
/// How many inserts to accept before sweeping expired entries. Eviction
/// is O(len), so amortizing keeps the per-call cost O(1) average. Stale
/// entries that sit in the map a little longer cost nothing — they
/// would just match the TTL skew check upstream and be rejected anyway.
const NONCE_EVICT_BATCH: usize = 1024;

#[derive(Default)]
pub struct NonceCache {
    /// `nonce → request timestamp (micros since epoch)`. We index by
    /// timestamp rather than insertion time so a delayed request whose
    /// own clock is slightly behind ours can't sneak past TTL eviction.
    seen: HashMap<[u8; 16], i64>,
    inserts_since_evict: usize,
}

impl NonceCache {
    /// Check whether `nonce` (carried with `request_ts_micros`) has been
    /// seen, and if not, record it. `now_micros` is the verifier's notion
    /// of the current time, used to evict stale entries periodically.
    /// Returns `true` if the nonce was *new* (request should proceed),
    /// `false` if it was a replay.
    pub fn check_and_insert(
        &mut self,
        nonce: [u8; 16],
        request_ts_micros: i64,
        now_micros: i64,
    ) -> bool {
        self.inserts_since_evict += 1;
        if self.inserts_since_evict >= NONCE_EVICT_BATCH {
            let cutoff = now_micros - NONCE_TTL_SECS * 1_000_000;
            self.seen.retain(|_, ts| *ts >= cutoff);
            self.inserts_since_evict = 0;
        }
        if self.seen.contains_key(&nonce) {
            return false;
        }
        self.seen.insert(nonce, request_ts_micros);
        true
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.seen.len()
    }
}

pub fn router(state: AppState) -> Router {
    use tower_http::trace::TraceLayer;
    Router::new()
        // Operational endpoint — outside /levcs/v1 so reverse proxies
        // can probe liveness without touching the federation surface.
        // Cheap on purpose: doesn't read state, doesn't touch disk.
        .route("/health", get(handle_health))
        .route("/levcs/v1/instance/info", get(handle_instance_info))
        .route("/levcs/v1/instance/peers", get(handle_instance_peers))
        .route("/levcs/v1/repos/:repo_id/info", get(handle_repo_info))
        .route("/levcs/v1/repos/:repo_id/refs", get(handle_repo_refs))
        .route(
            "/levcs/v1/repos/:repo_id/objects/:hash",
            get(handle_get_object),
        )
        .route("/levcs/v1/repos/:repo_id/pack", get(handle_get_pack))
        .route("/levcs/v1/repos/:repo_id/push", post(handle_push))
        .route("/levcs/v1/repos/:repo_id/init", post(handle_init))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn handle_health() -> impl IntoResponse {
    axum::Json(serde_json::json!({"status": "ok"}))
}

#[derive(Debug)]
struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Surface every error response in the server log before sending it
        // to the client. Without this, 5xx and auth failures would vanish
        // — the client sees the body but nothing reaches the operator.
        // 5xx is a server-side bug worth `error!`; 4xx is the caller's
        // problem (bad signature, malformed pack, conflict) and lands at
        // `warn!` so it's still grep-able but doesn't blow up alerts.
        let level_5xx = self.0.is_server_error();
        if level_5xx {
            tracing::error!(status = %self.0, error = %self.1, "request failed");
        } else {
            tracing::warn!(status = %self.0, error = %self.1, "request rejected");
        }
        (self.0, self.1).into_response()
    }
}

fn err(status: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(status, msg.into())
}

async fn handle_instance_info(State(s): State<AppState>) -> impl IntoResponse {
    let info = InstanceInfo {
        software: "levcs-instance".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        storage_mode: if s.config.storage_mode.is_empty() {
            "full".into()
        } else {
            s.config.storage_mode.clone()
        },
        allowed_handlers: s.config.allowed_handlers.clone(),
        federation_peers: s.config.federation_peers.clone(),
    };
    axum::Json(info)
}

async fn handle_instance_peers(State(s): State<AppState>) -> impl IntoResponse {
    axum::Json(s.config.federation_peers.clone())
}

async fn handle_repo_info(
    State(s): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
) -> Result<axum::Json<InfoResponse>, ApiError> {
    let repo = RepoId::parse(&repo_id).ok_or_else(not_found)?;
    let _reading = admit_read(&s, &repo, &headers, &format!("/repos/{repo}/info")).await?;
    let dir = s.repo_dir(&repo);
    let refs = levcs_core::Refs::new(dir.join(".levcs"));
    refuse_if_interrupted(&refs)?;
    let cur = refs
        .read("refs/authority/current")
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let genesis = refs
        .read("refs/authority/genesis")
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let branches = refs
        .list_branches()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mirror = s.config.mirror_for(&repo);
    let mut info = InfoResponse {
        repo_id: repo.to_string(),
        current_authority: cur.map(|c| c.to_hex()).unwrap_or_default(),
        genesis_authority: genesis.map(|c| c.to_hex()).unwrap_or_default(),
        is_mirror: mirror.is_some(),
        mirror_source: mirror.map(|m| m.source.clone()),
        mirror_mode: mirror.map(|m| m.mode.clone()),
        ..Default::default()
    };
    for (k, v) in branches {
        info.branches.insert(k, v.to_hex());
    }
    // Releases also belong in /info — clients without a mirror config look
    // here to discover the latest release for `construct --release` etc.
    let releases_dir = dir.join(".levcs/refs/releases");
    if releases_dir.is_dir() {
        if let Ok(read) = std::fs::read_dir(&releases_dir) {
            for ent in read.flatten() {
                let name = ent.file_name().to_string_lossy().to_string();
                if let Ok(txt) = std::fs::read_to_string(ent.path()) {
                    info.releases.insert(name, txt.trim().to_string());
                }
            }
        }
    }
    Ok(axum::Json(info))
}

async fn handle_repo_refs(
    State(s): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
) -> Result<axum::Json<RefList>, ApiError> {
    let repo = RepoId::parse(&repo_id).ok_or_else(not_found)?;
    let _reading = admit_read(&s, &repo, &headers, &format!("/repos/{repo}/refs")).await?;
    let dir = s.repo_dir(&repo);
    let refs = levcs_core::Refs::new(dir.join(".levcs"));
    refuse_if_interrupted(&refs)?;
    let mut out = RefList::default();
    for (k, v) in refs
        .list_branches()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    {
        out.branches.insert(k, v.to_hex());
    }
    let releases_dir = dir.join(".levcs/refs/releases");
    if releases_dir.is_dir() {
        if let Ok(read) = std::fs::read_dir(&releases_dir) {
            for ent in read.flatten() {
                let name = ent.file_name().to_string_lossy().to_string();
                if let Ok(txt) = std::fs::read_to_string(ent.path()) {
                    out.releases.insert(name, txt.trim().to_string());
                }
            }
        }
    }
    Ok(axum::Json(out))
}

async fn handle_get_object(
    State(s): State<AppState>,
    Path((repo_id, hash)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Vec<u8>, ApiError> {
    let repo = RepoId::parse(&repo_id).ok_or_else(not_found)?;
    let id = ObjectId::from_hex(&hash).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let _reading = admit_read(&s, &repo, &headers, &format!("/repos/{repo}/objects/{id}")).await?;
    let store = s.store(&repo);
    let bytes = store
        .read_raw(id)
        .map_err(|e| err(StatusCode::NOT_FOUND, e.to_string()))?;
    Ok(bytes)
}

#[derive(Deserialize)]
struct PackQuery {
    #[serde(default)]
    have: String,
    #[serde(default)]
    want: String,
}

async fn handle_get_pack(
    State(s): State<AppState>,
    Path(repo_id): Path<String>,
    Query(q): Query<PackQuery>,
    headers: HeaderMap,
) -> Result<Vec<u8>, ApiError> {
    let repo = RepoId::parse(&repo_id).ok_or_else(not_found)?;
    // Signed over the query rebuilt in a fixed order, never as a proxy may
    // have rewritten it.
    let path = format!("/repos/{repo}/pack?have={}&want={}", q.have, q.want);
    let _reading = admit_read(&s, &repo, &headers, &path).await?;
    let store = s.store(&repo);
    let have: Vec<ObjectId> = q
        .have
        .split(',')
        .filter(|x| !x.is_empty())
        .map(ObjectId::from_hex)
        .collect::<Result<_, _>>()
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let want: Vec<ObjectId> = q
        .want
        .split(',')
        .filter(|x| !x.is_empty())
        .map(ObjectId::from_hex)
        .collect::<Result<_, _>>()
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    // Compute closure of `want` minus closure of `have` (transitively).
    let mut have_closure: HashSet<ObjectId> = HashSet::new();
    for h in &have {
        collect_closure(&store, *h, &mut have_closure);
    }
    let mut want_set: HashSet<ObjectId> = HashSet::new();
    for w in &want {
        collect_closure(&store, *w, &mut want_set);
    }
    let mut pack = Pack::new();
    for id in want_set.difference(&have_closure) {
        if let Ok(bytes) = store.read_raw(*id) {
            // Determine type by parsing header byte.
            if bytes.len() >= 5 {
                pack.push(bytes[4], bytes);
            }
        }
    }
    Ok(pack.encode())
}

fn collect_closure(store: &ObjectStore, id: ObjectId, out: &mut HashSet<ObjectId>) {
    if !out.insert(id) {
        return;
    }
    let raw = match store.read_object(id) {
        Ok(r) => r,
        Err(_) => return,
    };
    use levcs_core::object::ObjectType;
    match raw.object_type {
        ObjectType::Tree => {
            if let Ok(tree) = levcs_core::Tree::parse_body(&raw.body) {
                for e in tree.entries {
                    collect_closure(store, e.hash, out);
                }
            }
        }
        ObjectType::Commit => {
            if let Ok(commit) = levcs_core::Commit::parse_body(&raw.body) {
                collect_closure(store, commit.tree, out);
                collect_closure(store, commit.authority, out);
                for p in commit.parents {
                    collect_closure(store, p, out);
                }
            }
        }
        ObjectType::Release => {
            if let Ok(rel) = levcs_core::Release::parse_body(&raw.body) {
                collect_closure(store, rel.tree, out);
                collect_closure(store, rel.predecessor, out);
                collect_closure(store, rel.authority, out);
                if !rel.parent_release.is_zero() {
                    collect_closure(store, rel.parent_release, out);
                }
            }
        }
        ObjectType::Authority => {
            if let Ok(body) = AuthorityBody::parse(&raw.body) {
                if !body.previous_authority.is_zero() {
                    collect_closure(store, body.previous_authority, out);
                }
            }
        }
        ObjectType::Blob => {}
    }
}

#[derive(Debug)]
struct AuthCheck {
    pub key: PublicKey,
}

fn verify_request_against(
    s: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<AuthCheck, ApiError> {
    let h = |name: &'static str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| err(StatusCode::UNAUTHORIZED, format!("missing header {name}")))
    };
    let key = h("LeVCS-Key")?;
    let ts = h("LeVCS-Timestamp")?;
    let nonce = h("LeVCS-Nonce")?;
    let sig = h("LeVCS-Signature")?;
    let now = levcs_protocol::auth::current_micros();
    let req = AuthRequest {
        method,
        path_with_query: path,
        body,
    };
    let auth = verify_request(&req, key, ts, nonce, sig, now, DEFAULT_CLOCK_SKEW)
        .map_err(|e| err(StatusCode::UNAUTHORIZED, e.to_string()))?;
    let mut cache = s.nonce_cache.lock().unwrap();
    if !cache.check_and_insert(auth.nonce, auth.timestamp_micros, now) {
        return Err(err(StatusCode::UNAUTHORIZED, "replayed nonce"));
    }
    Ok(AuthCheck { key: auth.key })
}

/// The answer for a repository that does not exist, and for one this
/// request may not read: the two are not told apart.
fn not_found() -> ApiError {
    err(
        StatusCode::NOT_FOUND,
        "repo not found, or not readable by this request",
    )
}

/// Who may read a repository.
enum Readers {
    Anyone,
    /// The members of its current authority.
    Members(AuthorityBody),
}

/// Who may read `repo`: its current authority's `public_read`, with that
/// authority proved back to the genesis the id pins. Decided under the
/// repository's lock, where no push is part way. A transaction record found
/// even so is one a recovery could not roll back, and the authority it would
/// replace decides: a change to `current` is not in effect until its push
/// has landed. Fails closed: an authority that is missing, unreadable or
/// unproved, and a `public_read` that is neither true nor false, let no one
/// read.
fn readers(s: &AppState, repo: &RepoId) -> Result<Readers, String> {
    let refs = levcs_core::Refs::new(s.repo_dir(repo).join(".levcs"));
    let pending = levcs_core::ref_tx::RefStore::pending(&refs)
        .map_err(|e| format!("its ref-transaction record is unreadable: {e}"))?;
    let current = match pending
        .into_iter()
        .flatten()
        .find(|c| c.name == "refs/authority/current")
    {
        Some(change) => change.expected,
        None => refs
            .read("refs/authority/current")
            .map_err(|e| format!("refs/authority/current is unreadable: {e}"))?,
    }
    .ok_or("it has no current authority")?;
    let store = s.store(repo);
    let genesis = verify_authority_chain(&store, current)
        .map_err(|e| format!("its current authority {current} is not proved: {e}"))?;
    if genesis.repo_id.to_hex() != repo.as_str() {
        return Err(format!(
            "its current authority {current} belongs to another repository"
        ));
    }
    let body = store
        .read_typed(current, ObjectType::Authority)
        .map_err(|e| e.to_string())
        .and_then(|raw| AuthorityBody::parse(&raw.body).map_err(|e| e.to_string()))
        .map_err(|e| format!("its current authority {current} is unreadable: {e}"))?;
    match body.policy_value("public_read") {
        Some([0x01]) => Ok(Readers::Anyone),
        None | Some([0x00]) => Ok(Readers::Members(body)),
        Some(v) => Err(format!(
            "its public_read policy is malformed ({} byte(s), not a boolean)",
            v.len()
        )),
    }
}

/// Who may read `repo`, if it exists and that can be established; the
/// answer for a missing repository otherwise. A repository whose read
/// policy cannot be established is logged for the operator.
fn read_gate(s: &AppState, repo: &RepoId) -> Result<Readers, ApiError> {
    if !s.repo_dir(repo).is_dir() {
        return Err(not_found());
    }
    readers(s, repo).map_err(|why| {
        tracing::error!(repo = %repo, "reads refused: {why}");
        not_found()
    })
}

fn member_or_not_found(
    repo: &RepoId,
    body: &AuthorityBody,
    key: &PublicKey,
) -> Result<(), ApiError> {
    if body.find_member(key).is_some() {
        Ok(())
    } else {
        tracing::warn!(repo = %repo, key = %key, "refused: not a member of its current authority");
        Err(not_found())
    }
}

/// `repo`'s lock, if it exists; the answer for a missing repository
/// otherwise. Only a repository that exists has a lock: an id no one
/// created, which anyone can name and any key can sign for, takes no entry
/// in the table of locks.
fn lock_of_existing(s: &AppState, repo: &RepoId) -> Result<Arc<tokio::sync::RwLock<()>>, ApiError> {
    if !s.repo_dir(repo).is_dir() {
        return Err(not_found());
    }
    Ok(s.repo_lock(repo))
}

/// Let a read of `repo` through, or answer as for a repository that does
/// not exist. A public repository is read by anyone. A private one only by
/// a member of its current authority, in a request signed over `path`. No
/// handler used to look at `public_read`, so a private repository was read
/// by anyone (audit C3).
///
/// The guard returned holds the repository's lock shared: the read keeps
/// it until it has answered, so that what it serves is of the state its
/// readers were decided by.
async fn admit_read(
    s: &AppState,
    repo: &RepoId,
    headers: &HeaderMap,
    path: &str,
) -> Result<tokio::sync::OwnedRwLockReadGuard<()>, ApiError> {
    let reading = lock_of_existing(s, repo)?.read_owned().await;
    match read_gate(s, repo)? {
        Readers::Anyone => {}
        Readers::Members(body) => {
            let auth = verify_request_against(s, headers, "GET", path, b"").map_err(|e| {
                tracing::warn!(repo = %repo, "read refused: {}", e.1);
                not_found()
            })?;
            member_or_not_found(repo, &body, &auth.key)?;
        }
    }
    Ok(reading)
}

async fn handle_init(
    State(s): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let repo = RepoId::parse(&repo_id).ok_or_else(not_found)?;
    let path = format!("/repos/{repo}/init");
    let auth = verify_request_against(&s, &headers, "POST", &path, body.as_ref())?;
    // Only the keys the operator names create repositories. Before this,
    // any key that owned the genesis it sent did, on any instance.
    if !s.creators.contains(&auth.key) {
        return Err(err(
            StatusCode::FORBIDDEN,
            format!("{} may not create repositories on this instance", auth.key),
        ));
    }
    // Body is the genesis authority object (signed).
    use levcs_core::object::SignedObject;
    let signed =
        SignedObject::parse(&body).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let body_parsed =
        verify_genesis(&signed).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    if hex::encode(body_parsed.repo_id.as_bytes()) != repo.as_str() {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "URL repo_id does not match authority body",
        ));
    }
    // Creating a repository publishes its genesis and current authority.
    // As in the v2 init contract, only an owner of that genesis may; any
    // member could, a Reader included.
    match body_parsed.find_member(&auth.key) {
        Some(m) if m.role == levcs_identity::authority::Role::Owner => {}
        Some(_) => {
            return Err(err(
                StatusCode::FORBIDDEN,
                "init key is not an owner of the genesis authority",
            ))
        }
        None => {
            return Err(err(
                StatusCode::FORBIDDEN,
                "init key is not a member of the authority",
            ))
        }
    }
    let lock = s.repo_lock(&repo);
    let _guard = lock.write().await;
    let dir = s.repo_dir(&repo);
    if dir.is_dir() {
        return Err(err(StatusCode::CONFLICT, "repo already exists"));
    }
    levcs_core::Repository::init_skeleton(&dir)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let store = s.store(&repo);
    let bytes = signed.serialize();
    let id = store
        .write_raw(&bytes)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let refs = levcs_core::Refs::new(dir.join(".levcs"));
    refs.write("refs/authority/genesis", id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    refs.write("refs/authority/current", id)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(StatusCode::CREATED)
}

async fn handle_push(
    State(s): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let repo = RepoId::parse(&repo_id).ok_or_else(not_found)?;
    let path = format!("/repos/{repo}/push");
    let auth = verify_request_against(&s, &headers, "POST", &path, body.as_ref())?;
    // A push to a repository its signer may not read is answered as one to
    // a repository that does not exist. Its refusals would describe what
    // the repository holds, its current authority among them. Checked here,
    // under the lock shared as a read holds it, so that a stranger's push is
    // not even decoded; and again under the exclusive lock, which decides.
    // Checked here without the lock, it could find the repository opened by
    // a push not yet landed, and decode a stranger's push to a private one.
    let lock = lock_of_existing(&s, &repo)?;
    {
        let _deciding = lock.read().await;
        match read_gate(&s, &repo)? {
            Readers::Anyone => {}
            Readers::Members(body) => member_or_not_found(&repo, &body, &auth.key)?,
        }
    }
    let dir = s.repo_dir(&repo);
    // §5.6: a mirror's refs are records of its source's state (Rule R.4).
    // Publishing over them is not replication, and `writeback`, which was
    // to forward a push to the source, is not implemented: a push used to
    // be applied here, over the records. Refuse, and point at the source.
    if let Some(m) = s.config.mirror_for(&repo) {
        return Err(err(
            StatusCode::FORBIDDEN,
            format!(
                "this instance mirrors {repo} from {} and does not accept writes; push to the source instead",
                m.source
            ),
        ));
    }
    // §4.3 storage-mode enforcement. We need the parsed manifest to
    // gate by ref namespace, so the actual rejection happens after
    // the manifest is decoded below. Metadata-mode is the only
    // wholesale reject we can make right now; the others require
    // looking at `manifest.updates`.
    if s.config.storage_mode() == StorageMode::Metadata {
        return Err(err(
            StatusCode::FORBIDDEN,
            "instance is in metadata-only mode and does not accept pushes; \
             populate via mirror configuration",
        ));
    }
    // Body layout: pack || u32 manifest_len || manifest_json || 64 sig
    if body.len() < 4 + 64 {
        return Err(err(StatusCode::BAD_REQUEST, "body too short"));
    }
    let (pack, pack_len) = Pack::decode_prefix(&body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("pack decode: {e}")))?;
    if body.len() < pack_len + 4 + 64 {
        return Err(err(StatusCode::BAD_REQUEST, "body truncated after pack"));
    }
    let manifest_len = u32::from_le_bytes([
        body[pack_len],
        body[pack_len + 1],
        body[pack_len + 2],
        body[pack_len + 3],
    ]) as usize;
    if body.len() != pack_len + 4 + manifest_len + 64 {
        return Err(err(StatusCode::BAD_REQUEST, "body length mismatch"));
    }
    let manifest_json = &body[pack_len + 4..pack_len + 4 + manifest_len];
    let manifest_sig = &body[pack_len + 4 + manifest_len..];
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(manifest_sig);
    auth.key
        .verify(manifest_json, &sig_arr)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "manifest signature invalid"))?;
    let manifest: levcs_protocol::PushManifest = serde_json::from_slice(manifest_json)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    // §4.3: release-mode instances accept only release ref updates.
    // Inter-release commits are not stored — `refs/branches/*` updates
    // would require us to keep the commit chain. Reject early so the
    // client gets a clear message before any object lands in the store.
    if s.config.storage_mode() == StorageMode::Release {
        for u in &manifest.updates {
            if !u.r#ref.starts_with("refs/releases/") {
                return Err(err(
                    StatusCode::FORBIDDEN,
                    format!(
                        "instance is in release-only mode; ref {:?} is not a release \
                         (only refs/releases/* updates are accepted)",
                        u.r#ref
                    ),
                ));
            }
        }
    }
    let store = s.store(&repo);

    // The per-repo lock, held from reading S0 to the last ref write.
    let _guard = lock.write().await;
    // Again, under the lock and against the state admission decides by:
    // the repository may have become private since the check above, and
    // each refusal from here on describes that state.
    match read_gate(&s, &repo)? {
        Readers::Anyone => {}
        Readers::Members(body) => member_or_not_found(&repo, &body, &auth.key)?,
    }

    // The pushed objects, held apart from the store until the push is
    // admitted. They used to be written first, so a refused push still
    // left them stored.
    let incoming = Overlay::new(&store, &pack)?;

    // Instance merge policy (§6.6.4): the outer ceiling on the merge
    // handlers a pushed commit may record. The repository's own policy is
    // the inner constraint and is verified independently.
    if !s.config.allowed_handlers.is_empty() {
        for ent in &pack.entries {
            if ent.object_type != ObjectType::Commit as u8 {
                continue;
            }
            let signed = match levcs_core::object::SignedObject::parse(&ent.bytes) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let commit = match Commit::from_signed(&signed) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let record_bytes = match find_merge_record(&incoming, commit.tree) {
                Ok(Some(b)) => b,
                _ => continue,
            };
            let record_str = match std::str::from_utf8(&record_bytes) {
                Ok(s) => s,
                Err(_) => {
                    return Err(err(
                        StatusCode::BAD_REQUEST,
                        "merge-record blob is not valid UTF-8",
                    ));
                }
            };
            let record = MergeRecord::from_toml(record_str)
                .map_err(|e| err(StatusCode::BAD_REQUEST, format!("merge-record: {e}")))?;
            for fr in &record.files {
                if !check_handler_allowed(&fr.handler, &fr.handler_hash, &s.config.allowed_handlers)
                {
                    return Err(err(
                        StatusCode::FORBIDDEN,
                        format!(
                            "merge handler '{}' is not permitted by this instance's policy",
                            fr.handler
                        ),
                    ));
                }
            }
        }
    }

    // Rule P (`doc/authority-semantics.md`), against the state read here,
    // under the lock: the stored current authority and the history the
    // instance's refs already reach. The manifest's authority used to
    // authorize the push (C1), only tips were checked, and `current` was
    // set to the newest authority any tip cited, without a boundary.
    let refs = levcs_core::Refs::new(dir.join(".levcs"));
    // A push this instance was killed part way through is rolled back
    // before anything reads the refs.
    levcs_core::ref_tx::recover(&refs).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("an interrupted push could not be rolled back: {e}"),
        )
    })?;
    let s0 = pre_state(&refs, &store, repo.as_str())?;
    let named = ObjectId::from_hex(&manifest.authority_hash)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("authority_hash: {e}")))?;
    let authority_update = authority_update(&incoming, &s0, named)?;
    let mut updates = Vec::new();
    for u in &manifest.updates {
        let new = ObjectId::from_hex(&u.new_hash)
            .map_err(|e| err(StatusCode::BAD_REQUEST, format!("new_hash: {e}")))?;
        let expected = match &u.old_hash {
            Some(h) if !h.is_empty() => Some(
                ObjectId::from_hex(h)
                    .map_err(|e| err(StatusCode::BAD_REQUEST, format!("bad old_hash: {e}")))?,
            ),
            _ => None,
        };
        updates.push(levcs_identity::admission::RefUpdate {
            name: u.r#ref.clone(),
            expected,
            new: Some(new),
            force: manifest.force,
        });
    }
    let tx = levcs_identity::admission::Transaction {
        signer: auth.key,
        updates,
        authority_update,
    };
    let admitted = levcs_identity::admission::admit(&incoming, &s0, &tx).map_err(|r| {
        use levcs_identity::admission::Refused;
        match r.kind {
            Refused::Stale => err(StatusCode::CONFLICT, r.to_string()),
            Refused::NotFastForward => err(
                StatusCode::CONFLICT,
                format!("non-fast-forward update: {r}; pass --force to override"),
            ),
            Refused::Unauthorized | Refused::Invalid => err(StatusCode::FORBIDDEN, r.to_string()),
        }
    })?;

    // Admitted: store the objects, then move the refs, then current.
    for ent in &pack.entries {
        store
            .write_raw(&ent.bytes)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    // One transaction: if any write fails, every ref it reached is read
    // back and put back, `current` included, since a write can land and
    // still fail. It used to leave `current` out, and to trust each write's
    // own report.
    let mut changes: Vec<levcs_core::ref_tx::RefChange> = tx
        .updates
        .iter()
        .map(|u| levcs_core::ref_tx::RefChange {
            name: u.name.clone(),
            expected: u.expected,
            new: u.new,
        })
        .collect();
    if let Some(a1) = admitted.new_current {
        changes.push(levcs_core::ref_tx::RefChange {
            name: "refs/authority/current".into(),
            expected: s0.current,
            new: Some(a1),
        });
    }
    levcs_core::ref_tx::apply(&refs, &changes).map_err(|e| {
        err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("push not applied: {e}"),
        )
    })?;
    Ok(StatusCode::OK)
}

/// The pushed objects over the store, read by admission before anything is
/// written. Each pushed object is keyed by the hash of its own bytes, so it
/// can only ever be found under its true id.
struct Overlay<'a> {
    store: &'a ObjectStore,
    pushed: HashMap<ObjectId, Vec<u8>>,
}

impl<'a> Overlay<'a> {
    fn new(store: &'a ObjectStore, pack: &Pack) -> Result<Self, ApiError> {
        let mut pushed = HashMap::new();
        for ent in &pack.entries {
            levcs_core::RawObject::parse(&ent.bytes)
                .map_err(|e| err(StatusCode::BAD_REQUEST, format!("pack object: {e}")))?;
            pushed.insert(levcs_core::blake3_hash(&ent.bytes), ent.bytes.clone());
        }
        Ok(Overlay { store, pushed })
    }
}

impl VerifySource for Overlay<'_> {
    fn read_raw(&self, id: ObjectId) -> levcs_identity::verify::Verification<Vec<u8>> {
        match self.pushed.get(&id) {
            Some(b) => Ok(b.clone()),
            None => Ok(self.store.read_raw(id)?),
        }
    }
}

/// `S0`: the genesis this repository's id pins, its current authority, and
/// its branch and release refs.
fn pre_state(
    refs: &levcs_core::Refs,
    store: &ObjectStore,
    repo_id: &str,
) -> Result<levcs_identity::admission::PreState, ApiError> {
    let internal =
        |e: levcs_core::error::Error| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    let pinned =
        ObjectId::from_hex(repo_id).map_err(|_| err(StatusCode::NOT_FOUND, "repo not found"))?;
    let genesis = refs
        .read("refs/authority/genesis")
        .map_err(internal)?
        .ok_or_else(|| {
            err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "repository has no genesis",
            )
        })?;
    let body = store
        .read_typed(genesis, ObjectType::Authority)
        .ok()
        .and_then(|raw| AuthorityBody::parse(&raw.body).ok());
    if body.map(|b| b.repo_id) != Some(pinned) {
        return Err(err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "this repository's genesis does not match its repo_id",
        ));
    }
    let current = refs.read("refs/authority/current").map_err(internal)?;
    let mut published = std::collections::BTreeMap::new();
    for (name, id) in refs.list_all().map_err(internal)? {
        if name.starts_with("refs/branches/") || name.starts_with("refs/releases/") {
            published.insert(name, id);
        }
    }
    Ok(levcs_identity::admission::PreState {
        genesis,
        current,
        refs: published,
    })
}

/// What the v1 manifest's `authority_hash` asks for. It is never used to
/// authorize anything. It is the authority the client made the push under,
/// as v2's `expected_authority`: the stored current authority asks for no
/// change, and a direct successor of it asks `current` to move there with
/// a boundary commit (`authority_update`). Anything else means the client
/// worked against a state this instance has left.
fn authority_update<S: VerifySource>(
    src: &S,
    s0: &levcs_identity::admission::PreState,
    named: ObjectId,
) -> Result<Option<ObjectId>, ApiError> {
    if Some(named) == s0.current {
        return Ok(None);
    }
    let previous = src
        .read_raw(named)
        .ok()
        .and_then(|b| levcs_core::object::SignedObject::parse(&b).ok())
        .filter(|o| o.object_type == ObjectType::Authority)
        .and_then(|o| AuthorityBody::parse(&o.body).ok())
        .map(|b| b.previous_authority);
    match (previous, s0.current) {
        (Some(p), Some(cur)) if p == cur => Ok(Some(named)),
        _ => Err(err(
            StatusCode::CONFLICT,
            format!(
                "this push was made under authority {named}, but this repository's \
                 current authority is {}",
                s0.current.map_or("unset".to_string(), |c| c.to_hex())
            ),
        )),
    }
}

/// A push killed part way leaves a record (`levcs_core::ref_tx`) until it
/// is rolled back. Its refs are not served meanwhile: they may be half of
/// a transaction.
fn refuse_if_interrupted(refs: &levcs_core::Refs) -> Result<(), ApiError> {
    match levcs_core::ref_tx::RefStore::pending(refs) {
        Ok(None) => Ok(()),
        Ok(Some(_)) => Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "an interrupted push is being rolled back; try again",
        )),
        Err(e) => Err(err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}

/// Roll back every push this instance was killed part way through, before
/// it serves anything: a push interrupted by an error is rolled back as it
/// fails, but one interrupted by the process dying leaves its record for
/// the next process. Returns one line per repository rolled back or not.
pub fn recover_interrupted_pushes(root: &std::path::Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(root) else {
        return out;
    };
    for ent in entries.flatten() {
        let name = ent.file_name().to_string_lossy().into_owned();
        let levcs = ent.path().join(".levcs");
        if RepoId::parse(&name).is_none() || !levcs.is_dir() {
            continue;
        }
        match levcs_core::ref_tx::recover(&levcs_core::Refs::new(levcs)) {
            Ok(None) => {}
            Ok(Some(refs)) => out.push(format!(
                "{name}: rolled back an interrupted push ({})",
                refs.join(", ")
            )),
            Err(e) => out.push(format!(
                "{name}: an interrupted push could not be rolled back: {e}"
            )),
        }
    }
    out
}

/// Helper used by tests and the binary's `main` to bind and serve.
pub async fn serve(state: AppState, addr: std::net::SocketAddr) -> std::io::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

/// Walk into `tree_id` looking for `.levcs/merge-record` and return the blob
/// body if found. Returns `Ok(None)` for a tree with no `.levcs` subtree, no
/// `merge-record` entry, or any non-blob entry at that path.
fn find_merge_record<S: VerifySource>(
    src: &S,
    tree_id: ObjectId,
) -> Result<Option<Vec<u8>>, String> {
    if tree_id.is_zero() {
        return Ok(None);
    }
    let typed = |id: ObjectId, want: ObjectType| -> Result<levcs_core::RawObject, String> {
        let bytes = src.read_raw(id).map_err(|e| e.to_string())?;
        let raw = levcs_core::RawObject::parse(&bytes).map_err(|e| e.to_string())?;
        if raw.object_type != want {
            return Err(format!("{id} is not a {}", want.name()));
        }
        Ok(raw)
    };
    let raw = typed(tree_id, ObjectType::Tree)?;
    let tree = Tree::parse_body(&raw.body).map_err(|e| e.to_string())?;
    let levcs_entry = match tree.entries.iter().find(|e| e.name == ".levcs") {
        Some(e) if e.entry_type == EntryType::Tree => e,
        _ => return Ok(None),
    };
    let raw = typed(levcs_entry.hash, ObjectType::Tree)?;
    let levcs_tree = Tree::parse_body(&raw.body).map_err(|e| e.to_string())?;
    let mr_entry = match levcs_tree.entries.iter().find(|e| e.name == "merge-record") {
        Some(e) if e.entry_type == EntryType::Blob => e,
        _ => return Ok(None),
    };
    Ok(Some(typed(mr_entry.hash, ObjectType::Blob)?.body))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only an id is ever joined onto the root.
    #[test]
    fn a_repo_id_is_64_lowercase_hex_characters_and_nothing_else() {
        let id = "0123456789abcdef".repeat(4);
        assert_eq!(RepoId::parse(&id).map(|r| r.to_string()), Some(id.clone()));
        for not in [
            id.to_uppercase(),
            id[..63].to_string(),
            format!("{id}0"),
            format!("{}g", &id[..63]),
            format!("../{}", &id[..61]),
            format!("/{}", &id[..63]),
            format!("{}%2F", &id[..61]),
            format!("{}\0", &id[..63]),
            String::new(),
        ] {
            assert!(RepoId::parse(&not).is_none(), "{not:?}");
        }
    }

    fn micros_from_secs(s: i64) -> i64 {
        s * 1_000_000
    }

    /// Re-inserting the same nonce within the TTL window must be rejected.
    /// This is the core anti-replay invariant; before the TTL rewrite the
    /// cache also satisfied this property, so a green test here is the
    /// floor, not the ceiling.
    #[test]
    fn nonce_replay_within_ttl_is_rejected() {
        let mut cache = NonceCache::default();
        let nonce = [0x42u8; 16];
        let ts = micros_from_secs(1_700_000_000);
        let now = ts + micros_from_secs(1);
        assert!(cache.check_and_insert(nonce, ts, now));
        // Same nonce, slightly later "now": still within TTL, must reject.
        assert!(!cache.check_and_insert(nonce, ts, now + micros_from_secs(60)));
    }

    /// Once a nonce ages past `NONCE_TTL_SECS` it must be evicted from
    /// the cache; what bounds memory growth is precisely this release.
    /// (`verify_request` will reject the timestamp for skew long before
    /// the cache ever sees a stale request again, so re-accepting the
    /// nonce bytes is safe.)
    ///
    /// We drive `NONCE_EVICT_BATCH` distinct inserts at a fresh timestamp
    /// to trigger one full eviction pass, then assert the original
    /// (now-stale) entry has been swept.
    #[test]
    fn nonce_evicted_after_ttl_expires() {
        let mut cache = NonceCache::default();
        let stale = [0x42u8; 16];
        let stale_ts = micros_from_secs(1_700_000_000);
        assert!(cache.check_and_insert(stale, stale_ts, stale_ts));
        // Fast-forward "now" past the TTL window and force an eviction
        // sweep by inserting a batch of fresh nonces.
        let later = stale_ts + micros_from_secs(NONCE_TTL_SECS + 1);
        for i in 0..(NONCE_EVICT_BATCH as u32) {
            let mut n = [0u8; 16];
            n[..4].copy_from_slice(&i.to_le_bytes());
            n[15] = 0xFF; // disambiguate from `stale`
            assert!(cache.check_and_insert(n, later, later));
        }
        // The stale entry is gone; same-nonce-bytes with a fresh
        // timestamp are allowed.
        assert!(cache.check_and_insert(stale, later, later));
    }

    /// Regression test for the original CVE-shaped bug: the previous
    /// implementation called `seen.clear()` once it grew past 100k
    /// entries, which dropped every recently-seen nonce in one step and
    /// allowed any captured request still within the 5-minute clock-skew
    /// window to be replayed.
    ///
    /// Here we (a) drive the cache through several eviction passes with
    /// junk-but-fresh nonces, then (b) try to replay a still-fresh nonce
    /// inserted at the start. With time-bounded eviction the replay
    /// must be rejected, because the original entry's timestamp is still
    /// inside the TTL window. With the old count-bounded `clear()`, this
    /// test would erroneously succeed (the replay would be accepted).
    /// The flood size is intentionally a small multiple of
    /// `NONCE_EVICT_BATCH` — the property doesn't depend on the exact
    /// count, just on triggering the eviction path.
    #[test]
    fn nonce_cache_does_not_drop_fresh_entries_under_load() {
        let mut cache = NonceCache::default();
        let base_ts = micros_from_secs(1_700_000_000);
        let mut victim = [0u8; 16];
        victim[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        // Insert the "captured" request first.
        assert!(cache.check_and_insert(victim, base_ts, base_ts));
        // Flood with NONCE_EVICT_BATCH * 4 fresh-but-distinct nonces, all
        // dated within the same TTL window so eviction can't help us.
        let flood: u32 = (NONCE_EVICT_BATCH as u32) * 4;
        for i in 0..flood {
            let mut n = [0u8; 16];
            n[..4].copy_from_slice(&i.to_le_bytes());
            let now = base_ts + (i as i64) * 1_000;
            assert!(cache.check_and_insert(n, now, now));
        }
        let replay_now = base_ts + micros_from_secs(60);
        assert!(
            !cache.check_and_insert(victim, base_ts, replay_now),
            "replay of fresh nonce must be rejected even when cache is large"
        );
    }
}
