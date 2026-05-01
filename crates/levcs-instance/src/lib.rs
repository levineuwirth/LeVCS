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
use levcs_protocol::auth::{verify_request, AuthRequest, DEFAULT_CLOCK_SKEW};
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
    pub fn mirror_for(&self, repo_id: &str) -> Option<&MirrorConfig> {
        self.mirrors.iter().find(|m| m.repo_id == repo_id)
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
    pub repo_locks: Arc<RwLock<HashMap<String, Arc<Mutex<()>>>>>,
}

impl AppState {
    pub fn new(config: InstanceConfig) -> Self {
        Self {
            config: Arc::new(config),
            nonce_cache: Arc::new(Mutex::new(NonceCache::default())),
            repo_locks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn repo_dir(&self, repo_id: &str) -> PathBuf {
        self.config.root.join(repo_id)
    }

    pub fn store(&self, repo_id: &str) -> ObjectStore {
        ObjectStore::new(self.repo_dir(repo_id).join(".levcs/objects"))
    }
}

#[derive(Default)]
pub struct NonceCache {
    /// Maps nonce → expiry epoch (in micros).
    seen: HashSet<[u8; 16]>,
}

impl NonceCache {
    pub fn check_and_insert(&mut self, nonce: [u8; 16]) -> bool {
        if self.seen.contains(&nonce) {
            false
        } else {
            self.seen.insert(nonce);
            // Cap memory by clearing periodically.
            if self.seen.len() > 100_000 {
                self.seen.clear();
            }
            true
        }
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
) -> Result<axum::Json<InfoResponse>, ApiError> {
    let dir = s.repo_dir(&repo_id);
    if !dir.is_dir() {
        return Err(err(StatusCode::NOT_FOUND, "repo not found"));
    }
    let refs = levcs_core::Refs::new(dir.join(".levcs"));
    let cur = refs
        .read("refs/authority/current")
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let genesis = refs
        .read("refs/authority/genesis")
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let branches = refs
        .list_branches()
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mirror = s.config.mirror_for(&repo_id);
    let mut info = InfoResponse {
        repo_id,
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
) -> Result<axum::Json<RefList>, ApiError> {
    let dir = s.repo_dir(&repo_id);
    if !dir.is_dir() {
        return Err(err(StatusCode::NOT_FOUND, "repo not found"));
    }
    let refs = levcs_core::Refs::new(dir.join(".levcs"));
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
) -> Result<Vec<u8>, ApiError> {
    let id = ObjectId::from_hex(&hash).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let store = s.store(&repo_id);
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
) -> Result<Vec<u8>, ApiError> {
    let store = s.store(&repo_id);
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
    if !cache.check_and_insert(auth.nonce) {
        return Err(err(StatusCode::UNAUTHORIZED, "replayed nonce"));
    }
    Ok(AuthCheck { key: auth.key })
}

async fn handle_init(
    State(s): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<StatusCode, ApiError> {
    let path = format!("/repos/{repo_id}/init");
    let auth = verify_request_against(&s, &headers, "POST", &path, body.as_ref())?;
    // Body is the genesis authority object (signed).
    use levcs_core::object::SignedObject;
    let signed =
        SignedObject::parse(&body).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let body_parsed =
        verify_genesis(&signed).map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    if hex::encode(body_parsed.repo_id.as_bytes()) != repo_id {
        return Err(err(
            StatusCode::BAD_REQUEST,
            "URL repo_id does not match authority body",
        ));
    }
    if body_parsed.find_member(&auth.key).is_none() {
        return Err(err(
            StatusCode::FORBIDDEN,
            "init key is not a member of the authority",
        ));
    }
    let dir = s.repo_dir(&repo_id);
    if dir.is_dir() {
        return Err(err(StatusCode::CONFLICT, "repo already exists"));
    }
    levcs_core::Repository::init_skeleton(&dir)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let store = s.store(&repo_id);
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
    let path = format!("/repos/{repo_id}/push");
    let auth = verify_request_against(&s, &headers, "POST", &path, body.as_ref())?;
    let dir = s.repo_dir(&repo_id);
    if !dir.is_dir() {
        return Err(err(StatusCode::NOT_FOUND, "repo not found"));
    }
    // §5.6: a mirror is read-only by default. Reject pushes unless the
    // operator has explicitly opted into writeback. We return 403 with a
    // body that points clients at the source so they can retry there.
    if let Some(m) = s.config.mirror_for(&repo_id) {
        if !m.writeback {
            return Err(err(
                StatusCode::FORBIDDEN,
                format!(
                    "this instance mirrors {repo_id} from {} and does not accept writes; push to the source instead",
                    m.source
                ),
            ));
        }
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
    let store = s.store(&repo_id);

    // Acquire per-repo lock for atomic ref updates.
    let lock = {
        let mut map = s.repo_locks.write().unwrap();
        map.entry(repo_id.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    };
    let _guard = lock.lock().unwrap();

    // Step 1: write all pack objects to the loose store (validated framing).
    for ent in &pack.entries {
        store
            .write_raw(&ent.bytes)
            .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    }
    // Step 1b: enforce instance merge-policy (§6.6.4). Walk every Commit in
    // the pack; if its tree carries `.levcs/merge-record`, parse it and
    // reject the whole push if any handler reference falls outside
    // `allowed_handlers`. The repository's own policy is the inner
    // constraint and is verified independently elsewhere; this is the
    // outer ceiling.
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
            let record_bytes = match find_merge_record(&store, commit.tree) {
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
    // Step 2: verify authority chain on the manifest's authority_hash.
    let auth_hash = ObjectId::from_hex(&manifest.authority_hash)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    verify_authority_chain(&store, auth_hash)
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("authority chain: {e}")))?;
    let auth_obj = store
        .read_raw(auth_hash)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let auth_signed = levcs_core::object::SignedObject::parse(&auth_obj)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
    let auth_body = AuthorityBody::parse(&auth_signed.body)
        .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;

    // Step 3: verify pusher has appropriate role.
    let member = auth_body
        .find_member(&auth.key)
        .ok_or_else(|| err(StatusCode::FORBIDDEN, "pusher not in authority"))?;
    if member.role < levcs_identity::authority::Role::Contributor {
        return Err(err(StatusCode::FORBIDDEN, "pusher lacks contributor role"));
    }

    // Step 4: verify each new commit and compare-and-swap each ref.
    let refs = levcs_core::Refs::new(dir.join(".levcs"));
    for u in &manifest.updates {
        let new_id = ObjectId::from_hex(&u.new_hash)
            .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
        let old_actual = refs
            .read(&u.r#ref)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        let old_expected = match &u.old_hash {
            Some(s) if !s.is_empty() => Some(
                ObjectId::from_hex(s)
                    .map_err(|e| err(StatusCode::BAD_REQUEST, format!("bad old_hash: {e}")))?,
            ),
            _ => None,
        };
        if old_actual != old_expected {
            return Err(err(
                StatusCode::CONFLICT,
                format!("ref {} changed concurrently", u.r#ref),
            ));
        }
        // Dispatch verification by the new tip's object type so we can
        // accept both branch refs (commit-typed) and release refs
        // (release-typed). Anything else gets rejected up front.
        let raw = store
            .read_object(new_id)
            .map_err(|e| err(StatusCode::BAD_REQUEST, e.to_string()))?;
        match raw.object_type {
            ObjectType::Commit => {
                levcs_identity::verify::verify_commit(&store, new_id, Some(&u.r#ref))
                    .map_err(|e| err(StatusCode::BAD_REQUEST, format!("commit verify: {e}")))?;
            }
            ObjectType::Release => {
                levcs_identity::verify::verify_release(&store, new_id)
                    .map_err(|e| err(StatusCode::BAD_REQUEST, format!("release verify: {e}")))?;
            }
            other => {
                return Err(err(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "ref tip is {} object, must be Commit or Release",
                        other.name()
                    ),
                ));
            }
        }
        // §5.4(e): non-fast-forward updates require force-push and a
        // sufficiently privileged key. Only check when this is an
        // update of an existing ref (old_actual is Some) — first-write
        // refs have no ancestry constraint.
        if let Some(old_id) = old_actual {
            if !is_ancestor(&store, old_id, new_id) {
                if !manifest.force {
                    return Err(err(
                        StatusCode::CONFLICT,
                        format!(
                            "non-fast-forward update for ref {}; pass --force to override",
                            u.r#ref
                        ),
                    ));
                }
                if member.role < levcs_identity::authority::Role::Maintainer {
                    return Err(err(
                        StatusCode::FORBIDDEN,
                        format!(
                            "force-push to {} requires maintainer or owner role",
                            u.r#ref
                        ),
                    ));
                }
            }
        }
        refs.write(&u.r#ref, new_id)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    // Update current authority pointer if any pushed tip modified it.
    // Walk all updates rather than just the last so the order in `updates`
    // can be arbitrary; pick the highest-numbered authority by version.
    let mut best_auth: Option<(ObjectId, u32)> = None;
    for u in &manifest.updates {
        let id = match ObjectId::from_hex(&u.new_hash) {
            Ok(i) => i,
            Err(_) => continue,
        };
        let bytes = match store.read_raw(id) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let signed = match levcs_core::object::SignedObject::parse(&bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let auth_id = match signed.object_type {
            ObjectType::Commit => match levcs_core::Commit::from_signed(&signed) {
                Ok(c) => c.authority,
                Err(_) => continue,
            },
            ObjectType::Release => match levcs_core::Release::parse_body(&signed.body) {
                Ok(r) => r.authority,
                Err(_) => continue,
            },
            _ => continue,
        };
        let auth_bytes = match store.read_raw(auth_id) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let auth_signed = match levcs_core::object::SignedObject::parse(&auth_bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let auth_body = match AuthorityBody::parse(&auth_signed.body) {
            Ok(b) => b,
            Err(_) => continue,
        };
        match best_auth {
            None => best_auth = Some((auth_id, auth_body.version)),
            Some((_, v)) if auth_body.version > v => best_auth = Some((auth_id, auth_body.version)),
            _ => {}
        }
    }
    if let Some((auth_id, _)) = best_auth {
        refs.write("refs/authority/current", auth_id)
            .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }
    Ok(StatusCode::OK)
}

/// Helper used by tests and the binary's `main` to bind and serve.
pub async fn serve(state: AppState, addr: std::net::SocketAddr) -> std::io::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await
}

/// Decide whether `old_id` is an ancestor of `new_id` for fast-forward
/// detection on push (§5.4(e)). Walks parent chains starting from
/// `new_id`. Considers Commit parents and Release predecessor +
/// parent_release; both flavours of ref can be advanced and either
/// chain might lead back to `old_id`. Returns false on read errors —
/// safer to require force-push than to silently accept an update we
/// can't verify.
fn is_ancestor(store: &ObjectStore, old_id: ObjectId, new_id: ObjectId) -> bool {
    use levcs_core::Release;
    if old_id == new_id {
        return true;
    }
    let mut visited: HashSet<ObjectId> = HashSet::new();
    let mut stack = vec![new_id];
    while let Some(id) = stack.pop() {
        if !visited.insert(id) {
            continue;
        }
        if id == old_id {
            return true;
        }
        let raw = match store.read_object(id) {
            Ok(r) => r,
            Err(_) => continue,
        };
        match raw.object_type {
            ObjectType::Commit => {
                if let Ok(c) = Commit::parse_body(&raw.body) {
                    stack.extend(c.parents);
                }
            }
            ObjectType::Release => {
                if let Ok(r) = Release::parse_body(&raw.body) {
                    if !r.predecessor.is_zero() {
                        stack.push(r.predecessor);
                    }
                    if !r.parent_release.is_zero() {
                        stack.push(r.parent_release);
                    }
                }
            }
            _ => {}
        }
    }
    false
}

/// Walk into `tree_id` looking for `.levcs/merge-record` and return the blob
/// body if found. Returns `Ok(None)` for a tree with no `.levcs` subtree, no
/// `merge-record` entry, or any non-blob entry at that path.
fn find_merge_record(
    store: &ObjectStore,
    tree_id: ObjectId,
) -> Result<Option<Vec<u8>>, levcs_core::error::Error> {
    if tree_id.is_zero() {
        return Ok(None);
    }
    let raw = store.read_typed(tree_id, ObjectType::Tree)?;
    let tree = Tree::parse_body(&raw.body)?;
    let levcs_entry = match tree.entries.iter().find(|e| e.name == ".levcs") {
        Some(e) if e.entry_type == EntryType::Tree => e,
        _ => return Ok(None),
    };
    let raw = store.read_typed(levcs_entry.hash, ObjectType::Tree)?;
    let levcs_tree = Tree::parse_body(&raw.body)?;
    let mr_entry = match levcs_tree.entries.iter().find(|e| e.name == "merge-record") {
        Some(e) if e.entry_type == EntryType::Blob => e,
        _ => return Ok(None),
    };
    let blob = store.read_typed(mr_entry.hash, ObjectType::Blob)?;
    Ok(Some(blob.body))
}

// Allow `verify_authority_chain` to use ObjectStore directly.
#[allow(dead_code)]
fn _vs(_: &dyn VerifySource) {}
