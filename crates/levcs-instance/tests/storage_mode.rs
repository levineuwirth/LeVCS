//! Instance storage-mode enforcement on push (§4.3).
//!
//! Each test boots an in-process instance with a specific
//! `storage_mode` and pushes a hand-built commit/release. The push
//! must be rejected (or accepted) according to the rules in §4.3:
//!
//!   * `full`     — accepts every push.
//!   * `release`  — only `refs/releases/*` updates are accepted.
//!   * `metadata` — every push is rejected (mode is intended to be
//!                  populated via mirroring, not direct push).

use std::net::SocketAddr;
use std::path::PathBuf;

use levcs_client::{Client, ClientError};
use levcs_core::hash::blake3_hash;
use levcs_core::object::ObjectType;
use levcs_core::{Blob, Commit, CommitFlags, EntryType, FileMode, Tree, TreeEntry, ZERO_ID};
use levcs_identity::authority::{AuthorityBody, MemberEntry, PolicyEntry, Role};
use levcs_identity::keys::SecretKey;
use levcs_identity::sign::{sign_authority, sign_commit};
use levcs_instance::{router, AppState, InstanceConfig};
use levcs_protocol::wire::{PushManifest, PushUpdate};
use levcs_protocol::Pack;

fn tempdir(prefix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("{prefix}-{n}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

async fn start(
    mode: &str,
    creators: Vec<String>,
) -> (SocketAddr, tokio::task::JoinHandle<()>, PathBuf) {
    let root = tempdir(&format!("levcs-storage-{mode}"));
    let cfg = InstanceConfig {
        root: root.clone(),
        storage_mode: mode.into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: Vec::new(),
        creators,
        limits: Default::default(),
    };
    let state = AppState::new(cfg);
    let app = router(state);
    let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, task, root)
}

struct Setup {
    sk: SecretKey,
    auth_id: levcs_core::ObjectId,
    repo_id: String,
    auth_bytes: Vec<u8>,
}

fn build_genesis() -> Setup {
    let sk = SecretKey::generate();
    let pk = sk.public();
    let now = 1_700_000_000_000_000;
    let mut auth = AuthorityBody {
        schema_version: 1,
        repo_id: ZERO_ID,
        previous_authority: ZERO_ID,
        version: 1,
        created_micros: now,
        members: vec![MemberEntry {
            key: pk,
            handle: "alice".into(),
            role: Role::Owner,
            added_micros: now,
            added_by: pk,
        }],
        policy: vec![PolicyEntry {
            key: "public_read".into(),
            value: vec![0x01],
        }],
    };
    auth.normalize().unwrap();
    auth.assign_genesis_repo_id().unwrap();
    let signed = sign_authority(&auth, &sk).unwrap();
    let auth_bytes = signed.serialize();
    let auth_id = blake3_hash(&auth_bytes);
    let repo_id = auth.repo_id.to_hex();
    Setup {
        sk,
        auth_id,
        repo_id,
        auth_bytes,
    }
}

/// Build a single-blob, single-commit pack for a push test. Returns
/// (pack, commit_id) so the caller can stuff the id into a manifest.
fn build_simple_pack(
    sk: &SecretKey,
    auth_id: levcs_core::ObjectId,
) -> (Pack, levcs_core::ObjectId) {
    let pk = sk.public();
    let blob = Blob::new(b"hello\n".to_vec());
    let blob_bytes = blob.serialize();
    let blob_id = blake3_hash(&blob_bytes);
    let mut tree = Tree::new();
    tree.entries.push(TreeEntry {
        name: "a.txt".into(),
        entry_type: EntryType::Blob,
        mode: FileMode::REGULAR,
        hash: blob_id,
    });
    tree.sort_and_validate().unwrap();
    let tree_bytes = tree.serialize();
    let tree_id = blake3_hash(&tree_bytes);
    let commit = Commit {
        tree: tree_id,
        parents: vec![],
        authority: auth_id,
        author_key: pk.0,
        timestamp_micros: 1_700_000_001_000_000,
        flags: CommitFlags::NONE,
        message: "test".into(),
    };
    let signed = sign_commit(commit, sk).unwrap();
    let commit_bytes = signed.serialize();
    let commit_id = blake3_hash(&commit_bytes);
    let mut pack = Pack::new();
    pack.push(ObjectType::Blob as u8, blob_bytes);
    pack.push(ObjectType::Tree as u8, tree_bytes);
    pack.push(ObjectType::Commit as u8, commit_bytes);
    (pack, commit_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_mode_rejects_all_pushes() {
    let setup = build_genesis();
    let (addr, task, root) = start("metadata", vec![setup.sk.public().to_levcs()]).await;
    let base = format!("http://{addr}/levcs/v1");

    let result = tokio::task::spawn_blocking({
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        move || {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            // init is allowed (it's how mirror discovery works); push
            // is what gets refused.
            client.init(&sk, &repo_id, &auth_bytes).unwrap();
            let (pack, commit_id) = build_simple_pack(&sk, auth_id);
            let manifest = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/main".into(),
                    old_hash: None,
                    new_hash: commit_id.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &pack, &manifest)
        }
    })
    .await
    .unwrap();
    match result {
        Err(ClientError::Server { status, body }) => {
            assert_eq!(status, 403);
            assert!(body.contains("metadata"), "error must explain mode: {body}");
        }
        other => panic!("expected 403, got {other:?}"),
    }
    task.abort();
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn release_mode_rejects_branch_push() {
    let setup = build_genesis();
    let (addr, task, root) = start("release", vec![setup.sk.public().to_levcs()]).await;
    let base = format!("http://{addr}/levcs/v1");

    let result = tokio::task::spawn_blocking({
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        move || {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            client.init(&sk, &repo_id, &auth_bytes).unwrap();
            let (pack, commit_id) = build_simple_pack(&sk, auth_id);
            let manifest = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/main".into(),
                    old_hash: None,
                    new_hash: commit_id.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &pack, &manifest)
        }
    })
    .await
    .unwrap();
    match result {
        Err(ClientError::Server { status, body }) => {
            assert_eq!(status, 403);
            assert!(
                body.contains("release-only") && body.contains("refs/branches/main"),
                "error must name mode and ref: {body}"
            );
        }
        other => panic!("expected 403, got {other:?}"),
    }
    task.abort();
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_mode_accepts_branch_push() {
    let setup = build_genesis();
    let (addr, task, root) = start("full", vec![setup.sk.public().to_levcs()]).await;
    let base = format!("http://{addr}/levcs/v1");

    let result = tokio::task::spawn_blocking({
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        move || {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            client.init(&sk, &repo_id, &auth_bytes).unwrap();
            let (pack, commit_id) = build_simple_pack(&sk, auth_id);
            let manifest = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/main".into(),
                    old_hash: None,
                    new_hash: commit_id.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &pack, &manifest)
        }
    })
    .await
    .unwrap();
    assert!(
        result.is_ok(),
        "full mode must accept branch push: {result:?}"
    );
    task.abort();
    let _ = std::fs::remove_dir_all(root);
}
