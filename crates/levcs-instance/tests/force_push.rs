//! Force-push enforcement (§5.4(e), §7.3.2).
//!
//! Spec rules:
//!   * A non-fast-forward push (new_hash is not a descendant of the
//!     ref's current value) must be rejected with a clear error.
//!   * `--force` permits the override, but only when the pusher holds
//!     maintainer or owner role.
//!
//! Our test pushes one commit, then tries to advance the ref to a
//! sibling commit (no shared ancestry beyond the existing ref's
//! current value). Without `force` that's a non-fast-forward and must
//! get a 409. With `force` and an owner-role key it's allowed.

use std::net::SocketAddr;
use std::path::PathBuf;

use levcs_client::{Client, ClientError};
use levcs_core::hash::blake3_hash;
use levcs_core::object::ObjectType;
use levcs_core::{
    Blob, Commit, CommitFlags, EntryType, FileMode, ObjectId, Tree, TreeEntry, ZERO_ID,
};
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

async fn start(creators: Vec<String>) -> (SocketAddr, tokio::task::JoinHandle<()>, PathBuf) {
    let root = tempdir("levcs-force-push");
    let cfg = InstanceConfig {
        root: root.clone(),
        storage_mode: "full".into(),
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
    auth_id: ObjectId,
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

/// Build a single root commit whose tree carries one blob with the
/// provided contents. Different `marker` strings give different
/// commit hashes — useful when we want two commits with no shared
/// ancestry beyond the genesis state.
fn build_commit(sk: &SecretKey, auth_id: ObjectId, marker: &str) -> (Pack, ObjectId) {
    let pk = sk.public();
    let blob = Blob::new(format!("hello-{marker}\n").into_bytes());
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
        timestamp_micros: 1_700_000_000_000_000,
        flags: CommitFlags::NONE,
        message: marker.into(),
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
async fn non_fast_forward_without_force_is_rejected() {
    let setup = build_genesis();
    let (addr, task, root) = start(vec![setup.sk.public().to_levcs()]).await;
    let base = format!("http://{addr}/levcs/v1");

    let result = tokio::task::spawn_blocking({
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        move || -> Result<(), ClientError> {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            client.init(&sk, &repo_id, &auth_bytes)?;

            // First push: commit "a", a clean fast-forward from nothing.
            let (pack_a, id_a) = build_commit(&sk, auth_id, "a");
            let manifest_a = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/main".into(),
                    old_hash: None,
                    new_hash: id_a.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &pack_a, &manifest_a)?;

            // Second push: commit "b", *also* a root commit with no
            // ancestry to "a". Try to overwrite main without --force.
            let (pack_b, id_b) = build_commit(&sk, auth_id, "b");
            let manifest_b = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/main".into(),
                    old_hash: Some(id_a.to_hex()),
                    new_hash: id_b.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &pack_b, &manifest_b)
        }
    })
    .await
    .unwrap();
    match result {
        Err(ClientError::Server { status, body }) => {
            assert_eq!(status, 409, "non-FF must be 409");
            assert!(
                body.contains("non-fast-forward") && body.contains("--force"),
                "error must explain: {body}"
            );
        }
        other => panic!("expected 409 server error, got {other:?}"),
    }
    task.abort();
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn non_fast_forward_with_force_and_owner_role_succeeds() {
    let setup = build_genesis();
    let (addr, task, root) = start(vec![setup.sk.public().to_levcs()]).await;
    let base = format!("http://{addr}/levcs/v1");

    let result = tokio::task::spawn_blocking({
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        move || -> Result<(), ClientError> {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            client.init(&sk, &repo_id, &auth_bytes)?;
            let (pack_a, id_a) = build_commit(&sk, auth_id, "a");
            let manifest_a = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/main".into(),
                    old_hash: None,
                    new_hash: id_a.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &pack_a, &manifest_a)?;

            // Same non-FF push, but with force=true. Alice is Owner so
            // the role check passes.
            let (pack_b, id_b) = build_commit(&sk, auth_id, "b");
            let manifest_b = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/main".into(),
                    old_hash: Some(id_a.to_hex()),
                    new_hash: id_b.to_hex(),
                }],
                timestamp: 0,
                force: true,
            };
            client.push(&sk, &repo_id, &pack_b, &manifest_b)
        }
    })
    .await
    .unwrap();
    assert!(result.is_ok(), "owner+force must succeed: {result:?}");
    task.abort();
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fast_forward_succeeds_without_force() {
    // Sanity check: a real fast-forward (parent-of-existing) must
    // still work without `force`. This guards against the new check
    // accidentally requiring force on every advance.
    let setup = build_genesis();
    let (addr, task, root) = start(vec![setup.sk.public().to_levcs()]).await;
    let base = format!("http://{addr}/levcs/v1");

    let result = tokio::task::spawn_blocking({
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        move || -> Result<(), ClientError> {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            client.init(&sk, &repo_id, &auth_bytes)?;
            let pk = sk.public();

            // First commit (root, no parents).
            let (pack_a, id_a) = build_commit(&sk, auth_id, "a");
            let manifest_a = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/main".into(),
                    old_hash: None,
                    new_hash: id_a.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &pack_a, &manifest_a)?;

            // Second commit explicitly parented on `a` — a true FF.
            let blob = Blob::new(b"hello-c\n".to_vec());
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
                parents: vec![id_a],
                authority: auth_id,
                author_key: pk.0,
                timestamp_micros: 1_700_000_001_000_000,
                flags: CommitFlags::NONE,
                message: "c".into(),
            };
            let signed = sign_commit(commit, &sk).unwrap();
            let commit_bytes = signed.serialize();
            let id_c = blake3_hash(&commit_bytes);
            let mut pack_c = Pack::new();
            pack_c.push(ObjectType::Blob as u8, blob_bytes);
            pack_c.push(ObjectType::Tree as u8, tree_bytes);
            pack_c.push(ObjectType::Commit as u8, commit_bytes);
            let manifest_c = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/main".into(),
                    old_hash: Some(id_a.to_hex()),
                    new_hash: id_c.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &pack_c, &manifest_c)
        }
    })
    .await
    .unwrap();
    assert!(result.is_ok(), "FF must succeed without force: {result:?}");
    task.abort();
    let _ = std::fs::remove_dir_all(root);
}
