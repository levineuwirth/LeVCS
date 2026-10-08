//! Instance merge-policy enforcement on push (§6.6.4).
//!
//! Each test boots an in-process instance, init's a repo via the client,
//! then pushes a hand-built commit. The interesting axis is whether that
//! commit's tree carries `.levcs/merge-record` and what handler names that
//! record references.

use std::net::SocketAddr;
use std::path::PathBuf;

use levcs_client::Client;
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
    allowed_handlers: Vec<String>,
    creators: Vec<String>,
) -> (SocketAddr, tokio::task::JoinHandle<()>, PathBuf) {
    let root = tempdir("levcs-policy");
    let cfg = InstanceConfig {
        root: root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers,
        mirrors: Vec::new(),
        creators,
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

/// Build a commit whose tree has `path` -> blob(content) and (optionally) a
/// `.levcs/merge-record` blob containing `merge_record_toml`. Returns the
/// pack containing all new objects and the new commit's id.
fn build_pack_with_optional_record(
    sk: &SecretKey,
    auth_id: levcs_core::ObjectId,
    path: &str,
    content: &[u8],
    merge_record_toml: Option<&str>,
    parent: Option<levcs_core::ObjectId>,
) -> (Pack, levcs_core::ObjectId) {
    let pk = sk.public();

    let blob = Blob::new(content.to_vec());
    let blob_bytes = blob.serialize();
    let blob_id = blake3_hash(&blob_bytes);

    let mut top = Tree::new();
    top.entries.push(TreeEntry {
        name: path.into(),
        entry_type: EntryType::Blob,
        mode: FileMode::REGULAR,
        hash: blob_id,
    });

    let mut pack = Pack::new();
    pack.push(ObjectType::Blob as u8, blob_bytes);

    if let Some(toml) = merge_record_toml {
        let mr_blob = Blob::new(toml.as_bytes().to_vec());
        let mr_blob_bytes = mr_blob.serialize();
        let mr_blob_id = blake3_hash(&mr_blob_bytes);

        let mut levcs_tree = Tree::new();
        levcs_tree.entries.push(TreeEntry {
            name: "merge-record".into(),
            entry_type: EntryType::Blob,
            mode: FileMode::REGULAR,
            hash: mr_blob_id,
        });
        levcs_tree.sort_and_validate().unwrap();
        let levcs_tree_bytes = levcs_tree.serialize();
        let levcs_tree_id = blake3_hash(&levcs_tree_bytes);

        top.entries.push(TreeEntry {
            name: ".levcs".into(),
            entry_type: EntryType::Tree,
            mode: FileMode::REGULAR,
            hash: levcs_tree_id,
        });

        pack.push(ObjectType::Blob as u8, mr_blob_bytes);
        pack.push(ObjectType::Tree as u8, levcs_tree_bytes);
    }

    top.sort_and_validate().unwrap();
    let tree_bytes = top.serialize();
    let tree_id = blake3_hash(&tree_bytes);
    pack.push(ObjectType::Tree as u8, tree_bytes);

    let commit = Commit {
        tree: tree_id,
        parents: parent.map(|p| vec![p]).unwrap_or_default(),
        authority: auth_id,
        author_key: pk.0,
        timestamp_micros: 1_700_000_001_000_000,
        flags: CommitFlags::NONE,
        message: "test commit".into(),
    };
    let commit_signed = sign_commit(commit, sk).unwrap();
    let commit_bytes = commit_signed.serialize();
    let commit_id = blake3_hash(&commit_bytes);
    pack.push(ObjectType::Commit as u8, commit_bytes);

    (pack, commit_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn builtin_only_policy_admits_clean_push() {
    let setup = build_genesis();
    let (addr, task, root) =
        start(vec!["builtin".into()], vec![setup.sk.public().to_levcs()]).await;
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
            let (pack, commit_id) =
                build_pack_with_optional_record(&sk, auth_id, "a.txt", b"hello\n", None, None);
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
    assert!(result.is_ok(), "clean push should succeed: {result:?}");

    task.abort();
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn builtin_only_policy_rejects_disallowed_plugin_handler() {
    let setup = build_genesis();
    let (addr, task, root) =
        start(vec!["builtin".into()], vec![setup.sk.public().to_levcs()]).await;
    let base = format!("http://{addr}/levcs/v1");

    let merge_record_toml = r#"schema_version = 1
base = "blake3:0000000000000000000000000000000000000000000000000000000000000000"
ours = "blake3:1111111111111111111111111111111111111111111111111111111111111111"
theirs = "blake3:2222222222222222222222222222222222222222222222222222222222222222"

[[file]]
path = "schema.proto"
handler = "tree-sitter:protobuf"
handler_hash = "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
status = "auto"
"#;

    let result = tokio::task::spawn_blocking({
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        let toml = merge_record_toml.to_string();
        move || {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            client.init(&sk, &repo_id, &auth_bytes).unwrap();
            let (pack, commit_id) = build_pack_with_optional_record(
                &sk,
                auth_id,
                "a.txt",
                b"hello\n",
                Some(&toml),
                None,
            );
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
        Err(levcs_client::ClientError::Server { status, body }) => {
            assert_eq!(status, 403, "expected 403, got {status} {body}");
            assert!(
                body.contains("tree-sitter:protobuf"),
                "error must name the rejected handler: {body}"
            );
        }
        other => panic!("expected 403 server error, got {other:?}"),
    }

    task.abort();
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_policy_admits_anything() {
    let setup = build_genesis();
    let (addr, task, root) = start(vec![], vec![setup.sk.public().to_levcs()]).await;
    let base = format!("http://{addr}/levcs/v1");

    let merge_record_toml = r#"schema_version = 1
base = "blake3:0000000000000000000000000000000000000000000000000000000000000000"
ours = "blake3:1111111111111111111111111111111111111111111111111111111111111111"
theirs = "blake3:2222222222222222222222222222222222222222222222222222222222222222"

[[file]]
path = "schema.proto"
handler = "tree-sitter:protobuf"
handler_hash = "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
status = "auto"
"#;

    let result = tokio::task::spawn_blocking({
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        let toml = merge_record_toml.to_string();
        move || {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            client.init(&sk, &repo_id, &auth_bytes).unwrap();
            let (pack, commit_id) = build_pack_with_optional_record(
                &sk,
                auth_id,
                "a.txt",
                b"hello\n",
                Some(&toml),
                None,
            );
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
        "permissive policy must accept any handler: {result:?}"
    );

    task.abort();
    let _ = std::fs::remove_dir_all(root);
}
