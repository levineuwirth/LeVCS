//! End-to-end "dogfood" scenario.
//!
//! A single test that exercises a realistic federation topology in one
//! motion. Stands up:
//!
//!   * Instance A — authoritative source-of-truth.
//!   * Instance B — a fresh peer the user wants to migrate the repo to.
//!   * Instance C — a read-only mirror of A.
//!
//! Then drives a multi-step session that the unit tests cover only in
//! pieces:
//!   1. Init repo on A.
//!   2. Push a chain of three commits on `main`.
//!   3. Publish a `v1.0.0` release tagging commit-2.
//!   4. Pull all reachable objects from A on a fresh client (clone).
//!   5. Sync mirror C from A; verify branches AND releases replicate.
//!   6. Mirror is read-only by configuration: pushes return 403.
//!   7. Migrate to B: re-init with the same authority and replay the
//!      pack. B and A end up with identical refs.
//!   8. Spot-check object identity: fetch the head commit object from
//!      A, B, and C; the bytes must be byte-for-byte equal everywhere.
//!
//! The test is deliberately one big function — that's the dogfood
//! claim. If any step regresses, this is the test that flags it before
//! anyone runs the CLI for real.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use levcs_client::Client;
use levcs_core::hash::blake3_hash;
use levcs_core::object::ObjectType;
use levcs_core::{
    Blob, Commit, CommitFlags, EntryType, FileMode, ObjectId, Release, Tree, TreeEntry, ZERO_ID,
};
use levcs_identity::authority::{AuthorityBody, MemberEntry, PolicyEntry, Role};
use levcs_identity::keys::SecretKey;
use levcs_identity::sign::{sign_authority, sign_commit, sign_release};
use levcs_instance::mirror::sync_mirror;
use levcs_instance::{router, AppState, InstanceConfig, MirrorConfig};
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

async fn start(cfg: InstanceConfig) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let state = AppState::new(cfg);
    let app = router(state);
    let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, task)
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

/// Build a single-file commit. Each successive call uses different
/// content so the commit hashes diverge.
fn build_commit(
    sk: &SecretKey,
    auth_id: ObjectId,
    file: &str,
    content: &[u8],
    parent: Option<ObjectId>,
    timestamp: i64,
) -> (Pack, ObjectId, ObjectId) {
    let pk = sk.public();
    let blob = Blob::new(content.to_vec());
    let blob_bytes = blob.serialize();
    let blob_id = blake3_hash(&blob_bytes);
    let mut top = Tree::new();
    top.entries.push(TreeEntry {
        name: file.into(),
        entry_type: EntryType::Blob,
        mode: FileMode::REGULAR,
        hash: blob_id,
    });
    top.sort_and_validate().unwrap();
    let tree_bytes = top.serialize();
    let tree_id = blake3_hash(&tree_bytes);
    let commit = Commit {
        tree: tree_id,
        parents: parent.map(|p| vec![p]).unwrap_or_default(),
        authority: auth_id,
        author_key: pk.0,
        timestamp_micros: timestamp,
        flags: CommitFlags::NONE,
        message: format!("commit for {file}"),
    };
    let signed = sign_commit(commit, sk).unwrap();
    let commit_bytes = signed.serialize();
    let commit_id = blake3_hash(&commit_bytes);
    let mut pack = Pack::new();
    pack.push(ObjectType::Blob as u8, blob_bytes);
    pack.push(ObjectType::Tree as u8, tree_bytes);
    pack.push(ObjectType::Commit as u8, commit_bytes);
    (pack, commit_id, tree_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn dogfood_three_instance_scenario() {
    let setup = build_genesis();
    // ---- 1. Stand up A, B, and C. ----
    let a_root = tempdir("dogfood-a");
    let b_root = tempdir("dogfood-b");
    let c_root = tempdir("dogfood-c");

    let a_cfg = InstanceConfig {
        root: a_root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: Vec::new(),
        creators: vec![setup.sk.public().to_levcs()],
        limits: Default::default(),
    };
    let b_cfg = InstanceConfig {
        root: b_root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: Vec::new(),
        creators: vec![setup.sk.public().to_levcs()],
        limits: Default::default(),
    };
    let (a_addr, a_task) = start(a_cfg).await;
    let (b_addr, b_task) = start(b_cfg).await;
    let a_base = format!("http://{a_addr}/levcs/v1");
    let b_base = format!("http://{b_addr}/levcs/v1");

    // ---- 2. Init + 3-commit chain on A. ----
    let (commit_ids, release_id) = tokio::task::spawn_blocking({
        let base = a_base.clone();
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        move || -> Result<(Vec<ObjectId>, ObjectId), levcs_client::ClientError> {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            client.init(&sk, &repo_id, &auth_bytes)?;

            let mut prev: Option<ObjectId> = None;
            let mut ids = Vec::new();
            let mut tree2: Option<ObjectId> = None;
            for (i, (file, content)) in [
                ("a.txt", b"first\n".as_slice()),
                ("a.txt", b"second\n".as_slice()),
                ("a.txt", b"third\n".as_slice()),
            ]
            .iter()
            .enumerate()
            {
                let ts = 1_700_000_000_000_000 + (i as i64) * 1_000_000;
                let (pack, cid, tid) = build_commit(&sk, auth_id, file, content, prev, ts);
                let manifest = PushManifest {
                    authority_hash: auth_id.to_hex(),
                    updates: vec![PushUpdate {
                        r#ref: "refs/branches/main".into(),
                        old_hash: prev.map(|p| p.to_hex()),
                        new_hash: cid.to_hex(),
                    }],
                    timestamp: 0,
                    force: false,
                };
                client.push(&sk, &repo_id, &pack, &manifest)?;
                if i == 1 {
                    tree2 = Some(tid);
                }
                prev = Some(cid);
                ids.push(cid);
            }

            // ---- 3. Publish a release tagging commit #2. ----
            let release = Release {
                tree: tree2.unwrap(),
                parent_release: ZERO_ID,
                predecessor: ids[1],
                authority: auth_id,
                declarer_key: sk.public().0,
                timestamp_micros: 1_700_000_010_000_000,
                label: "v1.0.0".into(),
                notes: "first dogfood release".into(),
            };
            let signed_release = sign_release(release, &sk).unwrap();
            let release_bytes = signed_release.serialize();
            let release_id = blake3_hash(&release_bytes);
            let mut release_pack = Pack::new();
            release_pack.push(ObjectType::Release as u8, release_bytes);
            let release_manifest = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/releases/v1.0.0".into(),
                    old_hash: None,
                    new_hash: release_id.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &release_pack, &release_manifest)?;

            Ok((ids, release_id))
        }
    })
    .await
    .unwrap()
    .expect("init+pushes on A must succeed");
    let head = commit_ids[2];

    // Sanity: A reports the right head and release.
    let a_refs = tokio::task::spawn_blocking({
        let base = a_base.clone();
        let rid = setup.repo_id.clone();
        move || Client::new(base).refs(&rid).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(a_refs.branches.get("main"), Some(&head.to_hex()));
    assert_eq!(a_refs.releases.get("v1.0.0"), Some(&release_id.to_hex()));

    // ---- 4. Clone A's full state to a fresh local pack via get_pack. ----
    // Empty `have`, `want` = head. The instance must walk from head to
    // include all reachable objects (commits + trees + blobs + authority).
    // This is what the CLI's `clone` invokes.
    let cloned = tokio::task::spawn_blocking({
        let base = a_base.clone();
        let rid = setup.repo_id.clone();
        let want = head;
        move || Client::new(base).get_pack(&rid, &[], &[want]).unwrap()
    })
    .await
    .unwrap();
    // Authority + 3 blobs + 3 trees + 3 commits = 10 objects minimum.
    assert!(
        cloned.entries.len() >= 10,
        "clone pack should carry full history: got {}",
        cloned.entries.len()
    );

    // ---- 5. Stand up C as a mirror of A; sync. ----
    let c_cfg = InstanceConfig {
        root: c_root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: vec![MirrorConfig {
            repo_id: setup.repo_id.clone(),
            source: a_base.clone(),
            mode: "full".into(),
            poll_interval: "60s".into(),
            writeback: false,
        }],
        creators: Vec::new(),
        limits: Default::default(),
    };
    let c_cfg_arc = Arc::new(c_cfg.clone());
    let (c_addr, c_task) = start(c_cfg).await;
    let c_base = format!("http://{c_addr}/levcs/v1");

    let report = tokio::task::spawn_blocking({
        let cfg = c_cfg_arc.clone();
        let m = cfg.mirrors[0].clone();
        move || sync_mirror(&cfg, &m).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(report.branches_updated, 1, "main must replicate");
    assert!(report.releases_updated >= 1, "release must replicate");

    // C now matches A.
    let (c_refs, c_info) = tokio::task::spawn_blocking({
        let base = c_base.clone();
        let rid = setup.repo_id.clone();
        move || {
            let c = Client::new(base);
            (c.refs(&rid).unwrap(), c.repo_info(&rid).unwrap())
        }
    })
    .await
    .unwrap();
    assert_eq!(c_refs.branches.get("main"), Some(&head.to_hex()));
    assert_eq!(c_refs.releases.get("v1.0.0"), Some(&release_id.to_hex()));
    assert!(c_info.is_mirror);
    assert_eq!(c_info.mirror_source.as_deref(), Some(a_base.as_str()));

    // ---- 6. Mirror is read-only: push to C must 403. ----
    let push_to_mirror = tokio::task::spawn_blocking({
        let base = c_base.clone();
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let prev = head;
        move || {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            let (pack, cid, _) = build_commit(
                &sk,
                auth_id,
                "a.txt",
                b"fourth\n",
                Some(prev),
                1_700_000_020_000_000,
            );
            let manifest = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/main".into(),
                    old_hash: Some(prev.to_hex()),
                    new_hash: cid.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &pack, &manifest)
        }
    })
    .await
    .unwrap();
    match push_to_mirror {
        Err(levcs_client::ClientError::Server { status: 403, body }) => {
            assert!(body.contains("mirror"));
        }
        other => panic!("expected 403 from mirror, got {other:?}"),
    }

    // ---- 7. Migrate the repo to B by replaying init + history + release. ----
    // This is what `levcs migrate` does end-to-end: re-init under the
    // same authority, re-push the cloned commit pack, and re-push the
    // release as its own pack (releases aren't reachable from commits,
    // so the clone walk doesn't carry them).
    let release_bytes = tokio::task::spawn_blocking({
        let base = a_base.clone();
        let rid = setup.repo_id.clone();
        move || Client::new(base).get_object(&rid, release_id).unwrap()
    })
    .await
    .unwrap();

    tokio::task::spawn_blocking({
        let base = b_base.clone();
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        let pack = cloned.clone();
        let release_bytes = release_bytes.clone();
        move || -> Result<(), levcs_client::ClientError> {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            client.init(&sk, &repo_id, &auth_bytes)?;

            // Push commit history.
            let manifest_main = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/main".into(),
                    old_hash: None,
                    new_hash: head.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &pack, &manifest_main)?;

            // Push the release object on its own.
            let mut rpack = Pack::new();
            rpack.push(ObjectType::Release as u8, release_bytes);
            let manifest_release = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/releases/v1.0.0".into(),
                    old_hash: None,
                    new_hash: release_id.to_hex(),
                }],
                timestamp: 0,
                force: false,
            };
            client.push(&sk, &repo_id, &rpack, &manifest_release)?;
            Ok(())
        }
    })
    .await
    .unwrap()
    .expect("migrate to B must succeed");

    let b_refs = tokio::task::spawn_blocking({
        let base = b_base.clone();
        let rid = setup.repo_id.clone();
        move || Client::new(base).refs(&rid).unwrap()
    })
    .await
    .unwrap();
    assert_eq!(b_refs.branches.get("main"), Some(&head.to_hex()));
    assert_eq!(b_refs.releases.get("v1.0.0"), Some(&release_id.to_hex()));

    // ---- 8. Spot-check object identity across all three instances. ----
    // The commit object's serialized bytes are content-addressed, so
    // identical commit_id on all three instances is necessary; identical
    // *bytes* is the stronger property we want to verify.
    let (a_obj, b_obj, c_obj) = tokio::task::spawn_blocking({
        let a = a_base.clone();
        let b = b_base.clone();
        let c = c_base.clone();
        let rid = setup.repo_id.clone();
        let head = head;
        move || {
            (
                Client::new(a).get_object(&rid, head).unwrap(),
                Client::new(b).get_object(&rid, head).unwrap(),
                Client::new(c).get_object(&rid, head).unwrap(),
            )
        }
    })
    .await
    .unwrap();
    assert_eq!(
        a_obj, b_obj,
        "A and B must serve byte-identical head commits"
    );
    assert_eq!(
        a_obj, c_obj,
        "A and C must serve byte-identical head commits"
    );
    assert_eq!(
        blake3_hash(&a_obj),
        head,
        "object hash must match the requested id"
    );

    a_task.abort();
    b_task.abort();
    c_task.abort();
    let _ = std::fs::remove_dir_all(a_root);
    let _ = std::fs::remove_dir_all(b_root);
    let _ = std::fs::remove_dir_all(c_root);
}
