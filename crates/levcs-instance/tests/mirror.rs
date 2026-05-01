//! Inter-instance mirroring (§5.6) and repository movement (§5.7).
//!
//! These tests boot two in-process instances and exercise the data
//! plane between them: a source instance receives a push, then a
//! mirror instance configured against that source pulls the same
//! state via `sync_mirror` and ends up serving identical /refs.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use levcs_client::Client;
use levcs_core::hash::blake3_hash;
use levcs_core::object::ObjectType;
use levcs_core::{Blob, Commit, CommitFlags, EntryType, FileMode, Tree, TreeEntry, ZERO_ID};
use levcs_identity::authority::{AuthorityBody, MemberEntry, PolicyEntry, Role};
use levcs_identity::keys::SecretKey;
use levcs_identity::sign::{sign_authority, sign_commit};
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

fn build_simple_commit_pack(
    sk: &SecretKey,
    auth_id: levcs_core::ObjectId,
    file: &str,
    content: &[u8],
    parent: Option<levcs_core::ObjectId>,
) -> (Pack, levcs_core::ObjectId) {
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
        timestamp_micros: 1_700_000_001_000_000,
        flags: CommitFlags::NONE,
        message: "test commit".into(),
    };
    let commit_signed = sign_commit(commit, sk).unwrap();
    let commit_bytes = commit_signed.serialize();
    let commit_id = blake3_hash(&commit_bytes);

    let mut pack = Pack::new();
    pack.push(ObjectType::Blob as u8, blob_bytes);
    pack.push(ObjectType::Tree as u8, tree_bytes);
    pack.push(ObjectType::Commit as u8, commit_bytes);
    (pack, commit_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mirror_pulls_state_from_source() {
    // Source: authoritative for the repo. Mirror: configured to pull from
    // source. After source receives a push, sync_mirror on the mirror
    // must replicate refs and content, and the mirror's /info must
    // advertise itself as a mirror of the source.
    let source_root = tempdir("mirror-src");
    let mirror_root = tempdir("mirror-dst");

    let source_cfg = InstanceConfig {
        root: source_root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: Vec::new(),
    };
    let (source_addr, source_task) = start(source_cfg).await;
    let source_base = format!("http://{source_addr}/levcs/v1");

    let setup = build_genesis();

    // Push a commit to source from a client.
    let result = tokio::task::spawn_blocking({
        let base = source_base.clone();
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        move || {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            client.init(&sk, &repo_id, &auth_bytes).unwrap();
            let (pack, commit_id) =
                build_simple_commit_pack(&sk, auth_id, "hello.txt", b"hello\n", None);
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
            client.push(&sk, &repo_id, &pack, &manifest)?;
            Ok::<_, levcs_client::ClientError>(commit_id)
        }
    })
    .await
    .unwrap();
    let source_commit = result.expect("push to source must succeed");

    // Configure the mirror instance pointing at source.
    let mirror_cfg = InstanceConfig {
        root: mirror_root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: vec![MirrorConfig {
            repo_id: setup.repo_id.clone(),
            source: source_base.clone(),
            mode: "full".into(),
            poll_interval: "60s".into(),
            writeback: false,
        }],
    };
    let mirror_cfg_arc = Arc::new(mirror_cfg.clone());
    let (mirror_addr, mirror_task) = start(mirror_cfg).await;
    let mirror_base = format!("http://{mirror_addr}/levcs/v1");

    // Run sync_mirror once on the mirror's behalf.
    let report = tokio::task::spawn_blocking({
        let cfg = mirror_cfg_arc.clone();
        let m = cfg.mirrors[0].clone();
        move || sync_mirror(&cfg, &m)
    })
    .await
    .unwrap()
    .expect("sync should succeed");
    assert!(
        report.objects_received >= 4,
        "expected pack with at least authority + commit + tree + blob; got {}",
        report.objects_received
    );
    assert_eq!(report.branches_updated, 1);

    // Mirror's /refs must now match source.
    let (mirror_refs, mirror_info) = tokio::task::spawn_blocking({
        let mb = mirror_base.clone();
        let rid = setup.repo_id.clone();
        move || {
            let c = Client::new(mb);
            let r = c.refs(&rid).unwrap();
            let i = c.repo_info(&rid).unwrap();
            (r, i)
        }
    })
    .await
    .unwrap();
    assert_eq!(
        mirror_refs.branches.get("main"),
        Some(&source_commit.to_hex()),
        "mirror's main must match source"
    );
    assert!(mirror_info.is_mirror, "/info must declare mirror status");
    assert_eq!(
        mirror_info.mirror_source.as_deref(),
        Some(source_base.as_str())
    );
    assert_eq!(mirror_info.mirror_mode.as_deref(), Some("full"));

    // Push to mirror must be refused (read-only by config).
    let push_err = tokio::task::spawn_blocking({
        let mb = mirror_base.clone();
        let seed = *setup.sk.seed();
        let auth_id = setup.auth_id;
        let repo_id = setup.repo_id.clone();
        move || {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(mb);
            let (pack, commit_id) = build_simple_commit_pack(&sk, auth_id, "x.txt", b"x\n", None);
            let manifest = PushManifest {
                authority_hash: auth_id.to_hex(),
                updates: vec![PushUpdate {
                    r#ref: "refs/branches/scratch".into(),
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
    match push_err {
        Err(levcs_client::ClientError::Server { status: 403, body }) => {
            assert!(
                body.contains("mirror") && body.contains(&source_base),
                "403 body should explain and point at the source: {body}"
            );
        }
        other => panic!("expected 403 push refusal, got {other:?}"),
    }

    // Idempotence: a second sync with no source change is a no-op.
    let report2 = tokio::task::spawn_blocking({
        let cfg = mirror_cfg_arc.clone();
        let m = cfg.mirrors[0].clone();
        move || sync_mirror(&cfg, &m)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        report2.branches_updated, 0,
        "second sync should not advance any ref"
    );

    source_task.abort();
    mirror_task.abort();
    let _ = std::fs::remove_dir_all(source_root);
    let _ = std::fs::remove_dir_all(mirror_root);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn migrate_replays_repo_to_fresh_instance() {
    // Spin up two authoritative instances. Init+push to the first, then
    // run the same init+push sequence against the second — the unit
    // under test is the wire path the `levcs migrate` orchestration
    // exercises end-to-end. The new instance must end up serving
    // identical refs under the same repo_id.
    let src_root = tempdir("migrate-src");
    let dst_root = tempdir("migrate-dst");

    let src_cfg = InstanceConfig {
        root: src_root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: Vec::new(),
    };
    let dst_cfg = InstanceConfig {
        root: dst_root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: Vec::new(),
    };
    let (src_addr, src_task) = start(src_cfg).await;
    let (dst_addr, dst_task) = start(dst_cfg).await;
    let src_base = format!("http://{src_addr}/levcs/v1");
    let dst_base = format!("http://{dst_addr}/levcs/v1");

    let setup = build_genesis();
    let repo_id = setup.repo_id.clone();
    let auth_id = setup.auth_id;

    // Push to source first.
    let source_commit = tokio::task::spawn_blocking({
        let base = src_base.clone();
        let seed = *setup.sk.seed();
        let repo_id = repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        move || {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            client.init(&sk, &repo_id, &auth_bytes).unwrap();
            let (pack, commit_id) = build_simple_commit_pack(&sk, auth_id, "f.txt", b"v1\n", None);
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
            client.push(&sk, &repo_id, &pack, &manifest).unwrap();
            commit_id
        }
    })
    .await
    .unwrap();

    // Migrate path: same identity, init on destination, push everything.
    let migrated_commit = tokio::task::spawn_blocking({
        let base = dst_base.clone();
        let seed = *setup.sk.seed();
        let repo_id = repo_id.clone();
        let auth_bytes = setup.auth_bytes.clone();
        move || {
            let sk = SecretKey::from_seed(seed);
            let client = Client::new(base);
            // §5.7 step 1: init with the authority object.
            client.init(&sk, &repo_id, &auth_bytes).unwrap();
            // §5.7 step 3: push history.
            let (pack, commit_id) = build_simple_commit_pack(&sk, auth_id, "f.txt", b"v1\n", None);
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
            client.push(&sk, &repo_id, &pack, &manifest).unwrap();
            commit_id
        }
    })
    .await
    .unwrap();

    // The repo_id must be identical on both sides — that is the property
    // §5.7 promises ("identifiably the same project at the new location").
    // And the same content yields the same commit hash deterministically.
    assert_eq!(source_commit, migrated_commit);

    // Both instances must now report the same /refs and the same /info
    // (modulo mirror metadata, which neither has set).
    let (src_refs, dst_refs, src_info, dst_info) = tokio::task::spawn_blocking({
        let s = src_base.clone();
        let d = dst_base.clone();
        let r = repo_id.clone();
        move || {
            let cs = Client::new(s);
            let cd = Client::new(d);
            (
                cs.refs(&r).unwrap(),
                cd.refs(&r).unwrap(),
                cs.repo_info(&r).unwrap(),
                cd.repo_info(&r).unwrap(),
            )
        }
    })
    .await
    .unwrap();
    assert_eq!(src_refs.branches, dst_refs.branches);
    assert_eq!(src_info.repo_id, dst_info.repo_id);
    assert_eq!(src_info.genesis_authority, dst_info.genesis_authority);
    assert_eq!(src_info.current_authority, dst_info.current_authority);
    assert!(!src_info.is_mirror && !dst_info.is_mirror);

    src_task.abort();
    dst_task.abort();
    let _ = std::fs::remove_dir_all(src_root);
    let _ = std::fs::remove_dir_all(dst_root);
}
