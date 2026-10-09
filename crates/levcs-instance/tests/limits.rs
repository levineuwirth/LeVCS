//! What an instance takes on at once, and how much one request may make it
//! read, hold or decode. None of it was bounded: a push's pack could decode
//! to many times the memory there is, a pack served walked history by
//! recursion, and requests, pushes, signed nonces and bodies piled up
//! without limit.

#![cfg(unix)]

use std::net::SocketAddr;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use levcs_client::{Client, ClientError};
use levcs_core::hash::blake3_hash;
use levcs_core::object::ObjectType;
use levcs_core::{
    Blob, Commit, CommitFlags, EntryType, FileMode, ObjectId, Tree, TreeEntry, ZERO_ID,
};
use levcs_identity::authority::{AuthorityBody, MemberEntry, PolicyEntry, Role};
use levcs_identity::keys::SecretKey;
use levcs_identity::sign::{sign_authority, sign_commit};
use levcs_instance::{router, AppState, InstanceConfig, Limits, RepoId};
use levcs_protocol::auth::{sign_request, AuthRequest};
use levcs_protocol::wire::{PushManifest, PushUpdate};
use levcs_protocol::Pack;

const OWNER: [u8; 32] = [1; 32];
const STRANGER: [u8; 32] = [3; 32];

fn key(seed: [u8; 32]) -> SecretKey {
    SecretKey::from_seed(seed)
}

fn tempdir(prefix: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Serve an instance with `limits` whose root is a fresh directory, and run
/// `f` against its base URL (`http://<addr>`), root and state.
async fn run(limits: Limits, f: impl FnOnce(String, PathBuf, AppState) + Send + 'static) {
    let root = tempdir("levcs-limits");
    let config = InstanceConfig {
        root: root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: Vec::new(),
        creators: vec![key(OWNER).public().to_levcs()],
        limits,
    };
    let state = AppState::new(config);
    let app = router(state.clone());
    let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    let r = root.clone();
    let res = tokio::task::spawn_blocking(move || f(format!("http://{addr}"), r, state)).await;
    task.abort();
    let _ = std::fs::remove_dir_all(root);
    res.unwrap();
}

fn api(base: &str) -> String {
    format!("{base}/levcs/v1")
}

fn public(value: u8) -> Vec<PolicyEntry> {
    vec![PolicyEntry {
        key: "public_read".into(),
        value: vec![value],
    }]
}

/// A genesis owned by OWNER, with `policy`.
fn genesis(policy: Vec<PolicyEntry>, salt: i64) -> (ObjectId, AuthorityBody, Vec<u8>) {
    let owner = key(OWNER);
    let mut body = AuthorityBody {
        schema_version: 1,
        repo_id: ZERO_ID,
        previous_authority: ZERO_ID,
        version: 1,
        created_micros: 1_700_000_000_000_000 + salt,
        members: vec![MemberEntry {
            key: owner.public(),
            handle: "owner".into(),
            role: Role::Owner,
            added_micros: 1,
            added_by: owner.public(),
        }],
        policy,
    };
    body.normalize().unwrap();
    body.assign_genesis_repo_id().unwrap();
    let bytes = sign_authority(&body, &owner).unwrap().serialize();
    (blake3_hash(&bytes), body, bytes)
}

/// A commit on `parents` whose tree holds `blobs`, citing `authority`, and
/// the pack carrying the commit, its tree and the blobs.
fn commit(
    authority: ObjectId,
    parents: &[ObjectId],
    blobs: &[Vec<u8>],
    t: i64,
) -> (ObjectId, Pack) {
    let mut pack = Pack::new();
    let mut entries = Vec::new();
    for (i, b) in blobs.iter().enumerate() {
        let blob = Blob::new(b.clone()).serialize();
        entries.push(TreeEntry {
            name: format!("f{i}"),
            entry_type: EntryType::Blob,
            mode: FileMode::REGULAR,
            hash: blake3_hash(&blob),
        });
        pack.push(ObjectType::Blob as u8, blob);
    }
    let mut tree = Tree { entries };
    tree.sort_and_validate().unwrap();
    let tree = tree.serialize();
    let tree_id = blake3_hash(&tree);
    pack.push(ObjectType::Tree as u8, tree);
    let c = Commit {
        tree: tree_id,
        parents: parents.to_vec(),
        authority,
        author_key: key(OWNER).public().0,
        timestamp_micros: 1_700_000_000_000_000 + t,
        flags: CommitFlags::NONE,
        message: format!("c{t}"),
    };
    let c = sign_commit(c, &key(OWNER)).unwrap().serialize();
    let id = blake3_hash(&c);
    pack.push(ObjectType::Commit as u8, c);
    (id, pack)
}

fn status<T>(r: Result<T, ClientError>) -> Result<T, (u16, String)> {
    r.map_err(|e| match e {
        ClientError::Server { status, body } => (status, body),
        e => panic!("{e}"),
    })
}

fn manifest(authority: ObjectId, updates: Vec<(String, ObjectId)>) -> PushManifest {
    PushManifest {
        authority_hash: authority.to_hex(),
        updates: updates
            .into_iter()
            .map(|(r, id)| PushUpdate {
                r#ref: r,
                old_hash: None,
                new_hash: id.to_hex(),
            })
            .collect(),
        timestamp: 0,
        force: false,
    }
}

/// Push `c` to main, which is expected to hold `old`.
fn push(
    base: &str,
    repo: &str,
    authority: ObjectId,
    old: Option<ObjectId>,
    (id, pack): &(ObjectId, Pack),
) -> Result<(), (u16, String)> {
    let mut m = manifest(authority, vec![("refs/branches/main".into(), *id)]);
    m.updates[0].old_hash = old.map(|o| o.to_hex());
    status(Client::new(api(base)).push(&key(OWNER), repo, pack, &m))
}

/// `n` bytes that do not compress.
fn noise(n: usize) -> Vec<u8> {
    (0..n.div_ceil(32))
        .flat_map(|i| blake3_hash(&(i as u64).to_le_bytes()).0)
        .take(n)
        .collect()
}

/// A repository created by OWNER, with one commit on main.
struct Hosted {
    id: String,
    genesis: ObjectId,
    commit: ObjectId,
    dir: PathBuf,
}

fn host(base: &str, root: &Path, policy: Vec<PolicyEntry>, salt: i64) -> Hosted {
    let g = genesis(policy, salt);
    let id = g.1.repo_id.to_hex();
    Client::new(api(base)).init(&key(OWNER), &id, &g.2).unwrap();
    let c = commit(g.0, &[], &[b"hosted".to_vec()], salt);
    push(base, &id, g.0, None, &c).unwrap();
    Hosted {
        dir: root.join(&id),
        id,
        genesis: g.0,
        commit: c.0,
    }
}

fn stored(h: &Hosted, id: ObjectId) -> bool {
    let x = id.to_hex();
    h.dir
        .join(".levcs/objects")
        .join(&x[..2])
        .join(&x[2..])
        .exists()
}

/// Write `bytes` into `h`'s store under their id, as admission would.
fn put(h: &Hosted, bytes: &[u8]) -> ObjectId {
    let id = blake3_hash(bytes);
    let x = id.to_hex();
    let dir = h.dir.join(".levcs/objects").join(&x[..2]);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(&x[2..]), bytes).unwrap();
    id
}

fn set_main(h: &Hosted, id: ObjectId) {
    std::fs::write(h.dir.join(".levcs/refs/branches/main"), format!("{id}\n")).unwrap();
}

fn get(base: &str, path: &str) -> (u16, String) {
    let res = reqwest::blocking::get(format!("{}{path}", api(base))).unwrap();
    (res.status().as_u16(), res.text().unwrap())
}

fn pack_of(
    base: &str,
    repo: &str,
    have: &[ObjectId],
    want: &[ObjectId],
) -> Result<Pack, (u16, String)> {
    status(Client::new(api(base)).get_pack(repo, have, want))
}

const PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether `t` is still running a while after it was started.
fn still_waiting<T>(t: &std::thread::JoinHandle<T>) -> bool {
    std::thread::sleep(std::time::Duration::from_millis(300));
    !t.is_finished()
}

/// What `t` returned; a failure, not a hang, if it does not finish in time.
fn finished<T>(t: std::thread::JoinHandle<T>) -> T {
    let deadline = std::time::Instant::now() + PATIENCE;
    while !t.is_finished() {
        assert!(std::time::Instant::now() < deadline, "never answered");
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    t.join().unwrap()
}

fn lock_of(state: &AppState, h: &Hosted) -> Arc<tokio::sync::RwLock<()>> {
    state.repo_lock(&RepoId::parse(&h.id).unwrap())
}

// Pushes.

/// A push's body is received only up to its limit, and an init's up to the
/// size of a genesis.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_over_its_limit_is_refused() {
    let limits = Limits {
        max_push_bytes: 64 << 10,
        ..Limits::default()
    };
    run(limits, |base, root, _| {
        let h = host(&base, &root, public(1), 0);
        // Random bytes, which do not compress below the limit.
        let c = commit(h.genesis, &[h.commit], &[noise(100_000)], 1);
        let (code, body) = push(&base, &h.id, h.genesis, Some(h.commit), &c).unwrap_err();
        assert_eq!(code, 413, "{body}");
        assert!(!stored(&h, c.0));

        let (_, _, g) = genesis(public(1), 1);
        let mut big = g.clone();
        big.resize(100 << 10, 0);
        let id = genesis(public(1), 1).1.repo_id.to_hex();
        let r = status(Client::new(api(&base)).init(&key(OWNER), &id, &big));
        assert_eq!(r.unwrap_err().0, 413);
        assert!(!root.join(&id).exists());
    })
    .await;
}

/// A pack is decoded only within its budgets: its objects together, their
/// number, and each one. A few kilobytes of zstd decoded to whatever size
/// the pack declared, up to 256 MiB an entry, with no total.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_is_decoded_only_within_its_budgets() {
    let limits = Limits {
        max_pack_bytes: 1 << 20,
        max_pack_objects: 8,
        max_object_bytes: 600 << 10,
        ..Limits::default()
    };
    run(limits, |base, root, _| {
        let h = host(&base, &root, public(1), 0);
        let zeros = |n: usize, mark: u8| {
            let mut b = vec![0u8; n];
            b[0] = mark;
            b
        };
        // Three blobs of 500 KiB: each under its limit, together over.
        let c = commit(
            h.genesis,
            &[h.commit],
            &[
                zeros(500 << 10, 1),
                zeros(500 << 10, 2),
                zeros(500 << 10, 3),
            ],
            1,
        );
        assert!(c.1.encode().len() < 16 << 10, "the pack is small");
        let (code, body) = push(&base, &h.id, h.genesis, Some(h.commit), &c).unwrap_err();
        assert_eq!(code, 413, "{body}");
        assert!(body.contains("pack too large"), "{body}");
        assert!(!stored(&h, c.0));

        // Nine objects.
        let many: Vec<Vec<u8>> = (0..7).map(|i| vec![i as u8; 10]).collect();
        let c = commit(h.genesis, &[h.commit], &many, 2);
        let (code, body) = push(&base, &h.id, h.genesis, Some(h.commit), &c).unwrap_err();
        assert_eq!(code, 413, "{body}");
        assert!(body.contains("entries exceeds limit"), "{body}");

        // One object over its own limit.
        let c = commit(h.genesis, &[h.commit], &[zeros(700 << 10, 4)], 3);
        let (code, body) = push(&base, &h.id, h.genesis, Some(h.commit), &c).unwrap_err();
        assert_eq!(code, 413, "{body}");
        assert!(body.contains("exceeds limit"), "{body}");

        // Within all three, it lands.
        let c = commit(h.genesis, &[h.commit], &[zeros(500 << 10, 5)], 4);
        push(&base, &h.id, h.genesis, Some(h.commit), &c).unwrap();
        assert!(stored(&h, c.0));
    })
    .await;
}

/// One push names at most `max_ref_updates` refs, 1024 unless configured,
/// and the instance says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_naming_too_many_refs_is_refused() {
    assert_eq!(Limits::default().max_ref_updates, 1024);
    let limits = Limits {
        max_ref_updates: 2,
        ..Limits::default()
    };
    run(limits, |base, root, _| {
        let said = Client::new(api(&base)).instance_info().unwrap().limits;
        assert_eq!(said.unwrap().max_ref_updates, Some(2));
        let h = host(&base, &root, public(1), 0);
        let c = commit(h.genesis, &[h.commit], &[b"x".to_vec()], 1);
        let updates = (0..3)
            .map(|i| (format!("refs/branches/b{i}"), c.0))
            .collect();
        let m = manifest(h.genesis, updates);
        let r = status(Client::new(api(&base)).push(&key(OWNER), &h.id, &c.1, &m));
        let (code, body) = r.unwrap_err();
        assert_eq!(code, 413, "{body}");
        assert!(!stored(&h, c.0));
    })
    .await;
}

// Packs sent.

/// A long history is walked without recursion: the walk took one stack
/// frame per object, and a history this long overflowed the stack.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_history_is_sent_without_recursion() {
    run(Limits::default(), |base, root, _| {
        let h = host(&base, &root, public(1), 0);
        let (tip, tree) = {
            let tree = commit(h.genesis, &[], &[b"shared".to_vec()], 0).1;
            (h.commit, tree)
        };
        for e in &tree.entries {
            if e.object_type != ObjectType::Commit as u8 {
                put(&h, &e.bytes);
            }
        }
        let tree_id = blake3_hash(&tree.entries[1].bytes);
        let mut tip = tip;
        const LENGTH: i64 = 5_000;
        for t in 1..=LENGTH {
            let c = Commit {
                tree: tree_id,
                parents: vec![tip],
                authority: h.genesis,
                author_key: key(OWNER).public().0,
                timestamp_micros: 1_700_000_000_000_000 + t,
                flags: CommitFlags::NONE,
                message: String::new(),
            };
            tip = put(&h, &sign_commit(c, &key(OWNER)).unwrap().serialize());
        }
        set_main(&h, tip);
        let pack = pack_of(&base, &h.id, &[], &[tip]).unwrap();
        assert!(pack.entries.len() as i64 > LENGTH, "{}", pack.entries.len());
    })
    .await;
}

/// A pack is sent only within its limits: the objects it walks, the
/// objects it holds, their bytes, and the ids asked for, at most 256.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pack_is_sent_only_within_its_limits() {
    let limits = Limits {
        max_pack_objects: 6,
        max_pack_bytes: 64 << 10,
        max_walk_objects: 12,
        ..Limits::default()
    };
    run(limits, |base, root, _| {
        let h = host(&base, &root, public(1), 0);
        // Within every limit: genesis, blob, tree, commit.
        assert_eq!(
            pack_of(&base, &h.id, &[], &[h.commit])
                .unwrap()
                .entries
                .len(),
            4
        );

        // Two more commits: eight objects, more than six.
        let c1 = commit(h.genesis, &[h.commit], &[b"one".to_vec()], 1);
        push(&base, &h.id, h.genesis, Some(h.commit), &c1).unwrap();
        let c2 = commit(h.genesis, &[c1.0], &[b"two".to_vec()], 2);
        let m = PushManifest {
            updates: vec![PushUpdate {
                r#ref: "refs/branches/main".into(),
                old_hash: Some(c1.0.to_hex()),
                new_hash: c2.0.to_hex(),
            }],
            ..manifest(h.genesis, Vec::new())
        };
        status(Client::new(api(&base)).push(&key(OWNER), &h.id, &c2.1, &m)).unwrap();
        let (code, body) = pack_of(&base, &h.id, &[], &[c2.0]).unwrap_err();
        assert_eq!(code, 413, "{body}");
        assert!(body.contains("more than 6 objects"), "{body}");
        // Saying what it has, the client is sent what it lacks.
        assert_eq!(
            pack_of(&base, &h.id, &[c1.0], &[c2.0])
                .unwrap()
                .entries
                .len(),
            3
        );

        // A walk past its limit, through what the client says it has: ten
        // objects behind main, and three new ones on a side branch, though
        // the pack would hold only the three.
        let side = commit(h.genesis, &[h.commit], &[b"side".to_vec()], 3);
        let m = manifest(h.genesis, vec![("refs/branches/side".into(), side.0)]);
        status(Client::new(api(&base)).push(&key(OWNER), &h.id, &side.1, &m)).unwrap();
        let (code, body) = pack_of(&base, &h.id, &[c2.0], &[side.0]).unwrap_err();
        assert_eq!(code, 413, "{body}");
        assert!(body.contains("walks more history"), "{body}");

        // More bytes than the limit.
        let big = put(&h, &Blob::new(noise(70_000)).serialize());
        let (code, body) = pack_of(&base, &h.id, &[], &[big]).unwrap_err();
        assert_eq!(code, 413, "{body}");
        assert!(body.contains("larger than"), "{body}");

        // More ids than a request may carry.
        let ids = vec![h.commit; 257];
        let (code, body) = pack_of(&base, &h.id, &[], &ids).unwrap_err();
        assert_eq!(code, 413, "{body}");
    })
    .await;
}

// Concurrent work.

/// Requests beyond the in-flight limit are refused at once (503), not
/// queued without bound; the liveness probe is still answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn requests_beyond_the_limit_are_refused() {
    let limits = Limits {
        max_in_flight: 1,
        ..Limits::default()
    };
    run(limits, |base, root, state| {
        let h = host(&base, &root, public(1), 0);
        // The one request under way waits for a push in flight.
        let lock = lock_of(&state, &h);
        let pushing = lock.blocking_write();
        let first = {
            let (base, id) = (base.clone(), h.id.clone());
            std::thread::spawn(move || get(&base, &format!("/repos/{id}/info")).0)
        };
        assert!(still_waiting(&first));
        let (code, body) = get(&base, &format!("/repos/{}/refs", h.id));
        assert_eq!(code, 503, "{body}");
        let health = reqwest::blocking::get(format!("{base}/health")).unwrap();
        assert_eq!(health.status().as_u16(), 200);
        drop(pushing);
        assert_eq!(finished(first), 200);
        assert_eq!(get(&base, &format!("/repos/{}/refs", h.id)).0, 200);
    })
    .await;
}

/// Pushes beyond their limit are refused before their bodies are read.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pushes_beyond_their_limit_are_refused() {
    let limits = Limits {
        max_concurrent_pushes: 1,
        ..Limits::default()
    };
    run(limits, |base, root, state| {
        let h = host(&base, &root, public(1), 0);
        let lock = lock_of(&state, &h);
        let pushing = lock.blocking_write();
        let c1 = commit(h.genesis, &[h.commit], &[b"one".to_vec()], 1);
        let first = {
            let (base, id, g, c, tip) =
                (base.clone(), h.id.clone(), h.genesis, c1.clone(), h.commit);
            std::thread::spawn(move || push(&base, &id, g, Some(tip), &c))
        };
        assert!(still_waiting(&first));
        let c2 = commit(h.genesis, &[h.commit], &[b"two".to_vec()], 2);
        let (code, body) = push(&base, &h.id, h.genesis, Some(h.commit), &c2).unwrap_err();
        assert_eq!(code, 503, "{body}");
        assert!(body.contains("pushes"), "{body}");
        drop(pushing);
        finished(first).unwrap();
        assert!(stored(&h, c1.0));
    })
    .await;
}

/// Packs and objects beyond their limit wait their turn; one held at a
/// file it is reading holds the next.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn transfers_beyond_their_limit_wait() {
    let limits = Limits {
        max_concurrent_transfers: 1,
        ..Limits::default()
    };
    run(limits, |base, root, _| {
        use std::io::Write;
        let h = host(&base, &root, public(1), 0);
        let x = h.commit.to_hex();
        let file = h.dir.join(".levcs/objects").join(&x[..2]).join(&x[2..]);
        let bytes = std::fs::read(&file).unwrap();
        std::fs::remove_file(&file).unwrap();
        assert!(std::process::Command::new("mkfifo")
            .arg(&file)
            .status()
            .unwrap()
            .success());
        let first = {
            let (base, id) = (base.clone(), h.id.clone());
            std::thread::spawn(move || get(&base, &format!("/repos/{id}/objects/{x}")).0)
        };
        // The first transfer is at the file once the FIFO's write end opens.
        let (tx, rx) = std::sync::mpsc::channel();
        let f = file.clone();
        std::thread::spawn(move || {
            let _ = tx.send(std::fs::OpenOptions::new().write(true).open(f));
        });
        let mut w = rx
            .recv_timeout(PATIENCE)
            .expect("the first transfer never read")
            .unwrap();
        let second = {
            let (base, id, g) = (base.clone(), h.id.clone(), h.genesis);
            std::thread::spawn(move || get(&base, &format!("/repos/{id}/objects/{g}")).0)
        };
        assert!(still_waiting(&second));
        w.write_all(&bytes).unwrap();
        drop(w);
        assert_eq!(finished(first), 200);
        assert_eq!(finished(second), 200);
        std::fs::remove_file(&file).unwrap();
        std::fs::write(&file, &bytes).unwrap();
    })
    .await;
}

/// A body not received in time is refused, and what its request held is
/// let go: the push that follows lands.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_not_received_in_time_is_refused() {
    let limits = Limits {
        body_timeout_secs: 1,
        max_concurrent_pushes: 1,
        ..Limits::default()
    };
    run(limits, |base, root, _| {
        use std::io::{Read, Write};
        let h = host(&base, &root, public(1), 0);
        let addr = base.trim_start_matches("http://");
        let mut conn = std::net::TcpStream::connect(addr).unwrap();
        write!(
            conn,
            "POST /levcs/v1/repos/{}/push HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 1000\r\n\r\n",
            h.id
        )
        .unwrap();
        conn.write_all(&[0u8; 10]).unwrap();
        conn.set_read_timeout(Some(PATIENCE)).unwrap();
        let mut answer = vec![0u8; 512];
        let n = conn.read(&mut answer).unwrap();
        let answer = String::from_utf8_lossy(&answer[..n]);
        assert!(answer.starts_with("HTTP/1.1 408"), "{answer}");
        let c = commit(h.genesis, &[h.commit], &[b"after".to_vec()], 1);
        push(&base, &h.id, h.genesis, Some(h.commit), &c).unwrap();
    })
    .await;
}

/// Signed requests are refused (503) while the replay cache is full, for a
/// repository that does not exist as for one that does; none is forgotten
/// early, and unsigned reads go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_requests_wait_for_room_in_the_replay_cache() {
    let limits = Limits {
        max_nonces: 2,
        ..Limits::default()
    };
    run(limits, |base, root, _| {
        // Creating and pushing take the cache's two places.
        let h = host(&base, &root, public(0), 0);
        let reader = Client::new(api(&base)).with_reader(Arc::new(key(OWNER)));
        let (code, body) = status(reader.refs(&h.id)).unwrap_err();
        assert_eq!(code, 503, "{body}");
        let (code, _) = status(reader.refs(&"ab".repeat(32))).unwrap_err();
        assert_eq!(code, 503);
        let stranger = Client::new(api(&base)).with_reader(Arc::new(key(STRANGER)));
        assert_eq!(status(stranger.refs(&h.id)).unwrap_err().0, 503);
        let p = host_public_read(&base, &root);
        assert!(p.is_ok(), "{p:?}");
    })
    .await;
}

/// An unsigned read of a public repository: still answered. Its repository
/// is written straight to disk, since creating one would sign.
fn host_public_read(base: &str, root: &Path) -> Result<(), (u16, String)> {
    let g = genesis(public(1), 9);
    let id = g.1.repo_id.to_hex();
    let dir = root.join(&id);
    levcs_core::Repository::init_skeleton(&dir).unwrap();
    let h = Hosted {
        dir,
        id: id.clone(),
        genesis: g.0,
        commit: g.0,
    };
    put(&h, &g.2);
    let refs = levcs_core::Refs::new(h.dir.join(".levcs"));
    refs.write("refs/authority/genesis", g.0).unwrap();
    refs.write("refs/authority/current", g.0).unwrap();
    status(Client::new(api(base)).refs(&id)).map(|_| ())
}

#[test]
fn every_limit_must_allow_something() {
    let config = InstanceConfig {
        root: PathBuf::from("/nonexistent"),
        limits: Limits {
            max_in_flight: 0,
            max_pack_bytes: 0,
            body_timeout_secs: 0,
            ..Limits::default()
        },
        ..InstanceConfig::default()
    };
    let problems = config.validate().unwrap_err();
    for name in ["max_in_flight", "max_pack_bytes", "body_timeout_secs"] {
        assert!(problems.contains(name), "{problems}");
    }
    assert!(InstanceConfig::default().validate().is_ok());
}

// What a request holds, and for how long.

fn request(path: String) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::builder()
        .uri(path)
        .body(axum::body::Body::empty())
        .unwrap()
}

/// A push of `c` to main, which is expected to hold `old`, signed by OWNER,
/// as the client sends it.
fn push_request(
    repo: &str,
    authority: ObjectId,
    old: Option<ObjectId>,
    (id, pack): &(ObjectId, Pack),
) -> axum::http::Request<axum::body::Body> {
    let sk = key(OWNER);
    let mut m = manifest(authority, vec![("refs/branches/main".into(), *id)]);
    m.updates[0].old_hash = old.map(|o| o.to_hex());
    let json = serde_json::to_vec(&m).unwrap();
    let mut body = pack.encode();
    body.extend_from_slice(&(json.len() as u32).to_le_bytes());
    body.extend_from_slice(&json);
    body.extend_from_slice(&sk.sign(&json));
    let path = format!("/repos/{repo}/push");
    let req = AuthRequest {
        method: "POST",
        path_with_query: &path,
        body: &body,
    };
    let (k, ts, nonce, sig) = sign_request(&sk, &req).unwrap();
    axum::http::Request::builder()
        .method("POST")
        .uri(format!("/levcs/v1{path}"))
        .header("LeVCS-Key", k)
        .header("LeVCS-Timestamp", ts)
        .header("LeVCS-Nonce", nonce)
        .header("LeVCS-Signature", sig)
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// Replace `path` with a FIFO: a read of it waits until the test writes.
fn fifo(path: &Path) {
    std::fs::remove_file(path).unwrap();
    let made = std::process::Command::new("mkfifo")
        .arg(path)
        .status()
        .unwrap();
    assert!(made.success());
}

/// The write end of the FIFO at `path`, once a reader has opened it, which
/// is then at that file. A failure, not a hang, if no reader comes.
fn reader_at(path: &Path) -> std::fs::File {
    let (tx, rx) = std::sync::mpsc::channel();
    let p = path.to_path_buf();
    std::thread::spawn(move || {
        let _ = tx.send(std::fs::OpenOptions::new().write(true).open(p));
    });
    rx.recv_timeout(PATIENCE)
        .unwrap_or_else(|_| panic!("nothing read {}", path.display()))
        .unwrap()
}

/// Put a regular file back where a FIFO was.
fn restore(path: &Path, line: String) {
    std::fs::remove_file(path).unwrap();
    std::fs::write(path, format!("{line}\n")).unwrap();
}

/// A sparse file of a terabyte under `id`'s name in `h`'s store: an object
/// that a read of the whole would not finish.
fn sparse(h: &Hosted, id: ObjectId) {
    let x = id.to_hex();
    let dir = h.dir.join(".levcs/objects").join(&x[..2]);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::File::create(dir.join(&x[2..]))
        .unwrap()
        .set_len(1 << 40)
        .unwrap();
}

/// A commit whose tree names `blob` as its one file, stored in `h`.
fn commit_naming(h: &Hosted, blob: ObjectId) -> ObjectId {
    let mut tree = Tree {
        entries: vec![TreeEntry {
            name: "big".into(),
            entry_type: EntryType::Blob,
            mode: FileMode::REGULAR,
            hash: blob,
        }],
    };
    tree.sort_and_validate().unwrap();
    let tree = put(h, &tree.serialize());
    let c = Commit {
        tree,
        parents: vec![h.commit],
        authority: h.genesis,
        author_key: key(OWNER).public().0,
        timestamp_micros: 1_700_000_000_000_100,
        flags: CommitFlags::NONE,
        message: "big".into(),
    };
    put(h, &sign_commit(c, &key(OWNER)).unwrap().serialize())
}

/// An object is sent only within the object limit, alone or in a pack, and
/// its size is checked before it is read: a terabyte under an object's name
/// is refused at once. Downloads did not apply the object limit at all, and
/// read every object whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn downloads_keep_to_the_object_limit() {
    let limits = Limits {
        max_object_bytes: 1024,
        ..Limits::default()
    };
    run(limits, |base, root, _| {
        let h = host(&base, &root, public(1), 0);
        let big = put(&h, &Blob::new(noise(2048)).serialize());
        let (code, body) = get(&base, &format!("/repos/{}/objects/{big}", h.id));
        assert_eq!(code, 413, "{body}");
        let (code, body) = pack_of(&base, &h.id, &[], &[big]).unwrap_err();
        assert_eq!(code, 413, "{body}");

        let huge = ObjectId([0xEE; 32]);
        sparse(&h, huge);
        let c = commit_naming(&h, huge);
        let started = std::time::Instant::now();
        assert_eq!(
            get(&base, &format!("/repos/{}/objects/{huge}", h.id)).0,
            413
        );
        let (code, body) = pack_of(&base, &h.id, &[], &[c]).unwrap_err();
        assert_eq!(code, 413, "{body}");
        assert!(body.contains("larger than this instance sends"), "{body}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    })
    .await;
}

/// What is left of a pack's byte budget is checked before each object is
/// read, not after: an object within the object limit, but past what the
/// pack has left, is refused unread. The bytes were counted only once each
/// object had been read whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pack_keeps_to_its_budget_before_reading() {
    let limits = Limits {
        max_object_bytes: 2 << 40,
        max_pack_bytes: 16 << 10,
        ..Limits::default()
    };
    run(limits, |base, root, _| {
        let h = host(&base, &root, public(1), 0);
        let huge = ObjectId([0xEE; 32]);
        sparse(&h, huge);
        let c = commit_naming(&h, huge);
        let started = std::time::Instant::now();
        let (code, body) = pack_of(&base, &h.id, &[], &[c]).unwrap_err();
        assert_eq!(code, 413, "{body}");
        assert!(body.contains("pack asked for is larger than"), "{body}");
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    })
    .await;
}

/// A response holds its transfer until it has been sent: while one client
/// leaves its body unread, the next transfer waits. The permit was let go
/// once the body had been built, so slow clients held bodies past the
/// limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_response_holds_its_transfer_until_sent() {
    let limits = Limits {
        max_concurrent_transfers: 1,
        ..Limits::default()
    };
    run(limits, |base, root, state| {
        use tower::ServiceExt;
        let h = host(&base, &root, public(1), 0);
        let app = router(state);
        tokio::runtime::Handle::current().block_on(async move {
            let routes = [
                format!("/levcs/v1/repos/{}/objects/{}", h.id, h.commit),
                format!("/levcs/v1/repos/{}/pack?have=&want={}", h.id, h.commit),
            ];
            for route in routes {
                let unread = app.clone().oneshot(request(route.clone())).await.unwrap();
                assert_eq!(unread.status().as_u16(), 200);
                let mut next = tokio::spawn(app.clone().oneshot(request(route.clone())));
                let early =
                    tokio::time::timeout(std::time::Duration::from_millis(300), &mut next).await;
                assert!(
                    early.is_err(),
                    "{route}: a transfer began while one was unsent"
                );
                drop(unread);
                let next = tokio::time::timeout(PATIENCE, next).await.unwrap();
                assert_eq!(next.unwrap().unwrap().status().as_u16(), 200);
            }
        });
    })
    .await;
}

/// A request cancelled while its work goes on keeps its place until the
/// work has stopped: here a read held at a file it is reading. Only the
/// middleware held the place, and gave it up when the request was dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_request_keeps_its_place_while_its_work_runs() {
    let limits = Limits {
        max_in_flight: 1,
        ..Limits::default()
    };
    run(limits, |_, root, state| {
        use std::io::Write;
        use tower::ServiceExt;
        let rt = tokio::runtime::Handle::current();
        let app = router(state.clone());
        // Created through the router, the one place in flight at a time.
        let h = {
            let g = genesis(public(1), 0);
            let id = g.1.repo_id.to_hex();
            let init = {
                let path = format!("/repos/{id}/init");
                let req = AuthRequest {
                    method: "POST",
                    path_with_query: &path,
                    body: &g.2,
                };
                let (k, ts, nonce, sig) = sign_request(&key(OWNER), &req).unwrap();
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/levcs/v1{path}"))
                    .header("LeVCS-Key", k)
                    .header("LeVCS-Timestamp", ts)
                    .header("LeVCS-Nonce", nonce)
                    .header("LeVCS-Signature", sig)
                    .body(axum::body::Body::from(g.2.clone()))
                    .unwrap()
            };
            let r = rt.block_on(app.clone().oneshot(init)).unwrap();
            assert_eq!(r.status().as_u16(), 201);
            let c = commit(g.0, &[], &[b"hosted".to_vec()], 0);
            let r = rt
                .block_on(app.clone().oneshot(push_request(&id, g.0, None, &c)))
                .unwrap();
            assert_eq!(r.status().as_u16(), 200);
            Hosted {
                dir: root.join(&id),
                id,
                genesis: g.0,
                commit: c.0,
            }
        };
        // What a request is answered within PATIENCE, if it is answered.
        let info = || {
            rt.block_on(tokio::time::timeout(
                PATIENCE,
                app.clone()
                    .oneshot(request("/levcs/v1/instance/info".into())),
            ))
            .ok()
            .map(|r| r.unwrap().status().as_u16())
        };
        // A request cancelled while its work is held at `file`: what the
        // next request is answered. The file is released before anything
        // is asserted, so that a failure does not leave work held.
        let cancelled_at = |file: &Path, route: String, line: String| {
            fifo(file);
            let first = rt.spawn(app.clone().oneshot(request(route.clone())));
            let mut w = reader_at(file);
            first.abort();
            assert!(rt.block_on(first).unwrap_err().is_cancelled());
            let held = lock_of(&state, &h).try_write().is_err();
            let next = info();
            writeln!(w, "{line}").unwrap();
            drop(w);
            let deadline = std::time::Instant::now() + PATIENCE;
            while info() != Some(200) {
                assert!(
                    std::time::Instant::now() < deadline,
                    "{route}: never let go"
                );
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            restore(file, line);
            assert!(held, "{route}: its work no longer held its read");
            assert_eq!(
                next,
                Some(503),
                "{route}: a request was let in while its work ran"
            );
        };
        // Deciding who may read, held at `current`.
        cancelled_at(
            &h.dir.join(".levcs/refs/authority/current"),
            format!("/levcs/v1/repos/{}/info", h.id),
            h.genesis.to_hex(),
        );
        // Answering, held at the branch.
        cancelled_at(
            &h.dir.join(".levcs/refs/branches/main"),
            format!("/levcs/v1/repos/{}/refs", h.id),
            h.commit.to_hex(),
        );
    })
    .await;
}

/// A push cancelled while its work goes on keeps its permit until the work
/// has stopped: here its first check, held at `current`. Only the last of
/// its stages held the permit; authentication and decoding did not.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancelled_push_keeps_its_permit_while_its_work_runs() {
    let limits = Limits {
        max_concurrent_pushes: 1,
        ..Limits::default()
    };
    run(limits, |base, root, state| {
        use std::io::Write;
        use tower::ServiceExt;
        let h = host(&base, &root, public(1), 0);
        let rt = tokio::runtime::Handle::current();
        let app = router(state);
        let current = h.dir.join(".levcs/refs/authority/current");
        fifo(&current);
        let c1 = commit(h.genesis, &[h.commit], &[b"one".to_vec()], 1);
        let first =
            rt.spawn(
                app.clone()
                    .oneshot(push_request(&h.id, h.genesis, Some(h.commit), &c1)),
            );
        let mut w = reader_at(&current);
        first.abort();
        assert!(rt.block_on(first).unwrap_err().is_cancelled());
        let c2 = commit(h.genesis, &[h.commit], &[b"two".to_vec()], 2);
        // What a push is answered within PATIENCE, if it is answered.
        let push = |c: &(ObjectId, Pack)| {
            rt.block_on(tokio::time::timeout(
                PATIENCE,
                app.clone()
                    .oneshot(push_request(&h.id, h.genesis, Some(h.commit), c)),
            ))
            .ok()
            .map(|r| r.unwrap().status().as_u16())
        };
        let next = push(&c2);
        // Released before anything is asserted, so that a failure does not
        // leave work held.
        writeln!(w, "{}", h.genesis).unwrap();
        drop(w);
        let deadline = std::time::Instant::now() + PATIENCE;
        loop {
            // Once the cancelled push's check has read `current`, the file
            // can be put back.
            std::thread::sleep(std::time::Duration::from_millis(20));
            if std::fs::metadata(&current)
                .map(|m| m.file_type().is_fifo())
                .unwrap_or(false)
            {
                restore(&current, h.genesis.to_hex());
            }
            match push(&c2) {
                Some(503) => assert!(
                    std::time::Instant::now() < deadline,
                    "its permit was never let go"
                ),
                code => {
                    assert_eq!(code, Some(200));
                    break;
                }
            }
        }
        assert_eq!(
            next,
            Some(503),
            "a push was let in while a cancelled one's work ran"
        );
        assert!(stored(&h, c2.0));
    })
    .await;
}
