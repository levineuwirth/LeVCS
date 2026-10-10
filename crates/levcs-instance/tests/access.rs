//! Who reaches a repository on an instance.
//!
//! - **Path confinement.** The id in a request is joined onto the
//!   instance's root only when it is an id. `/repos/%2F<path>/info` used to
//!   read a repository anywhere on the host (audit C3).
//! - **Creation.** Only the keys the operator names create repositories,
//!   and naming none creates none. Any owner of a genesis used to.
//! - **Reads.** A repository is read as its current authority's policy
//!   says: a public one by anyone, a private one by its members, in signed
//!   requests. A policy that cannot be established lets no one read. No
//!   handler used to look at the policy at all.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use levcs_client::{Client, ClientError};
use levcs_core::hash::blake3_hash;
use levcs_core::object::ObjectType;
use levcs_core::{
    Blob, Commit, CommitFlags, EntryType, FileMode, ObjectId, ObjectStore, Tree, TreeEntry, ZERO_ID,
};
use levcs_identity::authority::{AuthorityBody, MemberEntry, PolicyEntry, Role};
use levcs_identity::keys::SecretKey;
use levcs_identity::sign::{sign_authority, sign_commit};
use levcs_instance::mirror::{sync_mirror, MirrorError};
use levcs_instance::{router, AppState, InstanceConfig, MirrorConfig, RepoId};
use levcs_protocol::auth::{sign_request, AuthRequest};
use levcs_protocol::wire::{PushManifest, PushUpdate};
use levcs_protocol::Pack;

const OWNER: [u8; 32] = [1; 32];
const READER: [u8; 32] = [2; 32];
const STRANGER: [u8; 32] = [3; 32];

fn key(seed: [u8; 32]) -> SecretKey {
    SecretKey::from_seed(seed)
}

fn named(seed: [u8; 32]) -> String {
    key(seed).public().to_levcs()
}

fn tempdir(prefix: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn config(root: &Path, creators: Vec<String>) -> InstanceConfig {
    InstanceConfig {
        root: root.to_path_buf(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors: Vec::new(),
        creators,
        limits: Default::default(),
    }
}

/// Serve an instance whose root is a fresh directory, and run `f` against
/// its base URL (`http://<addr>`) and root.
async fn run(creators: Vec<String>, f: impl FnOnce(String, PathBuf) + Send + 'static) {
    run_with(creators, |base, root, _| f(base, root)).await
}

/// As `run`, with the instance's state, whose repository locks a test holds
/// to stand in for a push in flight.
async fn run_with(
    creators: Vec<String>,
    f: impl FnOnce(String, PathBuf, AppState) + Send + 'static,
) {
    let root = tempdir("levcs-access");
    let state = AppState::new(config(&root, creators));
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

fn member(k: &SecretKey, role: Role, by: &SecretKey) -> MemberEntry {
    MemberEntry {
        key: k.public(),
        handle: format!("{}", k.public().0[0]),
        role,
        added_micros: 1,
        added_by: by.public(),
    }
}

/// A genesis owned by `owner`, with `others` as members. `salt` keeps
/// repositories in one test apart.
fn genesis(
    owner: &SecretKey,
    others: &[(&SecretKey, Role)],
    policy: Vec<PolicyEntry>,
    salt: i64,
) -> (ObjectId, AuthorityBody, Vec<u8>) {
    let mut members = vec![member(owner, Role::Owner, owner)];
    members.extend(others.iter().map(|(k, r)| member(k, *r, owner)));
    let mut body = AuthorityBody {
        schema_version: 1,
        repo_id: ZERO_ID,
        previous_authority: ZERO_ID,
        version: 1,
        created_micros: 1_700_000_000_000_000 + salt,
        members,
        policy,
    };
    body.normalize().unwrap();
    body.assign_genesis_repo_id().unwrap();
    let bytes = sign_authority(&body, owner).unwrap().serialize();
    (blake3_hash(&bytes), body, bytes)
}

/// The successor of `prev`, with its members and `policy`.
fn successor(
    owner: &SecretKey,
    prev: &(ObjectId, AuthorityBody, Vec<u8>),
    policy: Vec<PolicyEntry>,
) -> (ObjectId, AuthorityBody, Vec<u8>) {
    let mut body = prev.1.clone();
    body.previous_authority = prev.0;
    body.version += 1;
    body.created_micros += 1;
    body.policy = policy;
    body.normalize().unwrap();
    let bytes = sign_authority(&body, owner).unwrap().serialize();
    (blake3_hash(&bytes), body, bytes)
}

/// A commit with one file, citing `authority`, and the pack carrying it.
fn commit(by: &SecretKey, authority: ObjectId, text: &str) -> (ObjectId, Pack) {
    let mut pack = Pack::new();
    let blob = Blob::new(text.as_bytes().to_vec()).serialize();
    let blob_id = blake3_hash(&blob);
    pack.push(ObjectType::Blob as u8, blob);
    let mut tree = Tree {
        entries: vec![TreeEntry {
            name: "a.txt".into(),
            entry_type: EntryType::Blob,
            mode: FileMode::REGULAR,
            hash: blob_id,
        }],
    };
    tree.sort_and_validate().unwrap();
    let tree = tree.serialize();
    let tree_id = blake3_hash(&tree);
    pack.push(ObjectType::Tree as u8, tree);
    let c = Commit {
        tree: tree_id,
        parents: Vec::new(),
        authority,
        author_key: by.public().0,
        timestamp_micros: 1_700_000_000_000_001,
        flags: CommitFlags::NONE,
        message: text.into(),
    };
    let c = sign_commit(c, by).unwrap().serialize();
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

fn push(
    base: &str,
    by: &SecretKey,
    repo: &str,
    authority: ObjectId,
    (id, pack): &(ObjectId, Pack),
) -> Result<(), (u16, String)> {
    let manifest = PushManifest {
        authority_hash: authority.to_hex(),
        updates: vec![PushUpdate {
            r#ref: "refs/branches/main".into(),
            old_hash: None,
            new_hash: id.to_hex(),
        }],
        timestamp: 0,
        force: false,
    };
    status(Client::new(api(base)).push(by, repo, pack, &manifest))
}

/// A repository created by `owner` with one commit on main.
struct Hosted {
    id: String,
    genesis: (ObjectId, AuthorityBody, Vec<u8>),
    commit: ObjectId,
    dir: PathBuf,
}

fn host(
    base: &str,
    root: &Path,
    others: &[(&SecretKey, Role)],
    policy: Vec<PolicyEntry>,
    salt: i64,
) -> Hosted {
    let owner = key(OWNER);
    let g = genesis(&owner, others, policy, salt);
    let id = g.1.repo_id.to_hex();
    Client::new(api(base)).init(&owner, &id, &g.2).unwrap();
    let c = commit(&owner, g.0, "hosted");
    push(base, &owner, &id, g.0, &c).unwrap();
    Hosted {
        dir: root.join(&id),
        id,
        commit: c.0,
        genesis: g,
    }
}

/// The four reads, by a client that signs as `reader` (anonymous for
/// `None`): what each answered.
fn reads(
    base: &str,
    repo: &str,
    obj: ObjectId,
    reader: Option<[u8; 32]>,
) -> Vec<Result<(), (u16, String)>> {
    let mut c = Client::new(api(base));
    if let Some(seed) = reader {
        c = c.with_reader(Arc::new(key(seed)));
    }
    vec![
        status(c.repo_info(repo).map(|_| ())),
        status(c.refs(repo).map(|_| ())),
        status(c.get_object(repo, obj).map(|_| ())),
        status(c.get_pack(repo, &[], &[obj]).map(|_| ())),
    ]
}

/// What the four reads of a repository that was never created answer.
fn as_missing(base: &str) -> Vec<Result<(), (u16, String)>> {
    reads(base, &"ab".repeat(32), ObjectId([7; 32]), None)
}

/// The routes, under `/levcs/v1/repos/<id>/`, the four reads use.
fn routes(obj: ObjectId) -> Vec<String> {
    vec![
        "info".into(),
        "refs".into(),
        format!("objects/{obj}"),
        format!("pack?have=&want={obj}"),
    ]
}

/// GET `/levcs/v1/repos/<repo>/<route>` with `headers`, unsigned or not.
fn raw_get(base: &str, repo: &str, route: &str, headers: &[(String, String)]) -> (u16, String) {
    let mut req =
        reqwest::blocking::Client::new().get(format!("{}/repos/{repo}/{route}", api(base)));
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let res = req.send().unwrap();
    (res.status().as_u16(), res.text().unwrap())
}

/// Request headers signed by `sk` for a GET of `path`.
fn signed(sk: &SecretKey, path: &str) -> Vec<(String, String)> {
    let req = AuthRequest {
        method: "GET",
        path_with_query: path,
        body: b"",
    };
    let (k, ts, nonce, sig) = sign_request(sk, &req).unwrap();
    vec![
        ("LeVCS-Key".into(), k),
        ("LeVCS-Timestamp".into(), ts),
        ("LeVCS-Nonce".into(), nonce),
        ("LeVCS-Signature".into(), sig),
    ]
}

/// POST `body` to `/levcs/v1/repos/<repo>/push`, signed by `sk`.
fn raw_push(base: &str, sk: &SecretKey, repo: &str, body: &[u8]) -> (u16, String) {
    let path = format!("/repos/{repo}/push");
    let req = AuthRequest {
        method: "POST",
        path_with_query: &path,
        body,
    };
    let (k, ts, nonce, sig) = sign_request(sk, &req).unwrap();
    let res = reqwest::blocking::Client::new()
        .post(format!("{}{path}", api(base)))
        .header("LeVCS-Key", k)
        .header("LeVCS-Timestamp", ts)
        .header("LeVCS-Nonce", nonce)
        .header("LeVCS-Signature", sig)
        .body(body.to_vec())
        .send()
        .unwrap();
    (res.status().as_u16(), res.text().unwrap())
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &to.join(e.file_name()));
        } else {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

fn store(h: &Hosted) -> ObjectStore {
    ObjectStore::new(h.dir.join(".levcs/objects"))
}

fn set_current(h: &Hosted, id: &str) {
    std::fs::write(
        h.dir.join(".levcs/refs/authority/current"),
        format!("{id}\n"),
    )
    .unwrap();
}

// Path confinement.

/// C3: a repository outside the root, reached by an absolute or a relative
/// path in place of an id, or an id in the wrong case, is answered on
/// every route as a repository that does not exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_path_in_place_of_an_id_reaches_nothing() {
    run(vec![named(OWNER)], |base, root| {
        let h = host(&base, &root, &[], public(1), 0);
        let outside = tempdir("levcs-access-outside");
        copy_dir(&h.dir, &outside.join(&h.id));
        let absolute = outside.join(&h.id).to_string_lossy().replace('/', "%2F");
        let relative = format!(
            "..%2F{}%2F{}",
            outside.file_name().unwrap().to_string_lossy(),
            h.id
        );
        let missing = as_missing(&base);
        for repo in [
            absolute,
            relative,
            h.id.to_uppercase(),
            format!("{}0", h.id),
        ] {
            for (route, expected) in routes(h.commit).iter().zip(&missing) {
                let (code, body) = raw_get(&base, &repo, route, &[]);
                assert_eq!(Err((code, body)), *expected, "{repo}/{route}");
            }
        }
        // The repository itself is still served by its id.
        assert!(reads(&base, &h.id, h.commit, None)
            .iter()
            .all(|r| r.is_ok()));
        std::fs::remove_dir_all(outside).unwrap();
    })
    .await;
}

/// Creating or pushing under a path creates nothing outside the root.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_and_push_under_a_path_write_nothing_outside_the_root() {
    run(vec![named(OWNER)], |base, _root| {
        let owner = key(OWNER);
        let outside = tempdir("levcs-access-outside");
        let target = outside.join("created");
        let encoded = target.to_string_lossy().replace('/', "%2F");
        let g = genesis(&owner, &[], public(1), 0);
        let init = Client::new(api(&base)).init(&owner, &encoded, &g.2);
        assert!(
            matches!(init, Err(ClientError::Server { status: 404, .. })),
            "{init:?}"
        );
        let c = commit(&owner, g.0, "x");
        assert_eq!(push(&base, &owner, &encoded, g.0, &c).unwrap_err().0, 404);
        assert!(!target.exists());
        std::fs::remove_dir_all(outside).unwrap();
    })
    .await;
}

/// Recovery at startup touches only directories named by an id: anything
/// else under the root is not a repository of this instance.
#[test]
fn recovery_leaves_alone_what_is_not_named_by_an_id() {
    let root = tempdir("levcs-access-recovery");
    let record = root.join("notes/.levcs/ref-transaction/record");
    std::fs::create_dir_all(record.parent().unwrap()).unwrap();
    let text = format!(
        "levcs ref transaction 1\nrefs/branches/main\t-\t{}\n",
        "ab".repeat(32)
    );
    std::fs::write(&record, &text).unwrap();
    assert!(levcs_instance::recover_interrupted_pushes(&root).is_empty());
    assert_eq!(std::fs::read_to_string(&record).unwrap(), text);
    std::fs::remove_dir_all(root).unwrap();
}

/// A mirror names its repository by id, or it reaches nothing: its
/// `repo_id` used to be joined onto the root as configured.
#[test]
fn a_mirror_reaches_only_a_repository_named_by_id() {
    let root = tempdir("levcs-access-mirror");
    // Named after this root, so that nothing another run left can count.
    let escaped = format!("{}-escaped", root.file_name().unwrap().to_string_lossy());
    let outside = root.parent().unwrap().join(&escaped);
    // Removed however the test ends: a failure must not leave it behind.
    struct Remove(PathBuf);
    impl Drop for Remove {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = (Remove(outside.clone()), Remove(root.clone()));
    for repo_id in [
        format!("../{escaped}"),
        format!("..%2F{escaped}"),
        "AB".repeat(32),
    ] {
        let mirror = MirrorConfig {
            repo_id: repo_id.clone(),
            source: "http://127.0.0.1:9/levcs/v1".into(),
            mode: "full".into(),
            poll_interval: String::new(),
            writeback: false,
        };
        let mut cfg = config(&root, Vec::new());
        cfg.mirrors = vec![mirror.clone()];
        let problems = cfg.validate().unwrap_err();
        assert!(problems.contains("is not 64 lowercase hex"), "{problems}");
        assert!(matches!(
            sync_mirror(&cfg, &mirror),
            Err(MirrorError::RepoId(_))
        ));
    }
    assert!(!outside.exists(), "a mirror created {}", outside.display());
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
}

/// Any mirror is refused, one named by a valid id included: a mirror
/// installs its source's history without checking it (Rule R), and the
/// instance does not start with one configured.
#[test]
fn a_mirror_is_refused_until_it_checks_what_it_receives() {
    let mut cfg = config(Path::new("/nonexistent"), Vec::new());
    cfg.mirrors = vec![MirrorConfig {
        repo_id: "ab".repeat(32),
        source: "http://127.0.0.1:9/levcs/v1".into(),
        mode: "full".into(),
        poll_interval: String::new(),
        writeback: false,
    }];
    let problems = cfg.validate().unwrap_err();
    assert!(
        problems.contains("mirroring is refused until it checks what it receives"),
        "{problems}"
    );
}

// Creation.

/// An instance that names no creator accepts no new repository, not even
/// from the owner of the genesis it is sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_instance_naming_no_creator_creates_nothing() {
    run(Vec::new(), |base, root| {
        let owner = key(OWNER);
        let g = genesis(&owner, &[], public(1), 0);
        let id = g.1.repo_id.to_hex();
        let (code, body) = status(Client::new(api(&base)).init(&owner, &id, &g.2)).unwrap_err();
        assert_eq!(code, 403, "{body}");
        assert!(body.contains("may not create repositories"), "{body}");
        assert!(!root.join(&id).exists());
    })
    .await;
}

/// Only the keys the operator names create repositories. An entry that is
/// not a key authorizes no one, and the binary refuses to start over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_the_named_keys_create_repositories() {
    let creators = vec!["not-a-key".into(), "ed25519:zz".into(), named(OWNER)];
    let problems = config(Path::new("/nonexistent"), creators.clone())
        .validate()
        .unwrap_err();
    assert!(
        problems.contains("not-a-key") && problems.contains("ed25519:zz"),
        "{problems}"
    );
    run(creators, |base, root| {
        let stranger = key(STRANGER);
        let g = genesis(&stranger, &[], public(1), 0);
        let id = g.1.repo_id.to_hex();
        let (code, body) = status(Client::new(api(&base)).init(&stranger, &id, &g.2)).unwrap_err();
        assert_eq!(code, 403, "{body}");
        assert!(!root.join(&id).exists());

        let owner = key(OWNER);
        let g = genesis(&owner, &[], public(1), 0);
        let id = g.1.repo_id.to_hex();
        status(Client::new(api(&base)).init(&owner, &id, &g.2)).unwrap();
        assert!(root.join(&id).is_dir());
    })
    .await;
}

// Reads.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_public_repository_is_read_by_anyone() {
    run(vec![named(OWNER)], |base, root| {
        let h = host(&base, &root, &[], public(1), 0);
        for reader in [None, Some(STRANGER), Some(OWNER)] {
            for r in reads(&base, &h.id, h.commit, reader) {
                assert_eq!(r, Ok(()), "{reader:?}");
            }
        }
    })
    .await;
}

/// A private repository, with `public_read` false or left out, is read by
/// the members of its current authority, a reader among them, in signed
/// requests. Anyone else is answered on every route as for a repository
/// that does not exist.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_private_repository_is_read_by_its_members_only() {
    run(vec![named(OWNER)], |base, root| {
        let reader = key(READER);
        let missing = as_missing(&base);
        for (salt, policy) in [(0, public(0)), (1, Vec::new())] {
            let h = host(&base, &root, &[(&reader, Role::Reader)], policy, salt);
            for who in [None, Some(STRANGER)] {
                assert_eq!(reads(&base, &h.id, h.commit, who), missing, "{who:?}");
            }
            for who in [READER, OWNER] {
                for r in reads(&base, &h.id, h.commit, Some(who)) {
                    assert_eq!(r, Ok(()));
                }
            }
        }
    })
    .await;
}

/// A signed read is good for its route, once. The query is signed in a
/// fixed order, so a proxy that reorders it changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_signed_read_is_bound_to_its_route_and_used_once() {
    run(vec![named(OWNER)], |base, root| {
        let reader = key(READER);
        let h = host(&base, &root, &[(&reader, Role::Reader)], public(0), 0);
        let info = signed(&reader, &format!("/repos/{}/info", h.id));
        assert_eq!(raw_get(&base, &h.id, "info", &info).0, 200);
        assert_eq!(raw_get(&base, &h.id, "info", &info).0, 404, "replayed");
        let info = signed(&reader, &format!("/repos/{}/info", h.id));
        assert_eq!(raw_get(&base, &h.id, "refs", &info).0, 404, "another route");

        let pack = format!("/repos/{}/pack?have=&want={}", h.id, h.commit);
        let headers = signed(&reader, &pack);
        let reordered = format!("pack?want={}&have=", h.commit);
        assert_eq!(raw_get(&base, &h.id, &reordered, &headers).0, 200);
        let headers = signed(&reader, &pack);
        let other = format!("pack?have=&want={}", h.genesis.0);
        assert_eq!(
            raw_get(&base, &h.id, &other, &headers).0,
            404,
            "another query"
        );
    })
    .await;
}

/// A push to a private repository by someone who may not read it is
/// answered as a push to a repository that does not exist. Its refusal
/// used to name the repository's current authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_tells_a_stranger_nothing_about_a_private_repository() {
    run(vec![named(OWNER)], |base, root| {
        let stranger = key(STRANGER);
        let h = host(&base, &root, &[], public(0), 0);
        // Made under an authority that is not current, which drew a
        // refusal naming the current one.
        let elsewhere = genesis(&stranger, &[], public(1), 1);
        let c = commit(&stranger, elsewhere.0, "x");
        let refused = push(&base, &stranger, &h.id, elsewhere.0, &c).unwrap_err();
        let missing = push(&base, &stranger, &"ab".repeat(32), elsewhere.0, &c).unwrap_err();
        assert_eq!(refused, missing);
        assert!(!refused.1.contains(&h.genesis.0.to_hex()), "{}", refused.1);
        assert!(
            !store(&h).read_raw(c.0).is_ok(),
            "a refused push stored its objects"
        );
        // Nor is a stranger's push decoded: a malformed one is answered as
        // one to a repository that does not exist, not as malformed.
        assert_eq!(
            raw_push(&base, &stranger, &h.id, b"x"),
            raw_push(&base, &stranger, &"ab".repeat(32), b"x")
        );
    })
    .await;
}

/// A read policy that cannot be established lets no one read, the owner
/// included: a current authority that is missing, not stored, another
/// repository's, or whose `public_read` is neither true nor false. Put
/// back, the repository is read again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_policy_that_cannot_be_established_lets_no_one_read() {
    run(vec![named(OWNER)], |base, root| {
        let owner = key(OWNER);
        let h = host(&base, &root, &[], public(1), 0);
        let other = host(&base, &root, &[], public(1), 1);
        std::fs::copy(
            other
                .dir
                .join(".levcs/objects")
                .join(&other.genesis.0.to_hex()[..2])
                .join(&other.genesis.0.to_hex()[2..]),
            {
                let p = h
                    .dir
                    .join(".levcs/objects")
                    .join(&other.genesis.0.to_hex()[..2]);
                std::fs::create_dir_all(&p).unwrap();
                p.join(&other.genesis.0.to_hex()[2..])
            },
        )
        .unwrap();
        let malformed = successor(&owner, &h.genesis, public(2));
        store(&h).write_raw(&malformed.2).unwrap();
        // This repository's, and stored, but signed by someone who may not
        // change its authority.
        let forged = successor(&key(STRANGER), &h.genesis, public(1));
        store(&h).write_raw(&forged.2).unwrap();
        let missing = as_missing(&base);
        let current = h.dir.join(".levcs/refs/authority/current");
        for (why, broken) in [
            ("not stored", Some("cd".repeat(32))),
            ("another repository's", Some(other.genesis.0.to_hex())),
            ("public_read malformed", Some(malformed.0.to_hex())),
            ("not proved", Some(forged.0.to_hex())),
            ("missing", None),
        ] {
            match &broken {
                Some(id) => set_current(&h, id),
                None => std::fs::remove_file(&current).unwrap(),
            }
            for who in [None, Some(OWNER)] {
                assert_eq!(
                    reads(&base, &h.id, h.commit, who),
                    missing,
                    "{why}, {who:?}"
                );
            }
        }
        set_current(&h, &h.genesis.0.to_hex());
        assert!(reads(&base, &h.id, h.commit, None)
            .iter()
            .all(|r| r.is_ok()));
    })
    .await;
}

/// While a push is in flight, the authority it would replace decides who
/// reads. A push that would make a private repository public, killed part
/// way, does not open it to anyone; its members are asked to try again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_in_flight_opens_nothing() {
    run(vec![named(OWNER)], |base, root| {
        let owner = key(OWNER);
        let h = host(&base, &root, &[], public(0), 0);
        let opened = successor(&owner, &h.genesis, public(1));
        store(&h).write_raw(&opened.2).unwrap();
        // As a kill leaves it: the record written, `current` moved.
        let levcs = h.dir.join(".levcs");
        std::fs::create_dir_all(levcs.join("ref-transaction")).unwrap();
        std::fs::write(
            levcs.join("ref-transaction/record"),
            format!(
                "levcs ref transaction 1\nrefs/authority/current\t{}\t{}\n",
                h.genesis.0, opened.0
            ),
        )
        .unwrap();
        set_current(&h, &opened.0.to_hex());

        assert_eq!(reads(&base, &h.id, h.commit, None), as_missing(&base));
        let by_owner = reads(&base, &h.id, h.commit, Some(OWNER));
        assert_eq!(by_owner[1].as_ref().unwrap_err().0, 503, "{by_owner:?}");
        assert_eq!(by_owner[2], Ok(()));

        let lines = levcs_instance::recover_interrupted_pushes(&root);
        assert!(lines.iter().any(|l| l.contains("rolled back")), "{lines:?}");
        assert_eq!(reads(&base, &h.id, h.commit, None), as_missing(&base));
    })
    .await;
}

// Reads and pushes in flight.

fn lock_of(state: &AppState, h: &Hosted) -> Arc<tokio::sync::RwLock<()>> {
    state.repo_lock(&RepoId::parse(&h.id).unwrap())
}

const PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether `t` is still running a while after it was started: a read that
/// waits for a lock stays waiting.
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

/// A read waits for a push in flight, and answers by what that push left
/// committed. A push making a private repository public had moved `current`
/// and not committed when a read decided by it: the reviewer's anonymous
/// object read answered 200 while the transaction's record stood.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_waits_for_a_push_in_flight() {
    run_with(vec![named(OWNER)], |base, root, state| {
        use levcs_core::ref_tx::RefStore;
        let owner = key(OWNER);
        let h = host(&base, &root, &[], public(0), 0);
        let opened = successor(&owner, &h.genesis, public(1));
        store(&h).write_raw(&opened.2).unwrap();
        let refs = levcs_core::Refs::new(h.dir.join(".levcs"));
        let open = levcs_core::ref_tx::RefChange {
            name: "refs/authority/current".into(),
            expected: Some(h.genesis.0),
            new: Some(opened.0),
        };
        let read = || {
            let (base, id, obj) = (base.clone(), h.id.clone(), h.commit);
            std::thread::spawn(move || raw_get(&base, &id, &format!("objects/{obj}"), &[]).0)
        };
        let lock = lock_of(&state, &h);

        // A push that moves `current`, and is then rolled back.
        let pushing = lock.blocking_write();
        refs.begin(std::slice::from_ref(&open)).unwrap();
        RefStore::write(&refs, "refs/authority/current", opened.0).unwrap();
        let r = read();
        assert!(still_waiting(&r), "a read was answered during a push");
        RefStore::write(&refs, "refs/authority/current", h.genesis.0).unwrap();
        refs.end().unwrap();
        drop(pushing);
        assert_eq!(finished(r), 404, "read by a change that was rolled back");

        // The same push, committed.
        let pushing = lock.blocking_write();
        refs.begin(std::slice::from_ref(&open)).unwrap();
        RefStore::write(&refs, "refs/authority/current", opened.0).unwrap();
        let r = read();
        assert!(still_waiting(&r), "a read was answered during a push");
        refs.end().unwrap();
        drop(pushing);
        assert_eq!(finished(r), 200, "the committed change is in effect");
    })
    .await;
}

/// No push starts while a read is deciding who may read, or while it is
/// answering: a read that found no transaction under way cannot then find
/// `current` moved. The read is held at the file it is reading.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_push_starts_while_a_read_decides_or_answers() {
    run_with(vec![named(OWNER)], |base, root, state| {
        use std::io::Write;
        let h = host(&base, &root, &[], public(0), 0);
        let lock = lock_of(&state, &h);

        // Deciding: an anonymous read, held at `current`.
        let current = h.dir.join(".levcs/refs/authority/current");
        fifo(&current);
        let r = {
            let (base, id, obj) = (base.clone(), h.id.clone(), h.commit);
            std::thread::spawn(move || raw_get(&base, &id, &format!("objects/{obj}"), &[]).0)
        };
        let mut w = reader_at(&current);
        let blocked = lock.try_write().is_err();
        writeln!(w, "{}", h.genesis.0).unwrap();
        drop(w);
        assert_eq!(finished(r), 404);
        restore(&current, h.genesis.0.to_hex());
        assert!(blocked, "a push could start while a read decided");
        assert!(lock.try_write().is_ok());

        // Answering: a member's read of the refs, held at the branch.
        let main = h.dir.join(".levcs/refs/branches/main");
        fifo(&main);
        let r = {
            let (base, id) = (base.clone(), h.id.clone());
            std::thread::spawn(move || {
                Client::new(api(&base))
                    .with_reader(Arc::new(key(OWNER)))
                    .refs(&id)
                    .map(|r| r.branches["main"].clone())
            })
        };
        let mut w = reader_at(&main);
        let blocked = lock.try_write().is_err();
        writeln!(w, "{}", h.commit).unwrap();
        drop(w);
        assert_eq!(finished(r).unwrap(), h.commit.to_hex());
        restore(&main, h.commit.to_hex());
        assert!(blocked, "a push could start while a read answered");
    })
    .await;
}

/// A push that passed the first check while the repository was public, and
/// waited for the exclusive lock while it was made private, is answered as a
/// push to a repository that does not exist. It used to be refused by the new
/// state, naming the new current authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_rechecks_privacy_under_the_lock() {
    run_with(vec![named(OWNER)], |base, root, state| {
        let h = host(&base, &root, &[], public(1), 0);
        let closed = successor(&key(OWNER), &h.genesis, public(0));
        store(&h).write_raw(&closed.2).unwrap();
        let lock = lock_of(&state, &h);
        // A read under way: the push's first check shares the lock with it,
        // and its exclusive lock waits for the read to end.
        let reading = lock.blocking_read();
        let stranger = key(STRANGER);
        let elsewhere = genesis(&stranger, &[], public(1), 1);
        let c = commit(&stranger, elsewhere.0, "x");
        let p = {
            let (base, id, c) = (base.clone(), h.id.clone(), c.clone());
            std::thread::spawn(move || push(&base, &key(STRANGER), &id, elsewhere.0, &c))
        };
        // Once the push waits for the exclusive lock, the lock, which is
        // fair, lets no further read in ahead of it.
        let deadline = std::time::Instant::now() + PATIENCE;
        while lock.try_read().is_ok() {
            assert!(
                std::time::Instant::now() < deadline,
                "the push never waited"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // Made private meanwhile, as a push that went first leaves it.
        let refs = levcs_core::Refs::new(h.dir.join(".levcs"));
        levcs_core::ref_tx::apply(
            &refs,
            &[levcs_core::ref_tx::RefChange {
                name: "refs/authority/current".into(),
                expected: Some(h.genesis.0),
                new: Some(closed.0),
            }],
        )
        .unwrap();
        drop(reading);
        let refused = finished(p).unwrap_err();
        let missing = push(&base, &stranger, &"ab".repeat(32), elsewhere.0, &c).unwrap_err();
        assert_eq!(refused, missing);
        assert!(!refused.1.contains(&closed.0.to_hex()), "{}", refused.1);
    })
    .await;
}

/// A stranger's push to a private repository waits, like a read, for a push
/// in flight, and is answered by what that push left committed: here, as a
/// push to a repository that does not exist, once a change that would have
/// made it public is rolled back. Its first check took no lock, found the
/// uncommitted public authority, and answered a malformed push as malformed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_strangers_push_waits_for_a_push_in_flight() {
    run_with(vec![named(OWNER)], |base, root, state| {
        use levcs_core::ref_tx::RefStore;
        let h = host(&base, &root, &[], public(0), 0);
        let opened = successor(&key(OWNER), &h.genesis, public(1));
        store(&h).write_raw(&opened.2).unwrap();
        let refs = levcs_core::Refs::new(h.dir.join(".levcs"));
        let lock = lock_of(&state, &h);

        let pushing = lock.blocking_write();
        refs.begin(&[levcs_core::ref_tx::RefChange {
            name: "refs/authority/current".into(),
            expected: Some(h.genesis.0),
            new: Some(opened.0),
        }])
        .unwrap();
        RefStore::write(&refs, "refs/authority/current", opened.0).unwrap();
        let p = {
            let (base, id) = (base.clone(), h.id.clone());
            std::thread::spawn(move || raw_push(&base, &key(STRANGER), &id, b"x"))
        };
        assert!(
            still_waiting(&p),
            "a stranger's push was answered during a push"
        );
        RefStore::write(&refs, "refs/authority/current", h.genesis.0).unwrap();
        refs.end().unwrap();
        drop(pushing);
        let missing = raw_push(&base, &key(STRANGER), &"ab".repeat(32), b"x");
        assert_eq!(finished(p), missing);
    })
    .await;
}
