//! Rule P at the instance: every push is admitted against the state the
//! instance holds, never against what the request says.
//!
//! The push used to authorize against the authority the manifest named
//! (C1), check only tips, write the pack before checking anything, apply
//! a batch's refs one by one, accept any ref name, and set `current` to the
//! newest authority any tip cited.

use std::collections::HashMap;
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
    // Tests run in parallel; a timestamp alone can repeat.
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let k = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("{prefix}-{n}-{k}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

async fn start() -> (SocketAddr, tokio::task::JoinHandle<()>, PathBuf) {
    start_with(Vec::new()).await
}

async fn start_with(
    mirrors: Vec<levcs_instance::MirrorConfig>,
) -> (SocketAddr, tokio::task::JoinHandle<()>, PathBuf) {
    let root = tempdir("levcs-admission");
    let cfg = InstanceConfig {
        root: root.clone(),
        storage_mode: "full".into(),
        federation_peers: Vec::new(),
        allowed_handlers: Vec::new(),
        mirrors,
    };
    let app = router(AppState::new(cfg));
    let listener = tokio::net::TcpListener::bind::<SocketAddr>("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (addr, task, root)
}

/// Objects built for one repository, and the keys that sign them.
struct World {
    owner: SecretKey,
    objects: HashMap<ObjectId, (u8, Vec<u8>)>,
    t: i64,
}

type Auth = (ObjectId, AuthorityBody);

impl World {
    fn new() -> Self {
        World {
            owner: SecretKey::generate(),
            objects: HashMap::new(),
            t: 1_700_000_000_000_000,
        }
    }

    fn put(&mut self, kind: ObjectType, bytes: Vec<u8>) -> ObjectId {
        let id = blake3_hash(&bytes);
        self.objects.insert(id, (kind as u8, bytes));
        id
    }

    fn member(&self, key: &SecretKey, role: Role) -> MemberEntry {
        MemberEntry {
            key: key.public(),
            handle: format!("{}", key.public().0[0]),
            role,
            added_micros: self.t,
            added_by: self.owner.public(),
        }
    }

    fn genesis(&mut self, others: &[(&SecretKey, Role)], policy: Vec<PolicyEntry>) -> Auth {
        let mut members = vec![self.member(&self.owner, Role::Owner)];
        members.extend(others.iter().map(|(k, r)| self.member(k, *r)));
        let mut body = AuthorityBody {
            schema_version: 1,
            repo_id: ZERO_ID,
            previous_authority: ZERO_ID,
            version: 1,
            created_micros: self.t,
            members,
            policy,
        };
        body.normalize().unwrap();
        body.assign_genesis_repo_id().unwrap();
        let s = sign_authority(&body, &self.owner).unwrap();
        (self.put(ObjectType::Authority, s.serialize()), body)
    }

    fn successor(&mut self, prev: &Auth, others: &[(&SecretKey, Role)]) -> Auth {
        let mut body = prev.1.clone();
        body.previous_authority = prev.0;
        body.version += 1;
        body.created_micros += 1;
        body.members = vec![self.member(&self.owner, Role::Owner)];
        body.members
            .extend(others.iter().map(|(k, r)| self.member(k, *r)));
        body.normalize().unwrap();
        let s = sign_authority(&body, &self.owner).unwrap();
        (self.put(ObjectType::Authority, s.serialize()), body)
    }

    fn tree(&mut self, entries: Vec<(&str, EntryType, ObjectId)>) -> ObjectId {
        let mut t = Tree {
            entries: entries
                .into_iter()
                .map(|(n, e, h)| TreeEntry {
                    name: n.into(),
                    entry_type: e,
                    mode: FileMode::REGULAR,
                    hash: h,
                })
                .collect(),
        };
        t.sort_and_validate().unwrap();
        self.put(ObjectType::Tree, t.serialize())
    }

    fn file_tree(&mut self, text: &str) -> ObjectId {
        let b = self.put(
            ObjectType::Blob,
            Blob::new(text.as_bytes().to_vec()).serialize(),
        );
        self.tree(vec![("a.txt", EntryType::Blob, b)])
    }

    fn commit_with(
        &mut self,
        cites: ObjectId,
        parents: &[ObjectId],
        by: &SecretKey,
        tree: ObjectId,
        flags: CommitFlags,
    ) -> ObjectId {
        self.t += 1;
        let c = Commit {
            tree,
            parents: parents.to_vec(),
            authority: cites,
            author_key: by.public().0,
            timestamp_micros: self.t,
            flags,
            message: format!("c{}", self.t),
        };
        let s = sign_commit(c, by).unwrap();
        self.put(ObjectType::Commit, s.serialize())
    }

    fn commit(&mut self, cites: ObjectId, parents: &[ObjectId], by: &SecretKey) -> ObjectId {
        let text = format!("{}", self.t);
        let tree = self.file_tree(&text);
        self.commit_with(cites, parents, by, tree, CommitFlags::NONE)
    }

    /// A commit citing `cites` and installing `new` at `.levcs/authority`.
    fn boundary(&mut self, cites: ObjectId, parents: &[ObjectId], new: ObjectId) -> ObjectId {
        let inner = self.tree(vec![("authority", EntryType::Blob, new)]);
        let root = self.tree(vec![(".levcs", EntryType::Tree, inner)]);
        let owner = SecretKey::from_seed(*self.owner.seed());
        self.commit_with(
            cites,
            parents,
            &owner,
            root,
            CommitFlags::MODIFIES_AUTHORITY,
        )
    }

    fn pack(&self, except: &[ObjectId]) -> Pack {
        let mut p = Pack::new();
        for (id, (kind, bytes)) in &self.objects {
            if !except.contains(id) {
                p.push(*kind, bytes.clone());
            }
        }
        p
    }
}

struct Repo {
    base: String,
    repo_id: String,
    dir: PathBuf,
}

impl Repo {
    fn client(&self) -> Client {
        Client::new(self.base.clone())
    }
    fn read(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.dir.join(".levcs").join(name))
            .ok()
            .map(|s| s.trim().to_string())
    }
    fn stored(&self, id: ObjectId) -> bool {
        let h = id.to_hex();
        self.dir
            .join(".levcs/objects")
            .join(&h[..2])
            .join(&h[2..])
            .exists()
    }
    fn push(
        &self,
        w: &World,
        by: &SecretKey,
        authority: ObjectId,
        updates: &[(&str, Option<ObjectId>, ObjectId)],
        except: &[ObjectId],
    ) -> Result<(), (u16, String)> {
        let manifest = PushManifest {
            authority_hash: authority.to_hex(),
            updates: updates
                .iter()
                .map(|(r, old, new)| PushUpdate {
                    r#ref: r.to_string(),
                    old_hash: old.map(|o| o.to_hex()),
                    new_hash: new.to_hex(),
                })
                .collect(),
            timestamp: 0,
            force: false,
        };
        match self
            .client()
            .push(by, &self.repo_id, &w.pack(except), &manifest)
        {
            Ok(()) => Ok(()),
            Err(ClientError::Server { status, body }) => Err((status, body)),
            Err(e) => panic!("{e:?}"),
        }
    }
}

fn init(base: String, root: &std::path::Path, w: &World, genesis: &Auth) -> Repo {
    let repo_id = genesis.1.repo_id.to_hex();
    let owner = SecretKey::from_seed(*w.owner.seed());
    Client::new(base.clone())
        .init(&owner, &repo_id, &w.objects[&genesis.0].1)
        .unwrap();
    Repo {
        base,
        dir: root.join(&repo_id),
        repo_id,
    }
}

const MAIN: &str = "refs/branches/main";

fn expect(r: Result<(), (u16, String)>, status: u16, needle: &str) {
    match r {
        Ok(()) => panic!("accepted; expected {status} mentioning {needle:?}"),
        Err((s, body)) => {
            assert_eq!(s, status, "{body}");
            assert!(body.contains(needle), "expected {needle:?} in: {body}");
        }
    }
}

async fn run(f: impl FnOnce(String, PathBuf) + Send + 'static) {
    let (addr, task, root) = start().await;
    let base = format!("http://{addr}/levcs/v1");
    let r = root.clone();
    tokio::task::spawn_blocking(move || f(base, r))
        .await
        .unwrap();
    task.abort();
    let _ = std::fs::remove_dir_all(root);
}

/// C1: the manifest's authority authorizes nothing. A revoked contributor
/// naming the authority that still lists them is refused, and `current`
/// stays where the boundary put it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_authority_a_push_names_authorizes_nothing() {
    run(|base, root| {
        let mut w = World::new();
        let x = SecretKey::generate();
        let v1 = w.genesis(&[(&x, Role::Contributor)], vec![]);
        let repo = init(base, &root, &w, &v1);
        let owner = SecretKey::from_seed(*w.owner.seed());
        let c1 = w.commit(v1.0, &[], &owner);
        repo.push(&w, &owner, v1.0, &[(MAIN, None, c1)], &[])
            .unwrap();

        let v2 = w.successor(&v1, &[]);
        let b = w.boundary(v1.0, &[c1], v2.0);
        repo.push(&w, &owner, v2.0, &[(MAIN, Some(c1), b)], &[])
            .unwrap();
        assert_eq!(repo.read("refs/authority/current"), Some(v2.0.to_hex()));

        let by_x = w.commit(v1.0, &[c1], &x);
        let x_branch = "refs/branches/x";
        expect(
            repo.push(&w, &x, v1.0, &[(x_branch, None, by_x)], &[]),
            409,
            "made under authority",
        );
        expect(
            repo.push(&w, &x, v2.0, &[(x_branch, None, by_x)], &[]),
            403,
            "is not a member",
        );
        assert_eq!(repo.read("refs/authority/current"), Some(v2.0.to_hex()));
        assert_eq!(repo.read(x_branch), None);
        assert!(!repo.stored(by_x), "a refused push stored its objects");
    })
    .await;
}

/// The boundary moves `current`, by itself; work citing the successor
/// waits for a later push.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_boundary_moves_current_and_successor_work_waits() {
    run(|base, root| {
        let mut w = World::new();
        let v1 = w.genesis(&[], vec![]);
        let repo = init(base, &root, &w, &v1);
        let owner = SecretKey::from_seed(*w.owner.seed());
        let c1 = w.commit(v1.0, &[], &owner);
        repo.push(&w, &owner, v1.0, &[(MAIN, None, c1)], &[])
            .unwrap();

        let y = SecretKey::generate();
        let v2 = w.successor(&v1, &[(&y, Role::Contributor)]);
        let b = w.boundary(v1.0, &[c1], v2.0);
        let by_y = w.commit(v2.0, &[b], &y);
        expect(
            repo.push(&w, &owner, v2.0, &[(MAIN, Some(c1), by_y)], &[]),
            403,
            &format!("commit {by_y}: cites authority {}", v2.0),
        );
        assert_eq!(repo.read(MAIN), Some(c1.to_hex()));
        assert_eq!(repo.read("refs/authority/current"), Some(v1.0.to_hex()));

        // A boundary pushed without moving current is refused too.
        expect(
            repo.push(&w, &owner, v1.0, &[(MAIN, Some(c1), b)], &[]),
            403,
            "does not move current with it",
        );

        repo.push(&w, &owner, v2.0, &[(MAIN, Some(c1), b)], &[])
            .unwrap();
        assert_eq!(repo.read("refs/authority/current"), Some(v2.0.to_hex()));
        repo.push(&w, &y, v2.0, &[(MAIN, Some(b), by_y)], &[])
            .unwrap();
        assert_eq!(repo.read(MAIN), Some(by_y.to_hex()));
    })
    .await;
}

/// A batch is admitted or refused whole: no ref moves when one fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_batch_moves_no_ref() {
    run(|base, root| {
        let mut w = World::new();
        let v1 = w.genesis(&[], vec![]);
        let repo = init(base, &root, &w, &v1);
        let owner = SecretKey::from_seed(*w.owner.seed());
        let c1 = w.commit(v1.0, &[], &owner);
        repo.push(&w, &owner, v1.0, &[(MAIN, None, c1)], &[])
            .unwrap();
        let fine = w.commit(v1.0, &[c1], &owner);
        let rewrite = w.commit(v1.0, &[], &owner);
        expect(
            repo.push(
                &w,
                &owner,
                v1.0,
                &[
                    ("refs/branches/fine", None, fine),
                    (MAIN, Some(c1), rewrite),
                ],
                &[],
            ),
            409,
            "non-fast-forward",
        );
        assert_eq!(repo.read("refs/branches/fine"), None);
        assert_eq!(repo.read(MAIN), Some(c1.to_hex()));
    })
    .await;
}

/// Only branches and releases can be pushed; `current` moves only with a
/// boundary, and the genesis never.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authority_refs_cannot_be_pushed() {
    run(|base, root| {
        let mut w = World::new();
        let v1 = w.genesis(&[], vec![]);
        let repo = init(base, &root, &w, &v1);
        let owner = SecretKey::from_seed(*w.owner.seed());
        let c1 = w.commit(v1.0, &[], &owner);
        for name in ["refs/authority/genesis", "refs/authority/current", "HEAD"] {
            expect(
                repo.push(&w, &owner, v1.0, &[(name, None, c1)], &[]),
                403,
                "cannot be published",
            );
        }
        assert_eq!(repo.read("refs/authority/genesis"), Some(v1.0.to_hex()));
        assert_eq!(repo.read("refs/authority/current"), Some(v1.0.to_hex()));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_contributor_cannot_push_a_protected_branch() {
    run(|base, root| {
        let mut w = World::new();
        let x = SecretKey::generate();
        let policy = vec![PolicyEntry {
            key: "protected_branches".into(),
            value: b"main".to_vec(),
        }];
        let v1 = w.genesis(&[(&x, Role::Contributor)], policy);
        let repo = init(base, &root, &w, &v1);
        let c1 = w.commit(v1.0, &[], &x);
        expect(
            repo.push(&w, &x, v1.0, &[(MAIN, None, c1)], &[]),
            403,
            "is protected",
        );
        repo.push(&w, &x, v1.0, &[("refs/branches/topic", None, c1)], &[])
            .unwrap();
    })
    .await;
}

/// History that is not all there is refused, and nothing is stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn incomplete_history_is_refused_and_nothing_stored() {
    run(|base, root| {
        let mut w = World::new();
        let v1 = w.genesis(&[], vec![]);
        let repo = init(base, &root, &w, &v1);
        let owner = SecretKey::from_seed(*w.owner.seed());
        let tree = w.file_tree("withheld");
        let c1 = w.commit_with(v1.0, &[], &owner, tree, CommitFlags::NONE);
        expect(
            repo.push(&w, &owner, v1.0, &[(MAIN, None, c1)], &[tree]),
            403,
            "cannot be read",
        );
        assert_eq!(repo.read(MAIN), None);
        assert!(!repo.stored(c1));
    })
    .await;
}

/// Creating a repository publishes its genesis: an owner of it only.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn init_needs_an_owner_of_the_genesis() {
    run(|base, root| {
        let mut w = World::new();
        let x = SecretKey::generate();
        let v1 = w.genesis(&[(&x, Role::Maintainer)], vec![]);
        let repo_id = v1.1.repo_id.to_hex();
        match Client::new(base).init(&x, &repo_id, &w.objects[&v1.0].1) {
            Err(ClientError::Server { status, body }) => {
                assert_eq!(status, 403, "{body}");
                assert!(body.contains("not an owner"), "{body}");
            }
            other => panic!("init by a maintainer: {other:?}"),
        }
        assert!(!root.join(&repo_id).exists());
    })
    .await;
}

/// A mirror's refs are records of its source (Rule R.4). Writeback, which
/// was to forward a push to the source, is not implemented, and a push was
/// applied over the records instead. Every push to a mirror is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mirror_refuses_pushes_even_with_writeback() {
    let mut w = World::new();
    let v1 = w.genesis(&[], vec![]);
    let repo_id = v1.1.repo_id.to_hex();
    let mirror = levcs_instance::MirrorConfig {
        repo_id: repo_id.clone(),
        source: "http://127.0.0.1:9/levcs/v1".into(),
        mode: "full".into(),
        writeback: true,
        poll_interval: "60s".into(),
    };
    let (addr, task, root) = start_with(vec![mirror]).await;
    let base = format!("http://{addr}/levcs/v1");
    let r = root.clone();
    tokio::task::spawn_blocking(move || {
        let repo = init(base, &r, &w, &v1);
        let owner = SecretKey::from_seed(*w.owner.seed());
        let c1 = w.commit(v1.0, &[], &owner);
        expect(
            repo.push(&w, &owner, v1.0, &[(MAIN, None, c1)], &[]),
            403,
            "push to the source instead",
        );
        assert_eq!(repo.read(MAIN), None);
    })
    .await
    .unwrap();
    task.abort();
    let _ = std::fs::remove_dir_all(root);
}

/// A push killed part way leaves its record (`levcs_core::ref_tx`). Its
/// refs are not served while it stands; recovery at startup, or at the
/// next push, rolls it back first.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_killed_part_way_is_rolled_back() {
    run(|base, root| {
        let mut w = World::new();
        let v1 = w.genesis(&[], vec![]);
        let repo = init(base.clone(), &root, &w, &v1);
        let owner = SecretKey::from_seed(*w.owner.seed());
        let c1 = w.commit(v1.0, &[], &owner);
        repo.push(&w, &owner, v1.0, &[(MAIN, None, c1)], &[])
            .unwrap();

        // As a kill leaves it: the record written, main moved, current not.
        let levcs = repo.dir.join(".levcs");
        let killed = || {
            std::fs::create_dir_all(levcs.join("ref-transaction")).unwrap();
            std::fs::write(
                levcs.join("ref-transaction/record"),
                format!(
                    "levcs ref transaction 1\n{MAIN}\t{c1}\t{}\nrefs/authority/current\t{}\t{}\n",
                    "ab".repeat(32),
                    v1.0,
                    "cd".repeat(32)
                ),
            )
            .unwrap();
            std::fs::write(
                levcs.join("refs/branches/main"),
                format!("{}\n", "ab".repeat(32)),
            )
            .unwrap();
        };
        killed();
        match repo.client().refs(&repo.repo_id) {
            Err(ClientError::Server { status, .. }) => assert_eq!(status, 503),
            other => panic!("refs served over an interrupted push: {other:?}"),
        }
        let lines = levcs_instance::recover_interrupted_pushes(&root);
        assert!(lines.iter().any(|l| l.contains("rolled back")), "{lines:?}");
        assert_eq!(repo.read(MAIN), Some(c1.to_hex()));
        assert!(!levcs.join("ref-transaction/record").exists());

        killed();
        let c2 = w.commit(v1.0, &[c1], &owner);
        repo.push(&w, &owner, v1.0, &[(MAIN, Some(c1), c2)], &[])
            .unwrap();
        assert_eq!(repo.read(MAIN), Some(c2.to_hex()));
        assert_eq!(repo.read("refs/authority/current"), Some(v1.0.to_hex()));
    })
    .await;
}
