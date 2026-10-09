//! `levcs clone` and `levcs pull` against an instance (Rule R).
//!
//! - **What is received is checked before it is written.** `clone`, `pull`
//!   and `fork` hold what an instance sends and check all of it, against
//!   the genesis the repository's id pins, by `levcs verify`'s walk. A
//!   transfer that fails writes nothing. `pull` used to record refs to
//!   objects it never received (audit H3), and there was no `clone`.
//! - **A clone is a workspace of its instance.** It holds the instance's
//!   branches, releases and authority, and work in it is pushed there.
//! - **Deep trees.** Every walk of a tree on this side used to recurse
//!   once per directory, so a received tree nested deeper than the stack
//!   aborted the client. The walks here run `levcs` on a small stack.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

use levcs_core::refs::Head;
use levcs_core::{
    blake3_hash, Blob, Commit, CommitFlags, EntryType, FileMode, ObjectId, Repository, Tree,
    TreeEntry, ZERO_ID,
};
use levcs_identity::authority::{
    AuthorityBody, MemberEntry, PolicyEntry, Role, AUTHORITY_SCHEMA_VERSION,
};
use levcs_identity::keychain::Keychain;
use levcs_identity::keys::SecretKey;
use levcs_identity::sign::{sign_authority, sign_commit};
use levcs_instance::{router, AppState, InstanceConfig, Limits};

fn tempdir(prefix: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// The main thread's stack for `levcs` in the deep-tree tests, 512 KiB.
/// `levcs` needs about 300 KiB with nothing deep, in a debug build; a walk
/// that recursed once per directory of [`DEEP`] needs more than this.
const SMALL_STACK: &str = "-s 512";

/// Address space for `levcs` where a tree names more than memory holds,
/// 256 MiB: what it takes is refused before it is held.
const SMALL_MEMORY: &str = "-v 262144";

/// `levcs args` in `cwd`, under the keychain in `xdg`; under `ulimit
/// limits` when given.
fn levcs(cwd: &Path, xdg: &Path, limits: Option<&str>, args: &[&str]) -> (ExitStatus, String) {
    let mut cmd = match limits {
        Some(limits) => {
            let mut c = Command::new("sh");
            c.arg("-c")
                .arg(format!("ulimit {limits} && exec \"$0\" \"$@\""))
                .arg(env!("CARGO_BIN_EXE_levcs"));
            c
        }
        None => Command::new(env!("CARGO_BIN_EXE_levcs")),
    };
    let out = cmd
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .unwrap();
    (
        out.status,
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// A working repository, and the keychain alice's key is in.
struct Local {
    work: PathBuf,
    xdg: PathBuf,
    limits: Option<&'static str>,
}

impl Local {
    fn new(tag: &str) -> Local {
        let base = tempdir(&format!("levcs-clone-{tag}"));
        let l = Local {
            work: base.join("w"),
            xdg: base.join("cfg"),
            limits: None,
        };
        std::fs::create_dir_all(&l.work).unwrap();
        l.ok(&["init", "--key", "alice"]);
        l
    }

    /// The working repository at `work`, under this keychain.
    fn at(&self, work: PathBuf) -> Local {
        Local {
            work,
            xdg: self.xdg.clone(),
            limits: self.limits,
        }
    }

    fn run(&self, args: &[&str]) -> (ExitStatus, String) {
        levcs(&self.work, &self.xdg, self.limits, args)
    }

    fn ok(&self, args: &[&str]) -> String {
        let (status, out) = self.run(args);
        assert!(status.success(), "{args:?}: {status}: {out}");
        out
    }

    fn refused(&self, args: &[&str]) -> String {
        let (status, out) = self.run(args);
        assert_eq!(status.code(), Some(1), "{args:?}: {status}: {out}");
        out
    }

    fn commit(&self, file: &str, bytes: &[u8]) {
        let path = self.work.join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
        self.ok(&["track", file]);
        self.ok(&["commit", "-m", file]);
    }

    fn levcs(&self, rel: &str) -> PathBuf {
        self.work.join(".levcs").join(rel)
    }

    fn read(&self, rel: &str) -> Option<String> {
        std::fs::read_to_string(self.levcs(rel))
            .ok()
            .map(|s| s.trim().to_string())
    }

    fn main(&self) -> String {
        self.read("refs/branches/main").unwrap()
    }

    fn alice(&self) -> String {
        self.ok(&["key", "show", "alice"]).trim().to_string()
    }

    fn alice_secret(&self) -> SecretKey {
        Keychain::load_or_default(&self.xdg.join("levcs/keys.toml"))
            .unwrap()
            .secret("alice", || panic!("alice's key is not encrypted"))
            .unwrap()
    }

    fn repo(&self) -> Repository {
        Repository::discover(&self.work).unwrap()
    }
}

/// A repository made with the library rather than `levcs init`, owned by
/// alice, public or not, whose main holds one commit of `tree(repo)`.
fn made(
    keys: &Local,
    tag: &str,
    public: bool,
    tree: impl FnOnce(&Repository) -> ObjectId,
) -> Local {
    let work = tempdir(&format!("levcs-clone-{tag}")).join("w");
    let sk = keys.alice_secret();
    let pk = sk.public();
    let repo = Repository::init_skeleton(&work).unwrap();
    let mut body = AuthorityBody {
        schema_version: AUTHORITY_SCHEMA_VERSION,
        repo_id: ZERO_ID,
        previous_authority: ZERO_ID,
        version: 1,
        created_micros: 1,
        members: vec![MemberEntry {
            key: pk,
            handle: "alice".into(),
            role: Role::Owner,
            added_micros: 1,
            added_by: pk,
        }],
        policy: vec![PolicyEntry {
            key: "public_read".into(),
            value: vec![public as u8],
        }],
    };
    body.normalize().unwrap();
    body.assign_genesis_repo_id().unwrap();
    let genesis = repo
        .write_signed(&sign_authority(&body, &sk).unwrap())
        .unwrap();
    repo.set_genesis_authority(genesis).unwrap();
    repo.set_current_authority(genesis).unwrap();
    let commit = Commit {
        tree: tree(&repo),
        parents: Vec::new(),
        authority: genesis,
        author_key: pk.0,
        timestamp_micros: 2,
        flags: CommitFlags::NONE,
        message: tag.into(),
    };
    let id = repo
        .write_signed(&sign_commit(commit, &sk).unwrap())
        .unwrap();
    repo.refs.write("refs/branches/main", id).unwrap();
    repo.refs
        .write_head(&Head::Branch("refs/branches/main".into()))
        .unwrap();
    keys.at(work)
}

/// A tree holding `bytes` at `name/name/…/f`, `depth` directories down,
/// and a file `top.txt` at its root.
fn deep(repo: &Repository, name: &str, depth: usize, bytes: &[u8]) -> ObjectId {
    let blob = |b: &[u8]| {
        repo.objects
            .write_raw(&Blob::new(b.to_vec()).serialize())
            .unwrap()
    };
    let tree = |entries: Vec<TreeEntry>| {
        let mut t = Tree::new();
        t.entries = entries;
        t.sort_and_validate().unwrap();
        repo.objects.write_raw(&t.serialize()).unwrap()
    };
    let mut entry = TreeEntry {
        name: "f".into(),
        entry_type: EntryType::Blob,
        mode: FileMode::REGULAR,
        hash: blob(bytes),
    };
    for _ in 0..depth {
        entry = TreeEntry {
            name: name.into(),
            entry_type: EntryType::Tree,
            mode: FileMode::REGULAR,
            hash: tree(vec![entry]),
        };
    }
    let top = TreeEntry {
        name: "top.txt".into(),
        entry_type: EntryType::Blob,
        mode: FileMode::REGULAR,
        hash: blob(b"top\n"),
    };
    tree(vec![entry, top])
}

/// A tree whose one subtree recurs under both `a` and `b` at each of
/// `levels` levels, down to `bytes` at `f`: 2^levels files from `levels`
/// + 4 objects, under `d/`, beside `top.txt`.
fn recurring(repo: &Repository, levels: usize, bytes: &[u8]) -> ObjectId {
    let blob = |b: &[u8]| {
        repo.objects
            .write_raw(&Blob::new(b.to_vec()).serialize())
            .unwrap()
    };
    let tree = |entries: Vec<(&str, EntryType, ObjectId)>| {
        let mut t = Tree::new();
        t.entries = entries
            .into_iter()
            .map(|(name, entry_type, hash)| TreeEntry {
                name: name.into(),
                entry_type,
                mode: FileMode::REGULAR,
                hash,
            })
            .collect();
        t.sort_and_validate().unwrap();
        repo.objects.write_raw(&t.serialize()).unwrap()
    };
    let mut id = tree(vec![("f", EntryType::Blob, blob(bytes))]);
    for _ in 0..levels {
        id = tree(vec![("a", EntryType::Tree, id), ("b", EntryType::Tree, id)]);
    }
    tree(vec![
        ("d", EntryType::Tree, id),
        ("top.txt", EntryType::Blob, blob(b"top\n")),
    ])
}

/// An instance on which alice may create repositories.
struct Instance {
    base: String,
    root: PathBuf,
    _rt: tokio::runtime::Runtime,
}

impl Instance {
    fn start(alice: String) -> Instance {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let root = tempdir("levcs-clone-instance");
        let config = InstanceConfig {
            root: root.clone(),
            storage_mode: "full".into(),
            federation_peers: Vec::new(),
            allowed_handlers: Vec::new(),
            mirrors: Vec::new(),
            creators: vec![alice],
            limits: Limits::default(),
        };
        let app = router(AppState::new(config));
        let addr: SocketAddr = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.ok();
            });
            addr
        });
        Instance {
            base: format!("http://{addr}/levcs/v1"),
            root,
            _rt: rt,
        }
    }

    /// The id of the one repository it holds.
    fn repo_id(&self) -> String {
        let repos: Vec<_> = std::fs::read_dir(&self.root)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(repos.len(), 1, "{repos:?}");
        repos[0].clone()
    }

    fn main(&self) -> String {
        std::fs::read_to_string(
            self.root
                .join(self.repo_id())
                .join(".levcs/refs/branches/main"),
        )
        .unwrap()
        .trim()
        .to_string()
    }
}

/// A fake instance: answers each expected request, in order.
fn fake_instance(responses: Vec<(&'static str, Vec<u8>)>) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{BufRead, BufReader, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        for (expected, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(
                line.contains(expected),
                "request {line:?}, wanted {expected}"
            );
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
            }
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\
                 Content-Type: application/json\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
        }
    });
    (url, handle)
}

/// A clone holds what the instance publishes: its files, branches,
/// releases and authority, every object checked. It is a workspace of the
/// instance, so work in it is pushed there, and a pull elsewhere records
/// that work, checked, as the instance's state.
#[test]
fn a_clone_holds_what_the_instance_publishes() {
    let a = Local::new("source");
    a.commit("a.txt", b"one\n");
    a.commit("src/nested/b.txt", b"two\n");
    let i = Instance::start(a.alice());
    a.ok(&["instance", "--set", &i.base]);
    a.ok(&["push"]);
    a.ok(&["release", "v1"]);
    a.ok(&["push", "refs/releases/v1"]);
    a.commit("a.txt", b"three\n");
    a.ok(&["push"]);

    let parent = tempdir("levcs-clone-into");
    let (status, out) = levcs(
        &parent,
        &a.xdg,
        None,
        &["clone", &i.repo_id(), "b", "--from", &i.base],
    );
    assert!(status.success(), "{out}");
    let b = a.at(parent.join("b"));
    assert_eq!(
        std::fs::read_to_string(b.work.join("a.txt")).unwrap(),
        "three\n"
    );
    assert_eq!(
        std::fs::read_to_string(b.work.join("src/nested/b.txt")).unwrap(),
        "two\n"
    );
    for r in [
        "refs/branches/main",
        "refs/releases/v1",
        "refs/authority/genesis",
        "refs/authority/current",
    ] {
        assert_eq!(b.read(r), a.read(r), "{r}");
    }
    assert_eq!(
        b.read("refs/remote/origin/branches/main"),
        a.read("refs/branches/main")
    );
    assert_eq!(
        b.read("refs/remote/origin/releases/v1"),
        a.read("refs/releases/v1")
    );
    assert_eq!(b.read("HEAD"), a.read("HEAD"));
    assert!(b.read("config").unwrap().contains(&i.base));
    assert!(b.ok(&["status"]).contains("working tree clean"));
    b.ok(&["verify"]);

    b.commit("c.txt", b"four\n");
    b.ok(&["push"]);
    assert_eq!(i.main(), b.main());

    let before = a.main();
    a.ok(&["pull"]);
    assert_eq!(a.read("refs/remote/origin/branches/main"), Some(b.main()));
    assert_eq!(a.main(), before, "a pull moved a branch");
    a.ok(&["verify"]);
}

/// A private repository is cloned by a member, in reads signed with
/// `--key`, and by no one else: to anyone else it is a repository that
/// does not exist.
#[test]
fn a_private_repository_is_cloned_only_by_a_member() {
    let keys = Local::new("keys");
    let p = made(&keys, "private", false, |r| deep(r, "x", 0, b"kept\n"));
    let i = Instance::start(keys.alice());
    p.ok(&["instance", "--set", &i.base]);
    p.ok(&["push"]);

    let parent = tempdir("levcs-clone-private");
    let id = i.repo_id();
    let (status, out) = levcs(
        &parent,
        &keys.xdg,
        None,
        &["clone", &id, "anyone", "--from", &i.base],
    );
    assert!(!status.success(), "{out}");
    assert!(
        out.contains("or none it lets this reader see (a private repository is read with --key)"),
        "{out}"
    );
    assert!(!parent.join("anyone").exists());

    let (status, out) = levcs(
        &parent,
        &keys.xdg,
        None,
        &["clone", &id, "member", "--from", &i.base, "--key", "alice"],
    );
    assert!(status.success(), "{out}");
    assert_eq!(
        std::fs::read_to_string(parent.join("member/f")).unwrap(),
        "kept\n"
    );
}

/// What an instance sends that does not verify is refused, and nothing of
/// it is written: not by a clone, not by a pull. The cases: a tip whose
/// signature is invalid; a history missing an object; a ref to an object
/// never sent (the audit's probe for pull); a genesis that is not the one
/// the asked-for id pins; this repository's own damaged copy of an object
/// it is sent. And what verifies is kept only as far as the refs reach it.
#[test]
fn received_history_that_does_not_verify_writes_nothing() {
    let a = Local::new("refused");
    a.commit("a.txt", b"one\n");
    let repo = a.repo();
    let tip = repo.refs.resolve_head().unwrap().unwrap();
    let genesis = repo.genesis_authority().unwrap().unwrap();
    let current = repo.current_authority().unwrap().unwrap();
    let repo_id = AuthorityBody::parse(&repo.read_signed(genesis).unwrap().body)
        .unwrap()
        .repo_id
        .to_hex();
    let mut all = levcs_protocol::Pack::new();
    for id in repo.objects.iter_ids().unwrap() {
        let bytes = repo.objects.read_raw(id).unwrap();
        all.push(bytes[4], bytes);
    }
    // The tip with its signature zeroed: another object, never written here.
    let mut child = repo.read_signed(tip).unwrap();
    child.signatures[0].signature = [0; 64];
    let forged = child.serialize();
    let forged_id = blake3_hash(&forged);
    let mut with_forged = all.clone();
    with_forged.push(forged[4], forged.clone());
    // The history without the blob a.txt holds.
    let blob = repo
        .lookup_path(
            Commit::from_signed(&repo.read_signed(tip).unwrap())
                .unwrap()
                .tree,
            "a.txt",
        )
        .unwrap()
        .unwrap()
        .1;
    let mut without_blob = levcs_protocol::Pack::new();
    for e in &all.entries {
        if blake3_hash(&e.bytes) != blob {
            without_blob.push(e.bytes[4], e.bytes.clone());
        }
    }
    let never_sent = ObjectId([0xab; 32]);
    let other_id = "cd".repeat(32);
    let info = |id: &str, main: ObjectId| {
        serde_json::to_vec(&serde_json::json!({
            "repo_id": id, "genesis_authority": genesis.to_hex(),
            "current_authority": current.to_hex(), "branches": {"main": main.to_hex()},
        }))
        .unwrap()
    };
    let cases = [
        (
            repo_id.as_str(),
            forged_id,
            &with_forged,
            format!("invalid {forged_id}: signature is invalid"),
        ),
        (
            repo_id.as_str(),
            tip,
            &without_blob,
            format!("damaged {blob}: cannot be read"),
        ),
        (
            repo_id.as_str(),
            never_sent,
            &all,
            format!("damaged {never_sent}: cannot be read"),
        ),
        (
            other_id.as_str(),
            tip,
            &all,
            format!("is repository {repo_id}, not {other_id}"),
        ),
    ];
    let parent = tempdir("levcs-clone-refused");
    // An answer for another repository is refused before anything is sent.
    let (url, server) = fake_instance(vec![("/info", info(&"ef".repeat(32), tip))]);
    let (status, out) = levcs(
        &parent,
        &a.xdg,
        None,
        &["clone", &repo_id, "b", "--from", &url],
    );
    server.join().unwrap();
    assert_eq!(status.code(), Some(1), "{out}");
    assert!(out.contains("and it answered for"), "{out}");
    assert!(!parent.join("b").exists());
    for (id, main, pack, refusal) in &cases {
        let (url, server) =
            fake_instance(vec![("/info", info(id, *main)), ("/pack?", pack.encode())]);
        let (status, out) = levcs(&parent, &a.xdg, None, &["clone", id, "b", "--from", &url]);
        server.join().unwrap();
        assert_eq!(status.code(), Some(1), "{out}");
        assert!(out.contains(refusal.as_str()), "{refusal}: {out}");
        assert!(out.contains("nothing"), "{out}");
        assert!(!parent.join("b").exists(), "a refused clone left {out}");
    }
    // What the refs do not reach is not kept, though it was sent.
    let stray = Blob::new(b"sent, reached by nothing\n".to_vec()).serialize();
    let mut with_stray = all.clone();
    with_stray.push(stray[4], stray.clone());
    let (url, server) = fake_instance(vec![
        ("/info", info(&repo_id, tip)),
        ("/pack?", with_stray.encode()),
    ]);
    let (status, out) = levcs(
        &parent,
        &a.xdg,
        None,
        &["clone", &repo_id, "b", "--from", &url],
    );
    server.join().unwrap();
    assert!(status.success(), "{out}");
    let b = Repository::discover(parent.join("b")).unwrap();
    assert!(b.objects.contains(tip));
    assert!(
        !b.objects.contains(blake3_hash(&stray)),
        "a stray object was kept"
    );

    // A pull over this repository's own damaged copy of an object it is
    // sent is refused: the store keeps the copy it has, so a sound one sent
    // would not replace it.
    let b2 = a.at(tempdir("levcs-clone-damaged").join("w"));
    assert!(Command::new("cp")
        .arg("-a")
        .arg(&a.work)
        .arg(&b2.work)
        .status()
        .unwrap()
        .success());
    b2.commit("b.txt", b"sound\n");
    let (b2_tip, b2_blob) = {
        let r = b2.repo();
        let tip = r.refs.resolve_head().unwrap().unwrap();
        let tree = Commit::from_signed(&r.read_signed(tip).unwrap())
            .unwrap()
            .tree;
        (tip, r.lookup_path(tree, "b.txt").unwrap().unwrap().1)
    };
    let mut b2_pack = levcs_protocol::Pack::new();
    for id in b2.repo().objects.iter_ids().unwrap() {
        let bytes = b2.repo().objects.read_raw(id).unwrap();
        b2_pack.push(bytes[4], bytes);
    }
    let damaged = repo.objects.path_for(b2_blob);
    std::fs::create_dir_all(damaged.parent().unwrap()).unwrap();
    std::fs::write(&damaged, b"damaged").unwrap();
    let (url, server) = fake_instance(vec![
        ("/info", info(&repo_id, b2_tip)),
        ("/pack?", b2_pack.encode()),
    ]);
    a.ok(&["instance", "--set", &url]);
    let out = a.refused(&["pull"]);
    server.join().unwrap();
    assert!(
        out.contains(&format!("damaged {b2_blob} (this repository's own copy)")),
        "{out}"
    );
    assert_eq!(a.read("refs/remote/origin/branches/main"), None, "{out}");
    std::fs::remove_file(&damaged).unwrap();

    // A pull, in a repository whose own genesis is the pin. It holds the
    // blob already, so a history missing it is complete here.
    for (id, main, pack, refusal) in [&cases[0], &cases[2]] {
        let (url, server) =
            fake_instance(vec![("/info", info(id, *main)), ("/pack?", pack.encode())]);
        a.ok(&["instance", "--set", &url]);
        let out = a.refused(&["pull"]);
        server.join().unwrap();
        assert!(out.contains(refusal.as_str()), "{refusal}: {out}");
        assert_eq!(a.read("refs/remote/origin/branches/main"), None, "{out}");
        assert!(!a.repo().objects.contains(forged_id));
    }
}

/// How deep [`deep_trees_are_received_and_worked_on_without_recursion`]
/// nests its file. Every tree is written, durably, three times (made,
/// pushed, cloned), so no deeper than recursion needs to be caught.
const DEEP: usize = 1000;

/// A tree [`DEEP`] directories deep is cloned, read, committed over (in
/// full and in part), switched from, merged and cached, each by `levcs` on a stack that a walk
/// recursing once per directory overflows. A tree whose path is longer
/// than a working tree may hold is refused, as an error, and the clone
/// leaves nothing behind.
#[test]
fn deep_trees_are_received_and_worked_on_without_recursion() {
    let keys = Local::new("deep-keys");
    let d = made(&keys, "deep", true, |r| deep(r, "x", DEEP, b"deep\n"));
    // 21 directories of 200-byte names: a path of 4,222 bytes.
    let too_deep = made(&keys, "too-deep", true, |r| {
        deep(r, &"y".repeat(200), 21, b"far\n")
    });
    let i = Instance::start(keys.alice());
    d.ok(&["instance", "--set", &i.base]);
    d.ok(&["push"]);

    let parent = tempdir("levcs-clone-deep");
    let (status, out) = levcs(
        &parent,
        &keys.xdg,
        Some(SMALL_STACK),
        &["clone", &i.repo_id(), "b", "--from", &i.base],
    );
    assert!(status.success(), "{status}: {out}");
    let mut b = keys.at(parent.join("b"));
    b.limits = Some(SMALL_STACK);
    assert!(b.ok(&["status"]).contains("working tree clean"));
    // A missing index is rebuilt from HEAD's tree.
    std::fs::remove_file(b.levcs("index")).unwrap();
    assert!(b.ok(&["status"]).contains("working tree clean"));
    b.ok(&["diff"]);
    b.ok(&["verify"]);
    b.ok(&["branch", "--create", "side"]);
    b.commit("top.txt", b"main\n");
    b.ok(&["branch", "--switch", "side"]);
    b.commit("side.txt", b"side\n");
    b.ok(&["merge", "main"]);
    b.ok(&["commit", "-m", "merged"]);
    // A commit of one path takes the rest from HEAD's tree.
    std::fs::write(b.work.join("top.txt"), b"scoped\n").unwrap();
    b.ok(&["commit", "-m", "scoped", "top.txt"]);
    std::fs::write(b.work.join("top.txt"), b"cached\n").unwrap();
    let saved = b.ok(&["cache", "--save"]);
    let cache = saved
        .trim()
        .strip_prefix("saved cache ")
        .unwrap()
        .to_string();
    b.ok(&["cache", "--restore", &cache]);
    b.ok(&["verify"]);

    // Past the longest path: an error, not an abort, and no clone left.
    let i2 = Instance::start(keys.alice());
    too_deep.ok(&["instance", "--set", &i2.base]);
    too_deep.ok(&["push"]);
    let (status, out) = levcs(
        &parent,
        &keys.xdg,
        Some(SMALL_STACK),
        &["clone", &i2.repo_id(), "c", "--from", &i2.base],
    );
    assert_eq!(status.code(), Some(1), "{status}: {out}");
    assert!(out.contains("is longer than 4096 bytes"), "{out}");
    assert!(!parent.join("c").exists(), "a failed clone was left behind");
}

/// A tree's objects can recur along many paths, so a few dozen objects can
/// name millions of files, or gigabytes. A clone of such a tree is refused,
/// as an error, before it holds or writes them, in a quarter of a gigabyte
/// of address space, and leaves nothing behind. So is every command that
/// reads such a tree's files: `status` rebuilding the index from it, `diff`
/// against it, a `construct` of part of it, which stops once it has read
/// what a working tree may hold.
#[test]
fn trees_that_recur_past_a_working_tree_are_refused() {
    let keys = Local::new("recur-keys");
    // 2^24 files of one byte, from 28 objects.
    let many = made(&keys, "recur-many", true, |r| recurring(r, 24, b"x"));
    // 2,048 files of 1 MiB, 2 GiB, from 15 objects.
    let big = made(&keys, "recur-big", true, |r| {
        recurring(r, 11, &vec![b'y'; 1 << 20])
    });
    let files = "files and directories, counting every place a shared subtree recurs";
    let bytes = "bytes, counting every place a shared file recurs";
    for (l, refusal) in [(&many, files), (&big, bytes)] {
        let i = Instance::start(keys.alice());
        l.ok(&["instance", "--set", &i.base]);
        l.ok(&["push"]);
        let parent = tempdir("levcs-clone-recur");
        let (status, out) = levcs(
            &parent,
            &keys.xdg,
            Some(SMALL_MEMORY),
            &["clone", &i.repo_id(), "b", "--from", &i.base],
        );
        assert_eq!(status.code(), Some(1), "{status}: {out}");
        assert!(out.contains(refusal), "{out}");
        assert!(
            !parent.join("b").exists(),
            "a refused clone was left behind"
        );
    }

    // The repository it was made in has no index, so status rebuilds one.
    let out = big.refused(&["status"]);
    assert!(out.contains(bytes), "{out}");
    big.repo().write_index(&levcs_core::Index::new()).unwrap();
    let main = big.main();
    for args in [&["diff", &main][..], &["construct", &main, "d"][..]] {
        let out = big.refused(args);
        assert!(out.contains(bytes), "{args:?}: {out}");
    }
    assert!(!big.work.join("d").exists(), "a refused construct wrote");

    // A construct is refused once it has read what a working tree may
    // hold, not after reading every place a file recurs: here 256 GiB, in a
    // minute it could not read them in.
    let huge = made(&keys, "recur-huge", true, |r| {
        recurring(r, 18, &vec![b'z'; 1 << 20])
    });
    huge.repo().write_index(&levcs_core::Index::new()).unwrap();
    let main = huge.main();
    let out = Command::new("timeout")
        .args(["60", "sh", "-c"])
        .arg(format!("ulimit {SMALL_MEMORY} && exec \"$0\" \"$@\""))
        .arg(env!("CARGO_BIN_EXE_levcs"))
        .args(["construct", &main, "d"])
        .current_dir(&huge.work)
        .env("XDG_CONFIG_HOME", &keys.xdg)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}: {text}", out.status);
    assert!(text.contains(bytes), "{text}");
}
