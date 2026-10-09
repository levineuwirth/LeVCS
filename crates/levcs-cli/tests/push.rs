//! `levcs push` against an instance.
//!
//! - **What a push expects.** A push said every ref it named was expected
//!   to be absent, so each push to a ref after its first was refused as
//!   stale (audit H11). It now expects what the instance holds.
//! - **What a push sends.** The whole history went every time. Now only
//!   what the instance's refs do not already reach.
//! - **What a push may be.** A push is measured, and checked against what
//!   the instance says it takes, before anything is sent: `--dry-run`
//!   reports the measure and sends nothing.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;

use levcs_instance::{router, AppState, InstanceConfig, Limits};

fn tempdir(prefix: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let p = std::env::temp_dir().join(format!("{prefix}-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A working repository, and the keychain alice's key is in.
struct Local {
    work: PathBuf,
    xdg: PathBuf,
}

impl Local {
    fn new(tag: &str) -> Local {
        let base = tempdir(&format!("levcs-push-{tag}"));
        let l = Local {
            work: base.join("w"),
            xdg: base.join("cfg"),
        };
        std::fs::create_dir_all(&l.work).unwrap();
        l.ok(&["init", "--key", "alice"]);
        l
    }

    /// Another working copy of this repository, under the same keychain.
    fn copy(&self, tag: &str) -> Local {
        let work = tempdir(&format!("levcs-push-{tag}")).join("w");
        let status = Command::new("cp")
            .arg("-a")
            .arg(&self.work)
            .arg(&work)
            .status()
            .unwrap();
        assert!(status.success());
        Local {
            work,
            xdg: self.xdg.clone(),
        }
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let out = Command::new(env!("CARGO_BIN_EXE_levcs"))
            .args(args)
            .current_dir(&self.work)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .output()
            .unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    fn ok(&self, args: &[&str]) -> String {
        let (code, out, err) = self.run(args);
        assert_eq!(code, 0, "{args:?}: {err}");
        format!("{out}{err}")
    }

    fn commit(&self, file: &str, bytes: &[u8]) {
        std::fs::write(self.work.join(file), bytes).unwrap();
        self.ok(&["track", file]);
        self.ok(&["commit", "-m", file]);
    }

    fn main(&self) -> String {
        std::fs::read_to_string(self.work.join(".levcs/refs/branches/main"))
            .unwrap()
            .trim()
            .to_string()
    }

    fn alice(&self) -> String {
        self.ok(&["key", "show", "alice"]).trim().to_string()
    }
}

/// An instance on which alice may create repositories, with `limits`.
struct Instance {
    base: String,
    root: PathBuf,
    _rt: tokio::runtime::Runtime,
}

impl Instance {
    fn start(alice: String, limits: Limits) -> Instance {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let root = tempdir("levcs-push-instance");
        let config = InstanceConfig {
            root: root.clone(),
            storage_mode: "full".into(),
            federation_peers: Vec::new(),
            allowed_handlers: Vec::new(),
            mirrors: Vec::new(),
            creators: vec![alice],
            limits,
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

    /// The repositories it holds.
    fn repos(&self) -> Vec<PathBuf> {
        std::fs::read_dir(&self.root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect()
    }

    /// What its one repository's main holds.
    fn main(&self) -> String {
        let repos = self.repos();
        assert_eq!(repos.len(), 1, "{repos:?}");
        std::fs::read_to_string(repos[0].join(".levcs/refs/branches/main"))
            .unwrap()
            .trim()
            .to_string()
    }
}

fn pointed_at(l: &Local, i: &Instance) {
    l.ok(&["instance", "--set", &i.base]);
}

/// The object count a dry run reports.
fn objects(dry_run: &str) -> u64 {
    let at = dry_run.find(" object(s)").expect(dry_run);
    dry_run[..at]
        .rsplit(' ')
        .next()
        .unwrap()
        .parse()
        .expect(dry_run)
}

/// The audit's H11: each push to a ref after its first was refused as
/// stale, `--force` too, because a push expected every ref to be absent.
#[test]
fn every_push_after_the_first_lands() {
    let a = Local::new("again");
    a.commit("a.txt", b"one\n");
    let i = Instance::start(a.alice(), Limits::default());
    pointed_at(&a, &i);
    a.ok(&["push"]);
    for text in ["two\n", "three\n"] {
        a.commit("a.txt", text.as_bytes());
        a.ok(&["push"]);
        assert_eq!(i.main(), a.main());
    }
}

/// A push sends what the instance's refs do not already reach: here three
/// objects, under a limit the whole history would pass. It sent the whole
/// history every time.
#[test]
fn a_push_sends_only_what_the_instance_lacks() {
    let a = Local::new("lacks");
    a.commit("a.txt", b"one\n");
    let limits = Limits {
        max_pack_objects: 5,
        ..Limits::default()
    };
    let i = Instance::start(a.alice(), limits);
    pointed_at(&a, &i);
    let first = objects(&a.ok(&["push", "--dry-run"]));
    assert_eq!(first, 4, "the genesis, a blob, a tree and a commit");
    a.ok(&["push"]);
    a.commit("a.txt", b"two\n");
    let dry = a.ok(&["push", "--dry-run"]);
    assert_eq!(objects(&dry), 3, "{dry}");
    assert!(dry.contains("within the instance's limits"), "{dry}");
    a.ok(&["push"]);
    assert_eq!(i.main(), a.main());
}

/// A push past what the instance says it takes is refused before anything
/// is sent: the repository is not even created. The dry run says why.
#[test]
fn a_push_past_the_instance_limits_sends_nothing() {
    let a = Local::new("past");
    let noise: Vec<u8> = (0..40_000u32)
        .flat_map(|i| levcs_core::blake3_hash(&i.to_le_bytes()).0)
        .take(40_000)
        .collect();
    a.commit("big.bin", &noise);
    let limits = Limits {
        max_push_bytes: 16 << 10,
        ..Limits::default()
    };
    let i = Instance::start(a.alice(), limits);
    pointed_at(&a, &i);
    let dry = a.ok(&["push", "--dry-run"]);
    assert!(dry.contains("the instance would refuse it"), "{dry}");
    let (code, _, err) = a.run(&["push"]);
    assert_ne!(code, 0);
    assert!(err.contains("the instance takes at most"), "{err}");
    assert!(err.contains("nothing was sent"), "{err}");
    assert!(i.repos().is_empty(), "{:?}", i.repos());
}

/// A push from a copy behind the instance is refused, and what the
/// instance holds stays; forced by an owner, it replaces it, against the
/// value the instance holds.
#[test]
fn a_push_behind_the_instance_is_refused_unless_forced() {
    let a = Local::new("behind");
    a.commit("a.txt", b"one\n");
    let i = Instance::start(a.alice(), Limits::default());
    pointed_at(&a, &i);
    a.ok(&["push"]);
    let b = a.copy("behind-b");
    a.commit("a.txt", b"from a\n");
    a.ok(&["push"]);
    b.commit("b.txt", b"from b\n");
    let (code, _, err) = b.run(&["push"]);
    assert_ne!(code, 0);
    assert!(err.contains("non-fast-forward"), "{err}");
    assert_eq!(i.main(), a.main());
    b.ok(&["push", "--force"]);
    assert_eq!(i.main(), b.main());
}

/// A push after a nested branch's lands, as does a second push of that
/// branch. The instance listed only the top level of its branches, read a
/// nested branch's directory as a ref, and failed every push after.
#[test]
fn pushes_after_a_nested_branch_land() {
    let a = Local::new("nested-branch");
    a.commit("a.txt", b"one\n");
    let i = Instance::start(a.alice(), Limits::default());
    pointed_at(&a, &i);
    a.ok(&["push"]);
    a.ok(&["branch", "--create", "feature/test"]);
    a.ok(&["push", "refs/branches/feature/test"]);
    a.commit("a.txt", b"two\n");
    a.ok(&["push", "refs/branches/main"]);
    assert_eq!(i.main(), a.main());
    // And the nested branch again, expecting what the instance holds.
    a.ok(&["branch", "--switch", "feature/test"]);
    a.commit("b.txt", b"on the branch\n");
    a.ok(&["push", "refs/branches/feature/test"]);
}

/// A second push of a nested release expects what the instance holds. The
/// instance left nested releases out of what it said it held, so the push
/// expected the release absent and was refused as stale.
#[test]
fn a_second_push_of_a_nested_release_lands() {
    let a = Local::new("nested-release");
    a.commit("a.txt", b"one\n");
    let i = Instance::start(a.alice(), Limits::default());
    pointed_at(&a, &i);
    a.ok(&["push"]);
    for _ in 0..2 {
        a.ok(&["release", "series/test"]);
        a.ok(&["push", "refs/releases/series/test"]);
    }
}

/// An instance serving everything but what it takes: its limits cannot be
/// asked.
fn instance_without_limits(alice: String, limits: Limits) -> Instance {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let root = tempdir("levcs-push-instance");
    let config = InstanceConfig {
        root: root.clone(),
        creators: vec![alice],
        limits,
        ..InstanceConfig::default()
    };
    let app = router(AppState::new(config)).layer(axum::middleware::from_fn(
        |req: axum::extract::Request, next: axum::middleware::Next| async move {
            use axum::response::IntoResponse;
            if req.uri().path() == "/levcs/v1/instance/info" {
                return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "try later").into_response();
            }
            next.run(req).await
        },
    ));
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

/// When the instance's limits cannot be asked, nothing is sent: the push
/// fails, and creates nothing. A failure to ask was taken for an instance
/// that says nothing, and the push went out unchecked.
#[test]
fn a_push_whose_limits_cannot_be_asked_sends_nothing() {
    let a = Local::new("unasked");
    a.commit("a.txt", b"one\n");
    let i = instance_without_limits(a.alice(), Limits::default());
    pointed_at(&a, &i);
    let (code, _, err) = a.run(&["push"]);
    assert_ne!(code, 0);
    assert!(err.contains("503"), "{err}");
    assert!(i.repos().is_empty(), "{:?}", i.repos());
    assert_ne!(a.run(&["push", "--dry-run"]).0, 0);
}

/// A push naming more refs than the instance takes is refused before
/// anything is sent. The limit was not said, nor checked, and the push
/// created the repository before it was refused.
#[test]
fn a_push_past_the_ref_update_limit_sends_nothing() {
    let a = Local::new("updates");
    a.commit("a.txt", b"one\n");
    a.ok(&["branch", "--create", "other"]);
    let limits = Limits {
        max_ref_updates: 1,
        ..Limits::default()
    };
    let i = Instance::start(a.alice(), limits);
    pointed_at(&a, &i);
    let both = ["refs/branches/main", "refs/branches/other"];
    let mut dry = vec!["push", "--dry-run"];
    dry.extend(both);
    let dry = a.ok(&dry);
    assert!(dry.contains("the instance would refuse it"), "{dry}");
    let mut push = vec!["push"];
    push.extend(both);
    let (code, _, err) = a.run(&push);
    assert_ne!(code, 0);
    assert!(err.contains("ref updates"), "{err}");
    assert!(i.repos().is_empty(), "{:?}", i.repos());
}

/// Remove `root` and everything under it without recursion, however deep
/// it goes.
fn remove_deep(root: &std::path::Path) {
    let mut stack = vec![(root.to_path_buf(), false)];
    while let Some((path, leaving)) = stack.pop() {
        if leaving {
            let _ = std::fs::remove_dir(&path);
            continue;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() => {
                stack.push((path.clone(), true));
                for e in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                    stack.push((e.path(), false));
                }
            }
            _ => {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// A branch 1,200 directories deep is published, read, pushed past and
/// verified, and the instance answers throughout. Its ref listings recursed
/// once per directory: an anonymous `info` overflowed a worker's stack and
/// aborted the instance, as admission's listing would on the next push. The
/// instance runs in a child process, so that an abort fails this test
/// rather than aborting its binary.
#[test]
fn a_deeply_nested_branch_is_served_without_recursion() {
    if std::env::var_os("LEVCS_DEEP_BRANCH_CHILD").is_some() {
        let a = Local::new("deep");
        a.commit("a.txt", b"one\n");
        let i = Instance::start(a.alice(), Limits::default());
        pointed_at(&a, &i);
        a.ok(&["push"]);
        let name = format!("{}tip", "x/".repeat(1200));
        a.ok(&["branch", "--create", &name]);
        a.ok(&["push", &format!("refs/branches/{name}")]);
        let repos = i.repos();
        let id = repos[0].file_name().unwrap().to_str().unwrap();
        let info = levcs_client::Client::new(&i.base).repo_info(id).unwrap();
        assert!(info.branches.contains_key(&name));
        a.commit("a.txt", b"two\n");
        a.ok(&["push", "refs/branches/main"]);
        assert_eq!(i.main(), a.main());
        a.ok(&["verify"]);
        return;
    }
    // The child's repository and instance go under a directory of their
    // own, removed whole whatever became of the child.
    let tmp = tempdir("levcs-push-deep-tmp");
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_deeply_nested_branch_is_served_without_recursion",
            "--nocapture",
        ])
        .env("LEVCS_DEEP_BRANCH_CHILD", "1")
        .env("TMPDIR", &tmp)
        .output()
        .unwrap();
    remove_deep(&tmp);
    assert!(
        child.status.success(),
        "the instance failed: {}; {}",
        child.status,
        String::from_utf8_lossy(&child.stderr)
    );
}
