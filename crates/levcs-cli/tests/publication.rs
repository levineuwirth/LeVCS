//! Rule P on the command line: every local command that moves a branch,
//! release or authority ref publishes, in a repository with no instance.
//!
//! None of them checked Rule P. `branch --create` or a fast-forward could
//! publish history that was only received, a merge's commit published its
//! second parent's history unchecked, and an authority change on a detached
//! HEAD moved `current` with no boundary commit on any ref.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn levcs(work: &Path, cfg: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_levcs"))
        .current_dir(work)
        .env("XDG_CONFIG_HOME", cfg)
        .args(args)
        .output()
        .unwrap()
}

fn ok(work: &Path, cfg: &Path, args: &[&str]) -> String {
    let o = levcs(work, cfg, args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn refused(work: &Path, cfg: &Path, args: &[&str]) -> String {
    let o = levcs(work, cfg, args);
    let err = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(!o.status.success(), "{args:?} succeeded: {err}");
    err
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap().trim().to_string()
}

fn commit_id(out: &str) -> String {
    out.lines()
        .next()
        .and_then(|l| l.strip_prefix('['))
        .and_then(|l| l.split(']').next())
        .unwrap()
        .to_string()
}

struct Vault {
    work: PathBuf,
    cfg: PathBuf,
}

impl Vault {
    fn ok(&self, args: &[&str]) -> String {
        ok(&self.work, &self.cfg, args)
    }
    fn refused(&self, args: &[&str]) -> String {
        refused(&self.work, &self.cfg, args)
    }
    fn levcs(&self, p: &str) -> PathBuf {
        self.work.join(".levcs").join(p)
    }
    fn write_commit(&self, file: &str, text: &str, key: &str) -> String {
        std::fs::write(self.work.join(file), text).unwrap();
        self.ok(&["track", file]);
        commit_id(&self.ok(&["commit", "-m", file, "--key", key, "--", file]))
    }
    /// HEAD, every ref, the index, and the merge state, as bytes.
    fn state(&self) -> Vec<(String, Option<Vec<u8>>)> {
        let mut out = Vec::new();
        let mut stack = vec![self.levcs("refs")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push((p.display().to_string(), std::fs::read(&p).ok()));
                }
            }
        }
        for f in ["HEAD", "index", "MERGE_HEAD"] {
            out.push((f.into(), std::fs::read(self.levcs(f)).ok()));
        }
        out.sort();
        out
    }
}

/// An owner and an `agent` contributor, as in the vaults, with one commit
/// on `main`.
fn vault(tag: &str) -> Vault {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "levcs-publication-{tag}-{}-{stamp}",
        std::process::id()
    ));
    let v = Vault {
        work: base.join("w"),
        cfg: base.join("cfg"),
    };
    std::fs::create_dir_all(&v.work).unwrap();
    v.ok(&["init", "--key", "owner"]);
    v.ok(&["key", "generate", "agent"]);
    let apk = v.ok(&["key", "show", "agent"]);
    v.ok(&[
        "authority",
        "add",
        apk.trim(),
        "--role",
        "contributor",
        "--signing-key",
        "owner",
    ]);
    v.write_commit("base.md", "base\n", "owner");
    v
}

/// Copy `from`'s objects into `to` and record `tip` as received from a
/// replica: what replication does, under refs/remote/.
fn replicate(from: &Path, to: &Path, tip: &str) {
    let (src, dst) = (from.join(".levcs/objects"), to.join(".levcs/objects"));
    for shard in std::fs::read_dir(&src).unwrap() {
        let shard = shard.unwrap().path();
        let target = dst.join(shard.file_name().unwrap());
        std::fs::create_dir_all(&target).unwrap();
        for obj in std::fs::read_dir(&shard).unwrap() {
            let obj = obj.unwrap().path();
            let t = target.join(obj.file_name().unwrap());
            if !t.exists() {
                std::fs::copy(&obj, &t).unwrap();
            }
        }
    }
    let r = to.join(".levcs/refs/remote/origin/branches");
    std::fs::create_dir_all(&r).unwrap();
    std::fs::write(r.join("main"), format!("{tip}\n")).unwrap();
}

/// The specification's promotion case. `agent` works in another replica
/// while the owner changes the authority here. The work is replicated in
/// under refs/remote/ and verifies there. Every way of putting it on a
/// branch is refused, because it cites an authority that is no longer
/// current, and adoption (D1) has no record format yet.
#[test]
fn received_work_under_an_older_authority_cannot_be_promoted() {
    let v = vault("promote");
    // The other replica, sharing the keychain.
    let other = v.work.parent().unwrap().join("other");
    let status = Command::new("cp")
        .args(["-r"])
        .arg(&v.work)
        .arg(&other)
        .status()
        .unwrap();
    assert!(status.success());
    std::fs::write(other.join("offline.md"), "offline\n").unwrap();
    ok(&other, &v.cfg, &["track", "offline.md"]);
    let offline = commit_id(&ok(
        &other,
        &v.cfg,
        &["commit", "-m", "offline", "--key", "agent"],
    ));

    // Here, the owner changes the authority on a side branch, so that
    // `main` stays where a fast-forward onto the offline work is possible.
    v.ok(&["key", "generate", "reader"]);
    let rpk = v.ok(&["key", "show", "reader"]);
    v.ok(&["branch", "--create", "side", "--key", "owner"]);
    v.ok(&["branch", "--switch", "side"]);
    v.ok(&[
        "authority",
        "add",
        rpk.trim(),
        "--role",
        "reader",
        "--signing-key",
        "owner",
    ]);
    v.ok(&["branch", "--switch", "main"]);

    replicate(&other, &v.work, &offline);
    // Replication succeeds: the received history is valid under Rule H.
    v.ok(&["verify"]);

    let before = v.state();
    let e = v.refused(&["branch", "--create", "promoted", &offline, "--key", "agent"]);
    assert!(e.contains("adoption (D1)") && e.contains(&offline), "{e}");
    let e = v.refused(&["merge", &offline, "--key", "agent"]);
    assert!(e.contains("adoption (D1)"), "{e}");
    assert_eq!(
        v.state(),
        before,
        "a refused promotion changed refs or the index"
    );
    assert!(
        !v.work.join("offline.md").exists(),
        "a refused fast-forward wrote the working tree"
    );

    // The same work brought in by a merge commit is refused at the commit:
    // its second parent is newly exposed.
    v.write_commit("later.md", "later\n", "owner");
    let o = levcs(&v.work, &v.cfg, &["merge", &offline, "--key", "agent"]);
    assert!(o.status.code().is_some(), "{o:?}");
    let main = read(&v.levcs("refs/branches/main"));
    let e = v.refused(&["commit", "-m", "merge", "--key", "agent"]);
    assert!(e.contains(&format!("commit {offline}")), "{e}");
    assert_eq!(read(&v.levcs("refs/branches/main")), main);
    v.ok(&["merge", "--abort"]);

    // Work citing the current authority is published as before.
    v.write_commit("current.md", "current\n", "agent");
}

/// An authority change publishes its boundary commit on a branch, and
/// `current` moves with it. On a detached HEAD there is no branch, and
/// `current` used to move anyway.
#[test]
fn an_authority_change_on_a_detached_head_is_refused() {
    let v = vault("detached");
    let main = read(&v.levcs("refs/branches/main"));
    std::fs::write(v.levcs("HEAD"), format!("{main}\n")).unwrap();
    let current = read(&v.levcs("refs/authority/current"));
    v.ok(&["key", "generate", "reader"]);
    let rpk = v.ok(&["key", "show", "reader"]);
    let before = v.state();
    let e = v.refused(&[
        "authority",
        "add",
        rpk.trim(),
        "--role",
        "reader",
        "--signing-key",
        "owner",
    ]);
    assert!(e.contains("made on a branch"), "{e}");
    assert_eq!(read(&v.levcs("refs/authority/current")), current);
    assert_eq!(v.state(), before);
}

/// D4: a change that would leave the authority without an owner is
/// refused before anything is written.
#[test]
fn an_ownerless_authority_is_refused() {
    let v = vault("ownerless");
    let opk = v.ok(&["key", "show", "owner"]);
    let before = v.state();
    let e = v.refused(&["authority", "remove", opk.trim(), "--signing-key", "owner"]);
    assert!(e.contains("D4"), "{e}");
    assert_eq!(v.state(), before);
}

/// A release publishes its predecessor if that is not yet published.
#[test]
fn a_release_on_unpublished_work_is_checked_like_the_work() {
    let v = vault("release");
    // An unpublished commit by a non-member: the agent's key, removed.
    let other = v.work.parent().unwrap().join("other");
    assert!(Command::new("cp")
        .args(["-r"])
        .arg(&v.work)
        .arg(&other)
        .status()
        .unwrap()
        .success());
    std::fs::write(other.join("x.md"), "x\n").unwrap();
    ok(&other, &v.cfg, &["track", "x.md"]);
    let x = commit_id(&ok(
        &other,
        &v.cfg,
        &["commit", "-m", "x", "--key", "agent"],
    ));
    let apk = v.ok(&["key", "show", "agent"]);
    v.ok(&["authority", "remove", apk.trim(), "--signing-key", "owner"]);
    replicate(&other, &v.work, &x);
    std::fs::write(v.levcs("HEAD"), format!("{x}\n")).unwrap();
    let before = v.state();
    let e = v.refused(&["release", "v1", "--key", "owner"]);
    assert!(e.contains(&format!("commit {x}")), "{e}");
    assert_eq!(v.state(), before);
}

#[test]
fn deleting_a_branch_that_unpublishes_history_is_refused() {
    let v = vault("delete");
    v.ok(&["branch", "--create", "merged", "--key", "agent"]);
    v.ok(&["branch", "--create", "topic", "--key", "agent"]);
    v.ok(&["branch", "--switch", "topic"]);
    v.write_commit("topic.md", "topic\n", "agent");
    v.ok(&["branch", "--switch", "main"]);
    // Nothing is lost: main still reaches it.
    v.ok(&["branch", "--delete", "merged", "--key", "agent"]);
    let e = v.refused(&["branch", "--delete", "topic", "--key", "agent"]);
    assert!(e.contains("would unpublish") && e.contains("forced"), "{e}");
    let e = v.refused(&["branch", "--delete", "topic", "--force", "--key", "agent"]);
    assert!(e.contains("needs a maintainer"), "{e}");
    assert!(v.levcs("refs/branches/topic").exists());
    v.ok(&["branch", "--delete", "topic", "--force", "--key", "owner"]);
    assert!(!v.levcs("refs/branches/topic").exists());
}

#[test]
fn creating_a_branch_never_overwrites_one() {
    let v = vault("overwrite");
    v.ok(&["branch", "--create", "topic", "--key", "agent"]);
    let topic = read(&v.levcs("refs/branches/topic"));
    v.write_commit("more.md", "more\n", "agent");
    let e = v.refused(&["branch", "--create", "topic", "--key", "agent"]);
    assert!(e.contains("already exists"), "{e}");
    assert_eq!(read(&v.levcs("refs/branches/topic")), topic);
}

/// Publishing needs a key, as committing does: with several in the
/// keychain, the one acted under is named.
#[test]
fn publishing_names_its_key_when_there_are_several() {
    let v = vault("key");
    let e = v.refused(&["branch", "--create", "topic"]);
    assert!(e.contains("--key"), "{e}");
    assert!(!v.levcs("refs/branches/topic").exists());
}

/// In a workspace of an instance, local refs are not authoritative: the
/// instance applies Rule P when the work is pushed. Locally they move
/// freely, so received history can be worked on there. Leaving workspace
/// mode does not make them published: the review reproduced a malformed
/// config, read as naming no instance, turning a workspace branch over
/// unadmitted history into published state.
#[test]
fn a_workspace_moves_freely_and_never_silently_becomes_published_state() {
    let v = vault("workspace");
    let other = v.work.parent().unwrap().join("other");
    assert!(Command::new("cp")
        .args(["-r"])
        .arg(&v.work)
        .arg(&other)
        .status()
        .unwrap()
        .success());
    std::fs::write(other.join("x.md"), "x\n").unwrap();
    ok(&other, &v.cfg, &["track", "x.md"]);
    let x = commit_id(&ok(
        &other,
        &v.cfg,
        &["commit", "-m", "x", "--key", "agent"],
    ));
    let apk = v.ok(&["key", "show", "agent"]);
    v.ok(&["authority", "remove", apk.trim(), "--signing-key", "owner"]);
    replicate(&other, &v.work, &x);
    v.refused(&["branch", "--create", "received", &x, "--key", "owner"]);
    v.ok(&["instance", "--set", "http://127.0.0.1:9/levcs/v1"]);
    assert!(
        v.levcs("workspace").exists(),
        "becoming a workspace is recorded"
    );
    v.ok(&["branch", "--create", "received", &x]);

    // A config that cannot be read decides nothing: everything that
    // publishes refuses, and `instance --set` will not rewrite it.
    let config = v.levcs("config");
    let good = std::fs::read_to_string(&config).unwrap();
    std::fs::write(&config, "[malformed config").unwrap();
    let e = v.refused(&["branch", "--create", "now", &x, "--key", "owner"]);
    assert!(e.contains("cannot read"), "{e}");
    std::fs::write(v.work.join("new.md"), "new\n").unwrap();
    v.ok(&["track", "new.md"]);
    let e = v.refused(&["commit", "-m", "new", "--key", "owner"]);
    assert!(e.contains("cannot read"), "{e}");
    let e = v.refused(&["instance", "--set", "http://127.0.0.1:9/levcs/v1"]);
    assert!(e.contains("not rewriting"), "{e}");

    // A valid config that no longer names the instance does not make the
    // workspace's refs published either.
    std::fs::write(&config, "").unwrap();
    let e = v.refused(&["branch", "--create", "now", &x, "--key", "owner"]);
    assert!(
        e.contains("has been a workspace") && e.contains("D6"),
        "{e}"
    );
    let e = v.refused(&["commit", "-m", "new", "--key", "owner"]);
    assert!(e.contains("has been a workspace"), "{e}");
    assert!(!v.levcs("refs/branches/now").exists());

    // Naming the instance again resumes the workspace.
    std::fs::write(&config, good).unwrap();
    v.ok(&["branch", "--create", "now", &x]);
}

/// A repository configured as a workspace by hand, or before workspaces
/// were recorded, is recorded as one when its refs first move.
#[test]
fn a_workspace_configured_by_hand_is_recorded_when_its_refs_move() {
    let v = vault("workspace-by-hand");
    std::fs::write(
        v.levcs("config"),
        "[instance]\nurl = \"http://127.0.0.1:9/levcs/v1\"\n",
    )
    .unwrap();
    assert!(!v.levcs("workspace").exists());
    v.ok(&["branch", "--create", "topic"]);
    assert!(v.levcs("workspace").exists());
    std::fs::write(v.levcs("config"), "").unwrap();
    let e = v.refused(&["branch", "--create", "again", "--key", "owner"]);
    assert!(e.contains("has been a workspace"), "{e}");
}

/// A publication killed part way, as the review killed an authority
/// removal: its branch write had landed and `current` had not moved. Its
/// record (`.levcs/ref-transaction/record`, written before any ref moves) lets the
/// next process undo it, before `verify` vouches for anything or anything
/// else is published. The state is made here as the kill leaves it.
#[test]
fn a_publication_killed_part_way_is_rolled_back_before_anything_else() {
    let v = vault("killed");
    let main = read(&v.levcs("refs/branches/main"));
    let current = read(&v.levcs("refs/authority/current"));
    let boundary = "ab".repeat(32);
    let successor = "cd".repeat(32);
    let killed = |v: &Vault| {
        std::fs::create_dir_all(v.levcs("ref-transaction")).unwrap();
        std::fs::write(
            v.levcs("ref-transaction/record"),
            format!(
                "levcs ref transaction 1\nrefs/branches/main\t{main}\t{boundary}\n\
                 refs/authority/current\t{current}\t{successor}\n"
            ),
        )
        .unwrap();
        std::fs::write(v.levcs("refs/branches/main"), format!("{boundary}\n")).unwrap();
    };

    killed(&v);
    let o = levcs(&v.work, &v.cfg, &["verify"]);
    let e = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{e}");
    assert!(e.contains("rolled back a publication"), "{e}");
    assert_eq!(read(&v.levcs("refs/branches/main")), main);
    assert_eq!(read(&v.levcs("refs/authority/current")), current);
    assert!(!v.levcs("ref-transaction/record").exists());

    // Any command that changes the repository rolls it back first, then
    // proceeds over the state as it was.
    killed(&v);
    let id = v.write_commit("after.md", "after\n", "agent");
    let main_now = read(&v.levcs("refs/branches/main"));
    assert_eq!(main_now, id);
    assert!(!v.levcs("ref-transaction/record").exists());
}

/// A fake source instance: answers each expected request, in order.
fn fake_source(responses: Vec<(&'static str, Vec<u8>)>) -> (String, std::thread::JoinHandle<()>) {
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

/// A fork is its repository's first publication, and the source history
/// behind it is checked against the source's own genesis. The fork used to
/// sign over a source tip whose signature was invalid (the audit's probe).
#[test]
fn a_fork_over_unverified_source_history_is_refused() {
    use levcs_core::Repository;
    let v = vault("fork");
    let source = Repository::discover(&v.work).unwrap();
    let tip = source.refs.resolve_head().unwrap().unwrap();
    let mut forged = source.read_signed(tip).unwrap();
    forged.signatures[0].signature = [0; 64];
    let forged_tip = source.write_signed(&forged).unwrap();
    let mut pack = levcs_protocol::Pack::new();
    for id in source.objects.iter_ids().unwrap() {
        let bytes = source.objects.read_raw(id).unwrap();
        pack.push(bytes[4], bytes);
    }
    let auth = source.current_authority().unwrap().unwrap().to_hex();
    let genesis = source.genesis_authority().unwrap().unwrap().to_hex();
    let advertised = "cd".repeat(32);
    let info = serde_json::to_vec(&serde_json::json!({
        "repo_id": advertised, "current_authority": auth, "genesis_authority": genesis
    }))
    .unwrap();
    let refs = serde_json::to_vec(
        &serde_json::json!({"branches": {"main": forged_tip.to_hex()}, "releases": {}}),
    )
    .unwrap();
    let (url, server) = fake_source(vec![
        ("/info", info),
        ("/refs", refs),
        ("/pack?", pack.encode()),
    ]);
    let e = v.refused(&[
        "fork",
        &advertised,
        "--from",
        &url,
        "--name",
        "forged-fork",
        "--key",
        "owner",
    ]);
    server.join().unwrap();
    assert!(e.contains("signature is invalid"), "{e}");
    let dest = v.work.join("forged-fork");
    assert!(
        !dest.join(".levcs/refs/branches/main").exists(),
        "the fork published a branch over a forged source tip"
    );
}
