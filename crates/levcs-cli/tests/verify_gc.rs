//! `verify` covers all history, and `gc` never turns damage into deletion.
//!
//! `verify` used to check HEAD and the current authority chain only; with
//! 400 of a vault's 3,726 objects overwritten it printed "verify: ok". `gc`
//! skipped objects it could not read, so everything beneath one was deleted
//! as unreachable.

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

fn setup(tag: &str) -> (PathBuf, PathBuf) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base =
        std::env::temp_dir().join(format!("levcs-verify-{tag}-{}-{stamp}", std::process::id()));
    let (work, cfg) = (base.join("w"), base.join("cfg"));
    std::fs::create_dir_all(&work).unwrap();
    ok(&work, &cfg, &["init", "--key", "owner"]);
    (work, cfg)
}

fn objects(work: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for shard in std::fs::read_dir(work.join(".levcs/objects")).unwrap() {
        let shard = shard.unwrap().path();
        if shard.is_dir() {
            for f in std::fs::read_dir(&shard).unwrap() {
                out.push(f.unwrap().path());
            }
        }
    }
    out
}

/// History whose first version of `a.md` is referenced only by the first
/// commit, then that blob overwritten. Returns the damaged object's id.
fn damaged_history(work: &Path, cfg: &Path) -> String {
    std::fs::write(
        work.join("a.md"),
        b"first version, only in the first commit\n",
    )
    .unwrap();
    std::fs::write(work.join("b.md"), b"b\n").unwrap();
    ok(work, cfg, &["track", "a.md", "b.md"]);
    ok(work, cfg, &["commit", "-m", "one", "--key", "owner"]);
    std::fs::write(work.join("a.md"), b"second version\n").unwrap();
    ok(work, cfg, &["commit", "-m", "two", "--key", "owner"]);
    let needle = b"first version, only in the first commit";
    let old = objects(work)
        .into_iter()
        .find(|p| {
            std::fs::read(p)
                .map(|b| b.windows(needle.len()).any(|w| w == needle))
                .unwrap_or(false)
        })
        .expect("the old blob");
    std::fs::write(&old, b"garbage").unwrap();
    let shard = old.parent().unwrap().file_name().unwrap().to_string_lossy();
    format!("{shard}{}", old.file_name().unwrap().to_string_lossy())
}

#[test]
fn verify_covers_history_behind_head() {
    let (work, cfg) = setup("verify");
    let o = levcs(&work, &cfg, &["verify"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));

    let damaged = damaged_history(&work, &cfg);
    let o = levcs(&work, &cfg, &["verify"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(
        o.status.code(),
        Some(1),
        "verify passed damaged history:\n{err}"
    );
    assert!(
        err.contains(&damaged),
        "verify did not name the damaged object {damaged}:\n{err}"
    );
    assert!(!err.contains("verify: ok"));
}

#[test]
fn verify_reports_what_it_covered() {
    let (work, cfg) = setup("covered");
    std::fs::write(work.join("a.md"), b"a\n").unwrap();
    ok(&work, &cfg, &["track", "a.md"]);
    ok(&work, &cfg, &["commit", "-m", "one", "--key", "owner"]);
    let o = levcs(&work, &cfg, &["verify"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{err}");
    assert!(
        err.contains("1 commits") && err.contains("hash-checked") && err.contains("verify: ok"),
        "{err}"
    );
}

#[test]
fn gc_refuses_to_delete_anything_when_history_is_damaged() {
    let (work, cfg) = setup("gc");
    damaged_history(&work, &cfg);
    let before = objects(&work).len();
    let o = levcs(&work, &cfg, &["gc", "--grace-days", "0"]);
    assert!(
        !o.status.success(),
        "gc ran over damaged history: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("refusing"));
    assert_eq!(objects(&work).len(), before, "gc deleted objects");
}

#[test]
fn gc_keeps_what_a_merge_in_progress_needs() {
    let (work, cfg) = setup("merge");
    std::fs::write(work.join("a.md"), b"a\n").unwrap();
    std::fs::write(work.join("b.md"), b"b\n").unwrap();
    ok(&work, &cfg, &["track", "a.md", "b.md"]);
    ok(&work, &cfg, &["commit", "-m", "base", "--key", "owner"]);
    ok(&work, &cfg, &["branch", "--create", "topic"]);
    std::fs::write(work.join("a.md"), b"main\n").unwrap();
    ok(&work, &cfg, &["commit", "-m", "main", "--key", "owner"]);
    ok(&work, &cfg, &["branch", "--switch", "topic"]);
    std::fs::write(work.join("b.md"), b"topic\n").unwrap();
    ok(&work, &cfg, &["commit", "-m", "topic", "--key", "owner"]);
    ok(&work, &cfg, &["branch", "--switch", "main"]);
    ok(&work, &cfg, &["merge", "topic"]);
    let theirs = std::fs::read_to_string(work.join(".levcs/MERGE_HEAD"))
        .unwrap()
        .trim()
        .to_string();
    // The merge's other side is now reachable from MERGE_HEAD alone.
    std::fs::remove_file(work.join(".levcs/refs/branches/topic")).unwrap();
    ok(&work, &cfg, &["gc", "--grace-days", "0"]);
    assert!(
        work.join(".levcs/objects")
            .join(&theirs[..2])
            .join(&theirs[2..])
            .is_file(),
        "gc deleted the commit a merge in progress needs"
    );
    ok(&work, &cfg, &["commit", "-m", "merge", "--key", "owner"]);
    ok(&work, &cfg, &["verify"]);
}

/// A topic branch holding unique history, back on main afterwards.
fn with_topic(work: &Path, cfg: &Path) -> String {
    std::fs::write(work.join("a.md"), b"base\n").unwrap();
    ok(work, cfg, &["track", "a.md"]);
    ok(work, cfg, &["commit", "-m", "base", "--key", "owner"]);
    ok(work, cfg, &["branch", "--create", "topic"]);
    ok(work, cfg, &["branch", "--switch", "topic"]);
    std::fs::write(work.join("a.md"), b"topic only\n").unwrap();
    ok(work, cfg, &["commit", "-m", "topic", "--key", "owner"]);
    let tip = std::fs::read_to_string(work.join(".levcs/refs/branches/topic"))
        .unwrap()
        .trim()
        .to_string();
    ok(work, cfg, &["branch", "--switch", "main"]);
    tip
}

fn assert_damaged_root_stops_both(work: &Path, cfg: &Path, tip: &str) {
    let before = objects(work).len();
    let v = levcs(work, cfg, &["verify"]);
    assert!(
        !v.status.success(),
        "verify passed with a damaged root: {}",
        String::from_utf8_lossy(&v.stderr)
    );
    let g = levcs(work, cfg, &["gc", "--grace-days", "0"]);
    assert!(
        !g.status.success(),
        "gc ran with a damaged root: {}",
        String::from_utf8_lossy(&g.stderr)
    );
    assert_eq!(objects(work).len(), before, "gc deleted objects");
    assert!(work
        .join(".levcs/objects")
        .join(&tip[..2])
        .join(&tip[2..])
        .is_file());
}

#[test]
fn a_malformed_branch_ref_stops_verify_and_gc() {
    // A skipped ref used to make its history unreachable, and gc deleted it.
    let (work, cfg) = setup("badref");
    let tip = with_topic(&work, &cfg);
    std::fs::write(work.join(".levcs/refs/branches/topic"), b"damaged ref\n").unwrap();
    assert_damaged_root_stops_both(&work, &cfg, &tip);
}

#[test]
fn an_unreadable_merge_marker_stops_verify_and_gc() {
    let (work, cfg) = setup("badmarker");
    let tip = with_topic(&work, &cfg);
    std::fs::remove_file(work.join(".levcs/refs/branches/topic")).unwrap();
    std::fs::write(work.join(".levcs/MERGE_HEAD"), [0xffu8]).unwrap();
    assert_damaged_root_stops_both(&work, &cfg, &tip);
}

#[test]
fn a_ref_naming_the_wrong_type_stops_gc() {
    // verify flagged this, but gc's own walk discarded types and deleted the
    // branch's commit.
    let (work, cfg) = setup("wrongtype");
    let tip = with_topic(&work, &cfg);
    let needle = b"topic only";
    let blob = objects(&work)
        .into_iter()
        .find(|p| {
            std::fs::read(p)
                .map(|b| b.windows(needle.len()).any(|w| w == needle))
                .unwrap_or(false)
        })
        .unwrap();
    let blob_id = format!(
        "{}{}",
        blob.parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy(),
        blob.file_name().unwrap().to_string_lossy()
    );
    std::fs::write(
        work.join(".levcs/refs/branches/topic"),
        format!("{blob_id}\n"),
    )
    .unwrap();
    assert_damaged_root_stops_both(&work, &cfg, &tip);
}

#[test]
fn a_release_named_like_a_namespace_verifies() {
    let (work, cfg) = setup("relname");
    std::fs::write(work.join("a.md"), b"a\n").unwrap();
    ok(&work, &cfg, &["track", "a.md"]);
    ok(&work, &cfg, &["commit", "-m", "one", "--key", "owner"]);
    ok(&work, &cfg, &["release", "branches", "--key", "owner"]);
    let o = levcs(&work, &cfg, &["verify"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

#[test]
fn gc_refuses_before_deleting_behind_an_undecodable_authority() {
    // A signed authority whose body is truncated, cited as current, with a
    // sound predecessor. gc used to skip the undecodable body, never reach
    // the predecessor, and delete it.
    use levcs_core::{Commit, CommitFlags, Repository, Tree, ZERO_ID};
    use levcs_identity::authority::{AuthorityBody, MemberEntry, Role, AUTHORITY_SCHEMA_VERSION};
    use levcs_identity::keys::SecretKey;
    use levcs_identity::sign::{sign_authority, sign_commit};

    let (work, cfg) = setup("badauth");
    std::fs::remove_dir_all(work.join(".levcs")).unwrap();
    let repo = Repository::init_skeleton(&work).unwrap();
    let owner = SecretKey::generate();
    let member = |role| MemberEntry {
        key: owner.public(),
        handle: "owner".into(),
        role,
        added_micros: 1,
        added_by: owner.public(),
    };
    let mut g = AuthorityBody {
        schema_version: AUTHORITY_SCHEMA_VERSION,
        repo_id: ZERO_ID,
        previous_authority: ZERO_ID,
        version: 1,
        created_micros: 1,
        members: vec![member(Role::Owner)],
        policy: vec![],
    };
    g.normalize().unwrap();
    g.assign_genesis_repo_id().unwrap();
    let genesis = repo
        .write_signed(&sign_authority(&g, &owner).unwrap())
        .unwrap();
    let mut v2 = g.clone();
    v2.previous_authority = genesis;
    v2.version = 2;
    let v2_id = repo
        .write_signed(&sign_authority(&v2, &owner).unwrap())
        .unwrap();
    let mut v3 = v2.clone();
    v3.previous_authority = v2_id;
    v3.version = 3;
    let mut bad = sign_authority(&v3, &owner).unwrap();
    bad.body.pop();
    bad.signatures[0].signature = owner.sign(bad.signing_hash().as_bytes());
    let bad_id = repo.write_signed(&bad).unwrap();
    let tree = repo
        .objects
        .write_raw(&Tree::default().serialize())
        .unwrap();
    let root = Commit {
        tree,
        parents: vec![],
        authority: genesis,
        author_key: owner.public().0,
        timestamp_micros: 2,
        flags: CommitFlags::NONE,
        message: "root".into(),
    };
    let root = repo
        .write_signed(&sign_commit(root, &owner).unwrap())
        .unwrap();
    repo.refs.write("refs/authority/genesis", genesis).unwrap();
    repo.refs.write("refs/authority/current", bad_id).unwrap();
    repo.refs.write("refs/branches/main", root).unwrap();
    repo.refs
        .write_head(&levcs_core::refs::Head::Branch("refs/branches/main".into()))
        .unwrap();

    let v = levcs(&work, &cfg, &["verify"]);
    assert!(!v.status.success());
    let g = levcs(&work, &cfg, &["gc", "--grace-days", "0"]);
    assert!(
        !g.status.success(),
        "gc ran past an undecodable authority: {}",
        String::from_utf8_lossy(&g.stderr)
    );
    assert!(
        repo.objects.path_for(v2_id).is_file(),
        "gc deleted the predecessor of an undecodable authority"
    );
}
