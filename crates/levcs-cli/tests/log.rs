//! A release label as a revision, and where a commit is required, a release
//! as the commit it was declared on. A label was not a revision, so
//! `show v1` failed as an unknown branch or commit.

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
    let e = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(!o.status.success(), "{args:?} succeeded: {e}");
    e
}

fn setup(tag: &str) -> (PathBuf, PathBuf) {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let k = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "levcs-log-{tag}-{}-{stamp}-{k}",
        std::process::id()
    ));
    let (work, cfg) = (base.join("w"), base.join("cfg"));
    std::fs::create_dir_all(&work).unwrap();
    ok(&work, &cfg, &["init", "--key", "owner"]);
    (work, cfg)
}

/// Commit `text` as `path` with `message`, and return the commit's id.
fn commit(work: &Path, cfg: &Path, path: &str, text: &str, message: &str) -> String {
    std::fs::write(work.join(path), text).unwrap();
    ok(work, cfg, &["track", path]);
    let out = ok(work, cfg, &["commit", "-m", message]);
    out.split(['[', ']'])
        .nth(1)
        .expect("commit prints [id]")
        .to_string()
}

/// A label resolves after a branch of the same name, and a suffix after a
/// release starts from the commit it was declared on.
#[test]
fn a_release_label_is_a_revision() {
    let (work, cfg) = setup("label");
    let one = commit(&work, &cfg, "a.txt", "a\n", "one");
    let two = commit(&work, &cfg, "a.txt", "a2\n", "two");
    ok(&work, &cfg, &["release", "v1", "-m", "notes"]);
    commit(&work, &cfg, "a.txt", "a3\n", "three");

    let shown = ok(&work, &cfg, &["show", "v1"]);
    assert!(
        shown.starts_with("release ") && shown.contains("Label:  v1"),
        "{shown}"
    );
    assert!(ok(&work, &cfg, &["show", "v1^0"]).starts_with(&format!("commit {two}")));
    assert!(ok(&work, &cfg, &["show", "v1~1"]).starts_with(&format!("commit {one}")));
    assert_eq!(ok(&work, &cfg, &["show", "v1:a.txt"]), "a2\n");

    // A branch of the same name wins.
    ok(&work, &cfg, &["branch", "--create", "v1", &one]);
    assert!(ok(&work, &cfg, &["show", "v1"]).starts_with(&format!("commit {one}")));
}

/// Where a commit is required, a release stands for the commit it was
/// declared on. `merge <release>` failed as "no common ancestor" between
/// HEAD and the release object, and `branch --create` refused it.
#[test]
fn merge_and_branch_take_a_release_as_its_commit() {
    let (work, cfg) = setup("release-commit");
    commit(&work, &cfg, "a.txt", "a\n", "one");
    ok(&work, &cfg, &["branch", "--create", "side"]);
    ok(&work, &cfg, &["branch", "--switch", "side"]);
    let side = commit(&work, &cfg, "b.txt", "b\n", "on side");
    ok(&work, &cfg, &["release", "s1"]);
    ok(&work, &cfg, &["branch", "--switch", "main"]);

    ok(&work, &cfg, &["branch", "--create", "from-s1", "s1"]);
    assert!(ok(&work, &cfg, &["show", "from-s1"]).starts_with(&format!("commit {side}")));

    commit(&work, &cfg, "a.txt", "a2\n", "two");
    let o = levcs(&work, &cfg, &["merge", "s1"]);
    let out = String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success() && out.contains("clean merge"), "{out}");
    ok(&work, &cfg, &["commit", "-m", "merge s1"]);
    let head = ok(&work, &cfg, &["show", "HEAD"]);
    assert!(head.contains("Merge:  ") && head.contains(&side), "{head}");
    assert_eq!(std::fs::read_to_string(work.join("b.txt")).unwrap(), "b\n");
}

/// A name one namespace holds in another shape is not a ref there. With a
/// branch `series/next`, `refs/branches/series` is a directory; with a
/// branch `stable`, `refs/branches/stable/v1` lies under a file. Looking up
/// a branch of either name failed with "Is a directory" or "Not a
/// directory" before the releases were looked at, though both releases were
/// declared. Each is a miss, and the release resolves.
#[test]
fn a_branch_shaped_otherwise_does_not_hide_a_release() {
    let (work, cfg) = setup("shapes");
    let one = commit(&work, &cfg, "a.txt", "a\n", "one");
    ok(&work, &cfg, &["branch", "--create", "series/next"]);
    ok(&work, &cfg, &["release", "series"]);
    ok(&work, &cfg, &["branch", "--create", "stable"]);
    ok(&work, &cfg, &["release", "stable/v1"]);
    commit(&work, &cfg, "a.txt", "a2\n", "two");

    for label in ["series", "stable/v1"] {
        let shown = ok(&work, &cfg, &["show", label]);
        assert!(
            shown.starts_with("release ") && shown.contains(&format!("Label:  {label}")),
            "{label}: {shown}"
        );
        assert!(
            shown.contains(&format!("Commit: {one}")),
            "{label}: {shown}"
        );
    }
    // The branches still resolve as themselves.
    assert!(ok(&work, &cfg, &["show", "series/next"]).starts_with(&format!("commit {one}")));
    assert!(ok(&work, &cfg, &["show", "stable"]).starts_with(&format!("commit {one}")));
    let e = refused(&work, &cfg, &["show", "stable/v2"]);
    assert!(e.contains("unknown branch or commit"), "{e}");
}
