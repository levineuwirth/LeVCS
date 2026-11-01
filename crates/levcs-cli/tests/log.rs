//! `log`: the whole first-parent line, `--since <rev>`, and `--release`.
//!
//! `log` stopped after 100 commits, and parsed `--since` and `--release`
//! without reading either. A release label was not a revision, so
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

/// The messages of the commits `log` printed, in order.
fn messages(log: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines = log.lines().peekable();
    while let Some(line) = lines.next() {
        if line.starts_with("commit ") {
            // Header lines, a blank line, then the message indented.
            for l in lines.by_ref() {
                if l.is_empty() {
                    break;
                }
            }
            if let Some(m) = lines.next() {
                out.push(m.trim().to_string());
            }
        }
    }
    out
}

/// The labels of the releases `log --release` printed, in order.
fn labels(log: &str) -> Vec<String> {
    log.lines()
        .filter_map(|l| l.strip_prefix("Label:  "))
        .map(str::to_string)
        .collect()
}

#[test]
fn log_walks_the_whole_first_parent_line() {
    let (work, cfg) = setup("all");
    for i in 0..105 {
        commit(&work, &cfg, "a.txt", &format!("{i}\n"), &format!("c{i}"));
    }
    let shown = messages(&ok(&work, &cfg, &["log"]));
    assert_eq!(shown.len(), 105, "{shown:?}");
    assert_eq!(shown.first().map(String::as_str), Some("c104"));
    assert_eq!(shown.last().map(String::as_str), Some("c0"));
}

/// `base` - `main1` - `merge` - `main2` on main; `side1` off `base`, merged.
#[test]
fn since_shows_the_commits_the_revision_does_not_contain() {
    let (work, cfg) = setup("since");
    let base = commit(&work, &cfg, "a.txt", "a\n", "base");
    ok(&work, &cfg, &["branch", "--create", "side"]);
    ok(&work, &cfg, &["branch", "--switch", "side"]);
    let side1 = commit(&work, &cfg, "b.txt", "b\n", "side1");
    ok(&work, &cfg, &["branch", "--switch", "main"]);
    commit(&work, &cfg, "a.txt", "a main\n", "main1");
    ok(&work, &cfg, &["merge", "side"]);
    ok(&work, &cfg, &["commit", "-m", "merge"]);
    commit(&work, &cfg, "a.txt", "a main 2\n", "main2");

    let since = |rev: &str| messages(&ok(&work, &cfg, &["log", "--since", rev]));
    assert_eq!(since("HEAD"), Vec::<String>::new());
    assert_eq!(since("HEAD~1"), ["main2"]);
    // side1 contains base, and not main1, which is on main's line.
    assert_eq!(since(&side1), ["main2", "merge", "main1"]);
    assert_eq!(since("side"), ["main2", "merge", "main1"]);
    assert_eq!(since(&base), ["main2", "merge", "main1"]);

    let e = refused(&work, &cfg, &["log", "--since", "nope"]);
    assert!(e.contains("nope"), "{e}");
}

#[test]
fn since_a_release_means_the_commit_it_was_declared_on() {
    let (work, cfg) = setup("since-release");
    commit(&work, &cfg, "a.txt", "a\n", "one");
    let two = commit(&work, &cfg, "a.txt", "a2\n", "two");
    ok(&work, &cfg, &["release", "r1", "-m", "first"]);
    commit(&work, &cfg, "a.txt", "a3\n", "three");
    commit(&work, &cfg, "a.txt", "a4\n", "four");
    assert_eq!(
        messages(&ok(&work, &cfg, &["log", "--since", "r1"])),
        ["four", "three"]
    );
    assert!(ok(&work, &cfg, &["show", "r1"]).contains(&format!("Commit: {two}")));
}

/// `release` followed only an earlier release of the same label, so
/// releases under different labels were never linked, and the chain the
/// technical report describes, the release history apart from the
/// branches, did not exist. Each release now follows the newest.
#[test]
fn release_lists_the_release_chain_newest_first() {
    let (work, cfg) = setup("release");
    commit(&work, &cfg, "a.txt", "a\n", "one");
    let e = refused(&work, &cfg, &["log", "--release"]);
    assert!(e.contains("no releases"), "{e}");

    ok(&work, &cfg, &["release", "r1", "-m", "the first"]);
    commit(&work, &cfg, "a.txt", "a2\n", "two");
    ok(&work, &cfg, &["release", "r2", "-m", "the second"]);
    commit(&work, &cfg, "a.txt", "a3\n", "three");
    ok(&work, &cfg, &["release", "r3"]);

    let out = ok(&work, &cfg, &["log", "--release"]);
    assert_eq!(labels(&out), ["r3", "r2", "r1"], "{out}");
    assert!(
        out.contains("    the second") && out.contains("    the first"),
        "{out}"
    );
    assert_eq!(
        labels(&ok(&work, &cfg, &["log", "--release", "--since", "r1"])),
        ["r3", "r2"]
    );
    assert_eq!(
        labels(&ok(&work, &cfg, &["log", "--release", "--since", "r3"])),
        Vec::<String>::new()
    );
    let e = refused(&work, &cfg, &["log", "--release", "--since", "HEAD"]);
    assert!(e.contains("names a release"), "{e}");
    refused(&work, &cfg, &["log", "--release", "--name-status"]);

    // A label declared again follows the newest release too, and its ref
    // moves from its own value.
    ok(&work, &cfg, &["release", "r1", "-m", "the first, again"]);
    assert_eq!(
        labels(&ok(&work, &cfg, &["log", "--release"])),
        ["r1", "r3", "r2", "r1"]
    );
    assert!(ok(&work, &cfg, &["show", "r1"]).contains("    the first, again"));
    ok(&work, &cfg, &["verify"]);
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

/// What a revision contains is reached through every parent: a side branch
/// that merged main back in contains main's commits up to that merge.
#[test]
fn since_reaches_through_every_parent_of_the_revision() {
    let (work, cfg) = setup("since-back-merge");
    commit(&work, &cfg, "a.txt", "a\n", "base");
    ok(&work, &cfg, &["branch", "--create", "side"]);
    ok(&work, &cfg, &["branch", "--switch", "side"]);
    commit(&work, &cfg, "b.txt", "b\n", "side1");
    ok(&work, &cfg, &["branch", "--switch", "main"]);
    commit(&work, &cfg, "a.txt", "a main\n", "main1");
    ok(&work, &cfg, &["branch", "--switch", "side"]);
    ok(&work, &cfg, &["merge", "main"]);
    ok(&work, &cfg, &["commit", "-m", "main into side"]);
    ok(&work, &cfg, &["branch", "--switch", "main"]);
    commit(&work, &cfg, "a.txt", "a main 2\n", "main2");
    assert_eq!(
        messages(&ok(&work, &cfg, &["log", "--since", "side"])),
        ["main2"]
    );
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
        assert_eq!(
            messages(&ok(&work, &cfg, &["log", "--since", label])),
            ["two"],
            "{label}"
        );
    }
    // The branches still resolve as themselves.
    assert!(ok(&work, &cfg, &["show", "series/next"]).starts_with(&format!("commit {one}")));
    assert!(ok(&work, &cfg, &["show", "stable"]).starts_with(&format!("commit {one}")));
    let e = refused(&work, &cfg, &["show", "stable/v2"]);
    assert!(e.contains("unknown branch or commit"), "{e}");
}
