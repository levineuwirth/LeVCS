//! The working tree keeps what is not committed, and levcs never reads it
//! through a symlink.
//!
//! - **Uncommitted work.** A switch wrote the target over uncommitted edits.
//!   A fast-forward wrote over untracked files and staged changes. A merge
//!   wrote over an untracked file where the other side added one. These
//!   are the audit's `audit_worktree` reproductions.
//! - **Symlinks.** Every read followed them, so a link to a file outside
//!   the repository committed that file's bytes. levcs now neither follows
//!   nor records links (the author's decision, after Fossil's).
//! - **Ignored but tracked.** `status` and `diff` read only the
//!   ignore-filtered walk, so a tracked file matching an ignore pattern was
//!   reported deleted, and `diff HEAD` showed it removed whole.
//! - **Staged work.** `status` compared the working tree with the index
//!   only, so a change staged with `track`, a newly tracked file and a
//!   forgotten one showed nowhere, though a switch refused over them (the
//!   audit's H7).

#![cfg(unix)]

use std::os::unix::fs::symlink;
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

struct Repo {
    work: PathBuf,
    cfg: PathBuf,
    outside: PathBuf,
}

impl Repo {
    fn ok(&self, args: &[&str]) -> String {
        let o = levcs(&self.work, &self.cfg, args);
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        )
    }
    fn refused(&self, args: &[&str]) -> String {
        let o = levcs(&self.work, &self.cfg, args);
        let e = String::from_utf8_lossy(&o.stderr).into_owned();
        assert!(!o.status.success(), "{args:?} succeeded: {e}");
        e
    }
    fn write(&self, path: &str, text: &str) {
        let p = self.work.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
    fn read(&self, path: &str) -> String {
        std::fs::read_to_string(self.work.join(path)).unwrap()
    }
    fn commit(&self, files: &[(&str, &str)], message: &str) {
        for (p, t) in files {
            self.write(p, t);
            self.ok(&["track", p]);
        }
        self.ok(&["commit", "-m", message]);
    }
    fn head(&self) -> String {
        std::fs::read_to_string(self.work.join(".levcs/HEAD")).unwrap()
    }
    fn branch(&self, name: &str) -> Option<String> {
        std::fs::read_to_string(self.work.join(".levcs/refs/branches").join(name)).ok()
    }
}

/// The paths `status` lists under the heading that begins with `name`.
fn section(status: &str, name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut on = false;
    for line in status.lines() {
        if let Some(path) = line.strip_prefix("  ") {
            if on {
                out.push(path.to_string());
            }
        } else if !line.is_empty() {
            on = line.ends_with(':')
                && (line == format!("{name}:") || line.starts_with(&format!("{name} (")));
        }
    }
    out
}

/// The paths a refusal names, from its `  path  (why)` lines.
fn named(refusal: &str) -> Vec<String> {
    let mut out: Vec<String> = refusal
        .lines()
        .filter_map(|l| l.strip_prefix("  "))
        .filter_map(|l| l.split("  (").next())
        .map(str::to_string)
        .collect();
    out.sort();
    out
}

fn repo(tag: &str) -> Repo {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("levcs-wti-{tag}-{}-{stamp}", std::process::id()));
    let r = Repo {
        work: base.join("w"),
        cfg: base.join("cfg"),
        outside: base.join("outside"),
    };
    std::fs::create_dir_all(&r.work).unwrap();
    std::fs::create_dir_all(&r.outside).unwrap();
    r.ok(&["init", "--key", "owner"]);
    r
}

/// `main` with `data.json` and `notes.md`; branch `feature` changes
/// `data.json` and adds `new.txt`. Ends on `main`.
fn diverged(tag: &str) -> Repo {
    let r = repo(tag);
    r.commit(
        &[("data.json", "{\"v\":0}\n"), ("notes.md", "notes\n")],
        "base",
    );
    r.ok(&["branch", "--create", "feature"]);
    r.ok(&["branch", "--switch", "feature"]);
    r.commit(
        &[("data.json", "{\"v\":1}\n"), ("new.txt", "feature\n")],
        "feature",
    );
    r.ok(&["branch", "--switch", "main"]);
    r
}

// Uncommitted work.

/// The audit's `audit_branch_switch_discards_dirty_work`.
#[test]
fn a_switch_refuses_to_overwrite_an_uncommitted_edit() {
    let r = diverged("switch-edit");
    r.write("data.json", "uncommitted valuable work");
    let head = r.head();
    let e = r.refused(&["branch", "--switch", "feature"]);
    assert!(
        e.contains("data.json") && e.contains("changed and not committed"),
        "{e}"
    );
    assert_eq!(r.read("data.json"), "uncommitted valuable work");
    assert_eq!(r.head(), head);
    // Put back as committed, the same switch goes through.
    r.ok(&["construct", "HEAD", "data.json"]);
    r.ok(&["branch", "--switch", "feature"]);
    assert_eq!(r.read("data.json"), "{\"v\":1}\n");
}

/// An edit to a file both branches have alike is carried over, as Git
/// does: the switch does not touch that file.
#[test]
fn a_switch_carries_an_edit_to_a_file_both_branches_share() {
    let r = diverged("switch-carry");
    r.write("notes.md", "edited, not committed\n");
    r.ok(&["branch", "--switch", "feature"]);
    assert_eq!(r.read("notes.md"), "edited, not committed\n");
    assert_eq!(r.read("data.json"), "{\"v\":1}\n");
    assert!(r.ok(&["status"]).contains("notes.md"));
}

/// A committed file the target lacks is removed, if it is as committed;
/// changed, it refuses the switch. Files the target lacks used to be left
/// behind.
#[test]
fn a_switch_removes_files_the_target_lacks_unless_they_hold_work() {
    let r = diverged("switch-remove");
    r.ok(&["branch", "--switch", "feature"]);
    r.ok(&["branch", "--switch", "main"]);
    assert!(!r.work.join("new.txt").exists());

    r.ok(&["branch", "--switch", "feature"]);
    r.write("new.txt", "edited on feature, not committed\n");
    let e = r.refused(&["branch", "--switch", "main"]);
    assert!(e.contains("new.txt"), "{e}");
    assert_eq!(r.read("new.txt"), "edited on feature, not committed\n");
}

/// Staged changes are work. One to a file the switch rewrites is refused;
/// one to a file both branches share is carried into the rebuilt index,
/// still staged, as edits are.
#[test]
fn a_switch_refuses_staged_work_it_would_overwrite_and_carries_the_rest() {
    let r = diverged("switch-staged");
    r.write("data.json", "{\"v\":\"staged\"}\n");
    r.ok(&["track", "data.json"]);
    let e = r.refused(&["branch", "--switch", "feature"]);
    assert!(e.contains("data.json") && e.contains("staged"), "{e}");
    assert_eq!(r.read("data.json"), "{\"v\":\"staged\"}\n");

    r.ok(&["construct", "HEAD", "data.json"]);
    r.ok(&["track", "data.json"]);
    r.write("notes.md", "staged notes\n");
    r.ok(&["track", "notes.md"]);
    r.ok(&["branch", "--switch", "feature"]);
    assert_eq!(r.read("notes.md"), "staged notes\n");
    // Still staged: the index holds it, so status lists it as staged and
    // not as modified.
    let status = r.ok(&["status"]);
    assert_eq!(section(&status, "staged"), ["notes.md"], "{status}");
    assert!(section(&status, "modified").is_empty(), "{status}");
    // Committing takes it, with nothing further tracked.
    r.ok(&["commit", "-m", "carried", "--", "notes.md"]);
    assert!(r.ok(&["status"]).contains("working tree clean"));
}

/// An untracked file where the target has one, or a link: refused.
#[test]
fn a_switch_refuses_an_untracked_file_or_a_link_where_the_target_has_a_file() {
    let r = diverged("switch-untracked");
    r.write("new.txt", "mine, untracked\n");
    let e = r.refused(&["branch", "--switch", "feature"]);
    assert!(e.contains("new.txt") && e.contains("untracked"), "{e}");
    assert_eq!(r.read("new.txt"), "mine, untracked\n");

    std::fs::remove_file(r.work.join("new.txt")).unwrap();
    std::fs::write(r.outside.join("secret"), "protected").unwrap();
    symlink(r.outside.join("secret"), r.work.join("new.txt")).unwrap();
    let e = r.refused(&["branch", "--switch", "feature"]);
    assert!(e.contains("new.txt") && e.contains("symlink"), "{e}");
    assert_eq!(
        std::fs::read_to_string(r.outside.join("secret")).unwrap(),
        "protected"
    );
}

/// The audit's `audit_fast_forward_overwrites_untracked_file`.
#[test]
fn a_fast_forward_refuses_to_overwrite_an_untracked_file() {
    let r = diverged("ff-untracked");
    r.write("new.txt", "local untracked valuable work");
    let main = r.branch("main");
    let e = r.refused(&["merge", "feature"]);
    assert!(e.contains("new.txt") && e.contains("untracked"), "{e}");
    assert_eq!(r.read("new.txt"), "local untracked valuable work");
    assert_eq!(r.branch("main"), main);
}

/// The audit's `audit_fast_forward_overwrites_staged_work`: the merge's
/// check compared with the index, so staged work counted as clean.
#[test]
fn a_merge_refuses_over_staged_work() {
    let r = diverged("ff-staged");
    r.write("data.json", "{\"v\":99}\n");
    r.ok(&["track", "data.json"]);
    let main = r.branch("main");
    let e = r.refused(&["merge", "feature"]);
    assert!(e.contains("data.json") && e.contains("staged"), "{e}");
    assert_eq!(r.read("data.json"), "{\"v\":99}\n");
    assert_eq!(r.branch("main"), main);
}

/// A three-way merge writes the files the other side added: an untracked
/// file there is refused, not overwritten.
#[test]
fn a_three_way_merge_refuses_to_overwrite_an_untracked_file() {
    let r = diverged("merge-untracked");
    r.commit(&[("notes.md", "main's notes\n")], "main");
    r.write("new.txt", "mine, untracked\n");
    let e = r.refused(&["merge", "feature"]);
    assert!(e.contains("new.txt") && e.contains("untracked"), "{e}");
    assert_eq!(r.read("new.txt"), "mine, untracked\n");
    assert!(!r.work.join(".levcs/MERGE_HEAD").exists());
}

// Symlinks: never followed, never recorded.

/// Naming a link is refused, and nothing of its target reaches the store.
#[test]
fn track_refuses_a_symlink_and_stores_nothing_of_its_target() {
    let r = repo("track-link");
    let secret = "a private key that lives outside the repository\n";
    std::fs::write(r.outside.join("secret"), secret).unwrap();
    symlink(r.outside.join("secret"), r.work.join("link.txt")).unwrap();
    let e = r.refused(&["track", "link.txt"]);
    assert!(e.contains("symlink"), "{e}");
    let blob = levcs_core::Blob::new(secret.as_bytes().to_vec()).object_id();
    let hex = blob.to_hex();
    assert!(
        !r.work
            .join(".levcs/objects")
            .join(&hex[..2])
            .join(&hex[2..])
            .exists(),
        "the link's target was stored"
    );
}

/// A path reached through a linked directory is refused too.
#[test]
fn track_refuses_a_path_through_a_symlinked_directory() {
    let r = repo("track-through");
    std::fs::write(r.outside.join("f.txt"), "outside\n").unwrap();
    symlink(&r.outside, r.work.join("linkdir")).unwrap();
    let e = r.refused(&["track", "linkdir/f.txt"]);
    assert!(e.contains("symlink"), "{e}");
}

/// A directory or `--all` passes links over, saying so, and tracks the rest.
#[test]
fn track_skips_symlinks_in_a_directory_and_says_so() {
    let r = repo("track-skip");
    r.write("dir/real.txt", "real\n");
    std::fs::write(r.outside.join("secret"), "protected").unwrap();
    symlink(r.outside.join("secret"), r.work.join("dir/link.txt")).unwrap();
    let out = r.ok(&["track", "dir"]);
    assert!(
        out.contains("skipped") && out.contains("dir/link.txt"),
        "{out}"
    );
    let out = r.ok(&["track", "--all"]);
    assert!(out.contains("dir/link.txt"), "{out}");
    r.ok(&["commit", "-m", "real only"]);
    let status = r.ok(&["status"]);
    assert!(
        status.contains("symlinks") && status.contains("dir/link.txt"),
        "{status}"
    );
}

/// A tracked file replaced by a link is not committed as its target.
#[test]
fn commit_refuses_a_tracked_file_replaced_by_a_symlink() {
    let r = repo("commit-link");
    r.commit(&[("a.txt", "a\n")], "base");
    std::fs::remove_file(r.work.join("a.txt")).unwrap();
    std::fs::write(r.outside.join("secret"), "protected").unwrap();
    symlink(r.outside.join("secret"), r.work.join("a.txt")).unwrap();
    let status = r.ok(&["status"]);
    assert!(status.contains("no longer a regular file"), "{status}");
    let e = r.refused(&["commit", "-m", "x"]);
    assert!(e.contains("a.txt") && e.contains("symlink"), "{e}");
}

/// A cache saves files, never what a link points at.
#[test]
fn cache_save_skips_symlinks() {
    let r = repo("cache-link");
    r.commit(&[("a.txt", "a\n")], "base");
    std::fs::write(r.outside.join("secret"), "protected").unwrap();
    symlink(r.outside.join("secret"), r.work.join("link.txt")).unwrap();
    let out = r.ok(&["cache", "--save"]);
    assert!(out.contains("skipped") && out.contains("link.txt"), "{out}");
    let cache = std::fs::read_dir(r.work.join(".levcs/cache/workdir"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    assert!(cache.join("a.txt").exists());
    assert!(!cache.join("link.txt").exists());
}

// Ignored but tracked.

/// A file tracked by naming it, though it matches an ignore pattern, is
/// compared where it is. It was reported deleted, `diff HEAD` showed it
/// removed whole, and a merge refused over it.
#[test]
fn an_ignored_but_tracked_file_is_not_reported_deleted() {
    let r = repo("ignored-tracked");
    r.write(".levcsignore", "pdf\n");
    r.ok(&["track", ".levcsignore"]);
    r.write("pdf/paper.pdf", "%PDF-1.4 not really\n");
    r.ok(&["track", "pdf/paper.pdf"]);
    let then = r.ok(&["commit", "-m", "a paper, named"]);
    let then = then
        .lines()
        .next()
        .and_then(|l| l.strip_prefix('['))
        .and_then(|l| l.split(']').next())
        .unwrap()
        .to_string();
    let status = r.ok(&["status"]);
    assert!(!status.contains("deleted"), "{status}");
    assert!(status.contains("working tree clean"), "{status}");
    let diff = r.ok(&["diff", "HEAD"]);
    assert!(!diff.contains("paper.pdf"), "{diff}");
    // A change to it is seen, and a merge is not refused over it unchanged.
    r.ok(&["branch", "--create", "other"]);
    r.ok(&["branch", "--switch", "other"]);
    r.commit(&[("b.txt", "b\n")], "other");
    r.ok(&["branch", "--switch", "main"]);
    r.ok(&["merge", "other"]);
    r.write("pdf/paper.pdf", "%PDF-1.4 changed\n");
    assert!(r.ok(&["status"]).contains("modified"));

    // Against an older commit, a file tracked then and no longer (still on
    // disk, still ignored) is compared too, not shown removed.
    r.write("pdf/paper.pdf", "%PDF-1.4 not really\n");
    r.ok(&["forget", "pdf/paper.pdf"]);
    r.ok(&["commit", "-m", "forgotten, kept on disk"]);
    let diff = r.ok(&["diff", &then]);
    assert!(!diff.contains("paper.pdf"), "{diff}");
}

// Cases from the review (2026-10-08).

/// A merge whose result lacks a path HEAD no longer tracks leaves the
/// working tree there alone: a file there is untracked. A merge deleted it.
#[test]
fn a_merge_never_deletes_an_untracked_file() {
    let r = repo("merge-delete-untracked");
    r.commit(&[("old.txt", "old\n"), ("notes.md", "notes\n")], "base");
    r.ok(&["branch", "--create", "topic"]);
    r.ok(&["forget", "--delete", "old.txt"]);
    r.ok(&["commit", "-m", "drop old.txt"]);
    r.ok(&["branch", "--switch", "topic"]);
    r.commit(&[("notes.md", "topic notes\n")], "topic");
    r.ok(&["branch", "--switch", "main"]);
    r.write("old.txt", "mine now, untracked\n");
    r.ok(&["merge", "topic"]);
    assert_eq!(r.read("old.txt"), "mine now, untracked\n");
}

/// A staged executable bit is a staged change: carried by a switch that
/// does not touch the file, and refusing a merge even with the file's mode
/// put back on disk. It was compared by content only, and discarded.
#[test]
fn a_staged_executable_bit_is_kept() {
    use std::os::unix::fs::PermissionsExt;
    let r = repo("staged-mode");
    r.commit(&[("script.sh", "echo hi\n"), ("a.txt", "a\n")], "base");
    r.ok(&["branch", "--create", "other"]);
    r.ok(&["branch", "--switch", "other"]);
    r.commit(&[("a.txt", "other\n")], "other");
    r.ok(&["branch", "--switch", "main"]);
    let chmod = |m: u32| {
        std::fs::set_permissions(r.work.join("script.sh"), std::fs::Permissions::from_mode(m))
            .unwrap()
    };
    chmod(0o755);
    r.ok(&["track", "script.sh"]);
    r.ok(&["branch", "--switch", "other"]);
    let status = r.ok(&["status"]);
    assert_eq!(
        section(&status, "staged"),
        ["script.sh"],
        "staged mode lost: {status}"
    );
    assert!(section(&status, "modified").is_empty(), "{status}");

    chmod(0o644);
    let e = r.refused(&["merge", "main"]);
    assert!(e.contains("script.sh") && e.contains("staged"), "{e}");
}

/// Every blob of the target is read and checked before anything changes,
/// including a file the move does not write. A missing one failed only
/// after other files were written and HEAD moved, leaving the old index.
#[test]
fn a_missing_target_blob_refuses_the_move_before_anything_changes() {
    let r = repo("missing-blob");
    r.commit(&[("shared.txt", "shared\n"), ("a.txt", "a\n")], "base");
    r.ok(&["branch", "--create", "other"]);
    r.ok(&["branch", "--switch", "other"]);
    r.commit(&[("a.txt", "other\n")], "other");
    r.ok(&["branch", "--switch", "main"]);
    let hex = levcs_core::Blob::new(b"shared\n".to_vec())
        .object_id()
        .to_hex();
    std::fs::remove_file(
        r.work
            .join(".levcs/objects")
            .join(&hex[..2])
            .join(&hex[2..]),
    )
    .unwrap();
    let state = |r: &Repo| {
        (
            r.head(),
            r.branch("main"),
            std::fs::read(r.work.join(".levcs/index")).ok(),
            r.read("a.txt"),
        )
    };
    let before = state(&r);
    r.refused(&["branch", "--switch", "other"]);
    assert_eq!(state(&r), before, "a refused switch changed something");
    r.refused(&["merge", "other"]);
    assert_eq!(
        state(&r),
        before,
        "a refused fast-forward changed something"
    );
}

// Staged work in `status`.

/// The audit's H7. A change staged with `track`, a staged mode, a newly
/// tracked file and two forgotten ones, one gone from disk and one still
/// there but ignored: `status` compared the working tree with the index,
/// found them alike, and said the working tree was clean.
#[test]
fn status_lists_what_the_index_holds_that_head_does_not() {
    use std::os::unix::fs::PermissionsExt;
    let r = repo("status-staged");
    r.commit(
        &[
            (".levcsignore", "pdf\n"),
            ("a.txt", "a\n"),
            ("b.sh", "echo b\n"),
            ("c.txt", "c\n"),
            ("pdf/paper.pdf", "%PDF-1.4 not really\n"),
        ],
        "base",
    );
    r.write("a.txt", "a, staged\n");
    r.ok(&["track", "a.txt"]);
    std::fs::set_permissions(r.work.join("b.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    r.ok(&["track", "b.sh"]);
    r.ok(&["forget", "c.txt"]);
    std::fs::remove_file(r.work.join("c.txt")).unwrap();
    r.ok(&["forget", "pdf/paper.pdf"]);
    r.write("d.txt", "d\n");
    r.ok(&["track", "d.txt"]);

    let status = r.ok(&["status"]);
    assert!(!status.contains("working tree clean"), "{status}");
    assert_eq!(section(&status, "new"), ["d.txt"], "{status}");
    assert_eq!(section(&status, "staged"), ["a.txt", "b.sh"], "{status}");
    assert_eq!(
        section(&status, "no longer tracked"),
        ["c.txt", "pdf/paper.pdf"],
        "{status}"
    );
    assert!(section(&status, "modified").is_empty(), "{status}");

    // Committing takes all of it, and leaves the ignored file on disk.
    r.ok(&["commit", "-m", "everything staged"]);
    let status = r.ok(&["status"]);
    assert!(status.contains("working tree clean"), "{status}");
    assert_eq!(r.read("pdf/paper.pdf"), "%PDF-1.4 not really\n");
}

/// `status` lists every path a refusal names as uncommitted, and nothing
/// else that is tracked: what a merge refuses over is what `status` shows.
/// A switch used to refuse over staged work `status` called clean.
#[test]
fn status_lists_exactly_what_a_merge_refuses_over() {
    use std::os::unix::fs::PermissionsExt;
    let r = repo("status-agrees");
    r.commit(
        &[
            (".levcsignore", "pdf\n"),
            ("a.txt", "a\n"),
            ("b.sh", "echo b\n"),
            ("c.txt", "c\n"),
            ("e.txt", "e\n"),
            ("f.txt", "f\n"),
            ("same.txt", "same\n"),
            ("pdf/paper.pdf", "%PDF-1.4 not really\n"),
        ],
        "base",
    );
    r.ok(&["branch", "--create", "other"]);
    r.ok(&["branch", "--switch", "other"]);
    r.commit(&[("g.txt", "g\n")], "other");
    r.ok(&["branch", "--switch", "main"]);

    // Staged, then edited again: staged and modified both.
    r.write("a.txt", "a, staged\n");
    r.ok(&["track", "a.txt"]);
    r.write("a.txt", "a, edited after\n");
    std::fs::set_permissions(r.work.join("b.sh"), std::fs::Permissions::from_mode(0o755)).unwrap();
    r.ok(&["track", "b.sh"]);
    r.ok(&["forget", "c.txt"]);
    std::fs::remove_file(r.work.join("c.txt")).unwrap();
    r.ok(&["forget", "pdf/paper.pdf"]);
    r.write("d.txt", "d\n");
    r.ok(&["track", "d.txt"]);
    r.write("e.txt", "e, edited\n");
    std::fs::remove_file(r.work.join("f.txt")).unwrap();
    // Staged, then put back on disk: only the index differs.
    r.write("same.txt", "same, staged\n");
    r.ok(&["track", "same.txt"]);
    r.write("same.txt", "same\n");

    let e = r.refused(&["merge", "other"]);
    assert!(e.contains("levcs track <path>"), "{e}");
    let status = r.ok(&["status"]);
    let mut listed: Vec<String> = [
        "new",
        "staged",
        "no longer tracked",
        "modified",
        "deleted",
        "no longer a regular file",
    ]
    .iter()
    .flat_map(|s| section(&status, s))
    .collect();
    listed.sort();
    listed.dedup();
    let expected = [
        "a.txt",
        "b.sh",
        "c.txt",
        "d.txt",
        "e.txt",
        "f.txt",
        "pdf/paper.pdf",
        "same.txt",
    ];
    assert_eq!(named(&e), expected, "{e}");
    assert_eq!(listed, expected, "{status}");
}
