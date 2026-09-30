//! Path arguments, and the verb that used to act outside the repository.
//!
//! Two properties are pinned here. A relative path means what it says from
//! wherever it is typed, and a path that matches nothing is refused instead of
//! quietly succeeding. Between them they close the cases where a command
//! reported success for something other than what was asked.

use std::process::Command;

fn levcs_bin() -> String {
    env!("CARGO_BIN_EXE_levcs").to_string()
}

fn run(args: &[&str], cwd: &std::path::Path, xdg: &std::path::Path) -> (i32, String, String) {
    let out = Command::new(levcs_bin())
        .args(args)
        .current_dir(cwd)
        .env("XDG_CONFIG_HOME", xdg)
        .output()
        .expect("run levcs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
    )
}

fn tempdir(prefix: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("{prefix}-{n}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A repository with `README.md` at the root *and* in `sub/`, which is the
/// shape that makes a wrong resolution pick a real file rather than miss.
fn nested(prefix: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let work = tempdir(prefix);
    let xdg = work.join("cfg");
    std::fs::create_dir_all(&xdg).unwrap();
    let repo = work.join("r");
    std::fs::create_dir_all(repo.join("sub")).unwrap();

    assert_eq!(run(&["key", "generate", "owner"], &work, &xdg).0, 0);
    std::fs::write(repo.join("README.md"), "root base\n").unwrap();
    std::fs::write(repo.join("sub/README.md"), "sub base\n").unwrap();
    std::fs::write(repo.join("sub/c.txt"), "c base\n").unwrap();
    assert_eq!(run(&["init", "--key", "owner"], &repo, &xdg).0, 0);
    assert_eq!(run(&["track", "--all"], &repo, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &repo, &xdg).0, 0);
    (work, repo, xdg)
}

// --- resolution --------------------------------------------------------------

#[test]
fn a_relative_path_commits_the_file_it_names_from_a_subdirectory() {
    // Regression: paths resolved against the repository root, so this
    // committed the *root* README.md, printed success, and left the file
    // actually named still modified. A signature over a file the signer did
    // not name is the failure the whole system exists to preclude.
    let (work, repo, xdg) = nested("levcs-cwd");
    let sub = repo.join("sub");

    std::fs::write(repo.join("README.md"), "root CHANGED\n").unwrap();
    std::fs::write(sub.join("README.md"), "sub CHANGED\n").unwrap();

    let (code, out, err) = run(&["commit", "-m", "the sub one", "README.md"], &sub, &xdg);
    assert_eq!(code, 0, "commit failed: {err}");
    assert!(
        out.contains("scoped to sub/README.md"),
        "the scope must report the file that was actually taken:\n{out}"
    );

    let (_, status, _) = run(&["status"], &repo, &xdg);
    assert!(
        status.contains("README.md"),
        "the root README.md must still be outstanding:\n{status}"
    );
    assert!(
        !status.contains("sub/README.md"),
        "the named file should be committed:\n{status}"
    );

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn a_relative_path_diffs_the_file_it_names_from_a_subdirectory() {
    // Regression: this printed nothing and exited 0 — "no changes" about a
    // file that had changed.
    let (work, repo, xdg) = nested("levcs-cwd-diff");
    let sub = repo.join("sub");
    std::fs::write(sub.join("c.txt"), "c CHANGED\n").unwrap();

    let (code, out, err) = run(&["diff", "c.txt"], &sub, &xdg);
    assert_eq!(code, 0, "diff failed: {err}");
    assert!(out.contains("c CHANGED"), "diff showed nothing:\n{out}");
    assert!(
        out.contains("sub/c.txt"),
        "output stays repository-relative, which is also the confirmation of \
         what the argument resolved to:\n{out}"
    );

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn a_diff_path_matching_nothing_is_refused_rather_than_empty() {
    let (work, repo, xdg) = nested("levcs-diff-miss");
    let (code, _, err) = run(&["diff", "no-such-file"], &repo, &xdg);
    assert_ne!(
        code, 0,
        "a path matching nothing must not read as 'no changes'"
    );
    assert!(
        err.contains("nothing at 'no-such-file'"),
        "unexpected error: {err}"
    );
    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn a_path_outside_the_repository_is_refused() {
    let (work, repo, xdg) = nested("levcs-outside");
    let (code, _, err) = run(&["commit", "-m", "no", "/etc/hostname"], &repo, &xdg);
    assert_ne!(code, 0);
    assert!(
        err.contains("outside the repository"),
        "unexpected error: {err}"
    );
    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn tracking_a_directory_honors_levcsignore() {
    // `track <dir>` used to run its own descent, which applied only the
    // always-ignored set. So `track --all` and `track sub/` disagreed about
    // what `.levcsignore` meant.
    let (work, repo, xdg) = nested("levcs-track-ignore");
    std::fs::write(repo.join(".levcsignore"), "sub/skipped.txt\n").unwrap();
    std::fs::write(repo.join("sub/skipped.txt"), "ignore me\n").unwrap();
    std::fs::write(repo.join("sub/kept.txt"), "keep me\n").unwrap();

    assert_eq!(run(&["track", "sub"], &repo, &xdg).0, 0);

    // Tracked: editing it makes it modified.
    std::fs::write(repo.join("sub/kept.txt"), "keep me, edited\n").unwrap();
    let (_, status, _) = run(&["status"], &repo, &xdg);
    assert!(
        status.contains("sub/kept.txt"),
        "kept.txt should have been tracked:\n{status}"
    );

    // Not tracked: removing it from disk would show as a deletion if it were.
    std::fs::remove_file(repo.join("sub/skipped.txt")).unwrap();
    let (_, status, _) = run(&["status"], &repo, &xdg);
    assert!(
        !status.contains("skipped.txt"),
        "the ignored file must not have been tracked:\n{status}"
    );

    let _ = std::fs::remove_dir_all(work);
}

// --- forget ------------------------------------------------------------------

#[test]
fn forget_untracks_and_leaves_the_file_alone() {
    let (work, repo, xdg) = nested("levcs-forget");
    let (code, out, err) = run(&["forget", "sub/c.txt"], &repo, &xdg);
    assert_eq!(code, 0, "forget failed: {err}");
    assert!(
        out.contains("untracked sub/c.txt"),
        "forget said nothing:\n{out}"
    );
    assert!(
        repo.join("sub/c.txt").exists(),
        "forget must not delete by default"
    );

    let (_, status, _) = run(&["status"], &repo, &xdg);
    assert!(
        status.contains("untracked:"),
        "the file should now be untracked:\n{status}"
    );

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn forget_delete_removes_the_file() {
    let (work, repo, xdg) = nested("levcs-forget-del");
    let (code, out, err) = run(&["forget", "--delete", "sub/c.txt"], &repo, &xdg);
    assert_eq!(code, 0, "forget --delete failed: {err}");
    assert!(out.contains("deleted"), "{out}");
    assert!(
        !repo.join("sub/c.txt").exists(),
        "--delete should remove it"
    );

    // And it is recoverable, because only tracked paths can be named.
    assert_eq!(run(&["construct", "sub/c.txt"], &repo, &xdg).0, 0);
    assert_eq!(
        std::fs::read_to_string(repo.join("sub/c.txt")).unwrap(),
        "c base\n"
    );

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn forget_refuses_a_path_it_never_tracked_and_does_not_delete_it() {
    // Regression, and the sharpest one: `forget` acted on the filesystem
    // rather than on the repository, so this deleted a file the repository
    // had never tracked — exit 0, no output, and nothing in the object store
    // to restore from.
    let (work, repo, xdg) = nested("levcs-forget-untracked");
    std::fs::write(repo.join("never.txt"), "not the vcs's to destroy\n").unwrap();

    let (code, _, err) = run(&["forget", "never.txt"], &repo, &xdg);
    assert_ne!(code, 0, "forget must refuse an untracked path");
    assert!(
        err.contains("nothing tracked at 'never.txt'"),
        "unexpected error: {err}"
    );
    assert!(
        repo.join("never.txt").exists(),
        "the file must survive; it was never the repository's to delete"
    );

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn forget_expands_a_directory_to_the_tracked_files_beneath_it() {
    // It used to silently do nothing for a directory: `idx.remove("sub")`
    // matched no entry and `remove_file` on a directory failed into a
    // swallowed error.
    let (work, repo, xdg) = nested("levcs-forget-dir");
    let (code, out, err) = run(&["forget", "sub"], &repo, &xdg);
    assert_eq!(code, 0, "forget of a directory failed: {err}");
    assert!(
        out.contains("sub/c.txt") && out.contains("sub/README.md"),
        "{out}"
    );

    let (_, status, _) = run(&["status"], &repo, &xdg);
    assert!(
        !status.contains("modified:"),
        "nothing was edited, only untracked:\n{status}"
    );

    let _ = std::fs::remove_dir_all(work);
}

// --- scoped commits carry only what was named ---------------------------------

#[test]
fn a_scoped_commit_leaves_a_newly_tracked_file_staged_not_committed() {
    // Regression: out-of-scope entries came from the index, so a file tracked
    // since HEAD was sealed into a commit that never named it.
    let (work, repo, xdg) = nested("levcs-scope-tracked");
    std::fs::write(repo.join("extra.txt"), "not this commit's\n").unwrap();
    assert_eq!(run(&["track", "extra.txt"], &repo, &xdg).0, 0);
    std::fs::write(repo.join("README.md"), "root CHANGED\n").unwrap();
    let (code, _, err) = run(&["commit", "-m", "readme only", "README.md"], &repo, &xdg);
    assert_eq!(code, 0, "{err}");

    std::fs::remove_file(repo.join("extra.txt")).unwrap();
    let (code, _, _) = run(&["construct", "HEAD", "extra.txt"], &repo, &xdg);
    assert_ne!(code, 0, "extra.txt must not be in the commit");
    assert!(!repo.join("extra.txt").exists());

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn a_scoped_commit_does_not_commit_a_pending_forget() {
    // Regression: a file forgotten since HEAD vanished from the tree of an
    // unrelated scoped commit.
    let (work, repo, xdg) = nested("levcs-scope-forgotten");
    assert_eq!(run(&["forget", "sub/c.txt"], &repo, &xdg).0, 0);
    std::fs::write(repo.join("README.md"), "root CHANGED\n").unwrap();
    let (code, _, err) = run(&["commit", "-m", "readme only", "README.md"], &repo, &xdg);
    assert_eq!(code, 0, "{err}");

    std::fs::remove_file(repo.join("sub/c.txt")).unwrap();
    let (code, _, err) = run(&["construct", "HEAD", "sub/c.txt"], &repo, &xdg);
    assert_eq!(code, 0, "c.txt must still be in HEAD: {err}");
    assert_eq!(
        std::fs::read_to_string(repo.join("sub/c.txt")).unwrap(),
        "c base\n"
    );

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn a_scoped_commit_cannot_finalize_a_merge() {
    // Regression: the conflict in sub/c.txt was outside the scope, so the
    // per-file marker check never saw it; the merge commit sealed the markers
    // and cleared MERGE_HEAD.
    let (work, repo, xdg) = nested("levcs-scope-merge");
    assert_eq!(run(&["branch", "--create", "feat"], &repo, &xdg).0, 0);
    std::fs::write(repo.join("sub/c.txt"), "main version\n").unwrap();
    assert_eq!(run(&["commit", "-m", "main edit"], &repo, &xdg).0, 0);
    assert_eq!(run(&["branch", "--switch", "feat"], &repo, &xdg).0, 0);
    std::fs::write(repo.join("sub/c.txt"), "feat version\n").unwrap();
    assert_eq!(run(&["commit", "-m", "feat edit"], &repo, &xdg).0, 0);
    assert_eq!(run(&["branch", "--switch", "main"], &repo, &xdg).0, 0);
    assert_ne!(run(&["merge", "feat"], &repo, &xdg).0, 0);
    assert!(repo.join(".levcs/MERGE_HEAD").exists());

    std::fs::write(repo.join("README.md"), "root CHANGED\n").unwrap();
    let (code, _, err) = run(&["commit", "-m", "readme only", "README.md"], &repo, &xdg);
    assert_ne!(code, 0);
    assert!(err.contains("merge is in progress"), "{err}");
    assert!(
        repo.join(".levcs/MERGE_HEAD").exists(),
        "merge state must survive"
    );

    let _ = std::fs::remove_dir_all(work);
}
