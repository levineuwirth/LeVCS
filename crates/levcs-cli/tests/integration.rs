//! End-to-end integration tests driving the `levcs` binary like a user.

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

#[test]
fn end_to_end_init_track_commit_log_verify() {
    let work = tempdir("levcs-it");
    let xdg = work.join("cfg");
    std::fs::create_dir_all(&xdg).unwrap();

    // init
    let (code, _o, e) = run(&["init", "--key", "alice"], &work, &xdg);
    assert_eq!(code, 0, "init failed: {e}");

    // write file, track, commit
    std::fs::write(work.join("a.txt"), b"hello\n").unwrap();
    let (code, _, e) = run(&["track", "--all"], &work, &xdg);
    assert_eq!(code, 0, "track failed: {e}");
    let (code, _, e) = run(&["commit", "-m", "first"], &work, &xdg);
    assert_eq!(code, 0, "commit failed: {e}");

    // status should be clean
    let (code, o, _) = run(&["status"], &work, &xdg);
    assert_eq!(code, 0);
    assert!(o.contains("working tree clean"));

    // verify
    let (code, _, e) = run(&["verify"], &work, &xdg);
    assert_eq!(code, 0, "verify failed: {e}");

    // log should show one commit
    let (code, o, _) = run(&["log"], &work, &xdg);
    assert_eq!(code, 0);
    assert!(o.contains("first"));

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn authority_chain_round_trip() {
    let work = tempdir("levcs-auth");
    let xdg = work.join("cfg");
    std::fs::create_dir_all(&xdg).unwrap();

    let (code, _, e) = run(&["init", "--key", "alice"], &work, &xdg);
    assert_eq!(code, 0, "init: {e}");

    std::fs::write(work.join("README"), b"hi\n").unwrap();
    run(&["track", "--all"], &work, &xdg);
    run(&["commit", "-m", "init"], &work, &xdg);

    // Generate bob and add as contributor
    let (_, _, _) = run(&["key", "generate", "bob"], &work, &xdg);
    let (_, bob_pub, _) = run(&["key", "show", "bob"], &work, &xdg);
    let bob_pub = bob_pub.trim().to_string();
    let (code, _, e) = run(
        &[
            "authority",
            "add",
            &bob_pub,
            "--role",
            "contributor",
            "--handle",
            "bob",
        ],
        &work,
        &xdg,
    );
    assert_eq!(code, 0, "authority add: {e}");

    // Bob commits
    std::fs::write(work.join("BOB"), b"bob's note\n").unwrap();
    run(&["track", "--all"], &work, &xdg);
    let (code, _, e) = run(&["commit", "-m", "bob's edit", "--key", "bob"], &work, &xdg);
    assert_eq!(code, 0, "bob's commit: {e}");

    // Verify the entire chain
    let (code, _, e) = run(&["verify"], &work, &xdg);
    assert_eq!(code, 0, "verify: {e}");

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn branch_create_and_switch() {
    let work = tempdir("levcs-branch");
    let xdg = work.join("cfg");
    std::fs::create_dir_all(&xdg).unwrap();
    run(&["init", "--key", "alice"], &work, &xdg);
    std::fs::write(work.join("a.txt"), b"hi\n").unwrap();
    run(&["track", "--all"], &work, &xdg);
    run(&["commit", "-m", "first"], &work, &xdg);

    let (code, _, _) = run(&["branch", "--create", "dev"], &work, &xdg);
    assert_eq!(code, 0);
    let (_, o, _) = run(&["branch", "--list"], &work, &xdg);
    assert!(o.contains("dev"));
    assert!(o.contains("main"));

    let _ = std::fs::remove_dir_all(work);
}

/// `gc` keeps unreachable objects newer than the grace period and
/// removes them once the period expires (§4.2.2). Drop a synthetic
/// hex-named file into the object store to give gc something
/// unreachable to reason about.
#[test]
fn gc_grace_period_keeps_young_objects_and_deletes_old_ones() {
    let work = tempdir("levcs-gc");
    let xdg = work.join("cfg");
    std::fs::create_dir_all(&xdg).unwrap();
    run(&["init", "--key", "alice"], &work, &xdg);
    std::fs::write(work.join("a.txt"), b"hi\n").unwrap();
    run(&["track", "--all"], &work, &xdg);
    run(&["commit", "-m", "first"], &work, &xdg);

    // Drop a hex-named "object" file into the sharded store. The
    // contents are arbitrary; gc's only reachability rule is "is the
    // hash visible from any ref?", so this name is unreachable by
    // construction.
    let stray_dir = work.join(".levcs/objects/ff");
    std::fs::create_dir_all(&stray_dir).unwrap();
    // The shard prefix is the first 2 hex chars; the on-disk filename
    // is the *remaining* 62. iter_ids reconstructs the full 64-char
    // hash from prefix + filename.
    let stray = stray_dir.join("ff".repeat(31));
    std::fs::write(&stray, b"unreachable garbage").unwrap();
    assert!(stray.is_file());

    // Default grace (14 days) — the just-written stray file is way
    // younger than that, so it must be kept.
    let (code, _, e) = run(&["gc"], &work, &xdg);
    assert_eq!(code, 0, "gc default: {e}");
    assert!(
        stray.is_file(),
        "young unreachable object must be kept under default grace"
    );
    assert!(e.contains("kept"), "gc must report kept count: {e}");

    // Force grace=0 and the stray file must go.
    let (code, _, e) = run(&["gc", "--grace-days=0"], &work, &xdg);
    assert_eq!(code, 0, "gc grace=0: {e}");
    assert!(
        !stray.is_file(),
        "with grace=0 the unreachable object must be deleted"
    );
    assert!(e.contains("removed"), "gc must report deletion count: {e}");

    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn a_refused_commit_leaves_the_repository_reporting_dirty() {
    // Regression: the authority check ran *after* the staged index was
    // written, so a commit refused for authorship still persisted the index.
    // `status` then compared the working tree against that index and reported
    // "working tree clean" while `diff` still showed the change against HEAD.
    // A repository that reports clean while holding uncommitted work is worse
    // than one that refuses loudly.
    let work = tempdir("levcs-refused");
    let xdg = work.join("cfg");
    std::fs::create_dir_all(&xdg).unwrap();

    let repo = work.join("r");
    std::fs::create_dir_all(&repo).unwrap();

    for label in ["owner", "outsider"] {
        let (c, _, e) = run(&["key", "generate", label], &work, &xdg);
        assert_eq!(c, 0, "key generate {label}: {e}");
    }

    std::fs::write(repo.join("a.txt"), "one\n").unwrap();
    assert_eq!(run(&["init", "--key", "owner"], &repo, &xdg).0, 0);
    assert_eq!(run(&["track", "--all"], &repo, &xdg).0, 0);
    assert_eq!(
        run(&["commit", "-m", "base", "--key", "owner"], &repo, &xdg).0,
        0
    );

    // Change the tree, then have the commit refused.
    std::fs::write(repo.join("a.txt"), "one\ntwo\n").unwrap();
    let (code, _, err) = run(&["commit", "-m", "no", "--key", "outsider"], &repo, &xdg);
    assert_ne!(code, 0, "a commit by a non-member must fail");
    assert!(
        err.contains("not in the current authority"),
        "unexpected refusal: {err}"
    );

    // The two views must agree that work is outstanding.
    let (_, status, _) = run(&["status"], &repo, &xdg);
    assert!(
        !status.contains("working tree clean"),
        "status reported clean after a refused commit:\n{status}"
    );
    assert!(
        status.contains("a.txt"),
        "status did not name the file:\n{status}"
    );

    let (_, diff, _) = run(&["diff"], &repo, &xdg);
    assert!(diff.contains("two"), "diff lost the change:\n{diff}");

    // And the legitimate commit still lands.
    assert_eq!(
        run(&["commit", "-m", "yes", "--key", "owner"], &repo, &xdg).0,
        0
    );
    let (_, status, _) = run(&["status"], &repo, &xdg);
    assert!(status.contains("working tree clean"), "{status}");
}

/// Set up a repository with `a.txt`, `b.txt` and `sub/c.txt` all committed.
fn scoped_repo(prefix: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let work = tempdir(prefix);
    let xdg = work.join("cfg");
    std::fs::create_dir_all(&xdg).unwrap();
    let repo = work.join("r");
    std::fs::create_dir_all(repo.join("sub")).unwrap();

    assert_eq!(run(&["key", "generate", "owner"], &work, &xdg).0, 0);
    std::fs::write(repo.join("a.txt"), "a base\n").unwrap();
    std::fs::write(repo.join("b.txt"), "b base\n").unwrap();
    std::fs::write(repo.join("sub/c.txt"), "c base\n").unwrap();
    assert_eq!(run(&["init", "--key", "owner"], &repo, &xdg).0, 0);
    assert_eq!(run(&["track", "--all"], &repo, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &repo, &xdg).0, 0);
    (work, repo, xdg)
}

#[test]
fn a_scoped_commit_takes_the_named_path_and_leaves_the_rest_dirty() {
    // The reason this exists: a working tree written by more than one hand
    // holds more than one piece of work, and a commit that had to sweep up
    // someone else's unfinished edits in order to exist would attribute their
    // work to whoever signed it.
    let (work, repo, xdg) = scoped_repo("levcs-scope");

    std::fs::write(repo.join("a.txt"), "a changed\n").unwrap();
    std::fs::write(repo.join("b.txt"), "b changed\n").unwrap();

    let (code, out, err) = run(&["commit", "-m", "just a", "a.txt"], &repo, &xdg);
    assert_eq!(code, 0, "scoped commit failed: {err}");
    assert!(out.contains("scoped to a.txt"), "commit did not say it was partial:\n{out}");

    let (_, status, _) = run(&["status"], &repo, &xdg);
    assert!(status.contains("b.txt"), "b.txt should still be outstanding:\n{status}");
    assert!(!status.contains("a.txt"), "a.txt should be committed:\n{status}");

    // And HEAD must hold b.txt as it was, not as it is on disk.
    let (_, diff, _) = run(&["diff"], &repo, &xdg);
    assert!(diff.contains("b changed"), "diff lost b.txt's change:\n{diff}");
    assert!(!diff.contains("a changed"), "a.txt is committed, so it must not appear:\n{diff}");

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn a_scope_naming_a_directory_takes_everything_beneath_it() {
    let (work, repo, xdg) = scoped_repo("levcs-scope-dir");

    std::fs::write(repo.join("sub/c.txt"), "c changed\n").unwrap();
    std::fs::write(repo.join("b.txt"), "b changed\n").unwrap();

    assert_eq!(run(&["commit", "-m", "just sub", "sub"], &repo, &xdg).0, 0);

    let (_, status, _) = run(&["status"], &repo, &xdg);
    assert!(status.contains("b.txt"), "{status}");
    assert!(!status.contains("c.txt"), "the directory scope should have taken it:\n{status}");

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn a_deletion_outside_the_scope_is_not_committed() {
    // The dangerous half of scoping: an out-of-scope entry must be carried
    // through untouched, and "the file is gone" must not be read as "drop it
    // from the tree" when the commit was never about that file.
    let (work, repo, xdg) = scoped_repo("levcs-scope-del");

    std::fs::write(repo.join("a.txt"), "a changed\n").unwrap();
    std::fs::remove_file(repo.join("b.txt")).unwrap();

    assert_eq!(run(&["commit", "-m", "just a", "a.txt"], &repo, &xdg).0, 0);

    let (_, status, _) = run(&["status"], &repo, &xdg);
    assert!(
        status.contains("deleted:") && status.contains("b.txt"),
        "the deletion must survive the scoped commit as outstanding work:\n{status}"
    );

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn a_path_that_matches_nothing_tracked_is_refused() {
    // A mistyped path that quietly commits nothing is the same class of
    // failure as a repository that reports clean while holding work.
    let (work, repo, xdg) = scoped_repo("levcs-scope-typo");

    std::fs::write(repo.join("a.txt"), "a changed\n").unwrap();
    let (code, _, err) = run(&["commit", "-m", "typo", "a.tx"], &repo, &xdg);
    assert_ne!(code, 0, "a path matching nothing must fail");
    assert!(err.contains("nothing tracked at 'a.tx'"), "unexpected error: {err}");

    let (_, status, _) = run(&["status"], &repo, &xdg);
    assert!(status.contains("a.txt"), "the refusal must leave the work outstanding:\n{status}");

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn a_scope_that_matches_head_says_so_rather_than_blaming_the_working_tree() {
    let (work, repo, xdg) = scoped_repo("levcs-scope-noop");

    std::fs::write(repo.join("b.txt"), "b changed\n").unwrap();
    let (code, _, err) = run(&["commit", "-m", "nothing", "a.txt"], &repo, &xdg);
    assert_ne!(code, 0);
    assert!(
        err.contains("named paths"),
        "the working tree does not match HEAD here; the message must not say it does: {err}"
    );

    let _ = std::fs::remove_dir_all(work);
}

#[test]
fn all_and_paths_are_mutually_exclusive() {
    let (work, repo, xdg) = scoped_repo("levcs-scope-all");

    std::fs::write(repo.join("a.txt"), "a changed\n").unwrap();
    let (code, _, _) = run(&["commit", "-m", "both", "--all", "a.txt"], &repo, &xdg);
    assert_ne!(code, 0, "--all with paths is a contradiction and must be refused");

    let _ = std::fs::remove_dir_all(work);
}
