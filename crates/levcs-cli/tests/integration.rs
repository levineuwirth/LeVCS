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
