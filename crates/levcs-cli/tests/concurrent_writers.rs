//! Several sessions writing one repository at once.
//!
//! This is the shape of a notes vault where independent agent sessions each
//! `track` their own files and make path-scoped commits. Before the
//! repository lock, two commits could read the same parent and the later ref
//! write discarded the earlier commit while both printed an id and exited 0;
//! concurrent `track` calls rewrote the whole index through one shared
//! temporary file, erasing each other's entries or failing on the rename.

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

/// A repository with an owner and an `agent` contributor, as in the vaults.
fn setup(tag: &str) -> (PathBuf, PathBuf) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "levcs-concurrent-{tag}-{}-{stamp}",
        std::process::id()
    ));
    let (work, cfg) = (base.join("w"), base.join("cfg"));
    std::fs::create_dir_all(&work).unwrap();
    ok(&work, &cfg, &["init", "--key", "owner"]);
    ok(&work, &cfg, &["key", "generate", "agent"]);
    let apk = ok(&work, &cfg, &["key", "show", "agent"]);
    ok(
        &work,
        &cfg,
        &[
            "authority",
            "add",
            apk.trim(),
            "--role",
            "contributor",
            "--signing-key",
            "owner",
        ],
    );
    (work, cfg)
}

fn commit_id(out: &Output) -> String {
    let s = String::from_utf8_lossy(&out.stdout);
    s.split(']')
        .next()
        .unwrap()
        .trim_start_matches('[')
        .to_string()
}

#[test]
fn concurrent_scoped_commits_all_succeed_and_all_land() {
    let (work, cfg) = setup("commits");
    const N: usize = 8;
    for i in 0..N {
        std::fs::write(work.join(format!("f{i}.md")), format!("session {i}\n")).unwrap();
        ok(&work, &cfg, &["track", &format!("f{i}.md")]);
    }
    let handles: Vec<_> = (0..N)
        .map(|i| {
            let (w, c) = (work.clone(), cfg.clone());
            std::thread::spawn(move || {
                levcs(
                    &w,
                    &c,
                    &[
                        "commit",
                        "-m",
                        &format!("s{i}"),
                        "--key",
                        "agent",
                        "--",
                        &format!("f{i}.md"),
                    ],
                )
            })
        })
        .collect();
    let outs: Vec<Output> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let failed: Vec<String> = outs
        .iter()
        .enumerate()
        .filter(|(_, o)| !o.status.success())
        .map(|(i, o)| format!("s{i}: {}", String::from_utf8_lossy(&o.stderr).trim()))
        .collect();
    assert!(failed.is_empty(), "concurrent commits failed: {failed:?}");

    let log = ok(&work, &cfg, &["log"]);
    let lost: Vec<String> = outs
        .iter()
        .enumerate()
        .map(|(i, o)| (i, commit_id(o)))
        .filter(|(_, id)| !log.contains(id.as_str()))
        .map(|(i, id)| format!("s{i} ({})", &id[..12.min(id.len())]))
        .collect();
    assert!(
        lost.is_empty(),
        "commits printed an id but are not on the branch: {lost:?}"
    );
    // Every file is in HEAD and nothing is left uncommitted.
    let diff = ok(&work, &cfg, &["diff", "HEAD"]);
    assert!(
        diff.trim().is_empty(),
        "files missing from HEAD after concurrent commits:\n{diff}"
    );
}

#[test]
fn concurrent_track_keeps_every_entry_and_a_parseable_index() {
    let (work, cfg) = setup("track");
    const N: usize = 8;
    let name = |i: usize| format!("{}{i}.md", "p".repeat(i * 17 + 1));
    for i in 0..N {
        std::fs::write(work.join(name(i)), b"x\n").unwrap();
    }
    let handles: Vec<_> = (0..N)
        .map(|i| {
            let (w, c, n) = (work.clone(), cfg.clone(), name(i));
            std::thread::spawn(move || levcs(&w, &c, &["track", &n]))
        })
        .collect();
    let outs: Vec<Output> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let failed: Vec<String> = outs
        .iter()
        .enumerate()
        .filter(|(_, o)| !o.status.success())
        .map(|(i, o)| format!("{}: {}", name(i), String::from_utf8_lossy(&o.stderr).trim()))
        .collect();
    assert!(failed.is_empty(), "concurrent track failed: {failed:?}");

    let st = levcs(&work, &cfg, &["status"]);
    assert!(
        st.status.success(),
        "index unreadable after concurrent track: {}",
        String::from_utf8_lossy(&st.stderr)
    );
    let out = String::from_utf8_lossy(&st.stdout).into_owned();
    let untracked: Vec<String> = (0..N)
        .map(name)
        .filter(|n| out.contains(&format!("  {n}")))
        .collect();
    assert!(
        untracked.is_empty(),
        "`track` exited 0 but these are untracked: {untracked:?}"
    );
}

/// Which of `names` are in HEAD's tree: delete each from the working tree
/// and ask `construct` to restore it from HEAD, which fails for a path HEAD
/// does not hold. Destructive, so only for a throwaway repository.
fn head_files(work: &Path, cfg: &Path, names: &[&str]) -> Vec<String> {
    names
        .iter()
        .filter(|n| {
            let _ = std::fs::remove_file(work.join(n));
            levcs(work, cfg, &["construct", "HEAD", n]).status.success() && work.join(n).is_file()
        })
        .map(|n| n.to_string())
        .collect()
}

#[test]
fn a_lost_index_is_head_with_nothing_staged() {
    let (work, cfg) = setup("noindex");
    std::fs::write(work.join("a.md"), b"a\n").unwrap();
    std::fs::write(work.join("b.md"), b"b\n").unwrap();
    ok(&work, &cfg, &["track", "a.md", "b.md"]);
    ok(&work, &cfg, &["commit", "-m", "base", "--key", "owner"]);

    // A lost index followed by an unscoped commit: nothing is staged, so
    // nothing changes, and nothing is deleted from HEAD.
    std::fs::remove_file(work.join(".levcs/index")).unwrap();
    let before = ok(&work, &cfg, &["log"]);
    let o = levcs(&work, &cfg, &["commit", "-m", "empty", "--key", "owner"]);
    assert!(
        !o.status.success(),
        "a commit from a lost index changed HEAD: {}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert_eq!(ok(&work, &cfg, &["log"]), before, "HEAD moved");

    // `track` used to recreate the index from empty, so the next commit held
    // only the newly tracked file and deleted the rest from HEAD. (The index
    // is still missing: a refused commit writes nothing.)
    let _ = std::fs::remove_file(work.join(".levcs/index"));
    std::fs::write(work.join("c.md"), b"c\n").unwrap();
    ok(&work, &cfg, &["track", "c.md"]);
    ok(&work, &cfg, &["commit", "-m", "add c", "--key", "owner"]);
    assert_eq!(
        head_files(&work, &cfg, &["a.md", "b.md", "c.md"]),
        ["a.md", "b.md", "c.md"],
        "a lost index dropped committed files from HEAD"
    );
}

#[test]
fn a_published_merge_whose_cleanup_fails_is_reported_and_not_repeated() {
    let (work, cfg) = setup("published");
    std::fs::write(work.join("a.md"), b"a\n").unwrap();
    std::fs::write(work.join("b.md"), b"b\n").unwrap();
    ok(&work, &cfg, &["track", "a.md", "b.md"]);
    ok(&work, &cfg, &["commit", "-m", "base", "--key", "owner"]);
    ok(&work, &cfg, &["branch", "--create", "topic"]);
    std::fs::write(work.join("a.md"), b"main changed a\n").unwrap();
    ok(&work, &cfg, &["commit", "-m", "main", "--key", "owner"]);
    ok(&work, &cfg, &["branch", "--switch", "topic"]);
    std::fs::write(work.join("b.md"), b"topic changed b\n").unwrap();
    ok(&work, &cfg, &["commit", "-m", "topic", "--key", "owner"]);
    ok(&work, &cfg, &["branch", "--switch", "main"]);
    ok(&work, &cfg, &["merge", "topic"]);
    assert!(work.join(".levcs/MERGE_HEAD").exists());
    let main_ref = work.join(".levcs/refs/branches/main");
    let before = std::fs::read_to_string(&main_ref).unwrap();

    // `.levcs/` read-only: the ref still moves (refs/ and the staging
    // directory are writable), but neither the index nor the merge state in
    // `.levcs/` itself can be rewritten afterwards.
    use std::os::unix::fs::PermissionsExt;
    let dot = work.join(".levcs");
    let mut perms = std::fs::metadata(&dot).unwrap().permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&dot, perms.clone()).unwrap();
    let o = levcs(&work, &cfg, &["commit", "-m", "merge", "--key", "owner"]);
    perms.set_mode(0o755);
    std::fs::set_permissions(&dot, perms).unwrap();

    let after = std::fs::read_to_string(&main_ref).unwrap();
    assert_ne!(before, after, "the merge commit was not published");
    assert_eq!(
        o.status.code(),
        Some(3),
        "published-but-incomplete must have its own status: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let id = commit_id(&o);
    assert_eq!(
        after.trim(),
        id,
        "the printed id is not the published commit"
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("is published"));

    // `status` must not call the committed merge "in progress".
    let status = ok(&work, &cfg, &["status"]);
    assert!(
        !status.contains("Merge      in progress"),
        "status reports a committed merge as in progress:\n{status}"
    );
    // A retry must not make a second merge commit.
    let _ = levcs(&work, &cfg, &["commit", "-m", "retry", "--key", "owner"]);
    assert_eq!(
        std::fs::read_to_string(&main_ref).unwrap(),
        after,
        "retrying after a published merge made another commit"
    );
    assert!(
        !work.join(".levcs/MERGE_HEAD").exists(),
        "stale merge state survived"
    );
}

#[test]
fn a_lock_held_on_the_old_workaround_path_does_not_block() {
    // The interim advice was `flock .levcs/lock levcs …`. A binary locking
    // that same file would wait forever on its own wrapper.
    let (work, cfg) = setup("wrapper");
    std::fs::write(work.join("a.md"), b"a\n").unwrap();
    let wrapper = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(work.join(".levcs/lock"))
        .unwrap();
    wrapper.lock().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_levcs"))
        .current_dir(&work)
        .env("XDG_CONFIG_HOME", &cfg)
        .args(["track", "a.md"])
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break Some(s);
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    drop(wrapper);
    assert!(
        matches!(status, Some(s) if s.success()),
        "track blocked on a lock held on .levcs/lock: {status:?}"
    );
}

#[test]
fn a_failed_commit_leaves_status_dirty() {
    // The index used to be written before the commit and ref, so a failure
    // in between left `status` reporting a clean tree for uncommitted work.
    let (work, cfg) = setup("failed");
    std::fs::write(work.join("a.md"), b"one\n").unwrap();
    ok(&work, &cfg, &["track", "a.md"]);
    ok(&work, &cfg, &["commit", "-m", "base", "--key", "owner"]);
    std::fs::write(work.join("a.md"), b"two\n").unwrap();

    // Make the branch ref unwritable, so the commit fails at its last step.
    let branches = work.join(".levcs/refs/branches");
    let mut perms = std::fs::metadata(&branches).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o555);
    std::fs::set_permissions(&branches, perms.clone()).unwrap();
    let o = levcs(&work, &cfg, &["commit", "-m", "fails", "--key", "owner"]);
    perms.set_mode(0o755);
    std::fs::set_permissions(&branches, perms).unwrap();

    assert!(
        !o.status.success(),
        "commit into a read-only refs dir succeeded"
    );
    let status = ok(&work, &cfg, &["status"]);
    assert!(
        !status.contains("working tree clean"),
        "status claims clean after a failed commit:\n{status}"
    );
}
