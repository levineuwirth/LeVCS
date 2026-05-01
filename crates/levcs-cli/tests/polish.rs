//! Tests covering polish on construct/status/diff.

use std::path::{Path, PathBuf};
use std::process::Command;

fn levcs_bin() -> String {
    env!("CARGO_BIN_EXE_levcs").to_string()
}

fn run(args: &[&str], cwd: &Path, xdg: &Path) -> (i32, String, String) {
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

fn tempdir(prefix: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("{prefix}-{n}-{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn init_repo() -> (PathBuf, PathBuf) {
    let work = tempdir("levcs-polish");
    let xdg = work.join("cfg");
    std::fs::create_dir_all(&xdg).unwrap();
    assert_eq!(run(&["init", "--key", "alice"], &work, &xdg).0, 0);
    (work, xdg)
}

#[test]
fn construct_restricted_to_paths_only_rewrites_those_files() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"a v1\n").unwrap();
    std::fs::write(work.join("b.txt"), b"b v1\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "v1"], &work, &xdg).0, 0);

    // Modify both files in the working tree.
    std::fs::write(work.join("a.txt"), b"a dirty\n").unwrap();
    std::fs::write(work.join("b.txt"), b"b dirty\n").unwrap();

    // Restore only a.txt from HEAD.
    let (code, _, e) = run(&["construct", "a.txt"], &work, &xdg);
    assert_eq!(code, 0, "construct a.txt: {e}");
    assert_eq!(
        std::fs::read_to_string(work.join("a.txt")).unwrap(),
        "a v1\n"
    );
    assert_eq!(
        std::fs::read_to_string(work.join("b.txt")).unwrap(),
        "b dirty\n"
    );
}

#[test]
fn construct_release_default_uses_latest_release() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"v1\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "v1"], &work, &xdg).0, 0);
    assert_eq!(run(&["release", "1.0.0"], &work, &xdg).0, 0);

    // Add another commit after the release; do NOT release it.
    std::fs::write(work.join("a.txt"), b"v2\n").unwrap();
    assert_eq!(run(&["commit", "-m", "v2"], &work, &xdg).0, 0);

    // Dirty the working tree, then construct --release: should restore to 1.0.0.
    std::fs::write(work.join("a.txt"), b"dirty\n").unwrap();
    let (code, _, e) = run(&["construct", "--release"], &work, &xdg);
    assert_eq!(code, 0, "construct --release: {e}");
    assert_eq!(std::fs::read_to_string(work.join("a.txt")).unwrap(), "v1\n");
}

#[test]
fn status_shows_release_when_one_exists() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"hello\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "first"], &work, &xdg).0, 0);
    assert_eq!(run(&["release", "0.1.0"], &work, &xdg).0, 0);

    let (code, o, _) = run(&["status"], &work, &xdg);
    assert_eq!(code, 0);
    assert!(o.contains("Release"));
    assert!(o.contains("0.1.0"));
}

#[test]
fn diff_restricted_to_paths_skips_other_changes() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"a base\n").unwrap();
    std::fs::write(work.join("b.txt"), b"b base\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &work, &xdg).0, 0);

    std::fs::write(work.join("a.txt"), b"a edited\n").unwrap();
    std::fs::write(work.join("b.txt"), b"b edited\n").unwrap();

    let (code, o, _) = run(&["diff", "a.txt"], &work, &xdg);
    assert_eq!(code, 0);
    assert!(o.contains("a/a.txt"));
    assert!(!o.contains("a/b.txt"), "should not diff b.txt: {o}");
}
