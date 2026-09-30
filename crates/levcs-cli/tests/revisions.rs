//! Revision specs (`HEAD~1`, `main^2`) on the commands that take a commit.

use std::process::Command;

fn run(args: &[&str], cwd: &std::path::Path, xdg: &std::path::Path) -> (i32, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_levcs"))
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

/// A repository whose `f.txt` reads "one", "two", "three" across three commits.
fn three_commits() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let work = tempdir("levcs-rev");
    let xdg = work.join("cfg");
    std::fs::create_dir_all(&xdg).unwrap();
    let repo = work.join("r");
    std::fs::create_dir_all(&repo).unwrap();
    assert_eq!(run(&["key", "generate", "owner"], &work, &xdg).0, 0);
    std::fs::write(repo.join("f.txt"), "one\n").unwrap();
    assert_eq!(run(&["init", "--key", "owner"], &repo, &xdg).0, 0);
    assert_eq!(run(&["track", "--all"], &repo, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "one"], &repo, &xdg).0, 0);
    for (text, msg) in [("two\n", "two"), ("three\n", "three")] {
        std::fs::write(repo.join("f.txt"), text).unwrap();
        assert_eq!(run(&["commit", "-m", msg], &repo, &xdg).0, 0);
    }
    (work, repo, xdg)
}

#[test]
fn diff_head_tilde_compares_against_the_previous_commit() {
    let (_w, repo, xdg) = three_commits();
    let (code, out, err) = run(&["diff", "HEAD~1"], &repo, &xdg);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("two") && out.contains("three"), "{out}");
    let (code, out, _) = run(&["diff", "HEAD~2"], &repo, &xdg);
    assert_eq!(code, 0);
    assert!(out.contains("one"), "{out}");
}

#[test]
fn construct_head_tilde_restores_the_older_content() {
    let (_w, repo, xdg) = three_commits();
    let (code, _, err) = run(&["construct", "HEAD~2", "f.txt"], &repo, &xdg);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        std::fs::read_to_string(repo.join("f.txt")).unwrap(),
        "one\n"
    );
}

#[test]
fn walking_past_the_root_is_an_error_not_a_path() {
    let (_w, repo, xdg) = three_commits();
    let (code, _, err) = run(&["diff", "HEAD~3"], &repo, &xdg);
    assert_ne!(code, 0);
    assert!(err.contains("has no parent"), "{err}");
}

#[test]
fn a_suffixed_name_that_is_not_a_ref_is_still_a_path() {
    let (_w, repo, xdg) = three_commits();
    std::fs::write(repo.join("f.txt~"), "backup\n").unwrap();
    // Not a revision, so it is treated as a path rather than rejected as one.
    let (_, _, err) = run(&["diff", "f.txt~"], &repo, &xdg);
    assert!(
        !err.contains("unknown") && !err.contains("no parent"),
        "{err}"
    );
}
