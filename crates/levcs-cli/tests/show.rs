//! Reading history without writing the working tree: `show` and
//! `log --name-status` (issue #12).
//!
//! `construct <rev> <path>` was the only way to see a file at a revision,
//! and it writes that revision over the working tree's file: used to read
//! history, it overwrote uncommitted work. A commit's paths could only be
//! inferred by comparing `diff <parent>` with `diff`, which is exact only
//! for the latest commit.

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

/// Two commits. The first adds `a.md`, `d.md` and `sub/s.md`. The second
/// changes `a.md`, deletes `d.md`, adds `sub/n.md` and makes `sub/s.md`
/// executable, changing nothing else about it.
fn setup(tag: &str) -> (PathBuf, PathBuf) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base =
        std::env::temp_dir().join(format!("levcs-show-{tag}-{}-{stamp}", std::process::id()));
    let (work, cfg) = (base.join("w"), base.join("cfg"));
    std::fs::create_dir_all(work.join("sub")).unwrap();
    std::fs::write(work.join("a.md"), "one\n").unwrap();
    std::fs::write(work.join("d.md"), "gone\n").unwrap();
    std::fs::write(work.join("sub/s.md"), "s\n").unwrap();
    ok(&work, &cfg, &["init", "--key", "owner"]);
    ok(&work, &cfg, &["track", "--all"]);
    ok(&work, &cfg, &["commit", "-m", "base"]);

    std::fs::write(work.join("a.md"), "two\n").unwrap();
    std::fs::remove_file(work.join("d.md")).unwrap();
    std::fs::write(work.join("sub/n.md"), "n\n").unwrap();
    ok(&work, &cfg, &["track", "sub/n.md"]);
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        work.join("sub/s.md"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    ok(&work, &cfg, &["commit", "-m", "second"]);
    (work, cfg)
}

/// The `<letter>\t<path>` lines of `out`.
fn name_status(out: &str) -> Vec<&str> {
    out.lines()
        .filter(|l| l.len() > 2 && l.as_bytes()[1] == b'\t')
        .collect()
}

#[test]
fn show_prints_a_file_at_a_revision_and_writes_nothing() {
    let (work, cfg) = setup("read");
    std::fs::write(work.join("a.md"), "UNCOMMITTED\n").unwrap();
    let status_before = ok(&work, &cfg, &["status"]);

    assert_eq!(ok(&work, &cfg, &["show", "HEAD~1:a.md"]), "one\n");
    assert_eq!(ok(&work, &cfg, &["show", "HEAD:a.md"]), "two\n");
    assert_eq!(ok(&work, &cfg, &["show", "HEAD~1:d.md"]), "gone\n");

    assert_eq!(
        std::fs::read_to_string(work.join("a.md")).unwrap(),
        "UNCOMMITTED\n",
        "show wrote the working tree"
    );
    assert_eq!(ok(&work, &cfg, &["status"]), status_before);
}

#[test]
fn show_prints_content_byte_for_byte() {
    let (work, cfg) = setup("bytes");
    let bytes = b"no final line ending\n\xff\x00\r\nend";
    std::fs::write(work.join("a.md"), bytes).unwrap();
    ok(&work, &cfg, &["commit", "-m", "bytes", "a.md"]);
    let o = levcs(&work, &cfg, &["show", "HEAD:a.md"]);
    assert!(o.status.success());
    assert_eq!(o.stdout, bytes);
}

#[test]
fn show_paths_are_relative_to_the_current_directory() {
    let (work, cfg) = setup("cwd");
    assert_eq!(ok(&work.join("sub"), &cfg, &["show", "HEAD:s.md"]), "s\n");
    assert_eq!(ok(&work, &cfg, &["show", "HEAD:sub"]), "n.md\ns.md\n");
    assert_eq!(ok(&work, &cfg, &["show", "HEAD:"]), "a.md\nsub/\n");
}

#[test]
fn show_refuses_a_path_the_revision_does_not_have() {
    let (work, cfg) = setup("miss");
    let o = levcs(&work, &cfg, &["show", "HEAD:d.md"]);
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("nothing at 'd.md' in HEAD"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
}

#[test]
fn show_lists_a_commits_paths_against_its_parent() {
    let (work, cfg) = setup("paths");
    let out = ok(&work, &cfg, &["show"]);
    assert!(out.starts_with("commit "), "{out}");
    assert!(out.contains("    second\n"), "{out}");
    assert_eq!(
        name_status(&out),
        ["M\ta.md", "D\td.md", "A\tsub/n.md", "M\tsub/s.md"],
        "a change to the executable bit alone is a modification"
    );
    // The root commit's paths are all added.
    assert_eq!(
        name_status(&ok(&work, &cfg, &["show", "HEAD~1"])),
        ["A\ta.md", "A\td.md", "A\tsub/s.md"]
    );
}

#[test]
fn log_name_status_is_exact_for_every_commit_not_just_the_latest() {
    let (work, cfg) = setup("log");
    // A third commit touching only a.md: the second commit's list must not
    // change because of it.
    std::fs::write(work.join("a.md"), "three\n").unwrap();
    ok(&work, &cfg, &["commit", "-m", "third"]);
    let out = ok(&work, &cfg, &["log", "--name-status"]);
    let per_commit: Vec<Vec<&str>> = out.split("commit ").skip(1).map(name_status).collect();
    assert_eq!(
        per_commit,
        [
            vec!["M\ta.md"],
            vec!["M\ta.md", "D\td.md", "A\tsub/n.md", "M\tsub/s.md"],
            vec!["A\ta.md", "A\td.md", "A\tsub/s.md"],
        ]
    );
    // Without the flag, no paths.
    assert!(name_status(&ok(&work, &cfg, &["log"])).is_empty());
}

#[test]
fn a_file_that_becomes_a_directory_is_deleted_and_its_files_added() {
    let (work, cfg) = setup("kind");
    ok(&work, &cfg, &["forget", "--delete", "a.md"]);
    std::fs::create_dir(work.join("a.md")).unwrap();
    std::fs::write(work.join("a.md/inner"), "i\n").unwrap();
    ok(&work, &cfg, &["track", "a.md/inner"]);
    ok(&work, &cfg, &["commit", "-m", "kind"]);
    assert_eq!(
        name_status(&ok(&work, &cfg, &["show"])),
        ["D\ta.md", "A\ta.md/inner"]
    );
}

#[test]
fn levcs_history_entries_are_not_listed_as_files() {
    // An authority change's tree carries `.levcs/authority`, and the next
    // commit's does not. Neither is a file in the working tree.
    let (work, cfg) = setup("authority");
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
    std::fs::write(work.join("a.md"), "after\n").unwrap();
    ok(&work, &cfg, &["commit", "--key", "owner", "-m", "after"]);
    let out = ok(&work, &cfg, &["log", "--name-status"]);
    assert!(!out.contains(".levcs"), "{out}");
    assert_eq!(name_status(&ok(&work, &cfg, &["show"])), ["M\ta.md"]);
    assert!(name_status(&ok(&work, &cfg, &["show", "HEAD~1"])).is_empty());
}

#[test]
fn show_prints_a_blob_that_diff_names() {
    // `diff --format json` names each side's blob; `show` reads it.
    let (work, cfg) = setup("blob");
    std::fs::write(work.join("a.md"), "edited\n").unwrap();
    let d: serde_json::Value =
        serde_json::from_str(&ok(&work, &cfg, &["diff", "--format", "json", "a.md"])).unwrap();
    let old = d["files"][0]["old_blob"].as_str().unwrap();
    assert_eq!(ok(&work, &cfg, &["show", old]), "two\n");
}

/// A reader that stops early, as `levcs log | head` does, made levcs panic
/// on the closed pipe. Commands that only read now end as any filter does.
#[cfg(unix)]
#[test]
fn a_reader_that_stops_early_does_not_make_levcs_panic() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;

    let (work, cfg) = setup("pipe");
    // More than a pipe holds, so levcs is still writing when the reader
    // goes: a 256 KiB file, and a 100 kB commit message for `log`.
    let line = format!("{}\n", "x".repeat(99));
    std::fs::write(work.join("big.txt"), line.repeat(2621)).unwrap();
    ok(&work, &cfg, &["track", "big.txt"]);
    ok(&work, &cfg, &["commit", "-m", &line.repeat(1000)]);
    for args in [&["log"][..], &["show", "HEAD:big.txt"]] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_levcs"))
            .current_dir(&work)
            .env("XDG_CONFIG_HOME", &cfg)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = child.stdout.take().unwrap();
        stdout.read_exact(&mut [0u8; 16]).unwrap();
        drop(stdout);
        let o = child.wait_with_output().unwrap();
        let err = String::from_utf8_lossy(&o.stderr);
        assert!(!err.contains("panicked"), "{args:?}: {err}");
        assert!(
            o.status.success() || o.status.signal() == Some(13),
            "{args:?}: {:?} {err}",
            o.status
        );
    }
}
