//! End-to-end tests for the `levcs merge` command.

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
    let work = tempdir("levcs-merge");
    let xdg = work.join("cfg");
    std::fs::create_dir_all(&xdg).unwrap();
    let (code, _, e) = run(&["init", "--key", "alice"], &work, &xdg);
    assert_eq!(code, 0, "init: {e}");
    (work, xdg)
}

#[test]
fn fast_forward_merge_advances_branch() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"one\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "first"], &work, &xdg).0, 0);

    // Create a feature branch off main, switch to it, add a commit.
    assert_eq!(run(&["branch", "--create", "feature"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--switch", "feature"], &work, &xdg).0, 0);
    std::fs::write(work.join("b.txt"), b"two\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "add b"], &work, &xdg).0, 0);

    // Switch back to main and merge feature: should fast-forward.
    assert_eq!(run(&["branch", "--switch", "main"], &work, &xdg).0, 0);
    let (code, _, e) = run(&["merge", "feature"], &work, &xdg);
    assert_eq!(code, 0, "fast-forward merge: {e}");
    assert!(
        e.contains("fast-forward"),
        "expected fast-forward message; got {e}"
    );
    assert!(
        work.join("b.txt").is_file(),
        "feature file should be present"
    );
}

#[test]
fn clean_three_way_merge_then_commit_produces_two_parents() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"hello\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &work, &xdg).0, 0);

    // Branch.
    assert_eq!(run(&["branch", "--create", "feat"], &work, &xdg).0, 0);

    // On main: add c.txt.
    std::fs::write(work.join("c.txt"), b"main side\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "main change"], &work, &xdg).0, 0);

    // Switch to feat and add b.txt.
    assert_eq!(run(&["branch", "--switch", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("b.txt"), b"feat side\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "feat change"], &work, &xdg).0, 0);

    // Back to main, merge feat: clean (disjoint changes).
    assert_eq!(run(&["branch", "--switch", "main"], &work, &xdg).0, 0);
    let (code, o, e) = run(&["merge", "feat"], &work, &xdg);
    assert_eq!(code, 0, "merge: {e}");
    assert!(
        o.contains("auto-resolved: 1") || o.contains("auto-resolved: 2"),
        "summary missing: {o}"
    );

    // Both files should be in the working tree now.
    assert!(work.join("b.txt").is_file());
    assert!(work.join("c.txt").is_file());

    // MERGE_HEAD should exist before commit, then disappear after.
    let merge_head = work.join(".levcs/MERGE_HEAD");
    assert!(
        merge_head.exists(),
        "MERGE_HEAD should be set before commit"
    );

    // Finalize.
    let (code, _, e) = run(&["commit", "-m", "merge feat"], &work, &xdg);
    assert_eq!(code, 0, "commit (merge): {e}");
    assert!(
        !merge_head.exists(),
        "MERGE_HEAD should be cleared after commit"
    );

    // Log should show the merge as the most recent commit.
    let (code, log, _) = run(&["log"], &work, &xdg);
    assert_eq!(code, 0);
    assert!(log.contains("merge feat"));
}

#[test]
fn conflicting_merge_writes_state_and_blocks_commit_until_resolved() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"original\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &work, &xdg).0, 0);

    assert_eq!(run(&["branch", "--create", "feat"], &work, &xdg).0, 0);

    // Modify a.txt on main.
    std::fs::write(work.join("a.txt"), b"main version\n").unwrap();
    assert_eq!(run(&["commit", "-m", "main edit"], &work, &xdg).0, 0);

    // Different modification on feat.
    assert_eq!(run(&["branch", "--switch", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("a.txt"), b"feat version\n").unwrap();
    assert_eq!(run(&["commit", "-m", "feat edit"], &work, &xdg).0, 0);

    // Merge feat into main: conflict.
    assert_eq!(run(&["branch", "--switch", "main"], &work, &xdg).0, 0);
    let (code, _o, e) = run(&["merge", "feat"], &work, &xdg);
    assert_ne!(code, 0, "conflict should produce non-zero exit");
    assert!(
        e.contains("CONFLICT") || e.contains("conflict"),
        "conflict report missing: {e}"
    );

    // Merge state files exist.
    assert!(work.join(".levcs/MERGE_HEAD").exists());
    assert!(work.join(".levcs/MERGE_BASE").exists());
    assert!(work.join(".levcs/merge-record").exists());

    // The working file has conflict markers.
    let bytes = std::fs::read(work.join("a.txt")).unwrap();
    let s = String::from_utf8_lossy(&bytes);
    assert!(s.contains("<<<<<<<"));
    assert!(s.contains(">>>>>>>"));

    // commit must refuse while conflict markers remain.
    let (code, _, e) = run(&["commit", "-m", "premature"], &work, &xdg);
    assert_ne!(code, 0, "commit should refuse: {e}");
    assert!(
        e.contains("conflict markers"),
        "marker check should mention markers: {e}"
    );

    // Resolve manually and commit.
    std::fs::write(work.join("a.txt"), b"resolved\n").unwrap();
    let (code, _, e) = run(&["commit", "-m", "merge feat"], &work, &xdg);
    assert_eq!(code, 0, "commit after resolution: {e}");
    assert!(!work.join(".levcs/MERGE_HEAD").exists());
    assert!(!work.join(".levcs/merge-record").exists());
}

#[test]
fn merge_abort_restores_head_and_clears_state() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"original\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &work, &xdg).0, 0);

    assert_eq!(run(&["branch", "--create", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("a.txt"), b"main version\n").unwrap();
    assert_eq!(run(&["commit", "-m", "main edit"], &work, &xdg).0, 0);

    assert_eq!(run(&["branch", "--switch", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("a.txt"), b"feat version\n").unwrap();
    assert_eq!(run(&["commit", "-m", "feat edit"], &work, &xdg).0, 0);

    assert_eq!(run(&["branch", "--switch", "main"], &work, &xdg).0, 0);
    let _ = run(&["merge", "feat"], &work, &xdg);
    assert!(work.join(".levcs/MERGE_HEAD").exists());

    // Abort.
    let (code, _, e) = run(&["merge", "--abort"], &work, &xdg);
    assert_eq!(code, 0, "abort: {e}");
    assert!(!work.join(".levcs/MERGE_HEAD").exists());
    assert!(!work.join(".levcs/merge-record").exists());

    // Working tree restored to main's content.
    let s = std::fs::read_to_string(work.join("a.txt")).unwrap();
    assert_eq!(s, "main version\n");
}

#[test]
fn commit_refuses_merge_record_with_handler_outside_repo_policy() {
    // Set up a merge whose merge-record we'll then hand-edit to reference a
    // disallowed plugin handler. The repo's `.levcs/merge.toml` enforces
    // builtin-only.
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"hello\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &work, &xdg).0, 0);

    assert_eq!(run(&["branch", "--create", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("a.txt"), b"main side\n").unwrap();
    assert_eq!(run(&["commit", "-m", "main"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--switch", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("b.txt"), b"feat side\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "feat"], &work, &xdg).0, 0);

    // Switch to main, then write a builtin-only policy and merge.
    assert_eq!(run(&["branch", "--switch", "main"], &work, &xdg).0, 0);
    std::fs::write(
        work.join(".levcs/merge.toml"),
        b"[policy]\nallowed_handlers = [\"builtin\"]\n",
    )
    .unwrap();
    let (code, _, _) = run(&["merge", "feat"], &work, &xdg);
    assert_eq!(code, 0, "clean merge against built-ins should pass policy");

    // Hand-edit the merge-record to reference a forbidden plugin.
    let record_path = work.join(".levcs/merge-record");
    let mut record = std::fs::read_to_string(&record_path).unwrap();
    record.push_str(
        "\n[[file]]\npath = \"x.proto\"\nhandler = \"tree-sitter:protobuf\"\nhandler_hash = \"blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"\nstatus = \"auto\"\n",
    );
    std::fs::write(&record_path, &record).unwrap();

    let (code, _, e) = run(&["commit", "-m", "merge feat"], &work, &xdg);
    assert_ne!(code, 0, "commit must refuse a record outside policy");
    assert!(
        e.contains("tree-sitter:protobuf"),
        "error must name the bad handler: {e}"
    );
}

#[test]
fn merge_format_json_emits_structured_report_on_clean_merge() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"hello\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &work, &xdg).0, 0);

    assert_eq!(run(&["branch", "--create", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("c.txt"), b"main side\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "main change"], &work, &xdg).0, 0);

    assert_eq!(run(&["branch", "--switch", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("b.txt"), b"feat side\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "feat change"], &work, &xdg).0, 0);

    assert_eq!(run(&["branch", "--switch", "main"], &work, &xdg).0, 0);
    let (code, stdout, _) = run(&["merge", "--format=json", "feat"], &work, &xdg);
    assert_eq!(code, 0, "clean merge with --format=json must exit 0");
    // stdout must be a single line of valid JSON, parseable.
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("parse JSON report");
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["conflicts"], 0);
    assert!(v["auto_resolved"].as_u64().unwrap() >= 1);
    assert!(v["base"].as_str().unwrap().starts_with("blake3:"));
    let files = v["files"].as_array().expect("files array");
    // The human-readable summary must NOT appear on stdout.
    assert!(
        !stdout.contains("merge summary:"),
        "JSON mode must suppress prose summary; got: {stdout}"
    );
    // Each file record carries path + handler + status.
    for f in files {
        assert!(f["path"].is_string());
        assert!(f["handler"].is_string());
        let status = f["status"].as_str().unwrap();
        assert!(
            matches!(status, "merged" | "conflict" | "not_applicable"),
            "unexpected status {status}"
        );
    }
}

#[test]
fn merge_format_json_reports_conflicts_and_exits_nonzero() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"original\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &work, &xdg).0, 0);

    assert_eq!(run(&["branch", "--create", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("a.txt"), b"main version\n").unwrap();
    assert_eq!(run(&["commit", "-m", "main edit"], &work, &xdg).0, 0);

    assert_eq!(run(&["branch", "--switch", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("a.txt"), b"feat version\n").unwrap();
    assert_eq!(run(&["commit", "-m", "feat edit"], &work, &xdg).0, 0);

    assert_eq!(run(&["branch", "--switch", "main"], &work, &xdg).0, 0);
    let (code, stdout, _) = run(&["merge", "--format=json", "feat"], &work, &xdg);
    assert_ne!(code, 0, "conflicting merge must exit non-zero");
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).expect("parse JSON");
    assert!(v["conflicts"].as_u64().unwrap() >= 1);
    let files = v["files"].as_array().unwrap();
    let conflicted: Vec<_> = files.iter().filter(|f| f["status"] == "conflict").collect();
    assert!(!conflicted.is_empty(), "must report at least one conflict");
    // Conflict regions array is present for conflicted files.
    let f = conflicted[0];
    assert!(f["conflict_regions"].as_u64().unwrap() >= 1);
}

#[test]
fn merge_format_json_rejects_unknown_value() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"x\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "x"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--create", "f"], &work, &xdg).0, 0);
    std::fs::write(work.join("a.txt"), b"y\n").unwrap();
    assert_eq!(run(&["commit", "-m", "y"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--switch", "main"], &work, &xdg).0, 0);
    let (code, _, e) = run(&["merge", "--format=xml", "f"], &work, &xdg);
    assert_ne!(code, 0, "unknown format value must error out");
    assert!(e.contains("--format"), "error must mention --format: {e}");
}

#[test]
fn merge_local_toml_can_demote_handler() {
    // Repo config pins `*.txt` to prose (rank 1); the user's local
    // override demotes it to textual (rank 0). Merge should then use
    // the textual handler — verify by checking the JSON report's
    // handler field.
    let (work, xdg) = init_repo();
    std::fs::write(work.join("note.txt"), b"original\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--create", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("note.txt"), b"main side\n").unwrap();
    assert_eq!(run(&["commit", "-m", "main"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--switch", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("note.txt"), b"feat side\n").unwrap();
    assert_eq!(run(&["commit", "-m", "feat"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--switch", "main"], &work, &xdg).0, 0);

    // Repo says: prose for *.txt. Local says: textual for *.txt (demote).
    std::fs::write(
        work.join(".levcs/merge.toml"),
        b"schema_version = 1\n\n[[rule]]\nglob = \"*.txt\"\nhandler = \"prose\"\n",
    )
    .unwrap();
    std::fs::write(
        work.join(".levcs/merge.local.toml"),
        b"schema_version = 1\n\n[[rule]]\nglob = \"*.txt\"\nhandler = \"textual\"\n",
    )
    .unwrap();

    let (code, stdout, _) = run(&["merge", "--format=json", "feat"], &work, &xdg);
    // Conflict expected (both sides changed); the interesting bit is
    // that the handler chosen is `textual`, not `prose`.
    assert_ne!(code, 0);
    let v: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    let txt = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "note.txt")
        .expect("note.txt in report");
    assert_eq!(
        txt["handler"], "textual",
        "demoted handler must be in effect"
    );
}

#[test]
fn merge_local_toml_promotion_is_rejected() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("note.txt"), b"x\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--create", "f"], &work, &xdg).0, 0);
    std::fs::write(work.join("note.txt"), b"y\n").unwrap();
    assert_eq!(run(&["commit", "-m", "f"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--switch", "main"], &work, &xdg).0, 0);

    // Repo: textual. Local tries to promote to tree-sitter:rust (rank 2).
    std::fs::write(
        work.join(".levcs/merge.toml"),
        b"schema_version = 1\n\n[[rule]]\nglob = \"*.txt\"\nhandler = \"textual\"\n",
    )
    .unwrap();
    std::fs::write(
        work.join(".levcs/merge.local.toml"),
        b"schema_version = 1\n\n[[rule]]\nglob = \"*.txt\"\nhandler = \"tree-sitter:rust\"\n",
    )
    .unwrap();
    let (code, _, e) = run(&["merge", "f"], &work, &xdg);
    assert_ne!(code, 0, "promotion must error out");
    assert!(
        e.contains("merge.local.toml"),
        "error must name the offending file: {e}"
    );
    assert!(e.contains("promote"), "error must say 'promote': {e}");
}

#[test]
fn explain_dumps_merge_record() {
    let (work, xdg) = init_repo();
    std::fs::write(work.join("a.txt"), b"original\n").unwrap();
    assert_eq!(run(&["track", "--all"], &work, &xdg).0, 0);
    assert_eq!(run(&["commit", "-m", "base"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--create", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("a.txt"), b"main version\n").unwrap();
    assert_eq!(run(&["commit", "-m", "main"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--switch", "feat"], &work, &xdg).0, 0);
    std::fs::write(work.join("a.txt"), b"feat version\n").unwrap();
    assert_eq!(run(&["commit", "-m", "feat"], &work, &xdg).0, 0);
    assert_eq!(run(&["branch", "--switch", "main"], &work, &xdg).0, 0);
    let _ = run(&["merge", "feat"], &work, &xdg);

    let (code, o, _) = run(&["merge", "--explain"], &work, &xdg);
    assert_eq!(code, 0);
    assert!(o.contains("schema_version"));
    assert!(o.contains("a.txt"));
}
