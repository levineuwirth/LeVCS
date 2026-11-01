//! `diff` text a parser can split, and `diff`/`status` in JSON for tools.
//!
//! A file's last line without a line ending used to print without one, so it
//! ran into the next line or the next file's header: `-b` and `+b` came out
//! as `-b+b`, and the second file's `---` header was lost (issue #14).

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

fn json(work: &Path, cfg: &Path, args: &[&str]) -> serde_json::Value {
    serde_json::from_str(&ok(work, cfg, args)).expect("one JSON object on stdout")
}

/// The repository of the issue: `one.md` is `a⏎b` with no final line ending,
/// `two.md` is `x⏎`, both committed.
fn setup(tag: &str) -> (PathBuf, PathBuf) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base =
        std::env::temp_dir().join(format!("levcs-diff-{tag}-{}-{stamp}", std::process::id()));
    let (work, cfg) = (base.join("w"), base.join("cfg"));
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("one.md"), "a\nb").unwrap();
    std::fs::write(work.join("two.md"), "x\n").unwrap();
    ok(&work, &cfg, &["init", "--key", "owner"]);
    ok(&work, &cfg, &["track", "--all"]);
    ok(&work, &cfg, &["commit", "-m", "base"]);
    (work, cfg)
}

#[test]
fn every_diff_line_ends_and_a_missing_line_ending_is_marked() {
    let (work, cfg) = setup("eol");
    std::fs::write(work.join("one.md"), "a\nb\nc").unwrap();
    std::fs::write(work.join("two.md"), "x\ny\n").unwrap();
    let out = ok(&work, &cfg, &["diff"]);
    assert_eq!(
        out,
        "--- a/one.md\n+++ b/one.md\n a\n-b\n\\ No newline at end of file\n+b\n+c\n\
         \\ No newline at end of file\n--- a/two.md\n+++ b/two.md\n x\n+y\n",
    );
}

#[test]
fn an_empty_file_deleted_or_added_is_a_change() {
    // Contents alone were compared, and a missing file read as empty, so
    // deleting an empty file diffed as no change.
    let (work, cfg) = setup("empty");
    std::fs::write(work.join("empty.md"), "").unwrap();
    ok(&work, &cfg, &["track", "empty.md"]);
    ok(&work, &cfg, &["commit", "-m", "empty"]);
    std::fs::remove_file(work.join("empty.md")).unwrap();
    assert_eq!(
        ok(&work, &cfg, &["diff"]),
        "--- a/empty.md\n+++ b/empty.md\n"
    );
    let d = json(&work, &cfg, &["diff", "--format", "json"]);
    assert_eq!(d["files"][0]["path"], "empty.md");
    assert_eq!(d["files"][0]["change"], "deleted");
    assert!(d["files"][0]["new_blob"].is_null());
}

#[test]
fn json_diff_gives_each_changed_line_its_number_and_its_line_ending() {
    let (work, cfg) = setup("json");
    std::fs::write(work.join("one.md"), "a\nb\nc").unwrap();
    std::fs::write(work.join("new.md"), "n\n").unwrap();
    let d = json(&work, &cfg, &["diff", "--format", "json"]);
    assert_eq!(d["schema_version"], 1);
    let head = json(&work, &cfg, &["status", "--format", "json"])["head"].clone();
    assert!(head.is_string());

    let files = d["files"].as_array().unwrap();
    let paths: Vec<&str> = files.iter().map(|f| f["path"].as_str().unwrap()).collect();
    assert_eq!(paths, ["new.md", "one.md"], "two.md is unchanged");

    assert_eq!(files[0]["change"], "added");
    assert!(files[0]["old_blob"].is_null());

    let one = &files[1];
    assert_eq!(one["change"], "modified");
    assert_eq!(one["binary"], false);
    let lines: Vec<(String, serde_json::Value, serde_json::Value, String)> = one["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            (
                l["op"].as_str().unwrap().to_string(),
                l["old_line"].clone(),
                l["new_line"].clone(),
                l["text"].as_str().unwrap().to_string(),
            )
        })
        .collect();
    use serde_json::json as j;
    assert_eq!(
        lines,
        [
            ("-".into(), j!(2), j!(null), "b".into()),
            ("+".into(), j!(null), j!(2), "b\n".into()),
            ("+".into(), j!(null), j!(3), "c".into()),
        ],
        "unchanged lines are left out; each text is the line as it is in the file"
    );
}

#[test]
fn json_diff_marks_a_file_that_is_not_utf8_binary() {
    let (work, cfg) = setup("binary");
    std::fs::write(work.join("two.md"), b"x\n\xff\n").unwrap();
    let d = json(&work, &cfg, &["diff", "--format", "json", "two.md"]);
    assert_eq!(d["files"][0]["binary"], true);
    assert_eq!(d["files"][0]["lines"], serde_json::json!([]));
}

#[test]
fn json_status_lists_the_groups_text_status_lists() {
    let (work, cfg) = setup("status");
    let s = json(&work, &cfg, &["status", "--format", "json"]);
    assert_eq!(s["branch"], "main");
    assert_eq!(s["clean"], true);

    std::fs::write(work.join("one.md"), "changed\n").unwrap();
    std::fs::remove_file(work.join("two.md")).unwrap();
    std::fs::write(work.join("loose.md"), "u\n").unwrap();
    let s = json(&work, &cfg, &["status", "--format", "json"]);
    assert_eq!(s["clean"], false);
    assert_eq!(s["modified"], serde_json::json!(["one.md"]));
    assert_eq!(s["deleted"], serde_json::json!(["two.md"]));
    assert_eq!(s["untracked"], serde_json::json!(["loose.md"]));
    assert!(s["merge"].is_null());
}

#[test]
fn an_unknown_format_is_refused() {
    let (work, cfg) = setup("format");
    for cmd in ["diff", "status"] {
        let o = levcs(&work, &cfg, &[cmd, "--format", "jsno"]);
        assert!(!o.status.success(), "{cmd} took --format jsno");
        assert!(String::from_utf8_lossy(&o.stderr).contains("allowed: text, json"));
    }
}

#[test]
fn status_reports_the_newest_release_not_the_last_label() {
    // Labels sort as text, so `v9.0` comes after the newer `v10.0`. Status
    // reported the last label, while `construct --release` built the newest.
    let (work, cfg) = setup("release");
    ok(&work, &cfg, &["release", "v9.0"]);
    std::fs::write(work.join("two.md"), "y\n").unwrap();
    ok(&work, &cfg, &["commit", "-m", "next"]);
    ok(&work, &cfg, &["release", "v10.0"]);
    let s = json(&work, &cfg, &["status", "--format", "json"]);
    assert_eq!(s["release"]["label"], "v10.0");
    let text = ok(&work, &cfg, &["status"]);
    assert!(text.contains("Release    v10.0"), "{text}");
}

/// A merge commit's tree holds `.levcs/merge-record`, history rather than a
/// file. `diff <merge>` read every baseline path from the working tree, that
/// one included, and refused the whole diff as a write into the repository's
/// metadata, so no merge commit could be diffed against. `merge` and
/// checkout already skipped the entry.
#[test]
fn a_merge_commit_is_a_baseline_like_any_other() {
    let (work, cfg) = setup("merge");
    ok(&work, &cfg, &["branch", "--create", "side"]);
    ok(&work, &cfg, &["branch", "--switch", "side"]);
    std::fs::write(work.join("two.md"), "x\nside\n").unwrap();
    ok(&work, &cfg, &["commit", "-m", "side"]);
    ok(&work, &cfg, &["branch", "--switch", "main"]);
    std::fs::write(work.join("one.md"), "a\nb\nmain\n").unwrap();
    ok(&work, &cfg, &["commit", "-m", "main"]);
    ok(&work, &cfg, &["merge", "side"]);
    ok(&work, &cfg, &["commit", "-m", "merge"]);
    let merge = json(&work, &cfg, &["status", "--format", "json"])["head"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(
        ok(&work, &cfg, &["show", &merge]).contains("Merge:"),
        "the baseline is a merge commit"
    );

    // HEAD is the merge commit, so a plain `diff` reads it too.
    assert_eq!(ok(&work, &cfg, &["diff"]), "");
    assert_eq!(ok(&work, &cfg, &["diff", &merge]), "");
    std::fs::write(work.join("two.md"), "x\nside\nafter\n").unwrap();
    let out = ok(&work, &cfg, &["diff", &merge]);
    assert!(out.contains("+after\n"), "{out}");
    assert!(!out.contains(".levcs"), "{out}");
    let d = json(&work, &cfg, &["diff", &merge, "--format", "json"]);
    let paths: Vec<&str> = d["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["two.md"]);
}
