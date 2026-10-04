//! Merging is textual unless configured otherwise, and every conflict must be
//! resolved explicitly before a merge commits.
//!
//! The structural handlers used to be the default by file extension, and they
//! lose, invent and reorder content while reporting AUTO. Conflicts were
//! detected at commit only by scanning for textual markers, so a conflict
//! with none (a structural handler's, a binary file's, a file deleted on one
//! side) could be committed unresolved.

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

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn setup(tag: &str) -> (PathBuf, PathBuf) {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "levcs-resolve-{tag}-{}-{stamp}",
        std::process::id()
    ));
    let (work, cfg) = (base.join("w"), base.join("cfg"));
    std::fs::create_dir_all(&work).unwrap();
    ok(&work, &cfg, &["init", "--key", "owner"]);
    (work, cfg)
}

/// Commit `base`, then diverge: `main` applies `ours`, branch `topic` applies
/// `theirs`, and `main` merges `topic`. Each side is a list of (path,
/// Some(bytes)) writes or (path, None) deletions.
type Side<'a> = &'a [(&'a str, Option<&'a [u8]>)];

fn diverge(work: &Path, cfg: &Path, base: Side, ours: Side, theirs: Side) -> Output {
    let apply = |side: Side| {
        for (p, content) in side {
            match content {
                Some(b) => {
                    std::fs::write(work.join(p), b).unwrap();
                    ok(work, cfg, &["track", p]);
                }
                None => {
                    ok(work, cfg, &["forget", "--delete", p]);
                }
            }
        }
    };
    apply(base);
    ok(work, cfg, &["commit", "-m", "base", "--key", "owner"]);
    ok(work, cfg, &["branch", "--create", "topic"]);
    apply(ours);
    ok(work, cfg, &["commit", "-m", "ours", "--key", "owner"]);
    ok(work, cfg, &["branch", "--switch", "topic"]);
    apply(theirs);
    ok(work, cfg, &["commit", "-m", "theirs", "--key", "owner"]);
    ok(work, cfg, &["branch", "--switch", "main"]);
    levcs(work, cfg, &["merge", "topic"])
}

fn commit_refused(work: &Path, cfg: &Path, path: &str) {
    let o = levcs(work, cfg, &["commit", "-m", "merge", "--key", "owner"]);
    assert!(
        !o.status.success(),
        "a merge with {path} unresolved was committed"
    );
    assert!(
        err(&o).contains("unresolved conflicts in") && err(&o).contains(path),
        "{}",
        err(&o)
    );
}

fn in_head(work: &Path, cfg: &Path, path: &str) -> Option<Vec<u8>> {
    let saved = std::fs::read(work.join(path)).ok();
    let _ = std::fs::remove_file(work.join(path));
    let o = levcs(work, cfg, &["construct", "HEAD", path]);
    let got = o
        .status
        .success()
        .then(|| std::fs::read(work.join(path)).ok())
        .flatten();
    match saved {
        Some(b) => std::fs::write(work.join(path), b).unwrap(),
        None => {
            let _ = std::fs::remove_file(work.join(path));
        }
    }
    got
}

#[test]
fn without_configuration_every_file_merges_textually() {
    let (work, cfg) = setup("default");
    let base: &[u8] = b"# Note\n\none\n\ntwo\n\nthree\n";
    let ours: &[u8] = b"# Note\n\none\n\ntwo\n\nthree, ours\n";
    let theirs: &[u8] = b"# Note\n\none, theirs\n\ntwo\n\nthree\n";
    let o = diverge(
        &work,
        &cfg,
        &[("note.md", Some(base))],
        &[("note.md", Some(ours))],
        &[("note.md", Some(theirs))],
    );
    assert!(o.status.success(), "{}", err(&o));
    assert!(
        err(&o).contains("AUTO     note.md  (textual)"),
        "{}",
        err(&o)
    );
    assert_eq!(
        std::fs::read(work.join("note.md")).unwrap(),
        b"# Note\n\none, theirs\n\ntwo\n\nthree, ours\n"
    );
    ok(&work, &cfg, &["commit", "-m", "merge", "--key", "owner"]);
}

#[test]
fn a_conflict_without_markers_blocks_the_commit() {
    // The audit's JSON case: a structural handler reports a conflict and
    // leaves no markers, so the marker scan alone let it be committed.
    let (work, cfg) = setup("nomarkers");
    std::fs::write(
        work.join(".levcs/merge.toml"),
        "schema_version = 1\n[[rule]]\nglob = \"*.json\"\nhandler = \"json\"\n",
    )
    .unwrap();
    let o = diverge(
        &work,
        &cfg,
        &[("c.json", Some(b"{\"v\": 1}\n"))],
        &[("c.json", Some(b"{\"v\": 2}\n"))],
        &[("c.json", Some(b"{\"v\": 3}\n"))],
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("CONFLICT c.json  (json"), "{}", err(&o));
    assert!(!std::fs::read_to_string(work.join("c.json"))
        .unwrap()
        .contains("<<<<<<<"));
    commit_refused(&work, &cfg, "c.json");
}

#[test]
fn a_binary_conflict_keeps_ours_untouched_until_resolved() {
    let (work, cfg) = setup("binary");
    let base: &[u8] = &[0, 159, 146, 150, 1, 2, 3];
    let ours: &[u8] = &[0, 159, 146, 150, 9, 9, 9];
    let theirs: &[u8] = &[0, 159, 146, 150, 7, 7, 7];
    let o = diverge(
        &work,
        &cfg,
        &[("img.bin", Some(base))],
        &[("img.bin", Some(ours))],
        &[("img.bin", Some(theirs))],
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("CONFLICT img.bin"), "{}", err(&o));
    // No text conversion and no markers: the working file is ours, byte for
    // byte.
    assert_eq!(std::fs::read(work.join("img.bin")).unwrap(), ours);
    let status = ok(&work, &cfg, &["status"]);
    assert!(
        status.contains("unresolved conflicts") && status.contains("img.bin"),
        "{status}"
    );
    commit_refused(&work, &cfg, "img.bin");

    // Resolve by choosing theirs, mark it, commit.
    std::fs::write(work.join("img.bin"), theirs).unwrap();
    let out = ok(&work, &cfg, &["track", "img.bin"]);
    assert!(out.contains("resolved   img.bin"), "{out}");
    ok(&work, &cfg, &["commit", "-m", "merge", "--key", "owner"]);
    assert_eq!(in_head(&work, &cfg, "img.bin").unwrap(), theirs);
}

#[test]
fn a_file_deleted_on_one_side_is_a_conflict_resolved_by_forget_or_track() {
    // Ours deletes, theirs edits. This used to reach a handler with the
    // deleted side as empty content and come back as fragments marked AUTO.
    for keep in [false, true] {
        let (work, cfg) = setup(if keep { "modkeep" } else { "moddel" });
        let o = diverge(
            &work,
            &cfg,
            &[("a.txt", Some(b"a\n")), ("b.txt", Some(b"base\n"))],
            &[("b.txt", None)],
            &[("b.txt", Some(b"theirs edit\n"))],
        );
        assert!(!o.status.success());
        assert!(
            err(&o).contains("CONFLICT b.txt  (modified by theirs, deleted by ours)"),
            "{}",
            err(&o)
        );
        assert_eq!(
            std::fs::read(work.join("b.txt")).unwrap(),
            b"theirs edit\n",
            "the edited side must be in the working tree, unmarked"
        );
        commit_refused(&work, &cfg, "b.txt");
        if keep {
            ok(&work, &cfg, &["track", "b.txt"]);
            ok(&work, &cfg, &["commit", "-m", "merge", "--key", "owner"]);
            assert_eq!(in_head(&work, &cfg, "b.txt").unwrap(), b"theirs edit\n");
        } else {
            ok(&work, &cfg, &["forget", "--delete", "b.txt"]);
            ok(&work, &cfg, &["commit", "-m", "merge", "--key", "owner"]);
            assert!(in_head(&work, &cfg, "b.txt").is_none(), "b.txt survived");
            assert!(in_head(&work, &cfg, "a.txt").is_some());
        }
    }
}

#[test]
fn abort_clears_the_conflicts_and_the_merge() {
    let (work, cfg) = setup("abort");
    let o = diverge(
        &work,
        &cfg,
        &[("img.bin", Some(&[0, 1, 2]))],
        &[("img.bin", Some(&[0, 1, 9]))],
        &[("img.bin", Some(&[0, 1, 7]))],
    );
    assert!(!o.status.success());
    ok(&work, &cfg, &["merge", "--abort"]);
    assert!(!work.join(".levcs/MERGE_HEAD").exists());
    assert_eq!(std::fs::read(work.join("img.bin")).unwrap(), [0, 1, 9]);
    let status = ok(&work, &cfg, &["status"]);
    assert!(!status.contains("unresolved"), "{status}");
    assert!(status.contains("working tree clean"), "{status}");
}

#[test]
fn a_lost_index_during_a_merge_stops_commit_and_track() {
    // Rebuilt from HEAD, the index would hold no conflict flags and none of
    // the files the merge added, and the commit would seal both mistakes.
    let (work, cfg) = setup("lostindex");
    let o = diverge(
        &work,
        &cfg,
        &[("img.bin", Some(&[0, 1, 2]))],
        &[("img.bin", Some(&[0, 1, 9]))],
        &[
            ("img.bin", Some(&[0, 1, 7])),
            ("new.txt", Some(b"added by theirs\n")),
        ],
    );
    assert!(!o.status.success());
    std::fs::remove_file(work.join(".levcs/index")).unwrap();
    for args in [
        vec!["commit", "-m", "merge", "--key", "owner"],
        vec!["track", "img.bin"],
    ] {
        let o = levcs(&work, &cfg, &args);
        assert!(
            !o.status.success(),
            "{args:?} ran without the merge's index"
        );
        assert!(err(&o).contains("merge --abort"), "{}", err(&o));
    }
    ok(&work, &cfg, &["merge", "--abort"]);
    ok(&work, &cfg, &["status"]);
}

#[test]
fn only_naming_a_conflicted_file_resolves_it() {
    let (work, cfg) = setup("naming");
    std::fs::create_dir_all(work.join("d")).unwrap();
    let o = diverge(
        &work,
        &cfg,
        &[("d/x.bin", Some(&[0, 1, 2]))],
        &[("d/x.bin", Some(&[0, 1, 9]))],
        &[("d/x.bin", Some(&[0, 1, 7]))],
    );
    assert!(!o.status.success());
    let out = ok(&work, &cfg, &["track", "--all"]);
    assert!(out.contains("conflicted d/x.bin"), "{out}");
    commit_refused(&work, &cfg, "d/x.bin");
    let out = ok(&work, &cfg, &["forget", "d"]);
    assert!(out.contains("conflicted d/x.bin"), "{out}");
    commit_refused(&work, &cfg, "d/x.bin");
    ok(&work, &cfg, &["track", "d/x.bin"]);
    ok(&work, &cfg, &["commit", "-m", "merge", "--key", "owner"]);
}

#[test]
fn an_overlapping_local_rule_stops_the_merge_before_it_writes() {
    let (work, cfg) = setup("overlap");
    std::fs::create_dir_all(work.join("special")).unwrap();
    std::fs::write(
        work.join(".levcs/merge.toml"),
        "schema_version = 1\n\
         [[rule]]\nglob = \"special/*.json\"\nhandler = \"textual\"\n\
         [[rule]]\nglob = \"*.json\"\nhandler = \"json\"\n",
    )
    .unwrap();
    std::fs::write(
        work.join(".levcs/merge.local.toml"),
        "schema_version = 1\n[[rule]]\nglob = \"*.json\"\nhandler = \"json\"\n",
    )
    .unwrap();
    let o = diverge(
        &work,
        &cfg,
        &[("special/a.json", Some(b"{\"a\": 1, \"b\": 1}\n"))],
        &[("special/a.json", Some(b"{\"a\": 2, \"b\": 1}\n"))],
        &[("special/a.json", Some(b"{\"a\": 1, \"b\": 2}\n"))],
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("special/a.json"), "{}", err(&o));
    assert!(
        !work.join(".levcs/MERGE_HEAD").exists(),
        "the merge started"
    );
    assert_eq!(
        std::fs::read(work.join("special/a.json")).unwrap(),
        b"{\"a\": 2, \"b\": 1}\n"
    );
}

#[test]
fn a_malformed_merge_config_stops_the_merge() {
    // It used to be read as an empty config, which silently turned off the
    // repository's rules and its allowed_handlers policy.
    let (work, cfg) = setup("badconfig");
    std::fs::write(work.join(".levcs/merge.toml"), "[[rule]\nglob = ").unwrap();
    let o = diverge(
        &work,
        &cfg,
        &[("a.txt", Some(b"a\n"))],
        &[("a.txt", Some(b"ours\n"))],
        &[("a.txt", Some(b"theirs\n"))],
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("merge.toml is malformed"), "{}", err(&o));
    assert!(!work.join(".levcs/MERGE_HEAD").exists());
}

// Cases from the review of this step (2026-10-04).

#[test]
fn a_branch_switch_cannot_discard_a_merge_in_progress() {
    // A switch rebuilds the index, which wiped the conflict flags while
    // MERGE_HEAD stayed, and the next commit sealed the conflict unresolved;
    // switching to the branch already checked out was enough.
    let (work, cfg) = setup("switch");
    let o = diverge(
        &work,
        &cfg,
        &[("f.bin", Some(b"\xffbase"))],
        &[("f.bin", Some(b"\xffours"))],
        &[("f.bin", Some(b"\xfftheirs"))],
    );
    assert!(!o.status.success());
    for target in ["main", "topic"] {
        let s = levcs(&work, &cfg, &["branch", "--switch", target]);
        assert!(!s.status.success(), "switched to {target} during a merge");
        assert!(err(&s).contains("merge is in progress"), "{}", err(&s));
    }
    assert_eq!(std::fs::read(work.join("f.bin")).unwrap(), b"\xffours");
    commit_refused(&work, &cfg, "f.bin");
    ok(&work, &cfg, &["merge", "--abort"]);
    ok(&work, &cfg, &["branch", "--switch", "topic"]);
}

#[test]
fn a_deleted_file_is_not_an_empty_file() {
    // Comparing bytes alone made absence equal to emptiness, and each of
    // these merged "cleanly" and committed.
    let cases: [(&str, &[u8], Option<&[u8]>, Option<&[u8]>, &[u8]); 4] = [
        (
            "empty-delete-edit",
            b"",
            None,
            Some(b"edited\n"),
            b"edited\n",
        ),
        (
            "empty-edit-delete",
            b"",
            Some(b"edited\n"),
            None,
            b"edited\n",
        ),
        ("truncate-delete", b"base\n", Some(b""), None, b""),
        ("delete-truncate", b"base\n", None, Some(b""), b""),
    ];
    for (tag, base, ours, theirs, kept) in cases {
        let (work, cfg) = setup(tag);
        let o = diverge(
            &work,
            &cfg,
            &[("a.txt", Some(b"a\n")), ("f.txt", Some(base))],
            &[("f.txt", ours)],
            &[("f.txt", theirs)],
        );
        assert!(!o.status.success(), "{tag}: merged cleanly");
        assert!(err(&o).contains("CONFLICT f.txt"), "{tag}: {}", err(&o));
        assert_eq!(
            std::fs::read(work.join("f.txt")).unwrap(),
            kept,
            "{tag}: the side still present must be in the working tree"
        );
        commit_refused(&work, &cfg, "f.txt");
    }
}

#[test]
fn files_containing_nul_are_never_line_merged() {
    // NUL is valid UTF-8, so binary formats used to reach the line merge:
    // overlapping edits got conflict markers inserted into the binary, and
    // disjoint edits were spliced together and reported AUTO.
    let cases: [(&str, &[u8], &[u8], &[u8]); 2] = [
        ("nul-overlap", b"\0base\n", b"\0ours\n", b"\0theirs\n"),
        (
            "nul-disjoint",
            b"\0one\n\0two\n\0three\n",
            b"\0ONE\n\0two\n\0three\n",
            b"\0one\n\0two\n\0THREE\n",
        ),
    ];
    for (tag, base, ours, theirs) in cases {
        let (work, cfg) = setup(tag);
        let o = diverge(
            &work,
            &cfg,
            &[("f.dat", Some(base))],
            &[("f.dat", Some(ours))],
            &[("f.dat", Some(theirs))],
        );
        assert!(!o.status.success(), "{tag}: merged");
        assert!(
            err(&o).contains("CONFLICT f.dat  (none"),
            "{tag}: {}",
            err(&o)
        );
        assert_eq!(std::fs::read(work.join("f.dat")).unwrap(), ours, "{tag}");
        commit_refused(&work, &cfg, "f.dat");
    }
}

// Second review round of this step (2026-10-04).

#[test]
fn forced_conflicts_leave_binary_files_untouched() {
    // `--no-auto` skipped the engine and wrapped binary content in markers.
    let cases: [(&str, &[u8], &[u8], &[u8]); 2] = [
        ("noauto-nul", b"\0base\n", b"\0ours\n", b"\0theirs\n"),
        ("noauto-utf8", b"\xffbase", b"\xffours", b"\xfftheirs"),
    ];
    for (tag, base, ours, theirs) in cases {
        let (work, cfg) = setup(tag);
        let o = diverge(
            &work,
            &cfg,
            &[("f.dat", Some(base))],
            &[("f.dat", Some(ours))],
            &[("f.dat", Some(theirs))],
        );
        assert!(!o.status.success());
        ok(&work, &cfg, &["merge", "--abort"]);
        let o = levcs(&work, &cfg, &["merge", "--no-auto", "topic"]);
        assert!(!o.status.success(), "{tag}: {}", err(&o));
        assert_eq!(std::fs::read(work.join("f.dat")).unwrap(), ours, "{tag}");
        commit_refused(&work, &cfg, "f.dat");
    }
}

/// The parent count of the commit `refs/branches/<branch>` names.
fn parent_count(work: &Path, branch: &str) -> u8 {
    let tip = std::fs::read_to_string(work.join(format!(".levcs/refs/branches/{branch}")))
        .unwrap()
        .trim()
        .to_string();
    let raw = std::fs::read(work.join(".levcs/objects").join(&tip[..2]).join(&tip[2..])).unwrap();
    // 16-byte header, then the 32-byte tree id, then the parent count.
    raw[48]
}

#[test]
fn a_switch_clears_a_published_merges_leftovers_or_refuses() {
    // A merge commit published but whose cleanup failed (exit 3) leaves its
    // merge files. Carried onto another branch, they made the next ordinary
    // commit a merge with two identical parents and the old merge's record.
    use std::os::unix::fs::PermissionsExt;
    let (work, cfg) = setup("staleswitch");
    let o = diverge(
        &work,
        &cfg,
        &[("a.txt", Some(b"base\n"))],
        &[("a.txt", Some(b"ours\n"))],
        &[("a.txt", Some(b"theirs\n"))],
    );
    assert!(!o.status.success());
    std::fs::write(work.join("a.txt"), b"resolved\n").unwrap();
    ok(&work, &cfg, &["track", "a.txt"]);
    let dot = work.join(".levcs");
    let mut perms = std::fs::metadata(&dot).unwrap().permissions();
    perms.set_mode(0o555);
    std::fs::set_permissions(&dot, perms.clone()).unwrap();
    let published = levcs(&work, &cfg, &["commit", "-m", "merge", "--key", "owner"]);
    // While the leftovers cannot be removed, the switch must refuse.
    let refused = levcs(&work, &cfg, &["branch", "--switch", "topic"]);
    perms.set_mode(0o755);
    std::fs::set_permissions(&dot, perms).unwrap();
    assert_eq!(published.status.code(), Some(3), "{}", err(&published));
    assert!(
        !refused.status.success(),
        "switched while stale merge state could not be cleared"
    );
    assert!(dot.join("MERGE_HEAD").exists());

    ok(&work, &cfg, &["branch", "--switch", "topic"]);
    for f in ["MERGE_HEAD", "MERGE_BASE", "merge-record"] {
        assert!(!dot.join(f).exists(), "{f} survived the switch");
    }
    std::fs::write(work.join("a.txt"), b"ordinary edit\n").unwrap();
    ok(&work, &cfg, &["commit", "-m", "ordinary", "--key", "owner"]);
    assert_eq!(
        parent_count(&work, "topic"),
        1,
        "an ordinary commit became a merge"
    );
}
