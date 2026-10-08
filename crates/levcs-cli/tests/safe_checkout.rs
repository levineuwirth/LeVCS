//! Every command that writes the working tree writes it safely, and one
//! that cannot leaves the repository where it was.
//!
//! The working tree used to be written by joined pathname: a directory in
//! it that had become a symlink sent a branch switch, a merge, an abort, a
//! path-restricted construct, a `forget --delete` or a cache restore to
//! files outside the repository. A switch and a fast-forward also moved
//! HEAD (or the branch) before writing the tree, so a checkout that failed
//! part way left HEAD naming a tree that was never written.
//!
//! Each test puts a symlink to a directory outside the repository where the
//! command will write, and checks that nothing outside changes, that
//! nothing inside was written first, and that HEAD, refs and the index are
//! unchanged.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::os::unix::fs::{symlink, PermissionsExt};
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

fn refused(work: &Path, cfg: &Path, args: &[&str]) -> String {
    let o = levcs(work, cfg, args);
    let stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    assert!(!o.status.success(), "{args:?} succeeded: {stderr}");
    stderr
}

struct Fixture {
    work: PathBuf,
    cfg: PathBuf,
    outside: PathBuf,
}

fn setup(tag: &str) -> Fixture {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!(
        "levcs-safe-checkout-{tag}-{}-{stamp}",
        std::process::id()
    ));
    let f = Fixture {
        work: base.join("w"),
        cfg: base.join("cfg"),
        outside: base.join("outside"),
    };
    std::fs::create_dir_all(&f.work).unwrap();
    std::fs::create_dir_all(&f.outside).unwrap();
    ok(&f.work, &f.cfg, &["init", "--key", "owner"]);
    f
}

impl Fixture {
    fn ok(&self, args: &[&str]) -> String {
        ok(&self.work, &self.cfg, args)
    }

    fn refused(&self, args: &[&str]) -> String {
        refused(&self.work, &self.cfg, args)
    }

    fn write(&self, path: &str, bytes: &[u8]) {
        let p = self.work.join(path);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, bytes).unwrap();
    }

    fn read(&self, path: &str) -> Vec<u8> {
        std::fs::read(self.work.join(path)).unwrap()
    }

    fn commit(&self, files: &[(&str, &[u8])], message: &str) {
        for (p, b) in files {
            self.write(p, b);
            self.ok(&["track", p]);
        }
        self.ok(&["commit", "-m", message, "--key", "owner"]);
    }

    /// Replace the working tree's `dir` with a symlink to `outside`.
    fn link_dir_outside(&self, dir: &str) {
        let p = self.work.join(dir);
        if p.exists() {
            std::fs::remove_dir_all(&p).unwrap();
        }
        symlink(&self.outside, &p).unwrap();
    }

    /// HEAD, every ref, the index, and the merge state, as bytes.
    fn state(&self) -> BTreeMap<String, Option<Vec<u8>>> {
        fn walk(dir: &Path, base: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
            for ent in std::fs::read_dir(dir).unwrap() {
                let p = ent.unwrap().path();
                if p.is_dir() {
                    walk(&p, base, out);
                } else {
                    let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                    out.insert(rel, Some(std::fs::read(&p).unwrap()));
                }
            }
        }
        let l = self.work.join(".levcs");
        let mut out = BTreeMap::new();
        walk(&l.join("refs"), &l, &mut out);
        for name in ["HEAD", "index", "MERGE_HEAD", "MERGE_BASE", "merge-record"] {
            out.insert(name.into(), std::fs::read(l.join(name)).ok());
        }
        out
    }

    fn outside_is_empty(&self) {
        let left: Vec<_> = std::fs::read_dir(&self.outside)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "written outside the repository: {left:?}");
    }
}

/// Base on `main`: `a.txt`. Branch `topic` changes `a.txt` and adds
/// `dir/f.txt`. Ends on `main`, with no `dir` in the working tree.
fn diverged(tag: &str) -> Fixture {
    let f = setup(tag);
    f.commit(&[("a.txt", b"base\n")], "base");
    f.ok(&["branch", "--create", "topic"]);
    f.ok(&["branch", "--switch", "topic"]);
    f.commit(
        &[("a.txt", b"topic\n"), ("dir/f.txt", b"topic file\n")],
        "topic",
    );
    f.ok(&["branch", "--switch", "main"]);
    let _ = std::fs::remove_dir_all(f.work.join("dir"));
    f
}

#[test]
fn refused_switch_leaves_head_refs_and_index() {
    let f = diverged("switch");
    f.link_dir_outside("dir");
    let before = f.state();
    f.refused(&["branch", "--switch", "topic"]);
    f.outside_is_empty();
    assert_eq!(
        f.state(),
        before,
        "a refused switch moved HEAD, a ref or the index"
    );
    assert_eq!(
        f.read("a.txt"),
        b"base\n",
        "a.txt was written before the refusal"
    );

    // With the symlink gone, the same switch goes through.
    std::fs::remove_file(f.work.join("dir")).unwrap();
    f.ok(&["branch", "--switch", "topic"]);
    assert_eq!(f.read("dir/f.txt"), b"topic file\n");
}

#[test]
fn refused_fast_forward_leaves_branch_and_index() {
    let f = diverged("ff");
    f.link_dir_outside("dir");
    let before = f.state();
    f.refused(&["merge", "topic"]);
    f.outside_is_empty();
    assert_eq!(
        f.state(),
        before,
        "a refused fast-forward moved the branch or the index"
    );
    assert_eq!(f.read("a.txt"), b"base\n");
}

/// A tracked file replaced by a symlink is uncommitted work: the switch is
/// refused before anything is written, and the link's target is never
/// written through. (It used to be replaced; before that, written through.)
#[test]
fn switch_refuses_a_symlinked_file_and_never_writes_through() {
    let f = diverged("final-link");
    let target = f.outside.join("secret");
    std::fs::write(&target, b"protected").unwrap();
    std::fs::remove_file(f.work.join("a.txt")).unwrap();
    symlink(&target, f.work.join("a.txt")).unwrap();
    let before = f.state();
    let e = f.refused(&["branch", "--switch", "topic"]);
    assert!(e.contains("a.txt") && e.contains("symlink"), "{e}");
    assert_eq!(std::fs::read(&target).unwrap(), b"protected");
    assert!(std::fs::symlink_metadata(f.work.join("a.txt"))
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(f.state(), before);
}

/// A clean file hard-linked to one outside is replaced by the switch, so
/// the outside file keeps its contents. Writing in place changed both.
#[test]
fn switch_replaces_a_hard_linked_file() {
    let f = diverged("hard-link");
    let target = f.outside.join("shared");
    std::fs::write(&target, b"base\n").unwrap();
    std::fs::remove_file(f.work.join("a.txt")).unwrap();
    std::fs::hard_link(&target, f.work.join("a.txt")).unwrap();
    f.ok(&["branch", "--switch", "topic"]);
    assert_eq!(std::fs::read(&target).unwrap(), b"base\n");
    assert_eq!(f.read("a.txt"), b"topic\n");
}

/// A three-way merge checks every path it will write before writing any:
/// `a.txt` merges cleanly, `dir/f.txt` would go through the symlink, and
/// neither is written. No merge state is recorded.
#[test]
fn refused_three_way_merge_writes_nothing() {
    let f = diverged("three-way");
    f.commit(&[("b.txt", b"main\n")], "main");
    f.link_dir_outside("dir");
    let before = f.state();
    f.refused(&["merge", "topic"]);
    f.outside_is_empty();
    assert_eq!(
        f.state(),
        before,
        "a refused merge changed refs, index or merge state"
    );
    assert_eq!(
        f.read("a.txt"),
        b"base\n",
        "a.txt was written before the refusal"
    );
}

#[test]
fn refused_abort_keeps_the_merge_to_retry() {
    let f = setup("abort");
    f.commit(&[("a.txt", b"base\n"), ("dir/g.txt", b"g\n")], "base");
    f.ok(&["branch", "--create", "topic"]);
    f.commit(&[("a.txt", b"ours\n")], "ours");
    f.ok(&["branch", "--switch", "topic"]);
    f.commit(&[("a.txt", b"theirs\n")], "theirs");
    f.ok(&["branch", "--switch", "main"]);
    let o = levcs(&f.work, &f.cfg, &["merge", "topic"]);
    assert_eq!(
        o.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(f.work.join(".levcs/MERGE_HEAD").exists());

    f.link_dir_outside("dir");
    let before = f.state();
    f.refused(&["merge", "--abort"]);
    f.outside_is_empty();
    assert_eq!(
        f.state(),
        before,
        "a refused abort changed the index or merge state"
    );

    std::fs::remove_file(f.work.join("dir")).unwrap();
    f.ok(&["merge", "--abort"]);
    assert!(!f.work.join(".levcs/MERGE_HEAD").exists());
    assert_eq!(f.read("a.txt"), b"ours\n");
    assert_eq!(f.read("dir/g.txt"), b"g\n");
}

/// The path-restricted form wrote the joined path with `fs::write`.
#[test]
fn construct_paths_do_not_follow_symlinks() {
    let f = setup("construct");
    f.commit(&[("a.txt", b"a\n"), ("dir/f.txt", b"f\n")], "base");
    f.link_dir_outside("dir");
    f.refused(&["construct", "dir/f.txt"]);
    f.refused(&["construct", "dir"]);
    f.refused(&["construct"]);
    f.outside_is_empty();

    std::fs::remove_file(f.work.join("dir")).unwrap();
    let target = f.outside.join("secret");
    std::fs::write(&target, b"protected").unwrap();
    std::fs::remove_file(f.work.join("a.txt")).unwrap();
    symlink(&target, f.work.join("a.txt")).unwrap();
    f.ok(&["construct", "a.txt"]);
    assert_eq!(std::fs::read(&target).unwrap(), b"protected");
    assert_eq!(f.read("a.txt"), b"a\n");
    // A symlink is replaced even when its target already holds the blob.
    std::fs::write(&target, b"a\n").unwrap();
    std::fs::remove_file(f.work.join("a.txt")).unwrap();
    symlink(&target, f.work.join("a.txt")).unwrap();
    f.ok(&["construct", "a.txt"]);
    assert!(std::fs::symlink_metadata(f.work.join("a.txt"))
        .unwrap()
        .is_file());
    f.ok(&["construct", "dir"]);
    assert_eq!(f.read("dir/f.txt"), b"f\n");
}

/// Several paths are one selection, checked whole before anything is
/// written: `a.txt` used to be overwritten before `dir` was found to be a
/// symlink.
#[test]
fn construct_checks_every_path_before_writing_any() {
    let f = setup("construct-many");
    f.commit(
        &[("a.txt", b"committed a\n"), ("dir/b.txt", b"committed b\n")],
        "base",
    );
    f.write("a.txt", b"local edit\n");
    f.link_dir_outside("dir");
    for args in [
        &["construct", "HEAD", "a.txt", "dir/b.txt"][..],
        &["construct", "HEAD", "a.txt", "dir"],
        &["construct", "--all", "HEAD", "a.txt", "dir/b.txt"],
    ] {
        f.refused(args);
        assert_eq!(
            f.read("a.txt"),
            b"local edit\n",
            "{args:?}: a.txt written first"
        );
    }
    f.outside_is_empty();

    // A directory where the selection has a file is found before writing too.
    std::fs::remove_file(f.work.join("dir")).unwrap();
    std::fs::create_dir_all(f.work.join("dir/b.txt/inner")).unwrap();
    for args in [
        &["construct", "HEAD", "a.txt", "dir/b.txt"][..],
        &["construct", "--all", "HEAD", "a.txt", "dir/b.txt"],
    ] {
        f.refused(args);
        assert_eq!(
            f.read("a.txt"),
            b"local edit\n",
            "{args:?}: a.txt written first"
        );
    }
}

/// A file whose contents already match is skipped only if its mode does
/// too: a mode-only change used to be left in place and reported restored.
#[test]
fn construct_restores_a_changed_mode() {
    let f = setup("construct-mode");
    let mode = |p: &str| {
        std::fs::metadata(f.work.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    let chmod = |p: &str, m: u32| {
        std::fs::set_permissions(f.work.join(p), std::fs::Permissions::from_mode(m)).unwrap()
    };
    f.write("script.sh", b"echo hello\n");
    chmod("script.sh", 0o755);
    f.write("plain.txt", b"plain\n");
    chmod("plain.txt", 0o644);
    f.ok(&["track", "script.sh", "plain.txt"]);
    f.ok(&["commit", "-m", "modes", "--key", "owner"]);

    chmod("script.sh", 0o644);
    chmod("plain.txt", 0o755);
    f.ok(&["construct", "HEAD", "script.sh", "plain.txt"]);
    assert_eq!(mode("script.sh"), 0o755);
    assert_eq!(mode("plain.txt"), 0o644);
}

/// A cache restores the permissions it saved, not only the executable bit:
/// a private file came back readable by everyone.
#[test]
fn cache_restore_keeps_saved_permissions() {
    let f = setup("cache-mode");
    f.commit(
        &[("private.txt", b"private\n"), ("run.sh", b"run\n")],
        "base",
    );
    for (p, m) in [("private.txt", 0o600), ("run.sh", 0o750)] {
        std::fs::set_permissions(f.work.join(p), std::fs::Permissions::from_mode(m)).unwrap();
    }
    f.ok(&["cache", "--save"]);
    let id = std::fs::read_dir(f.work.join(".levcs/cache/workdir"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .into_string()
        .unwrap();
    std::fs::remove_file(f.work.join("private.txt")).unwrap();
    std::fs::set_permissions(
        f.work.join("run.sh"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    f.ok(&["cache", "--restore", &id]);
    let mode = |p: &str| {
        std::fs::metadata(f.work.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    assert_eq!(mode("private.txt"), 0o600);
    assert_eq!(mode("run.sh"), 0o750);
}

#[test]
fn forget_delete_does_not_follow_symlinks() {
    let f = setup("forget");
    f.commit(&[("dir/f.txt", b"f\n")], "base");
    f.link_dir_outside("dir");
    std::fs::write(f.outside.join("f.txt"), b"protected").unwrap();
    let err = f.refused(&["forget", "--delete", "dir/f.txt"]);
    assert!(err.contains("could not delete"), "{err}");
    assert_eq!(
        std::fs::read(f.outside.join("f.txt")).unwrap(),
        b"protected"
    );
}

#[test]
fn cache_restore_does_not_follow_symlinks() {
    let f = setup("cache");
    f.commit(&[("dir/f.txt", b"f\n")], "base");
    f.ok(&["cache", "--save", "-m", "note"]);
    let id = std::fs::read_dir(f.work.join(".levcs/cache/workdir"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .file_name()
        .into_string()
        .unwrap();
    f.link_dir_outside("dir");
    f.refused(&["cache", "--restore", &id]);
    f.outside_is_empty();

    std::fs::remove_file(f.work.join("dir")).unwrap();
    f.ok(&["cache", "--restore", &id]);
    assert_eq!(f.read("dir/f.txt"), b"f\n");
    // The cache's own message is not restored into the working tree.
    assert!(!f.work.join(".message").exists());
}

#[test]
fn cache_ids_cannot_name_other_directories() {
    let f = setup("cache-id");
    f.commit(&[("a.txt", b"a\n")], "base");
    for id in ["..", "../..", "../../refs", "."] {
        f.refused(&["cache", "--drop", id]);
        f.refused(&["cache", "--restore", id]);
    }
    assert!(f.work.join(".levcs/refs").is_dir());
    assert!(f.work.join(".levcs/cache/workdir").is_dir());
}

/// Nothing named `.levcs` is tracked or committed below the top level,
/// since checkout refuses to write one: a nested repository's metadata is
/// skipped, and naming a `.levcs` path is refused.
#[test]
fn levcs_components_are_never_tracked() {
    let f = setup("nested");
    f.write("sub/.levcs/config", b"nested repository");
    f.write("sub/real.txt", b"real\n");
    f.ok(&["track", "sub"]);
    f.ok(&["commit", "-m", "sub", "--key", "owner"]);
    let listed = f.ok(&["status"]);
    assert!(!listed.contains(".levcs/config"), "{listed}");
    for p in ["sub/.levcs/config", ".levcs/config"] {
        let err = f.refused(&["track", p]);
        assert!(err.contains("refusing to track"), "{p}: {err}");
    }
    f.write(".LEVCS/x", b"case variant");
    f.refused(&["track", ".LEVCS/x"]);
}
