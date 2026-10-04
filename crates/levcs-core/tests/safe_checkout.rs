//! Checkout writes only inside the working tree, never through a link, and
//! checks the whole tree before writing anything.
//!
//! The first three tests are the audit's probes (`audit_checkout.rs`): a
//! tree from elsewhere could name `../outside` or `.levcs/config` and have
//! checkout write there, and a symlink in the working tree was written
//! through. The rest cover what fixing those had to cover too: a symlinked
//! directory anywhere on the way, a hard-linked file, an invalid name or
//! `.levcs` component deep in a tree, and a refusal that must come before
//! the first write.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use levcs_core::worktree::{self, Perms};
use levcs_core::{
    Blob, EntryType, FileMode, Index, IndexEntry, IndexEntryFlags, ObjectId, Repository, Tree,
    TreeEntry,
};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A fresh directory holding a repository at `checkout/` and room beside
/// it for the files a bad checkout would reach.
fn setup() -> (PathBuf, Repository) {
    let root = std::env::temp_dir().join(format!(
        "levcs-safe-checkout-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&root).unwrap();
    let repo = Repository::init_skeleton(root.join("checkout")).unwrap();
    (root, repo)
}

fn blob(repo: &Repository, bytes: &[u8]) -> ObjectId {
    repo.objects
        .write_raw(&Blob::new(bytes.to_vec()).serialize())
        .unwrap()
}

fn entry(name: &str, entry_type: EntryType, hash: ObjectId) -> TreeEntry {
    TreeEntry {
        name: name.into(),
        entry_type,
        mode: FileMode::REGULAR,
        hash,
    }
}

/// Write a tree with these entries as given: not sorted, not validated,
/// as a tree from another repository could arrive.
fn raw_tree(repo: &Repository, entries: Vec<TreeEntry>) -> ObjectId {
    repo.objects
        .write_raw(&Tree { entries }.serialize())
        .unwrap()
}

/// Files by path components, with their contents.
type Split<'a> = Vec<(Vec<&'a str>, &'a [u8])>;

/// A tree of files, built through the ordinary validating path.
fn tree(repo: &Repository, files: &[(&str, &[u8])]) -> ObjectId {
    fn build(repo: &Repository, files: &[(Vec<&str>, &[u8])]) -> ObjectId {
        let mut t = Tree::new();
        let mut dirs: std::collections::BTreeMap<&str, Split> = Default::default();
        for (comps, bytes) in files {
            if comps.len() == 1 {
                t.entries
                    .push(entry(comps[0], EntryType::Blob, blob(repo, bytes)));
            } else {
                dirs.entry(comps[0])
                    .or_default()
                    .push((comps[1..].to_vec(), bytes));
            }
        }
        for (name, sub) in dirs {
            t.entries
                .push(entry(name, EntryType::Tree, build(repo, &sub)));
        }
        t.sort_and_validate().unwrap();
        repo.objects.write_raw(&t.serialize()).unwrap()
    }
    let split: Split = files
        .iter()
        .map(|(p, b)| (p.split('/').collect(), *b))
        .collect();
    build(repo, &split)
}

fn checkout_name(repo: &Repository, name: &str) -> levcs_core::Result<()> {
    let b = blob(repo, b"attacker controlled");
    let id = raw_tree(repo, vec![entry(name, EntryType::Blob, b)]);
    repo.checkout_tree(id, &repo.workdir)
}

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

#[test]
fn audit_checkout_rejects_parent_escape() {
    let (root, repo) = setup();
    let result = checkout_name(&repo, "../outside");
    assert!(result.is_err(), "checkout accepted traversal");
    assert!(!root.join("outside").exists(), "checkout wrote outside");
}

#[test]
fn audit_checkout_protects_metadata_from_embedded_path() {
    let (_root, repo) = setup();
    let original = read(&repo.config_path());
    let result = checkout_name(&repo, ".levcs/config");
    assert!(result.is_err(), "a name containing '/' was accepted");
    assert_eq!(
        read(&repo.config_path()),
        original,
        "checkout overwrote metadata"
    );
}

#[cfg(unix)]
#[test]
fn audit_checkout_does_not_follow_worktree_symlink() {
    let (root, repo) = setup();
    let outside = root.join("outside");
    std::fs::write(&outside, b"protected").unwrap();
    std::os::unix::fs::symlink(&outside, repo.workdir.join("ordinary")).unwrap();
    checkout_name(&repo, "ordinary").unwrap();
    assert_eq!(
        read(&outside),
        b"protected",
        "checkout followed the symlink"
    );
    // The link is replaced by the tree's file, not left or written through.
    let meta = std::fs::symlink_metadata(repo.workdir.join("ordinary")).unwrap();
    assert!(meta.is_file());
    assert_eq!(read(&repo.workdir.join("ordinary")), b"attacker controlled");
}

/// An invalid name deep in a tree refuses the whole tree, and a file
/// earlier in the tree is not written first.
#[test]
fn nested_invalid_name_refuses_before_writing() {
    for bad in ["..", ".", "", "x/y", "nul\0"] {
        let (root, repo) = setup();
        let inner = raw_tree(&repo, vec![entry(bad, EntryType::Blob, blob(&repo, b"x"))]);
        let id = raw_tree(
            &repo,
            vec![
                entry("0first.txt", EntryType::Blob, blob(&repo, b"first")),
                entry("sub", EntryType::Tree, inner),
            ],
        );
        assert!(
            repo.checkout_tree(id, &repo.workdir).is_err(),
            "{bad:?} accepted"
        );
        assert!(
            !repo.workdir.join("0first.txt").exists(),
            "{bad:?}: wrote before refusing"
        );
        assert!(!repo.workdir.join("sub").exists(), "{bad:?}");
        assert!(!root.join("x").exists());
    }
}

/// A tree's own top-level `.levcs` is history (an authority, a merge
/// record): kept in the tree, skipped by checkout, never written over the
/// repository's metadata.
#[test]
fn root_levcs_entry_is_skipped_not_materialised() {
    let (_root, repo) = setup();
    let original = read(&repo.config_path());
    let meta = raw_tree(
        &repo,
        vec![entry("config", EntryType::Blob, blob(&repo, b"evil"))],
    );
    let id = raw_tree(
        &repo,
        vec![
            entry(".levcs", EntryType::Tree, meta),
            entry("a.txt", EntryType::Blob, blob(&repo, b"a")),
        ],
    );
    repo.checkout_tree(id, &repo.workdir).unwrap();
    assert_eq!(read(&repo.workdir.join("a.txt")), b"a");
    assert_eq!(read(&repo.config_path()), original);
    assert_eq!(repo.tree_files(id, "").unwrap().len(), 1);
}

/// Anywhere else, or in another letter case, a `.levcs` component would
/// write repository metadata (on a case-insensitive file system) or make a
/// nested repository. The whole tree is refused.
#[test]
fn other_levcs_components_refuse_the_tree() {
    for path in [
        "sub/.levcs/config",
        ".LEVCS/config",
        "sub/.Levcs",
        "a/b/.levcs",
    ] {
        let (_root, repo) = setup();
        let original = read(&repo.config_path());
        let id = tree(&repo, &[("0first.txt", b"first"), (path, b"evil")]);
        assert!(
            repo.checkout_tree(id, &repo.workdir).is_err(),
            "{path} accepted"
        );
        assert!(
            !repo.workdir.join("0first.txt").exists(),
            "{path}: wrote before refusing"
        );
        assert_eq!(read(&repo.config_path()), original);
    }
}

/// Entries out of order, repeated, or with unknown mode bits are parsed
/// as errors: writing never produces them, so a tree with them was made
/// elsewhere. Two entries with one name would be checked out twice.
#[test]
fn unsorted_duplicate_or_unknown_mode_entries_are_refused() {
    let (_root, repo) = setup();
    let a = blob(&repo, b"a");
    let b = blob(&repo, b"b");
    let unsorted = raw_tree(
        &repo,
        vec![
            entry("b.txt", EntryType::Blob, b),
            entry("a.txt", EntryType::Blob, a),
        ],
    );
    let duplicate = raw_tree(
        &repo,
        vec![
            entry("a.txt", EntryType::Blob, a),
            entry("a.txt", EntryType::Blob, b),
        ],
    );
    let mut odd = entry("a.txt", EntryType::Blob, a);
    odd.mode = FileMode(0b100);
    let unknown_mode = raw_tree(&repo, vec![odd]);
    for id in [unsorted, duplicate, unknown_mode] {
        assert!(repo.checkout_tree(id, &repo.workdir).is_err());
        assert!(!repo.workdir.join("a.txt").exists());
    }
}

/// A directory on the way that is a symlink is refused, at any depth, and
/// the refusal comes before any file is written.
#[cfg(unix)]
#[test]
fn ancestor_symlink_is_refused_before_writing() {
    for (link, path) in [("dir", "dir/f.txt"), ("real/link", "real/link/f.txt")] {
        let (root, repo) = setup();
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let link_path = repo.workdir.join(link);
        std::fs::create_dir_all(link_path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, &link_path).unwrap();
        let id = tree(&repo, &[("0first.txt", b"first"), (path, b"evil")]);
        let result = repo.checkout_tree(id, &repo.workdir);
        assert!(
            result.is_err(),
            "{path}: checkout went through a symlinked directory"
        );
        assert!(!outside.join("f.txt").exists(), "{path}: written outside");
        assert!(
            !repo.workdir.join("0first.txt").exists(),
            "{path}: wrote before refusing"
        );
    }
}

/// A file hard-linked to one outside the working tree is replaced, so the
/// outside file keeps its contents. Writing in place changed both.
#[cfg(unix)]
#[test]
fn hard_link_is_replaced_not_written_through() {
    use std::os::unix::fs::MetadataExt;
    let (root, repo) = setup();
    let outside = root.join("outside");
    std::fs::write(&outside, b"protected").unwrap();
    std::fs::hard_link(&outside, repo.workdir.join("shared.txt")).unwrap();
    let id = tree(&repo, &[("shared.txt", b"new")]);
    repo.checkout_tree(id, &repo.workdir).unwrap();
    assert_eq!(read(&outside), b"protected");
    assert_eq!(read(&repo.workdir.join("shared.txt")), b"new");
    assert_ne!(
        std::fs::metadata(&outside).unwrap().ino(),
        std::fs::metadata(repo.workdir.join("shared.txt"))
            .unwrap()
            .ino()
    );
}

/// A directory where the tree has a file is refused before anything is
/// written, rather than part way through.
#[test]
fn directory_in_the_way_refuses_before_writing() {
    let (_root, repo) = setup();
    std::fs::create_dir_all(repo.workdir.join("b.txt/inner")).unwrap();
    let id = tree(&repo, &[("a.txt", b"a"), ("b.txt", b"b")]);
    assert!(repo.checkout_tree(id, &repo.workdir).is_err());
    assert!(!repo.workdir.join("a.txt").exists());
    assert!(repo.workdir.join("b.txt/inner").is_dir());
}

/// Every blob is read and checked against its hash before the first write:
/// a missing or damaged one refuses the checkout, not half of it.
#[test]
fn missing_or_damaged_blob_refuses_before_writing() {
    let (_root, repo) = setup();
    let missing = ObjectId([7; 32]);
    let id = raw_tree(
        &repo,
        vec![
            entry("a.txt", EntryType::Blob, blob(&repo, b"a")),
            entry("b.txt", EntryType::Blob, missing),
        ],
    );
    assert!(repo.checkout_tree(id, &repo.workdir).is_err());
    assert!(!repo.workdir.join("a.txt").exists());

    let (_root, repo) = setup();
    let damaged = blob(&repo, b"damaged");
    let id = tree(&repo, &[("a.txt", b"a"), ("b.txt", b"damaged")]);
    let p = repo.objects.path_for(damaged);
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    std::fs::set_permissions(&p, perms).unwrap();
    std::fs::write(&p, b"not the object").unwrap();
    assert!(repo.checkout_tree(id, &repo.workdir).is_err());
    assert!(!repo.workdir.join("a.txt").exists());
}

/// A subtree checked out under a prefix is walked from the working tree's
/// root like any other path: the prefix cannot lead outside either.
#[cfg(unix)]
#[test]
fn checkout_under_a_prefix_cannot_leave_the_working_tree() {
    let (root, repo) = setup();
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, repo.workdir.join("dir")).unwrap();
    let sub = tree(&repo, &[("f.txt", b"evil")]);
    let under = |prefix: &str| {
        repo.tree_files(sub, prefix)
            .and_then(|files| repo.checkout_files(&files, &repo.workdir))
    };
    assert!(under("dir").is_err());
    assert!(under("../escape").is_err());
    assert!(under(".levcs").is_err());
    assert!(!outside.join("f.txt").exists());
    assert!(!root.join("escape").exists());
    under("real").unwrap();
    assert_eq!(read(&repo.workdir.join("real/f.txt")), b"evil");
}

/// A name some file system would read as `.levcs` is refused like
/// `.levcs` itself: letter case (case-insensitive file systems, with
/// Unicode folding), and the code points HFS+ ignores in names.
#[test]
fn names_a_file_system_reads_as_levcs_are_refused() {
    for path in [
        ".levcs\u{200c}/config",
        "\u{feff}.LEVCS/config",
        "sub/.Lev\u{202e}cs/x",
        ".levc\u{17f}/config",
    ] {
        assert!(worktree::components(path).is_err(), "{path:?} accepted");
    }
    for path in [".levcsignore", "levcs", "sub/.levcs-notes", ".levc"] {
        assert!(worktree::components(path).is_ok(), "{path:?} refused");
    }
}

/// The tree's executable bit is applied. A replaced file otherwise keeps
/// its permissions, as the in-place writes this replaces did: a private
/// file stays private across a checkout. `Perms::Keep` changes nothing.
#[cfg(unix)]
#[test]
fn modes_follow_the_tree_and_the_replaced_file() {
    use std::os::unix::fs::PermissionsExt;
    let (_root, repo) = setup();
    let set = |p: &str, mode: u32| {
        let p = repo.workdir.join(p);
        std::fs::write(&p, b"old").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    let mode = |p: &str| {
        std::fs::metadata(repo.workdir.join(p))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    set("private.txt", 0o600);
    set("was-exec.txt", 0o755);
    set("private.sh", 0o600);
    set("setuid.sh", 0o4755);
    let mut t = Tree::new();
    for (name, exec) in [
        ("new.sh", true),
        ("private.sh", true),
        ("private.txt", false),
        ("setuid.sh", true),
        ("was-exec.txt", false),
    ] {
        let mut e = entry(name, EntryType::Blob, blob(&repo, b"new"));
        if exec {
            e.mode = FileMode::EXECUTABLE;
        }
        t.entries.push(e);
    }
    t.sort_and_validate().unwrap();
    let id = repo.objects.write_raw(&t.serialize()).unwrap();
    repo.checkout_tree(id, &repo.workdir).unwrap();
    assert_ne!(mode("new.sh") & 0o100, 0);
    assert_eq!(mode("private.txt"), 0o600);
    assert_eq!(mode("private.sh"), 0o700);
    assert_eq!(mode("was-exec.txt"), 0o644);
    assert_eq!(mode("setuid.sh"), 0o755);

    let wt = worktree::open(&repo.workdir).unwrap();
    set("kept.txt", 0o640);
    wt.write_file("kept.txt", b"new", Perms::Keep).unwrap();
    assert_eq!(read(&repo.workdir.join("kept.txt")), b"new");
    assert_eq!(mode("kept.txt"), 0o640);

    // Exact permissions apply to a new file too, umask or not, without the
    // special bits.
    wt.write_file("exact.txt", b"new", Perms::Exact(0o600))
        .unwrap();
    assert_eq!(mode("exact.txt"), 0o600);
    set("exact.sh", 0o644);
    wt.write_file("exact.sh", b"new", Perms::Exact(0o2750))
        .unwrap();
    assert_eq!(mode("exact.sh"), 0o750);

    // Empty contents are never written, so the kernel clears no set-ID bit
    // on our behalf: the permissions alone must leave them out.
    set("suid.sh", 0o4755);
    wt.write_file("suid.sh", b"", Perms::Executable).unwrap();
    assert_eq!(mode("suid.sh"), 0o755);
    wt.write_file("exact-suid.sh", b"", Perms::Exact(0o4750))
        .unwrap();
    assert_eq!(mode("exact-suid.sh"), 0o750);
}

/// `holds` is what lets a write be skipped: true only for a regular file
/// with these exact bytes and the mode the write would leave, found without
/// following a link.
#[cfg(unix)]
#[test]
fn holds_requires_contents_mode_and_a_regular_file() {
    use std::os::unix::fs::PermissionsExt;
    let (root, repo) = setup();
    let w = |p: &str| repo.workdir.join(p);
    let wt = worktree::open(&repo.workdir).unwrap();
    std::fs::write(w("a.txt"), b"same").unwrap();
    std::fs::set_permissions(w("a.txt"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(wt.holds("a.txt", b"same", Perms::Regular).unwrap());
    assert!(!wt.holds("a.txt", b"other", Perms::Regular).unwrap());
    assert!(!wt.holds("a.txt", b"same", Perms::Executable).unwrap());
    assert!(!wt.holds("a.txt", b"same", Perms::Exact(0o600)).unwrap());
    assert!(!wt.holds("missing.txt", b"same", Perms::Regular).unwrap());
    assert!(!wt
        .holds("no/such/dir.txt", b"same", Perms::Regular)
        .unwrap());

    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("same.txt"), b"same").unwrap();
    std::os::unix::fs::symlink(outside.join("same.txt"), w("link.txt")).unwrap();
    assert!(!wt.holds("link.txt", b"same", Perms::Keep).unwrap());
    std::os::unix::fs::symlink(&outside, w("dir")).unwrap();
    assert!(wt.holds("dir/same.txt", b"same", Perms::Keep).is_err());
    std::fs::create_dir(w("sub")).unwrap();
    assert!(!wt.holds("sub", b"", Perms::Keep).unwrap());
}

/// Removal goes through the same walk: a symlinked directory on the way is
/// refused, and a symlink named directly is removed itself, not its target.
#[cfg(unix)]
#[test]
fn remove_does_not_follow_links() {
    let (root, repo) = setup();
    let outside = root.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("f.txt"), b"protected").unwrap();
    std::os::unix::fs::symlink(&outside, repo.workdir.join("dir")).unwrap();
    std::os::unix::fs::symlink(outside.join("f.txt"), repo.workdir.join("link")).unwrap();
    let wt = worktree::open(&repo.workdir).unwrap();
    assert!(wt.remove_file("dir/f.txt").is_err());
    assert!(wt.remove_file("dir").is_ok_and(|removed| removed));
    assert!(wt.remove_file("link").is_ok_and(|removed| removed));
    assert_eq!(read(&outside.join("f.txt")), b"protected");
    assert!(wt.remove_file("../outside/f.txt").is_err());
    assert!(wt.remove_file(".levcs/config").is_err());
    assert!(outside.join("f.txt").exists());
    assert!(repo.config_path().exists());
}

/// A commit never holds a tree its own checkout would refuse. `track`
/// refuses such paths; an index written before it did is caught here.
#[test]
fn commit_refuses_paths_checkout_would_refuse() {
    let (_root, repo) = setup();
    let b = blob(&repo, b"x");
    for path in ["sub/.levcs/config", ".LEVCS/x", ".levcs/config"] {
        let mut idx = Index::new();
        idx.upsert(IndexEntry {
            path: path.into(),
            blob_hash: b,
            mode: 0,
            flags: IndexEntryFlags::TRACKED,
            mtime_micros: 0,
            size: 0,
        });
        assert!(
            repo.build_tree_from_index(&idx).is_err(),
            "{path} committed"
        );
    }
}
