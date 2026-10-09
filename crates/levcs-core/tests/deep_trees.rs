//! Walks of a tree and of a working tree, without recursion, and within
//! what a working tree may hold.
//!
//! Every walk of a tree here used to recurse once per directory, so a tree
//! nested deeper than a thread's stack aborted the process, and a received
//! tree can nest as deep as its objects allow. Each walk now keeps a stack
//! of its own. A path longer than a working tree may hold is refused as it
//! is built, which also bounds what a walk holds: each level keeps its path.
//!
//! A tree's objects can recur along many paths, so a few dozen objects can
//! name millions of files, or gigabytes. A walk is refused past so many
//! entries, and reading a tree's files past so many bytes, each counted
//! every place it recurs.

use std::path::{Path, PathBuf};

use levcs_core::repo::ContentBudget;
use levcs_core::worktree;
use levcs_core::{
    Blob, EntryType, FileMode, Index, IndexEntry, IndexEntryFlags, ObjectId, Repository, Tree,
    TreeEntry,
};

/// How deep the small-stack test nests its file.
const DEPTH: usize = 600;

fn tempdir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "levcs-deep-trees-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

/// Remove `root` and everything under it without recursion, however deep
/// it goes.
fn remove_deep(root: &Path) {
    let mut stack = vec![(root.to_path_buf(), false)];
    while let Some((path, leaving)) = stack.pop() {
        if leaving {
            let _ = std::fs::remove_dir(&path);
            continue;
        }
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.is_dir() => {
                stack.push((path.clone(), true));
                for e in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                    stack.push((e.path(), false));
                }
            }
            _ => {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}

/// A tree holding `bytes` at `name/name/…/f`, `depth` directories down,
/// and `top.txt` at its root; and the blob at the bottom.
fn deep(repo: &Repository, name: &str, depth: usize, bytes: &[u8]) -> (ObjectId, ObjectId) {
    let blob = |b: &[u8]| {
        repo.objects
            .write_raw(&Blob::new(b.to_vec()).serialize())
            .unwrap()
    };
    let tree = |entries: Vec<TreeEntry>| {
        let mut t = Tree::new();
        t.entries = entries;
        t.sort_and_validate().unwrap();
        repo.objects.write_raw(&t.serialize()).unwrap()
    };
    let bottom = blob(bytes);
    let mut entry = TreeEntry {
        name: "f".into(),
        entry_type: EntryType::Blob,
        mode: FileMode::REGULAR,
        hash: bottom,
    };
    for _ in 0..depth {
        entry = TreeEntry {
            name: name.into(),
            entry_type: EntryType::Tree,
            mode: FileMode::REGULAR,
            hash: tree(vec![entry]),
        };
    }
    let top = TreeEntry {
        name: "top.txt".into(),
        entry_type: EntryType::Blob,
        mode: FileMode::REGULAR,
        hash: blob(b"top\n"),
    };
    (tree(vec![entry, top]), bottom)
}

/// A tree [`DEPTH`] directories deep is walked, listed, looked into,
/// rebuilt from an index, checked out and read back, all on a 128 KiB
/// stack. It runs in a child process, so that an overflow fails this test
/// rather than aborting its binary.
#[test]
fn a_deep_tree_is_walked_on_a_small_stack() {
    if let Some(dir) = std::env::var_os("LEVCS_DEEP_TREE_CHILD") {
        let repo = Repository::init_skeleton(PathBuf::from(dir)).unwrap();
        let (tree, bottom) = deep(&repo, "x", DEPTH, b"deep\n");
        let path = format!("{}f", "x/".repeat(DEPTH));
        std::thread::Builder::new()
            .stack_size(128 << 10)
            .spawn(move || {
                let mut visited = 0;
                repo.walk_tree(tree, "", |_, _| {
                    visited += 1;
                    Ok(true)
                })
                .unwrap();
                assert_eq!(visited, DEPTH + 2);
                let files: Vec<String> = repo
                    .tree_files(tree, "")
                    .unwrap()
                    .into_iter()
                    .map(|f| f.path)
                    .collect();
                assert_eq!(files, ["top.txt".to_string(), path.clone()]);
                assert_eq!(
                    repo.lookup_path(tree, &path).unwrap(),
                    Some((EntryType::Blob, bottom))
                );
                let mut idx = Index::new();
                for f in repo.tree_files(tree, "").unwrap() {
                    idx.upsert(IndexEntry {
                        path: f.path,
                        blob_hash: f.blob,
                        mode: 0,
                        flags: IndexEntryFlags::TRACKED,
                        mtime_micros: 0,
                        size: 0,
                    });
                }
                assert_eq!(repo.build_tree_from_index(&idx).unwrap(), tree);
                repo.checkout_tree(tree, &repo.workdir).unwrap();
                let walked: Vec<String> = repo
                    .walk_workdir_entries()
                    .unwrap()
                    .into_iter()
                    .map(|(p, _)| p)
                    .collect();
                assert_eq!(walked, ["top.txt".to_string(), path]);
            })
            .unwrap()
            .join()
            .unwrap();
        return;
    }
    let dir = tempdir("small-stack");
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_deep_tree_is_walked_on_a_small_stack",
            "--nocapture",
        ])
        .env("LEVCS_DEEP_TREE_CHILD", &dir)
        .output()
        .unwrap();
    remove_deep(&dir);
    assert!(
        out.status.success(),
        "the walks failed: {}; {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A path longer than [`worktree::MAX_PATH_BYTES`] is refused: by a walk,
/// before it builds the path, and by the check every path a working tree
/// is written by goes through.
#[test]
fn a_path_longer_than_a_working_tree_holds_is_refused() {
    let dir = tempdir("too-long");
    let repo = Repository::init_skeleton(&dir).unwrap();
    // 21 directories of 200-byte names: the file's path is 4,222 bytes.
    let (tree, _) = deep(&repo, &"y".repeat(200), 21, b"far\n");
    let mut longest = 0;
    let e = repo
        .walk_tree(tree, "", |path, _| {
            longest = longest.max(path.len());
            Ok(true)
        })
        .unwrap_err();
    assert!(e.to_string().contains("is longer than 4096 bytes"), "{e}");
    assert!(longest <= worktree::MAX_PATH_BYTES, "{longest}");
    let e = repo.tree_files(tree, "").unwrap_err();
    assert!(e.to_string().contains("is longer than 4096 bytes"), "{e}");
    // Where a tree's files go is checked as the files' own paths are.
    let (small, _) = deep(&repo, "x", 1, b"near\n");
    assert!(repo.tree_files(small, "sub").is_ok());
    assert!(repo.tree_files(small, "../outside").is_err());
    assert!(worktree::components(&format!("{}f", "a/".repeat(2047))).is_ok());
    let e = worktree::components(&format!("{}fgh", "a/".repeat(2047))).unwrap_err();
    assert!(e.to_string().contains("is longer than 4096 bytes"), "{e}");
    remove_deep(&dir);
}

/// A tree whose one subtree recurs under both `a` and `b` at each of
/// `levels` levels, down to `bytes` at `f`: 2^levels files from `levels`
/// + 2 objects.
fn recurring(repo: &Repository, levels: usize, bytes: &[u8]) -> ObjectId {
    let tree = |entries: Vec<(&str, EntryType, ObjectId)>| {
        let mut t = Tree::new();
        t.entries = entries
            .into_iter()
            .map(|(name, entry_type, hash)| TreeEntry {
                name: name.into(),
                entry_type,
                mode: FileMode::REGULAR,
                hash,
            })
            .collect();
        t.sort_and_validate().unwrap();
        repo.objects.write_raw(&t.serialize()).unwrap()
    };
    let blob = repo
        .objects
        .write_raw(&Blob::new(bytes.to_vec()).serialize())
        .unwrap();
    let mut id = tree(vec![("f", EntryType::Blob, blob)]);
    for _ in 0..levels {
        id = tree(vec![("a", EntryType::Tree, id), ("b", EntryType::Tree, id)]);
    }
    id
}

/// A walk stops at [`worktree::MAX_TREE_ENTRIES`] entries, each place a
/// shared subtree recurs counted (a clone's checkout of such a tree is in
/// the CLI's tests); a checkout, by either path, at
/// [`worktree::MAX_TREE_BYTES`] of content, each place a shared file recurs
/// counted, before it writes anything. A blob is read once and charged
/// every place it recurs.
#[test]
fn trees_whose_subtrees_recur_are_bounded() {
    let dir = tempdir("recurring");
    let repo = Repository::init_skeleton(&dir).unwrap();
    let files = "files and directories, counting every place a shared subtree recurs";
    let bytes = "bytes, counting every place a shared file recurs";

    // 2^21 files from 23 objects.
    let many = recurring(&repo, 21, b"x");
    let mut visited = 0;
    let e = repo
        .walk_tree(many, "", |_, _| {
            visited += 1;
            Ok(true)
        })
        .unwrap_err();
    assert!(e.to_string().contains(files), "{e}");
    assert_eq!(visited, worktree::MAX_TREE_ENTRIES);

    // 2,048 files of 1 MiB, 2 GiB, from 13 objects.
    let mib = vec![b'y'; 1 << 20];
    let big = recurring(&repo, 11, &mib);
    let e = repo.checkout_tree(big, &repo.workdir).unwrap_err();
    assert!(e.to_string().contains(bytes), "{e}");
    let plan = repo
        .plan_checkout(None, big, &Index::new())
        .unwrap()
        .unwrap();
    let e = repo.apply_checkout(&plan).unwrap_err();
    assert!(e.to_string().contains(bytes), "{e}");
    assert_eq!(repo.walk_workdir_entries().unwrap(), Vec::new());

    let blob = Blob::new(mib).object_id();
    let mut content = ContentBudget::default();
    let charged = (0..)
        .take_while(|_| repo.charge_blob(blob, &mut content).is_ok())
        .count();
    assert_eq!(charged as u64, worktree::MAX_TREE_BYTES >> 20);
    let mut content = ContentBudget::default();
    for _ in 1..charged {
        repo.charge_blob(blob, &mut content).unwrap();
    }
    assert_eq!(
        repo.read_blob(blob, &mut content).unwrap().body.len(),
        1 << 20
    );
    let e = repo.read_blob(blob, &mut content).unwrap_err();
    assert!(e.to_string().contains(bytes), "{e}");
    remove_deep(&dir);
}
