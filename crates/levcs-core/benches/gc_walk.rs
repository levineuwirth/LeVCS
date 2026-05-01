//! GC reachability-walk throughput.
//!
//! The walk is currently inlined in the CLI's `gc` command (see
//! `levcs-cli/src/repo_cmds.rs` near the `gc` fn). For benchmarking we
//! reproduce the same loop here against a synthetic store.
//!
//! Setup builds N blobs reachable through one tree under one commit,
//! writes them to a tempdir-backed store, then times the walk from
//! that single commit ID. Setup is heavy (10K loose-object writes hits
//! the disk hard); we let criterion amortize it across samples by
//! keeping the store across the bench's iterations — the walk is
//! read-only, so re-running it is harmless.

use std::collections::HashSet;
use std::path::PathBuf;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use levcs_core::hash::blake3_hash;
use levcs_core::object::ObjectType;
use levcs_core::{
    Blob, Commit, EntryType, FileMode, ObjectId, ObjectStore, Release, Tree, TreeEntry,
};

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

/// Populate `store` with N unique blobs and a single tree referencing
/// them all. Returns the tree's ID — the seed for the walk.
///
/// We deliberately do NOT include a commit. Commit objects are
/// signed-frame types whose `RawObject::parse` requires a signature
/// trailer; producing one needs `levcs-identity`, which isn't a dep of
/// `levcs-core`. Since the walk's cost is dominated by the per-object
/// loop body (HashSet insert + read + parse), the shape Tree → N Blobs
/// captures everything we want to characterize.
fn populate(store: &ObjectStore, n_blobs: usize) -> ObjectId {
    let mut tree = Tree::new();
    for i in 0..n_blobs {
        let body = format!("blob-{i:08}\n").into_bytes();
        let blob = Blob::new(body);
        let bytes = blob.serialize();
        let id = blake3_hash(&bytes);
        store.write_at(id, &bytes).unwrap();
        tree.entries.push(TreeEntry {
            name: format!("file_{i:08}.txt"),
            entry_type: EntryType::Blob,
            mode: FileMode::REGULAR,
            hash: id,
        });
    }
    tree.sort_and_validate().unwrap();
    let tree_bytes = tree.serialize();
    let tree_id = blake3_hash(&tree_bytes);
    store.write_at(tree_id, &tree_bytes).unwrap();
    tree_id
}

/// The walk loop — reproduces the body of `gc` in the CLI. Returns the
/// number of reachable IDs found, just to keep the optimizer honest.
fn walk_reachable(store: &ObjectStore, root: ObjectId) -> usize {
    let mut reachable: HashSet<ObjectId> = HashSet::new();
    let mut stack: Vec<ObjectId> = vec![root];
    while let Some(id) = stack.pop() {
        if !reachable.insert(id) {
            continue;
        }
        if let Ok(raw) = store.read_object(id) {
            match raw.object_type {
                ObjectType::Tree => {
                    if let Ok(t) = Tree::parse_body(&raw.body) {
                        for e in t.entries {
                            stack.push(e.hash);
                        }
                    }
                }
                ObjectType::Commit => {
                    if let Ok(c) = Commit::parse_body(&raw.body) {
                        stack.push(c.tree);
                        stack.extend(c.parents);
                    }
                }
                ObjectType::Release => {
                    if let Ok(r) = Release::parse_body(&raw.body) {
                        stack.push(r.tree);
                        stack.push(r.predecessor);
                    }
                }
                ObjectType::Blob | ObjectType::Authority => {}
            }
        }
    }
    reachable.len()
}

fn bench_walk(c: &mut Criterion) {
    let mut g = c.benchmark_group("gc_reachability_walk");
    // Reduce sample count for the heavy 10K case — setup is already
    // expensive and we don't need tight statistical bounds on a baseline.
    g.sample_size(20);

    for &n in &[1000usize, 10_000] {
        let dir = tempdir(&format!("levcs-bench-gc-{n}"));
        let store = ObjectStore::new(dir.clone());
        store.ensure_dirs().unwrap();
        let root = populate(&store, n);

        g.bench_with_input(
            BenchmarkId::from_parameter(format!("{n}_objects")),
            &(),
            |b, _| b.iter(|| black_box(walk_reachable(&store, root))),
        );

        let _ = std::fs::remove_dir_all(dir);
    }
    g.finish();
}

criterion_group!(benches, bench_walk);
criterion_main!(benches);
