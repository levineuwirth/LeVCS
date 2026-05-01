//! Object serialize + BLAKE3 hash microbenchmarks.
//!
//! Every commit, push, and clone pays this cost — content addressing
//! depends on serialize→hash being fast. Three object types, three
//! sizes each.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use levcs_core::hash::blake3_hash;
use levcs_core::{Blob, Commit, CommitFlags, EntryType, FileMode, ObjectId, Tree, TreeEntry};

fn lcg_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (s >> 33) as u8
        })
        .collect()
}

fn make_tree(n_entries: usize) -> Tree {
    let mut t = Tree::new();
    for i in 0..n_entries {
        t.entries.push(TreeEntry {
            name: format!("file_{i:04}.txt"),
            entry_type: EntryType::Blob,
            mode: FileMode::REGULAR,
            hash: ObjectId([(i & 0xff) as u8; 32]),
        });
    }
    t.sort_and_validate().unwrap();
    t
}

fn make_commit(message_size: usize) -> Commit {
    Commit {
        tree: ObjectId([1; 32]),
        parents: vec![ObjectId([2; 32])],
        authority: ObjectId([3; 32]),
        author_key: [4; 32],
        timestamp_micros: 1_700_000_000_000_000,
        flags: CommitFlags::NONE,
        message: "x".repeat(message_size),
    }
}

fn bench_blob(c: &mut Criterion) {
    let mut g = c.benchmark_group("blob_serialize_hash");
    for &(label, size) in &[
        ("1KiB", 1024usize),
        ("100KiB", 100 * 1024),
        ("1MiB", 1024 * 1024),
    ] {
        let bytes = lcg_bytes(0x1234_5678, size);
        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(label), &bytes, |b, bytes| {
            b.iter(|| {
                let blob = Blob::new(bytes.clone());
                black_box(blake3_hash(&blob.serialize()))
            })
        });
    }
    g.finish();
}

fn bench_tree(c: &mut Criterion) {
    let mut g = c.benchmark_group("tree_serialize_hash");
    for &n in &[10usize, 100, 1000] {
        let t = make_tree(n);
        g.bench_with_input(BenchmarkId::from_parameter(format!("{n}_entries")), &t, |b, t| {
            b.iter(|| black_box(blake3_hash(&t.serialize())))
        });
    }
    g.finish();
}

fn bench_commit(c: &mut Criterion) {
    let mut g = c.benchmark_group("commit_serialize_hash");
    for &(label, msg_size) in &[("short", 32usize), ("medium", 1024), ("long", 16 * 1024)] {
        let commit = make_commit(msg_size);
        g.bench_with_input(BenchmarkId::from_parameter(label), &commit, |b, commit| {
            b.iter(|| {
                let body = commit.body().unwrap();
                black_box(blake3_hash(&body))
            })
        });
    }
    g.finish();
}

criterion_group!(benches, bench_blob, bench_tree, bench_commit);
criterion_main!(benches);
