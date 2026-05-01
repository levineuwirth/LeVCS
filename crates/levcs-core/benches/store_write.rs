//! Object-store loose-write throughput.
//!
//! Tier 1 measured the pure-CPU cost of serialize+hash. This is the
//! disk-side bookend: temp file write → fsync → atomic rename, which
//! is what every received object pays on push.
//!
//! Each measured iteration writes a *unique* object (counter-keyed
//! body, so the BLAKE3 hash differs every time). Without that, the
//! second iteration would hit the `path.is_file()` short-circuit and
//! skip the actual write, giving a meaningless near-zero number.
//!
//! Result is filesystem-dependent: tmpfs / ext4 / btrfs / NVMe / spinning
//! disk all differ. The headline is "what does this machine give us"
//! — useful as a regression baseline, not a portable spec.

use std::cell::Cell;
use std::path::PathBuf;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use levcs_core::object::{frame_unsigned, ObjectType};
use levcs_core::ObjectStore;

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

/// Build a unique blob-framed body whose first 8 bytes are `counter`.
/// Different counter ⇒ different hash ⇒ a fresh write, not a no-op.
fn unique_blob(counter: u64, size: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(size);
    body.extend_from_slice(&counter.to_le_bytes());
    body.resize(size, 0xab);
    frame_unsigned(ObjectType::Blob, &body)
}

fn bench_write_raw(c: &mut Criterion) {
    let mut g = c.benchmark_group("store_write_raw");
    for &(label, size) in &[
        ("1KiB", 1024usize),
        ("100KiB", 100 * 1024),
        ("1MiB", 1024 * 1024),
    ] {
        // Fresh store per size — keeps the per-shard directory population
        // realistic (objects spread across 256 shards as the counter grows).
        let dir = tempdir(&format!("levcs-bench-store-{label}"));
        let store = ObjectStore::new(dir.clone());
        store.ensure_dirs().unwrap();

        // Use a Cell to advance the counter inside the closure without
        // taking a `&mut`. Each criterion sample runs many iterations,
        // so we burn through unique hashes quickly — at 100 KiB × 30
        // samples × ~thousands-of-iters that's still well under 1M
        // distinct objects, comfortably within tmp space.
        let counter = Cell::new(0u64);

        g.throughput(Throughput::Bytes(size as u64));
        g.bench_with_input(BenchmarkId::from_parameter(label), &store, |b, store| {
            b.iter(|| {
                let n = counter.get();
                counter.set(n + 1);
                let bytes = unique_blob(n, size);
                black_box(store.write_raw(&bytes).unwrap());
            })
        });

        // Don't leave gigabytes in /tmp after the bench.
        let _ = std::fs::remove_dir_all(dir);
    }
    g.finish();
}

criterion_group!(benches, bench_write_raw);
criterion_main!(benches);
