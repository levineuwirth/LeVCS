//! Pack encode/decode microbenchmarks.
//!
//! Goal: a baseline for the wire-path codec everyone hits on push and
//! clone. Sweeps four shapes — many-tiny, many-small, few-big, and the
//! delta-friendly "successive similar entries" case the encoder
//! optimizes for. The delta variant is the only one likely to be
//! sensitive to encoder heuristic changes; the rest are zstd-bound.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use levcs_protocol::Pack;

/// Pseudo-random byte generator (LCG). Outputs defeat zstd matching, so
/// "incompressible" entries actually exercise the worst-case encode path.
fn lcg_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut s = seed;
    (0..n)
        .map(|_| {
            s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (s >> 33) as u8
        })
        .collect()
}

/// Build a pack with `count` entries each of `size` bytes, all type=Blob,
/// all incompressible (worst case for zstd, no delta wins because content
/// shares nothing).
fn random_pack(seed_base: u64, count: usize, size: usize) -> Pack {
    let mut pk = Pack::new();
    for i in 0..count {
        pk.push(1, lcg_bytes(seed_base.wrapping_add(i as u64), size));
    }
    pk
}

/// Build a pack of `count` entries that are mostly identical to the
/// previous one — the case the delta encoder is optimized for. Each
/// successive entry equals the previous plus a small unique tail.
fn delta_friendly_pack(seed: u64, count: usize, size: usize) -> Pack {
    let base = lcg_bytes(seed, size);
    let mut pk = Pack::new();
    pk.push(1, base.clone());
    for i in 1..count {
        let mut v = base.clone();
        v.extend_from_slice(format!(" tail-{i}\n").as_bytes());
        pk.push(1, v);
    }
    pk
}

fn bench_encode(c: &mut Criterion) {
    let mut g = c.benchmark_group("pack_encode");
    for &(label, count, size) in &[
        ("1000x100B", 1000usize, 100usize),
        ("100x1KiB", 100, 1024),
        ("10x1MiB", 10, 1024 * 1024),
    ] {
        let pk = random_pack(0xa5a5_a5a5, count, size);
        g.throughput(Throughput::Bytes((count * size) as u64));
        g.bench_with_input(BenchmarkId::new("incompressible", label), &pk, |b, pk| {
            b.iter(|| black_box(pk.encode()))
        });
    }
    for &(label, count, size) in &[("100x1KiB-similar", 100usize, 1024usize)] {
        let pk = delta_friendly_pack(0x5a5a_5a5a, count, size);
        g.throughput(Throughput::Bytes((count * size) as u64));
        g.bench_with_input(BenchmarkId::new("delta_friendly", label), &pk, |b, pk| {
            b.iter(|| black_box(pk.encode()))
        });
    }
    g.finish();
}

fn bench_decode(c: &mut Criterion) {
    let mut g = c.benchmark_group("pack_decode");
    for &(label, count, size) in &[
        ("1000x100B", 1000usize, 100usize),
        ("100x1KiB", 100, 1024),
        ("10x1MiB", 10, 1024 * 1024),
    ] {
        let pk = random_pack(0xa5a5_a5a5, count, size);
        let bytes = pk.encode();
        g.throughput(Throughput::Bytes(bytes.len() as u64));
        g.bench_with_input(BenchmarkId::new("incompressible", label), &bytes, |b, bytes| {
            b.iter(|| black_box(Pack::decode(bytes).unwrap()))
        });
    }
    {
        let pk = delta_friendly_pack(0x5a5a_5a5a, 100, 1024);
        let bytes = pk.encode();
        g.throughput(Throughput::Bytes(bytes.len() as u64));
        g.bench_with_input(
            BenchmarkId::new("delta_friendly", "100x1KiB-similar"),
            &bytes,
            |b, bytes| b.iter(|| black_box(Pack::decode(bytes).unwrap())),
        );
    }
    g.finish();
}

criterion_group!(benches, bench_encode, bench_decode);
criterion_main!(benches);
