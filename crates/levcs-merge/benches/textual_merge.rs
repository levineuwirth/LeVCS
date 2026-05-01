//! Textual 3-way merge microbenchmarks.
//!
//! `similar`'s line diff is roughly O((N+M) D) where D is the edit
//! distance, so cost grows quickly with both file size and edit
//! density. We sweep three sizes at ~5% edit density on each side, plus
//! a conflicting variant where both sides edit overlapping regions.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use levcs_merge::textual::three_way_merge_lines;

/// Build a `lines`-line document. Each line is `"line N: <body>\n"` so
/// the diff has unique anchors and similarity heuristics can do real
/// work — purely random lines would be too easy (every line different)
/// or too hard (lots of false matches).
fn make_doc(lines: usize, body_len: usize) -> String {
    let body = "x".repeat(body_len);
    let mut s = String::with_capacity(lines * (body_len + 16));
    for i in 0..lines {
        s.push_str(&format!("line {i:06}: {body}\n"));
    }
    s
}

/// Mutate every Nth line to simulate a developer's edit pattern. `step`
/// of 20 ≈ 5% line density. Mutations are non-overlapping with the
/// `theirs` mutator below (different residues mod step) so the merge
/// resolves cleanly.
fn mutate_disjoint(doc: &str, step: usize, residue: usize, marker: char) -> String {
    let mut out = String::with_capacity(doc.len());
    for (i, line) in doc.lines().enumerate() {
        if i % step == residue {
            out.push_str(line);
            out.push(marker);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

/// Mutate every Nth line in a way that overlaps with the other side's
/// edit residue — both sides edit the same lines differently, producing
/// real conflicts.
fn mutate_conflicting(doc: &str, step: usize, marker: &str) -> String {
    let mut out = String::with_capacity(doc.len());
    for (i, line) in doc.lines().enumerate() {
        if i % step == 0 {
            out.push_str(marker);
            out.push('\n');
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn bench_clean_merge(c: &mut Criterion) {
    let mut g = c.benchmark_group("textual_merge_clean");
    for &(label, lines) in &[("1KiB", 50usize), ("10KiB", 500), ("100KiB", 5000)] {
        let base = make_doc(lines, 12);
        let ours = mutate_disjoint(&base, 20, 0, '!');
        let theirs = mutate_disjoint(&base, 20, 7, '?');
        let total_bytes = (base.len() + ours.len() + theirs.len()) as u64;
        g.throughput(Throughput::Bytes(total_bytes));
        g.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(base, ours, theirs),
            |b, (base, ours, theirs)| {
                b.iter(|| black_box(three_way_merge_lines(base, ours, theirs)))
            },
        );
    }
    g.finish();
}

fn bench_conflicting_merge(c: &mut Criterion) {
    let mut g = c.benchmark_group("textual_merge_conflicting");
    for &(label, lines) in &[("1KiB", 50usize), ("10KiB", 500), ("100KiB", 5000)] {
        let base = make_doc(lines, 12);
        let ours = mutate_conflicting(&base, 20, "OURS-EDIT");
        let theirs = mutate_conflicting(&base, 20, "THEIRS-EDIT");
        let total_bytes = (base.len() + ours.len() + theirs.len()) as u64;
        g.throughput(Throughput::Bytes(total_bytes));
        g.bench_with_input(
            BenchmarkId::from_parameter(label),
            &(base, ours, theirs),
            |b, (base, ours, theirs)| {
                b.iter(|| black_box(three_way_merge_lines(base, ours, theirs)))
            },
        );
    }
    g.finish();
}

criterion_group!(benches, bench_clean_merge, bench_conflicting_merge);
criterion_main!(benches);
