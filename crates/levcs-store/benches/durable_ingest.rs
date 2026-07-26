//! P1-micro durable-ingest benchmark over `drive.rs`.
//!
//! **Owned by A3 StoreHarness** (scope 2.1, 4-A3 deliverable 6).
//!
//! Diagnostic gate only: plan §3 P1 is "no unexplained >10% same-host
//! regression", and a storage primitive result can never be promoted to an
//! instance throughput claim. Nothing here produces a
//! `bench/result-schema.json` bundle; that is `store-bench`'s job and it is a
//! P2 artifact.
//!
//! # What is actually being measured
//!
//! The append-and-fence path of scope 3.7 steps 4–6 — encode into iovecs at
//! the write cursor, `write_vectored_all` with short-write looping and cursor
//! verification, and exactly one `fdatasync` per group. Group formation,
//! sequencing, the committed-root build, and publication are deliberately out:
//! they are not in `drive.rs` and measuring them here would produce a number
//! that P2 could not reproduce.
//!
//! # Why the group sizes are what they are
//!
//! Scope 8.1: the operating point is *not* the 512-transaction ceiling. With
//! four shards and a 1 ms idle delay, 75k/s closes groups of roughly 19, so the
//! interesting region is single digits to low tens. The 512 point is included
//! because it is the ceiling `StoreOptions` permits and because plan §2's
//! append-log measurement used it, which makes it the one point comparable to
//! the pre-rewrite numbers.
//!
//! Each iteration writes to a fresh root under the system temporary directory.
//! A `tmpfs` `/tmp` would make every number meaningless — the fence would cost
//! nothing — so the harness refuses to run on one rather than reporting a
//! fantasy.

use std::path::Path;
use std::time::{Duration, Instant};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use levcs_store::drive::{ShardDrive, DRIVE_PREALLOCATE_BYTES};
use levcs_store::format::{frame_total_len, JOURNAL_HEADER_LEN};
use levcs_store::types::NamespaceId;

/// Payload size per frame. The canonical small commit is a 1,024-byte blob
/// plus a one-file tree plus a signed commit, and scope 8.1 prices the whole
/// frame at 2.5–3 KB once evidence, the signed `CommittedTransactionV1`, and
/// receipt fields are added. 2,560 bytes sits inside that band, so the
/// bytes-per-fence ratio here is comparable to P2's.
const PAYLOAD_BYTES: usize = 2560;

/// Group sizes. See the module comment for why 8/16/32 matter more than 512.
const GROUP_SIZES: &[usize] = &[1, 8, 16, 32, 128, 512];

fn payload(ordinal: u64) -> Vec<u8> {
    let mut out = vec![0u8; PAYLOAD_BYTES];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"levcs-store/durable-ingest/p1-micro/v1\0");
    hasher.update(&ordinal.to_le_bytes());
    hasher.finalize_xof().fill(&mut out);
    out
}

fn namespace() -> NamespaceId {
    let mut bytes = [0u8; 32];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"levcs-store/durable-ingest/namespace/v1\0");
    hasher.finalize_xof().fill(&mut bytes);
    NamespaceId(bytes)
}

/// Refuse to report a number measured against a filesystem that cannot lose
/// data.
///
/// Plan §10 makes the evaluator reject tmpfs, overlay, remote, and
/// non-persistent data mounts before calculating any rate. A P1 diagnostic is
/// not a gate, but a P1 number measured on tmpfs would still be used to answer
/// "did this regress", and a fence that costs nothing answers it wrongly.
fn refuse_non_persistent(path: &Path) {
    let mounts = match std::fs::read_to_string("/proc/self/mountinfo") {
        Ok(text) => text,
        Err(_) => return,
    };
    let target = path.to_string_lossy().into_owned();
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let mount_point = match fields.get(4) {
            Some(value) => *value,
            None => continue,
        };
        let filesystem = line
            .split(" - ")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .unwrap_or("unknown");
        if target.starts_with(mount_point)
            && best
                .as_ref()
                .is_none_or(|(len, _)| mount_point.len() > *len)
        {
            best = Some((mount_point.len(), filesystem.to_string()));
        }
    }
    if let Some((_, filesystem)) = best {
        assert!(
            !matches!(filesystem.as_str(), "tmpfs" | "ramfs" | "overlay"),
            "durable_ingest refuses to run on {filesystem}: a fence that costs \
             nothing produces a P1 number that cannot answer the only question \
             P1 asks. Set TMPDIR to a persistent filesystem."
        );
    }
}

fn bench_group_append(c: &mut Criterion) {
    let probe = tempfile::tempdir().expect("tempdir");
    refuse_non_persistent(probe.path());

    let namespace = namespace();
    let mut group = c.benchmark_group("durable_ingest/append_and_fence");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(10));

    for size in GROUP_SIZES {
        group.throughput(Throughput::Elements(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, size| {
            b.iter_custom(|iterations| {
                let directory = tempfile::tempdir().expect("tempdir");
                let root = directory.path().join("root");
                let mut drive = ShardDrive::create(&root, 0, 1).expect("create shard drive");

                let frame_bytes = frame_total_len(PAYLOAD_BYTES as u64);
                let group_bytes = frame_bytes * *size as u64;
                let mut journal_bytes = JOURNAL_HEADER_LEN as u64;
                let mut seals = 0u64;

                let mut ordinal = 0u64;
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    // Rotation is real work the production writer also does,
                    // but it is per-journal work, not per-group work, and
                    // including it would fold a seal-and-manifest-install into
                    // one out of every few group latencies. It is therefore
                    // excluded from the timed region and *counted*, so the
                    // exclusion is visible rather than assumed.
                    if journal_bytes + group_bytes > DRIVE_PREALLOCATE_BYTES {
                        drive.seal_and_install().expect("seal and install");
                        journal_bytes = JOURNAL_HEADER_LEN as u64;
                        seals += 1;
                    }
                    journal_bytes += group_bytes;

                    // Frame construction is setup, not the measured path: it
                    // is the one thing `drive.rs` adds over `journal.rs`, and
                    // including it would measure the seam rather than the
                    // writer.
                    let mut frames = Vec::with_capacity(*size);
                    for offset in 0..*size as u64 {
                        frames.push(
                            drive
                                .build_frame(namespace, ordinal + offset, payload(ordinal + offset))
                                .expect("build frame"),
                        );
                    }
                    ordinal += *size as u64;

                    // "One fence per group" is checked against the counters,
                    // not read out of the code (scope 5 charter item 7), and
                    // per group rather than in aggregate: an aggregate over a
                    // run that also seals would be satisfied by a writer that
                    // fenced twice for one group and not at all for another.
                    let before = drive.counters().fdatasync;
                    let started = Instant::now();
                    drive
                        .append_group_and_fence(&frames)
                        .expect("append and fence");
                    elapsed += started.elapsed();
                    let fences = drive.counters().fdatasync - before;
                    assert_eq!(
                        fences, 1,
                        "a group of {size} produced {fences} fences; the whole \
                         premise of the design is exactly one"
                    );
                }

                assert!(
                    seals * 2 < iterations || iterations < 4,
                    "{seals} untimed seals across {iterations} timed groups is \
                     enough rotation to distort the number; raise \
                     DRIVE_PREALLOCATE_BYTES or lower the group size"
                );
                elapsed
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_group_append);
criterion_main!(benches);
