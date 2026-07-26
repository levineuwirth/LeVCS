//! Scope 4-A2 acceptance: recovery step 3, checkpoint selection and the
//! offline-rebuild decision.
//!
//! "Corrupt checkpoint (one generation, then all)" is two dedicated tests, not
//! one parameterized test, because the two have different *correct* answers:
//! one generation corrupt must fall back and open normally; all generations
//! corrupt must enter explicit offline rebuild and must NOT open by replaying
//! from sequence zero.

use levcs_store::checkpoint::{
    install, list_generations, prune, Checkpoint, CheckpointError, CheckpointLoad, ReceiptRecord,
};
use levcs_store::index::{
    NamespaceCatalog, NamespaceLifecycle, NamespaceRecord, NamespaceStorageMode,
};
use levcs_store::recovery::{checkpoint_for_recovery, load_checkpoint, ShardRecoveryReport};
use levcs_store::types::{DurabilityCounters, NamespaceId, OperationId};

use levcs_core::ObjectId;

const ROOT: [u8; 16] = [0x11; 16];
const SHARD: u16 = 1;

fn ns(b: u8) -> NamespaceId {
    NamespaceId([b; 32])
}

fn oid(b: u8) -> ObjectId {
    ObjectId([b; 32])
}

fn checkpoint(sequence: u64) -> Checkpoint {
    let mut catalog = NamespaceCatalog::new();
    catalog
        .bind(NamespaceRecord {
            namespace: ns(1),
            genesis_authority: oid(0xA0),
            current_authority: oid(0xA1),
            lifecycle: NamespaceLifecycle::Active,
            storage_mode: NamespaceStorageMode::Full,
            repo_sequence: sequence,
            previous_event_digest: oid(0xB0),
        })
        .expect("bind");
    Checkpoint {
        root_uuid: ROOT,
        shard_index: SHARD,
        shard_committed_sequence: sequence,
        active_journal_id: [0x22; 16],
        active_journal_offset: 512,
        created_at_micros: 1_700_000_000_000_000,
        catalog,
        refs: Vec::new(),
        receipts: vec![ReceiptRecord {
            namespace: ns(1),
            operation_id: OperationId([sequence as u8; 16]),
            operation_digest: oid(0xC0),
            repo_sequence: sequence,
            shard_sequence: sequence,
            current_authority: oid(0xA1),
            objects_new: 1,
            retry_until_micros: 1_700_000_900_000_000,
            first_receipt_visibility_micros: Some(1_700_000_000_100_000),
            receipt_visible_until_micros: 1_700_000_900_000_000,
        }],
    }
}

fn install_generations(dir: &std::path::Path, sequences: &[u64]) {
    let counters = DurabilityCounters::default();
    for sequence in sequences {
        install(dir, &checkpoint(*sequence), &counters).expect("install");
    }
}

fn damage(dir: &std::path::Path, sequence: u64) {
    let path = dir.join(format!("{sequence}.checkpoint"));
    let mut bytes = std::fs::read(&path).expect("read");
    let at = bytes.len() / 2;
    bytes[at] ^= 0xFF;
    std::fs::write(&path, bytes).expect("write");
}

// ===========================================================================
// One corrupt generation
// ===========================================================================

#[test]
fn one_corrupt_checkpoint_generation_falls_back_to_the_next() {
    let dir = tempfile::tempdir().expect("tempdir");
    install_generations(dir.path(), &[10, 20]);
    damage(dir.path(), 20);

    match load_checkpoint(dir.path(), &ROOT, SHARD, 2).expect("load") {
        CheckpointLoad::Loaded {
            checkpoint,
            rejected,
            ..
        } => {
            assert_eq!(checkpoint.shard_committed_sequence, 10);
            assert_eq!(rejected.len(), 1);
            assert_eq!(rejected[0].1, CheckpointError::BodyDigest);
        }
        CheckpointLoad::Empty => panic!("a directory with two generations is not empty"),
        CheckpointLoad::OfflineRebuildRequired { .. } => {
            panic!("one surviving generation is exactly what checkpoint_retain >= 2 buys")
        }
    }
}

#[test]
fn a_fallback_generation_keeps_recovery_ready_and_out_of_rebuild_mode() {
    let dir = tempfile::tempdir().expect("tempdir");
    install_generations(dir.path(), &[10, 20]);
    damage(dir.path(), 20);

    let mut report = ShardRecoveryReport::new(SHARD);
    let load = load_checkpoint(dir.path(), &ROOT, SHARD, 2).expect("load");
    let restored = checkpoint_for_recovery(load, &ROOT, SHARD, &mut report).expect("restored");

    assert_eq!(restored.shard_committed_sequence, 10);
    assert_eq!(report.checkpoint_sequence, Some(10));
    assert!(!report.offline_rebuild_required);
    assert_eq!(
        restored.active_journal_offset, 512,
        "the restored checkpoint must carry the offset replay resumes from"
    );
}

// ===========================================================================
// All generations corrupt
// ===========================================================================

#[test]
fn all_corrupt_checkpoint_generations_enter_explicit_offline_rebuild() {
    let dir = tempfile::tempdir().expect("tempdir");
    install_generations(dir.path(), &[10, 20]);
    damage(dir.path(), 10);
    damage(dir.path(), 20);

    match load_checkpoint(dir.path(), &ROOT, SHARD, 2).expect("load") {
        CheckpointLoad::OfflineRebuildRequired { rejected } => {
            assert_eq!(rejected.len(), 2);
            for (_, cause) in rejected {
                assert_eq!(cause, CheckpointError::BodyDigest);
            }
        }
        CheckpointLoad::Empty => panic!(
            "two corrupt generations must not be reported as an empty directory; \
             that would license a replay from sequence zero"
        ),
        CheckpointLoad::Loaded { .. } => panic!("no generation validates"),
    }
}

#[test]
fn offline_rebuild_leaves_the_shard_not_ready_and_supplies_no_checkpoint() {
    let dir = tempfile::tempdir().expect("tempdir");
    install_generations(dir.path(), &[10, 20]);
    damage(dir.path(), 10);
    damage(dir.path(), 20);

    let mut report = ShardRecoveryReport::new(SHARD);
    let load = load_checkpoint(dir.path(), &ROOT, SHARD, 2).expect("load");
    let restored = checkpoint_for_recovery(load, &ROOT, SHARD, &mut report);

    assert!(
        restored.is_none(),
        "offline rebuild must not hand back a usable checkpoint"
    );
    assert!(report.offline_rebuild_required);
    assert!(
        !report.ready,
        "scope 3.8 step 12: readiness stays false until replay and catalog \
         validation complete"
    );
}

#[test]
fn an_empty_checkpoint_directory_is_a_fresh_shard_not_a_rebuild() {
    let dir = tempfile::tempdir().expect("tempdir");
    assert_eq!(
        load_checkpoint(dir.path(), &ROOT, SHARD, 2).expect("load"),
        CheckpointLoad::Empty
    );

    let mut report = ShardRecoveryReport::new(SHARD);
    let restored = checkpoint_for_recovery(CheckpointLoad::Empty, &ROOT, SHARD, &mut report)
        .expect("a fresh shard is healthy");
    assert_eq!(restored.shard_committed_sequence, 0);
    assert!(!report.offline_rebuild_required);
}

// ===========================================================================
// Retention and installation
// ===========================================================================

#[test]
fn at_least_checkpoint_retain_generations_survive_a_prune() {
    let dir = tempfile::tempdir().expect("tempdir");
    let counters = DurabilityCounters::default();
    install_generations(dir.path(), &[1, 2, 3, 4, 5]);

    prune(dir.path(), 2, &counters).expect("prune");
    let remaining = list_generations(dir.path()).expect("list");
    assert_eq!(
        remaining.iter().map(|(g, _)| *g).collect::<Vec<_>>(),
        vec![5, 4],
        "the retention floor is what makes one corrupt generation survivable"
    );

    // And the floor still holds after the survivor set is damaged: two
    // generations remain, so one corruption still falls back.
    damage(dir.path(), 5);
    match load_checkpoint(dir.path(), &ROOT, SHARD, 2).expect("load") {
        CheckpointLoad::Loaded { checkpoint, .. } => {
            assert_eq!(checkpoint.shard_committed_sequence, 4)
        }
        CheckpointLoad::Empty | CheckpointLoad::OfflineRebuildRequired { .. } => {
            panic!("the retained predecessor must still be reachable")
        }
    }
}

#[test]
fn installing_a_generation_fences_the_file_and_syncs_the_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let counters = DurabilityCounters::default();
    install(dir.path(), &checkpoint(7), &counters).expect("install");

    let observed = counters.snapshot();
    assert_eq!(
        observed.fdatasync, 1,
        "exactly one fence per installed generation"
    );
    assert_eq!(observed.fsync_dir, 1, "the new name must be made durable");
    assert!(
        !dir.path().join("7.checkpoint.tmp").exists(),
        "the temporary must not be left under a name a reader could find"
    );
}

/// The body itself must be visible to the counters, not just the fence.
///
/// Review found `install` calling `File::write_all` directly, so every
/// checkpoint byte and every short write bypassed `DurabilityCounters` and the
/// write-fault seam could not reach this path at all. Counting the bytes is the
/// observable form of "the write goes through the funnel"; the fault campaign
/// that it unlocks lives in `recovery_checkpoint_faults.rs`.
#[test]
fn installing_a_generation_counts_its_bytes_through_the_durability_funnel() {
    let dir = tempfile::tempdir().expect("tempdir");
    let counters = DurabilityCounters::default();
    let generation = checkpoint(7);
    let encoded_len = generation.encode().expect("encode").len() as u64;

    install(dir.path(), &generation, &counters).expect("install");

    let observed = counters.snapshot();
    assert_eq!(
        observed.bytes_written, encoded_len,
        "every checkpoint byte must pass through sys::write_vectored_all"
    );
    assert_eq!(observed.fdatasync, 1);
    assert!(observed.write_vectored >= 1);
    assert_eq!(observed.short_writes, 0);
}

#[test]
fn a_partially_written_generation_is_never_visible_under_its_final_name() {
    // The install order is: write temp, fence, rename_noreplace, fsync_dir. A
    // crash before the rename leaves the temporary, which is not a candidate.
    let dir = tempfile::tempdir().expect("tempdir");
    let counters = DurabilityCounters::default();
    install_generations(dir.path(), &[10]);
    std::fs::write(dir.path().join("20.checkpoint.tmp"), b"half written")
        .expect("simulate a crash between the write and the rename");

    assert_eq!(
        list_generations(dir.path())
            .expect("list")
            .iter()
            .map(|(g, _)| *g)
            .collect::<Vec<_>>(),
        vec![10]
    );
    match load_checkpoint(dir.path(), &ROOT, SHARD, 2).expect("load") {
        CheckpointLoad::Loaded { checkpoint, .. } => {
            assert_eq!(checkpoint.shard_committed_sequence, 10)
        }
        CheckpointLoad::Empty | CheckpointLoad::OfflineRebuildRequired { .. } => {
            panic!("the completed generation must still load")
        }
    }
    let _ = counters;
}

#[test]
fn a_checkpoint_from_another_shard_is_refused_rather_than_adopted() {
    let dir = tempfile::tempdir().expect("tempdir");
    install_generations(dir.path(), &[10]);

    match load_checkpoint(dir.path(), &ROOT, SHARD + 1, 2).expect("load") {
        CheckpointLoad::OfflineRebuildRequired { rejected } => assert_eq!(
            rejected[0].1,
            CheckpointError::ShardIndex {
                expected: SHARD + 1,
                found: SHARD,
            }
        ),
        CheckpointLoad::Empty | CheckpointLoad::Loaded { .. } => panic!(
            "a shard must not adopt another shard's derived state; per-repository \
             sequence ownership depends on the assignment never moving"
        ),
    }
}
