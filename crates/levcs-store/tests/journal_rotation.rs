//! Scope 3.4 — sealing the active journal and continuing in a fresh one.
//!
//! A journal is preallocated. When a forming group no longer fits it, the shard
//! has to seal what it has into `segments/`, install the manifest generation
//! that names it, and keep going in a new file. Until that exists the shard
//! simply stops accepting work, which is the one failure mode a store cannot
//! have: nothing about the transactions being refused is wrong, and no amount
//! of retrying makes room.
//!
//! # What this asserts beyond "the submit succeeded"
//!
//! Rotation is easy to do in a way that passes a liveness test and loses data.
//! The frames sealed into the segment are still the only copy of everything
//! committed before the rotation, and every `IndexLocation` naming them was
//! written against the *tail's* logical generation — so a rotation that
//! installs the segment under a different generation, or that fails to retain
//! it, leaves those objects indexed at a generation nothing resolves. The
//! assertions here therefore span the rotation in both directions: objects
//! written before it must still locate after it, and the whole thing must
//! survive a reopen through production recovery.
//!
//! §3.4's link-then-unlink ordering exists for the crash window in the middle
//! of that sequence. This file does not crash the process — that is the crash
//! matrix's job — but it does prove the non-crash path leaves a root recovery
//! reopens without replaying the sealed prefix twice.

#![cfg(all(
    feature = "store-privileged",
    feature = "store-internals",
    feature = "failpoints"
))]

use levcs_core::{ObjectId, ObjectType};
use levcs_store::transaction::StagedObject;
use levcs_store::types::{NamespaceId, OperationId, PrivilegedConstruction};
use levcs_store::{StoreEngine, StoreOptions, ValidatedTransaction};

#[path = "support/engine_matrix.rs"]
mod engine_matrix;

use engine_matrix::{
    create_transaction, deadline, evidence, genesis_id, namespace_on_shard, submit,
    DEFAULT_MAX_INDEX_RUNS,
};

const SHARD_COUNT: u16 = 1;
/// Small enough that a handful of transactions fills it, and still at least
/// `max_group_bytes`, which `StoreOptions::validate` requires.
const JOURNAL_BYTES: u64 = 64 * 1024;
const GROUP_BYTES: u64 = 8 * 1024;
/// Four kilobytes per transaction, so the journal fills in about a dozen
/// commits rather than a thousand.
const OBJECT_BYTES: usize = 4 * 1024;

fn options(root: &std::path::Path) -> StoreOptions {
    let mut options =
        engine_matrix::options_with_index_runs(root, SHARD_COUNT, DEFAULT_MAX_INDEX_RUNS);
    options.journal_preallocate_bytes = JOURNAL_BYTES;
    options.segment_max_bytes = JOURNAL_BYTES;
    options.max_group_bytes = GROUP_BYTES;
    options
}

fn blob_id(seed: u16) -> ObjectId {
    let mut bytes = [0u8; 32];
    bytes[..2].copy_from_slice(&seed.to_le_bytes());
    ObjectId(bytes)
}

/// A transaction carrying one sizeable object, so the journal fills quickly.
fn filling_transaction(namespace: NamespaceId, seed: u16) -> ValidatedTransaction {
    let authority = genesis_id(&namespace);
    let mut operation = [0u8; 16];
    operation[..2].copy_from_slice(&seed.to_le_bytes());
    ValidatedTransaction::builder(PrivilegedConstruction::assert_validated())
        .namespace(namespace)
        .operation(
            OperationId(operation),
            ObjectId([seed as u8; 32]),
            deadline(),
        )
        .objects(vec![StagedObject {
            id: blob_id(seed),
            object_type: ObjectType::Blob,
            raw: vec![seed as u8; OBJECT_BYTES],
        }])
        .refs(Vec::new())
        .authority(Some(authority), Some(authority))
        .evidence(evidence())
        .build()
        .expect("a complete filling transaction")
}

fn segment_count(root: &std::path::Path) -> usize {
    let segments = root.join("shards").join("00").join("segments");
    std::fs::read_dir(&segments)
        .map(|entries| entries.filter_map(Result::ok).count())
        .unwrap_or(0)
}

/// `segment_max_bytes` is a rotation trigger in its own right.
///
/// `Journal::should_rotate` names two boundaries — the preallocated length and
/// the configured segment size, whichever comes first — and only the first one
/// is a question about whether the next group *fits*. A shard that rotates
/// solely on fit runs to the end of its preallocation however small the segment
/// ceiling is, and produces segments many times the configured maximum.
///
/// The two limits are deliberately far apart here. The main test above sets
/// them equal, which is the realistic default and also the one arrangement
/// where this defect is invisible.
#[test]
fn a_segment_ceiling_below_the_preallocation_rotates_first() {
    let directory = tempfile::TempDir::new().expect("a temporary root");
    let namespace = namespace_on_shard(0, SHARD_COUNT, 1);

    let mut options = options(directory.path());
    // Room for many groups in the file, but a segment ceiling reached after a
    // handful of them.
    options.journal_preallocate_bytes = 1024 * 1024;
    options.segment_max_bytes = 24 * 1024;

    let engine = StoreEngine::open(options).expect("the root initializes");
    let created = submit(&engine, create_transaction(namespace, 1));
    created
        .receipt()
        .unwrap_or_else(|| panic!("the repository must be created: {:?}", created.error()));

    const WRITES: u16 = 24;
    for seed in 1..=WRITES {
        let outcome = submit(&engine, filling_transaction(namespace, seed));
        outcome
            .receipt()
            .unwrap_or_else(|| panic!("write {seed} must commit: {:?}", outcome.error()));
    }

    // Roughly 96 KiB written against a 24 KiB ceiling, so several segments.
    // Asserted as "more than one" rather than an exact count: a segment may
    // overshoot the ceiling by up to one group, because the boundary is checked
    // before a group is added and not in the middle of one.
    let sealed = segment_count(directory.path());
    assert!(
        sealed > 1,
        "with segment_max_bytes far below journal_preallocate_bytes the shard must seal on \
         the segment ceiling, but only {sealed} segment(s) exist after {WRITES} writes"
    );

    for seed in 1..=WRITES {
        assert!(
            engine
                .snapshot(namespace)
                .expect("snapshot")
                .locate(blob_id(seed))
                .expect("locate")
                .is_some(),
            "object {seed} must survive a segment-ceiling rotation"
        );
    }
}

/// A frame that no rotation can ever seat is a ceiling, not a rotation.
///
/// The distinction is off by exactly the journal header. A fresh journal's
/// cursor starts past its own header, so the space a rotation actually offers
/// is the preallocation *less* that header. A frame in between — small enough
/// for the preallocation, too large once the header is there — was classified
/// as rotatable, and the retry against the fresh journal failed the same test
/// again. The caller was promised `LimitExceeded` and got a second rotation
/// instead.
#[test]
fn a_frame_larger_than_a_fresh_journal_is_refused_rather_than_rotated() {
    let directory = tempfile::TempDir::new().expect("a temporary root");
    let namespace = namespace_on_shard(0, SHARD_COUNT, 1);

    // The object is sized to land in the gap: its frame fits
    // `journal_preallocate_bytes` outright but not once the header is
    // accounted for. `max_group_bytes` is raised past it so the group ceiling
    // is not what refuses first -- this must be the journal's answer.
    const PREALLOCATED: u64 = 32 * 1024;
    let mut options = options(directory.path());
    options.journal_preallocate_bytes = PREALLOCATED;
    options.segment_max_bytes = PREALLOCATED;
    options.max_group_bytes = PREALLOCATED;

    let engine = StoreEngine::open(options).expect("the root initializes");
    let created = submit(&engine, create_transaction(namespace, 1));
    created
        .receipt()
        .unwrap_or_else(|| panic!("the repository must be created: {:?}", created.error()));

    // Just under the preallocation, so the frame around it is over the usable
    // space by roughly the header.
    let oversized = ValidatedTransaction::builder(PrivilegedConstruction::assert_validated())
        .namespace(namespace)
        .operation(OperationId([0xee; 16]), ObjectId([0xee; 32]), deadline())
        .objects(vec![StagedObject {
            id: blob_id(0xeee),
            object_type: ObjectType::Blob,
            raw: vec![0xee; PREALLOCATED as usize - 768],
        }])
        .refs(Vec::new())
        .authority(Some(genesis_id(&namespace)), Some(genesis_id(&namespace)))
        .evidence(evidence())
        .build()
        .expect("the transaction itself is well formed");

    let outcome = submit(&engine, oversized);
    match outcome.error() {
        Some(levcs_store::types::StoreError::LimitExceeded {
            limit,
            observed,
            allowed,
        }) => {
            assert_eq!(
                *limit, "journal_preallocate_bytes",
                "the refusal must name the ceiling that stopped it"
            );
            // The reported ceiling is what makes this test see the off-by-one
            // rather than merely see a refusal. A frame can be far enough over
            // to be refused either way; what distinguishes the two is *which*
            // ceiling the store believes it has. A fresh journal's cursor
            // starts past its header, so the space a rotation can offer is the
            // preallocation less that header, and reporting the whole
            // preallocation means frames in the gap were called rotatable.
            assert_eq!(
                *allowed,
                PREALLOCATED - levcs_store::format::JOURNAL_HEADER_LEN as u64,
                "the ceiling must be the space a fresh journal actually offers, not the raw \
                 preallocation"
            );
            assert!(
                *observed > *allowed,
                "the refusal must report a frame that genuinely exceeds the ceiling"
            );
        }
        other => panic!(
            "a frame no fresh journal can hold must be refused as a ceiling, not retried as a \
             rotation, but submit answered {other:?}"
        ),
    }

    // And the shard is still usable: a ceiling is a refusal of one transaction,
    // not a wedged writer.
    let after = submit(&engine, filling_transaction(namespace, 1));
    after
        .receipt()
        .unwrap_or_else(|| panic!("an ordinary write must still commit: {:?}", after.error()));
}

#[test]
fn a_full_active_journal_seals_and_the_shard_keeps_committing() {
    let directory = tempfile::TempDir::new().expect("a temporary root");
    let namespace = namespace_on_shard(0, SHARD_COUNT, 1);

    // Enough transactions to overrun the preallocated journal several times
    // over, so the test exercises repeated rotation rather than one boundary.
    const WRITES: u16 = 48;

    {
        let engine = StoreEngine::open(options(directory.path())).expect("the root initializes");
        let created = submit(&engine, create_transaction(namespace, 1));
        created
            .receipt()
            .unwrap_or_else(|| panic!("the repository must be created: {:?}", created.error()));

        for seed in 1..=WRITES {
            let outcome = submit(&engine, filling_transaction(namespace, seed));
            outcome.receipt().unwrap_or_else(|| {
                panic!(
                    "write {seed} of {WRITES} must commit; the journal filling is a rotation, \
                     not a ceiling: {:?}",
                    outcome.error()
                )
            });
        }

        // Before the reopen, because a rotation that lost the segment would
        // still answer correctly from a root that has not been rebuilt yet.
        let snapshot = engine.snapshot(namespace).expect("snapshot");
        for seed in [1u16, WRITES / 2, WRITES] {
            assert!(
                snapshot.locate(blob_id(seed)).expect("locate").is_some(),
                "object {seed} was committed before a rotation and must still be located \
                 after it"
            );
        }
    }

    // Through production recovery: the sealed segments are now the only copy of
    // everything but the last journal's frames, and a reopen is what proves the
    // manifest names them.
    let reopened = StoreEngine::open(options(directory.path())).expect("the root reopens");
    let snapshot = reopened.snapshot(namespace).expect("snapshot");
    for seed in 1..=WRITES {
        assert!(
            snapshot.locate(blob_id(seed)).expect("locate").is_some(),
            "object {seed} did not survive the reopen; a sealed prefix the manifest does not \
             name is a fenced, acknowledged transaction that recovery cannot find"
        );
    }
}
