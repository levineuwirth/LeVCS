//! Scope 4-A2 acceptance: `root_uuid` and `journal_id` binding.
//!
//! Scope 3.1 makes `root_uuid` bind every `CURRENT`, manifest, journal,
//! segment, index run, and checkpoint in the root, so a file copied in from
//! another instance is rejected. That claim is only worth anything if it is
//! checked at *every* one of those readers, so there is a test per reader here
//! rather than one test on the type that carries the field.

#[path = "recovery_reference_frame.rs"]
mod reference;

use levcs_core::ObjectId;
use levcs_store::checkpoint::{Checkpoint, CheckpointError};
use levcs_store::format::JournalHeader;
use levcs_store::index::{
    IndexDelta, IndexError, IndexKey, IndexLocation, IndexRun, IndexRunBuilder,
};
use levcs_store::recovery::{validate_journal_binding, JournalBindingFault};
use levcs_store::types::NamespaceId;

use reference::{JOURNAL_ID, ROOT_UUID};

const FOREIGN: [u8; 16] = [0xEE; 16];

fn header() -> JournalHeader {
    JournalHeader {
        shard_index: 3,
        root_uuid: ROOT_UUID,
        journal_id: JOURNAL_ID,
        first_shard_sequence: 100,
        preallocated_len: 1 << 20,
        created_at_micros: 1,
    }
}

// ===========================================================================
// The journal
// ===========================================================================

#[test]
fn a_matching_journal_binds() {
    validate_journal_binding(&header(), &ROOT_UUID, 3, Some(&JOURNAL_ID), Some(99))
        .expect("a journal that belongs here must bind");
}

#[test]
fn a_journal_carrying_the_wrong_root_uuid_is_refused() {
    match validate_journal_binding(&header(), &FOREIGN, 3, Some(&JOURNAL_ID), None) {
        Err(JournalBindingFault::RootUuidMismatch { expected, found }) => {
            assert_eq!(expected, hex::encode(FOREIGN));
            assert_eq!(found, hex::encode(ROOT_UUID));
        }
        Err(other) => panic!("expected a root_uuid fault, got {other:?}"),
        Ok(()) => panic!(
            "root_uuid is what catches a journal copied in from another instance; \
             accepting it would let one root's frames be replayed into another"
        ),
    }
}

#[test]
fn a_journal_carrying_the_wrong_journal_id_is_refused() {
    match validate_journal_binding(&header(), &ROOT_UUID, 3, Some(&FOREIGN), None) {
        Err(JournalBindingFault::JournalIdMismatch { .. }) => {}
        Err(other) => panic!("expected a journal_id fault, got {other:?}"),
        Ok(()) => panic!("a journal misfiled under another name must not be adopted"),
    }
}

#[test]
fn a_journal_belonging_to_another_shard_is_refused() {
    match validate_journal_binding(&header(), &ROOT_UUID, 4, Some(&JOURNAL_ID), None) {
        Err(JournalBindingFault::ShardIndexMismatch { expected, found }) => {
            assert_eq!(expected, 4);
            assert_eq!(found, 3);
        }
        Err(other) => panic!("expected a shard fault, got {other:?}"),
        Ok(()) => panic!(
            "per-repository sequence ownership is only sound while a repository's \
             shard assignment never moves"
        ),
    }
}

#[test]
fn a_journal_starting_above_the_checkpointed_sequence_is_a_hole_not_a_fresh_start() {
    match validate_journal_binding(&header(), &ROOT_UUID, 3, Some(&JOURNAL_ID), Some(50)) {
        Err(JournalBindingFault::SequenceHole { first, committed }) => {
            assert_eq!(first, 100);
            assert_eq!(committed, 50);
        }
        Err(other) => panic!("expected a sequence hole, got {other:?}"),
        Ok(()) => panic!("frames 51..99 are missing and recovery must say so"),
    }
}

#[test]
fn a_journal_starting_exactly_after_the_checkpoint_binds() {
    validate_journal_binding(&header(), &ROOT_UUID, 3, Some(&JOURNAL_ID), Some(99))
        .expect("first_shard_sequence == committed + 1 is the healthy boundary");
}

// ===========================================================================
// The checkpoint
// ===========================================================================

#[test]
fn a_checkpoint_carrying_the_wrong_root_uuid_is_refused() {
    let mut checkpoint = Checkpoint::empty(ROOT_UUID, 0);
    checkpoint.shard_committed_sequence = 5;
    let bytes = checkpoint.encode().expect("encode");
    assert_eq!(
        Checkpoint::decode(&bytes, &FOREIGN, 0).unwrap_err(),
        CheckpointError::RootUuid
    );
    Checkpoint::decode(&bytes, &ROOT_UUID, 0).expect("its own root must accept it");
}

// ===========================================================================
// The index run
// ===========================================================================

#[test]
fn an_index_run_carrying_the_wrong_root_uuid_is_refused() {
    let mut delta = IndexDelta::new(16, 1 << 16);
    delta
        .insert(
            IndexKey::new(NamespaceId([1u8; 32]), ObjectId([2u8; 32])),
            IndexLocation {
                segment_generation: 1,
                frame_offset: 512,
                frame_len: 224,
                object_type: 1,
                shard_sequence: 1,
            },
        )
        .expect("insert");
    let bytes = IndexRunBuilder::new(ROOT_UUID, 1, 9)
        .build(&delta)
        .expect("build");

    assert_eq!(
        IndexRun::from_vec(bytes.clone(), &FOREIGN).unwrap_err(),
        IndexError::RootUuid
    );
    IndexRun::from_vec(bytes, &ROOT_UUID).expect("its own root must accept it");
}

// ===========================================================================
// The manifest and CURRENT — covered in recovery_manifest.rs, cross-checked
// here so the "every reader" claim is visible in one place.
// ===========================================================================

#[test]
fn every_root_bound_reader_rejects_a_foreign_root() {
    use levcs_store::recovery::{
        resolve_manifest, ManifestFallbackReason, ManifestSource, PresenceAndLengthValidator,
    };
    use reference::{manifest, ShardDir};

    let shard = ShardDir::new();
    shard.write_placeholder_segment("4-0-9.seg", 4096);
    shard.write_manifest(&manifest(4, "4-0-9.seg"));
    shard.write_current(4, FOREIGN);

    let selection = resolve_manifest(
        &shard.paths,
        &ROOT_UUID,
        &PresenceAndLengthValidator::default(),
        8,
    )
    .expect("resolution")
    .expect("the manifest itself belongs here");
    assert_eq!(
        selection.source,
        ManifestSource::Fallback {
            reason: ManifestFallbackReason::CurrentRootUuidMismatch
        }
    );
}
