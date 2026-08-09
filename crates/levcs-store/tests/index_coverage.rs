//! Index coverage is a property of *publications*, not of index entries.
//!
//! A delta layer's `through_shard_sequence` states that every frame from its
//! shard through that sequence is accounted for in the index. Checkpointing
//! reads those stamps to decide whether pruning the journal would strand
//! objects, so a committed sequence that no layer reaches is indistinguishable
//! from a gap — the index simply does not reach that far.
//!
//! A group that introduces no objects has nothing to put in a layer and still
//! advances the committed sequence. Skipping its layer, on the reasonable-looking
//! grounds that an empty delta is not worth installing, left exactly that gap:
//! the shard could never checkpoint again, and the error said objects would be
//! dropped when there were none. An empty layer is the smallest honest way to
//! record that the sequence happened and carried nothing.
//!
//! This is asserted with a plain object-less transaction rather than through the
//! path that found it. An adopting transaction reaches the same state — its
//! frame carries a descriptor rather than object bytes — but it reaches it for a
//! reason specific to projections, and a regression that only fails when staging
//! is involved would not name what actually broke.

#![cfg(all(
    feature = "store-privileged",
    feature = "store-internals",
    feature = "failpoints"
))]

use levcs_core::ObjectId;
use levcs_store::types::{NamespaceId, OperationId, PrivilegedConstruction};
use levcs_store::ValidatedTransaction;

#[path = "support/engine_matrix.rs"]
mod engine_matrix;

use engine_matrix::{
    create_transaction, deadline, evidence, genesis_id, namespace_on_shard, open_absent_root,
    reopen_after_close, submit, DEFAULT_MAX_INDEX_RUNS,
};

const SHARD_COUNT: u16 = 2;

/// Authority-only: it moves the repository's state forward and introduces no
/// object, so its frame contributes nothing to the index.
fn objectless_transaction(namespace: NamespaceId, operation: u8) -> ValidatedTransaction {
    let authority = genesis_id(&namespace);
    ValidatedTransaction::builder(PrivilegedConstruction::assert_validated())
        .namespace(namespace)
        .operation(
            OperationId([operation; 16]),
            ObjectId([operation; 32]),
            deadline(),
        )
        .objects(Vec::new())
        .refs(Vec::new())
        .authority(Some(authority), Some(authority))
        .evidence(evidence())
        .build()
        .expect("an object-less transaction is complete")
}

#[test]
fn a_transaction_introducing_no_objects_still_lets_the_shard_checkpoint_and_reopen() {
    let directory = tempfile::TempDir::new().expect("a temporary root");
    let namespace = namespace_on_shard(0, SHARD_COUNT, 1);

    {
        let engine = open_absent_root(directory.path(), SHARD_COUNT, DEFAULT_MAX_INDEX_RUNS);

        // Sequence 0 carries the genesis authority object, so it stamps a layer
        // with an entry. Without it the shard would have no coverage at all and
        // the check under test would be skipped rather than exercised.
        let created = submit(&engine, create_transaction(namespace, 1));
        created
            .receipt()
            .unwrap_or_else(|| panic!("the repository must be created: {:?}", created.error()));

        // Sequence 1 carries nothing. This is the frame whose coverage had no
        // representation.
        let empty = submit(&engine, objectless_transaction(namespace, 2));
        empty.receipt().unwrap_or_else(|| {
            panic!(
                "an object-less transaction must commit: {:?}",
                empty.error()
            )
        });

        engine.checkpoint().unwrap_or_else(|error| {
            panic!(
                "the shard must checkpoint through a sequence that introduced no objects, but: \
                 {error:?}"
            )
        });
    }

    // Through production recovery, because the checkpoint above is only correct
    // if what it wrote can be opened. A run sealed from the empty layer holds
    // fewer entries than the sequences it covers, and a reopen is what proves
    // that is a shape this store reads back rather than one it only writes.
    let reopened = reopen_after_close(directory.path(), SHARD_COUNT, DEFAULT_MAX_INDEX_RUNS);
    let snapshot = reopened
        .snapshot(namespace)
        .expect("the repository survives");
    assert!(
        snapshot
            .locate(genesis_id(&namespace))
            .expect("locate")
            .is_some(),
        "the genesis authority object must still be findable after checkpoint and reopen; if the \
         empty layer sealed away the entries beside it, this is where that shows"
    );
    assert_eq!(
        snapshot.current_authority(),
        genesis_id(&namespace),
        "the object-less transaction's own effect must survive the round trip too — it is the \
         frame whose coverage was missing, so a checkpoint that lost it would look like success"
    );
}
