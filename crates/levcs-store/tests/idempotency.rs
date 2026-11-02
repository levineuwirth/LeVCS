//! Scope 6-B1 deliverable 7 — resubmitting an operation that already committed.
//!
//! A retry is the normal case, not an error. A client that submitted, lost the
//! connection, and submitted again must be told what happened the first time
//! rather than either appending a second frame or being refused. The operation
//! ID is the identity that makes that answerable, and the stable digest is what
//! makes the answer safe: the same ID over the same digest is the same request,
//! and the same ID over a *different* digest is two different requests claiming
//! one identity, which is the case that must be refused.
//!
//! Asserted against `oracle::coalescing_decision`, which is the frozen
//! statement of that rule, rather than against a second copy of it written
//! here. The oracle is fed the same three inputs the store has -- the durable
//! status, the in-flight digest, and the incoming digest -- and the store's
//! answer must be the one it names.

#![cfg(all(
    feature = "store-privileged",
    feature = "store-internals",
    feature = "failpoints"
))]

use levcs_core::{ObjectId, ObjectType};
use levcs_protocol::oracle::{coalescing_decision, CoalescingDecision};
use levcs_protocol::v2::TransactionStatusV1;
use levcs_store::transaction::StagedObject;
use levcs_store::types::{NamespaceId, OperationId, PrivilegedConstruction, StoreError};
use levcs_store::ValidatedTransaction;

#[path = "support/engine_matrix.rs"]
mod engine_matrix;

use engine_matrix::{
    create_transaction, deadline, evidence, genesis_id, namespace_on_shard, open_absent_root,
    reopen_after_close, submit, DEFAULT_MAX_INDEX_RUNS,
};

const SHARD_COUNT: u16 = 1;
const OPERATION: u8 = 0x40;

/// One transaction, parameterized by the payload that determines its stable
/// digest, so the same operation ID can be resubmitted with the same digest or
/// a different one.
fn transaction(namespace: NamespaceId, digest_seed: u8, blob: u8) -> ValidatedTransaction {
    let authority = genesis_id(&namespace);
    ValidatedTransaction::builder(PrivilegedConstruction::assert_validated())
        .namespace(namespace)
        .operation(
            OperationId([OPERATION; 16]),
            ObjectId([digest_seed; 32]),
            deadline(),
        )
        .objects(vec![StagedObject {
            id: ObjectId([blob; 32]),
            object_type: ObjectType::Blob,
            raw: vec![blob; 64],
        }])
        .refs(Vec::new())
        .authority(Some(authority), Some(authority))
        .evidence(evidence())
        .build()
        .expect("a complete transaction")
}

/// The durable status the oracle is asked about, built from the receipt the
/// store actually produced. Only `operation_digest` participates in the
/// decision; the rest is carried so the value is a real status rather than a
/// shape that happens to satisfy one accessor.
fn durable_status(
    receipt: &levcs_store::types::CommitReceipt,
    digest: ObjectId,
) -> TransactionStatusV1 {
    TransactionStatusV1::Committed(levcs_protocol::v2::CommitReceiptV1 {
        operation_id: *receipt.operation_id.as_bytes(),
        operation_digest: digest,
        repo_sequence: receipt.repo_sequence,
        current_authority: receipt.current_authority,
        refs: Vec::new(),
        objects_new: receipt.objects_new,
        retry_until_micros: 0,
        first_visible_at_micros: 0,
        receipt_visible_until_micros: 0,
    })
}

#[test]
fn a_resubmitted_operation_returns_its_durable_receipt() {
    let directory = tempfile::TempDir::new().expect("a temporary root");
    let namespace = namespace_on_shard(0, SHARD_COUNT, 1);
    let engine = open_absent_root(directory.path(), SHARD_COUNT, DEFAULT_MAX_INDEX_RUNS);
    submit(&engine, create_transaction(namespace, 1))
        .receipt()
        .expect("the repository is created");

    let first = submit(&engine, transaction(namespace, 0xd1, 0xb1));
    let first = first
        .receipt()
        .unwrap_or_else(|| panic!("the first submit must commit: {:?}", first.error()))
        .clone();

    // The oracle's answer for these inputs, stated before the store is asked.
    assert!(
        matches!(
            coalescing_decision(
                durable_status(&first, ObjectId([0xd1; 32])),
                None,
                ObjectId([0xd1; 32])
            ),
            CoalescingDecision::ReturnDurable(_)
        ),
        "the oracle must name this a durable return, or this test is asserting the wrong rule"
    );

    let again = submit(&engine, transaction(namespace, 0xd1, 0xb1));
    let again = again.receipt().unwrap_or_else(|| {
        panic!(
            "a same-digest resubmit must be answered: {:?}",
            again.error()
        )
    });
    assert_eq!(
        again.repo_sequence, first.repo_sequence,
        "a resubmit must return the receipt the first submit produced, not a new one; a second \
         repo_sequence means a second frame was appended for one operation"
    );
    assert_eq!(again.objects_new, first.objects_new);

    // And after a reopen, where the answer can only come from the committed
    // root recovery rebuilt.
    drop(engine);
    let reopened = reopen_after_close(directory.path(), SHARD_COUNT, DEFAULT_MAX_INDEX_RUNS);
    let recovered = submit(&reopened, transaction(namespace, 0xd1, 0xb1));
    let recovered = recovered.receipt().unwrap_or_else(|| {
        panic!(
            "a resubmit after reopen must still be answered: {:?}",
            recovered.error()
        )
    });
    assert_eq!(
        recovered.repo_sequence, first.repo_sequence,
        "the durable answer must survive recovery"
    );
}

#[test]
fn one_operation_id_with_a_second_digest_is_refused() {
    let directory = tempfile::TempDir::new().expect("a temporary root");
    let namespace = namespace_on_shard(0, SHARD_COUNT, 1);
    let engine = open_absent_root(directory.path(), SHARD_COUNT, DEFAULT_MAX_INDEX_RUNS);
    submit(&engine, create_transaction(namespace, 1))
        .receipt()
        .expect("the repository is created");

    let first = submit(&engine, transaction(namespace, 0xd1, 0xb1));
    let first = first
        .receipt()
        .unwrap_or_else(|| panic!("the first submit must commit: {:?}", first.error()))
        .clone();

    assert!(
        matches!(
            coalescing_decision(
                durable_status(&first, ObjectId([0xd1; 32])),
                None,
                ObjectId([0xd2; 32])
            ),
            CoalescingDecision::OperationIdMismatch
        ),
        "the oracle must name this a mismatch, or this test is asserting the wrong rule"
    );

    // Same operation ID, different stable digest: two different requests
    // claiming one identity. Returning the first receipt would tell the caller
    // its transaction committed when a different one did.
    let conflicting = submit(&engine, transaction(namespace, 0xd2, 0xb2));
    match conflicting.error() {
        Some(StoreError::Conflict(message)) => assert!(
            message.contains("digest"),
            "the refusal must say what disagreed: {message}"
        ),
        other => panic!("a same-ID/different-digest resubmit must be refused, got {other:?}"),
    }

    // The refusal is about identity, not about the shard: an unrelated
    // operation still commits.
    let unrelated = submit(&engine, {
        let authority = genesis_id(&namespace);
        ValidatedTransaction::builder(PrivilegedConstruction::assert_validated())
            .namespace(namespace)
            .operation(OperationId([0x77; 16]), ObjectId([0x77; 32]), deadline())
            .objects(vec![StagedObject {
                id: ObjectId([0x77; 32]),
                object_type: ObjectType::Blob,
                raw: vec![0x77; 64],
            }])
            .refs(Vec::new())
            .authority(Some(authority), Some(authority))
            .evidence(evidence())
            .build()
            .expect("a complete transaction")
    });
    unrelated.receipt().unwrap_or_else(|| {
        panic!(
            "an unrelated operation must commit: {:?}",
            unrelated.error()
        )
    });
}

/// A same-digest resubmit that arrives while the first is still in flight.
///
/// The durable path above cannot answer this one: nothing is committed yet, so
/// there is no receipt to return and no terminal entry to read. The second
/// submit has to attach to the first and receive whatever the first receives —
/// one frame, one sequence, two callers answered.
///
/// The leader is held in flight by a group that will not close on its own: the
/// transaction ceiling is high and the idle delay long, so the writer accepts
/// the leader and waits. The follower is submitted from this thread while the
/// leader's own submit is still blocked, which is the only arrangement where
/// `StatusReservation::Attached` is reachable at all.
#[test]
fn a_same_digest_resubmit_attaches_to_an_in_flight_leader() {
    let directory = tempfile::TempDir::new().expect("a temporary root");
    let namespace = namespace_on_shard(0, SHARD_COUNT, 1);

    let mut options = engine_matrix::options_with_index_runs(
        directory.path(),
        SHARD_COUNT,
        DEFAULT_MAX_INDEX_RUNS,
    );
    // Wide enough that the leader's group stays open until the follower has
    // been accepted, and short enough that the test does not depend on the
    // wall clock for correctness -- only for how long it waits.
    options.max_group_transactions = 8;
    options.max_group_idle = std::time::Duration::from_millis(250);

    // Held for the whole test though nothing is armed here. The failpoint
    // registry is a one-shot global, so a sibling test that arms one would
    // otherwise fire it inside this engine and take the leader down -- which is
    // a different test's property and this test's spurious failure.
    let _serial = engine_matrix::serial();

    let engine = levcs_store::StoreEngine::open(options).expect("the root initializes");
    submit(&engine, create_transaction(namespace, 1))
        .receipt()
        .expect("the repository is created");

    let (leader, follower) = std::thread::scope(|scope| {
        let leading = scope.spawn(|| submit(&engine, transaction(namespace, 0xd1, 0xb1)));
        // The leader has to be accepted before the follower is submitted, or
        // the follower becomes the leader and the test asserts nothing.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let follower = submit(&engine, transaction(namespace, 0xd1, 0xb1));
        (leading.join().expect("the leader's thread"), follower)
    });

    let leader = leader
        .receipt()
        .unwrap_or_else(|| panic!("the leader must commit: {:?}", leader.error()))
        .clone();
    let follower = follower
        .receipt()
        .unwrap_or_else(|| panic!("the follower must be answered: {:?}", follower.error()));

    assert_eq!(
        follower.repo_sequence, leader.repo_sequence,
        "a follower must receive the leader's outcome; a second repo_sequence means the store \
         appended a second frame for one operation"
    );
    assert_eq!(follower.objects_new, leader.objects_new);
}

/// A follower is answered when its leader fails, not only when it commits.
///
/// This is the half of coalescing that is easy to get wrong and impossible to
/// notice: a follower whose completion is never resolved does not fail, it
/// *hangs*, with no receipt and no error. There are eight places a waiter is
/// resolved and only one of them is the happy path, so the property worth
/// asserting is that a leader taken down inside the poison window takes its
/// followers' answers with it.
///
/// `AfterMarkedResolving` is armed to fail, which poisons the shard during
/// publication -- after the follower has attached and before any receipt
/// exists.
#[test]
fn a_follower_is_answered_when_its_leader_is_poisoned() {
    let directory = tempfile::TempDir::new().expect("a temporary root");
    let namespace = namespace_on_shard(0, SHARD_COUNT, 1);

    let mut options = engine_matrix::options_with_index_runs(
        directory.path(),
        SHARD_COUNT,
        DEFAULT_MAX_INDEX_RUNS,
    );
    options.max_group_transactions = 8;
    options.max_group_idle = std::time::Duration::from_millis(250);

    let engine = levcs_store::StoreEngine::open(options).expect("the root initializes");
    submit(&engine, create_transaction(namespace, 1))
        .receipt()
        .expect("the repository is created");

    let serial = engine_matrix::serial();
    engine_matrix::arm(
        &serial,
        levcs_store::failpoints::Failpoint::AfterMarkedResolving,
        engine_matrix::action_from_name("fail").expect("the fail action"),
    );

    let (leader, follower) = std::thread::scope(|scope| {
        let leading = scope.spawn(|| submit(&engine, transaction(namespace, 0xd1, 0xb1)));
        std::thread::sleep(std::time::Duration::from_millis(50));
        let follower = submit(&engine, transaction(namespace, 0xd1, 0xb1));
        (leading.join().expect("the leader's thread"), follower)
    });
    engine_matrix::disarm(&serial);

    assert!(
        leader.receipt().is_none(),
        "the armed failpoint must take the leader down, or this asserts nothing"
    );
    // The specific error matters less than its existence: what must not happen
    // is the follower waiting forever on a leader that is never going to
    // resolve it.
    assert!(
        follower.error().is_some(),
        "the follower must be told its leader failed; a follower with neither receipt nor \
         error is a hung request, which is the outcome this coalescing exists not to create"
    );
}
