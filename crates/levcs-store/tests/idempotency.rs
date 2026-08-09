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
