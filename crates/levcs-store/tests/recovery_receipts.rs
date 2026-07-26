//! Scope 4-A2 acceptance: recovery step 10, receipt-table reconstruction and
//! `first_receipt_visibility_micros` promotion.
//!
//! Every assertion is bound to `oracle::recovered_receipt_visibility`. The
//! store does not carry a second copy of the arithmetic; it delegates, and
//! these tests prove the delegation is faithful and that the one property the
//! oracle does *not* express — "recovery may only extend retention" — holds
//! against a checkpoint that disagrees.

use levcs_core::ObjectId;
use levcs_protocol::oracle;
use levcs_store::checkpoint::{Checkpoint, ReceiptRecord};
use levcs_store::recovery::{promote_receipt_visibility, VisibilityPromotion};
use levcs_store::types::{NamespaceId, OperationId, StoreError};

const GRACE: i64 = 900_000_000;

fn receipt(
    id: u8,
    first_visible: Option<i64>,
    retry_until: i64,
    visible_until: i64,
) -> ReceiptRecord {
    ReceiptRecord {
        namespace: NamespaceId([1u8; 32]),
        operation_id: OperationId([id; 16]),
        operation_digest: ObjectId([0xC0; 32]),
        repo_sequence: id as u64,
        shard_sequence: id as u64,
        current_authority: ObjectId([0xA1; 32]),
        objects_new: 1,
        retry_until_micros: retry_until,
        first_receipt_visibility_micros: first_visible,
        receipt_visible_until_micros: visible_until,
    }
}

// ===========================================================================
// The promotion itself
// ===========================================================================

#[test]
fn an_uncheckpointed_first_visibility_becomes_recovery_publication_time() {
    let retry_until = 1_000_000;
    let publication = 5_000_000;
    let mut receipts = [receipt(1, None, retry_until, retry_until)];

    let promotions =
        promote_receipt_visibility(&mut receipts, publication, GRACE).expect("promote");
    assert_eq!(
        promotions,
        vec![VisibilityPromotion::PromotedToRecoveryPublication]
    );

    let (expected_first, expected_until) =
        oracle::recovered_receipt_visibility(retry_until, None, publication, GRACE)
            .expect("oracle");
    assert_eq!(expected_first, publication);
    assert_eq!(
        receipts[0].first_receipt_visibility_micros,
        Some(expected_first)
    );
    assert_eq!(receipts[0].receipt_visible_until_micros, expected_until);
}

#[test]
fn a_durably_checkpointed_first_visibility_is_left_exactly_where_it_was() {
    let retry_until = 1_000_000;
    let checkpointed = 2_000_000;
    let publication = 5_000_000;
    let (_, until) =
        oracle::recovered_receipt_visibility(retry_until, Some(checkpointed), publication, GRACE)
            .expect("oracle");
    let mut receipts = [receipt(1, Some(checkpointed), retry_until, until)];

    let promotions =
        promote_receipt_visibility(&mut receipts, publication, GRACE).expect("promote");
    assert_eq!(promotions, vec![VisibilityPromotion::AlreadyDurable]);
    assert_eq!(
        receipts[0].first_receipt_visibility_micros,
        Some(checkpointed),
        "a value the checkpoint already made durable is not recovery's to move"
    );
    assert_eq!(receipts[0].receipt_visible_until_micros, until);
}

#[test]
fn promotion_extends_retention_and_never_shortens_it() {
    // The falsifying construction: a checkpoint whose stored deadline is far
    // beyond anything the recomputation would produce. If recovery simply
    // assigned the recomputed value it would shorten a live receipt's
    // visibility, which plan §4 transaction invariant 7 forbids.
    let stored_until = 4_000_000_000;
    let mut receipts = [receipt(1, None, 10, stored_until)];

    promote_receipt_visibility(&mut receipts, 20, GRACE).expect("promote");
    assert_eq!(
        receipts[0].receipt_visible_until_micros, stored_until,
        "recovery may only extend retention"
    );
}

#[test]
fn promotion_extends_retention_for_a_checkpointed_receipt_too() {
    let checkpointed = 1_000;
    let stored_until = 9_000_000_000;
    let mut receipts = [receipt(1, Some(checkpointed), 10, stored_until)];

    promote_receipt_visibility(&mut receipts, 20, GRACE).expect("promote");
    assert_eq!(
        receipts[0].first_receipt_visibility_micros,
        Some(checkpointed)
    );
    assert_eq!(receipts[0].receipt_visible_until_micros, stored_until);
}

#[test]
fn promotion_agrees_with_the_oracle_across_the_input_grid() {
    for retry_until in [0i64, 1, 1_000, 1_000_000, 1_000_000_000] {
        for checkpointed in [None, Some(0i64), Some(500_000), Some(2_000_000_000)] {
            for publication in [0i64, 1_000_000, 3_000_000_000] {
                let expected = oracle::recovered_receipt_visibility(
                    retry_until,
                    checkpointed,
                    publication,
                    GRACE,
                );
                // `i64::MIN` as the stored deadline makes the max() a no-op, so
                // the comparison is against the oracle alone.
                let mut receipts = [receipt(1, checkpointed, retry_until, i64::MIN)];
                let got = promote_receipt_visibility(&mut receipts, publication, GRACE);

                match (expected, got) {
                    (Ok((first, until)), Ok(promotions)) => {
                        assert_eq!(receipts[0].first_receipt_visibility_micros, Some(first));
                        assert_eq!(receipts[0].receipt_visible_until_micros, until);
                        assert_eq!(
                            promotions[0],
                            if checkpointed.is_some() {
                                VisibilityPromotion::AlreadyDurable
                            } else {
                                VisibilityPromotion::PromotedToRecoveryPublication
                            }
                        );
                    }
                    (Err(_), Err(StoreError::Corruption(_))) => {}
                    (Ok(_), Err(e)) => panic!(
                        "the oracle accepted ({retry_until}, {checkpointed:?}, \
                         {publication}) and the store refused it: {e:?}"
                    ),
                    (Err(e), Ok(_)) => panic!(
                        "the oracle refused ({retry_until}, {checkpointed:?}, \
                         {publication}) and the store accepted it: {e:?}"
                    ),
                    (Err(_), Err(e)) => panic!(
                        "the store must report a refused visibility computation as \
                         Corruption, got {e:?}"
                    ),
                }
            }
        }
    }
}

#[test]
fn an_overflowing_retention_sum_is_refused_rather_than_wrapped() {
    // `receipt_visible_until` is a checked addition in the frozen protocol; a
    // store that wrapped it would silently expire a receipt immediately.
    let mut receipts = [receipt(1, None, i64::MAX, 0)];
    let result = promote_receipt_visibility(&mut receipts, i64::MAX, GRACE);
    match result {
        Err(StoreError::Corruption(message)) => {
            assert!(message.contains(&OperationId([1u8; 16]).to_hex()))
        }
        Err(other) => panic!("expected Corruption, got {other:?}"),
        Ok(_) => {
            // Only acceptable if the oracle itself accepts this input.
            oracle::recovered_receipt_visibility(i64::MAX, None, i64::MAX, GRACE)
                .expect("the store may only accept what the oracle accepts");
        }
    }
}

// ===========================================================================
// The whole recovered table
// ===========================================================================

#[test]
fn a_mixed_receipt_table_is_promoted_row_by_row() {
    let publication = 7_000_000;
    let mut receipts = vec![
        receipt(1, Some(1_000_000), 2_000_000, 2_000_000),
        receipt(2, None, 2_000_000, 2_000_000),
        receipt(3, Some(1_500_000), 2_000_000, 2_000_000),
        receipt(4, None, 2_000_000, 2_000_000),
    ];

    let promotions =
        promote_receipt_visibility(&mut receipts, publication, GRACE).expect("promote");
    assert_eq!(
        promotions,
        vec![
            VisibilityPromotion::AlreadyDurable,
            VisibilityPromotion::PromotedToRecoveryPublication,
            VisibilityPromotion::AlreadyDurable,
            VisibilityPromotion::PromotedToRecoveryPublication,
        ],
        "each row's promotion is decided by that row's own durability, not by \
         whether the recovery as a whole found a checkpoint"
    );
    assert_eq!(receipts[0].first_receipt_visibility_micros, Some(1_000_000));
    assert_eq!(
        receipts[1].first_receipt_visibility_micros,
        Some(publication)
    );
    assert_eq!(receipts[2].first_receipt_visibility_micros, Some(1_500_000));
    assert_eq!(
        receipts[3].first_receipt_visibility_micros,
        Some(publication)
    );
}

#[test]
fn promotion_is_idempotent_across_two_recoveries() {
    // A second crash before the next checkpoint must not push the deadline out
    // again from a *different* publication time: after the first promotion the
    // value is set, so the second recovery treats it as durable-in-memory and
    // the retention window does not drift.
    let mut receipts = [receipt(1, None, 2_000_000, 2_000_000)];
    promote_receipt_visibility(&mut receipts, 7_000_000, GRACE).expect("first recovery");
    let after_first = receipts[0].clone();

    let promotions =
        promote_receipt_visibility(&mut receipts, 9_000_000, GRACE).expect("second recovery");
    assert_eq!(promotions, vec![VisibilityPromotion::AlreadyDurable]);
    assert_eq!(receipts[0], after_first);
}

#[test]
fn a_promoted_table_round_trips_through_a_checkpoint() {
    // The promoted value must be what the next checkpoint captures, or the
    // promotion is lost on the next crash and the window drifts forever.
    let root_uuid = [0x11u8; 16];
    let mut receipts = vec![receipt(1, None, 2_000_000, 2_000_000)];
    promote_receipt_visibility(&mut receipts, 7_000_000, GRACE).expect("promote");

    let mut checkpoint = Checkpoint::empty(root_uuid, 0);
    checkpoint.receipts = receipts.clone();
    let bytes = checkpoint.encode().expect("encode");
    let decoded = Checkpoint::decode(&bytes, &root_uuid, 0).expect("decode");

    assert_eq!(decoded.receipts, receipts);
    assert_eq!(
        decoded.receipts[0].first_receipt_visibility_micros,
        Some(7_000_000)
    );

    let promotions = promote_receipt_visibility(&mut decoded.receipts.clone(), 11_000_000, GRACE)
        .expect("promote");
    assert_eq!(
        promotions,
        vec![VisibilityPromotion::AlreadyDurable],
        "once a checkpoint records first visibility, later recoveries must leave it"
    );
}

#[test]
fn an_empty_receipt_table_promotes_nothing() {
    let mut receipts: Vec<ReceiptRecord> = Vec::new();
    assert_eq!(
        promote_receipt_visibility(&mut receipts, 1, GRACE).expect("promote"),
        Vec::new()
    );
}
