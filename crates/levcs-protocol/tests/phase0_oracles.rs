mod support;

use std::fs::OpenOptions;
use std::io::Write;

use levcs_protocol::oracle::*;
use levcs_protocol::v2::{PendingPhase, TransactionStatusV1};
use support::*;

#[test]
fn every_append_through_publication_boundary_has_a_deterministic_oracle() {
    assert_eq!(
        REJECTED_OR_STAGED_VISIBILITY,
        VisibilitySurface::default(),
        "rejected operations and unfinalized stage chunks expose nothing"
    );
    assert_eq!(APPEND_PUBLICATION_FAILPOINTS.len(), 17);
    for point in APPEND_PUBLICATION_FAILPOINTS {
        let expectation = append_publication_expectation(*point);
        // Every point's recovery outcome is pinned explicitly here, not by a
        // catch-all: the three-way split (deterministically absent before
        // any frame write; either-whole once a complete frame may have
        // reached the device with the fence outcome undetermined;
        // deterministically committed once the fence itself is known good)
        // is the core of the append-through-publication contract.
        let expected_recovery = match point {
            AppendFailpoint::BeforeAppend
            | AppendFailpoint::AfterMarkedResolving
            | AppendFailpoint::DuringFrameWriteTorn
            | AppendFailpoint::EvidenceHandoffFailure => RecoveryOutcome::AbsentRetriable,
            AppendFailpoint::AfterFrameWrite
            | AppendFailpoint::BeforeFence
            | AppendFailpoint::FenceFailed
            | AppendFailpoint::FenceAmbiguous
            | AppendFailpoint::WriterPanicBeforeFence => RecoveryOutcome::EitherWhole,
            AppendFailpoint::AfterSuccessfulFence
            | AppendFailpoint::DuringCommittedRootBuild
            | AppendFailpoint::AllocationFailureBeforePublication
            | AppendFailpoint::BeforeRootCas
            | AppendFailpoint::DuringRootCasRetry
            | AppendFailpoint::WriterPanicAfterFence
            | AppendFailpoint::AfterRootCasBeforeWaiterWake
            | AppendFailpoint::BeforeResponse => RecoveryOutcome::Committed,
        };
        assert_eq!(
            expectation.recovery_outcome, expected_recovery,
            "{point:?} recovery outcome"
        );
        match point {
            AppendFailpoint::BeforeAppend => {
                assert!(!expectation.shard_poisoned);
                assert_eq!(
                    expectation.immediate_status,
                    ImmediateStatus::DefinitiveAbsent
                );
                assert!(expectation.later_append_allowed_before_recovery);
                assert!(!expectation.acknowledgment_allowed);
            }
            AppendFailpoint::AfterRootCasBeforeWaiterWake | AppendFailpoint::BeforeResponse => {
                assert!(!expectation.shard_poisoned);
                assert_eq!(expectation.immediate_status, ImmediateStatus::Committed);
                assert!(expectation.acknowledgment_allowed);
                assert!(expectation.later_append_allowed_before_recovery);
            }
            _ => {
                assert!(expectation.shard_poisoned);
                assert_eq!(expectation.immediate_status, ImmediateStatus::Resolving);
                assert!(!expectation.later_append_allowed_before_recovery);
                assert!(!expectation.acknowledgment_allowed);
            }
        }
    }
    assert_eq!(
        resolve_ambiguous_tail(RecoveredTailFact::AbsentOrTorn),
        RecoveryOutcome::AbsentRetriable
    );
    assert_eq!(
        resolve_ambiguous_tail(RecoveredTailFact::CompleteChecksumValid),
        RecoveryOutcome::Committed
    );
}

#[test]
fn deadline_crossing_changes_at_append_start_and_resolution_dominates_expiry() {
    assert_eq!(
        deadline_decision(5_000, 5_000, AppendDeadlinePhase::PreAppend),
        DeadlineDecision::ContinuePreAppend
    );
    assert_eq!(
        deadline_decision(5_001, 5_000, AppendDeadlinePhase::PreAppend),
        DeadlineDecision::RejectReceiptExpired
    );
    assert_eq!(
        deadline_decision(50_000, 5_000, AppendDeadlinePhase::AppendStarted),
        DeadlineDecision::RemainResolving
    );
    let preappend_expired = deadline_expectation(5_001, 5_000, AppendDeadlinePhase::PreAppend);
    assert!(!preappend_expired.append_allowed);
    assert!(!preappend_expired.reservation_retained);
    assert!(!preappend_expired.durable_status_created);
    let resolving = deadline_expectation(50_000, 5_000, AppendDeadlinePhase::AppendStarted);
    assert!(resolving.reservation_retained);
    assert!(resolving.durable_status_created);
}

#[test]
fn coalescing_and_linearizable_status_precedence_never_mask_durable_state() {
    let receipt = receipt();
    let digest = receipt.operation_digest;
    let committed = TransactionStatusV1::Committed(receipt.clone());
    let pending = TransactionStatusV1::Pending {
        operation_digest: digest,
        retry_until_micros: receipt.retry_until_micros,
        phase: PendingPhase::Validating,
    };

    assert_eq!(
        coalescing_decision(TransactionStatusV1::Unknown, None, digest),
        CoalescingDecision::BecomeLeader
    );
    assert_eq!(
        coalescing_decision(TransactionStatusV1::Unknown, Some(digest), digest),
        CoalescingDecision::AttachToLeader
    );
    assert_eq!(
        coalescing_decision(TransactionStatusV1::Unknown, Some(id(99)), digest),
        CoalescingDecision::OperationIdMismatch
    );
    assert_eq!(
        coalescing_decision(committed.clone(), Some(id(99)), digest),
        CoalescingDecision::ReturnDurable(committed.clone())
    );
    assert_eq!(
        coalescing_decision(committed.clone(), None, id(200)),
        CoalescingDecision::OperationIdMismatch,
        "same ID/different digest rejects while a durable terminal record exists"
    );

    assert_eq!(
        two_root_status_read(None, None, Some(committed.clone())),
        committed,
        "reader paused after committed-root A must recheck B"
    );
    assert_eq!(
        public_status_read(
            TransactionStatusV1::Unknown,
            Some(pending),
            TransactionStatusV1::Committed(receipt.clone())
        ),
        TransactionStatusV1::Committed(receipt),
        "a stale registry entry cannot mask durable publication"
    );
}

#[test]
fn committed_receipt_then_tombstone_then_reuse_window_is_exact() {
    let receipt = receipt();
    assert!(matches!(
        retained_terminal_status(&receipt, 6_500, 500).unwrap(),
        TransactionStatusV1::Committed(_)
    ));
    assert!(matches!(
        retained_terminal_status(&receipt, 6_501, 500).unwrap(),
        TransactionStatusV1::Expired { .. }
    ));
    assert_eq!(
        retained_terminal_status(&receipt, 7_001, 500).unwrap(),
        TransactionStatusV1::Unknown
    );

    let checkpointed = recovered_receipt_visibility(5_000, Some(4_500), 10_000, 2_000).unwrap();
    assert_eq!(checkpointed, (4_500, 6_500));
    let reset_after_crash = recovered_receipt_visibility(5_000, None, 10_000, 2_000).unwrap();
    assert_eq!(reset_after_crash, (10_000, 12_000));
    assert!(reset_after_crash.1 >= receipt.receipt_visible_until_micros);
}

#[test]
fn replay_guard_rejects_same_nonce_until_its_checked_horizon_and_never_early() {
    let mut guard = ReplayGuardOracle::new();
    let key = [7; 32];
    let nonce = [9; 16];
    assert!(guard.reserve(key, nonce, 1_000, 60_000_000, 1_000_000, 1_000));
    assert!(
        !guard.reserve(key, nonce, 1_000, 60_000_000, 1_000_000, 1_000),
        "same (key, nonce) must be rejected while it is still live"
    );
    assert!(
        !guard.reserve(key, nonce, 1_000, 60_000_000, 1_000_000, 61_000_999),
        "eviction before issued_at + clock_skew + timer_resolution is forbidden"
    );
    assert_eq!(guard.live_count(), 1);
    assert!(
        guard.reserve(key, nonce, 1_000, 60_000_000, 1_000_000, 61_001_001),
        "the same nonce becomes reusable once its horizon has passed"
    );
    assert!(
        !guard.reserve(key, [1; 16], i64::MAX, 1, 1, 0),
        "overflowing the checked expiry must never yield a live reservation"
    );
}

#[test]
fn external_ack_journal_recovers_fenced_records_and_ignores_only_torn_tail() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("acks.lv");
    let first = AckRecord {
        repo_id: id(1),
        operation_id: [1; 16],
        operation_digest: id(2),
        receipt_digest: id(3),
        repo_sequence: 10,
        blob_ids: vec![id(10)],
        tree_ids: vec![id(11)],
        commit_ids: vec![id(12)],
    };
    let second = AckRecord {
        repo_id: id(1),
        operation_id: [3; 16],
        operation_digest: id(4),
        receipt_digest: id(5),
        repo_sequence: 11,
        blob_ids: vec![id(13)],
        tree_ids: vec![id(14)],
        commit_ids: vec![id(15)],
    };
    {
        let mut journal = ExternalAckJournal::open(&path).unwrap();
        journal.append_durable(&first).unwrap();
        journal.append_durable(&second).unwrap();
    }
    assert_eq!(
        ExternalAckJournal::recover(&path).unwrap(),
        vec![first.clone(), second.clone()]
    );

    {
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[0x38, 0, 0]).unwrap();
        file.sync_data().unwrap();
    }
    assert_eq!(
        ExternalAckJournal::recover(&path).unwrap(),
        vec![first.clone(), second]
    );
    assert_eq!(ExternalAckJournal::encoded_record_len(&first).unwrap(), 256);
}

#[test]
fn external_ack_journal_rejects_corrupt_complete_records() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bad-acks.lv");
    {
        let mut journal = ExternalAckJournal::open(&path).unwrap();
        journal
            .append_durable(&AckRecord {
                repo_id: id(1),
                operation_id: [1; 16],
                operation_digest: id(2),
                receipt_digest: id(3),
                repo_sequence: 1,
                blob_ids: vec![id(4)],
                tree_ids: vec![id(5)],
                commit_ids: vec![id(6)],
            })
            .unwrap();
    }
    let mut bytes = std::fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::write(&path, bytes).unwrap();
    assert!(matches!(
        ExternalAckJournal::recover(&path),
        Err(AckJournalError::Checksum)
    ));

    let invalid = AckRecord {
        repo_id: id(1),
        operation_id: [1; 16],
        operation_digest: id(2),
        receipt_digest: id(3),
        repo_sequence: 1,
        blob_ids: vec![],
        tree_ids: vec![],
        commit_ids: vec![],
    };
    assert!(matches!(
        ExternalAckJournal::encoded_record_len(&invalid),
        Err(AckJournalError::InvalidRecord(_))
    ));
}

#[test]
fn exact_restore_is_byte_exact_event_neutral_and_absent_destination_only() {
    let exported = ExactRestoreFixture {
        format_marker: b"FORMAT-v2".to_vec(),
        current_manifest: b"CURRENT-7".to_vec(),
        frames: vec![b"frame-a".to_vec(), b"frame-b".to_vec()],
        event_count: 2,
        receipt_count: 2,
    };
    verify_exact_restore(&exported, &exported).unwrap();

    let mut changed = exported.clone();
    changed.frames[0][0] ^= 1;
    assert_eq!(
        verify_exact_restore(&exported, &changed),
        Err(RestoreOracleError::BytesChanged)
    );
    let mut added_event = exported.clone();
    added_event.event_count += 1;
    assert_eq!(
        verify_exact_restore(&exported, &added_event),
        Err(RestoreOracleError::EventCountChanged)
    );

    RestorePreconditions {
        staging_device: 7,
        destination_parent_device: 7,
        destination_absent: true,
        format_marker_valid: true,
    }
    .validate()
    .unwrap();
    assert_eq!(
        RestorePreconditions {
            staging_device: 7,
            destination_parent_device: 8,
            destination_absent: true,
            format_marker_valid: true,
        }
        .validate(),
        Err(RestoreOracleError::CrossDevice)
    );
    assert_eq!(
        RestorePreconditions {
            staging_device: 7,
            destination_parent_device: 7,
            destination_absent: false,
            format_marker_valid: true,
        }
        .validate(),
        Err(RestoreOracleError::DestinationOccupied)
    );

    assert_eq!(RESTORE_FAILPOINTS.len(), 6);
    for point in RESTORE_FAILPOINTS {
        let expected = restore_failpoint_expectation(*point);
        assert!(!expected.new_transaction_or_event_allowed);
        if expected.destination != RestoredDestinationOutcome::Absent {
            assert!(expected.production_recovery_required);
        }
    }
    assert_eq!(
        restore_failpoint_expectation(RestoreFailpoint::AfterRenameBeforeParentSync).destination,
        RestoredDestinationOutcome::AbsentOrExact
    );
    assert_eq!(
        restore_failpoint_expectation(RestoreFailpoint::AfterParentSyncBeforeProductionRecovery)
            .destination,
        RestoredDestinationOutcome::ExactNotReady
    );
}
