mod support;

use levcs_protocol::v2::*;
use levcs_protocol::CanonicalCodec;
use support::*;

fn destination_event_for(evidence: &TransactionEvidenceV1) -> CommittedTransactionV1 {
    let repo_id = id(3);
    let (actor, operation_id) = match evidence {
        TransactionEvidenceV1::MirrorEventV1 {
            source_instance,
            source_event,
            ..
        } => (
            *source_instance,
            mirror_event_operation_id(
                *source_instance,
                repo_id,
                source_event.transaction.repo_sequence,
            ),
        ),
        TransactionEvidenceV1::MirrorSnapshotV1 {
            source_instance,
            source_snapshot,
            destination_projection,
            projected_manifest_digest,
            ..
        } => (
            *source_instance,
            mirror_snapshot_operation_id(
                *source_instance,
                repo_id,
                source_snapshot.snapshot.generation_digest().unwrap(),
                *destination_projection,
                *projected_manifest_digest,
            ),
        ),
        _ => (key(8).public().0, [0x71; 16]),
    };
    CommittedTransactionV1 {
        repo_id,
        repo_sequence: 1,
        previous_event_digest: id(0),
        sequenced_at_micros: 20_000,
        source_kind: evidence.source_kind(),
        actor,
        operation_id,
        operation_digest: id(72),
        signed_evidence_digest: evidence.evidence_digest().unwrap(),
        old_authority: id(4),
        new_authority: id(4),
        refs: vec![AppliedRefV1 {
            target: RefTarget::Branch("main".into()),
            old: None,
            new: Some(id(7)),
            force: false,
        }],
        object_ids: vec![id(31)],
        commit_ids: vec![id(31)],
        resulting_state_digest: id(73),
    }
}

#[test]
fn mirror_snapshot_consumer_accepts_both_inline_and_staged_atomic_publication() {
    let evidence = all_evidence()
        .into_iter()
        .find(|value| matches!(value, TransactionEvidenceV1::MirrorSnapshotV1 { .. }))
        .unwrap();
    let event = destination_event_for(&evidence);
    validate_mirror_application(
        MirrorApplicationKindV1::SnapshotInline,
        &evidence,
        &event,
        None,
    )
    .unwrap();

    let (
        destination_projection,
        projected_manifest_digest,
        projected_object_count,
        projected_object_bytes,
    ) = match &evidence {
        TransactionEvidenceV1::MirrorSnapshotV1 {
            destination_projection,
            projected_manifest_digest,
            projected_object_count,
            projected_object_bytes,
            ..
        } => (
            *destination_projection,
            *projected_manifest_digest,
            *projected_object_count,
            *projected_object_bytes,
        ),
        _ => unreachable!(),
    };
    let install = StagedProjectionInstallV1 {
        session_id: [0x72; 16],
        manifest_digest: projected_manifest_digest,
        projection: destination_projection,
        object_count: projected_object_count,
        object_bytes: projected_object_bytes,
        membership_root: id(74),
        artifact_set_digest: id(75),
    };
    validate_mirror_application(
        MirrorApplicationKindV1::SnapshotStaged,
        &evidence,
        &event,
        Some(&install),
    )
    .unwrap();

    let mut wrong = install;
    wrong.object_count += 1;
    assert!(validate_mirror_application(
        MirrorApplicationKindV1::SnapshotStaged,
        &evidence,
        &event,
        Some(&wrong)
    )
    .is_err());
}

#[test]
fn mirror_event_consumer_distinguishes_projected_from_cursor_only() {
    let evidence = all_evidence()
        .into_iter()
        .find(|value| matches!(value, TransactionEvidenceV1::MirrorEventV1 { .. }))
        .unwrap();
    let projected = destination_event_for(&evidence);
    validate_mirror_application(
        MirrorApplicationKindV1::ProjectedEvent,
        &evidence,
        &projected,
        None,
    )
    .unwrap();

    let cursor_only = CommittedTransactionV1 {
        refs: vec![],
        object_ids: vec![],
        commit_ids: vec![],
        resulting_state_digest: id(4),
        ..destination_event_for(&evidence)
    };
    validate_mirror_application(
        MirrorApplicationKindV1::CursorOnlyEvent,
        &evidence,
        &cursor_only,
        None,
    )
    .unwrap();
    assert!(validate_mirror_application(
        MirrorApplicationKindV1::ProjectedEvent,
        &evidence,
        &cursor_only,
        None
    )
    .is_err());
}

#[test]
fn consumer_dispatch_is_total_for_every_transaction_source_kind() {
    let mut seen = [false; 6];
    for evidence in all_evidence() {
        let index = match evidence.source_kind() {
            SourceKindV1::Client => 0,
            SourceKindV1::MirrorSnapshot => 1,
            SourceKindV1::MirrorEvent => 2,
            SourceKindV1::LegacyMigration => 3,
            SourceKindV1::ProjectionAdmin => 4,
            SourceKindV1::Administrative => 5,
        };
        seen[index] = true;
    }
    assert!(seen.into_iter().all(|value| value));
    assert_eq!(SourceKindV1::Client as u8, 1);
    assert_eq!(SourceKindV1::MirrorSnapshot as u8, 2);
    assert_eq!(SourceKindV1::MirrorEvent as u8, 3);
    assert_eq!(SourceKindV1::LegacyMigration as u8, 4);
    assert_eq!(SourceKindV1::ProjectionAdmin as u8, 5);
    assert_eq!(SourceKindV1::Administrative as u8, 6);
}

#[test]
fn typed_status_consumer_handles_pending_resolving_committed_expired_and_unknown() {
    let receipt = receipt();
    let values = vec![
        TransactionStatusV1::Pending {
            operation_digest: receipt.operation_digest,
            retry_until_micros: receipt.retry_until_micros,
            phase: PendingPhase::Receiving,
        },
        TransactionStatusV1::Resolving {
            operation_digest: receipt.operation_digest,
            retry_until_micros: receipt.retry_until_micros,
            shard_sequence: Some(77),
        },
        TransactionStatusV1::Committed(receipt.clone()),
        TransactionStatusV1::Expired {
            operation_digest: receipt.operation_digest,
            retry_until_micros: receipt.retry_until_micros,
            tombstone_until_micros: 7_000,
        },
        TransactionStatusV1::Unknown,
    ];
    for (status, expected_http) in values.into_iter().zip([202, 202, 200, 410, 404]) {
        roundtrip(&status);
        assert!(!status.status_digest().unwrap().is_zero());
        assert_eq!(status.http_status_code(), expected_http);
    }
}

#[test]
fn cursor_expired_response_contains_the_authenticated_resnapshot_checkpoint() {
    let snapshot = snapshot();
    let digest = snapshot.snapshot.generation_digest().unwrap();
    let disposition = cursor_disposition(8, 10, 12, digest).unwrap();
    match disposition {
        CursorDispositionV1::Resnapshot(response) => {
            assert_eq!(response.minimum_retained_sequence, 10);
            assert_eq!(response.authenticated_snapshot_digest, digest);
            assert_eq!(
                CursorExpiredV1::decode_canonical(&response.encode_canonical().unwrap()).unwrap(),
                response
            );
        }
        CursorDispositionV1::ReplayFrom { .. } => panic!("stale cursor must resnapshot"),
    }
}
