mod support;

use levcs_core::{Blob, ObjectId};
use levcs_protocol::oracle::{SnapshotLeaseOracle, SnapshotLeasePhase};
use levcs_protocol::v2::*;
use levcs_protocol::CanonicalCodec;
use support::*;

#[test]
fn v2_ingestion_codecs_signatures_and_stable_retry_digest_are_frozen() {
    let signed = signed_normal_push();
    roundtrip(&signed);
    signed.verify().unwrap();

    let mut retry_operation = signed.operation.clone();
    retry_operation.issued_at_micros += 10;
    retry_operation.nonce = [0x99; 16];
    let retry = SignedPushOperationV2::sign(retry_operation, &key(1)).unwrap();
    assert_ne!(
        signed.encode_canonical().unwrap(),
        retry.encode_canonical().unwrap()
    );
    assert_eq!(
        signed.stable_digest().unwrap(),
        retry.stable_digest().unwrap()
    );
    assert_ne!(
        signed.stable_digest().unwrap(),
        signed.operation.stable_digest(key(2).public().0).unwrap(),
        "the stable digest binds the signer"
    );

    let mut tampered = signed.clone();
    tampered.operation.pack_len += 1;
    assert!(tampered.verify().is_err());

    let init = signed_init();
    roundtrip(&init);
    init.verify().unwrap();
    let mut different_genesis = init.clone();
    different_genesis.operation.genesis_hash = id(99);
    assert_ne!(
        init.stable_digest().unwrap(),
        different_genesis.stable_digest().unwrap()
    );
}

#[test]
fn typed_ref_and_push_kind_invariants_reject_ambiguous_mutations() {
    let mut normal = signed_normal_push().operation;
    normal.projection_stage = Some(ProjectionStageRefV1 {
        session_id: [1; 16],
        manifest_digest: id(1),
        object_count: 1,
        object_bytes: 1,
    });
    assert!(normal.encode_canonical().is_err());

    let mut fork = signed_fork_push().operation;
    fork.authority_update = Some(id(2));
    assert!(fork.encode_canonical().is_err());

    let mut multi_ref_fork = signed_fork_push().operation;
    multi_ref_fork.updates.push(TypedRefCas {
        target: RefTarget::Branch("other".into()),
        expected: None,
        mutation: RefMutation::Set(id(23)),
        force: false,
    });
    assert!(multi_ref_fork.encode_canonical().is_err());

    let mut duplicate = signed_normal_push().operation;
    duplicate.updates.push(duplicate.updates[0].clone());
    assert!(duplicate.encode_canonical().is_err());

    let mut invalid_delete = signed_normal_push().operation;
    invalid_delete.updates = vec![TypedRefCas {
        target: RefTarget::Branch("main".into()),
        expected: None,
        mutation: RefMutation::Delete,
        force: false,
    }];
    assert!(invalid_delete.encode_canonical().is_err());

    let mut unsafe_name = signed_normal_push().operation;
    unsafe_name.updates[0].target = RefTarget::Branch("../authority".into());
    assert!(unsafe_name.encode_canonical().is_err());
}

#[test]
fn retry_replay_and_terminal_retention_arithmetic_is_checked() {
    validate_retry_window(1_000, 2_000, 1_000, 100, 1_000).unwrap();
    assert!(validate_retry_window(1_000, 2_001, 1_000, 100, 1_000).is_err());
    assert!(validate_retry_window(i64::MAX, i64::MAX, i64::MAX, 1, 1).is_err());
    assert!(validate_retry_window(1_000, 999, 1_000, 100, 1_000).is_err());
    assert!(validate_retry_window(1_000, 1_100, 1_101, 200, 1_000).is_err());

    assert!(matches!(
        validate_retry_window(999, 1_000, 1_100, 50, 1_000),
        Err(V2ValidationError::RetryWindow(
            "issued_at outside clock skew"
        ))
    ));
    assert!(matches!(
        validate_retry_window(1_200, 2_000, 1_100, 50, 1_000),
        Err(V2ValidationError::RetryWindow(
            "issued_at outside clock skew"
        ))
    ));

    assert_eq!(
        minimum_replay_retention_micros(60_000_000, 1_000_000).unwrap(),
        121_000_000
    );
    validate_replay_retention(121_000_000, 60_000_000, 1_000_000).unwrap();
    assert!(validate_replay_retention(120_999_999, 60_000_000, 1_000_000).is_err());
    assert!(minimum_replay_retention_micros(i64::MAX, 1).is_err());

    assert_eq!(receipt_visible_until(5_000, 4_500, 2_000).unwrap(), 6_500);
    assert_eq!(status_tombstone_until(6_500, 500).unwrap(), 7_000);
    assert!(receipt_visible_until(0, i64::MAX, 1).is_err());
    assert!(status_tombstone_until(i64::MAX, 1).is_err());
}

#[test]
fn snapshots_are_deterministic_while_tokens_and_request_pins_are_ephemeral() {
    let signed_generation = snapshot();
    roundtrip(&signed_generation);
    signed_generation.verify().unwrap();

    let generation_digest = signed_generation.snapshot.generation_digest().unwrap();
    let reader_key_digest = reader_key_digest_or_zero(Some(key(4).public().0));
    let mac_key = [0xa5; 32];
    let claims = SnapshotLeaseClaimsV1 {
        version: SNAPSHOT_LEASE_TOKEN_VERSION,
        mac_key_epoch: 3,
        token_id: [1; 16],
        repo_id: signed_generation.snapshot.repo_id,
        projection: signed_generation.snapshot.projection,
        generation_digest,
        high_repo_sequence: signed_generation.snapshot.high_repo_sequence,
        high_event_digest: signed_generation.snapshot.high_event_digest,
        issued_at_micros: 9_000,
        expires_at_micros: 10_000,
        reader_key_digest,
    };
    let token = SnapshotLeaseTokenV1::mint(claims, &mac_key).unwrap();
    roundtrip(&token);
    let expectation = SnapshotLeaseExpectationV1 {
        repo_id: signed_generation.snapshot.repo_id,
        generation_digest,
        projection: signed_generation.snapshot.projection,
        reader_key_digest,
        mac_key_epoch: 3,
        now_micros: 9_999,
    };
    token.verify(&mac_key, expectation).unwrap();
    assert!(token
        .verify(
            &mac_key,
            SnapshotLeaseExpectationV1 {
                repo_id: id(99),
                ..expectation
            },
        )
        .is_err());
    assert!(token
        .verify(
            &mac_key,
            SnapshotLeaseExpectationV1 {
                now_micros: 10_001,
                ..expectation
            },
        )
        .is_err());
    assert!(
        token.verify(&[0x5b; 32], expectation,).is_err(),
        "a wrong MAC key must be rejected even when every claim matches"
    );
    let mut tampered_claims = token.clone();
    tampered_claims.claims.repo_id = id(55);
    assert!(
        tampered_claims.verify(&mac_key, expectation).is_err(),
        "tampering with claims without re-minting the MAC must fail verification"
    );
    let mut wrong_version = token.clone();
    wrong_version.claims.version = SNAPSHOT_LEASE_TOKEN_VERSION + 1;
    assert!(wrong_version.verify(&mac_key, expectation).is_err());

    let mut second_token = token.clone();
    second_token.claims.token_id = [2; 16];
    second_token = SnapshotLeaseTokenV1::mint(second_token.claims, &mac_key).unwrap();
    let first = SnapshotResponseV1 {
        signed_generation: signed_generation.clone(),
        lease_token: token.encode_canonical().unwrap(),
    };
    let second = SnapshotResponseV1 {
        signed_generation,
        lease_token: second_token.encode_canonical().unwrap(),
    };
    assert_ne!(
        first.encode_canonical().unwrap(),
        second.encode_canonical().unwrap()
    );
    assert_eq!(
        first.evidence_generation_digest().unwrap(),
        second.evidence_generation_digest().unwrap()
    );

    let mut lease = SnapshotLeaseOracle::new();
    assert!(lease.admit_request());
    lease.close_or_expire();
    assert_eq!(lease.phase(), SnapshotLeasePhase::Closed);
    assert!(lease.base_pin_held());
    assert!(!lease.admit_request());
    assert!(lease.release_request());
    assert_eq!(lease.phase(), SnapshotLeasePhase::Released);
    assert!(!lease.base_pin_held());

    // Closing/expiring with zero admitted request pins releases the base
    // pin immediately, per plan §6.2: "released immediately when no admitted
    // request pin remains".
    let mut empty_lease = SnapshotLeaseOracle::new();
    assert_eq!(empty_lease.request_pins(), 0);
    empty_lease.close_or_expire();
    assert_eq!(empty_lease.phase(), SnapshotLeasePhase::Released);
    assert!(!empty_lease.base_pin_held());
}

#[test]
fn signed_private_read_and_missing_object_contracts_detect_tampering() {
    let signed = signed_read();
    roundtrip(&signed);
    signed.verify().unwrap();

    let request = MissingObjectsRequestV1 {
        generation_digest: id(71),
        object_ids: vec![id(1), id(2), id(3)],
    };
    roundtrip(&request);
    roundtrip(&MissingObjectsResponseV1 {
        generation_digest: request.generation_digest,
        missing_ids: request.object_ids.clone(),
    });

    let mut unordered = request.clone();
    unordered.object_ids.swap(0, 1);
    assert!(unordered.encode_canonical().is_err());

    let mut tampered = signed.clone();
    tampered.request.snapshot_token_digest = id(72);
    assert!(tampered.verify().is_err());

    let mut wrong_method = signed.request;
    wrong_method.method = HttpMethodV2::Get;
    assert!(wrong_method.encode_canonical().is_err());
}

#[test]
fn every_read_route_method_pairing_is_signed_and_frozen() {
    let reads = signed_reads();
    let expected_methods = [
        HttpMethodV2::Get,
        HttpMethodV2::Get,
        HttpMethodV2::Post,
        HttpMethodV2::Post,
        HttpMethodV2::Put,
        HttpMethodV2::Delete,
    ];
    assert_eq!(reads.len(), expected_methods.len());
    for (read, expected_method) in reads.iter().zip(expected_methods) {
        roundtrip(read);
        read.verify().unwrap();
        assert_eq!(read.request.method, expected_method);
    }
    assert!(reads[0].request.snapshot_token_digest.is_zero());
    assert!(!reads[1].request.snapshot_token_digest.is_zero());
}

#[test]
fn evidence_variants_are_canonical_and_bind_identity_epoch_and_admin_context() {
    let evidence = all_evidence();
    let expected_kinds = [
        SourceKindV1::Client,
        SourceKindV1::Client,
        SourceKindV1::MirrorEvent,
        SourceKindV1::MirrorSnapshot,
        SourceKindV1::LegacyMigration,
        SourceKindV1::ProjectionAdmin,
        SourceKindV1::Administrative,
    ];
    for (value, expected_kind) in evidence.iter().zip(expected_kinds) {
        assert_eq!(value.source_kind(), expected_kind);
        roundtrip(value);
        value
            .verify_authenticated_binding(evidence_context_for(value))
            .unwrap();
    }

    for value in &evidence[4..] {
        let wrong_context = AdministrativeEvidenceContextV1 {
            destination_repo: id(99),
            ..evidence_context_for(value)
        };
        assert!(value.verify_authenticated_binding(wrong_context).is_err());
    }

    let legacy = &evidence[4];
    let original_context = evidence_context_for(legacy);
    let mut ordinal_substitution = legacy.clone();
    if let TransactionEvidenceV1::LegacyMigrationV1 { chunk_ordinal, .. } =
        &mut ordinal_substitution
    {
        *chunk_ordinal += 1;
    }
    let changed_context = evidence_context_for(&ordinal_substitution);
    assert_ne!(original_context.operation_id, changed_context.operation_id);
    assert!(ordinal_substitution
        .verify_authenticated_binding(changed_context)
        .is_err());

    let mut wrong_epoch = evidence[2].clone();
    if let TransactionEvidenceV1::MirrorEventV1 {
        source_key_epoch, ..
    } = &mut wrong_epoch
    {
        *source_key_epoch += 1;
    }
    assert!(wrong_epoch
        .verify_authenticated_binding(evidence_context_for(&wrong_epoch))
        .is_err());

    let signed_event = signed_event();
    signed_event.verify(key(7).public().0).unwrap();
    let mut epoch_substitution = signed_event;
    epoch_substitution.source_key_epoch += 1;
    assert!(epoch_substitution.verify(key(7).public().0).is_err());
}

#[test]
fn event_hash_chain_and_dual_sequence_domains_are_independent() {
    let transaction = committed_transaction();
    roundtrip(&transaction);
    let page = TransactionPageV1 {
        repo_id: transaction.repo_id,
        after_repo_sequence: 11,
        after_event_digest: id(39),
        fixed_upper_repo_sequence: 12,
        events: vec![signed_event()],
    };
    roundtrip(&page);
    page.verify(key(7).public().0).unwrap();
    let mut wrong_upper = page;
    wrong_upper.fixed_upper_repo_sequence = 11;
    assert!(wrong_upper.encode_canonical().is_err());

    let relation = SequenceRelationV1 {
        previous_shard_sequence: 100,
        next_shard_sequence: 101,
        previous_repo_sequence: Some(11),
        previous_event_digest: Some(id(39)),
    };
    relation.validate_next(&transaction).unwrap();

    let other_repo_first = CommittedTransactionV1 {
        repo_id: id(200),
        repo_sequence: 1,
        previous_event_digest: ObjectId([0; 32]),
        ..transaction.clone()
    };
    SequenceRelationV1 {
        previous_shard_sequence: 101,
        next_shard_sequence: 102,
        previous_repo_sequence: None,
        previous_event_digest: None,
    }
    .validate_next(&other_repo_first)
    .unwrap();

    let mut gap = transaction;
    gap.repo_sequence += 1;
    assert!(relation.validate_next(&gap).is_err());
}

#[test]
fn staged_projection_bytes_manifest_and_install_are_one_binding() {
    let (session, chunks, manifest, install) = staged_projection();
    roundtrip(&session);
    roundtrip(&chunks[0]);
    roundtrip(&manifest);
    roundtrip(&install);
    validate_projection_stage_binding(&session, &chunks, &manifest, &install).unwrap();

    let mut changed = chunks.clone();
    changed[0].objects[0].raw_bytes.push(0);
    assert!(changed[0].encode_canonical().is_err());

    let mut wrong_install = install;
    wrong_install.membership_root = id(1);
    assert!(
        validate_projection_stage_binding(&session, &chunks, &manifest, &wrong_install).is_err()
    );
}

#[test]
fn projection_stage_finalize_rebinds_the_exact_final_operation() {
    let (session, ..) = staged_projection();
    validate_projection_stage_finalize(
        &session,
        session.expires_at_micros - 1,
        session.final_operation_id,
        session.final_operation_digest,
        session.final_evidence_digest,
        session.actor,
        session.fork_proof.as_ref(),
    )
    .unwrap();

    assert!(validate_projection_stage_finalize(
        &session,
        session.expires_at_micros + 1,
        session.final_operation_id,
        session.final_operation_digest,
        session.final_evidence_digest,
        session.actor,
        session.fork_proof.as_ref(),
    )
    .is_err());
    assert!(validate_projection_stage_finalize(
        &session,
        session.expires_at_micros - 1,
        [0x99; 16],
        session.final_operation_digest,
        session.final_evidence_digest,
        session.actor,
        session.fork_proof.as_ref(),
    )
    .is_err());
    assert!(validate_projection_stage_finalize(
        &session,
        session.expires_at_micros - 1,
        session.final_operation_id,
        session.final_operation_digest,
        session.final_evidence_digest,
        key(9).public().0,
        session.fork_proof.as_ref(),
    )
    .is_err());

    let fork_proof = ForkProofV2 {
        source_repo_id: id(60),
        source_genesis: id(61),
        source_tip: id(62),
        source_authority: id(63),
    };
    let fork_session = ProjectionStageSessionV1 {
        source_kind: StageSourceKindV1::Fork,
        fork_proof: Some(fork_proof.clone()),
        ..session
    };
    assert!(validate_projection_stage_finalize(
        &fork_session,
        fork_session.expires_at_micros - 1,
        fork_session.final_operation_id,
        fork_session.final_operation_digest,
        fork_session.final_evidence_digest,
        fork_session.actor,
        None,
    )
    .is_err());
    validate_projection_stage_finalize(
        &fork_session,
        fork_session.expires_at_micros - 1,
        fork_session.final_operation_id,
        fork_session.final_operation_digest,
        fork_session.final_evidence_digest,
        fork_session.actor,
        Some(&fork_proof),
    )
    .unwrap();
}

#[test]
fn push_and_init_http_body_framing_is_length_prefixed_and_exact() {
    let signed_push = signed_normal_push();
    let pack_bytes = vec![0x41; signed_push.operation.pack_len as usize];
    let body = encode_push_request_body(&signed_push, &pack_bytes).unwrap();
    let (decoded, decoded_pack) = decode_push_request_body(&body).unwrap();
    assert_eq!(decoded, signed_push);
    assert_eq!(decoded_pack, pack_bytes.as_slice());

    let mut truncated = body.clone();
    truncated.pop();
    assert!(decode_push_request_body(&truncated).is_err());
    let mut extended = body.clone();
    extended.push(0);
    assert!(decode_push_request_body(&extended).is_err());
    assert!(encode_push_request_body(&signed_push, &pack_bytes[..pack_bytes.len() - 1]).is_err());

    let signed_init_op = signed_init();
    let genesis_bytes = vec![0x42; signed_init_op.operation.genesis_len as usize];
    let init_body = encode_init_request_body(&signed_init_op, &genesis_bytes).unwrap();
    let (decoded_init, decoded_genesis) = decode_init_request_body(&init_body).unwrap();
    assert_eq!(decoded_init, signed_init_op);
    assert_eq!(decoded_genesis, genesis_bytes.as_slice());

    let mut truncated_init = init_body.clone();
    truncated_init.pop();
    assert!(decode_init_request_body(&truncated_init).is_err());
    assert!(
        encode_init_request_body(&signed_init_op, &genesis_bytes[..genesis_bytes.len() - 1])
            .is_err()
    );
}

#[test]
fn projection_oracle_freezes_every_reduced_boundary() {
    use ProjectionDecisionV1::*;
    use ProjectionEdgeV1::*;

    assert_eq!(
        projection_decision(ProjectionMode::Full, ForeignForkClosure),
        RetainAndVerify
    );
    assert_eq!(
        projection_decision(ProjectionMode::Release, BranchRef),
        OmitNonMember
    );
    assert_eq!(
        projection_decision(ProjectionMode::Release, OrdinaryCommitParent),
        VerifyThenOmitBoundary
    );
    assert_eq!(
        projection_decision(
            ProjectionMode::Release,
            ImmediatePredecessorEnvelope {
                tree_matches_release: true
            }
        ),
        RetainAndVerify
    );
    assert_eq!(
        projection_decision(
            ProjectionMode::Release,
            ImmediatePredecessorEnvelope {
                tree_matches_release: false
            }
        ),
        Reject
    );
    assert_eq!(
        projection_decision(ProjectionMode::Metadata, ReleaseTreeOrBlob),
        VerifyThenOmitBoundary
    );
    assert_eq!(
        projection_decision(ProjectionMode::Metadata, SignedTransactionEvidence),
        RetainAndVerify
    );
}

#[test]
fn cursor_expiry_forces_authenticated_resnapshot_and_cutover_is_strict() {
    let digest = snapshot().snapshot.generation_digest().unwrap();
    let expired = cursor_disposition(9, 10, 12, digest).unwrap();
    let CursorDispositionV1::Resnapshot(expired) = expired else {
        panic!("cursor below floor must resnapshot");
    };
    roundtrip(&expired);
    assert_eq!(expired.authenticated_snapshot_digest, digest);
    assert_eq!(
        cursor_disposition(10, 10, 12, digest).unwrap(),
        CursorDispositionV1::ReplayFrom {
            after: 10,
            through: 12
        }
    );
    assert!(cursor_disposition(13, 10, 12, digest).is_err());
    assert!(matches!(
        object_dependency_disposition(8, 9, 12, digest).unwrap(),
        ObjectDependencyDispositionV1::Resnapshot { .. }
    ));
    assert_eq!(
        object_dependency_disposition(9, 9, 12, digest).unwrap(),
        ObjectDependencyDispositionV1::Available
    );

    let cutover = MaintenanceCutoverV1 {
        storage_format_version: 2,
        minimum_protocol_version: 2,
        v1_post_disabled: true,
        writer_set_digest: id(1),
        peer_set_digest: id(2),
        maintenance_generation: 1,
    };
    roundtrip(&cutover);
    let mut unsafe_cutover = cutover;
    unsafe_cutover.v1_post_disabled = false;
    assert!(unsafe_cutover.encode_canonical().is_err());
}

#[test]
fn authority_successor_objects_wait_for_the_next_transaction() {
    let valid = AuthorityTransitionFactsV1 {
        expected_authority: id(1),
        authority_update: Some(id(2)),
        boundary_commit_count: 1,
        boundary_commit_cites_expected: true,
        boundary_exposes_direct_successor: true,
        cas_publishes_with_boundary: true,
        unrelated_successor_commit_or_release_count: 0,
        successor_reference_outside_boundary_path_count: 0,
    };
    valid.validate_normal_push().unwrap();

    let mut same_transaction_successor = valid.clone();
    same_transaction_successor.unrelated_successor_commit_or_release_count = 1;
    assert!(same_transaction_successor.validate_normal_push().is_err());

    let later_transaction = AuthorityTransitionFactsV1 {
        expected_authority: id(2),
        authority_update: None,
        boundary_commit_count: 0,
        boundary_commit_cites_expected: false,
        boundary_exposes_direct_successor: false,
        cas_publishes_with_boundary: false,
        unrelated_successor_commit_or_release_count: 0,
        successor_reference_outside_boundary_path_count: 0,
    };
    later_transaction.validate_normal_push().unwrap();
}

#[test]
fn foreign_fork_boundary_is_native_only_at_the_destination_commit() {
    let valid = ForeignForkBoundaryFactsV1 {
        destination_repo_id: id(1),
        destination_genesis: id(2),
        destination_current_authority: id(2),
        destination_is_empty: true,
        source_repo_id: id(3),
        derived_source_repo_id: id(3),
        source_genesis: id(4),
        verified_source_genesis: id(4),
        source_tip: id(5),
        fork_parent: id(5),
        source_authority: id(6),
        parent_cited_authority: id(6),
        fork_commit_authority: id(2),
        fork_tree_authority: id(2),
        fork_parent_count: 1,
        fork_and_modifies_authority_flags: true,
        envelope_signer_is_destination_owner: true,
        envelope_signer_is_commit_signer: true,
        source_read_authorized: true,
        projection_proof_complete: true,
    };
    valid.validate().unwrap();

    let mut forged_genesis = valid.clone();
    forged_genesis.verified_source_genesis = id(99);
    assert!(forged_genesis.validate().is_err());
    let mut wrong_destination = valid.clone();
    wrong_destination.fork_commit_authority = valid.source_authority;
    assert!(wrong_destination.validate().is_err());
    let mut nonempty = valid.clone();
    nonempty.destination_is_empty = false;
    assert!(nonempty.validate().is_err());
    let mut private_unauthorized = valid.clone();
    private_unauthorized.source_read_authorized = false;
    assert!(private_unauthorized.validate().is_err());
    let mut missing_projection = valid;
    missing_projection.projection_proof_complete = false;
    assert!(missing_projection.validate().is_err());
}

#[test]
fn deterministic_object_ref_snapshot_event_evidence_and_status_digests_exist() {
    let blob = Blob::new(vec![0x5a; 1_024]);
    let object_digest = blob.object_id();
    assert_eq!(object_digest, levcs_core::blake3_hash(&blob.serialize()));

    let snapshot = snapshot();
    let refs_digest = ref_state_digest(&snapshot.snapshot.refs).unwrap();
    let snapshot_digest = snapshot.snapshot.generation_digest().unwrap();
    let event_digest = committed_transaction().event_digest().unwrap();
    let evidence_digest = all_evidence()[3].evidence_digest().unwrap();
    let status_digest = TransactionStatusV1::Committed(receipt())
        .status_digest()
        .unwrap();
    for digest in [
        object_digest,
        refs_digest,
        snapshot_digest,
        event_digest,
        evidence_digest,
        status_digest,
    ] {
        assert!(!digest.is_zero());
    }
}
