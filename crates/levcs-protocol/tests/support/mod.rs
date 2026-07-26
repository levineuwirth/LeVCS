#![allow(dead_code)]

use levcs_core::{Blob, ObjectId, ObjectType};
use levcs_identity::keys::SecretKey;
use levcs_protocol::v2::*;
use levcs_protocol::CanonicalCodec;

pub fn id(byte: u8) -> ObjectId {
    ObjectId([byte; 32])
}

pub fn key(byte: u8) -> SecretKey {
    SecretKey::from_seed([byte; 32])
}

pub fn evidence_context() -> AdministrativeEvidenceContextV1 {
    AdministrativeEvidenceContextV1 {
        destination_repo: id(3),
        operation_id: [0x41; 16],
    }
}

pub fn evidence_context_for(evidence: &TransactionEvidenceV1) -> AdministrativeEvidenceContextV1 {
    match evidence {
        TransactionEvidenceV1::LegacyMigrationV1 {
            migration_id,
            repo_id,
            chunk_ordinal,
            chunk_count,
            chunk_digest,
            ..
        } => AdministrativeEvidenceContextV1 {
            destination_repo: *repo_id,
            operation_id: legacy_migration_operation_id(
                *migration_id,
                *repo_id,
                *chunk_ordinal,
                *chunk_count,
                *chunk_digest,
            ),
        },
        _ => evidence_context(),
    }
}

pub fn signed_init() -> SignedInitOperationV2 {
    let key = key(3);
    SignedInitOperationV2::sign(
        InitOperationV2 {
            operation_id: [0x31; 16],
            repo_id: id(2),
            issued_at_micros: 1_000,
            retry_until_micros: 5_000,
            nonce: [0x32; 16],
            genesis_len: 777,
            genesis_hash: id(4),
        },
        &key,
    )
    .unwrap()
}

pub fn signed_normal_push() -> SignedPushOperationV2 {
    let key = key(1);
    SignedPushOperationV2::sign(
        PushOperationV2 {
            operation_id: [0x11; 16],
            repo_id: id(2),
            issued_at_micros: 1_000,
            retry_until_micros: 5_000,
            nonce: [0x12; 16],
            expected_authority: id(4),
            authority_update: Some(id(5)),
            updates: vec![
                TypedRefCas {
                    target: RefTarget::Branch("main".into()),
                    expected: Some(id(6)),
                    mutation: RefMutation::Set(id(7)),
                    force: false,
                },
                TypedRefCas {
                    target: RefTarget::Release("v0".into()),
                    expected: Some(id(8)),
                    mutation: RefMutation::Delete,
                    force: true,
                },
            ],
            pack_len: 128,
            pack_hash: id(9),
            snapshot_generation_digest: id(10),
            projection_stage: None,
            kind: PushKindV2::Normal,
        },
        &key,
    )
    .unwrap()
}

pub fn signed_fork_push() -> SignedPushOperationV2 {
    let key = key(2);
    SignedPushOperationV2::sign(
        PushOperationV2 {
            operation_id: [0x21; 16],
            repo_id: id(20),
            issued_at_micros: 2_000,
            retry_until_micros: 8_000,
            nonce: [0x22; 16],
            expected_authority: id(21),
            authority_update: None,
            updates: vec![TypedRefCas {
                target: RefTarget::Branch("main".into()),
                expected: None,
                mutation: RefMutation::Set(id(22)),
                force: false,
            }],
            pack_len: 256,
            pack_hash: id(23),
            snapshot_generation_digest: id(24),
            projection_stage: None,
            kind: PushKindV2::Fork(ForkProofV2 {
                source_repo_id: id(25),
                source_genesis: id(26),
                source_tip: id(27),
                source_authority: id(28),
            }),
        },
        &key,
    )
    .unwrap()
}

pub fn snapshot() -> SignedRepoSnapshotV1 {
    let key = key(7);
    SignedRepoSnapshotV1::sign(
        RepoSnapshotV1 {
            source_instance: key.public().0,
            source_key_epoch: 9,
            repo_id: id(2),
            genesis_authority: id(4),
            current_authority: id(5),
            projection: ProjectionMode::Full,
            refs: vec![
                RefStateV1 {
                    target: RefTarget::Branch("main".into()),
                    object: id(7),
                },
                RefStateV1 {
                    target: RefTarget::Release("v1".into()),
                    object: id(8),
                },
            ],
            event_low_repo_sequence: 10,
            object_low_repo_sequence: 9,
            high_repo_sequence: 12,
            high_event_digest: id(40),
            resulting_state_digest: id(41),
            config_epoch: 3,
            capabilities_digest: id(42),
        },
        &key,
    )
    .unwrap()
}

pub fn committed_transaction() -> CommittedTransactionV1 {
    CommittedTransactionV1 {
        repo_id: id(2),
        repo_sequence: 12,
        previous_event_digest: id(39),
        sequenced_at_micros: 12_345,
        source_kind: SourceKindV1::Client,
        actor: key(1).public().0,
        operation_id: [0x11; 16],
        operation_digest: signed_normal_push().stable_digest().unwrap(),
        signed_evidence_digest: id(43),
        old_authority: id(4),
        new_authority: id(5),
        refs: vec![AppliedRefV1 {
            target: RefTarget::Branch("main".into()),
            old: Some(id(6)),
            new: Some(id(7)),
            force: false,
        }],
        object_ids: vec![id(31), id(32), id(33)],
        commit_ids: vec![id(33)],
        resulting_state_digest: id(41),
    }
}

pub fn signed_event() -> SignedCommittedTransactionV1 {
    SignedCommittedTransactionV1::sign(committed_transaction(), 9, &key(7)).unwrap()
}

pub fn receipt() -> CommitReceiptV1 {
    CommitReceiptV1 {
        operation_id: [0x11; 16],
        operation_digest: signed_normal_push().stable_digest().unwrap(),
        repo_sequence: 12,
        current_authority: id(5),
        refs: vec![AppliedRefV1 {
            target: RefTarget::Branch("main".into()),
            old: Some(id(6)),
            new: Some(id(7)),
            force: false,
        }],
        objects_new: 3,
        retry_until_micros: 5_000,
        first_visible_at_micros: 4_500,
        receipt_visible_until_micros: 6_500,
    }
}

pub fn signed_read() -> SignedReadRequestV2 {
    SignedReadRequestV2::sign(
        CanonicalReadRequestV2 {
            method: HttpMethodV2::Post,
            route: ReadRouteV2::MissingObjects,
            repo_id: id(2),
            body_digest: id(70),
            snapshot_token_digest: id(71),
            timestamp_micros: 3_000,
            nonce: [0x44; 16],
        },
        &key(4),
    )
    .unwrap()
}

/// One `SignedReadRequestV2` per HTTP method the typed routes use, including
/// a public (zero snapshot-token-digest) acquisition request, so the
/// method/route pairing itself is byte-frozen and not just one POST route.
pub fn signed_reads() -> Vec<SignedReadRequestV2> {
    vec![
        SignedReadRequestV2::sign(
            CanonicalReadRequestV2 {
                method: HttpMethodV2::Get,
                route: ReadRouteV2::Snapshot,
                repo_id: id(2),
                body_digest: id(0),
                snapshot_token_digest: ObjectId([0; 32]),
                timestamp_micros: 2_000,
                nonce: [0x43; 16],
            },
            &key(4),
        )
        .unwrap(),
        SignedReadRequestV2::sign(
            CanonicalReadRequestV2 {
                method: HttpMethodV2::Get,
                route: ReadRouteV2::Object { object_id: id(9) },
                repo_id: id(2),
                body_digest: id(0),
                snapshot_token_digest: id(71),
                timestamp_micros: 2_500,
                nonce: [0x45; 16],
            },
            &key(4),
        )
        .unwrap(),
        SignedReadRequestV2::sign(
            CanonicalReadRequestV2 {
                method: HttpMethodV2::Post,
                route: ReadRouteV2::Pack,
                repo_id: id(2),
                body_digest: id(70),
                snapshot_token_digest: id(71),
                timestamp_micros: 2_600,
                nonce: [0x46; 16],
            },
            &key(4),
        )
        .unwrap(),
        signed_read(),
        SignedReadRequestV2::sign(
            CanonicalReadRequestV2 {
                method: HttpMethodV2::Put,
                route: ReadRouteV2::ProjectionStageChunk {
                    session_id: [0x61; 16],
                    ordinal: 0,
                },
                repo_id: id(2),
                body_digest: id(70),
                snapshot_token_digest: id(0),
                timestamp_micros: 2_700,
                nonce: [0x47; 16],
            },
            &key(4),
        )
        .unwrap(),
        SignedReadRequestV2::sign(
            CanonicalReadRequestV2 {
                method: HttpMethodV2::Delete,
                route: ReadRouteV2::ReleaseLease,
                repo_id: id(2),
                body_digest: id(0),
                snapshot_token_digest: id(71),
                timestamp_micros: 2_800,
                nonce: [0x48; 16],
            },
            &key(4),
        )
        .unwrap(),
    ]
}

pub fn snapshot_lease_token() -> SnapshotLeaseTokenV1 {
    let generation_digest = snapshot().snapshot.generation_digest().unwrap();
    SnapshotLeaseTokenV1::mint(
        SnapshotLeaseClaimsV1 {
            version: SNAPSHOT_LEASE_TOKEN_VERSION,
            mac_key_epoch: 3,
            token_id: [0x51; 16],
            repo_id: id(2),
            projection: ProjectionMode::Full,
            generation_digest,
            high_repo_sequence: 12,
            high_event_digest: id(40),
            issued_at_micros: 9_000,
            expires_at_micros: 10_000,
            reader_key_digest: reader_key_digest_or_zero(Some(key(4).public().0)),
        },
        &[0xa5; 32],
    )
    .unwrap()
}

pub fn transaction_page() -> TransactionPageV1 {
    let transaction = committed_transaction();
    TransactionPageV1 {
        repo_id: transaction.repo_id,
        after_repo_sequence: 11,
        after_event_digest: id(39),
        fixed_upper_repo_sequence: 12,
        events: vec![signed_event()],
    }
}

pub fn maintenance_cutover() -> MaintenanceCutoverV1 {
    MaintenanceCutoverV1 {
        storage_format_version: 2,
        minimum_protocol_version: 2,
        v1_post_disabled: true,
        writer_set_digest: id(1),
        peer_set_digest: id(2),
        maintenance_generation: 1,
    }
}

pub fn all_evidence() -> Vec<TransactionEvidenceV1> {
    let context = evidence_context();
    let admin_key = key(8);
    let legacy = TransactionEvidenceV1::LegacyMigrationV1 {
        actor: admin_key.public().0,
        actor_key_epoch: 2,
        migration_id: [0x51; 16],
        repo_id: id(3),
        chunk_ordinal: 1,
        chunk_count: 4,
        chunk_digest: id(81),
        manifest_digest: id(82),
        source_layout_digest: id(83),
        signature: [0; 64],
    };
    let legacy_context = evidence_context_for(&legacy);
    vec![
        TransactionEvidenceV1::ClientV2 {
            signed_envelope: SignedClientOperationV2::Push(signed_normal_push()),
        },
        TransactionEvidenceV1::ClientV2 {
            signed_envelope: SignedClientOperationV2::Push(signed_fork_push()),
        },
        TransactionEvidenceV1::MirrorEventV1 {
            source_instance: key(7).public().0,
            source_key_epoch: 9,
            source_snapshot_digest: snapshot().snapshot.generation_digest().unwrap(),
            source_event: signed_event(),
        },
        TransactionEvidenceV1::MirrorSnapshotV1 {
            source_instance: key(7).public().0,
            source_key_epoch: 9,
            source_snapshot: snapshot(),
            destination_projection: ProjectionMode::Release,
            projected_manifest_digest: id(80),
            projected_object_count: 3,
            projected_object_bytes: 2048,
        },
        legacy
            .sign_administrative(legacy_context, &admin_key)
            .unwrap(),
        TransactionEvidenceV1::ProjectionAdminV1 {
            actor: admin_key.public().0,
            actor_key_epoch: 2,
            command_digest: id(84),
            previous_projection: ProjectionMode::Full,
            new_projection: ProjectionMode::Metadata,
            signature: [0; 64],
        }
        .sign_administrative(context, &admin_key)
        .unwrap(),
        TransactionEvidenceV1::AdministrativeV1 {
            actor: admin_key.public().0,
            actor_key_epoch: 2,
            command_digest: id(85),
            signature: [0; 64],
        }
        .sign_administrative(context, &admin_key)
        .unwrap(),
    ]
}

pub fn staged_projection() -> (
    ProjectionStageSessionV1,
    Vec<ProjectionStageChunkV1>,
    ProjectionStageManifestV1,
    StagedProjectionInstallV1,
) {
    let session_id = [0x61; 16];
    let raw = Blob::new(b"phase-zero-staged-object".to_vec()).serialize();
    let object_id = levcs_core::blake3_hash(&raw);
    let descriptor = StagedObjectV1 {
        object_id,
        object_type: ObjectType::Blob as u8,
        raw_len: raw.len() as u64,
        raw_digest: object_id,
    };
    let chunk = ProjectionStageChunkV1 {
        session_id,
        ordinal: 0,
        chunk_count: 1,
        objects: vec![StagedChunkObjectV1 {
            descriptor: descriptor.clone(),
            raw_bytes: raw,
        }],
    };
    let chunk_digest = chunk.chunk_digest().unwrap();
    let manifest = ProjectionStageManifestV1 {
        session_id,
        chunk_digests: vec![chunk_digest],
        objects: vec![descriptor.clone()],
        membership_root: id(90),
    };
    let manifest_digest = manifest.manifest_digest().unwrap();
    let session = ProjectionStageSessionV1 {
        session_id,
        destination_repo: id(3),
        destination_genesis: id(4),
        expected_authority: id(4),
        projection: ProjectionMode::Full,
        source_kind: StageSourceKindV1::Mirror,
        actor: key(7).public().0,
        actor_key_epoch: 9,
        source_generation_digest: snapshot().snapshot.generation_digest().unwrap(),
        fork_proof: None,
        final_operation_id: [0x62; 16],
        final_operation_digest: id(91),
        final_evidence_digest: id(92),
        total_object_count: 1,
        total_object_bytes: descriptor.raw_len,
        chunk_count: 1,
        manifest_digest,
        expires_at_micros: 100_000,
    };
    let install = StagedProjectionInstallV1 {
        session_id,
        manifest_digest,
        projection: ProjectionMode::Full,
        object_count: 1,
        object_bytes: descriptor.raw_len,
        membership_root: manifest.membership_root,
        artifact_set_digest: id(93),
    };
    (session, vec![chunk], manifest, install)
}

pub fn roundtrip<T>(value: &T)
where
    T: CanonicalCodec + std::fmt::Debug + PartialEq,
{
    let encoded = value.encode_canonical().unwrap();
    assert_eq!(&T::decode_canonical(&encoded).unwrap(), value);
}

pub fn golden_value() -> serde_json::Value {
    let evidence = all_evidence();
    let signed_snapshot = snapshot();
    let committed = committed_transaction();
    let receipt = receipt();
    let (_, chunks, manifest, _) = staged_projection();
    let blob = Blob::new(b"phase-zero-object-golden".to_vec());
    let blob_bytes = blob.serialize();
    let mut retry_operation = signed_normal_push().operation;
    retry_operation.issued_at_micros += 10;
    retry_operation.nonce = [0x99; 16];
    let retry_push = SignedPushOperationV2::sign(retry_operation, &key(1)).unwrap();
    let mut different_genesis_operation = signed_init().operation;
    different_genesis_operation.genesis_hash = id(99);
    let different_genesis =
        SignedInitOperationV2::sign(different_genesis_operation, &key(3)).unwrap();
    let mut pack = levcs_protocol::Pack::new();
    pack.push(ObjectType::Blob as u8, b"phase-0-pack".to_vec());

    let init_client_evidence = SignedClientOperationV2::Init(signed_init());
    let push_body = encode_push_request_body(
        &signed_normal_push(),
        &vec![0xab; signed_normal_push().operation.pack_len as usize],
    )
    .unwrap();
    let init_body = encode_init_request_body(
        &signed_init(),
        &vec![0xcd; signed_init().operation.genesis_len as usize],
    )
    .unwrap();
    let (session, _, _, install) = staged_projection();
    let lease_token = snapshot_lease_token();
    let page = transaction_page();
    let cutover = maintenance_cutover();
    let reads = signed_reads();

    let statuses = [
        TransactionStatusV1::Pending {
            operation_digest: receipt.operation_digest,
            retry_until_micros: receipt.retry_until_micros,
            phase: PendingPhase::Queued,
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

    serde_json::json!({
        "schema_version": 1,
        "objects": {
            "blob_hex": hex::encode(&blob_bytes),
            "blob_id": blob.object_id().to_hex(),
            "pack_v1_hex": hex::encode(pack.encode())
        },
        "vectors": {
            "init_envelope_hex": hex::encode(signed_init().encode_canonical().unwrap()),
            "init_same_id_different_genesis_hex": hex::encode(different_genesis.encode_canonical().unwrap()),
            "normal_push_envelope_hex": hex::encode(signed_normal_push().encode_canonical().unwrap()),
            "normal_push_retry_envelope_hex": hex::encode(retry_push.encode_canonical().unwrap()),
            "fork_evidence_hex": hex::encode(evidence[1].encode_canonical().unwrap()),
            "mirror_event_evidence_hex": hex::encode(evidence[2].encode_canonical().unwrap()),
            "mirror_snapshot_evidence_hex": hex::encode(evidence[3].encode_canonical().unwrap()),
            "legacy_evidence_hex": hex::encode(evidence[4].encode_canonical().unwrap()),
            "projection_admin_evidence_hex": hex::encode(evidence[5].encode_canonical().unwrap()),
            "administrative_evidence_hex": hex::encode(evidence[6].encode_canonical().unwrap()),
            "signed_event_hex": hex::encode(signed_event().encode_canonical().unwrap()),
            "signed_snapshot_hex": hex::encode(signed_snapshot.encode_canonical().unwrap()),
            "signed_private_read_hex": hex::encode(signed_read().encode_canonical().unwrap()),
            "missing_request_hex": hex::encode(MissingObjectsRequestV1 {
                generation_digest: id(71),
                object_ids: vec![id(1), id(2), id(3)]
            }.encode_canonical().unwrap()),
            "stage_chunk_hex": hex::encode(chunks[0].encode_canonical().unwrap()),
            "stage_manifest_hex": hex::encode(manifest.encode_canonical().unwrap()),
            "init_client_evidence_hex": hex::encode(init_client_evidence.encode_canonical().unwrap()),
            "push_body_hex": hex::encode(&push_body),
            "init_body_hex": hex::encode(&init_body),
            "stage_session_hex": hex::encode(session.encode_canonical().unwrap()),
            "staged_install_hex": hex::encode(install.encode_canonical().unwrap()),
            "snapshot_lease_token_hex": hex::encode(lease_token.encode_canonical().unwrap()),
            "transaction_page_hex": hex::encode(page.encode_canonical().unwrap()),
            "maintenance_cutover_hex": hex::encode(cutover.encode_canonical().unwrap()),
            "signed_reads_hex": reads.iter().map(|r| hex::encode(r.encode_canonical().unwrap())).collect::<Vec<_>>()
        },
        "digests": {
            "ref_state": ref_state_digest(&signed_snapshot.snapshot.refs).unwrap().to_hex(),
            "snapshot_generation": signed_snapshot.snapshot.generation_digest().unwrap().to_hex(),
            "event": committed.event_digest().unwrap().to_hex(),
            "fork_evidence": evidence[1].evidence_digest().unwrap().to_hex(),
            "mirror_event_evidence": evidence[2].evidence_digest().unwrap().to_hex(),
            "mirror_snapshot_evidence": evidence[3].evidence_digest().unwrap().to_hex(),
            "legacy_evidence": evidence[4].evidence_digest().unwrap().to_hex(),
            "projection_admin_evidence": evidence[5].evidence_digest().unwrap().to_hex(),
            "administrative_evidence": evidence[6].evidence_digest().unwrap().to_hex(),
            "status_pending": statuses[0].status_digest().unwrap().to_hex(),
            "status_resolving": statuses[1].status_digest().unwrap().to_hex(),
            "status_committed": statuses[2].status_digest().unwrap().to_hex(),
            "status_expired": statuses[3].status_digest().unwrap().to_hex(),
            "status_unknown": statuses[4].status_digest().unwrap().to_hex(),
            "stage_chunk": chunks[0].chunk_digest().unwrap().to_hex(),
            "stage_manifest": manifest.manifest_digest().unwrap().to_hex(),
            "init_stable": signed_init().stable_digest().unwrap().to_hex(),
            "stage_session": session.session_digest().unwrap().to_hex()
        }
    })
}
