//! Golden frame vector generator (scope 4-A1 deliverable 6).
//!
//! `cargo run -p levcs-store --example phase1_frame_golden > \
//!  crates/levcs-store/tests/fixtures/phase1-frames.json`
//!
//! This is the **only** way `tests/fixtures/phase1-frames.json` is produced.
//! `tests/frame_golden.rs` includes this file as a module and asserts the
//! fixture matches a fresh generation byte for byte, which is what turns
//! "encoding is deterministic" into a check rather than a claim.
//!
//! Every input here is a constant. No clock, no randomness, no environment: a
//! vector that changed because the machine changed would be worthless as a
//! format freeze.

use levcs_core::{ObjectId, ObjectType};
use levcs_protocol::v2::{
    CommittedTransactionV1, DurabilityResultV1, ProjectionMode, PushKindV2, PushOperationV2,
    RefMutation, RefStateV1, RefTarget, RepoSnapshotV1, SignedClientOperationV2,
    SignedCommittedTransactionV1, SignedPushOperationV2, SignedRepoSnapshotV1, SourceKindV1,
    StagedProjectionInstallV1, TransactionEvidenceV1, TypedRefCas,
};
use levcs_store::format::{
    digest, Frame, FrameHeader, FrameObjectV1, FrameObjectsV1, FrameReceiptFieldsV1,
    RepositoryCreateV1, TransactionFramePayloadV1, FRAME_PAYLOAD_DIGEST_DOMAIN,
};

/// Fixed journal identity for every vector. A frame is bound to its journal,
/// so the corpus pins one.
pub const GOLDEN_JOURNAL_ID: [u8; 16] = [0x4A; 16];

fn main() {
    println!(
        "{}",
        serde_json::to_string_pretty(&golden_value()).expect("serialize golden vectors")
    );
}

// ---------------------------------------------------------------------------
// Deterministic building blocks
// ---------------------------------------------------------------------------

pub fn id(byte: u8) -> ObjectId {
    ObjectId([byte; 32])
}

fn key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// A fabricated signature.
///
/// The store never verifies a signature — plan §5.1 forbids it from making
/// identity decisions, and scope §1 forbids any call into `levcs-identity`.
/// These vectors therefore carry signature-shaped bytes and assert only that
/// the store transports them byte for byte, which is exactly the property the
/// frame format is responsible for.
fn signature(byte: u8) -> [u8; 64] {
    [byte; 64]
}

fn ref_set(name: &str, expected: Option<u8>, new: u8, force: bool) -> TypedRefCas {
    TypedRefCas {
        target: RefTarget::Branch(name.into()),
        expected: expected.map(id),
        mutation: RefMutation::Set(id(new)),
        force,
    }
}

fn ref_delete(name: &str, expected: u8) -> TypedRefCas {
    TypedRefCas {
        target: RefTarget::Release(name.into()),
        expected: Some(id(expected)),
        mutation: RefMutation::Delete,
        force: false,
    }
}

fn committed(
    source_kind: SourceKindV1,
    repo_sequence: u64,
    old_authority: u8,
    new_authority: u8,
) -> CommittedTransactionV1 {
    CommittedTransactionV1 {
        repo_id: id(0x20),
        repo_sequence,
        previous_event_digest: id(0x21),
        sequenced_at_micros: 1_700_000_000_000_000,
        source_kind,
        actor: key(0x22),
        operation_id: [0x23; 16],
        operation_digest: id(0x24),
        signed_evidence_digest: id(0x25),
        old_authority: id(old_authority),
        new_authority: id(new_authority),
        refs: Vec::new(),
        object_ids: Vec::new(),
        commit_ids: Vec::new(),
        resulting_state_digest: id(0x26),
    }
}

fn signed_committed(transaction: CommittedTransactionV1) -> SignedCommittedTransactionV1 {
    SignedCommittedTransactionV1 {
        transaction,
        source_key_epoch: 7,
        durability_result: DurabilityResultV1::LocallyDurable,
        source_signature: signature(0x27),
    }
}

fn push_operation() -> PushOperationV2 {
    PushOperationV2 {
        operation_id: [0x11; 16],
        repo_id: id(0x20),
        issued_at_micros: 1_000,
        retry_until_micros: 5_000,
        nonce: [0x12; 16],
        expected_authority: id(4),
        authority_update: Some(id(5)),
        updates: vec![ref_set("main", Some(6), 7, false)],
        pack_len: 128,
        pack_hash: id(9),
        snapshot_generation_digest: id(10),
        projection_stage: None,
        kind: PushKindV2::Normal,
    }
}

fn client_evidence() -> TransactionEvidenceV1 {
    TransactionEvidenceV1::ClientV2 {
        signed_envelope: SignedClientOperationV2::Push(SignedPushOperationV2 {
            operation: push_operation(),
            signer: key(0x13),
            signature: signature(0x14),
        }),
    }
}

fn mirror_event_evidence() -> TransactionEvidenceV1 {
    // `validate_structure` requires the outer epoch to equal the signed
    // event's epoch, so the two are written from one value.
    let epoch = 7;
    TransactionEvidenceV1::MirrorEventV1 {
        source_instance: key(0x30),
        source_key_epoch: epoch,
        source_snapshot_digest: id(0x31),
        source_event: SignedCommittedTransactionV1 {
            transaction: committed(SourceKindV1::Client, 4, 0x32, 0x33),
            source_key_epoch: epoch,
            durability_result: DurabilityResultV1::LocallyDurable,
            source_signature: signature(0x34),
        },
    }
}

fn mirror_snapshot_evidence() -> TransactionEvidenceV1 {
    let source_instance = key(0x40);
    let epoch = 9;
    TransactionEvidenceV1::MirrorSnapshotV1 {
        source_instance,
        source_key_epoch: epoch,
        source_snapshot: SignedRepoSnapshotV1 {
            snapshot: RepoSnapshotV1 {
                source_instance,
                source_key_epoch: epoch,
                repo_id: id(0x41),
                genesis_authority: id(0x42),
                current_authority: id(0x43),
                projection: ProjectionMode::Full,
                refs: vec![RefStateV1 {
                    target: RefTarget::Branch("main".into()),
                    object: id(0x44),
                }],
                event_low_repo_sequence: 2,
                object_low_repo_sequence: 1,
                high_repo_sequence: 12,
                high_event_digest: id(0x45),
                resulting_state_digest: id(0x46),
                config_epoch: 3,
                capabilities_digest: id(0x47),
            },
            signature: signature(0x48),
        },
        destination_projection: ProjectionMode::Release,
        projected_manifest_digest: id(0x49),
        projected_object_count: 25,
        projected_object_bytes: 4_096,
    }
}

fn legacy_migration_evidence() -> TransactionEvidenceV1 {
    TransactionEvidenceV1::LegacyMigrationV1 {
        actor: key(0x50),
        actor_key_epoch: 2,
        migration_id: [0x51; 16],
        repo_id: id(0x52),
        chunk_ordinal: 1,
        chunk_count: 4,
        chunk_digest: id(0x53),
        manifest_digest: id(0x54),
        source_layout_digest: id(0x55),
        signature: signature(0x56),
    }
}

fn projection_admin_evidence() -> TransactionEvidenceV1 {
    TransactionEvidenceV1::ProjectionAdminV1 {
        actor: key(0x60),
        actor_key_epoch: 4,
        command_digest: id(0x61),
        previous_projection: ProjectionMode::Full,
        new_projection: ProjectionMode::Metadata,
        signature: signature(0x62),
    }
}

fn administrative_evidence() -> TransactionEvidenceV1 {
    TransactionEvidenceV1::AdministrativeV1 {
        actor: key(0x70),
        actor_key_epoch: 5,
        command_digest: id(0x71),
        signature: signature(0x72),
    }
}

fn evidence_for(kind: SourceKindV1) -> TransactionEvidenceV1 {
    // Exhaustive: a new source kind must break this generator rather than
    // quietly leave the corpus one vector short.
    match kind {
        SourceKindV1::Client => client_evidence(),
        SourceKindV1::MirrorSnapshot => mirror_snapshot_evidence(),
        SourceKindV1::MirrorEvent => mirror_event_evidence(),
        SourceKindV1::LegacyMigration => legacy_migration_evidence(),
        SourceKindV1::ProjectionAdmin => projection_admin_evidence(),
        SourceKindV1::Administrative => administrative_evidence(),
    }
}

pub const ALL_SOURCE_KINDS: [SourceKindV1; 6] = [
    SourceKindV1::Client,
    SourceKindV1::MirrorSnapshot,
    SourceKindV1::MirrorEvent,
    SourceKindV1::LegacyMigration,
    SourceKindV1::ProjectionAdmin,
    SourceKindV1::Administrative,
];

fn base_payload(kind: SourceKindV1) -> TransactionFramePayloadV1 {
    TransactionFramePayloadV1 {
        repository_create: None,
        objects: FrameObjectsV1::Inline(vec![FrameObjectV1 {
            object_type: ObjectType::Blob,
            object_id: id(0x80),
            raw: vec![0xAB; 16],
        }]),
        ref_cas: vec![ref_set("main", Some(6), 7, false)],
        expected_authority: id(4),
        new_authority: id(4),
        evidence: evidence_for(kind),
        committed: signed_committed(committed(kind, 1, 4, 4)),
        receipt: FrameReceiptFieldsV1 {
            objects_new: 1,
            retry_until_micros: 5_000,
            first_receipt_visibility_micros: 1_700_000_000_000_000,
        },
    }
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

struct Vector {
    name: &'static str,
    description: &'static str,
    frame: Frame,
}

fn frame_from(
    shard_sequence: u64,
    repo_sequence: u64,
    namespace: u8,
    operation: u8,
    payload: Vec<u8>,
) -> Frame {
    let payload_len = payload.len() as u64;
    Frame {
        header: FrameHeader {
            flags: 0,
            total_len: levcs_store::format::frame_total_len(payload_len),
            journal_id: GOLDEN_JOURNAL_ID,
            shard_sequence,
            repo_sequence,
            namespace: [namespace; 32],
            operation_id: [operation; 16],
            operation_digest: id(operation),
            payload_len,
            payload_digest: digest(FRAME_PAYLOAD_DIGEST_DOMAIN, &payload),
        },
        payload,
    }
}

fn encode(payload: &TransactionFramePayloadV1) -> Vec<u8> {
    payload.encode_canonical().expect("canonical frame payload")
}

fn vectors() -> Vec<Vector> {
    let mut out = Vec::new();

    // The physical minimum: a zero-length payload, `total_len == 224`. A
    // `Frame` carries opaque payload bytes precisely so completeness stays a
    // physical property, and this vector pins the smallest thing the
    // completeness definition must accept.
    out.push(Vector {
        name: "minimum-frame",
        description: "smallest physically valid frame: empty payload, total_len 224",
        frame: frame_from(0, 0, 0x00, 0x00, Vec::new()),
    });

    // Repository create.
    let mut payload = base_payload(SourceKindV1::Client);
    payload.repository_create = Some(RepositoryCreateV1 {
        genesis_authority: id(0x90),
        genesis_len: 777,
        genesis_hash: id(0x91),
        projection: ProjectionMode::Full,
    });
    out.push(Vector {
        name: "repository-create",
        description: "carries repository-create metadata (genesis authority, length, hash)",
        frame: frame_from(1, 0, 0x01, 0x01, encode(&payload)),
    });

    // Multiple inline objects, strictly ascending by ObjectId.
    let mut payload = base_payload(SourceKindV1::Client);
    payload.objects = FrameObjectsV1::Inline(vec![
        FrameObjectV1 {
            object_type: ObjectType::Blob,
            object_id: id(0xA0),
            raw: vec![0x01; 16],
        },
        FrameObjectV1 {
            object_type: ObjectType::Tree,
            object_id: id(0xA1),
            raw: vec![0x02; 24],
        },
        FrameObjectV1 {
            object_type: ObjectType::Commit,
            object_id: id(0xA2),
            raw: vec![0x03; 32],
        },
    ]);
    payload.receipt.objects_new = 3;
    out.push(Vector {
        name: "multi-object",
        description: "three inline new objects of three embedded types",
        frame: frame_from(2, 1, 0x02, 0x02, encode(&payload)),
    });

    // A multi-ref transaction mixing Set and Delete. Multi-ref atomicity is a
    // Phase 1 exit criterion, and it starts with the whole CAS set living in
    // one frame.
    let mut payload = base_payload(SourceKindV1::Client);
    payload.ref_cas = vec![
        ref_set("main", Some(0xB0), 0xB1, false),
        ref_set("topic/one", None, 0xB2, false),
        ref_delete("v1.0", 0xB3),
        ref_set("feature-x", Some(0xB4), 0xB5, true),
    ];
    out.push(Vector {
        name: "multi-ref-set-and-delete",
        description: "four typed ref CAS entries mixing Set, create-only Set, forced Set, Delete",
        frame: frame_from(3, 2, 0x03, 0x03, encode(&payload)),
    });

    // Authority transition: expected != new.
    let mut payload = base_payload(SourceKindV1::Client);
    payload.expected_authority = id(0xC0);
    payload.new_authority = id(0xC1);
    payload.committed = signed_committed(committed(SourceKindV1::Client, 3, 0xC0, 0xC1));
    out.push(Vector {
        name: "authority-transition",
        description: "expected and new current authority differ",
        frame: frame_from(4, 3, 0x04, 0x04, encode(&payload)),
    });

    // Staged projection install: exactly one descriptor and no inline object.
    let mut payload = base_payload(SourceKindV1::ProjectionAdmin);
    payload.objects = FrameObjectsV1::StagedProjectionInstall(StagedProjectionInstallV1 {
        session_id: [0xD0; 16],
        manifest_digest: id(0xD1),
        projection: ProjectionMode::Release,
        object_count: 1_000,
        object_bytes: 4_194_304,
        membership_root: id(0xD2),
        artifact_set_digest: id(0xD3),
    });
    payload.receipt.objects_new = 1_000;
    out.push(Vector {
        name: "staged-projection-install",
        description: "one StagedProjectionInstallV1 descriptor instead of inline objects",
        frame: frame_from(5, 4, 0x05, 0x05, encode(&payload)),
    });

    // One frame per SourceKindV1.
    for (index, kind) in ALL_SOURCE_KINDS.into_iter().enumerate() {
        let payload = base_payload(kind);
        let name: &'static str = match kind {
            SourceKindV1::Client => "source-kind-client",
            SourceKindV1::MirrorSnapshot => "source-kind-mirror-snapshot",
            SourceKindV1::MirrorEvent => "source-kind-mirror-event",
            SourceKindV1::LegacyMigration => "source-kind-legacy-migration",
            SourceKindV1::ProjectionAdmin => "source-kind-projection-admin",
            SourceKindV1::Administrative => "source-kind-administrative",
        };
        out.push(Vector {
            name,
            description: "one frame per SourceKindV1, with the matching evidence variant",
            frame: frame_from(
                6 + index as u64,
                5 + index as u64,
                0x10 + index as u8,
                0x10 + index as u8,
                encode(&payload),
            ),
        });
    }

    // Maximum-sequence edges. `shard_sequence` and `repo_sequence` are
    // independent domains (plan §4 transaction invariant 8), so each maximum
    // is its own vector rather than one frame carrying both.
    let payload = base_payload(SourceKindV1::Client);
    out.push(Vector {
        name: "max-shard-sequence",
        description: "shard_sequence == u64::MAX",
        frame: frame_from(u64::MAX, 6, 0x30, 0x30, encode(&payload)),
    });
    let payload = base_payload(SourceKindV1::Client);
    out.push(Vector {
        name: "max-repo-sequence",
        description: "repo_sequence == u64::MAX",
        frame: frame_from(12, u64::MAX, 0x31, 0x31, encode(&payload)),
    });
    let payload = base_payload(SourceKindV1::Client);
    out.push(Vector {
        name: "max-both-sequences",
        description: "shard_sequence and repo_sequence both u64::MAX",
        frame: frame_from(u64::MAX, u64::MAX, 0x32, 0x32, encode(&payload)),
    });

    out
}

/// The golden document. Stable key order comes from `serde_json`'s default
/// `BTreeMap`-backed object.
pub fn golden_value() -> serde_json::Value {
    let vectors: Vec<serde_json::Value> = vectors()
        .into_iter()
        .map(|vector| {
            let bytes = vector.frame.encode().expect("golden frames must encode");
            let header = &vector.frame.header;
            serde_json::json!({
                "name": vector.name,
                "description": vector.description,
                "shard_sequence": header.shard_sequence.to_string(),
                "repo_sequence": header.repo_sequence.to_string(),
                "namespace": hex::encode(header.namespace),
                "operation_id": hex::encode(header.operation_id),
                "operation_digest": hex::encode(header.operation_digest.as_bytes()),
                "journal_id": hex::encode(header.journal_id),
                "payload_len": header.payload_len.to_string(),
                "total_len": header.total_len.to_string(),
                "payload_digest": hex::encode(header.payload_digest.as_bytes()),
                "frame_digest": hex::encode(&bytes[bytes.len() - 32..]),
                "frame_hex": hex::encode(&bytes),
            })
        })
        .collect();

    serde_json::json!({
        "storage_version": levcs_store::format::STORAGE_VERSION,
        "frame_header_len": levcs_store::format::FRAME_HEADER_LEN,
        "frame_trailer_len": levcs_store::format::FRAME_TRAILER_LEN,
        "journal_header_len": levcs_store::format::JOURNAL_HEADER_LEN,
        "frames": vectors,
    })
}
