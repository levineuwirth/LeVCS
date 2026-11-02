//! Scope 6-B1 deliverable 3 and scope 6.2 item 9 — `adopt_projection` through
//! `StoreEngine::submit`, asserted through the public surface.
//!
//! The property under test is **ownership**, not visibility. An adopted
//! projection's objects are not in the frame that installed them: the frame
//! carries a descriptor, and the bytes stay in the artifacts staging sealed. So
//! two things have to be true at once, and each has a distinct way of being
//! wrong:
//!
//! 1. Each object is indexed at its **artifact's** logical generation, not at
//!    the frame's. Indexing at the frame location would still make `locate`
//!    return `Some`, and a reader following it would land at an offset inside a
//!    journal frame that contains a descriptor rather than the object — a
//!    plausible-looking answer that decodes into nothing.
//! 2. Those artifact generations survive the next retained generation. A
//!    checkpoint publishes a successor and releases the predecessor's pins; an
//!    adoption whose artifacts are not carried forward reads correctly exactly
//!    once and then resolves to nothing, with no error at the moment the
//!    mistake is made.
//!
//! One test catches both, which is why it is the first one written: locate and
//! resolve every object, checkpoint into a successor generation, then locate
//! and resolve all of them again. Failure 1 shows up in the first resolve,
//! failure 2 only in the second.
//!
//! **At least two chunks, always.** A single-chunk projection has exactly one
//! artifact, so "the index resolved every object to the right artifact" and
//! "the index resolved every object to the only artifact there is" are the same
//! observation, and B3 defines and resolves one `IndexLocation` per chunk. Two
//! chunks is the smallest arrangement where per-chunk ownership is load-bearing.

// The same three-feature gate as `namespace_snapshot.rs`, for the same reason:
// `engine_matrix` arms failpoints and reaches `drive.rs`, so it compiles only
// under the full set, and the Phase 1 gate runs exactly this combination.
#![cfg(all(
    feature = "store-privileged",
    feature = "store-internals",
    feature = "failpoints"
))]

use levcs_core::{blake3_hash, ObjectHeader, ObjectId, ObjectType, FORMAT_VERSION};
use levcs_protocol::v2::{
    ProjectionMode, ProjectionStageChunkV1, ProjectionStageManifestV1, ProjectionStageSessionV1,
    StageSourceKindV1, StagedChunkObjectV1, StagedObjectV1,
};
use levcs_store::staging::{ProjectionStageBinding, StagedProjectionAdoption};
use levcs_store::types::NamespaceId;
use levcs_store::{RetainedObjectSource, StoreEngine, ValidatedTransaction};

#[path = "support/engine_matrix.rs"]
mod engine_matrix;

use engine_matrix::{
    create_transaction, deadline, evidence, genesis_id, namespace_on_shard, now_micros,
    open_absent_root, push_transaction, submit, DEFAULT_MAX_INDEX_RUNS,
};

const SHARD_COUNT: u16 = 2;
const CHUNKS: u32 = 2;
const PER_CHUNK: usize = 2;
const HOUR_MICROS: i64 = 3_600_000_000;

// ---------------------------------------------------------------------------
// A projection bound to a repository the engine actually created
// ---------------------------------------------------------------------------

struct Staged {
    binding: ProjectionStageBinding,
    chunks: Vec<ProjectionStageChunkV1>,
}

impl Staged {
    /// Every object across every chunk, in no particular order — the test
    /// asserts about all of them and never about their arrangement.
    fn object_ids(&self) -> Vec<ObjectId> {
        self.chunks
            .iter()
            .flat_map(|chunk| chunk.objects.iter())
            .map(|object| object.descriptor.object_id)
            .collect()
    }
}

fn blob(body: &[u8]) -> StagedChunkObjectV1 {
    let mut raw = ObjectHeader {
        object_type: ObjectType::Blob,
        format_version: FORMAT_VERSION,
        body_len: body.len() as u64,
    }
    .encode()
    .to_vec();
    raw.extend_from_slice(body);
    let id = blake3_hash(&raw);
    StagedChunkObjectV1 {
        descriptor: StagedObjectV1 {
            object_id: id,
            object_type: ObjectType::Blob as u8,
            raw_len: raw.len() as u64,
            raw_digest: id,
        },
        raw_bytes: raw,
    }
}

/// A self-consistent projection bound to `namespace`.
///
/// The binding's `destination_repo`, `destination_genesis`, and
/// `expected_authority` are taken from the repository the engine created rather
/// than from constants. A projection bound to a repository that does not exist
/// is a different refusal entirely, and one bound to the wrong authority is
/// another; neither is what this file is about.
fn staged_projection(namespace: NamespaceId, session_id: [u8; 16], actor: [u8; 32]) -> Staged {
    let total = CHUNKS as usize * PER_CHUNK;
    let mut objects: Vec<StagedChunkObjectV1> = (0..total)
        .map(|index| blob(format!("adopted-{}-{index}", hex::encode(session_id)).as_bytes()))
        .collect();
    // The manifest is the ordered concatenation of the chunks and must be
    // strictly sorted, so the sort happens before the split, not inside each
    // chunk.
    objects.sort_by(|left, right| left.descriptor.cmp(&right.descriptor));

    let total_object_bytes = objects
        .iter()
        .map(|object| object.descriptor.raw_len)
        .sum::<u64>();
    let descriptors: Vec<StagedObjectV1> = objects
        .iter()
        .map(|object| object.descriptor.clone())
        .collect();

    let chunks: Vec<ProjectionStageChunkV1> = (0..CHUNKS)
        .map(|ordinal| {
            let start = ordinal as usize * PER_CHUNK;
            ProjectionStageChunkV1 {
                session_id,
                ordinal,
                chunk_count: CHUNKS,
                objects: objects[start..start + PER_CHUNK].to_vec(),
            }
        })
        .collect();
    let chunk_digests: Vec<ObjectId> = chunks
        .iter()
        .map(|chunk| chunk.chunk_digest().expect("chunk digest"))
        .collect();

    // The instance layer's commitment. B3 stores it and proves the manifest
    // digest binds it; nothing in the store evaluates it.
    let membership_root = blake3_hash(&session_id[..]);
    let manifest = ProjectionStageManifestV1 {
        session_id,
        chunk_digests,
        objects: descriptors,
        membership_root,
    };
    let manifest_digest = manifest.manifest_digest().expect("manifest digest");
    let authority = genesis_id(&namespace);

    Staged {
        binding: ProjectionStageBinding {
            session: ProjectionStageSessionV1 {
                session_id,
                destination_repo: ObjectId(*namespace.as_bytes()),
                destination_genesis: authority,
                expected_authority: authority,
                projection: ProjectionMode::Full,
                source_kind: StageSourceKindV1::Mirror,
                actor,
                actor_key_epoch: 3,
                source_generation_digest: ObjectId([12; 32]),
                fork_proof: None,
                final_operation_id: [13; 16],
                final_operation_digest: ObjectId([14; 32]),
                final_evidence_digest: ObjectId([15; 32]),
                total_object_count: total as u64,
                total_object_bytes,
                chunk_count: CHUNKS,
                manifest_digest,
                expires_at_micros: now_micros() + HOUR_MICROS,
            },
            membership_root,
        },
        chunks,
    }
}

/// Stage the projection through the engine's own staging and take the pin.
///
/// Through `engine.staging()` and not a second `ProjectionStaging`: staging's
/// ceilings are root-global and its constructor demands the root lock, so a
/// test that opened its own would be a second accountant for one root and would
/// prove the property against a staging the store does not use.
fn stage_and_finalize(engine: &StoreEngine, staged: &Staged) -> StagedProjectionAdoption {
    let session = engine
        .staging()
        .begin(staged.binding.clone(), now_micros())
        .expect("staging admits the session");
    for chunk in &staged.chunks {
        session.put_chunk(chunk, now_micros()).expect("chunk lands");
    }
    session.seal(now_micros()).expect("the session seals");
    session
        .finalize(now_micros())
        .expect("the sealed session yields an adoption pin")
}

fn adopting_transaction(
    namespace: NamespaceId,
    operation: u8,
    adoption: StagedProjectionAdoption,
) -> ValidatedTransaction {
    let authority = genesis_id(&namespace);
    ValidatedTransaction::builder(levcs_store::types::PrivilegedConstruction::assert_validated())
        .namespace(namespace)
        .operation(
            levcs_store::types::OperationId([operation; 16]),
            ObjectId([operation; 32]),
            deadline(),
        )
        // Empty, and not a convenience: `FrameObjectsV1` is an enum, so a frame
        // carries inline objects or an install descriptor and never both. The
        // projection *is* this transaction's payload.
        .objects(Vec::new())
        .refs(Vec::new())
        .authority(Some(authority), Some(authority))
        .evidence(evidence())
        .adopt_projection(adoption)
        .expect("the builder admits one adoption")
        .build()
        .expect("a complete adopting transaction")
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[test]
fn an_adopted_projection_is_owned_by_its_artifacts_and_survives_a_checkpoint() {
    let directory = tempfile::TempDir::new().expect("a temporary root");
    let engine = open_absent_root(directory.path(), SHARD_COUNT, DEFAULT_MAX_INDEX_RUNS);
    let namespace = namespace_on_shard(0, SHARD_COUNT, 1);

    submit(&engine, create_transaction(namespace, 1))
        .receipt()
        .expect("the repository is created");

    let staged = staged_projection(namespace, [25; 16], [21; 32]);
    let ids = staged.object_ids();
    assert_eq!(
        ids.len(),
        CHUNKS as usize * PER_CHUNK,
        "the fixture must produce one object per chunk slot"
    );

    // Nothing staged is visible before a submit adopts it. Asserted before the
    // adoption so a later `Some` is evidence the adoption produced it, rather
    // than something that was always there.
    let before = engine.snapshot(namespace).expect("snapshot");
    for id in &ids {
        assert_eq!(
            before.locate(*id).expect("locate"),
            None,
            "a sealed but unadopted object must not be visible"
        );
    }

    let adoption = stage_and_finalize(&engine, &staged);
    let committed = submit(&engine, adopting_transaction(namespace, 2, adoption));
    committed
        .receipt()
        .unwrap_or_else(|| panic!("the adoption must commit: {:?}", committed.error()));

    let adopted = engine.snapshot(namespace).expect("snapshot");
    let generations = resolve_all(&adopted, &ids, "immediately after adoption");

    // A checkpoint publishes a successor retained generation and releases the
    // predecessor's pins. This is the moment an adoption that was never carried
    // forward stops resolving.
    engine.checkpoint().expect("the store checkpoints");

    let after = engine.snapshot(namespace).expect("snapshot");
    let survived = resolve_all(&after, &ids, "after a checkpoint");

    assert_eq!(
        generations, survived,
        "an adopted object's generation must not move when a successor generation is published; \
         the artifacts are the same files either side of the checkpoint"
    );
}

/// An adoption is admitted against the same run ceilings a seal enforces, and
/// it may land exactly on them. Landing there while mergeable manifest rows
/// still held slots used to hand every later seal a zero install budget: the
/// compaction trigger fired, nothing could install, and every admission that
/// reached the seal repeated the refusal. Admission now compacts first, so
/// the rows return their headroom before the adoption claims it.
#[test]
fn an_adoption_near_the_run_ceiling_compacts_rather_than_wedging_the_seal() {
    let directory = tempfile::TempDir::new().expect("a temporary root");
    // Ceiling three: two sealed rows plus this adoption's one staged run land
    // exactly on it.
    let engine = open_absent_root(directory.path(), 1, 3);
    let namespace = namespace_on_shard(0, 1, 1);
    submit(&engine, create_transaction(namespace, 1))
        .receipt()
        .expect("the repository is created");

    // Two sealed manifest rows: each push is its own group and layer, and the
    // fan-out ceiling seals on the admission that finds three layers.
    for step in 0u8..6 {
        let pushed = submit(
            &engine,
            push_transaction(namespace, 0x30 + step, 0x30 + step),
        );
        pushed
            .receipt()
            .unwrap_or_else(|| panic!("push {step} commits: {:?}", pushed.error()));
    }

    let staged = staged_projection(namespace, [26; 16], [22; 32]);
    let ids = staged.object_ids();
    let adoption = stage_and_finalize(&engine, &staged);
    let committed = submit(&engine, adopting_transaction(namespace, 0x50, adoption));
    committed.receipt().unwrap_or_else(|| {
        panic!(
            "the adoption commits at the ceiling: {:?}",
            committed.error()
        )
    });

    // The admission compacted before claiming the slot: the manifest now names
    // the merge of the two rows, not the rows beside a resident staged run.
    let layout = levcs_store::segment::RootLayout::new(directory.path());
    let uuid = levcs_store::segment::read_format(&layout)
        .expect("FORMAT")
        .root_uuid;
    let paths = layout.shard(0);
    let pointer = levcs_store::segment::read_current(&paths, &uuid)
        .expect("read CURRENT")
        .expect("a sealed store has a CURRENT");
    let rows = levcs_store::segment::read_manifest(&paths, pointer.generation, &uuid)
        .expect("read the current manifest")
        .index_runs;
    assert_eq!(
        rows.len(),
        1,
        "admission must merge the mergeable rows before the adoption lands, found {rows:?}"
    );

    // The seal after the adoption is the wedge this test pins: three more
    // layers and the admission that finds them must seal, not refuse.
    for step in 0u8..3 {
        let pushed = submit(
            &engine,
            push_transaction(namespace, 0x60 + step, 0x60 + step),
        );
        pushed.receipt().unwrap_or_else(|| {
            panic!(
                "push {step} after the adoption commits: {:?}",
                pushed.error()
            )
        });
    }

    // And the adoption's objects still resolve after that seal.
    let snapshot = engine.snapshot(namespace).expect("snapshot");
    for id in &ids {
        assert!(
            snapshot.locate(*id).expect("locate").is_some(),
            "adopted object {} must survive the compaction and the seal after it",
            id.to_hex()
        );
    }
}

/// Staging outlives the engine, so the root lock has to outlive it too.
///
/// `StoreEngine::staging` hands out a reference, but a reference is not a
/// lifetime bound on what a caller may keep: `Arc::clone` escapes it, and so do
/// a `ProjectionStageSession` and an adoption pin, each of which owns a clone.
/// If `LOCK` were released when the engine dropped, any of those could still
/// write into a root another process had since opened.
///
/// Asserted against `RecoverySession::open` rather than against a second
/// `StoreEngine::open`, deliberately. Staging keeps an in-process registry of
/// open roots, so an engine open would be refused by *that* whether or not the
/// lock were held — a passing test proving nothing about the lock. Taking the
/// lock directly is the only form of this assertion that fails when the lease
/// is not retained.
#[test]
fn a_retained_staging_holds_the_root_lock_past_the_engine() {
    let directory = tempfile::TempDir::new().expect("a temporary root");
    let engine = open_absent_root(directory.path(), SHARD_COUNT, DEFAULT_MAX_INDEX_RUNS);
    let staging = std::sync::Arc::clone(engine.staging());
    drop(engine);

    let contested = levcs_store::recovery::RecoverySession::open(directory.path());
    assert!(
        contested.is_err(),
        "the root lock must still be held while staging is retained, but a second session took \
         it: {contested:?}"
    );

    drop(staging);
    levcs_store::recovery::RecoverySession::open(directory.path())
        .expect("the lock is released once the last staging reference is gone");
}

/// Locate every id, require an artifact source for each, and hand back the
/// generations so the caller can compare them across a checkpoint.
///
/// Requiring `ProjectionArtifact` and not merely `Some` is the whole point:
/// an object indexed at the installing frame's location resolves to a tail or a
/// segment and would satisfy a `Some` assertion perfectly.
fn resolve_all(
    snapshot: &levcs_store::RepoSnapshot,
    ids: &[ObjectId],
    when: &str,
) -> Vec<(ObjectId, u64)> {
    let mut generations = Vec::with_capacity(ids.len());
    for id in ids {
        let location = snapshot
            .locate(*id)
            .expect("locate")
            .unwrap_or_else(|| panic!("object {} is not visible {when}", hex::encode(id.0)));
        let source = snapshot
            .object_source(&location)
            .expect("resolving a location this snapshot produced")
            .unwrap_or_else(|| {
                panic!(
                    "object {} resolves to no retained source {when}: generation {} is not \
                     retained, so its artifact was not carried forward",
                    hex::encode(id.0),
                    location.segment_generation
                )
            });
        match source {
            RetainedObjectSource::ProjectionArtifact(_) => {}
            other => panic!(
                "object {} resolves to {:?} {when}, not a projection artifact: it was indexed at \
                 the installing frame's location rather than at its chunk's",
                hex::encode(id.0),
                std::mem::discriminant(&other)
            ),
        }
        generations.push((*id, location.segment_generation));
    }
    generations
}
