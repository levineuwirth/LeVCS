//! B3 StagingSessions — scope 6.5 deliverables 1-5, asserted through the
//! entry points a consumer actually calls.
//!
//! Charter item 8 is the organizing rule here. Every bound, every refusal, and
//! every durability claim below is driven through `ProjectionStaging::begin`,
//! `ProjectionStageSession::put_chunk`, `::seal`, `::abort`, or
//! `ProjectionStaging::expire` — never through an internal helper. A helper
//! that enforces a ceiling correctly and is not on the path `begin` takes is
//! not a bound; it is a decoy that makes this file look finished.
//!
//! Charter item 7 is the second rule: occupancy and sync behavior are read out
//! of `StagingCounters` and `DurabilityCounters`, not asserted about.

use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;

use levcs_core::{blake3_hash, ObjectHeader, ObjectId, ObjectType, FORMAT_VERSION};
use levcs_protocol::v2::{
    validate_projection_stage_binding, ProjectionMode, ProjectionStageChunkV1,
    ProjectionStageSessionV1, StageSourceKindV1, StagedChunkObjectV1, StagedObjectV1,
};
use levcs_store::recovery::RecoverySession;
use levcs_store::segment::{initialize_root, RootLayout};
use levcs_store::staging::{
    ChunkPutOutcome, ProjectionStageBinding, ProjectionStaging, StagedSessionState,
};
use levcs_store::{CommittedRoot, DurabilityCounters, NamespaceId, StoreError, StoreOptions};
use tempfile::TempDir;

const HOUR_MICROS: i64 = 3_600_000_000;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A real v2 store root plus the held root lock.
///
/// The lock is part of the fixture because it is part of the constructor:
/// staging's ceilings are root-global, and `ProjectionStaging::open` requires
/// proof that this process holds `<root>/LOCK` so a second accountant for one
/// root is not expressible. A fixture that forged its way past that would test
/// a constructor production cannot reach.
struct Root {
    directory: TempDir,
    lock: RecoverySession,
    options: StoreOptions,
}

impl Root {
    fn new() -> Self {
        Self::with(|_| {})
    }

    fn with(mutate: impl FnOnce(&mut StoreOptions)) -> Self {
        let directory = TempDir::new().unwrap();
        let mut options = StoreOptions::new(directory.path());
        options.shard_count = 4;
        mutate(&mut options);
        initialize_root(
            &RootLayout::new(directory.path()),
            options.shard_count,
            [42; 16],
            0,
            &DurabilityCounters::default(),
        )
        .expect("v2 root layout");
        let lock = RecoverySession::open(directory.path()).expect("root lock");
        Self {
            directory,
            lock,
            options,
        }
    }

    fn path(&self) -> &std::path::Path {
        self.directory.path()
    }

    fn open(&self) -> (Arc<ProjectionStaging>, Arc<DurabilityCounters>) {
        let durability = Arc::new(DurabilityCounters::default());
        let staging = self.open_with(Arc::clone(&durability));
        (staging, durability)
    }

    fn open_with(&self, durability: Arc<DurabilityCounters>) -> Arc<ProjectionStaging> {
        ProjectionStaging::open(&self.lock, self.options.clone(), durability)
            .expect("staging root opens")
    }

    fn session_directory(&self, session_id: [u8; 16]) -> std::path::PathBuf {
        let shard = StoreOptions::shard_of(&NamespaceId([7; 32]), self.options.shard_count);
        self.path()
            .join("staging")
            .join(format!("{shard:02}"))
            .join(hex::encode(session_id))
    }
}

/// One canonical unsigned object. Real bytes, because the frozen chunk codec
/// parses them and checks the embedded type against the outer descriptor.
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

struct Fixture {
    binding: ProjectionStageBinding,
    chunks: Vec<ProjectionStageChunkV1>,
}

impl Fixture {
    fn session_id(&self) -> [u8; 16] {
        self.binding.session.session_id
    }
}

/// Build a self-consistent projection: globally sorted objects split into
/// `chunk_count` chunks, the manifest they reconstruct to, and a session bound
/// to that manifest's digest.
fn projection(
    session_id: [u8; 16],
    actor: [u8; 32],
    chunk_count: u32,
    per_chunk: usize,
    expires_at_micros: i64,
) -> Fixture {
    assert!(chunk_count >= 1 && per_chunk >= 1);
    let total = chunk_count as usize * per_chunk;
    let mut objects: Vec<StagedChunkObjectV1> = (0..total)
        .map(|index| blob(format!("staged-object-{}-{index}", hex::encode(session_id)).as_bytes()))
        .collect();
    // The manifest must be strictly sorted, and the manifest is the ordered
    // concatenation of the chunks, so the global sort has to happen before the
    // split rather than inside each chunk.
    objects.sort_by(|left, right| left.descriptor.cmp(&right.descriptor));

    let total_object_bytes = objects
        .iter()
        .map(|object| object.descriptor.raw_len)
        .sum::<u64>();
    let descriptors: Vec<StagedObjectV1> = objects
        .iter()
        .map(|object| object.descriptor.clone())
        .collect();

    let mut chunks = Vec::with_capacity(chunk_count as usize);
    for ordinal in 0..chunk_count {
        let start = ordinal as usize * per_chunk;
        chunks.push(ProjectionStageChunkV1 {
            session_id,
            ordinal,
            chunk_count,
            objects: objects[start..start + per_chunk].to_vec(),
        });
    }
    let chunk_digests: Vec<ObjectId> = chunks
        .iter()
        .map(|chunk| chunk.chunk_digest().expect("chunk digest"))
        .collect();

    // The membership root is the instance layer's commitment, not the store's.
    // Any stable value works here; B3 stores it and proves the manifest digest
    // binds it, and evaluates nothing about it.
    let membership_root = blake3_hash(&session_id[..]);
    let manifest = levcs_protocol::v2::ProjectionStageManifestV1 {
        session_id,
        chunk_digests,
        objects: descriptors,
        membership_root,
    };
    let manifest_digest = manifest.manifest_digest().expect("manifest digest");

    Fixture {
        binding: ProjectionStageBinding {
            session: ProjectionStageSessionV1 {
                session_id,
                destination_repo: ObjectId([7; 32]),
                destination_genesis: ObjectId([8; 32]),
                expected_authority: ObjectId([9; 32]),
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
                chunk_count,
                manifest_digest,
                expires_at_micros,
            },
            membership_root,
        },
        chunks,
    }
}

// ---------------------------------------------------------------------------
// Deliverable 1 and 2 — lifecycle and the canonical binding
// ---------------------------------------------------------------------------

#[test]
fn seal_reconstructs_a_manifest_the_frozen_binding_validator_accepts() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([1; 16], [21; 32], 3, 2, HOUR_MICROS);

    let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
    for chunk in &fixture.chunks {
        assert_eq!(
            session.put_chunk(chunk, 0).expect("put"),
            ChunkPutOutcome::Stored
        );
    }
    let install = session.seal(0).expect("seal");
    let resolution = session.resolve().expect("resolve");

    // The frozen validator is the oracle, not a second opinion assembled here.
    // Seal composes chunk digests, manifest position, totals, and the install
    // descriptor from its own on-disk state; this proves that composition is
    // exactly what the contract accepts.
    validate_projection_stage_binding(
        &fixture.binding.session,
        &fixture.chunks,
        &resolution.manifest,
        &install,
    )
    .expect("the sealed descriptor must satisfy the frozen binding contract");

    assert_eq!(install.session_id, fixture.session_id());
    assert_eq!(install.projection, fixture.binding.session.projection);
    assert_eq!(
        install.object_count,
        fixture.binding.session.total_object_count
    );
    assert_eq!(
        install.object_bytes,
        fixture.binding.session.total_object_bytes
    );
    assert_eq!(
        install.manifest_digest,
        fixture.binding.session.manifest_digest
    );
    assert_eq!(install.membership_root, fixture.binding.membership_root);
    assert_eq!(resolution.artifacts.len(), fixture.chunks.len());

    let status = session.describe().expect("describe");
    assert_eq!(status.state, StagedSessionState::Sealed);
    assert_eq!(status.chunks_present, status.chunks_expected);
    assert_eq!(staging.counters().sessions_sealed.load(Relaxed), 1);
}

/// The security property, from the side this pass can prove.
///
/// A sealed session yields a *descriptor* and a read-only resolution. It does
/// not yield an adoption capability: `ProjectionAdoption` has no public
/// constructor and `finalize` is crate-private, so nothing outside the crate
/// can turn possession of a session ID into something `submit` would accept.
/// The other half — that the objects are invisible to a reader until a
/// `submit` adopts the descriptor — is
/// `sealed_objects_stay_invisible_until_a_submit_adopts_them` below, and is
/// blocked on B1.
#[test]
fn sealing_yields_a_descriptor_and_no_adoption_capability() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([2; 16], [21; 32], 1, 2, HOUR_MICROS);
    let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
    session.put_chunk(&fixture.chunks[0], 0).expect("put");
    session.seal(0).expect("seal");

    // Resolution is read-only: it hands back shared immutable state, so an
    // adopter can reject it but cannot repair it.
    let first = session.resolve().expect("resolve");
    let second = session.resolve().expect("resolve");
    assert!(Arc::ptr_eq(&first, &second));

    // A sealed session is immutable: a further chunk put is refused rather
    // than quietly extending a projection somebody has already been handed a
    // descriptor for.
    let result = session.put_chunk(&fixture.chunks[0], 0);
    let Err(StoreError::Conflict(message)) = result else {
        panic!("a sealed session must refuse further chunks, got {result:?}");
    };
    assert!(message.contains("sealed"), "{message}");
}

#[test]
fn chunk_put_is_idempotent_by_ordinal_and_digest_and_costs_no_second_write() {
    let root = Root::new();
    let (staging, durability) = root.open();
    let fixture = projection([3; 16], [21; 32], 2, 1, HOUR_MICROS);
    let session = staging.begin(fixture.binding.clone(), 0).expect("begin");

    assert_eq!(
        session.put_chunk(&fixture.chunks[0], 0).expect("put"),
        ChunkPutOutcome::Stored
    );
    let after_first = durability.snapshot();

    assert_eq!(
        session.put_chunk(&fixture.chunks[0], 0).expect("repeat"),
        ChunkPutOutcome::AlreadyPresent
    );
    // Counters, not claims: a restart re-offering a chunk performs no write,
    // no fence, and no directory sync.
    assert_eq!(durability.snapshot(), after_first);
    assert_eq!(staging.counters().chunks_deduplicated.load(Relaxed), 1);
    assert_eq!(staging.counters().chunks_written.load(Relaxed), 1);
}

#[test]
fn a_different_digest_at_a_bound_ordinal_is_refused() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([4; 16], [21; 32], 2, 1, HOUR_MICROS);
    let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
    session.put_chunk(&fixture.chunks[0], 0).expect("put");

    // Chunk 1's objects offered at ordinal 0: same session, same declared
    // chunk count, different bytes.
    let impostor = ProjectionStageChunkV1 {
        session_id: fixture.session_id(),
        ordinal: 0,
        chunk_count: fixture.binding.session.chunk_count,
        objects: fixture.chunks[1].objects.clone(),
    };
    let result = session.put_chunk(&impostor, 0);
    let Err(StoreError::Conflict(message)) = result else {
        panic!("a rebound ordinal must be refused, got {result:?}");
    };
    assert!(message.contains("already bound to digest"), "{message}");
    assert_eq!(staging.counters().chunks_written.load(Relaxed), 1);
}

/// Handle reuse only. This proves a *dropped handle* is not an abort; it
/// deliberately does not claim anything about a process restart, which is
/// `a_real_reopen_reconstructs_sessions_chunks_and_accounting_from_disk`.
#[test]
fn dropping_a_session_handle_is_not_an_abort() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([5; 16], [21; 32], 2, 1, HOUR_MICROS);
    let session_id = fixture.session_id();

    {
        let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
        session.put_chunk(&fixture.chunks[0], 0).expect("put");
        // Dropping the handle must not abort: sessions outlive the party
        // holding them, which is what "restartable" means.
    }

    let resumed = staging.session(session_id).expect("resume by ID");
    assert_eq!(
        resumed.put_chunk(&fixture.chunks[0], 0).expect("repeat"),
        ChunkPutOutcome::AlreadyPresent
    );
    resumed.put_chunk(&fixture.chunks[1], 0).expect("finish");
    resumed.seal(0).expect("seal");
}

#[test]
fn seal_refuses_an_incomplete_chunk_set() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([6; 16], [21; 32], 3, 1, HOUR_MICROS);
    let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
    session.put_chunk(&fixture.chunks[0], 0).expect("put");
    session.put_chunk(&fixture.chunks[2], 0).expect("put");

    let result = session.seal(0);
    let Err(StoreError::Conflict(message)) = result else {
        panic!("a partial chunk set must not seal, got {result:?}");
    };
    assert!(message.contains("2 of 3 chunks"), "{message}");
}

/// A binding is only binding if a mismatch is refused, and refused for the
/// same reason the frozen validator would refuse it.
#[test]
fn seal_refuses_a_projection_the_session_did_not_bind() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([7; 16], [21; 32], 1, 2, HOUR_MICROS);

    // Same chunks, a membership root the session's manifest digest does not
    // commit to. Nothing about the uploaded bytes changed.
    let mut tampered = fixture.binding.clone();
    tampered.membership_root = ObjectId([99; 32]);

    let session = staging.begin(tampered, 0).expect("begin");
    session.put_chunk(&fixture.chunks[0], 0).expect("put");
    let result = session.seal(0);
    let Err(StoreError::Conflict(message)) = result else {
        panic!("an unbound manifest must not seal, got {result:?}");
    };
    assert!(message.contains("binds manifest digest"), "{message}");
}

// ---------------------------------------------------------------------------
// Deliverable 4 — bounds
// ---------------------------------------------------------------------------

#[test]
fn a_declared_projection_over_a_configured_ceiling_is_refused_before_pinning() {
    // Contract review 2026-07-28-A caps `max_projection_bytes` at
    // `max_projection_chunks * MAX_CANONICAL_BYTES`, so the chunk ceiling and
    // the byte ceiling can no longer be varied one at a time: lowering chunks
    // alone is now an unsatisfiable configuration that `StoreOptions::validate`
    // refuses at open, and the fixture would die before reaching `begin`. Each
    // case therefore sets a configuration the store will actually accept, and
    // the assertion is unchanged — the *declaration* is what must be refused,
    // and refused before anything is pinned.
    const CANONICAL_BYTES: u64 = levcs_protocol::codec::MAX_CANONICAL_BYTES as u64;
    for (limit, mutate) in [
        (
            "max_projection_objects",
            (|options: &mut StoreOptions| options.max_projection_objects = 1)
                as fn(&mut StoreOptions),
        ),
        ("max_projection_bytes", |options| {
            options.max_projection_bytes = 1
        }),
        ("max_projection_chunks", |options| {
            options.max_projection_chunks = 1;
            options.max_projection_bytes = CANONICAL_BYTES;
            options.staging_max_bytes_per_principal = CANONICAL_BYTES;
            options.staging_max_bytes_global = CANONICAL_BYTES;
            options.staging_max_compaction_debt_bytes = CANONICAL_BYTES;
        }),
    ] {
        let root = Root::with(mutate);
        let (staging, durability) = root.open();
        let before = durability.snapshot();

        let fixture = projection([8; 16], [21; 32], 2, 2, HOUR_MICROS);
        let result = staging.begin(fixture.binding, 0);
        let Err(StoreError::LimitExceeded {
            limit: observed_limit,
            ..
        }) = result
        else {
            panic!("{limit} must be a typed refusal, got {result:?}");
        };
        assert_eq!(observed_limit, limit);

        // "Before pinning" is the whole point: no budget, no file, no fence.
        let counters = staging.counters().snapshot();
        assert_eq!(counters.sessions_live, 0);
        assert_eq!(counters.reserved_bytes, 0);
        assert_eq!(counters.reserved_files, 0);
        assert_eq!(counters.compaction_debt_reserved_bytes, 0);
        assert_eq!(durability.snapshot(), before);
    }
}

#[test]
fn a_session_older_than_the_advertised_maximum_is_refused() {
    let root = Root::new();
    let maximum = root.options.staging_session_max_age_micros;
    let (staging, _durability) = root.open();

    let fixture = projection([9; 16], [21; 32], 1, 1, maximum + 1);
    let result = staging.begin(fixture.binding, 0);
    let Err(StoreError::LimitExceeded {
        limit,
        observed,
        allowed,
    }) = result
    else {
        panic!("an over-long session must be refused, got {result:?}");
    };
    assert_eq!(limit, "staging_session_max_age_micros");
    assert_eq!(observed, maximum as u64 + 1);
    assert_eq!(allowed, maximum as u64);

    // And exactly at the maximum it is admitted, so the bound is the bound and
    // not an off-by-one that happens to reject.
    let fixture = projection([10; 16], [21; 32], 1, 1, maximum);
    staging
        .begin(fixture.binding, 0)
        .expect("the boundary value is legal");
}

/// The feasibility check: configured floor rate, finalize margin, and the
/// session's own expiry must make one complete transfer possible.
#[test]
fn a_session_that_cannot_finish_is_refused_before_pinning() {
    let root = Root::new();
    // One second of transfer at the floor rate plus the configured margin.
    let margin = root.options.staging_finalize_margin_micros;
    let (staging, durability) = root.open();
    let before = durability.snapshot();

    let fixture = projection([11; 16], [21; 32], 1, 1, margin);
    let result = staging.begin(fixture.binding.clone(), 0);
    let Err(StoreError::LimitExceeded {
        limit,
        observed,
        allowed,
    }) = result
    else {
        panic!("an infeasible session must be refused, got {result:?}");
    };
    assert_eq!(limit, "staging_session_transfer_feasibility_micros");
    assert!(
        observed > allowed,
        "the refusal must report the shortfall it computed: {observed} vs {allowed}"
    );

    let counters = staging.counters().snapshot();
    assert_eq!(counters.sessions_live, 0);
    assert_eq!(counters.reserved_bytes, 0);
    assert_eq!(durability.snapshot(), before);

    // The same projection with one microsecond more than the computed
    // requirement is admitted, so the refusal is arithmetic and not a blanket
    // rejection of short sessions.
    let mut feasible = fixture.binding;
    feasible.session.expires_at_micros = observed as i64;
    staging
        .begin(feasible, 0)
        .expect("a session with exactly the required lifetime is feasible");
}

#[test]
fn the_global_session_ceiling_is_enforced_atomically_with_insertion() {
    // Per-principal is 1 and every thread uses its own principal, so the only
    // bound in play is the global one.
    let root = Root::with(|options| {
        options.staging_max_sessions_per_principal = 1;
        options.staging_max_sessions_global = 4;
    });
    let (staging, _durability) = root.open();

    let threads = 32u8;
    let admitted = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..threads)
            .map(|index| {
                let staging = Arc::clone(&staging);
                scope.spawn(move || {
                    // Dropping the handle is not an abort, so the budget stays
                    // held for the whole race whatever order the threads end in.
                    let fixture = projection([index; 16], [index; 32], 1, 1, HOUR_MICROS);
                    match staging.begin(fixture.binding, 0) {
                        Ok(_session) => true,
                        Err(error) => {
                            let StoreError::Overloaded {
                                limit,
                                retry_after_micros,
                            } = &error
                            else {
                                panic!("a ceiling must refuse by overload, got {error:?}");
                            };
                            assert_eq!(*limit, "staging_max_sessions_global");
                            assert!(
                                *retry_after_micros > 0,
                                "an overload must carry usable retry guidance"
                            );
                            false
                        }
                    }
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .filter(|admitted| *admitted)
            .count()
    });

    // A check-then-insert race admits entries past the ceiling under exactly
    // this concurrency (decision 9.8). The count is the assertion.
    assert_eq!(admitted, 4);
    assert_eq!(staging.counters().sessions_live.load(Relaxed), 4);
    assert_eq!(
        staging.counters().sessions_refused.load(Relaxed),
        u64::from(threads) - 4
    );
}

#[test]
fn the_per_principal_session_ceiling_refuses_the_same_principal_only() {
    let root = Root::with(|options| {
        options.staging_max_sessions_per_principal = 1;
        options.staging_max_sessions_global = 8;
    });
    let (staging, _durability) = root.open();

    staging
        .begin(projection([12; 16], [21; 32], 1, 1, HOUR_MICROS).binding, 0)
        .expect("first session for this principal");
    let result = staging.begin(projection([13; 16], [21; 32], 1, 1, HOUR_MICROS).binding, 0);
    let Err(StoreError::Overloaded { limit, .. }) = result else {
        panic!("a second session for one principal must be refused, got {result:?}");
    };
    assert_eq!(limit, "staging_max_sessions_per_principal");

    staging
        .begin(projection([14; 16], [22; 32], 1, 1, HOUR_MICROS).binding, 0)
        .expect("a different principal has its own budget");
}

#[test]
fn compaction_debt_is_bounded_independently_of_the_byte_budget() {
    let fixture = projection([15; 16], [21; 32], 1, 2, HOUR_MICROS);
    let session_bytes = fixture.binding.session.total_object_bytes;

    // Byte budget generous, debt ceiling exactly one session. The refusal must
    // therefore name debt, which is only possible because staging accounts it
    // on its own counter rather than sharing one with the byte budget.
    let root = Root::with(|options| {
        options.max_projection_bytes = session_bytes;
        options.staging_max_bytes_per_principal = session_bytes * 8;
        options.staging_max_bytes_global = session_bytes * 8;
        options.staging_max_compaction_debt_bytes = session_bytes;
    });
    let (staging, _durability) = root.open();

    staging.begin(fixture.binding, 0).expect("first session");
    assert_eq!(
        staging
            .counters()
            .compaction_debt_reserved_bytes
            .load(Relaxed),
        session_bytes
    );

    let second = projection([16; 16], [22; 32], 1, 2, HOUR_MICROS);
    let result = staging.begin(second.binding, 0);
    let Err(StoreError::Overloaded { limit, .. }) = result else {
        panic!("the debt ceiling must refuse, got {result:?}");
    };
    assert_eq!(limit, "staging_max_compaction_debt_bytes");
}

#[test]
fn uploaded_totals_may_not_exceed_the_declared_binding() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([17; 16], [21; 32], 2, 1, HOUR_MICROS);

    // Declare one chunk's worth of objects, then upload both chunks.
    let mut understated = fixture.binding.clone();
    understated.session.total_object_count = 1;
    understated.session.total_object_bytes = fixture.chunks[0].objects[0].descriptor.raw_len;

    let session = staging.begin(understated, 0).expect("begin");
    session
        .put_chunk(&fixture.chunks[0], 0)
        .expect("first fits");
    let result = session.put_chunk(&fixture.chunks[1], 0);
    let Err(StoreError::LimitExceeded { limit, .. }) = result else {
        panic!("an over-declaration upload must be refused, got {result:?}");
    };
    assert_eq!(limit, "projection_stage_session_objects");
}

// ---------------------------------------------------------------------------
// Deliverable 5 — artifacts are written by maintenance workers, synced,
// uniquely named, and unreferenced
// ---------------------------------------------------------------------------

/// Charter item 7, with the correction it needed: **pin the count that is
/// correct, not the count you observe.**
///
/// The previous version of this test asserted two directory syncs for the first
/// session in a shard. Two is what the code did, and two is wrong: creating
/// `staging/<shard>/<session>` when `staging/<shard>` did not exist creates
/// *two* directory entries, and syncing only the innermost one leaves a fully
/// fenced session under a shard directory that a crash can take away. A counter
/// assertion pinned to the observed number preserved the omission instead of
/// exposing it.
///
/// So the count is now stated by nesting depth: the first session in a shard
/// pays three (`staging/`, `staging/<shard>/`, and the session directory the
/// record lands in), every later session in that shard pays two.
#[test]
fn every_artifact_is_fenced_and_every_new_directory_entry_is_synced() {
    let root = Root::new();
    let (staging, durability) = root.open();
    let fixture = projection([18; 16], [21; 32], 2, 1, HOUR_MICROS);

    let before = durability.snapshot();
    let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
    let after_begin = durability.snapshot();
    assert_eq!(after_begin.fdatasync - before.fdatasync, 1);
    assert_eq!(
        after_begin.fsync_dir - before.fsync_dir,
        3,
        "the first session in a shard creates the shard directory too, and its entry \
         under staging/ must be synced before the record that depends on it"
    );

    for chunk in &fixture.chunks {
        session.put_chunk(chunk, 0).expect("put");
    }
    let after_chunks = durability.snapshot();
    assert_eq!(after_chunks.fdatasync - after_begin.fdatasync, 2);
    assert_eq!(after_chunks.fsync_dir - after_begin.fsync_dir, 2);

    session.seal(0).expect("seal");
    let after_seal = durability.snapshot();
    assert_eq!(after_seal.fdatasync - after_chunks.fdatasync, 1);
    assert_eq!(after_seal.fsync_dir - after_chunks.fsync_dir, 1);
    assert!(after_seal.bytes_written > after_chunks.bytes_written);

    // A second session in the *same* shard creates one directory entry, so it
    // pays two syncs. Without both halves the three above could be a constant
    // that happens to be right.
    let sibling = projection([28; 16], [22; 32], 1, 1, HOUR_MICROS);
    let before_sibling = durability.snapshot();
    staging.begin(sibling.binding, 0).expect("begin");
    let after_sibling = durability.snapshot();
    assert_eq!(after_sibling.fsync_dir - before_sibling.fsync_dir, 2);

    // Charter item 7 for deliverable 5's other half: every artifact byte on
    // disk was written by a maintenance worker, not by the calling thread.
    let counters = staging.counters().snapshot();
    assert_eq!(
        counters.maintenance_artifact_writes,
        2 + 2 + 1,
        "two session records, two chunks, and one manifest"
    );
    assert!(counters.maintenance_jobs >= counters.maintenance_artifact_writes);
}

#[test]
fn staged_artifacts_are_uniquely_named_and_unreferenced_by_committed_state() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([19; 16], [21; 32], 2, 1, HOUR_MICROS);
    let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
    for chunk in &fixture.chunks {
        session.put_chunk(chunk, 0).expect("put");
    }
    session.seal(0).expect("seal");
    let resolution = session.resolve().expect("resolve");

    // The reference proof is answered against a committed root, never against
    // staging's own bookkeeping. An empty root references nothing, and a
    // staged artifact is exactly the thing that has not been adopted.
    let committed = CommittedRoot::default();
    for artifact in resolution.artifacts.iter() {
        assert!(
            !committed.references_artifact(&artifact.path),
            "a sealed artifact must not be referenced by committed state"
        );
        // Structural half: staging is a sibling of shards/, so nothing a
        // manifest, CURRENT, checkpoint, or index run can name lives here.
        assert!(artifact.path.starts_with(staging.staging_root()));
        assert!(!artifact.path.starts_with(root.path().join("shards")));
    }

    let names: std::collections::BTreeSet<_> = resolution
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect();
    assert_eq!(names.len(), resolution.artifacts.len(), "names are unique");
}

// ---------------------------------------------------------------------------
// Deliverable 1 — expiry, abort, and the deferred cleanup entry point
// ---------------------------------------------------------------------------

#[test]
fn expiry_reclaims_a_dead_session_and_leaves_a_live_one() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let short = projection([20; 16], [21; 32], 1, 1, HOUR_MICROS);
    let long = projection([21; 16], [22; 32], 1, 1, HOUR_MICROS * 2);

    let short_session = staging.begin(short.binding.clone(), 0).expect("begin");
    short_session.put_chunk(&short.chunks[0], 0).expect("put");
    staging.begin(long.binding.clone(), 0).expect("begin");
    let live = staging.counters().snapshot();
    assert_eq!(live.sessions_live, 2);

    // One microsecond past the short session's advertised expiry.
    assert_eq!(staging.expire(HOUR_MICROS + 1).expect("expire"), 1);
    let after = staging.counters().snapshot();
    assert_eq!(after.sessions_live, 1);
    assert_eq!(after.sessions_expired, 1);
    assert_eq!(after.artifacts_unlinked, 2, "session record and one chunk");
    assert_eq!(
        after.reserved_bytes, long.binding.session.total_object_bytes,
        "only the dead session's budget is released"
    );
    assert_eq!(
        after.compaction_debt_written_bytes, 0,
        "reclaimed bytes stop being debt"
    );

    let result = short_session.describe();
    let Err(StoreError::Conflict(message)) = result else {
        panic!("an expired session must be gone, got {result:?}");
    };
    assert!(message.contains("no staging session"), "{message}");
    staging
        .session(long.binding.session.session_id)
        .expect("the live session is untouched");
}

#[test]
fn expiry_at_the_advertised_instant_does_not_reclaim() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([22; 16], [21; 32], 1, 1, HOUR_MICROS);
    staging.begin(fixture.binding, 0).expect("begin");

    // The frozen `validate_projection_stage_finalize` treats `now > expires_at`
    // as expired, so the store must agree at exactly the boundary microsecond.
    assert_eq!(staging.expire(HOUR_MICROS).expect("expire"), 0);
    assert_eq!(staging.counters().sessions_live.load(Relaxed), 1);
    assert_eq!(staging.expire(HOUR_MICROS + 1).expect("expire"), 1);
}

#[test]
fn abort_releases_the_budget_and_removes_every_artifact() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([23; 16], [21; 32], 2, 1, HOUR_MICROS);
    let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
    for chunk in &fixture.chunks {
        session.put_chunk(chunk, 0).expect("put");
    }
    let session_directory = root.session_directory(fixture.session_id());
    assert!(session_directory.exists());

    session.abort().expect("abort");

    assert!(!session_directory.exists());
    let counters = staging.counters().snapshot();
    assert_eq!(counters.sessions_live, 0);
    assert_eq!(counters.sessions_aborted, 1);
    assert_eq!(counters.reserved_bytes, 0);
    assert_eq!(counters.reserved_objects, 0);
    assert_eq!(counters.reserved_files, 0);
    assert_eq!(counters.compaction_debt_reserved_bytes, 0);
    assert_eq!(counters.compaction_debt_written_bytes, 0);
    assert_eq!(counters.artifacts_unlinked, 3, "record plus two chunks");

    // The budget is genuinely back: the same principal may open again.
    staging
        .begin(projection([24; 16], [21; 32], 1, 1, HOUR_MICROS).binding, 0)
        .expect("released budget is reusable");
}

/// Cleanup on a root with live sessions and nothing adopted reclaims nothing —
/// and says so by succeeding.
///
/// The distinction this asserts is the one the deferred stub used to stand for:
/// "there was nothing to do" and "I cannot answer yet" are different results,
/// and only one of them is true now. Reaching it through the public surface also
/// pins that a caller can run cleanup against a root that references nothing at
/// all without it becoming a licence to delete the sessions in flight — which is
/// exactly what a reference proof alone, unqualified by state, would do.
#[test]
fn cleanup_reclaims_nothing_when_no_session_has_been_adopted() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([26; 16], [21; 32], 1, 2, HOUR_MICROS);
    let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
    for chunk in &fixture.chunks {
        session.put_chunk(chunk, 0).expect("put");
    }
    session.seal(0).expect("seal");

    assert_eq!(
        staging
            .cleanup_unreferenced(&CommittedRoot::default())
            .expect("cleanup answers rather than deferring"),
        0,
        "no session has been adopted, so there is nothing for the reference proof to remove"
    );
    assert_eq!(
        staging
            .session(fixture.session_id())
            .expect("still there")
            .describe()
            .expect("describe")
            .state,
        StagedSessionState::Sealed,
        "and a sealed session survives a cleanup against a root that references nothing"
    );
}

// ---------------------------------------------------------------------------
// Deliverable 1 — restartable, meaning a process restart
// ---------------------------------------------------------------------------

/// Drop the whole `ProjectionStaging` and rebuild it from the filesystem.
///
/// This is what "restartable" has to mean. The earlier version of this test
/// dropped a *handle* and reacquired one from the same live registry, which
/// proves nothing about a reopen: every fact it checked was still in memory.
/// Nothing in-memory survives this one.
#[test]
fn a_real_reopen_reconstructs_sessions_chunks_and_accounting_from_disk() {
    let root = Root::new();
    let fixture = projection([30; 16], [21; 32], 2, 1, HOUR_MICROS);
    let session_id = fixture.session_id();

    {
        let (staging, _durability) = root.open();
        let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
        session.put_chunk(&fixture.chunks[0], 0).expect("put");
    }

    let (staging, durability) = root.open();
    let counters = staging.counters().snapshot();
    assert_eq!(counters.sessions_reconstructed, 1);
    assert_eq!(counters.sessions_live, 1);
    assert_eq!(
        counters.reserved_bytes, fixture.binding.session.total_object_bytes,
        "a root-global byte budget that ignored durable sessions would be a count of \
         this process's uptime"
    );
    assert_eq!(
        counters.reserved_objects,
        fixture.binding.session.total_object_count
    );
    assert_eq!(
        counters.compaction_debt_reserved_bytes,
        counters.reserved_bytes
    );
    assert_eq!(counters.abandoned_materializations_reclaimed, 0);

    // The chunk index came back too: re-offering ordinal 0 costs no write.
    let resumed = staging.session(session_id).expect("resume after reopen");
    let status = resumed.describe().expect("describe");
    assert_eq!(status.state, StagedSessionState::Open);
    assert_eq!(status.chunks_present, 1);
    assert_eq!(status.chunks_expected, 2);
    assert_eq!(
        status.written_bytes,
        fixture.chunks[0].objects[0].descriptor.raw_len
    );

    let before = durability.snapshot();
    assert_eq!(
        resumed.put_chunk(&fixture.chunks[0], 0).expect("repeat"),
        ChunkPutOutcome::AlreadyPresent
    );
    assert_eq!(durability.snapshot(), before);

    resumed.put_chunk(&fixture.chunks[1], 0).expect("finish");
    resumed.seal(0).expect("a reconstructed session seals");
}

/// The compounding half of the restart defect, and the reason it was a P1.
///
/// Before the fix, a reopen carried no sessions, so `begin` admitted a durable
/// session ID as new; if materialization then failed, the error path deleted
/// the directory recursively and took the previously durable session with it.
/// Data loss from an ordinary restart plus one error.
#[test]
fn a_reopen_refuses_to_admit_a_durable_session_id_as_new() {
    let root = Root::new();
    let fixture = projection([31; 16], [21; 32], 1, 1, HOUR_MICROS);
    let directory = root.session_directory(fixture.session_id());

    {
        let (staging, _durability) = root.open();
        let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
        session.put_chunk(&fixture.chunks[0], 0).expect("put");
    }

    let (staging, _durability) = root.open();
    let result = staging.begin(fixture.binding.clone(), 0);
    let Err(StoreError::Conflict(message)) = result else {
        panic!("a durable session ID must not be admitted as new, got {result:?}");
    };
    assert!(message.contains("already exists"), "{message}");

    // And the durable session is untouched: the refusal happens before the
    // error path that used to delete it could ever be reached.
    assert!(directory.join("session").exists());
    assert_eq!(staging.counters().snapshot().sessions_live, 1);
    staging
        .session(fixture.session_id())
        .expect("the durable session is still resumable");
}

#[test]
fn a_sealed_session_survives_a_reopen_and_still_resolves() {
    let root = Root::new();
    let fixture = projection([32; 16], [21; 32], 2, 1, HOUR_MICROS);

    let install = {
        let (staging, _durability) = root.open();
        let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
        for chunk in &fixture.chunks {
            session.put_chunk(chunk, 0).expect("put");
        }
        session.seal(0).expect("seal")
    };

    let (staging, _durability) = root.open();
    let resumed = staging.session(fixture.session_id()).expect("resume");
    assert_eq!(
        resumed.describe().expect("describe").state,
        StagedSessionState::Sealed,
        "a durable manifest artifact is the seal's commit point, so it is what makes a \
         reopened session sealed again"
    );
    let resolution = resumed.resolve().expect("a reopened seal still resolves");
    assert_eq!(resolution.manifest.chunk_digests.len(), 2);
    assert_eq!(
        resolution.manifest.manifest_digest().expect("digest"),
        install.manifest_digest
    );

    // Sealed is immutable across the restart too.
    let result = resumed.put_chunk(&fixture.chunks[0], 0);
    let Err(StoreError::Conflict(message)) = result else {
        panic!("a reopened sealed session must refuse chunks, got {result:?}");
    };
    assert!(message.contains("sealed"), "{message}");
}

/// A directory that never acquired a `session` record is not a session.
///
/// It is what a crash between `mkdir` and the record's rename leaves behind.
/// Nothing accounted for it, nothing can reference it, and — the point — it
/// must not be confused with the final state, which is why the two do not
/// share a code path.
#[test]
fn an_abandoned_materialization_is_reclaimed_and_a_final_session_is_not() {
    let root = Root::new();
    let fixture = projection([33; 16], [21; 32], 1, 1, HOUR_MICROS);
    {
        let (staging, _durability) = root.open();
        let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
        session.put_chunk(&fixture.chunks[0], 0).expect("put");
    }

    // Hand-built: the directory exists, the record never landed.
    let abandoned = root.session_directory([34; 16]);
    std::fs::create_dir_all(&abandoned).expect("abandoned directory");
    std::fs::write(abandoned.join("session.tmp"), b"torn").expect("torn temporary");

    let (staging, _durability) = root.open();
    let counters = staging.counters().snapshot();
    assert_eq!(counters.abandoned_materializations_reclaimed, 1);
    assert_eq!(counters.sessions_reconstructed, 1);
    assert_eq!(counters.sessions_live, 1);
    assert!(!abandoned.exists(), "the abandoned directory is reclaimed");
    assert!(
        root.session_directory(fixture.session_id())
            .join("session")
            .exists(),
        "the final session in the same shard is untouched"
    );
}

// ---------------------------------------------------------------------------
// Deliverable 4 — the ceilings are root-global, which requires one accountant
// ---------------------------------------------------------------------------

/// A second `ProjectionStaging` for one root is not expressible.
///
/// Two registries each admit up to the full global and per-principal budget, so
/// a freely callable constructor turned every "global" ceiling into a
/// per-handle ceiling. The cross-process half is closed by requiring the root
/// lock; this is the in-process half.
#[test]
fn one_root_admits_exactly_one_staging_accountant() {
    let root = Root::new();
    let (_first, _durability) = root.open();

    let result = ProjectionStaging::open(
        &root.lock,
        root.options.clone(),
        Arc::new(DurabilityCounters::default()),
    );
    let Err(StoreError::Conflict(message)) = result else {
        panic!("a second staging instance for one root must be refused, got {result:?}");
    };
    assert!(message.contains("already open"), "{message}");
}

/// And the lock has to be a lock on *this* root.
#[test]
fn a_root_lock_held_on_another_root_is_not_proof() {
    let owner = Root::new();
    let other = Root::new();

    let result = ProjectionStaging::open(
        &other.lock,
        owner.options.clone(),
        Arc::new(DurabilityCounters::default()),
    );
    let Err(StoreError::InvalidConfiguration(message)) = result else {
        panic!("a foreign root lock must not open staging, got {result:?}");
    };
    assert!(message.contains("proves nothing"), "{message}");
}

// ---------------------------------------------------------------------------
// Deliverable 7's discipline, applied to reclamation
// ---------------------------------------------------------------------------

/// Reclamation proves the whole directory before it unlinks anything.
///
/// Unlinking as the scan walks means a valid marked artifact can be destroyed
/// and *then* an unexpected file encountered, leaving a live session partially
/// destroyed: not removed, and no longer sealable. Either the whole directory
/// goes or nothing does.
#[test]
fn reclamation_removes_nothing_when_the_directory_holds_a_surprise() {
    let root = Root::new();
    let (staging, _durability) = root.open();
    let fixture = projection([35; 16], [21; 32], 2, 1, HOUR_MICROS);
    let session = staging.begin(fixture.binding.clone(), 0).expect("begin");
    for chunk in &fixture.chunks {
        session.put_chunk(chunk, 0).expect("put");
    }
    let directory = root.session_directory(fixture.session_id());
    let before: Vec<_> = std::fs::read_dir(&directory)
        .expect("read")
        .map(|entry| entry.expect("entry").path())
        .collect();
    assert_eq!(before.len(), 3, "record plus two chunks");
    std::fs::write(directory.join("not-ours"), b"someone else's bytes").expect("foreign file");

    let result = session.abort();
    let Err(StoreError::Corruption(message)) = result else {
        panic!("an unexplained file must stop reclamation, got {result:?}");
    };
    assert!(message.contains("not a licence to delete"), "{message}");

    // Counters, not claims: nothing was unlinked, and the session still holds
    // its budget rather than being half gone.
    let counters = staging.counters().snapshot();
    assert_eq!(counters.artifacts_unlinked, 0);
    assert_eq!(counters.sessions_live, 1);
    assert_eq!(counters.sessions_aborted, 0);
    for path in &before {
        assert!(
            path.exists(),
            "{} was destroyed before the refusal",
            path.display()
        );
    }
    // And it is still a usable session, not a wreck.
    session_of(&staging, fixture.session_id())
        .seal(0)
        .expect("a session that survived a refused reclamation still seals");
}

fn session_of(
    staging: &Arc<ProjectionStaging>,
    session_id: [u8; 16],
) -> levcs_store::staging::ProjectionStageSession {
    staging.session(session_id).expect("session")
}

// ---------------------------------------------------------------------------
// The security property, asserted through the reader API
// ---------------------------------------------------------------------------

/// **Sealing cannot publish membership** (plan §4 identity invariant 7, §8).
///
/// This is the acceptance test for the whole package and it is deliberately
/// written in the shape it must finally take: seal a session, then prove
/// through `RepoSnapshot::locate` — the entry point a reader actually calls —
/// that the staged objects are invisible, and that they become visible only
/// after a `submit` adopts the descriptor.
///
/// Still blocked on B1 NamespaceTxn, and blocked in one more place than before.
/// `RepoSnapshot::locate`, `StoreEngine::snapshot`, and the submit path are all
/// `NotImplemented`/`unimplemented!` today. On top of that, the P1-4 fix moved
/// staging inside the locked engine lifetime: this test can no longer open its
/// own `ProjectionStaging` beside a `StoreEngine`, because holding two root
/// locks is exactly what was made unrepresentable. It needs an accessor on the
/// engine — recorded as an interface request to B1 — to reach the staging the
/// engine owns.
///
/// Asserting the property against staging's own state instead would be charter
/// item 8 exactly — a property proved against the helper rather than the path
/// that runs — so it is marked blocked rather than satisfied the wrong way.
#[test]
#[ignore = "blocked on B1 NamespaceTxn: needs RepoSnapshot::locate, StoreEngine::snapshot/submit (scope 6.4 deliverables 1, 3-8), and a StoreEngine accessor for the engine-owned ProjectionStaging"]
fn sealed_objects_stay_invisible_until_a_submit_adopts_them() {
    let root = Root::new();
    let fixture = projection([25; 16], [21; 32], 1, 2, HOUR_MICROS);
    let namespace = NamespaceId::from(fixture.binding.session.destination_repo);
    let staged_ids: Vec<ObjectId> = fixture.chunks[0]
        .objects
        .iter()
        .map(|object| object.descriptor.object_id)
        .collect();

    // The engine takes the root lock, so the fixture's own lock is released
    // first. That is the P1-4 shape: one lock, one engine, one staging.
    let options = root.options.clone();
    drop(root);
    let engine = levcs_store::StoreEngine::open(options).expect("engine opens");
    let snapshot = engine.snapshot(namespace).expect("snapshot");
    for id in &staged_ids {
        assert_eq!(
            snapshot.locate(*id).expect("locate"),
            None,
            "nothing is visible before anything is staged"
        );
    }

    unimplemented!(
        "B1: expose the engine-owned ProjectionStaging, begin/put/seal a session through it, \
         re-assert locate() is None for every staged object, then build a ValidatedTransaction \
         with adopt_projection(install, handle), submit it, and assert locate() returns Some"
    );
}
