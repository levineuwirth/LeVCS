//! Bounded invisible projection-staging sessions.
//!
//! B3 owns the storage mechanism. D0-B owns and freezes the adoption seam in
//! this file so B1 never has to read B3's on-disk representation directly.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use levcs_core::ObjectId;
use levcs_protocol::v2::{
    ProjectionStageManifestV1, ProjectionStageSessionV1, StagedProjectionInstallV1,
};

use crate::index::{IndexDelta, IndexKey, IndexLocation, IndexRun};
use crate::roots::{CommittedRoot, PinnedFile, RetainedIndexRun, RetainedProjectionArtifact};
use crate::types::{NamespaceId, StoreError};

/// One immutable artifact offered for adoption.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionArtifact {
    pub path: PathBuf,
    pub digest: ObjectId,
    pub bytes: u64,
}

/// Everything B1 may inspect while revalidating a sealed staged projection.
///
/// This is deliberately read-only. Adoption may reject this state but may
/// never repair or mutate it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionAdoptionResolution {
    pub session: ProjectionStageSessionV1,
    pub manifest: ProjectionStageManifestV1,
    pub artifacts: Arc<[ProjectionArtifact]>,
}

/// The only three ways ownership of an admitted adoption pin may end.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProjectionAdoptionOutcome {
    /// The frame naming these artifacts committed at `committed_shard_sequence`.
    ///
    /// The sequence is carried because *when* an adoption happened is what makes
    /// a later reference proof meaningful. Cleanup answers "does any committed
    /// root still point at this directory?" against a root a caller supplies,
    /// and a root captured **before** this adoption references none of these
    /// artifacts for the trivial reason that it predates them — so absence
    /// measured against it is not absence, and cleanup would delete a directory
    /// the current root points into. Recording the position turns that into a
    /// question staging can refuse: a root at or past this sequence necessarily
    /// includes this adoption's effects, and an earlier one is not evidence.
    ///
    /// The value is B1's to supply because only B1 knows it — the append that
    /// produced it has just returned — and staging is constructed before any
    /// committed root exists (it is recovery's resolver), so there is no moment
    /// at which it could observe the position itself. Frozen D0-B amendment,
    /// contract review 2026-07-31-C.
    Adopted {
        committed_shard_sequence: u64,
    },
    DefinitivePreAppendFailure,
    TransferredToRecovery,
}

/// Resolution delivered to staging after production recovery has made the
/// final frame authoritative or proved that no complete frame exists.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecoveredProjectionOutcome {
    Committed,
    ProvedAbsent,
}

/// Recovery's resolution of a staging pin transferred across a poisoned
/// process boundary.
///
/// B3 consumes these notifications before expiry or cleanup may inspect the
/// recovered shard.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RecoveredProjectionResolution {
    pub session_id: [u8; 16],
    pub outcome: RecoveredProjectionOutcome,
}

/// Read-only recovery result for one authoritative staged-install frame.
///
/// A final frame carries only a canonical descriptor, not the installed
/// object's locations. Recovery obtains those locations and live file
/// ownership from B3 through this value. The vectors are newest-first where
/// order is observable by index lookup.
///
/// The fields remain private so recovery can compose the result into its
/// recovered root but cannot mutate staging state or reinterpret B3's on-disk
/// representation.
#[derive(Clone, Debug)]
pub(crate) struct RecoveredProjectionArtifacts {
    descriptor: StagedProjectionInstallV1,
    index_delta: Arc<IndexDelta>,
    /// Newest-first; each retained entry is also the lookup run, so lookup
    /// membership cannot accidentally diverge from physical ownership.
    retained_index_runs: Arc<[RetainedIndexRun]>,
    retained_artifacts: Arc<[RetainedProjectionArtifact]>,
}

impl RecoveredProjectionArtifacts {
    /// Construct the complete physical result of resolving one descriptor.
    ///
    /// B3 calls this only after mechanically verifying the descriptor against
    /// the sealed session, manifest, artifact hashes, and index. Identity,
    /// graph, policy, authority, and federation decisions are deliberately
    /// absent from this interface.
    pub(crate) fn new(
        descriptor: StagedProjectionInstallV1,
        index_delta: Arc<IndexDelta>,
        retained_index_runs: Arc<[RetainedIndexRun]>,
        retained_artifacts: Arc<[RetainedProjectionArtifact]>,
    ) -> Result<Self, StoreError> {
        let run_entries = retained_index_runs
            .iter()
            .try_fold(0u64, |count, retained| {
                count.checked_add(retained.run().entry_count())
            })
            .ok_or_else(|| {
                StoreError::Corruption(
                    "recovered staged-projection index entry count overflowed".into(),
                )
            })?;
        let delta_entries = u64::try_from(index_delta.len()).map_err(|_| {
            StoreError::Corruption(
                "recovered staged-projection delta count does not fit u64".into(),
            )
        })?;
        let total_entries = run_entries.checked_add(delta_entries).ok_or_else(|| {
            StoreError::Corruption(
                "recovered staged-projection total index count overflowed".into(),
            )
        })?;
        if total_entries == 0 {
            return Err(StoreError::Corruption(
                "committed staged projection resolved without object membership".into(),
            ));
        }
        if total_entries != descriptor.object_count {
            return Err(StoreError::Corruption(format!(
                "committed staged projection declares {} objects but its recovered \
                 index contains {total_entries}",
                descriptor.object_count
            )));
        }
        if retained_artifacts.is_empty() {
            return Err(StoreError::Corruption(
                "committed staged projection resolved without live artifact ownership".into(),
            ));
        }

        Ok(Self {
            descriptor,
            index_delta,
            retained_index_runs,
            retained_artifacts,
        })
    }

    pub(crate) fn descriptor(&self) -> &StagedProjectionInstallV1 {
        &self.descriptor
    }

    pub(crate) fn index_delta(&self) -> &Arc<IndexDelta> {
        &self.index_delta
    }

    pub(crate) fn index_runs_newest_first(&self) -> impl ExactSizeIterator<Item = &Arc<IndexRun>> {
        self.retained_index_runs.iter().map(RetainedIndexRun::run)
    }

    pub(crate) fn retained_index_runs(&self) -> &[RetainedIndexRun] {
        &self.retained_index_runs
    }

    pub(crate) fn retained_artifacts(&self) -> &[RetainedProjectionArtifact] {
        &self.retained_artifacts
    }
}

/// The complete staging-owned seam used by production recovery.
///
/// `resolve_committed` is read-only: the complete frame is already the
/// durable authority and resolution may inspect, open, hash, and pin its
/// immutable artifacts but may not repair them. `notify_recovered` is the
/// separate lifecycle transition performed only after recovery has either
/// incorporated a committed result into the recovered root or proved absence
/// by scanning the complete authoritative journal history.
pub(crate) trait ProjectionRecoveryResolver: Send + Sync {
    /// Sessions whose in-process adoption handle transferred responsibility
    /// to recovery before the previous engine stopped.
    fn transferred_sessions(&self, shard_index: u16) -> Result<Arc<[[u8; 16]]>, StoreError>;

    /// Resolve a canonical committed descriptor into exact namespace-scoped
    /// membership and live physical ownership.
    ///
    /// `adoption_shard_sequence` is the shard sequence of the **complete
    /// replayed adoption frame**, and is required rather than optional or
    /// inferred. It is the identity every artifact's logical generation is
    /// derived from, and staging cannot supply it: a transferred `Finalizing`
    /// session has no durable position — that is exactly the state recovery is
    /// resolving — and this frame is the sole authority that creates one.
    ///
    /// The recovery-direction counterpart of the D0-B
    /// `ProjectionAdoptionOutcome::Adopted` amendment, and granted for the same
    /// reason: an adoption's position is known only to the side that made the
    /// frame authoritative. There it flowed B1 to B3 after a live append; here
    /// it flows recovery to B3 after a replayed one. Contract review
    /// 2026-07-31-D.
    fn resolve_committed(
        &self,
        namespace: NamespaceId,
        descriptor: &StagedProjectionInstallV1,
        adoption_shard_sequence: u64,
    ) -> Result<RecoveredProjectionArtifacts, StoreError>;

    /// Finish one transferred session after the physical-state proof is
    /// complete. This transition must be idempotent: recovery remains unready
    /// if a later notification fails and repeats every notification on the
    /// next attempt.
    fn notify_recovered(&self, resolution: RecoveredProjectionResolution)
        -> Result<(), StoreError>;
}

/// B3's implementation behind the opaque handle.
///
/// The trait and constructor are crate-private: external callers may carry a
/// handle issued by staging but cannot forge one.
pub(crate) trait ProjectionAdoptionLifecycle: Send + Sync {
    fn resolution(&self) -> Result<Arc<ProjectionAdoptionResolution>, StoreError>;

    fn finish(&self, outcome: ProjectionAdoptionOutcome) -> Result<(), StoreError>;

    fn dropped_without_outcome(&self);
}

/// An unforgeable staging capability consumed alongside the wire descriptor.
///
/// Holding this value pins the sealed artifacts. Exactly one terminal outcome
/// must be recorded before it is dropped.
pub struct ProjectionAdoption {
    lifecycle: Arc<dyn ProjectionAdoptionLifecycle>,
    finished: bool,
}

impl ProjectionAdoption {
    pub(crate) fn new(lifecycle: Arc<dyn ProjectionAdoptionLifecycle>) -> Self {
        Self {
            lifecycle,
            finished: false,
        }
    }

    pub(crate) fn resolution(&self) -> Result<Arc<ProjectionAdoptionResolution>, StoreError> {
        self.lifecycle.resolution()
    }

    /// Prove artifact retention against the state readers actually capture.
    pub(crate) fn artifact_is_referenced(&self, root: &CommittedRoot, path: &Path) -> bool {
        root.references_path(path)
    }

    pub(crate) fn finish(mut self, outcome: ProjectionAdoptionOutcome) -> Result<(), StoreError> {
        self.lifecycle.finish(outcome)?;
        self.finished = true;
        Ok(())
    }
}

impl fmt::Debug for ProjectionAdoption {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectionAdoption")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Drop for ProjectionAdoption {
    fn drop(&mut self) {
        if !self.finished {
            self.lifecycle.dropped_without_outcome();
        }
    }
}

/// D0-B's exact B1/B3 handoff payload.
pub(crate) struct StagedProjectionAdoption {
    pub(crate) descriptor: StagedProjectionInstallV1,
    pub(crate) handle: ProjectionAdoption,
}

// ===========================================================================
// B3 StagingSessions — the storage mechanism and its bounds (scope 6.5,
// deliverables 1-5). Everything above this line is D0-B's frozen adoption
// seam and is not edited here.
//
// What this half decides: what a session is on disk, what it costs, when it
// dies, and that none of it is visible until a transaction adopts it. What it
// deliberately does not decide: `ProjectionCore` validation, identity and
// authority proofs, policy, source-snapshot and `ForkProofV2` checks, session
// authentication, and the export lease. Plan §5.1 puts those in Phase 2's
// `levcs-instance`. Every field those checks key on is bound, stored, and
// exposed here; none of them is evaluated here.
// ===========================================================================

// A second `use` block rather than an addition to the frozen one at the top of
// the file, so the ownership boundary is visible in the diff.
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::IoSlice;
use std::ops::{Deref, DerefMut};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock};
use std::thread::JoinHandle;

use levcs_protocol::v2::{ProjectionStageChunkV1, StagedObjectV1};
use levcs_protocol::CanonicalCodec;

use crate::format::digest;
use crate::options::StoreOptions;
use crate::recovery::RecoverySession;
use crate::types::DurabilityCounters;

/// Subdirectory of the store root holding every staging session (scope 3.1).
///
/// It is a sibling of `shards/`, not a child of one, and that placement is the
/// structural half of deliverable 5: nothing a manifest, `CURRENT`, checkpoint,
/// or index run can name lives under this path, so a staged artifact cannot
/// enter committed state by being mistaken for a shard file.
const STAGING_DIR: &str = "staging";

const STAGING_ARTIFACT_MAGIC: [u8; 8] = *b"LVCSSTG\0";
const STAGING_ARTIFACT_VERSION: u16 = 1;
const STAGING_ARTIFACT_DIGEST_DOMAIN: &[u8] = b"levcs-staging-artifact/v1\0";
const STAGING_ARTIFACT_SET_DIGEST_DOMAIN: &[u8] = b"levcs-staging-artifact-set/v1\0";
/// `magic || version || kind || session_id || payload_len`.
const STAGING_ARTIFACT_HEADER_LEN: usize = 8 + 2 + 2 + 16 + 4;

const SESSION_RECORD_NAME: &str = "session";
const MANIFEST_NAME: &str = "manifest";
/// Deliverable 6's durable pin state.
///
/// One file rather than one per outcome, rewritten in place by a replacing
/// rename, so a session never holds two markers that disagree and the per
/// session file bound does not grow with the number of outcomes.
const ADOPTION_NAME: &str = "adoption";

/// Files a session may hold at once: one per chunk, plus the session record, the
/// sealed manifest, the adoption marker, and the marker's temporary. `options.rs`
/// validates `staging_max_files_per_session >= max_projection_chunks +
/// SESSION_FIXED_FILES` against exactly this layout.
///
/// It was 2 and became 4 with deliverable 6: the pin's durable marker, and the
/// `adoption.tmp` that exists beside it for the width of the
/// `Finalizing -> Adopted` replacement. A **peak**, not a total — the temporary
/// is gone the moment the rename returns — and the reservation is charged
/// against the peak because that is the instant the directory is widest.
///
/// The constant's doc already claimed to be "the shared definition rather than a
/// second opinion" while `options.rs` carried a literal `+ 2`, so the claim was
/// false in the one way that matters; adding a file is exactly the edit that
/// finds that out. `options.rs` now reads the constant.
///
/// Four is the true peak, and the marker is the only reason it is not three.
/// Every other artifact publishes through a `<name>.tmp` as well, but each of
/// those temporaries stands in for a final name that is *absent* — a chunk or a
/// first manifest does not yet exist — so it occupies the slot it is about to
/// become rather than an extra one. State ordering keeps those writes from
/// overlapping a seal or a finalize. `adoption.tmp` is the single case that
/// coexists with a final file already on disk, because the transition it
/// publishes replaces a marker rather than creating one.
pub(crate) const SESSION_FIXED_FILES: u64 = 4;

/// Which of the three staging artifact kinds a file is.
///
/// The kind travels in the header beside the session ID because cleanup
/// (deliverable 7) must be able to decide, from the bytes alone, that a file
/// belongs to a session it is reclaiming. A directory name is not a marker: a
/// file moved or left behind by a partial reclamation would keep it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum StagingArtifactKind {
    SessionRecord = 1,
    Chunk = 2,
    Manifest = 3,
    /// The adoption marker of deliverable 6. Carries the outcome so the pin's
    /// fate is durable, not only its existence.
    Adoption = 4,
}

impl StagingArtifactKind {
    fn code(self) -> u16 {
        self as u16
    }

    fn from_code(code: u16) -> Option<Self> {
        match code {
            1 => Some(Self::SessionRecord),
            2 => Some(Self::Chunk),
            3 => Some(Self::Manifest),
            4 => Some(Self::Adoption),
            _ => None,
        }
    }
}

/// The immutable creation binding of one staging session.
///
/// `session` is the frozen wire binding: destination repo/genesis and expected
/// authority, projection mode, authenticated source kind and actor/key epoch,
/// source generation or `ForkProofV2`, final operation ID/digest/evidence
/// digest, total object/byte/chunk counts, the ordered manifest digest, and
/// expiry. B3 stores all of it and enforces the mechanical parts; it evaluates
/// none of the identity or policy fields.
///
/// `membership_root` is carried separately because it is not a field of
/// `ProjectionStageSessionV1` and yet is an input to the manifest digest the
/// session already binds. Without it the seal could not reconstruct the exact
/// manifest the creator committed to — and inventing one would make
/// `manifest_digest` unverifiable rather than binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionStageBinding {
    pub session: ProjectionStageSessionV1,
    pub membership_root: ObjectId,
}

/// Observable staging occupancy and work.
///
/// Charter item 7: the bounds below are asserted against these counters and
/// against [`DurabilityCounters`], not read out of the code. The gauges are
/// the reserved budget, not the bytes on disk, because the budget is what the
/// ceilings are enforced against.
#[derive(Debug, Default)]
pub struct StagingCounters {
    pub sessions_created: AtomicU64,
    pub sessions_refused: AtomicU64,
    pub sessions_sealed: AtomicU64,
    pub sessions_aborted: AtomicU64,
    pub sessions_expired: AtomicU64,
    /// Sessions that took an adoption pin, and the four ways one ends. Kept
    /// apart because they are four different physical claims: `adopted` means a
    /// committed root references the artifacts, `released` means nothing was
    /// appended, and both `transferred` and `dropped` mean this process cannot
    /// say — the second being the one nobody intended.
    pub sessions_finalized: AtomicU64,
    pub sessions_adopted: AtomicU64,
    pub adoption_pins_released: AtomicU64,
    pub adoption_pins_transferred: AtomicU64,
    pub adoption_pins_dropped: AtomicU64,
    /// Adopted sessions whose directories cleanup reclaimed after proving no
    /// committed root referenced them, and the times it declined for the
    /// opposite reason. Separate counters because "nothing to do" and "there
    /// was something and it was still referenced" are different answers, and
    /// only one of them says the reference proof did any work.
    pub sessions_cleaned_up: AtomicU64,
    pub cleanup_declined_referenced: AtomicU64,
    /// Adopted sessions cleanup skipped because the root it was given had not
    /// reached the adoption. Counted apart from a referenced decline because
    /// they say different things about the caller: one is a healthy store
    /// holding its artifacts, the other is a caller asking the wrong question.
    pub cleanup_declined_stale_root: AtomicU64,
    /// Gauge: sessions currently holding budget.
    pub sessions_live: AtomicU64,
    /// Gauge: object bytes reserved by live sessions.
    pub reserved_bytes: AtomicU64,
    /// Gauge: objects reserved by live sessions.
    pub reserved_objects: AtomicU64,
    /// Gauge: files reserved by live sessions.
    pub reserved_files: AtomicU64,
    /// Gauge: reclaimable staged object bytes charged to staging alone.
    /// Deliberately never shares an accumulator with receive spools, journal
    /// bytes, or segment bytes (plan §8: "independently of ordinary receive
    /// spools"); a shared counter would let unrelated traffic close staging's
    /// ceiling, or hide it.
    pub compaction_debt_reserved_bytes: AtomicU64,
    /// Gauge: staged object bytes charged by an accepted chunk put. Charged
    /// when the ordinal is reserved and released if the artifact write fails,
    /// so the declared-total bound stays atomic even though the write itself
    /// happens on a maintenance worker with the registry unlocked.
    pub compaction_debt_written_bytes: AtomicU64,
    pub chunks_written: AtomicU64,
    /// Chunk puts satisfied by an identical ordinal/digest already present.
    /// A restart re-uploading a chunk must cost no second write; this is how
    /// that is asserted rather than asserted about.
    pub chunks_deduplicated: AtomicU64,
    pub artifact_bytes_written: AtomicU64,
    pub artifacts_unlinked: AtomicU64,
    /// Durable sessions reconstructed from disk by [`ProjectionStaging::open`].
    /// A root-global ceiling is only meaningful if it counts what is already
    /// durable, so this is how "the accounting survived the restart" is
    /// asserted rather than asserted about.
    pub sessions_reconstructed: AtomicU64,
    /// Session directories reclaimed at open because they never acquired a
    /// durable session record. Counted separately from `sessions_aborted` and
    /// `sessions_expired` because an abandoned materialization was never a
    /// session: nothing ever charged budget for it, and confusing the two is
    /// how a reopen deletes a durable session.
    pub abandoned_materializations_reclaimed: AtomicU64,
    /// Artifact writes performed on a maintenance worker. Deliverable 5 says
    /// artifacts are written by maintenance workers; this is the counter that
    /// says so, and `write_artifact` refuses to run anywhere else.
    pub maintenance_artifact_writes: AtomicU64,
    /// Jobs dispatched to the maintenance pool and completed.
    pub maintenance_jobs: AtomicU64,
    /// Entries under `staging/` that are not a shard directory, a session
    /// directory, or a recognized artifact. Never deleted, never interpreted;
    /// counted so a surprise in the tree is visible instead of silent.
    pub unrecognized_entries: AtomicU64,
}

impl StagingCounters {
    pub fn snapshot(&self) -> StagingCounterSnapshot {
        StagingCounterSnapshot {
            sessions_created: self.sessions_created.load(Relaxed),
            sessions_refused: self.sessions_refused.load(Relaxed),
            sessions_sealed: self.sessions_sealed.load(Relaxed),
            sessions_finalized: self.sessions_finalized.load(Relaxed),
            sessions_adopted: self.sessions_adopted.load(Relaxed),
            adoption_pins_released: self.adoption_pins_released.load(Relaxed),
            adoption_pins_transferred: self.adoption_pins_transferred.load(Relaxed),
            adoption_pins_dropped: self.adoption_pins_dropped.load(Relaxed),
            sessions_cleaned_up: self.sessions_cleaned_up.load(Relaxed),
            cleanup_declined_referenced: self.cleanup_declined_referenced.load(Relaxed),
            cleanup_declined_stale_root: self.cleanup_declined_stale_root.load(Relaxed),
            sessions_aborted: self.sessions_aborted.load(Relaxed),
            sessions_expired: self.sessions_expired.load(Relaxed),
            sessions_live: self.sessions_live.load(Relaxed),
            reserved_bytes: self.reserved_bytes.load(Relaxed),
            reserved_objects: self.reserved_objects.load(Relaxed),
            reserved_files: self.reserved_files.load(Relaxed),
            compaction_debt_reserved_bytes: self.compaction_debt_reserved_bytes.load(Relaxed),
            compaction_debt_written_bytes: self.compaction_debt_written_bytes.load(Relaxed),
            chunks_written: self.chunks_written.load(Relaxed),
            chunks_deduplicated: self.chunks_deduplicated.load(Relaxed),
            artifact_bytes_written: self.artifact_bytes_written.load(Relaxed),
            artifacts_unlinked: self.artifacts_unlinked.load(Relaxed),
            sessions_reconstructed: self.sessions_reconstructed.load(Relaxed),
            abandoned_materializations_reclaimed: self
                .abandoned_materializations_reclaimed
                .load(Relaxed),
            maintenance_artifact_writes: self.maintenance_artifact_writes.load(Relaxed),
            maintenance_jobs: self.maintenance_jobs.load(Relaxed),
            unrecognized_entries: self.unrecognized_entries.load(Relaxed),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StagingCounterSnapshot {
    pub sessions_created: u64,
    pub sessions_refused: u64,
    pub sessions_sealed: u64,
    pub sessions_finalized: u64,
    pub sessions_adopted: u64,
    pub adoption_pins_released: u64,
    pub adoption_pins_transferred: u64,
    pub adoption_pins_dropped: u64,
    pub sessions_cleaned_up: u64,
    pub cleanup_declined_referenced: u64,
    pub cleanup_declined_stale_root: u64,
    pub sessions_aborted: u64,
    pub sessions_expired: u64,
    pub sessions_live: u64,
    pub reserved_bytes: u64,
    pub reserved_objects: u64,
    pub reserved_files: u64,
    pub compaction_debt_reserved_bytes: u64,
    pub compaction_debt_written_bytes: u64,
    pub chunks_written: u64,
    pub chunks_deduplicated: u64,
    pub artifact_bytes_written: u64,
    pub artifacts_unlinked: u64,
    pub sessions_reconstructed: u64,
    pub abandoned_materializations_reclaimed: u64,
    pub maintenance_artifact_writes: u64,
    pub maintenance_jobs: u64,
    pub unrecognized_entries: u64,
}

/// Outcome of one numbered chunk put. Both arms are terminal successes; the
/// distinction exists so a restart can be asserted to cost no second write.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChunkPutOutcome {
    Stored,
    AlreadyPresent,
}

/// Every state a session can hold, all four durable and all four
/// reconstructable.
///
/// Reconstructability is the membership rule, and it is why `SessionBusy` is a
/// separate private enum: a value that a restart cannot produce has no business
/// on the wire. Each of these is decided by an artifact on disk — the session
/// record, the sealed manifest, and the adoption marker's recorded outcome —
/// never by a flag that only this process remembers.
///
/// The previous pass predicted deliverable 6 would add one variant. It adds two.
/// `Adopted` is not in the deliverable's own text, and dropping the session on
/// adoption instead is what forced it: the artifacts stay in `staging/` and are
/// pinned by the committed root from then on, so removing the session record
/// would make the next reconstruction read the directory as an abandoned
/// materialization and reclaim committed content. Keeping the record without a
/// state, the other way out, re-charges the whole reservation for a session that
/// no longer occupies any staging budget — a bound that leaks a little on every
/// restart. A durable `Adopted` says the true thing instead: this directory is
/// store content now, and it is cleanup's business rather than staging's.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StagedSessionState {
    Open,
    Sealed,
    /// An adoption pin is outstanding. The artifacts may not be reclaimed by
    /// expiry, abort, or cleanup while a session is here, and a pin that
    /// outlives its process is resolved by recovery rather than dropped.
    Finalizing,
    /// The pin ended in `Adopted`: a committed transaction references these
    /// artifacts, they are no longer staging occupancy, and the session holds no
    /// reservation. It stays in the registry so cleanup can prove — against a
    /// `CommittedRoot` rather than against this state — whether anything still
    /// references them.
    Adopted,
}

/// Read-only view of one live session. Never carries artifact bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedSessionStatus {
    pub session_id: [u8; 16],
    pub state: StagedSessionState,
    pub shard_index: u16,
    pub chunks_present: u32,
    pub chunks_expected: u32,
    pub written_objects: u64,
    pub written_bytes: u64,
    pub expires_at_micros: i64,
}

// --- maintenance workers (deliverable 5) -----------------------------------
//
// Deliverable 5 requires artifacts to be *written by maintenance workers*.
// Two properties follow from that and neither is a matter of taste:
//
//   * No filesystem work happens while the registry mutex is held. The
//     registry is the one place every ceiling is evaluated, so holding it
//     across a disk write makes admission latency a function of unrelated
//     uploads — and makes the global bound's own critical section as slow as
//     the slowest device in the root.
//   * No filesystem work happens on the caller's thread. The caller is an
//     instance-layer request thread (plan §5.2 forbids filesystem work on the
//     Tokio pool); staging's own writes must not be the exception.
//
// Both are enforced mechanically rather than documented: `run_maintenance`
// refuses to dispatch while this thread holds the registry lock, and
// `write_artifact` refuses to run anywhere but a maintenance worker.

thread_local! {
    /// Set for the whole life of a maintenance worker thread.
    static ON_MAINTENANCE_WORKER: Cell<bool> = const { Cell::new(false) };
    /// How many registry guards this thread currently holds.
    static REGISTRY_LOCK_DEPTH: Cell<u32> = const { Cell::new(0) };
}

/// Maintenance workers per store root.
///
/// A constant rather than a configured value: `options.rs` is frozen for this
/// pass and inventing a local knob that no operator can reach would be a
/// second opinion about configuration. Two is enough to keep one slow device
/// from serializing an unrelated session's chunk write, and small enough that
/// staging cannot become a source of I/O concurrency the capacity analysis did
/// not budget for. Raising it is an interface request against `options.rs`,
/// not an edit here.
const STAGING_MAINTENANCE_WORKERS: usize = 2;

type MaintenanceJob = Box<dyn FnOnce() + Send + 'static>;

struct MaintenancePool {
    jobs: Option<crossbeam_channel::Sender<MaintenanceJob>>,
    workers: Vec<JoinHandle<()>>,
}

impl MaintenancePool {
    fn new(root: &Path) -> Self {
        let (jobs, receiver) = crossbeam_channel::unbounded::<MaintenanceJob>();
        let workers = (0..STAGING_MAINTENANCE_WORKERS)
            .map(|index| {
                let receiver = receiver.clone();
                std::thread::Builder::new()
                    .name(format!("levcs-staging-maint-{index}"))
                    .spawn(move || {
                        ON_MAINTENANCE_WORKER.with(|flag| flag.set(true));
                        for job in receiver {
                            job();
                        }
                    })
                    .unwrap_or_else(|error| {
                        panic!(
                            "staging maintenance worker for {} could not start: {error}",
                            root.display()
                        )
                    })
            })
            .collect();
        Self {
            jobs: Some(jobs),
            workers,
        }
    }
}

impl Drop for MaintenancePool {
    fn drop(&mut self) {
        // Closing the channel is the shutdown signal; the join is what makes
        // "no artifact write outlives the staging instance" true rather than
        // likely.
        self.jobs = None;
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// Guard whose only extra job is to make "this thread holds the registry"
/// observable to [`ProjectionStaging::run_maintenance`].
struct RegistryGuard<'a>(std::sync::MutexGuard<'a, Registry>);

impl Deref for RegistryGuard<'_> {
    type Target = Registry;

    fn deref(&self) -> &Registry {
        &self.0
    }
}

impl DerefMut for RegistryGuard<'_> {
    fn deref_mut(&mut self) -> &mut Registry {
        &mut self.0
    }
}

impl Drop for RegistryGuard<'_> {
    fn drop(&mut self) {
        REGISTRY_LOCK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// Every store root with a live [`ProjectionStaging`] in this process.
///
/// The `RecoverySession` argument to `open` proves no *other* process holds
/// the root. This closes the remaining half: a second in-process instance for
/// one root would carry a second registry, and two registries each admit up to
/// the full global and per-principal ceilings, which makes a "global" bound a
/// per-handle bound. Membership is released when the instance is dropped.
static OPEN_STAGING_ROOTS: OnceLock<Mutex<BTreeSet<PathBuf>>> = OnceLock::new();

fn open_staging_roots() -> &'static Mutex<BTreeSet<PathBuf>> {
    OPEN_STAGING_ROOTS.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// How staging learns which device a path is on.
///
/// Behind a trait for exactly one reason: the cross-device refusal must be
/// asserted through `begin`, the entry point a consumer calls, and an
/// unprivileged test cannot create a second mount under a temporary root. The
/// production probe is the real `st_dev`, and a test asserts that it agrees
/// with `std::fs::metadata(..).dev()` so the substitute cannot come to mean
/// something the real one does not.
trait DeviceProbe: Send + Sync {
    fn device_of(&self, path: &Path) -> Result<u64, StoreError>;
}

struct StatDeviceProbe;

impl DeviceProbe for StatDeviceProbe {
    fn device_of(&self, path: &Path) -> Result<u64, StoreError> {
        Ok(std::fs::metadata(path)?.dev())
    }
}

/// One stored chunk artifact.
#[derive(Clone, Debug)]
struct StoredChunk {
    digest: ObjectId,
    path: PathBuf,
    /// Bytes of the artifact file, header and all. Staged *object* bytes —
    /// the unit every byte budget is denominated in — are accumulated on the
    /// session record instead, so the running total has exactly one home and
    /// cannot drift from the per-chunk copies.
    file_bytes: u64,
}

/// What the registry knows about one ordinal.
///
/// `InFlight` exists because the artifact write happens on a maintenance
/// worker with the registry unlocked. Without it, two concurrent puts of the
/// same ordinal would both see an empty slot, both dispatch a write, and the
/// second `rename_noreplace` would fail with a filesystem error instead of the
/// typed answer this contract owes.
#[derive(Clone, Debug)]
enum ChunkSlot {
    InFlight { digest: ObjectId },
    Stored(StoredChunk),
}

impl ChunkSlot {
    fn digest(&self) -> ObjectId {
        match self {
            Self::InFlight { digest } => *digest,
            Self::Stored(stored) => stored.digest,
        }
    }

    fn stored(&self) -> Option<&StoredChunk> {
        match self {
            Self::InFlight { .. } => None,
            Self::Stored(stored) => Some(stored),
        }
    }
}

/// What long-running work a session is currently inside.
///
/// Deliberately *not* a variant of the public [`StagedSessionState`]: sealing
/// and reclaiming are in-process exclusions, not durable states, and a caller
/// asking `describe()` about a session mid-seal is still being told the truth
/// when it hears `Open`. Making them public states would put a value on the
/// wire that no restart could ever reconstruct.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum SessionBusy {
    Idle,
    Sealing,
    /// Between admitting the sole finalizer and the marker being durable. The
    /// pin does not exist yet, so this is an exclusion and not a state.
    Finalizing,
    Reclaiming,
}

/// Budget one session holds. Charged once at creation from the declared
/// totals and released exactly once when the session leaves the registry.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
struct Reservation {
    objects: u64,
    bytes: u64,
    files: u64,
}

#[derive(Copy, Clone, Debug, Default)]
struct Usage {
    sessions: u64,
    objects: u64,
    bytes: u64,
    files: u64,
}

struct SessionRecord {
    binding: ProjectionStageBinding,
    shard_index: u16,
    directory: PathBuf,
    state: StagedSessionState,
    busy: SessionBusy,
    chunks: BTreeMap<u32, ChunkSlot>,
    written_objects: u64,
    written_bytes: u64,
    reservation: Reservation,
    resolution: Option<Arc<ProjectionAdoptionResolution>>,
    /// The committed shard sequence this session's adoption frame reached, for
    /// an `Adopted` session and nothing else.
    ///
    /// Cleanup's reference proof is only meaningful against a root that includes
    /// this adoption; an earlier root omits every reference the adoption created
    /// and would "prove" an absence that is really a date. Durable in the
    /// adoption marker, so the proof survives the restart that separates an
    /// adoption from the compaction that eventually drops its reference.
    adopted_at_shard_sequence: Option<u64>,
}

impl SessionRecord {
    fn principal(&self) -> [u8; 32] {
        self.binding.session.actor
    }
}

/// The one place staging occupancy lives.
///
/// A single lock, and every ceiling is evaluated and the entry inserted under
/// one acquisition of it. Decision 9.8 is explicit that a check-then-insert
/// race admits entries past the ceiling under exactly the concurrency the
/// ceiling exists for, so there is deliberately no read-then-decide path here
/// at all — not even a fast one.
#[derive(Default)]
struct Registry {
    sessions: BTreeMap<[u8; 16], SessionRecord>,
    principals: BTreeMap<[u8; 32], Usage>,
    global: Usage,
    debt_reserved_bytes: u64,
}

/// Bounded invisible projection staging for one store root.
///
/// **Exactly one of these exists per root, for the life of the root lock.**
/// See [`ProjectionStaging::open`].
pub struct ProjectionStaging {
    options: StoreOptions,
    staging_root: PathBuf,
    /// Canonical root path, held so `Drop` releases exactly the entry `open`
    /// claimed even if `options.root` was relative.
    canonical_root: PathBuf,
    counters: Arc<StagingCounters>,
    durability: Arc<DurabilityCounters>,
    device: Box<dyn DeviceProbe>,
    registry: Mutex<Registry>,
    maintenance: MaintenancePool,
}

impl Drop for ProjectionStaging {
    fn drop(&mut self) {
        if let Ok(mut roots) = open_staging_roots().lock() {
            roots.remove(&self.canonical_root);
        }
    }
}

impl fmt::Debug for ProjectionStaging {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectionStaging")
            .field("staging_root", &self.staging_root)
            .field("counters", &self.counters.snapshot())
            .finish_non_exhaustive()
    }
}

impl ProjectionStaging {
    /// Open `<root>/staging` under a held root lock and reconstruct every
    /// durable session from disk.
    ///
    /// **The `lock` argument is the ownership proof, not a convenience.** The
    /// ceilings this type enforces are advertised as root-global, and a global
    /// bound is only global if exactly one accountant exists per root. A freely
    /// callable constructor made "two handles on one root" expressible, and two
    /// registries each admit up to the full global and per-principal limits —
    /// so the bound silently became per-handle. [`RecoverySession`] holds the
    /// root-wide `LOCK` and can only be obtained by taking it, which closes the
    /// cross-process half; `OPEN_STAGING_ROOTS` closes the in-process half.
    /// Together they make the second instance unrepresentable rather than
    /// discouraged.
    ///
    /// The lock's root must be *this* root: a lock on a different root proves
    /// nothing about this one, and accepting it would turn the proof back into
    /// a convention.
    ///
    /// Construction is where accounting is rebuilt (see [`Self::reconstruct`]).
    /// A root-global count that ignored what is already durable would be a
    /// count of this process's uptime, not of the root.
    ///
    /// The directory is created and its parent synced here rather than lazily,
    /// so the same-device check at session creation compares two directories
    /// that both actually exist. A check against a path that is about to be
    /// created would compare the device of whatever `metadata` happened to
    /// resolve, which is how a same-device assertion becomes decorative.
    pub fn open(
        lock: &RecoverySession,
        options: StoreOptions,
        durability: Arc<DurabilityCounters>,
    ) -> Result<Arc<Self>, StoreError> {
        Self::open_with_device_probe(lock, options, durability, Box::new(StatDeviceProbe))
    }

    fn open_with_device_probe(
        lock: &RecoverySession,
        options: StoreOptions,
        durability: Arc<DurabilityCounters>,
        device: Box<dyn DeviceProbe>,
    ) -> Result<Arc<Self>, StoreError> {
        options.validate()?;
        let canonical_root = std::fs::canonicalize(&options.root)?;
        let locked_root = std::fs::canonicalize(lock.root())?;
        if canonical_root != locked_root {
            return Err(StoreError::InvalidConfiguration(format!(
                "projection staging for {} was offered a root lock held on {}; a lock on \
                 another root proves nothing about this one",
                canonical_root.display(),
                locked_root.display()
            )));
        }
        {
            let mut roots = open_staging_roots()
                .lock()
                .expect("staging root registry mutex poisoned");
            if !roots.insert(canonical_root.clone()) {
                return Err(StoreError::Conflict(format!(
                    "projection staging is already open for {}; its ceilings are root-global \
                     and a second registry would admit a second full budget",
                    canonical_root.display()
                )));
            }
        }

        let staging_root = options.root.join(STAGING_DIR);
        if !staging_root.exists() {
            std::fs::create_dir_all(&staging_root)?;
            crate::sys::fsync_dir(&options.root, &durability)?;
        }
        let maintenance = MaintenancePool::new(&options.root);
        let staging = Arc::new(Self {
            options,
            staging_root,
            canonical_root,
            counters: Arc::new(StagingCounters::default()),
            durability,
            device,
            registry: Mutex::new(Registry::default()),
            maintenance,
        });
        staging.reconstruct()?;
        Ok(staging)
    }

    pub fn counters(&self) -> &Arc<StagingCounters> {
        &self.counters
    }

    pub fn staging_root(&self) -> &Path {
        &self.staging_root
    }

    // --- restart reconstruction (deliverable 1: "restartable") -------------

    /// Rebuild every durable session, its chunk index, and the whole occupancy
    /// account from `<root>/staging`.
    ///
    /// **A durable session directory and an abandoned materialization are
    /// different states and must never share a cleanup path.** The commit point
    /// of a session is the `rename_noreplace` that installs its `session`
    /// record: the record is written to a temporary, fenced, and renamed, so
    /// the final name only ever appears over complete, digest-checked bytes.
    /// Therefore:
    ///
    ///   * a directory holding a valid `session` record for its own ID is a
    ///     **final session**. It is reconstructed, it charges budget, and its
    ///     ID is thereafter occupied — which is what stops a reopen from
    ///     admitting it as new and then destroying it from an error path;
    ///   * a directory with no such record is an **abandoned materialization**:
    ///     a crash or an error between `create_dir` and that rename. Nothing
    ///     ever accounted for it and nothing can reference it, so it is
    ///     reclaimed here — through the same validate-the-whole-directory-first
    ///     path everything else uses, never `remove_dir_all`.
    ///
    /// Reconstruction charges budget without evaluating the ceilings. A root
    /// whose durable occupancy exceeds a newly lowered configuration must still
    /// open, or lowering a limit would strand the very sessions the operator
    /// needs to expire; admission then refuses new work until the durable set
    /// drains, which is the enforcement the ceiling actually owes.
    fn reconstruct(self: &Arc<Self>) -> Result<(), StoreError> {
        let mut abandoned: Vec<([u8; 16], PathBuf)> = Vec::new();
        for shard_entry in std::fs::read_dir(&self.staging_root)? {
            let shard_path = shard_entry?.path();
            let Some(shard_index) = self.shard_index_of_directory(&shard_path) else {
                self.counters.unrecognized_entries.fetch_add(1, Relaxed);
                continue;
            };
            for session_entry in std::fs::read_dir(&shard_path)? {
                let session_path = session_entry?.path();
                let Some(session_id) = session_directory_id(&session_path) else {
                    self.counters.unrecognized_entries.fetch_add(1, Relaxed);
                    continue;
                };
                match self.reconstruct_session(shard_index, &session_path, session_id)? {
                    Some(record) => {
                        self.insert_reconstructed(session_id, record);
                        self.counters.sessions_reconstructed.fetch_add(1, Relaxed);
                    }
                    None => abandoned.push((session_id, session_path)),
                }
            }
        }
        for (session_id, path) in abandoned {
            self.reclaim_directory(path, session_id)?;
            self.counters
                .abandoned_materializations_reclaimed
                .fetch_add(1, Relaxed);
        }
        Ok(())
    }

    fn shard_index_of_directory(&self, path: &Path) -> Option<u16> {
        if !path.is_dir() {
            return None;
        }
        let name = path.file_name()?.to_str()?;
        if name.len() != 2 {
            return None;
        }
        let index: u16 = name.parse().ok()?;
        (index < self.options.shard_count).then_some(index)
    }

    /// `Ok(None)` is "abandoned materialization", not "nothing to see".
    fn reconstruct_session(
        &self,
        shard_index: u16,
        directory: &Path,
        session_id: [u8; 16],
    ) -> Result<Option<SessionRecord>, StoreError> {
        let record_path = directory.join(SESSION_RECORD_NAME);
        if !record_path.exists() {
            return Ok(None);
        }
        let payload =
            read_staging_artifact(&record_path, StagingArtifactKind::SessionRecord, session_id)?;
        if payload.len() < 32 {
            return Err(StoreError::Corruption(format!(
                "staging session record {} is shorter than its membership root",
                record_path.display()
            )));
        }
        let mut root_bytes = [0u8; 32];
        root_bytes.copy_from_slice(&payload[..32]);
        let session = ProjectionStageSessionV1::decode_canonical(&payload[32..]).map_err(|e| {
            StoreError::Corruption(format!(
                "staging session record {} no longer decodes: {e}",
                record_path.display()
            ))
        })?;
        if session.session_id != session_id {
            return Err(StoreError::Corruption(format!(
                "staging session record {} names session {} but lives under {}",
                record_path.display(),
                hex::encode(session.session_id),
                hex::encode(session_id)
            )));
        }
        let expected_shard = StoreOptions::shard_of(
            &NamespaceId::from(session.destination_repo),
            self.options.shard_count,
        );
        if expected_shard != shard_index {
            return Err(StoreError::Corruption(format!(
                "staging session {} is stored under shard {shard_index} but its destination \
                 repository belongs to shard {expected_shard}",
                hex::encode(session_id)
            )));
        }
        let binding = ProjectionStageBinding {
            session,
            membership_root: ObjectId(root_bytes),
        };

        let mut chunks: BTreeMap<u32, ChunkSlot> = BTreeMap::new();
        let mut sealed_manifest: Option<PathBuf> = None;
        let mut adoption: Option<(AdoptionMark, u64)> = None;
        let mut written_objects = 0u64;
        let mut written_bytes = 0u64;
        for entry in std::fs::read_dir(directory)? {
            let path = entry?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                self.counters.unrecognized_entries.fetch_add(1, Relaxed);
                continue;
            };
            if !path.is_file() {
                self.counters.unrecognized_entries.fetch_add(1, Relaxed);
                continue;
            }
            // A `.tmp` never survived a rename, so it is by construction not
            // durable state. It is left where it is; reclamation removes it.
            if name.ends_with(".tmp") || name == SESSION_RECORD_NAME {
                continue;
            }
            if name == MANIFEST_NAME {
                sealed_manifest = Some(path);
                continue;
            }
            if name == ADOPTION_NAME {
                adoption = Some(read_adoption_marker(&path, session_id, &binding.session)?);
                continue;
            }
            let Some((ordinal, digest_from_name)) = parse_chunk_artifact_name(name) else {
                self.counters.unrecognized_entries.fetch_add(1, Relaxed);
                continue;
            };
            let bytes = read_staging_artifact(&path, StagingArtifactKind::Chunk, session_id)?;
            let chunk = ProjectionStageChunkV1::decode_canonical(&bytes).map_err(|e| {
                StoreError::Corruption(format!(
                    "staged chunk artifact {} no longer decodes: {e}",
                    path.display()
                ))
            })?;
            let digest = chunk.chunk_digest().map_err(|e| {
                StoreError::Corruption(format!(
                    "staged chunk artifact {} digest: {e}",
                    path.display()
                ))
            })?;
            if digest != digest_from_name
                || chunk.ordinal != ordinal
                || chunk.session_id != session_id
                || chunk.chunk_count != binding.session.chunk_count
            {
                return Err(StoreError::Corruption(format!(
                    "staged chunk artifact {} no longer matches the ordinal, digest, session, \
                     or chunk count it was stored under",
                    path.display()
                )));
            }
            written_objects = written_objects
                .checked_add(u64::try_from(chunk.objects.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| {
                    StoreError::Corruption("reconstructed staged object count overflowed".into())
                })?;
            for object in &chunk.objects {
                written_bytes = written_bytes
                    .checked_add(object.descriptor.raw_len)
                    .ok_or_else(|| {
                        StoreError::Corruption("reconstructed staged bytes overflowed".into())
                    })?;
            }
            let file_bytes = std::fs::metadata(&path)?.len();
            if chunks
                .insert(
                    ordinal,
                    ChunkSlot::Stored(StoredChunk {
                        digest,
                        path: path.clone(),
                        file_bytes,
                    }),
                )
                .is_some()
            {
                return Err(StoreError::Corruption(format!(
                    "staging session {} has two durable artifacts for chunk ordinal {ordinal}",
                    hex::encode(session_id)
                )));
            }
        }

        let reservation = Reservation {
            objects: binding.session.total_object_count,
            bytes: binding.session.total_object_bytes,
            files: u64::from(binding.session.chunk_count)
                .checked_add(SESSION_FIXED_FILES)
                .ok_or_else(|| {
                    StoreError::Corruption("reconstructed staging file count overflowed".into())
                })?,
        };

        // A durable manifest artifact is the seal's own commit point, so its
        // presence — not a flag — is what makes the session `Sealed` again, and
        // the adoption marker beside it is what carries the pin across the
        // process boundary. A marker without a manifest is not a state this
        // store can produce: `finalize` only admits a sealed session, and the
        // marker is written after the manifest is durable. Refusing it is the
        // difference between reconstructing a pin and inventing one.
        let mut adopted_at: Option<u64> = None;
        let (state, resolution) = match (sealed_manifest, adoption) {
            (None, None) => (StagedSessionState::Open, None),
            (None, Some(_)) => {
                return Err(StoreError::Corruption(format!(
                    "staging session {} carries an adoption marker with no sealed manifest",
                    hex::encode(session_id)
                )))
            }
            (Some(path), mark) => {
                let resolution =
                    self.reconstruct_resolution(&path, &binding, session_id, &chunks)?;
                let state = match mark {
                    None => StagedSessionState::Sealed,
                    Some((AdoptionMark::Finalizing, _)) => StagedSessionState::Finalizing,
                    Some((AdoptionMark::Adopted, at)) => {
                        adopted_at = Some(at);
                        StagedSessionState::Adopted
                    }
                };
                (state, Some(resolution))
            }
        };

        // An adopted session's bytes are store content, not staging occupancy.
        // Reconstructing its reservation would re-charge, on every restart, a
        // budget the adoption released — a ceiling that quietly shrinks each
        // time the process comes back.
        let reservation = match state {
            StagedSessionState::Open
            | StagedSessionState::Sealed
            | StagedSessionState::Finalizing => reservation,
            StagedSessionState::Adopted => Reservation::default(),
        };

        Ok(Some(SessionRecord {
            binding,
            shard_index,
            directory: directory.to_path_buf(),
            state,
            busy: SessionBusy::Idle,
            chunks,
            written_objects,
            written_bytes,
            reservation,
            resolution,
            adopted_at_shard_sequence: adopted_at,
        }))
    }

    fn reconstruct_resolution(
        &self,
        manifest_path: &Path,
        binding: &ProjectionStageBinding,
        session_id: [u8; 16],
        chunks: &BTreeMap<u32, ChunkSlot>,
    ) -> Result<Arc<ProjectionAdoptionResolution>, StoreError> {
        let bytes =
            read_staging_artifact(manifest_path, StagingArtifactKind::Manifest, session_id)?;
        let manifest = ProjectionStageManifestV1::decode_canonical(&bytes).map_err(|e| {
            StoreError::Corruption(format!(
                "sealed staging manifest {} no longer decodes: {e}",
                manifest_path.display()
            ))
        })?;
        let manifest_digest = manifest.manifest_digest().map_err(|e| {
            StoreError::Corruption(format!(
                "sealed staging manifest {} digest: {e}",
                manifest_path.display()
            ))
        })?;
        if manifest.session_id != session_id
            || manifest.membership_root != binding.membership_root
            || manifest_digest != binding.session.manifest_digest
        {
            return Err(StoreError::Corruption(format!(
                "sealed staging manifest {} no longer reconstructs the digest its session binds",
                manifest_path.display()
            )));
        }
        let mut artifacts = Vec::with_capacity(chunks.len());
        for ordinal in 0..binding.session.chunk_count {
            let stored = chunks
                .get(&ordinal)
                .and_then(ChunkSlot::stored)
                .ok_or_else(|| {
                    StoreError::Corruption(format!(
                        "sealed staging session {} is missing durable chunk ordinal {ordinal}",
                        hex::encode(session_id)
                    ))
                })?;
            artifacts.push(ProjectionArtifact {
                path: stored.path.clone(),
                digest: stored.digest,
                bytes: stored.file_bytes,
            });
        }
        Ok(Arc::new(ProjectionAdoptionResolution {
            session: binding.session.clone(),
            manifest,
            artifacts: Arc::from(artifacts),
        }))
    }

    /// Charge a reconstructed session's budget. No ceiling is evaluated; see
    /// [`Self::reconstruct`].
    fn insert_reconstructed(&self, session_id: [u8; 16], record: SessionRecord) {
        let principal = record.principal();
        let reservation = record.reservation;
        let written_bytes = record.written_bytes;
        let mut registry = self.lock();
        let entry = registry.principals.entry(principal).or_default();
        entry.sessions += 1;
        entry.objects += reservation.objects;
        entry.bytes += reservation.bytes;
        entry.files += reservation.files;
        registry.global.sessions += 1;
        registry.global.objects += reservation.objects;
        registry.global.bytes += reservation.bytes;
        registry.global.files += reservation.files;
        registry.debt_reserved_bytes += reservation.bytes;
        registry.sessions.insert(session_id, record);
        drop(registry);

        let counters = &self.counters;
        counters.sessions_live.fetch_add(1, Relaxed);
        counters
            .reserved_objects
            .fetch_add(reservation.objects, Relaxed);
        counters
            .reserved_bytes
            .fetch_add(reservation.bytes, Relaxed);
        counters
            .reserved_files
            .fetch_add(reservation.files, Relaxed);
        counters
            .compaction_debt_reserved_bytes
            .fetch_add(reservation.bytes, Relaxed);
        counters
            .compaction_debt_written_bytes
            .fetch_add(written_bytes, Relaxed);
    }

    /// Begin one session. Every refusal below happens before any budget is
    /// charged and before any file exists.
    pub fn begin(
        self: &Arc<Self>,
        binding: ProjectionStageBinding,
        now_micros: i64,
    ) -> Result<ProjectionStageSession, StoreError> {
        match self.begin_inner(binding, now_micros) {
            Ok(session) => Ok(session),
            Err(error) => {
                self.counters.sessions_refused.fetch_add(1, Relaxed);
                Err(error)
            }
        }
    }

    fn begin_inner(
        self: &Arc<Self>,
        binding: ProjectionStageBinding,
        now_micros: i64,
    ) -> Result<ProjectionStageSession, StoreError> {
        // 1. The frozen binding must be internally well formed. `session_digest`
        //    runs `ProjectionStageSessionV1::validate`, which is where the
        //    nonzero-totals and Fork-proof-presence rules live. Restating them
        //    here would create a second opinion about a frozen contract.
        let session_id = binding.session.session_id;
        binding
            .session
            .session_digest()
            .map_err(|e| StoreError::Conflict(format!("projection stage session binding: {e}")))?;

        // 2. Declared shape against the configured projection ceilings.
        //
        //    The per-session `MAX_CANONICAL_ITEMS` checks that used to sit here
        //    are **deliberately gone.** Contract review 2026-07-28-A caps
        //    `max_projection_objects` and `max_projection_chunks` at that
        //    constant in `StoreOptions::validate`, so no configuration this
        //    store can open admits a declaration that reaches them. A typed
        //    refusal no caller can ever observe is not a belt: it advertises a
        //    limit name that will never appear in a real error, and it is a
        //    second opinion about a bound the configuration already owns —
        //    which is the exact defect the review deleted four copies of.
        let options = &self.options;
        require_at_most(
            "max_projection_objects",
            binding.session.total_object_count,
            options.max_projection_objects,
        )?;
        require_at_most(
            "max_projection_bytes",
            binding.session.total_object_bytes,
            options.max_projection_bytes,
        )?;
        require_at_most(
            "max_projection_chunks",
            u64::from(binding.session.chunk_count),
            u64::from(options.max_projection_chunks),
        )?;
        // 3. Age and feasibility. `expires_at_micros` is the advertised
        //    maximum: there is no renewal entry point on this type, so the
        //    only way to outlive it is to create a new session, which pays for
        //    a new budget.
        let lifetime = binding
            .session
            .expires_at_micros
            .checked_sub(now_micros)
            .ok_or_else(|| {
                StoreError::Conflict("staging session lifetime arithmetic overflowed".into())
            })?;
        if lifetime <= 0 {
            return Err(StoreError::Conflict(format!(
                "staging session {} expires at {} which is not after {now_micros}",
                hex::encode(session_id),
                binding.session.expires_at_micros
            )));
        }
        require_at_most(
            "staging_session_max_age_micros",
            u64::try_from(lifetime).expect("positive lifetime fits u64"),
            u64::try_from(options.staging_session_max_age_micros)
                .expect("options.rs refuses a non-positive maximum age"),
        )?;
        self.require_feasible(&binding, lifetime)?;

        // 4. Same device. Checked before any budget is charged, because a
        //    session on the wrong device can never be adopted at all.
        let shard_index = StoreOptions::shard_of(
            &NamespaceId::from(binding.session.destination_repo),
            options.shard_count,
        );
        self.require_same_device(shard_index)?;

        // 5. Occupancy. Ceilings and insertion under one lock acquisition.
        let directory = self.session_directory(shard_index, &session_id);
        let reservation = Reservation {
            objects: binding.session.total_object_count,
            bytes: binding.session.total_object_bytes,
            files: u64::from(binding.session.chunk_count)
                .checked_add(SESSION_FIXED_FILES)
                .ok_or_else(|| {
                    StoreError::Conflict("staging session file count overflowed".into())
                })?,
        };
        require_at_most(
            "staging_max_files_per_session",
            reservation.files,
            options.staging_max_files_per_session,
        )?;
        self.admit(
            &binding,
            shard_index,
            directory.clone(),
            reservation,
            now_micros,
        )?;

        // 6. Only now does anything exist on disk. A failure here releases the
        //    budget rather than stranding it: a reservation nobody can abort
        //    is the leak the bound exists to prevent.
        //
        //    The cleanup is the validated reclaim, never `remove_dir_all`. A
        //    recursive delete keyed only on a path is how an ordinary restart
        //    plus a materialization error destroys a session that was already
        //    durable; reclamation here removes only files this exact session
        //    could have written, and leaves the directory standing if it finds
        //    anything else.
        if let Err(error) = self.materialize(&binding, &directory) {
            self.release(session_id);
            let _ = self.reclaim_directory(directory, session_id);
            return Err(error);
        }

        self.counters.sessions_created.fetch_add(1, Relaxed);
        Ok(ProjectionStageSession {
            staging: Arc::clone(self),
            session_id,
        })
    }

    /// Reattach to a live session by ID. This is what makes a session
    /// restartable: the handle carries no state, so a caller that lost it —
    /// or a fresh request for the same transfer — resumes with the same
    /// budget, the same artifacts, and the same idempotent ordinals.
    pub fn session(
        self: &Arc<Self>,
        session_id: [u8; 16],
    ) -> Result<ProjectionStageSession, StoreError> {
        let registry = self.lock();
        if !registry.sessions.contains_key(&session_id) {
            return Err(unknown_session(session_id));
        }
        drop(registry);
        Ok(ProjectionStageSession {
            staging: Arc::clone(self),
            session_id,
        })
    }

    /// Reclaim every session whose advertised expiry has passed.
    ///
    /// Legal in this pass only because no state reachable here can hold an
    /// adoption pin: `StagedSessionState` has exactly `Open` and `Sealed`, and
    /// neither has been handed to `submit`. Deliverable 6 adds `Finalizing`,
    /// and deliverable 7 adds the committed-root reference proof; the match
    /// below is exhaustive so both arrive as compile errors here rather than
    /// as a silent reclamation of pinned artifacts.
    pub fn expire(&self, now_micros: i64) -> Result<u64, StoreError> {
        // The candidate set is computed under the lock; every reclamation then
        // runs on a maintenance worker with the lock released, so an expiry
        // sweep never makes admission wait on a directory walk.
        let registry = self.lock();
        let expired: Vec<[u8; 16]> = registry
            .sessions
            .iter()
            .filter(|(_, record)| {
                let past_expiry = now_micros > record.binding.session.expires_at_micros;
                let idle = match record.busy {
                    SessionBusy::Idle => true,
                    // Mid-maintenance; the next sweep takes it.
                    SessionBusy::Sealing | SessionBusy::Finalizing | SessionBusy::Reclaiming => {
                        false
                    }
                };
                past_expiry
                    && idle
                    && match record.state {
                        StagedSessionState::Open | StagedSessionState::Sealed => true,
                        // The named acceptance case of deliverable 6: expiry
                        // prevents a *new* finalizer but must never delete
                        // artifacts an already-admitted one holds. `finalize`
                        // takes `require_live` under the same registry lock this
                        // sweep uses, so the race has exactly two orderings and
                        // both are safe — expiry first reclaims a session no
                        // finalizer can then admit, finalize first leaves a
                        // pinned session this arm declines.
                        StagedSessionState::Finalizing => false,
                        // Not staging occupancy any more, and not expiry's to
                        // reclaim: a committed transaction may reference these
                        // artifacts, and only a proof against a `CommittedRoot`
                        // can say. That proof is cleanup's (deliverable 7).
                        StagedSessionState::Adopted => false,
                    }
            })
            .map(|(id, _)| *id)
            .collect();
        drop(registry);

        let mut reclaimed = 0u64;
        for session_id in expired {
            self.reclaim_session(session_id)?;
            self.counters.sessions_expired.fetch_add(1, Relaxed);
            reclaimed += 1;
        }
        Ok(reclaimed)
    }

    /// Remove staged artifacts no committed root references.
    ///
    /// Deliverable 7. The candidate set is exactly the **adopted** sessions, and
    /// that is the whole design rather than a filter on it:
    ///
    /// * `Open` and `Sealed` are live and belong to expiry and abort, which
    ///   already own them and already know when they are dead.
    /// * `Finalizing` holds an outstanding pin. Nothing in this process knows
    ///   whether a frame naming its artifacts is about to be appended, so there
    ///   is nothing to prove absence *of* yet.
    /// * `Adopted` is the one state where the artifacts are store content and
    ///   the question "does anything still point at them?" is both meaningful
    ///   and answerable. A checkpoint or a compaction that stops referencing an
    ///   adopted projection is what eventually makes its directory reclaimable,
    ///   and this is the only path that may remove it.
    ///
    /// # Whole directories, not individual artifacts
    ///
    /// The deliverable's wording is per-artifact and the unit here is the
    /// session, deliberately. A session's chunks are not independent files: the
    /// manifest names all of them, and reconstruction refuses a sealed session
    /// missing any ordinal. Removing the unreferenced half of a directory would
    /// leave a session that no longer reconstructs — trading a bounded leak for
    /// a root that fails to open — so a session is reclaimed only when *nothing*
    /// in it is referenced. `reclaim_session_directory` then applies the
    /// per-artifact rule that clause is really about: it removes only files
    /// carrying this session's own marker, and refuses the whole directory if it
    /// finds anything else.
    ///
    /// # The supplied root has to be new enough to be evidence
    ///
    /// A caller passes the root it holds, and a root captured **before** a
    /// session was adopted references none of that session's artifacts — for the
    /// trivial reason that it predates every reference the adoption created.
    /// Absence measured against it is a date, not an absence, and acting on it
    /// deletes a directory the *current* root points into.
    ///
    /// So each adopted session carries the committed shard sequence its adoption
    /// frame reached, and is skipped unless the supplied root has reached at
    /// least that far. A root at or past it necessarily includes the adoption's
    /// effects, which is what makes the absence real.
    ///
    /// I had this backwards in review and it is worth stating plainly: the
    /// argument "a racing newer root can only *add* references" is an argument
    /// for the hazard, not against it. Adding references is precisely what makes
    /// an older root omit them.
    pub fn cleanup_unreferenced(&self, root: &CommittedRoot) -> Result<u64, StoreError> {
        let candidates: Vec<([u8; 16], PathBuf, u16, Option<u64>)> = {
            let mut registry = self.lock();
            let eligible: Vec<[u8; 16]> = registry
                .sessions
                .iter()
                .filter(|(_, record)| match record.state {
                    StagedSessionState::Adopted => true,
                    StagedSessionState::Open
                    | StagedSessionState::Sealed
                    | StagedSessionState::Finalizing => false,
                })
                .filter(|(_, record)| matches!(record.busy, SessionBusy::Idle))
                .map(|(session_id, _)| *session_id)
                .collect();
            // Marked `Reclaiming` under the same acquisition that selected them,
            // so nothing can begin operating on a session between the choice and
            // the exclusion.
            let mut candidates = Vec::with_capacity(eligible.len());
            for session_id in eligible {
                if let Some(record) = registry.sessions.get_mut(&session_id) {
                    record.busy = SessionBusy::Reclaiming;
                    candidates.push((
                        session_id,
                        record.directory.clone(),
                        record.shard_index,
                        record.adopted_at_shard_sequence,
                    ));
                }
            }
            candidates
        };

        let mut reclaimed = 0u64;
        for (session_id, directory, shard_index, recorded) in candidates {
            // The position is what makes the absence proof below evidence rather
            // than a date. A session missing one is not reclaimable at all: an
            // adopted session always records where it was adopted, so its
            // absence means this store cannot say when the reference it is about
            // to disprove came into existence.
            let adopted_at = match recorded {
                Some(sequence) => sequence,
                None => {
                    self.clear_busy(session_id);
                    continue;
                }
            };
            // `Some(0)` and `None` are different answers and only one of them is
            // evidence. Zero is a valid committed sequence, so defaulting an
            // absent entry to it makes a root that says *nothing* about this
            // shard indistinguishable from one that has committed through its
            // first frame — and an adoption at sequence 0 becomes reclaimable
            // through a root that never mentioned the shard it lives on.
            let reached = matches!(
                root.shard_committed_sequence(shard_index),
                Some(through) if through >= adopted_at
            );
            if !reached {
                self.counters
                    .cleanup_declined_stale_root
                    .fetch_add(1, Relaxed);
                self.clear_busy(session_id);
                continue;
            }
            match self.session_is_unreferenced(root, &directory, session_id, adopted_at) {
                Ok(true) => {}
                Ok(false) => {
                    self.clear_busy(session_id);
                    continue;
                }
                Err(error) => {
                    self.clear_busy(session_id);
                    return Err(error);
                }
            }
            match self.reclaim_directory(directory, session_id) {
                Ok(()) => {
                    let mut registry = self.lock();
                    // The reservation was already released at adoption, so this
                    // only drops the record. Releasing twice is why
                    // `release_reservation_locked` zeroes as it goes.
                    self.release_locked(&mut registry, session_id);
                    drop(registry);
                    self.counters.sessions_cleaned_up.fetch_add(1, Relaxed);
                    reclaimed += 1;
                }
                Err(error) => {
                    self.clear_busy(session_id);
                    return Err(error);
                }
            }
        }
        Ok(reclaimed)
    }

    /// Does the committed root reference nothing in this session's directory?
    ///
    /// Every file is checked, not only the chunks. A root that pinned a
    /// session's manifest and nothing else would still be holding that
    /// directory, and answering on chunks alone would delete the file it holds.
    fn session_is_unreferenced(
        &self,
        root: &CommittedRoot,
        directory: &Path,
        session_id: [u8; 16],
        adopted_at: u64,
    ) -> Result<bool, StoreError> {
        let _ = adopted_at;
        if !directory.exists() {
            return Ok(true);
        }
        let directory = directory.to_path_buf();
        let entries = self.run_maintenance(move || {
            let mut paths = Vec::new();
            for entry in std::fs::read_dir(&directory)? {
                paths.push(entry?.path());
            }
            Ok(paths)
        })?;
        for path in entries {
            if root.references_artifact(&path) {
                self.counters
                    .cleanup_declined_referenced
                    .fetch_add(1, Relaxed);
                let _ = session_id;
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn clear_busy(&self, session_id: [u8; 16]) {
        let mut registry = self.lock();
        if let Some(record) = registry.sessions.get_mut(&session_id) {
            record.busy = SessionBusy::Idle;
        }
    }

    // --- internals ------------------------------------------------------

    fn lock(&self) -> RegistryGuard<'_> {
        // Poisoning means a panic left the accounting half-applied. Continuing
        // on it would spend a budget nobody can release, so this fails loudly.
        let guard = self
            .registry
            .lock()
            .expect("staging registry mutex poisoned by a panic mid-accounting");
        REGISTRY_LOCK_DEPTH.with(|depth| depth.set(depth.get() + 1));
        RegistryGuard(guard)
    }

    /// Run one unit of filesystem work on a maintenance worker.
    ///
    /// The assertion is the deliverable. It is checked on every dispatch rather
    /// than reviewed once, because "no disk I/O under the registry lock" is a
    /// property a future edit removes by accident — moving a `write_artifact`
    /// call three lines up is all it takes — and nothing else in the crate
    /// would notice.
    fn run_maintenance<T: Send + 'static>(
        &self,
        job: impl FnOnce() -> Result<T, StoreError> + Send + 'static,
    ) -> Result<T, StoreError> {
        assert_eq!(
            REGISTRY_LOCK_DEPTH.with(Cell::get),
            0,
            "staging dispatched filesystem work while holding the registry mutex; the \
             registry is where every root-global ceiling is evaluated and it may not be \
             held across a disk write (scope 6.5 deliverable 5)"
        );
        let sender = self
            .maintenance
            .jobs
            .as_ref()
            .expect("the maintenance channel is closed only by Drop");
        let (reply, answer) = crossbeam_channel::bounded(1);
        let counters = Arc::clone(&self.counters);
        sender
            .send(Box::new(move || {
                let result = job();
                counters.maintenance_jobs.fetch_add(1, Relaxed);
                let _ = reply.send(result);
            }))
            .map_err(|_| {
                StoreError::Corruption("staging maintenance workers are not running".into())
            })?;
        answer.recv().map_err(|_| {
            StoreError::Corruption("a staging maintenance worker died mid-artifact".into())
        })?
    }

    fn session_directory(&self, shard_index: u16, session_id: &[u8; 16]) -> PathBuf {
        self.staging_root
            .join(format!("{shard_index:02}"))
            .join(hex::encode(session_id))
    }

    fn shard_directory(&self, shard_index: u16) -> PathBuf {
        self.options
            .root
            .join("shards")
            .join(format!("{shard_index:02}"))
    }

    /// `<root>/staging` and the target shard must share an `st_dev`.
    ///
    /// Adoption is a `link` into the shard's generation, exactly as scope 3.4's
    /// seal is, and `link(2)` across devices is `EXDEV`. A copy fallback is
    /// forbidden rather than merely unimplemented: a copy is not a rename, so
    /// it reintroduces a window in which the adopted bytes exist under neither
    /// a durable staging name nor a manifest-referenced one. Refusing here
    /// costs one `stat`; discovering it at adoption costs a full transfer.
    fn require_same_device(&self, shard_index: u16) -> Result<(), StoreError> {
        let shard = self.shard_directory(shard_index);
        let staging_device = self.device.device_of(&self.staging_root)?;
        let shard_device = self.device.device_of(&shard)?;
        if staging_device != shard_device {
            return Err(StoreError::InvalidConfiguration(format!(
                "{} is on device {staging_device} and {} is on device {shard_device}; \
                 adoption is a link and a link across devices is not a rename, and a \
                 copy fallback is forbidden",
                self.staging_root.display(),
                shard.display()
            )));
        }
        Ok(())
    }

    /// One complete transfer must fit in the session's own lifetime at the
    /// supported floor rate, with the finalize margin left over.
    ///
    /// `options.rs` already proves the *configured maximum* is feasible at
    /// startup. This is the per-session instance of the same arithmetic
    /// against the bytes this session actually declares and the expiry it
    /// actually asks for, which startup cannot see. A session that cannot
    /// finish consumes budget for its whole life and then fails.
    fn require_feasible(
        &self,
        binding: &ProjectionStageBinding,
        lifetime_micros: i64,
    ) -> Result<(), StoreError> {
        let floor = self.options.minimum_projection_transfer_bytes_per_second;
        let seconds = binding
            .session
            .total_object_bytes
            .checked_add(floor - 1)
            .map(|rounded| rounded / floor)
            .ok_or_else(|| {
                StoreError::Conflict("staged transfer duration arithmetic overflowed".into())
            })?;
        let transfer_micros = seconds
            .checked_mul(1_000_000)
            .and_then(|micros| i64::try_from(micros).ok())
            .ok_or_else(|| {
                StoreError::Conflict("staged transfer duration does not fit i64 micros".into())
            })?;
        let required = transfer_micros
            .checked_add(self.options.staging_finalize_margin_micros)
            .ok_or_else(|| {
                StoreError::Conflict("staged transfer plus finalize margin overflowed".into())
            })?;
        if required > lifetime_micros {
            return Err(StoreError::LimitExceeded {
                limit: "staging_session_transfer_feasibility_micros",
                observed: u64::try_from(required).unwrap_or(u64::MAX),
                allowed: u64::try_from(lifetime_micros).unwrap_or(0),
            });
        }
        Ok(())
    }

    /// Evaluate every occupancy ceiling and insert, under one lock.
    fn admit(
        &self,
        binding: &ProjectionStageBinding,
        shard_index: u16,
        directory: PathBuf,
        reservation: Reservation,
        now_micros: i64,
    ) -> Result<(), StoreError> {
        let options = &self.options;
        let principal = binding.session.actor;
        let session_id = binding.session.session_id;
        let mut registry = self.lock();

        if registry.sessions.contains_key(&session_id) {
            return Err(StoreError::Conflict(format!(
                "staging session {} already exists; a session is restartable by ID, \
                 not re-creatable",
                hex::encode(session_id)
            )));
        }

        let used = registry
            .principals
            .get(&principal)
            .copied()
            .unwrap_or_default();
        let global = registry.global;
        let retry_after = registry.retry_after_micros(now_micros, options);

        overload_at_most(
            "staging_max_sessions_per_principal",
            used.sessions + 1,
            u64::from(options.staging_max_sessions_per_principal),
            retry_after,
        )?;
        overload_at_most(
            "staging_max_sessions_global",
            global.sessions + 1,
            u64::from(options.staging_max_sessions_global),
            retry_after,
        )?;
        overload_sum(
            "staging_max_objects_per_principal",
            used.objects,
            reservation.objects,
            options.staging_max_objects_per_principal,
            retry_after,
        )?;
        overload_sum(
            "staging_max_objects_global",
            global.objects,
            reservation.objects,
            options.staging_max_objects_global,
            retry_after,
        )?;
        overload_sum(
            "staging_max_bytes_per_principal",
            used.bytes,
            reservation.bytes,
            options.staging_max_bytes_per_principal,
            retry_after,
        )?;
        overload_sum(
            "staging_max_bytes_global",
            global.bytes,
            reservation.bytes,
            options.staging_max_bytes_global,
            retry_after,
        )?;
        overload_sum(
            "staging_max_files_per_principal",
            used.files,
            reservation.files,
            options.staging_max_files_per_principal,
            retry_after,
        )?;
        overload_sum(
            "staging_max_files_global",
            global.files,
            reservation.files,
            options.staging_max_files_global,
            retry_after,
        )?;
        // Compaction debt is reserved from the declared bytes, not accrued as
        // chunks land. Charging it on arrival would let a session be admitted
        // whose completion is already guaranteed to breach the ceiling, which
        // is the same defect the feasibility check exists to prevent one axis
        // over.
        overload_sum(
            "staging_max_compaction_debt_bytes",
            registry.debt_reserved_bytes,
            reservation.bytes,
            options.staging_max_compaction_debt_bytes,
            retry_after,
        )?;

        let entry = registry.principals.entry(principal).or_default();
        entry.sessions += 1;
        entry.objects += reservation.objects;
        entry.bytes += reservation.bytes;
        entry.files += reservation.files;
        registry.global.sessions += 1;
        registry.global.objects += reservation.objects;
        registry.global.bytes += reservation.bytes;
        registry.global.files += reservation.files;
        registry.debt_reserved_bytes += reservation.bytes;
        registry.sessions.insert(
            session_id,
            SessionRecord {
                binding: binding.clone(),
                shard_index,
                directory,
                state: StagedSessionState::Open,
                busy: SessionBusy::Idle,
                chunks: BTreeMap::new(),
                written_objects: 0,
                written_bytes: 0,
                reservation,
                resolution: None,
                adopted_at_shard_sequence: None,
            },
        );

        let counters = &self.counters;
        counters.sessions_live.fetch_add(1, Relaxed);
        counters
            .reserved_objects
            .fetch_add(reservation.objects, Relaxed);
        counters
            .reserved_bytes
            .fetch_add(reservation.bytes, Relaxed);
        counters
            .reserved_files
            .fetch_add(reservation.files, Relaxed);
        counters
            .compaction_debt_reserved_bytes
            .fetch_add(reservation.bytes, Relaxed);
        Ok(())
    }

    /// Release one session's budget. Idempotent by absence.
    fn release(&self, session_id: [u8; 16]) {
        let mut registry = self.lock();
        self.release_locked(&mut registry, session_id);
    }

    /// Release a session's budget while leaving the record in place.
    ///
    /// Adoption ends staging occupancy without ending the directory: the
    /// artifacts are store content from that point and a committed root points
    /// into them, so charging them against staging's ceilings forever would make
    /// every adoption permanently shrink the budget for the next one. The record
    /// stays so cleanup can still identify the directory and prove, against a
    /// `CommittedRoot`, whether anything references it.
    ///
    /// Idempotent by construction: the reservation is zeroed as it is released,
    /// so a repeated call subtracts nothing.
    fn release_reservation_locked(&self, registry: &mut Registry, session_id: [u8; 16]) {
        let Some(record) = registry.sessions.get_mut(&session_id) else {
            return;
        };
        let reservation = std::mem::take(&mut record.reservation);
        let written_bytes = std::mem::take(&mut record.written_bytes);
        let principal = record.principal();
        if let Some(entry) = registry.principals.get_mut(&principal) {
            entry.sessions = entry.sessions.saturating_sub(1);
            entry.objects = entry.objects.saturating_sub(reservation.objects);
            entry.bytes = entry.bytes.saturating_sub(reservation.bytes);
            entry.files = entry.files.saturating_sub(reservation.files);
            if entry.sessions == 0 {
                registry.principals.remove(&principal);
            }
        }
        registry.global.sessions = registry.global.sessions.saturating_sub(1);
        registry.global.objects = registry.global.objects.saturating_sub(reservation.objects);
        registry.global.bytes = registry.global.bytes.saturating_sub(reservation.bytes);
        registry.global.files = registry.global.files.saturating_sub(reservation.files);
        registry.debt_reserved_bytes = registry
            .debt_reserved_bytes
            .saturating_sub(reservation.bytes);

        let counters = &self.counters;
        counters.sessions_live.fetch_sub(1, Relaxed);
        counters
            .reserved_objects
            .fetch_sub(reservation.objects, Relaxed);
        counters
            .reserved_bytes
            .fetch_sub(reservation.bytes, Relaxed);
        counters
            .reserved_files
            .fetch_sub(reservation.files, Relaxed);
        counters
            .compaction_debt_reserved_bytes
            .fetch_sub(reservation.bytes, Relaxed);
        counters
            .compaction_debt_written_bytes
            .fetch_sub(written_bytes, Relaxed);
    }

    fn release_locked(&self, registry: &mut Registry, session_id: [u8; 16]) {
        let Some(record) = registry.sessions.remove(&session_id) else {
            return;
        };
        let principal = record.principal();
        let reservation = record.reservation;
        if let Some(entry) = registry.principals.get_mut(&principal) {
            entry.sessions = entry.sessions.saturating_sub(1);
            entry.objects = entry.objects.saturating_sub(reservation.objects);
            entry.bytes = entry.bytes.saturating_sub(reservation.bytes);
            entry.files = entry.files.saturating_sub(reservation.files);
            if entry.sessions == 0 {
                registry.principals.remove(&principal);
            }
        }
        registry.global.sessions = registry.global.sessions.saturating_sub(1);
        registry.global.objects = registry.global.objects.saturating_sub(reservation.objects);
        registry.global.bytes = registry.global.bytes.saturating_sub(reservation.bytes);
        registry.global.files = registry.global.files.saturating_sub(reservation.files);
        registry.debt_reserved_bytes = registry
            .debt_reserved_bytes
            .saturating_sub(reservation.bytes);

        let counters = &self.counters;
        counters.sessions_live.fetch_sub(1, Relaxed);
        counters
            .reserved_objects
            .fetch_sub(reservation.objects, Relaxed);
        counters
            .reserved_bytes
            .fetch_sub(reservation.bytes, Relaxed);
        counters
            .reserved_files
            .fetch_sub(reservation.files, Relaxed);
        counters
            .compaction_debt_reserved_bytes
            .fetch_sub(reservation.bytes, Relaxed);
        counters
            .compaction_debt_written_bytes
            .fetch_sub(record.written_bytes, Relaxed);
    }

    /// Create the session directory and write the durable session record, on a
    /// maintenance worker.
    ///
    /// The renamed `session` record is this session's durability commit point,
    /// so **every directory entry on the path to it must be synced first.**
    /// Syncing only the immediate parent was a real gap: when
    /// `staging/<shard>` was itself created by this call, its own entry under
    /// `staging/` was never synced, so the first session in a shard could
    /// survive as fenced bytes under a directory that no longer exists.
    fn materialize(
        &self,
        binding: &ProjectionStageBinding,
        directory: &Path,
    ) -> Result<(), StoreError> {
        let mut payload = binding.membership_root.0.to_vec();
        payload.extend_from_slice(
            &binding
                .session
                .encode_canonical()
                .map_err(|e| StoreError::Conflict(format!("staging session record: {e}")))?,
        );
        let bytes = encode_staging_artifact(
            StagingArtifactKind::SessionRecord,
            binding.session.session_id,
            &payload,
        );
        let directory = directory.to_path_buf();
        let staging_root = self.staging_root.clone();
        let durability = Arc::clone(&self.durability);
        let counters = Arc::clone(&self.counters);
        self.run_maintenance(move || {
            create_session_directory(&staging_root, &directory, &durability)?;
            write_artifact(
                &directory,
                SESSION_RECORD_NAME,
                &bytes,
                &durability,
                &counters,
            )?;
            Ok(())
        })
    }

    /// Validate a session directory completely, then reclaim it, on a
    /// maintenance worker.
    fn reclaim_directory(
        &self,
        directory: PathBuf,
        session_id: [u8; 16],
    ) -> Result<(), StoreError> {
        let durability = Arc::clone(&self.durability);
        let counters = Arc::clone(&self.counters);
        self.run_maintenance(move || {
            reclaim_session_directory(&directory, session_id, &durability, &counters)
        })
    }

    /// End one accounted session: exclude it, reclaim its directory off the
    /// registry lock, and release its budget only if the reclamation succeeded.
    ///
    /// The budget is released last on purpose. Releasing first and then failing
    /// would leave files on disk that nothing accounts for and no later call
    /// can name — the leak the bound exists to prevent — while this ordering
    /// leaves a live session and a named error.
    fn reclaim_session(&self, session_id: [u8; 16]) -> Result<(), StoreError> {
        let directory = {
            let mut registry = self.lock();
            let record = registry
                .sessions
                .get_mut(&session_id)
                .ok_or_else(|| unknown_session(session_id))?;
            match record.state {
                StagedSessionState::Open | StagedSessionState::Sealed => {}
                // Reclamation deletes the directory, so it may not run against
                // a session whose artifacts something else is entitled to: an
                // outstanding pin, or a committed root's reference. Both are
                // refused here rather than filtered by every caller, because a
                // caller that forgets is a caller that deletes committed data.
                StagedSessionState::Finalizing | StagedSessionState::Adopted => {
                    return Err(StoreError::Conflict(format!(
                        "staging session {} holds an adoption outcome and may not be \
                         reclaimed by expiry or abort; only a reference proof against a \
                         committed root may remove it",
                        hex::encode(session_id)
                    )))
                }
            }
            match record.busy {
                SessionBusy::Idle => {}
                SessionBusy::Sealing | SessionBusy::Finalizing | SessionBusy::Reclaiming => {
                    return Err(StoreError::Overloaded {
                        limit: "staging_session_maintenance_in_flight",
                        retry_after_micros: 1,
                    })
                }
            }
            record.busy = SessionBusy::Reclaiming;
            record.directory.clone()
        };

        let result = self.reclaim_directory(directory, session_id);
        let mut registry = self.lock();
        match result {
            Ok(()) => {
                self.release_locked(&mut registry, session_id);
                Ok(())
            }
            Err(error) => {
                if let Some(record) = registry.sessions.get_mut(&session_id) {
                    record.busy = SessionBusy::Idle;
                }
                Err(error)
            }
        }
    }
}

impl Registry {
    /// Honest retry guidance: the soonest a live session can free budget is
    /// its own advertised expiry. Derived from the sessions actually holding
    /// the budget, never a constant — a fixed retry hint is a guess that gets
    /// stale in exactly the overloaded state it is issued in.
    fn retry_after_micros(&self, now_micros: i64, options: &StoreOptions) -> u64 {
        self.sessions
            .values()
            .map(|record| record.binding.session.expires_at_micros)
            .map(|expires| expires.saturating_sub(now_micros).max(1))
            .min()
            .map(|micros| u64::try_from(micros).unwrap_or(u64::MAX))
            .unwrap_or_else(|| {
                u64::try_from(options.staging_finalize_margin_micros)
                    .unwrap_or(0)
                    .max(1)
            })
    }
}

/// One staging session. Opaque: begin, idempotent numbered chunk-put,
/// read-only resolver, seal, abort (plan §5.1).
///
/// Dropping this is deliberately not an abort. Sessions are restartable by ID
/// and survive the process; a handle is a way to name one, not ownership of
/// it. The only things that end a session are abort, expiry, and — from
/// deliverable 6 — adoption.
pub struct ProjectionStageSession {
    staging: Arc<ProjectionStaging>,
    session_id: [u8; 16],
}

impl fmt::Debug for ProjectionStageSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectionStageSession")
            .field("session_id", &hex::encode(self.session_id))
            .finish_non_exhaustive()
    }
}

impl ProjectionStageSession {
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Read-only status. Carries no artifact bytes and no adoption capability.
    pub fn describe(&self) -> Result<StagedSessionStatus, StoreError> {
        let registry = self.staging.lock();
        let record = registry
            .sessions
            .get(&self.session_id)
            .ok_or_else(|| unknown_session(self.session_id))?;
        Ok(StagedSessionStatus {
            session_id: self.session_id,
            state: record.state,
            shard_index: record.shard_index,
            // Durable chunks only. An ordinal whose artifact is still being
            // written by a maintenance worker is reserved, not present, and
            // reporting it as present would let a caller conclude a seal would
            // succeed when the bytes are not fenced yet.
            chunks_present: u32::try_from(
                record
                    .chunks
                    .values()
                    .filter(|slot| slot.stored().is_some())
                    .count(),
            )
            .unwrap_or(u32::MAX),
            chunks_expected: record.binding.session.chunk_count,
            written_objects: record.written_objects,
            written_bytes: record.written_bytes,
            expires_at_micros: record.binding.session.expires_at_micros,
        })
    }

    /// Store one numbered chunk, idempotently by ordinal and digest.
    ///
    /// The chunk is validated by the frozen codec before anything is written:
    /// `chunk_digest` runs `ProjectionStageChunkV1::validate`, which checks
    /// framing, embedded types, IDs, exact bytes, canonical order, and the
    /// declared ordinal against the declared chunk count. None of that is
    /// restated here — a second implementation of a frozen validation rule is
    /// a second opinion, and the two only have to disagree once.
    pub fn put_chunk(
        &self,
        chunk: &ProjectionStageChunkV1,
        now_micros: i64,
    ) -> Result<ChunkPutOutcome, StoreError> {
        let canonical = chunk
            .encode_canonical()
            .map_err(|e| StoreError::Conflict(format!("staged chunk: {e}")))?;
        let chunk_digest = chunk
            .chunk_digest()
            .map_err(|e| StoreError::Conflict(format!("staged chunk digest: {e}")))?;

        let staging = &self.staging;
        let mut registry = staging.lock();
        let record = registry
            .sessions
            .get(&self.session_id)
            .ok_or_else(|| unknown_session(self.session_id))?;
        require_open(record, self.session_id)?;
        require_live(record, self.session_id, now_micros)?;
        require_idle(record, self.session_id)?;

        if chunk.session_id != self.session_id {
            return Err(StoreError::Conflict(format!(
                "staged chunk names session {} but was offered to session {}",
                hex::encode(chunk.session_id),
                hex::encode(self.session_id)
            )));
        }
        if chunk.chunk_count != record.binding.session.chunk_count {
            return Err(StoreError::Conflict(format!(
                "staged chunk declares {} chunks but session {} is bound to {}",
                chunk.chunk_count,
                hex::encode(self.session_id),
                record.binding.session.chunk_count
            )));
        }

        // Restartability: an identical ordinal/digest is a repeat of work
        // already durable, so it costs no write. A different digest at a
        // bound ordinal is a different projection wearing the same session,
        // and is refused rather than overwritten.
        if let Some(existing) = record.chunks.get(&chunk.ordinal) {
            if existing.digest() != chunk_digest {
                return Err(StoreError::Conflict(format!(
                    "staged chunk ordinal {} of session {} is already bound to digest {}",
                    chunk.ordinal,
                    hex::encode(self.session_id),
                    hex::encode(existing.digest().0)
                )));
            }
            return match existing {
                ChunkSlot::Stored(_) => {
                    staging.counters.chunks_deduplicated.fetch_add(1, Relaxed);
                    Ok(ChunkPutOutcome::AlreadyPresent)
                }
                // A concurrent identical put is already writing this ordinal.
                // Answering `AlreadyPresent` here would claim durability the
                // artifact has not reached yet, which is the one thing this
                // outcome is relied on to mean.
                ChunkSlot::InFlight { .. } => Err(StoreError::Overloaded {
                    limit: "staging_chunk_ordinal_in_flight",
                    retry_after_micros: 1,
                }),
            };
        }

        let object_count = u64::try_from(chunk.objects.len())
            .map_err(|_| StoreError::Conflict("staged chunk object count overflowed".into()))?;
        let object_bytes = chunk
            .objects
            .iter()
            .try_fold(0u64, |total, object| {
                total.checked_add(object.descriptor.raw_len)
            })
            .ok_or_else(|| StoreError::Conflict("staged chunk byte count overflowed".into()))?;

        // The uploaded totals may never exceed what creation reserved. This is
        // why the reservation is taken from the *declared* totals rather than
        // accrued as bytes arrive: the global and per-principal ceilings are
        // then unreachable by uploading at all, and the only place they can be
        // breached is admission, where they are enforced atomically.
        let session = &record.binding.session;
        require_at_most(
            "projection_stage_session_objects",
            record
                .written_objects
                .checked_add(object_count)
                .ok_or_else(|| StoreError::Conflict("staged object count overflowed".into()))?,
            session.total_object_count,
        )?;
        require_at_most(
            "projection_stage_session_bytes",
            record
                .written_bytes
                .checked_add(object_bytes)
                .ok_or_else(|| StoreError::Conflict("staged byte count overflowed".into()))?,
            session.total_object_bytes,
        )?;

        // Reserve the ordinal *and its share of the declared totals*, then
        // release the registry before touching the disk. The reservation is
        // what makes the write safe to perform unlocked: a second put of this
        // ordinal now sees `InFlight` and is answered typed instead of racing
        // to the same `rename_noreplace`, and two concurrent puts of different
        // ordinals cannot both pass the totals check against the same
        // pre-write figure.
        let directory = record.directory.clone();
        let name = chunk_artifact_name(chunk.ordinal, &chunk_digest);
        let ordinal = chunk.ordinal;
        let record = registry
            .sessions
            .get_mut(&self.session_id)
            .ok_or_else(|| unknown_session(self.session_id))?;
        record.chunks.insert(
            ordinal,
            ChunkSlot::InFlight {
                digest: chunk_digest,
            },
        );
        record.written_objects += object_count;
        record.written_bytes += object_bytes;
        drop(registry);
        staging
            .counters
            .compaction_debt_written_bytes
            .fetch_add(object_bytes, Relaxed);

        let bytes =
            encode_staging_artifact(StagingArtifactKind::Chunk, self.session_id, &canonical);
        let written = {
            let directory = directory.clone();
            let name = name.clone();
            let durability = Arc::clone(&staging.durability);
            let counters = Arc::clone(&staging.counters);
            staging.run_maintenance(move || {
                write_artifact(&directory, &name, &bytes, &durability, &counters)
            })
        };

        let mut registry = staging.lock();
        let record = registry
            .sessions
            .get_mut(&self.session_id)
            .ok_or_else(|| unknown_session(self.session_id))?;
        let file_bytes = match written {
            Ok(file_bytes) => file_bytes,
            Err(error) => {
                // The ordinal and its totals are released, not left reserved:
                // a reservation nothing can retire would make the chunk
                // unputtable for the rest of the session's life.
                record.chunks.remove(&ordinal);
                record.written_objects -= object_count;
                record.written_bytes -= object_bytes;
                drop(registry);
                staging
                    .counters
                    .compaction_debt_written_bytes
                    .fetch_sub(object_bytes, Relaxed);
                return Err(error);
            }
        };
        record.chunks.insert(
            ordinal,
            ChunkSlot::Stored(StoredChunk {
                digest: chunk_digest,
                path: directory.join(&name),
                file_bytes,
            }),
        );
        drop(registry);

        staging.counters.chunks_written.fetch_add(1, Relaxed);
        Ok(ChunkPutOutcome::Stored)
    }

    /// Reconstruct the exact ordered manifest and produce the adoption
    /// descriptor.
    ///
    /// **Sealing publishes nothing.** It returns a canonical descriptor and no
    /// capability: `ProjectionAdoption` is issued only by finalize, and only
    /// `submit` may consume it. That is plan §4 identity invariant 7 — normal
    /// possession of a session ID never grants membership to pre-uploaded
    /// bytes.
    pub fn seal(&self, now_micros: i64) -> Result<StagedProjectionInstallV1, StoreError> {
        let staging = &self.staging;

        // Phase 1, under the registry: admit exactly one sealer and take the
        // physical inputs. Everything after this — reading every chunk
        // artifact back, rehashing it, and writing the manifest — is disk work
        // and runs on a maintenance worker with the registry released.
        let (binding, stored, directory) = {
            let mut registry = staging.lock();
            let record = registry
                .sessions
                .get(&self.session_id)
                .ok_or_else(|| unknown_session(self.session_id))?;
            require_open(record, self.session_id)?;
            require_live(record, self.session_id, now_micros)?;
            require_idle(record, self.session_id)?;

            let expected_chunks = record.binding.session.chunk_count;
            let mut stored = Vec::with_capacity(usize::try_from(expected_chunks).unwrap_or(0));
            for ordinal in 0..expected_chunks {
                match record.chunks.get(&ordinal).and_then(ChunkSlot::stored) {
                    Some(chunk) => stored.push(chunk.clone()),
                    None => {
                        let present = record
                            .chunks
                            .values()
                            .filter(|slot| slot.stored().is_some())
                            .count();
                        return Err(StoreError::Conflict(format!(
                            "staging session {} holds {present} of {expected_chunks} chunks",
                            hex::encode(self.session_id)
                        )));
                    }
                }
            }
            let binding = record.binding.clone();
            let directory = record.directory.clone();
            let record = registry
                .sessions
                .get_mut(&self.session_id)
                .ok_or_else(|| unknown_session(self.session_id))?;
            record.busy = SessionBusy::Sealing;
            (binding, stored, directory)
        };

        let session_id = self.session_id;
        let durability = Arc::clone(&staging.durability);
        let counters = Arc::clone(&staging.counters);
        let composed = staging.run_maintenance(move || {
            compose_seal(
                session_id,
                binding,
                stored,
                directory,
                &durability,
                &counters,
            )
        });

        // Phase 3, under the registry: publish the sealed state, or clear the
        // exclusion and hand the caller the reason.
        let mut registry = staging.lock();
        let record = registry
            .sessions
            .get_mut(&self.session_id)
            .ok_or_else(|| unknown_session(self.session_id))?;
        record.busy = SessionBusy::Idle;
        let (install, resolution) = composed?;
        record.state = StagedSessionState::Sealed;
        record.resolution = Some(Arc::new(resolution));
        drop(registry);
        staging.counters.sessions_sealed.fetch_add(1, Relaxed);
        Ok(install)
    }

    /// Read-only resolution of a sealed session.
    ///
    /// Read-only is load-bearing: the adopting side revalidates, and a view
    /// that could mutate would let adoption repair what it was meant to
    /// reject.
    pub fn resolve(&self) -> Result<Arc<ProjectionAdoptionResolution>, StoreError> {
        let registry = self.staging.lock();
        let record = registry
            .sessions
            .get(&self.session_id)
            .ok_or_else(|| unknown_session(self.session_id))?;
        match record.state {
            // A pinned or adopted session still has the manifest sealing wrote,
            // and the adopting side revalidates against it. Refusing here would
            // make a pin unusable by the caller holding it.
            StagedSessionState::Sealed
            | StagedSessionState::Finalizing
            | StagedSessionState::Adopted => {}
            StagedSessionState::Open => {
                return Err(StoreError::Conflict(format!(
                    "staging session {} is still open and has no sealed manifest to resolve",
                    hex::encode(self.session_id)
                )))
            }
        }
        record.resolution.clone().ok_or_else(|| {
            StoreError::Corruption("sealed staging session lost its resolution".into())
        })
    }
}

/// The whole of sealing that touches the disk, on a maintenance worker.
///
/// Split out as a free function for the same reason `write_artifact` is: taking
/// `&self` here is what let a full re-read of every staged chunk happen while
/// the one lock every ceiling is evaluated under was held.
fn compose_seal(
    session_id: [u8; 16],
    binding: ProjectionStageBinding,
    stored: Vec<StoredChunk>,
    directory: PathBuf,
    durability: &DurabilityCounters,
    counters: &StagingCounters,
) -> Result<(StagedProjectionInstallV1, ProjectionAdoptionResolution), StoreError> {
    {
        let session = &binding.session;
        let expected_chunks = session.chunk_count;

        // Ordinal order is manifest order. The frozen binding validator reads
        // chunk `i` at manifest position `i`, so composing in any other order
        // would produce a manifest that no adopter could reproduce.
        let mut chunk_digests = Vec::with_capacity(stored.len());
        let mut objects: Vec<StagedObjectV1> = Vec::new();
        let mut artifacts = Vec::with_capacity(stored.len());
        let mut total_bytes = 0u64;
        for (ordinal, stored) in (0..expected_chunks).zip(stored.iter()) {
            let payload =
                read_staging_artifact(&stored.path, StagingArtifactKind::Chunk, session_id)?;
            let chunk = ProjectionStageChunkV1::decode_canonical(&payload).map_err(|e| {
                // Our own fenced artifact failed a decode it passed on the way
                // in. That is store state gone bad, not a caller's mistake.
                StoreError::Corruption(format!(
                    "staged chunk artifact {} no longer decodes: {e}",
                    stored.path.display()
                ))
            })?;
            let digest = chunk.chunk_digest().map_err(|e| {
                StoreError::Corruption(format!(
                    "staged chunk artifact {} digest: {e}",
                    stored.path.display()
                ))
            })?;
            if digest != stored.digest || chunk.ordinal != ordinal {
                return Err(StoreError::Corruption(format!(
                    "staged chunk artifact {} no longer matches the ordinal/digest it was \
                     stored under",
                    stored.path.display()
                )));
            }
            for object in &chunk.objects {
                total_bytes = total_bytes
                    .checked_add(object.descriptor.raw_len)
                    .ok_or_else(|| {
                        StoreError::Conflict("staged object byte count overflowed".into())
                    })?;
                objects.push(object.descriptor.clone());
            }
            chunk_digests.push(digest);
            artifacts.push(ProjectionArtifact {
                path: stored.path.clone(),
                digest,
                bytes: stored.file_bytes,
            });
        }

        let manifest = ProjectionStageManifestV1 {
            session_id,
            chunk_digests,
            objects,
            membership_root: binding.membership_root,
        };
        // `manifest_digest` runs the frozen manifest validation: nonempty,
        // bounded, strictly sorted and unique. Concatenating chunks in ordinal
        // order therefore has to produce a globally ordered object list or the
        // seal fails here, which is the ordering rule and not a copy of it.
        let manifest_digest = manifest
            .manifest_digest()
            .map_err(|e| StoreError::Conflict(format!("staged manifest: {e}")))?;
        let object_count = u64::try_from(manifest.objects.len())
            .map_err(|_| StoreError::Conflict("staged object count overflowed".into()))?;
        if manifest_digest != session.manifest_digest {
            return Err(StoreError::Conflict(format!(
                "staging session {} binds manifest digest {} but its chunks and membership \
                 root reconstruct to {}",
                hex::encode(session_id),
                hex::encode(session.manifest_digest.0),
                hex::encode(manifest_digest.0)
            )));
        }
        if object_count != session.total_object_count || total_bytes != session.total_object_bytes {
            return Err(StoreError::Conflict(format!(
                "staging session {} binds {}/{} objects/bytes but its chunks carry {}/{}",
                hex::encode(session_id),
                session.total_object_count,
                session.total_object_bytes,
                object_count,
                total_bytes
            )));
        }

        let install = StagedProjectionInstallV1 {
            session_id,
            manifest_digest,
            projection: session.projection,
            object_count,
            object_bytes: total_bytes,
            membership_root: manifest.membership_root,
            artifact_set_digest: artifact_set_digest(&artifacts),
        };
        // The descriptor must be encodable, because a final frame carries it.
        install
            .encode_canonical()
            .map_err(|e| StoreError::Conflict(format!("staged projection install: {e}")))?;

        let manifest_bytes = encode_staging_artifact(
            StagingArtifactKind::Manifest,
            session_id,
            &manifest
                .encode_canonical()
                .map_err(|e| StoreError::Conflict(format!("staged manifest: {e}")))?,
        );
        write_artifact(
            &directory,
            MANIFEST_NAME,
            &manifest_bytes,
            durability,
            counters,
        )?;

        Ok((
            install,
            ProjectionAdoptionResolution {
                session: session.clone(),
                manifest,
                artifacts: Arc::from(artifacts),
            },
        ))
    }
}

impl ProjectionStageSession {
    /// Abort and reclaim. Explicit cancellation, per plan §8.
    pub fn abort(self) -> Result<(), StoreError> {
        let staging = Arc::clone(&self.staging);
        staging.reclaim_session(self.session_id)?;
        staging.counters.sessions_aborted.fetch_add(1, Relaxed);
        Ok(())
    }

    /// Move `Sealed -> Finalizing` for the sole bound operation/digest and take
    /// the adoption pin.
    ///
    /// From `Sealed`, not `Open`: the sealed manifest is what an adopter
    /// revalidates against, so a pin on a session without one names state that
    /// does not exist. Scope §6.5 and plan §8 both said `Open` and are amended
    /// by contract review 2026-07-31-A.
    ///
    /// The pin is made durable **before** it is issued. A handle backed by an
    /// in-memory flag is an adoption capability with nothing behind it — the
    /// process stops, no marker is on the device, and the next open reconstructs
    /// a plain sealed session while a committed frame may already reference its
    /// artifacts. That is precisely the security property this package exists to
    /// hold.
    #[allow(dead_code)] // B1's `adopt_projection` is the only legitimate caller.
    pub(crate) fn finalize(&self, now_micros: i64) -> Result<StagedProjectionAdoption, StoreError> {
        let staging = &self.staging;

        // Phase 1, under the registry: admit exactly one finalizer, and do it
        // in the same critical section that expiry evaluates. That shared lock
        // is the whole of the expiry/finalize race: either this runs first and
        // `expire` then declines a `Finalizing` session, or expiry runs first
        // and `require_live` refuses here. There is no ordering in which a
        // sweep deletes artifacts a pin already holds.
        let (install, directory, operation, digest) = {
            let mut registry = staging.lock();
            let record = registry
                .sessions
                .get(&self.session_id)
                .ok_or_else(|| unknown_session(self.session_id))?;
            require_finalizable(record, self.session_id)?;
            require_live(record, self.session_id, now_micros)?;
            require_idle(record, self.session_id)?;

            let resolution = record.resolution.clone().ok_or_else(|| {
                StoreError::Corruption("sealed staging session lost its resolution".into())
            })?;
            let install = install_from_resolution(&resolution)?;
            let directory = record.directory.clone();
            let operation = record.binding.session.final_operation_id;
            let digest = record.binding.session.final_operation_digest;
            let record = registry
                .sessions
                .get_mut(&self.session_id)
                .ok_or_else(|| unknown_session(self.session_id))?;
            record.busy = SessionBusy::Finalizing;
            (install, directory, operation, digest)
        };

        // Phase 2, on a maintenance worker: make the pin durable *before*
        // handing it out. A handle issued against an in-memory flag is an
        // adoption capability with nothing behind it — the process stops, the
        // marker is not there, and the next open reconstructs a plain sealed
        // session while a committed frame may already reference its artifacts.
        let session_id = self.session_id;
        let durability = Arc::clone(&staging.durability);
        let counters = Arc::clone(&staging.counters);
        let written = staging.run_maintenance(move || {
            write_adoption_marker(
                &directory,
                session_id,
                AdoptionMark::Finalizing,
                operation,
                digest,
                &durability,
                &counters,
            )
        });

        // Phase 3, under the registry: publish the state the marker now proves,
        // or clear the exclusion and hand back the reason.
        let mut registry = staging.lock();
        let record = registry
            .sessions
            .get_mut(&self.session_id)
            .ok_or_else(|| unknown_session(self.session_id))?;
        record.busy = SessionBusy::Idle;
        written?;
        record.state = StagedSessionState::Finalizing;
        drop(registry);
        staging.counters.sessions_finalized.fetch_add(1, Relaxed);

        Ok(StagedProjectionAdoption {
            descriptor: install,
            handle: ProjectionAdoption::new(Arc::new(SessionAdoptionPin {
                staging: Arc::clone(staging),
                session_id: self.session_id,
            })),
        })
    }
}

/// The lifecycle behind one issued [`ProjectionAdoption`].
///
/// Holds an `Arc<ProjectionStaging>` rather than a borrow because the pin is
/// deliberately allowed to outlive the `ProjectionStageSession` that produced
/// it: B1 carries the handle into a `ValidatedTransaction` and finishes it after
/// the append decides, which is a different scope entirely.
struct SessionAdoptionPin {
    staging: Arc<ProjectionStaging>,
    session_id: [u8; 16],
}

impl ProjectionAdoptionLifecycle for SessionAdoptionPin {
    fn resolution(&self) -> Result<Arc<ProjectionAdoptionResolution>, StoreError> {
        let registry = self.staging.lock();
        let record = registry
            .sessions
            .get(&self.session_id)
            .ok_or_else(|| unknown_session(self.session_id))?;
        record.resolution.clone().ok_or_else(|| {
            StoreError::Corruption("pinned staging session lost its resolution".into())
        })
    }

    /// Record the one terminal outcome, durably, before the pin is released.
    ///
    /// Each arm is a different physical claim and none of them is a flag:
    ///
    /// * `Adopted` — a committed transaction references these artifacts. The
    ///   marker is rewritten so the next reconstruction says so; the directory
    ///   stays exactly where it is, because a committed root now points into it.
    ///   The reservation is released: staged bytes that became store content are
    ///   not staging occupancy, and charging them forever would make every
    ///   adoption shrink the budget for the next one.
    /// * `DefinitivePreAppendFailure` — nothing was appended, so the pin simply
    ///   ends. The marker is removed and the session returns to `Sealed`, which
    ///   is what the durable manifest already says it is. Deliverable 6's text
    ///   says "returns the session to `Open`"; `Open` here would contradict
    ///   reconstruction, which reads the sealed manifest's presence as the seal's
    ///   own commit point and would hand back `Sealed` on the next restart
    ///   regardless. Returning it to a state a restart cannot reproduce is the
    ///   defect `SessionBusy` exists to avoid, so it returns to `Sealed` — still
    ///   finalizable, which is the property the sentence is about. If the session
    ///   is no longer live, the marker still goes and expiry reclaims it on the
    ///   next sweep, which is "otherwise cleanup aborts it".
    /// * `TransferredToRecovery` — nobody in this process knows whether the frame
    ///   reached the journal. The marker stays, so the next open reconstructs
    ///   `Finalizing` and `transferred_sessions` hands the question to recovery.
    fn finish(&self, outcome: ProjectionAdoptionOutcome) -> Result<(), StoreError> {
        match outcome {
            ProjectionAdoptionOutcome::Adopted {
                committed_shard_sequence,
            } => {
                self.adopt_mark(committed_shard_sequence)?;
                let mut registry = self.staging.lock();
                if let Some(record) = registry.sessions.get_mut(&self.session_id) {
                    record.state = StagedSessionState::Adopted;
                    record.adopted_at_shard_sequence = Some(committed_shard_sequence);
                }
                self.staging
                    .release_reservation_locked(&mut registry, self.session_id);
                drop(registry);
                self.staging.counters.sessions_adopted.fetch_add(1, Relaxed);
                Ok(())
            }
            ProjectionAdoptionOutcome::DefinitivePreAppendFailure => {
                self.clear_mark()?;
                let mut registry = self.staging.lock();
                if let Some(record) = registry.sessions.get_mut(&self.session_id) {
                    record.state = StagedSessionState::Sealed;
                }
                drop(registry);
                self.staging
                    .counters
                    .adoption_pins_released
                    .fetch_add(1, Relaxed);
                Ok(())
            }
            ProjectionAdoptionOutcome::TransferredToRecovery => {
                self.staging
                    .counters
                    .adoption_pins_transferred
                    .fetch_add(1, Relaxed);
                Ok(())
            }
        }
    }

    /// A handle dropped without an outcome is not an error to report — there is
    /// nobody left to report it to — but it is emphatically not a release.
    ///
    /// The caller was somewhere between "about to append" and "knows the
    /// answer", and unwound without saying which. That is exactly the state
    /// `TransferredToRecovery` describes, so the marker stays and recovery
    /// decides. Treating it as a release would let the next sweep delete
    /// artifacts a committed frame may already reference.
    fn dropped_without_outcome(&self) {
        self.staging
            .counters
            .adoption_pins_dropped
            .fetch_add(1, Relaxed);
    }
}

impl SessionAdoptionPin {
    fn adopt_mark(&self, committed_shard_sequence: u64) -> Result<(), StoreError> {
        let (directory, session) = {
            let registry = self.staging.lock();
            let record = registry
                .sessions
                .get(&self.session_id)
                .ok_or_else(|| unknown_session(self.session_id))?;
            (record.directory.clone(), record.binding.session.clone())
        };
        let session_id = self.session_id;
        let durability = Arc::clone(&self.staging.durability);
        let counters = Arc::clone(&self.staging.counters);
        self.staging.run_maintenance(move || {
            adopt_adoption_marker(
                &directory,
                session_id,
                &session,
                committed_shard_sequence,
                &durability,
                &counters,
            )
        })
    }

    fn clear_mark(&self) -> Result<(), StoreError> {
        let (directory, _, _) = self.pin_identity()?;
        let durability = Arc::clone(&self.staging.durability);
        self.staging
            .run_maintenance(move || remove_adoption_marker(&directory, &durability))
    }

    #[allow(clippy::type_complexity)]
    fn pin_identity(&self) -> Result<(PathBuf, [u8; 16], ObjectId), StoreError> {
        let registry = self.staging.lock();
        let record = registry
            .sessions
            .get(&self.session_id)
            .ok_or_else(|| unknown_session(self.session_id))?;
        Ok((
            record.directory.clone(),
            record.binding.session.final_operation_id,
            record.binding.session.final_operation_digest,
        ))
    }
}

/// Deliverable 8, complete: all three methods answer.
///
/// The seam existed before it was implemented so recovery's dependency on
/// staging was visible at the type level — a store that recovers a committed
/// staged install without resolving it would publish membership for objects it
/// cannot locate — and while two methods were deferred they named the
/// deliverable rather than returning an empty result, because "nothing to
/// resolve" and "cannot answer yet" are different answers and only one of them
/// was true.
///
/// Both now answer. `resolve_committed` binds a descriptor to the bytes on disk
/// and resolves whole or not at all; `notify_recovered` ends a transferred pin
/// as an adoption or reclaims artifacts recovery proved no frame names. Contract
/// review 2026-07-31-D.
impl ProjectionRecoveryResolver for ProjectionStaging {
    /// The transferred set, **derived rather than asserted.**
    ///
    /// It was provably empty while `finalize` was deferred, because no session
    /// could enter `Finalizing` at all. Deliverable 6 landed that state and made
    /// it durable, so this now answers the question it was written to be able to
    /// answer: a session reconstructed in `Finalizing` held a pin when its
    /// process stopped, and nothing in *this* process knows whether the final
    /// frame reached the journal.
    ///
    /// Still an exhaustive match over the state rather than a filter, which is
    /// how `Finalizing` and `Adopted` arrived here as compile errors — at the one
    /// place that had to learn a pin can outlive the process — rather than being
    /// swept silently into "none".
    fn transferred_sessions(&self, shard_index: u16) -> Result<Arc<[[u8; 16]]>, StoreError> {
        let registry = self.lock();
        let transferred: Vec<[u8; 16]> = registry
            .sessions
            .iter()
            .filter(|(_, record)| record.shard_index == shard_index)
            .filter(|(_, record)| match record.state {
                StagedSessionState::Open | StagedSessionState::Sealed => false,
                // The answer this method was written to be able to give. A
                // session reconstructed in `Finalizing` held a pin when its
                // process stopped, so nothing in this process knows whether the
                // final frame reached the journal — only recovery can say.
                StagedSessionState::Finalizing => true,
                // Already resolved. Reporting it would ask recovery to decide a
                // question that has a durable answer, and `notify_recovered`
                // would then be handed a session with nothing left to notify.
                StagedSessionState::Adopted => false,
            })
            .map(|(session_id, _)| *session_id)
            .collect();
        Ok(Arc::from(transferred))
    }

    /// Resolve a committed descriptor into membership and live ownership.
    ///
    /// Read-only, and mechanical: this verifies the descriptor against the
    /// session's own sealed state and hands back what it finds. Identity, graph,
    /// policy, authority, and federation decisions are deliberately absent — the
    /// complete frame is already the durable authority, and resolution may
    /// inspect, open, hash, and pin its immutable artifacts but may not repair
    /// them.
    ///
    /// # It can never expose a partial chunk set
    ///
    /// Every ordinal the manifest declares is read back, decoded, and checked
    /// before a single location is produced, and a missing or unreadable one
    /// fails the whole resolution. `RecoveredProjectionArtifacts::new` then
    /// refuses unless the entry count it was given equals the descriptor's own
    /// `object_count`. So a directory holding some of its chunks resolves to an
    /// error rather than to a smaller projection — which is the deliverable's
    /// central claim, and the one a "resolve what is present" implementation
    /// would quietly violate.
    ///
    /// # One location per chunk
    ///
    /// An `IndexLocation` names the whole certified record, never the object
    /// bytes inside it, so every object in a chunk shares that chunk's location
    /// and a reader validates the artifact before extracting from its decoded
    /// vector — exactly as several objects share one journal frame. This is why
    /// no per-object byte offsets are needed and why none are computed here:
    /// pointing at object bytes would let a reader return bytes from a record it
    /// never proved complete.
    fn resolve_committed(
        &self,
        namespace: NamespaceId,
        descriptor: &StagedProjectionInstallV1,
        adoption_shard_sequence: u64,
    ) -> Result<RecoveredProjectionArtifacts, StoreError> {
        let session_id = descriptor.session_id;
        let resolution = {
            let registry = self.lock();
            let record = registry.sessions.get(&session_id).ok_or_else(|| {
                StoreError::Corruption(format!(
                    "committed staged projection names session {}, which this root does not \
                     hold; its artifacts cannot be resolved and the objects it published \
                     would be unreadable",
                    hex::encode(session_id)
                ))
            })?;
            record.resolution.clone().ok_or_else(|| {
                StoreError::Corruption(format!(
                    "committed staged projection session {} has no sealed manifest to \
                     resolve",
                    hex::encode(session_id)
                ))
            })?
        };

        // The descriptor a frame carries must be the one this session would
        // install. Anything else means the frame and the artifacts on this device
        // describe different projections, and adopting either would publish
        // membership the other does not support.
        let expected = install_from_resolution(&resolution)?;
        if &expected != descriptor {
            return Err(StoreError::Corruption(format!(
                "committed staged projection session {} does not reconstruct the descriptor \
                 its frame carries",
                hex::encode(session_id)
            )));
        }

        let artifacts = Arc::clone(&resolution.artifacts);
        let session = resolution.session.clone();
        let sealed_digests = resolution.manifest.chunk_digests.clone();
        let expected_set = descriptor.artifact_set_digest;
        let read = self.run_maintenance(move || {
            let mut chunks = Vec::with_capacity(artifacts.len());
            let mut observed_set: Vec<ProjectionArtifact> = Vec::with_capacity(artifacts.len());
            for (ordinal, artifact) in artifacts.iter().enumerate() {
                let ordinal = u32::try_from(ordinal).map_err(|_| {
                    StoreError::Corruption("staged chunk ordinal does not fit u32".into())
                })?;
                let bytes =
                    read_staging_artifact(&artifact.path, StagingArtifactKind::Chunk, session_id)?;
                let chunk = ProjectionStageChunkV1::decode_canonical(&bytes).map_err(|e| {
                    StoreError::Corruption(format!(
                        "committed staged chunk {} no longer decodes: {e}",
                        artifact.path.display()
                    ))
                })?;
                if chunk.ordinal != ordinal
                    || chunk.session_id != session_id
                    || chunk.chunk_count != session.chunk_count
                {
                    return Err(StoreError::Corruption(format!(
                        "committed staged chunk {} no longer matches the ordinal, session, or \
                         chunk count its manifest binds",
                        artifact.path.display()
                    )));
                }
                // Bind on the bytes just read, not on the sealed record beside
                // them. Everything above is shape — session, ordinal, count —
                // and a *different* valid chunk of the same shape satisfies all
                // of it while carrying entirely different objects. What makes
                // this artifact the one the descriptor commits to is its digest.
                let observed = chunk.chunk_digest().map_err(|e| {
                    StoreError::Corruption(format!(
                        "committed staged chunk {} digest: {e}",
                        artifact.path.display()
                    ))
                })?;
                if observed != artifact.digest {
                    return Err(StoreError::Corruption(format!(
                        "committed staged chunk {} hashes to {} but its sealed manifest \
                         records {}; the artifact on disk is not the one this projection \
                         committed",
                        artifact.path.display(),
                        hex::encode(observed.0),
                        hex::encode(artifact.digest.0)
                    )));
                }
                // And against the manifest's own ordered list, so a resolution
                // cannot be satisfied by a set of chunks that individually match
                // records which were themselves swapped.
                let sealed = sealed_digests.get(ordinal as usize).ok_or_else(|| {
                    StoreError::Corruption(format!(
                        "committed staged chunk {} has ordinal {ordinal}, beyond the \
                         manifest's chunk list",
                        artifact.path.display()
                    ))
                })?;
                if &observed != sealed {
                    return Err(StoreError::Corruption(format!(
                        "committed staged chunk {} does not match the digest its manifest \
                         binds at ordinal {ordinal}",
                        artifact.path.display()
                    )));
                }
                let file_bytes = std::fs::metadata(&artifact.path)?.len();
                if file_bytes != artifact.bytes {
                    return Err(StoreError::Corruption(format!(
                        "committed staged chunk {} is {file_bytes} bytes but its sealed \
                         manifest records {}; a location naming the whole record would name \
                         a different span than the one that was certified",
                        artifact.path.display(),
                        artifact.bytes
                    )));
                }
                let pinned = PinnedFile::open(artifact.path.clone())?;
                observed_set.push(ProjectionArtifact {
                    path: artifact.path.clone(),
                    digest: observed,
                    bytes: file_bytes,
                });
                chunks.push((ordinal, chunk, file_bytes, pinned));
            }
            // The descriptor's own binding over the whole set, recomputed from
            // what is on disk. The per-chunk checks above prove each artifact
            // against the sealed record; this proves the *set* against the frame,
            // which is the only value the committed transaction actually signed.
            let observed_digest = artifact_set_digest(&observed_set);
            if observed_digest != expected_set {
                return Err(StoreError::Corruption(format!(
                    "committed staged projection session {} resolves to artifact set {} but \
                     its frame commits to {}",
                    hex::encode(session_id),
                    hex::encode(observed_digest.0),
                    hex::encode(expected_set.0)
                )));
            }
            Ok(chunks)
        })?;

        if u32::try_from(read.len()).unwrap_or(u32::MAX) != session.chunk_count {
            return Err(StoreError::Corruption(format!(
                "committed staged projection session {} resolved {} of {} chunks; a partial \
                 chunk set is never exposed",
                hex::encode(session_id),
                read.len(),
                session.chunk_count
            )));
        }

        // The configured active-index bounds, the same ones ordinary recovery
        // rebuilds under. Sizing this from `max_projection_objects` and a
        // synthetic byte limit would have let a resolution admit a projection
        // the recovered root cannot hold: nothing requires the active-index
        // limits to admit a maximal projection, so the two are independent
        // configurations and only one of them governs what a reopen may rebuild.
        let mut delta = IndexDelta::from_options(&self.options);
        let mut retained = Vec::with_capacity(read.len());
        for (ordinal, chunk, file_bytes, pinned) in read {
            let generation = projection_generation(adoption_shard_sequence, ordinal, session_id)?;
            let frame_len = u32::try_from(file_bytes).map_err(|_| {
                StoreError::Corruption(format!(
                    "committed staged chunk ordinal {ordinal} of session {} is {file_bytes} \
                     bytes, beyond what a location can name",
                    hex::encode(session_id)
                ))
            })?;
            for object in &chunk.objects {
                delta.insert(
                    IndexKey::new(namespace, object.descriptor.object_id),
                    IndexLocation {
                        segment_generation: generation,
                        // The whole artifact is the certified record.
                        frame_offset: 0,
                        frame_len,
                        object_type: object.descriptor.object_type,
                        shard_sequence: adoption_shard_sequence,
                    },
                )?;
            }
            retained.push(RetainedProjectionArtifact::new(
                generation,
                crate::roots::ProjectionArtifactFormat::CanonicalStageChunkV1,
                pinned,
            ));
        }

        // Remembered so `notify_recovered` can end the pin as an adoption at
        // the position this frame established. It is not durable yet: only a
        // `Committed` notification, which follows the physical-state proof, may
        // write it into the marker.
        {
            let mut registry = self.lock();
            if let Some(record) = registry.sessions.get_mut(&session_id) {
                record.adopted_at_shard_sequence = Some(adoption_shard_sequence);
            }
        }

        RecoveredProjectionArtifacts::new(
            descriptor.clone(),
            Arc::new(delta),
            Arc::from([]),
            retained.into(),
        )
    }

    /// Finish one transferred session once recovery has proved its physical
    /// state.
    ///
    /// This is the transition `finish` could not make: the process holding the
    /// pin stopped without knowing whether its frame reached the journal, and
    /// recovery has now either made that frame authoritative or scanned the
    /// complete history and proved no such frame exists.
    ///
    /// * `Committed` ends the pin as an adoption, at the position
    ///   `resolve_committed` recorded for this session in the same recovery.
    ///   Without that position cleanup could never prove absence of reference
    ///   against a root, so a `Committed` notification for a session this
    ///   recovery did not resolve is refused rather than adopted at a guess.
    /// * `ProvedAbsent` means no complete frame names these artifacts and none
    ///   ever will — recovery has read the whole authoritative history. They are
    ///   synced-but-unreferenced garbage, which is exactly what the deliverable
    ///   says recovery treats as invisible, so the session is aborted and its
    ///   directory reclaimed.
    ///
    /// **Idempotent**, because recovery repeats every notification on the next
    /// attempt if a later one fails: a session already in the state being asked
    /// for, or already gone, is success and not a conflict.
    fn notify_recovered(
        &self,
        resolution: RecoveredProjectionResolution,
    ) -> Result<(), StoreError> {
        let session_id = resolution.session_id;
        match resolution.outcome {
            RecoveredProjectionOutcome::Committed => {
                let adopted_at = {
                    let registry = self.lock();
                    let Some(record) = registry.sessions.get(&session_id) else {
                        return Ok(());
                    };
                    if matches!(record.state, StagedSessionState::Adopted) {
                        return Ok(());
                    }
                    record.adopted_at_shard_sequence.ok_or_else(|| {
                        StoreError::Corruption(format!(
                            "staging session {} is reported committed but this recovery never \
                             resolved it, so nothing recorded where its adoption committed",
                            hex::encode(session_id)
                        ))
                    })?
                };
                let (directory, session) = {
                    let registry = self.lock();
                    let record = registry
                        .sessions
                        .get(&session_id)
                        .ok_or_else(|| unknown_session(session_id))?;
                    (record.directory.clone(), record.binding.session.clone())
                };
                let durability = Arc::clone(&self.durability);
                let counters = Arc::clone(&self.counters);
                self.run_maintenance(move || {
                    adopt_adoption_marker(
                        &directory,
                        session_id,
                        &session,
                        adopted_at,
                        &durability,
                        &counters,
                    )
                })?;
                let mut registry = self.lock();
                if let Some(record) = registry.sessions.get_mut(&session_id) {
                    record.state = StagedSessionState::Adopted;
                }
                self.release_reservation_locked(&mut registry, session_id);
                drop(registry);
                self.counters.sessions_adopted.fetch_add(1, Relaxed);
                Ok(())
            }
            RecoveredProjectionOutcome::ProvedAbsent => {
                {
                    let mut registry = self.lock();
                    let Some(record) = registry.sessions.get_mut(&session_id) else {
                        return Ok(());
                    };
                    // The pin is over: recovery proved no frame names these
                    // artifacts. Returning the record to a reclaimable state is
                    // what lets `reclaim_session` — which refuses a pinned or
                    // adopted session on purpose — take it.
                    record.state = StagedSessionState::Sealed;
                    record.adopted_at_shard_sequence = None;
                }
                let directory = {
                    let registry = self.lock();
                    match registry.sessions.get(&session_id) {
                        Some(record) => record.directory.clone(),
                        None => return Ok(()),
                    }
                };
                let durability = Arc::clone(&self.durability);
                self.run_maintenance(move || remove_adoption_marker(&directory, &durability))?;
                self.reclaim_session(session_id)?;
                self.counters.sessions_aborted.fetch_add(1, Relaxed);
                Ok(())
            }
        }
    }
}

// --- free helpers ---------------------------------------------------------

/// The band every adopted projection artifact's logical generation lives in.
///
/// Segments, active tails, and projection artifacts share **one** generation
/// space — `validate_retained_object_sources` inserts all three into a single
/// map and refuses a duplicate — so a projection generation that collided with a
/// segment's would be a `Corruption` at open. Reserving the top bit makes the
/// collision impossible by construction rather than unlikely: segment and tail
/// generations are a counter that advances once per seal, and a store that
/// reached 2^63 seals has arithmetic problems that this constant is not the
/// right place to discover.
///
/// `projection_generation` refuses anything that would land outside the band,
/// so the disjointness is enforced at the one place generations are minted
/// rather than assumed everywhere they are read.
const PROJECTION_GENERATION_BAND: u64 = 1 << 63;

/// Bits reserved for the chunk ordinal within a band entry.
///
/// `max_projection_chunks` is capped at `codec::MAX_CANONICAL_ITEMS`, which is
/// 1,000,000 and therefore fits in 20 bits; 24 leaves room for that ceiling to
/// rise without the mapping silently starting to alias.
const PROJECTION_ORDINAL_BITS: u32 = 24;

/// The logical generation of one adopted chunk artifact.
///
/// **Stable and injective in `(adoption frame sequence, chunk ordinal)`**, which
/// is the requirement rather than a convenience. Stable because a sealed index
/// run persists `IndexLocation`s across sessions, so the generation a run names
/// must resolve to the same artifact at the next open — the rule contract review
/// 2026-07-30-A established for segments and the active tail, applied here.
/// Injective because a multi-chunk session has one file per chunk and the root
/// validator correctly refuses two projection files at one generation: deriving
/// from the frame sequence alone would make every multi-chunk adoption
/// unopenable.
///
/// Both inputs are durable — the frame's own sequence and the ordinal the
/// manifest fixes — so this is a function of committed state and not of
/// anything a session remembers.
fn projection_generation(
    adoption_shard_sequence: u64,
    ordinal: u32,
    session_id: [u8; 16],
) -> Result<u64, StoreError> {
    let ordinal_ceiling = 1u64 << PROJECTION_ORDINAL_BITS;
    if u64::from(ordinal) >= ordinal_ceiling {
        return Err(StoreError::Corruption(format!(
            "staged projection session {} has chunk ordinal {ordinal}, beyond the {} the \
             generation mapping can distinguish",
            hex::encode(session_id),
            ordinal_ceiling - 1
        )));
    }
    // The sequence must fit *below* the band bit once shifted, not merely
    // survive the shift. A round-trip check is not enough and the boundary is
    // exactly one value wide: `1 << 39` shifts to `1 << 63`, which is the band
    // bit itself, loses nothing on the way, and round-trips perfectly — and then
    // OR-ing the band is a no-op, so it produces the same generation as sequence
    // 0 at the same ordinal. One collision, at the one input a shift check
    // cannot see.
    let sequence_ceiling = 1u64 << (63 - PROJECTION_ORDINAL_BITS);
    if adoption_shard_sequence >= sequence_ceiling {
        return Err(StoreError::Corruption(format!(
            "staged projection session {} was adopted at shard sequence {}, at or beyond the \
             {sequence_ceiling} the projection generation mapping can distinguish",
            hex::encode(session_id),
            adoption_shard_sequence
        )));
    }
    let shifted = adoption_shard_sequence << PROJECTION_ORDINAL_BITS;
    debug_assert_eq!(shifted & PROJECTION_GENERATION_BAND, 0);
    Ok(PROJECTION_GENERATION_BAND | shifted | u64::from(ordinal))
}

/// Create `<staging>/<shard>/<session>` and sync every directory entry the new
/// session directory depends on, outermost first.
fn create_session_directory(
    staging_root: &Path,
    directory: &Path,
    durability: &DurabilityCounters,
) -> Result<(), StoreError> {
    let parent = directory
        .parent()
        .expect("a session directory always has a shard parent");
    let parent_is_new = !parent.exists();
    std::fs::create_dir_all(directory)?;
    if parent_is_new {
        // `staging/<shard>`'s own entry, in `staging/`. Without this the shard
        // directory can vanish on a crash and take a fully fenced session
        // with it.
        crate::sys::fsync_dir(staging_root, durability)?;
    }
    // `<session>`'s entry, in `staging/<shard>`.
    crate::sys::fsync_dir(parent, durability)?;
    Ok(())
}

/// Write one uniquely named, unreferenced, fenced artifact.
///
/// Ordering matches `checkpoint::install`: temporary, fence, then a no-replace
/// rename, then a directory fsync. The final name therefore only ever appears
/// over complete, fenced bytes. `rename_noreplace` is the load-bearing half of
/// "uniquely named": if a name were ever reused the rename fails rather than
/// quietly replacing an artifact another ordinal or another session still
/// accounts for.
///
/// A free function, and asserted to run on a maintenance worker, because
/// deliverable 5 says artifacts are written by maintenance workers. Taking
/// `&self` is what let this drift onto whatever thread happened to hold the
/// registry lock.
/// What an adoption marker asserts. One file, one of these, rewritten in place.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum AdoptionMark {
    /// A pin is outstanding and this process no longer gets to decide its fate.
    Finalizing = 1,
    /// A committed transaction references these artifacts.
    Adopted = 2,
}

impl AdoptionMark {
    fn code(self) -> u8 {
        self as u8
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Finalizing),
            2 => Some(Self::Adopted),
            _ => None,
        }
    }
}

/// `mark || final_operation_id || final_operation_digest || adopted_at`.
///
/// The operation and digest travel with the mark so a reconstruction can check
/// them against the session record beside it. A marker naming a different
/// operation than the session it lives in is not a pin this store issued, and
/// the deliverable's "every different operation/digest rejects" has to survive a
/// restart to mean anything.
/// `adopted_at` is zero while the mark is `Finalizing` and carries the adoption's
/// committed shard sequence once it is `Adopted`. Fixed width either way, so the
/// two marks are the same size and a replacement never changes the file's shape.
const ADOPTION_MARKER_LEN: usize = 1 + 16 + 32 + 8;

fn write_adoption_marker(
    directory: &Path,
    session_id: [u8; 16],
    mark: AdoptionMark,
    operation: [u8; 16],
    digest: ObjectId,
    durability: &DurabilityCounters,
    counters: &StagingCounters,
) -> Result<(), StoreError> {
    let bytes = encode_staging_artifact(
        StagingArtifactKind::Adoption,
        session_id,
        &adoption_payload(mark, operation, digest, 0),
    );
    write_artifact(directory, ADOPTION_NAME, &bytes, durability, counters)?;
    Ok(())
}

/// Decode a marker and prove it belongs to the session it was found in.
fn adoption_payload(
    mark: AdoptionMark,
    operation: [u8; 16],
    digest: ObjectId,
    adopted_at: u64,
) -> Vec<u8> {
    let mut payload = Vec::with_capacity(ADOPTION_MARKER_LEN);
    payload.push(mark.code());
    payload.extend_from_slice(&operation);
    payload.extend_from_slice(&digest.0);
    payload.extend_from_slice(&adopted_at.to_le_bytes());
    debug_assert_eq!(payload.len(), ADOPTION_MARKER_LEN);
    payload
}

fn read_adoption_marker(
    path: &Path,
    session_id: [u8; 16],
    session: &ProjectionStageSessionV1,
) -> Result<(AdoptionMark, u64), StoreError> {
    let payload = read_staging_artifact(path, StagingArtifactKind::Adoption, session_id)?;
    if payload.len() != ADOPTION_MARKER_LEN {
        return Err(StoreError::Corruption(format!(
            "staging adoption marker {} is {} bytes, not {ADOPTION_MARKER_LEN}",
            path.display(),
            payload.len()
        )));
    }
    let mark = AdoptionMark::from_code(payload[0]).ok_or_else(|| {
        StoreError::Corruption(format!(
            "staging adoption marker {} carries unknown outcome {}",
            path.display(),
            payload[0]
        ))
    })?;
    let mut operation = [0u8; 16];
    operation.copy_from_slice(&payload[1..17]);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&payload[17..49]);
    let mut adopted_at = [0u8; 8];
    adopted_at.copy_from_slice(&payload[49..]);
    let adopted_at = u64::from_le_bytes(adopted_at);
    if operation != session.final_operation_id || ObjectId(digest) != session.final_operation_digest
    {
        return Err(StoreError::Corruption(format!(
            "staging adoption marker {} names operation {} but its session binds {}",
            path.display(),
            hex::encode(operation),
            hex::encode(session.final_operation_id)
        )));
    }
    // A `Finalizing` marker carrying a position would be claiming an adoption it
    // does not record, which is exactly the confusion the position exists to
    // prevent.
    if matches!(mark, AdoptionMark::Finalizing) && adopted_at != 0 {
        return Err(StoreError::Corruption(format!(
            "staging adoption marker {} is still finalizing but records a committed \
             sequence of {adopted_at}",
            path.display()
        )));
    }
    Ok((mark, adopted_at))
}

/// Replace this session's `Finalizing` marker with `Adopted`, atomically.
///
/// A separate path from [`write_artifact`], and deliberately not a relaxation of
/// it. That writer publishes with `rename_noreplace` because every other staging
/// artifact is unique-by-name and must never be overwritten — a chunk or a
/// manifest arriving twice at one name is a fault, not an update. The adoption
/// marker is the one file in a session that legitimately changes, and routing it
/// through a "replace if you like" flag on the shared writer would hand that
/// permission to the artifacts the no-replace rule exists to protect.
///
/// So the licence to overwrite is bounded by proof rather than by a parameter,
/// exactly once, here: the marker on disk must decode as a staging artifact of
/// this session, carry the operation and digest this session binds, and say
/// `Finalizing`. Anything else is refused with the file untouched.
///
/// Idempotent on an already-`Adopted` marker. `finish` can be reached twice —
/// a retried outcome is not a second event — and re-adopting what is already
/// adopted has to be a no-op rather than a refusal, or the retry wedges the
/// session in `Finalizing` forever.
fn adopt_adoption_marker(
    directory: &Path,
    session_id: [u8; 16],
    session: &ProjectionStageSessionV1,
    committed_shard_sequence: u64,
    durability: &DurabilityCounters,
    counters: &StagingCounters,
) -> Result<(), StoreError> {
    assert!(
        ON_MAINTENANCE_WORKER.with(Cell::get),
        "staging artifacts are written by maintenance workers (scope 6.5 deliverable 5); \
         {} was offered to a caller thread",
        directory.join(ADOPTION_NAME).display()
    );
    let final_path = directory.join(ADOPTION_NAME);
    match read_adoption_marker(&final_path, session_id, session)? {
        (AdoptionMark::Adopted, _) => return Ok(()),
        (AdoptionMark::Finalizing, _) => {}
    }

    let bytes = encode_staging_artifact(
        StagingArtifactKind::Adoption,
        session_id,
        &adoption_payload(
            AdoptionMark::Adopted,
            session.final_operation_id,
            session.final_operation_digest,
            committed_shard_sequence,
        ),
    );

    let tmp_path = directory.join(format!("{ADOPTION_NAME}.tmp"));
    {
        // Through the no-follow funnel. This path publishes by *replacing*, so a
        // symlink planted at the temporary name would redirect the write and
        // then the rename would publish whatever it pointed at over a marker the
        // store still believes it owns.
        let Some(mut file) =
            crate::sys::open_or_create_regular_truncated_nofollow(&tmp_path, durability)?
        else {
            return Err(StoreError::UnrecognizedLayout(format!(
                "{} is not a regular file; refusing to record an adoption through it",
                tmp_path.display()
            )));
        };
        let end = crate::sys::write_vectored_all(&mut file, &[IoSlice::new(&bytes)], durability)?;
        if end != bytes.len() as u64 {
            return Err(StoreError::from(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!(
                    "short write recording adoption for staging session {}: wrote {end} of {} \
                     bytes; the temporary is left behind and never renamed",
                    hex::encode(session_id),
                    bytes.len()
                ),
            )));
        }
        crate::sys::fdatasync(&file, durability)?;
    }
    // Replacing, and only ever over the marker just proved to be this session's
    // outstanding pin. A crash on either side of it leaves a whole, valid marker
    // — `Finalizing` before, `Adopted` after — and never a torn one, which is
    // why this is a rename and not a fixed-size overwrite in place.
    crate::sys::rename_replace(&tmp_path, &final_path)?;
    crate::sys::fsync_dir(directory, durability)?;
    counters
        .artifact_bytes_written
        .fetch_add(bytes.len() as u64, Relaxed);
    counters.maintenance_artifact_writes.fetch_add(1, Relaxed);
    Ok(())
}

fn remove_adoption_marker(
    directory: &Path,
    durability: &DurabilityCounters,
) -> Result<(), StoreError> {
    let path = directory.join(ADOPTION_NAME);
    match crate::sys::unlink(&path) {
        Ok(()) => {}
        // Already gone is the outcome this asked for. `finish` must be safe to
        // reach twice — a retried definitive failure is not a new event.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(StoreError::from(error)),
    }
    crate::sys::fsync_dir(directory, durability)?;
    Ok(())
}

/// The descriptor a sealed session installs, derived from its own resolution.
///
/// One derivation, used by `compose_seal` and by `finalize`, so a reconstructed
/// session cannot produce a descriptor that differs from the one its seal
/// returned. Two constructions of the same value is how a restart starts
/// disagreeing with the session it restarted.
fn install_from_resolution(
    resolution: &ProjectionAdoptionResolution,
) -> Result<StagedProjectionInstallV1, StoreError> {
    let manifest_digest = resolution
        .manifest
        .manifest_digest()
        .map_err(|e| StoreError::Corruption(format!("sealed staging manifest digest: {e}")))?;
    let object_count = u64::try_from(resolution.manifest.objects.len()).map_err(|_| {
        StoreError::Corruption("sealed staging manifest object count does not fit u64".into())
    })?;
    let mut object_bytes = 0u64;
    for object in &resolution.manifest.objects {
        object_bytes = object_bytes.checked_add(object.raw_len).ok_or_else(|| {
            StoreError::Corruption("sealed staging manifest byte total overflowed".into())
        })?;
    }
    Ok(StagedProjectionInstallV1 {
        session_id: resolution.session.session_id,
        manifest_digest,
        projection: resolution.session.projection,
        object_count,
        object_bytes,
        membership_root: resolution.manifest.membership_root,
        artifact_set_digest: artifact_set_digest(&resolution.artifacts),
    })
}

fn write_artifact(
    directory: &Path,
    name: &str,
    bytes: &[u8],
    durability: &DurabilityCounters,
    counters: &StagingCounters,
) -> Result<u64, StoreError> {
    assert!(
        ON_MAINTENANCE_WORKER.with(Cell::get),
        "staging artifacts are written by maintenance workers (scope 6.5 deliverable 5); \
         {} was offered to a caller thread",
        directory.join(name).display()
    );
    let final_path = directory.join(name);
    let tmp_path = directory.join(format!("{name}.tmp"));
    {
        let mut file = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        let end = crate::sys::write_vectored_all(&mut file, &[IoSlice::new(bytes)], durability)?;
        if end != bytes.len() as u64 {
            return Err(StoreError::from(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!(
                    "short write staging artifact {}: wrote {end} of {} bytes; the \
                     temporary is left behind and never renamed",
                    final_path.display(),
                    bytes.len()
                ),
            )));
        }
        crate::sys::fdatasync(&file, durability)?;
    }
    crate::sys::rename_noreplace(&tmp_path, &final_path)?;
    crate::sys::fsync_dir(directory, durability)?;
    counters
        .artifact_bytes_written
        .fetch_add(bytes.len() as u64, Relaxed);
    counters.maintenance_artifact_writes.fetch_add(1, Relaxed);
    Ok(bytes.len() as u64)
}

/// Prove the whole directory is reclaimable, and only then unlink anything.
///
/// The two-phase shape is the point. Unlinking as the scan walks the directory
/// means a valid marked artifact can be destroyed and *then* an unexpected file
/// encountered, which leaves a live session partially reclaimed: neither
/// removed nor usable, and no longer able to seal. Reclamation either takes the
/// whole directory or takes nothing and says which file stopped it.
fn reclaim_session_directory(
    directory: &Path,
    session_id: [u8; 16],
    durability: &DurabilityCounters,
    counters: &StagingCounters,
) -> Result<(), StoreError> {
    if !directory.exists() {
        return Ok(());
    }
    let mut plan: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_owned();
        if !path.is_file() {
            return Err(StoreError::Corruption(format!(
                "staging session directory {} holds {}, which is not a file; reclamation \
                 removes nothing rather than deleting around a surprise",
                directory.display(),
                path.display()
            )));
        }
        // A `.tmp` under one of this session's own artifact names never
        // survived a rename, so it is ours by construction and may carry a
        // torn header. Nothing else in the directory is taken on faith.
        if let Some(stem) = name.strip_suffix(".tmp") {
            if is_session_artifact_name(stem) {
                plan.push(path);
                continue;
            }
        }
        if artifact_session_marker(&path)? == Some(session_id) {
            plan.push(path);
            continue;
        }
        return Err(StoreError::Corruption(format!(
            "staging session directory {} holds {}, which carries no valid marker for \
             session {}; reclamation is not a licence to delete whatever is in the path",
            directory.display(),
            path.display(),
            hex::encode(session_id)
        )));
    }

    let mut unlinked = 0u64;
    for path in &plan {
        crate::sys::unlink(path)?;
        unlinked += 1;
    }
    crate::sys::fsync_dir(directory, durability)?;
    std::fs::remove_dir(directory)?;
    if let Some(parent) = directory.parent() {
        crate::sys::fsync_dir(parent, durability)?;
    }
    counters.artifacts_unlinked.fetch_add(unlinked, Relaxed);
    Ok(())
}

/// A name this session's own writer could have produced.
fn is_session_artifact_name(name: &str) -> bool {
    name == SESSION_RECORD_NAME
        || name == MANIFEST_NAME
        || name == ADOPTION_NAME
        || parse_chunk_artifact_name(name).is_some()
}

/// The inverse of [`chunk_artifact_name`], so reconstruction reads the ordinal
/// and digest a name binds instead of trusting the file's contents about them.
fn parse_chunk_artifact_name(name: &str) -> Option<(u32, ObjectId)> {
    let rest = name.strip_prefix("chunk-")?;
    let (ordinal, digest) = rest.split_once('-')?;
    if ordinal.len() != 10 || digest.len() != 64 {
        return None;
    }
    let ordinal: u32 = ordinal.parse().ok()?;
    let mut bytes = [0u8; 32];
    hex::decode_to_slice(digest, &mut bytes).ok()?;
    Some((ordinal, ObjectId(bytes)))
}

/// The session ID a directory name binds, or `None` if the name is not one.
fn session_directory_id(path: &Path) -> Option<[u8; 16]> {
    if !path.is_dir() {
        return None;
    }
    let name = path.file_name()?.to_str()?;
    if name.len() != 32 {
        return None;
    }
    let mut session_id = [0u8; 16];
    hex::decode_to_slice(name, &mut session_id).ok()?;
    Some(session_id)
}

fn unknown_session(session_id: [u8; 16]) -> StoreError {
    StoreError::Conflict(format!("no staging session {}", hex::encode(session_id)))
}

fn require_open(record: &SessionRecord, session_id: [u8; 16]) -> Result<(), StoreError> {
    match record.state {
        StagedSessionState::Open => Ok(()),
        StagedSessionState::Sealed
        | StagedSessionState::Finalizing
        | StagedSessionState::Adopted => Err(StoreError::Conflict(format!(
            "staging session {} is sealed and immutable",
            hex::encode(session_id)
        ))),
    }
}

/// Admit the sole finalizer: a session that has sealed and is not already
/// carrying an outcome.
///
/// Deliverable 6 asks for "identical concurrent finalizers coalesce onto one",
/// and at this layer that is one pin, not two handles. [`ProjectionAdoption`] is
/// an unforgeable capability with exactly one terminal outcome and a `Drop` that
/// reports its absence; there is no second copy to hand a second caller. So the
/// coalescing an instance layer does across retries of one operation appears
/// here as this refusal, which names the pin rather than pretending to issue
/// another. The bound operation/digest half needs no test at all: the binding
/// carries the *sole* final operation and digest, fixed at `begin`, so a
/// different one cannot reach a session in the first place.
fn require_finalizable(record: &SessionRecord, session_id: [u8; 16]) -> Result<(), StoreError> {
    match record.state {
        StagedSessionState::Sealed => Ok(()),
        StagedSessionState::Open => Err(StoreError::Conflict(format!(
            "staging session {} has not sealed and has no descriptor to adopt",
            hex::encode(session_id)
        ))),
        StagedSessionState::Finalizing => Err(StoreError::Conflict(format!(
            "staging session {} already holds an adoption pin",
            hex::encode(session_id)
        ))),
        StagedSessionState::Adopted => Err(StoreError::Conflict(format!(
            "staging session {} has already been adopted",
            hex::encode(session_id)
        ))),
    }
}

/// Exclude a session that is already inside a maintenance operation.
///
/// Exhaustive rather than a `!= Idle` test, for the same reason the state match
/// is: deliverable 6 adds a pinned case, and it must arrive here as a compile
/// error rather than be silently swept into "busy".
fn require_idle(record: &SessionRecord, session_id: [u8; 16]) -> Result<(), StoreError> {
    match record.busy {
        SessionBusy::Idle => Ok(()),
        SessionBusy::Sealing => Err(StoreError::Conflict(format!(
            "staging session {} is sealing",
            hex::encode(session_id)
        ))),
        SessionBusy::Finalizing => Err(StoreError::Conflict(format!(
            "staging session {} is taking an adoption pin",
            hex::encode(session_id)
        ))),
        SessionBusy::Reclaiming => Err(StoreError::Conflict(format!(
            "staging session {} is being reclaimed",
            hex::encode(session_id)
        ))),
    }
}

/// Expiry comparison, matching the frozen `validate_projection_stage_finalize`
/// exactly: a session is usable *at* its expiry instant and not after it. A
/// stricter or looser comparison here would make the store and the protocol
/// disagree about a one-microsecond boundary, which is the kind of divergence
/// that only shows up as an unreproducible failure at the deadline.
fn require_live(
    record: &SessionRecord,
    session_id: [u8; 16],
    now_micros: i64,
) -> Result<(), StoreError> {
    if now_micros > record.binding.session.expires_at_micros {
        return Err(StoreError::Conflict(format!(
            "staging session {} expired at {}",
            hex::encode(session_id),
            record.binding.session.expires_at_micros
        )));
    }
    Ok(())
}

/// A bound the request violates by itself, regardless of load. Typed refusal,
/// never a clamp and never an eviction (decision 9.8).
fn require_at_most(limit: &'static str, observed: u64, allowed: u64) -> Result<(), StoreError> {
    if observed > allowed {
        return Err(StoreError::LimitExceeded {
            limit,
            observed,
            allowed,
        });
    }
    Ok(())
}

/// A bound the request violates only because of concurrent occupancy. Plan
/// §5.1 reserves `StoreError` for inability to answer, and a store whose
/// staging budget is spent genuinely cannot answer *yet* — which is what
/// distinguishes this from `LimitExceeded`, where retrying changes nothing.
fn overload_at_most(
    limit: &'static str,
    observed: u64,
    allowed: u64,
    retry_after_micros: u64,
) -> Result<(), StoreError> {
    if observed > allowed {
        return Err(StoreError::Overloaded {
            limit,
            retry_after_micros,
        });
    }
    Ok(())
}

fn overload_sum(
    limit: &'static str,
    used: u64,
    requested: u64,
    allowed: u64,
    retry_after_micros: u64,
) -> Result<(), StoreError> {
    let total = used.checked_add(requested).ok_or(StoreError::Overloaded {
        limit,
        retry_after_micros,
    })?;
    overload_at_most(limit, total, allowed, retry_after_micros)
}

/// Chunk artifact name: ordinal for order, digest for content.
///
/// Both halves are required. The ordinal alone would let a retry with
/// different bytes reuse a name; the digest alone would let two ordinals
/// carrying identical bytes collide onto one file and make the manifest
/// position ambiguous.
fn chunk_artifact_name(ordinal: u32, digest: &ObjectId) -> String {
    format!("chunk-{ordinal:010}-{}", hex::encode(digest.0))
}

/// Digest over the artifact set, in ordinal order, by content and size only.
///
/// Paths are deliberately excluded: the shard owner assigns manifest-visible
/// names at adoption, so a digest over paths would change at exactly the
/// moment it is supposed to prove nothing changed.
fn artifact_set_digest(artifacts: &[ProjectionArtifact]) -> ObjectId {
    let mut bytes = Vec::with_capacity(artifacts.len() * 40);
    for (ordinal, artifact) in artifacts.iter().enumerate() {
        bytes.extend_from_slice(&(ordinal as u32).to_le_bytes());
        bytes.extend_from_slice(&artifact.digest.0);
        bytes.extend_from_slice(&artifact.bytes.to_le_bytes());
    }
    digest(STAGING_ARTIFACT_SET_DIGEST_DOMAIN, &bytes)
}

fn encode_staging_artifact(
    kind: StagingArtifactKind,
    session_id: [u8; 16],
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(STAGING_ARTIFACT_HEADER_LEN + payload.len() + 32);
    bytes.extend_from_slice(&STAGING_ARTIFACT_MAGIC);
    bytes.extend_from_slice(&STAGING_ARTIFACT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&kind.code().to_le_bytes());
    bytes.extend_from_slice(&session_id);
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    let trailer = digest(STAGING_ARTIFACT_DIGEST_DOMAIN, &bytes);
    bytes.extend_from_slice(&trailer.0);
    bytes
}

/// The session marker a file carries, or `None` if it carries none.
///
/// Deliverable 7's "valid session marker" in its cheapest form. A file whose
/// header is absent, truncated, wrong-magic, wrong-version, or fails its own
/// trailer digest has no marker, so reclamation leaves it alone rather than
/// guessing from its name or its directory.
fn artifact_session_marker(path: &Path) -> Result<Option<[u8; 16]>, StoreError> {
    let bytes = std::fs::read(path)?;
    Ok(parse_staging_artifact(&bytes).map(|(_, session_id, _)| session_id))
}

fn parse_staging_artifact(bytes: &[u8]) -> Option<(StagingArtifactKind, [u8; 16], &[u8])> {
    if bytes.len() < STAGING_ARTIFACT_HEADER_LEN + 32 {
        return None;
    }
    if bytes[..8] != STAGING_ARTIFACT_MAGIC {
        return None;
    }
    if u16::from_le_bytes([bytes[8], bytes[9]]) != STAGING_ARTIFACT_VERSION {
        return None;
    }
    let kind = StagingArtifactKind::from_code(u16::from_le_bytes([bytes[10], bytes[11]]))?;
    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&bytes[12..28]);
    let payload_len = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]) as usize;
    let payload_end = STAGING_ARTIFACT_HEADER_LEN.checked_add(payload_len)?;
    if bytes.len() != payload_end + 32 {
        return None;
    }
    if digest(STAGING_ARTIFACT_DIGEST_DOMAIN, &bytes[..payload_end]).0 != bytes[payload_end..] {
        return None;
    }
    Some((
        kind,
        session_id,
        &bytes[STAGING_ARTIFACT_HEADER_LEN..payload_end],
    ))
}

fn read_staging_artifact(
    path: &Path,
    kind: StagingArtifactKind,
    session_id: [u8; 16],
) -> Result<Vec<u8>, StoreError> {
    let bytes = std::fs::read(path)?;
    let (actual_kind, actual_session, payload) =
        parse_staging_artifact(&bytes).ok_or_else(|| {
            StoreError::Corruption(format!(
                "staging artifact {} has no valid session marker",
                path.display()
            ))
        })?;
    if actual_kind != kind || actual_session != session_id {
        return Err(StoreError::Corruption(format!(
            "staging artifact {} carries a marker for a different kind or session",
            path.display()
        )));
    }
    Ok(payload.to_vec())
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::sync::Mutex;

    use levcs_protocol::v2::{ProjectionMode, StageSourceKindV1};
    use tempfile::TempDir;

    use super::*;
    use crate::index::{IndexKey, IndexLocation};
    use crate::roots::{PinnedFile, ProjectionArtifactFormat};

    struct RecordingLifecycle {
        resolution: Arc<ProjectionAdoptionResolution>,
        outcomes: Mutex<Vec<ProjectionAdoptionOutcome>>,
        dropped: Mutex<u64>,
    }

    impl ProjectionAdoptionLifecycle for RecordingLifecycle {
        fn resolution(&self) -> Result<Arc<ProjectionAdoptionResolution>, StoreError> {
            Ok(Arc::clone(&self.resolution))
        }

        fn finish(&self, outcome: ProjectionAdoptionOutcome) -> Result<(), StoreError> {
            self.outcomes.lock().unwrap().push(outcome);
            Ok(())
        }

        fn dropped_without_outcome(&self) {
            *self.dropped.lock().unwrap() += 1;
        }
    }

    fn resolution() -> Arc<ProjectionAdoptionResolution> {
        Arc::new(ProjectionAdoptionResolution {
            session: ProjectionStageSessionV1 {
                session_id: [1; 16],
                destination_repo: ObjectId([2; 32]),
                destination_genesis: ObjectId([3; 32]),
                expected_authority: ObjectId([4; 32]),
                projection: ProjectionMode::Full,
                source_kind: StageSourceKindV1::Mirror,
                actor: [5; 32],
                actor_key_epoch: 7,
                source_generation_digest: ObjectId([6; 32]),
                fork_proof: None,
                final_operation_id: [8; 16],
                final_operation_digest: ObjectId([9; 32]),
                final_evidence_digest: ObjectId([10; 32]),
                total_object_count: 1,
                total_object_bytes: 1,
                chunk_count: 1,
                manifest_digest: ObjectId([11; 32]),
                expires_at_micros: 12,
            },
            manifest: ProjectionStageManifestV1 {
                session_id: [1; 16],
                chunk_digests: Vec::new(),
                objects: Vec::new(),
                membership_root: ObjectId([13; 32]),
            },
            artifacts: Arc::from([]),
        })
    }

    fn lifecycle() -> Arc<RecordingLifecycle> {
        Arc::new(RecordingLifecycle {
            resolution: resolution(),
            outcomes: Mutex::new(Vec::new()),
            dropped: Mutex::new(0),
        })
    }

    fn install() -> StagedProjectionInstallV1 {
        StagedProjectionInstallV1 {
            session_id: [20; 16],
            manifest_digest: ObjectId([21; 32]),
            projection: ProjectionMode::Full,
            object_count: 1,
            object_bytes: 32,
            membership_root: ObjectId([22; 32]),
            artifact_set_digest: ObjectId([23; 32]),
        }
    }

    fn recovered_artifacts(
        directory: &TempDir,
    ) -> Result<RecoveredProjectionArtifacts, StoreError> {
        let path = directory.path().join("projection-objects");
        File::create(&path)?;
        let mut delta = IndexDelta::new(8, 4096);
        delta.insert(
            IndexKey::new(NamespaceId([24; 32]), ObjectId([25; 32])),
            IndexLocation {
                segment_generation: 7,
                frame_offset: 128,
                frame_len: 256,
                object_type: 1,
                shard_sequence: 9,
            },
        )?;
        RecoveredProjectionArtifacts::new(
            install(),
            Arc::new(delta),
            Arc::from([]),
            Arc::from([RetainedProjectionArtifact::new(
                7,
                ProjectionArtifactFormat::CanonicalStageChunkV1,
                PinnedFile::open(path)?,
            )]),
        )
    }

    struct RecordingRecoveryResolver {
        artifacts: RecoveredProjectionArtifacts,
        transferred: Arc<[[u8; 16]]>,
        notifications: Mutex<Vec<RecoveredProjectionResolution>>,
    }

    impl ProjectionRecoveryResolver for RecordingRecoveryResolver {
        fn transferred_sessions(&self, _shard_index: u16) -> Result<Arc<[[u8; 16]]>, StoreError> {
            Ok(Arc::clone(&self.transferred))
        }

        fn resolve_committed(
            &self,
            _namespace: NamespaceId,
            descriptor: &StagedProjectionInstallV1,
            _adoption_shard_sequence: u64,
        ) -> Result<RecoveredProjectionArtifacts, StoreError> {
            if self.artifacts.descriptor() != descriptor {
                return Err(StoreError::Corruption(
                    "descriptor did not name the sealed staging session".into(),
                ));
            }
            Ok(self.artifacts.clone())
        }

        fn notify_recovered(
            &self,
            resolution: RecoveredProjectionResolution,
        ) -> Result<(), StoreError> {
            self.notifications.lock().unwrap().push(resolution);
            Ok(())
        }
    }

    #[test]
    fn handle_drop_without_outcome_is_observable() {
        let lifecycle = lifecycle();
        let handle = ProjectionAdoption::new(lifecycle.clone());
        drop(handle);
        assert_eq!(*lifecycle.dropped.lock().unwrap(), 1);
        assert!(lifecycle.outcomes.lock().unwrap().is_empty());
    }

    #[test]
    fn each_terminal_outcome_suppresses_the_drop_bug() {
        for outcome in [
            ProjectionAdoptionOutcome::Adopted {
                committed_shard_sequence: 1,
            },
            ProjectionAdoptionOutcome::DefinitivePreAppendFailure,
            ProjectionAdoptionOutcome::TransferredToRecovery,
        ] {
            let lifecycle = lifecycle();
            ProjectionAdoption::new(lifecycle.clone())
                .finish(outcome)
                .unwrap();
            assert_eq!(&*lifecycle.outcomes.lock().unwrap(), &[outcome]);
            assert_eq!(*lifecycle.dropped.lock().unwrap(), 0);
        }
    }

    #[test]
    fn recovery_resolution_is_read_only_and_carries_live_ownership() {
        let directory = TempDir::new().unwrap();
        let artifacts = recovered_artifacts(&directory).unwrap();
        let retained_path = artifacts.retained_artifacts()[0].path().to_owned();
        let resolver = RecordingRecoveryResolver {
            artifacts,
            transferred: Arc::from([[20; 16], [26; 16]]),
            notifications: Mutex::new(Vec::new()),
        };

        let transferred = resolver.transferred_sessions(3).unwrap();
        assert_eq!(&*transferred, &[[20; 16], [26; 16]]);
        let recovered = resolver
            .resolve_committed(NamespaceId([24; 32]), &install(), 0)
            .unwrap();
        assert_eq!(recovered.descriptor(), &install());
        assert_eq!(recovered.index_delta().len(), 1);
        assert_eq!(recovered.index_runs_newest_first().len(), 0);
        assert!(recovered.retained_index_runs().is_empty());
        assert_eq!(recovered.retained_artifacts()[0].path(), retained_path);
    }

    #[test]
    fn recovery_notifies_both_terminal_physical_outcomes() {
        let directory = TempDir::new().unwrap();
        let resolver = RecordingRecoveryResolver {
            artifacts: recovered_artifacts(&directory).unwrap(),
            transferred: Arc::from([]),
            notifications: Mutex::new(Vec::new()),
        };
        for outcome in [
            RecoveredProjectionOutcome::Committed,
            RecoveredProjectionOutcome::ProvedAbsent,
        ] {
            resolver
                .notify_recovered(RecoveredProjectionResolution {
                    session_id: [20; 16],
                    outcome,
                })
                .unwrap();
        }
        assert_eq!(
            &*resolver.notifications.lock().unwrap(),
            &[
                RecoveredProjectionResolution {
                    session_id: [20; 16],
                    outcome: RecoveredProjectionOutcome::Committed,
                },
                RecoveredProjectionResolution {
                    session_id: [20; 16],
                    outcome: RecoveredProjectionOutcome::ProvedAbsent,
                },
            ]
        );
    }

    #[test]
    fn recovery_rejects_membership_without_live_artifact_ownership() {
        let mut delta = IndexDelta::new(8, 4096);
        delta
            .insert(
                IndexKey::new(NamespaceId([24; 32]), ObjectId([25; 32])),
                IndexLocation {
                    segment_generation: 7,
                    frame_offset: 128,
                    frame_len: 256,
                    object_type: 1,
                    shard_sequence: 9,
                },
            )
            .unwrap();
        let error = RecoveredProjectionArtifacts::new(
            install(),
            Arc::new(delta),
            Arc::from([]),
            Arc::from([]),
        )
        .unwrap_err();
        assert!(matches!(error, StoreError::Corruption(message) if message.contains("ownership")));
    }
}

/// B3-owned unit tests.
///
/// These cover the two seams an integration test cannot reach: the device
/// probe, which needs a second `st_dev` under one temporary root, and the
/// artifact marker, which is the physical representation cleanup will key on.
/// Everything else about the session lifecycle is asserted through the public
/// entry points in `tests/staging_sessions.rs`, because a bound proved only
/// against an internal helper is charter item 8's decoy.
#[cfg(test)]
mod b3_tests {
    use std::collections::BTreeMap;

    use levcs_protocol::v2::{ProjectionMode, StageSourceKindV1};
    use tempfile::TempDir;

    use super::*;

    const HOUR_MICROS: i64 = 3_600_000_000;

    struct FixedDeviceProbe {
        devices: BTreeMap<PathBuf, u64>,
    }

    impl DeviceProbe for FixedDeviceProbe {
        fn device_of(&self, path: &Path) -> Result<u64, StoreError> {
            self.devices.get(path).copied().ok_or_else(|| {
                StoreError::Corruption(format!("no device configured for {}", path.display()))
            })
        }
    }

    /// A real v2 root plus the held root lock staging now requires.
    ///
    /// The lock is returned, not dropped: it is the ownership proof, and a
    /// fixture that let it die would be testing a constructor production can
    /// never reach.
    fn layout(directory: &TempDir) -> (StoreOptions, RecoverySession) {
        let mut options = StoreOptions::new(directory.path());
        options.shard_count = 4;
        crate::segment::initialize_root(
            &crate::segment::RootLayout::new(directory.path()),
            options.shard_count,
            [42; 16],
            0,
            &DurabilityCounters::default(),
        )
        .expect("root layout");
        let lock = RecoverySession::open(directory.path()).expect("root lock");
        (options, lock)
    }

    fn binding(session_id: [u8; 16], expires_at_micros: i64) -> ProjectionStageBinding {
        ProjectionStageBinding {
            session: ProjectionStageSessionV1 {
                session_id,
                destination_repo: ObjectId([7; 32]),
                destination_genesis: ObjectId([8; 32]),
                expected_authority: ObjectId([9; 32]),
                projection: ProjectionMode::Full,
                source_kind: StageSourceKindV1::Mirror,
                actor: [11; 32],
                actor_key_epoch: 3,
                source_generation_digest: ObjectId([12; 32]),
                fork_proof: None,
                final_operation_id: [13; 16],
                final_operation_digest: ObjectId([14; 32]),
                final_evidence_digest: ObjectId([15; 32]),
                total_object_count: 2,
                total_object_bytes: 64,
                chunk_count: 1,
                manifest_digest: ObjectId([16; 32]),
                expires_at_micros,
            },
            membership_root: ObjectId([17; 32]),
        }
    }

    /// A self-consistent one-chunk projection and the binding that seals to it.
    ///
    /// [`binding`] carries a placeholder `manifest_digest` and so can never
    /// reach `Sealed`, which is why every sealing test lived in the integration
    /// file. `finalize` is `pub(crate)` — B1's `adopt_projection` is its only
    /// legitimate caller — so its regressions cannot live there, and the fixture
    /// has to exist on this side of the wall.
    fn sealable(session_id: [u8; 16]) -> (ProjectionStageBinding, ProjectionStageChunkV1) {
        use levcs_protocol::v2::StagedChunkObjectV1;
        let mut objects: Vec<StagedChunkObjectV1> = (0..2u8)
            .map(|index| {
                let body = [index; 24];
                let mut raw = levcs_core::ObjectHeader {
                    object_type: levcs_core::ObjectType::Blob,
                    format_version: levcs_core::FORMAT_VERSION,
                    body_len: body.len() as u64,
                }
                .encode()
                .to_vec();
                raw.extend_from_slice(&body);
                let id = levcs_core::blake3_hash(&raw);
                StagedChunkObjectV1 {
                    descriptor: StagedObjectV1 {
                        object_id: id,
                        object_type: levcs_core::ObjectType::Blob as u8,
                        raw_len: raw.len() as u64,
                        raw_digest: id,
                    },
                    raw_bytes: raw,
                }
            })
            .collect();
        // The manifest is the ordered concatenation of the chunks and must be
        // strictly sorted, so the sort happens before the split.
        objects.sort_by(|left, right| left.descriptor.cmp(&right.descriptor));

        let total_object_bytes = objects.iter().map(|o| o.descriptor.raw_len).sum::<u64>();
        let descriptors: Vec<StagedObjectV1> =
            objects.iter().map(|o| o.descriptor.clone()).collect();
        let chunk = ProjectionStageChunkV1 {
            session_id,
            ordinal: 0,
            chunk_count: 1,
            objects,
        };
        let membership_root = levcs_core::blake3_hash(&session_id[..]);
        let manifest = ProjectionStageManifestV1 {
            session_id,
            chunk_digests: vec![chunk.chunk_digest().expect("chunk digest")],
            objects: descriptors,
            membership_root,
        };
        let manifest_digest = manifest.manifest_digest().expect("manifest digest");

        let mut session = binding(session_id, HOUR_MICROS).session;
        session.total_object_count = 2;
        session.total_object_bytes = total_object_bytes;
        session.chunk_count = 1;
        session.manifest_digest = manifest_digest;
        (
            ProjectionStageBinding {
                session,
                membership_root,
            },
            chunk,
        )
    }

    /// Deliverable 6 end to end, and the one test that had to exist first.
    ///
    /// It catches three things that are only visible together. The pin has to be
    /// *takeable*: `finalize` writes a marker that no marker precedes. It has to
    /// be *finishable*: recording `Adopted` replaces that marker rather than
    /// colliding with it — the shared artifact writer publishes with
    /// `rename_noreplace`, so routing the second write through it wedges every
    /// adoption in `Finalizing` with an `EEXIST` nobody sees. And the outcome has
    /// to be *durable and accounted*: adoption releases the reservation because
    /// the bytes are store content now, and the reopen must reconstruct that
    /// without charging for them a second time — a budget that shrinks on every
    /// restart is a ceiling nobody can reason about.
    #[test]
    fn an_adopted_pin_survives_the_reopen_without_recharging_its_budget() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let (binding, chunk) = sealable([31; 16]);
        let session_id = binding.session.session_id;

        let reserved = {
            let staging = ProjectionStaging::open(
                &lock,
                options.clone(),
                Arc::new(DurabilityCounters::default()),
            )
            .expect("staging opens");
            let session = staging.begin(binding.clone(), 0).expect("begin");
            session.put_chunk(&chunk, 0).expect("put");
            session.seal(0).expect("seal");
            let reserved = staging.counters().snapshot().reserved_bytes;
            assert!(reserved > 0, "a sealed session holds budget");

            let adoption = session.finalize(0).expect("a sealed session may be pinned");
            assert_eq!(
                staging.counters().snapshot().sessions_finalized,
                1,
                "the pin was taken"
            );
            assert_eq!(
                describe_state(&staging, session_id),
                StagedSessionState::Finalizing
            );

            adoption
                .handle
                .finish(ProjectionAdoptionOutcome::Adopted {
                    committed_shard_sequence: 7,
                })
                .expect(
                    "recording adoption must replace the pin's own marker; the shared artifact \
                     writer refuses to replace, which would leave every adoption stuck in \
                     Finalizing",
                );
            assert_eq!(
                describe_state(&staging, session_id),
                StagedSessionState::Adopted
            );
            assert_eq!(
                staging.counters().snapshot().reserved_bytes,
                0,
                "adopted bytes are store content and stop being staging occupancy"
            );
            reserved
        };

        let staging =
            ProjectionStaging::open(&lock, options, Arc::new(DurabilityCounters::default()))
                .expect("staging reopens");
        assert_eq!(
            describe_state(&staging, session_id),
            StagedSessionState::Adopted,
            "the outcome is durable, or the next open would offer the pin again"
        );
        assert_eq!(
            staging.counters().snapshot().reserved_bytes,
            0,
            "reconstructing an adopted session must not re-charge the {reserved} bytes its \
             adoption released; a ceiling that shrinks on every restart is not a ceiling"
        );

        // The adoption's position has to survive too. A restart separates an
        // adoption from the compaction that eventually drops its reference, so a
        // position held only in memory would leave every reconstructed session
        // either permanently unreclaimable or reclaimable through a stale root —
        // the defect this records against.
        assert_eq!(
            staging
                .cleanup_unreferenced(&root_at(&[], 6))
                .expect("cleanup"),
            0,
            "a root short of the reconstructed adoption is still not evidence"
        );
        assert_eq!(staging.counters().snapshot().cleanup_declined_stale_root, 1);
        assert_eq!(
            staging
                .cleanup_unreferenced(&root_at(&[], 7))
                .expect("cleanup"),
            1,
            "and a root that has reached it reclaims, so the position reconstructed as \
             itself rather than as something unreachable"
        );
    }

    /// A sealed session, its staging, and the on-disk path of its marker.
    ///
    /// Returned rather than rebuilt per test because "did the marker actually
    /// move" is the question every one of these asks, and a test that asserted
    /// only the in-memory state would pass against a pin that never reached the
    /// device.
    fn sealed(
        directory: &TempDir,
        lock: &RecoverySession,
        options: StoreOptions,
        session_id: [u8; 16],
    ) -> (
        Arc<ProjectionStaging>,
        ProjectionStageSession,
        PathBuf,
        StagedProjectionInstallV1,
    ) {
        let (binding, chunk) = sealable(session_id);
        let shard = StoreOptions::shard_of(
            &NamespaceId::from(binding.session.destination_repo),
            options.shard_count,
        );
        let staging =
            ProjectionStaging::open(lock, options, Arc::new(DurabilityCounters::default()))
                .expect("staging opens");
        let session = staging.begin(binding, 0).expect("begin");
        session.put_chunk(&chunk, 0).expect("put");
        // Returned rather than discarded: `seal` requires `Open`, so it is the
        // only chance to observe the descriptor a later resolution must match.
        let install = session.seal(0).expect("seal");
        let marker = directory
            .path()
            .join(STAGING_DIR)
            .join(format!("{shard:02}"))
            .join(hex::encode(session_id))
            .join(ADOPTION_NAME);
        (staging, session, marker, install)
    }

    /// One pin, and the second finalizer is told so by name.
    ///
    /// Scope §6.5 originally promised that identical concurrent finalizers
    /// "coalesce onto one" here. They cannot: a `ProjectionAdoption` is an
    /// unforgeable capability with exactly one terminal outcome and a `Drop` that
    /// reports its absence, so there is no second copy to hand a second caller.
    /// Coalescing retries of one request belongs to whoever owns the request
    /// (contract review 2026-07-31-A). What this layer owes is that a second
    /// finalizer never produces a second pin and never quietly succeeds.
    #[test]
    fn a_second_finalizer_is_refused_rather_than_issued_a_second_pin() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let (staging, session, _marker, _install) = sealed(&directory, &lock, options, [41; 16]);

        let first = session
            .finalize(0)
            .expect("the first finalizer takes the pin");
        let Err(StoreError::Conflict(detail)) = session.finalize(0) else {
            panic!("a second finalizer must be refused, not handed another pin");
        };
        assert!(detail.contains("already holds an adoption pin"), "{detail}");
        assert_eq!(
            staging.counters().snapshot().sessions_finalized,
            1,
            "a refused finalizer must not count as a pin"
        );
        first
            .handle
            .finish(ProjectionAdoptionOutcome::DefinitivePreAppendFailure)
            .expect("release");
    }

    /// The named acceptance case: expiry may stop a *new* finalizer, never an
    /// admitted one.
    ///
    /// Both halves matter. The sweep must decline the pinned session, and it must
    /// leave the artifacts where they are — an expiry that reclaimed here would
    /// delete the objects a transaction may already be appending a frame about.
    #[test]
    fn expiry_after_finalization_reclaims_nothing() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let (staging, session, marker, _install) = sealed(&directory, &lock, options, [42; 16]);
        let adoption = session.finalize(0).expect("pin");

        assert_eq!(
            staging.expire(HOUR_MICROS + 1).expect("sweep"),
            0,
            "a pinned session is not expiry's to reclaim"
        );
        assert_eq!(
            describe_state(&staging, [42; 16]),
            StagedSessionState::Finalizing
        );
        assert!(
            marker.exists() && marker.parent().expect("session directory").exists(),
            "the sweep must leave a pinned session's artifacts on the device"
        );
        adoption
            .handle
            .finish(ProjectionAdoptionOutcome::DefinitivePreAppendFailure)
            .expect("release");
    }

    /// The other ordering of the named race: expiry arrives while a finalizer is
    /// mid-admission.
    ///
    /// `expiry_after_finalization_reclaims_nothing` covers the ordering where the
    /// marker is already durable and the *state* says `Finalizing`. This is the
    /// window before that — the finalizer has been admitted under the registry
    /// lock and released it to write the marker, so the session still reads
    /// `Sealed` with no marker on disk. An expiry sweep that looked only at state
    /// would find an expired, sealed, unpinned session and reclaim it, deleting
    /// the artifacts out from under a pin that is about to be issued.
    ///
    /// What prevents it is the `busy` exclusion, so that is what this drives
    /// directly. The session is put in exactly the mid-flight shape rather than
    /// raced into it, because a race that reproduces one time in a thousand is a
    /// test that passes for the wrong reason the other nine hundred and ninety
    /// nine.
    ///
    /// The second half is what makes it load-bearing: clearing `busy` and
    /// sweeping again *does* reclaim. Without that, an assertion that nothing was
    /// reclaimed proves only that something declined — not that the exclusion is
    /// what declined it.
    #[test]
    fn expiry_during_the_finalize_admission_window_reclaims_nothing() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let (staging, _session, marker, _install) = sealed(&directory, &lock, options, [45; 16]);
        let session_directory = marker.parent().expect("session directory").to_path_buf();

        // The shape `finalize` holds between phase 1 and phase 3.
        {
            let mut registry = staging.lock();
            let record = registry.sessions.get_mut(&[45; 16]).expect("session");
            assert_eq!(record.state, StagedSessionState::Sealed);
            record.busy = SessionBusy::Finalizing;
        }
        assert!(
            !marker.exists(),
            "the window under test is the one before the marker is durable"
        );

        assert_eq!(
            staging.expire(HOUR_MICROS + 1).expect("sweep"),
            0,
            "an expiry sweep must not reclaim a session a finalizer has already been \
             admitted to, even though its state still reads Sealed"
        );
        assert!(
            session_directory.exists(),
            "and it must leave the artifacts the pin is about to cover"
        );

        {
            let mut registry = staging.lock();
            registry.sessions.get_mut(&[45; 16]).expect("session").busy = SessionBusy::Idle;
        }
        assert_eq!(
            staging.expire(HOUR_MICROS + 1).expect("sweep"),
            1,
            "with the exclusion cleared the same sweep does reclaim, so the decline above \
             was the exclusion and not some other refusal"
        );
    }

    /// Nothing was appended, so the pin simply ends — and the session is
    /// finalizable again.
    ///
    /// Refinalization is the assertion that matters. Deliverable 6 says a
    /// definitive pre-append failure returns a live session to a state it can be
    /// finalized from; a repair that only cleared an in-memory flag, or that left
    /// the marker behind, would pass a state check and still refuse the retry.
    #[test]
    fn a_definitive_pre_append_failure_returns_a_live_session_to_sealed() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let (staging, session, marker, _install) = sealed(&directory, &lock, options, [43; 16]);

        let adoption = session.finalize(0).expect("pin");
        assert!(marker.exists(), "the pin is durable before it is issued");

        adoption
            .handle
            .finish(ProjectionAdoptionOutcome::DefinitivePreAppendFailure)
            .expect("release");
        assert!(!marker.exists(), "the marker goes with the pin");
        assert_eq!(
            describe_state(&staging, [43; 16]),
            StagedSessionState::Sealed,
            "the durable manifest is still the seal's commit point, so Sealed is the only \
             state a restart could reproduce here"
        );
        assert_eq!(
            staging.counters().snapshot().adoption_pins_released,
            1,
            "a release is its own event, distinct from an adoption"
        );

        session
            .finalize(0)
            .expect("a released session is finalizable again, or the retry has nowhere to go")
            .handle
            .finish(ProjectionAdoptionOutcome::DefinitivePreAppendFailure)
            .expect("release");
    }

    /// The pin outlives the process, which is the only reason `Finalizing` is
    /// durable at all.
    ///
    /// `TransferredToRecovery` means nobody in this process knows whether the
    /// final frame reached the journal. The marker therefore stays, the next open
    /// reconstructs `Finalizing`, and `transferred_sessions` hands the question
    /// to recovery — the answer that method was written to be able to give and
    /// could only prove empty while `finalize` was deferred.
    #[test]
    fn a_transferred_pin_reconstructs_and_is_offered_to_recovery() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let session_id = [44; 16];
        let shard =
            StoreOptions::shard_of(&NamespaceId::from(ObjectId([7; 32])), options.shard_count);
        let marker = {
            let (staging, session, marker, _install) =
                sealed(&directory, &lock, options.clone(), session_id);
            session
                .finalize(0)
                .expect("pin")
                .handle
                .finish(ProjectionAdoptionOutcome::TransferredToRecovery)
                .expect("transfer");
            assert_eq!(staging.counters().snapshot().adoption_pins_transferred, 1);
            marker
        };
        assert!(
            marker.exists(),
            "a transferred pin leaves its marker behind"
        );

        let staging =
            ProjectionStaging::open(&lock, options, Arc::new(DurabilityCounters::default()))
                .expect("staging reopens");
        assert_eq!(
            describe_state(&staging, session_id),
            StagedSessionState::Finalizing,
            "the pin survived the process, or recovery is never told to resolve it"
        );
        assert_eq!(
            &*staging.transferred_sessions(shard).expect("transferred"),
            &[session_id],
            "the session must be offered to recovery for the shard it belongs to"
        );
        assert!(
            staging
                .transferred_sessions(shard ^ 1)
                .expect("transferred")
                .is_empty(),
            "and to no other shard"
        );
    }

    /// A committed root that pins `paths` as staged projection artifacts.
    ///
    /// Built through the real `RetainedProjectionArtifact`, which holds an open
    /// descriptor, so a root in a test references a file the same way a root in
    /// production does — by owning it, not by naming it.
    fn root_referencing(paths: &[PathBuf]) -> CommittedRoot {
        root_at(paths, 7)
    }

    /// A root pinning `paths` that records no committed sequence for any shard.
    ///
    /// Not the same as one recording zero. This is the shape a root has for a
    /// shard it knows nothing about, and cleanup must treat it as no evidence
    /// rather than as evidence of zero.
    fn root_without_sequences(paths: &[PathBuf]) -> CommittedRoot {
        let mut root = root_at(paths, 0);
        root = CommittedRoot::new(
            root.repositories().clone(),
            crate::roots::LayeredObjectIndex::default(),
            root.terminal_statuses().clone(),
            crate::roots::ShardSequenceMap::new(),
            root.retained_generations().clone(),
        );
        root
    }

    /// A root pinning `paths` whose shards have committed through `through`.
    ///
    /// The sequence is not decoration: cleanup skips an adopted session unless
    /// the root it is given has reached the adoption, so a root built without one
    /// proves nothing and a test using it would assert against a skip rather than
    /// against the reference proof.
    fn root_at(paths: &[PathBuf], through: u64) -> CommittedRoot {
        let artifacts: Vec<RetainedProjectionArtifact> = paths
            .iter()
            .enumerate()
            .map(|(index, path)| {
                RetainedProjectionArtifact::new(
                    index as u64,
                    crate::roots::ProjectionArtifactFormat::CanonicalStageChunkV1,
                    crate::roots::PinnedFile::open(path.clone()).expect("pin the artifact"),
                )
            })
            .collect();
        let mut generations = crate::roots::GenerationMap::new();
        generations.insert(
            crate::roots::GenerationId::new(0, 0),
            Arc::new(crate::roots::RetainedGeneration::new(
                crate::roots::GenerationId::new(0, 0),
                Vec::new().into(),
                Vec::new().into(),
                Vec::new().into(),
                Vec::new().into(),
                artifacts.into(),
            )),
        );
        // Every shard, because a real committed root carries a sequence per
        // shard and the fixture's destination does not land on shard 0. A helper
        // that populated only one would make every test measure a stale-root
        // skip while claiming to measure the reference proof.
        let mut sequences = crate::roots::ShardSequenceMap::new();
        for shard in 0..4u16 {
            sequences.insert(shard, through);
        }
        CommittedRoot::new(
            crate::roots::RepoMap::new(),
            crate::roots::LayeredObjectIndex::default(),
            crate::roots::TerminalStatusMap::new(),
            sequences,
            generations,
        )
    }

    fn session_files(directory: &Path) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = std::fs::read_dir(directory)
            .expect("session directory")
            .map(|entry| entry.expect("entry").path())
            .collect();
        paths.sort();
        paths
    }

    /// Deliverable 7's named acceptance case, and its inverse in the same test
    /// so neither half can pass alone.
    ///
    /// Cleanup declines a session a committed root still references, and the
    /// same session against a root that references nothing is reclaimed. Running
    /// both against one adopted session is what makes the first assertion mean
    /// "the reference proof declined it" rather than "cleanup does nothing here";
    /// a cleanup that reclaimed nothing ever would pass the decline half
    /// perfectly.
    #[test]
    fn cleanup_declines_a_referenced_session_and_reclaims_an_unreferenced_one() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let (staging, session, marker, _install) = sealed(&directory, &lock, options, [51; 16]);
        let session_directory = marker.parent().expect("session directory").to_path_buf();

        session
            .finalize(0)
            .expect("pin")
            .handle
            .finish(ProjectionAdoptionOutcome::Adopted {
                committed_shard_sequence: 7,
            })
            .expect("adopt");
        let files = session_files(&session_directory);
        assert!(
            files.len() >= 3,
            "an adopted session keeps its chunk, manifest, and marker: {files:?}"
        );

        // A root holding exactly one of the session's artifacts. That is the
        // state immediately after adoption, and it must be enough to decline.
        let chunk = files
            .iter()
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| parse_chunk_artifact_name(name).is_some())
            })
            .expect("a chunk artifact")
            .clone();
        let referencing = root_referencing(&[chunk]);
        assert_eq!(
            staging
                .cleanup_unreferenced(&referencing)
                .expect("cleanup runs"),
            0,
            "an artifact a committed root still references is not cleanup's to remove"
        );
        assert_eq!(
            session_files(&session_directory),
            files,
            "and it must leave every file where it found it, not only the referenced one"
        );
        assert_eq!(
            describe_state(&staging, [51; 16]),
            StagedSessionState::Adopted,
            "a declined session stays exactly as it was"
        );
        assert_eq!(
            staging.counters().snapshot().cleanup_declined_referenced,
            1,
            "the decline is the reference proof doing work, and is counted as such"
        );

        // Nothing points at it any more — a later checkpoint or compaction
        // dropped the pin — so now it goes.
        let empty = root_referencing(&[]);
        assert_eq!(
            staging.cleanup_unreferenced(&empty).expect("cleanup runs"),
            1,
            "an adopted session nothing references is exactly what cleanup exists to reclaim"
        );
        assert!(
            !session_directory.exists(),
            "the directory goes with it, or the next open reconstructs a session that was \
             reclaimed"
        );
        assert_eq!(staging.counters().snapshot().sessions_cleaned_up, 1);
    }

    /// P1: a stale root proves nothing, and cleanup trusted whatever it was
    /// handed.
    ///
    /// The sequence is the reviewer's. `R0` is captured before the projection is
    /// published and therefore references none of its artifacts. `R1` is
    /// published referencing them, and the session records `Adopted`. Cleanup is
    /// then called with `R0` — an older root that is not wrong, merely earlier —
    /// and every artifact in it is absent from that root's pins, so the absence
    /// proof succeeds and the directory is deleted out from under a committed
    /// root that still points into it.
    ///
    /// My review note had this backwards: I argued a racing newer root "can only
    /// add references", and concluded the proof was safe. Adding references is
    /// precisely the hazard — it means an older root omits references a newer one
    /// holds, so absence measured against the older root is not absence.
    #[test]
    fn cleanup_will_not_delete_through_a_root_older_than_the_adoption() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let (staging, session, marker, _install) = sealed(&directory, &lock, options, [53; 16]);
        let session_directory = marker.parent().expect("session directory").to_path_buf();

        // 1. A root captured before anything adopted this projection: it holds
        //    none of its artifacts, and its committed prefix stops short of the
        //    sequence the adoption frame will reach.
        let before = root_at(&[], 6);

        // 2 and 3. The projection is published and the session records it.
        let files = session_files(&session_directory);
        let referenced = root_at(&files, 7);
        session
            .finalize(0)
            .expect("pin")
            .handle
            .finish(ProjectionAdoptionOutcome::Adopted {
                committed_shard_sequence: 7,
            })
            .expect("adopt");
        assert!(
            referenced.references_artifact(&files[0]),
            "the newer root does reference the artifacts, or this proves nothing"
        );

        // 4. Cleanup with the older root.
        let reclaimed = staging
            .cleanup_unreferenced(&before)
            .expect("cleanup answers");
        assert_eq!(
            reclaimed, 0,
            "a root older than the adoption cannot prove absence of reference: it predates \
             every reference the adoption created"
        );
        assert!(
            session_directory.exists(),
            "the committed root published at step 2 still points into this directory"
        );
        assert_eq!(
            staging.counters().snapshot().cleanup_declined_stale_root,
            1,
            "and the reason must be the root's age, not an incidental refusal"
        );

        // The same session against a root that *has* reached the adoption and
        // references nothing is reclaimable, so the skip above is the position
        // check and not cleanup declining everything.
        assert_eq!(
            staging
                .cleanup_unreferenced(&root_at(&[], 7))
                .expect("cleanup"),
            1
        );
    }

    /// A committed projection resolves to complete membership, and a partial
    /// chunk set never resolves at all.
    ///
    /// The second half is the deliverable's central claim and the one an
    /// implementation drifts away from by being helpful: resolving whatever
    /// chunks are present would publish a smaller projection than the frame
    /// committed, and every object in the missing chunk would be unreadable
    /// through a root that says it is there.
    #[test]
    fn a_committed_projection_resolves_whole_or_not_at_all() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let (staging, _session, marker, install) = sealed(&directory, &lock, options, [63; 16]);
        let session_directory = marker.parent().expect("session directory").to_path_buf();
        let namespace = NamespaceId::from(ObjectId([7; 32]));

        let resolved = staging
            .resolve_committed(namespace, &install, 9)
            .expect("a sealed session resolves its own descriptor");
        assert_eq!(resolved.descriptor(), &install);
        assert_eq!(
            resolved.retained_artifacts().len(),
            1,
            "one pinned artifact per chunk"
        );
        let generation = projection_generation(9, 0, [63; 16]).expect("in range");
        assert_eq!(
            resolved.retained_artifacts()[0].logical_generation,
            generation,
            "the artifact is pinned at the generation its locations name"
        );
        assert_eq!(
            resolved.index_delta().len() as u64,
            install.object_count,
            "every object the descriptor declares is located, or the root would publish \
             membership it cannot resolve"
        );

        // Every object in a chunk shares that chunk's location: the location
        // names the whole certified record, and a reader validates the artifact
        // before extracting from its decoded vector.
        let file_bytes = std::fs::metadata(
            &session_files(&session_directory)
                .into_iter()
                .find(|path| {
                    path.file_name()
                        .and_then(|name| name.to_str())
                        .is_some_and(|name| parse_chunk_artifact_name(name).is_some())
                })
                .expect("a chunk artifact"),
        )
        .expect("metadata")
        .len();
        for (_, location) in resolved.index_delta().iter() {
            assert_eq!(location.segment_generation, generation);
            assert_eq!(location.frame_offset, 0);
            assert_eq!(u64::from(location.frame_len), file_bytes);
        }

        // Now take one chunk away. Nothing partial may resolve.
        let chunk = session_files(&session_directory)
            .into_iter()
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| parse_chunk_artifact_name(name).is_some())
            })
            .expect("a chunk artifact");
        std::fs::remove_file(&chunk).expect("remove one chunk");
        let refused = staging
            .resolve_committed(namespace, &install, 9)
            .expect_err("a missing chunk must fail the whole resolution");
        assert!(
            matches!(refused, StoreError::Corruption(_) | StoreError::Io(_)),
            "expected a named fault, got {refused:?}"
        );
    }

    /// Resolution obeys the active-index ceilings, not a limit of its own.
    ///
    /// `max_projection_objects` bounds what a *session* may stage;
    /// `max_active_index_entries` and `max_active_index_bytes` bound what a
    /// reopen may rebuild. Nothing requires the second pair to admit a maximal
    /// projection, so a resolution sized from the first would hand recovery a
    /// delta the recovered root cannot hold — publishing an over-limit root
    /// instead of refusing, which is the hole admission accounting exists to
    /// keep shut.
    ///
    /// Both ceilings are driven separately because they are separate refusals: a
    /// projection can be under one and over the other.
    #[test]
    fn resolution_refuses_a_projection_over_the_active_index_ceilings() {
        for (limit, adjust) in [
            (
                "max_active_index_entries",
                Box::new(|options: &mut StoreOptions| options.max_active_index_entries = 1)
                    as Box<dyn Fn(&mut StoreOptions)>,
            ),
            (
                "max_active_index_bytes",
                Box::new(|options: &mut StoreOptions| {
                    options.max_active_index_bytes = crate::index::encoded_bytes_for(1, 1)
                }),
            ),
        ] {
            let directory = TempDir::new().unwrap();
            let (mut options, lock) = layout(&directory);
            adjust(&mut options);
            let (staging, _session, _marker, install) =
                sealed(&directory, &lock, options, [68; 16]);
            assert_eq!(
                install.object_count, 2,
                "the fixture must exceed a ceiling of one, or this asserts nothing"
            );

            let refused = staging
                .resolve_committed(NamespaceId::from(ObjectId([7; 32])), &install, 9)
                .expect_err("a projection over the active-index ceiling must not resolve");
            match refused {
                StoreError::LimitExceeded { limit: named, .. } => assert_eq!(
                    named, limit,
                    "the refusal must name the ceiling that stopped it"
                ),
                other => panic!("expected {limit}, got {other:?}"),
            }
        }
    }

    /// A swapped chunk of the same shape must not resolve.
    ///
    /// Shape is not identity. A replacement chunk carrying the same session ID,
    /// ordinal, chunk count and object count satisfies every structural check a
    /// resolution can make, and carries entirely different objects — so a
    /// resolution that verified the descriptor against its own cached sealed
    /// state, rather than against the bytes it just read, would index the
    /// impostor's objects under a committed frame that never named them. That is
    /// what this resolution did before review caught it.
    #[test]
    fn a_chunk_swapped_for_another_of_the_same_shape_is_refused() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let (staging, _session, marker, install) = sealed(&directory, &lock, options, [66; 16]);
        let session_directory = marker.parent().expect("session directory").to_path_buf();
        let namespace = NamespaceId::from(ObjectId([7; 32]));

        let chunk_path = session_files(&session_directory)
            .into_iter()
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| parse_chunk_artifact_name(name).is_some())
            })
            .expect("a chunk artifact");

        // A chunk claiming this session's identity: same session ID, same
        // ordinal, same chunk count, same object count. Only the object bytes
        // differ, which is exactly the difference no structural check can see.
        //
        // Built inline rather than from `sealable`, because that fixture derives
        // object bodies from the index alone — a second session produces
        // byte-identical objects, and an "impostor" equal to the original tests
        // nothing at all.
        use levcs_protocol::v2::StagedChunkObjectV1;
        let mut objects: Vec<StagedChunkObjectV1> = (0..2u8)
            .map(|index| {
                let body = [index.wrapping_add(0x80); 24];
                let mut raw = levcs_core::ObjectHeader {
                    object_type: levcs_core::ObjectType::Blob,
                    format_version: levcs_core::FORMAT_VERSION,
                    body_len: body.len() as u64,
                }
                .encode()
                .to_vec();
                raw.extend_from_slice(&body);
                let id = levcs_core::blake3_hash(&raw);
                StagedChunkObjectV1 {
                    descriptor: StagedObjectV1 {
                        object_id: id,
                        object_type: levcs_core::ObjectType::Blob as u8,
                        raw_len: raw.len() as u64,
                        raw_digest: id,
                    },
                    raw_bytes: raw,
                }
            })
            .collect();
        objects.sort_by(|left, right| left.descriptor.cmp(&right.descriptor));
        let impostor = ProjectionStageChunkV1 {
            session_id: [66; 16],
            ordinal: 0,
            chunk_count: 1,
            objects,
        };
        assert_ne!(
            impostor.chunk_digest().expect("digest"),
            ProjectionStageChunkV1::decode_canonical(
                &read_staging_artifact(&chunk_path, StagingArtifactKind::Chunk, [66; 16])
                    .expect("read the original")
            )
            .expect("decode")
            .chunk_digest()
            .expect("digest"),
            "the replacement must actually differ, or this test proves nothing"
        );
        let bytes = encode_staging_artifact(
            StagingArtifactKind::Chunk,
            [66; 16],
            &impostor.encode_canonical().expect("encode"),
        );
        std::fs::write(&chunk_path, &bytes).expect("swap the chunk");

        let refused = staging
            .resolve_committed(namespace, &install, 9)
            .expect_err("a chunk of the right shape but the wrong content must not resolve");
        let StoreError::Corruption(detail) = refused else {
            panic!("expected a named corruption, got {refused:?}");
        };
        assert!(
            detail.contains("is not the one this projection committed")
                || detail.contains("does not match the digest its manifest binds"),
            "the refusal must name the digest mismatch rather than some incidental \
             difference: {detail}"
        );
    }

    /// The two answers recovery can bring back, and both are idempotent.
    ///
    /// `Committed` ends a transferred pin as an adoption at the position the
    /// resolution established. `ProvedAbsent` means recovery read the complete
    /// authoritative history and no frame names these artifacts — they are
    /// synced-but-unreferenced garbage, which is what the deliverable says
    /// recovery treats as invisible, so the session goes.
    #[test]
    fn recovery_notifications_end_a_transferred_pin_either_way() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let namespace = NamespaceId::from(ObjectId([7; 32]));

        // Committed.
        {
            let (staging, session, _marker, install) =
                sealed(&directory, &lock, options.clone(), [64; 16]);
            session
                .finalize(0)
                .expect("pin")
                .handle
                .finish(ProjectionAdoptionOutcome::TransferredToRecovery)
                .expect("transfer");
            staging
                .resolve_committed(namespace, &install, 11)
                .expect("resolve");
            for _ in 0..2 {
                staging
                    .notify_recovered(RecoveredProjectionResolution {
                        session_id: [64; 16],
                        outcome: RecoveredProjectionOutcome::Committed,
                    })
                    .expect("notification is repeated when a later one fails, so it repeats");
            }
            assert_eq!(
                describe_state(&staging, [64; 16]),
                StagedSessionState::Adopted
            );
            // The position the resolution established is what cleanup will later
            // measure a root against.
            assert_eq!(
                staging
                    .cleanup_unreferenced(&root_at(&[], 10))
                    .expect("cleanup"),
                0,
                "a root short of the adoption is not evidence"
            );
        }

        // Proved absent.
        {
            let (staging, session, marker, _install) = sealed(&directory, &lock, options, [65; 16]);
            let session_directory = marker.parent().expect("session directory").to_path_buf();
            session
                .finalize(0)
                .expect("pin")
                .handle
                .finish(ProjectionAdoptionOutcome::TransferredToRecovery)
                .expect("transfer");
            for _ in 0..2 {
                staging
                    .notify_recovered(RecoveredProjectionResolution {
                        session_id: [65; 16],
                        outcome: RecoveredProjectionOutcome::ProvedAbsent,
                    })
                    .expect("idempotent");
            }
            assert!(
                !session_directory.exists(),
                "artifacts no complete frame names are invisible garbage and are reclaimed"
            );
        }
    }

    /// The generation mapping is injective and stays inside its band.
    ///
    /// Injectivity is the requirement a multi-chunk session imposes: one file per
    /// chunk, and the root validator refuses two projection files at one
    /// generation, so deriving from the adoption's frame sequence alone would
    /// make every multi-chunk adoption fail to open. Disjointness from segments
    /// and tails is the other half — they share one generation space, and a
    /// collision there is a `Corruption` at open rather than a silent
    /// misresolution, but only because something refuses it.
    #[test]
    fn projection_generations_are_injective_and_stay_in_their_band() {
        let session = [61; 16];
        let mut seen = std::collections::BTreeSet::new();
        for sequence in [0u64, 1, 2, 4095, 1 << 32] {
            for ordinal in [0u32, 1, 2, 999_999] {
                let generation =
                    projection_generation(sequence, ordinal, session).expect("in range");
                assert!(
                    generation >= PROJECTION_GENERATION_BAND,
                    "generation {generation} escaped the band reserved against segment and \
                     tail generations"
                );
                assert!(
                    seen.insert(generation),
                    "({sequence}, {ordinal}) collided with an earlier pair; two projection \
                     files at one generation make the root unopenable"
                );
            }
        }

        // Stability is the other property a sealed run depends on: the same pair
        // must map to the same number in a later session.
        assert_eq!(
            projection_generation(7, 3, session).expect("in range"),
            projection_generation(7, 3, session).expect("in range"),
        );

        // And the mapping refuses rather than aliases when either input leaves
        // the range it can distinguish.
        assert!(projection_generation(0, 1 << PROJECTION_ORDINAL_BITS, session).is_err());
        assert!(projection_generation(u64::MAX, 0, session).is_err());
        assert!(projection_generation(1 << 40, 0, session).is_err());
    }

    /// The sequence boundary is one value wide, and a shift check cannot see it.
    ///
    /// `1 << 39` shifts left by the ordinal width onto the band bit itself. It
    /// loses no bits, so a round-trip check accepts it — and then OR-ing the band
    /// is a no-op, so it lands on exactly the generation sequence 0 produces at
    /// the same ordinal. Two adopted projections at one generation make the root
    /// unopenable, and this is the one input that reaches that state through a
    /// check designed to prevent it.
    ///
    /// My first version tested `1 << 40` and believed it covered this. It does
    /// not: that value fails because bits shift off the top, which is a different
    /// mechanism reached from the far side of the boundary. An out-of-range case
    /// is not a boundary case.
    #[test]
    fn the_sequence_boundary_refuses_the_value_that_would_alias_sequence_zero() {
        let session = [62; 16];
        let boundary = 1u64 << (63 - PROJECTION_ORDINAL_BITS);

        for ordinal in [0u32, 1, 999_999] {
            assert!(
                projection_generation(boundary, ordinal, session).is_err(),
                "sequence {boundary} shifts onto the band bit and aliases sequence 0"
            );
            let below = projection_generation(boundary - 1, ordinal, session)
                .expect("the value below the boundary is still representable");
            let zero = projection_generation(0, ordinal, session).expect("sequence zero");
            assert_ne!(
                below, zero,
                "the last representable sequence must not alias sequence 0 either"
            );
            assert!(below >= PROJECTION_GENERATION_BAND);
        }
    }

    /// The zero boundary: `Some(0)` is evidence and `None` is not.
    ///
    /// Zero is a valid committed shard sequence — a shard that has committed its
    /// first frame and nothing since — so a root recording `Some(0)` for the
    /// shard has genuinely reached an adoption at zero. A root recording nothing
    /// for that shard has not said anything at all, and reading it as zero is how
    /// the position check quietly stops being a check for exactly the adoption
    /// that needs it most: the earliest one.
    ///
    /// Both halves are asserted against one session, because the failure this
    /// guards is the two answers becoming the same. A test that only checked the
    /// absent case would also pass against a cleanup that declined every root.
    #[test]
    fn an_adoption_at_sequence_zero_needs_a_root_that_says_so() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let (staging, session, marker, _install) = sealed(&directory, &lock, options, [54; 16]);
        let session_directory = marker.parent().expect("session directory").to_path_buf();

        session
            .finalize(0)
            .expect("pin")
            .handle
            .finish(ProjectionAdoptionOutcome::Adopted {
                committed_shard_sequence: 0,
            })
            .expect("adopt");

        assert_eq!(
            staging
                .cleanup_unreferenced(&root_without_sequences(&[]))
                .expect("cleanup"),
            0,
            "a root holding no sequence for this shard is silent about it, not a witness \
             that it has committed through zero"
        );
        assert!(session_directory.exists());
        assert_eq!(
            staging.counters().snapshot().cleanup_declined_stale_root,
            1,
            "and the decline must be the position check, not a referenced artifact"
        );

        assert_eq!(
            staging
                .cleanup_unreferenced(&root_at(&[], 0))
                .expect("cleanup"),
            1,
            "an explicit zero has reached an adoption at zero, so the same session is \
             reclaimable and the decline above was about the absence and not the value"
        );
        assert!(!session_directory.exists());
    }

    /// Cleanup is for adopted sessions and nothing else.
    ///
    /// A sealed session and a pinned one are both unreferenced by any root —
    /// nothing has adopted them — so a cleanup that proved absence of reference
    /// and stopped there would delete a session a client is still uploading to,
    /// and one whose adoption frame may be mid-append. The reference proof is
    /// necessary and is not sufficient.
    #[test]
    fn cleanup_leaves_live_and_pinned_sessions_alone() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let (staging, session, marker, _install) =
            sealed(&directory, &lock, options.clone(), [52; 16]);
        let sealed_directory = marker.parent().expect("session directory").to_path_buf();

        let empty = root_referencing(&[]);
        assert_eq!(
            staging.cleanup_unreferenced(&empty).expect("cleanup runs"),
            0,
            "a sealed session is expiry's and abort's, not cleanup's"
        );
        assert!(sealed_directory.exists());

        let adoption = session.finalize(0).expect("pin");
        assert_eq!(
            staging.cleanup_unreferenced(&empty).expect("cleanup runs"),
            0,
            "a pinned session has no absence to prove: the frame naming its artifacts may \
             be mid-append"
        );
        assert!(sealed_directory.exists());
        assert_eq!(
            describe_state(&staging, [52; 16]),
            StagedSessionState::Finalizing
        );
        adoption
            .handle
            .finish(ProjectionAdoptionOutcome::DefinitivePreAppendFailure)
            .expect("release");
    }

    fn describe_state(
        staging: &Arc<ProjectionStaging>,
        session_id: [u8; 16],
    ) -> StagedSessionState {
        staging
            .session(session_id)
            .expect("the session is known")
            .describe()
            .expect("describe")
            .state
    }

    #[test]
    fn cross_device_staging_is_refused_at_session_creation() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let staging_root = directory.path().join(STAGING_DIR);
        let shard = StoreOptions::shard_of(&NamespaceId([7; 32]), options.shard_count);
        let shard_directory = directory.path().join("shards").join(format!("{shard:02}"));

        let staging = ProjectionStaging::open_with_device_probe(
            &lock,
            options,
            Arc::new(DurabilityCounters::default()),
            Box::new(FixedDeviceProbe {
                devices: BTreeMap::from([(staging_root, 64), (shard_directory, 65)]),
            }),
        )
        .expect("staging opens");

        let result = staging.begin(binding([1; 16], HOUR_MICROS), 0);
        let Err(StoreError::InvalidConfiguration(message)) = result else {
            panic!("a cross-device session must be refused, got {result:?}");
        };
        assert!(
            message.contains("link across devices"),
            "the refusal must say why a copy fallback is not an option: {message}"
        );

        // Refused before pinning: no budget charged and no session directory.
        let counters = staging.counters().snapshot();
        assert_eq!(counters.sessions_live, 0);
        assert_eq!(counters.reserved_bytes, 0);
        assert_eq!(counters.compaction_debt_reserved_bytes, 0);
        assert_eq!(counters.sessions_refused, 1);
        assert!(!directory
            .path()
            .join(STAGING_DIR)
            .join(format!("{shard:02}"))
            .exists());
    }

    #[test]
    fn same_device_staging_is_admitted_through_the_production_probe() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let staging =
            ProjectionStaging::open(&lock, options, Arc::new(DurabilityCounters::default()))
                .expect("staging opens");
        staging
            .begin(binding([2; 16], HOUR_MICROS), 0)
            .expect("a same-device session is admitted by the real st_dev probe");
    }

    #[test]
    fn the_production_device_probe_reports_the_real_st_dev() {
        // The substituted probe is only honest if the real one means exactly
        // this. Without this assertion the cross-device test could pass while
        // production compared something else entirely.
        let directory = TempDir::new().unwrap();
        let probe = StatDeviceProbe;
        let observed = probe.device_of(directory.path()).expect("probe");
        let expected = std::fs::metadata(directory.path()).unwrap().dev();
        assert_eq!(observed, expected);
    }

    #[test]
    fn a_foreign_or_tampered_file_carries_no_session_marker() {
        let directory = TempDir::new().unwrap();
        let session_id = [21u8; 16];
        let encoded =
            encode_staging_artifact(StagingArtifactKind::Chunk, session_id, b"payload bytes");

        let good = directory.path().join("good");
        std::fs::write(&good, &encoded).unwrap();
        assert_eq!(artifact_session_marker(&good).unwrap(), Some(session_id));
        assert_eq!(
            read_staging_artifact(&good, StagingArtifactKind::Chunk, session_id).unwrap(),
            b"payload bytes"
        );

        // A file that is not ours at all.
        let foreign = directory.path().join("foreign");
        std::fs::write(&foreign, b"not a staging artifact").unwrap();
        assert_eq!(artifact_session_marker(&foreign).unwrap(), None);

        // One flipped payload byte breaks the trailer digest, so the marker is
        // gone rather than merely suspect. Reclamation must not delete a file
        // it cannot prove it owns.
        let mut tampered = encoded.clone();
        let last_payload = STAGING_ARTIFACT_HEADER_LEN;
        tampered[last_payload] ^= 0xff;
        let tampered_path = directory.path().join("tampered");
        std::fs::write(&tampered_path, &tampered).unwrap();
        assert_eq!(artifact_session_marker(&tampered_path).unwrap(), None);

        // A valid artifact belonging to another session is refused by kind or
        // session, not accepted because it parsed.
        let other = read_staging_artifact(&good, StagingArtifactKind::Manifest, session_id);
        let Err(StoreError::Corruption(message)) = other else {
            panic!("a kind mismatch must be refused, got {other:?}");
        };
        assert!(message.contains("different kind or session"));
    }

    /// Reconstruction reads a chunk's ordinal and digest out of its *name*
    /// and then checks the file against them, so the name parser has to be
    /// the exact inverse of the name builder. If it were not, a reopen would
    /// either drop durable chunks (name unrecognized) or accept a file under
    /// an ordinal it was never stored at.
    #[test]
    fn the_chunk_artifact_name_round_trips_and_rejects_everything_else() {
        let digest = ObjectId([9; 32]);
        let name = chunk_artifact_name(4_294_967_295, &digest);
        assert_eq!(
            parse_chunk_artifact_name(&name),
            Some((4_294_967_295, digest))
        );
        assert_eq!(parse_chunk_artifact_name("chunk-0000000000"), None);
        assert_eq!(parse_chunk_artifact_name("chunk-4-abc"), None);
        assert_eq!(parse_chunk_artifact_name(SESSION_RECORD_NAME), None);
        assert_eq!(parse_chunk_artifact_name(MANIFEST_NAME), None);
        assert_eq!(parse_chunk_artifact_name(&format!("{name}.tmp")), None);
        assert!(is_session_artifact_name(&name));
        assert!(is_session_artifact_name(SESSION_RECORD_NAME));
        assert!(is_session_artifact_name(MANIFEST_NAME));
        assert!(is_session_artifact_name(ADOPTION_NAME));
        assert!(!is_session_artifact_name("not-ours"));
    }

    /// An unsealed session has no descriptor, so there is nothing to pin.
    ///
    /// The first thing `finalize` must not do is issue a capability against a
    /// session that has not reached its own commit point: the manifest is what
    /// an adopter revalidates against, and a pin without one is an adoption
    /// capability naming state that does not exist.
    #[test]
    fn an_unsealed_session_cannot_be_finalized() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let staging =
            ProjectionStaging::open(&lock, options, Arc::new(DurabilityCounters::default()))
                .expect("staging opens");
        let session = staging
            .begin(binding([3; 16], HOUR_MICROS), 0)
            .expect("session");
        let Err(StoreError::Conflict(detail)) = session.finalize(0) else {
            panic!("finalizing an open session must be refused, not defaulted");
        };
        assert!(detail.contains("has not sealed"), "{detail}");
        assert_eq!(
            staging.counters().snapshot().sessions_finalized,
            0,
            "a refused finalize must not count as one"
        );
    }

    #[test]
    fn the_recovery_resolver_seam_answers_rather_than_deferring() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let staging =
            ProjectionStaging::open(&lock, options, Arc::new(DurabilityCounters::default()))
                .expect("staging opens");

        // `transferred_sessions` *is* answered, and answers emptily here for the
        // reason it always did: a session that has not been finalized has no pin
        // to transfer. Deliverable 6 made the non-empty answer reachable — see
        // `a_transferred_pin_reconstructs_and_is_offered_to_recovery` — so this
        // asserts the negative case rather than an impossibility. The proof that
        // it is derived and not a constant is the exhaustive state match it is
        // computed from.
        let session = staging
            .begin(binding([9; 16], HOUR_MICROS), 0)
            .expect("session");
        let shard = StoreOptions::shard_of(&NamespaceId([7; 32]), 4);
        assert!(staging.transferred_sessions(shard).unwrap().is_empty());
        drop(session);

        // Both methods answer now, and both refuse a session this root does not
        // hold rather than inventing one. `Corruption` and not `NotImplemented`:
        // a descriptor naming an unknown session means a committed frame
        // published objects whose artifacts are not here, which is a fault about
        // the store rather than about this build.
        let resolved = staging.resolve_committed(
            NamespaceId([1; 32]),
            &StagedProjectionInstallV1 {
                session_id: [4; 16],
                manifest_digest: ObjectId([5; 32]),
                projection: ProjectionMode::Full,
                object_count: 1,
                object_bytes: 1,
                membership_root: ObjectId([6; 32]),
                artifact_set_digest: ObjectId([7; 32]),
            },
            3,
        );
        let Err(StoreError::Corruption(detail)) = resolved else {
            panic!("resolving an unheld session must be a named fault");
        };
        assert!(detail.contains("this root does not hold"), "{detail}");

        // Notification is idempotent, and a session this root does not hold is
        // the terminal case of that: recovery repeats every notification on the
        // next attempt, so "already gone" has to be success rather than a
        // conflict that would keep the shard unready forever.
        staging
            .notify_recovered(RecoveredProjectionResolution {
                session_id: [4; 16],
                outcome: RecoveredProjectionOutcome::Committed,
            })
            .expect("notifying an unheld session is a no-op, not a fault");
        staging
            .notify_recovered(RecoveredProjectionResolution {
                session_id: [4; 16],
                outcome: RecoveredProjectionOutcome::ProvedAbsent,
            })
            .expect("and so is proving one absent");
    }
}
