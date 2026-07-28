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

use crate::index::{IndexDelta, IndexRun};
use crate::roots::{CommittedRoot, RetainedIndexRun, RetainedProjectionArtifact};
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
    Adopted,
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
    fn resolve_committed(
        &self,
        namespace: NamespaceId,
        descriptor: &StagedProjectionInstallV1,
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

/// Files a session may create: one per chunk, plus the session record and the
/// sealed manifest. `options.rs` validates `staging_max_files_per_session >=
/// max_projection_chunks + 2` against exactly this layout, so the constant is
/// the shared definition of that `+ 2` rather than a second opinion about it.
const SESSION_FIXED_FILES: u64 = 2;

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

/// The two states a session can hold in this pass.
///
/// Deliverable 6 adds `Finalizing`, which is the state that holds an adoption
/// pin. Expiry and abort match this exhaustively rather than defaulting, so
/// adding that variant will fail to compile at exactly the sites that must
/// learn about a pin instead of silently reclaiming a pinned session.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StagedSessionState {
    Open,
    Sealed,
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
        // presence — not a flag — is what makes the session `Sealed` again.
        let (state, resolution) = match sealed_manifest {
            None => (StagedSessionState::Open, None),
            Some(path) => {
                let resolution =
                    self.reconstruct_resolution(&path, &binding, session_id, &chunks)?;
                (StagedSessionState::Sealed, Some(resolution))
            }
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
                    // A sealing session is mid-maintenance; the next sweep
                    // takes it. Deliverable 6 replaces this with the pinned
                    // case, which expiry may never reclaim at all.
                    SessionBusy::Sealing | SessionBusy::Reclaiming => false,
                };
                past_expiry
                    && idle
                    && match record.state {
                        StagedSessionState::Open | StagedSessionState::Sealed => true,
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

    /// Remove artifacts no committed manifest references.
    ///
    /// Deferred: deliverable 7. The proof this owes is answered against a
    /// `CommittedRoot`, and the state it must be able to observe — an adopted
    /// session — cannot exist until deliverable 6 and B1's `adopt_projection`
    /// land. A version that reclaimed everything unreferenced today would be
    /// correct today and would silently become a reclamation of adopted
    /// artifacts the moment adoption started working.
    pub fn cleanup_unreferenced(&self, _root: &CommittedRoot) -> Result<u64, StoreError> {
        Err(StoreError::NotImplemented(
            "ProjectionStaging::cleanup_unreferenced — B3 StagingSessions, scope 6.5 \
             deliverable 7 (reference proof against a CommittedRoot)",
        ))
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
            }
            match record.busy {
                SessionBusy::Idle => {}
                SessionBusy::Sealing | SessionBusy::Reclaiming => {
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
            StagedSessionState::Sealed => {}
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

    /// Move `Open -> Finalizing` for the sole bound operation/digest and take
    /// the adoption pin.
    ///
    /// Deferred: deliverable 6. This is where the `ProjectionAdoptionLifecycle`
    /// implementation lands, and it is the live B1/B3 seam — the pin has to
    /// survive a definitive pre-append failure, an expiry racing an admitted
    /// finalizer, and a transfer to recovery, and none of those can be tested
    /// against a `submit` that does not exist yet. A placeholder that returned
    /// a handle would hand out an adoption capability with no pin behind it,
    /// which is precisely the security property this package exists to hold.
    #[allow(dead_code)] // B1's `adopt_projection` is the only legitimate caller.
    pub(crate) fn finalize(
        &self,
        _now_micros: i64,
    ) -> Result<StagedProjectionAdoption, StoreError> {
        Err(StoreError::NotImplemented(
            "ProjectionStageSession::finalize — B3 StagingSessions, scope 6.5 deliverable 6 \
             (finalize and the adoption pin)",
        ))
    }
}

/// Deliverable 8, one method answered and two still deferred.
///
/// The seam is implemented rather than absent so recovery's dependency on
/// staging is visible at the type level: a store that recovers a committed
/// staged install without resolving it would publish membership for objects it
/// cannot locate. The two deferred methods name the deliverable rather than
/// returning an empty result, because "nothing to resolve" and "cannot answer
/// yet" are different answers and only one of them is true.
impl ProjectionRecoveryResolver for ProjectionStaging {
    /// The transferred set, **derived rather than asserted, and provably empty
    /// today.**
    ///
    /// A pin transfers to recovery only from `Finalizing`, and `Finalizing` is
    /// deliverable 6: `finalize` returns `NotImplemented`, so no session has
    /// ever entered that state, and — now that reconstruction exists — the only
    /// states a durable session directory can come back in are `Open` and
    /// `Sealed`. The empty answer is therefore a proof about the reachable
    /// state space, not the "no transferred sessions" guess the deferred
    /// version would have been making.
    ///
    /// It is computed by an exhaustive match over the state rather than
    /// returned as a constant, so adding `Finalizing` fails to compile here —
    /// at the one place that must learn a pin can now outlive the process —
    /// instead of silently continuing to answer "none".
    fn transferred_sessions(&self, shard_index: u16) -> Result<Arc<[[u8; 16]]>, StoreError> {
        let registry = self.lock();
        let transferred: Vec<[u8; 16]> = registry
            .sessions
            .iter()
            .filter(|(_, record)| record.shard_index == shard_index)
            .filter(|(_, record)| match record.state {
                StagedSessionState::Open | StagedSessionState::Sealed => false,
            })
            .map(|(session_id, _)| *session_id)
            .collect();
        Ok(Arc::from(transferred))
    }

    fn resolve_committed(
        &self,
        _namespace: NamespaceId,
        _descriptor: &StagedProjectionInstallV1,
    ) -> Result<RecoveredProjectionArtifacts, StoreError> {
        Err(StoreError::NotImplemented(
            "ProjectionStaging::resolve_committed — B3 StagingSessions, scope 6.5 \
             deliverable 8 (recovery treatment of unreferenced artifacts)",
        ))
    }

    fn notify_recovered(
        &self,
        _resolution: RecoveredProjectionResolution,
    ) -> Result<(), StoreError> {
        Err(StoreError::NotImplemented(
            "ProjectionStaging::notify_recovered — B3 StagingSessions, scope 6.5 \
             deliverable 8 (recovery treatment of unreferenced artifacts)",
        ))
    }
}

// --- free helpers ---------------------------------------------------------

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
        StagedSessionState::Sealed => Err(StoreError::Conflict(format!(
            "staging session {} is sealed and immutable",
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
            ProjectionAdoptionOutcome::Adopted,
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
            .resolve_committed(NamespaceId([24; 32]), &install())
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
        assert!(!is_session_artifact_name("not-ours"));
    }

    #[test]
    fn finalize_is_deferred_and_names_its_deliverable() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let staging =
            ProjectionStaging::open(&lock, options, Arc::new(DurabilityCounters::default()))
                .expect("staging opens");
        let session = staging
            .begin(binding([3; 16], HOUR_MICROS), 0)
            .expect("session");
        let result = session.finalize(0);
        let Err(StoreError::NotImplemented(detail)) = result else {
            panic!("finalize must be an explicit stub, not a plausible default");
        };
        assert!(detail.contains("deliverable 6"), "{detail}");
    }

    #[test]
    fn the_recovery_resolver_seam_is_deferred_and_names_its_deliverable() {
        let directory = TempDir::new().unwrap();
        let (options, lock) = layout(&directory);
        let staging =
            ProjectionStaging::open(&lock, options, Arc::new(DurabilityCounters::default()))
                .expect("staging opens");

        // `transferred_sessions` *is* answered: no session can reach the
        // transferred state until deliverable 6 exists, and a sealed session
        // is not a transferred one. The proof that this is derived and not a
        // constant is the exhaustive state match it is computed from.
        let session = staging
            .begin(binding([9; 16], HOUR_MICROS), 0)
            .expect("session");
        let shard = StoreOptions::shard_of(&NamespaceId([7; 32]), 4);
        assert!(staging.transferred_sessions(shard).unwrap().is_empty());
        drop(session);

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
        );
        let Err(StoreError::NotImplemented(detail)) = resolved else {
            panic!("resolve_committed must not answer before deliverable 8");
        };
        assert!(detail.contains("deliverable 8"), "{detail}");

        let notified = staging.notify_recovered(RecoveredProjectionResolution {
            session_id: [4; 16],
            outcome: RecoveredProjectionOutcome::Committed,
        });
        let Err(StoreError::NotImplemented(detail)) = notified else {
            panic!("notify_recovered must not silently succeed");
        };
        assert!(detail.contains("deliverable 8"), "{detail}");
    }
}
