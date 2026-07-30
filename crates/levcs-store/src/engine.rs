//! `StoreEngine`: shard routing, startup and recovery, lifecycle, and the
//! `ArcSwap` committed/status roots.
//!
//! **Shared file.** Lead owns the signatures (D0); **B1 NamespaceTxn** fills
//! the bodies (scope 2.1, 6-B1). Same pattern as `format.rs` and `drive.rs`:
//! the public API must compile in D0 so A3 can write against real signatures
//! in Wave A rather than retrofitting them in Wave B.
//!
//! # What is implemented here and what is not
//!
//! This is the first vertical slice: one retained [`RecoverySession`] across
//! every shard, one shard writer per shard wired
//! `GroupBuilder` -> `append_group_and_fence` -> [`ShardSubtree`] -> committed
//! root CAS -> completion, and the publication ordering of scope 6.3. Startup
//! states 1 and 2 are implemented — an absent or empty root is initialized
//! under the root lock, and a valid `FORMAT` opens through production
//! recovery. States 3 and 4, the signer pool and its suffix repair,
//! coalescing, terminal
//! retention, rotation/sealing, and `RepoSnapshot` are later B1 assignments
//! and refuse with a [`StoreError::NotImplemented`] naming themselves. None of
//! them returns a partial result or a plausible default; a caller that reaches
//! one gets told which deliverable it is waiting on.
//!
//! # The ordering that matters most in this file
//!
//! Scope 6.3 steps 7, 8, and 9, in that order and never another. The committed
//! root is published first, the status entries are removed second, and waiters
//! are woken third. Removing a status entry before the receipt is visible
//! manufactures `Unknown` for a transaction that is already durable — the
//! exact race the mandatory committed-root B read exists to close, reintroduced
//! from the write side where no read can fix it. Waking before publication
//! would let a caller act on a receipt no other reader can see yet.

use std::collections::BTreeMap;
use std::sync::atomic::{fence, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use crossbeam_channel::{Receiver, RecvTimeoutError, Sender, TrySendError};
use im::Vector;
use levcs_core::{ObjectId, ObjectType};
use levcs_protocol::oracle::{self, AppendDeadlinePhase, DeadlineDecision};
use levcs_protocol::v2::{
    self as protocol, AppliedRefV1, CommittedTransactionV1, DurabilityResultV1, RefMutation,
    RefStateV1, SignedCommittedTransactionV1,
};

use crate::checkpoint::{ReceiptRecord, RefRecord};
use crate::completion::SharedCompletion;
use crate::failpoints::{self, Failpoint, FailpointAction};
use crate::format::{
    frame_total_len, object_type_code, Frame, FrameHeader, FrameObjectV1, FrameObjectsV1,
    FrameReceiptFieldsV1, RepositoryCreateV1, TransactionFramePayloadV1,
};
use crate::index::{
    delta_pressure, DeltaPressure, IndexDelta, IndexKey, IndexLocation, IndexRun, IndexRunBuilder,
    NamespaceLifecycle, NamespaceRecord, NamespaceStorageMode,
};
use crate::journal::{GroupBuilder, Journal};
use crate::options::StoreOptions;
use crate::recovery::{RecoveredShard, RecoveryConfig, RecoverySession};
use crate::roots::{
    CommittedRoot, GenerationId, GenerationMap, LayeredObjectIndex, OperationKey,
    OperationStatusMetricSnapshot, OperationStatusMetrics, OperationStatusRoot, RepoMap, RepoState,
    RetainedGeneration, RetainedIndexRun, RetainedReceipt, ShardSequenceMap, ShardSubtree,
    StatusEntry, StatusReservation, TerminalStatusEntry, TerminalStatusMap, TypedRefMap,
};
use crate::segment::{self, RootLayout};
use crate::snapshot::RepoSnapshot;
use crate::staging::ProjectionStaging;
use crate::transaction::ValidatedTransaction;
use crate::types::{
    CommitEvidenceSigner, CommitReceipt, DurabilityCounterSnapshot, DurabilityCounters,
    NamespaceId, OperationId, PendingPhase, StoreError, TransactionStatus,
};

/// The durable transaction service.
///
/// Owns one `ArcSwap<CommittedRoot>` and one bounded
/// `ArcSwap<OperationStatusRoot>`; neither uses `RwLock<Arc<_>>` (plan §5.1).
/// The committed-root swap is the visibility boundary.
pub struct StoreEngine {
    shared: Arc<EngineShared>,
    shards: Vec<ShardHandle>,
}

/// A held checkpoint export lease. Pins the referenced generation's segments,
/// indexes, and checkpoints against reclamation until dropped.
pub struct CheckpointLease {
    _private: (),
}

impl std::fmt::Debug for StoreEngine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoreEngine")
            .field("root", &self.shared.options.root)
            .field("shard_count", &self.shared.shard_count)
            .finish_non_exhaustive()
    }
}

/// Everything a shard writer and a reader share.
///
/// The [`RecoverySession`] is in here rather than in `StoreEngine` for one
/// reason: it holds the root-wide `LOCK`, and it must stay held for exactly as
/// long as anything in this process can write to the root. Tying its lifetime
/// to the shared state rather than to the handle makes "the lock outlives every
/// writer" a fact about ownership instead of a rule about drop order.
struct EngineShared {
    options: StoreOptions,
    signer: Arc<dyn CommitEvidenceSigner>,
    shard_count: u16,
    root_uuid: [u8; 16],
    committed: ArcSwap<CommittedRoot>,
    status: ArcSwap<OperationStatusRoot>,
    status_metrics: OperationStatusMetrics,
    /// The one `ProjectionStaging` for this root.
    ///
    /// Constructed exactly once, by [`StoreEngine::open`], under the already
    /// held [`RecoverySession`], and kept alive for exactly as long as that
    /// session holds `LOCK`. Staging's ceilings are root-global, and a second
    /// handle built outside the lock would carry its own independent accounting
    /// — two handles, or two processes, each admitting up to the full global
    /// limit. Ownership here is what makes "root-global" true rather than
    /// asserted.
    _staging: Arc<ProjectionStaging>,
    _session: RecoverySession,
    /// What startup state 1 actually cost, or `None` when this open did not
    /// initialize.
    ///
    /// Charter item 7: "state 1 created the tree and fsynced it" is otherwise
    /// a claim about [`initialize_root_state_1`] rather than an observation. A
    /// test that opens an absent root can read the directory fsyncs the
    /// initialization performed instead of inferring them from the tree it
    /// left behind — and, just as importantly, an open of state 2 can assert
    /// this is `None`, which is the only direct evidence that reopening a
    /// formatted root writes nothing.
    ///
    /// `#[cfg(test)]` because exposing it is a frozen-surface change; see the
    /// interface request in this deliverable's report.
    #[cfg(test)]
    initialization: Option<DurabilityCounterSnapshot>,
    /// What recovery concluded about each shard during this open, in shard
    /// order.
    ///
    /// The engine consumes these reports and keeps only their effects, which
    /// is right for production and leaves nothing to compare against the drive
    /// seam — `DriveRecovery` retains its report precisely so the two can be
    /// compared, and the engine side had no counterpart. `#[cfg(test)]` for
    /// the same reason as [`EngineShared::initialization`].
    #[cfg(test)]
    recovery_reports: Vec<crate::recovery::ShardRecoveryReport>,
    /// Observed committed-root CAS contention.
    ///
    /// Charter item 7: the re-merge path is otherwise only reachable as a race,
    /// so a test that claims to have exercised it has to be able to count it.
    #[cfg(test)]
    root_cas_retries: std::sync::atomic::AtomicU64,
}

struct ShardHandle {
    /// `Option` so `Drop` can close the channel before joining. A shard thread
    /// exits on disconnect, so dropping the sender is the shutdown signal.
    submissions: Option<Sender<Submission>>,
    thread: Option<JoinHandle<()>>,
    /// **Not reachable from outside the crate yet.** The counters are the only
    /// witness for "one fence per group", and B4's harness will need them
    /// through the public API; adding a public accessor is a frozen-surface
    /// change and therefore an interface request, not an edit. In-crate tests
    /// read them today.
    #[cfg_attr(not(test), allow(dead_code))]
    counters: Arc<DurabilityCounters>,
}

struct Submission {
    transaction: ValidatedTransaction,
    completion: SharedCompletion,
}

impl StoreEngine {
    /// Open or initialize a store root.
    ///
    /// Handles plan §5.2's four startup states explicitly and in order, with
    /// no inference: absent-or-empty initializes; a valid `FORMAT` opens
    /// through production recovery; a recognized non-empty legacy layout
    /// without `FORMAT` is refused with the exact `migrate-store` command; and
    /// every other non-empty unrecognized layout is refused without
    /// modification. It never infers legacy state merely from a missing
    /// marker.
    ///
    /// **This slice implements states 1 and 2**, including state 1's
    /// crash-resume shape: a root whose initialization was interrupted is
    /// recognized by the marker this path installs before it builds anything
    /// and is finished rather than refused
    /// ([`RootStartupState::InterruptedInitialization`]). States 3 and 4 are
    /// still refused by name below, after a read-only classification and before
    /// anything is written, so a caller cannot mistake "not built yet" for
    /// "your root is broken". See [`classify_root`] for why the classification
    /// itself creates nothing.
    ///
    /// Recovery runs through **one** [`RecoverySession`] for every shard, and
    /// that session then moves into the engine. `LOCK` is root-wide: taking
    /// and dropping one lock per shard would leave a window between two shard
    /// recoveries, and another between the last recovery and readiness, in
    /// which a second process could enter and invalidate the root this one is
    /// about to publish.
    pub fn open(options: StoreOptions) -> Result<Self, StoreError> {
        // Configuration is validated first: an invalid configuration must fail
        // startup regardless of what is on disk, and validating after touching
        // the root would make the refusal depend on the root's state.
        options.validate()?;

        // Hoisted above every root access on purpose. This used to run after
        // the `FORMAT` probe, which was harmless while state 1 refused — but
        // now that an absent root is *initialized*, a signerless configuration
        // reaching this point would have already created a tree, written
        // `FORMAT`, and fsynced the parent before failing. A configuration
        // error must not be able to leave a root behind.
        let signer = options.signer.clone().ok_or_else(|| {
            StoreError::InvalidConfiguration(
                "a CommitEvidenceSigner must be registered by instance composition before the \
                 engine can sequence a transaction"
                    .into(),
            )
        })?;

        let layout = RootLayout::new(&options.root);
        #[cfg_attr(not(test), allow(unused_variables))]
        let initialization =
            match classify_root(&layout)? {
                // Both reach the same code because they are the same state: a root
                // that has never finished initializing. The second one only carries
                // residue this code path wrote, and `initialize_root_state_1`
                // re-decides which it is under the lock before it writes anything.
                RootStartupState::AbsentOrEmpty | RootStartupState::InterruptedInitialization => {
                    Some(initialize_root_state_1(&layout, &options)?)
                }
                RootStartupState::Formatted => None,
                // States 3 and 4 share one refusal because telling them apart is
                // the legacy recognizer, and returning `UnrecognizedLayout` for a
                // root that is in fact a legacy instance would tell an operator
                // holding real data "refusing to modify" instead of the migration
                // command. Nothing here has written, probed, or inferred.
                RootStartupState::NonEmptyWithoutFormat => return Err(StoreError::NotImplemented(
                    "StoreEngine::open startup states 3 and 4 (LegacyLayout carrying the exact \
                     migrate-store command, UnrecognizedLayout) — B1 NamespaceTxn, scope 6-B1 \
                     deliverable 1. The root is non-empty and carries no FORMAT; it has not been \
                     modified",
                )),
            };

        let session = RecoverySession::open(&options.root)?;
        if session.shard_count() != options.shard_count {
            // Scope 2.5: the topology is frozen into FORMAT for the life of
            // the root. A silent reroute would move repositories between
            // shards, and per-repository sequence ownership is only sound
            // while a repository's shard assignment never moves.
            return Err(StoreError::FormatMismatch(format!(
                "root was initialized with {} shards but this process is configured for {}",
                session.shard_count(),
                options.shard_count
            )));
        }

        // The single `ProjectionStaging` for this root, built here and nowhere
        // else. It is constructed *after* the session has taken `LOCK` and
        // *before* any shard is recovered, because it is recovery's projection
        // resolver: a committed staged-install frame cannot become ready
        // without it, and a resolver constructed after recovery would be a
        // resolver recovery never had. It then lives in `EngineShared` for
        // exactly as long as the session does.
        let staging_durability = Arc::new(DurabilityCounters::default());
        let staging =
            ProjectionStaging::open(&session, options.clone(), Arc::clone(&staging_durability))?;

        let config = RecoveryConfig::from_store_options(&options)
            .with_projection_recovery_resolver(staging.as_ref());
        let mut recovered = Vec::with_capacity(session.shard_count() as usize);
        for shard in 0..session.shard_count() {
            recovered.push(session.recover_shard(shard, &config)?);
        }
        drop(config);

        // Scope 3.8 step 12. Readiness is a computed field of each shard's
        // report; a shard that is not ready is not a shard this engine may
        // publish a root from.
        for shard in &recovered {
            if !shard.report.ready {
                return Err(StoreError::RecoveryRequired);
            }
        }

        let root = initial_committed_root(&recovered)?;
        let shared = Arc::new(EngineShared {
            shard_count: session.shard_count(),
            root_uuid: session.root_uuid(),
            signer,
            committed: ArcSwap::from(Arc::new(root)),
            status: ArcSwap::from(Arc::new(OperationStatusRoot::new(
                options.max_status_entries,
            ))),
            status_metrics: OperationStatusMetrics::default(),
            options,
            _staging: staging,
            _session: session,
            #[cfg(test)]
            initialization,
            #[cfg(test)]
            recovery_reports: recovered.iter().map(|shard| shard.report.clone()).collect(),
            #[cfg(test)]
            root_cas_retries: std::sync::atomic::AtomicU64::new(0),
        });

        let mut shards = Vec::with_capacity(recovered.len());
        for shard in recovered {
            shards.push(spawn_shard_writer(Arc::clone(&shared), shard)?);
        }

        Ok(Self { shared, shards })
    }

    /// Acquire exactly one committed root and derive a repository view from
    /// it. Readers never observe an index entry newer than their captured
    /// root (plan §5.3).
    pub fn snapshot(&self, _repo: NamespaceId) -> Result<RepoSnapshot, StoreError> {
        Err(StoreError::NotImplemented(
            "StoreEngine::snapshot — B1 NamespaceTxn, scope 6-B1 deliverable 8",
        ))
    }

    /// Submit a validated transaction for sequencing, group append, fence, and
    /// publication.
    ///
    /// Returns only after the durable sequence is fenced and the committed
    /// root published. A success response means every reachable object and ref
    /// in the receipt survives immediate power loss (plan §4 transaction
    /// invariant 3).
    pub async fn submit(&self, txn: ValidatedTransaction) -> Result<CommitReceipt, StoreError> {
        let shard = StoreOptions::shard_of(&txn.namespace, self.shared.shard_count);
        let handle = self
            .shards
            .get(shard as usize)
            .ok_or_else(|| StoreError::Corruption(format!("shard {shard} has no writer")))?;
        let sender = handle.submissions.as_ref().ok_or(StoreError::NotReady)?;

        let completion = SharedCompletion::new();
        let waiter = completion.subscribe();
        let submission = Submission {
            transaction: txn,
            completion,
        };
        // The queue bound is backpressure, not a wait. Blocking the caller's
        // task inside a crate that starts no runtime would hand the store a
        // scheduling decision that belongs to its embedder (plan §7).
        match sender.try_send(submission) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(StoreError::Overloaded {
                    limit: "shard_submission_queue",
                    retry_after_micros: self
                        .shared
                        .options
                        .max_group_idle
                        .as_micros()
                        .try_into()
                        .unwrap_or(u64::MAX),
                })
            }
            // The writer thread is gone, which in this slice means the process
            // is shutting down or the thread panicked inside the poison
            // window. Either way nothing further can be appended.
            Err(TrySendError::Disconnected(_)) => return Err(StoreError::NotReady),
        }

        let receipt = waiter.await?;

        // Scope 6.3 step 10. A failure here is not a failure of the
        // transaction: the fence succeeded and the root published, so the
        // receipt stays queryable through `transaction_status` whatever this
        // returns. The failpoint is evaluated only on the success path,
        // because it names the moment a receipt is handed back and a request
        // that already failed has no receipt to lose.
        match failpoints::hit(Failpoint::BeforeResponse) {
            FailpointAction::Continue => Ok(receipt),
            FailpointAction::Fail => Err(StoreError::Io(Arc::new(std::io::Error::other(
                "failpoint BeforeResponse: the response was lost after publication; the \
                 transaction is committed and its receipt remains queryable",
            )))),
            FailpointAction::Panic => {
                panic!("failpoint BeforeResponse panicked the responding task")
            }
            FailpointAction::HardExit => {
                unreachable!("HardExit calls _exit(3) inside failpoints::hit and never returns")
            }
        }
    }

    /// Linearizable status lookup across the two roots.
    ///
    /// Plan §5.1: load committed root A and return any receipt or expired
    /// tombstone; otherwise load the status root and return any pending or
    /// resolving entry; if no status entry exists, load committed root B,
    /// return any terminal entry found there, and otherwise `Unknown`. The
    /// mandatory B read closes the old-committed/new-empty-status race without
    /// requiring A and B to share a generation.
    ///
    /// The three loads are `Acquire` (`ArcSwap::load`), and the writer publishes
    /// the committed root before it removes a status entry. So a reader that
    /// observes the status root *without* an entry has synchronized with the
    /// store that removed it, and therefore cannot then read a committed root
    /// older than the publication that preceded that removal. That is what
    /// makes the B read a proof rather than a retry.
    ///
    /// Time-based promotion of a retained receipt to `Expired` and then to
    /// `Unknown` (`oracle::retained_terminal_status`) is B1 deliverable 7; this
    /// read reports the terminal row the root actually holds.
    pub fn transaction_status(
        &self,
        repo: NamespaceId,
        operation: OperationId,
    ) -> Result<TransactionStatus, StoreError> {
        let key = OperationKey::new(repo, operation);
        Ok(two_root_status_read(
            self.shared.committed.load().terminal_status(&key).cloned(),
            self.shared.status.load().get(&key).copied(),
            // Evaluated eagerly and deliberately: the B load must happen after
            // the status load in program order, and a lazily evaluated
            // argument would let a future refactor skip it.
            self.shared.committed.load().terminal_status(&key).cloned(),
        ))
    }

    /// Force a checkpoint and hold a lease on the resulting generation.
    pub fn checkpoint(&self) -> Result<CheckpointLease, StoreError> {
        Err(StoreError::NotImplemented(
            "StoreEngine::checkpoint — B1 NamespaceTxn, scope 6-B1",
        ))
    }

    /// Durability counters for one shard, so "one fence per group" and "no
    /// per-object fsync" are assertions against observed syscalls rather than
    /// claims about this file (scope 2.3, charter item 7).
    ///
    /// Returns a **snapshot**, never the live `Arc<DurabilityCounters>`. The
    /// counter object is a set of mutable atomics: handing it out would let a
    /// consumer — including the harness whose whole job is to measure this
    /// store — add to the very numbers it reports, and a durability claim that
    /// its own auditor can write to is not evidence. `None` names a shard index
    /// this engine has no writer for, which is a caller error rather than a
    /// zeroed reading.
    pub fn durability_counters(&self, shard: u16) -> Option<DurabilityCounterSnapshot> {
        self.shards
            .get(shard as usize)
            .map(|handle| handle.counters.snapshot())
    }

    /// Status-root occupancy and refusal counts, root-wide.
    ///
    /// Read-only for the same reason as [`StoreEngine::durability_counters`].
    /// Occupancy is the size of the status root as of the last successful CAS
    /// by any writer, and `rejections` counts operations refused by the
    /// decision-9.8 capacity bound.
    pub fn operation_status_metrics(&self) -> OperationStatusMetricSnapshot {
        self.shared.status_metrics.snapshot()
    }

    /// What index maintenance has done and what it still owes, root-wide.
    ///
    /// Both fields come from **one** captured `CommittedRoot`. Reading them from
    /// two loads would let a caller see a run count from one publication beside a
    /// backlog from another — and the pair is only meaningful together, because
    /// the whole claim of a seal is that runs went up as the backlog went down.
    /// Two loads could show both rising, which never happens in any single root.
    ///
    /// A snapshot of immutable counts, not a counter handle, for the reason
    /// [`StoreEngine::durability_counters`] gives: the harness that reports these
    /// numbers must not be able to write to them.
    pub fn index_maintenance(&self) -> IndexMaintenanceSnapshot {
        let root = self.shared.committed.load();
        IndexMaintenanceSnapshot {
            sealed_runs: root.index().sealed_run_count() as u64,
            unsealed_delta_layers: root.index().delta_layer_count() as u64,
        }
    }
}

/// Sealed runs and unsealed backlog, as of one committed root.
///
/// `unsealed_delta_layers` is the count of delta layers no sealed run covers
/// yet — the backlog a seal removes. Zero after a seal that covered everything
/// published; nonzero whenever groups have committed since.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IndexMaintenanceSnapshot {
    pub sealed_runs: u64,
    pub unsealed_delta_layers: u64,
}

/// Plan §5.1's two-root read, written once so both the engine and its test can
/// only ever agree with `oracle::two_root_status_read`.
fn two_root_status_read(
    committed_a: Option<TerminalStatusEntry>,
    status: Option<StatusEntry>,
    committed_b: Option<TerminalStatusEntry>,
) -> TransactionStatus {
    if let Some(entry) = committed_a {
        return entry.transaction_status();
    }
    if let Some(entry) = status {
        return entry.transaction_status();
    }
    match committed_b {
        Some(entry) => entry.transaction_status(),
        None => TransactionStatus::Unknown,
    }
}

impl Drop for StoreEngine {
    fn drop(&mut self) {
        // Close every channel first, then join. A shard thread publishes its
        // open group on disconnect, so a transaction already accepted by a
        // writer is fenced and published before this returns rather than
        // abandoned with its waiter attached.
        for shard in &mut self.shards {
            shard.submissions = None;
        }
        for shard in &mut self.shards {
            if let Some(thread) = shard.thread.take() {
                let _ = thread.join();
            }
        }
    }
}

// ===========================================================================
// Startup: classifying the root (plan §5.2, scope 3.1)
// ===========================================================================

/// Which of plan §5.2's startup states a root is in, decided by reading and
/// nothing else.
///
/// States 3 and 4 share a variant because this pass does not implement the
/// legacy recognizer that separates them. That is a deliberate under-
/// classification, not a catch-all: the variant is named for exactly the
/// condition it holds — non-empty, no `FORMAT` — and `open` refuses it by
/// naming both unbuilt states. Charter item 6 forbids a `_ =>` arm; it does
/// not require inventing a distinction whose recognizer has not been written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootStartupState {
    /// §5.2 state 1. The path does not exist, or it is a directory holding
    /// nothing that this store did not create before it had decided anything.
    AbsentOrEmpty,
    /// §5.2 state 2. A `FORMAT` entry exists. Whether it *validates* is
    /// deliberately not decided here; see [`classify_root`].
    Formatted,
    /// §5.2 state 1, interrupted. The root carries this store's own
    /// initialization marker and nothing outside the skeleton that
    /// [`segment::initialize_root`] builds, so it is a root that started
    /// initializing and never finished.
    ///
    /// Not a fifth plan state: it is state 1 observed part-way through, and it
    /// resolves to the same action state 1 takes. It exists as its own variant
    /// because the *evidence* is different — an empty root proves nothing has
    /// been written, this one proves that what was written was written by this
    /// code path — and because charter item 6 requires the condition that
    /// authorizes a write to be named rather than folded into a neighbour.
    InterruptedInitialization,
    /// §5.2 states 3 and 4, undivided this pass.
    NonEmptyWithoutFormat,
}

// ---------------------------------------------------------------------------
// The initialization marker (plan §5.2 state 1, crash-resume)
// ---------------------------------------------------------------------------

/// The name of the marker that says "this root is mid-initialization".
///
/// Computed from `layout.root` here rather than added to [`RootLayout`],
/// because `RootLayout` is A1's frozen surface. Giving the name one definition
/// there is filed as an interface request; until it moves, this is the only
/// place in the crate that spells it.
const INITIALIZING_NAME: &str = "INITIALIZING";

/// The staging name the marker is installed from, so the marker itself is
/// never observed torn.
const INITIALIZING_TMP_NAME: &str = "INITIALIZING.tmp";

/// First bytes of the marker. The whole point of the classification is that
/// this cannot be produced by accident: a directory that merely *looks* like an
/// abandoned root has no reason to contain a file whose first sixteen bytes are
/// this string.
const INITIALIZING_MAGIC: &[u8; 16] = b"levcs-store-init";

/// 16 magic + 1 version + 2 shard_count + 8 created_at_micros.
const INITIALIZING_MARKER_LEN: usize = 27;

/// The exact bytes of the marker for one initialization attempt.
///
/// `shard_count` and `created_at_micros` are **evidence, not input**. A resume
/// restarts from the configuration the resuming process was given, not from the
/// one recorded here — the interrupted attempt published nothing, so it has no
/// claim on the topology. They are recorded so that an operator looking at
/// residue can see what the interrupted attempt intended, which is the one
/// question the file's existence alone cannot answer.
fn initializing_marker_bytes(shard_count: u16, created_at_micros: i64) -> [u8; 27] {
    let mut bytes = [0u8; INITIALIZING_MARKER_LEN];
    bytes[..16].copy_from_slice(INITIALIZING_MAGIC);
    bytes[16] = 1;
    bytes[17..19].copy_from_slice(&shard_count.to_le_bytes());
    bytes[19..27].copy_from_slice(&created_at_micros.to_le_bytes());
    bytes
}

/// Open `path` if and only if it is a **regular file holding exactly this code
/// path's marker**, and return the open descriptor so a caller that then wants
/// to act on those bytes acts on the object it validated rather than on the
/// name a second time.
///
/// Four conditions, all necessary, none inferred from the name:
///
/// 1. **Regular file, not a symlink** — [`crate::sys::open_regular_nofollow`]
///    opens with `O_NOFOLLOW` and checks the type through `fstat` on the
///    descriptor it got. A symlink here is not "our marker whose bytes live
///    elsewhere", it is somebody else's name, and following it would let a link
///    planted in the root decide what this process reads and (see
///    [`install_initializing_marker`]) writes.
/// 2. **Exactly [`INITIALIZING_MARKER_LEN`] bytes** — one byte more is read
///    than the marker occupies, so a longer file is rejected by the same
///    comparison that rejects a shorter one.
/// 3. **[`INITIALIZING_MAGIC`]**, which nothing else in this crate and nothing
///    in a legacy layout writes.
/// 4. **A version this build knows.**
///
/// `Ok(None)` for every failure, including absence: the caller has already seen
/// the name in a `read_dir` that may be a moment stale, and a marker that
/// vanished between the scan and this read is a root with no marker. Every one
/// of these answers means the same thing to every caller — *these are not our
/// bytes* — so they are one variant rather than a distinction no caller acts
/// on.
fn open_exact_marker(path: &std::path::Path) -> Result<Option<std::fs::File>, StoreError> {
    let file = match crate::sys::open_regular_nofollow(path)? {
        Some(file) => file,
        None => return Ok(None),
    };
    // One byte more than the marker, so a longer file is rejected by the same
    // length comparison that rejects a shorter one.
    let mut bytes = [0u8; INITIALIZING_MARKER_LEN + 1];
    let read = crate::sys::pread(&file, 0, &mut bytes)?;
    if read == INITIALIZING_MARKER_LEN && &bytes[..16] == INITIALIZING_MAGIC && bytes[16] == 1 {
        Ok(Some(file))
    } else {
        Ok(None)
    }
}

/// Whether `<root>/INITIALIZING` is this code path's marker.
///
/// Judged on content and file type, never on the name alone. A file of any
/// other length, with any other first sixteen bytes, or that is not a regular
/// file at all, is somebody else's and is treated as unrecognized content — the
/// direction that wastes an operator's time rather than the one that destroys
/// their data.
fn initializing_marker_is_ours(layout: &RootLayout) -> Result<bool, StoreError> {
    Ok(open_exact_marker(&layout.root.join(INITIALIZING_NAME))?.is_some())
}

/// Decide the startup state of `layout.root` **without creating, modifying, or
/// removing anything**.
///
/// One `read_dir` and a name comparison. No `create_dir_all`, no `File::open`
/// with `create`, no lock — a probe that creates a directory has already
/// broken state 4's byte-identity guarantee before the refusal it exists to
/// support is even reached, and there would be no test that could tell.
///
/// # The names this function has to rule on
///
/// - **`FORMAT` present.** State 2, on the strength of the *name* alone. A
///   `FORMAT` that fails to decode is still `FORMAT`: it is not evidence of an
///   empty root, and treating it as one would let a corrupt marker authorize
///   `initialize_root` to build a fresh tree over a populated one. Validation
///   is [`segment::read_format`]'s job inside [`RecoverySession::open`], where
///   failing is a refusal and never a rebuild.
/// - **`LOCK`, present as a regular file.** Ignored. It is not store data and
///   it is not evidence that anything has been decided: `LOCK` is a zero-length
///   file that [`segment::lock_root`] creates if absent, as a side
///   effect of *asking* whether the root is busy, so any process that merely
///   probed the root leaves one. Treating it as state 4 would permanently wedge
///   a root that has no bytes to lose.
/// - **`INITIALIZING.tmp`, present as a regular file holding exactly the
///   marker.** Ignored, on the same reasoning and on nothing weaker. It is the
///   staging name the marker below is installed from, and it normally exists
///   only between a fenced write and the `rename_noreplace` that consumes it.
/// - **`INITIALIZING` present as a regular file, and every other entry inside
///   the initialization skeleton.**
///   [`RootStartupState::InterruptedInitialization`] — see below.
/// - **Anything else.** State 3 or 4, refused without modification. Including
///   `FORMAT.tmp` on its own: it is residue this code path writes, but by
///   itself it is residue from *after* the marker was installed and then
///   removed, which cannot happen — a `FORMAT.tmp` with no marker beside it is
///   somebody else's file.
///
/// # Why a name is never enough, and why the *type* of every entry is checked
///
/// Contract review finding P1 (2026-07-29). This function used to ignore
/// `INITIALIZING.tmp` **whatever it was**, on the argument that the name can
/// only be this code path's residue by construction — and
/// [`build_root_under_lock`] then opened it with `create` + `truncate`. The
/// argument is not available here, twice over. It is the very claim the
/// classification is running in order to establish, and before the store owns
/// the root it has no standing to assume anything about what is in it. An
/// operator's regular file of that name in an otherwise-empty configured root
/// was destroyed silently; a **symlink** of that name was followed, so the
/// truncation landed on a file outside the root entirely, and the link was then
/// renamed away and unlinked so the evidence went with it.
///
/// So every entry is judged by `DirEntry::file_type`, which reports the type of
/// the directory entry itself and never of a symlink's target, and the two
/// names whose contents can authorize anything are additionally opened with
/// `O_NOFOLLOW` and validated ([`open_exact_marker`]). A symlink at `LOCK`,
/// `INITIALIZING`, `INITIALIZING.tmp`, or `FORMAT.tmp`, and a directory or fifo
/// at any of them, is a foreign entry and disqualifies the root. `FORMAT` is
/// still decided on its name alone, which stays safe for the opposite reason:
/// nothing on the state-2 path ever creates or truncates it — `initialize_root`
/// installs it only by `rename_noreplace`, which refuses an occupied name
/// including a symlink — so the worst a planted `FORMAT` can do is be read and
/// fail to decode, which is a refusal.
///
/// # The cost of this, stated rather than discovered
///
/// A torn or partially written `INITIALIZING.tmp` — a crash between its
/// creation and its fence — is now **refused** rather than overwritten, and
/// that refusal is permanent until an operator removes the file. That is the
/// intended trade and it is the same asymmetry the rest of this classification
/// is built on: refusing a resumable root costs an operator time, and
/// overwriting a real file costs them data. There is no test that can tell a
/// torn marker of ours from a stranger's truncated file, because there is no
/// difference between them on disk.
///
/// # Why an interrupted initialization is recognized, and how it cannot be
/// confused with a root that merely looks abandoned
///
/// [`segment::initialize_root`] creates `quarantine/`, `staging/`, `shards/`
/// and the per-shard tree *before* it installs `FORMAT`. A crash anywhere in
/// that window used to leave a non-empty root with no `FORMAT`, which this
/// function classified as states 3/4 and `open` refused — permanently, with a
/// message about legacy layouts and migration, for a root that had never held
/// a byte of anyone's data. That is why [`initialize_root_state_1`] installs
/// `INITIALIZING` as its first durable act and removes it as its last.
///
/// Two independent conditions must both hold before this returns
/// `InterruptedInitialization`, and each alone is enough to exclude a genuine
/// unrecognized layout:
///
/// 1. **`INITIALIZING` decodes as this code path's marker** — a regular file of
///    exactly [`INITIALIZING_MARKER_LEN`] bytes, opened `O_NOFOLLOW`, opening
///    with [`INITIALIZING_MAGIC`] and a version this build knows. Nothing else
///    in this crate, and nothing in a legacy layout, writes that file. A
///    human's note that happens to be named `INITIALIZING` fails on content.
/// 2. **Every entry in the root is inside the initialization skeleton, with the
///    type this store creates it as** — `LOCK`, `INITIALIZING`,
///    `INITIALIZING.tmp` and `FORMAT.tmp` as regular files, `quarantine`,
///    `staging` and `shards` as directories, and nothing else. A single foreign
///    name — a legacy `<64-hex>/` repository directory, a `notes.txt`, anything
///    an operator put there — disqualifies the root however convincing the
///    marker is, and so does a right name of the wrong type.
///
/// So mistaking a real root for an abandoned one requires an operator to have
/// placed a byte-exact copy of this marker into a directory that otherwise
/// contains only names this store invented. The asymmetry is deliberate: the
/// failure this can produce is a refusal that wastes time, and the failure it
/// cannot produce is initializing over somebody's data.
///
/// The ordering makes the converse hole impossible too. The marker is fenced,
/// and the root directory fsynced, *before* the first directory of the tree is
/// created — so a durable partial tree always has a durable marker beside it,
/// and there is no crash point that leaves tree residue this function would
/// refuse.
///
/// A missing directory and an empty directory are the same state and are
/// deliberately not distinguished. That is now true because
/// [`initialize_root_state_1`] fences every directory entry it creates on the
/// way down to the root, not because `initialize_root` fsyncs `root.parent()`:
/// that parent fsync covers exactly one link, and a root reached through
/// several newly created ancestors has several.
fn classify_root(layout: &RootLayout) -> Result<RootStartupState, StoreError> {
    let entries = match std::fs::read_dir(&layout.root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RootStartupState::AbsentOrEmpty)
        }
        // Every other failure — `ENOTDIR` because the configured root is a
        // regular file, `EACCES`, `ELOOP` — is reported as itself. A root this
        // process cannot read is not a root it may conclude is empty, and the
        // refusal has modified nothing.
        Err(error) => return Err(StoreError::from(error)),
    };

    let mut has_format = false;
    let mut has_marker = false;
    // Anything that is neither `FORMAT` nor an ignorable probe artifact.
    // Non-empty in the sense states 3 and 4 mean it.
    let mut has_content = false;
    // Anything outside the closed set of names an initialization can leave.
    let mut has_foreign = false;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        // `DirEntry::file_type` is the type of the entry itself: it is `lstat`,
        // never `stat`, so a symlink reports as a symlink and this loop cannot
        // be made to describe an object outside the root.
        let kind = entry.file_type()?;

        if name == std::ffi::OsStr::new("FORMAT") {
            has_format = true;
            continue;
        }
        // Probe residue, ignorable only in the exact shape the probe leaves.
        if name == std::ffi::OsStr::new("LOCK") {
            if kind.is_file() {
                continue;
            }
            has_content = true;
            has_foreign = true;
            continue;
        }
        // The staging name, ignorable only when it is a regular file carrying
        // this code path's marker byte for byte. Anything else at that name —
        // a symlink, a directory, a stranger's file, a torn write — is foreign,
        // because the alternative is deciding it is ours and then writing
        // through it.
        if name == std::ffi::OsStr::new(INITIALIZING_TMP_NAME) {
            if kind.is_file()
                && open_exact_marker(&layout.root.join(INITIALIZING_TMP_NAME))?.is_some()
            {
                continue;
            }
            has_content = true;
            has_foreign = true;
            continue;
        }
        has_content = true;
        if name == std::ffi::OsStr::new(INITIALIZING_NAME) {
            // Content is checked below, once, and only if nothing foreign was
            // found; the type is checked here because a non-regular entry at
            // this name is foreign whatever it would have read as.
            if kind.is_file() {
                has_marker = true;
            } else {
                has_foreign = true;
            }
            continue;
        }
        // The rest of what `segment::initialize_root` creates directly in the
        // root, each with the type it creates it as. Named exhaustively rather
        // than pattern-matched: a name this list does not contain must
        // disqualify the root, and a wildcard here is the one edit that would
        // silently stop it doing so. The type is part of the name's meaning —
        // a symlink called `FORMAT.tmp` is not residue, it is an instruction to
        // write outside the root. `segment::write_fenced` refuses one directly
        // now as well; this list is why the root is disqualified rather than
        // initialized-then-refused, which is a different and better answer.
        if !matches!(
            (name.to_str(), kind.is_file(), kind.is_dir()),
            (Some("FORMAT.tmp"), true, _)
                | (Some("quarantine"), _, true)
                | (Some("staging"), _, true)
                | (Some("shards"), _, true)
        ) {
            has_foreign = true;
        }
    }

    // Order is plan §5.2's order. `FORMAT` wins over everything below it
    // because state 2 is decided before any other state; the interrupted shape
    // is decided next because it is state 1 and its evidence is positive; and
    // "empty" is evaluated against the same scan rather than a second one, so
    // no interleaved writer can make the two disagree.
    if has_format {
        return Ok(RootStartupState::Formatted);
    }
    if has_marker && !has_foreign && initializing_marker_is_ours(layout)? {
        return Ok(RootStartupState::InterruptedInitialization);
    }
    Ok(if has_content {
        RootStartupState::NonEmptyWithoutFormat
    } else {
        RootStartupState::AbsentOrEmpty
    })
}

/// Plan §5.2 startup state 1: build the v2 tree under the root lock.
///
/// # Why the lock, and why it is taken here rather than inherited
///
/// Initializing a root is a mutation, and two processes configured for the
/// same absent path will otherwise both classify it `AbsentOrEmpty` and both
/// run [`segment::initialize_root`]. The loser's `rename_noreplace` of
/// `FORMAT` would fail, but only after it had already created a shard tree and
/// fsynced it into a root the winner had begun to consider its own. So the
/// classification is repeated **under the lock**, and it is the second answer
/// that authorizes the write. That is the whole race: `FORMAT` is installed by
/// a no-replace rename as the last durable act of initialization, so if the
/// second classification still says `AbsentOrEmpty` while this process holds
/// `LOCK`, no other process can be mid-initialization.
///
/// The lock is a [`segment::RootLock`] and is released by dropping it, which
/// issues an explicit `LOCK_UN` rather than relying on a descriptor close a
/// concurrently forked child can extend (commit `e050b6d`).
///
/// The same rule governs the resume path. Finding an `INITIALIZING` marker
/// before the lock authorizes nothing: another process may be building that
/// tree *right now*, in which case this one is refused `AlreadyLocked` and never
/// reaches the second classification. It is the classification taken **while
/// holding `LOCK`** that authorizes finishing someone else's interrupted
/// initialization, and by then the only process that could have been mid-build
/// has released the lock and is gone.
///
/// # Why the lock is then released and immediately retaken
///
/// [`RecoverySession::open`] takes `LOCK` itself, and there is no constructor
/// that adopts an already-held one — adding it is a change to A2's frozen
/// surface and is filed as an interface request, not made here. The gap is
/// safe but it is a real gap and worth stating exactly: an initialized root is
/// complete and durable the moment this returns, so a second process entering
/// the window can only take state 2, and if it does, this process's
/// `RecoverySession::open` is refused `AlreadyLocked` — the correct answer for
/// a root another process owns, not a corruption. What the window cannot
/// produce is two initializations, because the second process no longer
/// classifies the root as empty.
fn initialize_root_state_1(
    layout: &RootLayout,
    options: &StoreOptions,
) -> Result<DurabilityCounterSnapshot, StoreError> {
    let counters = DurabilityCounters::default();

    // `LOCK` lives inside the root, so the directory has to exist before it
    // can be locked. This is the one write that precedes the lock, and it is
    // the write state 1 is defined to perform: creating the path is
    // idempotent, two racing processes both succeed, and neither has yet
    // written a byte either could lose. It is reached only after the read-only
    // classification said the root has never been initialized, so it never runs
    // against states 2, 3, or 4.
    create_and_fence_root_path(&layout.root, &counters)?;
    let lock = segment::lock_root(layout)?;

    match classify_root(layout)? {
        // Both are state 1. The second says the marker is already on disk, so
        // `build_root_under_lock` re-fences the name it finds instead of
        // installing a second one.
        RootStartupState::AbsentOrEmpty => {
            build_root_under_lock(layout, options, false, &counters)?
        }
        RootStartupState::InterruptedInitialization => {
            build_root_under_lock(layout, options, true, &counters)?
        }
        // Another process initialized this root between the first
        // classification and this lock. Its tree is complete and fsynced, so
        // there is nothing to do and nothing to repair; the caller falls
        // straight through to state 2.
        RootStartupState::Formatted => {}
        // Non-empty with no `FORMAT` and no marker, discovered only under the
        // lock. The refusal is the same one state 3/4 gets, and this path has
        // written nothing but the directories it was told were absent.
        RootStartupState::NonEmptyWithoutFormat => {
            return Err(StoreError::NotImplemented(
                "StoreEngine::open startup states 3 and 4 (LegacyLayout carrying the exact \
                 migrate-store command, UnrecognizedLayout) — B1 NamespaceTxn, scope 6-B1 \
                 deliverable 1. The root became non-empty without a FORMAT between \
                 classification and the root lock; it has not been modified",
            ))
        }
    }

    drop(lock);
    Ok(counters.snapshot())
}

/// Create every missing directory on the way to `root`, and fence each new
/// directory entry — deepest first.
///
/// # Why this is not `create_dir_all` followed by `initialize_root`
///
/// `create_dir_all` creates *every* missing ancestor, and
/// [`segment::initialize_root`] fences exactly one link: `root.parent()`. So a
/// configured root of `.../not/yet/a-root` under an existing directory left the
/// entries naming `not` and `yet` unfenced, while `open` returned success. A
/// power loss could then take an ancestor and the whole initialized root with
/// it — a store that reported itself initialized, reachable only through
/// directory entries no one had made durable.
///
/// # Why fencing rather than refusing an absent parent
///
/// Refusing would have been less code and is genuinely safe. It was rejected
/// because it moves a durability defect onto the operator as a configuration
/// restriction: a root path under a per-instance directory the store is
/// expected to create is the ordinary deployment shape, and `StoreEngine::open`
/// already promises to build an absent root. "Absent" would then have had to
/// mean "absent by exactly one component", which is a rule nothing on disk
/// explains and which every caller would have to learn by being refused.
///
/// # The ordering, which is the whole content of the fix
///
/// Only the directories *this call* creates are fenced, and a directory entry
/// lives in the parent that names it — so fencing directory `D` is fsyncing
/// `parent(D)`. They are fenced deepest first: a child's entry must be durable
/// before the entry naming its parent, because the reverse order can leave a
/// crash image in which a fenced parent names a child that was never fenced.
/// For `base/a/b/c` with `base` already present, that is fsync(`b`), fsync(`a`),
/// fsync(`base`) — one fsync per created directory.
///
/// `c`'s own contents are not this function's concern: it is empty here, and
/// [`segment::initialize_root`] fsyncs the root itself once it has built the
/// tree inside it.
///
/// Routed through `sys::fsync_dir` because that module is the crate's sole
/// durability funnel; a raw `File::open(..).sync_all()` here would be invisible
/// to the counters that make this fix testable at all.
fn create_and_fence_root_path(
    root: &std::path::Path,
    counters: &DurabilityCounters,
) -> Result<(), StoreError> {
    // Deepest first. `try_exists` rather than `exists` so that a path this
    // process cannot stat is an error instead of silently "missing" — creating
    // over an `EACCES` would be a refusal turned into a mutation.
    let mut missing: Vec<&std::path::Path> = Vec::new();
    let mut cursor = Some(root);
    while let Some(path) = cursor {
        if path.try_exists()? {
            break;
        }
        missing.push(path);
        cursor = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty());
    }
    if missing.is_empty() {
        return Ok(());
    }

    // Shallowest first: a directory cannot be created before the one that names
    // it. `create_dir` rather than `create_dir_all` so that what this call
    // created is exactly what it fences — `create_dir_all` would silently
    // absorb an ancestor another process created in the same instant and leave
    // this one believing it had made the link.
    for path in missing.iter().rev() {
        match std::fs::create_dir(path) {
            Ok(()) => {}
            // A racing initializer of the same path got there first. Its own
            // fence covers the link either way, and fencing it twice is
            // harmless; refusing here would make two correct processes fight.
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(StoreError::from(error)),
        }
    }

    for path in &missing {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        crate::sys::fsync_dir(parent, counters)?;
    }
    Ok(())
}

/// Install the initialization marker, build the tree, and remove the marker.
///
/// The order is the contract [`classify_root`] reads back:
///
/// 1. `INITIALIZING.tmp` is created with `O_EXCL`, written and fenced
///    ([`install_initializing_marker`]), renamed onto `INITIALIZING` with
///    `rename_noreplace`, and the root directory fsynced. The marker is
///    therefore never observable torn under its installed name, and it is
///    durable **before** any part of the tree exists.
/// 2. [`segment::initialize_root`] builds the tree and installs `FORMAT`.
/// 3. The marker is unlinked and the removal fenced.
///
/// A crash in step 1 leaves at most `LOCK` and `INITIALIZING.tmp`. A *whole*
/// `INITIALIZING.tmp` classifies as an empty root and is adopted by the next
/// attempt; a torn one is refused, which is the trade
/// [`install_initializing_marker`] states. A crash in step 2 leaves the marker and a partial
/// skeleton, which classify as `InterruptedInitialization` and land back here.
/// A crash in step 3 leaves a complete, valid root, which classifies as state 2
/// — the marker is then inert litter that `FORMAT` outranks, and removing it on
/// a state-2 open is rejected precisely because it would make reopening a
/// formatted root a mutation.
///
/// `resuming` says the marker is already there. It is passed rather than
/// re-derived because `rename_noreplace` onto an existing `INITIALIZING` would
/// fail, and because re-deciding it here would be a third classification that
/// could disagree with the one taken under the lock.
///
/// A resume restarts the build from the *current* configuration rather than the
/// one the marker records: the interrupted attempt published no `FORMAT`, so it
/// froze no topology and has no claim on this one. If the two disagree on
/// `shard_count`, the surplus shard directories from the wider attempt are left
/// behind — empty, referenced by no `FORMAT`, and read by nothing, since every
/// consumer iterates `0..FORMAT.shard_count`.
fn build_root_under_lock(
    layout: &RootLayout,
    options: &StoreOptions,
    resuming: bool,
    counters: &DurabilityCounters,
) -> Result<(), StoreError> {
    let marker = layout.root.join(INITIALIZING_NAME);
    if resuming {
        // The marker exists but its *name* may not be durable: the crash could
        // have landed between the rename and the fsync below. Fencing it again
        // before touching the tree is what keeps "a durable partial tree always
        // has a durable marker beside it" true across a second interruption.
        crate::sys::fsync_dir(&layout.root, counters)?;
    } else {
        let tmp = layout.root.join(INITIALIZING_TMP_NAME);
        let bytes = initializing_marker_bytes(options.shard_count, now_micros());
        install_initializing_marker(&tmp, &bytes, counters)?;
        crate::sys::rename_noreplace(&tmp, &marker)?;
        crate::sys::fsync_dir(&layout.root, counters)?;
    }

    segment::initialize_root(
        layout,
        options.shard_count,
        fresh_root_uuid(),
        now_micros(),
        counters,
    )?;

    // Last, and after `FORMAT` is durable. Removing it earlier would open a
    // window in which the tree exists, `FORMAT` does not, and nothing says the
    // residue is ours — which is the exact defect this marker was added to
    // close.
    crate::sys::unlink(&marker)?;
    crate::sys::fsync_dir(&layout.root, counters)?;
    Ok(())
}

/// Put the marker's bytes at the staging name and fence them, **without ever
/// writing through a name this process has not established is its own**. The
/// name is not durable when this returns; the caller renames and fsyncs the
/// directory.
///
/// # The two branches, and why neither of them can truncate
///
/// The ordinary case creates the name: [`crate::sys::create_new_nofollow`] is
/// `O_CREAT | O_EXCL | O_NOFOLLOW`, so it either brings a brand-new regular
/// file into existence in *this* directory or reports that the name is taken.
/// `O_CREAT | O_EXCL` is specified to fail on a symlink whether or not the link
/// resolves, so there is no arrangement of the root that can redirect this
/// write.
///
/// The name being taken is the interesting case, and this is where contract
/// review finding P1 was. What used to happen was `create` + `truncate`: an
/// operator's file at that name was destroyed, and a *symlink* at that name was
/// followed so the destruction landed on a file outside the root, after which
/// the link was renamed and unlinked and the evidence went with it. What
/// happens now is that the occupant is validated by [`open_exact_marker`] —
/// regular file, exact length, exact magic, known version — and only *then*
/// adopted, in place, by fencing the bytes that are already there. Adoption
/// writes nothing: the file already holds exactly what this call was about to
/// write, so the fence is the whole remaining act.
///
/// Adopting the occupant's bytes rather than replacing them also keeps the
/// resume rule consistent. `shard_count` and `created_at_micros` in the marker
/// are evidence of the interrupted attempt, not input to this one
/// ([`initializing_marker_bytes`]), and the resume-from-`INITIALIZING` path
/// already carries the earlier attempt's bytes forward untouched. This does the
/// same thing one step earlier.
///
/// # What is refused, and what that costs
///
/// Everything else at that name: a stranger's file, a symlink, a directory, and
/// a **torn or partially written marker** — a crash between the create and the
/// fence. The torn case is the one that costs something real: a root that was
/// previously resumable now needs an operator to remove one file before it will
/// initialize. That is the intended trade, and it is not close. Refusing a
/// resumable root costs an operator time; overwriting a real file costs them
/// their data. And nothing on disk distinguishes our torn 12-byte marker from a
/// stranger's truncated 12-byte file, so a rule that recovers the first
/// necessarily destroys the second.
///
/// # Standing disclosure
///
/// This began as a second copy of `segment::write_fenced`, which is private to
/// A1's file, and the duplication was filed as an interface request. Neither can
/// follow a symlink any more — contract review 2026-07-29-B routed
/// `write_fenced` through the same funnel — so what remains is a real difference
/// in refusal rule rather than in safety: this one refuses an existing regular
/// file, because a marker that already exists is somebody's data and adopting it
/// would be a decision about content; `write_fenced` adopts and empties one,
/// because a `.tmp` name is residue from an interrupted attempt at that exact
/// write and reusing it is how the retry works. Both are correct for their name.
/// Any hoisting therefore has to keep two rules, not pick one.
fn install_initializing_marker(
    tmp: &std::path::Path,
    bytes: &[u8],
    counters: &DurabilityCounters,
) -> Result<(), StoreError> {
    match crate::sys::create_new_nofollow(tmp)? {
        Some(mut file) => {
            crate::sys::write_vectored_all(&mut file, &[std::io::IoSlice::new(bytes)], counters)?;
            crate::sys::fdatasync(&file, counters)?;
            Ok(())
        }
        // Reachable in normal operation when a previous attempt crashed between
        // the create and the rename, and reachable adversarially at any time,
        // since the classification that ran a moment ago under `LOCK` is a
        // statement about the past. Both are handled by looking, not by
        // assuming.
        None => match open_exact_marker(tmp)? {
            Some(file) => {
                crate::sys::fdatasync(&file, counters)?;
                Ok(())
            }
            None => Err(StoreError::UnrecognizedLayout(format!(
                "{}: the initialization staging name is occupied by something that is not this \
                 store's marker — a foreign file, a symlink, a directory, or a torn marker from \
                 an interrupted attempt. Refusing to write through it; nothing has been modified. \
                 Remove that entry to let the root initialize",
                tmp.display()
            ))),
        },
    }
}

/// A fresh `root_uuid` for a root being initialized.
///
/// `FORMAT.root_uuid` binds every `CURRENT`, manifest, journal, segment, index
/// run, and checkpoint in the root (scope 3.1), and its whole job is to make a
/// file copied in from another instance detectable. So it must not be a
/// function of anything two roots can share — the path in particular, since a
/// root deleted and recreated at the same path is exactly the case this is
/// meant to catch.
///
/// **Duplication, disclosed rather than hidden:** `drive.rs` has a private
/// `fresh_id` doing the same thing for journal and root identifiers. This is a
/// second implementation of "derive 16 bytes with enough entropy to be unique
/// per process and per call", and it is here because `drive.rs` is A1's file
/// and is `#[cfg(feature = "store-internals")]`, so neither borrowing it nor
/// editing it is available to this deliverable. Hoisting one into `sys` is
/// filed as an interface request.
fn fresh_root_uuid() -> [u8; 16] {
    use std::sync::atomic::AtomicU64;
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let stack = 0u8;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"levcs-store-root-uuid/v1\0");
    hasher.update(&now_micros().to_le_bytes());
    hasher.update(&COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    hasher.update(&std::process::id().to_le_bytes());
    hasher.update(&(&stack as *const u8 as usize).to_le_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    id
}

// ===========================================================================
// Startup: the recovered state becomes the first committed root
// ===========================================================================

fn initial_committed_root(shards: &[RecoveredShard]) -> Result<CommittedRoot, StoreError> {
    let mut repositories = RepoMap::new();
    let mut terminal_statuses = TerminalStatusMap::new();
    let mut shard_committed_sequences = ShardSequenceMap::new();
    let mut retained_generations = GenerationMap::new();
    let mut delta_layers_newest_first = Vector::new();
    let mut sealed_runs_newest_first = Vector::new();

    for shard in shards {
        for (namespace, record) in shard.catalog.iter() {
            repositories.insert(
                *namespace,
                Arc::new(repo_state_from_recovery(record, &shard.refs)?),
            );
        }
        for receipt in &shard.receipts {
            terminal_statuses.insert(
                OperationKey::new(receipt.namespace, receipt.operation_id),
                TerminalStatusEntry::Committed(retained_receipt(receipt)?),
            );
        }
        if let Some(sequence) = shard.committed_shard_sequence {
            shard_committed_sequences.insert(shard.shard_index, sequence);
        }
        // The generation, not its name: recovery opened these artifacts, and
        // handing over a path instead of the live reference would leave a
        // window in which nothing holds them and reclamation is legal.
        retained_generations.insert(
            shard.retained_generation.id,
            Arc::clone(&shard.retained_generation),
        );
        for layer in shard.index.delta_layers() {
            delta_layers_newest_first.push_back(layer.clone());
        }
        for run in shard.index.sealed_runs() {
            sealed_runs_newest_first.push_back(Arc::clone(run));
        }
    }

    Ok(CommittedRoot::new(
        repositories,
        LayeredObjectIndex::new(delta_layers_newest_first, sealed_runs_newest_first),
        terminal_statuses,
        shard_committed_sequences,
        retained_generations,
    ))
}

fn repo_state_from_recovery(
    record: &NamespaceRecord,
    refs: &[RefRecord],
) -> Result<RepoState, StoreError> {
    let mut typed_refs = TypedRefMap::new();
    for reference in refs.iter().filter(|r| r.namespace == record.namespace) {
        // Contract review 2026-07-28-A item 4: the ref-kind table is stated
        // once, in `checkpoint.rs`, in each direction. This file used to carry
        // a third copy that agreed with it today.
        typed_refs.insert(reference.target()?, reference.target);
    }
    Ok(RepoState {
        repo_sequence: record.repo_sequence,
        current_authority: record.current_authority,
        genesis_authority: record.genesis_authority,
        refs: typed_refs,
        lifecycle: record.lifecycle,
        storage_mode: record.storage_mode,
        previous_event_digest: record.previous_event_digest,
    })
}

fn retained_receipt(record: &ReceiptRecord) -> Result<RetainedReceipt, StoreError> {
    // Recovery step 10 has already promoted every row, so `None` here means a
    // receipt reached the root without passing through the promotion that
    // decides its retention. That is a store-consistency failure, not a value
    // to substitute.
    let first_visible_at_micros = record.first_receipt_visibility_micros.ok_or_else(|| {
        StoreError::Corruption(format!(
            "recovered receipt for operation {} has no first-visibility instant",
            record.operation_id.to_hex()
        ))
    })?;
    Ok(RetainedReceipt {
        operation_digest: record.operation_digest,
        receipt: CommitReceipt {
            operation_id: record.operation_id,
            repo_sequence: record.repo_sequence,
            current_authority: record.current_authority,
            refs: record.refs.clone(),
            objects_new: record.objects_new,
        },
        shard_sequence: record.shard_sequence,
        retry_until_micros: record.retry_until_micros,
        first_visible_at_micros,
        receipt_visible_until_micros: record.receipt_visible_until_micros,
    })
}

fn spawn_shard_writer(
    shared: Arc<EngineShared>,
    recovered: RecoveredShard,
) -> Result<ShardHandle, StoreError> {
    let shard_index = recovered.shard_index;
    let tail = recovered.tail.as_ref().ok_or_else(|| {
        StoreError::Corruption(format!(
            "shard {shard_index} reported ready with no active journal"
        ))
    })?;
    let counters = Arc::new(DurabilityCounters::default());
    let (journal, _scan) = Journal::open(&tail.path, &shared.root_uuid, Arc::clone(&counters))?;

    // The journal recovery installed is empty, so its next sequence is the one
    // after the committed tail. Checking rather than assuming: a mismatch here
    // would silently append into a sequence range recovery already adopted.
    let expected_next = recovered
        .committed_shard_sequence
        .map(|sequence| sequence.saturating_add(1))
        .unwrap_or(0);
    if journal.next_shard_sequence() != expected_next {
        return Err(StoreError::Corruption(format!(
            "shard {shard_index} recovered through sequence {expected_next} but its active \
             journal resumes at {}",
            journal.next_shard_sequence()
        )));
    }

    let mut repositories = BTreeMap::new();
    for (namespace, record) in recovered.catalog.iter() {
        repositories.insert(
            *namespace,
            repo_state_from_recovery(record, &recovered.refs)?,
        );
    }

    let writer = ShardWriter {
        builder: GroupBuilder::from_options(&shared.options),
        pending: Vec::new(),
        waiters: Vec::new(),
        group_base: BTreeMap::new(),
        in_flight_reservation: None,
        repositories,
        tail_generation: tail.logical_generation,
        journal,
        shard_index,
        poison: None,
        shared,
    };

    let (submissions, receiver) = crossbeam_channel::bounded(submission_queue_depth(&writer));
    let thread = std::thread::Builder::new()
        .name(format!("levcs-store-shard-{shard_index}"))
        .spawn(move || run_shard_writer(writer, receiver))?;

    Ok(ShardHandle {
        submissions: Some(submissions),
        thread: Some(thread),
        counters,
    })
}

/// Two maximal groups' worth of queue.
///
/// One would make every group boundary a backpressure event even when the
/// device is keeping up; unbounded would replace a typed `Overloaded` refusal
/// with unbounded memory, which decision 9.8 rules out for the status root for
/// the same reason.
fn submission_queue_depth(writer: &ShardWriter) -> usize {
    (writer.shared.options.max_group_transactions as usize).saturating_mul(2)
}

// ===========================================================================
// The shard writer
// ===========================================================================

/// One shard's sequencer and journal writer.
///
/// Everything in here is owned by exactly one thread. `repo_sequence`, the
/// per-repository event chain, and `shard_sequence` are assigned with no
/// cross-shard coordination, which is sound only because a repository's shard
/// assignment never moves (scope 2.5).
struct ShardWriter {
    shared: Arc<EngineShared>,
    shard_index: u16,
    journal: Journal,
    builder: GroupBuilder,
    /// Parallel to the frames held by `builder`, in the same order.
    pending: Vec<Prepared>,
    /// Every caller this thread owes an outcome to, oldest first.
    ///
    /// Deliberately *not* stored inside [`Prepared`]. A panic anywhere in the
    /// sequencer or the publication window unwinds this thread, and a
    /// completion that unwound with the frame it belonged to is a request that
    /// never resolves — indistinguishable from a store that hung. Keeping the
    /// waiters on the writer means the panic handler can still reach them, and
    /// each one carries the publication phase it is actually in so that the
    /// handler resolves it as that phase rather than as the worst one.
    waiters: Vec<Waiter>,
    /// Speculative state: every earlier accepted transaction in the pending
    /// group is already applied here, which is what scope 6.3 step 1 requires
    /// the precondition checks to see.
    repositories: BTreeMap<NamespaceId, RepoState>,
    /// The repository state each namespace held *before* the open group
    /// touched it, so the whole group can be re-derived from a clean base when
    /// a member is dropped by the pre-mark deadline recheck.
    ///
    /// `None` records "this namespace did not exist yet", which is a different
    /// fact from "it existed with default state" and is the difference between
    /// restoring a repository and inventing one.
    group_base: BTreeMap<NamespaceId, Option<RepoState>>,
    /// The status-root reservation held by a transaction that is inside
    /// `prepare` and has not yet joined `pending`.
    ///
    /// Scope 6.3 steps 1-3 are pre-append and definitively absent on failure,
    /// including on a panic. Without this, a panic between `reserve` and the
    /// push into `pending` leaves a `Pending` entry that nothing owns and that
    /// no recovery resolves, because recovery only ever sees what reached the
    /// device — and nothing did.
    in_flight_reservation: Option<OperationKey>,
    /// Logical index generation of the active journal, so an index location
    /// built here resolves to the same pinned file after a reopen.
    tail_generation: u64,
    poison: Option<StoreError>,
}

/// One shard's unsealed index backlog, summed from one captured root.
#[derive(Copy, Clone, Debug, Default)]
struct UnsealedBacklog {
    layers: usize,
    entries: u64,
    encoded_bytes: u64,
    /// The highest shard sequence any of those layers covers, which is what a
    /// seal built from them may claim to cover.
    through_shard_sequence: u64,
}

/// Which of scope 6.3's phases a caller is actually in.
///
/// The fate of a request on an abnormal exit is a function of this and nothing
/// else. Treating every panic as a publication panic is what lets a transaction
/// that never reached step 4 be reported as possibly durable, and a transaction
/// that is already committed be reported as poisoned.
enum WaiterPhase {
    /// Steps 1-3. Nothing is appended and nothing can be; a failure here is
    /// definitively absent and releases the reservation.
    PreAppend,
    /// Steps 4-8, the poison window. A failure here leaves the operation
    /// `Resolving` and the shard read-only until recovery.
    Publishing,
    /// Steps 9-10. The fence succeeded and the root published, so the only
    /// honest outcome is the receipt. Scope 6.3: failure here is not a failure.
    Committed(CommitReceipt),
}

struct Waiter {
    completion: SharedCompletion,
    phase: WaiterPhase,
    /// The status-root reservation this waiter owns while it is `PreAppend`.
    /// Taken over by step 8 once the group publishes.
    reservation: Option<OperationKey>,
}

impl Waiter {
    fn new(completion: SharedCompletion) -> Self {
        Self {
            completion,
            phase: WaiterPhase::PreAppend,
            reservation: None,
        }
    }
}

/// One sequenced transaction, complete except for where its frame landed.
struct Prepared {
    key: OperationKey,
    operation_digest: ObjectId,
    retry_until_micros: i64,
    first_visible_at_micros: i64,
    shard_sequence: u64,
    /// The repository state *after* this transaction.
    repo_state: Arc<RepoState>,
    objects: Vec<(ObjectId, u8)>,
    receipt: CommitReceipt,
    /// Retained so the whole group can be re-sequenced, re-chained, and
    /// re-signed when the pre-mark deadline recheck drops a member.
    ///
    /// Signing covers `SignedCommittedTransactionV1::signing_digest`, which
    /// commits to the chained `previous_event_digest`; dropping a member
    /// therefore invalidates every signature after it. Keeping only the derived
    /// frame would make a partial repair the only available repair, and a
    /// partial repair is a durable, correctly fenced frame carrying a signature
    /// that verifies against nothing.
    transaction: Arc<ValidatedTransaction>,
}

fn run_shard_writer(mut writer: ShardWriter, submissions: Receiver<Submission>) {
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        loop {
            // The idle bound is a receive deadline, not a timer thread: an
            // open group closes on time even when nothing else arrives, and a
            // shard with no open group blocks instead of spinning.
            let message = match writer.builder.time_to_close() {
                Some(remaining) => submissions.recv_timeout(remaining),
                None => submissions
                    .recv()
                    .map_err(|_| RecvTimeoutError::Disconnected),
            };
            match message {
                Ok(submission) => writer.accept(submission),
                Err(RecvTimeoutError::Timeout) => writer.publish_open_group(),
                Err(RecvTimeoutError::Disconnected) => {
                    // A transaction already accepted is already sequenced.
                    // Closing the engine publishes it rather than dropping it
                    // with its waiter attached.
                    writer.publish_open_group();
                    break;
                }
            }
        }
    }));

    if let Err(payload) = unwound {
        // A writer-thread panic still resolves every caller this thread owes an
        // outcome to — a completion that unwound with its frame is a request
        // that never resolves. What each caller is told is decided by the phase
        // it was in, not by where the catch happens to be: this boundary sees
        // pre-append requests and published-but-unwoken requests as well as the
        // poison window, and reporting all three as `ShardPoisoned` would claim
        // that a transaction which never reached step 4 might be durable.
        let poison =
            writer.poison_error("the writer thread panicked inside the publication window".into());
        let mut poisoned_any = false;
        for waiter in std::mem::take(&mut writer.waiters) {
            match waiter.phase {
                WaiterPhase::PreAppend => {
                    if let Some(key) = waiter.reservation {
                        writer.release_reservation(&key);
                    }
                    waiter.completion.complete(Err(pre_append_panic_error()));
                }
                WaiterPhase::Publishing => {
                    poisoned_any = true;
                    waiter.completion.complete(Err(poison.clone()));
                }
                WaiterPhase::Committed(receipt) => {
                    waiter.completion.complete(Ok(receipt));
                }
            }
        }
        if let Some(key) = writer.in_flight_reservation.take() {
            // A panic strictly inside `prepare`, before the transaction had a
            // waiter phase to be in.
            writer.release_reservation(&key);
        }
        if poisoned_any {
            writer.poison.get_or_insert(poison);
        }
        std::panic::resume_unwind(payload);
    }
}

/// The outcome of a panic in scope 6.3 steps 1-3.
///
/// Definitive, not poisoning: no sequence was consumed, no byte was written,
/// and the reservation is released, so the operation reads back `Unknown` and
/// the caller may retry. `Conflict` is the taxonomy's definitive-rejection
/// variant and is what the ordinary pre-append refusals in this file already
/// return.
fn pre_append_panic_error() -> StoreError {
    StoreError::Conflict(
        "the sequencer panicked before this transaction was marked Resolving; scope 6.3 steps \
         1-3 are pre-append, so nothing was appended and nothing can be"
            .into(),
    )
}

impl ShardWriter {
    fn accept(&mut self, submission: Submission) {
        let Submission {
            transaction,
            completion,
        } = submission;
        // Registered before anything that can fail or panic. Until this
        // transaction joins `pending`, it is the last waiter in the list and
        // `fail_newest_waiter` is what resolves it.
        self.waiters.push(Waiter::new(completion));

        if let Some(poison) = self.poison.clone() {
            self.fail_newest_waiter(poison);
            return;
        }
        let transaction = Arc::new(transaction);

        let (prepared, frame) = match self.prepare_caught(&transaction) {
            Ok(pair) => pair,
            Err(error) => {
                self.fail_newest_waiter(error);
                return;
            }
        };

        if let Err(frame) = self.builder.push(frame) {
            // The group is full. The new request is rolled back completely —
            // reservation released, speculative state restored — *before* the
            // open group publishes, and re-prepared afterwards.
            //
            // The alternative, publishing while this request is prepared but
            // not yet in `pending`, is what made a publication panic report a
            // trailing request as poisoned though it never appended, and leave
            // its reservation pending. It also made its `shard_sequence` a
            // prediction about how many members the group about to publish
            // would keep, which the pre-mark deadline recheck can change.
            drop(frame);
            self.roll_back_prepared(&prepared);
            self.publish_open_group();
            if let Some(poison) = self.poison.clone() {
                self.fail_newest_waiter(poison);
                return;
            }
            let (reprepared, frame) = match self.prepare_caught(&transaction) {
                Ok(pair) => pair,
                Err(error) => {
                    self.fail_newest_waiter(error);
                    return;
                }
            };
            self.builder
                .push(frame)
                .expect("an empty group admits any frame");
            self.attach_newest_reservation(reprepared.key);
            self.pending.push(reprepared);
        } else {
            self.attach_newest_reservation(prepared.key);
            self.pending.push(prepared);
        }

        if self.builder.is_closed() {
            self.publish_open_group();
        }
    }

    /// Scope 6.3 steps 1-3 with their own unwind boundary.
    ///
    /// A panic in here is a pre-append failure by definition, so it must not
    /// take the shard with it: `later_append_allowed_before_recovery` is true
    /// for every step 1-3 row of the frozen oracle, and a dead writer thread
    /// makes that false no matter what the error says.
    fn prepare_caught(
        &mut self,
        transaction: &Arc<ValidatedTransaction>,
    ) -> Result<(Prepared, Frame), StoreError> {
        let sequence = self.journal.next_shard_sequence() + self.pending.len() as u64;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.prepare(transaction, sequence)
        })) {
            Ok(result) => result,
            Err(_) => {
                if let Some(key) = self.in_flight_reservation.take() {
                    self.release_reservation(&key);
                }
                Err(pre_append_panic_error())
            }
        }
    }

    /// Hand the reservation the newest waiter is about to depend on to that
    /// waiter, so a panic before publication releases exactly one reservation
    /// per unresolved caller.
    fn attach_newest_reservation(&mut self, key: OperationKey) {
        self.in_flight_reservation = None;
        if let Some(waiter) = self.waiters.last_mut() {
            waiter.reservation = Some(key);
        }
    }

    /// Undo a prepared-but-unpublished transaction completely: release its
    /// status reservation and restore the speculative repository state it
    /// advanced. No sequence was consumed, because sequences are assigned at
    /// publication.
    fn roll_back_prepared(&mut self, prepared: &Prepared) {
        self.release_reservation(&prepared.key);
        self.in_flight_reservation = None;
        let namespace = prepared.key.namespace;
        // The group base still holds this namespace's pre-image only if this
        // transaction is the one that recorded it; otherwise an earlier member
        // of the open group did, and its post-state is what must be restored.
        let restored = self
            .pending
            .iter()
            .rev()
            .find(|earlier| earlier.key.namespace == namespace)
            .map(|earlier| (*earlier.repo_state).clone());
        match restored {
            Some(state) => {
                self.repositories.insert(namespace, state);
            }
            None => match self.group_base.remove(&namespace) {
                Some(Some(before)) => {
                    self.repositories.insert(namespace, before);
                }
                Some(None) => {
                    self.repositories.remove(&namespace);
                }
                None => {}
            },
        }
    }

    /// Resolve the most recently registered waiter, which is the transaction
    /// currently being accepted.
    fn fail_newest_waiter(&mut self, error: StoreError) {
        if let Some(waiter) = self.waiters.pop() {
            if let Some(key) = waiter.reservation {
                self.release_reservation(&key);
            }
            waiter.completion.complete(Err(error));
        }
    }

    /// Admission, reservation, and scope 6.3 steps 1 to 3 for one new
    /// submission.
    ///
    /// Ordering inside this function is load-bearing. Every refusal that can
    /// happen must happen before the reservation is turned into a group
    /// member. `shard_sequence` is *not* consumed here: it is the tentative
    /// position `sequence` this transaction would occupy, and the journal's
    /// counter advances only at publication, once the pre-mark deadline
    /// recheck has decided which members survive. Consuming it here would make
    /// a dropped member leave a sequence hole, which poisons the shard.
    fn prepare(
        &mut self,
        transaction: &Arc<ValidatedTransaction>,
        sequence: u64,
    ) -> Result<(Prepared, Frame), StoreError> {
        let namespace = transaction.namespace;
        let key = OperationKey::new(namespace, transaction.operation_id);
        let now = now_micros();

        // The configured per-transaction ceilings, checked where a consumer's
        // input actually arrives: `submit` is the only entry point that takes
        // a caller-shaped transaction, and the codec's static maxima are a
        // hostile-decode bound, not an operator's configuration. Refused before
        // anything is reserved or sequenced.
        let objects = transaction.objects.len() as u64;
        let allowed_objects = u64::from(self.shared.options.max_objects_per_transaction);
        if objects > allowed_objects {
            return Err(StoreError::LimitExceeded {
                limit: "max_objects_per_transaction",
                observed: objects,
                allowed: allowed_objects,
            });
        }
        let refs = transaction.refs.len() as u64;
        let allowed_refs = u64::from(self.shared.options.max_refs_per_transaction);
        if refs > allowed_refs {
            return Err(StoreError::LimitExceeded {
                limit: "max_refs_per_transaction",
                observed: refs,
                allowed: allowed_refs,
            });
        }

        // Decision 9.8 ordering, first rule: a committed or expired operation
        // is answered from the committed root and never touches the status
        // root. The answer itself — returning the durable receipt to a
        // retrying caller — is deliverable 7.
        if self.shared.committed.load().terminal_status(&key).is_some() {
            return Err(StoreError::NotImplemented(
                "submit idempotency against an already committed operation — B1 NamespaceTxn, \
                 scope 6-B1 deliverable 7",
            ));
        }

        // Plan §5.3: at a hard ceiling the shard seals synchronously **before
        // admitting more work**. Here, and not after publishing, because this is
        // the last point at which a refusal has reserved and sequenced nothing —
        // a seal that fails partway through has to poison, and poisoning a shard
        // that has just accepted a transaction owes that caller an answer it can
        // no longer give.
        self.seal_index_if_required(transaction)?;

        // The reservation is what makes two concurrent submissions of one
        // operation ID resolvable at all. It happens before sequencing, so a
        // refusal here has consumed nothing.
        self.reserve(key, transaction, now)?;

        // Everything from here on releases the reservation on failure. Scope
        // 6.3 steps 1-3 fail definitively and pre-append, and leaving a
        // `Pending` entry behind would report `Pending` forever for an
        // operation the oracle calls definitively absent.
        match self.sequence_into_frame(transaction, sequence, now) {
            Ok(pair) => Ok(pair),
            Err(error) => {
                self.release_reservation(&key);
                Err(error)
            }
        }
    }

    /// Scope 6.3 steps 1 to 3 and the frame they feed, for a transaction whose
    /// reservation already exists.
    ///
    /// Called both by `prepare` for a new submission and by `reform_group` for
    /// a member being re-sequenced after an earlier member was dropped. There
    /// is exactly one of these because the repair path must produce bytes
    /// indistinguishable from the ones the first pass would have produced at
    /// the same position; two implementations of "sequence, chain, sign, encode"
    /// is precisely how a repaired suffix acquires a signature over a chain
    /// that no longer exists.
    fn sequence_into_frame(
        &mut self,
        transaction: &Arc<ValidatedTransaction>,
        shard_sequence: u64,
        now: i64,
    ) -> Result<(Prepared, Frame), StoreError> {
        let namespace = transaction.namespace;
        let key = OperationKey::new(namespace, transaction.operation_id);
        let state = self.speculative_state(transaction)?;
        let sequenced = self.sequence_and_sign(transaction, &state, now)?;

        let payload = sequenced.payload.encode_canonical()?;
        let payload_len = payload.len() as u64;
        let total_len = frame_total_len(payload_len);

        // Rotation and sealing are not in this slice. Refusing a group that no
        // longer fits the preallocated journal here — with the exact length in
        // hand, before anything is marked `Resolving` — keeps the missing
        // deliverable a clean pre-append refusal rather than a `LimitExceeded`
        // discovered between the `Resolving` mark and the fence.
        if !self
            .journal
            .fits(self.builder.bytes().saturating_add(total_len))
        {
            return Err(StoreError::NotImplemented(
                "active journal rotation and sealing — B1 NamespaceTxn, scope 6-B1 \
                 deliverable 1 and scope 3.4",
            ));
        }

        let frame = Frame {
            header: FrameHeader {
                flags: 0,
                total_len,
                journal_id: self.journal.journal_id(),
                shard_sequence,
                repo_sequence: sequenced.receipt.repo_sequence,
                namespace: *key.namespace.as_bytes(),
                operation_id: *key.operation_id.as_bytes(),
                operation_digest: transaction.operation_digest,
                payload_len,
                // Derived by `Frame::encode`; carried here so the value this
                // writer holds is the value that reaches the device.
                payload_digest: crate::format::digest(
                    crate::format::FRAME_PAYLOAD_DIGEST_DOMAIN,
                    &payload,
                ),
            },
            payload,
        };

        // The speculative state of scope 6.3 step 1 advances here, not at
        // publication: every later member of the forming group must check its
        // preconditions against every earlier accepted one.
        //
        // The pre-image is recorded the first time the open group touches a
        // namespace, and it is the *only* way back: the pre-mark deadline
        // recheck can drop any member, and every retained member after it has
        // to be re-derived from the state that member saw, not from the state
        // the dropped member left.
        self.group_base
            .entry(namespace)
            .or_insert_with(|| self.repositories.get(&namespace).cloned());
        self.repositories
            .insert(namespace, (*sequenced.repo_state).clone());

        Ok((
            Prepared {
                key,
                operation_digest: sequenced.operation_digest,
                retry_until_micros: sequenced.retry_until_micros,
                first_visible_at_micros: sequenced.first_visible_at_micros,
                shard_sequence,
                repo_state: sequenced.repo_state,
                objects: sequenced.objects,
                receipt: sequenced.receipt,
                transaction: Arc::clone(transaction),
            },
            frame,
        ))
    }

    fn speculative_state(
        &self,
        transaction: &ValidatedTransaction,
    ) -> Result<RepoState, StoreError> {
        let namespace = transaction.namespace;
        let existing = self.repositories.get(&namespace);

        if let Some(genesis) = transaction.create_genesis_authority {
            if let Some(existing) = existing {
                // Plan §4 identity invariant 2: the binding is permanent.
                return Err(StoreError::Conflict(format!(
                    "namespace {} is already bound to genesis {}; refusing to rebind to {}",
                    namespace.to_hex(),
                    hex::encode(existing.genesis_authority.0),
                    hex::encode(genesis.0)
                )));
            }
            return Ok(RepoState {
                repo_sequence: 0,
                // Zero, not the genesis: `old_authority` in the event and
                // `expected_authority` in the frame are the same fact written
                // twice, and a create transaction's expected authority is
                // nothing. Seeding this with the genesis would make the two
                // copies disagree in every init frame the store ever writes.
                current_authority: ObjectId([0u8; 32]),
                genesis_authority: genesis,
                refs: TypedRefMap::new(),
                lifecycle: NamespaceLifecycle::Active,
                storage_mode: NamespaceStorageMode::Full,
                previous_event_digest: ObjectId([0u8; 32]),
            });
        }

        let existing = existing.ok_or_else(|| {
            StoreError::Conflict(format!(
                "namespace {} is not bound; a transaction that does not create a repository \
                 cannot be the first one in it",
                namespace.to_hex()
            ))
        })?;
        if !matches!(existing.lifecycle, NamespaceLifecycle::Active) {
            return Err(StoreError::Conflict(format!(
                "namespace {} does not admit mutation in lifecycle {:?}",
                namespace.to_hex(),
                existing.lifecycle
            )));
        }
        Ok(existing.clone())
    }

    /// Scope 6.3 steps 2 and 3, and the mutable-precondition half of step 1.
    ///
    /// The signer is called inline and in repository-sequence order, so no
    /// speculative suffix can exist to repair: each member is chained, signed,
    /// and sequenced completely before the next is looked at. Moving signing
    /// onto its own bounded pool (deliverable 5) is what introduces
    /// out-of-order completion, and with it the suffix re-chaining that
    /// deliverable owns.
    fn sequence_and_sign(
        &mut self,
        transaction: &ValidatedTransaction,
        before: &RepoState,
        now: i64,
    ) -> Result<Sequenced, StoreError> {
        let namespace = transaction.namespace;
        let creates = transaction.create_genesis_authority.is_some();

        // Mutable preconditions only. Nothing here re-parses, re-hashes,
        // re-verifies a signature, or re-evaluates policy: those ran before
        // the transaction was validated, and repeating them inside the
        // mutation lane is what the sequencer exists to avoid.
        let mut refs = before.refs.clone();
        let mut applied = Vec::with_capacity(transaction.refs.len());
        for update in &transaction.refs {
            let observed = refs.get(&update.target).copied();
            if observed != update.expected {
                return Err(StoreError::Conflict(format!(
                    "typed ref CAS for {:?} in namespace {} expected {:?} but observed {:?}",
                    update.target,
                    namespace.to_hex(),
                    update.expected.map(|id| hex::encode(id.0)),
                    observed.map(|id| hex::encode(id.0))
                )));
            }
            let new = match update.mutation {
                RefMutation::Set(target) => {
                    refs.insert(update.target.clone(), target);
                    Some(target)
                }
                RefMutation::Delete => {
                    refs.remove(&update.target);
                    None
                }
            };
            applied.push(AppliedRefV1 {
                target: update.target.clone(),
                old: observed,
                new,
                force: update.force,
            });
        }

        let expected_authority = transaction
            .expected_authority
            .unwrap_or(ObjectId([0u8; 32]));
        if !creates && expected_authority != before.current_authority {
            return Err(StoreError::Conflict(format!(
                "authority CAS for namespace {} expected {} but observed {}",
                namespace.to_hex(),
                hex::encode(expected_authority.0),
                hex::encode(before.current_authority.0)
            )));
        }
        let new_authority = transaction
            .new_authority
            .unwrap_or(before.current_authority);
        if creates && Some(before.genesis_authority) != transaction.new_authority {
            // The catalog binds `current_authority` from the event's
            // `new_authority` and `genesis_authority` from the create record.
            // A create that moves the first to something other than the second
            // would bind a repository to an authority it never held.
            return Err(StoreError::Conflict(
                "a repository-create transaction must set its new authority to the genesis \
                 authority it binds"
                    .into(),
            ));
        }

        // Scope 6.3 step 3, stated once (`deadline_permits_append`) and
        // delegated to the frozen oracle rather than restated. This evaluation
        // is the one at sequencing time; the binding one runs again immediately
        // before the group is marked `Resolving`.
        deadline_permits_append(now, transaction.retry_until_micros)
            .map_err(|reason| reason.into_error(transaction.operation_id))?;

        let repo_sequence = if creates {
            0
        } else {
            before.repo_sequence.checked_add(1).ok_or_else(|| {
                StoreError::Corruption(format!(
                    "repo_sequence overflow in namespace {}",
                    namespace.to_hex()
                ))
            })?
        };

        let mut object_ids: Vec<ObjectId> = transaction.objects.iter().map(|o| o.id).collect();
        object_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        let commit_ids: Vec<ObjectId> = transaction
            .objects
            .iter()
            .filter(|object| matches!(object.object_type, ObjectType::Commit))
            .map(|object| object.id)
            .collect();

        let mut ref_states: Vec<RefStateV1> = refs
            .iter()
            .map(|(target, object)| RefStateV1 {
                target: target.clone(),
                object: *object,
            })
            .collect();
        ref_states.sort();
        let resulting_state_digest = protocol::ref_state_digest(&ref_states)
            .map_err(|e| StoreError::Corruption(format!("resulting state digest: {e}")))?;

        let committed = CommittedTransactionV1 {
            repo_id: ObjectId(*namespace.as_bytes()),
            repo_sequence,
            previous_event_digest: before.previous_event_digest,
            sequenced_at_micros: now,
            source_kind: transaction.evidence.source_kind(),
            // The evidence, never this instance's signing key. Frozen mirror
            // validation requires `destination_event.actor == source_instance`
            // for all four mirror kinds, and the administrative signing digests
            // bind `actor` directly, so `actor` is a property of the evidence
            // that this event restates. Filling it from the destination signer
            // produces an event that signs, fences and publishes, and only then
            // fails evidence verification — at a mirror, on another instance,
            // with the transaction already durable and unwithdrawable.
            actor: transaction.evidence.actor(),
            operation_id: *transaction.operation_id.as_bytes(),
            operation_digest: transaction.operation_digest,
            signed_evidence_digest: transaction
                .evidence
                .evidence_digest()
                .map_err(|e| StoreError::Corruption(format!("evidence digest: {e}")))?,
            old_authority: before.current_authority,
            new_authority,
            refs: applied.clone(),
            object_ids,
            commit_ids,
            resulting_state_digest,
        };
        let event_digest = committed
            .event_digest()
            .map_err(|e| StoreError::Corruption(format!("event digest: {e}")))?;

        // Scope 6.3 step 2. The handoff is the last thing that can fail before
        // a sequence is consumed.
        match failpoints::hit(Failpoint::EvidenceHandoffFailure) {
            FailpointAction::Continue => {}
            FailpointAction::Fail => {
                return Err(StoreError::Signer(crate::types::SignerError::Unavailable))
            }
            FailpointAction::Panic => {
                panic!("failpoint EvidenceHandoffFailure panicked the sequencer")
            }
            FailpointAction::HardExit => {
                unreachable!("HardExit calls _exit(3) inside failpoints::hit and never returns")
            }
        }
        let source_key_epoch = self.shared.signer.key_epoch();
        let durability_result = DurabilityResultV1::LocallyDurable;
        // The signature must be the one `SignedCommittedTransactionV1::verify`
        // checks, so it covers that type's signing digest — which binds the
        // key epoch and the durability result around the canonical event —
        // rather than the bare event digest. A frame carrying a signature over
        // anything else would be durable, correctly fenced, and verifiable
        // against nothing.
        let signing_digest = SignedCommittedTransactionV1::signing_digest(
            &committed,
            source_key_epoch,
            &durability_result,
        )
        .map_err(|e| StoreError::Corruption(format!("event signing digest: {e}")))?;
        let source_signature = self.shared.signer.sign_event(&ObjectId(signing_digest))?;

        let objects_new = transaction.objects.len() as u64;
        let receipt = CommitReceipt {
            operation_id: transaction.operation_id,
            repo_sequence,
            current_authority: new_authority,
            refs: applied,
            objects_new,
        };

        Ok(Sequenced {
            operation_digest: transaction.operation_digest,
            retry_until_micros: transaction.retry_until_micros,
            first_visible_at_micros: now,
            repo_state: Arc::new(RepoState {
                repo_sequence,
                current_authority: new_authority,
                genesis_authority: before.genesis_authority,
                refs,
                lifecycle: before.lifecycle,
                storage_mode: before.storage_mode,
                previous_event_digest: event_digest,
            }),
            objects: transaction
                .objects
                .iter()
                .map(|object| (object.id, object_type_code(object.object_type)))
                .collect(),
            receipt,
            payload: TransactionFramePayloadV1 {
                repository_create: repository_create(transaction)?,
                objects: FrameObjectsV1::Inline(
                    transaction
                        .objects
                        .iter()
                        .map(|object| FrameObjectV1 {
                            object_type: object.object_type,
                            object_id: object.id,
                            raw: object.raw.clone(),
                        })
                        .collect(),
                ),
                ref_cas: transaction.refs.clone(),
                expected_authority,
                new_authority,
                evidence: transaction.evidence.clone(),
                committed: SignedCommittedTransactionV1 {
                    transaction: committed,
                    source_key_epoch,
                    durability_result,
                    source_signature,
                },
                receipt: FrameReceiptFieldsV1 {
                    objects_new,
                    retry_until_micros: transaction.retry_until_micros,
                    first_receipt_visibility_micros: now,
                },
            },
        })
    }

    // -----------------------------------------------------------------------
    // Publication: scope 6.3 steps 4 to 9
    // -----------------------------------------------------------------------

    fn publish_open_group(&mut self) {
        if self.builder.is_empty() {
            debug_assert!(self.pending.is_empty());
            return;
        }
        // Scope 6.3 step 3, in the position the ordering actually requires:
        // immediately before the group is marked `Resolving`, not back at
        // sequencing time. Between the two sit the signer handoff and the whole
        // idle delay that closes an unfull group, either of which can be longer
        // than what remains of a caller's signed deadline.
        let (frames, pending) = self.close_group();
        if frames.is_empty() {
            debug_assert!(pending.is_empty());
            return;
        }
        debug_assert_eq!(frames.len(), pending.len());
        // The oldest `pending.len()` waiters are this group's. A transaction
        // being accepted when a full group forced this publication is newer
        // than all of them and stays registered.
        debug_assert!(self.waiters.len() >= pending.len());

        // Steps 4-8 are the poison window and the waiters say so *before* it is
        // entered, so a panic inside is classified by the phase the request is
        // in rather than by where the catch happens to sit.
        for waiter in self.waiters.iter_mut().take(pending.len()) {
            waiter.phase = WaiterPhase::Publishing;
        }

        let keys: Vec<OperationKey> = pending.iter().map(|prepared| prepared.key).collect();
        let outcome = self.publish_window(&frames, &pending, &keys);
        match outcome {
            Ok(()) => {
                // Step 8 removed the status entries, so the reservations are no
                // longer this waiter's to release, and the receipt is the only
                // outcome that remains truthful.
                for (prepared, waiter) in pending.iter().zip(self.waiters.iter_mut()) {
                    waiter.reservation = None;
                    waiter.phase = WaiterPhase::Committed(prepared.receipt.clone());
                }
                self.wake_committed_group(pending.len());
            }
            Err(error) => {
                // Scope 3.7: steps 4 to 8 are the poison window. The shard is
                // read-only from here, the group's status entries stay
                // `Resolving` because step 8 never ran, and nothing is
                // appended, published, or acknowledged until a close and
                // reopen through recovery.
                self.poison = Some(error.clone());
                for waiter in self.waiters.drain(..pending.len()) {
                    waiter.completion.complete(Err(error.clone()));
                }
            }
        }
    }

    /// Scope 6.3 steps 9 and 10, which cannot poison.
    ///
    /// The transaction is committed: the fence succeeded and the root
    /// published. So this has its own unwind boundary — a panic here must not
    /// kill the writer, because the frozen oracle says
    /// `later_append_allowed_before_recovery` for this row and a dead writer
    /// thread makes that false whatever the error says. The waiters are still
    /// owned by `self` while the failpoint fires, so a caught panic can still
    /// hand every one of them the receipt it is owed.
    fn wake_committed_group(&mut self, members: usize) {
        let hung = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            match failpoints::hit(Failpoint::AfterRootCasBeforeWaiterWake) {
                // Deliberately a hung request and not an error: scope 6.3 says
                // a waiter that never wakes is a hung request, never an absent
                // transaction, and the receipt stays queryable either way.
                FailpointAction::Fail => true,
                FailpointAction::Continue => false,
                FailpointAction::Panic => {
                    panic!("failpoint AfterRootCasBeforeWaiterWake panicked the writer thread")
                }
                FailpointAction::HardExit => {
                    unreachable!("HardExit calls _exit(3) inside failpoints::hit and never returns")
                }
            }
        }));

        // Charter item 6: every outcome named, no catch-all. `hung` being
        // `Err` is a caught panic, which is a *harder* reason to deliver the
        // receipt than an ordinary return, not a reason to skip it.
        let deliver = !matches!(hung, Ok(true));
        for waiter in self.waiters.drain(..members) {
            match waiter.phase {
                WaiterPhase::Committed(receipt) => {
                    if deliver {
                        waiter.completion.complete(Ok(receipt));
                    }
                }
                WaiterPhase::PreAppend | WaiterPhase::Publishing => unreachable!(
                    "every member of a published group was marked Committed before the wake"
                ),
            }
        }
    }

    /// Close the open group, applying scope 6.3 step 3 to every member.
    ///
    /// A member past its signed deadline appends nothing. Because signing
    /// covers `SignedCommittedTransactionV1::signing_digest`, which commits to
    /// the chained `previous_event_digest`, dropping one member invalidates
    /// every signature after it — so the retained suffix is not patched, it is
    /// re-derived: restored to the state the group started from and then
    /// re-sequenced, re-chained, re-signed, and re-encoded in order. A partial
    /// repair would produce a durable, correctly fenced frame carrying a
    /// signature that verifies against nothing, which no later recovery can
    /// detect.
    fn close_group(&mut self) -> (Vec<Frame>, Vec<Prepared>) {
        let frames = self.builder.take();
        let pending = std::mem::take(&mut self.pending);
        let base = std::mem::take(&mut self.group_base);
        let now = now_micros();

        if pending
            .iter()
            .all(|prepared| deadline_permits_append(now, prepared.retry_until_micros).is_ok())
        {
            return (frames, pending);
        }

        // Back to the state the group started from, so every retained member is
        // re-derived against exactly what it would have seen had the dropped
        // members never been accepted.
        for (namespace, before) in base {
            match before {
                Some(state) => {
                    self.repositories.insert(namespace, state);
                }
                None => {
                    self.repositories.remove(&namespace);
                }
            }
        }

        let base_sequence = self.journal.next_shard_sequence();
        let mut new_frames = Vec::with_capacity(pending.len());
        let mut new_pending: Vec<Prepared> = Vec::with_capacity(pending.len());
        // Index into `self.waiters` of the member currently being re-derived.
        // The group's waiters are its oldest `pending.len()`, in order, and a
        // dropped member's waiter is removed at this cursor so the survivors
        // stay aligned with `new_pending`.
        let mut cursor = 0usize;

        for prepared in pending {
            let key = prepared.key;
            let transaction = Arc::clone(&prepared.transaction);
            let next_sequence = base_sequence + new_pending.len() as u64;
            let outcome = deadline_permits_append(now, prepared.retry_until_micros)
                .map_err(|reason| reason.into_error(key.operation_id))
                .and_then(|()| self.sequence_into_frame(&transaction, next_sequence, now));
            match outcome {
                Ok((reprepared, frame)) => {
                    new_frames.push(frame);
                    new_pending.push(reprepared);
                    cursor += 1;
                }
                Err(error) => {
                    // Pre-append and definitive: no sequence was consumed, the
                    // reservation goes, and the caller learns its transaction
                    // is absent rather than waiting on a frame that will never
                    // be written.
                    self.release_reservation(&key);
                    let waiter = self.waiters.remove(cursor);
                    waiter.completion.complete(Err(error));
                }
            }
        }

        // `sequence_into_frame` repopulated the base for a group that is
        // closing right now; the next group starts from a clean one.
        self.group_base.clear();
        (new_frames, new_pending)
    }

    /// Scope 6.3 steps 4 through 8. Every failure inside poisons the shard.
    fn publish_window(
        &mut self,
        frames: &[Frame],
        pending: &[Prepared],
        keys: &[OperationKey],
    ) -> Result<(), StoreError> {
        // The journal's sequence counter advances here and nowhere else.
        // `prepare` computes a member's position but consumes nothing, because
        // the pre-mark deadline recheck above may drop members and a consumed
        // sequence that never appends is a hole that poisons the shard. By this
        // point the retained set is final, so consuming is safe and the
        // assertion below is what proves the two agree.
        for frame in frames {
            let assigned = self.journal.assign_shard_sequence();
            if assigned != frame.header.shard_sequence {
                return Err(self.poison_error(format!(
                    "the journal assigned shard_sequence {assigned} where the closed group \
                     carried {}",
                    frame.header.shard_sequence
                )));
            }
        }

        // --- step 4: mark every operation in the group Resolving -----------
        self.mark_resolving(pending)?;
        fire_in_poison_window(self.shard_index, Failpoint::AfterMarkedResolving)?;

        // --- step 5: exact reserved frames, one fence ----------------------
        let sequences = self.journal.append_group_and_fence(frames)?;
        if sequences.len() != pending.len() {
            return Err(self.poison_error(format!(
                "append returned {} sequences for a group of {}",
                sequences.len(),
                pending.len()
            )));
        }

        // --- step 6: build the immutable shard subtree ---------------------
        fire_in_poison_window(self.shard_index, Failpoint::DuringCommittedRootBuild)?;
        let subtree = self.build_subtree(pending)?;
        fire_in_poison_window(
            self.shard_index,
            Failpoint::AllocationFailureBeforePublication,
        )?;

        // --- step 7: CAS-publish the committed root ------------------------
        fire_in_poison_window(self.shard_index, Failpoint::BeforeRootCas)?;
        self.publish_subtree(&subtree)?;

        #[cfg(test)]
        probe::fire(&self.shared, keys);

        // --- step 8: remove the group's status entries ---------------------
        //
        // Strictly after step 7 and never before. `ArcSwap`'s store is a
        // release operation and its load is an acquire, so a reader that
        // observes the status root without these entries has synchronized
        // with this removal and cannot then read a committed root older than
        // the publication above. The explicit fence makes the dependency
        // between the two swaps a statement rather than an inherited property
        // of the crate that implements them.
        fence(Ordering::Release);
        self.remove_status_entries(keys);
        Ok(())
    }

    fn mark_resolving(&self, pending: &[Prepared]) -> Result<(), StoreError> {
        loop {
            let current = self.shared.status.load();
            let mut next = OperationStatusRoot::clone(&current);
            for prepared in pending {
                next = next
                    .replace_existing(
                        prepared.key,
                        StatusEntry::resolving(
                            prepared.operation_digest,
                            prepared.retry_until_micros,
                            Some(prepared.shard_sequence),
                        ),
                    )
                    .ok_or_else(|| {
                        // The reservation was made by this thread before
                        // sequencing and nothing else may remove or rebind it.
                        self.poison_error(format!(
                            "operation {} lost its status reservation before append",
                            prepared.key.operation_id.to_hex()
                        ))
                    })?;
            }
            let next = Arc::new(next);
            // The root that was just published, never the one it replaced.
            // Recording `current` makes occupancy lag every insertion and every
            // removal by one publication, which is a metric that is wrong in
            // exactly the direction that hides an approach to the ceiling.
            let previous = self
                .shared
                .status
                .compare_and_swap(&current, Arc::clone(&next));
            if Arc::ptr_eq(&previous, &current) {
                self.shared.status_metrics.record_published(&next);
                return Ok(());
            }
        }
    }

    fn build_subtree(&self, pending: &[Prepared]) -> Result<ShardSubtree, StoreError> {
        let mut delta = IndexDelta::from_options(&self.shared.options);
        // The device offsets the fence just made durable, read back from the
        // journal rather than predicted, so an index location can only ever
        // name bytes that are actually there.
        let index = self.journal.frame_index();
        let appended = &index[index.len() - pending.len()..];
        for (prepared, (sequence, offset, len)) in pending.iter().zip(appended) {
            if *sequence != prepared.shard_sequence {
                return Err(self.poison_error(format!(
                    "journal recorded sequence {sequence} where the group carried {}",
                    prepared.shard_sequence
                )));
            }
            let frame_len = u32::try_from(*len).map_err(|_| StoreError::LimitExceeded {
                limit: "frame_len",
                observed: *len,
                allowed: u64::from(u32::MAX),
            })?;
            for (object, object_type) in &prepared.objects {
                delta.insert(
                    IndexKey::new(prepared.key.namespace, *object),
                    IndexLocation {
                        segment_generation: self.tail_generation,
                        frame_offset: *offset,
                        frame_len,
                        object_type: *object_type,
                        shard_sequence: *sequence,
                    },
                )?;
            }
        }

        let mut repositories = RepoMap::new();
        let mut terminal_statuses = TerminalStatusMap::new();
        for prepared in pending {
            // In group order, so a group touching one repository twice leaves
            // the later state.
            repositories.insert(prepared.key.namespace, Arc::clone(&prepared.repo_state));
            terminal_statuses.insert(
                prepared.key,
                TerminalStatusEntry::Committed(RetainedReceipt {
                    operation_digest: prepared.operation_digest,
                    receipt: prepared.receipt.clone(),
                    shard_sequence: prepared.shard_sequence,
                    retry_until_micros: prepared.retry_until_micros,
                    first_visible_at_micros: prepared.first_visible_at_micros,
                    // Computed by the frozen protocol function, never
                    // restated: the store and the wire must not be able to
                    // disagree about when a receipt stops being visible.
                    receipt_visible_until_micros: protocol::receipt_visible_until(
                        prepared.retry_until_micros,
                        prepared.first_visible_at_micros,
                        self.shared.options.terminal_status_grace_micros,
                    )
                    .map_err(|e| StoreError::Corruption(format!("receipt visibility: {e}")))?,
                }),
            );
        }

        let last = pending
            .last()
            .map(|prepared| prepared.shard_sequence)
            .ok_or_else(|| self.poison_error("published an empty group".into()))?;

        Ok(ShardSubtree::new(
            self.shard_index,
            last,
            Arc::new(delta),
            None,
            Vector::new(),
            repositories,
            terminal_statuses,
            // No new generation: the active journal these frames landed in is
            // already pinned by the generation recovery installed.
            GenerationMap::new(),
        ))
    }

    /// This shard's unsealed index backlog, as one captured root reports it.
    fn unsealed_backlog(&self, root: &CommittedRoot) -> UnsealedBacklog {
        let mut backlog = UnsealedBacklog::default();
        for layer in root.index().delta_layers() {
            if layer.shard_index != self.shard_index {
                continue;
            }
            backlog.layers += 1;
            backlog.entries += layer.delta.len();
            // Summed rather than deduplicated: two layers holding the same key
            // are counted twice, so the total is an over-estimate and the
            // decision it feeds can only ever seal *early*. Deduplicating would
            // mean merging every layer on every admission.
            backlog.encoded_bytes += layer.delta.encoded_bytes();
            backlog.through_shard_sequence = backlog
                .through_shard_sequence
                .max(layer.through_shard_sequence);
        }
        backlog
    }

    /// The index a reopen of this shard would have to rebuild, **including** work
    /// that is admitted but not yet published.
    ///
    /// Three sources, and leaving out any one of them was a way to overshoot:
    ///
    /// - sealed runs and unsealed layers, which the published root reports;
    /// - the open group, whose members have been admitted and will publish;
    /// - the transaction being admitted right now.
    ///
    /// The last two are the reason this takes an incoming shape rather than
    /// reading the root alone. A root-only check passes on the state *before*
    /// the transaction it is deciding about, so a two-object transaction against
    /// a one-object ceiling committed and then failed to reopen.
    ///
    /// Namespaces are counted because the encoding pays a section header per
    /// namespace and the byte ceiling is measured in encoded bytes. Both figures
    /// over-estimate — an object rewritten in two groups is counted twice, and a
    /// namespace already present is re-counted if it is in the open group — so
    /// the decision can only ever refuse early.
    fn replayable_index(
        &self,
        root: &CommittedRoot,
        backlog: &UnsealedBacklog,
        incoming: Option<&ValidatedTransaction>,
    ) -> (u64, u64) {
        let sealed: u64 = root
            .retained_generations()
            .values()
            .filter(|generation| generation.id.shard_index == self.shard_index)
            .flat_map(|generation| generation.index_runs.iter())
            .map(|retained| retained.run().entry_count())
            .sum();
        let open_group: u64 = self
            .pending
            .iter()
            .map(|prepared| prepared.objects.len() as u64)
            .sum();
        let admitting = incoming.map_or(0, |transaction| transaction.objects.len() as u64);
        let entries = sealed + backlog.entries + open_group + admitting;

        // Every namespace this shard owns, from the published root, plus the
        // ones only the open group and the incoming transaction know about.
        let shard_count = self.shared.shard_count;
        let mut namespaces: std::collections::BTreeSet<NamespaceId> = root
            .repositories()
            .keys()
            .copied()
            .filter(|namespace| StoreOptions::shard_of(namespace, shard_count) == self.shard_index)
            .collect();
        namespaces.extend(self.pending.iter().map(|prepared| prepared.key.namespace));
        if let Some(transaction) = incoming {
            namespaces.insert(transaction.namespace);
        }
        (
            entries,
            crate::index::encoded_bytes_for(entries, namespaces.len() as u64),
        )
    }

    /// The newest shard sequence a run may claim to cover.
    ///
    /// An `IndexLocation` names a **logical generation**, and a run is the first
    /// thing in this store that persists one across a session. That is only sound
    /// while the generation it names is stable across an open, and since contract
    /// review 2026-07-30-A two kinds are: a **segment**, which the manifest pins
    /// by name, and the **active tail**, whose identity is derived from the
    /// manifest's committed prefix rather than from a counter over artifacts, and
    /// which the segment recovery seals it into now inherits. Moving frames from
    /// `active/` to `segments/` changes where they are, not what they are called,
    /// so a run may cover the frames of the session that wrote them.
    ///
    /// Coverage therefore stops at the first layer holding an entry the root
    /// resolves to neither — an oldest-first prefix rather than a filter, because
    /// the discard is expressed as "everything through sequence N": covering a
    /// later layer while skipping an earlier one would discard the earlier one
    /// too.
    ///
    /// # What still bounds this
    ///
    /// A tail's identity can be *occupied* by an orphan `.seg` from an
    /// interrupted seal, and recovery must then rename the frames. Rather than
    /// leave a published run naming a generation nothing pins, recovery refuses
    /// the open (contract review 2026-07-30-B), so the unsound state this
    /// function used to avoid by restricting coverage is now avoided by
    /// refusing to produce it. The closure — recovery discarding such a run
    /// instead of refusing — is scope §6.5, with the checkpointing work.
    ///
    /// Separately and unrelated to identity: sealing moves no frame out of
    /// `active/`, so the replay ceiling below still bounds admission until
    /// `StoreEngine::checkpoint` can advance the committed prefix.
    fn coverable_through(&self, root: &CommittedRoot) -> Option<u64> {
        let mut covered = None;
        for layer in root.index().delta_layers().iter().rev() {
            if layer.shard_index != self.shard_index {
                continue;
            }
            let stable = layer.delta.iter().all(|(_, location)| {
                matches!(
                    root.object_source(self.shard_index, location.segment_generation),
                    Ok(Some(
                        crate::roots::RetainedObjectSource::Segment(_)
                            | crate::roots::RetainedObjectSource::ActiveTail(_)
                    ))
                )
            });
            if !stable {
                break;
            }
            covered = Some(layer.through_shard_sequence);
        }
        covered
    }

    /// Seal when the accumulated delta has reached a hard ceiling (scope 3.6).
    ///
    /// Two ceilings, because the backlog has two costs. `delta_pressure` answers
    /// for entries and bytes — the memory the unsealed delta occupies — through
    /// the same function `IndexDelta::pressure` uses, so the watermark has one
    /// implementation. The layer *count* is the other cost: every layer is a map
    /// a lookup consults before it reaches any run, so a million single-object
    /// groups would leave lookup fan-out unbounded while entry pressure stayed
    /// low. `max_index_runs` bounds it, which is the ceiling the refusal this
    /// replaced already used for exactly that reason.
    fn seal_index_if_required(
        &mut self,
        incoming: &ValidatedTransaction,
    ) -> Result<(), StoreError> {
        let root = self.shared.committed.load();
        let backlog = self.unsealed_backlog(&root);
        // Only the *seal* depends on there being a backlog. The replayability
        // checks below must run on every admission: once a seal has emptied the
        // layers, everything a reopen would rebuild lives in the run it just
        // wrote, and returning early here admitted work against a ceiling that
        // was already full — the store accepted it and then could not reopen.
        let entries_or_bytes = delta_pressure(
            backlog.entries,
            backlog.encoded_bytes,
            self.shared.options.max_active_index_entries,
            self.shared.options.max_active_index_bytes,
        ) == DeltaPressure::SealRequired;
        let fan_out = backlog.layers as u64 >= u64::from(self.shared.options.max_index_runs);
        if backlog.layers != 0 && (entries_or_bytes || fan_out) {
            // Only what a run may soundly persist; see `coverable_through`. When
            // nothing is coverable the seal does not happen and the ceiling check
            // below refuses instead, which is the honest outcome — a run over
            // active-journal locations would be unreadable after the next open.
            if let Some(covered_through) = self.coverable_through(&root) {
                self.seal_index(&root, covered_through)?;
            }
        }

        // What a reopen would have to rebuild, checked **after** the seal so a
        // seal that was due still happens.
        //
        // Sealing moves entries out of the delta layers and into a run, but it
        // does not move a single *frame* out of `active/`. The manifest's
        // `committed_shard_sequence` advances only when a checkpoint or a segment
        // rotation makes a prefix durable elsewhere, and neither happens in this
        // slice — so recovery replays every frame this shard ever wrote, into one
        // delta bounded by `max_active_index_entries`. A shard that kept
        // accepting work past that point would be writing a store it could not
        // reopen, and would find out at the next open.
        //
        // Refusing makes that a refusal instead of a corrupt outcome, and it is
        // not conservative padding: recovery's delta holds at most
        // `max_active_index_entries`, and every admitted transaction adds at
        // least one object.
        //
        // The consequence is worth stating plainly, because it bounds what this
        // slice delivers: a seal triggered by **entry pressure** lands the shard
        // exactly on this ceiling, so the next admission is refused. Only a seal
        // triggered by the **fan-out** ceiling leaves the shard able to continue.
        // Entry-pressure sealing becomes useful when `StoreEngine::checkpoint`
        // can advance the committed prefix; until then it converts an
        // unreopenable store into an honest refusal, which is all it can do.
        let root = self.shared.committed.load();
        let backlog = self.unsealed_backlog(&root);
        let (entries, bytes) = self.replayable_index(&root, &backlog, Some(incoming));
        // Recovery rebuilds into one `IndexDelta::from_options`, which refuses on
        // either ceiling, so both are checked here. Guarding only entries let a
        // run of narrow frames across many namespaces pass admission and fail to
        // reopen on `max_active_index_bytes`.
        if entries > self.shared.options.max_active_index_entries {
            return Err(StoreError::LimitExceeded {
                limit: "max_active_index_entries",
                observed: entries,
                allowed: self.shared.options.max_active_index_entries,
            });
        }
        if bytes > self.shared.options.max_active_index_bytes {
            return Err(StoreError::LimitExceeded {
                limit: "max_active_index_bytes",
                observed: bytes,
                allowed: self.shared.options.max_active_index_bytes,
            });
        }
        Ok(())
    }

    /// Seal this shard's covered delta layers into one durable run and publish
    /// it, discarding exactly what the run covers in the same CAS.
    ///
    /// # The poison boundary
    ///
    /// Everything before [`segment::install_index_run`] is pre-durable: the
    /// ceiling checks, the generation lookup, the merge and the encode all fail
    /// without having changed a byte on the device, so they are ordinary errors
    /// and the shard stays usable. From that call onward the shard poisons on any
    /// failure, including a failure the call may have made *before* writing
    /// anything — the caller cannot tell those apart, and the conservative
    /// direction is the one that refuses to keep writing against a root that may
    /// no longer describe the device. A false poison costs an operator a
    /// recovery; a missed one lets the writer continue on an ambiguous root,
    /// which is the failure this boundary exists to prevent.
    fn seal_index(&mut self, root: &CommittedRoot, covered_through: u64) -> Result<(), StoreError> {
        // Both ceilings, before anything is durable, and against the *same*
        // numbers recovery enforces when it reopens the manifest (scope 3.8). A
        // seal that passed here can always be reopened; one that bypassed them
        // would install a manifest this store could never open again.
        // This shard's runs, not the root's. Recovery enforces both ceilings
        // against one shard's manifest, so counting every shard here refused a
        // shard its first run because another shard already had one — a refusal
        // recovery would never have made.
        let owned_runs: u64 = root
            .retained_generations()
            .values()
            .filter(|generation| generation.id.shard_index == self.shard_index)
            .map(|generation| generation.index_runs.len() as u64)
            .sum();
        let projected = owned_runs + 1;
        for (limit, allowed) in [
            ("max_index_runs", self.shared.options.max_index_runs),
            (
                "max_open_index_runs",
                self.shared.options.max_open_index_runs,
            ),
        ] {
            if projected > u64::from(allowed) {
                return Err(StoreError::LimitExceeded {
                    limit,
                    observed: projected,
                    allowed: u64::from(allowed),
                });
            }
        }

        // Newest-first, skipping any key a newer layer already answered: that is
        // `LayeredObjectIndex::lookup`'s first-hit-wins rule, so the run answers
        // every covered key exactly as the layers did. Merging oldest-first would
        // instead meet `IndexDelta::insert`'s conflict check the moment one object
        // had been rewritten at a new offset — a legitimate history that would
        // then fail to seal.
        //
        // The merge target's ceilings are relaxed on purpose. Its contents are
        // already resident in the layers being merged, so the bound that matters
        // was applied when those were admitted; measuring the accumulation
        // against the configured ceiling *here* would refuse the very seal that
        // relieves it.
        let mut merged = IndexDelta::new(u64::MAX, u64::MAX);
        for layer in root.index().delta_layers() {
            if layer.shard_index != self.shard_index
                || layer.through_shard_sequence > covered_through
            {
                continue;
            }
            for (key, location) in layer.delta.iter() {
                if merged.get(&key).is_none() {
                    merged.insert(key, location)?;
                }
            }
        }

        let current_generation = root
            .retained_generations()
            .keys()
            .filter(|id| id.shard_index == self.shard_index)
            .map(|id| id.manifest_generation)
            .max()
            .ok_or_else(|| {
                // Not a poison: nothing has been written, and wedging the shard
                // for a condition that only recovery can have produced would
                // turn a diagnosable state into an outage.
                StoreError::Corruption(format!(
                    "shard {} has no retained manifest generation to seal an index run against",
                    self.shard_index
                ))
            })?;
        let next_generation = current_generation + 1;

        let root_uuid = self.shared.root_uuid;
        let run_bytes = IndexRunBuilder::new(root_uuid, next_generation, next_generation)
            .build(&merged)
            .map_err(|error| {
                StoreError::Corruption(format!("encoding index run {next_generation}: {error}"))
            })?;
        let paths = RootLayout::new(&self.shared.options.root).shard(self.shard_index);
        let manifest_retain = self.shared.options.manifest_retain;
        let counters = Arc::clone(self.journal.counters_handle());

        // --- durable from here: every failure below poisons ----------------
        let sealed = segment::install_index_run(
            &paths,
            &root_uuid,
            current_generation,
            next_generation,
            &run_bytes,
            manifest_retain,
            &counters,
        );
        let sealed = match sealed {
            Ok(sealed) => sealed,
            Err(error) => return Err(self.poison_now(format!("installing index run: {error}"))),
        };

        // Reopened from the device rather than kept from the bytes just encoded.
        // The run's checksum, header and `root_uuid` are validated by the same
        // code recovery will use, so a run that cannot be reopened is found now —
        // while the shard can still poison — instead of at the next open.
        let run = match IndexRun::open(&sealed.path, &root_uuid) {
            Ok(run) => Arc::new(run),
            Err(error) => return Err(self.poison_now(format!("reopening a sealed run: {error}"))),
        };

        // The successor generation pins what the predecessor pinned plus the new
        // run, and the predecessor's pin is released in the same publication.
        // Copying rather than referencing keeps `object_source`'s rule satisfied:
        // one logical generation may appear in several manifest generations, but
        // every occurrence must name the same path.
        let previous = root
            .retained_generations()
            .get(&GenerationId::new(self.shard_index, current_generation))
            .map(Arc::clone);
        let previous = match previous {
            Some(previous) => previous,
            None => {
                return Err(self.poison_now(format!(
                    "generation {current_generation} vanished from the root while sealing"
                )))
            }
        };
        let mut index_runs = previous.index_runs.to_vec();
        index_runs.push(RetainedIndexRun::new(sealed.path.clone(), Arc::clone(&run)));
        let successor = Arc::new(RetainedGeneration::new(
            GenerationId::new(self.shard_index, next_generation),
            Arc::clone(&previous.segments),
            index_runs.into(),
            Arc::clone(&previous.checkpoints),
            Arc::clone(&previous.active_tails),
            Arc::clone(&previous.projection_artifacts),
        ));

        let mut generations = GenerationMap::new();
        generations.insert(successor.id, successor);
        let mut sealed_runs = Vector::new();
        sealed_runs.push_back(run);
        let mut subtree = ShardSubtree::new(
            self.shard_index,
            // No frame was appended, so the shard's committed sequence is
            // unchanged. `CommittedRoot::merge` recognizes a maintenance
            // publication and does not treat the unchanged sequence as a
            // duplicate group (contract review 2026-07-29-C, amendment 3).
            root.shard_committed_sequence(self.shard_index)
                .unwrap_or(covered_through),
            Arc::new(IndexDelta::from_options(&self.shared.options)),
            Some(covered_through),
            sealed_runs,
            RepoMap::new(),
            TerminalStatusMap::new(),
            generations,
        );
        subtree
            .retained_generation_removals
            .push_back(GenerationId::new(self.shard_index, current_generation));

        if let Err(error) = self.publish_subtree(&subtree) {
            return Err(self.poison_now(format!("publishing a sealed index run: {error}")));
        }
        Ok(())
    }

    fn publish_subtree(&self, subtree: &ShardSubtree) -> Result<(), StoreError> {
        loop {
            let current = self.shared.committed.load();
            #[cfg(test)]
            probe::fire_cas_contention(&self.shared);
            let merged = Arc::new(current.merge(subtree));
            let previous = self.shared.committed.compare_and_swap(&current, merged);
            if Arc::ptr_eq(&previous, &current) {
                return Ok(());
            }
            // Another shard published between the load and the swap. Merge
            // again against the newer root; the subtree is unchanged and
            // `merge` is pure, so this is a re-merge and never a lost update.
            #[cfg(test)]
            self.shared
                .root_cas_retries
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            fire_in_poison_window(self.shard_index, Failpoint::DuringRootCasRetry)?;
        }
    }

    fn remove_status_entries(&self, keys: &[OperationKey]) {
        loop {
            let current = self.shared.status.load();
            let next = Arc::new(current.without_all(keys));
            let previous = self
                .shared
                .status
                .compare_and_swap(&current, Arc::clone(&next));
            if Arc::ptr_eq(&previous, &current) {
                self.shared.status_metrics.record_published(&next);
                return;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Status-root reservations
    // -----------------------------------------------------------------------

    fn reserve(
        &mut self,
        key: OperationKey,
        transaction: &ValidatedTransaction,
        now: i64,
    ) -> Result<(), StoreError> {
        let entry = StatusEntry::pending(
            transaction.operation_digest,
            transaction.retry_until_micros,
            PendingPhase::Sequenced,
        );
        loop {
            let current = self.shared.status.load();
            // Decision 9.8: identity is examined before capacity, and the
            // bound is enforced atomically with the insert by retrying this
            // whole reconsideration on CAS failure.
            match current.reserve(key, entry) {
                StatusReservation::Attached(_) => {
                    return Err(StoreError::NotImplemented(
                        "same-ID/same-digest coalescing onto an in-flight leader — B1 \
                         NamespaceTxn, scope 6-B1 deliverable 7",
                    ))
                }
                StatusReservation::OperationIdMismatch { .. } => {
                    return Err(StoreError::Conflict(format!(
                        "operation {} is already in flight with a different stable digest",
                        key.operation_id.to_hex()
                    )))
                }
                StatusReservation::AtCapacity { .. } => {
                    // Decision 9.8: the bound is enforced by refusal, never by
                    // eviction. Evicting a `Pending` entry would silently turn
                    // it into `Unknown`, which is a correctness change wearing
                    // a capacity policy's clothes.
                    self.shared.status_metrics.record_rejection();
                    return Err(StoreError::Overloaded {
                        limit: "max_status_entries",
                        retry_after_micros: retry_after_micros(
                            transaction.retry_until_micros,
                            now,
                            &self.shared.options,
                        ),
                    });
                }
                StatusReservation::Inserted(next) => {
                    let next = Arc::new(next);
                    let previous = self
                        .shared
                        .status
                        .compare_and_swap(&current, Arc::clone(&next));
                    if Arc::ptr_eq(&previous, &current) {
                        self.shared.status_metrics.record_published(&next);
                        // Owned by the writer until it is handed to a waiter or
                        // released, so a panic anywhere in steps 1-3 has exactly
                        // one place to look for a reservation to drop.
                        self.in_flight_reservation = Some(key);
                        return Ok(());
                    }
                }
            }
        }
    }

    /// Drop a reservation for a transaction that will definitively never
    /// append. Only legal before step 5; after it, a status entry is removed
    /// exactly once, by step 8.
    fn release_reservation(&mut self, key: &OperationKey) {
        loop {
            let current = self.shared.status.load();
            let next = Arc::new(current.without(key));
            let previous = self
                .shared
                .status
                .compare_and_swap(&current, Arc::clone(&next));
            if Arc::ptr_eq(&previous, &current) {
                self.shared.status_metrics.record_published(&next);
                if self.in_flight_reservation == Some(*key) {
                    self.in_flight_reservation = None;
                }
                return;
            }
        }
    }

    fn poison_error(&self, cause: String) -> StoreError {
        StoreError::ShardPoisoned {
            shard: self.shard_index,
            cause,
        }
    }

    /// Poison the shard **and** latch it, for a failure outside the publication
    /// window that reaches this file's other durable sequence.
    ///
    /// `poison_error` only builds the error. That is right inside
    /// `publish_window`, whose caller latches `self.poison` for the whole group;
    /// it is wrong for an index seal, which runs at admission and whose error
    /// otherwise returns to one caller and leaves the writer accepting the next
    /// transaction against a root that may no longer describe the device.
    fn poison_now(&mut self, cause: String) -> StoreError {
        let error = self.poison_error(cause);
        self.poison = Some(error.clone());
        error
    }
}

/// A [`Prepared`] that still carries its undecoded payload.
struct Sequenced {
    operation_digest: ObjectId,
    retry_until_micros: i64,
    first_visible_at_micros: i64,
    repo_state: Arc<RepoState>,
    objects: Vec<(ObjectId, u8)>,
    receipt: CommitReceipt,
    payload: TransactionFramePayloadV1,
}

/// Why scope 6.3 step 3 refused an append.
///
/// Named rather than inlined because the rule is evaluated at two points — at
/// sequencing, and again immediately before the group is marked `Resolving` —
/// and the two must be the same rule. Two copies of a deadline test are two
/// opinions about when a signed receipt expires.
enum DeadlineRefusal {
    Expired,
    AlreadyAppending,
}

impl DeadlineRefusal {
    fn into_error(self, operation: OperationId) -> StoreError {
        match self {
            Self::Expired => StoreError::Conflict(format!(
                "operation {} passed its signed deadline before append",
                operation.to_hex()
            )),
            Self::AlreadyAppending => StoreError::Corruption(
                "pre-append deadline check reported an append that had already started".into(),
            ),
        }
    }
}

/// Scope 6.3 step 3, delegated to the frozen oracle rather than restated.
///
/// Plan §7 stage 9: no operation may first append after its signed deadline.
fn deadline_permits_append(now: i64, retry_until_micros: i64) -> Result<(), DeadlineRefusal> {
    let deadline =
        oracle::deadline_expectation(now, retry_until_micros, AppendDeadlinePhase::PreAppend);
    match deadline.decision {
        DeadlineDecision::ContinuePreAppend => Ok(()),
        DeadlineDecision::RejectReceiptExpired => Err(DeadlineRefusal::Expired),
        DeadlineDecision::RemainResolving => Err(DeadlineRefusal::AlreadyAppending),
    }
}

/// Fire a failpoint inside the poison window. Every action is enumerated, so a
/// new one cannot be added without a decision here.
fn fire_in_poison_window(shard: u16, point: Failpoint) -> Result<(), StoreError> {
    match failpoints::hit(point) {
        FailpointAction::Continue => Ok(()),
        FailpointAction::Fail => Err(StoreError::ShardPoisoned {
            shard,
            cause: format!("failpoint {} inside the publication window", point.name()),
        }),
        FailpointAction::Panic => {
            panic!("failpoint {} panicked the writer thread", point.name())
        }
        FailpointAction::HardExit => {
            unreachable!("HardExit calls _exit(3) inside failpoints::hit and never returns")
        }
    }
}

fn repository_create(
    transaction: &ValidatedTransaction,
) -> Result<Option<RepositoryCreateV1>, StoreError> {
    let Some(genesis) = transaction.create_genesis_authority else {
        return Ok(None);
    };
    // The builder already refused a create whose genesis object is absent, so
    // this is the second half of that check rather than a new one: the exact
    // length and hash come from the bytes the transaction carries.
    let object = transaction
        .objects
        .iter()
        .find(|object| object.id == genesis)
        .ok_or_else(|| {
            StoreError::Corruption(
                "a repository-create transaction reached the sequencer without its genesis \
                 authority object"
                    .into(),
            )
        })?;
    Ok(Some(RepositoryCreateV1 {
        genesis_authority: genesis,
        genesis_len: object.raw.len() as u64,
        genesis_hash: object.id,
        projection: protocol::ProjectionMode::Full,
    }))
}

/// How long an overloaded caller should wait.
///
/// Bounded by what remains of the caller's own signed deadline: telling a
/// caller to retry after its receipt expires is telling it to stop.
fn retry_after_micros(retry_until_micros: i64, now: i64, options: &StoreOptions) -> u64 {
    let idle = options
        .max_group_idle
        .as_micros()
        .try_into()
        .unwrap_or(i64::MAX);
    let remaining = retry_until_micros.saturating_sub(now).max(0);
    u64::try_from(idle.min(remaining.max(0))).unwrap_or(0)
}

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_micros() as i64)
        .unwrap_or(0)
}

/// A hook fired at exactly one place: after the committed root is published
/// and before the status entries are removed.
///
/// It exists because the scope 6.3 step 7/8 ordering is otherwise only
/// observable as a race. A concurrent reader can prove the property
/// statistically, and a test over a helper would prove nothing about the path
/// that runs. Firing here lets a test assert, deterministically and on the
/// real writer, that at this instant the receipt is already in the committed
/// root *and* the status entry is still present. Moving the removal before the
/// publication fails the first half; moving the publication after the removal
/// fails the second.
///
/// `cfg(test)` only: the shipping writer has no hook, no atomic load, and no
/// indirect call here.
#[cfg(test)]
mod probe {
    use std::sync::{Arc, Mutex, MutexGuard};

    use super::{EngineShared, OperationKey};

    type Hook = Arc<dyn Fn(&EngineShared, &[OperationKey]) + Send + Sync>;
    type CasHook = Arc<dyn Fn(&EngineShared) + Send + Sync>;

    static SERIAL: Mutex<()> = Mutex::new(());
    static INSTALLED: Mutex<Option<Hook>> = Mutex::new(None);
    static CAS_CONTENTION: Mutex<Option<CasHook>> = Mutex::new(None);

    /// Exclusive use of the process-global hook, cleared on acquire.
    ///
    /// Takes the same shape as `sys::FaultSerial` and for the same reason: a
    /// lock a test *may* take is a lock a new test will not take, and a test
    /// that panics cannot run its own cleanup.
    pub(super) struct ProbeSerial(#[allow(dead_code)] MutexGuard<'static, ()>);

    pub(super) fn serial() -> ProbeSerial {
        let guard = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *INSTALLED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        *CAS_CONTENTION
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        ProbeSerial(guard)
    }

    /// Install a competing publisher that runs between the committed root's
    /// load and its compare-and-swap.
    ///
    /// Contention on that CAS is otherwise only reachable as a race, and a test
    /// that waits for one either flakes or asserts nothing. This runs inside
    /// the real `publish_subtree` loop — the production path — and only the
    /// source of the contention is synthetic.
    pub(super) fn install_cas_contention(
        _serial: &ProbeSerial,
        hook: impl Fn(&EngineShared) + Send + Sync + 'static,
    ) {
        *CAS_CONTENTION
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(hook));
    }

    pub(super) fn fire_cas_contention(shared: &EngineShared) {
        let hook = CAS_CONTENTION
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(hook) = hook {
            hook(shared);
        }
    }

    pub(super) fn install(
        _serial: &ProbeSerial,
        hook: impl Fn(&EngineShared, &[OperationKey]) + Send + Sync + 'static,
    ) {
        *INSTALLED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(hook));
    }

    pub(super) fn fire(shared: &EngineShared, keys: &[OperationKey]) {
        let hook = INSTALLED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        if let Some(hook) = hook {
            hook(shared, keys);
        }
    }
}

#[cfg(test)]
impl StoreEngine {
    /// The published committed root, for assertions the reader API cannot yet
    /// make: `RepoSnapshot` is B1 deliverable 8. This is the same immutable
    /// value every reader captures, not a private mirror of it.
    fn committed_root(&self) -> arc_swap::Guard<Arc<CommittedRoot>> {
        self.shared.committed.load()
    }
}

#[cfg(test)]
// `WriterSerial` is `crate::sys::FaultSerial` with the `failpoints` feature and
// `()` without it, so the token every test binds is a unit value in the default
// configuration. Binding it anyway is the point: the same test source must take
// the lock in the configuration where the lock exists.
#[allow(clippy::let_unit_value)]
mod tests {
    use std::future::Future;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::sync::Mutex;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    use levcs_protocol::v2::{RefTarget, TransactionEvidenceV1, TypedRefCas};

    use super::*;
    use crate::index::IndexKey;
    use crate::segment;
    use crate::transaction::StagedObject;
    use crate::types::{PrivilegedConstruction, SignerError};

    // -----------------------------------------------------------------------
    // Harness
    // -----------------------------------------------------------------------

    /// A deterministic stand-in for the injected signer.
    ///
    /// It is not Ed25519, and it does not need to be: the store never verifies
    /// a signature (plan §5.1 forbids it from deciding who may sign). What the
    /// tests need is a signature that is a pure function of the digest it was
    /// asked to cover, so a test can recompute what *should* have been signed
    /// and prove the writer signed that and not something else.
    #[derive(Default)]
    struct TestSigner {
        calls: AtomicU64,
    }

    impl TestSigner {
        fn expected_signature(digest: &ObjectId) -> [u8; 64] {
            let mut signature = [0u8; 64];
            let first = blake3::hash(digest.as_bytes());
            let second = blake3::hash(first.as_bytes());
            signature[..32].copy_from_slice(first.as_bytes());
            signature[32..].copy_from_slice(second.as_bytes());
            signature
        }
    }

    impl CommitEvidenceSigner for TestSigner {
        fn key_epoch(&self) -> u64 {
            7
        }

        fn public_key(&self) -> [u8; 32] {
            [0x5a; 32]
        }

        fn sign_event(&self, event_digest: &ObjectId) -> Result<[u8; 64], SignerError> {
            self.calls.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(Self::expected_signature(event_digest))
        }
    }

    /// Drive one future to completion on this thread.
    ///
    /// `levcs-store` starts no runtime, so its tests must not depend on one
    /// either.
    pub(super) fn block_on<F: Future>(future: F) -> F::Output {
        match block_on_until(future, Duration::from_secs(30)) {
            Some(output) => output,
            None => panic!("future did not complete within the test deadline"),
        }
    }

    /// Drive one future until it completes or the deadline passes.
    ///
    /// `None` is a real answer here rather than a failure: scope 6.3 says a
    /// failure to wake a waiter leaves a hung request, and a test that asserts
    /// that has to be able to observe the hang.
    fn block_on_until<F: Future>(future: F, deadline: Duration) -> Option<F::Output> {
        struct ThreadWaker(std::thread::Thread);
        impl Wake for ThreadWaker {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.unpark();
            }
        }

        let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        let start = std::time::Instant::now();
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return Some(output),
                Poll::Pending => {
                    let elapsed = start.elapsed();
                    if elapsed >= deadline {
                        return None;
                    }
                    std::thread::park_timeout(deadline - elapsed);
                }
            }
        }
    }

    /// Exclusive use of the process-global failpoint and fault registries.
    ///
    /// Every helper that can produce a `StoreOptions` takes one, so a test
    /// cannot reach the writer without holding it. That is deliberate and it
    /// is the Wave A `recovery_eio.rs` lesson applied one layer up: the
    /// registries are one-shot and global, so a test that merely *submits* can
    /// consume a failpoint another test armed. A comment cannot fail a build;
    /// a parameter can.
    #[cfg(feature = "failpoints")]
    pub(super) type WriterSerial = crate::sys::FaultSerial;
    #[cfg(not(feature = "failpoints"))]
    pub(super) type WriterSerial = ();

    pub(super) fn writer_serial() -> WriterSerial {
        #[cfg(feature = "failpoints")]
        {
            crate::sys::serial()
        }
    }

    fn counters() -> Arc<DurabilityCounters> {
        Arc::new(DurabilityCounters::default())
    }

    pub(super) fn options(_serial: &WriterSerial, root: &Path, shard_count: u16) -> StoreOptions {
        let mut options = StoreOptions::new(root);
        options.shard_count = shard_count;
        options.max_group_transactions = 4;
        options.max_group_bytes = 64 * 1024;
        options.max_group_idle = Duration::from_millis(50);
        options.journal_preallocate_bytes = 4 * 1024 * 1024;
        options.signer = Some(Arc::new(TestSigner::default()));
        options
    }

    /// Every writer test's root, built by the entry point a consumer calls.
    ///
    /// This used to seed the root with `segment::initialize_root` and then
    /// open it, because `StoreEngine::open` refused startup state 1. That was
    /// the charter item 8 weakening at the heart of this deliverable: the
    /// production `submit` was being exercised over a root production could
    /// not create. With state 1 implemented there is nothing left to seed —
    /// the first call initializes and every later call on the same path is
    /// state 2, which is also what makes the reopen tests below reopens rather
    /// than re-seedings.
    fn open(serial: &WriterSerial, root: &Path, shard_count: u16) -> StoreEngine {
        StoreEngine::open(options(serial, root, shard_count))
            .expect("open initializes an absent root and reopens a formatted one")
    }

    /// The client principal on whose behalf a transaction is submitted.
    ///
    /// Deliberately **not** `TestSigner`'s public key. The two were the same
    /// value, and `CommittedTransactionV1.actor` was being filled from the
    /// destination signer rather than from the evidence — a defect no assertion
    /// in this file could see, because every value it could have been was
    /// `[0x5a; 32]`. Frozen mirror validation requires
    /// `destination_event.actor == source_instance`, so the substitution
    /// produces an event that signs, fences, and publishes and only then fails
    /// verification at a mirror on another instance.
    const EVIDENCE_ACTOR: [u8; 32] = [0x7e; 32];

    pub(super) fn evidence() -> TransactionEvidenceV1 {
        TransactionEvidenceV1::AdministrativeV1 {
            actor: EVIDENCE_ACTOR,
            actor_key_epoch: 7,
            command_digest: ObjectId([0x33; 32]),
            signature: [0x44; 64],
        }
    }

    pub(super) fn deadline() -> i64 {
        now_micros() + 600_000_000
    }

    pub(super) fn genesis_object() -> StagedObject {
        StagedObject {
            id: ObjectId([0xa1; 32]),
            object_type: ObjectType::Authority,
            raw: vec![0xa1; 32],
        }
    }

    pub(super) fn create_transaction(
        namespace: NamespaceId,
        operation: u8,
    ) -> ValidatedTransaction {
        let genesis = genesis_object();
        let id = genesis.id;
        ValidatedTransaction::builder(PrivilegedConstruction::internal())
            .namespace(namespace)
            .operation(
                OperationId([operation; 16]),
                ObjectId([operation; 32]),
                deadline(),
            )
            .create_repository(id)
            .objects(vec![genesis])
            .refs(Vec::new())
            .authority(None, Some(id))
            .evidence(evidence())
            .build()
            .expect("a complete create transaction")
    }

    /// A push carrying one blob and, optionally, one typed ref update.
    pub(super) fn push_transaction(
        namespace: NamespaceId,
        operation: u8,
        blob: u8,
        reference: Option<TypedRefCas>,
    ) -> ValidatedTransaction {
        let authority = genesis_object().id;
        ValidatedTransaction::builder(PrivilegedConstruction::internal())
            .namespace(namespace)
            .operation(
                OperationId([operation; 16]),
                ObjectId([operation; 32]),
                deadline(),
            )
            .objects(vec![StagedObject {
                id: ObjectId([blob; 32]),
                object_type: ObjectType::Blob,
                raw: vec![blob; 64],
            }])
            .refs(reference.into_iter().collect())
            .authority(Some(authority), Some(authority))
            .evidence(evidence())
            .build()
            .expect("a complete push transaction")
    }

    fn set_branch(name: &str, expected: Option<ObjectId>, target: ObjectId) -> TypedRefCas {
        TypedRefCas {
            target: RefTarget::Branch(name.into()),
            expected,
            mutation: RefMutation::Set(target),
            force: false,
        }
    }

    // -----------------------------------------------------------------------
    // Startup
    // -----------------------------------------------------------------------

    /// Deliverable 1's central claim: one session, held from before the first
    /// shard's recovery until the engine is dropped.
    ///
    /// The lock is the observable. If `open` took and released a session per
    /// shard, or dropped it once recovery finished, a second `open` would
    /// succeed here — and a second process entering a recovered-but-not-yet-
    /// ready root is exactly what the single session exists to prevent.
    #[test]
    fn one_retained_session_recovers_every_shard_and_holds_the_root_lock() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let engine = open(&serial, temporary.path(), 4);

        assert!(matches!(
            StoreEngine::open(options(&serial, temporary.path(), 4)),
            Err(StoreError::AlreadyLocked)
        ));

        // Every shard was recovered, not only the one a transaction happens to
        // route to: each contributes its committed sequence and its retained
        // generation to the first published root.
        let root = engine.committed_root();
        assert_eq!(root.retained_generations().len(), 4);

        drop(engine);
        StoreEngine::open(options(&serial, temporary.path(), 4))
            .expect("the lock is released when the engine is dropped");
    }

    // -----------------------------------------------------------------------
    // Plan §5.2's startup states, one test per state
    //
    // Charter item 8: every one of these asserts against `StoreEngine::open`,
    // the entry point a consumer calls, and never against `classify_root` or
    // `segment::initialize_root` directly. A root that only `initialize_root`
    // can create is a root the production path has never been shown to build.
    // -----------------------------------------------------------------------

    /// A recursive, order-independent image of a directory tree: relative
    /// path, whether it is a directory, and the exact bytes of every file.
    ///
    /// This is what "byte-identical after the refusal" is asserted with. It
    /// deliberately captures *contents* rather than mtimes: an mtime can
    /// change for reasons outside this process, and a test that flakes on it
    /// would be retried rather than believed. What it must catch is a probe
    /// that created a directory, truncated a file, or appended a byte, and it
    /// catches all three including the empty-directory case, which a
    /// contents-only digest would miss.
    fn tree_image(root: &Path) -> Vec<(PathBuf, bool, Vec<u8>)> {
        fn walk(base: &Path, dir: &Path, out: &mut Vec<(PathBuf, bool, Vec<u8>)>) {
            let mut entries: Vec<_> = std::fs::read_dir(dir)
                .expect("read a directory of the image")
                .map(|entry| entry.expect("a directory entry").path())
                .collect();
            entries.sort();
            for path in entries {
                let relative = path
                    .strip_prefix(base)
                    .expect("every walked path is under the base")
                    .to_path_buf();
                if path.is_dir() {
                    out.push((relative, true, Vec::new()));
                    walk(base, &path, out);
                } else {
                    out.push((relative, false, std::fs::read(&path).expect("read a file")));
                }
            }
        }
        let mut image = Vec::new();
        if root.exists() {
            walk(root, root, &mut image);
        }
        image
    }

    /// State 1, absent path. The root's *name* does not exist when `open` is
    /// called, so this also covers the case in which initialization has to
    /// make a new directory entry durable in the parent.
    #[test]
    fn startup_state_1_initializes_an_absent_root_through_open() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().join("not").join("yet").join("a-root");
        assert!(!root.exists());

        let engine = StoreEngine::open(options(&serial, &root, 3))
            .expect("startup state 1 initializes an absent root");

        // Charter item 7: not "it must have fsynced", but how many times, and
        // for which entry. The total is stated as its parts so that a change to
        // any one of them fails here with its name attached.
        //
        // `segment::initialize_root` costs six directories per shard, each
        // fsynced as it is created, plus the shard directory a second time once
        // its children are durable — seven per shard — and then shards/,
        // quarantine/, the root, and the root's parent. `staging/` is created
        // and not separately fsynced, which is correct rather than missing: it
        // is empty, so the only thing that has to become durable about it is
        // its name in the root, and the root fsync is what covers that.
        let inside_initialize_root = 3 * 7 + 4;
        // The path is `<tmp>/not/yet/a-root` and none of the three exist, so
        // `open` creates three directory entries before it can take the root
        // lock — and fences each one by fsyncing the directory that names it:
        // `yet` (which names `a-root`), `not` (which names `yet`), and the
        // tempdir (which names `not`), in that order.
        //
        // This is the assertion the P1-1 finding turns on. `initialize_root`
        // fsyncs `root.parent()` and nothing above it, so before the fix this
        // number was zero and a power loss could take `not` or `yet` — and the
        // root with them — from a store that had already reported itself
        // initialized.
        let created_ancestors = 3;
        // The `INITIALIZING` marker: one fsync of the root to make its name
        // durable before the tree is built, and one more to make its removal
        // durable after `FORMAT` is installed.
        let initialization_marker = 2;
        let initialization = engine
            .shared
            .initialization
            .expect("state 1 records what it cost");
        assert_eq!(
            initialization.fdatasync, 2,
            "the INITIALIZING marker and FORMAT are each fenced exactly once"
        );
        assert_eq!(
            initialization.fsync_dir,
            created_ancestors + initialization_marker + inside_initialize_root,
            "every created ancestor, the initialization marker's install and removal, \
             every created directory, shards/, quarantine/, the root, and its parent"
        );
        assert_eq!(initialization.short_writes, 0);
        assert!(
            !root.join("INITIALIZING").exists(),
            "a finished initialization leaves no marker behind"
        );

        // The root it built is the root the production path then opens: the
        // frozen topology is the configured one, and it is readable through
        // `FORMAT` rather than assumed.
        assert_eq!(engine.shared.shard_count, 3);
        let marker = segment::read_format(&RootLayout::new(&root)).expect("FORMAT is valid");
        assert_eq!(marker.shard_count, 3);
        assert_eq!(marker.root_uuid, engine.shared.root_uuid);

        // And it is a *usable* root, not merely a well-formed one.
        let namespace = NamespaceId([0x51; 32]);
        block_on(engine.submit(create_transaction(namespace, 1)))
            .expect("a transaction commits into a root open() created");
    }

    /// P1-1, isolated from every other cost in the open.
    ///
    /// The absolute count above is the whole claim, but it is one number made
    /// of four terms, and a reader has to trust the arithmetic to believe the
    /// ancestor term is in it. This asserts the ancestor term on its own: two
    /// otherwise identical initializations whose roots differ only in how many
    /// directory entries have to be created must differ in directory fsyncs by
    /// exactly that many.
    ///
    /// Before the fix the difference was zero — `create_dir_all` made all the
    /// entries and `initialize_root` fenced one of them — so this fails without
    /// it, and it fails with a number rather than an absence.
    #[test]
    fn startup_state_1_fences_one_directory_entry_per_created_ancestor() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");

        // One new entry: the root itself, inside an existing directory.
        let shallow = temporary.path().join("shallow");
        let shallow_cost = StoreEngine::open(options(&serial, &shallow, 1))
            .expect("state 1 at depth one")
            .shared
            .initialization
            .expect("state 1 records what it cost")
            .fsync_dir;

        // Three new entries: two ancestors and the root.
        let deep = temporary.path().join("deep").join("er").join("still");
        let deep_cost = StoreEngine::open(options(&serial, &deep, 1))
            .expect("state 1 at depth three")
            .shared
            .initialization
            .expect("state 1 records what it cost")
            .fsync_dir;

        assert_eq!(
            deep_cost - shallow_cost,
            2,
            "two extra created ancestors must cost two extra directory fences; \
             everything else about the two initializations is identical"
        );
    }

    /// State 1, present but empty. Distinguished from the absent case only by
    /// who created the directory entry, and required to reach the same place.
    #[test]
    fn startup_state_1_initializes_an_existing_empty_root() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        assert_eq!(tree_image(temporary.path()), Vec::new());

        let engine = StoreEngine::open(options(&serial, temporary.path(), 1))
            .expect("an existing empty directory is startup state 1");
        assert!(engine.shared.initialization.is_some());
        assert!(temporary.path().join("FORMAT").exists());
    }

    /// State 1, and the deliberate decision inside it: a directory holding
    /// only `LOCK` is empty.
    ///
    /// This is not a hypothetical. `segment::lock_root` creates `LOCK` if it is
    /// absent, so an initialization that dies between taking the lock
    /// and the `FORMAT` rename leaves precisely this, and so does any process
    /// that merely asked whether the root was busy. Classifying it as
    /// unrecognized would wedge a root with no bytes to lose.
    #[test]
    fn startup_state_1_treats_a_root_holding_only_lock_as_empty() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let layout = RootLayout::new(temporary.path());
        drop(segment::lock_root(&layout).expect("probing the root creates LOCK"));

        let image = tree_image(temporary.path());
        assert_eq!(image.len(), 1, "exactly LOCK is present: {image:?}");
        assert_eq!(image[0].0, PathBuf::from("LOCK"));

        let engine = StoreEngine::open(options(&serial, temporary.path(), 1))
            .expect("a root holding only LOCK is still startup state 1");
        assert!(engine.shared.initialization.is_some());
    }

    /// State 1 is a mutation, so it happens under the root lock.
    ///
    /// The observable is the refusal: with `LOCK` held elsewhere, `open` on
    /// what is otherwise a state-1 root must be refused `AlreadyLocked` and
    /// must leave the root exactly as empty as it found it. An initialization
    /// that ran before locking, or without locking, would create `FORMAT` here
    /// — and two processes doing that concurrently is the race the lock
    /// exists to close.
    #[test]
    fn startup_state_1_does_not_initialize_a_root_another_process_holds() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let layout = RootLayout::new(temporary.path());
        let held = segment::lock_root(&layout).expect("take the root lock first");

        assert!(matches!(
            StoreEngine::open(options(&serial, temporary.path(), 1)),
            Err(StoreError::AlreadyLocked)
        ));
        let image = tree_image(temporary.path());
        assert_eq!(image.len(), 1, "nothing but LOCK was created: {image:?}");

        // Releasing it makes the same call succeed, so the refusal was the
        // lock and not something else about the root.
        drop(held);
        StoreEngine::open(options(&serial, temporary.path(), 1))
            .expect("the same root initializes once the lock is released");
        assert_eq!(segment::RootLock::release_failures(), 0);
    }

    /// P1-2. An initialization interrupted after it has left residue is
    /// **finished** by the next `open` rather than refused for ever.
    ///
    /// Before the fix, any crash between `segment::initialize_root`'s first
    /// `create_dir_all` and its `FORMAT` rename turned a brand-new root into a
    /// permanently unopenable one: the root was non-empty and carried no
    /// `FORMAT`, so it was refused as states 3/4 — with a message about legacy
    /// layouts and migration, for a root that had never held a byte of anyone's
    /// data.
    ///
    /// The crash is simulated, not raced: the image below is written directly,
    /// so this test has no timing in it at all. The load-bearing part of the
    /// image — the marker — is produced by *production's own* encoder, so a
    /// change to the marker format cannot leave this test passing against bytes
    /// production no longer writes. The companion test below injects the
    /// interruption into a real `open` instead, which is what proves production
    /// writes the marker at the moment this image claims it does.
    #[test]
    fn startup_state_1_resumes_an_interrupted_initialization() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().join("interrupted");

        // The crash image: the marker `open` installs as its first durable act,
        // plus as much of the tree as `segment::initialize_root` had built when
        // the power went — including a half-built shard directory, which is the
        // deepest residue the window can produce.
        std::fs::create_dir_all(root.join("quarantine")).expect("partial tree");
        std::fs::create_dir_all(root.join("staging")).expect("partial tree");
        std::fs::create_dir_all(root.join("shards").join("00").join("active"))
            .expect("partial tree");
        std::fs::write(
            root.join("INITIALIZING"),
            initializing_marker_bytes(2, now_micros()),
        )
        .expect("the marker production writes");

        let engine = StoreEngine::open(options(&serial, &root, 2))
            .expect("an interrupted initialization is finished, not refused");
        assert!(
            engine.shared.initialization.is_some(),
            "the resume is an initialization, and is recorded as one"
        );
        assert!(root.join("FORMAT").exists());
        assert!(
            !root.join("INITIALIZING").exists(),
            "the marker is removed once FORMAT is durable, so the finished root \
             classifies as state 2 and not as an interrupted one"
        );

        // Usable, not merely well-formed. A resume that produced a tree nothing
        // could commit into would satisfy every assertion above.
        let namespace = NamespaceId([0x62; 32]);
        block_on(engine.submit(create_transaction(namespace, 1)))
            .expect("a transaction commits into a resumed root");
    }

    /// P1-2's dangerous direction, asserted rather than argued.
    ///
    /// Refusing a resumable root wastes an operator's time; adopting a root
    /// that is not ours destroys their data. Each of these is one condition
    /// away from the resumable shape, and each must be refused **and left
    /// byte-identical**.
    #[test]
    fn an_unrecognized_layout_is_never_mistaken_for_an_interrupted_initialization() {
        let serial = writer_serial();
        let refuse = |label: &str, root: &Path| {
            let before = tree_image(root);
            match StoreEngine::open(options(&serial, root, 1)) {
                Err(StoreError::NotImplemented(reason)) => {
                    assert!(
                        reason.contains("startup states 3 and 4"),
                        "{label}: {reason}"
                    );
                }
                other => panic!("{label}: expected a refusal, got {other:?}"),
            }
            assert_eq!(
                tree_image(root),
                before,
                "{label}: a refused layout must be byte-identical afterwards"
            );
        };

        // The whole initialization skeleton and no marker. This is the shape
        // the classification must *not* adopt on the strength of the names
        // alone: those names are ours, but without the marker there is nothing
        // to say this directory was ever built by this store rather than
        // arranged to look like it was.
        let skeleton = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(skeleton.path().join("quarantine")).expect("skeleton");
        std::fs::create_dir_all(skeleton.path().join("staging")).expect("skeleton");
        std::fs::create_dir_all(skeleton.path().join("shards").join("00")).expect("skeleton");
        refuse("skeleton without a marker", skeleton.path());

        // A byte-exact marker with one foreign name beside it. The marker alone
        // does not authorize anything: an initialization in progress cannot
        // have produced a name this store never writes, so the foreign entry
        // means the marker is in somebody else's directory.
        let intruded = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            intruded.path().join("INITIALIZING"),
            initializing_marker_bytes(1, now_micros()),
        )
        .expect("marker");
        std::fs::create_dir_all(intruded.path().join("quarantine")).expect("skeleton");
        std::fs::write(intruded.path().join("notes.txt"), b"someone's data\n").expect("foreign");
        refuse("a valid marker with a foreign entry", intruded.path());

        // A file of exactly the marker's length, under exactly the marker's
        // name, that is not the marker. Length is not evidence; the magic is.
        let impostor = tempfile::tempdir().expect("tempdir");
        std::fs::write(impostor.path().join("INITIALIZING"), [0u8; 27]).expect("impostor");
        refuse("a same-length file that is not the marker", impostor.path());

        // The magic and nothing after it. A prefix of the marker is not the
        // marker: accepting short reads would make every truncated file in the
        // universe of this name a licence to initialize.
        let truncated = tempfile::tempdir().expect("tempdir");
        std::fs::write(truncated.path().join("INITIALIZING"), b"levcs-store-init").expect("short");
        refuse("a truncated marker", truncated.path());

        // A symlink of the marker's name, pointing at bytes that *are* a valid
        // marker. The content test passes if it is allowed to run at all, so
        // this is entirely a test of the type check: our marker is a regular
        // file in this directory, not a name that resolves to one somewhere
        // else.
        let elsewhere = tempfile::tempdir().expect("tempdir");
        let real_marker = elsewhere.path().join("borrowed-marker");
        std::fs::write(&real_marker, initializing_marker_bytes(1, now_micros())).expect("marker");
        let linked = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink(&real_marker, linked.path().join("INITIALIZING"))
            .expect("symlink");
        refuse("a symlink at the marker's name", linked.path());
    }

    /// Contract review finding P1, direction 1: **a regular file at the staging
    /// name is not this store's residue and is not destroyed.**
    ///
    /// `classify_root` used to ignore `INITIALIZING.tmp` whatever it held,
    /// because the name "can only be this code path's residue by construction"
    /// — the one claim a classifier running *in order to establish* that is not
    /// entitled to. `build_root_under_lock` then opened it `create` +
    /// `truncate`. So an otherwise-empty configured root containing an
    /// operator's file of that name lost it silently, and reported success.
    ///
    /// Every shape below is one that used to be overwritten, including the torn
    /// marker — refusing that one is the trade `install_initializing_marker`
    /// states, and it is asserted here so the trade is a fact rather than a
    /// comment.
    #[test]
    fn a_foreign_entry_at_the_initializing_staging_name_is_refused_and_left_intact() {
        let serial = writer_serial();
        let refuse = |label: &str, root: &Path| {
            let before = tree_image(root);
            match StoreEngine::open(options(&serial, root, 1)) {
                Err(StoreError::NotImplemented(reason)) => assert!(
                    reason.contains("startup states 3 and 4"),
                    "{label}: {reason}"
                ),
                other => panic!("{label}: expected a refusal, got {other:?}"),
            }
            assert_eq!(
                tree_image(root),
                before,
                "{label}: a refused root must be byte-identical afterwards"
            );
        };

        // An operator's file that happens to carry the name. This is the whole
        // finding: nothing else is in the root, so before the fix `open`
        // returned a working store and this file was gone.
        let operators = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            operators.path().join("INITIALIZING.tmp"),
            b"do not delete: staging notes for the migration\n",
        )
        .expect("operator file");
        refuse("an operator's file at the staging name", operators.path());

        // A prefix of the marker — the exact residue of a crash between the
        // create and the fence. Refused, deliberately: nothing on disk tells it
        // apart from a stranger's truncated file, so a rule that adopts this one
        // destroys that one.
        let torn = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            torn.path().join("INITIALIZING.tmp"),
            &initializing_marker_bytes(1, now_micros())[..12],
        )
        .expect("torn marker");
        refuse("a torn temporary marker", torn.path());

        // The right length and the wrong bytes, and a directory. Both are
        // "not a regular file holding our marker", and neither is a shape the
        // classifier may fold into a neighbour.
        let impostor = tempfile::tempdir().expect("tempdir");
        std::fs::write(impostor.path().join("INITIALIZING.tmp"), [0u8; 27]).expect("impostor");
        refuse("a same-length file that is not the marker", impostor.path());

        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(directory.path().join("INITIALIZING.tmp")).expect("directory");
        refuse("a directory at the staging name", directory.path());

        // A fifo, asserted without `tree_image` — deliberately, and the reason
        // is the point of the case. `tree_image` reads every entry it walks,
        // and reading a fifo with no writer blocks for ever; using it here
        // hangs the test before `open` is ever called. That is exactly the
        // hazard on the production side: anything that opens a name in an
        // unowned root before establishing its type can be stopped dead by one
        // `mkfifo`. `classify_root` checks `file_type` first and never opens
        // this entry, and `sys::open_regular_nofollow` passes `O_NONBLOCK` for
        // the path that can reach one anyway. This test completes rather than
        // timing out only because both of those hold.
        let fifo = tempfile::tempdir().expect("tempdir");
        let fifo_name = fifo.path().join("INITIALIZING.tmp");
        rustix::fs::mknodat(
            rustix::fs::CWD,
            &fifo_name,
            rustix::fs::FileType::Fifo,
            rustix::fs::Mode::from_raw_mode(0o644),
            0,
        )
        .expect("mkfifo");
        match StoreEngine::open(options(&serial, fifo.path(), 1)) {
            Err(StoreError::NotImplemented(reason)) => {
                assert!(reason.contains("startup states 3 and 4"), "{reason}")
            }
            other => panic!("a fifo at the staging name: expected a refusal, got {other:?}"),
        }
        assert!(
            std::os::unix::fs::FileTypeExt::is_fifo(
                &fifo_name
                    .symlink_metadata()
                    .expect("the fifo is still there")
                    .file_type()
            ),
            "the refusal must not have replaced the fifo with anything"
        );
        assert!(!fifo.path().join("FORMAT").exists());
    }

    /// Contract review finding P1, direction 2 and the worse one: **a symlink
    /// at the staging name must not be written through.**
    ///
    /// `create` + `truncate` follows a final symlink, so the truncation landed
    /// on a file the store had never owned and that was not even inside the
    /// configured root — and the link was then renamed onto `INITIALIZING` and
    /// unlinked, so the only evidence of what had been destroyed went with it.
    ///
    /// The assertion is on the *target*, outside the root, because that is
    /// where the damage was. `O_CREAT | O_EXCL` is what makes it impossible:
    /// it fails with `EEXIST` on a symlink whether or not the link resolves.
    #[test]
    fn a_symlink_at_the_initializing_staging_name_never_truncates_its_target() {
        let serial = writer_serial();

        let outside = tempfile::tempdir().expect("tempdir");
        let victim = outside.path().join("payroll.db");
        let contents: Vec<u8> = (0..4096u32).map(|byte| (byte % 251) as u8).collect();
        std::fs::write(&victim, &contents).expect("the file outside the root");

        let root = tempfile::tempdir().expect("tempdir");
        let link = root.path().join("INITIALIZING.tmp");
        std::os::unix::fs::symlink(&victim, &link).expect("symlink");

        match StoreEngine::open(options(&serial, root.path(), 1)) {
            Err(StoreError::NotImplemented(reason)) => {
                assert!(reason.contains("startup states 3 and 4"), "{reason}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        assert_eq!(
            std::fs::read(&victim).expect("the target still exists"),
            contents,
            "a symlink in the root must not be able to redirect a truncation at a \
             file outside it"
        );
        assert_eq!(
            std::fs::read_link(&link).expect("the link is still a link"),
            victim,
            "the link itself must not have been renamed or unlinked either — that is \
             what removed the evidence"
        );
        assert!(
            !root.path().join("FORMAT").exists(),
            "the refusal must not have initialized the root"
        );
    }

    /// The other half of the trade: a **whole** temporary marker still resumes,
    /// and is *adopted* rather than rewritten.
    ///
    /// This is the shape a crash between the fence and the `rename_noreplace`
    /// leaves, and it must not become collateral damage of the type and content
    /// checks above.
    ///
    /// "Still resumes" alone cannot fail without the fix — the old code reached
    /// the same working root by truncating the file and writing it again, which
    /// is precisely the operation that destroyed an operator's file at the same
    /// name. So the load-bearing assertion is a counter, not an outcome: two
    /// otherwise identical initializations, one from an empty root and one from
    /// a root already carrying a whole marker, must differ in durable bytes by
    /// exactly the marker's length, because the second one does not write it.
    /// Before the fix that difference was zero.
    #[test]
    fn a_whole_temporary_marker_is_adopted_rather_than_rewritten() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");

        // The control: the same initialization with nothing staged.
        let fresh = temporary.path().join("fresh");
        let fresh_bytes = StoreEngine::open(options(&serial, &fresh, 1))
            .expect("state 1 from an empty root")
            .shared
            .initialization
            .expect("state 1 records what it cost")
            .bytes_written;

        let staged = temporary.path().join("staged");
        std::fs::create_dir(&staged).expect("root");
        std::fs::write(
            staged.join("INITIALIZING.tmp"),
            initializing_marker_bytes(1, now_micros()),
        )
        .expect("staged marker");

        let engine = StoreEngine::open(options(&serial, &staged, 1))
            .expect("a whole temporary marker is this store's residue and is resumed from");
        let initialization = engine
            .shared
            .initialization
            .expect("the resume is an initialization");
        assert_eq!(
            fresh_bytes - initialization.bytes_written,
            INITIALIZING_MARKER_LEN as u64,
            "the staged marker already holds what this attempt would have written, so \
             adoption writes nothing and fences what is there; everything else about the \
             two initializations is identical"
        );
        assert_eq!(
            initialization.fdatasync, 2,
            "adoption still costs exactly the marker's fence and FORMAT's"
        );
        assert!(staged.join("FORMAT").exists());
        assert!(
            !staged.join("INITIALIZING.tmp").exists(),
            "the staging name is consumed by the rename onto INITIALIZING"
        );
        assert!(!staged.join("INITIALIZING").exists());

        let namespace = NamespaceId([0x73; 32]);
        block_on(engine.submit(create_transaction(namespace, 1)))
            .expect("a transaction commits into a root resumed from a staged marker");
    }

    /// The same hazard at the other two names this file opens or ignores.
    ///
    /// `segment::lock_root` opens `LOCK` and `segment::write_fenced` opens
    /// `FORMAT.tmp`. Both are in A1's frozen file, so neither open was changed by
    /// this deliverable; what it changed is that a root carrying a symlink at
    /// either name never reaches them, because the classification that authorizes
    /// the write refuses it first.
    ///
    /// Both have since been amended by the lead — `lock_root` in contract review
    /// 2026-07-29-A, `write_fenced` in 2026-07-29-B — because
    /// `RecoverySession::open`, `drive.rs` and `store-bench` all reach them with
    /// no classification at all. This test therefore no longer carries either
    /// guarantee on its own; it asserts that the classifier refuses first, which
    /// is still the answer an operator wants, and the assertions in `segment.rs`
    /// are what hold the opens themselves.
    #[test]
    fn a_symlink_at_lock_or_format_tmp_is_refused_before_anything_opens_it() {
        let serial = writer_serial();
        let outside = tempfile::tempdir().expect("tempdir");

        // `LOCK`, pointing at a name that does not exist. `create(true)` through
        // this link would bring a file into being outside the root.
        let absent = outside.path().join("not-there");
        let locked = tempfile::tempdir().expect("tempdir");
        std::os::unix::fs::symlink(&absent, locked.path().join("LOCK")).expect("symlink");
        match StoreEngine::open(options(&serial, locked.path(), 1)) {
            Err(StoreError::NotImplemented(reason)) => {
                assert!(reason.contains("startup states 3 and 4"), "{reason}")
            }
            other => panic!("expected a refusal for a symlinked LOCK, got {other:?}"),
        }
        assert!(
            !absent.exists(),
            "a symlinked LOCK must not create a file outside the root"
        );

        // `FORMAT.tmp`, beside a valid marker — the one arrangement that would
        // otherwise reach `segment::write_fenced`, because a `FORMAT.tmp` on its
        // own is already refused for having no marker to explain it.
        let victim = outside.path().join("ledger");
        std::fs::write(&victim, b"balances\n").expect("the file outside the root");
        let resumable = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            resumable.path().join("INITIALIZING"),
            initializing_marker_bytes(1, now_micros()),
        )
        .expect("marker");
        std::os::unix::fs::symlink(&victim, resumable.path().join("FORMAT.tmp")).expect("symlink");
        match StoreEngine::open(options(&serial, resumable.path(), 1)) {
            Err(StoreError::NotImplemented(reason)) => {
                assert!(reason.contains("startup states 3 and 4"), "{reason}")
            }
            other => panic!("expected a refusal for a symlinked FORMAT.tmp, got {other:?}"),
        }
        assert_eq!(
            std::fs::read(&victim).expect("the target still exists"),
            b"balances\n",
            "a symlink at FORMAT.tmp must not become a truncation outside the root"
        );
    }

    /// P1-2, with the interruption injected into a real `StoreEngine::open`
    /// instead of written to disk.
    ///
    /// One directory fsync is made to fail. On an existing empty root the first
    /// one `open` issues is the fence that makes the marker's *name* durable,
    /// so this stops initialization at the earliest instant that can leave
    /// residue — and proves the ordering the classification depends on: the
    /// marker is on disk and the tree is not.
    ///
    /// Deterministic, not raced: the fault registry is one-shot and positional,
    /// and this test holds the serial that makes it exclusively its own.
    #[cfg(feature = "failpoints")]
    #[test]
    fn an_interrupted_open_leaves_a_marker_the_next_open_resumes_from() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");

        crate::sys::arm(&serial, crate::sys::Fault::DirSyncEio);
        let interrupted = StoreEngine::open(options(&serial, temporary.path(), 1));
        crate::sys::disarm(&serial);
        match interrupted {
            Err(StoreError::NotImplemented(reason)) => {
                panic!("an injected I/O failure must not read as an unbuilt state: {reason}")
            }
            Err(_) => {}
            Ok(_) => panic!("the injected directory fsync failure did not stop the open"),
        }

        let marker = temporary.path().join("INITIALIZING");
        assert_eq!(
            std::fs::read(&marker)
                .expect("the interrupted open left its marker")
                .len(),
            27,
            "the marker is installed by rename, so it is whole or absent and never torn"
        );
        assert!(
            !temporary.path().join("shards").exists(),
            "the marker must become durable before the first directory of the tree exists, \
             or a crash can leave tree residue with nothing to say whose it is"
        );

        let engine = StoreEngine::open(options(&serial, temporary.path(), 1))
            .expect("the next open finishes what the interrupted one started");
        assert!(engine.shared.initialization.is_some());
        assert!(!marker.exists(), "the finished root carries no marker");
        assert_eq!(segment::RootLock::release_failures(), 0);
    }

    /// State 2. Reopening a formatted root runs recovery and initializes
    /// nothing — asserted directly, through the counter, rather than inferred
    /// from the tree looking unchanged.
    #[test]
    fn startup_state_2_opens_a_formatted_root_without_reinitializing_it() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().join("root");

        let first = StoreEngine::open(options(&serial, &root, 2)).expect("state 1");
        let uuid = first.shared.root_uuid;
        assert!(first.shared.initialization.is_some());
        drop(first);

        let second = StoreEngine::open(options(&serial, &root, 2)).expect("state 2");
        assert!(
            second.shared.initialization.is_none(),
            "a formatted root must not be initialized again"
        );
        assert_eq!(
            second.shared.root_uuid, uuid,
            "the identity FORMAT froze is the identity the reopen carries"
        );
    }

    /// States 3 and 4, both still refused this pass — and the property that
    /// survives the refusal either way: **the root is byte-identical**.
    ///
    /// Both layouts are checked because the whole hazard of implementing state
    /// 1 is that classifying "absent or empty" requires looking at a root that
    /// might be neither, and a probe that creates so much as a directory has
    /// destroyed this guarantee before the refusal is reached.
    #[test]
    fn startup_states_3_and_4_are_refused_by_name_and_leave_the_root_byte_identical() {
        let serial = writer_serial();

        // State 3's shape: the legacy instance signature, `<64-hex>/.levcs/`.
        let legacy = tempfile::tempdir().expect("tempdir");
        let repo = legacy.path().join("a".repeat(64));
        std::fs::create_dir_all(repo.join(".levcs").join("objects")).expect("legacy tree");
        std::fs::write(repo.join(".levcs").join("HEAD"), b"ref: refs/heads/main\n")
            .expect("legacy file");

        // State 4's shape: non-empty, no `FORMAT`, no legacy signature —
        // including an empty directory and a zero-byte file, which a
        // contents-only comparison would not notice being removed.
        let unrecognized = tempfile::tempdir().expect("tempdir");
        std::fs::write(unrecognized.path().join("notes.txt"), b"someone's data\n")
            .expect("stray file");
        std::fs::write(unrecognized.path().join("FORMAT.tmp"), b"\x00\x01\x02").expect("residue");
        std::fs::create_dir_all(unrecognized.path().join("empty")).expect("stray directory");
        std::fs::write(unrecognized.path().join("empty-file"), b"").expect("stray empty file");

        for root in [legacy.path(), unrecognized.path()] {
            let before = tree_image(root);
            match StoreEngine::open(options(&serial, root, 1)) {
                Err(StoreError::NotImplemented(reason)) => {
                    assert!(reason.contains("startup states 3 and 4"), "{reason}");
                    assert!(reason.contains("LegacyLayout"), "{reason}");
                    assert!(reason.contains("UnrecognizedLayout"), "{reason}");
                    assert!(reason.contains("has not been modified"), "{reason}");
                }
                other => panic!("expected an explicit refusal for {root:?}, got {other:?}"),
            }
            assert_eq!(
                tree_image(root),
                before,
                "a refused non-empty layout must be byte-identical afterwards: {root:?}"
            );
        }
    }

    /// A `FORMAT` that exists but does not decode is state 2 and stays state
    /// 2. The dangerous misclassification is the other direction: treating an
    /// unreadable marker as "no marker, therefore empty" would authorize
    /// `initialize_root` to build a fresh tree over a populated root.
    #[test]
    fn a_corrupt_format_is_refused_rather_than_reinitialized_over() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        drop(StoreEngine::open(options(&serial, temporary.path(), 1)).expect("state 1"));

        let format = RootLayout::new(temporary.path()).format_path();
        let original = std::fs::read(&format).expect("read FORMAT");
        std::fs::write(&format, vec![0u8; original.len()]).expect("corrupt FORMAT");
        let before = tree_image(temporary.path());

        let error = StoreEngine::open(options(&serial, temporary.path(), 1))
            .expect_err("a corrupt FORMAT is refused");
        assert!(
            !matches!(error, StoreError::NotImplemented(_)),
            "a corrupt marker is state 2's refusal, not an unbuilt state: {error:?}"
        );
        assert_eq!(
            tree_image(temporary.path()),
            before,
            "the refusal must not have rebuilt the root"
        );
    }

    /// Copy a whole directory tree, file bytes included.
    ///
    /// The equivalence test below needs *two* copies of one crash image
    /// because recovery is a mutation: it seals the validated prefix,
    /// quarantines the discarded tail, and opens a fresh journal. Running both
    /// paths over one directory would compare the first path's recovery
    /// against the second path's recovery of what the first left behind, which
    /// would agree for the wrong reason.
    #[cfg(feature = "store-internals")]
    fn copy_tree(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).expect("create the destination");
        for entry in std::fs::read_dir(from).expect("read the source") {
            let entry = entry.expect("a directory entry");
            let target = to.join(entry.file_name());
            if entry.path().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).expect("copy a file");
            }
        }
    }

    /// Scope 6.4 deliverable 1's second acceptance clause: **the engine and
    /// the drive seam produce the same recovered state from one crash image.**
    ///
    /// The two go through `recovery::recover_shard`, so they agree by
    /// construction — but "by construction" is exactly the kind of claim that
    /// survives the construction changing. `ShardDrive::reopen_through_recovery`
    /// makes one call to that function and `StoreEngine::open` makes one per
    /// shard; if either ever grows a local decision, this is what notices.
    ///
    /// The image is built at production altitude: `StoreEngine::open`
    /// initializes the root (startup state 1), real transactions are
    /// submitted, sequenced, signed and fenced through `submit`, and only then
    /// is the *journal file* damaged. The damage is a byte-level edit and not
    /// a logic-level one, which is the only kind a crash can produce.
    ///
    /// # What is compared, and what is deliberately not
    ///
    /// Every field of `ShardRecoveryReport` that is a function of the crash
    /// image. The two `PathBuf` fields — `quarantined` and `preserved_journal`
    /// — are excluded because they name files inside two different copies and
    /// can never be equal; their *contents* are covered by
    /// `quarantined_bytes`, which is compared. The recovery configurations are
    /// pinned to the drive's constants so that a disagreement here is a
    /// disagreement about the algorithm rather than about tuning.
    #[cfg(feature = "store-internals")]
    #[test]
    fn the_engine_and_the_drive_seam_recover_one_crash_image_identically() {
        use crate::drive::{ShardDrive, DRIVE_PREALLOCATE_BYTES};

        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x9c; 32]);

        // The drive's recovery configuration is a set of constants rather than
        // a `StoreOptions`, so the engine's options are pinned to match it.
        // Anything left unmatched would show up as an algorithmic
        // disagreement, which is the one thing this test must not be able to
        // report falsely.
        let configured = |root: &Path| {
            let mut configured = options(&serial, root, 1);
            configured.journal_preallocate_bytes = DRIVE_PREALLOCATE_BYTES;
            configured.manifest_retain = 2;
            configured.checkpoint_retain = 2;
            configured.terminal_status_grace_micros = 900_000_000;
            configured.max_active_index_entries = 4_000_000;
            configured.max_active_index_bytes = 512 * 1024 * 1024;
            configured.max_index_runs = 64;
            configured.max_open_index_runs = 32;
            configured
        };

        let image = temporary.path().join("image");
        {
            let engine = StoreEngine::open(configured(&image)).expect("startup state 1");
            block_on(engine.submit(create_transaction(namespace, 1))).expect("create");
            block_on(engine.submit(push_transaction(namespace, 2, 0xb1, None))).expect("push");
            block_on(engine.submit(push_transaction(namespace, 3, 0xb2, None))).expect("push");
        }

        // Where the fenced region ends, asked of the scanner rather than
        // computed: there is one definition of where a journal ends and this
        // test does not get to be a second one.
        let layout = RootLayout::new(&image);
        let root_uuid = segment::read_format(&layout).expect("FORMAT").root_uuid;
        let journal_path = std::fs::read_dir(layout.shard(0).active())
            .expect("read active/")
            .map(|entry| entry.expect("entry").path())
            .next()
            .expect("one active journal");
        let (stop_offset, last_frame) = {
            let (_journal, scan) =
                crate::journal::Journal::open(&journal_path, &root_uuid, counters())
                    .expect("open the journal");
            assert_eq!(scan.frames.len(), 3, "three fenced frames");
            // A cleanly closed journal already stops early: the preallocated
            // remainder is zeros, and zeros are `NotAFrame`. Stated here
            // because it is why the damage below has to be a *torn frame* and
            // not merely non-zero residue — the latter would produce the same
            // classification a clean close does, and the comparison would no
            // longer be about a crash.
            assert_eq!(scan.stop, crate::journal::TailStop::NotAFrame);
            let last = scan.frames.last().expect("a third frame").clone();
            (scan.stop_offset, last)
        };

        // The crash residue: a frame whose header reached the device and whose
        // tail did not — the interrupted append. Recovery must stop at it,
        // discard it, and quarantine it, and both paths must reach the same
        // verdict about *which* completeness condition failed.
        {
            use std::io::{Read, Seek, SeekFrom, Write};
            let mut torn = vec![0u8; last_frame.len as usize];
            let mut file = std::fs::File::open(&journal_path).expect("read the journal");
            file.seek(SeekFrom::Start(last_frame.offset)).expect("seek");
            file.read_exact(&mut torn).expect("read a whole frame");
            drop(file);
            torn.truncate(torn.len() - 8);

            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(&journal_path)
                .expect("open the journal for damage");
            file.seek(SeekFrom::Start(stop_offset)).expect("seek");
            file.write_all(&torn).expect("write the torn frame");
            file.sync_all().expect("fence the damage");
        }

        let through_drive_root = temporary.path().join("through-drive");
        let through_engine_root = temporary.path().join("through-engine");
        copy_tree(&image, &through_drive_root);
        copy_tree(&image, &through_engine_root);

        let drive = ShardDrive::reopen_through_recovery(&through_drive_root, 0)
            .expect("the drive seam recovers the image");
        let engine =
            StoreEngine::open(configured(&through_engine_root)).expect("the engine recovers it");
        let engine_report = engine.shared.recovery_reports[0].clone();
        let drive_report = drive.report.clone();

        // The image really was a crash image, or the comparison below is a
        // comparison of two clean opens and proves nothing.
        assert!(
            drive_report.quarantined_bytes > 0,
            "the damaged tail must have been discarded: {drive_report:?}"
        );
        assert!(
            matches!(
                drive_report.tail_stop,
                Some(crate::journal::TailStop::Incomplete(_))
            ),
            "the tail must have been rejected as an incomplete frame: {drive_report:?}"
        );

        assert_eq!(engine_report.shard_index, drive_report.shard_index);
        assert_eq!(
            engine_report.adopted_shard_sequences,
            drive_report.adopted_shard_sequences
        );
        assert_eq!(engine_report.tail_stop, drive_report.tail_stop);
        assert_eq!(
            engine_report.quarantined_bytes,
            drive_report.quarantined_bytes
        );
        assert_eq!(engine_report.active_journal, drive_report.active_journal);
        assert_eq!(
            engine_report.manifest_generation,
            drive_report.manifest_generation
        );
        assert_eq!(engine_report.manifest_source, drive_report.manifest_source);
        assert_eq!(
            engine_report.checkpoint_sequence,
            drive_report.checkpoint_sequence
        );
        assert_eq!(
            engine_report.offline_rebuild_required,
            drive_report.offline_rebuild_required
        );
        assert_eq!(engine_report.promotions, drive_report.promotions);
        assert_eq!(engine_report.ready, drive_report.ready);
        assert!(engine_report.ready);

        // And the engine turned that shared recovered state into a committed
        // root a consumer can read, which is the half the drive seam has no
        // opinion about: three operations survived the crash image, and the
        // fourth — never submitted — is `Unknown` rather than invented.
        for operation in 1u8..=3 {
            assert!(
                matches!(
                    engine.transaction_status(namespace, OperationId([operation; 16])),
                    Ok(TransactionStatus::Committed(_))
                ),
                "operation {operation} did not survive the crash image"
            );
        }
        assert!(matches!(
            engine.transaction_status(namespace, OperationId([4; 16])),
            Ok(TransactionStatus::Unknown)
        ));
    }

    /// A configuration error must not be able to leave a root behind. The
    /// signer check runs before the root is touched at all, so a signerless
    /// open of an absent path creates nothing — not even the directory.
    #[test]
    fn a_configuration_error_refuses_before_startup_state_1_creates_anything() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let root = temporary.path().join("never-created");

        let mut without = options(&serial, &root, 1);
        without.signer = None;
        assert!(matches!(
            StoreEngine::open(without),
            Err(StoreError::InvalidConfiguration(_))
        ));
        assert!(!root.exists(), "a refused configuration created a root");
    }

    #[test]
    fn a_configured_shard_count_that_disagrees_with_format_is_refused() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        // The topology is frozen by the *production* initialization, so the
        // mismatch is between two consumer-visible opens of one path rather
        // than between a hand-seeded root and an open.
        drop(open(&serial, temporary.path(), 4));
        match StoreEngine::open(options(&serial, temporary.path(), 2)) {
            Err(StoreError::FormatMismatch(reason)) => {
                assert!(reason.contains("4 shards"), "{reason}")
            }
            other => panic!("expected FormatMismatch, got {other:?}"),
        }
    }

    #[test]
    fn opening_without_a_signer_is_refused_rather_than_deferred_to_the_first_submit() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        drop(open(&serial, temporary.path(), 1));
        let mut without = options(&serial, temporary.path(), 1);
        without.signer = None;
        assert!(matches!(
            StoreEngine::open(without),
            Err(StoreError::InvalidConfiguration(_))
        ));
    }

    // -----------------------------------------------------------------------
    // The writer, end to end
    // -----------------------------------------------------------------------

    #[test]
    fn a_committed_transaction_survives_close_and_reopen_through_recovery() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x20; 32]);
        let blob = ObjectId([0x77; 32]);
        let branch = set_branch("main", None, blob);

        let (create_receipt, push_receipt) = {
            let engine = open(&serial, temporary.path(), 1);
            let create = block_on(engine.submit(create_transaction(namespace, 1)))
                .expect("the create commits");
            let push =
                block_on(engine.submit(push_transaction(namespace, 2, 0x77, Some(branch.clone()))))
                    .expect("the push commits");

            assert_eq!(create.repo_sequence, 0);
            assert_eq!(push.repo_sequence, 1);
            assert_eq!(push.objects_new, 1);
            assert_eq!(
                push.refs,
                vec![AppliedRefV1 {
                    target: RefTarget::Branch("main".into()),
                    old: None,
                    new: Some(blob),
                    force: false,
                }]
            );
            assert_eq!(
                engine
                    .transaction_status(namespace, OperationId([2; 16]))
                    .expect("status"),
                TransactionStatus::Committed(push.clone())
            );
            (create, push)
        };

        // Reopen through production recovery. Everything asserted below came
        // back off the device: the receipts, the applied refs, the repository
        // state, and the index entry with its object-type code.
        let engine = StoreEngine::open(options(&serial, temporary.path(), 1)).expect("reopen");
        assert_eq!(
            engine
                .transaction_status(namespace, OperationId([1; 16]))
                .expect("status"),
            TransactionStatus::Committed(create_receipt)
        );
        assert_eq!(
            engine
                .transaction_status(namespace, OperationId([2; 16]))
                .expect("status"),
            TransactionStatus::Committed(push_receipt)
        );

        let root = engine.committed_root();
        let repository = root.repo(&namespace).expect("the repository is bound");
        assert_eq!(repository.repo_sequence, 1);
        assert_eq!(repository.genesis_authority, genesis_object().id);
        assert_eq!(repository.current_authority, genesis_object().id);
        assert_eq!(
            repository.refs.get(&RefTarget::Branch("main".into())),
            Some(&blob)
        );

        // The object-type code this writer put in the index and the one
        // recovery reconstructs are the same table stated twice (see the
        // interface request on `object_type_code`). This is the assertion that
        // fails if they ever diverge.
        let located = root
            .index()
            .get(&IndexKey::new(namespace, blob))
            .expect("the recovered index locates the pushed blob");
        assert_eq!(located.object_type, object_type_code(ObjectType::Blob));
        assert!(
            root.index()
                .get(&IndexKey::new(NamespaceId([0x21; 32]), blob))
                .is_none(),
            "namespace isolation is a property of the key, on the recovered path too"
        );
    }

    /// The frame the writer appends carries a signature over
    /// `SignedCommittedTransactionV1::signing_digest`, which is what the frozen
    /// `verify` checks — not over the bare event digest.
    ///
    /// A frame signed over anything else would be durable, correctly fenced,
    /// and verifiable against nothing, which no later recovery could detect.
    #[test]
    fn the_appended_frame_is_signed_over_the_digest_the_frozen_verifier_checks() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x30; 32]);
        {
            let engine = open(&serial, temporary.path(), 1);
            block_on(engine.submit(create_transaction(namespace, 1))).expect("commit");
        }
        // Reopening runs production recovery, which seals the validated
        // prefix. Reading the frame back out of that segment means this test
        // inspects the bytes recovery accepted, not the bytes the writer
        // believes it wrote.
        drop(StoreEngine::open(options(&serial, temporary.path(), 1)).expect("reopen"));

        let signed = only_frame_payload(temporary.path()).committed;
        let digest = SignedCommittedTransactionV1::signing_digest(
            &signed.transaction,
            signed.source_key_epoch,
            &signed.durability_result,
        )
        .expect("signing digest");
        assert_eq!(
            signed.source_signature,
            TestSigner::expected_signature(&ObjectId(digest))
        );
        assert_eq!(signed.source_key_epoch, 7);
        assert_ne!(
            digest,
            signed.transaction.event_digest().expect("event digest").0,
            "the two digests must differ, or this test proves nothing"
        );
    }

    /// Read the single frame a one-transaction store wrote, through the same
    /// sealed segment the reopen produced.
    fn only_frame_payload(root: &Path) -> TransactionFramePayloadV1 {
        let layout = RootLayout::new(root);
        let paths = layout.shard(0);
        // The root identity is read out of `FORMAT` rather than restated: the
        // root is now built by `StoreEngine::open`, which mints a fresh
        // `root_uuid` per root, and a hard-coded one here would be a second
        // definition of the identity every file in the root is bound to.
        let root_uuid = segment::read_format(&layout).expect("FORMAT").root_uuid;
        // Reopening sealed the validated prefix, so the frame is in a segment.
        let (manifest, _) = segment::load_manifest_with_fallback(&paths, &root_uuid)
            .expect("manifest")
            .expect("a manifest exists after the reopen sealed the prefix");
        let range = manifest
            .retained_tail_ranges
            .last()
            .expect("one retained range");
        let reader =
            segment::SegmentReader::open(&paths.segments().join(&range.filename), &root_uuid)
                .expect("segment");
        let frame = reader
            .read_frame(range.first_shard_sequence)
            .expect("frame");
        TransactionFramePayloadV1::decode_canonical(&frame.payload).expect("canonical payload")
    }

    /// Every frame the store durably wrote, in `shard_sequence` order, read
    /// back out of the sealed segments a reopen produced.
    fn all_frame_payloads(root: &Path) -> Vec<TransactionFramePayloadV1> {
        let layout = RootLayout::new(root);
        let paths = layout.shard(0);
        let root_uuid = segment::read_format(&layout).expect("FORMAT").root_uuid;
        let (manifest, _) = segment::load_manifest_with_fallback(&paths, &root_uuid)
            .expect("manifest")
            .expect("a manifest exists after the reopen sealed the prefix");
        let mut payloads = Vec::new();
        for range in &manifest.retained_tail_ranges {
            let reader =
                segment::SegmentReader::open(&paths.segments().join(&range.filename), &root_uuid)
                    .expect("segment");
            for sequence in range.first_shard_sequence..=range.last_shard_sequence {
                let frame = reader.read_frame(sequence).expect("frame");
                payloads.push(
                    TransactionFramePayloadV1::decode_canonical(&frame.payload)
                        .expect("canonical payload"),
                );
            }
        }
        payloads
    }

    /// Every durable frame carries a signature over the digest the frozen
    /// verifier recomputes, and its `previous_event_digest` is the event digest
    /// of the frame before it in its repository.
    ///
    /// This is the assertion a partial suffix repair fails. Dropping a member
    /// from a forming group re-chains every later member, and a repair that
    /// re-chained without re-signing leaves a durable, correctly fenced frame
    /// whose signature covers a chain that no longer exists — which nothing
    /// downstream of the append can detect.
    fn assert_every_frame_is_chained_and_signed(root: &Path) -> Vec<TransactionFramePayloadV1> {
        let payloads = all_frame_payloads(root);
        let mut previous: BTreeMap<ObjectId, ObjectId> = BTreeMap::new();
        for payload in &payloads {
            let signed = &payload.committed;
            let digest = SignedCommittedTransactionV1::signing_digest(
                &signed.transaction,
                signed.source_key_epoch,
                &signed.durability_result,
            )
            .expect("signing digest");
            assert_eq!(
                signed.source_signature,
                TestSigner::expected_signature(&ObjectId(digest)),
                "repo_sequence {} carries a signature over a message the signer never signed",
                signed.transaction.repo_sequence
            );
            let repo = signed.transaction.repo_id;
            let expected = previous.get(&repo).copied().unwrap_or(ObjectId([0u8; 32]));
            assert_eq!(
                signed.transaction.previous_event_digest, expected,
                "repo_sequence {} is chained to an event that is not its predecessor",
                signed.transaction.repo_sequence
            );
            previous.insert(
                repo,
                signed.transaction.event_digest().expect("event digest"),
            );
        }
        payloads
    }

    /// P1-1. The committed event's `actor` is the evidence's principal, never
    /// the destination instance's signing key.
    ///
    /// The two are deliberately different values in this file. Under the defect
    /// this test exists for, `actor` was `TestSigner::public_key()`, the frame
    /// signed and fenced and published, and the first thing to notice was a
    /// mirror on another instance running `validate_mirror_application` against
    /// a transaction that could no longer be withdrawn.
    #[test]
    fn the_committed_event_takes_its_actor_from_the_evidence_not_from_the_signer() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x31; 32]);
        {
            let engine = open(&serial, temporary.path(), 1);
            block_on(engine.submit(create_transaction(namespace, 1))).expect("commit");
        }
        drop(StoreEngine::open(options(&serial, temporary.path(), 1)).expect("reopen"));

        let signed = only_frame_payload(temporary.path()).committed;
        assert_eq!(
            signed.transaction.actor,
            evidence().actor(),
            "the committed event restates the evidence's actor"
        );
        assert_eq!(signed.transaction.actor, EVIDENCE_ACTOR);
        assert_ne!(
            signed.transaction.actor,
            TestSigner::default().public_key(),
            "the destination signer's key is not the actor, and this store's two values \
             differ so that substituting one for the other is visible"
        );
    }

    /// Configured per-transaction ceilings, asserted through `submit` — the
    /// entry point a consumer calls — rather than through the codec maxima that
    /// happen to sit further down.
    #[test]
    fn configured_per_transaction_ceilings_are_enforced_at_submit() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x32; 32]);
        let mut configured = options(&serial, temporary.path(), 1);
        configured.max_objects_per_transaction = 1;
        configured.max_refs_per_transaction = 1;
        let engine = StoreEngine::open(configured).expect("open");
        block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

        let authority = genesis_object().id;
        let two_objects = ValidatedTransaction::builder(PrivilegedConstruction::internal())
            .namespace(namespace)
            .operation(OperationId([2; 16]), ObjectId([2; 32]), deadline())
            .objects(vec![
                StagedObject {
                    id: ObjectId([0xb1; 32]),
                    object_type: ObjectType::Blob,
                    raw: vec![1; 8],
                },
                StagedObject {
                    id: ObjectId([0xb2; 32]),
                    object_type: ObjectType::Blob,
                    raw: vec![2; 8],
                },
            ])
            .refs(Vec::new())
            .authority(Some(authority), Some(authority))
            .evidence(evidence())
            .build()
            .expect("a well formed but oversized transaction");
        match block_on(engine.submit(two_objects)) {
            Err(StoreError::LimitExceeded {
                limit,
                observed,
                allowed,
            }) => {
                assert_eq!(limit, "max_objects_per_transaction");
                assert_eq!((observed, allowed), (2, 1));
            }
            other => panic!("the configured object ceiling must refuse, got {other:?}"),
        }

        let two_refs = ValidatedTransaction::builder(PrivilegedConstruction::internal())
            .namespace(namespace)
            .operation(OperationId([3; 16]), ObjectId([3; 32]), deadline())
            .objects(vec![StagedObject {
                id: ObjectId([0xb3; 32]),
                object_type: ObjectType::Blob,
                raw: vec![3; 8],
            }])
            .refs(vec![
                set_branch("main", None, ObjectId([0xb3; 32])),
                set_branch("other", None, ObjectId([0xb3; 32])),
            ])
            .authority(Some(authority), Some(authority))
            .evidence(evidence())
            .build()
            .expect("a well formed but over-referenced transaction");
        match block_on(engine.submit(two_refs)) {
            Err(StoreError::LimitExceeded {
                limit,
                observed,
                allowed,
            }) => {
                assert_eq!(limit, "max_refs_per_transaction");
                assert_eq!((observed, allowed), (2, 1));
            }
            other => panic!("the configured ref ceiling must refuse, got {other:?}"),
        }

        // Neither refusal reserved anything, and the shard still commits.
        for operation in [2u8, 3] {
            assert_eq!(
                engine
                    .transaction_status(namespace, OperationId([operation; 16]))
                    .expect("status"),
                TransactionStatus::Unknown
            );
        }
        block_on(engine.submit(push_transaction(namespace, 4, 0xb4, None))).expect("push");
    }

    /// Status occupancy is the size of the root that was just published, not of
    /// the one it replaced.
    ///
    /// Recording the previous root makes occupancy lag every insertion and
    /// every removal by one publication — wrong in exactly the direction that
    /// hides an approach to `max_status_entries`, since the reading is always
    /// one behind on the way up and never returns to zero on the way down.
    #[test]
    fn status_occupancy_reports_the_root_that_was_published() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x33; 32]);
        let engine = open(&serial, temporary.path(), 1);
        assert_eq!(engine.operation_status_metrics().occupancy, 0);

        block_on(engine.submit(create_transaction(namespace, 1))).expect("create");
        assert_eq!(
            engine.operation_status_metrics().occupancy,
            0,
            "a published group removes its status entries, and the metric must say so"
        );
        assert_eq!(engine.operation_status_metrics().rejections, 0);

        block_on(engine.submit(push_transaction(namespace, 2, 0xc1, None))).expect("push");
        assert_eq!(engine.operation_status_metrics().occupancy, 0);
    }

    /// Deliverable 6's concurrent-publication case, and the first test in this
    /// package to submit to more than one shard.
    ///
    /// Two shards publish into one `ArcSwap<CommittedRoot>`, so the losing CAS
    /// must reload and merge against the newer root. Charter item 7: the retry
    /// is counted rather than asserted to have happened, and the no-lost-update
    /// property is checked against every receipt from both shards.
    #[test]
    fn concurrent_publication_from_two_shards_re_merges_and_never_loses_an_update() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let mut configured = options(&serial, temporary.path(), 2);
        configured.max_group_transactions = 2;
        configured.max_group_idle = Duration::from_millis(20);
        let engine = StoreEngine::open(configured).expect("open");

        // Two namespaces that route to different shards, found rather than
        // assumed: the routing function is the authority on the mapping.
        let mut namespaces: Vec<NamespaceId> = Vec::new();
        for byte in 0u8..=255 {
            let candidate = NamespaceId([byte; 32]);
            let shard = StoreOptions::shard_of(&candidate, 2);
            if namespaces.len() == usize::from(shard) {
                namespaces.push(candidate);
            }
            if namespaces.len() == 2 {
                break;
            }
        }
        assert_eq!(namespaces.len(), 2, "both shards must be reachable");

        const ROUNDS: u8 = 24;
        std::thread::scope(|scope| {
            let handles: Vec<_> = namespaces
                .iter()
                .enumerate()
                .map(|(lane, namespace)| {
                    let namespace = *namespace;
                    let engine = &engine;
                    let base = 1 + (lane as u8) * (ROUNDS + 1);
                    scope.spawn(move || {
                        block_on(engine.submit(create_transaction(namespace, base)))
                            .expect("create");
                        for index in 0..ROUNDS {
                            block_on(engine.submit(push_transaction(
                                namespace,
                                base + 1 + index,
                                index,
                                None,
                            )))
                            .expect("push");
                        }
                    })
                })
                .collect();
            for handle in handles {
                handle.join().expect("no writer panics");
            }
        });

        // No lost update: every operation from both lanes is in the one root,
        // and each repository's sequence counted every one of its own.
        let root = engine.committed_root();
        for (lane, namespace) in namespaces.iter().enumerate() {
            let base = 1 + (lane as u8) * (ROUNDS + 1);
            for index in 0..=ROUNDS {
                let key = OperationKey::new(*namespace, OperationId([base + index; 16]));
                assert!(
                    root.terminal_status(&key).is_some(),
                    "lane {lane} operation {index} is missing from the merged root"
                );
            }
            assert_eq!(
                root.repo(namespace).expect("bound").repo_sequence,
                u64::from(ROUNDS)
            );
        }
        assert_eq!(root.retained_generations().len(), 2);
    }

    /// Deliverable 6's re-merge, made deterministic.
    ///
    /// A competing root is published between the load and the compare-and-swap
    /// of the real `publish_subtree` loop, so the CAS provably fails exactly
    /// once. What must survive is both sides: the receipt this writer is
    /// publishing *and* the entry the competing publisher added. A lost update
    /// here is a re-merge against the stale root, which the previous test —
    /// two shards racing — can only ever catch by luck.
    ///
    /// The sibling test above submits to two shards concurrently and asserts no
    /// lost update; it cannot assert that any CAS contended, because whether it
    /// does depends on scheduling. This one owns that claim.
    #[test]
    fn a_contended_root_cas_re_merges_against_the_newer_root() {
        let probe_serial = probe::serial();
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x71; 32]);
        // The competing subtree names the shard this namespace does *not*
        // route to, so it never disturbs the sequence bookkeeping of the shard
        // under test. Derived from the routing function rather than assumed.
        let publishing_shard = StoreOptions::shard_of(&namespace, 2);
        let other_shard = 1 - publishing_shard;
        // A marker only the competing publisher writes. If the writer re-merges
        // against the root it loaded rather than the newer one, this is gone.
        let marker = OperationKey::new(NamespaceId([0x72; 32]), OperationId([0x72; 16]));
        let competing = Arc::new(ShardSubtree::new(
            other_shard,
            0,
            Arc::new(IndexDelta::from_options(&options(
                &serial,
                temporary.path(),
                2,
            ))),
            None,
            Vector::new(),
            RepoMap::new(),
            {
                let mut statuses = TerminalStatusMap::new();
                statuses.insert(
                    marker,
                    TerminalStatusEntry::Committed(RetainedReceipt {
                        operation_digest: ObjectId([0x72; 32]),
                        receipt: CommitReceipt {
                            operation_id: marker.operation_id,
                            repo_sequence: 0,
                            current_authority: ObjectId([0; 32]),
                            refs: Vec::new(),
                            objects_new: 0,
                        },
                        shard_sequence: 0,
                        retry_until_micros: deadline(),
                        first_visible_at_micros: now_micros(),
                        receipt_visible_until_micros: deadline(),
                    }),
                );
                statuses
            },
            GenerationMap::new(),
        ));

        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let armed = Arc::clone(&fired);
        // Filtered by root, because the hook is process-global and every other
        // test in this binary publishes through the same `publish_subtree`.
        // Without this, the one-shot perturbation is consumed by whichever
        // engine happens to publish first and this test observes no contention
        // at all — the Wave A lesson about one-shot global registries, one
        // layer up.
        let this_root = temporary.path().to_path_buf();
        probe::install_cas_contention(&probe_serial, move |shared| {
            if shared.options.root != this_root {
                return;
            }
            // Once: the second pass through the loop must find an uncontended
            // root, or the writer would spin forever.
            if armed.swap(true, AtomicOrdering::SeqCst) {
                return;
            }
            let current = shared.committed.load();
            shared.committed.store(Arc::new(current.merge(&competing)));
        });

        let engine = StoreEngine::open(options(&serial, temporary.path(), 2)).expect("open");
        let receipt = block_on(engine.submit(create_transaction(namespace, 1)))
            .expect("the contended publication still commits");

        assert_eq!(
            engine.shared.root_cas_retries.load(AtomicOrdering::Relaxed),
            1,
            "the committed-root CAS must have contended exactly once"
        );
        let root = engine.committed_root();
        assert!(
            root.terminal_status(&marker).is_some(),
            "the competing publisher's entry was lost: the re-merge used the stale root"
        );
        assert_eq!(
            root.terminal_status(&OperationKey::new(namespace, OperationId([1; 16])))
                .map(|entry| entry.transaction_status()),
            Some(TransactionStatus::Committed(receipt)),
            "this writer's own receipt was lost by the re-merge"
        );
    }

    // -----------------------------------------------------------------------
    // Scope 6.3 step 3: the pre-mark deadline recheck and its suffix repair
    // -----------------------------------------------------------------------

    /// Submit `members` pushes into one forming group, the one at `expiring`
    /// carrying a deadline that passes while the group waits for its idle
    /// bound, and report each submission's outcome in submission order.
    ///
    /// The group is closed by the idle delay and never by the transaction
    /// ceiling, which is what puts real time between sequencing and the mark:
    /// scope 6.3 step 3 exists precisely because signing latency and the idle
    /// wait sit between the two.
    fn group_with_one_expiring_member(
        engine: &StoreEngine,
        namespace: NamespaceId,
        first_operation: u8,
        members: u8,
        expiring: u8,
    ) -> Vec<Result<CommitReceipt, StoreError>> {
        let outcomes: Arc<Mutex<Vec<(u8, Result<CommitReceipt, StoreError>)>>> =
            Arc::new(Mutex::new(Vec::new()));
        std::thread::scope(|scope| {
            for index in 0..members {
                let outcomes = Arc::clone(&outcomes);
                scope.spawn(move || {
                    // Staggered so the group forms in a known order.
                    std::thread::sleep(Duration::from_millis(60 * u64::from(index)));
                    let operation = first_operation + index;
                    let retry_until = if index == expiring {
                        now_micros() + 250_000
                    } else {
                        deadline()
                    };
                    let transaction =
                        ValidatedTransaction::builder(PrivilegedConstruction::internal())
                            .namespace(namespace)
                            .operation(
                                OperationId([operation; 16]),
                                ObjectId([operation; 32]),
                                retry_until,
                            )
                            .objects(vec![StagedObject {
                                id: ObjectId([operation; 32]),
                                object_type: ObjectType::Blob,
                                raw: vec![operation; 64],
                            }])
                            .refs(Vec::new())
                            .authority(Some(genesis_object().id), Some(genesis_object().id))
                            .evidence(evidence())
                            .build()
                            .expect("a complete push transaction");
                    let outcome = block_on(engine.submit(transaction));
                    outcomes.lock().expect("outcomes").push((index, outcome));
                });
            }
        });
        let mut collected = Arc::try_unwrap(outcomes)
            .map_err(|_| "outcomes outlived the scope")
            .expect("sole owner")
            .into_inner()
            .expect("outcomes");
        collected.sort_by_key(|(index, _)| *index);
        collected.into_iter().map(|(_, outcome)| outcome).collect()
    }

    /// Scope 6.3 step 3 at the first, middle, and last position of a forming
    /// group, each with the later members already sequenced and signed.
    ///
    /// The expired member appends nothing, and every retained member is
    /// re-sequenced, re-chained, re-signed, and left with no sequence gap.
    /// A repair that re-chained without re-signing, or that shifted sequences
    /// without re-chaining, produces a durable and correctly fenced frame
    /// carrying a signature that verifies against nothing — which is why the
    /// assertion is made against the bytes recovery read back, not against the
    /// receipts.
    #[test]
    fn a_member_that_crosses_its_deadline_before_the_mark_appends_nothing() {
        for expiring in 0u8..3 {
            let serial = writer_serial();
            let temporary = tempfile::tempdir().expect("tempdir");
            let namespace = NamespaceId([0x60 + expiring; 32]);
            let mut configured = options(&serial, temporary.path(), 1);
            // Never the transaction ceiling: the idle bound is what closes this
            // group, and it is long enough that the short deadline passes while
            // the group is still open.
            configured.max_group_transactions = 16;
            configured.max_group_idle = Duration::from_millis(900);
            let engine = StoreEngine::open(configured).expect("open");
            block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

            let outcomes = group_with_one_expiring_member(&engine, namespace, 2, 3, expiring);
            let mut expected_repo_sequence = 1u64;
            for (index, outcome) in outcomes.iter().enumerate() {
                if index as u8 == expiring {
                    match outcome {
                        Err(StoreError::Conflict(reason)) => assert!(
                            reason.contains("passed its signed deadline"),
                            "position {expiring}: {reason}"
                        ),
                        other => panic!(
                            "position {expiring}: an expired member must be refused, \
                             got {other:?}"
                        ),
                    }
                    // Definitively absent: the reservation is released, so the
                    // operation reads back Unknown rather than Pending forever.
                    assert_eq!(
                        engine
                            .transaction_status(namespace, OperationId([2 + expiring; 16]))
                            .expect("status"),
                        TransactionStatus::Unknown,
                        "position {expiring}: an expired member holds no reservation"
                    );
                } else {
                    let receipt = outcome
                        .as_ref()
                        .unwrap_or_else(|e| panic!("position {expiring}: retained member {e:?}"));
                    assert_eq!(
                        receipt.repo_sequence, expected_repo_sequence,
                        "position {expiring}: the retained suffix left a repo_sequence gap"
                    );
                    expected_repo_sequence += 1;
                }
            }

            // The shard is not poisoned: nothing was appended for the dropped
            // member, so no sequence was consumed and no hole exists.
            block_on(engine.submit(push_transaction(namespace, 9, 0x9f, None)))
                .expect("the shard still admits mutation");
            drop(engine);

            let engine = StoreEngine::open(options(&serial, temporary.path(), 1)).expect("reopen");
            let payloads = assert_every_frame_is_chained_and_signed(temporary.path());
            assert_eq!(
                payloads.len(),
                4,
                "position {expiring}: one create, two retained members, one later push"
            );
            for (index, payload) in payloads.iter().enumerate() {
                assert_eq!(
                    payload.committed.transaction.repo_sequence, index as u64,
                    "position {expiring}: durable repo_sequence is not gapless"
                );
            }
            assert_eq!(
                engine
                    .transaction_status(namespace, OperationId([2 + expiring; 16]))
                    .expect("status"),
                TransactionStatus::Unknown,
                "position {expiring}: an expired member is absent after recovery too"
            );
        }
    }

    #[test]
    fn a_repository_create_binds_its_genesis_permanently() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x40; 32]);
        let engine = open(&serial, temporary.path(), 1);
        block_on(engine.submit(create_transaction(namespace, 1))).expect("the first create");

        match block_on(engine.submit(create_transaction(namespace, 2))) {
            Err(StoreError::Conflict(reason)) => {
                assert!(reason.contains("already bound to genesis"), "{reason}")
            }
            other => panic!("a second create must be refused, got {other:?}"),
        }
    }

    /// Phase 1 exit criterion "exact same-ref winner", asserted through
    /// `submit` rather than through the ref map it updates.
    #[test]
    fn exactly_one_writer_wins_a_contested_typed_ref() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x50; 32]);
        let engine = open(&serial, temporary.path(), 1);
        block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

        let first = block_on(engine.submit(push_transaction(
            namespace,
            2,
            0x60,
            Some(set_branch("main", None, ObjectId([0x60; 32]))),
        )))
        .expect("the first writer wins");
        assert_eq!(first.refs.len(), 1);

        // Same expected value, different new value: the loser must be a typed
        // conflict and must leave no partial state behind.
        match block_on(engine.submit(push_transaction(
            namespace,
            3,
            0x61,
            Some(set_branch("main", None, ObjectId([0x61; 32]))),
        ))) {
            Err(StoreError::Conflict(reason)) => {
                assert!(reason.contains("typed ref CAS"), "{reason}")
            }
            other => panic!("the loser must be a typed conflict, got {other:?}"),
        }

        let root = engine.committed_root();
        assert_eq!(
            root.repo(&namespace)
                .expect("bound")
                .refs
                .get(&RefTarget::Branch("main".into())),
            Some(&ObjectId([0x60; 32]))
        );
        assert!(
            root.index()
                .get(&IndexKey::new(namespace, ObjectId([0x61; 32])))
                .is_none(),
            "a refused transaction publishes none of its objects"
        );
        assert_eq!(
            engine
                .transaction_status(namespace, OperationId([3; 16]))
                .expect("status"),
            TransactionStatus::Unknown,
            "a definitively refused operation leaves no status entry behind"
        );
    }

    // -----------------------------------------------------------------------
    // Counters, not claims (charter item 7)
    // -----------------------------------------------------------------------

    /// Group formation is bounded by transactions, bytes, and idle delay —
    /// asserted against the sequencer that forms the groups, and counted in
    /// `DurabilityCounters.fdatasync`, which is the only witness that says how
    /// many fences actually reached the device.
    ///
    /// This is the Wave A `GroupBuilder` carry-forward: the bounds are now
    /// observed through the production caller rather than through unit tests
    /// over a type nothing calls.
    #[test]
    fn group_formation_bounds_are_observed_as_fences_on_the_device() {
        // (a) the transaction bound: eight concurrent submissions with a
        //     ceiling of four close exactly two groups.
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x70; 32]);
        let mut configured = options(&serial, temporary.path(), 1);
        configured.max_group_transactions = 4;
        // Long enough that the idle bound cannot be what closes these groups.
        configured.max_group_idle = Duration::from_secs(5);
        let engine = StoreEngine::open(configured).expect("open");

        // The create is alone in its group, so it is the idle bound that
        // closes it — case (c), and the reason this engine cannot use a
        // multi-second idle delay for the whole test.
        let before_create = engine.durability_counters(0).expect("counters").fdatasync;
        assert_eq!(before_create, 0, "opening a recovered shard fences nothing");

        let fences_after = commit_concurrently(&engine, namespace, 1, 8);
        assert_eq!(
            fences_after, 3,
            "one fence for the create's group and one for each of two full groups"
        );
        assert!(
            fences_after < 9,
            "nine transactions must not cost nine fences"
        );
    }

    #[test]
    fn a_group_is_also_closed_by_its_byte_ceiling() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x80; 32]);
        let mut configured = options(&serial, temporary.path(), 1);
        configured.max_group_transactions = 64;
        // One push frame is comfortably over 512 bytes once its evidence and
        // signed event are encoded, so the byte ceiling closes the group after
        // one transaction while the transaction ceiling is nowhere near.
        configured.max_group_bytes = 512;
        configured.max_group_idle = Duration::from_secs(5);
        let engine = StoreEngine::open(configured).expect("open");

        let fences = commit_concurrently(&engine, namespace, 1, 4);
        assert_eq!(
            fences, 5,
            "the byte ceiling admits one transaction per group, so five \
             transactions cost five fences"
        );
    }

    /// Submit a create for `namespace` and then `pushes` concurrent pushes,
    /// and report the shard's fence count once every one of them has resolved.
    fn commit_concurrently(
        engine: &StoreEngine,
        namespace: NamespaceId,
        first_operation: u8,
        pushes: u8,
    ) -> u64 {
        block_on(engine.submit(create_transaction(namespace, first_operation))).expect("create");

        std::thread::scope(|scope| {
            let handles: Vec<_> = (0..pushes)
                .map(|index| {
                    let operation = first_operation + 1 + index;
                    scope.spawn(move || {
                        block_on(engine.submit(push_transaction(
                            namespace,
                            operation,
                            0x90 + index,
                            None,
                        )))
                    })
                })
                .collect();
            for handle in handles {
                handle.join().expect("no writer panics").expect("commit");
            }
        });

        engine.durability_counters(0).expect("counters").fdatasync
    }

    // -----------------------------------------------------------------------
    // Publication ordering (scope 6.3 steps 7 to 9)
    // -----------------------------------------------------------------------

    /// Step 8 is strictly after step 7.
    ///
    /// The probe fires between them on the real writer. At that instant the
    /// receipt must already be in the committed root and the status entry must
    /// still be present. Removing the entry before the CAS fails the second
    /// assertion; publishing after the removal fails the first. Nothing else
    /// in this file can distinguish the two orders deterministically, because
    /// from outside they differ only by a window.
    #[test]
    fn the_committed_root_is_published_before_the_status_entry_is_removed() {
        let probe_serial = probe::serial();
        let observations = Arc::new(Mutex::new(Vec::new()));
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0xa0; 32]);
        let recorded = Arc::clone(&observations);
        // Filtered by namespace: the hook is process-global and other tests
        // publish through it in parallel. Recording their groups would make
        // this test's count depend on the rest of the binary.
        probe::install(&probe_serial, move |shared, keys| {
            for key in keys.iter().filter(|key| key.namespace == namespace) {
                let committed = shared.committed.load().terminal_status(key).is_some();
                let still_resolving = matches!(
                    shared.status.load().get(key).map(|entry| entry.phase),
                    Some(crate::roots::StatusPhase::Resolving)
                );
                recorded
                    .lock()
                    .expect("probe mutex")
                    .push((*key, committed, still_resolving));
            }
        });

        let engine = open(&serial, temporary.path(), 1);
        block_on(engine.submit(create_transaction(namespace, 1))).expect("create");
        block_on(engine.submit(push_transaction(namespace, 2, 0xb0, None))).expect("push");

        let observations = observations.lock().expect("probe mutex").clone();
        assert_eq!(observations.len(), 2, "one observation per published group");
        for (key, committed, still_resolving) in observations {
            assert!(
                committed,
                "operation {} must be in the committed root before its status entry is removed",
                key.operation_id.to_hex()
            );
            assert!(
                still_resolving,
                "operation {} must still be Resolving at the instant its receipt becomes visible",
                key.operation_id.to_hex()
            );
        }
    }

    /// The same property from the outside, through the API a consumer calls.
    ///
    /// A reader spinning on `transaction_status` may legitimately see
    /// `Unknown` before the operation is reserved. What it may never see is
    /// `Unknown` *after* it has already seen the operation, because that is
    /// the manufactured-`Unknown` race step 8 exists to close.
    #[test]
    fn a_status_reader_never_regresses_to_unknown_once_an_operation_is_visible() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0xc0; 32]);
        let engine = open(&serial, temporary.path(), 1);
        block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reader_stop = Arc::clone(&stop);
        std::thread::scope(|scope| {
            let observer = scope.spawn(|| {
                // Per operation, not per sweep: `Unknown` before an operation
                // is reserved is correct, and only a regression *after* it has
                // been seen is the manufactured `Unknown` step 8 closes.
                let mut seen = [false; 16];
                let mut regressions = 0u64;
                while !reader_stop.load(AtomicOrdering::Relaxed) {
                    for operation in 2u8..=17 {
                        let index = usize::from(operation) - 2;
                        let status = engine
                            .transaction_status(namespace, OperationId([operation; 16]))
                            .expect("status");
                        match status {
                            TransactionStatus::Unknown => {
                                if seen[index] {
                                    regressions += 1;
                                }
                            }
                            TransactionStatus::Committed(_)
                            | TransactionStatus::Pending { .. }
                            | TransactionStatus::Resolving { .. }
                            | TransactionStatus::Expired { .. } => seen[index] = true,
                        }
                    }
                }
                regressions
            });

            for operation in 2u8..=17 {
                block_on(engine.submit(push_transaction(namespace, operation, operation, None)))
                    .expect("push");
            }
            stop.store(true, AtomicOrdering::Relaxed);
            assert_eq!(
                observer.join().expect("observer"),
                0,
                "a committed operation may never read back as Unknown"
            );
        });
    }

    // -----------------------------------------------------------------------
    // Failpoints: the publication half of the matrix (scope 6.3, oracle rows)
    // -----------------------------------------------------------------------

    #[cfg(feature = "failpoints")]
    mod publication_failures {
        use levcs_protocol::oracle::{append_publication_expectation, ImmediateStatus};

        use super::*;
        use crate::failpoints::{arm, disarm};

        /// The frozen oracle's classification for a row, so each test below
        /// states which contract it is pinning rather than restating it.
        fn expectation(point: Failpoint) -> levcs_protocol::oracle::FailpointExpectation {
            append_publication_expectation(point.into())
        }

        /// Scope 6.3 step 9. The fence succeeded and the root published, so
        /// the transaction is committed even though no waiter will ever be
        /// woken: a hung request, never an absent transaction.
        #[test]
        fn a_lost_wake_leaves_a_committed_and_queryable_receipt() {
            let expectation = expectation(Failpoint::AfterRootCasBeforeWaiterWake);
            assert!(!expectation.shard_poisoned);
            assert!(expectation.acknowledgment_allowed);
            assert_eq!(expectation.immediate_status, ImmediateStatus::Committed);

            let serial = writer_serial();
            let temporary = tempfile::tempdir().expect("tempdir");
            let namespace = NamespaceId([0xd0; 32]);
            let engine = open(&serial, temporary.path(), 1);
            block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

            arm(
                &serial,
                Failpoint::AfterRootCasBeforeWaiterWake,
                FailpointAction::Fail,
            );
            let hung = block_on_until(
                engine.submit(push_transaction(namespace, 2, 0xd1, None)),
                Duration::from_millis(750),
            );
            disarm(&serial);
            assert!(hung.is_none(), "the waiter is never woken");

            match engine
                .transaction_status(namespace, OperationId([2; 16]))
                .expect("status")
            {
                TransactionStatus::Committed(receipt) => {
                    assert_eq!(receipt.repo_sequence, 1);
                    assert_eq!(receipt.objects_new, 1);
                }
                other => panic!("a published transaction must stay queryable, got {other:?}"),
            }

            // The shard is not poisoned, so the next transaction commits.
            block_on(engine.submit(push_transaction(namespace, 3, 0xd2, None)))
                .expect("a later append is allowed");
        }

        /// Scope 6.3 step 10, same rule one step later.
        #[test]
        fn a_lost_response_leaves_a_committed_and_queryable_receipt() {
            let expectation = expectation(Failpoint::BeforeResponse);
            assert!(!expectation.shard_poisoned);
            assert!(expectation.acknowledgment_allowed);
            assert_eq!(expectation.immediate_status, ImmediateStatus::Committed);

            let serial = writer_serial();
            let temporary = tempfile::tempdir().expect("tempdir");
            let namespace = NamespaceId([0xe0; 32]);
            let engine = open(&serial, temporary.path(), 1);
            block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

            arm(&serial, Failpoint::BeforeResponse, FailpointAction::Fail);
            let lost = block_on(engine.submit(push_transaction(namespace, 2, 0xe1, None)));
            disarm(&serial);
            assert!(matches!(lost, Err(StoreError::Io(_))));

            assert!(matches!(
                engine
                    .transaction_status(namespace, OperationId([2; 16]))
                    .expect("status"),
                TransactionStatus::Committed(_)
            ));
            block_on(engine.submit(push_transaction(namespace, 3, 0xe2, None)))
                .expect("a later append is allowed");
        }

        /// Scope 3.7: steps 4 to 8 are the poison window. A failure between
        /// the `Resolving` mark and the committed-root publication leaves the
        /// operation `Resolving` — never `Unknown`, and never a receipt — and
        /// the shard admits no further mutation.
        #[test]
        fn a_failure_inside_the_publication_window_poisons_and_stays_resolving() {
            let expectation = expectation(Failpoint::BeforeRootCas);
            assert!(expectation.shard_poisoned);
            assert!(!expectation.acknowledgment_allowed);
            assert!(!expectation.later_append_allowed_before_recovery);
            assert_eq!(expectation.immediate_status, ImmediateStatus::Resolving);

            let serial = writer_serial();
            let temporary = tempfile::tempdir().expect("tempdir");
            let namespace = NamespaceId([0xf0; 32]);
            let engine = open(&serial, temporary.path(), 1);
            block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

            arm(&serial, Failpoint::BeforeRootCas, FailpointAction::Fail);
            let poisoned = block_on(engine.submit(push_transaction(namespace, 2, 0xf1, None)));
            disarm(&serial);
            assert!(matches!(poisoned, Err(StoreError::ShardPoisoned { .. })));

            match engine
                .transaction_status(namespace, OperationId([2; 16]))
                .expect("status")
            {
                TransactionStatus::Resolving {
                    shard_sequence,
                    operation_digest,
                    ..
                } => {
                    assert_eq!(shard_sequence, Some(1));
                    assert_eq!(operation_digest, ObjectId([2; 32]));
                }
                other => panic!("the group must remain Resolving, got {other:?}"),
            }

            assert!(matches!(
                block_on(engine.submit(push_transaction(namespace, 3, 0xf2, None))),
                Err(StoreError::ShardPoisoned { .. })
            ));
        }

        /// The `Panic` action on a publication-side row (scope 4-A3 condition
        /// (b)). The failpoint names a *location*; the driver chooses the
        /// *action*, and the two axes are independent.
        ///
        /// The property under test is not the panic — it is that a panicking
        /// writer thread still resolves every caller it owes an outcome to. A
        /// completion that unwound with the frame it belonged to would leave
        /// `submit` waiting forever, which from outside is indistinguishable
        /// from a store that hung.
        #[test]
        fn a_writer_panic_inside_the_window_resolves_its_callers_rather_than_hanging() {
            let serial = writer_serial();
            let expectation = expectation(Failpoint::DuringCommittedRootBuild);
            assert!(expectation.shard_poisoned);
            assert_eq!(expectation.immediate_status, ImmediateStatus::Resolving);

            let temporary = tempfile::tempdir().expect("tempdir");
            let namespace = NamespaceId([0x28; 32]);
            let engine = open(&serial, temporary.path(), 1);
            block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

            arm(
                &serial,
                Failpoint::DuringCommittedRootBuild,
                FailpointAction::Panic,
            );
            let outcome = block_on_until(
                engine.submit(push_transaction(namespace, 2, 0x29, None)),
                Duration::from_secs(5),
            );
            disarm(&serial);
            match outcome {
                Some(Err(StoreError::ShardPoisoned { shard, .. })) => assert_eq!(shard, 0),
                other => panic!("a panicking writer must resolve its callers, got {other:?}"),
            }

            // The operation stays `Resolving`: step 8 never ran, and only
            // recovery may resolve it.
            assert!(matches!(
                engine
                    .transaction_status(namespace, OperationId([2; 16]))
                    .expect("status"),
                TransactionStatus::Resolving { .. }
            ));

            // The writer thread is gone, so the shard admits no further
            // mutation before a close and reopen through recovery.
            assert!(matches!(
                block_on(engine.submit(push_transaction(namespace, 3, 0x2a, None))),
                Err(StoreError::NotReady)
            ));
        }

        /// P1-5 case 1. A **panic** in scope 6.3 steps 1-3 is a pre-append
        /// failure, not a poisoning one.
        ///
        /// The single boundary catch treated every panic as a publication
        /// panic: the caller was told `ShardPoisoned` — which asserts the
        /// transaction may already be durable — and the reservation taken
        /// before sequencing was left behind, so the operation read back
        /// `Pending` forever for something that never reached the device.
        /// Nothing appended, so nothing can: the fate must match the phase.
        #[test]
        fn a_panic_before_the_mark_is_definitively_absent_and_does_not_poison() {
            let expectation = expectation(Failpoint::EvidenceHandoffFailure);
            assert!(!expectation.shard_poisoned);
            assert!(expectation.later_append_allowed_before_recovery);
            assert_eq!(
                expectation.immediate_status,
                ImmediateStatus::DefinitiveAbsent
            );

            let serial = writer_serial();
            let temporary = tempfile::tempdir().expect("tempdir");
            let namespace = NamespaceId([0x1b; 32]);
            let engine = open(&serial, temporary.path(), 1);
            block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

            arm(
                &serial,
                Failpoint::EvidenceHandoffFailure,
                FailpointAction::Panic,
            );
            let refused = block_on_until(
                engine.submit(push_transaction(namespace, 2, 0x1c, None)),
                Duration::from_secs(5),
            );
            disarm(&serial);
            match refused {
                Some(Err(StoreError::Conflict(reason))) => assert!(
                    reason.contains("pre-append"),
                    "the refusal must say the transaction is absent, got {reason}"
                ),
                other => panic!(
                    "a pre-append panic must be a definitive refusal, never a poisoned \
                     shard or a hang, got {other:?}"
                ),
            }

            assert_eq!(
                engine
                    .transaction_status(namespace, OperationId([2; 16]))
                    .expect("status"),
                TransactionStatus::Unknown,
                "a pre-append panic releases the reservation it took"
            );
            assert_eq!(
                engine.operation_status_metrics().occupancy,
                0,
                "no status entry survives a pre-append panic"
            );

            // Steps 1-3 cannot poison, and a dead writer thread would make
            // `later_append_allowed_before_recovery` false whatever the error
            // said. The next transaction commits, contiguously.
            let later = block_on(engine.submit(push_transaction(namespace, 3, 0x1d, None)))
                .expect("a later append is allowed");
            assert_eq!(later.repo_sequence, 1);
        }

        /// P1-5 case 2. A request that overflows the open byte-bounded group is
        /// not a member of the group that publication is about to write.
        ///
        /// The old order added the new request to the group's bookkeeping and
        /// then published the *old* group, so a publication panic reported the
        /// trailing request as poisoned though it never appended, and left its
        /// reservation `Pending` with nothing to resolve it. It also made the
        /// trailing frame's `shard_sequence` a prediction about how many
        /// members the closing group would keep — which scope 6.3 step 3 can
        /// change.
        #[test]
        fn a_request_that_overflows_a_publishing_group_is_not_reported_as_its_member() {
            let serial = writer_serial();
            let temporary = tempfile::tempdir().expect("tempdir");
            let namespace = NamespaceId([0x1e; 32]);
            let mut configured = options(&serial, temporary.path(), 1);
            configured.max_group_transactions = 64;
            // Wide enough that one small frame leaves the group open, and
            // narrow enough that a small frame plus a large one overflows it.
            // Stated as two sizes rather than one measured constant so the
            // overflow does not depend on the exact framing overhead.
            configured.max_group_bytes = 8 * 1024;
            configured.max_group_idle = Duration::from_secs(5);
            let engine = StoreEngine::open(configured).expect("open");
            block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

            let large = || {
                ValidatedTransaction::builder(PrivilegedConstruction::internal())
                    .namespace(namespace)
                    .operation(OperationId([3; 16]), ObjectId([3; 32]), deadline())
                    .objects(vec![StagedObject {
                        id: ObjectId([0x3f; 32]),
                        object_type: ObjectType::Blob,
                        raw: vec![0x3f; 32 * 1024],
                    }])
                    .refs(Vec::new())
                    .authority(Some(genesis_object().id), Some(genesis_object().id))
                    .evidence(evidence())
                    .build()
                    .expect("a complete push transaction")
            };

            // A panic and not a `Fail`: the old code released the trailing
            // request's reservation explicitly on the `Fail` path, so the leak
            // only appears when the publication unwinds and the single boundary
            // catch is the only thing left to resolve anyone.
            arm(
                &serial,
                Failpoint::AfterMarkedResolving,
                FailpointAction::Panic,
            );
            let (small, big) = std::thread::scope(|scope| {
                let small = scope.spawn(|| {
                    block_on_until(
                        engine.submit(push_transaction(namespace, 2, 0x2f, None)),
                        Duration::from_secs(10),
                    )
                });
                let big = scope.spawn(|| {
                    // Long enough that the small frame is already in the open
                    // group, short enough that the idle bound has not closed it.
                    std::thread::sleep(Duration::from_millis(300));
                    block_on_until(engine.submit(large()), Duration::from_secs(10))
                });
                (small.join().expect("small"), big.join().expect("big"))
            });
            disarm(&serial);

            assert!(
                matches!(small, Some(Err(StoreError::ShardPoisoned { .. }))),
                "the member that was marked Resolving is inside the poison window, got {small:?}"
            );
            match big {
                Some(Err(StoreError::Conflict(ref reason))) => assert!(
                    reason.contains("pre-append"),
                    "the trailing request never appended, so its refusal must say so: {reason}"
                ),
                ref other => panic!(
                    "a request that never joined the published group is pre-append, never \
                     poisoned, got {other:?}"
                ),
            }

            // The point of the test: the trailing request appended nothing and
            // holds nothing. Under the old order it was left `Pending` with no
            // owner, which no recovery resolves because recovery only ever sees
            // what reached the device.
            assert_eq!(
                engine
                    .transaction_status(namespace, OperationId([3; 16]))
                    .expect("status"),
                TransactionStatus::Unknown,
                "a request that never joined the published group leaves no reservation"
            );
            assert!(
                matches!(
                    engine
                        .transaction_status(namespace, OperationId([2; 16]))
                        .expect("status"),
                    TransactionStatus::Resolving { .. }
                ),
                "the group that was marked Resolving stays Resolving"
            );
            assert_eq!(
                engine.operation_status_metrics().occupancy,
                1,
                "exactly one operation — the one inside the poison window — is retained"
            );
        }

        /// P1-5 case 3. Scope 6.3 steps 9 and 10 cannot poison, so a panic
        /// there resolves every caller with the receipt it is owed and leaves
        /// the writer running.
        ///
        /// The fence succeeded and the root published: the transaction is
        /// committed and unwithdrawable. The old boundary catch unwound after
        /// the waiters had been drained out of writer-owned storage, so it
        /// could not reach them at all, and it killed the writer — which makes
        /// `later_append_allowed_before_recovery` false for a row the frozen
        /// oracle marks `shard_poisoned: false`.
        #[test]
        fn a_panic_after_publication_still_hands_back_the_receipt_and_keeps_the_writer() {
            let expectation = expectation(Failpoint::AfterRootCasBeforeWaiterWake);
            assert!(!expectation.shard_poisoned);
            assert!(expectation.acknowledgment_allowed);
            assert!(expectation.later_append_allowed_before_recovery);
            assert_eq!(expectation.immediate_status, ImmediateStatus::Committed);

            let serial = writer_serial();
            let temporary = tempfile::tempdir().expect("tempdir");
            let namespace = NamespaceId([0x1f; 32]);
            let engine = open(&serial, temporary.path(), 1);
            block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

            arm(
                &serial,
                Failpoint::AfterRootCasBeforeWaiterWake,
                FailpointAction::Panic,
            );
            let outcome = block_on_until(
                engine.submit(push_transaction(namespace, 2, 0x2b, None)),
                Duration::from_secs(5),
            );
            disarm(&serial);
            match outcome {
                Some(Ok(receipt)) => assert_eq!(receipt.repo_sequence, 1),
                other => panic!(
                    "a published transaction is committed; steps 9-10 may not turn it into \
                     anything else, got {other:?}"
                ),
            }

            assert!(matches!(
                engine
                    .transaction_status(namespace, OperationId([2; 16]))
                    .expect("status"),
                TransactionStatus::Committed(_)
            ));
            let later = block_on(engine.submit(push_transaction(namespace, 3, 0x2c, None)))
                .expect("the writer survives a non-poisoning panic");
            assert_eq!(later.repo_sequence, 2);
        }

        /// Scope 6.3 step 2, as reclassified by contract review 2026-07-26-A:
        /// definitively absent, shard not poisoned, later append allowed. A
        /// routine `SignerError::Unavailable` must not take the shard down.
        #[test]
        fn an_evidence_handoff_failure_is_definitively_absent() {
            let expectation = expectation(Failpoint::EvidenceHandoffFailure);
            assert!(!expectation.shard_poisoned);
            assert!(!expectation.acknowledgment_allowed);
            assert!(expectation.later_append_allowed_before_recovery);
            assert_eq!(
                expectation.immediate_status,
                ImmediateStatus::DefinitiveAbsent
            );

            let serial = writer_serial();
            let temporary = tempfile::tempdir().expect("tempdir");
            let namespace = NamespaceId([0x18; 32]);
            let engine = open(&serial, temporary.path(), 1);
            block_on(engine.submit(create_transaction(namespace, 1))).expect("create");

            arm(
                &serial,
                Failpoint::EvidenceHandoffFailure,
                FailpointAction::Fail,
            );
            let refused = block_on(engine.submit(push_transaction(namespace, 2, 0x19, None)));
            disarm(&serial);
            assert!(matches!(
                refused,
                Err(StoreError::Signer(SignerError::Unavailable))
            ));

            assert_eq!(
                engine
                    .transaction_status(namespace, OperationId([2; 16]))
                    .expect("status"),
                TransactionStatus::Unknown,
                "a definitively absent operation releases its reservation"
            );

            // Not poisoned, and no sequence was consumed: the next append is
            // contiguous with the create rather than leaving a hole.
            let later = block_on(engine.submit(push_transaction(namespace, 3, 0x1a, None)))
                .expect("a later append is allowed");
            assert_eq!(later.repo_sequence, 1);
        }
    }
}

// ---------------------------------------------------------------------------
// Index maintenance (scope 3.6, deliverable 1)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod index_maintenance_tests {
    use std::future::Future;
    use std::path::Path;
    use std::task::{Context, Poll, Wake, Waker};
    use std::time::Duration;

    use super::tests::*;
    use super::*;
    use crate::index::IndexKey;
    use crate::segment::{index_run_filename, read_current, read_manifest, RootLayout};
    use crate::{PrivilegedConstruction, StagedObject};

    /// A root whose index ceilings make sealing reachable in a few groups.
    ///
    /// `max_active_index_entries` is the lever the acceptance point names:
    /// crossing it is `DeltaPressure::SealRequired`. One object per transaction
    /// means one entry per group, so the ceiling is also the layer count that
    /// crosses it.
    fn sealing_options(serial: &WriterSerial, root: &Path, entries: u64) -> StoreOptions {
        let mut options = options(serial, root, 1);
        options.max_active_index_entries = entries;
        // Sequential submits must each close their own group, or "three groups"
        // is one group of three and no layer accumulates.
        options.max_group_transactions = 1;
        options
    }

    fn shard_paths(root: &Path, shard: u16) -> crate::segment::ShardPaths {
        RootLayout::new(root).shard(shard)
    }

    /// Every index run the manifest `CURRENT` names, which is the only list
    /// that makes a run authoritative.
    fn manifest_runs(root: &Path, shard: u16, root_uuid: [u8; 16]) -> Vec<String> {
        let paths = shard_paths(root, shard);
        let pointer = read_current(&paths, &root_uuid)
            .expect("read CURRENT")
            .expect("a root that has been opened has a CURRENT");
        read_manifest(&paths, pointer.generation, &root_uuid)
            .expect("read the current manifest")
            .index_runs
            .into_iter()
            .map(|(_, name)| name)
            .collect()
    }

    fn root_uuid_of(root: &Path) -> [u8; 16] {
        crate::segment::read_format(&RootLayout::new(root))
            .expect("FORMAT")
            .root_uuid
    }

    /// A push carrying two objects, for the projection tests.
    fn two_object_push(namespace: NamespaceId, blob: u8) -> ValidatedTransaction {
        let authority = genesis_object().id;
        ValidatedTransaction::builder(PrivilegedConstruction::internal())
            .namespace(namespace)
            .operation(OperationId([blob; 16]), ObjectId([blob; 32]), deadline())
            .objects(vec![
                StagedObject {
                    id: ObjectId([blob; 32]),
                    object_type: ObjectType::Blob,
                    raw: vec![blob; 64],
                },
                StagedObject {
                    id: ObjectId([blob.wrapping_add(1); 32]),
                    object_type: ObjectType::Blob,
                    raw: vec![blob.wrapping_add(1); 64],
                },
            ])
            .refs(Vec::new())
            .authority(Some(authority), Some(authority))
            .evidence(evidence())
            .build()
            .expect("a two-object push")
    }

    /// Commit `count` single-object pushes, each in its own group.
    fn push_groups(
        engine: &StoreEngine,
        namespace: NamespaceId,
        first: u8,
        count: u8,
    ) -> Vec<ObjectId> {
        let mut objects = Vec::new();
        for step in 0..count {
            let blob = first + step;
            block_on(engine.submit(push_transaction(namespace, blob, blob, None)))
                .unwrap_or_else(|error| panic!("push {blob} commits: {error:?}"));
            objects.push(ObjectId([blob; 32]));
        }
        objects
    }

    /// Drive two submissions with both in flight.
    ///
    /// The first is polled once before the second starts, which is what puts it
    /// in the writer's open group while the second is being admitted. Then both
    /// are polled to completion — the first cannot finish until the group
    /// publishes, so waiting on it alone would deadlock against a group the
    /// second submission is meant to be judged against.
    fn submit_together<A, B>(first: A, second: B) -> (A::Output, B::Output)
    where
        A: Future,
        B: Future,
    {
        struct ThreadWaker(std::thread::Thread);
        impl Wake for ThreadWaker {
            fn wake(self: Arc<Self>) {
                self.0.unpark();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.0.unpark();
            }
        }
        let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut first = std::pin::pin!(first);
        let mut second = std::pin::pin!(second);
        let (mut first_out, mut second_out) = (None, None);

        // The order matters: the first submission must reach the writer before
        // the second is polled at all.
        if let Poll::Ready(output) = first.as_mut().poll(&mut context) {
            first_out = Some(output);
        }

        let start = std::time::Instant::now();
        loop {
            if second_out.is_none() {
                if let Poll::Ready(output) = second.as_mut().poll(&mut context) {
                    second_out = Some(output);
                }
            }
            if first_out.is_none() {
                if let Poll::Ready(output) = first.as_mut().poll(&mut context) {
                    first_out = Some(output);
                }
            }
            if first_out.is_some() && second_out.is_some() {
                return (first_out.expect("checked"), second_out.expect("checked"));
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "neither submission completed within the test deadline"
            );
            std::thread::park_timeout(Duration::from_millis(5));
        }
    }

    /// Two namespaces that route to different shards of a four-shard root.
    fn two_shards() -> Vec<(u16, NamespaceId)> {
        let mut namespaces = Vec::new();
        for byte in 0u8..64 {
            let candidate = NamespaceId([byte; 32]);
            let shard = StoreOptions::shard_of(&candidate, 4);
            if !namespaces.iter().any(|(s, _)| *s == shard) {
                namespaces.push((shard, candidate));
            }
            if namespaces.len() == 2 {
                break;
            }
        }
        namespaces
    }

    /// The acceptance point, and the discard it pays for.
    ///
    /// Three groups leave three layers at a ceiling of three. The fourth
    /// submission is admitted only after the seal — and is then refused by the
    /// replay ceiling, which a seal cannot relieve while every frame is still in
    /// `active/`.
    #[test]
    fn crossing_seal_required_seals_before_admitting_more_work() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let engine = StoreEngine::open(sealing_options(&serial, temporary.path(), 3))
            .expect("open a fresh root");
        let namespace = NamespaceId([0x41; 32]);
        block_on(engine.submit(create_transaction(namespace, 1))).expect("create");
        push_groups(&engine, namespace, 0x60, 2);

        let before = engine.index_maintenance();
        assert_eq!(
            (before.sealed_runs, before.unsealed_delta_layers),
            (0, 3),
            "three groups must leave three unsealed layers and no run"
        );

        let refused = block_on(engine.submit(push_transaction(namespace, 0x70, 0x70, None)))
            .expect_err("the shard is at the ceiling a reopen would have to rebuild");
        assert!(
            matches!(
                refused,
                StoreError::LimitExceeded {
                    limit: "max_active_index_entries",
                    ..
                }
            ),
            "expected the replay ceiling, got {refused:?}"
        );

        let after = engine.index_maintenance();
        assert_eq!(
            (after.sealed_runs, after.unsealed_delta_layers),
            (1, 0),
            "the seal must publish one run and discard exactly the three layers it covered"
        );
        assert_eq!(
            manifest_runs(temporary.path(), 0, root_uuid_of(temporary.path())),
            vec![index_run_filename(1)],
            "the run must be named by the current manifest"
        );
    }

    /// Sealing is only correct if the run answers what the layers answered.
    #[test]
    fn a_sealed_run_answers_every_covered_object_before_and_after_reopen() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x42; 32]);
        let configure = || {
            let mut options = sealing_options(&serial, temporary.path(), 4_000_000);
            options.max_index_runs = 3;
            options.max_open_index_runs = 3;
            options
        };
        let mut covered = vec![genesis_object().id];
        {
            let engine = StoreEngine::open(configure()).expect("open a fresh root");
            block_on(engine.submit(create_transaction(namespace, 2))).expect("create");
            covered.extend(push_groups(&engine, namespace, 0x80, 2));
            // Three layers cross the fan-out ceiling, so this submission seals.
            block_on(engine.submit(push_transaction(namespace, 0x88, 0x88, None)))
                .expect("the group after the seal commits");
            assert_eq!(engine.index_maintenance().sealed_runs, 1, "the seal ran");

            let root = engine.committed_root();
            for object in &covered {
                let key = IndexKey::new(namespace, *object);
                // Without this the lookup below would pass on a store that
                // sealed nothing: a delta layer still holding the key answers
                // it, and the run is never consulted.
                assert!(
                    root.index()
                        .delta_layers()
                        .iter()
                        .all(|layer| layer.delta.get(&key).is_none()),
                    "{} is still answered by a delta layer, so this asserts nothing about the run",
                    object.to_hex()
                );
                let location = root
                    .index()
                    .get(&key)
                    .unwrap_or_else(|| panic!("{} is not in the sealed run", object.to_hex()));
                assert!(
                    root.object_source(0, location.segment_generation)
                        .expect("resolve")
                        .is_some(),
                    "the run's location must resolve to a file the root still pins"
                );
            }
        }

        let engine = StoreEngine::open(configure()).expect("reopen through production recovery");
        assert_eq!(
            engine.index_maintenance().sealed_runs,
            1,
            "a manifest-published run must be recovered"
        );
        let root = engine.committed_root();
        for object in &covered {
            assert!(
                root.index()
                    .get(&IndexKey::new(namespace, *object))
                    .is_some(),
                "{} did not survive the reopen",
                object.to_hex()
            );
        }
    }

    /// A run that reached the device but never a manifest is not a run.
    #[test]
    fn a_run_no_manifest_names_is_ignored_on_reopen() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x43; 32]);
        {
            let engine = StoreEngine::open(sealing_options(&serial, temporary.path(), 3))
                .expect("open a fresh root");
            block_on(engine.submit(create_transaction(namespace, 3))).expect("create");
        }

        // Exactly what an interrupted seal leaves: a complete, valid run at the
        // name the next generation would have used, with no manifest naming it.
        let uuid = root_uuid_of(temporary.path());
        let mut delta = IndexDelta::new(16, 1 << 20);
        delta
            .insert(
                IndexKey::new(namespace, ObjectId([0xEE; 32])),
                IndexLocation {
                    segment_generation: 1,
                    frame_offset: 0,
                    frame_len: 1,
                    object_type: ObjectType::Blob as u8,
                    shard_sequence: 1,
                },
            )
            .expect("one entry");
        let orphan = shard_paths(temporary.path(), 0)
            .indexes()
            .join(index_run_filename(9));
        std::fs::write(
            &orphan,
            IndexRunBuilder::new(uuid, 9, 9)
                .build(&delta)
                .expect("encode"),
        )
        .expect("write the orphan");

        let engine = StoreEngine::open(sealing_options(&serial, temporary.path(), 3))
            .expect("reopen with an orphan present");
        assert_eq!(
            engine.index_maintenance().sealed_runs,
            0,
            "an index run no manifest references must not become authoritative by existing"
        );
        assert!(
            engine
                .committed_root()
                .index()
                .get(&IndexKey::new(namespace, ObjectId([0xEE; 32])))
                .is_none(),
            "the orphan's entries must be invisible"
        );
        assert!(orphan.is_file(), "and it is left alone, not reclaimed here");
    }

    /// Link the live journal into `segments/` under `generation`.
    ///
    /// Scope 3.4 step 4 interrupted before step 5: the name is taken, and what
    /// holds it is not a readable segment, so recovery learns the generation is
    /// occupied from the name alone.
    fn orphan_segment_at(root: &Path, shard: u16, generation: u64) {
        let paths = shard_paths(root, shard);
        std::fs::hard_link(
            active_journal_path(&paths),
            paths
                .segments()
                .join(crate::segment::segment_filename(generation, 0, 9)),
        )
        .expect("link the orphan");
    }

    fn active_journal_path(paths: &crate::segment::ShardPaths) -> std::path::PathBuf {
        std::fs::read_dir(paths.active())
            .expect("active/")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.extension().and_then(|value| value.to_str()) == Some("journal"))
            .expect("an open root has an active journal")
    }

    /// A zero-length `.recovery-<journal>-<generation>.prefix`.
    ///
    /// An interrupted recovery that crashed just after creating its
    /// construction artifact, which is the state that fixes the identity a
    /// resumed recovery must reuse. Zero-length is a valid one: the seal
    /// compares the bytes that exist — none — and copies the rest.
    fn resumable_prefix_at(root: &Path, shard: u16, generation: u64) {
        use std::io::Read;

        let paths = shard_paths(root, shard);
        let mut bytes = [0u8; crate::format::JOURNAL_HEADER_LEN];
        std::fs::File::open(active_journal_path(&paths))
            .expect("open the journal")
            .read_exact(&mut bytes)
            .expect("read its header");
        let header = crate::format::JournalHeader::decode(&bytes).expect("decode its header");
        std::fs::write(
            paths.segments().join(format!(
                ".recovery-{}-{generation}.prefix",
                hex::encode(header.journal_id)
            )),
            [],
        )
        .expect("write the interrupted artifact");
    }

    /// Every path that names the frames something other than the identity they
    /// carry owes the same refusal, so the tests assert it through one function
    /// rather than through copies that can drift apart the way the code did.
    fn assert_the_open_refuses_naming_the_run(options: StoreOptions, root: &Path) {
        let runs = manifest_runs(root, 0, root_uuid_of(root));
        assert_eq!(runs.len(), 1, "one published run is the whole premise");

        match StoreEngine::open(options) {
            Err(StoreError::Corruption(message)) => assert!(
                message.contains(&runs[0]),
                "the refusal must name the run that cannot be resolved, not just \
                 report a generation: {message}"
            ),
            Err(other) => panic!("expected Corruption naming the run, got {other:?}"),
            // Not prose: the state this refuses is verified here, so removing
            // the refusal reports what it costs rather than a bare expectation.
            Ok(opened) => {
                let committed = opened.committed_root();
                let pinned = committed.object_source(0, 1).expect("resolve generation 1");
                panic!(
                    "the open succeeded with a published run naming generation 1, and the \
                     reopened root pins {pinned:?} there — every lookup reaching the run \
                     rather than the replay delta above it reads nothing"
                );
            }
        }
    }

    /// Contract review 2026-07-30-B: the two states an occupied identity leaves.
    ///
    /// The tail's identity is generation 1 and a published run holds locations
    /// against it. An orphan `.seg` occupies that name, so recovery must seal
    /// the frames under a different one — and the run then stays authoritative
    /// through the manifest while resolving to nothing. Recovery refuses.
    ///
    /// Replay masks this while a lookup goes through the delta above the run, so
    /// the assertion is the open itself. `StoreEngine::checkpoint` is a direct
    /// run consumer and would not be masked.
    #[test]
    fn an_orphan_holding_a_published_runs_identity_refuses_the_open() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x4A; 32]);
        let configure = || {
            let mut options = sealing_options(&serial, temporary.path(), 4_000_000);
            options.max_index_runs = 3;
            options.max_open_index_runs = 3;
            options
        };
        {
            let engine = StoreEngine::open(configure()).expect("open a fresh root");
            block_on(engine.submit(create_transaction(namespace, 2))).expect("create");
            push_groups(&engine, namespace, 0x60, 2);
            block_on(engine.submit(push_transaction(namespace, 0x68, 0x68, None)))
                .expect("the group after the seal commits");
            assert_eq!(engine.index_maintenance().sealed_runs, 1, "the seal ran");
            orphan_segment_at(temporary.path(), 0, 1);
        }

        assert_the_open_refuses_naming_the_run(configure(), temporary.path());
    }

    /// The same displacement, one crash later, which is the case the first
    /// version of this guard let through.
    ///
    /// A previous recovery already fell back to generation 2 and left its
    /// construction artifact behind. Resuming reuses that identity — correctly,
    /// since finishing an interrupted seal must not orphan the artifact — but
    /// the identity it reuses is still not the one the frames carry, so the
    /// published run naming generation 1 is stranded exactly as it would be by a
    /// fresh fallback. Resumption is a reason to keep a choice, not a reason to
    /// skip the check on it.
    #[test]
    fn a_resumed_fallback_refuses_on_the_identity_it_resumes() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x4C; 32]);
        let configure = || {
            let mut options = sealing_options(&serial, temporary.path(), 4_000_000);
            options.max_index_runs = 3;
            options.max_open_index_runs = 3;
            options
        };
        {
            let engine = StoreEngine::open(configure()).expect("open a fresh root");
            block_on(engine.submit(create_transaction(namespace, 2))).expect("create");
            push_groups(&engine, namespace, 0x60, 2);
            block_on(engine.submit(push_transaction(namespace, 0x68, 0x68, None)))
                .expect("the group after the seal commits");
            assert_eq!(engine.index_maintenance().sealed_runs, 1, "the seal ran");
            orphan_segment_at(temporary.path(), 0, 1);
            resumable_prefix_at(temporary.path(), 0, 2);
        }

        assert_the_open_refuses_naming_the_run(configure(), temporary.path());
    }

    /// Resumption itself is not the hazard, and a guard that treated it as one
    /// would refuse every interrupted recovery on a root that has ever sealed.
    ///
    /// Here the interrupted seal had chosen the identity the frames already
    /// carry, so resuming it displaces nothing and the published run resolves
    /// through the segment the resumed seal installs.
    #[test]
    fn a_resumed_seal_at_the_frames_own_identity_still_opens() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x4D; 32]);
        let configure = || {
            let mut options = sealing_options(&serial, temporary.path(), 4_000_000);
            options.max_index_runs = 3;
            options.max_open_index_runs = 3;
            options
        };
        {
            let engine = StoreEngine::open(configure()).expect("open a fresh root");
            block_on(engine.submit(create_transaction(namespace, 2))).expect("create");
            push_groups(&engine, namespace, 0x60, 2);
            block_on(engine.submit(push_transaction(namespace, 0x68, 0x68, None)))
                .expect("the group after the seal commits");
            assert_eq!(engine.index_maintenance().sealed_runs, 1, "the seal ran");
            resumable_prefix_at(temporary.path(), 0, 1);
        }

        let engine = StoreEngine::open(configure()).expect("resuming its own identity must open");
        let root = engine.committed_root();
        assert!(
            root.object_source(0, 1)
                .expect("resolve generation 1")
                .is_some(),
            "the resumed seal kept the identity the run names, so it must resolve"
        );
    }

    /// The other half, and the reason the refusal is conditioned on the run
    /// rather than on the orphan.
    ///
    /// Same occupied identity, nothing published against it. An orphan segment
    /// is a state in which the active journal remains the authority, and
    /// refusing here would turn a recoverable root into an outage.
    #[test]
    fn an_orphan_holding_no_published_identity_still_opens() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x4B; 32]);
        let mut objects = vec![genesis_object().id];
        {
            let engine = StoreEngine::open(sealing_options(&serial, temporary.path(), 4_000_000))
                .expect("open a fresh root");
            block_on(engine.submit(create_transaction(namespace, 2))).expect("create");
            objects.extend(push_groups(&engine, namespace, 0x70, 2));
            assert_eq!(
                engine.index_maintenance().sealed_runs,
                0,
                "nothing is published against the identity the orphan takes"
            );
            orphan_segment_at(temporary.path(), 0, 1);
        }

        let engine = StoreEngine::open(sealing_options(&serial, temporary.path(), 4_000_000))
            .expect("an orphan segment alone must not fail recovery");
        let root = engine.committed_root();
        for object in &objects {
            assert!(
                root.index()
                    .get(&IndexKey::new(namespace, *object))
                    .is_some(),
                "{} was acknowledged and must survive the reopen",
                object.to_hex()
            );
        }
    }

    /// The discard is scoped to the shard that sealed.
    #[test]
    fn only_the_sealing_shards_layers_are_discarded() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespaces = two_shards();
        let (sealing_shard, sealing_namespace) = namespaces[0];
        let (other_shard, other_namespace) = namespaces[1];
        let mut options = sealing_options(&serial, temporary.path(), 4_000_000);
        options.shard_count = 4;
        options.max_index_runs = 1;
        options.max_open_index_runs = 1;
        let engine = StoreEngine::open(options).expect("open a fresh root");

        // One layer on the other shard and no further submission to it, so it
        // never reaches an admission that would seal.
        block_on(engine.submit(create_transaction(other_namespace, 0x11))).expect("create");
        let other_layers_before = engine
            .committed_root()
            .index()
            .delta_layers()
            .iter()
            .filter(|layer| layer.shard_index == other_shard)
            .count();
        assert!(
            other_layers_before > 0,
            "the other shard must have a backlog"
        );

        block_on(engine.submit(create_transaction(sealing_namespace, 0x12))).expect("create");
        // Its one layer crosses a fan-out ceiling of one, so this seals.
        block_on(engine.submit(push_transaction(sealing_namespace, 0xB0, 0xB0, None)))
            .expect("the group after the seal commits");

        let root = engine.committed_root();
        assert_eq!(
            root.index()
                .delta_layers()
                .iter()
                .filter(|layer| layer.shard_index == other_shard)
                .count(),
            other_layers_before,
            "shard {other_shard} lost layers to a seal on shard {sealing_shard}"
        );
        assert_eq!(
            root.index().sealed_run_count(),
            1,
            "exactly the sealing shard published a run"
        );
    }

    /// The ceilings recovery enforces are the ceilings the writer enforces.
    ///
    /// With room for one run, a second seal is refused as `LimitExceeded` naming
    /// the ceiling — not raised, not bypassed, and not the `NotImplemented` the
    /// unimplemented path used to answer. Nothing durable was attempted, so the
    /// shard stays usable.
    #[test]
    fn the_run_ceilings_are_enforced_rather_than_raised() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let mut options = sealing_options(&serial, temporary.path(), 4_000_000);
        options.max_index_runs = 1;
        options.max_open_index_runs = 1;
        let engine = StoreEngine::open(options).expect("open a fresh root");
        let namespace = NamespaceId([0x44; 32]);

        block_on(engine.submit(create_transaction(namespace, 4))).expect("create");
        // One layer crosses the fan-out ceiling of one, so this seals.
        block_on(engine.submit(push_transaction(namespace, 0xC0, 0xC0, None)))
            .expect("the group after the seal commits");
        assert_eq!(engine.index_maintenance().sealed_runs, 1);

        // That group left a layer of its own, so the next admission is due a
        // second seal — which does not fit.
        let refused = block_on(engine.submit(push_transaction(namespace, 0xC5, 0xC5, None)))
            .expect_err("a second run does not fit under max_index_runs = 1");
        match refused {
            StoreError::LimitExceeded { limit, allowed, .. } => {
                assert_eq!(limit, "max_index_runs");
                assert_eq!(allowed, 1);
            }
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
        assert_eq!(
            engine.index_maintenance().sealed_runs,
            1,
            "the refusal must not have installed a run"
        );
        assert_eq!(
            manifest_runs(temporary.path(), 0, root_uuid_of(temporary.path())).len(),
            1
        );
    }

    /// P1: admission must project the transaction it is deciding about.
    ///
    /// A root-only check reads the state *before* the incoming objects, so with
    /// room for two entries and one already present, a two-object transaction
    /// committed and the store then failed to open. The reopen is the assertion:
    /// a store must never be unable to read back what it accepted.
    #[test]
    fn admission_projects_the_incoming_transaction_into_the_replay_ceiling() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x46; 32]);
        {
            let engine = StoreEngine::open(sealing_options(&serial, temporary.path(), 2))
                .expect("open a fresh root");
            block_on(engine.submit(create_transaction(namespace, 6))).expect("one object");

            let refused = block_on(engine.submit(two_object_push(namespace, 0xE0)))
                .expect_err("two more objects do not fit under a ceiling of two");
            assert!(
                matches!(
                    refused,
                    StoreError::LimitExceeded {
                        limit: "max_active_index_entries",
                        ..
                    }
                ),
                "expected the replay ceiling to refuse, got {refused:?}"
            );
        }
        StoreEngine::open(sealing_options(&serial, temporary.path(), 2))
            .expect("a store must reopen whatever it accepted");
    }

    /// The same projection, for members already admitted into the open group.
    ///
    /// Both submissions are genuinely **in flight**. `submit` is an `async fn`,
    /// so its send happens on the first poll; awaiting one to completion before
    /// starting the other is two groups and not one, and a test written that way
    /// passes with the pending-group projection removed — the refusal follows
    /// from the published root alone. Here the first submission is polled once so
    /// that it reaches `pending`, and the second is decided while it is still
    /// there.
    #[test]
    fn admission_projects_the_open_group_into_the_replay_ceiling() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x47; 32]);
        let mut options = sealing_options(&serial, temporary.path(), 3);
        // The group must stay open across both submissions.
        options.max_group_transactions = 8;
        options.max_group_idle = Duration::from_millis(300);
        {
            let engine = StoreEngine::open(options).expect("open a fresh root");
            block_on(engine.submit(create_transaction(namespace, 7))).expect("one object");

            let (first, second) = submit_together(
                engine.submit(two_object_push(namespace, 0xE4)),
                engine.submit(two_object_push(namespace, 0xE6)),
            );
            assert!(
                [&first, &second].iter().any(|outcome| matches!(
                    outcome,
                    Err(StoreError::LimitExceeded {
                        limit: "max_active_index_entries",
                        ..
                    })
                )),
                "five objects must not both be admitted under a ceiling of three: \
                 {first:?} / {second:?}"
            );
        }
        StoreEngine::open(sealing_options(&serial, temporary.path(), 3))
            .expect("a store must reopen whatever it accepted");
    }

    /// P1: the replayability check must not depend on there being a backlog.
    ///
    /// After a seal the layers are empty and everything a reopen would rebuild
    /// lives in the run. An early return on "no layers" therefore admitted work
    /// against a ceiling that was already full: the store accepted it and then
    /// could not reopen.
    #[test]
    fn an_emptied_backlog_does_not_reopen_the_replay_ceiling() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x4A; 32]);
        // Fan-out room to spare, so the seal is driven purely by entry pressure
        // at the third entry and not by the layer count part-way through.
        let configure = || {
            let mut options = sealing_options(&serial, temporary.path(), 3);
            options.max_index_runs = 8;
            options.max_open_index_runs = 8;
            options
        };
        {
            let engine = StoreEngine::open(configure()).expect("open a fresh root");
            block_on(engine.submit(create_transaction(namespace, 0x0A))).expect("create");
            push_groups(&engine, namespace, 0x2A, 2);

            // Seals the three-entry backlog, then refuses this submission.
            let _ = block_on(engine.submit(push_transaction(namespace, 0x3A, 0x3A, None)));
            let maintenance = engine.index_maintenance();
            assert_eq!(
                (maintenance.sealed_runs, maintenance.unsealed_delta_layers),
                (1, 0),
                "the seal must leave one run and an empty backlog"
            );

            // The admission the early return used to skip entirely.
            let refused = block_on(engine.submit(push_transaction(namespace, 0x3B, 0x3B, None)))
                .expect_err("the run already holds everything the ceiling allows");
            assert!(
                matches!(
                    refused,
                    StoreError::LimitExceeded {
                        limit: "max_active_index_entries",
                        ..
                    }
                ),
                "expected the replay ceiling, got {refused:?}"
            );
        }
        StoreEngine::open(configure()).expect("a store must reopen whatever it accepted");
    }

    /// P1: the byte ceiling is a ceiling too.
    ///
    /// Sized so entries stay far below their own limit and only the encoded byte
    /// total crosses. Recovery rebuilds into one `IndexDelta::from_options`,
    /// which refuses on either.
    #[test]
    fn admission_projects_the_replay_byte_ceiling() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x48; 32]);
        let mut options = sealing_options(&serial, temporary.path(), 4_000_000);
        // Room for a couple of entries and their one section header, and no more.
        options.max_active_index_bytes = crate::index::encoded_bytes_for(2, 1);
        {
            let engine = StoreEngine::open(options).expect("open a fresh root");
            block_on(engine.submit(create_transaction(namespace, 8))).expect("one object");
            block_on(engine.submit(push_transaction(namespace, 0xE8, 0xE8, None)))
                .expect("a second object still fits");
            let refused = block_on(engine.submit(push_transaction(namespace, 0xE9, 0xE9, None)))
                .expect_err("a third object exceeds the encoded byte ceiling");
            assert!(
                matches!(
                    refused,
                    StoreError::LimitExceeded {
                        limit: "max_active_index_bytes",
                        ..
                    }
                ),
                "expected the byte ceiling, got {refused:?}"
            );
        }
        let mut reopen = sealing_options(&serial, temporary.path(), 4_000_000);
        reopen.max_active_index_bytes = crate::index::encoded_bytes_for(2, 1);
        StoreEngine::open(reopen).expect("a store must reopen whatever it accepted");
    }

    /// The property the generation split exists for: a run written against the
    /// **active tail** still resolves after recovery seals that tail away.
    ///
    /// This is the case that was unwritable before. Every location in the run
    /// names the tail's logical generation; recovery then moves those frames into
    /// a segment, and the segment inherits the identity rather than taking a
    /// fresh one. The run is queried directly out of the recovered root — not
    /// through the layered index, where the replay delta would shadow it — which
    /// is what a checkpoint reading through the run would do.
    #[test]
    fn a_recovered_runs_locations_still_resolve_to_a_pinned_source() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespace = NamespaceId([0x49; 32]);
        let configure = || {
            let mut options = sealing_options(&serial, temporary.path(), 4_000_000);
            options.max_index_runs = 2;
            options.max_open_index_runs = 2;
            options
        };
        {
            let engine = StoreEngine::open(configure()).expect("open a fresh root");
            block_on(engine.submit(create_transaction(namespace, 9))).expect("create");
            push_groups(&engine, namespace, 0xF0, 1);
            // Two layers cross the fan-out ceiling, so this seals — over
            // locations that name the active tail.
            block_on(engine.submit(push_transaction(namespace, 0xF8, 0xF8, None)))
                .expect("the group after the seal commits");
            assert_eq!(engine.index_maintenance().sealed_runs, 1, "the seal ran");
        }

        let engine = StoreEngine::open(configure()).expect("reopen");
        let root = engine.committed_root();
        let run = root
            .index()
            .sealed_runs()
            .iter()
            .next()
            .expect("the manifest's run is recovered")
            .clone();
        let mut resolved = 0usize;
        for object in [genesis_object().id, ObjectId([0xF0; 32])] {
            let Some(location) = run.get(&IndexKey::new(namespace, object)) else {
                continue;
            };
            resolved += 1;
            assert!(
                root.object_source(0, location.segment_generation)
                    .expect("resolve")
                    .is_some(),
                "the recovered run points at logical generation {} which nothing pins: the \
                 sealed segment did not inherit the tail's identity",
                location.segment_generation
            );
        }
        assert!(
            resolved > 0,
            "the run must answer for the objects it covers"
        );
    }

    /// P2: the run ceilings are per shard, as recovery enforces them.
    #[test]
    fn the_run_ceilings_are_counted_per_shard() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let namespaces = two_shards();
        let mut options = sealing_options(&serial, temporary.path(), 4_000_000);
        options.shard_count = 4;
        options.max_index_runs = 1;
        options.max_open_index_runs = 1;
        let engine = StoreEngine::open(options).expect("open a fresh root");

        for (index, (_, namespace)) in namespaces.iter().enumerate() {
            let tag = 0x20 + index as u8;
            block_on(engine.submit(create_transaction(*namespace, tag))).expect("create");
            block_on(engine.submit(push_transaction(
                *namespace,
                0x30 + index as u8,
                0x30 + index as u8,
                None,
            )))
            .expect("the group after the seal commits");
        }
        assert_eq!(
            engine.index_maintenance().sealed_runs,
            2,
            "each shard owns one run; a per-root count would refuse the second shard its first"
        );
    }

    /// A seal that fails after the device has moved leaves no usable writer.
    ///
    /// The fence inside the run's own write is made to fail. That is the first
    /// durable step of the seal and it happens at admission, before this
    /// transaction has appended anything — so the fault cannot be consumed by a
    /// group append and lands where the test means it to.
    #[cfg(feature = "failpoints")]
    #[test]
    fn a_failed_seal_never_lets_the_writer_continue() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        let mut options = sealing_options(&serial, temporary.path(), 4_000_000);
        options.max_index_runs = 1;
        options.max_open_index_runs = 1;
        let engine = StoreEngine::open(options).expect("open a fresh root");
        let namespace = NamespaceId([0x45; 32]);
        block_on(engine.submit(create_transaction(namespace, 5))).expect("create");

        crate::sys::arm(&serial, crate::sys::Fault::FenceEio);
        let failed = block_on(engine.submit(push_transaction(namespace, 0xD0, 0xD0, None)))
            .expect_err("a seal whose fence fails must not report success");
        crate::sys::disarm(&serial);
        assert!(
            matches!(failed, StoreError::ShardPoisoned { .. }),
            "expected the shard to poison, got {failed:?}"
        );

        let next = block_on(engine.submit(push_transaction(namespace, 0xD1, 0xD1, None)))
            .expect_err("a poisoned shard admits no further work");
        assert!(
            matches!(next, StoreError::ShardPoisoned { .. }),
            "expected ShardPoisoned, got {next:?}"
        );
        assert_eq!(
            engine.index_maintenance().sealed_runs,
            0,
            "a failed seal must publish nothing"
        );
    }
}
