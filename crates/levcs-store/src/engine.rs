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
//! root CAS -> completion, and the publication ordering of scope 6.3. The
//! startup states other than "a valid `FORMAT` opens through production
//! recovery", the signer pool and its suffix repair, coalescing, terminal
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
    IndexDelta, IndexKey, IndexLocation, NamespaceLifecycle, NamespaceRecord, NamespaceStorageMode,
};
use crate::journal::{GroupBuilder, Journal};
use crate::options::StoreOptions;
use crate::recovery::{RecoveredShard, RecoveryConfig, RecoverySession};
use crate::roots::{
    CommittedRoot, GenerationMap, LayeredObjectIndex, OperationKey, OperationStatusMetricSnapshot,
    OperationStatusMetrics, OperationStatusRoot, RepoMap, RepoState, RetainedReceipt,
    ShardSequenceMap, ShardSubtree, StatusEntry, StatusReservation, TerminalStatusEntry,
    TerminalStatusMap, TypedRefMap,
};
use crate::segment::RootLayout;
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
    /// **This slice implements the second state only.** The other three are
    /// refused by name below, before anything is written, so a caller cannot
    /// mistake "not built yet" for "your root is broken".
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

        let layout = RootLayout::new(&options.root);
        if !layout.format_path().exists() {
            // States 1, 3, and 4 are distinguished by inspecting a root this
            // slice does not yet classify. Refusing without probing is the
            // same rule those states obey: no writes, no inference.
            return Err(StoreError::NotImplemented(
                "StoreEngine::open startup states 1, 3, and 4 (initialize an absent or empty \
                 root, LegacyLayout, UnrecognizedLayout) — B1 NamespaceTxn, scope 6-B1 \
                 deliverable 1",
            ));
        }

        let signer = options.signer.clone().ok_or_else(|| {
            StoreError::InvalidConfiguration(
                "a CommitEvidenceSigner must be registered by instance composition before the \
                 engine can sequence a transaction"
                    .into(),
            )
        })?;

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

        // Publishing a group adds one delta layer, and nothing in this slice
        // ever seals one into an `IndexRun`. Refusing here, before anything is
        // reserved or sequenced, keeps lookup fan-out bounded by the same
        // configured ceiling the sealed-run path uses, and makes the missing
        // deliverable visible instead of turning it into a slow leak.
        let layers = self.shared.committed.load().index().delta_layer_count() as u64;
        if layers >= u64::from(self.shared.options.max_index_runs) {
            return Err(StoreError::NotImplemented(
                "sealing the in-memory index delta into an IndexRun — B1 NamespaceTxn, \
                 scope 6-B1 deliverable 1 and scope 3.6",
            ));
        }

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
    use std::path::Path;
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
    fn block_on<F: Future>(future: F) -> F::Output {
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
    type WriterSerial = crate::sys::FaultSerial;
    #[cfg(not(feature = "failpoints"))]
    type WriterSerial = ();

    fn writer_serial() -> WriterSerial {
        #[cfg(feature = "failpoints")]
        {
            crate::sys::serial()
        }
    }

    fn counters() -> Arc<DurabilityCounters> {
        Arc::new(DurabilityCounters::default())
    }

    fn initialized_root(_serial: &WriterSerial, path: &Path, shard_count: u16) {
        segment::initialize_root(
            &RootLayout::new(path),
            shard_count,
            [0x11; 16],
            now_micros(),
            &counters(),
        )
        .expect("initialize the store root");
    }

    fn options(_serial: &WriterSerial, root: &Path, shard_count: u16) -> StoreOptions {
        let mut options = StoreOptions::new(root);
        options.shard_count = shard_count;
        options.max_group_transactions = 4;
        options.max_group_bytes = 64 * 1024;
        options.max_group_idle = Duration::from_millis(50);
        options.journal_preallocate_bytes = 4 * 1024 * 1024;
        options.signer = Some(Arc::new(TestSigner::default()));
        options
    }

    fn open(serial: &WriterSerial, root: &Path, shard_count: u16) -> StoreEngine {
        initialized_root(serial, root, shard_count);
        StoreEngine::open(options(serial, root, shard_count)).expect("open the initialized root")
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

    fn evidence() -> TransactionEvidenceV1 {
        TransactionEvidenceV1::AdministrativeV1 {
            actor: EVIDENCE_ACTOR,
            actor_key_epoch: 7,
            command_digest: ObjectId([0x33; 32]),
            signature: [0x44; 64],
        }
    }

    fn deadline() -> i64 {
        now_micros() + 600_000_000
    }

    fn genesis_object() -> StagedObject {
        StagedObject {
            id: ObjectId([0xa1; 32]),
            object_type: ObjectType::Authority,
            raw: vec![0xa1; 32],
        }
    }

    fn create_transaction(namespace: NamespaceId, operation: u8) -> ValidatedTransaction {
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
    fn push_transaction(
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

    #[test]
    fn a_root_without_format_is_refused_by_naming_the_unbuilt_startup_states() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        match StoreEngine::open(options(&serial, temporary.path(), 1)) {
            Err(StoreError::NotImplemented(reason)) => {
                assert!(reason.contains("startup states 1, 3, and 4"), "{reason}")
            }
            other => panic!("expected an explicit refusal, got {other:?}"),
        }
        assert_eq!(
            std::fs::read_dir(temporary.path())
                .expect("read the root")
                .count(),
            0,
            "a refused startup must not write to the root"
        );
    }

    #[test]
    fn a_configured_shard_count_that_disagrees_with_format_is_refused() {
        let serial = writer_serial();
        let temporary = tempfile::tempdir().expect("tempdir");
        initialized_root(&serial, temporary.path(), 4);
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
        initialized_root(&serial, temporary.path(), 1);
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
        // Reopening sealed the validated prefix, so the frame is in a segment.
        let (manifest, _) = segment::load_manifest_with_fallback(&paths, &[0x11; 16])
            .expect("manifest")
            .expect("a manifest exists after the reopen sealed the prefix");
        let range = manifest
            .retained_tail_ranges
            .last()
            .expect("one retained range");
        let reader =
            segment::SegmentReader::open(&paths.segments().join(&range.filename), &[0x11; 16])
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
        let (manifest, _) = segment::load_manifest_with_fallback(&paths, &[0x11; 16])
            .expect("manifest")
            .expect("a manifest exists after the reopen sealed the prefix");
        let mut payloads = Vec::new();
        for range in &manifest.retained_tail_ranges {
            let reader =
                segment::SegmentReader::open(&paths.segments().join(&range.filename), &[0x11; 16])
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
        initialized_root(&serial, temporary.path(), 1);
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
        initialized_root(&serial, temporary.path(), 2);
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

        initialized_root(&serial, temporary.path(), 2);
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
            initialized_root(&serial, temporary.path(), 1);
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
        initialized_root(&serial, temporary.path(), 1);
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
        initialized_root(&serial, temporary.path(), 1);
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
            initialized_root(&serial, temporary.path(), 1);
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
