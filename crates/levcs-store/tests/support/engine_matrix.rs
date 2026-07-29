//! Driving a crash-matrix row through the production `StoreEngine::submit`.
//!
//! **Owned by B4 StoreHarnessB** (scope 2.1, 6.6 deliverable 2).
//!
//! Wave A could assert only the physical-state-class and `recovery_outcome`
//! halves of a [`FailpointExpectation`], because `drive.rs` has no status
//! root, no sequencer, and no acknowledgment path. This module supplies the
//! other four. Every observation here is made through a method a *consumer*
//! calls — `StoreEngine::submit`, `StoreEngine::transaction_status`,
//! `StoreEngine::open`, `StoreEngine::durability_counters` — and never through
//! an internal helper, because scope 5 charter item 8 is precisely about a
//! safety property that is asserted on a function production does not call.
//!
//! # Why this is in-process and the Wave A rows are not
//!
//! A Wave A row's action set includes `HardExit`, which is `_exit(3)`: it can
//! only be observed from a parent process. The eight Wave B rows are driven
//! with `Fail` and `Panic`, both of which leave the process alive, and the
//! four fields they add — `shard_poisoned`, `immediate_status`,
//! `acknowledgment_allowed`, `later_append_allowed_before_recovery` — are
//! statements about a *live* engine that no post-mortem reopen can make. A
//! child process that has already died cannot be asked whether its shard would
//! have accepted another append.
//!
//! `recovery_outcome` is still observed the Wave A way — close the engine and
//! reopen through production recovery in a fresh `StoreEngine::open` — so the
//! two waves answer that half by the same means.
//!
//! # No catch-all arm
//!
//! Same rule as `crash_matrix.rs`. Every `TransactionStatus` variant, every
//! `FailpointAction`, and every `ImmediateStatus` is named. A fallback binding
//! here would silently classify a status nobody expected as the one the oracle
//! happened to want.

#![allow(dead_code)]

use std::future::Future;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Wake, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use levcs_core::{ObjectId, ObjectType};
use levcs_protocol::oracle::{ImmediateStatus, RecoveredTailFact};
use levcs_protocol::v2::TransactionEvidenceV1;
use levcs_store::failpoints::{Failpoint, FailpointAction};
use levcs_store::options::StoreOptions;
use levcs_store::segment::{initialize_root, RootLayout};
use levcs_store::transaction::StagedObject;
use levcs_store::types::{
    CommitEvidenceSigner, CommitReceipt, DurabilityCounters, NamespaceId, OperationId, SignerError,
    StoreError, TransactionStatus,
};
use levcs_store::{StoreEngine, ValidatedTransaction};

// ---------------------------------------------------------------------------
// Seeding a root
// ---------------------------------------------------------------------------

/// **Charter item 8 disclosure, stated where it is committed rather than in a
/// report only.**
///
/// `StoreEngine::open` refuses startup state 1 — initializing an absent or
/// empty root — by name (`engine.rs`, B1 deliverable 1, unimplemented). So a
/// store that is about to be exercised through the production `submit` cannot
/// be *created* through the production `open`. It is created here by calling
/// `segment::initialize_root`, which is the same function state 1 will call
/// when B1 implements it, but reached directly rather than through the
/// entry point a consumer uses.
///
/// This is a real weakening and it is named rather than buried: everything
/// below asserts against the production path *after* the root exists, and
/// nothing below asserts anything about how a root comes into existence. When
/// B1 lands startup state 1, this function becomes one line — `StoreEngine::open`
/// on an absent path — and the Wave B rows gain that half for free.
pub const ROOT_SEEDED_BY_NON_PRODUCTION_PATH: &str =
    "segment::initialize_root under the store-internals-adjacent public module, because \
     StoreEngine::open still refuses startup state 1 (B1 deliverable 1)";

fn now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

pub fn seed_root(root: &Path, shard_count: u16) {
    initialize_root(
        &RootLayout::new(root),
        shard_count,
        [0x4b; 16],
        now_micros(),
        &DurabilityCounters::default(),
    )
    .expect("initialize the store root");
}

// ---------------------------------------------------------------------------
// The injected signer
// ---------------------------------------------------------------------------

/// A deterministic stand-in for instance composition's signer.
///
/// The store never verifies a signature (plan §5.1 forbids it from deciding
/// who may sign), so this does not need to be Ed25519. It needs to be a pure
/// function of the digest it is handed, and it needs to count its calls, so a
/// row that claims nothing was signed can be checked rather than believed.
#[derive(Default)]
pub struct CountingSigner {
    pub calls: AtomicU64,
}

impl CommitEvidenceSigner for CountingSigner {
    fn key_epoch(&self) -> u64 {
        11
    }

    fn public_key(&self) -> [u8; 32] {
        [0x5a; 32]
    }

    fn sign_event(&self, signing_digest: &ObjectId) -> Result<[u8; 64], SignerError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut signature = [0u8; 64];
        let first = blake3::hash(signing_digest.as_bytes());
        let second = blake3::hash(first.as_bytes());
        signature[..32].copy_from_slice(first.as_bytes());
        signature[32..].copy_from_slice(second.as_bytes());
        Ok(signature)
    }
}

/// `StoreOptions::max_index_runs`, the ceiling this slice reaches soonest.
///
/// Publishing a group adds one in-memory index delta layer, and B1's slice
/// seals none of them into an `IndexRun` — deliverable 1 refuses by name. So
/// `submit` refuses `NotImplemented` after exactly `max_index_runs` group
/// publications for the life of an engine, root-wide, whatever the workload.
/// At the shipping default of 64 that is 64 commits.
///
/// The single-row driver leaves the default alone: three submits per row is
/// nowhere near it, and a row driven under a non-default ceiling would be a row
/// driven against a store nobody ships. The contention driver raises it,
/// because it must publish groups until two of them collide and the collision
/// is not on a schedule. **That is a disclosed weakening**: the raised value is
/// a real configuration, not a bypass, but it configures around a missing
/// deliverable rather than around a tuning choice, and it is the same
/// unimplemented seal that caps the benchmark.
pub const DEFAULT_MAX_INDEX_RUNS: u32 = 64;

/// Enough that the collision search is never the thing that ends the run.
/// Measured: the failpoint fires within 6 to 64 group publications, and the
/// eight repository creations consume eight of them.
pub const CONTENTION_MAX_INDEX_RUNS: u32 = 4096;

pub fn options(root: &Path, shard_count: u16) -> StoreOptions {
    options_with_index_runs(root, shard_count, DEFAULT_MAX_INDEX_RUNS)
}

pub fn options_with_index_runs(root: &Path, shard_count: u16, max_index_runs: u32) -> StoreOptions {
    let mut options = StoreOptions::new(root);
    options.shard_count = shard_count;
    options.max_index_runs = max_index_runs;
    options.max_open_index_runs = options.max_open_index_runs.min(max_index_runs);
    // A group of one, formed promptly. Every Wave B row is about where in the
    // publication of *this* group the fault lands, so a group that waits for
    // company would only add scheduling noise to the observation.
    options.max_group_transactions = 1;
    options.max_group_bytes = 64 * 1024;
    options.max_group_idle = Duration::from_millis(5);
    options.journal_preallocate_bytes = 4 * 1024 * 1024;
    options.signer = Some(Arc::new(CountingSigner::default()));
    options
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

/// The client principal, deliberately not the signer's public key.
const EVIDENCE_ACTOR: [u8; 32] = [0x7e; 32];

fn evidence() -> TransactionEvidenceV1 {
    TransactionEvidenceV1::AdministrativeV1 {
        actor: EVIDENCE_ACTOR,
        actor_key_epoch: 11,
        command_digest: ObjectId([0x33; 32]),
        signature: [0x44; 64],
    }
}

fn deadline() -> i64 {
    now_micros() + 600_000_000
}

fn genesis_id(namespace: &NamespaceId) -> ObjectId {
    let mut bytes = [0u8; 32];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"levcs-store/b4/genesis-authority/v1\0");
    hasher.update(namespace.as_bytes());
    hasher.finalize_xof().fill(&mut bytes);
    ObjectId(bytes)
}

/// A namespace that routes to `shard`, found by search rather than by
/// arithmetic over a routing rule this file would then own a second copy of.
pub fn namespace_on_shard(shard: u16, shard_count: u16, salt: u64) -> NamespaceId {
    for attempt in 0..4096u64 {
        let mut bytes = [0u8; 32];
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"levcs-store/b4/namespace/v1\0");
        hasher.update(&salt.to_le_bytes());
        hasher.update(&attempt.to_le_bytes());
        hasher.finalize_xof().fill(&mut bytes);
        let namespace = NamespaceId(bytes);
        if StoreOptions::shard_of(&namespace, shard_count) == shard {
            return namespace;
        }
    }
    panic!("no namespace routed to shard {shard} of {shard_count} in 4096 attempts");
}

pub fn create_transaction(namespace: NamespaceId, operation: u8) -> ValidatedTransaction {
    let id = genesis_id(&namespace);
    ValidatedTransaction::builder(privileged())
        .namespace(namespace)
        .operation(
            OperationId([operation; 16]),
            ObjectId([operation; 32]),
            deadline(),
        )
        .create_repository(id)
        .objects(vec![StagedObject {
            id,
            object_type: ObjectType::Authority,
            raw: vec![0xa1; 32],
        }])
        .refs(Vec::new())
        .authority(None, Some(id))
        .evidence(evidence())
        .build()
        .expect("a complete create transaction")
}

pub fn push_transaction(namespace: NamespaceId, operation: u8, blob: u8) -> ValidatedTransaction {
    let authority = genesis_id(&namespace);
    ValidatedTransaction::builder(privileged())
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
        .refs(Vec::new())
        .authority(Some(authority), Some(authority))
        .evidence(evidence())
        .build()
        .expect("a complete push transaction")
}

fn privileged() -> levcs_store::types::PrivilegedConstruction {
    levcs_store::types::PrivilegedConstruction::assert_validated()
}

// ---------------------------------------------------------------------------
// A local executor
// ---------------------------------------------------------------------------

/// Drive one future on this thread until it completes or `deadline` passes.
///
/// `None` is a real answer, not a failure: scope 6.3 says a failure to wake a
/// waiter leaves a *hung request*, never an absent transaction, and a harness
/// that cannot represent a hang cannot assert the difference.
/// `levcs-store` starts no runtime, so neither does this.
pub fn block_on_until<F: Future>(future: F, deadline: Duration) -> Option<F::Output> {
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
    let started = Instant::now();
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return Some(output),
            Poll::Pending => {
                let elapsed = started.elapsed();
                if elapsed >= deadline {
                    return None;
                }
                std::thread::park_timeout(deadline - elapsed);
            }
        }
    }
}

/// How long a submit is given before it is called hung.
///
/// Generous, because the alternative failure mode is a flaky matrix: a
/// deadline tuned close to the observed latency turns an unrelated scheduling
/// hiccup into a "hung request" finding. A committing submit in this harness
/// takes single-digit milliseconds, so the margin is three orders of
/// magnitude. Only `AfterRootCasBeforeWaiterWake` with `Fail` is expected to
/// reach it — that row's whole claim is that the waiter never wakes.
pub const SUBMIT_DEADLINE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// One submit, with its outcome fully enumerated
// ---------------------------------------------------------------------------

/// What one call to `StoreEngine::submit` did. Every case is named; there is
/// no residual "something else" arm.
#[derive(Debug)]
pub enum SubmitOutcome {
    /// The engine returned a receipt.
    Committed(CommitReceipt),
    /// The engine returned a typed refusal.
    Refused(StoreError),
    /// The call panicked in the caller's task and the panic was caught.
    CallerPanicked,
    /// The future never completed within `SUBMIT_DEADLINE`.
    Hung,
}

impl SubmitOutcome {
    pub fn receipt(&self) -> Option<&CommitReceipt> {
        match self {
            SubmitOutcome::Committed(receipt) => Some(receipt),
            SubmitOutcome::Refused(_) => None,
            SubmitOutcome::CallerPanicked => None,
            SubmitOutcome::Hung => None,
        }
    }

    pub fn error(&self) -> Option<&StoreError> {
        match self {
            SubmitOutcome::Refused(error) => Some(error),
            SubmitOutcome::Committed(_) => None,
            SubmitOutcome::CallerPanicked => None,
            SubmitOutcome::Hung => None,
        }
    }

    /// Whether the shard named itself poisoned in this call's own answer.
    pub fn names_shard_poisoned(&self) -> bool {
        matches!(self.error(), Some(StoreError::ShardPoisoned { .. }))
    }
}

/// Submit one transaction, catching a panic raised in the caller's task.
///
/// `BeforeResponse` fires on the caller's side of the completion, so a
/// `Panic` there unwinds *here* and not on a writer thread. Catching it is not
/// leniency: the row's claim is that the transaction stays committed and its
/// receipt stays queryable even then, and a harness that dies with the caller
/// cannot check that.
pub fn submit(engine: &StoreEngine, transaction: ValidatedTransaction) -> SubmitOutcome {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        block_on_until(engine.submit(transaction), SUBMIT_DEADLINE)
    }));
    std::panic::set_hook(previous);
    match caught {
        Ok(Some(Ok(receipt))) => SubmitOutcome::Committed(receipt),
        Ok(Some(Err(error))) => SubmitOutcome::Refused(error),
        Ok(None) => SubmitOutcome::Hung,
        Err(_) => SubmitOutcome::CallerPanicked,
    }
}

// ---------------------------------------------------------------------------
// Status classification, exhaustively
// ---------------------------------------------------------------------------

/// Map a `TransactionStatus` onto the oracle's `ImmediateStatus`.
///
/// `Unknown` is `DefinitiveAbsent` and that is a claim worth stating rather
/// than assuming. `transaction_status` performs plan §5.1's two-root read: it
/// loads the committed root, then the status root, then the committed root
/// again. A reader that observes no entry in any of the three has synchronized
/// with the store that removed it, so "nothing is recorded" is a positive
/// finding about a linearizable read, not an absence of information.
///
/// `Pending` and `Expired` are enumerated and refused. Neither can arise from
/// a Wave B row — a group is marked `Resolving` before any byte is written and
/// a deadline is rechecked immediately before that — so seeing one is a
/// finding, and mapping it into a neighbouring bucket would hide it.
pub fn immediate_status_of(status: &TransactionStatus, row: &str) -> ImmediateStatus {
    match status {
        TransactionStatus::Committed(_) => ImmediateStatus::Committed,
        TransactionStatus::Resolving { .. } => ImmediateStatus::Resolving,
        TransactionStatus::Unknown => ImmediateStatus::DefinitiveAbsent,
        TransactionStatus::Pending { phase, .. } => panic!(
            "row {row}: transaction_status reported Pending({phase:?}); no Wave B failpoint \
             can leave an operation in a pre-Resolving phase, so this is a finding rather \
             than a status to classify"
        ),
        TransactionStatus::Expired { .. } => panic!(
            "row {row}: transaction_status reported Expired; the retry deadline in this \
             harness is ten minutes out, so an expiry here means the deadline recheck ran \
             against the wrong clock"
        ),
    }
}

pub fn immediate_status_name(status: ImmediateStatus) -> &'static str {
    match status {
        ImmediateStatus::DefinitiveAbsent => "DefinitiveAbsent",
        ImmediateStatus::Resolving => "Resolving",
        ImmediateStatus::Committed => "Committed",
    }
}

/// What a reopened store says about an operation, as a tail fact the frozen
/// `outcome_admits` relation can be applied to.
pub fn recovered_fact(status: &TransactionStatus, row: &str) -> RecoveredTailFact {
    match status {
        TransactionStatus::Committed(_) => RecoveredTailFact::CompleteChecksumValid,
        TransactionStatus::Unknown => RecoveredTailFact::AbsentOrTorn,
        TransactionStatus::Resolving { .. } => panic!(
            "row {row}: an operation is still Resolving after a close and reopen through \
             production recovery. Recovery publishes a committed root and a receipt table \
             exactly once (scope 3.8 step 11); a surviving Resolving entry would mean the \
             status root outlived the process that owned it"
        ),
        TransactionStatus::Pending { .. } => panic!(
            "row {row}: a reopened store reported Pending, which no recovery path constructs"
        ),
        TransactionStatus::Expired { .. } => panic!(
            "row {row}: a reopened store reported Expired for an operation whose deadline is \
             ten minutes out"
        ),
    }
}

// ---------------------------------------------------------------------------
// Arming
// ---------------------------------------------------------------------------

pub fn action_name(action: FailpointAction) -> &'static str {
    match action {
        FailpointAction::Continue => "continue",
        FailpointAction::Fail => "fail",
        FailpointAction::Panic => "panic",
        FailpointAction::HardExit => "hard-exit",
    }
}

pub fn action_from_name(name: &str) -> Option<FailpointAction> {
    [
        FailpointAction::Continue,
        FailpointAction::Fail,
        FailpointAction::Panic,
        FailpointAction::HardExit,
    ]
    .into_iter()
    .find(|action| action_name(*action) == name)
}

/// Exclusive use of the process-global failpoint and fault registries.
///
/// The same token `drive.rs` hands the Wave A driver, taken for the same
/// reason: the registries are one-shot globals, and a test that merely submits
/// can consume an arming another test placed.
pub type Serial = levcs_store::drive::faults::FaultSerial;

pub fn serial() -> Serial {
    levcs_store::drive::faults::serial()
}

pub fn arm(serial: &Serial, point: Failpoint, action: FailpointAction) {
    levcs_store::failpoints::arm(serial, point, action);
}

pub fn disarm(serial: &Serial) {
    levcs_store::failpoints::disarm(serial);
}

// ---------------------------------------------------------------------------
// Reopening after a close
// ---------------------------------------------------------------------------

/// How long the harness will wait for `LOCK` after `StoreEngine` was dropped.
pub const LOCK_RELEASE_BUDGET: Duration = Duration::from_secs(30);

/// What one close-and-reopen cost.
pub struct Reopen {
    pub engine: StoreEngine,
    /// Attempts made. `1` means the lock was already free when `drop` returned.
    pub attempts: u32,
    pub waited: Duration,
}

/// Reopen a root after its engine was dropped, waiting for the root lock.
///
/// # This wait is compensating for a defect, and it is not the harness's
///
/// `StoreEngine::drop` closes every shard channel and joins every writer
/// thread, so on its own account the root lock is released by the time `drop`
/// returns. Measured, it is not: reopening immediately after `drop` returns
/// fails `AlreadyLocked` in roughly one run in six, and the lock then becomes
/// free between a few hundred microseconds and about 150 milliseconds later.
/// Something outlives the join and holds the `RecoverySession`.
///
/// This matters outside the harness. Scope 3.1 says `AlreadyLocked` is a
/// refusal and **never a wait**, so a consumer that closes a store and reopens
/// it — a recovery drill, an in-place restart, the Phase 2 migrator — gets a
/// spurious refusal with no defined retry. It is reported to the lead and to
/// B1 as a finding rather than fixed here: `engine.rs` is not B4's file, and
/// re-deriving its shutdown sequence in the harness is exactly the local
/// restatement the ownership matrix exists to prevent.
///
/// The wait is therefore **bounded, measured, and reported**, not silent. It is
/// not a retry-until-green: a single reopen either succeeds within the budget
/// or the run fails, and `attempts` is published so a regression that lengthens
/// the window shows up as a number rather than as an intermittent failure.
pub fn reopen_after_close(root: &Path, shard_count: u16, max_index_runs: u32) -> Reopen {
    let started = Instant::now();
    let mut attempts = 0u32;
    loop {
        attempts += 1;
        match StoreEngine::open(options_with_index_runs(root, shard_count, max_index_runs)) {
            Ok(engine) => {
                return Reopen {
                    engine,
                    attempts,
                    waited: started.elapsed(),
                }
            }
            Err(StoreError::AlreadyLocked) if started.elapsed() < LOCK_RELEASE_BUDGET => {
                std::thread::sleep(Duration::from_micros(200));
            }
            Err(StoreError::AlreadyLocked) => panic!(
                "the root lock was still held {:?} after StoreEngine::drop returned, over \
                 {attempts} attempts. The known window is under a second; this is longer, \
                 which means the holder is not merely slow to be reclaimed.",
                started.elapsed()
            ),
            Err(other) => panic!("reopen through production recovery failed: {other:?}"),
        }
    }
}

// ---------------------------------------------------------------------------
// One driven row
// ---------------------------------------------------------------------------

/// Everything one Wave B row's run observed, through consumer-callable methods
/// only.
///
/// The four fields Wave A could not reach are derived here from **four
/// different observations**, not from one restated four ways:
///
/// | field | observation |
/// |---|---|
/// | `shard_poisoned` | the store names itself poisoned — a `StoreError::ShardPoisoned` from the victim's own answer or the probe's |
/// | `immediate_status` | `transaction_status` on the victim operation, which is plan §5.1's two-root read |
/// | `acknowledgment_allowed` | a `CommitReceipt` is obtainable for the victim, from `submit`'s return value or from a retrying status read |
/// | `later_append_allowed_before_recovery` | a *different* transaction submitted to the same shard commits |
///
/// The last two are genuinely distinct from the first two. A shard can be
/// unpoisoned and still refuse a later append, because a dead writer thread
/// makes `later_append_allowed_before_recovery` false whatever the error says —
/// that is the defect B1's phase-aware panic ownership closes, and folding the
/// two into one observation would have made it invisible here.
pub struct RowObservation {
    pub row: String,
    pub action: FailpointAction,
    pub victim: SubmitOutcome,
    pub immediate: TransactionStatus,
    pub probe: SubmitOutcome,
    pub recovered: TransactionStatus,
    /// The transaction committed *before* the failpoint was armed. Every row
    /// also proves an already-fenced, already-acknowledged transaction
    /// survives, exactly as the Wave A rows prove it for a prior group.
    pub prior_recovered: TransactionStatus,
    /// `fdatasync` on the victim's shard, immediately before the failpoint was
    /// armed and immediately after the victim's submit resolved. Charter item
    /// 7: the physical state class is checked against a syscall count, not
    /// against a comment about where the fence sits.
    pub fences_before: u64,
    pub fences_after: u64,
    /// How many `StoreEngine::open` attempts the reopen needed, and how long it
    /// waited. `1` and a near-zero wait is the expected reading; anything else
    /// is the root-lock release window documented on [`reopen_after_close`].
    pub lock_release_attempts: u32,
    pub lock_release_wait: Duration,
}

impl RowObservation {
    pub fn shard_poisoned_observed(&self) -> bool {
        self.victim.names_shard_poisoned() || self.probe.names_shard_poisoned()
    }

    pub fn later_append_allowed_observed(&self) -> bool {
        matches!(self.probe, SubmitOutcome::Committed(_))
    }

    /// A receipt is obtainable for the victim operation through a path a
    /// consumer calls.
    ///
    /// `submit` returning one is the direct case. A status read returning
    /// `Committed` is the retry case, and it is not redundant: a hung waiter
    /// gets no return value at all, and the row's claim is precisely that the
    /// transaction is still acknowledgeable then.
    pub fn acknowledgment_allowed_observed(&self) -> bool {
        self.victim.receipt().is_some() || matches!(self.immediate, TransactionStatus::Committed(_))
    }

    pub fn fences_during_victim(&self) -> u64 {
        self.fences_after - self.fences_before
    }
}

/// Drive one Wave B row on a single-shard root.
///
/// The shape mirrors the Wave A driving loop: a transaction that commits
/// cleanly first, then the victim with the failpoint armed, then the
/// classification. The difference is that the classification happens on a live
/// engine as well as on a reopened one.
pub fn drive_submit_row(
    serial: &Serial,
    point: Failpoint,
    action: FailpointAction,
) -> RowObservation {
    let row = format!("{} [{}]", point.name(), action_name(action));
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");
    seed_root(&root, 1);

    let namespace = namespace_on_shard(0, 1, 0x5643_5342);
    let prior_operation = OperationId([0x11; 16]);
    let victim_operation = OperationId([0x22; 16]);

    let engine = StoreEngine::open(options(&root, 1)).expect("open the seeded root");

    let prior = submit(&engine, create_transaction(namespace, 0x11));
    assert!(
        matches!(prior, SubmitOutcome::Committed(_)),
        "row {row}: the transaction before the fault must commit cleanly, or the row \
         proves nothing about what the fault cost: {prior:?}"
    );

    let fences_before = engine
        .durability_counters(0)
        .expect("shard 0 has a writer")
        .fdatasync;

    arm(serial, point, action);
    let victim = submit(&engine, push_transaction(namespace, 0x22, 0xb2));
    let fences_after = engine
        .durability_counters(0)
        .expect("shard 0 has a writer")
        .fdatasync;
    let immediate = engine
        .transaction_status(namespace, victim_operation)
        .expect("transaction_status is a read and never fails on an open engine");

    let probe = submit(&engine, push_transaction(namespace, 0x33, 0xb3));
    // Whatever happened, nothing may stay armed for the next row: the registry
    // is a one-shot global and a row that did not fire would otherwise hand its
    // arming to whoever submits next.
    disarm(serial);
    drop(engine);

    let reopen = reopen_after_close(&root, 1, DEFAULT_MAX_INDEX_RUNS);
    let lock_release_attempts = reopen.attempts;
    let lock_release_wait = reopen.waited;
    let reopened = reopen.engine;
    let recovered = reopened
        .transaction_status(namespace, victim_operation)
        .expect("status read");
    let prior_recovered = reopened
        .transaction_status(namespace, prior_operation)
        .expect("status read");
    drop(reopened);

    RowObservation {
        row,
        action,
        victim,
        immediate,
        probe,
        recovered,
        prior_recovered,
        fences_before,
        fences_after,
        lock_release_attempts,
        lock_release_wait,
    }
}

// ---------------------------------------------------------------------------
// DuringRootCasRetry: the one location behind a lost compare-and-swap
// ---------------------------------------------------------------------------

/// Shards used by the contention driver.
///
/// The committed root is one `ArcSwap` for the whole store, so contention on
/// it is contention *between shards*. One shard can never reach
/// `DuringRootCasRetry`, however long it runs, because nothing else ever
/// swaps the root out from under it.
pub const CONTENTION_SHARDS: u16 = 8;

/// Objects per contending transaction.
///
/// The window this row needs is the interval between `publish_subtree`'s load
/// of the committed root and its compare-and-swap, and the work inside that
/// window is `CommittedRoot::merge`. A transaction carrying one object leaves a
/// window of a few hundred nanoseconds; carrying this many leaves a window
/// wide enough that eight shards publishing concurrently collide within
/// seconds rather than within a statistical hope. This widens a real window in
/// the production path — it does not add one.
const CONTENTION_OBJECTS: usize = 48;

fn contending_transaction(namespace: NamespaceId, operation: u64) -> ValidatedTransaction {
    let authority = genesis_id(&namespace);
    let mut operation_id = [0u8; 16];
    operation_id[..8].copy_from_slice(&operation.to_le_bytes());
    operation_id[8..].copy_from_slice(namespace.as_bytes()[..8].try_into().expect("8 bytes"));

    let objects = (0..CONTENTION_OBJECTS as u64)
        .map(|index| {
            let mut bytes = [0u8; 32];
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"levcs-store/b4/contention-object/v1\0");
            hasher.update(namespace.as_bytes());
            hasher.update(&operation.to_le_bytes());
            hasher.update(&index.to_le_bytes());
            hasher.finalize_xof().fill(&mut bytes);
            StagedObject {
                id: ObjectId(bytes),
                object_type: ObjectType::Blob,
                raw: bytes.to_vec(),
            }
        })
        .collect();

    let mut digest = [0u8; 32];
    digest[..16].copy_from_slice(&operation_id);
    ValidatedTransaction::builder(privileged())
        .namespace(namespace)
        .operation(OperationId(operation_id), ObjectId(digest), deadline())
        .objects(objects)
        .refs(Vec::new())
        .authority(Some(authority), Some(authority))
        .evidence(evidence())
        .build()
        .expect("a complete contending transaction")
}

/// A submit with no panic-hook manipulation, for use from several threads at
/// once.
///
/// The single-row driver installs a silent hook so a `Panic` row does not spray
/// a backtrace over the test output. Doing that from eight threads would be a
/// race on a process-global, so the contention driver accepts the noise
/// instead. `DuringRootCasRetry` panics on a *writer* thread, never on the
/// caller's, so nothing here needs catching.
fn submit_plain(engine: &StoreEngine, transaction: ValidatedTransaction) -> SubmitOutcome {
    match block_on_until(engine.submit(transaction), SUBMIT_DEADLINE) {
        Some(Ok(receipt)) => SubmitOutcome::Committed(receipt),
        Some(Err(error)) => SubmitOutcome::Refused(error),
        None => SubmitOutcome::Hung,
    }
}

/// What the contention driver measured, whether or not it fired.
pub struct ContentionRun {
    pub observation: Option<RowObservation>,
    /// A refusal seen during the run that is not the one this location
    /// produces. Non-`None` means the run observed something the row does not
    /// describe, and the row must not be asserted from it.
    pub anomaly: Option<(u16, String)>,
    /// Transactions submitted across every shard before the location was
    /// reached. Reported so "it fired" is a measurement rather than a claim,
    /// and so a regression that makes the window narrower shows up as a number
    /// climbing rather than as an intermittent failure.
    pub attempts: u64,
    pub elapsed: Duration,
}

/// Drive `DuringRootCasRetry` by manufacturing a genuinely lost
/// compare-and-swap.
///
/// **This is the one Wave B row whose location is not reachable by submitting
/// a transaction.** It sits inside `publish_subtree`'s retry loop, after a
/// failed `compare_and_swap`, so it is reached only when another shard
/// publishes between this shard's load and its swap. B1 disclosed that the
/// failpoint is never armed by any existing test; this is what arms it.
///
/// The contention is real, not simulated: eight shard writer threads publish
/// into the same `ArcSwap<CommittedRoot>` through the production path, and the
/// only thing the harness chooses is how much work each publication carries
/// into the window. Nothing here reaches into the engine.
pub fn drive_root_cas_retry_row(
    serial: &Serial,
    action: FailpointAction,
    budget: Duration,
) -> ContentionRun {
    use std::sync::atomic::AtomicBool;
    use std::sync::Mutex;

    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");
    seed_root(&root, CONTENTION_SHARDS);

    let namespaces: Vec<NamespaceId> = (0..CONTENTION_SHARDS)
        .map(|shard| namespace_on_shard(shard, CONTENTION_SHARDS, 0x0CA5_0000 + shard as u64))
        .collect();

    let engine = StoreEngine::open(options_with_index_runs(
        &root,
        CONTENTION_SHARDS,
        CONTENTION_MAX_INDEX_RUNS,
    ))
    .expect("open the seeded root");
    for (index, namespace) in namespaces.iter().enumerate() {
        let created = submit_plain(&engine, create_transaction(*namespace, 0x40 + index as u8));
        assert!(
            matches!(created, SubmitOutcome::Committed(_)),
            "the repository on shard {index} must be created before the contention run: \
             {created:?}"
        );
    }

    arm(serial, Failpoint::DuringRootCasRetry, action);

    let stop = AtomicBool::new(false);
    let attempts = AtomicU64::new(0);
    #[allow(clippy::type_complexity)]
    let victim: Mutex<Option<(u16, NamespaceId, OperationId, SubmitOutcome, u64)>> =
        Mutex::new(None);
    // A refusal that is *not* the row's. The location poisons the shard, so the
    // only answer this run's victim can give is `ShardPoisoned`; anything else
    // is a different event that happened to land in the same loop, and adopting
    // it as the victim would assert this row against a transaction the
    // failpoint never touched. Recorded rather than skipped: a run that meets
    // one is not a run that can be repeated until it does not.
    let anomaly: Mutex<Option<(u16, String)>> = Mutex::new(None);
    let started = Instant::now();

    std::thread::scope(|scope| {
        for shard in 0..CONTENTION_SHARDS {
            let namespace = namespaces[shard as usize];
            let engine = &engine;
            let stop = &stop;
            let attempts = &attempts;
            let victim = &victim;
            let anomaly = &anomaly;
            scope.spawn(move || {
                let mut operation = 0u64;
                while !stop.load(Ordering::Relaxed) && started.elapsed() < budget {
                    operation += 1;
                    let transaction = contending_transaction(namespace, operation);
                    let mut operation_id = [0u8; 16];
                    operation_id[..8].copy_from_slice(&operation.to_le_bytes());
                    operation_id[8..]
                        .copy_from_slice(namespace.as_bytes()[..8].try_into().expect("8 bytes"));
                    attempts.fetch_add(1, Ordering::Relaxed);
                    // Read immediately before the call under test. Only this
                    // shard's writer advances this shard's counter and only
                    // this thread submits to this shard, so the difference
                    // across the submit is exactly the fences that submit
                    // caused — no hook, no shared counter, no inference.
                    let fences_before = engine
                        .durability_counters(shard)
                        .expect("every shard has a writer")
                        .fdatasync;
                    let outcome = submit_plain(engine, transaction);
                    match outcome {
                        SubmitOutcome::Committed(_) => {}
                        SubmitOutcome::Refused(_) | SubmitOutcome::Hung => {
                            if !outcome.names_shard_poisoned() {
                                let mut slot = anomaly.lock().expect("anomaly mutex");
                                if slot.is_none() {
                                    *slot = Some((shard, format!("{outcome:?}")));
                                }
                                stop.store(true, Ordering::Relaxed);
                                return;
                            }
                            let mut slot = victim.lock().expect("victim mutex");
                            if slot.is_none() {
                                *slot = Some((
                                    shard,
                                    namespace,
                                    OperationId(operation_id),
                                    outcome,
                                    fences_before,
                                ));
                            }
                            stop.store(true, Ordering::Relaxed);
                            return;
                        }
                        SubmitOutcome::CallerPanicked => unreachable!(
                            "submit_plain does not catch, so a caller panic would have \
                             unwound this thread"
                        ),
                    }
                }
            });
        }
    });

    let elapsed = started.elapsed();
    let attempts = attempts.load(Ordering::Relaxed);
    let victim = victim.into_inner().expect("victim mutex");
    let anomaly = anomaly.into_inner().expect("anomaly mutex");

    let Some((shard, namespace, victim_operation, victim_outcome, fences_before)) = victim else {
        disarm(serial);
        drop(engine);
        return ContentionRun {
            observation: None,
            anomaly,
            attempts,
            elapsed,
        };
    };

    let fences_after = engine
        .durability_counters(shard)
        .expect("the poisoned shard still has a counter")
        .fdatasync;
    let immediate = engine
        .transaction_status(namespace, victim_operation)
        .expect("status read");
    let probe = submit_plain(&engine, contending_transaction(namespace, u64::MAX / 2));
    disarm(serial);
    drop(engine);

    let reopen = reopen_after_close(&root, CONTENTION_SHARDS, CONTENTION_MAX_INDEX_RUNS);
    let lock_release_attempts = reopen.attempts;
    let lock_release_wait = reopen.waited;
    let reopened = reopen.engine;
    let recovered = reopened
        .transaction_status(namespace, victim_operation)
        .expect("status read");
    // The repository-create on the same shard is the transaction acknowledged
    // before the fault; it must survive.
    let prior_recovered = reopened
        .transaction_status(namespace, OperationId([0x40 + shard as u8; 16]))
        .expect("status read");
    drop(reopened);

    ContentionRun {
        anomaly,
        attempts,
        elapsed,
        observation: Some(RowObservation {
            row: format!("DuringRootCasRetry [{}]", action_name(action)),
            action,
            victim: victim_outcome,
            immediate,
            probe,
            recovered,
            prior_recovered,
            fences_before,
            fences_after,
            lock_release_attempts,
            lock_release_wait,
        }),
    }
}
