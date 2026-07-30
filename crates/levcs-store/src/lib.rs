//! levcs-store: the durable transaction spine for LeVCS instances.
//!
//! One validated, durably acknowledged transaction service: append-only
//! journal, group commit behind a single durability fence, crash recovery,
//! namespace-scoped object index, and committed snapshots.
//!
//! Scoped in `doc/phase1-storage-spine-scope.md`, which realizes §12 Phase 1
//! of `doc/instance-throughput-rewrite-plan.md`. The plan is authoritative.
//!
//! # What this crate decides, and what it does not
//!
//! It decides durability, ordering, sequencing, and physical layout. It does
//! not decide identity, roles, merge policy, or federation trust: plan §5.1
//! forbids it. Event signing is injected as a [`CommitEvidenceSigner`], and no
//! `levcs_identity::` path appears anywhere in this crate — a D0 contract test
//! enforces that. `levcs-identity` is nonetheless in the build graph
//! transitively through `levcs-protocol`; the invariant is about calls, not
//! about the link edge (scope §1).
//!
//! # Status
//!
//! D0: the sealed skeleton. The public API compiles and returns
//! [`StoreError::NotImplemented`]; the lead-owned foundations — configuration
//! validation, the durability syscall funnel, and the failpoint registry — are
//! real. Wave A implements the format, journal, segments, index, checkpoints,
//! and recovery; Wave B implements the engine, transactions, snapshots, and
//! staging.
//!
//! # Physical format is internal
//!
//! Plan §13: the physical format remains internal until recovery, migration,
//! compaction, and P5 pass. Future workflow code binds only to logical
//! snapshots and events, never to these bytes.

pub mod checkpoint;
pub mod completion;
pub mod engine;
pub mod failpoints;
pub mod format;
pub mod index;
pub mod journal;
pub mod options;
pub mod recovery;
pub mod roots;
pub mod segment;
pub mod snapshot;
pub mod staging;
pub mod transaction;
pub mod types;

// D0 scaffolding: the durability funnel is complete and unit-tested, but its
// call sites are `journal.rs`, `segment.rs`, `checkpoint.rs`, and
// `recovery.rs`, which land in Wave A. Remove this allow when A1's first
// append path lands — after that, an unused durability primitive is a real
// signal, not scaffolding.
#[allow(dead_code)]
mod sys;

#[cfg(feature = "store-internals")]
pub mod drive;

pub use completion::{CompletionWaiter, SharedCompletion};
pub use engine::{CheckpointLease, IndexMaintenanceSnapshot, StoreEngine};
pub use options::{StoreDirectoryAttributes, StoreOptions};
pub use roots::{
    CommittedRoot, GenerationId, IndexDeltaLayer, LayeredObjectIndex, OperationKey,
    OperationStatusMetricSnapshot, OperationStatusMetrics, OperationStatusRoot, PinnedFile,
    ProjectionArtifactFormat, ReceiptTombstone, RepoState, RetainedGeneration, RetainedIndexRun,
    RetainedObjectSource, RetainedProjectionArtifact, RetainedReceipt, RetainedSegment,
    RetainedTail, ShardSubtree, StatusEntry, StatusPhase, StatusReservation, TerminalStatusEntry,
};
pub use snapshot::RepoSnapshot;
pub use staging::{
    ProjectionAdoption, ProjectionAdoptionOutcome, ProjectionAdoptionResolution,
    ProjectionArtifact, RecoveredProjectionOutcome, RecoveredProjectionResolution,
};
pub use transaction::{StagedObject, ValidatedTransaction, ValidatedTransactionBuilder};
pub use types::{
    AppliedRef, CommitEvidenceSigner, CommitReceipt, DurabilityCounterSnapshot, DurabilityCounters,
    NamespaceId, OperationId, PendingPhase, PrivilegedConstruction, SignerError, StoreError,
    TransactionStatus,
};
