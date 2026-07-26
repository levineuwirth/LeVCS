//! `StoreEngine`: shard routing, startup and recovery, lifecycle, and the
//! `ArcSwap` committed/status roots.
//!
//! **Shared file.** Lead owns the signatures (D0); **B1 NamespaceTxn** fills
//! the bodies (scope 2.1, 6-B1). Same pattern as `format.rs` and `drive.rs`:
//! the public API must compile in D0 so A3 can write against real signatures
//! in Wave A rather than retrofitting them in Wave B.

use crate::options::StoreOptions;
use crate::snapshot::RepoSnapshot;
use crate::transaction::ValidatedTransaction;
use crate::types::{CommitReceipt, NamespaceId, OperationId, StoreError, TransactionStatus};

/// The durable transaction service.
///
/// Owns one `ArcSwap<CommittedRoot>` and one bounded
/// `ArcSwap<OperationStatusRoot>`; neither uses `RwLock<Arc<_>>` (plan §5.1).
/// The committed-root swap is the visibility boundary.
pub struct StoreEngine {
    _private: (),
}

/// A held checkpoint export lease. Pins the referenced generation's segments,
/// indexes, and checkpoints against reclamation until dropped.
pub struct CheckpointLease {
    _private: (),
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
    pub fn open(options: StoreOptions) -> Result<Self, StoreError> {
        // Configuration is validated even in D0: an invalid configuration must
        // fail startup regardless of how much of the engine exists, and this
        // is the one behavior callers can already rely on.
        options.validate()?;
        Err(StoreError::NotImplemented(
            "StoreEngine::open — B1 NamespaceTxn, scope 6-B1 deliverable 1",
        ))
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
    pub async fn submit(&self, _txn: ValidatedTransaction) -> Result<CommitReceipt, StoreError> {
        Err(StoreError::NotImplemented(
            "StoreEngine::submit — B1 NamespaceTxn, scope 6-B1 deliverables 4-7",
        ))
    }

    /// Linearizable status lookup across the two roots.
    ///
    /// Plan §5.1: load committed root A and return any receipt or expired
    /// tombstone; otherwise load the status root and return any pending or
    /// resolving entry; if no status entry exists, load committed root B,
    /// return any terminal entry found there, and otherwise `Unknown`. The
    /// mandatory B read closes the old-committed/new-empty-status race without
    /// requiring A and B to share a generation.
    pub fn transaction_status(
        &self,
        _repo: NamespaceId,
        _operation: OperationId,
    ) -> Result<TransactionStatus, StoreError> {
        Err(StoreError::NotImplemented(
            "StoreEngine::transaction_status — B1 NamespaceTxn, scope 6-B1 deliverable 6",
        ))
    }

    /// Force a checkpoint and hold a lease on the resulting generation.
    pub fn checkpoint(&self) -> Result<CheckpointLease, StoreError> {
        Err(StoreError::NotImplemented(
            "StoreEngine::checkpoint — B1 NamespaceTxn, scope 6-B1",
        ))
    }
}
