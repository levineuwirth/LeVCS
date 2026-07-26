//! `ValidatedTransaction` and its sealed builder, the shard sequencer's
//! mutable-precondition checks, receipts, idempotency, and terminal retention.
//!
//! **Shared file.** Lead owns the signatures (D0); **B1 NamespaceTxn** fills
//! the bodies (scope 2.1, 6-B1).

use levcs_core::{ObjectId, ObjectType};
use levcs_protocol::v2::{TransactionEvidenceV1, TypedRefCas};

use crate::types::{NamespaceId, OperationId, PrivilegedConstruction, StoreError};

/// The immutable output of the instance pipeline's stages 4-8 (plan §7).
///
/// Sealed against arbitrary callers. It carries exact new bytes, the complete
/// ordered typed ref set, the authority CAS, operation evidence, digest, and
/// deadline, and the snapshot/config epochs. The sequencer rechecks only
/// mutable preconditions against speculative state; it never re-parses,
/// re-hashes, re-verifies signatures, or re-evaluates policy while holding the
/// mutation lane.
pub struct ValidatedTransaction {
    _private: (),
}

/// One object entering namespace membership.
pub struct StagedObject {
    pub id: ObjectId,
    pub object_type: ObjectType,
    pub raw: Vec<u8>,
}

impl ValidatedTransaction {
    /// Begin construction. Requires a capability token that is not reachable
    /// from a `&StoreEngine`; see `PrivilegedConstruction` (scope 2.2).
    pub fn builder(_token: PrivilegedConstruction) -> ValidatedTransactionBuilder {
        ValidatedTransactionBuilder { _private: () }
    }
}

pub struct ValidatedTransactionBuilder {
    _private: (),
}

impl ValidatedTransactionBuilder {
    pub fn namespace(self, _namespace: NamespaceId) -> Self {
        self
    }

    pub fn operation(self, _id: OperationId, _digest: ObjectId, _retry_until_micros: i64) -> Self {
        self
    }

    /// Repository-create metadata. Present only for an init transaction, which
    /// permanently binds `repo_id` and the genesis authority hash in the
    /// catalog (plan §4 identity invariant 2).
    pub fn create_repository(self, _genesis_authority: ObjectId) -> Self {
        self
    }

    pub fn objects(self, _objects: Vec<StagedObject>) -> Self {
        self
    }

    /// The complete typed Set/Delete set. Multi-ref updates are entirely old
    /// or entirely new, including after crashes (plan §4 transaction
    /// invariant 2).
    pub fn refs(self, _refs: Vec<TypedRefCas>) -> Self {
        self
    }

    /// Explicit expected and new current authority. Never inferred.
    pub fn authority(self, _expected: Option<ObjectId>, _new: Option<ObjectId>) -> Self {
        self
    }

    pub fn evidence(self, _evidence: TransactionEvidenceV1) -> Self {
        self
    }

    pub fn build(self) -> Result<ValidatedTransaction, StoreError> {
        Err(StoreError::NotImplemented(
            "ValidatedTransactionBuilder::build — B1 NamespaceTxn, scope 6-B1 deliverable 3",
        ))
    }
}
