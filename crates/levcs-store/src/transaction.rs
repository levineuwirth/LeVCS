//! `ValidatedTransaction` and its sealed builder, the shard sequencer's
//! mutable-precondition checks, receipts, idempotency, and terminal retention.
//!
//! **Shared file.** Lead owns the signatures (D0); **B1 NamespaceTxn** fills
//! the bodies (scope 2.1, 6-B1).

use levcs_core::{ObjectId, ObjectType};
use levcs_protocol::v2::{TransactionEvidenceV1, TypedRefCas};

use crate::staging::{ProjectionAdoptionOutcome, StagedProjectionAdoption};
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
        ValidatedTransactionBuilder { adoption: None }
    }
}

pub struct ValidatedTransactionBuilder {
    adoption: Option<StagedProjectionAdoption>,
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

    /// Adopt one sealed staged projection. The opaque handle is the adoption
    /// pin and is consumed with the canonical wire descriptor so neither half
    /// can be forgotten independently.
    pub fn adopt_projection(
        mut self,
        descriptor: levcs_protocol::v2::StagedProjectionInstallV1,
        handle: crate::staging::ProjectionAdoption,
    ) -> Result<Self, StoreError> {
        if let Some(previous) = self.adoption.take() {
            // Both pins were admitted, so both receive a terminal outcome
            // even though the builder rejects the duplicate. Returning early
            // after finishing only one would turn the other drop into the
            // lifecycle bug this handle exists to expose.
            let previous_result = previous
                .handle
                .finish(ProjectionAdoptionOutcome::DefinitivePreAppendFailure);
            let submitted_result =
                handle.finish(ProjectionAdoptionOutcome::DefinitivePreAppendFailure);
            previous_result?;
            submitted_result?;
            return Err(StoreError::Conflict(
                "a transaction may adopt exactly one staged projection".into(),
            ));
        }
        self.adoption = Some(StagedProjectionAdoption { descriptor, handle });
        Ok(self)
    }

    pub fn build(mut self) -> Result<ValidatedTransaction, StoreError> {
        if let Some(adoption) = self.adoption.take() {
            // D0-B freezes the lifecycle while B1 still owns the successful
            // builder body. `NotImplemented` is definitive and pre-append.
            adoption
                .handle
                .finish(ProjectionAdoptionOutcome::DefinitivePreAppendFailure)?;
        }
        Err(StoreError::NotImplemented(
            "ValidatedTransactionBuilder::build — B1 NamespaceTxn, scope 6-B1 deliverable 3",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use levcs_protocol::v2::{ProjectionMode, StagedProjectionInstallV1};

    use super::*;
    use crate::staging::{
        ProjectionAdoption, ProjectionAdoptionLifecycle, ProjectionAdoptionResolution,
    };

    #[derive(Default)]
    struct Lifecycle {
        outcomes: Mutex<Vec<ProjectionAdoptionOutcome>>,
        dropped: Mutex<u64>,
    }

    impl ProjectionAdoptionLifecycle for Lifecycle {
        fn resolution(&self) -> Result<Arc<ProjectionAdoptionResolution>, StoreError> {
            Err(StoreError::NotImplemented(
                "not needed by this contract test",
            ))
        }

        fn finish(&self, outcome: ProjectionAdoptionOutcome) -> Result<(), StoreError> {
            self.outcomes.lock().unwrap().push(outcome);
            Ok(())
        }

        fn dropped_without_outcome(&self) {
            *self.dropped.lock().unwrap() += 1;
        }
    }

    fn descriptor(session_id: [u8; 16]) -> StagedProjectionInstallV1 {
        StagedProjectionInstallV1 {
            session_id,
            manifest_digest: ObjectId([1; 32]),
            projection: ProjectionMode::Full,
            object_count: 1,
            object_bytes: 1,
            membership_root: ObjectId([2; 32]),
            artifact_set_digest: ObjectId([3; 32]),
        }
    }

    #[test]
    fn duplicate_projection_adoption_releases_both_pins() {
        let first = Arc::new(Lifecycle::default());
        let second = Arc::new(Lifecycle::default());
        let builder = ValidatedTransaction::builder(PrivilegedConstruction::internal())
            .adopt_projection(descriptor([1; 16]), ProjectionAdoption::new(first.clone()))
            .expect("first adoption");

        let result =
            builder.adopt_projection(descriptor([2; 16]), ProjectionAdoption::new(second.clone()));
        assert!(matches!(result, Err(StoreError::Conflict(_))));
        for lifecycle in [first, second] {
            assert_eq!(
                &*lifecycle.outcomes.lock().unwrap(),
                &[ProjectionAdoptionOutcome::DefinitivePreAppendFailure]
            );
            assert_eq!(*lifecycle.dropped.lock().unwrap(), 0);
        }
    }
}
