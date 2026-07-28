//! `ValidatedTransaction` and its sealed builder, the shard sequencer's
//! mutable-precondition checks, receipts, idempotency, and terminal retention.
//!
//! **Shared file.** Lead owns the signatures (D0); **B1 NamespaceTxn** fills
//! the bodies (scope 2.1, 6-B1).
//!
//! # What the builder settles and what the sequencer settles
//!
//! Everything here is fixed before the mutation lane is entered: the exact
//! bytes, the complete ordered ref CAS set, the explicit authority CAS, the
//! evidence, the operation identity, and the signed deadline. The sequencer
//! then rechecks only what can have changed since — ref CAS, authority, and
//! lifecycle — and never re-parses, re-hashes, or re-verifies any of it.
//!
//! `build` therefore refuses an incomplete transaction rather than filling a
//! field in. A defaulted `expected_authority` or an inferred `new_authority`
//! would turn an authority CAS into an unconditional overwrite, and the
//! sequencer cannot tell the difference between a value a caller chose and one
//! a builder supplied.

use std::collections::BTreeSet;

use levcs_core::{ObjectId, ObjectType};
use levcs_protocol::v2::{RefTarget, TransactionEvidenceV1, TypedRefCas};

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
    pub(crate) namespace: NamespaceId,
    pub(crate) operation_id: OperationId,
    pub(crate) operation_digest: ObjectId,
    pub(crate) retry_until_micros: i64,
    /// Present only for an init transaction.
    pub(crate) create_genesis_authority: Option<ObjectId>,
    /// Strictly ascending by `ObjectId`, which is the canonical frame order.
    /// Sorting here rather than at encode time means the sequencer never
    /// reorders bytes it is holding the mutation lane for.
    pub(crate) objects: Vec<StagedObject>,
    pub(crate) refs: Vec<TypedRefCas>,
    pub(crate) expected_authority: Option<ObjectId>,
    pub(crate) new_authority: Option<ObjectId>,
    pub(crate) evidence: TransactionEvidenceV1,
}

/// Deliberately does not print object or evidence bytes. A transaction's
/// payload is user content and a diagnostic that dumps it is a diagnostic
/// nobody can paste into a bug report.
impl std::fmt::Debug for ValidatedTransaction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedTransaction")
            .field("namespace", &self.namespace)
            .field("operation_id", &self.operation_id)
            .field(
                "creates_repository",
                &self.create_genesis_authority.is_some(),
            )
            .field("objects", &self.objects.len())
            .field("refs", &self.refs.len())
            .finish_non_exhaustive()
    }
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
        ValidatedTransactionBuilder {
            namespace: None,
            operation: None,
            create_genesis_authority: None,
            objects: None,
            refs: None,
            authority: None,
            evidence: None,
            adoption: None,
        }
    }
}

pub struct ValidatedTransactionBuilder {
    namespace: Option<NamespaceId>,
    operation: Option<(OperationId, ObjectId, i64)>,
    create_genesis_authority: Option<ObjectId>,
    objects: Option<Vec<StagedObject>>,
    refs: Option<Vec<TypedRefCas>>,
    /// `Some((None, None))` is a caller that explicitly moves no authority.
    /// `None` is a caller that never said, and is refused.
    #[allow(clippy::type_complexity)]
    authority: Option<(Option<ObjectId>, Option<ObjectId>)>,
    evidence: Option<TransactionEvidenceV1>,
    adoption: Option<StagedProjectionAdoption>,
}

fn incomplete(field: &str) -> StoreError {
    StoreError::InvalidConfiguration(format!(
        "validated transaction is incomplete: {field} was never set"
    ))
}

impl ValidatedTransactionBuilder {
    pub fn namespace(mut self, namespace: NamespaceId) -> Self {
        self.namespace = Some(namespace);
        self
    }

    pub fn operation(mut self, id: OperationId, digest: ObjectId, retry_until_micros: i64) -> Self {
        self.operation = Some((id, digest, retry_until_micros));
        self
    }

    /// Repository-create metadata. Present only for an init transaction, which
    /// permanently binds `repo_id` and the genesis authority hash in the
    /// catalog (plan §4 identity invariant 2).
    pub fn create_repository(mut self, genesis_authority: ObjectId) -> Self {
        self.create_genesis_authority = Some(genesis_authority);
        self
    }

    pub fn objects(mut self, objects: Vec<StagedObject>) -> Self {
        self.objects = Some(objects);
        self
    }

    /// The complete typed Set/Delete set. Multi-ref updates are entirely old
    /// or entirely new, including after crashes (plan §4 transaction
    /// invariant 2).
    pub fn refs(mut self, refs: Vec<TypedRefCas>) -> Self {
        self.refs = Some(refs);
        self
    }

    /// Explicit expected and new current authority. Never inferred.
    pub fn authority(mut self, expected: Option<ObjectId>, new: Option<ObjectId>) -> Self {
        self.authority = Some((expected, new));
        self
    }

    pub fn evidence(mut self, evidence: TransactionEvidenceV1) -> Self {
        self.evidence = Some(evidence);
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
            // Adoption is the B1/B3 seam of scope 6.2 item 9 and is not part
            // of this slice. The pin is released with a definitive pre-append
            // outcome before the refusal, because a dropped pin with no
            // outcome is the leak §6.5 declares a bug — the refusal must not
            // create one.
            adoption
                .handle
                .finish(ProjectionAdoptionOutcome::DefinitivePreAppendFailure)?;
            return Err(StoreError::NotImplemented(
                "ValidatedTransactionBuilder::adopt_projection — B1 NamespaceTxn, \
                 scope 6-B1 deliverable 3 and scope 6.2 item 9",
            ));
        }

        let namespace = self.namespace.ok_or_else(|| incomplete("namespace"))?;
        let (operation_id, operation_digest, retry_until_micros) =
            self.operation.ok_or_else(|| incomplete("operation"))?;
        let evidence = self.evidence.ok_or_else(|| incomplete("evidence"))?;
        let (expected_authority, new_authority) =
            self.authority.ok_or_else(|| incomplete("authority"))?;
        let mut objects = self.objects.ok_or_else(|| incomplete("objects"))?;
        let refs = self.refs.ok_or_else(|| incomplete("refs"))?;

        // Canonical frame order, established once. A duplicate `ObjectId` is
        // refused rather than deduplicated: two records for one object make
        // `objects_new` and the index disagree about what the transaction
        // introduced, and only the caller knows which one it meant.
        objects.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
        if objects.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err(StoreError::Conflict(
                "a transaction may introduce one object at most once".into(),
            ));
        }

        let mut targets: BTreeSet<&RefTarget> = BTreeSet::new();
        for update in &refs {
            if !targets.insert(&update.target) {
                return Err(StoreError::Conflict(
                    "a transaction may name one typed ref at most once; a duplicate target \
                     makes the same-ref winner ambiguous inside a single frame"
                        .into(),
                ));
            }
        }

        // An init transaction binds a genesis authority permanently, so the
        // authority object itself has to be in this transaction's bytes. The
        // frame records its exact length and hash, and neither can be invented
        // from a bare `ObjectId`.
        if let Some(genesis) = self.create_genesis_authority {
            let present = objects.iter().any(|object| {
                object.id == genesis && matches!(object.object_type, ObjectType::Authority)
            });
            if !present {
                return Err(StoreError::Conflict(
                    "a repository-create transaction must carry its genesis authority object"
                        .into(),
                ));
            }
        }

        Ok(ValidatedTransaction {
            namespace,
            operation_id,
            operation_digest,
            retry_until_micros,
            create_genesis_authority: self.create_genesis_authority,
            objects,
            refs,
            expected_authority,
            new_authority,
            evidence,
        })
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

    pub(crate) fn administrative_evidence() -> TransactionEvidenceV1 {
        TransactionEvidenceV1::AdministrativeV1 {
            actor: [9; 32],
            actor_key_epoch: 1,
            command_digest: ObjectId([4; 32]),
            signature: [5; 64],
        }
    }

    fn complete() -> ValidatedTransactionBuilder {
        ValidatedTransaction::builder(PrivilegedConstruction::internal())
            .namespace(NamespaceId([1; 32]))
            .operation(OperationId([2; 16]), ObjectId([3; 32]), 1_000)
            .objects(Vec::new())
            .refs(Vec::new())
            .authority(None, None)
            .evidence(administrative_evidence())
    }

    /// Every omitted field is refused by name. An enumerated list rather than
    /// one representative case: the defect this guards against is a builder
    /// that quietly defaults exactly one field, and a single-case test cannot
    /// see which field that is.
    #[test]
    fn an_incomplete_builder_is_refused_field_by_field() {
        complete().build().expect("the complete builder builds");

        let bare = || ValidatedTransaction::builder(PrivilegedConstruction::internal());
        let cases: Vec<(&str, ValidatedTransactionBuilder)> = vec![
            (
                "namespace",
                bare()
                    .operation(OperationId([2; 16]), ObjectId([3; 32]), 1_000)
                    .objects(Vec::new())
                    .refs(Vec::new())
                    .authority(None, None)
                    .evidence(administrative_evidence()),
            ),
            (
                "operation",
                bare()
                    .namespace(NamespaceId([1; 32]))
                    .objects(Vec::new())
                    .refs(Vec::new())
                    .authority(None, None)
                    .evidence(administrative_evidence()),
            ),
            (
                "evidence",
                bare()
                    .namespace(NamespaceId([1; 32]))
                    .operation(OperationId([2; 16]), ObjectId([3; 32]), 1_000)
                    .objects(Vec::new())
                    .refs(Vec::new())
                    .authority(None, None),
            ),
            (
                "authority",
                bare()
                    .namespace(NamespaceId([1; 32]))
                    .operation(OperationId([2; 16]), ObjectId([3; 32]), 1_000)
                    .objects(Vec::new())
                    .refs(Vec::new())
                    .evidence(administrative_evidence()),
            ),
            (
                "objects",
                bare()
                    .namespace(NamespaceId([1; 32]))
                    .operation(OperationId([2; 16]), ObjectId([3; 32]), 1_000)
                    .refs(Vec::new())
                    .authority(None, None)
                    .evidence(administrative_evidence()),
            ),
            (
                "refs",
                bare()
                    .namespace(NamespaceId([1; 32]))
                    .operation(OperationId([2; 16]), ObjectId([3; 32]), 1_000)
                    .objects(Vec::new())
                    .authority(None, None)
                    .evidence(administrative_evidence()),
            ),
        ];

        for (field, builder) in cases {
            match builder.build() {
                Err(StoreError::InvalidConfiguration(message)) => assert!(
                    message.contains(field),
                    "refusal must name the missing field {field}, got {message}"
                ),
                other => panic!("omitting {field} must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_duplicate_object_or_ref_target_is_refused() {
        let object = |byte: u8| StagedObject {
            id: ObjectId([byte; 32]),
            object_type: ObjectType::Blob,
            raw: vec![byte],
        };
        match complete().objects(vec![object(7), object(7)]).build() {
            Err(StoreError::Conflict(message)) => {
                assert!(message.contains("at most once"), "{message}")
            }
            other => panic!("a duplicate object must be refused, got {other:?}"),
        }

        let update = || TypedRefCas {
            target: RefTarget::Branch("main".into()),
            expected: None,
            mutation: levcs_protocol::v2::RefMutation::Set(ObjectId([8; 32])),
            force: false,
        };
        match complete().refs(vec![update(), update()]).build() {
            Err(StoreError::Conflict(message)) => {
                assert!(message.contains("same-ref winner"), "{message}")
            }
            other => panic!("a duplicate ref target must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_create_without_its_genesis_authority_object_is_refused() {
        let genesis = ObjectId([12; 32]);
        match complete().create_repository(genesis).build() {
            Err(StoreError::Conflict(message)) => {
                assert!(message.contains("genesis authority object"), "{message}")
            }
            other => panic!("a create with no genesis object must be refused, got {other:?}"),
        }

        complete()
            .create_repository(genesis)
            .objects(vec![StagedObject {
                id: genesis,
                object_type: ObjectType::Authority,
                raw: vec![1, 2, 3],
            }])
            .build()
            .expect("a create carrying its genesis authority builds");
    }

    #[test]
    fn a_projection_adoption_is_refused_and_releases_its_pin() {
        let lifecycle = Arc::new(Lifecycle::default());
        let result = complete()
            .adopt_projection(
                descriptor([3; 16]),
                ProjectionAdoption::new(lifecycle.clone()),
            )
            .expect("one adoption is admitted")
            .build();

        assert!(matches!(result, Err(StoreError::NotImplemented(_))));
        assert_eq!(
            &*lifecycle.outcomes.lock().unwrap(),
            &[ProjectionAdoptionOutcome::DefinitivePreAppendFailure]
        );
        assert_eq!(*lifecycle.dropped.lock().unwrap(), 0);
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
