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
use std::sync::Arc;

use levcs_core::{ObjectId, ObjectType};
use levcs_protocol::v2::{
    RefTarget, StagedProjectionInstallV1, TransactionEvidenceV1, TypedRefCas,
};

use crate::staging::{ProjectionAdoption, ProjectionAdoptionOutcome, StagedProjectionAdoption};
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
    /// The canonical descriptor of an adopted projection, kept here rather than
    /// beside the pin because the frame is rebuilt from this value on **every**
    /// sequencing attempt. A pre-mark deadline recheck that drops a group member
    /// re-sequences, re-chains, and re-signs everything after it, and a
    /// descriptor that had left with the pin would leave the retry with no
    /// payload to encode.
    pub(crate) projection: Option<StagedProjectionInstallV1>,
    /// The live pin, and the one field of this struct that is not reproducible.
    ///
    /// `Option` because the writer **takes** it, exactly once, before wrapping
    /// this transaction in the `Arc` that survives re-sequencing — an `Arc` has
    /// no move-out, so a pin left in here would be unreachable at the moment it
    /// has to be settled. From that point the pin lives in an `AdoptionSlot`
    /// beside the `Arc`, and `projection` above is what the retries read.
    pub(crate) adoption_pin: Option<AdoptionSlot>,
}

impl ValidatedTransaction {
    /// Take the slot out on its way into the writer.
    ///
    /// Called once, before `Arc::new`. Calling it twice yields `None` rather
    /// than a second capability: the pin is linear and there is only ever one.
    pub(crate) fn take_adoption(&mut self) -> Option<AdoptionSlot> {
        self.adoption_pin.take()
    }

    /// Read by the writer when it encodes the frame payload. See the note on
    /// [`AppendPhase`] for why it is unreached today.
    #[allow(dead_code)]
    pub(crate) fn projection(&self) -> Option<&StagedProjectionInstallV1> {
        self.projection.as_ref()
    }
}

/// How far this transaction's frame has gone toward the device.
///
/// Only two values, because only two answers matter to a pin that has to be
/// settled without knowing why: either nothing of this frame reached the
/// journal, or something may have.
// `Appended` is constructed only by the writer's append path, and the parts of
// `AdoptionSlot` below that the writer alone calls are likewise unreached until
// `StoreEngine::submit` stops refusing an adoption. Both are exercised by this
// module's tests; the allow covers the non-test build only.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum AppendPhase {
    /// No byte of this transaction's frame has been written. An adoption
    /// abandoned here is definitively not installed.
    BeforeAppend,
    /// A write has been attempted. **Not** "a fence succeeded" — the
    /// transition is at the first possible frame write, so torn bytes and whole
    /// unfenced frames are both on this side of it. Recovery, which can read
    /// the device, is the only thing that can say which happened.
    Appended,
}

/// The one-shot owner of an admitted adoption pin.
///
/// # Why this exists rather than a field on the transaction
///
/// `Prepared` retains an `Arc<ValidatedTransaction>` so a group can be
/// re-sequenced, re-chained, and re-signed when the pre-mark deadline recheck
/// drops a member. An `Arc` has no move-out, so a linear `ProjectionAdoption`
/// stored inside one could never be taken out to be settled. The pin therefore
/// travels *beside* the `Arc`, in this slot, and the descriptor the retries
/// need stays in the transaction where it can be read any number of times.
///
/// # Why the phase, rather than settling at each site
///
/// Every route out of a submit has to settle the pin, and the dangerous ones
/// are the routes nobody enumerated: a full or disconnected submission queue,
/// a pre-append error, a panic inside the writer, a deadline recheck that
/// reforms the group, an unwind. Naming them one at a time means the next
/// route added is a leak. Instead the slot settles itself on drop and reads the
/// outcome off the phase, so a route that was never considered is still
/// correct — and correct in the safe direction, because the phase advances
/// before the write rather than after the fence.
pub(crate) struct AdoptionSlot {
    /// `None` only after an explicit [`Self::finish`]. A slot that still holds
    /// its pin at drop time settles it from the phase.
    handle: Option<ProjectionAdoption>,
    phase: AppendPhase,
}

#[allow(dead_code)] // See the note on `AppendPhase`.
impl AdoptionSlot {
    pub(crate) fn new(handle: ProjectionAdoption) -> Self {
        Self {
            handle: Some(handle),
            phase: AppendPhase::BeforeAppend,
        }
    }

    /// Advance to [`AppendPhase::Appended`], at the first possible frame write.
    ///
    /// Deliberately idempotent and one-way: a group that re-forms and appends
    /// again must not walk the phase back to `BeforeAppend`, because the
    /// earlier attempt's bytes may already be on the device.
    pub(crate) fn entered_append(&mut self) {
        self.phase = AppendPhase::Appended;
    }

    pub(crate) fn phase(&self) -> AppendPhase {
        self.phase
    }

    /// Read the pin without consuming it, for the pre-append revalidation.
    ///
    /// `None` cannot happen before [`Self::finish`] and is not an error worth a
    /// second failure mode: a caller that gets it has already settled the pin
    /// and has nothing left to validate.
    pub(crate) fn resolution(
        &self,
    ) -> Option<Result<Arc<crate::staging::ProjectionAdoptionResolution>, StoreError>> {
        self.handle.as_ref().map(|handle| handle.resolution())
    }

    /// Settle with an explicit outcome, and hand back staging's answer.
    ///
    /// The only path that reports a settlement failure. [`Drop`] cannot, which
    /// is why the writer calls this at the two points where it knows the
    /// outcome — the publication that adopted, and the pre-append refusal that
    /// did not.
    pub(crate) fn finish(mut self, outcome: ProjectionAdoptionOutcome) -> Result<(), StoreError> {
        match self.handle.take() {
            Some(handle) => handle.finish(outcome),
            None => Ok(()),
        }
    }
}

impl Drop for AdoptionSlot {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        let outcome = match self.phase {
            AppendPhase::BeforeAppend => ProjectionAdoptionOutcome::DefinitivePreAppendFailure,
            AppendPhase::Appended => ProjectionAdoptionOutcome::TransferredToRecovery,
        };
        // Swallowed because a `Drop` has nowhere to put it, and accounted for
        // regardless: a `finish` that fails leaves `ProjectionAdoption` unfinished,
        // so its own `Drop` records the pin as dropped without an outcome. The
        // failure is visible in staging's counters rather than lost — it is only
        // this frame's error text that cannot be carried out of here.
        let _ = handle.finish(outcome);
    }
}

/// Deliberately no `Debug` derive on the slot: `#[derive]` on a struct holding
/// a capability invites printing it, and what a pin identifies is a session
/// whose id belongs in staging's diagnostics rather than in a transaction dump.
impl std::fmt::Debug for AdoptionSlot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdoptionSlot")
            .field("settled", &self.handle.is_none())
            .field("phase", &self.phase)
            .finish()
    }
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
    /// The descriptor and its pin, the pin already inside the slot that owns
    /// it. Held as a pair because `build` needs the descriptor and the slot to
    /// travel to different places, and neither may arrive without the other.
    adoption: Option<(StagedProjectionInstallV1, AdoptionSlot)>,
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

    /// Adopt one sealed staged projection.
    ///
    /// Takes the whole [`StagedProjectionAdoption`] rather than a descriptor
    /// and a pin separately. The frozen signature took two arguments so that
    /// neither half could be *forgotten* independently, which this keeps — and
    /// it additionally makes them impossible to *mismatch*, which two
    /// arguments could not. See the type's own note. Contract review
    /// 2026-08-09-A.
    pub fn adopt_projection(
        mut self,
        adoption: StagedProjectionAdoption,
    ) -> Result<Self, StoreError> {
        let StagedProjectionAdoption { descriptor, handle } = adoption;
        // Wrapped before anything below can fail. From here the pin is owned by
        // a slot, so a builder abandoned mid-chain — `adopt_projection` called
        // and `build` never reached — releases it with a pre-append outcome
        // instead of dropping a live capability.
        let slot = AdoptionSlot::new(handle);
        if let Some((_, previous)) = self.adoption.take() {
            // Both pins were admitted, so both receive a terminal outcome
            // even though the builder rejects the duplicate. Returning early
            // after finishing only one would turn the other drop into the
            // lifecycle bug this handle exists to expose. Settled explicitly
            // rather than by drop because only this path can report a
            // settlement that itself failed.
            let previous_result =
                previous.finish(ProjectionAdoptionOutcome::DefinitivePreAppendFailure);
            let submitted_result =
                slot.finish(ProjectionAdoptionOutcome::DefinitivePreAppendFailure);
            previous_result?;
            submitted_result?;
            return Err(StoreError::Conflict(
                "a transaction may adopt exactly one staged projection".into(),
            ));
        }
        self.adoption = Some((descriptor, slot));
        Ok(self)
    }

    pub fn build(mut self) -> Result<ValidatedTransaction, StoreError> {
        // Held across every fallible step below rather than unwrapped at the
        // end. `AdoptionSlot` settles itself when dropped, so each `?` in this
        // function releases the pin with a definitive pre-append outcome
        // without naming it — and a refusal that forgot to would create exactly
        // the unsettled-drop §6.5 declares a bug. The slot reaches the returned
        // transaction only on the success path.
        let adoption = self.adoption.take();

        let namespace = self.namespace.ok_or_else(|| incomplete("namespace"))?;
        let (operation_id, operation_digest, retry_until_micros) =
            self.operation.ok_or_else(|| incomplete("operation"))?;
        let evidence = self.evidence.ok_or_else(|| incomplete("evidence"))?;
        let (expected_authority, new_authority) =
            self.authority.ok_or_else(|| incomplete("authority"))?;
        let mut objects = self.objects.ok_or_else(|| incomplete("objects"))?;
        let refs = self.refs.ok_or_else(|| incomplete("refs"))?;

        // A frame carries inline objects or an install descriptor and never
        // both: `FrameObjectsV1` is an enum, so there is no encoding for the
        // pair. This is a refusal rather than a silent choice because both
        // silent choices are wrong — dropping the inline objects loses bytes
        // the caller asked to commit, and dropping the projection commits a
        // frame that references artifacts nothing installs.
        //
        // An adopting transaction is therefore built with an *empty* object
        // list, not with the list omitted. The projection is the payload.
        if adoption.is_some() && !objects.is_empty() {
            return Err(StoreError::Conflict(format!(
                "a transaction adopting a staged projection may not also introduce {} inline \
                 object(s); a frame carries one payload or the other",
                objects.len()
            )));
        }

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

        let (projection, adoption_pin) = match adoption {
            Some((descriptor, slot)) => (Some(descriptor), Some(slot)),
            None => (None, None),
        };

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
            projection,
            adoption_pin,
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

    /// The pairing a caller outside this crate cannot assemble by hand, which
    /// is the point of the type. These tests are inside the crate and can, so
    /// they build it through one helper rather than at each call site — a
    /// second construction site is a second chance to pair a descriptor with a
    /// pin from somewhere else, which is exactly what production no longer
    /// permits.
    fn adoption(session_id: [u8; 16], lifecycle: Arc<Lifecycle>) -> StagedProjectionAdoption {
        StagedProjectionAdoption {
            descriptor: descriptor(session_id),
            handle: ProjectionAdoption::new(lifecycle),
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
    fn an_adoption_reaches_the_built_transaction_still_unsettled() {
        let lifecycle = Arc::new(Lifecycle::default());
        let transaction = complete()
            .adopt_projection(adoption([3; 16], lifecycle.clone()))
            .expect("one adoption is admitted")
            .build()
            .expect("an adopting transaction builds");

        assert_eq!(
            transaction.projection().map(|install| install.session_id),
            Some([3; 16]),
            "the descriptor the frame is encoded from must survive `build`"
        );
        // Unsettled on purpose: `build` is not a decision about whether the
        // projection installs. Recording an outcome here would either claim an
        // append that has not happened or release artifacts a submit is about
        // to reference.
        assert_eq!(&*lifecycle.outcomes.lock().unwrap(), &[]);
        assert_eq!(*lifecycle.dropped.lock().unwrap(), 0);
    }

    /// The enum has no encoding for both payloads, so the builder refuses
    /// rather than choosing which one to lose.
    #[test]
    fn an_adoption_alongside_inline_objects_is_refused_and_releases_its_pin() {
        let lifecycle = Arc::new(Lifecycle::default());
        let result = complete()
            .objects(vec![StagedObject {
                id: ObjectId([9; 32]),
                object_type: ObjectType::Blob,
                raw: vec![9; 8],
            }])
            .adopt_projection(adoption([3; 16], lifecycle.clone()))
            .expect("one adoption is admitted")
            .build();

        let Err(StoreError::Conflict(message)) = result else {
            panic!("expected a conflict, got {result:?}");
        };
        assert!(message.contains("one payload or the other"), "{message}");
        assert_eq!(
            &*lifecycle.outcomes.lock().unwrap(),
            &[ProjectionAdoptionOutcome::DefinitivePreAppendFailure]
        );
        assert_eq!(*lifecycle.dropped.lock().unwrap(), 0);
    }

    /// The two abandonment routes that no call site names.
    ///
    /// Neither is reachable by an enumerated release: one drops a builder that
    /// was never finished, the other drops a transaction that was never
    /// submitted. Both are ordinary things for a caller to do, and both would
    /// leak a live pin if settlement lived at the call sites rather than in the
    /// slot's `Drop`.
    #[test]
    fn an_abandoned_builder_or_transaction_releases_its_pin() {
        for abandon_before_build in [true, false] {
            let lifecycle = Arc::new(Lifecycle::default());
            let builder = complete()
                .adopt_projection(adoption([4; 16], lifecycle.clone()))
                .expect("one adoption is admitted");

            if abandon_before_build {
                drop(builder);
            } else {
                drop(builder.build().expect("an adopting transaction builds"));
            }

            assert_eq!(
                &*lifecycle.outcomes.lock().unwrap(),
                &[ProjectionAdoptionOutcome::DefinitivePreAppendFailure],
                "abandon_before_build = {abandon_before_build}"
            );
            assert_eq!(
                *lifecycle.dropped.lock().unwrap(),
                0,
                "abandon_before_build = {abandon_before_build}"
            );
        }
    }

    /// The phase, and only the phase, decides an unattended settlement.
    ///
    /// Asserted directly on the slot because the writer's routes into
    /// `Appended` are failures and panics, and a test that could only reach
    /// this rule through one of them would be asserting about that failure
    /// rather than about the rule.
    #[test]
    fn a_dropped_slot_settles_from_its_append_phase() {
        let cases = [
            (
                false,
                ProjectionAdoptionOutcome::DefinitivePreAppendFailure,
                "no byte was written",
            ),
            (
                true,
                ProjectionAdoptionOutcome::TransferredToRecovery,
                "a write was attempted",
            ),
        ];
        for (entered_append, expected, why) in cases {
            let lifecycle = Arc::new(Lifecycle::default());
            let mut slot = AdoptionSlot::new(ProjectionAdoption::new(lifecycle.clone()));
            assert_eq!(slot.phase(), AppendPhase::BeforeAppend);
            if entered_append {
                slot.entered_append();
                // One-way: a group that re-forms must not walk the phase back.
                slot.entered_append();
                assert_eq!(slot.phase(), AppendPhase::Appended);
            }
            drop(slot);

            assert_eq!(&*lifecycle.outcomes.lock().unwrap(), &[expected], "{why}");
            assert_eq!(*lifecycle.dropped.lock().unwrap(), 0, "{why}");
        }
    }

    /// An explicit settlement wins over the phase, and happens once.
    #[test]
    fn an_explicitly_finished_slot_does_not_settle_again_on_drop() {
        let lifecycle = Arc::new(Lifecycle::default());
        let mut slot = AdoptionSlot::new(ProjectionAdoption::new(lifecycle.clone()));
        slot.entered_append();
        slot.finish(ProjectionAdoptionOutcome::Adopted {
            committed_shard_sequence: 7,
        })
        .expect("staging accepts the outcome");

        assert_eq!(
            &*lifecycle.outcomes.lock().unwrap(),
            &[ProjectionAdoptionOutcome::Adopted {
                committed_shard_sequence: 7
            }],
            "the drop that follows `finish` must not add a second outcome"
        );
        assert_eq!(*lifecycle.dropped.lock().unwrap(), 0);
    }

    #[test]
    fn duplicate_projection_adoption_releases_both_pins() {
        let first = Arc::new(Lifecycle::default());
        let second = Arc::new(Lifecycle::default());
        let builder = ValidatedTransaction::builder(PrivilegedConstruction::internal())
            .adopt_projection(adoption([1; 16], first.clone()))
            .expect("first adoption");

        let result = builder.adopt_projection(adoption([2; 16], second.clone()));
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
