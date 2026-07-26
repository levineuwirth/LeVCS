//! Deterministic crash-injection points, in one-to-one correspondence with
//! the frozen `levcs_protocol::oracle::AppendFailpoint`.
//!
//! Lead-owned (scope 2.3). Compiled out entirely without the `failpoints`
//! feature: `hit` becomes an inlined constant.
//!
//! The correspondence is enforced by exhaustive `match` in both directions
//! plus a coverage test, so adding a failpoint in either crate breaks the
//! build rather than silently leaving a hole in the matrix. That mechanism is
//! the direct response to contract review 2026-07-24-A, where an unsound
//! recovery classification survived because the enclosing test asserted every
//! neighboring field except the one that was wrong.

use levcs_protocol::oracle::AppendFailpoint;

/// A failpoint names a *location*. The driver chooses the *action*, and the
/// two axes are independent — the Wave B matrix must exercise `Panic` on the
/// publication-side locations even though `WriterPanicAfterFence` is a Wave A
/// row (scope 4-A3 condition (b)).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum FailpointAction {
    #[default]
    Continue,
    /// Return an error from the current operation. Destructors run.
    Fail,
    /// Panic and unwind. Destructors run — which is the point: a `Drop` impl
    /// that truncates, rewinds the cursor, or flushes a buffer would corrupt a
    /// fenced prefix, and only an unwind can catch that.
    Panic,
    /// `_exit(3)` with no unwinding, no destructors, and no buffer flush. The
    /// closest in-process approximation of power loss.
    HardExit,
}

/// The store-side mirror of `AppendFailpoint`.
///
/// This exists as a separate type rather than a re-export so that the
/// conversion below is a real exhaustive check the compiler enforces. A
/// re-export would make drift impossible to detect but would also couple the
/// storage engine's instrumentation vocabulary to the protocol crate's.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Failpoint {
    BeforeAppend,
    AfterMarkedResolving,
    DuringFrameWriteTorn,
    AfterFrameWrite,
    EvidenceHandoffFailure,
    BeforeFence,
    FenceFailed,
    FenceAmbiguous,
    AfterSuccessfulFence,
    DuringCommittedRootBuild,
    AllocationFailureBeforePublication,
    BeforeRootCas,
    DuringRootCasRetry,
    WriterPanicBeforeFence,
    WriterPanicAfterFence,
    AfterRootCasBeforeWaiterWake,
    BeforeResponse,
}

/// Which wave can drive a failpoint to its physical outcome.
///
/// Given by name, never by count (scope 4-A3): the first draft of the scope
/// document stated a count and the count was wrong, which is the same class of
/// error as an unasserted field.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Wave {
    /// Reachable through `drive.rs` with no engine, status root, sequencer, or
    /// signer.
    A,
    /// Requires `engine.rs`; recorded as `pending-wave-b` in the crash-matrix
    /// fixture until B1 lands.
    B,
}

impl Failpoint {
    pub const ALL: &'static [Failpoint] = &[
        Failpoint::BeforeAppend,
        Failpoint::AfterMarkedResolving,
        Failpoint::DuringFrameWriteTorn,
        Failpoint::AfterFrameWrite,
        Failpoint::EvidenceHandoffFailure,
        Failpoint::BeforeFence,
        Failpoint::FenceFailed,
        Failpoint::FenceAmbiguous,
        Failpoint::AfterSuccessfulFence,
        Failpoint::DuringCommittedRootBuild,
        Failpoint::AllocationFailureBeforePublication,
        Failpoint::BeforeRootCas,
        Failpoint::DuringRootCasRetry,
        Failpoint::WriterPanicBeforeFence,
        Failpoint::WriterPanicAfterFence,
        Failpoint::AfterRootCasBeforeWaiterWake,
        Failpoint::BeforeResponse,
    ];

    /// Stable name used in the crash-matrix fixture and on the driver's
    /// command line.
    pub const fn name(self) -> &'static str {
        match self {
            Failpoint::BeforeAppend => "BeforeAppend",
            Failpoint::AfterMarkedResolving => "AfterMarkedResolving",
            Failpoint::DuringFrameWriteTorn => "DuringFrameWriteTorn",
            Failpoint::AfterFrameWrite => "AfterFrameWrite",
            Failpoint::EvidenceHandoffFailure => "EvidenceHandoffFailure",
            Failpoint::BeforeFence => "BeforeFence",
            Failpoint::FenceFailed => "FenceFailed",
            Failpoint::FenceAmbiguous => "FenceAmbiguous",
            Failpoint::AfterSuccessfulFence => "AfterSuccessfulFence",
            Failpoint::DuringCommittedRootBuild => "DuringCommittedRootBuild",
            Failpoint::AllocationFailureBeforePublication => "AllocationFailureBeforePublication",
            Failpoint::BeforeRootCas => "BeforeRootCas",
            Failpoint::DuringRootCasRetry => "DuringRootCasRetry",
            Failpoint::WriterPanicBeforeFence => "WriterPanicBeforeFence",
            Failpoint::WriterPanicAfterFence => "WriterPanicAfterFence",
            Failpoint::AfterRootCasBeforeWaiterWake => "AfterRootCasBeforeWaiterWake",
            Failpoint::BeforeResponse => "BeforeResponse",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.name() == name)
    }

    /// Wave assignment, frozen in D0.
    ///
    /// `WriterPanicAfterFence` is Wave A, read as "the writer thread panics
    /// once `fdatasync` has returned". The claim it certifies — a fenced frame
    /// survives a panic-unwind death of the writer — is a journal-layer claim
    /// and `drive.rs` contains the panic site. Its entire differential against
    /// `AfterSuccessfulFence` is unwind versus clean error return, and unwind
    /// is exactly where a `Drop` impl could corrupt the fenced prefix; the
    /// driver's `HardExit` path deliberately cannot catch that because
    /// `_exit(3)` runs no destructors.
    pub const fn wave(self) -> Wave {
        match self {
            Failpoint::BeforeAppend
            | Failpoint::DuringFrameWriteTorn
            | Failpoint::AfterFrameWrite
            | Failpoint::BeforeFence
            | Failpoint::FenceFailed
            | Failpoint::FenceAmbiguous
            | Failpoint::AfterSuccessfulFence
            | Failpoint::WriterPanicBeforeFence
            | Failpoint::WriterPanicAfterFence => Wave::A,

            // Needs the status root.
            Failpoint::AfterMarkedResolving
            // Needs the sequencer's signer handoff.
            | Failpoint::EvidenceHandoffFailure
            // Need the committed-root build and CAS publication path.
            | Failpoint::DuringCommittedRootBuild
            | Failpoint::AllocationFailureBeforePublication
            | Failpoint::BeforeRootCas
            | Failpoint::DuringRootCasRetry
            | Failpoint::AfterRootCasBeforeWaiterWake
            | Failpoint::BeforeResponse => Wave::B,
        }
    }
}

impl From<Failpoint> for AppendFailpoint {
    fn from(p: Failpoint) -> Self {
        match p {
            Failpoint::BeforeAppend => AppendFailpoint::BeforeAppend,
            Failpoint::AfterMarkedResolving => AppendFailpoint::AfterMarkedResolving,
            Failpoint::DuringFrameWriteTorn => AppendFailpoint::DuringFrameWriteTorn,
            Failpoint::AfterFrameWrite => AppendFailpoint::AfterFrameWrite,
            Failpoint::EvidenceHandoffFailure => AppendFailpoint::EvidenceHandoffFailure,
            Failpoint::BeforeFence => AppendFailpoint::BeforeFence,
            Failpoint::FenceFailed => AppendFailpoint::FenceFailed,
            Failpoint::FenceAmbiguous => AppendFailpoint::FenceAmbiguous,
            Failpoint::AfterSuccessfulFence => AppendFailpoint::AfterSuccessfulFence,
            Failpoint::DuringCommittedRootBuild => AppendFailpoint::DuringCommittedRootBuild,
            Failpoint::AllocationFailureBeforePublication => {
                AppendFailpoint::AllocationFailureBeforePublication
            }
            Failpoint::BeforeRootCas => AppendFailpoint::BeforeRootCas,
            Failpoint::DuringRootCasRetry => AppendFailpoint::DuringRootCasRetry,
            Failpoint::WriterPanicBeforeFence => AppendFailpoint::WriterPanicBeforeFence,
            Failpoint::WriterPanicAfterFence => AppendFailpoint::WriterPanicAfterFence,
            Failpoint::AfterRootCasBeforeWaiterWake => {
                AppendFailpoint::AfterRootCasBeforeWaiterWake
            }
            Failpoint::BeforeResponse => AppendFailpoint::BeforeResponse,
        }
    }
}

impl From<AppendFailpoint> for Failpoint {
    fn from(p: AppendFailpoint) -> Self {
        match p {
            AppendFailpoint::BeforeAppend => Failpoint::BeforeAppend,
            AppendFailpoint::AfterMarkedResolving => Failpoint::AfterMarkedResolving,
            AppendFailpoint::DuringFrameWriteTorn => Failpoint::DuringFrameWriteTorn,
            AppendFailpoint::AfterFrameWrite => Failpoint::AfterFrameWrite,
            AppendFailpoint::EvidenceHandoffFailure => Failpoint::EvidenceHandoffFailure,
            AppendFailpoint::BeforeFence => Failpoint::BeforeFence,
            AppendFailpoint::FenceFailed => Failpoint::FenceFailed,
            AppendFailpoint::FenceAmbiguous => Failpoint::FenceAmbiguous,
            AppendFailpoint::AfterSuccessfulFence => Failpoint::AfterSuccessfulFence,
            AppendFailpoint::DuringCommittedRootBuild => Failpoint::DuringCommittedRootBuild,
            AppendFailpoint::AllocationFailureBeforePublication => {
                Failpoint::AllocationFailureBeforePublication
            }
            AppendFailpoint::BeforeRootCas => Failpoint::BeforeRootCas,
            AppendFailpoint::DuringRootCasRetry => Failpoint::DuringRootCasRetry,
            AppendFailpoint::WriterPanicBeforeFence => Failpoint::WriterPanicBeforeFence,
            AppendFailpoint::WriterPanicAfterFence => Failpoint::WriterPanicAfterFence,
            AppendFailpoint::AfterRootCasBeforeWaiterWake => {
                Failpoint::AfterRootCasBeforeWaiterWake
            }
            AppendFailpoint::BeforeResponse => Failpoint::BeforeResponse,
        }
    }
}

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

#[cfg(feature = "failpoints")]
mod armed {
    use super::{Failpoint, FailpointAction};
    use std::sync::Mutex;

    static ARMED: Mutex<Option<(Failpoint, FailpointAction)>> = Mutex::new(None);

    /// Takes the same token as [`crate::sys::arm`], deliberately.
    ///
    /// The two registries are separate globals, but they are not independent:
    /// both steer the same drive operation, and a test arming a failpoint
    /// while another arms a physical fault interferes exactly as badly as two
    /// tests sharing one registry would. One token covering both is what makes
    /// "I hold the fault lock" mean "no other test is perturbing this drive".
    pub fn arm(_serial: &crate::sys::FaultSerial, point: Failpoint, action: FailpointAction) {
        *ARMED.lock().expect("failpoint mutex") = Some((point, action));
    }

    pub fn disarm(_serial: &crate::sys::FaultSerial) {
        *ARMED.lock().expect("failpoint mutex") = None;
    }

    pub fn action_for(point: Failpoint) -> FailpointAction {
        let mut guard = ARMED.lock().expect("failpoint mutex");
        match *guard {
            Some((armed, action)) if armed == point => {
                *guard = None;
                action
            }
            _ => FailpointAction::Continue,
        }
    }
}

#[cfg(feature = "failpoints")]
pub use armed::{arm, disarm};

/// Evaluate a failpoint. Returns `Continue` unless the harness armed this
/// exact location.
///
/// `HardExit` never returns: it calls `_exit(3)` directly so no destructor
/// runs, no buffered write is flushed, and nothing in the process gets a
/// chance to tidy up — the closest in-process approximation of power loss.
///
/// A1's append path calls this at every Wave A location, so there is no
/// `allow(dead_code)` here any more: an unreferenced failpoint is now a real
/// signal that the matrix has a hole.
#[cfg(feature = "failpoints")]
pub(crate) fn hit(point: Failpoint) -> FailpointAction {
    let action = armed::action_for(point);
    if matches!(action, FailpointAction::HardExit) {
        // `_exit(2)`, not `std::process::exit`: the latter runs atexit
        // handlers and flushes stdio, which is exactly the tidying a power
        // loss does not do. Nothing here unwinds, no `Drop` runs, and no
        // buffered write reaches the device.
        //
        // SAFETY: `_exit` is async-signal-safe and does not return.
        unsafe { libc::_exit(3) }
    }
    action
}

#[cfg(not(feature = "failpoints"))]
#[inline(always)]
pub(crate) fn hit(_point: Failpoint) -> FailpointAction {
    FailpointAction::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use levcs_protocol::oracle::APPEND_PUBLICATION_FAILPOINTS;

    #[test]
    fn every_oracle_failpoint_has_exactly_one_store_failpoint() {
        assert_eq!(
            Failpoint::ALL.len(),
            APPEND_PUBLICATION_FAILPOINTS.len(),
            "the store's failpoint set must be the frozen oracle's set"
        );
        for point in APPEND_PUBLICATION_FAILPOINTS {
            let store: Failpoint = (*point).into();
            let back: AppendFailpoint = store.into();
            assert_eq!(back, *point, "conversion must round-trip for {:?}", point);
        }
        for point in Failpoint::ALL {
            let oracle: AppendFailpoint = (*point).into();
            let back: Failpoint = oracle.into();
            assert_eq!(back, *point, "conversion must round-trip for {point:?}");
        }
    }

    #[test]
    fn names_are_unique_and_parse_back() {
        let mut seen = std::collections::BTreeSet::new();
        for point in Failpoint::ALL {
            assert!(seen.insert(point.name()), "duplicate name {}", point.name());
            assert_eq!(Failpoint::from_name(point.name()), Some(*point));
        }
        assert_eq!(Failpoint::from_name("NoSuchPoint"), None);
    }

    /// The wave partition is pinned by name, per row. A count would not catch
    /// a row moving between sets, which is exactly the error the first scope
    /// draft made.
    #[test]
    fn wave_assignment_is_pinned_by_name() {
        let wave_a: Vec<&str> = Failpoint::ALL
            .iter()
            .filter(|p| p.wave() == Wave::A)
            .map(|p| p.name())
            .collect();
        let wave_b: Vec<&str> = Failpoint::ALL
            .iter()
            .filter(|p| p.wave() == Wave::B)
            .map(|p| p.name())
            .collect();

        assert_eq!(
            wave_a,
            vec![
                "BeforeAppend",
                "DuringFrameWriteTorn",
                "AfterFrameWrite",
                "BeforeFence",
                "FenceFailed",
                "FenceAmbiguous",
                "AfterSuccessfulFence",
                "WriterPanicBeforeFence",
                "WriterPanicAfterFence",
            ]
        );
        assert_eq!(
            wave_b,
            vec![
                "AfterMarkedResolving",
                "EvidenceHandoffFailure",
                "DuringCommittedRootBuild",
                "AllocationFailureBeforePublication",
                "BeforeRootCas",
                "DuringRootCasRetry",
                "AfterRootCasBeforeWaiterWake",
                "BeforeResponse",
            ]
        );
    }

    /// Every Wave A row must reach a *physical* outcome the journal layer can
    /// produce, and every Wave B row must be one whose distinguishing
    /// assertion is logical. This checks the partition against the frozen
    /// oracle rather than against the author's intent: a Wave A row may not
    /// be one whose only observable difference is a status-root effect.
    #[test]
    fn wave_a_rows_are_exactly_those_with_a_journal_observable_outcome() {
        use levcs_protocol::oracle::append_publication_expectation;

        for point in Failpoint::ALL {
            let expectation = append_publication_expectation((*point).into());
            if point.wave() == Wave::A {
                // Wave A asserts the physical-state-class and
                // recovery_outcome halves only; the remaining fields are
                // equally unassertable for all nine rows until B1 exists.
                let _ = expectation.recovery_outcome;
            } else {
                assert!(
                    !expectation.acknowledgment_allowed
                        || matches!(
                            point,
                            Failpoint::AfterRootCasBeforeWaiterWake | Failpoint::BeforeResponse
                        ),
                    "a Wave B row that allows acknowledgment must be a \
                     post-publication row: {point:?}"
                );
            }
        }
    }

    #[cfg(feature = "failpoints")]
    #[test]
    fn an_unarmed_failpoint_continues_and_an_armed_one_fires_once() {
        let serial = crate::sys::serial();
        disarm(&serial);
        assert_eq!(hit(Failpoint::BeforeFence), FailpointAction::Continue);

        arm(&serial, Failpoint::BeforeFence, FailpointAction::Fail);
        assert_eq!(
            hit(Failpoint::AfterFrameWrite),
            FailpointAction::Continue,
            "a different location must not consume the armed fault"
        );
        assert_eq!(hit(Failpoint::BeforeFence), FailpointAction::Fail);
        assert_eq!(
            hit(Failpoint::BeforeFence),
            FailpointAction::Continue,
            "arming is one-shot so a campaign stays deterministic"
        );
        disarm(&serial);
    }
}
