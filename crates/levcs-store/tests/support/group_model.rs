//! The group-aware failpoint model (scope 4-A3 deliverable 3, ruling 9.3).
//!
//! `levcs_protocol::oracle::append_publication_expectation` is a
//! *single-transaction* contract. A real group carries up to
//! `max_group_transactions` frames behind one fence, and a failpoint fires at
//! one victim frame inside it. This module layers the group answer on top of
//! the frozen oracle; per ruling 9.3 it does not extend the oracle.
//!
//! # The contract is a contiguous adopted prefix, not a per-frame answer
//!
//! Each individual unfenced frame is independently either-whole via page
//! writeback, so a *per-frame* formulation would permit "frame 3 absent, frame
//! 4 committed". Recovery step 6 (scope 3.8) forbids exactly that, and an
//! implementation that adopts a syntactically valid frame sitting after a hole
//! is the single most consequential recovery bug this phase can ship. This
//! module therefore answers with a window of legal prefix lengths:
//!
//! > there exists some *p* ≤ `victim_index` such that frames `0..p` are
//! > committed and frames `p..group_len` are absent; nothing at or after the
//! > victim is ever committed.
//!
//! [`verify_adopted_prefix`] is the checker that turns that statement into a
//! failure for an adopt-past-a-hole implementation, which a per-frame
//! formulation could not do.
//!
//! # Degeneracy
//!
//! [`group_failpoint_expectation`] must reduce to the frozen oracle at
//! `group_len == 1`, and per ruling 9.3's condition that reduction must hold
//! for **every** physical state class, not only the torn one. The proof lives
//! in `crash_matrix.rs` and iterates every failpoint, which covers every class
//! by construction because [`PhysicalStateClass::ALL`] is asserted to be
//! exactly the set of classes witnessed by some failpoint.

#![allow(dead_code)]

use levcs_protocol::oracle::{append_publication_expectation, RecoveredTailFact, RecoveryOutcome};
use levcs_store::failpoints::Failpoint;

/// The structural half of the prefix contract, shared verbatim with
/// `store-crash-driver` and `store-bench` rather than restated here.
///
/// The reconcilers and this model must not disagree about what "contiguous"
/// means; the review that produced this include found them disagreeing, with
/// the binaries carrying the weaker rule.
#[path = "../../src/bin/support/adopted_set.rs"]
pub mod adopted_set;

use adopted_set::{classify_adopted_set, SequenceFault};

// ---------------------------------------------------------------------------
// Physical state classes
// ---------------------------------------------------------------------------

/// What a failpoint leaves on the device, independent of what any in-memory
/// state believes.
///
/// This is the first of the crash matrix's two independent derivations: the
/// class determines the required recovery outcome through
/// [`PhysicalStateClass::required_outcome`], and the frozen oracle determines
/// it again through `append_publication_expectation`. The matrix asserts both
/// and requires them to agree.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PhysicalStateClass {
    /// Not one byte of the group reached the file.
    NoBytes,
    /// The victim frame's bytes are truncated. A short write is not an error;
    /// it leaves a durable prefix (scope 3.7).
    PartialFrame,
    /// Every frame up to the victim is byte-complete, but no fence has
    /// returned successfully. Whether any of it reached durable storage is
    /// precisely what production recovery must decide.
    WholeFrameUnfenced,
    /// `fdatasync` returned success over the frames written before it.
    WholeFrameFenced,
    /// Fenced *and* the committed root was published, so an acknowledgment is
    /// already permitted.
    WholeFrameFencedAndPublished,
}

impl PhysicalStateClass {
    pub const ALL: &'static [PhysicalStateClass] = &[
        PhysicalStateClass::NoBytes,
        PhysicalStateClass::PartialFrame,
        PhysicalStateClass::WholeFrameUnfenced,
        PhysicalStateClass::WholeFrameFenced,
        PhysicalStateClass::WholeFrameFencedAndPublished,
    ];

    /// The four classes ruling 9.3 names for the degeneracy condition. The
    /// published class is a Wave B refinement of `WholeFrameFenced` and is
    /// listed separately so the matrix can carry the scope 4-A3 table's
    /// "`WholeFrameFenced` + published" rows verbatim.
    pub const RULING_9_3_CLASSES: &'static [PhysicalStateClass] = &[
        PhysicalStateClass::NoBytes,
        PhysicalStateClass::PartialFrame,
        PhysicalStateClass::WholeFrameUnfenced,
        PhysicalStateClass::WholeFrameFenced,
    ];

    /// Name as it appears in `tests/fixtures/phase1-failpoints.json`.
    pub const fn name(self) -> &'static str {
        match self {
            PhysicalStateClass::NoBytes => "NoBytes",
            PhysicalStateClass::PartialFrame => "PartialFrame",
            PhysicalStateClass::WholeFrameUnfenced => "WholeFrameUnfenced",
            PhysicalStateClass::WholeFrameFenced => "WholeFrameFenced",
            PhysicalStateClass::WholeFrameFencedAndPublished => "WholeFrameFencedAndPublished",
        }
    }

    /// Parse without a catch-all arm: a linear search over `ALL` rather than a
    /// `match` with a fallback binding, so adding a class cannot silently
    /// acquire a default.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|c| c.name() == name)
    }

    /// The class-derived half of the crash matrix's expectation.
    ///
    /// Exactly scope 4-A3's table: absent bytes and torn bytes are absent and
    /// retriable, unfenced whole bytes are `EitherWhole`, fenced whole bytes
    /// are committed.
    pub const fn required_outcome(self) -> RecoveryOutcome {
        match self {
            PhysicalStateClass::NoBytes => RecoveryOutcome::AbsentRetriable,
            PhysicalStateClass::PartialFrame => RecoveryOutcome::AbsentRetriable,
            PhysicalStateClass::WholeFrameUnfenced => RecoveryOutcome::EitherWhole,
            PhysicalStateClass::WholeFrameFenced => RecoveryOutcome::Committed,
            PhysicalStateClass::WholeFrameFencedAndPublished => RecoveryOutcome::Committed,
        }
    }

    /// Whether an acknowledgment is already permitted when the failpoint
    /// fires. Only the published class permits one; scope 4-A3's table marks
    /// exactly those two rows "ack allowed".
    pub const fn acknowledgment_allowed(self) -> bool {
        match self {
            PhysicalStateClass::NoBytes => false,
            PhysicalStateClass::PartialFrame => false,
            PhysicalStateClass::WholeFrameUnfenced => false,
            PhysicalStateClass::WholeFrameFenced => false,
            PhysicalStateClass::WholeFrameFencedAndPublished => true,
        }
    }
}

/// The physical state class each failpoint produces.
///
/// One arm per failpoint, deliberately unfactored. Grouping the arms would
/// save lines and lose the property that adding a failpoint breaks the build
/// here rather than inheriting a neighbour's class — the failure mode contract
/// review 2026-07-24-A was about.
pub const fn physical_state_class(point: Failpoint) -> PhysicalStateClass {
    match point {
        Failpoint::BeforeAppend => PhysicalStateClass::NoBytes,
        Failpoint::AfterMarkedResolving => PhysicalStateClass::NoBytes,
        Failpoint::EvidenceHandoffFailure => PhysicalStateClass::NoBytes,

        Failpoint::DuringFrameWriteTorn => PhysicalStateClass::PartialFrame,

        Failpoint::AfterFrameWrite => PhysicalStateClass::WholeFrameUnfenced,
        Failpoint::BeforeFence => PhysicalStateClass::WholeFrameUnfenced,
        Failpoint::FenceFailed => PhysicalStateClass::WholeFrameUnfenced,
        Failpoint::FenceAmbiguous => PhysicalStateClass::WholeFrameUnfenced,
        Failpoint::WriterPanicBeforeFence => PhysicalStateClass::WholeFrameUnfenced,

        Failpoint::AfterSuccessfulFence => PhysicalStateClass::WholeFrameFenced,
        Failpoint::DuringCommittedRootBuild => PhysicalStateClass::WholeFrameFenced,
        Failpoint::AllocationFailureBeforePublication => PhysicalStateClass::WholeFrameFenced,
        Failpoint::BeforeRootCas => PhysicalStateClass::WholeFrameFenced,
        Failpoint::DuringRootCasRetry => PhysicalStateClass::WholeFrameFenced,
        Failpoint::WriterPanicAfterFence => PhysicalStateClass::WholeFrameFenced,

        Failpoint::AfterRootCasBeforeWaiterWake => PhysicalStateClass::WholeFrameFencedAndPublished,
        Failpoint::BeforeResponse => PhysicalStateClass::WholeFrameFencedAndPublished,
    }
}

// ---------------------------------------------------------------------------
// Victim placement
// ---------------------------------------------------------------------------

/// Where in a group of `group_len` frames a failpoint's victim sits.
///
/// Recorded per row in the fixture so a reviewer can see that a post-fence row
/// is group-wide rather than assume it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VictimPlacement {
    /// The fault precedes any frame, so the victim is frame 0 and no frame of
    /// the group is written.
    First,
    /// The fault truncates one frame. The harness tears the last frame of the
    /// group, which degenerates to frame 0 at `group_len == 1`.
    Last,
    /// The fault has no per-frame victim: the whole group's bytes were emitted
    /// before it fired. The victim index is `group_len`, which is what makes
    /// "∃ p ≤ victim_index" permit the whole group.
    GroupWide,
}

impl VictimPlacement {
    pub const ALL: &'static [VictimPlacement] = &[
        VictimPlacement::First,
        VictimPlacement::Last,
        VictimPlacement::GroupWide,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            VictimPlacement::First => "first",
            VictimPlacement::Last => "last",
            VictimPlacement::GroupWide => "group-wide",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|p| p.name() == name)
    }

    /// Resolve to a concrete victim index for a group of `group_len` frames.
    pub fn index(self, group_len: usize) -> usize {
        match self {
            VictimPlacement::First => 0,
            VictimPlacement::Last => group_len.saturating_sub(1),
            VictimPlacement::GroupWide => group_len,
        }
    }
}

/// The placement each physical state class implies.
///
/// This is derived from the class rather than stated per failpoint, because it
/// is a property of what the device holds, not of where in the code the fault
/// was injected.
pub const fn victim_placement(class: PhysicalStateClass) -> VictimPlacement {
    match class {
        PhysicalStateClass::NoBytes => VictimPlacement::First,
        PhysicalStateClass::PartialFrame => VictimPlacement::Last,
        PhysicalStateClass::WholeFrameUnfenced => VictimPlacement::GroupWide,
        PhysicalStateClass::WholeFrameFenced => VictimPlacement::GroupWide,
        PhysicalStateClass::WholeFrameFencedAndPublished => VictimPlacement::GroupWide,
    }
}

// ---------------------------------------------------------------------------
// The group expectation
// ---------------------------------------------------------------------------

/// A window of legal contiguous adopted prefixes.
///
/// Recovery is correct for this group iff it adopted frames `0..p` and nothing
/// else, for some `p` in `min_prefix..=max_prefix`. `max_prefix` never exceeds
/// the victim index, which is the "nothing at or after the victim is ever
/// committed" half of the contract.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AdoptedPrefixExpectation {
    pub point: Failpoint,
    pub class: PhysicalStateClass,
    pub group_len: usize,
    pub victim_index: usize,
    pub min_prefix: usize,
    pub max_prefix: usize,
}

impl AdoptedPrefixExpectation {
    /// The outcome the model permits for one frame of the group.
    ///
    /// Below `min_prefix` the frame is committed under every legal `p`; at or
    /// above `max_prefix` it is absent under every legal `p`; in between the
    /// two the model is genuinely undetermined, which is `EitherWhole` and is
    /// the only honest answer for an unfenced frame.
    pub fn outcome_for_frame(&self, frame_index: usize) -> RecoveryOutcome {
        if frame_index < self.min_prefix {
            RecoveryOutcome::Committed
        } else if frame_index >= self.max_prefix {
            RecoveryOutcome::AbsentRetriable
        } else {
            RecoveryOutcome::EitherWhole
        }
    }

    /// The outcome for the victim frame itself. Equal to the class's required
    /// outcome by construction; the matrix asserts the equality rather than
    /// assuming it.
    pub fn victim_outcome(&self) -> RecoveryOutcome {
        self.class.required_outcome()
    }

    /// Structural invariants the model must satisfy for any input.
    pub fn check_invariants(&self) {
        assert!(self.group_len >= 1, "a group has at least one frame");
        assert!(
            self.victim_index <= self.group_len,
            "victim {} is outside a group of {}",
            self.victim_index,
            self.group_len
        );
        assert!(
            self.min_prefix <= self.max_prefix,
            "empty prefix window for {:?}",
            self.point
        );
        assert!(
            self.max_prefix <= self.victim_index,
            "the model must never permit adopting the victim frame or anything \
             after it: {:?} allows p={} with victim {}",
            self.point,
            self.max_prefix,
            self.victim_index
        );
    }
}

/// Layered group expectation. Scope 4-A3 deliverable 3, ruling 9.3.
///
/// `victim_index` is the index of the first frame the fault prevented from
/// completing; it equals `group_len` for a fault with no per-frame victim.
/// The function is total: every `(victim_index, group_len)` pair with
/// `victim_index <= group_len` has a meaningful answer, so the matrix never
/// has to special-case a row.
pub fn group_failpoint_expectation(
    point: Failpoint,
    victim_index: usize,
    group_len: usize,
) -> AdoptedPrefixExpectation {
    assert!(group_len >= 1, "a group has at least one frame");
    assert!(
        victim_index <= group_len,
        "victim index {victim_index} is outside a group of {group_len}"
    );

    let class = physical_state_class(point);
    let (min_prefix, max_prefix) = match class {
        // No byte of the group reached the file, so p is pinned at 0
        // regardless of where the caller places the victim.
        PhysicalStateClass::NoBytes => (0, 0),

        // Frames before the victim are byte-complete but unfenced, so each is
        // independently either-whole; the victim is truncated and can never be
        // adopted; everything after it was never written. p ranges over the
        // whole window below the victim.
        PhysicalStateClass::PartialFrame => (0, victim_index),

        // Every frame below the victim is byte-complete and unfenced. Same
        // window as the torn case — which is the point: an unfenced whole
        // frame and an unfenced whole frame sitting before a tear are the same
        // physical situation, and only the victim differs.
        PhysicalStateClass::WholeFrameUnfenced => (0, victim_index),

        // The fence returned success over everything written before it, which
        // is frames `0..victim_index`. p is pinned, not a window: a fence that
        // returned success and then lost data is a hardware finding surfaced
        // by the external ACK journal (scope 3.8), never a legal outcome the
        // model may admit.
        PhysicalStateClass::WholeFrameFenced => (victim_index, victim_index),
        PhysicalStateClass::WholeFrameFencedAndPublished => (victim_index, victim_index),
    };

    let expectation = AdoptedPrefixExpectation {
        point,
        class,
        group_len,
        victim_index,
        min_prefix,
        max_prefix,
    };
    expectation.check_invariants();
    expectation
}

/// The expectation for a row driven with the canonical placement of its class.
pub fn canonical_group_expectation(point: Failpoint, group_len: usize) -> AdoptedPrefixExpectation {
    let placement = victim_placement(physical_state_class(point));
    group_failpoint_expectation(point, placement.index(group_len), group_len)
}

// ---------------------------------------------------------------------------
// Prefix verification
// ---------------------------------------------------------------------------

/// How an observed adoption set fails the contiguous-prefix contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefixViolation {
    /// Recovery adopted a frame that sits after a gap. This is the bug the
    /// whole prefix formulation exists to catch: recovery step 6 stops at the
    /// first incomplete frame unconditionally, even when a later region holds
    /// a syntactically complete, checksum-valid frame.
    AdoptedPastAHole { expected_next: u64, observed: u64 },
    /// The adopted set is not sorted/unique, so it is not a prefix at all.
    NotAscendingUnique { observed: Vec<u64> },
    /// Recovery started somewhere other than the group's first sequence.
    WrongStart { expected: u64, observed: u64 },
    /// More frames adopted than the failpoint can possibly have made durable.
    PrefixTooLong { adopted: usize, max_prefix: usize },
    /// Fewer frames adopted than a successful fence guarantees.
    PrefixTooShort { adopted: usize, min_prefix: usize },
}

/// Prove an observed adoption set is a contiguous prefix inside the model's
/// window.
///
/// `observed` is the set of `shard_sequence` values recovery adopted **from
/// this group**, and `first_sequence` is the sequence assigned to frame 0.
/// Returns the adopted prefix length `p` on success.
pub fn verify_adopted_prefix(
    observed: &[u64],
    first_sequence: u64,
    expectation: &AdoptedPrefixExpectation,
) -> Result<usize, PrefixViolation> {
    let report = classify_adopted_set(observed);
    if report.repeated_adoptions() != 0 {
        return Err(PrefixViolation::NotAscendingUnique {
            observed: observed.to_vec(),
        });
    }

    if let Some(first) = observed.first() {
        if *first != first_sequence {
            return Err(PrefixViolation::WrongStart {
                expected: first_sequence,
                observed: *first,
            });
        }
    }

    if let Some(SequenceFault::ForwardGap {
        expected_next,
        observed,
    }) = report.first_fault
    {
        return Err(PrefixViolation::AdoptedPastAHole {
            expected_next,
            observed,
        });
    }

    let adopted = observed.len();
    if adopted > expectation.max_prefix {
        return Err(PrefixViolation::PrefixTooLong {
            adopted,
            max_prefix: expectation.max_prefix,
        });
    }
    if adopted < expectation.min_prefix {
        return Err(PrefixViolation::PrefixTooShort {
            adopted,
            min_prefix: expectation.min_prefix,
        });
    }
    Ok(adopted)
}

// ---------------------------------------------------------------------------
// Outcome admission
// ---------------------------------------------------------------------------

/// Whether a concrete observed tail fact is admitted by an expected outcome.
///
/// `EitherWhole` is the only outcome that admits two facts, and it admits them
/// only through the frozen `resolve_ambiguous_tail`, so an implementation
/// cannot resolve an ambiguous fence deterministically before recovery re-reads
/// the device (scope 5 charter item 4).
pub fn outcome_admits(expected: RecoveryOutcome, fact: RecoveredTailFact) -> bool {
    let resolved = levcs_protocol::oracle::resolve_ambiguous_tail(fact);
    match expected {
        RecoveryOutcome::AbsentRetriable => resolved == RecoveryOutcome::AbsentRetriable,
        RecoveryOutcome::Committed => resolved == RecoveryOutcome::Committed,
        RecoveryOutcome::EitherWhole => {
            resolved == RecoveryOutcome::AbsentRetriable || resolved == RecoveryOutcome::Committed
        }
    }
}

/// The frozen oracle's half of the matrix's two derivations.
pub fn oracle_recovery_outcome(point: Failpoint) -> RecoveryOutcome {
    append_publication_expectation(point.into()).recovery_outcome
}
