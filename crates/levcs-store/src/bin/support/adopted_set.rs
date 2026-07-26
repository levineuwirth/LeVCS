//! The one structural checker for a set of adopted `shard_sequence` values.
//!
//! **Owned by A3 StoreHarness.** Not a Cargo target: `src/bin/support/` holds
//! no `main.rs`, so Cargo's binary auto-discovery ignores it. It is included by
//! `#[path]` into `store-crash-driver`, `store-bench`, and
//! `tests/support/group_model.rs`, which is the point — there is exactly one
//! implementation of this property in the harness, not one per caller.
//!
//! # The property
//!
//! What production recovery adopted must be a **strictly increasing contiguous
//! run**: no forward gap, no duplicate, no regression. A checker that tests
//! only `next > previous + 1` accepts `0,1,2,3,0,1,2,3` — the reviewer's
//! witness — and reports a contiguous prefix for a store that adopted the same
//! four frames twice.
//!
//! The three faults are counted apart because they mean different things:
//!
//! * a **forward gap** means recovery adopted a frame sitting after a hole,
//!   which recovery step 6 (scope 3.8) forbids unconditionally. What it
//!   publishes is a group neither wholly present nor wholly absent, which is
//!   why the crash driver reports it as `torn_transactions`;
//! * a **duplicate** or a **regression** means the same frames were adopted
//!   twice — a segment counted alongside the journal that supersedes it, or a
//!   manifest range replayed — which is not a torn group at all and must not be
//!   folded into the same counter.

#![allow(dead_code)]

/// The first place an adopted set stopped being a strictly increasing
/// contiguous run, kept so a failure names bytes rather than a count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SequenceFault {
    /// The same sequence appears twice in a row.
    Duplicate { value: u64 },
    /// A sequence lower than the one before it.
    Regression { previous: u64, observed: u64 },
    /// A sequence higher than the one before it, but not by one.
    ForwardGap { expected_next: u64, observed: u64 },
}

/// Every way an adopted set departs from the property, counted separately.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdoptedSetReport {
    /// Adjacent pairs that repeat a value.
    pub duplicates: u64,
    /// Adjacent pairs that go backwards.
    pub regressions: u64,
    /// Adjacent pairs separated by a hole.
    pub forward_gaps: u64,
    /// Total sequences absent inside those holes. A single gap can hide many
    /// frames, and the number of lost frames is the interesting figure.
    pub missing_sequences: u64,
    /// The first fault in adoption order.
    pub first_fault: Option<SequenceFault>,
}

impl AdoptedSetReport {
    /// True only for a strictly increasing contiguous run (or an empty one).
    pub fn is_strictly_contiguous(&self) -> bool {
        self.duplicates == 0 && self.regressions == 0 && self.forward_gaps == 0
    }

    /// Adopting the same frame twice is not a torn group; it is counted here so
    /// a caller can refuse on it without pretending it was one.
    pub fn repeated_adoptions(&self) -> u64 {
        self.duplicates + self.regressions
    }
}

/// Classify an adopted set in adoption order.
///
/// The input is deliberately the sequence recovery reported, in the order it
/// reported it — not a sorted set. Sorting first would erase exactly the
/// regression this function exists to find.
pub fn classify_adopted_set(adopted: &[u64]) -> AdoptedSetReport {
    let mut report = AdoptedSetReport::default();
    for pair in adopted.windows(2) {
        let (previous, observed) = (pair[0], pair[1]);
        let fault = if observed == previous {
            report.duplicates += 1;
            SequenceFault::Duplicate { value: observed }
        } else if observed < previous {
            report.regressions += 1;
            SequenceFault::Regression { previous, observed }
        } else if observed > previous + 1 {
            report.forward_gaps += 1;
            report.missing_sequences += observed - previous - 1;
            SequenceFault::ForwardGap {
                expected_next: previous + 1,
                observed,
            }
        } else {
            continue;
        };
        if report.first_fault.is_none() {
            report.first_fault = Some(fault);
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_contiguous_run_has_no_faults() {
        let report = classify_adopted_set(&[7, 8, 9, 10]);
        assert!(report.is_strictly_contiguous());
        assert_eq!(report, AdoptedSetReport::default());
        assert!(classify_adopted_set(&[]).is_strictly_contiguous());
        assert!(classify_adopted_set(&[42]).is_strictly_contiguous());
    }

    #[test]
    fn the_reviewers_witness_is_rejected() {
        // `0,1,2,3,0,1,2,3` passed the old `pair[1] > pair[0] + 1` check with
        // torn_transactions=0 and prefix_contiguous=true.
        let report = classify_adopted_set(&[0, 1, 2, 3, 0, 1, 2, 3]);
        assert!(!report.is_strictly_contiguous());
        assert_eq!(report.regressions, 1);
        assert_eq!(report.duplicates, 0);
        assert_eq!(report.forward_gaps, 0);
        assert_eq!(report.missing_sequences, 0);
        assert_eq!(
            report.first_fault,
            Some(SequenceFault::Regression {
                previous: 3,
                observed: 0
            })
        );
    }

    #[test]
    fn duplicates_regressions_and_gaps_are_counted_apart() {
        let report = classify_adopted_set(&[0, 0, 1, 5, 4]);
        assert_eq!(report.duplicates, 1);
        assert_eq!(report.forward_gaps, 1);
        assert_eq!(report.missing_sequences, 3);
        assert_eq!(report.regressions, 1);
        assert_eq!(report.repeated_adoptions(), 2);
        assert_eq!(
            report.first_fault,
            Some(SequenceFault::Duplicate { value: 0 })
        );
    }

    #[test]
    fn a_gap_reports_every_missing_sequence_not_just_the_hole() {
        let report = classify_adopted_set(&[10, 20]);
        assert_eq!(report.forward_gaps, 1);
        assert_eq!(report.missing_sequences, 9);
        assert_eq!(
            report.first_fault,
            Some(SequenceFault::ForwardGap {
                expected_next: 11,
                observed: 20
            })
        );
    }
}
