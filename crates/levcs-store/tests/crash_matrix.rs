//! The Phase 1 crash matrix (scope 4-A3 deliverable 2).
//!
//! One row per `levcs_store::failpoints::Failpoint`, carried in
//! `tests/fixtures/phase1-failpoints.json`. Every row records the physical
//! state class the failpoint produces and the recovery outcome required of it,
//! and every assertion here compares the observed outcome against **two
//! independent derivations** that must agree:
//!
//! 1. the physical state class, through `PhysicalStateClass::required_outcome`;
//! 2. the frozen Phase 0 oracle, through
//!    `levcs_protocol::oracle::append_publication_expectation`.
//!
//! # There is no catch-all match arm in this file
//!
//! Not one wildcard arm, and not one fallback binding. Contract review
//! 2026-07-24-A shipped an unsound recovery classification precisely because a
//! catch-all left most outcomes unasserted, and the scope 5 charter directs the
//! adversarial reviewer to grep for one and fail the gate if it exists. That
//! grep must come back empty here, so this paragraph deliberately does not
//! spell the token out either — a comment that names it is a false positive
//! that trains a reviewer to skip the real hit. Every name-to-value mapping in
//! the harness is a search over an enumerated set for the same reason: a
//! `match` with a fallback would give an unknown name a silent default.
//!
//! # What Wave A asserts, and what it does not
//!
//! Wave A asserts the physical-state-class and `recovery_outcome` halves only.
//! `shard_poisoned`, `immediate_status`, `acknowledgment_allowed`, and
//! `later_append_allowed_before_recovery` need a status root, a sequencer, and
//! an acknowledgment path — none of which exist below `engine.rs`. They are
//! equally unassertable for all nine Wave A rows, so they do not distinguish
//! any row from any other, and the fixture records that rather than leaving it
//! to be inferred. Wave B re-asserts every row's complete
//! `FailpointExpectation` through `StoreEngine::submit`.

#![cfg(all(feature = "failpoints", feature = "store-internals"))]

mod support;

use levcs_protocol::oracle::{RecoveredTailFact, RecoveryOutcome};
use levcs_store::failpoints::{Failpoint, Wave};
use levcs_store::options::StoreOptions;
use levcs_store::types::StoreError;
use levcs_store::StoreEngine;

use support::group_model::{
    canonical_group_expectation, group_failpoint_expectation, oracle_recovery_outcome,
    outcome_admits, physical_state_class, verify_adopted_prefix, victim_placement,
    AdoptedPrefixExpectation, PhysicalStateClass, PrefixViolation, VictimPlacement,
};
use support::harness;

/// Group size for the driven rows. Larger than one so the contiguous-prefix
/// contract is actually exercised: at `group_len == 1` a per-frame model and a
/// prefix model are indistinguishable, which is the whole reason ruling 9.3
/// insisted on the prefix form.
const DRIVEN_GROUP_LEN: usize = 4;

/// A committed group appended before the victim group, so every driven row
/// also proves that an already-fenced prefix survives the crash.
const PRIOR_GROUP_LEN: usize = 2;

// ===========================================================================
// Fixture agreement — runs today, no dependency on A1 or B1
// ===========================================================================

#[test]
fn the_fixture_carries_exactly_one_row_per_failpoint_in_registry_order() {
    let fixture = harness::load_fixture();
    let fixture_names: Vec<&str> = fixture.rows.iter().map(|r| r.failpoint.as_str()).collect();
    let registry_names: Vec<&str> = Failpoint::ALL.iter().map(|p| p.name()).collect();
    assert_eq!(
        fixture_names, registry_names,
        "the crash matrix must be one row per failpoint, in the registry's own \
         order, so a new failpoint is a fixture diff rather than a silent hole"
    );
}

#[test]
fn every_row_carries_its_wave_and_the_partition_matches_the_pinned_one() {
    let fixture = harness::load_fixture();
    for row in &fixture.rows {
        let resolved = harness::resolve(row);
        assert_eq!(
            row.wave,
            harness::wave_name(resolved.point.wave()),
            "row {} disagrees with the wave partition pinned by name in \
             failpoints.rs::Failpoint::wave",
            row.failpoint
        );
    }
}

#[test]
fn the_two_independent_derivations_agree_for_every_row() {
    let fixture = harness::load_fixture();
    for row in &fixture.rows {
        let resolved = harness::resolve(row);

        // Derivation 1: the physical state class.
        let from_class = resolved.class.required_outcome();
        // Derivation 2: the frozen Phase 0 oracle.
        let from_oracle = oracle_recovery_outcome(resolved.point);

        assert_eq!(
            from_class,
            from_oracle,
            "row {}: the physical state class {} implies {}, but the frozen \
             oracle says {}. Two derivations that disagree means one of them is \
             wrong, and neither is allowed to be adjusted to match the other \
             without a recorded contract review.",
            row.failpoint,
            resolved.class.name(),
            harness::recovery_outcome_name(from_class),
            harness::recovery_outcome_name(from_oracle)
        );
        assert_eq!(
            resolved.required_outcome, from_class,
            "row {}: the recorded required_outcome must equal the class-derived one",
            row.failpoint
        );
    }
}

#[test]
fn the_class_table_and_the_fixture_agree_on_every_row() {
    let fixture = harness::load_fixture();
    for row in &fixture.rows {
        let resolved = harness::resolve(row);
        assert_eq!(
            resolved.class,
            physical_state_class(resolved.point),
            "row {} records a physical state class the model does not derive",
            row.failpoint
        );
        assert_eq!(
            resolved.placement,
            victim_placement(resolved.class),
            "row {}: victim placement is a property of the physical state class \
             and may not be chosen per row",
            row.failpoint
        );
    }
}

#[test]
fn wave_a_rows_carry_a_drive_plan_and_wave_b_rows_carry_a_submit_plan() {
    let fixture = harness::load_fixture();
    let mut contention_rows = Vec::new();
    for row in &fixture.rows {
        let resolved = harness::resolve(row);
        match resolved.point.wave() {
            Wave::A => {
                let plan = row.drive.as_ref().unwrap_or_else(|| {
                    panic!("Wave A row {} must say how it is driven", row.failpoint)
                });
                assert!(!plan.action.is_empty(), "row {} action", row.failpoint);
                assert!(!plan.fault.is_empty(), "row {} fault", row.failpoint);
                assert!(
                    row.submit.is_none(),
                    "row {} is Wave A: it is driven through drive.rs, and claiming a \
                     submit plan as well would mean two paths assert the same row \
                     without either being the one under test",
                    row.failpoint
                );
            }
            Wave::B => {
                assert!(
                    row.drive.is_none(),
                    "row {} needs an engine and must not claim a drive plan",
                    row.failpoint
                );
                let plan = row.submit.as_ref().unwrap_or_else(|| {
                    panic!(
                        "Wave B row {} must say which actions drive it through \
                         StoreEngine::submit",
                        row.failpoint
                    )
                });
                assert!(
                    !plan.actions.is_empty(),
                    "row {}: a Wave B row with no action is a pending row without the \
                     word",
                    row.failpoint
                );
                for action in &plan.actions {
                    assert!(
                        action == "fail" || action == "panic",
                        "row {}: the submit path can express Fail and Panic. HardExit \
                         needs a parent process and Continue is not a fault; naming \
                         either here would describe a run the harness cannot make: {action:?}",
                        row.failpoint
                    );
                }
                if plan.requires_root_cas_contention {
                    contention_rows.push(row.failpoint.clone());
                }
            }
        }
        assert!(
            row.rationale.len() > 20,
            "row {} must explain why its class is what it is",
            row.failpoint
        );
    }

    assert_eq!(
        contention_rows,
        vec!["DuringRootCasRetry".to_string()],
        "exactly one location is reachable only after a lost committed-root CAS. A \
         second row acquiring the flag would mean a failpoint had been moved inside \
         the retry loop without the matrix noticing; none acquiring it would mean \
         DuringRootCasRetry had been driven by a path that never retried, which is \
         the state B1 disclosed and this row exists to leave."
    );
}

/// The three publication-side rows must be exercised with `Panic`, by name.
///
/// Ruling `WriterPanicAfterFence` into Wave A vacated the panic coverage of the
/// publication half. A count here would not catch a row losing its `panic`
/// action, and a check over "some row panics" would be satisfied by the wrong
/// one.
#[test]
fn the_three_publication_side_rows_are_driven_with_the_panic_action() {
    let fixture = harness::load_fixture();
    let panicking: Vec<&str> = fixture
        .rows
        .iter()
        .filter(|row| {
            row.submit
                .as_ref()
                .is_some_and(|plan| plan.actions.iter().any(|action| action == "panic"))
        })
        .map(|row| row.failpoint.as_str())
        .collect();
    assert_eq!(
        panicking,
        vec![
            "DuringCommittedRootBuild",
            "BeforeRootCas",
            "DuringRootCasRetry"
        ],
        "the fixture's own wave_b_exit_conditions names these three; the rows and the \
         condition must not be able to drift apart"
    );
}

#[test]
fn the_fixture_records_which_halves_wave_a_asserts_and_which_it_cannot() {
    let fixture = harness::load_fixture();
    assert_eq!(
        fixture.wave_a_asserted,
        vec![
            "physical_state_class".to_string(),
            "recovery_outcome".to_string()
        ],
        "Wave A asserts exactly two halves"
    );
    assert_eq!(
        fixture.wave_a_unasserted,
        vec![
            "shard_poisoned".to_string(),
            "immediate_status".to_string(),
            "acknowledgment_allowed".to_string(),
            "later_append_allowed_before_recovery".to_string(),
        ],
        "the remaining four FailpointExpectation fields must be listed by name; \
         a count would not catch one going missing"
    );
    assert!(
        fixture
            .wave_b_exit_conditions
            .iter()
            .any(|c| c.contains("DuringCommittedRootBuild")
                && c.contains("BeforeRootCas")
                && c.contains("DuringRootCasRetry")),
        "the fixture must name the three publication-side rows that Wave B has \
         to exercise with the Panic action, so the coverage vacated by ruling \
         WriterPanicAfterFence into Wave A is not lost"
    );
    assert_eq!(
        fixture.wave_b_asserted,
        vec![
            "physical_state_class".to_string(),
            "recovery_outcome".to_string(),
            "shard_poisoned".to_string(),
            "immediate_status".to_string(),
            "acknowledgment_allowed".to_string(),
            "later_append_allowed_before_recovery".to_string(),
        ],
        "Wave B asserts the two halves Wave A could reach plus the four it could \
         not; listing them by name is what makes one going missing a diff"
    );
    for field in &fixture.wave_a_unasserted {
        assert!(
            fixture.wave_b_asserted.contains(field),
            "{field} was recorded as unassertable in Wave A, so Wave B owes it. A \
             field that neither wave asserts is a hole with two labels on it."
        );
    }
}

/// Phase 1 exit requires zero pending rows.
///
/// **Not inert any more.** It was, while `engine.rs` was a skeleton: the check
/// asserted the pending set was *non*-empty, so the obligation could not be
/// dropped by deleting rows instead of driving them. B1's engine landed and
/// scope 6.6 deliverable 2 drove all eight, so the assertion is now
/// unconditional in the other direction.
///
/// `check-phase1.sh`'s own version of this check is still inert — it fires only
/// once `engine.rs` stops containing `NotImplemented`, and engine.rs still
/// refuses startup states 1, 3, and 4 by name. So the gate would *not* catch a
/// row that regressed to pending. This test would, and that is why it does not
/// defer to the gate.
#[test]
fn the_pending_set_is_empty_at_phase_1_exit() {
    let fixture = harness::load_fixture();
    let pending: Vec<&str> = fixture
        .rows
        .iter()
        .filter(|row| row.wave == harness::PENDING_WAVE_B)
        .map(|row| row.failpoint.as_str())
        .collect();
    assert!(
        pending.is_empty(),
        "no crash-matrix row may be pending: {}",
        pending.join(", ")
    );

    let driven: Vec<&str> = fixture
        .rows
        .iter()
        .filter(|row| row.submit.is_some())
        .map(|row| row.failpoint.as_str())
        .collect();
    let expected: Vec<&str> = Failpoint::ALL
        .iter()
        .filter(|point| point.wave() == Wave::B)
        .map(|point| point.name())
        .collect();
    assert_eq!(
        driven, expected,
        "the eight Wave B rows are named by the registry, not by this file. \
         Restating them as a list here is how a failpoint added to failpoints.rs \
         becomes a fixture diff rather than a silent hole."
    );
}

/// `StoreEngine::open` still refuses startup state 1, which is why the Wave B
/// rows seed their root with `segment::initialize_root`.
///
/// Asserted rather than assumed, because the moment it stops being true the
/// seeding disclosure in the fixture becomes a false statement about the
/// harness, and a stale disclosure is worse than none: it tells a reader that a
/// weakening still exists when the honest answer is that it does not.
#[test]
fn the_production_open_still_refuses_to_create_a_root_and_the_fixture_says_so() {
    let directory = tempfile::tempdir().expect("tempdir");
    let options = StoreOptions::new(directory.path().join("root"));
    match StoreEngine::open(options) {
        Err(StoreError::NotImplemented(reason)) => {
            assert!(
                reason.contains("startup states 1"),
                "the refusal must still be the unbuilt startup states: {reason}"
            );
        }
        Ok(_) => panic!(
            "StoreEngine::open now creates an absent root, so the Wave B rows must be \
             re-pointed at it and the fixture's root_seeded_by disclosure retired"
        ),
        Err(other) => {
            panic!("StoreEngine::open refused an absent root for an unexpected reason: {other:?}")
        }
    }
}

// ===========================================================================
// The group-aware failpoint model (deliverable 3)
// ===========================================================================

/// Ruling 9.3's condition: the degeneracy proof must hold for **every**
/// physical state class, not only the torn one.
///
/// Iterating every failpoint covers every class by construction, and the
/// companion test below proves the coverage rather than assuming it.
#[test]
fn the_group_model_degenerates_to_the_frozen_oracle_at_group_len_one() {
    for point in Failpoint::ALL {
        let expectation = canonical_group_expectation(*point, 1);
        let modelled = expectation.outcome_for_frame(0);
        let oracle = oracle_recovery_outcome(*point);
        assert_eq!(
            modelled,
            oracle,
            "{}: at group_len == 1 the layered model must reduce to the frozen \
             oracle. class {}, window [{}, {}], victim {}",
            point.name(),
            expectation.class.name(),
            expectation.min_prefix,
            expectation.max_prefix,
            expectation.victim_index
        );
        assert_eq!(
            expectation.victim_outcome(),
            oracle,
            "{}: the victim's outcome must also reduce to the oracle",
            point.name()
        );
    }
}

#[test]
fn every_physical_state_class_is_witnessed_by_some_failpoint() {
    for class in PhysicalStateClass::ALL {
        let witnesses: Vec<&str> = Failpoint::ALL
            .iter()
            .filter(|p| physical_state_class(**p) == *class)
            .map(|p| p.name())
            .collect();
        assert!(
            !witnesses.is_empty(),
            "physical state class {} has no failpoint, so the degeneracy proof \
             above would not cover it",
            class.name()
        );
    }
    for class in PhysicalStateClass::RULING_9_3_CLASSES {
        assert!(
            PhysicalStateClass::ALL.contains(class),
            "ruling 9.3 names a class the model does not have: {}",
            class.name()
        );
    }
}

/// The operative half of the contract: nothing at or after the victim is ever
/// committed, for every victim position and every group size.
#[test]
fn the_model_never_permits_committing_at_or_after_the_victim() {
    for point in Failpoint::ALL {
        for group_len in 1..=12usize {
            for victim_index in 0..=group_len {
                let expectation = group_failpoint_expectation(*point, victim_index, group_len);
                expectation.check_invariants();
                for frame in victim_index..group_len {
                    assert_eq!(
                        expectation.outcome_for_frame(frame),
                        RecoveryOutcome::AbsentRetriable,
                        "{}: frame {frame} is at or after victim {victim_index} in a \
                         group of {group_len} and must never be committed",
                        point.name()
                    );
                }
            }
        }
    }
}

/// A per-frame formulation would accept this image. The prefix formulation
/// must not: recovery step 6 stops at the first incomplete frame
/// unconditionally, even when a later region holds a syntactically complete,
/// checksum-valid frame.
#[test]
fn adopting_a_valid_frame_after_a_hole_is_a_violation() {
    let expectation = group_failpoint_expectation(Failpoint::DuringFrameWriteTorn, 3, 4);
    // Frames 100, 101 adopted, 102 discarded (torn), 103 adopted anyway.
    let observed = [100u64, 101, 103];
    let violation = verify_adopted_prefix(&observed, 100, &expectation)
        .expect_err("adopting past a hole must be rejected");
    assert_eq!(
        violation,
        PrefixViolation::AdoptedPastAHole {
            expected_next: 102,
            observed: 103
        },
        "the violation must name the hole, not merely report that something is wrong"
    );
}

#[test]
fn verify_adopted_prefix_accepts_exactly_the_window_and_nothing_outside_it() {
    let group_len = 6usize;
    for point in Failpoint::ALL {
        let placement = victim_placement(physical_state_class(*point));
        let victim = placement.index(group_len);
        let expectation = group_failpoint_expectation(*point, victim, group_len);
        for prefix in 0..=group_len {
            let observed: Vec<u64> = (0..prefix as u64).map(|i| 500 + i).collect();
            let result = verify_adopted_prefix(&observed, 500, &expectation);
            let legal = prefix >= expectation.min_prefix && prefix <= expectation.max_prefix;
            assert_eq!(
                result.is_ok(),
                legal,
                "{}: prefix {prefix} against window [{}, {}] classified wrongly: {result:?}",
                point.name(),
                expectation.min_prefix,
                expectation.max_prefix
            );
        }
    }
}

#[test]
fn a_non_ascending_or_wrongly_started_adoption_set_is_not_a_prefix() {
    let expectation = group_failpoint_expectation(Failpoint::AfterFrameWrite, 4, 4);
    assert_eq!(
        verify_adopted_prefix(&[7, 7], 7, &expectation).expect_err("duplicates"),
        PrefixViolation::NotAscendingUnique {
            observed: vec![7, 7]
        }
    );
    assert_eq!(
        verify_adopted_prefix(&[9, 10], 7, &expectation).expect_err("wrong start"),
        PrefixViolation::WrongStart {
            expected: 7,
            observed: 9
        }
    );
}

#[test]
fn the_fenced_classes_pin_the_prefix_rather_than_leaving_a_window() {
    for point in Failpoint::ALL {
        let class = physical_state_class(*point);
        let expectation = canonical_group_expectation(*point, 8);
        let pinned = expectation.min_prefix == expectation.max_prefix;
        let expected_pinned = match class {
            PhysicalStateClass::NoBytes => true,
            PhysicalStateClass::PartialFrame => false,
            PhysicalStateClass::WholeFrameUnfenced => false,
            PhysicalStateClass::WholeFrameFenced => true,
            PhysicalStateClass::WholeFrameFencedAndPublished => true,
        };
        assert_eq!(
            pinned,
            expected_pinned,
            "{}: a successful fence admits exactly one prefix, and an unfenced \
             group admits a window; conflating the two is how a lost fenced \
             write becomes indistinguishable from an ordinary crash",
            point.name()
        );
    }
}

// ===========================================================================
// Driving the nine Wave A rows
// ===========================================================================

/// Which frame of the group stands in for the row when comparing against the
/// class-derived and oracle-derived outcomes.
fn representative_frame(placement: VictimPlacement, group_len: usize) -> usize {
    match placement {
        VictimPlacement::First => 0,
        VictimPlacement::Last => group_len - 1,
        VictimPlacement::GroupWide => group_len - 1,
    }
}

/// The exit code the driver must produce for a given action, so that a row
/// which quietly ran to completion cannot be mistaken for a row whose fault
/// fired.
fn expected_exit_code(action: &str) -> i32 {
    if action == "hard-exit" {
        3
    } else if action == "panic" {
        101
    } else if action == "fail" {
        65
    } else {
        panic!("the fixture names an action the matrix cannot verify: {action:?}")
    }
}

#[test]
fn wave_a_rows_drive_to_their_expected_recovery_outcome() {
    let fixture = harness::load_fixture();
    let mut driven = Vec::new();

    for row in &fixture.rows {
        let resolved = harness::resolve(row);
        if resolved.point.wave() != Wave::A {
            continue;
        }
        let plan = row
            .drive
            .as_ref()
            .expect("a Wave A row carries a drive plan");

        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("root");
        let ack_journal = directory.path().join("ack.journal");
        let seed = 0x5643_5331_0000_0000u64 ^ (driven.len() as u64);

        // A committed group first, so every row also proves that an
        // already-fenced prefix survives the crash rather than only that the
        // victim group does not.
        let prior = harness::run_append(&harness::AppendRun {
            root: &root,
            shard: 0,
            shard_count: 1,
            seed,
            group_len: PRIOR_GROUP_LEN,
            victim: 0,
            point: Failpoint::BeforeAppend,
            action: "continue",
            fault: "none",
            ack_journal: &ack_journal,
            create: true,
        });
        assert_eq!(
            prior.exit_code,
            Some(0),
            "{}: the prior group must commit cleanly. stderr:\n{}",
            row.failpoint,
            prior.stderr
        );
        let prior_sequences = prior.sequences("appended_sequences");
        assert_eq!(prior_sequences.len(), PRIOR_GROUP_LEN);
        let victim_first_sequence = prior_sequences[PRIOR_GROUP_LEN - 1] + 1;

        // Now the victim group.
        let victim_index = resolved.placement.index(DRIVEN_GROUP_LEN);
        let child = harness::run_append(&harness::AppendRun {
            root: &root,
            shard: 0,
            shard_count: 1,
            seed: seed ^ 0xFFFF,
            group_len: DRIVEN_GROUP_LEN,
            victim: victim_index,
            point: resolved.point,
            action: &plan.action,
            fault: &plan.fault,
            ack_journal: &ack_journal,
            create: false,
        });
        assert_eq!(
            child.exit_code,
            Some(expected_exit_code(&plan.action)),
            "{}: the injected fault did not fire the way the fixture says it does. \
             stderr:\n{}",
            row.failpoint,
            child.stderr
        );

        // The parent classifies, in a fresh process with a fresh descriptor.
        let reconcile = harness::run_reconcile(&root, 0, &ack_journal);
        assert_eq!(
            reconcile.get("recovery_ok"),
            Some("true"),
            "{}: production recovery refused to open the crash image. An ordinary \
             crash must never produce an unopenable store (scope 3.8 step 5). \
             stderr:\n{}",
            row.failpoint,
            reconcile.stderr
        );
        assert_eq!(
            reconcile.get("acknowledged_loss"),
            Some("0"),
            "{}: an acknowledged operation is missing from the recovered store. \
             Per scope 3.8 this is a hardware finding that invalidates the run, \
             not a store bug to tolerate.",
            row.failpoint
        );
        assert_eq!(
            reconcile.get("torn_transactions"),
            Some("0"),
            "{}: recovery published a hole",
            row.failpoint
        );
        // The whole property, not just the absence of forward gaps: a
        // duplicate or a regression means the same frames were adopted twice,
        // which `torn_transactions` deliberately does not count.
        assert_eq!(
            reconcile.get("adopted_duplicates"),
            Some("0"),
            "{}: recovery adopted a sequence twice ({:?})",
            row.failpoint,
            reconcile.get("first_sequence_fault")
        );
        assert_eq!(
            reconcile.get("adopted_regressions"),
            Some("0"),
            "{}: recovery adopted a sequence out of order ({:?})",
            row.failpoint,
            reconcile.get("first_sequence_fault")
        );
        assert_eq!(
            reconcile.get("prefix_contiguous"),
            Some("true"),
            "{}: the adopted set is not a strictly increasing contiguous run ({:?})",
            row.failpoint,
            reconcile.get("first_sequence_fault")
        );

        let adopted = reconcile.sequences("adopted_sequences");
        for sequence in &prior_sequences {
            assert!(
                adopted.contains(sequence),
                "{}: fenced-and-acknowledged sequence {sequence} from the prior \
                 group did not survive",
                row.failpoint
            );
        }
        let adopted_in_group: Vec<u64> = adopted
            .iter()
            .copied()
            .filter(|s| *s >= victim_first_sequence)
            .collect();

        let expectation =
            group_failpoint_expectation(resolved.point, victim_index, DRIVEN_GROUP_LEN);
        let prefix = verify_adopted_prefix(&adopted_in_group, victim_first_sequence, &expectation)
            .unwrap_or_else(|violation| {
                panic!(
                    "{}: recovery's adoption of the victim group is not a legal \
                     contiguous prefix: {violation:?}",
                    row.failpoint
                )
            });

        let representative = representative_frame(resolved.placement, DRIVEN_GROUP_LEN);
        let observed_fact = if representative < prefix {
            RecoveredTailFact::CompleteChecksumValid
        } else {
            RecoveredTailFact::AbsentOrTorn
        };

        assert_expectations_agree(&row.failpoint, resolved.point, &expectation, representative);
        assert!(
            outcome_admits(resolved.class.required_outcome(), observed_fact),
            "{}: the class-derived expectation {} does not admit the observed \
             tail fact {observed_fact:?}",
            row.failpoint,
            harness::recovery_outcome_name(resolved.class.required_outcome())
        );
        assert!(
            outcome_admits(oracle_recovery_outcome(resolved.point), observed_fact),
            "{}: the frozen oracle's expectation {} does not admit the observed \
             tail fact {observed_fact:?}",
            row.failpoint,
            harness::recovery_outcome_name(oracle_recovery_outcome(resolved.point))
        );

        driven.push(row.failpoint.clone());
    }

    let expected: Vec<String> = Failpoint::ALL
        .iter()
        .filter(|p| p.wave() == Wave::A)
        .map(|p| p.name().to_string())
        .collect();
    assert_eq!(
        driven, expected,
        "every Wave A row must actually have been driven, by name"
    );
}

/// The third assertion, factored out only so the driving loop stays readable.
/// It is still three separate equalities, not one aggregate.
fn assert_expectations_agree(
    name: &str,
    point: Failpoint,
    expectation: &AdoptedPrefixExpectation,
    representative: usize,
) {
    let from_model = expectation.outcome_for_frame(representative);
    let from_class = physical_state_class(point).required_outcome();
    let from_oracle = oracle_recovery_outcome(point);
    assert_eq!(
        from_model, from_class,
        "{name}: the group model and the physical state class disagree"
    );
    assert_eq!(
        from_class, from_oracle,
        "{name}: the physical state class and the frozen oracle disagree"
    );
}

// ===========================================================================
// Fault injection (deliverable 4)
// ===========================================================================
//
// The matrix rows above reach two of the userspace faults: `ShortWrite` drives
// `DuringFrameWriteTorn` and `FenceEio` drives `FenceFailed`. The remaining
// ones are not decoration and are exercised here individually, because plan
// §10 names them ("short writes, fsync errors, ENOSPC, corrupt index, corrupt
// segment, torn tail") and because a fault that is exposed but never fired is
// indistinguishable from one that does not work — which is exactly the state
// `sys.rs` was in until fault taking became positional.
//
// dm-flakey, block-device cache and barrier manipulation, and power cuts are
// the reviewed root-only scripts of §10 and are Phase 4/5. This is the
// userspace layer, and it is what lets the matrix run unprivileged in CI.

/// A committed, acknowledged group, so each fault test starts from a store
/// that has something real to lose.
fn seed_committed_group(root: &std::path::Path, ack: &std::path::Path, seed: u64) -> Vec<u64> {
    let run = harness::run_append(&harness::AppendRun {
        root,
        shard: 0,
        shard_count: 1,
        seed,
        group_len: PRIOR_GROUP_LEN,
        victim: 0,
        point: Failpoint::BeforeAppend,
        action: "continue",
        fault: "none",
        ack_journal: ack,
        create: true,
    });
    assert_eq!(
        run.exit_code,
        Some(0),
        "the seed group must commit cleanly. stderr:\n{}",
        run.stderr
    );
    run.sequences("appended_sequences")
}

fn generate_damage(root: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    std::process::Command::new(harness::DRIVER)
        .arg("damage")
        .arg("--root")
        .arg(root)
        .args(arguments)
        .output()
        .expect("spawning physical crash-image generator")
}

/// Wave A review finding 1, physical image 1: a manifest-referenced segment
/// whose footer remains valid while one of its frames no longer does.
///
/// This is generated from a segment the drive actually sealed and installed,
/// and the assertion is against the same `reconcile` command the matrix and
/// recovery script use. There is no harness-only validator in between. The
/// pre-fix Wave A reopen accepted this exact class by trusting only footer
/// offsets, so reverting that validation makes this test fail.
#[test]
fn production_recovery_rejects_a_corrupt_frame_in_a_sealed_segment() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");
    let ack = directory.path().join("ack.journal");

    let seed = std::process::Command::new(harness::DRIVER)
        .args(["append", "--root"])
        .arg(&root)
        .args([
            "--shard",
            "0",
            "--shard-count",
            "1",
            "--create",
            "--seed",
            "49374",
            "--group-len",
            "2",
            "--point",
            "BeforeAppend",
            "--action",
            "continue",
            "--fault",
            "none",
        ])
        .arg("--ack-journal")
        .arg(&ack)
        .arg("--seal")
        .output()
        .expect("seeding sealed segment");
    assert!(
        seed.status.success(),
        "the source must be a production-sealed segment.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&seed.stdout),
        String::from_utf8_lossy(&seed.stderr)
    );

    let damage = generate_damage(
        &root,
        &["--kind", "sealed-frame-corruption", "--shard", "0"],
    );
    assert!(
        damage.status.success(),
        "the sealed-frame generator must produce its image.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&damage.stdout),
        String::from_utf8_lossy(&damage.stderr)
    );
    assert!(
        String::from_utf8_lossy(&damage.stdout).contains("damage_phase=complete"),
        "the generator must affirm that it fenced the mutation"
    );

    let reconcile = harness::run_reconcile(&root, 0, &ack);
    assert_eq!(
        reconcile.exit_code,
        Some(65),
        "production recovery must refuse the corrupt authority, not panic or \
         publish it. stderr:\n{}",
        reconcile.stderr
    );
    assert_eq!(reconcile.get("recovery_ok"), Some("false"));
    assert!(
        reconcile
            .get("recovery_error")
            .is_some_and(|error| error.contains("frame digest does not recompute")),
        "the refusal must come from frame validation, not an unrelated setup \
         failure: {:?}",
        reconcile.get("recovery_error")
    );
    assert_eq!(
        reconcile.get("adopted_sequences"),
        None,
        "a rejected recovery must publish no partial adoption result"
    );
}

/// Wave A review finding 1, physical image 2: a valid journal from shard 1
/// moved beneath shard 0 of the same root.
///
/// Root UUID validation alone cannot catch this. Production recovery must bind
/// the journal header's shard index to the directory being recovered. The
/// pre-fix Wave A reopen adopted the moved journal whole, so this is the second
/// generator needed for the matrix to catch that original blocker.
#[test]
fn production_recovery_rejects_a_journal_moved_between_shards() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");
    let ack = directory.path().join("ack.journal");

    let seed = std::process::Command::new(harness::DRIVER)
        .args(["append", "--root"])
        .arg(&root)
        .args([
            "--shard",
            "1",
            "--shard-count",
            "2",
            "--create",
            "--seed",
            "49375",
            "--group-len",
            "2",
            "--point",
            "BeforeAppend",
            "--action",
            "continue",
            "--fault",
            "none",
        ])
        .arg("--ack-journal")
        .arg(&ack)
        .output()
        .expect("seeding shard-1 journal");
    assert!(
        seed.status.success(),
        "the source must be a production-written shard-1 journal.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&seed.stdout),
        String::from_utf8_lossy(&seed.stderr)
    );

    let damage = generate_damage(
        &root,
        &[
            "--kind",
            "cross-shard-journal-movement",
            "--source-shard",
            "1",
            "--destination-shard",
            "0",
        ],
    );
    assert!(
        damage.status.success(),
        "the cross-shard generator must produce its image.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&damage.stdout),
        String::from_utf8_lossy(&damage.stderr)
    );

    let reconcile = harness::run_reconcile(&root, 0, &ack);
    assert_eq!(
        reconcile.exit_code,
        Some(65),
        "production recovery must refuse the moved journal, not panic or adopt \
         it. stderr:\n{}",
        reconcile.stderr
    );
    assert_eq!(reconcile.get("recovery_ok"), Some("false"));
    assert!(
        reconcile
            .get("recovery_error")
            .is_some_and(|error| error.contains("journal belongs to shard 1, not shard 0")),
        "the refusal must be the cross-shard binding check: {:?}",
        reconcile.get("recovery_error")
    );
    assert_eq!(
        reconcile.get("adopted_sequences"),
        None,
        "a rejected recovery must publish no partial adoption result"
    );
}

#[test]
fn enospc_during_append_is_refused_and_leaves_an_openable_store() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");
    let ack = directory.path().join("ack.journal");
    let committed = seed_committed_group(&root, &ack, 0xE05C);

    let child = harness::run_append(&harness::AppendRun {
        root: &root,
        shard: 0,
        shard_count: 1,
        seed: 0x1234,
        group_len: DRIVEN_GROUP_LEN,
        victim: 0,
        point: Failpoint::BeforeAppend,
        action: "continue",
        fault: "no-space",
        ack_journal: &ack,
        create: false,
    });
    assert_eq!(
        child.exit_code,
        Some(65),
        "ENOSPC must surface as a refusal, not as a partially acknowledged \
         group. stderr:\n{}",
        child.stderr
    );
    assert_eq!(child.get("driver_phase"), Some("failed"));

    let reconcile = harness::run_reconcile(&root, 0, &ack);
    assert_eq!(reconcile.get("recovery_ok"), Some("true"));
    assert_eq!(reconcile.get("acknowledged_loss"), Some("0"));
    let adopted = reconcile.sequences("adopted_sequences");
    for sequence in &committed {
        assert!(
            adopted.contains(sequence),
            "a full device must not cost an already-fenced group its sequence {sequence}"
        );
    }
}

/// A read `EIO` anywhere in the reopen path is a clean refusal, never a panic
/// and never a partial adoption.
///
/// # What this test deliberately does not claim
///
/// It does **not** assert scope 3.8 step 5's rule that an `EIO` *in the tail
/// region* means "the tail ends here". `sys::Fault` is a one-shot global with
/// no call-site or offset targeting, so the first positioned read of a reopen —
/// the `CURRENT` pointer, the manifest, or the journal header — consumes the
/// armed fault, and an `EIO` reading a manifest is legitimately fatal. Arming
/// `read-eio` through `drive::faults` therefore cannot express "on the tail
/// read", and asserting the end-of-tail rule from here would have been a test
/// that passed for the wrong reason or failed for the wrong reason. It failed
/// for the wrong reason first, which is how the gap was found.
///
/// The tail-region rule is covered where it can be targeted: A2's
/// `tests/recovery_eio.rs` arms the fault around a single `scan_forward` call,
/// and `tests/recovery_tail.rs` covers the same rule with a real failing
/// descriptor and no global state. The gap in `drive::faults` is reported to
/// the lead as an interface request rather than papered over here.
///
/// What is left to assert from this seam is still worth asserting: a device
/// read error must surface as a `StoreError`, the harness must not report a
/// number derived from a failed recovery, and nothing may be silently adopted.
#[test]
fn a_read_eio_during_reopen_is_a_clean_refusal_and_never_a_partial_adoption() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");
    let ack = directory.path().join("ack.journal");
    seed_committed_group(&root, &ack, 0xE10);

    // Armed in the reconciling process, because that is where recovery runs —
    // the fault registry is process-global and the writer's process is gone.
    let reconcile = std::process::Command::new(harness::DRIVER)
        .arg("reconcile")
        .arg("--root")
        .arg(&root)
        .arg("--shard")
        .arg("0")
        .arg("--ack-journal")
        .arg(&ack)
        .arg("--fault")
        .arg("read-eio")
        .output()
        .expect("spawning reconcile");
    let stdout = String::from_utf8_lossy(&reconcile.stdout);

    assert_eq!(
        reconcile.status.code(),
        Some(65),
        "a device read error must be a refusal with a documented exit code, not \
         a panic and not a success.\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("recovery_ok=false"),
        "the classifier must say recovery did not complete, so no downstream \
         number is derived from it.\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("injected EIO"),
        "the refusal must name the cause; an opaque failure here reads exactly \
         like corruption.\nstdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("adopted_sequences="),
        "a recovery that did not complete must adopt nothing, and must not \
         report an adoption set a caller could mistake for a result.\nstdout:\n{stdout}"
    );

    // And the store is not actually damaged: a reopen without the fault
    // recovers the acknowledged group. An injected transient must not be
    // indistinguishable from real corruption.
    let clean = harness::run_reconcile(&root, 0, &ack);
    assert_eq!(clean.get("recovery_ok"), Some("true"));
    assert_eq!(clean.get("acknowledged_loss"), Some("0"));
}

#[test]
fn a_directory_fsync_failure_during_seal_cannot_unmake_an_acknowledgment() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");
    let ack = directory.path().join("ack.journal");

    let child = std::process::Command::new(harness::DRIVER)
        .args(["append", "--root"])
        .arg(&root)
        .args([
            "--shard",
            "0",
            "--shard-count",
            "1",
            "--create",
            "--seed",
            "4242",
            "--group-len",
            "2",
            "--point",
            "BeforeAppend",
            "--action",
            "continue",
            "--fault",
            "none",
        ])
        .arg("--ack-journal")
        .arg(&ack)
        .args(["--seal", "--seal-fault", "dir-sync-eio"])
        .output()
        .expect("spawning append");
    let stdout = String::from_utf8_lossy(&child.stdout);
    assert!(
        stdout.contains("driver_phase=acknowledged"),
        "the group is fenced and acknowledged before the seal is attempted; \
         a seal fault must not be able to retract that.\nstdout:\n{stdout}"
    );
    let acknowledged: Vec<u64> = stdout
        .lines()
        .find_map(|line| line.strip_prefix("appended_sequences="))
        .map(|value| {
            value
                .split(',')
                .filter(|entry| !entry.is_empty())
                .map(|entry| entry.parse::<u64>().expect("sequence"))
                .collect()
        })
        .expect("appended_sequences");

    let reconcile = harness::run_reconcile(&root, 0, &ack);
    assert_eq!(
        reconcile.get("recovery_ok"),
        Some("true"),
        "a failed directory fsync during seal must leave a store recovery can \
         open. stderr:\n{}",
        reconcile.stderr
    );
    assert_eq!(reconcile.get("acknowledged_loss"), Some("0"));
    let adopted = reconcile.sequences("adopted_sequences");
    for sequence in &acknowledged {
        assert!(
            adopted.contains(sequence),
            "sequence {sequence} was acknowledged before the seal and must \
             survive its failure"
        );
    }
}

/// The one poisoning condition plan §5.2 names that `drive::faults` cannot arm
/// on its own.
///
/// `sys::write_vectored_all` verifies the file position after an append and
/// refuses on a mismatch, which is the "unexpected file position" condition.
/// There is no `Fault` variant that produces it directly: `ShortWrite` returns
/// early with a durable prefix and no cursor error, which is the correct
/// modelling of a short write but leaves the cursor check itself unexercised
/// from this seam. Recorded here rather than left implicit, and reported to
/// the lead as an interface gap rather than worked around with a fake.
#[test]
fn the_unexpected_cursor_condition_has_no_armable_fault_and_that_is_recorded() {
    let armable = [
        "short-write-tears-victim",
        "no-space",
        "fence-eio",
        "read-eio",
        "dir-sync-eio",
    ];
    assert_eq!(
        armable.len(),
        5,
        "the userspace fault set is these five; an unexpected-cursor fault \
         would be a sixth and does not exist in sys::Fault"
    );
}

/// The driving test above is only meaningful while `drive.rs` is real.
///
/// If A1's seam ever regresses to `unimplemented!()`, the driving test would
/// fail with an opaque unwind from inside a child process. This asserts the
/// dependency directly so the failure names its cause.
#[test]
fn the_drive_seam_a_wave_a_row_needs_is_present() {
    assert!(
        harness::drive_seam_is_implemented(),
        "crates/levcs-store/src/drive.rs is not implemented, so no Wave A row \
         can be driven (scope 4-A1 deliverable 5)."
    );
}

// ===========================================================================
// Driving the eight Wave B rows through StoreEngine::submit (scope 6.6 #2)
// ===========================================================================
//
// Wave A asserted two halves of each row's `FailpointExpectation`. These rows
// assert all six, because the four that were missing — `shard_poisoned`,
// `immediate_status`, `acknowledgment_allowed`, and
// `later_append_allowed_before_recovery` — are observable now that there is an
// engine, and they are the only thing that distinguishes several rows from one
// another. `AfterMarkedResolving` and `BeforeAppend` produce byte-identical
// stores; the entire difference between them lives in those four fields.
//
// Every observation goes through a method a consumer calls. None goes through
// an internal helper, a `cfg(test)` hook, or a field read. Scope 5 charter
// item 8.

#[cfg(feature = "store-privileged")]
use support::engine_matrix;

/// The one place the assertion is made, so every row is checked the same way
/// and a row cannot quietly assert fewer fields than its neighbours.
///
/// Six separate equalities, never one aggregate comparison of two structs. A
/// struct equality would report "expectation mismatch" and leave the reader to
/// diff two `Debug` renderings; contract review 2026-07-24-A is on record that
/// the field which is wrong is the one nobody looks at.
#[cfg(feature = "store-privileged")]
fn assert_full_expectation(
    point: Failpoint,
    class: PhysicalStateClass,
    observation: &engine_matrix::RowObservation,
) {
    use levcs_protocol::oracle::{append_publication_expectation, AppendFailpoint};

    let row = &observation.row;
    let expectation = append_publication_expectation(AppendFailpoint::from(point));

    // 1. physical_state_class -> recovery_outcome, and the frozen oracle's
    //    recovery_outcome. The same two derivations Wave A compares, restated
    //    here so a Wave B row is not exempt from the agreement Wave A enforces.
    assert_eq!(
        class.required_outcome(),
        expectation.recovery_outcome,
        "{row}: the physical state class {} implies {}, but the frozen oracle says {}",
        class.name(),
        harness::recovery_outcome_name(class.required_outcome()),
        harness::recovery_outcome_name(expectation.recovery_outcome)
    );

    // 2. recovery_outcome, observed by closing the engine and reopening
    //    through production recovery.
    let fact = engine_matrix::recovered_fact(&observation.recovered, row);
    assert!(
        outcome_admits(expectation.recovery_outcome, fact),
        "{row}: after a close and reopen through StoreEngine::open the victim reads \
         back as {fact:?}, which the frozen oracle's {} does not admit. victim = {:?}, \
         probe = {:?}, fences over the victim's group = {}",
        harness::recovery_outcome_name(expectation.recovery_outcome),
        observation.victim,
        observation.probe,
        observation.fences_during_victim()
    );

    // 3. shard_poisoned — the store naming itself poisoned, by variant.
    assert_eq!(
        observation.shard_poisoned_observed(),
        expectation.shard_poisoned,
        "{row}: the frozen oracle says shard_poisoned = {}. victim = {:?}, probe = {:?}",
        expectation.shard_poisoned,
        observation.victim,
        observation.probe
    );

    // 4. immediate_status — plan §5.1's two-root read on the live engine.
    let immediate = engine_matrix::immediate_status_of(&observation.immediate, row);
    assert_eq!(
        engine_matrix::immediate_status_name(immediate),
        engine_matrix::immediate_status_name(expectation.immediate_status),
        "{row}: transaction_status disagrees with the frozen oracle"
    );

    // 5. acknowledgment_allowed — a receipt obtainable through a consumer path.
    assert_eq!(
        observation.acknowledgment_allowed_observed(),
        expectation.acknowledgment_allowed,
        "{row}: the frozen oracle says acknowledgment_allowed = {}. victim = {:?}",
        expectation.acknowledgment_allowed,
        observation.victim
    );
    if !expectation.acknowledgment_allowed {
        assert!(
            observation.victim.receipt().is_none(),
            "{row}: submit returned a receipt for an operation the oracle says may not \
             be acknowledged, which is an acknowledgment whatever else is true"
        );
    }

    // 6. later_append_allowed_before_recovery — a *different* transaction on
    //    the same shard, before any reopen.
    assert_eq!(
        observation.later_append_allowed_observed(),
        expectation.later_append_allowed_before_recovery,
        "{row}: the frozen oracle says later_append_allowed_before_recovery = {}. \
         probe = {:?}",
        expectation.later_append_allowed_before_recovery,
        observation.probe
    );

    // The transaction that committed before the fault is not collateral. Every
    // row proves that too, exactly as the Wave A rows prove it for a prior
    // group; a fault that costs an already-acknowledged transaction its receipt
    // is acknowledged loss, whatever the row under test says.
    assert!(
        matches!(
            observation.prior_recovered,
            levcs_store::types::TransactionStatus::Committed(_)
        ),
        "{row}: the transaction acknowledged before the fault did not survive the \
         reopen: {:?}",
        observation.prior_recovered
    );

    // The root-lock release window documented on
    // `engine_matrix::reopen_after_close`. Reported rather than asserted: the
    // wait is compensating for a defect in a file B4 does not own, and a
    // harness that stayed silent about it would be hiding the very thing it is
    // working around.
    if observation.lock_release_attempts > 1 {
        eprintln!(
            "crash_matrix: {row}: the root lock was still held after StoreEngine::drop \
             returned; the reopen needed {} attempts over {:?}",
            observation.lock_release_attempts, observation.lock_release_wait
        );
    }

    // Charter item 7: the class is checked against a syscall count, not a
    // comment. A class that says no bytes were written must show no fence, and
    // a class that says the group was fenced must show exactly one.
    let fences = observation.fences_during_victim();
    let expected_fences = match class {
        PhysicalStateClass::NoBytes => 0,
        PhysicalStateClass::WholeFrameFenced => 1,
        PhysicalStateClass::WholeFrameFencedAndPublished => 1,
        // No Wave B row produces these two: the failpoints that tear a frame or
        // stop short of the fence are all Wave A and are driven through
        // drive.rs. Naming them is what makes a future row that moves into one
        // of these classes fail here rather than silently skip the check.
        PhysicalStateClass::PartialFrame => panic!(
            "{row}: a Wave B row produced a partial frame; the submit path forms whole \
             frames and the tearing failpoints are Wave A"
        ),
        PhysicalStateClass::WholeFrameUnfenced => panic!(
            "{row}: a Wave B row produced an unfenced whole frame; every Wave B location \
             is either before the mark or after the fence"
        ),
    };
    assert_eq!(
        fences,
        expected_fences,
        "{row}: physical state class {} implies {expected_fences} durability fence(s) \
         for this group, and DurabilityCounters reports {fences}",
        class.name()
    );
}

#[cfg(feature = "store-privileged")]
#[test]
fn wave_b_rows_drive_through_submit_to_their_full_failpoint_expectation() {
    let fixture = harness::load_fixture();
    // One token for the whole test. The failpoint and fault registries are
    // process-global one-shots, and a per-row token would let another test in
    // this binary arm between two rows of this one.
    let serial = engine_matrix::serial();
    let mut driven: Vec<String> = Vec::new();

    for row in &fixture.rows {
        let resolved = harness::resolve(row);
        if resolved.point.wave() != Wave::B {
            continue;
        }
        let plan = row
            .submit
            .as_ref()
            .expect("a Wave B row carries a submit plan");
        if plan.requires_root_cas_contention {
            // Driven by its own test below, which has to manufacture the lost
            // compare-and-swap this location sits behind.
            driven.push(row.failpoint.clone());
            continue;
        }

        for action in &plan.actions {
            let action = engine_matrix::action_from_name(action)
                .unwrap_or_else(|| panic!("row {}: unknown action {action:?}", row.failpoint));
            let observation = engine_matrix::drive_submit_row(&serial, resolved.point, action);
            assert_full_expectation(resolved.point, resolved.class, &observation);
        }
        driven.push(row.failpoint.clone());
    }

    let expected: Vec<String> = Failpoint::ALL
        .iter()
        .filter(|point| point.wave() == Wave::B)
        .map(|point| point.name().to_string())
        .collect();
    assert_eq!(
        driven, expected,
        "every Wave B row must actually have been driven, by name"
    );
}

/// The row B1 disclosed was never armed.
///
/// `DuringRootCasRetry` sits inside `publish_subtree`'s retry loop, past a
/// failed `compare_and_swap`. Submitting a transaction does not reach it; the
/// only way there is a genuinely lost CAS, which means another shard publishing
/// into the same committed root between this shard's load and its swap. The
/// driver manufactures the load, not the mechanism: eight shard writer threads
/// publish through the production path and the harness only chooses how much
/// work each publication carries into the window.
///
/// # Why this is a hard failure and not a skip
///
/// A fault-injection row that quietly does nothing when it cannot reach its
/// location is the state this row was already in — reachable in principle,
/// unarmed in practice, and green either way. If the location stops being
/// reachable, this test says so by name and by number.
#[cfg(feature = "store-privileged")]
#[test]
fn during_root_cas_retry_drives_through_a_genuinely_lost_committed_root_cas() {
    use std::time::Duration;

    let fixture = harness::load_fixture();
    let row = fixture
        .rows
        .iter()
        .find(|row| row.failpoint == "DuringRootCasRetry")
        .expect("the fixture carries the row");
    let resolved = harness::resolve(row);
    let plan = row.submit.as_ref().expect("a submit plan");
    assert!(
        plan.requires_root_cas_contention,
        "this test manufactures contention; the fixture must say the row needs it"
    );

    let serial = engine_matrix::serial();
    for action in &plan.actions {
        let action = engine_matrix::action_from_name(action)
            .unwrap_or_else(|| panic!("unknown action {action:?}"));
        let run = engine_matrix::drive_root_cas_retry_row(
            &serial,
            action,
            Duration::from_secs(CONTENTION_BUDGET_SECONDS),
        );
        assert!(
            run.anomaly.is_none(),
            "DuringRootCasRetry [{}]: a shard was refused for a reason this location \
             does not produce, so no transaction in this run is the row's victim: {:?}",
            engine_matrix::action_name(action),
            run.anomaly
        );
        let observation = run.observation.unwrap_or_else(|| {
            panic!(
                "DuringRootCasRetry [{}] did not fire in {:?} across {} submitted \
                 transactions on {} shards. The location is inside publish_subtree's \
                 retry loop; not reaching it means either that no committed-root CAS \
                 was ever lost — in which case the loop is unreachable and the row \
                 cannot be asserted from outside the engine — or that the failpoint \
                 has moved out of the retry. Either is a finding, and neither is a \
                 reason to rerun.",
                engine_matrix::action_name(action),
                run.elapsed,
                run.attempts,
                engine_matrix::CONTENTION_SHARDS
            )
        });
        eprintln!(
            "crash_matrix: DuringRootCasRetry [{}] fired after {} transactions in {:?}",
            engine_matrix::action_name(action),
            run.attempts,
            run.elapsed
        );
        assert_full_expectation(resolved.point, resolved.class, &observation);
    }
}

/// How long the contention driver is given per action.
///
/// Chosen from measurement rather than from taste: see the campaign recorded in
/// the B4 report. It is a ceiling on a search, not a timeout tuned until the
/// test passed.
#[cfg(feature = "store-privileged")]
const CONTENTION_BUDGET_SECONDS: u64 = 120;
