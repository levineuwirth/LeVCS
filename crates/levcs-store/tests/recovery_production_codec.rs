//! Cross-derivation check: A1's frozen codec in `format.rs` and A2's reference
//! implementation of scope 3.3 must agree on every input.
//!
//! # Status
//!
//! Green against A1's landed `format.rs`. Before A1 landed these panicked on
//! `unimplemented!()`, which was the intended signal: no skip was ever added,
//! because a self-skipping test would keep passing if A1's codec later
//! diverged.
//!
//! One divergence was found and is not a defect. Scope 3.3 numbers its eight
//! conditions but does not fix an evaluation order, and `format.rs` checks
//! `flags` (condition 7) before `frame_digest` (condition 5) while this file's
//! reference implementation follows the numbering. On an input that violates
//! both at once the two name different `FrameError` variants while agreeing
//! that the frame is not complete. `agree` therefore compares variants only on
//! single-defect inputs, and `agree_on_the_verdict` compares the verdict on
//! multi-defect ones. See the report note on 3.3.
//!
//! # Why the check is worth having
//!
//! The scope 5 charter directs the reviewer to attack the completeness
//! definition first, and warns that "every condition in 3.3" must be covered
//! rather than a counted subset. Two independent derivations agreeing on a
//! corpus that includes a valid frame, each condition violated alone, and every
//! truncation offset is the mechanical form of that instruction. A single
//! implementation checked against itself is not.

#[path = "recovery_reference_frame.rs"]
mod reference;

use levcs_store::format::verify_complete as production_verify;

use reference::{frame, reference_verify, reseal_frame_digest, FrameSpec, JOURNAL_ID};

/// Both derivations must reach the same verdict, and — when the input has
/// exactly one defect — name the same condition.
///
/// The two halves are separate on purpose. Scope 3.3 numbers its eight
/// conditions but does not fix an evaluation order, and `format.rs` checks
/// `flags` (condition 7) before `frame_digest` (condition 5) while this file's
/// reference implementation follows the numbering. On an input that violates
/// both at once the two therefore name different variants while agreeing that
/// the frame is not complete. That is a documentation gap, not a defect: the
/// *set* of complete frames is what recovery depends on, and it is identical.
fn agree(bytes: &[u8], journal_id: &[u8; 16], remaining: u64, what: &str) {
    let reference = reference_verify(bytes, journal_id, remaining);
    let production = production_verify(bytes, journal_id, remaining);
    match (&reference, &production) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "{what}: both accepted but disagreed on the header"),
        (Err(a), Err(b)) => assert_eq!(
            a, b,
            "{what}: both rejected but named different completeness conditions"
        ),
        (Ok(_), Err(e)) => panic!("{what}: the reference accepted, format.rs rejected with {e}"),
        (Err(e), Ok(_)) => panic!("{what}: the reference rejected with {e}, format.rs accepted"),
    }
}

/// Verdict-only agreement, for inputs that may violate more than one condition
/// at once. This is the property recovery actually rests on: a byte sequence is
/// a complete frame, or it is not, and both derivations must say the same.
fn agree_on_the_verdict(bytes: &[u8], journal_id: &[u8; 16], remaining: u64, what: &str) {
    let reference = reference_verify(bytes, journal_id, remaining);
    let production = production_verify(bytes, journal_id, remaining);
    match (&reference, &production) {
        (Ok(a), Ok(b)) => assert_eq!(a, b, "{what}: both accepted but disagreed on the header"),
        (Err(_), Err(_)) => {}
        (Ok(_), Err(e)) => panic!("{what}: the reference accepted, format.rs rejected with {e}"),
        (Err(e), Ok(_)) => panic!("{what}: the reference rejected with {e}, format.rs accepted"),
    }
}

#[test]
fn the_two_derivations_agree_on_a_well_formed_frame() {
    let bytes = frame(1);
    agree(&bytes, &JOURNAL_ID, bytes.len() as u64, "well-formed frame");
}

#[test]
fn the_two_derivations_agree_on_each_violated_condition() {
    let good = frame(1);
    let remaining = good.len() as u64;

    let mut length = good.clone();
    let total = u64::from_le_bytes(length[16..24].try_into().unwrap());
    length[16..24].copy_from_slice(&(total + 1).to_le_bytes());
    agree(&length, &JOURNAL_ID, remaining, "unaligned total_len");

    let mut magic = good.clone();
    magic[0] ^= 0xFF;
    reseal_frame_digest(&mut magic);
    agree(&magic, &JOURNAL_ID, remaining, "header magic");

    let mut header_len = good.clone();
    header_len[10..12].copy_from_slice(&99u16.to_le_bytes());
    reseal_frame_digest(&mut header_len);
    agree(&header_len, &JOURNAL_ID, remaining, "header_len");

    agree(&good, &[0xEE; 16], remaining, "journal_id");

    let mut trailer = good.clone();
    let at = trailer.len() - 48;
    trailer[at] ^= 0xFF;
    reseal_frame_digest(&mut trailer);
    agree(&trailer, &JOURNAL_ID, remaining, "trailer magic");

    let mut digest = good.clone();
    let at = digest.len() - 1;
    digest[at] ^= 0xFF;
    agree(&digest, &JOURNAL_ID, remaining, "frame digest");

    let mut payload = good.clone();
    payload[176] ^= 0xFF;
    reseal_frame_digest(&mut payload);
    agree(&payload, &JOURNAL_ID, remaining, "payload digest");

    let mut flags = FrameSpec::new(1);
    flags.flags = 1;
    let flags = flags.encode();
    agree(&flags, &JOURNAL_ID, flags.len() as u64, "non-zero flags");

    let mut padded = FrameSpec::new(1);
    padded.pad_byte = 0xFF;
    let padded = padded.encode();
    agree(
        &padded,
        &JOURNAL_ID,
        padded.len() as u64,
        "non-zero padding",
    );
}

#[test]
fn the_two_derivations_agree_at_every_truncation_offset() {
    let good = frame(2);
    for cut in 0..good.len() {
        agree(
            &good[..cut],
            &JOURNAL_ID,
            cut as u64,
            &format!("truncated at {cut}"),
        );
    }
}

#[test]
fn the_two_derivations_agree_under_single_bit_mutation() {
    let good = frame(3);
    let remaining = good.len() as u64;
    for byte in (0..good.len()).step_by(5) {
        for bit in [0u8, 4, 7] {
            let mut mutated = good.clone();
            mutated[byte] ^= 1 << bit;
            // A single bit flip can violate several conditions at once (a flag
            // bit also breaks the frame digest), so only the verdict is
            // comparable here.
            agree_on_the_verdict(
                &mutated,
                &JOURNAL_ID,
                remaining,
                &format!("bit {bit} of byte {byte}"),
            );
            assert!(
                production_verify(&mutated, &JOURNAL_ID, remaining).is_err(),
                "no single-bit mutation of a valid frame may validate \
                 (bit {bit} of byte {byte})"
            );
        }
    }
}

// ===========================================================================
// The tail scan over the production codec
// ===========================================================================
//
// The scan tests in `recovery_tail.rs` drive the reference verifier so that
// A2's stopping logic is provable independently of A1. These re-run the two
// highest-risk cases through `format::verify_complete` itself, so the claim is
// not only "A2 stops correctly given a correct verifier" but "A2 stops
// correctly in the shipped configuration".

use levcs_protocol::oracle::RecoveryOutcome;
use levcs_store::journal::{TailScan, TailStop};
use levcs_store::recovery::tail_outcome;
use reference::{JournalImage, PREALLOCATED};

fn scan_with_production(image: &JournalImage) -> TailScan {
    image.scan()
}

fn adopted(scan: &TailScan) -> Vec<u64> {
    scan.frames.iter().map(|f| f.shard_sequence).collect()
}

#[test]
fn production_recovery_stops_at_the_first_incomplete_frame() {
    let mut bytes = Vec::new();
    for sequence in 0..3 {
        bytes.extend_from_slice(&frame(sequence));
    }
    let torn_offset = JournalImage::frame_offset(bytes.len());
    let mut torn = frame(3);
    torn[180] ^= 0xFF;
    bytes.extend_from_slice(&torn);

    let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
    let scan = scan_with_production(&image);

    assert_eq!(adopted(&scan), vec![0, 1, 2]);
    assert_eq!(scan.stop_offset, torn_offset);
}

#[test]
fn production_recovery_discards_a_complete_frame_that_sits_after_a_torn_one() {
    let mut bytes = Vec::new();
    for sequence in 0..2 {
        bytes.extend_from_slice(&frame(sequence));
    }
    let torn_offset = JournalImage::frame_offset(bytes.len());
    let mut torn = frame(2);
    torn[180] ^= 0xFF;
    bytes.extend_from_slice(&torn);
    let complete_offset = JournalImage::frame_offset(bytes.len());
    bytes.extend_from_slice(&frame(3));

    let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);

    // Prove independently, with the production verifier, that the trailing
    // frame is genuinely complete before asserting that it is discarded.
    let all = image.bytes();
    production_verify(
        &all[complete_offset as usize..],
        &JOURNAL_ID,
        image.header.preallocated_len - complete_offset,
    )
    .expect("the trailing frame must itself be complete under format.rs");

    let scan = scan_with_production(&image);
    assert_eq!(adopted(&scan), vec![0, 1]);
    assert_eq!(scan.stop_offset, torn_offset);
    assert_eq!(
        tail_outcome(&scan, complete_offset),
        RecoveryOutcome::AbsentRetriable
    );
}

#[test]
fn production_recovery_treats_a_zeroed_tail_as_the_end_of_the_tail() {
    let mut bytes = Vec::new();
    for sequence in 0..2 {
        bytes.extend_from_slice(&frame(sequence));
    }
    let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
    let scan = scan_with_production(&image);

    assert_eq!(adopted(&scan), vec![0, 1]);
    assert_eq!(scan.stop, TailStop::NotAFrame);
}

#[test]
fn production_recovery_treats_stale_preallocated_content_as_the_end_of_the_tail() {
    let mut bytes = Vec::new();
    for sequence in 0..2 {
        bytes.extend_from_slice(&frame(sequence));
    }
    let image = JournalImage::stale_tail(&bytes, PREALLOCATED);
    let scan = scan_with_production(&image);

    assert_eq!(adopted(&scan), vec![0, 1]);
    assert_eq!(scan.stop, TailStop::NotAFrame);
}
