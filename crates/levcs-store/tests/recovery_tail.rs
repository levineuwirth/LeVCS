//! Scope 4-A2 acceptance: the tail scan, one dedicated test per case.
//!
//! Steps 5, 6, and 7 of scope 3.8. The scanner under test is
//! `journal::scan_journal` — the production one, the same walk `Journal::open`
//! and `segment::seal_journal` use — driven over real journal files with a real
//! 512-byte header. There is no A2 scanner any more; a parallel one would be a
//! second definition of where a journal ends.
//!
//! Every case in the acceptance list gets its own test with its own physical
//! image. Nothing is asserted in aggregate, and no test has a catch-all `match`
//! arm.

#[path = "recovery_reference_frame.rs"]
mod reference;

use levcs_protocol::oracle::RecoveryOutcome;
use levcs_store::format::{FrameError, JOURNAL_HEADER_LEN};
use levcs_store::journal::{TailScan, TailStop};
use levcs_store::recovery::{recover_journal_tail, tail_outcome};
use levcs_store::types::DurabilityCounters;

use reference::{frame, reseal_frame_digest, FrameSpec, JournalImage, JOURNAL_ID, PREALLOCATED};

fn adopted(scan: &TailScan) -> Vec<u64> {
    scan.frames.iter().map(|f| f.shard_sequence).collect()
}

/// Two clean frames, then a torn one, then a *complete* one. Returns the image
/// plus the offsets of the torn and the trailing complete frame.
fn torn_then_complete() -> (JournalImage, u64, u64) {
    let mut bytes = Vec::new();
    for sequence in 0..2 {
        bytes.extend_from_slice(&frame(sequence));
    }
    let torn_offset = JournalImage::frame_offset(bytes.len());

    // Frame 2, torn: one byte of its payload flipped, digest not resealed.
    // Under `nodatacow` the checksums are gone and this is what a torn block
    // looks like on read-back.
    let mut torn = frame(2);
    torn[180] ^= 0xFF;
    bytes.extend_from_slice(&torn);

    let complete_offset = JournalImage::frame_offset(bytes.len());
    bytes.extend_from_slice(&frame(3));

    (
        JournalImage::zeroed_tail(&bytes, PREALLOCATED),
        torn_offset,
        complete_offset,
    )
}

// ===========================================================================
// Torn final frame
// ===========================================================================

#[test]
fn a_torn_final_frame_is_discarded_and_the_prefix_is_adopted() {
    let mut bytes = Vec::new();
    for sequence in 0..3 {
        bytes.extend_from_slice(&frame(sequence));
    }
    let torn_offset = JournalImage::frame_offset(bytes.len());
    let mut torn = frame(3);
    let at = torn.len() - 40;
    torn[at] ^= 0xFF;
    bytes.extend_from_slice(&torn);

    let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
    let scan = image.scan();

    assert_eq!(adopted(&scan), vec![0, 1, 2]);
    assert_eq!(scan.stop, TailStop::Incomplete(FrameError::Trailer));
    assert_eq!(scan.stop_offset, torn_offset);
    assert_eq!(
        tail_outcome(&scan, torn_offset),
        RecoveryOutcome::AbsentRetriable
    );
    assert_eq!(
        tail_outcome(&scan, JOURNAL_HEADER_LEN as u64),
        RecoveryOutcome::Committed
    );
}

// ===========================================================================
// Step 6 — a complete frame AFTER a torn one must be discarded
// ===========================================================================

#[test]
fn a_complete_frame_after_a_torn_frame_is_discarded() {
    let (image, torn_offset, complete_offset) = torn_then_complete();

    // Establish, independently of the scan, that the trailing frame really is
    // complete and checksum-valid under the production codec. Without this the
    // test could pass for the wrong reason — a malformed trailing frame the
    // scan rejected on its own merits rather than because of its position.
    let all = image.bytes();
    let header = levcs_store::format::verify_complete(
        &all[complete_offset as usize..],
        &JOURNAL_ID,
        image.header.preallocated_len - complete_offset,
    )
    .expect("the trailing frame must itself be a complete, checksum-valid frame");
    assert_eq!(header.shard_sequence, 3);

    let scan = image.scan();

    assert_eq!(
        adopted(&scan),
        vec![0, 1],
        "recovery must stop at the hole and adopt only the contiguous prefix"
    );
    assert_eq!(scan.stop_offset, torn_offset);
    assert_eq!(scan.stop, TailStop::Incomplete(FrameError::FrameDigest));
    assert_eq!(
        tail_outcome(&scan, complete_offset),
        RecoveryOutcome::AbsentRetriable,
        "adopting a valid frame that sits after a hole would publish a gap and \
         break shard_sequence contiguity, multi-ref atomicity, and the \
         wholly-present-or-wholly-absent invariant"
    );
    assert!(
        !scan.frames.iter().any(|f| f.shard_sequence == 3),
        "shard_sequence 3 must not appear anywhere in the adopted set"
    );
}

#[test]
fn the_adopted_set_is_always_a_contiguous_prefix_wherever_the_hole_falls() {
    // The same claim swept over every hole position rather than asserted at
    // one. A per-frame implementation would pass the single-position test.
    for hole in 0..5usize {
        let mut bytes = Vec::new();
        let mut offsets = Vec::new();
        for sequence in 0..5u64 {
            offsets.push(JournalImage::frame_offset(bytes.len()));
            let mut f = frame(sequence);
            if sequence as usize == hole {
                f[190] ^= 0xFF;
            }
            bytes.extend_from_slice(&f);
        }
        let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
        let scan = image.scan();

        let expected: Vec<u64> = (0..hole as u64).collect();
        assert_eq!(
            adopted(&scan),
            expected,
            "with the hole at frame {hole}, only frames before it may be adopted"
        );
        assert_eq!(scan.stop_offset, offsets[hole]);
        for (i, offset) in offsets.iter().enumerate() {
            let expected_outcome = if i < hole {
                RecoveryOutcome::Committed
            } else {
                RecoveryOutcome::AbsentRetriable
            };
            assert_eq!(
                tail_outcome(&scan, *offset),
                expected_outcome,
                "frame {i} with the hole at {hole}"
            );
        }
    }
}

// ===========================================================================
// Zeroed tail
// ===========================================================================

#[test]
fn a_zeroed_tail_ends_the_scan_cleanly_and_is_not_an_error() {
    let mut bytes = Vec::new();
    for sequence in 0..3 {
        bytes.extend_from_slice(&frame(sequence));
    }
    let written = JournalImage::frame_offset(bytes.len());
    let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
    let scan = image.scan();

    assert_eq!(adopted(&scan), vec![0, 1, 2]);
    assert_eq!(
        scan.stop,
        TailStop::NotAFrame,
        "the region past the write cursor of a preallocated file reads as zeros; \
         that is the ordinary copy-on-write crash image, not a fault"
    );
    assert_eq!(scan.stop_offset, written);
}

// ===========================================================================
// Stale preallocated content
// ===========================================================================

#[test]
fn stale_preallocated_content_in_the_tail_ends_the_scan_cleanly() {
    let mut bytes = Vec::new();
    for sequence in 0..3 {
        bytes.extend_from_slice(&frame(sequence));
    }
    let written = JournalImage::frame_offset(bytes.len());
    let image = JournalImage::stale_tail(&bytes, PREALLOCATED);
    let scan = image.scan();

    assert_eq!(adopted(&scan), vec![0, 1, 2]);
    assert_eq!(
        scan.stop,
        TailStop::NotAFrame,
        "a recycled non-zeroing extent leaves stale bytes rather than zeros; the \
         decision is the same, and the quarantine record is what tells the two \
         apart afterwards"
    );
    assert_eq!(scan.stop_offset, written);
}

#[test]
fn stale_content_that_happens_to_carry_the_frame_magic_is_still_the_end_of_the_tail() {
    // The nastier stale-content case: the recycled extent holds a whole frame
    // from a *previous* incarnation of the file. `journal_id` is the defense,
    // and it must fire rather than the frame being adopted.
    let mut bytes = frame(0);
    let stale_offset = JournalImage::frame_offset(bytes.len());
    bytes.extend_from_slice(&FrameSpec::new(1).with_journal_id([0x99; 16]).encode());

    let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
    let scan = image.scan();

    assert_eq!(adopted(&scan), vec![0]);
    assert_eq!(scan.stop, TailStop::Incomplete(FrameError::JournalId));
    assert_eq!(scan.stop_offset, stale_offset);
}

// ===========================================================================
// EIO on tail read
// ===========================================================================

#[test]
fn a_failed_positioned_read_in_the_tail_ends_the_tail_rather_than_failing_the_store() {
    // A real read error, produced without a failpoint feature: a directory
    // descriptor is openable and every positioned read against it fails. The
    // point under test is that `scan_journal` has no error channel at all, so
    // no read failure can propagate out as a store error.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = std::fs::File::open(dir.path()).expect("a directory is openable");
    let header = levcs_store::format::JournalHeader {
        shard_index: 0,
        root_uuid: reference::ROOT_UUID,
        journal_id: JOURNAL_ID,
        first_shard_sequence: 0,
        preallocated_len: PREALLOCATED,
        created_at_micros: 1,
    };

    let scan = levcs_store::journal::scan_journal(&file, &header, JOURNAL_HEADER_LEN as u64);

    assert!(scan.frames.is_empty());
    match scan.stop {
        TailStop::ReadError => assert_eq!(scan.stop_offset, JOURNAL_HEADER_LEN as u64),
        TailStop::EndOfPreallocation | TailStop::NotAFrame | TailStop::Incomplete(_) => {
            panic!("a failing positioned read must stop the tail as ReadError")
        }
    }
    assert!(
        scan.stopped_early(),
        "a read failure leaves a region that must be quarantined"
    );
}

// ===========================================================================
// Wrong journal_id
// ===========================================================================

#[test]
fn a_frame_carrying_the_wrong_journal_id_is_never_adopted() {
    let bytes = FrameSpec::new(0).with_journal_id([0xAB; 16]).encode();
    let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
    let scan = image.scan();

    assert!(scan.frames.is_empty());
    assert_eq!(
        scan.stop,
        TailStop::Incomplete(FrameError::JournalId),
        "journal_id is the defense against a frame from a previous incarnation \
         of a recycled extent being accepted as live"
    );
    assert_eq!(scan.stop_offset, JOURNAL_HEADER_LEN as u64);
    assert_eq!(
        tail_outcome(&scan, JOURNAL_HEADER_LEN as u64),
        RecoveryOutcome::AbsentRetriable
    );
}

// ===========================================================================
// Length attacks on the tail
// ===========================================================================

#[test]
fn a_total_len_that_overflows_the_region_stops_the_scan() {
    let mut bytes = frame(0);
    let bad_offset = JournalImage::frame_offset(bytes.len());
    let mut bad = frame(1);
    bad[16..24].copy_from_slice(&(1u64 << 40).to_le_bytes());
    reseal_frame_digest(&mut bad);
    bytes.extend_from_slice(&bad);

    let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
    let scan = image.scan();

    assert_eq!(adopted(&scan), vec![0]);
    assert_eq!(scan.stop, TailStop::Incomplete(FrameError::Length));
    assert_eq!(scan.stop_offset, bad_offset);
}

#[test]
fn a_total_len_that_is_not_eight_aligned_stops_the_scan() {
    let mut bytes = frame(0);
    let bad_offset = JournalImage::frame_offset(bytes.len());
    let mut bad = frame(1);
    let total = u64::from_le_bytes(bad[16..24].try_into().unwrap());
    bad[16..24].copy_from_slice(&(total + 1).to_le_bytes());
    reseal_frame_digest(&mut bad);
    bytes.extend_from_slice(&bad);

    let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
    let scan = image.scan();
    assert_eq!(adopted(&scan), vec![0]);
    assert_eq!(scan.stop, TailStop::Incomplete(FrameError::Length));
    assert_eq!(scan.stop_offset, bad_offset);
}

#[test]
fn a_frame_truncated_at_every_offset_never_extends_the_adopted_prefix() {
    let head = frame(0);
    let tail = frame(1);
    for cut in 0..tail.len() {
        let mut bytes = head.clone();
        bytes.extend_from_slice(&tail[..cut]);
        let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
        let scan = image.scan();
        assert_eq!(
            adopted(&scan),
            vec![0],
            "a tail truncated at {cut} bytes must never be adopted"
        );
        assert_eq!(scan.stop_offset, JournalImage::frame_offset(head.len()));
    }
}

// ===========================================================================
// Quarantine and the no-in-place-rewrite rule
// ===========================================================================

#[test]
fn recovery_quarantines_the_discarded_tail_and_leaves_the_journal_untouched() {
    let (image, torn_offset, _) = torn_then_complete();
    let before = image.bytes();
    let file = image.open();
    let counters = DurabilityCounters::default();
    let quarantine = image.root().join("quarantine");

    let (scan, record) = recover_journal_tail(
        &quarantine,
        &file,
        &image.header,
        JOURNAL_HEADER_LEN as u64,
        &counters,
    )
    .expect("recovery must not fail on a torn tail");

    assert_eq!(adopted(&scan), vec![0, 1]);
    assert_eq!(scan.stop_offset, torn_offset);
    // `recover_journal_tail` now returns the record it wrote rather than a
    // byte count alone, so `report.quarantined` can name where the bytes went.
    // The assertion below is deliberately the same one as before — `> 0` — and
    // not the stronger `is_some()` the new shape invites: keeping the
    // semantics identical is what makes this a mechanical refactor.
    let bytes = record.as_ref().map(|r| r.bytes).unwrap_or(0);
    assert!(bytes > 0, "a torn tail is evidence and must be captured");
    assert_eq!(
        image.bytes(),
        before,
        "recovery must never rewrite a journal in place"
    );

    let captured = std::fs::read_dir(&quarantine)
        .expect("quarantine dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().to_string())
        .collect::<Vec<_>>();
    assert_eq!(captured.len(), 1);
    assert!(captured[0].starts_with(&hex::encode(JOURNAL_ID)));
    assert!(captured[0].contains(&torn_offset.to_string()));
}

#[test]
fn a_journal_filled_exactly_to_its_preallocated_end_quarantines_nothing() {
    let mut bytes = Vec::new();
    for sequence in 0..3 {
        bytes.extend_from_slice(&frame(sequence));
    }
    let preallocated = JournalImage::frame_offset(bytes.len());
    let image = JournalImage::zeroed_tail(&bytes, preallocated);
    let file = image.open();
    let counters = DurabilityCounters::default();

    let (scan, record) = recover_journal_tail(
        &image.root().join("quarantine"),
        &file,
        &image.header,
        JOURNAL_HEADER_LEN as u64,
        &counters,
    )
    .expect("recovery");

    assert_eq!(adopted(&scan), vec![0, 1, 2]);
    assert_eq!(scan.stop, TailStop::EndOfPreallocation);
    assert!(!scan.stopped_early());
    let quarantined = record.as_ref().map(|r| r.bytes).unwrap_or(0);
    assert_eq!(quarantined, 0);
    assert_eq!(counters.snapshot().fdatasync, 0);
}

#[test]
fn an_all_zero_tail_writes_no_quarantine_record() {
    // The ordinary copy-on-write crash leaves exactly this. A quarantine file
    // for every clean crash would bury the one that matters.
    let bytes = frame(0);
    let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
    let file = image.open();
    let counters = DurabilityCounters::default();
    let quarantine = image.root().join("quarantine");

    let (scan, record) = recover_journal_tail(
        &quarantine,
        &file,
        &image.header,
        JOURNAL_HEADER_LEN as u64,
        &counters,
    )
    .expect("recovery");

    assert_eq!(adopted(&scan), vec![0]);
    assert!(scan.stopped_early());
    let quarantined = record.as_ref().map(|r| r.bytes).unwrap_or(0);
    assert_eq!(quarantined, 0);
    assert!(!quarantine.exists(), "no record for a clean zeroed tail");
}

// ===========================================================================
// Resuming from a checkpoint offset
// ===========================================================================

#[test]
fn the_scan_resumes_from_the_checkpoint_offset_rather_than_the_file_start() {
    let mut bytes = Vec::new();
    let mut offsets = Vec::new();
    for sequence in 0..4 {
        offsets.push(JournalImage::frame_offset(bytes.len()));
        bytes.extend_from_slice(&frame(sequence));
    }
    let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);

    let scan = levcs_store::journal::scan_journal(&image.open(), &image.header, offsets[2]);
    assert_eq!(
        adopted(&scan),
        vec![2, 3],
        "replay must be bounded by the checkpoint, not restart at the file header"
    );
}
