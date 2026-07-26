//! Scope 4-A2 acceptance: `EIO` on a tail read.
//!
//! Its own test binary. The armed fault in `sys.rs` is a one-shot global, so a
//! test that arms it must not share a process with tests that also read
//! through the funnel — otherwise whichever `pread` happens to run first
//! consumes the fault and the campaign stops being deterministic.
//! `recovery_tail.rs` covers the same rule with a real failing descriptor,
//! which needs no global state; this file covers the specific `EIO` the frozen
//! hardware profile makes live.
//!
//! This header used to say "and deliberately the only test in it", and a
//! second test was added anyway — both arming `ReadEio`, one of them scanning
//! cleanly before it armed. That unarmed scan is itself a funnel read, so it
//! consumed the other test's fault; since a binary's tests run in parallel
//! threads, the binary failed 8 runs in 40 measured. The separate binary is
//! still worth having, but it is not the mechanism: every test here holds
//! `drive::faults::serial()` for its whole body, and `arm` will not compile
//! without it — which a later test cannot forget as easily as it forgot a
//! comment.

#[path = "recovery_reference_frame.rs"]
mod reference;

#[cfg(all(feature = "failpoints", feature = "store-internals"))]
mod eio {
    use super::reference::{frame, JournalImage, PREALLOCATED};
    use levcs_store::drive::faults::{arm, disarm, Fault};
    use levcs_store::format::JOURNAL_HEADER_LEN;
    use levcs_store::journal::{scan_journal, TailStop};

    /// The rule under test: scope 3.8 step 5 requires an `EIO` in the tail
    /// region to mean "the tail ends here", never a fatal store error. Getting
    /// this wrong turns an ordinary crash into an unopenable store.
    ///
    /// The residual risk this accepts is named in scope 3.8 and is not closed
    /// here: an `EIO` over a frame that *was* fenced and that the device then
    /// lost is indistinguishable by inspection from an unfenced tail. A3's
    /// external ACK reconciliation is the detector, and a non-zero
    /// `acknowledged_loss` there is a hardware finding.
    #[test]
    fn an_injected_eio_on_the_tail_read_ends_the_tail_rather_than_failing_the_store() {
        let serial = levcs_store::drive::faults::serial();
        let mut bytes = Vec::new();
        for sequence in 0..3 {
            bytes.extend_from_slice(&frame(sequence));
        }
        let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
        let file = image.open();

        disarm(&serial);
        arm(&serial, Fault::ReadEio);
        let scan = scan_journal(&file, &image.header, JOURNAL_HEADER_LEN as u64);
        disarm(&serial);

        assert!(
            scan.frames.is_empty(),
            "the first read failed, so nothing may be adopted"
        );
        match scan.stop {
            TailStop::ReadError => {
                assert_eq!(scan.stop_offset, JOURNAL_HEADER_LEN as u64)
            }
            TailStop::EndOfPreallocation | TailStop::NotAFrame | TailStop::Incomplete(_) => {
                panic!("an injected EIO must stop the tail as ReadError")
            }
        }
        assert!(
            scan.stopped_early(),
            "the unreadable region must still be quarantined"
        );
    }

    /// The same rule mid-file: a scan resuming at a frame whose read fails
    /// stops there rather than erroring, and the frames below it — already
    /// adopted by the clean pass — are untouched.
    #[test]
    fn an_eio_after_a_healthy_prefix_keeps_the_prefix() {
        // Held from the top, not from the `arm` below: the clean scan this test
        // performs first is itself a funnel read, and it was consuming the
        // other test's armed `ReadEio`.
        let serial = levcs_store::drive::faults::serial();
        let mut bytes = Vec::new();
        for sequence in 0..3 {
            bytes.extend_from_slice(&frame(sequence));
        }
        let image = JournalImage::zeroed_tail(&bytes, PREALLOCATED);
        let file = image.open();

        // Adopt the first two frames with no fault armed, then arm the fault
        // and resume from where the third begins.
        let clean = scan_journal(&file, &image.header, JOURNAL_HEADER_LEN as u64);
        assert_eq!(
            clean
                .frames
                .iter()
                .map(|f| f.shard_sequence)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        let third = clean.frames[2].offset;

        disarm(&serial);
        arm(&serial, Fault::ReadEio);
        let second = scan_journal(&file, &image.header, third);
        disarm(&serial);

        assert!(second.frames.is_empty());
        match second.stop {
            TailStop::ReadError => assert_eq!(second.stop_offset, third),
            TailStop::EndOfPreallocation | TailStop::NotAFrame | TailStop::Incomplete(_) => {
                panic!("an injected EIO must stop the tail as ReadError")
            }
        }
    }
}
