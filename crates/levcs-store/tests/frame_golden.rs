//! A1 JournalWriter tests: the golden frame corpus, negative decode coverage
//! for every completeness condition, and the durability counter assertions of
//! scope 4-A1's acceptance.
//!
//! # No catch-all arms
//!
//! Scope 5 charter item 6: no expectation in this file is asserted through a
//! catch-all `match` arm. Contract review 2026-07-24-A shipped an unsound
//! recovery classification because a catch-all left 14 of 17 outcomes
//! unasserted, and a reviewer greps for one. Every negative case names the
//! exact `FrameError` variant it expects.

#[path = "../examples/phase1_frame_golden.rs"]
#[allow(dead_code)]
mod generator;

use std::sync::Arc;
use std::time::Duration;

use levcs_store::format::{
    self, verify_complete, Frame, FrameError, FrameHeader, JournalHeader, Manifest, SegmentFooter,
    TailRange, TransactionFramePayloadV1, FRAME_HEADER_LEN, FRAME_TRAILER_LEN, JOURNAL_HEADER_LEN,
    MIN_FRAME_LEN,
};
use levcs_store::journal::{GroupBuilder, Journal, TailStop};
use levcs_store::types::DurabilityCounters;

/// Exclusive use of the process-global fault and failpoint registries, held
/// for the **whole test body**.
///
/// This file previously kept its own `APPEND_SERIAL` mutex — a fourth private
/// copy of the same mechanism, and one that protected nothing outside this
/// binary's own module. `sys::fault_state::serial` is now the single
/// definition: it returns the token `arm` demands, so an unguarded call site
/// is a compile error rather than a comment nobody reads, and acquiring it
/// clears anything a panicking test left armed.
///
/// Holding it across the whole body, not just across `arm`, is deliberate: the
/// original defect was a clean scan performed *before* arming, which is itself
/// funnel traffic and consumed another test's armed fault.
#[cfg(feature = "failpoints")]
fn serial() -> levcs_store::drive::faults::FaultSerial {
    levcs_store::drive::faults::serial()
}

/// Without `failpoints` there is no registry, nothing can be armed, and there
/// is therefore nothing to contend for. The call sites stay identical in both
/// configurations rather than being `cfg`-ed one by one, because a lock that
/// exists in only one build is a lock the other build's new test will forget.
#[cfg(not(feature = "failpoints"))]
fn serial() {}

// ---------------------------------------------------------------------------
// Golden corpus
// ---------------------------------------------------------------------------

#[test]
fn golden_frame_vectors_are_byte_for_byte_frozen() {
    let expected: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/phase1-frames.json"))
            .expect("the golden fixture must be valid JSON");
    assert_eq!(
        generator::golden_value(),
        expected,
        "the frame format changed. Regenerate only with \
         `cargo run -p levcs-store --example phase1_frame_golden`, and only \
         with a recorded decision: every post-freeze frame change invalidates \
         the crash fixtures too."
    );
}

/// Determinism is the property that makes the corpus meaningful: two
/// regenerations in one process must be identical, which is the in-test form
/// of the acceptance criterion "byte-stable across two consecutive
/// regenerations".
#[test]
fn regeneration_is_byte_stable() {
    let first = serde_json::to_string(&generator::golden_value()).expect("serialize");
    let second = serde_json::to_string(&generator::golden_value()).expect("serialize");
    assert_eq!(first, second);
}

#[test]
fn the_corpus_covers_every_case_scope_4_a1_names() {
    let value = generator::golden_value();
    let names: Vec<String> = value["frames"]
        .as_array()
        .expect("frames array")
        .iter()
        .map(|f| f["name"].as_str().expect("name").to_string())
        .collect();

    for required in [
        "minimum-frame",
        "repository-create",
        "multi-object",
        "multi-ref-set-and-delete",
        "authority-transition",
        "staged-projection-install",
        "source-kind-client",
        "source-kind-mirror-snapshot",
        "source-kind-mirror-event",
        "source-kind-legacy-migration",
        "source-kind-projection-admin",
        "source-kind-administrative",
        "max-shard-sequence",
        "max-repo-sequence",
    ] {
        assert!(
            names.iter().any(|n| n == required),
            "the golden corpus is missing the {required} vector"
        );
    }
    assert_eq!(
        names.len(),
        names
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        "vector names must be unique"
    );
}

#[test]
fn every_golden_frame_verifies_decodes_and_re_encodes_identically() {
    for (bytes, name) in golden_frames() {
        let header = verify_complete(&bytes, &generator::GOLDEN_JOURNAL_ID, bytes.len() as u64)
            .unwrap_or_else(|e| panic!("golden frame {name} must verify: {e}"));
        assert_eq!(header.total_len, bytes.len() as u64);

        let frame = Frame::decode(&bytes, &generator::GOLDEN_JOURNAL_ID)
            .unwrap_or_else(|e| panic!("golden frame {name} must decode: {e}"));
        let re_encoded = frame.encode().expect("re-encode");
        assert_eq!(
            re_encoded, bytes,
            "decode/encode must be the identity on frame {name}"
        );

        if !frame.payload.is_empty() {
            let payload = TransactionFramePayloadV1::decode_canonical(&frame.payload)
                .unwrap_or_else(|e| panic!("golden payload {name} must revalidate: {e}"));
            assert_eq!(
                payload.encode_canonical().expect("re-encode payload"),
                frame.payload,
                "payload encoding must be canonical on frame {name}"
            );
        }
    }
}

fn golden_frames() -> Vec<(Vec<u8>, String)> {
    generator::golden_value()["frames"]
        .as_array()
        .expect("frames array")
        .iter()
        .map(|f| {
            (
                hex::decode(f["frame_hex"].as_str().expect("frame_hex")).expect("hex"),
                f["name"].as_str().expect("name").to_string(),
            )
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Negative decode: the eight completeness conditions, violated independently
// ---------------------------------------------------------------------------

const JOURNAL_ID: [u8; 16] = [0x5A; 16];

/// A frame whose payload length is not a multiple of 8, so it has a real
/// padding region for condition 8 to be violated in.
fn sample_frame(payload_len: usize) -> Vec<u8> {
    let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
    let payload_len = payload.len() as u64;
    Frame {
        header: FrameHeader {
            flags: 0,
            total_len: format::frame_total_len(payload_len),
            journal_id: JOURNAL_ID,
            shard_sequence: 42,
            repo_sequence: 7,
            namespace: [0x11; 32],
            operation_id: [0x22; 16],
            operation_digest: levcs_core::ObjectId([0x33; 32]),
            payload_len,
            payload_digest: format::digest(format::FRAME_PAYLOAD_DIGEST_DOMAIN, &payload),
        },
        payload,
    }
    .encode()
    .expect("encode")
}

/// Recompute the trailing frame digest so that a mutation elsewhere is the
/// *only* defect. Without this every mutation would also fail condition 5 and
/// no other condition could ever be observed in isolation.
fn reseal(bytes: &mut [u8]) {
    let at = bytes.len() - 32;
    let digest = format::digest(format::FRAME_DIGEST_DOMAIN, &bytes[..at]);
    bytes[at..].copy_from_slice(digest.as_bytes());
}

fn expect_error(bytes: &[u8], remaining: u64, expected: FrameError, what: &str) {
    match verify_complete(bytes, &JOURNAL_ID, remaining) {
        Ok(_) => panic!("{what} must be rejected, but verified as a complete frame"),
        Err(observed) => assert_eq!(
            observed, expected,
            "{what} must be rejected by {expected:?}, not by {observed:?}"
        ),
    }
}

/// `total_len` appears twice by design — once in the header and once in the
/// trailer — so a `total_len` mutation necessarily perturbs condition 4 as
/// well. That redundancy is the point: the trailer is what makes a torn write
/// detectable. These tests therefore assert the *first* condition that fires,
/// which is condition 1, and every other negative test below violates exactly
/// one condition (the `reseal` helper is what makes that possible).
#[test]
fn condition_1_total_len_below_the_minimum_is_rejected() {
    let mut bytes = sample_frame(5);
    bytes[16..24].copy_from_slice(&(MIN_FRAME_LEN - 8).to_le_bytes());
    reseal(&mut bytes);
    expect_error(
        &bytes,
        bytes.len() as u64,
        FrameError::Length,
        "a total_len below 224",
    );
}

#[test]
fn condition_1_total_len_that_is_not_eight_aligned_is_rejected() {
    let mut bytes = sample_frame(5);
    let total = bytes.len() as u64;
    bytes[16..24].copy_from_slice(&(total + 4).to_le_bytes());
    reseal(&mut bytes);
    expect_error(
        &bytes,
        total + 4,
        FrameError::Length,
        "a total_len that is not 8-aligned",
    );
}

#[test]
fn condition_1_total_len_overflowing_the_file_is_rejected() {
    let bytes = sample_frame(5);
    let total = bytes.len() as u64;
    expect_error(
        &bytes,
        total - 8,
        FrameError::Length,
        "a frame that runs past the journal's preallocated length",
    );
}

#[test]
fn condition_2_header_magic_is_rejected() {
    let mut bytes = sample_frame(5);
    bytes[0] ^= 0x01;
    reseal(&mut bytes);
    expect_error(
        &bytes,
        bytes.len() as u64,
        FrameError::HeaderMagic,
        "a frame with the wrong header magic",
    );
}

#[test]
fn condition_2_storage_version_is_rejected() {
    let mut bytes = sample_frame(5);
    bytes[8..10].copy_from_slice(&2u16.to_le_bytes());
    reseal(&mut bytes);
    expect_error(
        &bytes,
        bytes.len() as u64,
        FrameError::HeaderMagic,
        "a frame declaring a future storage version",
    );
}

#[test]
fn condition_2_header_len_is_rejected_with_its_own_variant() {
    let mut bytes = sample_frame(5);
    bytes[10..12].copy_from_slice(&160u16.to_le_bytes());
    reseal(&mut bytes);
    expect_error(
        &bytes,
        bytes.len() as u64,
        FrameError::HeaderLen,
        "a frame declaring a header_len other than 176",
    );
}

#[test]
fn condition_3_wrong_journal_id_is_rejected() {
    let mut bytes = sample_frame(5);
    bytes[24] ^= 0xFF;
    reseal(&mut bytes);
    expect_error(
        &bytes,
        bytes.len() as u64,
        FrameError::JournalId,
        "a frame from a previous incarnation of a recycled extent",
    );
}

#[test]
fn condition_4_trailer_magic_is_rejected() {
    let mut bytes = sample_frame(5);
    let at = bytes.len() - FRAME_TRAILER_LEN;
    bytes[at] ^= 0x01;
    reseal(&mut bytes);
    expect_error(
        &bytes,
        bytes.len() as u64,
        FrameError::Trailer,
        "a frame with the wrong trailer magic",
    );
}

#[test]
fn condition_4_repeated_total_len_disagreeing_with_the_header_is_rejected() {
    let mut bytes = sample_frame(5);
    let at = bytes.len() - FRAME_TRAILER_LEN + 8;
    let wrong = bytes.len() as u64 + 8;
    bytes[at..at + 8].copy_from_slice(&wrong.to_le_bytes());
    reseal(&mut bytes);
    expect_error(
        &bytes,
        bytes.len() as u64,
        FrameError::Trailer,
        "a trailer whose repeated total_len disagrees with the header",
    );
}

#[test]
fn condition_5_frame_digest_is_rejected() {
    let mut bytes = sample_frame(5);
    let at = bytes.len() - 1;
    bytes[at] ^= 0x01;
    expect_error(
        &bytes,
        bytes.len() as u64,
        FrameError::FrameDigest,
        "a frame whose digest does not recompute",
    );
}

#[test]
fn condition_6_payload_digest_is_rejected() {
    let mut bytes = sample_frame(5);
    // Corrupt only the payload digest field and re-seal, so the frame digest
    // still recomputes and condition 6 is the only one left to fire.
    bytes[144] ^= 0x01;
    reseal(&mut bytes);
    expect_error(
        &bytes,
        bytes.len() as u64,
        FrameError::PayloadDigest,
        "a frame whose payload digest does not recompute",
    );
}

/// Without condition 7, any of 2^32 flag values yields a frame satisfying
/// every other condition that the writer never produced — exactly the byte
/// sequence the scope 5 charter directs a reviewer to construct.
#[test]
fn condition_7_a_frame_whose_only_defect_is_a_set_flag_bit_is_rejected() {
    for bit in 0..32u32 {
        let mut bytes = sample_frame(5);
        bytes[12..16].copy_from_slice(&(1u32 << bit).to_le_bytes());
        reseal(&mut bytes);
        expect_error(
            &bytes,
            bytes.len() as u64,
            FrameError::Flags,
            &format!("a frame whose only defect is flag bit {bit}"),
        );
    }
}

/// Without condition 8 the padding is a covert region that `frame_digest`
/// authenticates but nothing constrains.
#[test]
fn condition_8_a_frame_whose_only_defect_is_a_padding_byte_is_rejected() {
    let payload_len = 5usize;
    let padding = format::frame_padding_len(payload_len as u64) as usize;
    assert!(
        padding > 0,
        "this test needs a frame that actually has padding"
    );

    for offset in 0..padding {
        let mut bytes = sample_frame(payload_len);
        let at = FRAME_HEADER_LEN + payload_len + offset;
        assert_eq!(bytes[at], 0, "the writer must emit zero padding");
        bytes[at] = 0xFF;
        reseal(&mut bytes);
        expect_error(
            &bytes,
            bytes.len() as u64,
            FrameError::Padding,
            &format!("a frame whose only defect is padding byte {offset}"),
        );
    }
}

#[test]
fn a_payload_length_disagreeing_with_total_len_is_rejected() {
    // A payload_len that changes the derived total_len is a length failure...
    let mut bytes = sample_frame(5);
    bytes[136..144].copy_from_slice(&13u64.to_le_bytes());
    reseal(&mut bytes);
    expect_error(
        &bytes,
        bytes.len() as u64,
        FrameError::Length,
        "a frame whose payload_len disagrees with its total_len",
    );

    // ...and one that shifts the payload/padding boundary without changing
    // total_len is caught by the payload digest instead. Both are rejections;
    // asserting which one fires is the point of the taxonomy.
    let mut bytes = sample_frame(5);
    bytes[136..144].copy_from_slice(&6u64.to_le_bytes());
    reseal(&mut bytes);
    expect_error(
        &bytes,
        bytes.len() as u64,
        FrameError::PayloadDigest,
        "a frame whose payload_len shifts the payload boundary",
    );
}

#[test]
fn truncation_at_every_byte_offset_is_rejected_without_panicking() {
    let bytes = sample_frame(37);
    for cut in 0..bytes.len() {
        match verify_complete(&bytes[..cut], &JOURNAL_ID, bytes.len() as u64) {
            Ok(_) => panic!("a frame truncated at {cut} of {} verified", bytes.len()),
            Err(FrameError::Length) => {}
            Err(FrameError::HeaderMagic) => {}
            Err(other) => panic!(
                "truncation at {cut} must be rejected as a length or magic failure, got {other:?}"
            ),
        }
    }
    verify_complete(&bytes, &JOURNAL_ID, bytes.len() as u64).expect("the whole frame verifies");
}

#[test]
fn no_single_bit_mutation_ever_validates() {
    let bytes = sample_frame(0);
    assert_eq!(bytes.len() as u64, MIN_FRAME_LEN);
    for byte in 0..bytes.len() {
        for bit in 0..8 {
            let mut mutated = bytes.clone();
            mutated[byte] ^= 1 << bit;
            assert!(
                verify_complete(&mutated, &JOURNAL_ID, mutated.len() as u64).is_err(),
                "a frame with bit {bit} of byte {byte} flipped must never validate"
            );
        }
    }
}

#[test]
fn decode_rejects_trailing_bytes() {
    let mut bytes = sample_frame(5);
    bytes.push(0);
    match Frame::decode(&bytes, &JOURNAL_ID) {
        Err(FrameError::Length) => {}
        Err(other) => panic!("trailing bytes must be a length rejection, got {other:?}"),
        Ok(_) => panic!("a frame with trailing bytes must not decode"),
    }
}

#[test]
fn encode_refuses_a_header_whose_lengths_disagree_with_its_payload() {
    let payload = vec![1u8, 2, 3];
    let mut frame = Frame::decode(&sample_frame(3), &JOURNAL_ID).expect("decode");
    frame.payload = payload;
    frame.header.payload_len = 9;
    match frame.encode() {
        Err(FrameError::Length) => {}
        Err(other) => panic!("expected Length, got {other:?}"),
        Ok(_) => panic!("encode must not silently correct a disagreeing payload_len"),
    }
}

#[test]
fn encode_refuses_a_non_zero_flags_field() {
    let mut frame = Frame::decode(&sample_frame(3), &JOURNAL_ID).expect("decode");
    frame.header.flags = 1;
    match frame.encode() {
        Err(FrameError::Flags) => {}
        Err(other) => panic!("expected Flags, got {other:?}"),
        Ok(_) => panic!("the writer must never produce a frame with a set flag bit"),
    }
}

// ---------------------------------------------------------------------------
// Journal header
// ---------------------------------------------------------------------------

fn sample_journal_header() -> JournalHeader {
    JournalHeader {
        shard_index: 3,
        root_uuid: [0x61; 16],
        journal_id: JOURNAL_ID,
        first_shard_sequence: 900,
        preallocated_len: 1 << 20,
        created_at_micros: 1_700_000_000_000_000,
    }
}

#[test]
fn journal_header_round_trips_and_is_deterministic() {
    let header = sample_journal_header();
    let a = header.encode().expect("encode");
    let b = header.encode().expect("encode");
    assert_eq!(a, b, "journal header encoding must be deterministic");
    assert_eq!(a.len(), JOURNAL_HEADER_LEN);
    assert_eq!(JournalHeader::decode(&a).expect("decode"), header);
}

#[test]
fn journal_header_rejects_a_non_zero_padding_byte() {
    let header = sample_journal_header();
    // Two disjoint padding regions: the two reserved bytes after
    // `shard_index`, and everything past `header_digest`.
    for at in [14usize, 15, 104, 300, JOURNAL_HEADER_LEN - 1] {
        let mut bytes = header.encode().expect("encode");
        bytes[at] = 0xFF;
        // Re-seal the digest so padding is the only defect.
        let mut zeroed = bytes;
        let saved = zeroed;
        let mut for_digest = saved;
        for_digest[72..104].fill(0);
        let digest = format::digest(format::JOURNAL_HEADER_DIGEST_DOMAIN, &for_digest);
        zeroed = saved;
        zeroed[72..104].copy_from_slice(digest.as_bytes());

        match JournalHeader::decode(&zeroed) {
            Err(FrameError::Padding) => {}
            Err(other) => panic!("padding byte {at} must be rejected as Padding, got {other:?}"),
            Ok(_) => {
                panic!("a journal header with a non-zero padding byte at {at} must not decode")
            }
        }
    }
}

#[test]
fn journal_header_rejects_a_broken_digest_and_a_wrong_magic() {
    let header = sample_journal_header();

    let mut bytes = header.encode().expect("encode");
    bytes[72] ^= 0x01;
    match JournalHeader::decode(&bytes) {
        Err(FrameError::FrameDigest) => {}
        Err(other) => panic!("expected FrameDigest, got {other:?}"),
        Ok(_) => panic!("a journal header whose digest does not recompute must not decode"),
    }

    let mut bytes = header.encode().expect("encode");
    bytes[0] ^= 0x01;
    match JournalHeader::decode(&bytes) {
        Err(FrameError::HeaderMagic) => {}
        Err(other) => panic!("expected HeaderMagic, got {other:?}"),
        Ok(_) => panic!("a journal header with the wrong magic must not decode"),
    }
}

// ---------------------------------------------------------------------------
// Segment footer, manifest, CURRENT, FORMAT
// ---------------------------------------------------------------------------

#[test]
fn segment_footer_round_trips_and_locates_itself_from_end_of_file() {
    let footer = SegmentFooter {
        root_uuid: [0x71; 16],
        journal_id: JOURNAL_ID,
        generation: 4,
        first_shard_sequence: 10,
        last_shard_sequence: 12,
        frame_count: 3,
        offsets: vec![(10, 512, 224), (11, 736, 232), (12, 968, 224)],
    };
    let bytes = footer.encode().expect("encode");
    assert_eq!(bytes, footer.encode().expect("encode"), "deterministic");
    assert_eq!(SegmentFooter::decode(&bytes).expect("decode"), footer);

    let locator = &bytes[bytes.len() - format::SEGMENT_FOOTER_LOCATOR_LEN..];
    assert_eq!(
        SegmentFooter::decode_locator(locator).expect("locator"),
        bytes.len() as u64
    );
}

#[test]
fn segment_footer_rejects_a_table_that_does_not_ascend() {
    let footer = SegmentFooter {
        root_uuid: [0x71; 16],
        journal_id: JOURNAL_ID,
        generation: 4,
        first_shard_sequence: 10,
        last_shard_sequence: 11,
        frame_count: 2,
        offsets: vec![(11, 512, 224), (10, 736, 224)],
    };
    match footer.encode() {
        Err(FrameError::Payload(reason)) => assert!(reason.contains("ascend")),
        Err(other) => panic!("expected a Payload rejection, got {other:?}"),
        Ok(_) => panic!("an out-of-order offset table must not encode"),
    }
}

fn sample_manifest() -> Manifest {
    Manifest {
        root_uuid: [0x81; 16],
        generation: 3,
        base_generation: 0,
        retained_tail_ranges: vec![
            TailRange {
                generation: 1,
                first_shard_sequence: 0,
                last_shard_sequence: 9,
                filename: "1-0-9.seg".into(),
            },
            TailRange {
                generation: 2,
                first_shard_sequence: 10,
                last_shard_sequence: 19,
                filename: "2-10-19.seg".into(),
            },
        ],
        index_runs: vec![(1, "1.idx".into())],
        checkpoints: vec![(19, "19.checkpoint".into())],
        committed_shard_sequence: 19,
    }
}

#[test]
fn manifest_round_trips_and_is_deterministic() {
    let manifest = sample_manifest();
    let a = manifest.encode().expect("encode");
    assert_eq!(a, manifest.encode().expect("encode"));
    assert_eq!(Manifest::decode(&a).expect("decode"), manifest);
}

#[test]
fn manifest_refuses_a_filename_that_could_escape_the_shard_directory() {
    for hostile in ["../CURRENT", "a/b.seg", ".hidden", "", "with space.seg"] {
        let mut manifest = sample_manifest();
        manifest.index_runs = vec![(1, hostile.to_string())];
        match manifest.encode() {
            Err(FrameError::Payload(_)) => {}
            Err(other) => panic!("{hostile:?} must be a Payload rejection, got {other:?}"),
            Ok(_) => panic!("a manifest naming {hostile:?} must not encode"),
        }
    }
}

#[test]
fn manifest_rejects_a_broken_digest_and_trailing_bytes() {
    let manifest = sample_manifest();

    let mut bytes = manifest.encode().expect("encode");
    let at = bytes.len() - 1;
    bytes[at] ^= 0x01;
    match Manifest::decode(&bytes) {
        Err(FrameError::FrameDigest) => {}
        Err(other) => panic!("expected FrameDigest, got {other:?}"),
        Ok(_) => panic!("a manifest whose digest does not recompute must not decode"),
    }

    let mut bytes = manifest.encode().expect("encode");
    bytes.push(0);
    match Manifest::decode(&bytes) {
        Err(FrameError::FrameDigest) => {}
        Err(other) => panic!("expected FrameDigest, got {other:?}"),
        Ok(_) => panic!("a manifest with trailing bytes must not decode"),
    }
}

#[test]
fn current_pointer_and_format_marker_round_trip() {
    let pointer = format::CurrentPointer {
        root_uuid: [0x91; 16],
        generation: 12,
    };
    let bytes = pointer.encode().expect("encode");
    assert_eq!(bytes.len(), format::CURRENT_POINTER_LEN);
    assert_eq!(
        format::CurrentPointer::decode(&bytes).expect("decode"),
        pointer
    );

    let marker = format::FormatMarker {
        format_version: 2,
        storage_version: format::STORAGE_VERSION,
        shard_count: 4,
        root_uuid: [0x92; 16],
        created_at_micros: 1_700_000_000_000_000,
    };
    let bytes = marker.encode().expect("encode");
    assert_eq!(bytes.len(), format::FORMAT_MARKER_LEN);
    assert_eq!(
        format::FormatMarker::decode(&bytes).expect("decode"),
        marker
    );

    let mut broken = bytes;
    broken[20] ^= 0x01;
    match format::FormatMarker::decode(&broken) {
        Err(FrameError::FrameDigest) => {}
        Err(other) => panic!("expected FrameDigest, got {other:?}"),
        Ok(_) => panic!("a corrupt FORMAT must not decode"),
    }
}

/// Magic constants and digest domains are frozen bytes, and `format.rs` is not
/// the only file that declares them: A2 owns the checkpoint and index-run
/// formats and declares four constants of its own. The lead asked that the
/// distinctness check be widened rather than left to luck, so this test spans
/// every file that declares one.
#[test]
fn no_magic_or_domain_collides_across_the_crate() {
    let magics: Vec<(&str, [u8; 8])> = vec![
        ("FRAME_MAGIC", format::FRAME_MAGIC),
        ("FRAME_TRAILER_MAGIC", format::FRAME_TRAILER_MAGIC),
        ("JOURNAL_MAGIC", format::JOURNAL_MAGIC),
        ("SEGMENT_FOOTER_MAGIC", format::SEGMENT_FOOTER_MAGIC),
        ("MANIFEST_MAGIC", format::MANIFEST_MAGIC),
        ("CURRENT_MAGIC", format::CURRENT_MAGIC),
        ("CHECKPOINT_MAGIC", format::CHECKPOINT_MAGIC),
        ("FORMAT_MAGIC", format::FORMAT_MAGIC),
        ("INDEX_RUN_MAGIC", levcs_store::index::INDEX_RUN_MAGIC),
        (
            "INDEX_RUN_TRAILER_MAGIC",
            levcs_store::index::INDEX_RUN_TRAILER_MAGIC,
        ),
    ];
    for (i, (left_name, left)) in magics.iter().enumerate() {
        for (right_name, right) in &magics[i + 1..] {
            assert_ne!(
                left, right,
                "{left_name} and {right_name} are the same eight bytes; two on-disk \
                 structures would be indistinguishable"
            );
        }
    }

    let domains: Vec<(&str, &[u8])> = vec![
        ("FRAME_DIGEST_DOMAIN", format::FRAME_DIGEST_DOMAIN),
        (
            "FRAME_PAYLOAD_DIGEST_DOMAIN",
            format::FRAME_PAYLOAD_DIGEST_DOMAIN,
        ),
        (
            "JOURNAL_HEADER_DIGEST_DOMAIN",
            format::JOURNAL_HEADER_DIGEST_DOMAIN,
        ),
        (
            "SEGMENT_FOOTER_DIGEST_DOMAIN",
            format::SEGMENT_FOOTER_DIGEST_DOMAIN,
        ),
        ("MANIFEST_DIGEST_DOMAIN", format::MANIFEST_DIGEST_DOMAIN),
        ("CURRENT_DIGEST_DOMAIN", format::CURRENT_DIGEST_DOMAIN),
        ("CHECKPOINT_DIGEST_DOMAIN", format::CHECKPOINT_DIGEST_DOMAIN),
        ("FORMAT_DIGEST_DOMAIN", format::FORMAT_DIGEST_DOMAIN),
        (
            "INDEX_RUN_DIGEST_DOMAIN",
            levcs_store::index::INDEX_RUN_DIGEST_DOMAIN,
        ),
        ("INDEX_BLOOM_DOMAIN", levcs_store::index::INDEX_BLOOM_DOMAIN),
    ];
    for (name, domain) in &domains {
        assert_eq!(
            domain.last(),
            Some(&0u8),
            "{name} must be NUL-terminated so no domain is a prefix of another"
        );
    }
    for (i, (left_name, left)) in domains.iter().enumerate() {
        for (right_name, right) in &domains[i + 1..] {
            assert_ne!(
                left, right,
                "{left_name} and {right_name} are the same domain; a digest over one \
                 structure would be a valid digest over the other"
            );
        }
    }
}

/// The accessor seam A2 filed an interface change request for: recovery step 9
/// walks the per-repository event chain, and it must read the link out of the
/// frame rather than recompute it from a second source.
#[test]
fn payload_facts_expose_the_event_chain_a2_verifies() {
    for (bytes, name) in golden_frames() {
        let frame = Frame::decode(&bytes, &generator::GOLDEN_JOURNAL_ID).expect("decode");
        if frame.payload.is_empty() {
            continue;
        }
        let payload = TransactionFramePayloadV1::decode_canonical(&frame.payload)
            .unwrap_or_else(|e| panic!("payload {name} must decode: {e}"));
        let facts = payload
            .facts()
            .unwrap_or_else(|e| panic!("facts {name}: {e}"));

        assert_eq!(facts.source_kind, payload.source_kind());
        assert_eq!(
            facts.previous_event_digest,
            payload.previous_event_digest(),
            "the chain link must come from the embedded event, not a copy"
        );
        assert_eq!(facts.event_digest, payload.event_digest().expect("digest"));
        assert_eq!(
            facts,
            TransactionFramePayloadV1::decode_facts(&frame.payload).expect("decode_facts"),
            "decode_facts and facts must agree on frame {name}"
        );
        assert_ne!(
            facts.event_digest, facts.previous_event_digest,
            "an event must not chain to itself"
        );
    }
}

// ---------------------------------------------------------------------------
// Journal: append, fence counting, tail scan
// ---------------------------------------------------------------------------

struct Fixture {
    _dir: tempfile::TempDir,
    active: std::path::PathBuf,
    counters: Arc<DurabilityCounters>,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let active = dir.path().join("active");
    std::fs::create_dir_all(&active).expect("mkdir");
    Fixture {
        _dir: dir,
        active,
        counters: Arc::new(DurabilityCounters::default()),
    }
}

fn new_journal(fixture: &Fixture, preallocated: u64) -> Journal {
    Journal::create(
        &fixture.active,
        JOURNAL_ID,
        0,
        0,
        [0x61; 16],
        preallocated,
        1_700_000_000_000_000,
        Arc::clone(&fixture.counters),
    )
    .expect("create journal")
}

fn frame_for(journal: &mut Journal, payload: Vec<u8>) -> Frame {
    let shard_sequence = journal.assign_shard_sequence();
    let payload_len = payload.len() as u64;
    Frame {
        header: FrameHeader {
            flags: 0,
            total_len: format::frame_total_len(payload_len),
            journal_id: journal.journal_id(),
            shard_sequence,
            repo_sequence: shard_sequence,
            namespace: [0x11; 32],
            operation_id: [0x22; 16],
            operation_digest: levcs_core::ObjectId([0x33; 32]),
            payload_len,
            payload_digest: format::digest(format::FRAME_PAYLOAD_DIGEST_DOMAIN, &payload),
        },
        payload,
    }
}

/// Phase 1 exit criterion "no per-object fsync", as a counter assertion rather
/// than a claim about the code (scope 5 charter item 7).
#[test]
fn ten_thousand_transactions_fence_once_per_group() {
    let _serial = serial();
    const TRANSACTIONS: u64 = 10_000;
    const GROUP: usize = 64;

    let fixture = fixture();
    let mut journal = new_journal(&fixture, 32 * 1024 * 1024);
    // Creating a journal fences its header; measure only the append path.
    let baseline = journal.counters();

    let mut group_count = 0u64;
    let mut appended = 0u64;
    while appended < TRANSACTIONS {
        let mut frames = Vec::with_capacity(GROUP);
        for _ in 0..GROUP.min((TRANSACTIONS - appended) as usize) {
            frames.push(frame_for(&mut journal, vec![0xEE; 96]));
        }
        appended += frames.len() as u64;
        journal
            .append_group_and_fence(&frames)
            .expect("group must append and fence");
        group_count += 1;
    }

    let counters = journal.counters();
    let fences = counters.fdatasync - baseline.fdatasync;
    assert_eq!(
        fences, group_count,
        "exactly one fdatasync per group: observed {fences} fences for {group_count} groups"
    );
    assert!(
        fences < TRANSACTIONS,
        "the fence count must be far below the transaction count, got {fences} for {TRANSACTIONS}"
    );
    assert_eq!(
        counters.short_writes, 0,
        "no short write is expected on a healthy file"
    );
}

#[test]
fn a_journal_reopens_at_its_write_cursor_and_the_scan_matches() {
    let _serial = serial();
    let fixture = fixture();
    let path;
    let cursor;
    {
        let mut journal = new_journal(&fixture, 1 << 20);
        path = journal.path().to_path_buf();
        let frames: Vec<Frame> = (0..5)
            .map(|i| frame_for(&mut journal, vec![i as u8; 40]))
            .collect();
        journal.append_group_and_fence(&frames).expect("append");
        cursor = journal.cursor();
        assert_eq!(journal.frame_index().len(), 5);
    }

    let (reopened, scan) =
        Journal::open(&path, &[0x61; 16], Arc::new(DurabilityCounters::default())).expect("reopen");
    assert_eq!(reopened.cursor(), cursor);
    assert_eq!(scan.frames.len(), 5);
    assert_eq!(scan.stop_offset, cursor);
    assert_eq!(reopened.next_shard_sequence(), 5);
    // The tail of a preallocated journal reads as zeros, which is not a frame.
    assert_eq!(scan.stop, TailStop::NotAFrame);
}

#[test]
fn a_journal_opened_under_the_wrong_root_uuid_is_refused() {
    let _serial = serial();
    let fixture = fixture();
    let path = {
        let journal = new_journal(&fixture, 1 << 20);
        journal.path().to_path_buf()
    };
    let message = match Journal::open(&path, &[0x62; 16], Arc::new(DurabilityCounters::default())) {
        Err(e) => e.to_string(),
        Ok(_) => panic!("a journal from another root must be refused"),
    };
    assert!(
        message.contains("root uuid"),
        "the refusal must name the root uuid mismatch, got: {message}"
    );
}

#[test]
fn the_scan_stops_at_a_torn_frame_and_never_adopts_the_complete_frame_after_it() {
    let _serial = serial();
    use std::io::{Seek, SeekFrom, Write};

    let fixture = fixture();
    let path;
    let torn_at;
    let good_after;
    {
        let mut journal = new_journal(&fixture, 1 << 20);
        path = journal.path().to_path_buf();
        let frames: Vec<Frame> = (0..3)
            .map(|i| frame_for(&mut journal, vec![i as u8; 40]))
            .collect();
        journal.append_group_and_fence(&frames).expect("append");
        // Frame 1's offset, and frame 2's, from the journal's own index.
        torn_at = journal.frame_index()[1].1;
        good_after = journal.frame_index()[2].1;
    }

    // Tear frame 1 in place. Frame 2 is untouched and remains complete and
    // checksum-valid — the exact crash image scope 3.8 step 6 is about.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open");
    file.seek(SeekFrom::Start(torn_at + 200)).expect("seek");
    file.write_all(&[0xFF; 8]).expect("write");
    drop(file);

    let (_journal, scan) =
        Journal::open(&path, &[0x61; 16], Arc::new(DurabilityCounters::default())).expect("reopen");

    assert_eq!(
        scan.frames.len(),
        1,
        "only the frame before the tear may be adopted"
    );
    assert_eq!(scan.stop_offset, torn_at);
    assert!(
        good_after > torn_at,
        "the untouched frame really is after the tear"
    );
    match scan.stop {
        TailStop::Incomplete(FrameError::FrameDigest) => {}
        other => panic!("the torn frame must stop the scan on its digest, got {other:?}"),
    }
}

#[test]
fn a_group_whose_sequences_are_not_contiguous_is_refused_before_any_write() {
    let _serial = serial();
    let fixture = fixture();
    let mut journal = new_journal(&fixture, 1 << 20);
    let baseline = journal.counters();

    let mut a = frame_for(&mut journal, vec![1; 8]);
    let b = frame_for(&mut journal, vec![2; 8]);
    a.header.shard_sequence = 5;

    let err = journal
        .append_group_and_fence(&[a, b])
        .expect_err("a sequence gap must be refused");
    assert!(err.to_string().contains("contiguous"));
    assert_eq!(
        journal.counters().bytes_written,
        baseline.bytes_written,
        "a refused group must not have written a byte"
    );
}

#[test]
fn a_group_that_does_not_fit_the_preallocated_journal_is_refused_not_poisoned() {
    let _serial = serial();
    let fixture = fixture();
    let mut journal = new_journal(&fixture, JOURNAL_HEADER_LEN as u64 + MIN_FRAME_LEN);
    let big = frame_for(&mut journal, vec![7; 4096]);
    match journal.append_group_and_fence(&[big]) {
        Err(levcs_store::StoreError::LimitExceeded { limit, .. }) => {
            assert_eq!(limit, "journal_preallocate_bytes");
        }
        Err(other) => panic!("expected LimitExceeded, got {other:?}"),
        Ok(_) => panic!("a group larger than the journal must not append"),
    }
    assert!(
        journal.poison_cause().is_none(),
        "refusing before writing anything is not a poisoning condition"
    );
}

#[test]
fn group_formation_is_bounded_by_transactions_bytes_and_idle_delay() {
    let _serial = serial();
    let fixture = fixture();
    let mut journal = new_journal(&fixture, 1 << 20);

    // Transaction bound.
    let mut builder = GroupBuilder::new(3, 1 << 20, Duration::from_secs(3600));
    for _ in 0..3 {
        builder
            .push(frame_for(&mut journal, vec![0; 8]))
            .expect("fits");
    }
    assert!(
        builder.is_closed(),
        "the transaction ceiling closes a group"
    );
    assert!(
        builder.push(frame_for(&mut journal, vec![0; 8])).is_err(),
        "a full group hands the frame back"
    );
    assert_eq!(builder.take().len(), 3);

    // Byte bound.
    let mut builder = GroupBuilder::new(1_000, 700, Duration::from_secs(3600));
    builder
        .push(frame_for(&mut journal, vec![0; 8]))
        .expect("first frame is always admitted");
    let mut admitted = 1;
    while builder.push(frame_for(&mut journal, vec![0; 8])).is_ok() {
        admitted += 1;
        assert!(admitted < 10, "the byte ceiling must close the group");
    }
    assert!(builder.bytes() <= 700);

    // Idle bound.
    let mut builder = GroupBuilder::new(1_000, 1 << 20, Duration::from_millis(1));
    builder
        .push(frame_for(&mut journal, vec![0; 8]))
        .expect("fits");
    assert!(!builder.is_closed() || builder.is_expired());
    std::thread::sleep(Duration::from_millis(3));
    assert!(
        builder.is_expired() && builder.is_closed(),
        "the idle delay closes a group that neither other bound would"
    );
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(128))]

    /// Encode/decode round-trips for an arbitrary payload, and the encoding is
    /// deterministic.
    #[test]
    fn encode_decode_round_trips(payload in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
        let payload_len = payload.len() as u64;
        let frame = Frame {
            header: FrameHeader {
                flags: 0,
                total_len: format::frame_total_len(payload_len),
                journal_id: JOURNAL_ID,
                shard_sequence: 1,
                repo_sequence: 2,
                namespace: [3; 32],
                operation_id: [4; 16],
                operation_digest: levcs_core::ObjectId([5; 32]),
                payload_len,
                payload_digest: format::digest(format::FRAME_PAYLOAD_DIGEST_DOMAIN, &payload),
            },
            payload,
        };
        let bytes = frame.encode().expect("encode");
        proptest::prop_assert_eq!(&bytes, &frame.encode().expect("encode"));
        let decoded = Frame::decode(&bytes, &JOURNAL_ID).expect("decode");
        proptest::prop_assert_eq!(decoded, frame);
    }

    /// Truncation at any offset is rejected, and never panics.
    #[test]
    fn truncation_at_any_offset_is_rejected(
        payload_len in 0usize..512,
        cut in 0usize..4096,
    ) {
        let bytes = sample_frame(payload_len);
        let cut = cut % bytes.len();
        let result = verify_complete(&bytes[..cut], &JOURNAL_ID, bytes.len() as u64);
        proptest::prop_assert!(result.is_err());
    }

    /// Arbitrary bytes never verify as a frame, and never panic the verifier.
    #[test]
    fn arbitrary_bytes_never_verify(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..1024)) {
        let result = verify_complete(&bytes, &JOURNAL_ID, bytes.len() as u64);
        proptest::prop_assert!(result.is_err());
    }
}

// ---------------------------------------------------------------------------
// The drive seam and the Wave A failpoints
//
// `drive.rs` adds frame construction and nothing else: every append here goes
// through the same `journal::Journal::append_group_and_fence` the engine will
// call, and every failpoint fires inside it. These tests assert the *physical*
// half of each Wave A row; A3's crash matrix owns the classification against
// the frozen oracle.
// ---------------------------------------------------------------------------

#[cfg(all(feature = "store-internals", feature = "failpoints"))]
mod drive_seam {
    use levcs_store::drive::points::{arm, disarm, Failpoint, FailpointAction, Wave};
    use levcs_store::drive::{faults, DriveRecovery, ShardDrive};
    use levcs_store::recovery::ActiveJournalDisposition;
    use levcs_store::NamespaceId;

    use super::serial;

    fn root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    fn append_one(
        drive: &mut ShardDrive,
        repo_sequence: u64,
    ) -> Result<Vec<u64>, levcs_store::StoreError> {
        let frame = drive
            .build_frame(NamespaceId([0x44; 32]), repo_sequence, vec![0x99; 64])
            .expect("build frame");
        drive.append_group_and_fence(&[frame])
    }

    fn recover(dir: &std::path::Path) -> DriveRecovery {
        ShardDrive::reopen_through_recovery(dir, 0).expect("reopen through recovery")
    }

    #[test]
    fn a_clean_run_seals_installs_and_recovers_every_sequence() {
        let _serial = serial();
        let dir = root();
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            for i in 0..5 {
                append_one(&mut drive, i).expect("append");
            }
            let generation = drive.seal_and_install().expect("seal");
            assert_eq!(generation, 1);
            for i in 5..8 {
                append_one(&mut drive, i).expect("append after rotation");
            }
        }

        let recovered = recover(dir.path());
        assert_eq!(
            recovered.adopted_shard_sequences,
            (0..8).collect::<Vec<u64>>(),
            "every fenced frame must be recovered, across the seal boundary"
        );
        assert_eq!(
            recovered.tail_stop_offset, None,
            "a clean tail is not a torn one"
        );
        assert_eq!(recovered.quarantined_bytes, 0);
        assert!(!recovered.used_manifest_fallback, "CURRENT validates");
        // The seal completed *including* its unlink, so the journal opened
        // after it is live. This is the assertion the adopted set cannot make:
        // `0..8` is equally consistent with a journal misclassified as already
        // sealed and its three frames coming from somewhere else.
        assert_eq!(
            recovered.active_journal(),
            Some(&ActiveJournalDisposition::Replay),
            "a journal opened after a completed seal is live, not sealed"
        );
        assert!(!recovered.completed_interrupted_seal());
    }

    #[test]
    fn one_fence_per_group_through_the_drive() {
        let _serial = serial();
        let dir = root();
        let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
        let baseline = drive.counters();

        for group in 0..4u64 {
            let frames: Vec<_> = (0..8)
                .map(|i| {
                    drive
                        .build_frame(NamespaceId([0x44; 32]), group * 8 + i, vec![0x11; 32])
                        .expect("build")
                })
                .collect();
            drive.append_group_and_fence(&frames).expect("append");
        }

        let counters = drive.counters();
        assert_eq!(
            counters.fdatasync - baseline.fdatasync,
            4,
            "32 transactions in 4 groups must fence exactly 4 times"
        );
    }

    #[test]
    fn before_append_leaves_no_bytes() {
        let _serial = serial();
        let dir = root();
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append_one(&mut drive, 0).expect("first append");
            arm(&_serial, Failpoint::BeforeAppend, FailpointAction::Fail);
            append_one(&mut drive, 1).expect_err("BeforeAppend must fail the group");
            assert!(drive.poison_cause().is_some(), "the shard must poison");
        }
        let recovered = recover(dir.path());
        assert_eq!(
            recovered.adopted_shard_sequences,
            vec![0],
            "a failpoint before the append leaves no bytes for the second frame"
        );
        assert_eq!(recovered.tail_stop_offset, None);
    }

    #[test]
    fn a_torn_frame_write_stops_recovery_at_the_tear() {
        let _serial = serial();
        let dir = root();
        let journal_id;
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append_one(&mut drive, 0).expect("first append");
            journal_id = drive.journal_id();
            arm(
                &_serial,
                Failpoint::DuringFrameWriteTorn,
                FailpointAction::Fail,
            );
            append_one(&mut drive, 1).expect_err("a torn write must fail the group");
        }
        let recovered = recover(dir.path());
        assert_eq!(
            recovered.adopted_shard_sequences,
            vec![0],
            "a partial frame is never adopted"
        );
        assert!(
            recovered.tail_stop_offset.is_some(),
            "a torn tail must be reported"
        );
        assert!(
            recovered.quarantined_bytes > 0,
            "the discarded tail bytes must be quarantined for forensics"
        );
        assert_eq!(
            recovered.active_journal(),
            Some(&ActiveJournalDisposition::Replay),
            "a torn tail is a live journal with a hole, never a completed seal"
        );

        // Where the bytes went, not merely that some were kept. This field's
        // entire purpose is telling an operator — and A3's external ACK
        // reconciliation — which file to look at after a crash, so asserting
        // only `is_some()` would let it become a path that names nothing.
        let quarantined = recovered
            .report
            .quarantined
            .as_ref()
            .expect("a quarantined tail must say where it was written");
        let stop_offset = recovered
            .tail_stop_offset
            .expect("a torn tail reports where it stopped");
        assert_eq!(
            quarantined.parent(),
            Some(dir.path().join("quarantine").as_path()),
            "the record belongs in the root's quarantine directory, not beside \
             the journal it came from"
        );
        assert_eq!(
            quarantined.file_name().and_then(|n| n.to_str()),
            Some(format!("{}-{stop_offset}.tail", hex::encode(journal_id)).as_str()),
            "scope 3.8 step 7 names the record by journal and offset, which is \
             what makes two crashes at different offsets separate evidence"
        );
        assert!(
            quarantined.exists(),
            "the named record must actually be there"
        );
        assert_eq!(
            std::fs::metadata(quarantined).expect("stat").len(),
            recovered.quarantined_bytes,
            "the byte count and the file must describe the same record; they \
             come from the one call that wrote it and cannot disagree"
        );
    }

    #[test]
    fn a_whole_unfenced_frame_is_physically_present() {
        let _serial = serial();
        let dir = root();
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            arm(&_serial, Failpoint::AfterFrameWrite, FailpointAction::Fail);
            append_one(&mut drive, 0).expect_err("AfterFrameWrite must fail the group");
        }
        // WholeFrameUnfenced is `EitherWhole`: recovery may or may not see it
        // after a power cut. In-process the bytes are in the page cache, so
        // this asserts only that the frame is whole when it is there — never
        // that it is guaranteed to be there.
        let recovered = recover(dir.path());
        assert!(
            recovered.adopted_shard_sequences == vec![0]
                || recovered.adopted_shard_sequences.is_empty(),
            "an unfenced whole frame is either wholly present or wholly absent, got {:?}",
            recovered.adopted_shard_sequences
        );
    }

    #[test]
    fn a_fenced_frame_survives_a_writer_panic_after_the_fence() {
        let _serial = serial();
        let dir = root();
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append_one(&mut drive, 0).expect("first append");
            arm(
                &_serial,
                Failpoint::WriterPanicAfterFence,
                FailpointAction::Panic,
            );
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = append_one(&mut drive, 1);
            }));
            assert!(panicked.is_err(), "the writer must panic and unwind");
            // The drive is dropped here, running every destructor on the
            // unwind path. A `Drop` that truncated, rewound the cursor, or
            // flushed a buffer would corrupt the fenced prefix — which is the
            // whole differential this row certifies.
        }
        let recovered = recover(dir.path());
        assert_eq!(
            recovered.adopted_shard_sequences,
            vec![0, 1],
            "a fenced frame survives a panic-unwind death of the writer"
        );
    }

    #[test]
    fn a_failed_fence_is_terminal_and_is_never_retried() {
        let _serial = serial();
        let dir = root();
        let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
        let baseline = drive.counters();

        arm(&_serial, Failpoint::FenceFailed, FailpointAction::Fail);
        let err = append_one(&mut drive, 0).expect_err("a failed fence must fail the group");
        assert!(err.to_string().contains("poisoned"), "got: {err}");

        assert_eq!(
            drive.counters().fdatasync - baseline.fdatasync,
            0,
            "a fence that fails is never attempted a second time: on Linux the error \
             may be reported once with the dirty pages already dropped, so a retry can \
             return success while the data is gone"
        );
        assert!(drive.poison_cause().is_some());
        // Every later append is refused until close-and-reopen through recovery.
        append_one(&mut drive, 1).expect_err("a poisoned shard admits no further append");
    }

    /// The same terminality through the physical fault seam rather than the
    /// failpoint: `sys::Fault::FenceEio` models a device that failed the
    /// flush. `fdatasync` is called exactly once and never again.
    #[test]
    fn an_eio_fence_is_terminal_and_is_never_retried() {
        let _serial = serial();
        let dir = root();
        let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
        let baseline = drive.counters();

        faults::arm(&_serial, faults::Fault::FenceEio);
        let err = append_one(&mut drive, 0).expect_err("an EIO fence must fail the group");
        assert!(err.to_string().contains("poisoned"), "got: {err}");

        assert_eq!(
            drive.counters().fdatasync - baseline.fdatasync,
            1,
            "the fence is attempted exactly once: on Linux the error may be reported \
             once with the dirty pages already dropped, so a retry can return success \
             while the data is permanently gone"
        );
        assert!(drive.poison_cause().is_some());
        append_one(&mut drive, 1).expect_err("a poisoned shard admits no further append");
    }

    /// A fault armed for a *positioned read* must survive every write and
    /// fence in front of it and fire at the `pread`. Scope 3.8 step 5 requires
    /// an `EIO` in the tail region be treated as "the tail ends here", never
    /// as a fatal store error: getting that wrong turns an ordinary crash into
    /// an unopenable store.
    ///
    /// Driven at the journal layer because the fault is one-shot and
    /// `reopen_through_recovery` reads `FORMAT` and the journal header first —
    /// an `EIO` there is a different failure from an `EIO` in the tail, and
    /// this test is about the tail.
    #[test]
    fn a_read_eio_ends_the_tail_and_is_never_a_fatal_store_error() {
        use levcs_store::journal::{Journal, TailStop};
        use levcs_store::types::DurabilityCounters;
        use std::sync::Arc;

        let _serial = serial();
        let dir = root();
        let (path, root_uuid) = {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            for i in 0..3 {
                append_one(&mut drive, i).expect("append");
            }
            (drive.journal_path().to_path_buf(), drive.root_uuid())
        };

        let (journal, clean) =
            Journal::open(&path, &root_uuid, Arc::new(DurabilityCounters::default()))
                .expect("open");
        assert_eq!(clean.frames.len(), 3, "the healthy scan sees every frame");

        // The next positioned read fails. The scan must stop, not fail.
        faults::arm(&_serial, faults::Fault::ReadEio);
        let scan = journal.scan_from_start();
        match scan.stop {
            TailStop::ReadError => {}
            other => panic!("an EIO in the tail region must end the tail, got {other:?}"),
        }
        assert!(
            scan.frames.len() < 3,
            "the frame whose read failed is not adopted"
        );
        faults::disarm(&_serial);
    }

    /// A fault armed for a *directory* fsync likewise reaches `fsync_dir` and
    /// fails the operation that depends on the name becoming durable, rather
    /// than being swallowed by the write that precedes it.
    #[test]
    fn a_dir_sync_eio_fails_the_operation_that_needed_the_name() {
        let _serial = serial();
        let dir = root();
        let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
        append_one(&mut drive, 0).expect("append");

        faults::arm(&_serial, faults::Fault::DirSyncEio);
        let err = drive
            .seal_and_install()
            .expect_err("a failed directory fsync must fail the seal");
        assert!(
            err.to_string().contains("directory fsync"),
            "the failure must name the directory fsync, got: {err}"
        );
        faults::disarm(&_serial);
    }

    #[test]
    fn a_short_write_leaves_a_durable_prefix_and_poisons() {
        let _serial = serial();
        let dir = root();
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append_one(&mut drive, 0).expect("first append");
            faults::arm(&_serial, faults::Fault::ShortWrite { prefix_bytes: 64 });
            append_one(&mut drive, 1).expect_err("a short append must poison the shard");
            assert!(drive.counters().short_writes > 0, "the counter must see it");
        }
        let recovered = recover(dir.path());
        assert_eq!(
            recovered.adopted_shard_sequences,
            vec![0],
            "the short write left a durable prefix, and completeness — not a \
             return value — decided the second frame's outcome"
        );
    }

    #[test]
    fn every_wave_a_failpoint_is_reachable_through_the_drive() {
        let _serial = serial();
        // The nine Wave A rows are exactly the ones this seam must be able to
        // fire. Each is armed and driven; a row that never fires would leave a
        // hole in the crash matrix. No catch-all arm: each name is listed.
        for point in Failpoint::ALL
            .iter()
            .copied()
            .filter(|p| p.wave() == Wave::A)
        {
            let dir = root();
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            arm(&_serial, point, FailpointAction::Fail);
            let result = append_one(&mut drive, 0);
            assert!(
                result.is_err(),
                "Wave A failpoint {} must be reachable from the drive seam",
                point.name()
            );
            assert!(
                drive
                    .poison_cause()
                    .is_some_and(|c| c.contains(point.name())),
                "the poison cause must name {}",
                point.name()
            );
            disarm(&_serial);
        }
    }

    #[test]
    fn recovery_falls_back_when_current_does_not_validate() {
        let _serial = serial();
        let dir = root();
        let current;
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            for i in 0..3 {
                append_one(&mut drive, i).expect("append");
            }
            drive.seal_and_install().expect("generation 1");
            for i in 3..6 {
                append_one(&mut drive, i).expect("append");
            }
            drive.seal_and_install().expect("generation 2");
            current = drive.shard_paths().current();
        }

        // Corrupt the pointer, leaving a valid predecessor behind.
        let mut bytes = std::fs::read(&current).expect("read CURRENT");
        let at = bytes.len() - 1;
        bytes[at] ^= 0xFF;
        std::fs::write(&current, &bytes).expect("write CURRENT");

        let recovered = recover(dir.path());
        assert!(
            recovered.used_manifest_fallback,
            "a corrupt CURRENT must fall back to the newest valid manifest, not fail"
        );
        assert_eq!(
            recovered.adopted_shard_sequences,
            (0..6).collect::<Vec<u64>>()
        );
        assert_eq!(
            recovered.active_journal(),
            Some(&ActiveJournalDisposition::Replay),
            "falling back to an older manifest generation must not change what \
             the active journal is; a fallback that also reclassified the \
             journal would silently drop or duplicate its frames"
        );
        assert!(!recovered.completed_interrupted_seal());
    }
}

// ---------------------------------------------------------------------------
// The drive recovery seam (scope 4-A1 deliverable 5, scope 3.8)
// ---------------------------------------------------------------------------
//
// These tests exist because of an adversarial-review finding: the first
// `drive::reopen_through_recovery` reimplemented a simplified recovery instead
// of calling `recovery.rs`, so a corrupted frame inside a manifest-referenced
// segment, a journal belonging to another shard, and an interrupted seal all
// "recovered" successfully. Every test here drives
// `ShardDrive::reopen_through_recovery` — the entry point the crash matrix
// uses — and never a helper called directly, because a helper that is correct
// and uncalled is not a safeguard.
//
// This module is gated on `store-internals` alone, not on `failpoints`: the
// gate runs a `bench-harness,store-internals` configuration in which a
// `failpoints`-gated module would silently not exist.

#[cfg(feature = "store-internals")]
mod drive_recovery_seam {
    use levcs_store::drive::{DriveRecovery, ShardDrive};
    use levcs_store::format::{JournalHeader, JOURNAL_HEADER_LEN};
    use levcs_store::recovery::ActiveJournalDisposition;
    use levcs_store::segment::{self, RootLayout, SegmentReader, ShardPaths};
    use levcs_store::types::DurabilityCounters;
    use levcs_store::{NamespaceId, StoreError};
    use std::path::{Path, PathBuf};

    use super::serial;

    const NS: NamespaceId = NamespaceId([0x44; 32]);

    fn root() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    /// Append `count` frames whose `repo_sequence` continues from `from`.
    fn append(drive: &mut ShardDrive, from: u64, count: u64) {
        for i in 0..count {
            let frame = drive
                .build_frame(NS, from + i, vec![0x99; 64])
                .expect("build frame");
            drive.append_group_and_fence(&[frame]).expect("append");
        }
    }

    fn recover(dir: &Path) -> Result<DriveRecovery, StoreError> {
        ShardDrive::reopen_through_recovery(dir, 0)
    }

    fn paths_of(dir: &Path) -> ShardPaths {
        RootLayout::new(dir).shard(0)
    }

    fn only_file(dir: &Path, extension: &str) -> PathBuf {
        let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| entry.expect("entry").path())
            .filter(|path| path.extension().is_some_and(|e| e == extension))
            .collect();
        assert_eq!(
            found.len(),
            1,
            "expected exactly one .{extension} under {}, found {found:?}",
            dir.display()
        );
        found.pop().expect("one")
    }

    /// Rewrite a journal header through the production codec, so the file that
    /// results is one the store would accept if only the mutated field were
    /// legal. Mutating bytes in place would fail the header digest instead,
    /// and would prove nothing about the binding check.
    fn rewrite_journal_header(path: &Path, mutate: impl FnOnce(&mut JournalHeader)) {
        let mut bytes = std::fs::read(path).expect("read journal");
        let mut header =
            JournalHeader::decode(&bytes[..JOURNAL_HEADER_LEN]).expect("decode journal header");
        mutate(&mut header);
        let encoded = header.encode().expect("encode journal header");
        bytes[..JOURNAL_HEADER_LEN].copy_from_slice(&encoded);
        std::fs::write(path, &bytes).expect("write journal");
    }

    // -----------------------------------------------------------------------
    // 1. A frame inside a manifest-referenced segment is validated, not
    //    trusted because the footer names it.
    // -----------------------------------------------------------------------

    #[test]
    fn a_corrupt_frame_inside_a_referenced_segment_fails_recovery() {
        let _serial = serial();
        let dir = root();
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append(&mut drive, 0, 4);
            drive.seal_and_install().expect("seal");
        }

        // The segment footer still validates: this mutates one frame, inside
        // the frame region, and touches neither the footer nor its digest.
        // The reviewer's repro was exactly this, and it returned
        // `recovery_ok=true` with sequences 0,1,2,3.
        let segment = only_file(&paths_of(dir.path()).segments(), "seg");
        let mut bytes = std::fs::read(&segment).expect("read segment");
        bytes[JOURNAL_HEADER_LEN] ^= 0xFF;
        std::fs::write(&segment, &bytes).expect("write segment");

        // The footer is still readable, which is the point: footer validity is
        // not frame validity.
        SegmentReader::open(&segment, &segment_root_uuid(dir.path()))
            .expect("the footer still validates, which is why this case existed");

        let error = recover(dir.path()).expect_err("a corrupt frame must fail recovery");
        assert!(
            error.to_string().contains("frame header magic"),
            "recovery must name the completeness condition that rejected the \
             frame, got: {error}"
        );
    }

    fn segment_root_uuid(dir: &Path) -> [u8; 16] {
        segment::read_format(&RootLayout::new(dir))
            .expect("read FORMAT")
            .root_uuid
    }

    // -----------------------------------------------------------------------
    // 2 and 3. Journal identity binding.
    // -----------------------------------------------------------------------

    #[test]
    fn a_journal_from_another_shard_fails_recovery() {
        let _serial = serial();
        let dir = root();
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 2).expect("create");
            append(&mut drive, 0, 3);
        }

        // The file is otherwise perfect: correct root, correct digests, whole
        // frames. Only the shard it belongs to is wrong, and nothing inside a
        // frame records that — the journal header is the sole binding.
        let journal = only_file(&paths_of(dir.path()).active(), "journal");
        rewrite_journal_header(&journal, |header| header.shard_index = 1);

        let error =
            recover(dir.path()).expect_err("a journal from another shard must fail recovery");
        assert!(
            error
                .to_string()
                .contains("belongs to shard 1, not shard 0"),
            "the refusal must name the shard mismatch, got: {error}"
        );
    }

    #[test]
    fn a_journal_bound_to_another_root_fails_recovery() {
        let _serial = serial();
        let dir = root();
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append(&mut drive, 0, 3);
        }

        let journal = only_file(&paths_of(dir.path()).active(), "journal");
        rewrite_journal_header(&journal, |header| header.root_uuid = [0xAB; 16]);

        let error = recover(dir.path())
            .expect_err("a journal copied in from another instance must fail recovery");
        assert!(
            error.to_string().contains("does not match this store root"),
            "the refusal must name the root binding, got: {error}"
        );
    }

    // -----------------------------------------------------------------------
    // 4. The interrupted seal (scope 3.4, crash between steps 5 and 6).
    // -----------------------------------------------------------------------

    /// Reconstructs the crash image scope 3.4 describes: the manifest
    /// generation naming the segment is durable, and the `active/` name still
    /// points at the same inode because the final unlink was lost.
    ///
    /// Built by hand rather than by a failpoint because there is no failpoint
    /// between `install_manifest` and `unlink_sealed_journal`; the image is
    /// exact — same inode, same `journal_id`, same bytes — and asserting on a
    /// hand-built image is only unsound when the image is not the one the
    /// crash produces.
    #[test]
    fn an_interrupted_seal_adopts_its_frames_exactly_once() {
        let _serial = serial();
        let dir = root();
        let paths = paths_of(dir.path());
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append(&mut drive, 0, 4);
            drive.seal_and_install().expect("seal");
        }

        let segment = only_file(&paths.segments(), "seg");
        let fresh = only_file(&paths.active(), "journal");
        std::fs::remove_file(&fresh).expect("remove the post-rotation journal");
        let stale = paths.active().join("0.journal");
        std::fs::hard_link(&segment, &stale).expect("restore the lost active name");

        let recovered = recover(dir.path()).expect("an interrupted seal must recover");

        // The decision, asserted directly. An adopted set of `0,1,2,3` is
        // consistent with *both* dispositions — a correctly finished seal and
        // a journal that happened to be empty — so the adoption set alone
        // cannot distinguish "classified correctly" from "classified at all".
        // That indistinguishability is precisely how the missing
        // `classify_active_journal` call stayed invisible.
        assert!(
            recovered.completed_interrupted_seal(),
            "the seal completed through the manifest install and only its final \
             unlink was lost; recovery must say so, got {:?}",
            recovered.active_journal()
        );
        match recovered.active_journal() {
            Some(ActiveJournalDisposition::AlreadySealed {
                segment: named,
                first_shard_sequence,
                last_shard_sequence,
            }) => {
                assert_eq!(
                    named, &segment,
                    "the disposition must name the segment that proved the seal \
                     completed, so an operator is not left to guess which file it was"
                );
                assert_eq!(*first_shard_sequence, 0);
                assert_eq!(*last_shard_sequence, 3);
            }
            // No catch-all: every other state is named, per the scope 5 charter.
            Some(ActiveJournalDisposition::Replay) => panic!(
                "replaying a journal the manifest already covers adopts every \
                 frame twice; this is the exact P1 the review found"
            ),
            None => panic!("a journal is present under active/ and must be classified"),
        }

        assert_eq!(
            recovered.adopted_shard_sequences,
            vec![0, 1, 2, 3],
            "the frames come from the manifest exactly once"
        );
        assert!(
            !stale.exists(),
            "recovery must finish the interrupted seal's unlink, not leave the \
             stale active name for the next reopen to trip over"
        );
    }

    /// The opposite crash point, and the reason the two are variants rather
    /// than a bool: between scope 3.4 steps 4 and 5 a segment exists that *no*
    /// manifest generation references, and the `active/` journal is still the
    /// authority. Classifying this one as `AlreadySealed` drops every frame
    /// the manifest does not yet name — acknowledged data loss, the opposite
    /// error from a double adoption and just as invisible in the adopted set
    /// alone.
    #[test]
    fn an_orphan_segment_leaves_the_active_journal_the_authority() {
        let _serial = serial();
        let dir = root();
        let paths = paths_of(dir.path());
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append(&mut drive, 0, 2);
            // A completed seal, so a manifest generation exists for
            // `classify_active_journal` to search.
            //
            // **Do not "simplify" the setup by dropping this.** With no
            // manifest at all the classifier is never consulted — the seam
            // short-circuits to `Replay` because nothing could prove a seal
            // completed — and every assertion below still passes while
            // testing nothing. A test that passes for the wrong reason is the
            // exact failure this whole record is about.
            drive.seal_and_install().expect("seal");
            append(&mut drive, 2, 2);
            // Now scope 3.4 step 4 for the *second* seal — link the live
            // journal into `segments/` — and crash before step 5. No manifest
            // generation names it.
            std::fs::hard_link(drive.journal_path(), paths.segments().join("2-2-3.seg"))
                .expect("link the orphan");
        }

        let recovered = recover(dir.path()).expect("an orphan segment must not fail recovery");
        assert_eq!(
            recovered.active_journal(),
            Some(&ActiveJournalDisposition::Replay),
            "only segments the selected manifest *references* can prove a seal \\
             completed; an orphan proves nothing and the journal is still the \\
             authority"
        );
        assert!(!recovered.completed_interrupted_seal());
        assert_eq!(
            recovered.adopted_shard_sequences,
            vec![0, 1, 2, 3],
            "taking the orphan as sealed would have dropped sequences 2 and 3, \\
             which are fenced and acknowledged and which no manifest names"
        );
        assert!(
            only_file(&paths.active(), "journal").exists(),
            "this seal never became visible, so its active name must not be unlinked"
        );
    }

    /// A shard with no `active/` journal at all — the image a crash between
    /// sealing and opening the next journal leaves.
    ///
    /// `None` is a third state. Collapsing it into `Replay` would make "there
    /// was nothing to classify" indistinguishable from "it was classified as
    /// live", which is the same conflation the two dispositions exist to
    /// prevent one level down.
    #[test]
    fn a_shard_with_no_active_journal_has_no_disposition_at_all() {
        let _serial = serial();
        let dir = root();
        let paths = paths_of(dir.path());
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append(&mut drive, 0, 4);
            drive.seal_and_install().expect("seal");
        }
        std::fs::remove_file(only_file(&paths.active(), "journal"))
            .expect("remove the post-rotation journal");

        let recovered = recover(dir.path()).expect("a shard with no active journal must recover");
        assert_eq!(
            recovered.active_journal(),
            None,
            "there was no journal to classify, which is not the same fact as \
             classifying one as live"
        );
        assert!(!recovered.completed_interrupted_seal());
        assert_eq!(
            recovered.adopted_shard_sequences,
            vec![0, 1, 2, 3],
            "the sealed frames come from the manifest"
        );
        assert_eq!(recovered.tail_stop_offset, None);
        assert_eq!(recovered.quarantined_bytes, 0);
    }

    // -----------------------------------------------------------------------
    // 5. The two sequence verifiers, and their two distinct faults.
    // -----------------------------------------------------------------------

    #[test]
    fn a_shard_sequence_duplicate_fails_recovery() {
        let _serial = serial();
        use levcs_core::ObjectId;
        use levcs_store::format::{self, Frame, FrameHeader, FRAME_PAYLOAD_DIGEST_DOMAIN};
        use levcs_store::journal::Journal;
        use std::sync::Arc;

        let dir = root();
        let paths = paths_of(dir.path());
        let root_uuid;
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append(&mut drive, 0, 4);
            drive.seal_and_install().expect("seal");
            root_uuid = drive.root_uuid();
        }

        // A manifest-referenced segment covering 0..=3, and an `active/`
        // journal that starts again at 3. Every file validates, every frame is
        // whole, the journal binds to this root and this shard, and its
        // `journal_id` is not the segment's — so it is genuinely a live
        // journal, not an interrupted seal. The only thing wrong is that
        // `shard_sequence` 3 appears twice, which nothing below step 9 can
        // see.
        std::fs::remove_file(only_file(&paths.active(), "journal"))
            .expect("remove the post-rotation journal");
        let counters = Arc::new(DurabilityCounters::default());
        let journal_id = [0x5D; 16];
        let mut journal = Journal::create(
            &paths.active(),
            journal_id,
            3,
            0,
            root_uuid,
            1 << 20,
            1_700_000_000_000_000,
            Arc::clone(&counters),
        )
        .expect("create an overlapping journal");
        let payload = vec![0x99; 64];
        let payload_len = payload.len() as u64;
        let frame = Frame {
            header: FrameHeader {
                flags: 0,
                total_len: format::frame_total_len(payload_len),
                journal_id,
                shard_sequence: 3,
                repo_sequence: 3,
                namespace: *NS.as_bytes(),
                operation_id: [0x5E; 16],
                operation_digest: ObjectId([0x5F; 32]),
                payload_len,
                payload_digest: format::digest(FRAME_PAYLOAD_DIGEST_DOMAIN, &payload),
            },
            payload,
        };
        journal
            .append_group_and_fence(&[frame])
            .expect("append the overlapping frame");
        drop(journal);

        let error = recover(dir.path()).expect_err("a duplicated shard_sequence must fail");
        let rendered = error.to_string();
        assert!(
            rendered.contains("shard sequence: duplicate shard_sequence 3"),
            "the shard domain must report its own fault, got: {rendered}"
        );
        assert!(
            !rendered.contains("repository sequence"),
            "a shard-domain fault must never arrive as a repository fault: {rendered}"
        );
    }

    #[test]
    fn a_repo_sequence_gap_fails_recovery_with_its_own_fault() {
        let _serial = serial();
        let dir = root();
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            for repo_sequence in [0u64, 1, 3] {
                let frame = drive
                    .build_frame(NS, repo_sequence, vec![0x99; 64])
                    .expect("build frame");
                drive.append_group_and_fence(&[frame]).expect("append");
            }
        }

        let error = recover(dir.path()).expect_err("a repo_sequence gap must fail recovery");
        let rendered = error.to_string();
        assert!(
            rendered.contains("repository sequence: repo_sequence gap"),
            "the repository domain must report its own fault, got: {rendered}"
        );
        assert!(
            rendered.contains("expected 2, observed 3"),
            "the fault must name the gap it found, got: {rendered}"
        );
        assert!(
            !rendered.contains("shard sequence"),
            "the shard sequence is contiguous here; reporting it would be the \
             two domains being interchanged: {rendered}"
        );
    }

    // -----------------------------------------------------------------------
    // 6. The drive path and A2's production entry points must not diverge.
    // -----------------------------------------------------------------------

    /// The regression guard for the defect class itself.
    ///
    /// Both packages passed their own tests while the seam between them was
    /// never exercised. This composes A2's entry points independently and
    /// asserts they conclude what `reopen_through_recovery` concluded, so the
    /// two cannot silently drift again.
    #[test]
    fn the_drive_path_and_a2s_recovery_agree_on_a_valid_store() {
        let _serial = serial();
        use levcs_store::journal::Journal;
        use levcs_store::recovery::{self, ActiveJournalDisposition, SegmentFooterValidator};
        use std::sync::Arc;

        let dir = root();
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append(&mut drive, 0, 3);
            drive.seal_and_install().expect("seal");
            append(&mut drive, 3, 3);
        }

        // The drive path first, so its exclusive LOCK is released before the
        // independent composition reads the same files.
        let recovered = recover(dir.path()).expect("a valid store must recover");

        let root_uuid = segment_root_uuid(dir.path());
        let paths = paths_of(dir.path());
        let selection = recovery::resolve_manifest(
            &paths,
            &root_uuid,
            &SegmentFooterValidator::new(root_uuid),
            8,
        )
        .expect("resolve_manifest")
        .expect("a sealed shard has a manifest generation");

        let mut expected = Vec::new();
        for range in &selection.manifest.retained_tail_ranges {
            let reader = SegmentReader::open(&paths.segments().join(&range.filename), &root_uuid)
                .expect("open segment");
            for (sequence, _, _) in &reader.footer().offsets {
                expected.push(*sequence);
            }
        }

        let journal_path = only_file(&paths.active(), "journal");
        let (journal, scan) = Journal::open(
            &journal_path,
            &root_uuid,
            Arc::new(DurabilityCounters::default()),
        )
        .expect("open the active journal");
        let disposition = recovery::classify_active_journal(
            &paths,
            &selection.manifest,
            &journal.journal_id(),
            &root_uuid,
        )
        .expect("classify");
        assert_eq!(
            disposition,
            ActiveJournalDisposition::Replay,
            "a journal opened after a completed seal is live, not sealed"
        );
        for frame in &scan.frames {
            expected.push(frame.shard_sequence);
        }

        assert_eq!(
            recovered.adopted_shard_sequences, expected,
            "drive::reopen_through_recovery and A2's production recovery must \
             conclude the same thing about the same bytes"
        );
        // Agreement about the *decision* and not only about its effect. A2's
        // composition above concluded `Replay`; the seam must have concluded
        // the same thing, and asserting that is the half the adopted set
        // cannot express.
        assert_eq!(
            recovered.active_journal(),
            Some(&disposition),
            "the two paths must agree about what the active journal is, not \
             only about which sequences came out"
        );
        assert!(!recovered.completed_interrupted_seal());
        assert_eq!(
            recovered.adopted_shard_sequences,
            (0..6).collect::<Vec<u64>>()
        );
        assert!(!recovered.used_manifest_fallback);
        assert_eq!(
            recovered.report.manifest_generation,
            Some(selection.generation)
        );
        assert!(recovered.report.ready);
        assert_eq!(
            recovered.report.checkpoint_sequence, None,
            "no checkpoint was installed; an empty checkpoint load must not \
             report a sequence it did not read"
        );
    }

    // -----------------------------------------------------------------------
    // Recovery step 3, against real crash images rather than a hand-built
    // checkpoint directory.
    // -----------------------------------------------------------------------

    #[test]
    fn a_checkpoint_bounds_replay_without_losing_a_single_sequence() {
        let _serial = serial();
        let dir = root();
        let paths = paths_of(dir.path());
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append(&mut drive, 0, 4);
            drive.checkpoint().expect("install a checkpoint");
            append(&mut drive, 4, 2);
        }
        assert_eq!(
            std::fs::read_dir(paths.checkpoints())
                .expect("checkpoints dir")
                .count(),
            1,
            "the drive must actually install a checkpoint file; a crash image \
             with no checkpoint directory cannot exercise recovery step 3"
        );

        let recovered = recover(dir.path()).expect("a checkpointed store must recover");
        assert_eq!(
            recovered.report.checkpoint_sequence,
            Some(3),
            "the checkpoint installed at shard_sequence 3 must be the one \
             recovery loaded; without this the test passes just as well when \
             the checkpoint is ignored entirely"
        );
        assert!(!recovered.report.offline_rebuild_required);
        assert_eq!(
            recovered.active_journal(),
            Some(&ActiveJournalDisposition::Replay),
            "the journal was never sealed; it is live"
        );
        assert_eq!(
            recovered.adopted_shard_sequences,
            (0..6).collect::<Vec<u64>>(),
            "bounding the replay must not cost a sequence its place in the \
             adopted set, or the external ACK reconciliation would report \
             acknowledged loss for every checkpointed operation"
        );
    }

    #[test]
    fn a_corrupt_newest_checkpoint_falls_back_to_its_predecessor() {
        let _serial = serial();
        let dir = root();
        let paths = paths_of(dir.path());
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append(&mut drive, 0, 4);
            drive.checkpoint().expect("generation at sequence 3");
            append(&mut drive, 4, 2);
            drive.checkpoint().expect("generation at sequence 5");
        }

        let newest = paths.checkpoints().join("5.checkpoint");
        let mut bytes = std::fs::read(&newest).expect("read the newest checkpoint");
        let at = bytes.len() - 1;
        bytes[at] ^= 0xFF;
        std::fs::write(&newest, &bytes).expect("corrupt the newest checkpoint");

        let recovered = recover(dir.path())
            .expect("a corrupt newest generation must fall back, not refuse to open");
        assert_eq!(
            recovered.report.checkpoint_sequence,
            Some(3),
            "recovery must have fallen back to the predecessor generation, not \
             loaded the corrupt one and not silently loaded none at all"
        );
        assert!(!recovered.report.offline_rebuild_required);
        assert_eq!(
            recovered.active_journal(),
            Some(&ActiveJournalDisposition::Replay)
        );
        assert_eq!(
            recovered.adopted_shard_sequences,
            (0..6).collect::<Vec<u64>>()
        );
    }

    #[test]
    fn a_checkpoint_directory_where_every_generation_fails_refuses_to_open() {
        let _serial = serial();
        let dir = root();
        let paths = paths_of(dir.path());
        {
            let mut drive = ShardDrive::create(dir.path(), 0, 1).expect("create");
            append(&mut drive, 0, 4);
            drive.checkpoint().expect("generation at sequence 3");
            append(&mut drive, 4, 2);
            drive.checkpoint().expect("generation at sequence 5");
        }

        for entry in std::fs::read_dir(paths.checkpoints()).expect("checkpoints dir") {
            let path = entry.expect("entry").path();
            let mut bytes = std::fs::read(&path).expect("read checkpoint");
            let at = bytes.len() - 1;
            bytes[at] ^= 0xFF;
            std::fs::write(&path, &bytes).expect("corrupt checkpoint");
        }

        let error = recover(dir.path()).expect_err(
            "a shard whose every checkpoint generation fails must refuse to open \
             rather than replay from sequence zero as though it were fresh",
        );
        assert!(
            matches!(error, StoreError::RecoveryRequired),
            "the refusal must be the offline-rebuild one, got: {error}"
        );

        // This test reaches for `load_checkpoint` directly while every one of
        // its neighbours asserts through the seam. That is deliberate and is
        // not drift.
        //
        // The refusal is an `Err`, so no `DriveRecovery` — and therefore no
        // `ShardRecoveryReport` — comes back to assert on. Rather than invent
        // a way to return a report alongside an error purely to make this test
        // look like the others, the decision behind the refusal is pinned
        // against the same on-disk image: a `RecoveryRequired` raised for any
        // other reason would leave `offline_rebuild_required` false here and
        // fail. The asymmetry is a property of error paths, not of this test.
        let root_uuid = segment_root_uuid(dir.path());
        let mut report = levcs_store::recovery::ShardRecoveryReport::new(0);
        let load = levcs_store::recovery::load_checkpoint(&paths.checkpoints(), &root_uuid, 0, 2)
            .expect("load_checkpoint");
        let loaded =
            levcs_store::recovery::checkpoint_for_recovery(load, &root_uuid, 0, &mut report);
        assert!(loaded.is_none());
        assert!(
            report.offline_rebuild_required,
            "every generation failed validation, so step 3 must demand an \
             explicit offline rebuild and never an unbounded scan"
        );
        assert!(!report.ready);
    }
}
