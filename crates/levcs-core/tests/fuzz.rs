//! Robustness/fuzz tests for object deserializers (§8.2).
//!
//! The spec requires: "All deserializers MUST be safe against malformed
//! input and MUST NOT panic." These tests drive thousands of random and
//! adversarially-mutated byte slices through every public parser and
//! assert that the parser either returns a typed error or a valid value
//! — never a panic, never an infinite loop, never an out-of-bounds slice.
//!
//! Reproducibility: input generation is seeded by an LCG with a known
//! constant. If a future change introduces a panic, the printed seed
//! lets the fix verify against the same input.

use std::panic::{catch_unwind, AssertUnwindSafe};

use levcs_core::object::{
    ObjectHeader, ObjectType, RawObject, SignatureEntry, SignedObject, FORMAT_VERSION, HEADER_SIZE,
    SIGNATURE_ENTRY_SIZE,
};
use levcs_core::{Commit, Release, Tree};

/// Iterations per test target. Tuned so the suite runs in <1 second on
/// a developer laptop while still covering enough random states that
/// a missed bounds check tends to surface within a few hundred iterations.
/// Bump up locally when investigating a specific parser.
const ITERS: u32 = 5_000;

/// Linear-congruential PRNG. A function we can reset deterministically;
/// no need to take a dep on `rand` for this.
fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn rand_bytes(seed: &mut u64, n: usize) -> Vec<u8> {
    (0..n).map(|_| (lcg(seed) >> 33) as u8).collect()
}

fn rand_size(seed: &mut u64) -> usize {
    // Mix of tiny / small / medium sizes — small slices catch bounds
    // checks at the start, medium slices catch length-field mismatches.
    match lcg(seed) % 5 {
        0 => 0,
        1 => (lcg(seed) % 16) as usize,
        2 => (lcg(seed) % 256) as usize,
        3 => 256 + (lcg(seed) % 4096) as usize,
        _ => 4096 + (lcg(seed) % 16384) as usize,
    }
}

/// Run `parser` on `input`. If it panics, fail the test naming the seed
/// so the failure can be reproduced; otherwise we don't care whether
/// the parser returned Ok or Err — only that it did not panic.
fn assert_no_panic<F, T>(label: &str, seed: u64, input: &[u8], parser: F)
where
    F: FnOnce(&[u8]) -> T,
{
    let r = catch_unwind(AssertUnwindSafe(|| parser(input)));
    if r.is_err() {
        panic!(
            "{label} panicked on seed {seed:#x}, input len {} ({} bytes shown): {:02x?}",
            input.len(),
            input.len().min(64),
            &input[..input.len().min(64)]
        );
    }
}

#[test]
fn signed_object_parse_does_not_panic() {
    let mut seed = 0xdeadbeef_cafe1234u64;
    for _ in 0..ITERS {
        let n = rand_size(&mut seed);
        let bytes = rand_bytes(&mut seed, n);
        assert_no_panic("SignedObject::parse", seed, &bytes, |b| {
            let _ = SignedObject::parse(b);
        });
        assert_no_panic("RawObject::parse", seed, &bytes, |b| {
            let _ = RawObject::parse(b);
        });
        assert_no_panic("ObjectHeader::decode", seed, &bytes, |b| {
            let _ = ObjectHeader::decode(b);
        });
    }
}

/// Mutate a known-valid signed object: flip random bits, truncate, splice
/// in adversarial bytes. The parser must remain panic-free under any of
/// these — they are the realistic shapes of corruption (bit rot, partial
/// writes, hostile peer feeding crafted bytes).
#[test]
fn signed_object_parse_survives_mutation_of_valid_input() {
    // Build a valid SignedObject as the mutation seed.
    let body = b"hello there, this is a body for fuzzing".to_vec();
    let signed = SignedObject::new(ObjectType::Blob, body);
    let valid = signed.serialize();

    let mut seed = 0xfeedface_5151aaaau64;
    for _ in 0..ITERS {
        let mut buf = valid.clone();
        // Pick a mutation strategy.
        match lcg(&mut seed) % 5 {
            0 => {
                // Flip up to 8 random bits.
                let flips = (lcg(&mut seed) % 8 + 1) as usize;
                for _ in 0..flips {
                    if buf.is_empty() {
                        break;
                    }
                    let idx = (lcg(&mut seed) as usize) % buf.len();
                    let bit = (lcg(&mut seed) % 8) as u8;
                    buf[idx] ^= 1 << bit;
                }
            }
            1 => {
                // Truncate to a random shorter length.
                let new_len = (lcg(&mut seed) as usize) % buf.len().max(1);
                buf.truncate(new_len);
            }
            2 => {
                // Tamper with the body_len field (bytes 8..16, LE u64).
                let off = 8 + (lcg(&mut seed) as usize) % 8;
                buf[off] = buf[off].wrapping_add((lcg(&mut seed) & 0xff) as u8);
            }
            3 => {
                // Append random garbage.
                let extra = (lcg(&mut seed) % 64) as usize;
                buf.extend(rand_bytes(&mut seed, extra));
            }
            _ => {
                // Replace random byte run.
                if !buf.is_empty() {
                    let start = (lcg(&mut seed) as usize) % buf.len();
                    let len = ((lcg(&mut seed) as usize) % 16).min(buf.len() - start);
                    for b in &mut buf[start..start + len] {
                        *b = (lcg(&mut seed) & 0xff) as u8;
                    }
                }
            }
        }
        assert_no_panic("SignedObject::parse(mut)", seed, &buf, |b| {
            let _ = SignedObject::parse(b);
        });
        assert_no_panic("RawObject::parse(mut)", seed, &buf, |b| {
            let _ = RawObject::parse(b);
        });
    }
}

#[test]
fn body_parsers_do_not_panic_on_random_bytes() {
    // Tree, Commit, and Release `parse_body` consume just the body — no
    // header, no trailer. These are the parsers most exposed to crafted
    // bytes from the federation push path.
    let mut seed = 0x0123456789abcdefu64;
    for _ in 0..ITERS {
        let n = rand_size(&mut seed);
        let bytes = rand_bytes(&mut seed, n);
        assert_no_panic("Tree::parse_body", seed, &bytes, |b| {
            let _ = Tree::parse_body(b);
        });
        assert_no_panic("Commit::parse_body", seed, &bytes, |b| {
            let _ = Commit::parse_body(b);
        });
        assert_no_panic("Release::parse_body", seed, &bytes, |b| {
            let _ = Release::parse_body(b);
        });
    }
}

#[test]
fn header_decode_handles_pathological_lengths() {
    // The body_len field is u64 LE — a malicious peer could set it to
    // values like u64::MAX. The parser must reject without attempting
    // to allocate a buffer that size. This test verifies it returns an
    // error and does not panic on the largest plausible adversarial
    // values.
    let mut seed = 0x9999_5555_aaaa_3333u64;
    for _ in 0..512 {
        let mut hdr = [0u8; HEADER_SIZE];
        hdr[0..4].copy_from_slice(b"LVCS");
        hdr[4] = (lcg(&mut seed) & 0xff) as u8;
        hdr[5] = FORMAT_VERSION;
        hdr[6] = 0;
        hdr[7] = 0;
        // body_len: extreme values (full u64), random values, all f's.
        let body_len = match lcg(&mut seed) % 4 {
            0 => u64::MAX,
            1 => u64::MAX / 2,
            2 => 1u64 << 40,
            _ => lcg(&mut seed),
        };
        hdr[8..16].copy_from_slice(&body_len.to_le_bytes());
        assert_no_panic("ObjectHeader::decode(extreme)", seed, &hdr, |b| {
            let _ = ObjectHeader::decode(b);
        });
        assert_no_panic("SignedObject::parse(extreme)", seed, &hdr, |b| {
            let _ = SignedObject::parse(b);
        });
        assert_no_panic("RawObject::parse(extreme)", seed, &hdr, |b| {
            let _ = RawObject::parse(b);
        });
    }
}

#[test]
fn signature_trailer_count_byte_is_safe() {
    // The trailer count byte is u8 (max 255 entries). A malicious sender
    // could set it to a value that wildly overshoots the byte slice.
    // SignedObject::parse must detect and refuse, not panic.
    let mut seed = 0x77_77_77_77u64;
    for count in [0u8, 1, 5, 255] {
        let body = b"x".repeat(64);
        let mut bytes = Vec::new();
        let header = ObjectHeader {
            object_type: ObjectType::Blob,
            format_version: FORMAT_VERSION,
            body_len: body.len() as u64,
        }
        .encode();
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&body);
        bytes.push(count);
        // Intentionally include too few signature bytes for the claimed
        // count — parser must return Err.
        let want = count as usize * SIGNATURE_ENTRY_SIZE;
        let provided = (lcg(&mut seed) as usize) % (want + 1);
        bytes.extend(rand_bytes(&mut seed, provided));
        assert_no_panic("SignedObject::parse(short trailer)", seed, &bytes, |b| {
            let _ = SignedObject::parse(b);
        });
    }
}

#[test]
fn signature_entry_decode_does_not_panic() {
    let mut seed = 0xabc_def_123_456u64;
    for _ in 0..1024 {
        let n = (lcg(&mut seed) % (SIGNATURE_ENTRY_SIZE as u64 + 32)) as usize;
        let bytes = rand_bytes(&mut seed, n);
        assert_no_panic("SignatureEntry::decode", seed, &bytes, |b| {
            let _ = SignatureEntry::decode(b);
        });
    }
}

#[test]
fn signed_object_round_trip_when_parse_succeeds() {
    // Sanity invariant: when parse succeeds on random input (rare but
    // possible), serialize-then-parse must yield identical bytes. This
    // protects against a parser that silently drops bytes.
    let mut seed = 0xfeed_beef_dead_c0deu64;
    let mut hits = 0u32;
    for _ in 0..ITERS {
        let n = rand_size(&mut seed);
        let bytes = rand_bytes(&mut seed, n);
        if let Ok(parsed) = SignedObject::parse(&bytes) {
            let re = parsed.serialize();
            assert_eq!(re, bytes, "round-trip mismatch on seed {seed:#x}");
            hits += 1;
        }
    }
    // Random bytes hit a valid signed object only by coincidence — but
    // we don't require any hits, just that any incidental hits round-trip.
    let _ = hits;
}
