//! Property tests for the pack codec.
//!
//! The hand-rolled fuzz suite in `fuzz.rs` covers panic-resistance under
//! random and mutated bytes. This file complements it with *structured*
//! round-trip properties: build valid packs by construction, encode them,
//! decode the result, and assert the entries come back identical.
//!
//! When proptest finds a counterexample it shrinks toward the smallest
//! input that still fails, which is far more debuggable than the seed-
//! based fuzz harness.

use levcs_protocol::Pack;
use proptest::collection::vec;
use proptest::prelude::*;

/// One pack entry: an object_type byte (1..=5 — Blob/Tree/Commit/Release/
/// Authority per pack.rs) and a body of up to ~10 KiB.
fn entry_strategy() -> impl Strategy<Value = (u8, Vec<u8>)> {
    (1u8..=5u8, vec(any::<u8>(), 0..10_240))
}

proptest! {
    /// Round-trip: any sequence of valid entries encodes to bytes that
    /// decode back to those same entries (object_type + body).
    #[test]
    fn pack_roundtrip_arbitrary_entries(
        es in vec(entry_strategy(), 0..16)
    ) {
        let mut pk = Pack::new();
        for (t, b) in &es {
            pk.push(*t, b.clone());
        }
        let encoded = pk.encode();
        let decoded = Pack::decode(&encoded).expect("valid pack must decode");
        prop_assert_eq!(decoded.entries.len(), es.len());
        for (i, (t, b)) in es.iter().enumerate() {
            prop_assert_eq!(decoded.entries[i].object_type, *t);
            prop_assert_eq!(&decoded.entries[i].bytes, b);
        }
    }

    /// `decode_prefix` consumes exactly the bytes the encoder emitted —
    /// trailing bytes appended after a valid pack must be reported as
    /// unconsumed, not silently swallowed.
    #[test]
    fn pack_decode_prefix_reports_consumed_bytes_correctly(
        es in vec(entry_strategy(), 0..8),
        tail in vec(any::<u8>(), 0..64),
    ) {
        let mut pk = Pack::new();
        for (t, b) in &es {
            pk.push(*t, b.clone());
        }
        let mut encoded = pk.encode();
        let pack_len = encoded.len();
        encoded.extend_from_slice(&tail);
        let (decoded, consumed) = Pack::decode_prefix(&encoded)
            .expect("valid pack prefix must decode");
        prop_assert_eq!(consumed, pack_len);
        prop_assert_eq!(decoded.entries.len(), es.len());
    }

    /// Single-byte truncation of a valid pack must never panic.
    /// (The fuzz suite covers random truncation; this nails down the
    /// shrunk one-byte-short case proptest gravitates toward.)
    #[test]
    fn pack_truncated_by_one_does_not_panic(
        es in vec(entry_strategy(), 1..8)
    ) {
        let mut pk = Pack::new();
        for (t, b) in &es {
            pk.push(*t, b.clone());
        }
        let encoded = pk.encode();
        let truncated = &encoded[..encoded.len() - 1];
        let _ = Pack::decode(truncated);
    }
}
