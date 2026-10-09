//! Pack files (§4.2.1).
//!
//! ```text
//! Header:
//!   magic           4 bytes  "LVPK"
//!   version         4 bytes  uint32 LE
//!   object_count    8 bytes  uint64 LE
//!
//! For each object:
//!   type            1 byte   1=Blob, 2=Tree, 3=Commit, 4=Release, 5=Authority
//!   size            8 bytes  uncompressed size (LE u64)
//!   flags           1 byte   bit 0 zstd-compressed, bit 1 delta-encoded
//!   if delta:
//!     base_hash     32 bytes
//!   data            variable
//! ```
//!
//! Bit 0 (zstd): when set, `data` is a zstd frame whose decompressed image
//! is the object's `size` bytes. Bit 1 (delta): when set, `data` is a zstd
//! frame whose dictionary is the *uncompressed* image of an earlier entry
//! in the same pack (identified by `base_hash`); decompression yields the
//! object's `size` bytes. FLAG_DELTA implies FLAG_ZSTD — there is no
//! defined raw-delta encoding.
//!
//! Delta resolution is positional: a delta entry's `base_hash` must match
//! some entry that already appeared earlier in the same pack. This makes
//! decoding a single linear pass and rules out cycles by construction.
//!
//! Compression and delta selection are encoder-side optimizations; the wire
//! format is exact in either direction. The current encoder uses
//!   * zstd level 3 (libzstd's default — balanced ratio/throughput),
//!   * a 256-byte threshold below which framing overhead beats savings,
//!   * "previous entry of same object_type" as the delta-base candidate,
//! and only emits the compressed/delta form when the result is strictly
//! smaller than the alternative. This keeps encode O(N total bytes) and
//! decode at zstd-with-dictionary speed (essentially the same as plain
//! zstd decode — the dictionary is just a prefix to the LZ window).

use std::collections::HashMap;

use byteorder::{ByteOrder, LittleEndian};
use thiserror::Error;

pub const PACK_MAGIC: [u8; 4] = *b"LVPK";
pub const PACK_VERSION: u32 = 1;
const FLAG_ZSTD: u8 = 0b0000_0001;
const FLAG_DELTA: u8 = 0b0000_0010;
/// Compress entries whose object bytes are at least this large; below the
/// threshold the framing overhead outweighs the savings.
pub const COMPRESSION_THRESHOLD: usize = 256;
/// zstd compression level used when the encoder chooses to compress. Level
/// 3 is libzstd's default — a sensible balance of throughput and ratio.
pub const COMPRESSION_LEVEL: i32 = 3;

/// Default ceiling on a single object's *uncompressed* size when decoding
/// a pack. The recorded `size` field is read straight off the wire and is
/// otherwise used as the destination capacity for decompression — a
/// hostile peer can declare `size = 1 TiB` against a tiny zstd frame and
/// trigger a multi-gigabyte allocation before any data has been
/// validated. Capping `size` at decode time short-circuits that.
///
/// 256 MiB is generous for normal repository content (source files, even
/// large binaries) while remaining well below practical RAM limits on a
/// modest VPS. Callers that genuinely need to move larger blobs should
/// use `Pack::decode_prefix_with_limit` and pick their own ceiling.
pub const DEFAULT_MAX_OBJECT_BYTES: usize = 256 * 1024 * 1024;

/// Default ceiling on a whole pack's decoded size, and on its entries. The
/// per-object ceiling alone left the total open: each zstd entry can expand
/// a few kilobytes into its full size, so a small pack could decode to many
/// times the memory there is. A receiver that knows its budget passes its
/// own `PackLimits`.
pub const DEFAULT_MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_ENTRIES: usize = 4_000_000;

/// What a decoder will take: each checked before anything is allocated or
/// decompressed for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackLimits {
    /// Entries in the pack.
    pub max_entries: usize,
    /// One entry, decoded.
    pub max_object_bytes: usize,
    /// All entries together, decoded.
    pub max_total_bytes: usize,
}

impl Default for PackLimits {
    fn default() -> Self {
        PackLimits {
            max_entries: DEFAULT_MAX_ENTRIES,
            max_object_bytes: DEFAULT_MAX_OBJECT_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
        }
    }
}

#[derive(Debug, Error)]
pub enum PackError {
    #[error("malformed pack: {0}")]
    Malformed(String),
    /// Well formed, but past what the decoder was asked to take.
    #[error("pack too large: {0}")]
    TooLarge(String),
}

#[derive(Clone, Debug)]
pub struct PackEntry {
    pub object_type: u8,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct Pack {
    pub entries: Vec<PackEntry>,
}

impl Pack {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, object_type: u8, bytes: Vec<u8>) {
        self.entries.push(PackEntry { object_type, bytes });
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            16 + self
                .entries
                .iter()
                .map(|e| 10 + e.bytes.len())
                .sum::<usize>(),
        );
        out.extend_from_slice(&PACK_MAGIC);
        let mut v = [0u8; 4];
        LittleEndian::write_u32(&mut v, PACK_VERSION);
        out.extend_from_slice(&v);
        let mut c = [0u8; 8];
        LittleEndian::write_u64(&mut c, self.entries.len() as u64);
        out.extend_from_slice(&c);

        // Pre-hash each entry once. We need these to write base_hash for any
        // delta we emit, and BLAKE3 is the same hash the receiver will use
        // for content addressing — there is no duplicated work here in
        // aggregate.
        let hashes: Vec<[u8; 32]> = self
            .entries
            .iter()
            .map(|e| *blake3::hash(&e.bytes).as_bytes())
            .collect();

        // Delta-base selection heuristic: the most recent prior entry of the
        // same object_type. Cheap (O(1) lookup, O(types) memory) and good
        // enough to capture the common case — successive tree revisions, a
        // chain of commits, sibling blobs from one push. Smarter selectors
        // (size-bucketed candidates, simhash near-neighbour) are a future
        // refinement; the on-wire format does not change.
        let mut last_idx_by_type: HashMap<u8, usize> = HashMap::new();

        for (i, e) in self.entries.iter().enumerate() {
            out.push(e.object_type);
            let mut s = [0u8; 8];
            LittleEndian::write_u64(&mut s, e.bytes.len() as u64);
            out.extend_from_slice(&s);

            // Tiny entries: skip both zstd and delta unconditionally; the
            // 32-byte base_hash alone would dwarf any plausible saving.
            if e.bytes.len() < COMPRESSION_THRESHOLD {
                out.push(0u8);
                out.extend_from_slice(&e.bytes);
                last_idx_by_type.insert(e.object_type, i);
                continue;
            }

            // Always try plain zstd as the floor. The delta path is then a
            // strict improvement opportunity — never a regression — because
            // we only switch to delta when its frame is smaller than plain
            // zstd plus the 32-byte base_hash overhead.
            let plain = zstd::encode_all(&e.bytes[..], COMPRESSION_LEVEL).ok();
            let plain_len = plain.as_ref().map_or(usize::MAX, |p| p.len());

            let delta = last_idx_by_type.get(&e.object_type).and_then(|&base_idx| {
                let base_bytes = &self.entries[base_idx].bytes;
                zstd::bulk::Compressor::with_dictionary(COMPRESSION_LEVEL, base_bytes)
                    .and_then(|mut c| c.compress(&e.bytes))
                    .ok()
                    .map(|d| (base_idx, d))
            });
            // The +32 accounts for base_hash on the wire — a delta only
            // wins if it saves more than that versus plain zstd.
            let delta_total_len = delta.as_ref().map_or(usize::MAX, |(_, d)| d.len() + 32);

            if delta_total_len < plain_len && delta_total_len < e.bytes.len() {
                let (base_idx, d) = delta.unwrap();
                out.push(FLAG_ZSTD | FLAG_DELTA);
                out.extend_from_slice(&hashes[base_idx]);
                out.extend_from_slice(&d);
            } else if plain_len < e.bytes.len() {
                out.push(FLAG_ZSTD);
                out.extend_from_slice(plain.as_ref().unwrap());
            } else {
                out.push(0u8);
                out.extend_from_slice(&e.bytes);
            }

            last_idx_by_type.insert(e.object_type, i);
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PackError> {
        let (pack, consumed) = Self::decode_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(PackError::Malformed("trailing bytes after entries".into()));
        }
        Ok(pack)
    }

    /// Decode a pack from the start of `bytes` using the default per-object
    /// size ceiling (`DEFAULT_MAX_OBJECT_BYTES`). Returns the pack and the
    /// number of bytes consumed; trailing bytes are not an error. This is
    /// used by the push wire format, which appends a manifest after the
    /// pack.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize), PackError> {
        Self::decode_prefix_within(bytes, &PackLimits::default())
    }

    /// Like `decode_prefix`, but lets the caller pick the per-object size
    /// ceiling. Any entry whose recorded `size` exceeds `max_object_bytes`
    /// is rejected before any allocation or decompression takes place.
    pub fn decode_prefix_with_limit(
        bytes: &[u8],
        max_object_bytes: usize,
    ) -> Result<(Self, usize), PackError> {
        Self::decode_prefix_within(
            bytes,
            &PackLimits {
                max_object_bytes,
                ..PackLimits::default()
            },
        )
    }

    /// Like `decode_prefix`, within `limits`: a pack with more entries, an
    /// entry larger, or entries larger together, is refused before the
    /// entry that would pass a limit is allocated or decompressed.
    pub fn decode_prefix_within(
        bytes: &[u8],
        limits: &PackLimits,
    ) -> Result<(Self, usize), PackError> {
        let max_object_bytes = limits.max_object_bytes;
        if bytes.len() < 16 {
            return Err(PackError::Malformed("header truncated".into()));
        }
        if &bytes[0..4] != PACK_MAGIC.as_ref() {
            return Err(PackError::Malformed("bad magic".into()));
        }
        let version = LittleEndian::read_u32(&bytes[4..8]);
        if version != PACK_VERSION {
            return Err(PackError::Malformed(format!("version {version}")));
        }
        let count = LittleEndian::read_u64(&bytes[8..16]);
        if count > limits.max_entries as u64 {
            return Err(PackError::TooLarge(format!(
                "{count} entries exceeds limit {}",
                limits.max_entries
            )));
        }
        let count = count as usize;
        // Decoded so far, against `limits.max_total_bytes`.
        let mut total: usize = 0;
        // Cap the capacity hint by the number of entries that can
        // possibly fit in the remaining bytes — each entry's minimum
        // on-wire size is 10 bytes (type+size+flags), and an empty
        // payload still needs that header. Without this cap, a hostile
        // sender's `count = u64::MAX` triggers `Vec::with_capacity` to
        // panic with "capacity overflow" before we ever look at an entry.
        const MIN_ENTRY_BYTES: usize = 10;
        let max_plausible = bytes.len().saturating_sub(16) / MIN_ENTRY_BYTES + 1;
        let mut entries: Vec<PackEntry> = Vec::with_capacity(count.min(max_plausible));
        // Index decoded entries by content hash so a later delta entry can
        // resolve its base in O(1). We build this incrementally as we decode.
        let mut idx_by_hash: HashMap<[u8; 32], usize> = HashMap::new();
        let mut p = 16usize;
        for _ in 0..count {
            if bytes.len() < p + 1 + 8 + 1 {
                return Err(PackError::Malformed("entry header truncated".into()));
            }
            let object_type = bytes[p];
            p += 1;
            let size_u64 = LittleEndian::read_u64(&bytes[p..p + 8]);
            p += 8;
            // Reject implausibly-large `size` declarations *before* we
            // touch the data. zstd's `decompress(_, size)` allocates the
            // declared size up front, so leaving this unbounded is a
            // memory-exhaustion vector. We also reject `size > usize::MAX`
            // explicitly on 32-bit targets where the cast below would
            // truncate.
            if size_u64 > max_object_bytes as u64 {
                return Err(PackError::TooLarge(format!(
                    "entry size {size_u64} exceeds limit {max_object_bytes}"
                )));
            }
            let size = size_u64 as usize;
            total = total.saturating_add(size);
            if total > limits.max_total_bytes {
                return Err(PackError::TooLarge(format!(
                    "entries decode to more than the limit of {} bytes",
                    limits.max_total_bytes
                )));
            }
            let flags = bytes[p];
            p += 1;
            let unknown = flags & !(FLAG_ZSTD | FLAG_DELTA);
            if unknown != 0 {
                return Err(PackError::Malformed(format!("unknown flags: {unknown:#b}")));
            }

            let data = if flags & FLAG_DELTA != 0 {
                if flags & FLAG_ZSTD == 0 {
                    return Err(PackError::Malformed(
                        "delta entries must be zstd-framed".into(),
                    ));
                }
                if bytes.len() < p + 32 {
                    return Err(PackError::Malformed("delta base hash truncated".into()));
                }
                let mut base_hash = [0u8; 32];
                base_hash.copy_from_slice(&bytes[p..p + 32]);
                p += 32;
                let base_idx = idx_by_hash.get(&base_hash).copied().ok_or_else(|| {
                    PackError::Malformed(
                        "delta base not in pack (deltas must follow their base)".into(),
                    )
                })?;
                let frame_len = zstd::zstd_safe::find_frame_compressed_size(&bytes[p..])
                    .map_err(|e| PackError::Malformed(format!("zstd frame size: {e}")))?;
                if bytes.len() < p + frame_len {
                    return Err(PackError::Malformed("zstd delta frame truncated".into()));
                }
                let frame = &bytes[p..p + frame_len];
                let mut decompressor =
                    zstd::bulk::Decompressor::with_dictionary(&entries[base_idx].bytes)
                        .map_err(|e| PackError::Malformed(format!("zstd dict: {e}")))?;
                let data = decompressor
                    .decompress(frame, size)
                    .map_err(|e| PackError::Malformed(format!("zstd decompress: {e}")))?;
                if data.len() != size {
                    return Err(PackError::Malformed(format!(
                        "decompressed length {} mismatches recorded size {size}",
                        data.len()
                    )));
                }
                p += frame_len;
                data
            } else if flags & FLAG_ZSTD != 0 {
                let frame_len = zstd::zstd_safe::find_frame_compressed_size(&bytes[p..])
                    .map_err(|e| PackError::Malformed(format!("zstd frame size: {e}")))?;
                if bytes.len() < p + frame_len {
                    return Err(PackError::Malformed("zstd frame truncated".into()));
                }
                let frame = &bytes[p..p + frame_len];
                let data = zstd::bulk::decompress(frame, size)
                    .map_err(|e| PackError::Malformed(format!("zstd decompress: {e}")))?;
                if data.len() != size {
                    return Err(PackError::Malformed(format!(
                        "decompressed length {} mismatches recorded size {size}",
                        data.len()
                    )));
                }
                p += frame_len;
                data
            } else {
                if bytes.len() < p + size {
                    return Err(PackError::Malformed("entry data truncated".into()));
                }
                let d = bytes[p..p + size].to_vec();
                p += size;
                d
            };

            // Index by hash so subsequent deltas can resolve their base.
            // Duplicate-content entries simply keep the first index; either
            // is a valid base.
            let hash = *blake3::hash(&data).as_bytes();
            idx_by_hash.entry(hash).or_insert(entries.len());
            entries.push(PackEntry {
                object_type,
                bytes: data,
            });
        }
        Ok((Self { entries }, p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Entries of `n` zero bytes, each compressing to a few bytes: what a
    /// small pack can claim to decode to.
    fn zeros(entries: usize, n: usize) -> Vec<u8> {
        let mut p = Pack::new();
        for i in 0..entries {
            let mut b = vec![0u8; n];
            b[0] = i as u8; // distinct, so none is a delta of another
            p.push(1, b);
        }
        p.encode()
    }

    /// The whole pack's decoded size is bounded, not only each entry's: a
    /// pack a few kilobytes long is refused before it decodes past the
    /// budget.
    #[test]
    fn a_pack_decoding_past_its_budget_is_refused() {
        let bytes = zeros(3, 1 << 20);
        assert!(bytes.len() < 64 * 1024, "{}", bytes.len());
        let limits = |total| PackLimits {
            max_entries: 10,
            max_object_bytes: 1 << 20,
            max_total_bytes: total,
        };
        assert!(Pack::decode_prefix_within(&bytes, &limits(3 << 20)).is_ok());
        let e = Pack::decode_prefix_within(&bytes, &limits((3 << 20) - 1)).unwrap_err();
        assert!(e.to_string().contains("more than the limit"), "{e}");
    }

    /// A pack with more entries than allowed is refused from its header.
    #[test]
    fn a_pack_with_too_many_entries_is_refused() {
        let bytes = zeros(3, 16);
        let limits = |n| PackLimits {
            max_entries: n,
            ..PackLimits::default()
        };
        assert!(Pack::decode_prefix_within(&bytes, &limits(3)).is_ok());
        let e = Pack::decode_prefix_within(&bytes, &limits(2)).unwrap_err();
        assert!(e.to_string().contains("entries exceeds limit"), "{e}");
    }

    /// Pseudo-random byte generator (linear congruential). Produces output
    /// that defeats zstd's matching, so plain zstd compression is near-zero
    /// — useful for testing that delta encoding actually saves space when
    /// two entries share most of their content.
    fn lcg_bytes(seed: u64, n: usize) -> Vec<u8> {
        let mut s = seed;
        (0..n)
            .map(|_| {
                s = s
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (s >> 33) as u8
            })
            .collect()
    }

    #[test]
    fn pack_roundtrip() {
        let mut pk = Pack::new();
        pk.push(1, b"hello".to_vec());
        pk.push(3, b"world!".to_vec());
        let bytes = pk.encode();
        let pk2 = Pack::decode(&bytes).unwrap();
        assert_eq!(pk2.entries.len(), 2);
        assert_eq!(pk2.entries[0].object_type, 1);
        assert_eq!(pk2.entries[1].bytes, b"world!");
    }

    #[test]
    fn pack_compresses_large_compressible_entry() {
        // A long run of repeated bytes is highly compressible; the encoder
        // must pick the zstd path and the decoded bytes must match exactly.
        let payload = b"abc".repeat(4096); // ~12 KiB
        let mut pk = Pack::new();
        pk.push(1, payload.clone());
        let encoded = pk.encode();
        // Entry overhead: type(1) + size(8) + flags(1) = 10 bytes per entry,
        // plus 16-byte header. Encoded length should be far smaller than raw.
        let raw_size = 16 + 10 + payload.len();
        assert!(
            encoded.len() < raw_size / 2,
            "expected substantial compression: encoded={}, raw={}",
            encoded.len(),
            raw_size
        );
        let pk2 = Pack::decode(&encoded).unwrap();
        assert_eq!(pk2.entries.len(), 1);
        assert_eq!(pk2.entries[0].bytes, payload);
    }

    #[test]
    fn pack_keeps_small_entries_uncompressed() {
        // Below the threshold the encoder should not pay framing overhead,
        // so the on-wire bytes contain the raw payload.
        let payload = b"short".to_vec();
        let mut pk = Pack::new();
        pk.push(2, payload.clone());
        let encoded = pk.encode();
        // The flag byte for the (only) entry sits at offset 16 + 1 + 8 = 25.
        assert_eq!(encoded[25], 0, "small entry must keep flags=0");
        // And the raw payload should follow immediately.
        assert_eq!(&encoded[26..26 + payload.len()], payload.as_slice());
        let pk2 = Pack::decode(&encoded).unwrap();
        assert_eq!(pk2.entries[0].bytes, payload);
    }

    #[test]
    fn pack_roundtrip_mixed_entries() {
        let small = b"x".to_vec();
        let big = b"abc".repeat(4096);
        let mut pk = Pack::new();
        pk.push(1, small.clone());
        pk.push(3, big.clone());
        pk.push(2, b"medium-but-not-huge".to_vec());
        let encoded = pk.encode();
        let pk2 = Pack::decode(&encoded).unwrap();
        assert_eq!(pk2.entries.len(), 3);
        assert_eq!(pk2.entries[0].bytes, small);
        assert_eq!(pk2.entries[1].bytes, big);
        assert_eq!(pk2.entries[2].bytes, b"medium-but-not-huge");
    }

    #[test]
    fn pack_rejects_unknown_flags() {
        // Hand-craft a pack with an unsupported flag bit (bit 7).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PACK_MAGIC);
        bytes.extend_from_slice(&PACK_VERSION.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes()); // count
        bytes.push(1); // type
        bytes.extend_from_slice(&3u64.to_le_bytes()); // size
        bytes.push(0b1000_0000); // unknown flag
        bytes.extend_from_slice(b"abc");
        let err = Pack::decode(&bytes).unwrap_err();
        match err {
            PackError::Malformed(s) => assert!(s.contains("unknown flags")),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn pack_uses_delta_for_similar_entries_and_roundtrips() {
        // Two same-type incompressible blobs that share most of their
        // content. Plain zstd on each is near-zero compression, so the
        // delta path must win for the second entry — and the second
        // entry's flag byte must show FLAG_DELTA set.
        let base = lcg_bytes(0xDEADBEEF, 4096);
        let near = {
            let mut v = base.clone();
            v.extend_from_slice(b" appended tail of about 50 bytes for variation.");
            v
        };

        let mut pk = Pack::new();
        pk.push(1, base.clone());
        pk.push(1, near.clone());
        let encoded = pk.encode();

        // Verify roundtrip first — correctness comes before compression.
        let pk2 = Pack::decode(&encoded).unwrap();
        assert_eq!(pk2.entries.len(), 2);
        assert_eq!(pk2.entries[0].bytes, base);
        assert_eq!(pk2.entries[1].bytes, near);

        // Inspect the second entry's flag byte. Walk past the header and
        // first entry to find it.
        // header(16) + type(1) + size(8) + flags(1) = 26
        let first_flags = encoded[25];
        assert_eq!(first_flags & FLAG_DELTA, 0, "first entry cannot be a delta");
        let first_data_offset = 26;
        let first_data_len = if first_flags & FLAG_ZSTD != 0 {
            zstd::zstd_safe::find_frame_compressed_size(&encoded[first_data_offset..]).unwrap()
        } else {
            base.len()
        };
        let second_header = first_data_offset + first_data_len;
        // type(1) + size(8) -> flags
        let second_flags = encoded[second_header + 9];
        assert_eq!(
            second_flags & FLAG_DELTA,
            FLAG_DELTA,
            "second entry must be delta-encoded against the first"
        );
        assert_eq!(
            second_flags & FLAG_ZSTD,
            FLAG_ZSTD,
            "delta entries are always zstd-framed"
        );

        // And the on-wire size should be much smaller than two independent
        // copies — even with the 32-byte base_hash overhead, the second
        // entry's payload is mostly references into the first.
        assert!(
            encoded.len() < base.len() + near.len() / 2,
            "delta did not produce expected savings: encoded={}",
            encoded.len()
        );
    }

    #[test]
    fn pack_delta_chain_roundtrips() {
        // A → B (delta of A) → C (delta of B). Each level adds a small
        // tail; the encoder should chain deltas and the decoder should
        // resolve them in order.
        let a = lcg_bytes(0x11111111, 2048);
        let b = {
            let mut v = a.clone();
            v.extend_from_slice(b" stage-B suffix");
            v
        };
        let c = {
            let mut v = b.clone();
            v.extend_from_slice(b" stage-C suffix");
            v
        };

        let mut pk = Pack::new();
        pk.push(2, a.clone());
        pk.push(2, b.clone());
        pk.push(2, c.clone());
        let encoded = pk.encode();
        let pk2 = Pack::decode(&encoded).unwrap();
        assert_eq!(pk2.entries.len(), 3);
        assert_eq!(pk2.entries[0].bytes, a);
        assert_eq!(pk2.entries[1].bytes, b);
        assert_eq!(pk2.entries[2].bytes, c);
    }

    #[test]
    fn pack_does_not_delta_across_object_types() {
        // Two large similar blobs of *different* object_type — selector
        // restricts deltas to within a type, so neither becomes a delta.
        let a = lcg_bytes(0x22222222, 1024);
        let b = a.clone();
        let mut pk = Pack::new();
        pk.push(1, a);
        pk.push(2, b);
        let encoded = pk.encode();

        // First entry's flag byte at offset 25, second's flag byte we'll
        // compute. Neither should be a delta.
        let first_flags = encoded[25];
        assert_eq!(first_flags & FLAG_DELTA, 0);
        let first_data_offset = 26;
        let first_data_len = if first_flags & FLAG_ZSTD != 0 {
            zstd::zstd_safe::find_frame_compressed_size(&encoded[first_data_offset..]).unwrap()
        } else {
            1024
        };
        let second_flags = encoded[first_data_offset + first_data_len + 9];
        assert_eq!(
            second_flags & FLAG_DELTA,
            0,
            "delta selection must not cross object_type boundaries"
        );

        let pk2 = Pack::decode(&encoded).unwrap();
        assert_eq!(pk2.entries.len(), 2);
    }

    #[test]
    fn pack_rejects_delta_without_zstd() {
        // FLAG_DELTA without FLAG_ZSTD is undefined and must be rejected.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PACK_MAGIC);
        bytes.extend_from_slice(&PACK_VERSION.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&3u64.to_le_bytes());
        bytes.push(FLAG_DELTA); // delta but no zstd
        bytes.extend_from_slice(&[0u8; 32]); // base_hash
        bytes.extend_from_slice(b"abc");
        let err = Pack::decode(&bytes).unwrap_err();
        match err {
            PackError::Malformed(s) => assert!(s.contains("zstd-framed")),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn pack_rejects_delta_with_unknown_base() {
        // Hand-craft a single delta entry whose base_hash matches no
        // earlier entry. Decode must fail cleanly.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PACK_MAGIC);
        bytes.extend_from_slice(&PACK_VERSION.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&3u64.to_le_bytes());
        bytes.push(FLAG_DELTA | FLAG_ZSTD);
        // 32-byte base_hash that no entry could produce
        bytes.extend_from_slice(&[0xAAu8; 32]);
        // A valid-looking zstd frame so we get past frame-size parsing
        let frame = zstd::encode_all(&b"abc"[..], COMPRESSION_LEVEL).unwrap();
        bytes.extend_from_slice(&frame);
        let err = Pack::decode(&bytes).unwrap_err();
        match err {
            PackError::Malformed(s) => assert!(s.contains("delta base not in pack")),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn pack_rejects_oversized_object_declaration() {
        // Hand-craft a pack whose single entry declares a uncompressed
        // size of 1 TiB. The decoder must reject this before allocating
        // anything, regardless of how much data actually follows on the
        // wire — a hostile peer can pair this with a tiny zstd frame to
        // trigger a multi-gigabyte allocation in `zstd::bulk::decompress`.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PACK_MAGIC);
        bytes.extend_from_slice(&PACK_VERSION.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.push(1); // type
        bytes.extend_from_slice(&(1u64 << 40).to_le_bytes()); // 1 TiB
        bytes.push(0); // flags: raw
                       // (no body needed — the size check should fire before we look)
        let err = Pack::decode(&bytes).unwrap_err();
        match err {
            PackError::TooLarge(s) => assert!(
                s.contains("exceeds limit"),
                "error must mention size limit: {s}"
            ),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn pack_decode_with_limit_admits_objects_under_caller_ceiling() {
        // The custom-limit decoder should accept any entry up to its
        // configured ceiling, even when smaller than the default. Build
        // a 1 KiB raw entry, then decode with a 4 KiB limit.
        let payload = vec![0xABu8; 1024];
        let mut pk = Pack::new();
        pk.push(1, payload.clone());
        let encoded = pk.encode();
        let (pk2, _) = Pack::decode_prefix_with_limit(&encoded, 4096).unwrap();
        assert_eq!(pk2.entries.len(), 1);
        assert_eq!(pk2.entries[0].bytes, payload);

        // Same encoded pack, decoded with a 512-byte limit, must reject.
        let err = Pack::decode_prefix_with_limit(&encoded, 512).unwrap_err();
        match err {
            PackError::TooLarge(s) => assert!(s.contains("exceeds limit")),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn pack_rejects_delta_with_truncated_base_hash() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PACK_MAGIC);
        bytes.extend_from_slice(&PACK_VERSION.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&3u64.to_le_bytes());
        bytes.push(FLAG_DELTA | FLAG_ZSTD);
        // Only 10 of the required 32 bytes of base_hash
        bytes.extend_from_slice(&[0u8; 10]);
        let err = Pack::decode(&bytes).unwrap_err();
        match err {
            PackError::Malformed(s) => assert!(s.contains("base hash truncated")),
            other => panic!("{other}"),
        }
    }
}
