//! Robustness/fuzz tests for protocol deserializers (§8.2).
//!
//! Targets every parser an instance or peer could feed us bytes for:
//!   * `Pack::decode` — reachable via federation push and P2P deploy.
//!   * `p2p::read_frame` — every byte from a dialing peer comes through here.
//!   * The federation JSON wire types (`PushManifest`, `InfoResponse`,
//!     `RefList`, `RefsResponse`).
//!   * The P2P `DeployManifest`.
//!
//! All of these must accept malformed input without panicking.

use std::io::Cursor;
use std::panic::{catch_unwind, AssertUnwindSafe};

use levcs_protocol::p2p::{read_frame, DeployManifest};
use levcs_protocol::{InfoResponse, Pack, PushManifest, RefList, RefsResponse};

const ITERS: u32 = 5_000;

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
    match lcg(seed) % 5 {
        0 => 0,
        1 => (lcg(seed) % 16) as usize,
        2 => (lcg(seed) % 256) as usize,
        3 => 256 + (lcg(seed) % 4096) as usize,
        _ => 4096 + (lcg(seed) % 16384) as usize,
    }
}

fn assert_no_panic<F, T>(label: &str, seed: u64, input: &[u8], parser: F)
where
    F: FnOnce(&[u8]) -> T,
{
    let r = catch_unwind(AssertUnwindSafe(|| parser(input)));
    if r.is_err() {
        panic!(
            "{label} panicked on seed {seed:#x}, input len {}: {:02x?}",
            input.len(),
            &input[..input.len().min(64)]
        );
    }
}

#[test]
fn pack_decode_does_not_panic_on_random_bytes() {
    let mut seed = 0x6677_8899_aabb_ccddu64;
    for _ in 0..ITERS {
        let n = rand_size(&mut seed);
        let bytes = rand_bytes(&mut seed, n);
        assert_no_panic("Pack::decode", seed, &bytes, |b| {
            let _ = Pack::decode(b);
        });
        assert_no_panic("Pack::decode_prefix", seed, &bytes, |b| {
            let _ = Pack::decode_prefix(b);
        });
    }
}

/// Pack decoder does internal arithmetic over object_count and entry
/// sizes — both could overflow on hostile inputs. Build packs with a
/// valid magic + extreme `object_count` and verify the decoder rejects
/// gracefully without trying to allocate `count * struct_size` bytes.
#[test]
fn pack_decode_handles_extreme_object_counts() {
    let mut seed = 0xc0ffee_aaaa_5555u64;
    for _ in 0..512 {
        let mut bytes = b"LVPK".to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // version
        let count = match lcg(&mut seed) % 4 {
            0 => u64::MAX,
            1 => u64::MAX / 2,
            2 => 1u64 << 50,
            _ => lcg(&mut seed),
        };
        bytes.extend_from_slice(&count.to_le_bytes());
        // Append a small amount of random body — far less than `count`
        // entries' worth, so the decoder must report "truncated", not panic.
        let pad = (lcg(&mut seed) % 256) as usize;
        bytes.extend(rand_bytes(&mut seed, pad));
        assert_no_panic("Pack::decode(huge count)", seed, &bytes, |b| {
            let _ = Pack::decode(b);
        });
    }
}

#[test]
fn p2p_read_frame_does_not_panic_on_random_bytes() {
    let mut seed = 0x1212_3434_5656_7878u64;
    for _ in 0..ITERS {
        let n = rand_size(&mut seed);
        let bytes = rand_bytes(&mut seed, n);
        let r = catch_unwind(AssertUnwindSafe(|| {
            let mut cur = Cursor::new(&bytes);
            let _ = read_frame(&mut cur);
        }));
        if r.is_err() {
            panic!(
                "read_frame panicked on seed {seed:#x}, input len {}: {:02x?}",
                bytes.len(),
                &bytes[..bytes.len().min(64)]
            );
        }
    }
}

/// Forge frame headers that claim plausible-looking lengths just shy of
/// the cap, then provide far less payload than promised. The reader must
/// return EOF/short-read errors, not panic.
#[test]
fn p2p_read_frame_handles_lying_length_prefixes() {
    use levcs_protocol::p2p::MAX_FRAME_BYTES;
    let mut seed = 0xfeed_face_1357_2468u64;
    for _ in 0..512 {
        let mut hdr = Vec::new();
        let claimed_len = match lcg(&mut seed) % 4 {
            0 => MAX_FRAME_BYTES as u32 + 1,
            1 => MAX_FRAME_BYTES as u32,
            2 => u32::MAX,
            _ => (lcg(&mut seed) & 0xffff_ffff) as u32,
        };
        hdr.extend_from_slice(&claimed_len.to_be_bytes());
        // Provide some random tail, far short of `claimed_len` bytes.
        let tail_len = (lcg(&mut seed) % 64) as usize;
        let tail = rand_bytes(&mut seed, tail_len);
        hdr.extend(tail);
        let r = catch_unwind(AssertUnwindSafe(|| {
            let mut cur = Cursor::new(&hdr);
            let _ = read_frame(&mut cur);
        }));
        if r.is_err() {
            panic!(
                "read_frame panicked on lying header (claimed_len={claimed_len}, seed {seed:#x}): {:02x?}",
                hdr
            );
        }
    }
}

#[test]
fn deploy_manifest_json_does_not_panic() {
    let mut seed = 0x9999_8888_7777_6666u64;
    for _ in 0..ITERS {
        let n = rand_size(&mut seed);
        let bytes = rand_bytes(&mut seed, n);
        assert_no_panic("DeployManifest::deserialize", seed, &bytes, |b| {
            let _: Result<DeployManifest, _> = serde_json::from_slice(b);
        });
    }
}

/// Build inputs that *look* like JSON (random ASCII with braces and
/// quotes) — closer to what a buggy or hostile peer might produce than
/// pure random bytes, and pushes the JSON parser into deeper code paths.
#[test]
fn json_wire_types_handle_pseudo_json_inputs() {
    let mut seed = 0x4444_5555_6666_7777u64;
    let pool: &[u8] = b"{}[],:\"\\nrue0123456789abcdefghijklmnopqrstuvwxyz_- ";
    for _ in 0..ITERS {
        let n = (lcg(&mut seed) % 4096) as usize;
        let bytes: Vec<u8> = (0..n)
            .map(|_| pool[(lcg(&mut seed) as usize) % pool.len()])
            .collect();
        assert_no_panic("PushManifest", seed, &bytes, |b| {
            let _: Result<PushManifest, _> = serde_json::from_slice(b);
        });
        assert_no_panic("InfoResponse", seed, &bytes, |b| {
            let _: Result<InfoResponse, _> = serde_json::from_slice(b);
        });
        assert_no_panic("RefList", seed, &bytes, |b| {
            let _: Result<RefList, _> = serde_json::from_slice(b);
        });
        assert_no_panic("RefsResponse", seed, &bytes, |b| {
            let _: Result<RefsResponse, _> = serde_json::from_slice(b);
        });
        assert_no_panic("DeployManifest(pseudo)", seed, &bytes, |b| {
            let _: Result<DeployManifest, _> = serde_json::from_slice(b);
        });
    }
}

/// A pack assembled from valid object bytes that the encoder picks the
/// delta path on. Then we mutate that valid pack and re-decode — the
/// decoder must refuse mutated bytes, never panic.
#[test]
fn pack_decode_survives_mutation_of_valid_pack() {
    // Construct a tiny valid pack so we have something to mutate.
    let mut pk = Pack::new();
    pk.push(1, b"hello world fuzz".to_vec());
    pk.push(1, b"hello world fuzz, slight variant".to_vec());
    let valid = pk.encode();

    let mut seed = 0x7777_8888_9999_aaaau64;
    for _ in 0..ITERS {
        let mut buf = valid.clone();
        match lcg(&mut seed) % 4 {
            0 => {
                let flips = (lcg(&mut seed) % 4 + 1) as usize;
                for _ in 0..flips {
                    if buf.is_empty() { break; }
                    let idx = (lcg(&mut seed) as usize) % buf.len();
                    let bit = (lcg(&mut seed) % 8) as u8;
                    buf[idx] ^= 1 << bit;
                }
            }
            1 => {
                let new_len = (lcg(&mut seed) as usize) % buf.len().max(1);
                buf.truncate(new_len);
            }
            2 => {
                // Stomp on the entry-count field (bytes 8..16).
                let off = 8 + (lcg(&mut seed) as usize) % 8;
                buf[off] = buf[off].wrapping_add((lcg(&mut seed) & 0xff) as u8);
            }
            _ => {
                let extra = (lcg(&mut seed) % 64) as usize;
                buf.extend(rand_bytes(&mut seed, extra));
            }
        }
        assert_no_panic("Pack::decode(mut)", seed, &buf, |b| {
            let _ = Pack::decode(b);
        });
    }
}
