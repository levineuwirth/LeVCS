//! Robustness/fuzz tests for identity deserializers (§8.2).
//!
//! Mirror of `levcs-core/tests/fuzz.rs`, scoped to authority parsing
//! (binary and TOML) and key string parsers. Same panic-catching
//! discipline: nothing in this crate may panic on hostile bytes.

use std::panic::{catch_unwind, AssertUnwindSafe};

use levcs_identity::authority::{parse_toml_authority, AuthorityBody};
use levcs_identity::keys::{PublicKey, SecretKey};

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
fn authority_body_parse_does_not_panic_on_random_bytes() {
    let mut seed = 0x1111_2222_3333_4444u64;
    for _ in 0..ITERS {
        let n = rand_size(&mut seed);
        let bytes = rand_bytes(&mut seed, n);
        assert_no_panic("AuthorityBody::parse", seed, &bytes, |b| {
            let _ = AuthorityBody::parse(b);
        });
    }
}

/// Authority bodies have many length-prefixed fields (member count,
/// handle length, policy count, key length, value length). Each is a
/// classic place for a parser to fail to bounds-check. Build inputs with
/// a *valid* prefix (so the parser advances past schema version checks)
/// and then random nonsense — that exercises the inner offset arithmetic.
#[test]
fn authority_body_parse_survives_crafted_length_prefixes() {
    let mut seed = 0xfeed_face_8888_1234u64;
    for _ in 0..ITERS {
        let mut buf = Vec::new();
        // schema_version = 1 (so we get past the version check).
        buf.extend_from_slice(&1u16.to_le_bytes());
        // repo_id (32 bytes), previous_authority (32 bytes).
        buf.extend(rand_bytes(&mut seed, 32));
        buf.extend(rand_bytes(&mut seed, 32));
        // version (u32), created_micros (i64).
        buf.extend(rand_bytes(&mut seed, 4));
        buf.extend(rand_bytes(&mut seed, 8));
        // Crafted member_count: pick a value that may or may not match
        // the bytes we'll append.
        let mc = (lcg(&mut seed) & 0xff) as u16;
        buf.extend_from_slice(&mc.to_le_bytes());
        // Append random bytes (probably not enough to satisfy mc members).
        let pad = (lcg(&mut seed) % 4096) as usize;
        buf.extend(rand_bytes(&mut seed, pad));
        assert_no_panic("AuthorityBody::parse(crafted)", seed, &buf, |b| {
            let _ = AuthorityBody::parse(b);
        });
    }
}

#[test]
fn authority_body_round_trip_when_parse_succeeds() {
    let mut seed = 0xbeef_dead_4321_8765u64;
    for _ in 0..ITERS {
        let n = rand_size(&mut seed);
        let bytes = rand_bytes(&mut seed, n);
        if let Ok(parsed) = AuthorityBody::parse(&bytes) {
            // Encode then re-parse — must yield the same body.
            let re = parsed.encode().expect("re-encode");
            let re_parsed = AuthorityBody::parse(&re).expect("re-parse");
            assert_eq!(parsed.repo_id, re_parsed.repo_id);
            assert_eq!(parsed.version, re_parsed.version);
            assert_eq!(parsed.members.len(), re_parsed.members.len());
            assert_eq!(parsed.policy.len(), re_parsed.policy.len());
        }
    }
}

#[test]
fn parse_toml_authority_does_not_panic() {
    let mut seed = 0xfacefade_1357_2468u64;
    for _ in 0..ITERS {
        let n = rand_size(&mut seed);
        let bytes = rand_bytes(&mut seed, n);
        // Coerce to UTF-8 best-effort — non-UTF-8 input must still not
        // panic, just return an error to the caller.
        let text = String::from_utf8_lossy(&bytes);
        assert_no_panic("parse_toml_authority", seed, text.as_bytes(), |b| {
            let _ = parse_toml_authority(std::str::from_utf8(b).unwrap_or(""));
        });
    }
}

#[test]
fn key_parsers_do_not_panic_on_random_input() {
    let mut seed = 0xa1b2_c3d4_e5f6_0789u64;
    for _ in 0..ITERS {
        let n = (lcg(&mut seed) % 256) as usize;
        let bytes = rand_bytes(&mut seed, n);
        let text = String::from_utf8_lossy(&bytes).into_owned();
        assert_no_panic("PublicKey::parse_levcs", seed, text.as_bytes(), |b| {
            let _ = PublicKey::parse_levcs(std::str::from_utf8(b).unwrap_or(""));
        });
        assert_no_panic("SecretKey::parse_levcs", seed, text.as_bytes(), |b| {
            let _ = SecretKey::parse_levcs(std::str::from_utf8(b).unwrap_or(""));
        });
    }
}

/// Build inputs that *look* like ed25519:<hex> strings but with various
/// hex-content corruptions. These are realistic adversarial shapes — a
/// peer might produce strings in the right syntactic form but with bad
/// length, odd nibble counts, non-hex characters in the middle, etc.
#[test]
fn key_parsers_handle_almost_valid_inputs() {
    let mut seed = 0x0011_2233_4455_6677u64;
    for _ in 0..ITERS {
        let len = (lcg(&mut seed) % 80) as usize;
        let mut hex_part = String::new();
        for _ in 0..len {
            // Mix valid hex chars with garbage.
            let pick = lcg(&mut seed) % 16;
            let c = match pick {
                0 => '!',
                1 => 'g',
                2 => 'Z',
                3 => ' ',
                _ => "0123456789abcdef".chars().nth((lcg(&mut seed) % 16) as usize).unwrap(),
            };
            hex_part.push(c);
        }
        let s = format!("ed25519:{hex_part}");
        assert_no_panic("PublicKey::parse_levcs(almost)", seed, s.as_bytes(), |b| {
            let _ = PublicKey::parse_levcs(std::str::from_utf8(b).unwrap_or(""));
        });
    }
}
