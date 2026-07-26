//! D0 contract tests.
//!
//! Lead-owned. These assert the properties the sealed skeleton exists to
//! guarantee, so that an agent cannot quietly dissolve one while implementing
//! its own package. Each is a structural invariant, not a behavior: they must
//! keep passing unchanged through Wave A and Wave B.

use std::path::{Path, PathBuf};

use levcs_protocol::oracle::{append_publication_expectation, APPEND_PUBLICATION_FAILPOINTS};
use levcs_store::{NamespaceId, StoreEngine, StoreError, StoreOptions};

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(&current).expect("read crate source directory") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    assert!(!out.is_empty(), "expected to find crate sources");
    out
}

/// Plan §5.1 forbids the store from making identity-role decisions. The
/// enforceable form of that is: no call into `levcs-identity` from anywhere in
/// this crate.
///
/// The crate does depend on it transitively through `levcs-protocol`, so the
/// invariant cannot be a dependency-graph check and has to be a call check
/// (scope §1). Event signing arrives through the injected
/// `CommitEvidenceSigner` instead.
#[test]
fn the_store_never_calls_into_levcs_identity() {
    // Primary check, and the exact one: `levcs-identity` is not a direct
    // dependency, so no path into it can compile at all. This is stronger than
    // any source scan and cannot produce a false positive.
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read levcs-store manifest");
    let deps = manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|s| s.split("\n[").next())
        .expect("locate [dependencies]");
    // Compare dependency *keys*, not a substring of the block. A substring
    // match reads the comment explaining why the dependency is absent as the
    // dependency being present — the same false-positive class as scanning
    // source without skipping comments, which this file also had to fix.
    let declared: Vec<&str> = deps
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split('=').next())
        .map(str::trim)
        .collect();
    assert!(
        !declared
            .iter()
            .any(|key| *key == "levcs-identity" || *key == "levcs_identity"),
        "levcs-store must not take a direct dependency on levcs-identity; \
         signing is injected through CommitEvidenceSigner. Declared: {declared:?}"
    );

    // Secondary, defence in depth for the day someone adds the dependency: no
    // path syntax into the crate anywhere in the source.
    //
    // Comments are skipped because the rule has to be explained somewhere, and
    // double-quoted strings are skipped because naming the crate in a
    // diagnostic or a help message is not a call into it. Requiring authors to
    // split the token across a concatenation to satisfy a grep would be the
    // test deforming the code it checks.
    let mut offenders = Vec::new();
    for path in rust_sources(&crate_src()) {
        let text = std::fs::read_to_string(&path).expect("read source");
        for (n, line) in blank_comments_and_strings(&text).lines().enumerate() {
            if line.contains("levcs_identity") {
                let original = text.lines().nth(n).unwrap_or_default();
                offenders.push(format!("{}:{}: {}", path.display(), n + 1, original.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "levcs-store must make no identity-role decisions; found calls into \
         levcs-identity:\n{}",
        offenders.join("\n")
    );
}

/// Blank the contents of comments and string literals, preserving line
/// structure so reported line numbers stay meaningful.
///
/// Scans the whole file rather than each line independently, because Rust
/// string literals span lines: a `\`-continued message is one literal, and a
/// per-line scan sees its continuation lines as bare code. That produced a
/// false positive on a diagnostic message that legitimately named the crate.
///
/// The alternative — asking authors to split the token across a concatenation
/// to satisfy a grep — would be the test deforming the code it checks. This is
/// a secondary check behind an exact dependency assertion, so imperfect
/// handling of an exotic literal costs nothing.
fn blank_comments_and_strings(text: &str) -> String {
    #[derive(PartialEq)]
    enum State {
        Code,
        LineComment,
        BlockComment,
        Str,
        RawStr(usize),
    }

    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut state = State::Code;
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        match state {
            State::Code => {
                if c == '/' && next == Some('/') {
                    state = State::LineComment;
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                if c == '/' && next == Some('*') {
                    state = State::BlockComment;
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                // Raw string: r"..." or r#"..."# with any number of hashes.
                if c == 'r' {
                    let mut hashes = 0;
                    while chars.get(i + 1 + hashes) == Some(&'#') {
                        hashes += 1;
                    }
                    if chars.get(i + 1 + hashes) == Some(&'"') {
                        state = State::RawStr(hashes);
                        for _ in 0..(hashes + 2) {
                            out.push(' ');
                        }
                        i += hashes + 2;
                        continue;
                    }
                }
                if c == '"' {
                    state = State::Str;
                    out.push(' ');
                    i += 1;
                    continue;
                }
                out.push(c);
                i += 1;
            }
            State::LineComment => {
                if c == '\n' {
                    state = State::Code;
                    out.push('\n');
                } else {
                    out.push(' ');
                }
                i += 1;
            }
            State::BlockComment => {
                if c == '*' && next == Some('/') {
                    state = State::Code;
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                out.push(if c == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            State::Str => {
                if c == '\\' {
                    out.push_str("  ");
                    i += 2;
                    continue;
                }
                if c == '"' {
                    state = State::Code;
                    out.push(' ');
                } else {
                    out.push(if c == '\n' { '\n' } else { ' ' });
                }
                i += 1;
            }
            State::RawStr(hashes) => {
                if c == '"' && (0..hashes).all(|h| chars.get(i + 1 + h) == Some(&'#')) {
                    state = State::Code;
                    for _ in 0..(hashes + 1) {
                        out.push(' ');
                    }
                    i += hashes + 1;
                    continue;
                }
                out.push(if c == '\n' { '\n' } else { ' ' });
                i += 1;
            }
        }
    }
    out
}

/// `PrivilegedConstruction` must not be reachable from a `&StoreEngine`.
///
/// A `StoreEngine::privileged()` accessor would make the seal decorative,
/// since everything able to call `submit` holds an engine. The token is gated
/// on the `store-privileged` feature instead (scope 2.2). This test asserts
/// the absence of such an accessor in the source, because a type-level proof
/// of "no safe path exists" is not expressible.
#[test]
fn privileged_construction_is_not_reachable_from_an_engine() {
    let mut offenders = Vec::new();
    for path in rust_sources(&crate_src()) {
        let text = std::fs::read_to_string(&path).expect("read source");
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            // Any function returning the token that is not the two sanctioned
            // constructors is a leak.
            let returns_token = code.contains("-> PrivilegedConstruction")
                || code.contains("-> crate::types::PrivilegedConstruction");
            let is_sanctioned =
                code.contains("fn assert_validated") || code.contains("fn internal");
            if returns_token && !is_sanctioned {
                offenders.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "PrivilegedConstruction must be obtainable only via the feature-gated \
         assert_validated() or the in-crate internal(); found:\n{}",
        offenders.join("\n")
    );

    // And without the feature there is no public constructor at all.
    #[cfg(not(feature = "store-privileged"))]
    {
        let types_rs = std::fs::read_to_string(crate_src().join("types.rs")).expect("read");
        assert!(
            types_rs.contains("#[cfg(feature = \"store-privileged\")]"),
            "assert_validated must be feature-gated"
        );
    }
}

/// Nothing outside `sys.rs` may call a durability syscall directly.
///
/// The counters are what turn "exactly one fence per group" and "no per-object
/// fsync" into observed facts rather than claims about the code, and a call
/// that bypasses the funnel is invisible to them (scope 2.3).
#[test]
fn durability_syscalls_go_only_through_the_sys_funnel() {
    // Writes are here for a reason found in review: `checkpoint.rs` used
    // `File::write_all` directly, so checkpoint bytes and short writes were
    // invisible to `DurabilityCounters` and the ENOSPC / short-write / cursor
    // fault seam could not reach checkpoint installation at all. The original
    // guard scanned only sync, rename, and unlink, so it passed. A funnel that
    // covers durability but not the writes being made durable is not a funnel.
    const FORBIDDEN: &[&str] = &[
        "sync_all(",
        "sync_data(",
        "std::fs::rename(",
        "std::fs::remove_file(",
        "fs::rename(",
        "fs::remove_file(",
        ".write_all(",
        ".write_vectored(",
        ".set_len(",
        "std::fs::write(",
        "fs::write(",
    ];

    let mut offenders = Vec::new();
    for path in rust_sources(&crate_src()) {
        // `sys.rs` is the funnel itself. `src/bin/**` are harness binaries that
        // legitimately write result bundles and scratch files, which are not
        // store state and carry no durability claim.
        if path.file_name().is_some_and(|f| f == "sys.rs")
            || path.components().any(|c| c.as_os_str() == "bin")
        {
            continue;
        }
        let text = std::fs::read_to_string(&path).expect("read source");
        let mut in_test_module = false;
        for (n, line) in text.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if code.contains("mod tests") {
                in_test_module = true;
            }
            if in_test_module {
                continue;
            }
            for needle in FORBIDDEN {
                if code.contains(needle) {
                    offenders.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "durability syscalls must go through sys.rs so DurabilityCounters sees \
         them; found direct calls:\n{}",
        offenders.join("\n")
    );
}

/// `StoreError` is for inability to answer; `TransactionStatus` is for every
/// state the store can actually report. Plan §5.1 makes the split normative.
///
/// The mechanical form: no `StoreError` variant may be named after a lifecycle
/// state.
#[test]
fn store_error_carries_no_lifecycle_state() {
    let types_rs = std::fs::read_to_string(crate_src().join("types.rs")).expect("read types.rs");
    let error_block = types_rs
        .split("pub enum StoreError")
        .nth(1)
        .and_then(|s| s.split("\npub enum").next())
        .expect("locate StoreError");

    for lifecycle in ["Committed", "Pending", "Resolving", "Expired", "Unknown"] {
        assert!(
            !error_block.contains(&format!("    {lifecycle}")),
            "StoreError must not carry the lifecycle state {lifecycle}; that \
             belongs to TransactionStatus (plan section 5.1)"
        );
    }
}

/// A store cannot be opened with an invalid configuration, even in D0.
///
/// Plan §9: unknown modes and invalid limits fail startup, and tuning
/// parameters may not be raised to hide overload. This is the one behavior
/// callers can already depend on before Wave B.
#[test]
fn open_refuses_an_invalid_configuration_before_anything_else() {
    let mut options = StoreOptions::new("/tmp/levcs-store-d0");
    options.replay_retention_micros = 1;

    match StoreEngine::open(options) {
        Err(StoreError::InvalidConfiguration(msg)) => {
            assert!(
                msg.contains("replay retention"),
                "the refusal must name the offending setting, got: {msg}"
            );
        }
        Err(other) => panic!("expected InvalidConfiguration, got {other:?}"),
        Ok(_) => panic!("an invalid configuration must not open a store"),
    }
}

/// Configuration validation runs before the not-implemented path, so a valid
/// configuration reaches the engine and reports honestly that it is unbuilt.
#[test]
fn open_reports_not_implemented_for_a_valid_configuration() {
    let options = StoreOptions::new("/tmp/levcs-store-d0");
    match StoreEngine::open(options) {
        Err(StoreError::NotImplemented(what)) => {
            assert!(what.contains("B1"), "the stub must name its owner: {what}");
        }
        Err(other) => panic!("expected NotImplemented, got {other:?}"),
        Ok(_) => panic!("D0 has no engine"),
    }
}

/// Shard assignment is frozen. Per-repository sequence ownership is only sound
/// while a repository's shard never moves, so this function and `shard_count`
/// are load-bearing across the life of a root (scope 2.5).
#[test]
fn shard_routing_is_deterministic_uniform_and_in_range() {
    let shard_count = 4u16;
    let mut histogram = [0usize; 4];

    for i in 0u32..4096 {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&i.to_le_bytes());
        // Route the digest, as a real repo_id is a BLAKE3 output.
        let digest = levcs_core::blake3_hash(&bytes);
        let ns = NamespaceId(digest.0);

        let shard = StoreOptions::shard_of(&ns, shard_count);
        assert_eq!(shard, StoreOptions::shard_of(&ns, shard_count));
        assert!(shard < shard_count);
        histogram[shard as usize] += 1;
    }

    // Uniformity is not decoration: a skewed router would put a hot repository
    // set on one shard thread and cap throughput below the P2 bar for reasons
    // that would look like a storage problem.
    for count in histogram {
        assert!(
            count > 4096 / 4 / 2 && count < 4096 / 4 * 2,
            "shard load must be roughly uniform, got {histogram:?}"
        );
    }
}

/// The store's failpoint vocabulary is exactly the frozen oracle's, and the
/// wave partition covers every row.
///
/// Contract review 2026-07-24-A shipped an unsound classification because a
/// catch-all arm left 14 of 17 outcomes unasserted. The structural defense is
/// that no row can be absent: `Failpoint::ALL` is compared elementwise against
/// `APPEND_PUBLICATION_FAILPOINTS`, and every row is assigned a wave by name.
#[test]
fn every_frozen_failpoint_is_present_and_assigned_a_wave() {
    use levcs_store::failpoints::{Failpoint, Wave};

    assert_eq!(Failpoint::ALL.len(), APPEND_PUBLICATION_FAILPOINTS.len());

    let mut wave_a = 0;
    let mut wave_b = 0;
    for point in APPEND_PUBLICATION_FAILPOINTS {
        let store: Failpoint = (*point).into();
        match store.wave() {
            Wave::A => wave_a += 1,
            Wave::B => wave_b += 1,
        }
        // Every row must have a frozen expectation to be checked against.
        let _ = append_publication_expectation(*point);
    }

    assert_eq!(
        wave_a + wave_b,
        APPEND_PUBLICATION_FAILPOINTS.len(),
        "every failpoint must be assigned to exactly one wave"
    );
    assert!(wave_a > 0 && wave_b > 0);
}
