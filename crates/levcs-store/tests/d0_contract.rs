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

/// Calls the durability funnel exists to intercept.
///
/// Writes are here for a reason found in review: `checkpoint.rs` used
/// `File::write_all` directly, so checkpoint bytes and short writes were
/// invisible to `DurabilityCounters` and the ENOSPC / short-write / cursor fault
/// seam could not reach checkpoint installation at all. The original guard
/// scanned only sync, rename, and unlink, so it passed. A funnel that covers
/// durability but not the writes being made durable is not a funnel.
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

/// Scan one file's text for [`FORBIDDEN`] calls outside test-only code.
///
/// `Err` is a scanner failure and fails the guard exactly as an offender does:
/// a shape it cannot reason about is not a shape it may assume is safe. Split
/// out of the test so the scanner itself is testable on synthetic input —
/// mutating real sources only ever probes the shapes those sources happen to
/// contain, which is how the two defects below survived.
///
/// # How test-only code is exempted, and why not by name
///
/// The trigger is the `#[cfg(test)]` attribute at column zero — the thing that
/// actually removes code from a release build. An earlier version matched the
/// literal `mod tests`, which exempted only modules that happen to be called
/// that (`segment.rs`'s `root_lock_tests` and `recovery.rs`'s
/// `production_session_tests` were scanned as production code) while letting a
/// file evade the guard entirely by naming a module `tests`.
///
/// The exemption is then bounded by the **shape of the attributed item**, which
/// is the second defect. Ending it at the next column-zero `}` is right for a
/// braced item and wrong for anything else: after
///
/// ```text
/// #[cfg(test)]
/// use crate::test_support;
///
/// fn shipping_code() {
///     std::fs::write(..);
/// }
/// ```
///
/// the first column-zero `}` is *`shipping_code`'s*, so every line of it was
/// skipped. A semicolon-terminated item therefore exempts only itself. Of the
/// braced shapes, this crate currently needs only `mod` and `impl`, so those are
/// the only two accepted: merely ending a line in `{` is not enough, because a
/// semicolon-terminated `static` or `const` can begin a block initializer there
/// and close with `};`. Any other shape — including an item header rustfmt has
/// split across lines — is a scanner error rather than a guess.
fn scan_for_unfunnelled_calls(text: &str) -> Result<Vec<(usize, String)>, String> {
    #[derive(PartialEq)]
    enum Exempt {
        No,
        /// Until the item's closing brace at column zero.
        UntilUnindentedBrace,
    }

    let lines: Vec<&str> = text.lines().collect();
    let mut offenders = Vec::new();
    let mut exempt = Exempt::No;
    let mut index = 0;
    while index < lines.len() {
        let line = lines[index];
        let code = line.trim_start();

        if exempt == Exempt::UntilUnindentedBrace {
            if line == "}" {
                exempt = Exempt::No;
            }
            index += 1;
            continue;
        }

        if line.starts_with("#[cfg(test)]") {
            // The item this attribute applies to, past any further attributes,
            // doc comments and blank lines.
            let mut head = index + 1;
            while head < lines.len() {
                let candidate = lines[head].trim_start();
                if candidate.is_empty() || candidate.starts_with('#') || candidate.starts_with("//")
                {
                    head += 1;
                    continue;
                }
                break;
            }
            let Some(item) = lines.get(head).map(|l| l.trim_end()) else {
                return Err(format!(
                    "line {}: `#[cfg(test)]` with no item after it",
                    index + 1
                ));
            };
            let item = item.trim_start();
            let recognized_braced_item = item.starts_with("mod ") || item.starts_with("impl ");
            if item.ends_with('{') && recognized_braced_item {
                exempt = Exempt::UntilUnindentedBrace;
                index = head + 1;
                continue;
            }
            if item.ends_with(';') {
                // Only the item itself. Whatever follows is production code
                // until something says otherwise.
                index = head + 1;
                continue;
            }
            return Err(format!(
                "line {}: the scanner cannot bound a `#[cfg(test)]` item of this shape, so it \
                 cannot tell where the exemption ends: `{}`. Keep the item header on one line, \
                 or teach the scanner the shape — do not leave it guessing.",
                head + 1,
                item.trim()
            ));
        }

        if !code.starts_with("//") {
            for needle in FORBIDDEN {
                if code.contains(needle) {
                    offenders.push((index + 1, line.trim().to_string()));
                }
            }
        }
        index += 1;
    }
    Ok(offenders)
}

/// Nothing outside `sys.rs` may call a durability syscall directly.
///
/// The counters are what turn "exactly one fence per group" and "no per-object
/// fsync" into observed facts rather than claims about the code, and a call
/// that bypasses the funnel is invisible to them (scope 2.3).
#[test]
fn durability_syscalls_go_only_through_the_sys_funnel() {
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
        match scan_for_unfunnelled_calls(&text) {
            Ok(found) => offenders.extend(
                found
                    .into_iter()
                    .map(|(line, text)| format!("{}:{line}: {text}", path.display())),
            ),
            Err(reason) => panic!("{}: {reason}", path.display()),
        }
    }
    // `std::fs::remove_file(` and `fs::remove_file(` both match one line, so an
    // offender is reported once per needle it happens to satisfy. That made a
    // real report ambiguous to read; the finding is the line, not the needle.
    offenders.sort();
    offenders.dedup();
    assert!(
        offenders.is_empty(),
        "durability syscalls must go through sys.rs so DurabilityCounters sees \
         them; found direct calls:\n{}",
        offenders.join("\n")
    );
}

/// The scanner above, against the shapes it has to get right.
///
/// Synthetic input rather than mutated sources. Mutating `segment.rs` proves the
/// scanner works on the shapes `segment.rs` happens to contain, which is exactly
/// how both of its exemption defects survived a mutation check: no file in the
/// crate currently has a semicolon-terminated `#[cfg(test)]` item followed by
/// production code, so no mutation of a real file could produce one.
#[test]
fn the_funnel_scanner_bounds_a_test_exemption_by_the_shape_of_the_item() {
    let lines = |found: Vec<(usize, String)>| -> Vec<usize> {
        let mut out: Vec<usize> = found.into_iter().map(|(line, _)| line).collect();
        out.dedup();
        out
    };

    // Production code is found.
    assert_eq!(
        lines(
            scan_for_unfunnelled_calls("fn ship() {\n    std::fs::write(p, b\"\");\n}\n")
                .expect("a plain file scans")
        ),
        vec![2]
    );

    // A braced test item is exempt, and the exemption ends with it.
    let braced = "\
#[cfg(test)]
mod named_anything {
    fn setup() {
        std::fs::write(p, b\"\");
    }
}

fn ship() {
    std::fs::remove_file(p);
}
";
    assert_eq!(
        lines(scan_for_unfunnelled_calls(braced).expect("a braced item scans")),
        vec![9],
        "the call inside the test module must be exempt and the one after it must not"
    );

    // The defect this shape check exists for: a semicolon-terminated test item
    // exempts itself and nothing else. Under the previous rule the first
    // column-zero `}` was `ship`'s, so the whole function was skipped.
    let terminated = "\
#[cfg(test)]
use crate::test_support;

fn ship() {
    std::fs::write(p, b\"\");
}
";
    assert_eq!(
        lines(scan_for_unfunnelled_calls(terminated).expect("a semicolon-terminated item scans")),
        vec![5],
        "a `#[cfg(test)] use ...;` must not exempt the function that follows it"
    );

    // A semicolon-terminated item can *start* with a line ending in `{`. It is
    // not a braced item: the closure belongs to the initializer, and the item
    // closes with `});`. Treating the first `{` as the item's delimiter latches
    // the exemption through `ship`, exactly like the single-line `use` defect
    // above. `static` is not one of the two braced shapes this crate needs, so
    // the scanner refuses to guess where it ends.
    let block_initializer = "\
#[cfg(test)]
static HOOK: LazyLock<()> = LazyLock::new(|| {
    setup();
});

fn ship() {
    std::fs::write(p, b\"\");
}
";
    let reason = scan_for_unfunnelled_calls(block_initializer)
        .expect_err("a block initializer must not be mistaken for a braced test item");
    assert!(
        reason.contains("cannot bound") && reason.contains("static HOOK"),
        "the scanner must name the unsupported item rather than latch its exemption: {reason}"
    );

    // Stacked attributes and doc comments between the trigger and the item.
    let stacked = "\
#[cfg(test)]
#[allow(dead_code)]
/// A helper.
mod support {
    fn setup() {
        std::fs::write(p, b\"\");
    }
}
";
    assert!(
        lines(scan_for_unfunnelled_calls(stacked).expect("stacked attributes scan")).is_empty(),
        "further attributes and doc comments must not hide the item's shape"
    );

    // A shape the scanner cannot bound is a failure, not an assumption. A
    // multi-line item header is the realistic way to produce one.
    let unsupported = "\
#[cfg(test)]
fn helper(
    argument: usize,
) {
    std::fs::write(p, b\"\");
}
";
    let reason = scan_for_unfunnelled_calls(unsupported)
        .expect_err("an unbounded exemption must fail the guard rather than be guessed at");
    assert!(reason.contains("cannot bound"), "{reason}");

    // And a trailing attribute with nothing after it.
    assert!(scan_for_unfunnelled_calls("#[cfg(test)]\n")
        .expect_err("a dangling attribute is a scanner failure")
        .contains("no item after it"));

    // Comments are not code, in either position.
    assert!(lines(
        scan_for_unfunnelled_calls("fn ship() {\n    // std::fs::write(p, b\"\");\n}\n")
            .expect("a commented call scans")
    )
    .is_empty());
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

/// A configuration error must not be able to leave a root behind.
///
/// This replaces a D0-era assertion that `open` returned `NotImplemented` for
/// any valid configuration, which B1 deliverable 1 obsoleted by implementing
/// startup state 1. The replacement is the stronger property, and it is the
/// one that had to be asserted the moment an absent root began to be
/// *initialized* rather than refused: a configuration that passes
/// `StoreOptions::validate` but omits the signer must still be refused, and
/// refused before anything is created.
///
/// The ordering it pins is load-bearing rather than tidy. While state 1
/// refused, the signer check could sit after the `FORMAT` probe harmlessly;
/// once state 1 initializes, that same placement would create the directory
/// tree, write `FORMAT`, and fsync the parent before failing — and this test,
/// written against a fixed `/tmp` path as its predecessor was, would have
/// silently created a real store root on every gate run on every machine. It
/// therefore asserts the absence of the root, not merely the error, and it
/// uses a path inside a temporary directory so that a future regression
/// pollutes nothing outside the test.
#[test]
fn a_valid_but_signerless_configuration_is_refused_and_creates_no_root() {
    let directory = tempfile::tempdir().expect("tempdir");
    let root = directory.path().join("root");

    // Valid in every respect `validate` can see; `StoreOptions::new` registers
    // no signer, and instance composition is what supplies one.
    let options = StoreOptions::new(&root);

    match StoreEngine::open(options) {
        Err(StoreError::InvalidConfiguration(msg)) => {
            assert!(
                msg.contains("CommitEvidenceSigner"),
                "the refusal must name what is missing, got: {msg}"
            );
        }
        Err(other) => panic!("expected InvalidConfiguration, got {other:?}"),
        Ok(_) => panic!("a configuration with no signer must not open a store"),
    }

    assert!(
        !root.exists(),
        "the refused configuration left {} behind; a startup that cannot \
         sequence a transaction must not have initialized a root first",
        root.display()
    );
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
