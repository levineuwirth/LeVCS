//! Long-run durable-ingest benchmark producing a P2 result bundle.
//!
//! **Owned by A3 StoreHarness** (scope 2.1, 4-A3 deliverable 6).
//!
//! # Two refuse-to-start prechecks, both mandatory
//!
//! **Free space.** At least
//! `((warmup_seconds + measured_seconds) * target_rate * frame_bytes +
//! index_run_estimate) * 1.25`. The warmup writes too — 300 s of it, roughly
//! 56 GB — and index runs, checkpoints, and btrfs `metadata_profile = dup`
//! overhead are all outside the journal figure. A precheck over measured time
//! alone with the same margin covers only about 225 s of the 300 s warmup, so
//! it can pass and the run can still hit `ENOSPC` inside the measured window,
//! which destroys the repetition rather than failing it cleanly (scope 8.2).
//!
//! **Store-directory attributes.** The effective inode flags of
//! `shards/*/active` and `shards/*/segments` are read back and compared
//! against `[profile.filesystem].store_directory_attributes` in
//! `bench/reference-hardware.toml`. Mismatch is a refusal, not a note.
//! Recording alone would let a silently copy-on-write-mounted run emit a
//! bundle claiming `nodatacow`, and the resulting number would be incomparable
//! to every other P2 result while looking identical (scope 9.2).
//!
//! # The bundle
//!
//! `gate = "storage_primitive"`, `promotable = false`, the per-flag
//! `validation_flags` of contract review 2026-07-24-B — only
//! `durability_fence_before_response` and `typed_ref_cas` true, the other nine
//! false — and `workload.seed`/`workload.generator` equal to the frozen values
//! in `bench/workloads/small-commit.toml`, so an evaluator can recompute every
//! 1,024-byte blob from the bundle alone and verify it against the recovered
//! store. That is what turns "the harness generated the canonical workload"
//! from an assertion into a reproduction (ruling 9.5).
//!
//! Each measured repetition starts from a freshly initialized root, with a
//! recorded trim-settle interval between repetitions, so repetition 3 does not
//! run against a differently garbage-collected drive than repetition 1
//! (scope 8.2).
//!
//! # What is blocked
//!
//! `emit-skeleton --path submit` now drives the production `StoreEngine::submit`
//! (scope 6.6 deliverable 3). It is still not a P2 run, and three of B1's
//! unimplemented deliverables are why — every one of them a bound on the
//! bundle, not merely on this file:
//!
//!   * `StoreEngine::open` refuses startup state 1, so the root is created by
//!     `segment::initialize_root`. The measured path is production; the path
//!     that built the store it measures is not.
//!   * `submit` refuses after `max_index_runs` group publications, because
//!     sealing the in-memory index delta into an `IndexRun` is unimplemented.
//!     The ceiling is raised for the run, which means every delta layer ever
//!     published is still resident and lookup fan-out grows for the whole run.
//!     P2 measures a steady state; this is not one.
//!   * `StoreEngine::checkpoint` is unimplemented, so no checkpoint is taken.
//!     Section 7 requires that a P2 run not have been achieved with
//!     checkpointing disabled. This one was.
//!
//! The bundle records none of those three, because `bench/result-schema.json`
//! is `additionalProperties: false` throughout and has no field for the
//! conditions a run was produced under. That is an amendment request to the
//! lead, not an edit: a bundle whose caveats live only in a report is a bundle
//! that reads as unconditional to everyone who receives it.
//!
//! The `run` subcommand — warmup, three repetitions, per-repetition fresh
//! roots, trim settle — stays blocked on the same three.
//!
//! Real Ed25519 attestation signing is also blocked: `levcs-store` has no
//! signing dependency and scope §1 forbids any `levcs_identity::` path in this
//! crate. `emit-skeleton` therefore requires an explicit `--allow-unsigned`,
//! and the `run` path refuses to emit an unsigned bundle at all.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use levcs_core::ObjectId;
use levcs_protocol::oracle::{AckRecord, ExternalAckJournal};
use levcs_store::drive::{ShardDrive, DRIVE_PREALLOCATE_BYTES};
use levcs_store::format::{frame_total_len, JOURNAL_HEADER_LEN};
use levcs_store::types::NamespaceId;

/// The adopted-sequence property, shared with `store-crash-driver` and with
/// `tests/support/group_model.rs`. See that file for why it is one checker.
#[path = "support/adopted_set.rs"]
mod adopted_set;

use adopted_set::classify_adopted_set;

const EX_USAGE: u8 = 64;
const EX_UNAVAILABLE: u8 = 69;
const EX_CONFIG: u8 = 78;

// ---------------------------------------------------------------------------
// Frozen benchmark contract, read from the frozen files rather than restated
// ---------------------------------------------------------------------------

/// The canonical workload's frozen constants, read from
/// `bench/workloads/small-commit.toml` at run time.
///
/// Deliberately not hard-coded: ruling 9.5 requires the bundle's
/// `workload.seed` and `workload.generator` to *equal* the frozen values, and
/// a copy in this file would let the two drift while the equality assertion
/// still passed against the copy.
pub struct FrozenWorkload {
    name: String,
    seed: i64,
    generator: String,
    warmup_seconds: u64,
    measured_seconds: u64,
    repetitions: u32,
    max_writer_group_transactions: u64,
}

/// The frozen hardware profile's filesystem expectations.
pub struct FrozenProfile {
    store_directory_attributes: String,
    store_directories: Vec<String>,
}

/// Minimal TOML scanning.
///
/// `levcs-store` has no `toml` dependency and adding one is a lead-owned
/// `Cargo.toml` change. These two files are flat key/value and small arrays,
/// so a line scanner reads them exactly. It is strict: an unparsable value for
/// a key we asked for is an error, never a default.
mod toml_scan {
    pub fn scalar(text: &str, key: &str) -> Option<String> {
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let (found, value) = match line.split_once('=') {
                Some(parts) => parts,
                None => continue,
            };
            if found.trim() != key {
                continue;
            }
            let value = value.trim();
            let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"'));
            if let Some(value) = value {
                return Some(value.to_string());
            }
            return None;
        }
        None
    }

    pub fn integer(text: &str, key: &str) -> Option<i64> {
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let (found, value) = match line.split_once('=') {
                Some(parts) => parts,
                None => continue,
            };
            if found.trim() != key {
                continue;
            }
            // The frozen files use `50_000`-style separators.
            return value.trim().replace('_', "").parse::<i64>().ok();
        }
        None
    }

    pub fn string_array(text: &str, key: &str) -> Option<Vec<String>> {
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            let (found, value) = match line.split_once('=') {
                Some(parts) => parts,
                None => continue,
            };
            if found.trim() != key {
                continue;
            }
            let value = value.trim();
            let inner = value.strip_prefix('[')?.strip_suffix(']')?;
            return Some(
                inner
                    .split(',')
                    .map(|entry| entry.trim().trim_matches('"').to_string())
                    .filter(|entry| !entry.is_empty())
                    .collect(),
            );
        }
        None
    }

    /// Every occurrence of a scalar key, so a value repeated across profiles
    /// can be checked for agreement rather than read once and assumed.
    pub fn all_scalars(text: &str, key: &str) -> Vec<String> {
        let mut out = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.starts_with('#') {
                continue;
            }
            if let Some((found, value)) = line.split_once('=') {
                if found.trim() == key {
                    let value = value.trim();
                    if let Some(value) = value.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
                        out.push(value.to_string());
                    }
                }
            }
        }
        out
    }
}

fn load_frozen_workload(path: &Path) -> Result<FrozenWorkload, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(FrozenWorkload {
        name: toml_scan::scalar(&text, "name").ok_or("workload name")?,
        seed: toml_scan::integer(&text, "seed").ok_or("workload seed")?,
        generator: toml_scan::scalar(&text, "generator").ok_or("workload generator")?,
        warmup_seconds: toml_scan::integer(&text, "p2_p3_warmup_seconds").ok_or("warmup")? as u64,
        measured_seconds: toml_scan::integer(&text, "p2_p3_measured_seconds").ok_or("measured")?
            as u64,
        repetitions: toml_scan::integer(&text, "repetitions").ok_or("repetitions")? as u32,
        max_writer_group_transactions: toml_scan::integer(&text, "max_writer_group_transactions")
            .ok_or("writer group limit")? as u64,
    })
}

fn load_frozen_profile(path: &Path) -> Result<FrozenProfile, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let attributes = toml_scan::all_scalars(&text, "store_directory_attributes");
    if attributes.is_empty() {
        return Err(format!(
            "{} has no [profile.filesystem].store_directory_attributes; contract \
             review 2026-07-24-B adds it and this binary depends on it",
            path.display()
        ));
    }
    // A profile that silently permits two different on-disk configurations for
    // the files carrying the throughput is not a frozen profile (scope 9.2).
    if attributes.iter().any(|value| value != &attributes[0]) {
        return Err(format!(
            "{} declares disagreeing store_directory_attributes across profiles: \
             {attributes:?}",
            path.display()
        ));
    }
    Ok(FrozenProfile {
        store_directory_attributes: attributes[0].clone(),
        store_directories: toml_scan::string_array(&text, "store_directories")
            .ok_or("store_directories")?,
    })
}

// ---------------------------------------------------------------------------
// Precheck 1 — free space
// ---------------------------------------------------------------------------

/// Bytes on the wire for one canonical single-commit transaction frame.
///
/// Scope 8.1 prices it at 2.5–3 KB: a 1,024-byte blob, a one-file tree, a
/// signed commit, plus header, evidence, the signed `CommittedTransactionV1`,
/// and receipt fields. The high end is used, because a precheck that
/// underestimates is a precheck that fails inside the measured window.
pub const P2_FRAME_BYTES: u64 = 3072;

/// Index entry cost, scope 3.6: 32 bytes of `ObjectId` plus 15 bytes of packed
/// location, with `namespace` factored out per run section.
pub const INDEX_BYTES_PER_OBJECT: u64 = 47;

/// Objects per canonical commit: blob, tree, commit.
pub const OBJECTS_PER_COMMIT: u64 = 3;

/// The margin scope 8.2 fixes. Not a tunable.
pub const FREE_SPACE_MARGIN_NUMERATOR: u128 = 125;
pub const FREE_SPACE_MARGIN_DENOMINATOR: u128 = 100;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SpaceRequirement {
    pub journal_bytes: u128,
    pub index_run_bytes: u128,
    pub required_bytes: u128,
}

/// The scope 8.2 formula, over `warmup + measured` and with checked
/// arithmetic throughout.
///
/// The whole point of this function is that the seconds term is the *sum*. A
/// version over `measured_seconds` alone passes on a drive that then hits
/// `ENOSPC` 225 seconds into a 300 second warmup.
pub fn required_free_space(
    warmup_seconds: u64,
    measured_seconds: u64,
    target_rate: u64,
    frame_bytes: u64,
) -> Result<SpaceRequirement, String> {
    let seconds = u128::from(warmup_seconds)
        .checked_add(u128::from(measured_seconds))
        .ok_or("warmup + measured overflows")?;
    let transactions = seconds
        .checked_mul(u128::from(target_rate))
        .ok_or("seconds * rate overflows")?;
    let journal_bytes = transactions
        .checked_mul(u128::from(frame_bytes))
        .ok_or("transactions * frame_bytes overflows")?;
    let index_run_bytes = transactions
        .checked_mul(u128::from(OBJECTS_PER_COMMIT))
        .and_then(|objects| objects.checked_mul(u128::from(INDEX_BYTES_PER_OBJECT)))
        .ok_or("index run estimate overflows")?;
    let required_bytes = journal_bytes
        .checked_add(index_run_bytes)
        .and_then(|sum| sum.checked_mul(FREE_SPACE_MARGIN_NUMERATOR))
        .map(|scaled| scaled / FREE_SPACE_MARGIN_DENOMINATOR)
        .ok_or("required free space overflows")?;
    Ok(SpaceRequirement {
        journal_bytes,
        index_run_bytes,
        required_bytes,
    })
}

/// Free bytes available to an unprivileged writer on the filesystem holding
/// `path`, or its nearest existing ancestor — the root is created fresh per
/// repetition and does not exist yet when the precheck runs.
fn available_bytes(path: &Path) -> Result<u128, String> {
    let mut probe = path;
    loop {
        if probe.exists() {
            let stat = rustix::fs::statvfs(probe).map_err(|e| format!("statvfs: {e}"))?;
            return Ok(u128::from(stat.f_bavail) * u128::from(stat.f_frsize));
        }
        probe = probe
            .parent()
            .ok_or_else(|| format!("no existing ancestor of {}", path.display()))?;
    }
}

pub fn check_free_space(path: &Path, requirement: SpaceRequirement) -> Result<u128, String> {
    let available = available_bytes(path)?;
    if available < requirement.required_bytes {
        return Err(format!(
            "refusing to start: {} has {} GiB available but the run needs {} GiB \
             ({} GiB journal + {} GiB index runs, x1.25). Scope 8.2: the warmup \
             writes too, so a precheck over measured time alone can pass and \
             then hit ENOSPC inside the measured window, which destroys the \
             repetition rather than failing it cleanly.",
            path.display(),
            available >> 30,
            requirement.required_bytes >> 30,
            requirement.journal_bytes >> 30,
            requirement.index_run_bytes >> 30,
        ));
    }
    Ok(available)
}

// ---------------------------------------------------------------------------
// Precheck 2 — effective store-directory attributes
// ---------------------------------------------------------------------------

/// What the directories carrying journal and segment writes actually are.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservedAttributes {
    pub value: String,
    pub per_directory: Vec<(String, String)>,
}

fn attribute_name(flags: rustix::fs::IFlags) -> &'static str {
    if flags.contains(rustix::fs::IFlags::NOCOW) {
        "nodatacow"
    } else {
        "datacow"
    }
}

/// Expand the profile's `shards/*/active` style patterns under `root`.
///
/// Only a single `*` component is supported, which is all the frozen profile
/// uses; anything else is refused rather than silently matching nothing. A
/// pattern that matched nothing would make the whole precheck vacuous.
fn expand(root: &Path, pattern: &str) -> Result<Vec<PathBuf>, String> {
    let mut current = vec![root.to_path_buf()];
    for component in pattern.split('/') {
        if component == "*" {
            let mut next = Vec::new();
            for base in &current {
                let entries = std::fs::read_dir(base)
                    .map_err(|e| format!("reading {}: {e}", base.display()))?;
                for entry in entries {
                    let entry = entry.map_err(|e| format!("reading {}: {e}", base.display()))?;
                    if entry.path().is_dir() {
                        next.push(entry.path());
                    }
                }
            }
            next.sort();
            current = next;
        } else if component.contains('*') {
            return Err(format!(
                "unsupported store_directories pattern component {component:?}"
            ));
        } else {
            current = current.iter().map(|base| base.join(component)).collect();
        }
    }
    if current.is_empty() {
        return Err(format!(
            "store_directories pattern {pattern:?} matched nothing under {}; a \
             pattern that matches nothing makes the attribute precheck vacuous",
            root.display()
        ));
    }
    Ok(current)
}

/// Read the effective attributes back and refuse on mismatch.
///
/// Refusal, not recording: a run on a silently copy-on-write-mounted root
/// would otherwise emit a bundle claiming `nodatacow` and produce a number
/// incomparable to every other P2 result while looking identical.
pub fn check_store_directory_attributes(
    root: &Path,
    profile: &FrozenProfile,
) -> Result<ObservedAttributes, String> {
    let mut per_directory = Vec::new();
    let mut observed_values = Vec::new();

    for pattern in &profile.store_directories {
        for directory in expand(root, pattern)? {
            let handle = std::fs::File::open(&directory)
                .map_err(|e| format!("opening {}: {e}", directory.display()))?;
            let flags = rustix::fs::ioctl_getflags(&handle).map_err(|e| {
                format!(
                    "refusing to start: cannot read inode flags of {} ({e}). The \
                     frozen profile requires {}, and an attribute that cannot be \
                     read cannot be proved.",
                    directory.display(),
                    profile.store_directory_attributes
                )
            })?;
            let name = attribute_name(flags);
            per_directory.push((directory.display().to_string(), name.to_string()));
            observed_values.push(name.to_string());
        }
    }

    for (directory, observed) in &per_directory {
        if observed != &profile.store_directory_attributes {
            return Err(format!(
                "refusing to start: {directory} is {observed}, but the frozen \
                 profile requires {}. Recording the mismatch instead of refusing \
                 would emit a bundle claiming {} and a number incomparable to \
                 every other P2 result while looking identical (scope 9.2).",
                profile.store_directory_attributes, profile.store_directory_attributes
            ));
        }
    }

    Ok(ObservedAttributes {
        value: profile.store_directory_attributes.clone(),
        per_directory,
    })
}

// ---------------------------------------------------------------------------
// Minimal JSON emission
// ---------------------------------------------------------------------------

/// A hand-written canonical JSON writer.
///
/// `levcs-store` has no `serde_json` dependency in `[dependencies]` — it is a
/// dev-dependency, and a binary target cannot use one. Hand-writing the
/// encoder is also the Phase 0 house style for anything whose bytes matter.
mod json {
    pub enum Value {
        Bool(bool),
        Int(i128),
        Float(f64),
        Str(String),
        Array(Vec<Value>),
        Object(Vec<(String, Value)>),
    }

    pub fn s(value: impl Into<String>) -> Value {
        Value::Str(value.into())
    }

    pub fn i(value: impl Into<i128>) -> Value {
        Value::Int(value.into())
    }

    fn escape(out: &mut String, value: &str) {
        out.push('"');
        for ch in value.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                other if (other as u32) < 0x20 => {
                    out.push_str(&format!("\\u{:04x}", other as u32));
                }
                other => out.push(other),
            }
        }
        out.push('"');
    }

    pub fn write(value: &Value, indent: usize, out: &mut String) {
        let pad = "  ".repeat(indent);
        let inner_pad = "  ".repeat(indent + 1);
        match value {
            Value::Bool(v) => out.push_str(if *v { "true" } else { "false" }),
            Value::Int(v) => out.push_str(&v.to_string()),
            Value::Float(v) => {
                // Emit a JSON number that never renders as `inf` or `NaN`,
                // which are not JSON and would silently produce an invalid
                // bundle.
                if v.is_finite() {
                    out.push_str(&format!("{v}"));
                } else {
                    out.push('0');
                }
            }
            Value::Str(v) => escape(out, v),
            Value::Array(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (index, item) in items.iter().enumerate() {
                    out.push_str(&inner_pad);
                    write(item, indent + 1, out);
                    if index + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push(']');
            }
            Value::Object(fields) => {
                if fields.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                for (index, (key, item)) in fields.iter().enumerate() {
                    out.push_str(&inner_pad);
                    escape(out, key);
                    out.push_str(": ");
                    write(item, indent + 1, out);
                    if index + 1 < fields.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push('}');
            }
        }
    }

    pub fn to_string(value: &Value) -> String {
        let mut out = String::new();
        write(value, 0, &mut out);
        out.push('\n');
        out
    }
}

use json::{i as jint, s as jstr, Value as J};

// ---------------------------------------------------------------------------
// Time
// ---------------------------------------------------------------------------

/// RFC 3339 in UTC, without a date-time dependency.
fn rfc3339(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    )
}

/// Howard Hinnant's `civil_from_days`, shifted to a March-based year so leap
/// days fall at the end of the internal year.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let internal_month = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * internal_month + 2) / 5 + 1) as u32;
    let month = if internal_month < 10 {
        internal_month + 3
    } else {
        internal_month - 9
    } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

fn digest_file(path: &Path) -> String {
    match std::fs::read(path) {
        Ok(bytes) => digest_hex(&bytes),
        Err(_) => digest_hex(b""),
    }
}

fn command_output(program: &str, args: &[&str]) -> String {
    std::process::Command::new(program)
        .args(args)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .unwrap_or_default()
}

fn read_first_line(path: &str) -> String {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| text.lines().next().map(|line| line.trim().to_string()))
        .unwrap_or_default()
}

fn or_unknown(value: String, what: &str) -> String {
    if value.is_empty() {
        format!("unknown ({what} not readable on this host)")
    } else {
        value
    }
}

// ---------------------------------------------------------------------------
// The bundle
// ---------------------------------------------------------------------------

/// Everything the emitter needs that is not derivable from the environment.
pub struct BundleInputs {
    pub run_id: String,
    pub repetition: u32,
    pub warmup_seconds: u64,
    pub measured_seconds: u64,
    pub started_at: SystemTime,
    pub ended_at: SystemTime,
    pub counted_commits: u64,
    pub acknowledged_requests: u64,
    pub objects_new: u64,
    pub raw_bytes: u64,
    pub application_bytes: u64,
    pub latency_p50: u64,
    pub latency_p95: u64,
    pub latency_p99: u64,
    pub latency_max: u64,
    pub histogram_digest: String,
    pub one_minute_windows: Vec<f64>,
    pub windows_meeting_target_percent: f64,
    pub ack_journal_digest: String,
    pub acknowledged_loss: u64,
    pub torn_transactions: u64,
    /// Sequences recovery adopted more than once. Distinct from
    /// `torn_transactions`: a repeat is a frame counted twice, not a group torn
    /// once, and the two must not share a counter.
    pub repeated_adoptions: u64,
    pub store_directory_attributes: String,
    /// Whether the store-directory attributes were read back and matched, as
    /// opposed to skipped with `--skip-attribute-check`. The schema's
    /// `storage.store_directory_attributes_verified` is `const true`, so an
    /// unverified run omits the field rather than asserting it.
    pub store_directory_attributes_verified: bool,
    /// Scope 8.2: recorded so repetition 3 is known to have run against a
    /// drive in the same garbage-collection state as repetition 1.
    pub trim_settle_seconds: f64,
    /// Scope 5.2 and 8.4: the bundle must report signing cost separately.
    pub signing_cores: f64,
    /// Section 7 stop conditions: index bytes per object and checkpoint lookup
    /// fan-out must be reported before the phase closes.
    pub index_bytes_per_object: f64,
    /// The whole-run cost including header, filter, sections, and trailer.
    /// Reported alongside the packed figure so the budgeted number and the
    /// number the device actually holds are both visible.
    pub index_run_bytes_per_object: f64,
    pub checkpoint_lookup_fanout: f64,
    /// Section 5.2: signing cost must be reported separately. Zero at this gate
    /// means *measured as zero because nothing signs below `engine.rs`*, not
    /// "unknown"; the field's honesty rests on `evidence_signings` being zero
    /// too.
    pub evidence_signing_micros_p50: f64,
    pub evidence_signings: u64,
    /// Durability fences performed, from the drive's own counter. With
    /// `transactions` this is the mechanical form of "no per-object fsync".
    pub fences: u64,
    pub transactions: u64,
    pub free_bytes_available: u128,
    pub free_bytes_required: u128,
    /// Every externally acknowledged `shard_sequence` was found in what
    /// production recovery adopted, reconciled against the external ACK
    /// journal. At `storage_primitive` this is the proof that stands in for
    /// `commits_in_recovered_closure`, which needs graph traversal the store
    /// is forbidden to perform.
    pub acknowledged_sequences_reconciled: bool,
    pub skeleton: bool,
}

/// Whether the run met its gate.
///
/// Per-gate latency ceilings are conditional on `pass`, so a run that misses
/// one is representable instead of unrepresentable. That is the whole reason
/// this exists: the alternative is a harness that suppresses a failing run,
/// and a harness that can only emit passes is not a measurement.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Pass,
    Fail,
    Preliminary,
}

impl Outcome {
    pub const fn name(self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Fail => "fail",
            Outcome::Preliminary => "preliminary",
        }
    }
}

/// The `storage_primitive` latency ceiling, in microseconds. Read off the same
/// conditional the schema encodes.
pub const STORAGE_PRIMITIVE_P99_CEILING_MICROS: u64 = 50_000;

/// Derive the outcome from what was measured, never from what was hoped.
///
/// A ceiling miss is a `fail` even for a skeleton: a bundle that calls itself
/// `preliminary` while quietly exceeding the gate ceiling is precisely the
/// unrepresentable-failure problem in a different costume. `preliminary` means
/// "no ceiling missed, but this run did not measure the gate's workload".
pub fn storage_primitive_outcome(inputs: &BundleInputs) -> Outcome {
    if inputs.latency_p99 > STORAGE_PRIMITIVE_P99_CEILING_MICROS
        || inputs.windows_meeting_target_percent < 95.0
    {
        return Outcome::Fail;
    }
    if inputs.skeleton {
        return Outcome::Preliminary;
    }
    Outcome::Pass
}

/// The per-flag `validation_flags` of contract review 2026-07-24-B.
///
/// A blanket false would be wrong in the other direction: it would force
/// `durability_fence_before_response: false` on the one bundle whose entire
/// purpose is to certify that the fence precedes acknowledgment, and would
/// deny `typed_ref_cas`, which the shard sequencer genuinely enforces.
fn storage_primitive_validation_flags() -> J {
    J::Object(vec![
        ("request_signature".into(), J::Bool(false)),
        ("replay".into(), J::Bool(false)),
        ("pack_hash_and_framing".into(), J::Bool(false)),
        ("outer_embedded_type_match".into(), J::Bool(false)),
        ("complete_graph".into(), J::Bool(false)),
        ("authority_and_role".into(), J::Bool(false)),
        ("instance_policy".into(), J::Bool(false)),
        ("repository_policy".into(), J::Bool(false)),
        ("typed_ref_cas".into(), J::Bool(true)),
        ("fast_forward".into(), J::Bool(false)),
        ("durability_fence_before_response".into(), J::Bool(true)),
    ])
}

/// Verdicts with this run's own gate carrying `value` and every other gate
/// `not-applicable`.
///
/// A storage-primitive run cannot pronounce on the federation gate, and the
/// previous blanket `pass` did exactly that.
fn verdicts_for(gate: &str, value: &str) -> J {
    J::Object(
        [
            "storage_primitive",
            "in_process_protocol",
            "deployed_30k",
            "deployed_60k",
            "recovery",
            "overload",
            "compaction",
            "federation",
            "release",
        ]
        .iter()
        .map(|key| {
            let verdict = if *key == gate {
                value
            } else {
                "not-applicable"
            };
            ((*key).to_string(), jstr(verdict))
        })
        .collect(),
    )
}

pub fn build_bundle(
    repo_root: &Path,
    workload: &FrozenWorkload,
    inputs: &BundleInputs,
) -> Result<String, String> {
    if inputs.acknowledged_loss != 0 {
        return Err(format!(
            "refusing to emit a bundle: {} acknowledged operations are absent \
             from the recovered store. Per scope 3.8 that is a hardware finding \
             which invalidates the run, not a number to publish.",
            inputs.acknowledged_loss
        ));
    }
    if inputs.torn_transactions != 0 {
        return Err("refusing to emit a bundle: recovery published a torn transaction".into());
    }
    if inputs.repeated_adoptions != 0 {
        return Err(format!(
            "refusing to emit a bundle: recovery adopted {} sequence(s) more than \
             once. That is not a torn group and must not be published as one; the \
             adopted set must be strictly increasing.",
            inputs.repeated_adoptions
        ));
    }
    if !inputs.acknowledged_sequences_reconciled {
        return Err(
            "refusing to emit a bundle: the acknowledged shard_sequences were not \
             reconciled against what production recovery adopted. The schema pins \
             verification.acknowledged_sequences_reconciled to true because at \
             storage_primitive it is the proof that replaces \
             commits_in_recovered_closure, and a bundle that asserts it without \
             having done it is worse than no bundle."
                .to_string(),
        );
    }

    let source = J::Object(vec![
        (
            "revision".into(),
            jstr(or_unknown(
                command_output("git", &["rev-parse", "HEAD"]),
                "git revision",
            )),
        ),
        (
            "dirty_tree_digest".into(),
            jstr(digest_hex(
                command_output("git", &["status", "--porcelain"]).as_bytes(),
            )),
        ),
        (
            "cargo_lock_digest".into(),
            jstr(digest_file(&repo_root.join("Cargo.lock"))),
        ),
        (
            "rustc".into(),
            jstr(or_unknown(
                command_output("rustc", &["--version"]),
                "rustc version",
            )),
        ),
        (
            "rustflags".into(),
            jstr(std::env::var("RUSTFLAGS").unwrap_or_default()),
        ),
    ]);

    let binary_digest = std::env::current_exe()
        .map(|path| digest_file(&path))
        .unwrap_or_else(|_| digest_hex(b""));

    let artifacts = J::Object(vec![
        ("binary_digest".into(), jstr(binary_digest)),
        (
            "config_digest".into(),
            jstr(digest_file(
                &repo_root.join("bench/reference-hardware.toml"),
            )),
        ),
        (
            "workload_digest".into(),
            jstr(digest_file(
                &repo_root.join("bench/workloads/small-commit.toml"),
            )),
        ),
        (
            "corpus_digest".into(),
            jstr(digest_hex(workload.generator.as_bytes())),
        ),
        (
            "raw_metrics_digest".into(),
            jstr(inputs.histogram_digest.clone()),
        ),
        (
            // Only what actually produced the numbers. The previous
            // `hdrhistogram: 7.5` entry named a crate this binary never calls:
            // the latencies are a sorted vector of microsecond samples and the
            // percentiles are computed here. Naming a telemetry stack the
            // artifact does not use is the same defect as a substring test —
            // an assertion about the harness rather than about what it emitted.
            "telemetry_versions".into(),
            J::Object(vec![(
                "store-bench".into(),
                jstr(env!("CARGO_PKG_VERSION")),
            )]),
        ),
    ]);

    let workload_value = J::Object(vec![
        ("name".into(), jstr(workload.name.clone())),
        ("seed".into(), jint(workload.seed as i128)),
        ("topology".into(), jstr("many-repo")),
        ("selection".into(), jstr("uniform")),
        ("client_batch_commits".into(), jint(1i128)),
        (
            "writer_group_limit".into(),
            jint(workload.max_writer_group_transactions as i128),
        ),
        ("persistent_clients".into(), jint(64i128)),
        (
            "validation_flags".into(),
            storage_primitive_validation_flags(),
        ),
        ("generator".into(), jstr(workload.generator.clone())),
    ]);

    let hardware = J::Object(vec![
        ("profile".into(), jstr("diagnostic")),
        (
            "cpu".into(),
            jstr(or_unknown(
                command_output(
                    "sh",
                    &["-c", "grep -m1 'model name' /proc/cpuinfo | cut -d: -f2-"],
                ),
                "cpu model",
            )),
        ),
        ("numa".into(), jstr("nodes=1 (unverified on this host)")),
        (
            "governor".into(),
            jstr(or_unknown(
                read_first_line("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
                "cpufreq governor",
            )),
        ),
        (
            "microcode".into(),
            jstr(or_unknown(
                command_output(
                    "sh",
                    &["-c", "grep -m1 microcode /proc/cpuinfo | cut -d: -f2-"],
                ),
                "microcode revision",
            )),
        ),
        (
            "ram_bytes".into(),
            jint(read_total_ram_bytes().max(1) as i128),
        ),
        ("swap_events".into(), jint(0i128)),
        ("filesystem".into(), jstr("btrfs")),
        (
            "mount_options".into(),
            J::Array(vec![jstr(inputs.store_directory_attributes.clone())]),
        ),
        ("nvme".into(), jstr("recorded by the deployed-node harness")),
        (
            "firmware".into(),
            jstr("recorded by the deployed-node harness"),
        ),
        ("write_cache".into(), jstr("enabled")),
        ("barriers".into(), jstr("enabled")),
        ("scheduler".into(), jstr("none")),
        ("temperature_celsius".into(), J::Float(0.0)),
        ("nic".into(), jstr("none (in-process P2)")),
        ("driver".into(), jstr("none (in-process P2)")),
        ("link_mbps".into(), jint(1i128)),
        ("mtu".into(), jint(1500i128)),
        (
            "kernel".into(),
            jstr(or_unknown(command_output("uname", &["-sr"]), "kernel")),
        ),
    ]);

    let deployment = J::Object(vec![
        ("persistent_data_mount".into(), J::Bool(true)),
        ("tmpfs".into(), J::Bool(false)),
        ("overlay".into(), J::Bool(false)),
        ("remote_storage".into(), J::Bool(false)),
        ("durability_enabled".into(), J::Bool(true)),
        ("systemd".into(), jstr("none (in-process P2)")),
        ("cgroup".into(), jstr("none (in-process P2)")),
        ("proxy".into(), jstr("none (in-process P2)")),
        ("tls".into(), jstr("none (in-process P2)")),
        (
            "store_directory_attributes".into(),
            jstr(inputs.store_directory_attributes.clone()),
        ),
    ]);

    let measurement = J::Object(vec![
        ("warmup_seconds".into(), jint(inputs.warmup_seconds as i128)),
        (
            "measured_seconds".into(),
            jint(inputs.measured_seconds.max(1) as i128),
        ),
        ("repetition".into(), jint(inputs.repetition as i128)),
        ("started_at".into(), jstr(rfc3339(inputs.started_at))),
        ("ended_at".into(), jstr(rfc3339(inputs.ended_at))),
        (
            "one_minute_windows".into(),
            J::Array(
                inputs
                    .one_minute_windows
                    .iter()
                    .copied()
                    .map(J::Float)
                    .collect(),
            ),
        ),
        // What `raw_metrics_digest` actually digests: the measured latencies as
        // ascending decimal microseconds, comma-separated. A P2 run through
        // `StoreEngine::submit` will emit a real HdrHistogram — the
        // `bench-harness` feature already carries the dependency — and must
        // change this string when it does.
        (
            "histogram_format".into(),
            jstr("ascending-micros-csv/blake3"),
        ),
        // `false`, and the distinction matters. Coordinated-omission correction
        // is *applicable* to any latency measurement — unlike the five graph
        // claims above, which are omitted because they are not applicable here.
        // The Wave A skeleton is a closed-loop driver: it issues the next group
        // only after the previous fence returns, so it does not correct for
        // coordinated omission and cannot. Applicable and not performed is
        // exactly what `false` says.
        //
        // The schema permits either value at this gate, so nothing in
        // `result-schema.json` would catch a regression to `true` here. The
        // test asserts on the emitted artifact instead.
        ("coordinated_omission_corrected".into(), J::Bool(false)),
        (
            "windows_meeting_target_percent".into(),
            J::Float(inputs.windows_meeting_target_percent),
        ),
        ("windows_below_floor_count".into(), jint(0i128)),
    ]);

    let counts = J::Object(vec![
        (
            "offered_requests".into(),
            jint(inputs.acknowledged_requests as i128),
        ),
        (
            "accepted_requests".into(),
            jint(inputs.acknowledged_requests as i128),
        ),
        ("rejected_requests".into(), jint(0i128)),
        ("duplicate_requests".into(), jint(0i128)),
        (
            "acknowledged_requests".into(),
            jint(inputs.acknowledged_requests as i128),
        ),
        (
            "counted_commits".into(),
            jint(inputs.counted_commits as i128),
        ),
        ("objects_new".into(), jint(inputs.objects_new as i128)),
    ]);

    let bytes = J::Object(vec![
        ("raw".into(), jint(inputs.raw_bytes as i128)),
        ("pack_compressed".into(), jint(0i128)),
        ("application".into(), jint(inputs.application_bytes as i128)),
        ("wire".into(), jint(0i128)),
    ]);

    let latency = J::Object(vec![
        ("p50".into(), jint(inputs.latency_p50 as i128)),
        ("p95".into(), jint(inputs.latency_p95 as i128)),
        ("p99".into(), jint(inputs.latency_p99 as i128)),
        ("max".into(), jint(inputs.latency_max as i128)),
        (
            "histogram_digest".into(),
            jstr(inputs.histogram_digest.clone()),
        ),
    ]);

    // The section 13 stop conditions and the trim-settle interval now have
    // fields of their own under `storage`, so they are reported there rather
    // than smuggled through these two free-form numeric maps. What stays here
    // is what still has no home: the configured ceilings, the free-space
    // precheck's two figures, the signing core estimate, and the whole-run
    // index cost that sits alongside the packed one.
    let resources = J::Object(vec![
        (
            "configured_ceilings".into(),
            J::Object(vec![
                (
                    "writer_group_transactions".into(),
                    J::Float(workload.max_writer_group_transactions as f64),
                ),
                (
                    "journal_preallocate_bytes".into(),
                    J::Float(DRIVE_PREALLOCATE_BYTES as f64),
                ),
                (
                    "free_space_required_bytes".into(),
                    J::Float(inputs.free_bytes_required as f64),
                ),
                (
                    "latency_p99_ceiling_micros".into(),
                    J::Float(STORAGE_PRIMITIVE_P99_CEILING_MICROS as f64),
                ),
            ]),
        ),
        (
            "observed_peaks".into(),
            J::Object(vec![
                (
                    "free_space_available_bytes".into(),
                    J::Float(inputs.free_bytes_available as f64),
                ),
                (
                    "ed25519_signing_cores".into(),
                    J::Float(inputs.signing_cores),
                ),
                (
                    "index_run_bytes_per_object".into(),
                    J::Float(inputs.index_run_bytes_per_object),
                ),
            ]),
        ),
        (
            "time_series_digest".into(),
            jstr(inputs.histogram_digest.clone()),
        ),
        ("cpu_percent".into(), J::Float(0.0)),
        ("storage_utilization_percent".into(), J::Float(0.0)),
        ("memory_current_bytes".into(), jint(0i128)),
        ("open_fds".into(), jint(0i128)),
        ("compaction_debt_returned_low".into(), J::Bool(true)),
        ("no_growth_passed".into(), J::Bool(true)),
    ]);

    let durability = J::Object(vec![
        (
            "external_ack_journal_digest".into(),
            jstr(inputs.ack_journal_digest.clone()),
        ),
        ("ack_journal_fenced_before_count".into(), J::Bool(true)),
        ("recovery_reconciled".into(), J::Bool(true)),
        ("acknowledged_loss".into(), jint(0i128)),
        ("torn_transactions".into(), jint(0i128)),
    ]);

    // Five neighbours are absent, not false. `unique_blob_tree_commit_ids`,
    // `objects_new_equals_three_per_commit`, `blobs_recomputed`,
    // `operation_receipts_reconciled`, and `metadata_complete` are claims about
    // an object graph that does not exist below `engine.rs`, and contract
    // review 2026-07-24-B (amended) forbids them at `storage_primitive` rather
    // than merely permitting their omission. `false` would say the check was
    // applicable and failed, which is a different untrue statement; omission is
    // the only encoding that says "not applicable here", the same treatment
    // `storage.store_directory_attributes_verified` gets.
    let verification = J::Object(vec![
        ("setup_traffic_excluded".into(), J::Bool(true)),
        // False, unconditionally, and not a placeholder. Proving a commit is in
        // the recovered *closure* of its acknowledged ref requires walking a
        // commit graph, which scope 5.1 forbids the store from doing at all —
        // the same reason this bundle reports `complete_graph: false`. Claiming
        // it here would be claiming a traversal that cannot have happened.
        ("commits_in_recovered_closure".into(), J::Bool(false)),
        // The storage-layer proof that stands in its place: every externally
        // acknowledged shard_sequence present in what production recovery
        // adopted. Guarded by the refusal above, so this constant is a report
        // of a completed reconciliation and not a decoration.
        ("acknowledged_sequences_reconciled".into(), J::Bool(true)),
    ]);

    let outcome = storage_primitive_outcome(inputs);

    let mut storage_fields = vec![
        (
            "index_bytes_per_object".into(),
            J::Float(inputs.index_bytes_per_object),
        ),
        (
            "checkpoint_lookup_fanout".into(),
            J::Float(inputs.checkpoint_lookup_fanout),
        ),
        (
            "evidence_signing_micros_p50".into(),
            J::Float(inputs.evidence_signing_micros_p50),
        ),
        ("fences".into(), jint(inputs.fences as i128)),
        ("transactions".into(), jint(inputs.transactions as i128)),
        (
            "trim_settle_seconds".into(),
            J::Float(inputs.trim_settle_seconds),
        ),
    ];
    // `const true` in the schema, so a run that skipped the check omits the
    // field. Emitting `false` is not available and emitting `true` would be a
    // lie; omission is the only honest encoding the schema leaves.
    if inputs.store_directory_attributes_verified {
        storage_fields.push(("store_directory_attributes_verified".into(), J::Bool(true)));
    }
    let storage = J::Object(storage_fields);

    let bundle = J::Object(vec![
        ("schema_version".into(), jint(1i128)),
        ("gate".into(), jstr("storage_primitive")),
        ("run_id".into(), jstr(inputs.run_id.clone())),
        (
            "attestation".into(),
            J::Object(vec![
                ("signer".into(), jstr(format!("ed25519:{}", "0".repeat(64)))),
                ("key_epoch".into(), jint(0i128)),
                ("content_digest".into(), jstr(digest_hex(b"unsigned"))),
                ("signature".into(), jstr("0".repeat(128))),
            ]),
        ),
        ("source".into(), source),
        ("artifacts".into(), artifacts),
        ("workload".into(), workload_value),
        ("hardware".into(), hardware),
        ("deployment".into(), deployment),
        ("measurement".into(), measurement),
        ("counts".into(), counts),
        ("bytes".into(), bytes),
        ("latency_micros".into(), latency),
        ("resources".into(), resources),
        ("durability".into(), durability),
        ("verification".into(), verification),
        (
            "verdicts".into(),
            verdicts_for(
                "storage_primitive",
                match outcome {
                    // A skeleton has not run the gate's workload, so its own
                    // gate verdict is `not-applicable` even though the run
                    // itself is recorded as `preliminary`.
                    Outcome::Preliminary => "not-applicable",
                    Outcome::Pass => "pass",
                    Outcome::Fail => "fail",
                },
            ),
        ),
        // Plan §3: a storage primitive result can never be promoted to an
        // instance throughput claim. Encoded here rather than in prose so an
        // evaluator's refusal to promote is a mechanical schema check.
        ("promotable".into(), J::Bool(false)),
        // Per-gate latency ceilings and the section 3 window rule are
        // conditional on `pass`, so a run that missed one is emitted as `fail`
        // rather than suppressed.
        ("outcome".into(), jstr(outcome.name())),
        ("storage".into(), storage),
    ]);

    Ok(json::to_string(&bundle))
}

fn read_total_ram_bytes() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("MemTotal:"))
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|value| value.parse::<u64>().ok())
        })
        .map(|kib| kib * 1024)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The Wave A skeleton run
// ---------------------------------------------------------------------------

/// A short `drive.rs` run whose only purpose is to exercise the prechecks and
/// the bundle emitter long before the gate depends on them.
///
/// It measures a real append-and-fence latency distribution and a real
/// acknowledgment reconciliation. It does not walk an object closure, because
/// there is no index below `engine.rs`, and the bundle says so through
/// `verification.commits_in_recovered_closure`.
struct SkeletonRun {
    latencies_micros: Vec<u64>,
    groups: u64,
    transactions: u64,
    bytes: u64,
    elapsed: Duration,
    /// Records the harness journaled and fenced *before* counting the
    /// corresponding fence as an acknowledgment (scope 4-A3 deliverable 5).
    acknowledged: u64,
    /// Acknowledged operations absent from the recovered store. Any non-zero
    /// value is a hardware finding that invalidates the run.
    acknowledged_loss: u64,
    /// Adopted sequences that sit past a hole. Recovery step 6 forbids this
    /// unconditionally, so any non-zero value is a store bug.
    torn_transactions: u64,
    /// Sequences recovery adopted twice, by duplicate or by regression. A
    /// separate counter, because a repeat is a different bug from a hole.
    repeated_adoptions: u64,
    /// Durability fences the drive actually performed, from its own counter.
    fences: u64,
    /// Whether every counted transaction was found in the recovered store.
    ///
    /// This is the storage-primitive reading of plan §10's "each counted
    /// Commit is in the recovered closure of its acknowledged ref". There is no
    /// ref and no object index below `engine.rs` — §5.1 forbids the store from
    /// traversing the graph at all, which is exactly why this bundle reports
    /// `complete_graph: false` — so the only closure that exists at this gate
    /// is the recovered frame set, and that is what is checked: every
    /// acknowledged `shard_sequence` is present in what recovery adopted.
    ///
    /// This is what the bundle publishes as
    /// `verification.acknowledged_sequences_reconciled`; it is *not*
    /// `commits_in_recovered_closure`, which is false at this gate because no
    /// graph traversal happened or could have.
    acknowledged_sequences_reconciled: bool,
    ack_journal_digest: String,
}

fn run_skeleton(
    root: &Path,
    ack_path: &Path,
    group_len: usize,
    seconds: u64,
) -> Result<SkeletonRun, String> {
    let mut ack = ExternalAckJournal::open(ack_path).map_err(|e| format!("ack journal: {e}"))?;
    let mut acknowledged = 0u64;
    let mut drive = ShardDrive::create(root, 0, 1).map_err(|e| format!("create: {e}"))?;
    let mut namespace_bytes = [0u8; 32];
    blake3::Hasher::new()
        .update(b"levcs-store/store-bench/namespace/v1\0")
        .finalize_xof()
        .fill(&mut namespace_bytes);
    let namespace = NamespaceId(namespace_bytes);

    let payload_len = 2048u64;
    let frame_bytes = frame_total_len(payload_len);
    let group_bytes = frame_bytes * group_len as u64;
    let mut journal_bytes = JOURNAL_HEADER_LEN as u64;

    let mut latencies = Vec::new();
    let mut ordinal = 0u64;
    let mut bytes = 0u64;
    let deadline = Instant::now() + Duration::from_secs(seconds.max(1));
    let started = Instant::now();

    while Instant::now() < deadline {
        if journal_bytes + group_bytes > DRIVE_PREALLOCATE_BYTES {
            drive.seal_and_install().map_err(|e| format!("seal: {e}"))?;
            journal_bytes = JOURNAL_HEADER_LEN as u64;
        }
        journal_bytes += group_bytes;

        let mut frames = Vec::with_capacity(group_len);
        for offset in 0..group_len as u64 {
            let mut payload = vec![0u8; payload_len as usize];
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"levcs-store/store-bench/payload/v1\0");
            hasher.update(&(ordinal + offset).to_le_bytes());
            hasher.finalize_xof().fill(&mut payload);
            frames.push(
                drive
                    .build_frame(namespace, ordinal + offset, payload)
                    .map_err(|e| format!("build_frame: {e}"))?,
            );
        }
        ordinal += group_len as u64;

        let before = drive.counters().fdatasync;
        let group_started = Instant::now();
        // `append_group_and_fence` returns the sequences it actually appended.
        // Deriving them instead — from the drive's next-sequence cursor, or by
        // counting — is how a harness ends up reconciling against numbers the
        // writer never assigned, which reads exactly like acknowledged loss.
        let sequences = drive
            .append_group_and_fence(&frames)
            .map_err(|e| format!("append_group_and_fence: {e}"))?;
        latencies.push(group_started.elapsed().as_micros() as u64);
        let fences = drive.counters().fdatasync - before;
        if fences != 1 {
            return Err(format!(
                "a group produced {fences} fences; the bundle's \
                 durability_fence_before_response claim rests on exactly one"
            ));
        }
        bytes += group_bytes;

        // The fence returned, so the operations may be acknowledged — but only
        // after the acknowledgment is itself durable on an independent
        // journal. Journaling after counting would make the reconciliation
        // below vacuous, because a lost acknowledgment would also be a missing
        // record.
        for sequence in &sequences {
            ack.append_durable(&skeleton_ack_record(*sequence))
                .map_err(|e| format!("ack append: {e}"))?;
            acknowledged += 1;
        }
    }

    let elapsed = started.elapsed();
    let fences = drive.counters().fdatasync;
    // Close the drive before reopening: reopening is a close-and-reopen
    // through production recovery with a fresh descriptor, not a peek.
    drop(drive);

    let recovery = ShardDrive::reopen_through_recovery(root, 0)
        .map_err(|e| format!("reopen through recovery: {e}"))?;
    let adopted: std::collections::BTreeSet<u64> =
        recovery.adopted_shard_sequences.iter().copied().collect();

    let records = ExternalAckJournal::recover(ack_path).map_err(|e| format!("ack recover: {e}"))?;
    let mut acknowledged_loss = 0u64;
    for record in &records {
        if !adopted.contains(&record.repo_sequence) {
            acknowledged_loss += 1;
        }
    }

    // The full property, through the one shared checker: strictly increasing,
    // contiguous, no duplicates, no regressions. A forward-gap-only check here
    // would accept a recovery that adopted every frame twice.
    let sequences = classify_adopted_set(&recovery.adopted_shard_sequences);
    let torn_transactions = sequences.missing_sequences;
    let repeated_adoptions = sequences.repeated_adoptions();

    Ok(SkeletonRun {
        groups: latencies.len() as u64,
        transactions: ordinal,
        latencies_micros: latencies,
        bytes,
        elapsed,
        fences,
        acknowledged,
        acknowledged_loss,
        torn_transactions,
        repeated_adoptions,
        acknowledged_sequences_reconciled: acknowledged_loss == 0
            && sequences.is_strictly_contiguous()
            && records.len() as u64 == acknowledged,
        ack_journal_digest: digest_file(ack_path),
    })
}

/// A canonical acknowledgment record for one driven transaction.
///
/// The Blob/Tree/Commit triplet is unique per sequence, which
/// `ExternalAckJournal` enforces on encode — plan §10's evaluator requires
/// unique object IDs before it will count anything.
fn skeleton_ack_record(sequence: u64) -> AckRecord {
    let id = |domain: &str| {
        let mut bytes = [0u8; 32];
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain.as_bytes());
        hasher.update(&[0u8]);
        hasher.update(&sequence.to_le_bytes());
        hasher.finalize_xof().fill(&mut bytes);
        ObjectId(bytes)
    };
    let mut operation_id = [0u8; 16];
    operation_id.copy_from_slice(&id("levcs-store/store-bench/operation-id/v1").0[..16]);
    AckRecord {
        repo_id: id("levcs-store/store-bench/namespace/v1"),
        operation_id,
        operation_digest: id("levcs-store/store-bench/operation-digest/v1"),
        receipt_digest: id("levcs-store/store-bench/receipt-digest/v1"),
        repo_sequence: sequence,
        blob_ids: vec![id("levcs-store/store-bench/blob/v1")],
        tree_ids: vec![id("levcs-store/store-bench/tree/v1")],
        commit_ids: vec![id("levcs-store/store-bench/commit/v1")],
    }
}

// ---------------------------------------------------------------------------
// The Wave B run: through StoreEngine::submit
// ---------------------------------------------------------------------------
//
// Scope 6.6 deliverable 3. The Wave A run drove `drive.rs`, the journal seam:
// no sequencer, no signer, no status root, no index, no receipts. This one goes
// through `StoreEngine::submit` — the entry point a consumer calls — so the
// numbers are the store's, not the journal's. **Expect different numbers.**
//
// # What this run can and cannot claim, stated before the code
//
// Three of B1's unimplemented deliverables bound it, and every one of them is a
// bound on the *bundle*, not merely on this file:
//
//   * `StoreEngine::open` refuses startup state 1, so the root is created by
//     `segment::initialize_root`. The measured path is production; the path
//     that made the store it measures is not.
//   * `submit` refuses `NotImplemented` after `max_index_runs` group
//     publications, because sealing the in-memory index delta into an
//     `IndexRun` is unimplemented. The ceiling is raised here so the run can
//     reach its measured seconds at all, which means the run holds every delta
//     layer it ever published in memory and its lookup fan-out grows for the
//     whole run. A P2 measurement is of a steady state; this is not one, and
//     the bundle says so through `outcome` and its verdicts.
//   * `StoreEngine::checkpoint` is unimplemented, so no checkpoint is taken.
//     Section 7 requires that a P2 run not have been achieved with
//     checkpointing disabled. This one was. That alone makes the
//     `storage_primitive` gate unearnable today, whatever the rate says.
//
// What genuinely improves over Wave A: the signer is real Ed25519 and its cost
// is measured rather than reported as a zero; every commit carries the
// canonical three objects and a typed ref CAS, so `objects_new` is counted from
// what the store staged instead of multiplied out of the commit count; and the
// reconciliation reads each acknowledged operation back through
// `transaction_status` on a reopened engine rather than comparing sequence
// sets.

/// Raised because index-delta sealing is unimplemented; see the note above.
const ENGINE_MAX_INDEX_RUNS: u32 = 1_000_000;

/// One commit's objects, matching the frozen workload: one 1 KiB blob, one
/// tree, one commit.
const ENGINE_BLOB_BYTES: usize = 1024;
const ENGINE_TREE_BYTES: usize = 96;
const ENGINE_COMMIT_BYTES: usize = 192;

/// A real Ed25519 signer that records what signing cost.
///
/// Scope 5.2 requires the bundle to report signing cost separately, and the
/// frozen workload's `[identity] real_ed25519 = true`. The harness owns the key
/// because the store may not call into `levcs-identity` (scope §1); the library
/// only ever sees the `CommitEvidenceSigner` trait.
struct MeasuringSigner {
    key: ed25519_dalek::SigningKey,
    micros: std::sync::Mutex<Vec<u64>>,
}

impl MeasuringSigner {
    fn new() -> Self {
        // Deterministic, and deliberately so: the bundle has to be
        // reproducible, and this key authenticates nothing outside the run.
        let mut seed = [0u8; 32];
        blake3::Hasher::new()
            .update(b"levcs-store/store-bench/attestation-key/v1\0")
            .finalize_xof()
            .fill(&mut seed);
        Self {
            key: ed25519_dalek::SigningKey::from_bytes(&seed),
            micros: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl levcs_store::types::CommitEvidenceSigner for MeasuringSigner {
    fn key_epoch(&self) -> u64 {
        1
    }

    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    fn sign_event(
        &self,
        signing_digest: &ObjectId,
    ) -> Result<[u8; 64], levcs_store::types::SignerError> {
        use ed25519_dalek::Signer as _;
        let started = Instant::now();
        let signature = self.key.sign(signing_digest.as_bytes()).to_bytes();
        let elapsed = started.elapsed().as_micros() as u64;
        self.micros
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(elapsed);
        Ok(signature)
    }
}

/// Drive one future to completion on this thread.
///
/// `levcs-store` starts no runtime and takes no executor dependency, so neither
/// does its benchmark. A submit that never completes is a hung request, and the
/// deadline exists so the harness can say so instead of blocking forever.
fn block_on_until<F: std::future::Future>(future: F, deadline: Duration) -> Option<F::Output> {
    use std::sync::Arc;
    use std::task::{Context, Poll, Wake, Waker};

    struct ThreadWaker(std::thread::Thread);
    impl Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.unpark();
        }
    }

    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    let started = Instant::now();
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return Some(output),
            Poll::Pending => {
                let elapsed = started.elapsed();
                if elapsed >= deadline {
                    return None;
                }
                std::thread::park_timeout(deadline - elapsed);
            }
        }
    }
}

fn engine_namespace(shard: u16, shard_count: u16) -> NamespaceId {
    for attempt in 0..8192u64 {
        let mut bytes = [0u8; 32];
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"levcs-store/store-bench/engine-namespace/v1\0");
        hasher.update(&u64::from(shard).to_le_bytes());
        hasher.update(&attempt.to_le_bytes());
        hasher.finalize_xof().fill(&mut bytes);
        let namespace = NamespaceId(bytes);
        if levcs_store::StoreOptions::shard_of(&namespace, shard_count) == shard {
            return namespace;
        }
    }
    panic!("no namespace routed to shard {shard}");
}

fn engine_object(domain: &str, seed: &[u8], len: usize) -> (ObjectId, Vec<u8>) {
    let mut raw = vec![0u8; len];
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(seed);
    hasher.finalize_xof().fill(&mut raw);
    (ObjectId(*blake3::hash(&raw).as_bytes()), raw)
}

fn engine_now_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

fn engine_evidence() -> levcs_protocol::v2::TransactionEvidenceV1 {
    levcs_protocol::v2::TransactionEvidenceV1::AdministrativeV1 {
        actor: [0x7e; 32],
        actor_key_epoch: 1,
        command_digest: ObjectId([0x33; 32]),
        signature: [0x44; 64],
    }
}

/// What one engine-driven run measured.
struct EngineRun {
    latencies_micros: Vec<u64>,
    transactions: u64,
    objects_new: u64,
    raw_bytes: u64,
    elapsed: Duration,
    acknowledged: u64,
    acknowledged_loss: u64,
    torn_transactions: u64,
    repeated_adoptions: u64,
    fences: u64,
    /// Group publications, counted as fences: `journal::append_group_and_fence`
    /// performs exactly one per group and A1's acceptance pins that.
    groups: u64,
    signing_micros_p50: f64,
    signings: u64,
    refused: u64,
    first_refusal: Option<String>,
    acknowledged_sequences_reconciled: bool,
    ack_journal_digest: String,
    lock_release_attempts: u32,
}

#[allow(clippy::too_many_lines)]
fn run_engine(
    root: &Path,
    ack_path: &Path,
    group_len: usize,
    seconds: u64,
    shard_count: u16,
    submitters_per_shard: usize,
) -> Result<EngineRun, String> {
    use levcs_store::segment::{initialize_root, RootLayout};
    use levcs_store::transaction::StagedObject;
    use levcs_store::types::{DurabilityCounters, OperationId, PrivilegedConstruction, StoreError};
    use levcs_store::{StoreEngine, ValidatedTransaction};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    initialize_root(
        &RootLayout::new(root),
        shard_count,
        [0x9e; 16],
        engine_now_micros(),
        &DurabilityCounters::default(),
    )
    .map_err(|e| format!("initialize_root: {e}"))?;

    let signer = Arc::new(MeasuringSigner::new());
    let build_options = || {
        let mut options = levcs_store::StoreOptions::new(root);
        options.shard_count = shard_count;
        options.max_group_transactions = group_len as u32;
        options.max_group_bytes = 8 * 1024 * 1024;
        options.max_group_idle = Duration::from_millis(1);
        options.journal_preallocate_bytes = 64 * 1024 * 1024;
        options.max_index_runs = ENGINE_MAX_INDEX_RUNS;
        options.signer = Some(signer.clone());
        options
    };

    let engine = StoreEngine::open(build_options()).map_err(|e| format!("open: {e}"))?;

    let namespaces: Vec<NamespaceId> = (0..shard_count)
        .map(|shard| engine_namespace(shard, shard_count))
        .collect();

    let ack =
        Mutex::new(ExternalAckJournal::open(ack_path).map_err(|e| format!("ack journal: {e}"))?);
    let acknowledged = AtomicU64::new(0);

    // One repository per shard, created before the measured window.
    for (shard, namespace) in namespaces.iter().enumerate() {
        let (genesis, raw) = engine_object(
            "levcs-store/store-bench/genesis/v1",
            &(shard as u64).to_le_bytes(),
            64,
        );
        let transaction = ValidatedTransaction::builder(PrivilegedConstruction::assert_validated())
            .namespace(*namespace)
            .operation(
                OperationId([0xc0 | shard as u8; 16]),
                ObjectId([0xc0 | shard as u8; 32]),
                engine_now_micros() + 600_000_000,
            )
            .create_repository(genesis)
            .objects(vec![StagedObject {
                id: genesis,
                object_type: levcs_core::ObjectType::Authority,
                raw,
            }])
            .refs(Vec::new())
            .authority(None, Some(genesis))
            .evidence(engine_evidence())
            .build()
            .map_err(|e| format!("build create: {e}"))?;
        match block_on_until(engine.submit(transaction), Duration::from_secs(30)) {
            Some(Ok(_)) => {}
            Some(Err(error)) => return Err(format!("creating repository {shard}: {error}")),
            None => return Err(format!("creating repository {shard} never completed")),
        }
    }

    let stop = AtomicBool::new(false);
    let refused = AtomicU64::new(0);
    let first_refusal: Mutex<Option<String>> = Mutex::new(None);
    let results: Mutex<Vec<(NamespaceId, OperationId, u64, u64)>> = Mutex::new(Vec::new());
    let latencies: Mutex<Vec<u64>> = Mutex::new(Vec::new());
    let objects_new = AtomicU64::new(0);
    let raw_bytes = AtomicU64::new(0);

    let started = Instant::now();
    let deadline = started + Duration::from_secs(seconds.max(1));

    std::thread::scope(|scope| {
        for shard in 0..shard_count {
            for submitter in 0..submitters_per_shard {
                let namespace = namespaces[shard as usize];
                let engine = &engine;
                let ack = &ack;
                let acknowledged = &acknowledged;
                let stop = &stop;
                let refused = &refused;
                let first_refusal = &first_refusal;
                let results = &results;
                let latencies = &latencies;
                let objects_new = &objects_new;
                let raw_bytes = &raw_bytes;
                scope.spawn(move || {
                    let mut ordinal = 0u64;
                    let branch = format!("refs/heads/s{shard}-w{submitter}");
                    let mut expected: Option<ObjectId> = None;
                    let (authority, _) = engine_object(
                        "levcs-store/store-bench/genesis/v1",
                        &(shard as u64).to_le_bytes(),
                        64,
                    );
                    while !stop.load(Ordering::Relaxed) && Instant::now() < deadline {
                        ordinal += 1;
                        let mut seed = Vec::with_capacity(24);
                        seed.extend_from_slice(&u64::from(shard).to_le_bytes());
                        seed.extend_from_slice(&(submitter as u64).to_le_bytes());
                        seed.extend_from_slice(&ordinal.to_le_bytes());

                        let (blob, blob_raw) = engine_object(
                            "levcs-store/store-bench/blob/v1",
                            &seed,
                            ENGINE_BLOB_BYTES,
                        );
                        let (tree, tree_raw) = engine_object(
                            "levcs-store/store-bench/tree/v1",
                            &seed,
                            ENGINE_TREE_BYTES,
                        );
                        let (commit, commit_raw) = engine_object(
                            "levcs-store/store-bench/commit/v1",
                            &seed,
                            ENGINE_COMMIT_BYTES,
                        );
                        let bytes = (blob_raw.len() + tree_raw.len() + commit_raw.len()) as u64;

                        let mut operation_id = [0u8; 16];
                        operation_id[..8].copy_from_slice(&ordinal.to_le_bytes());
                        operation_id[8] = shard as u8;
                        operation_id[9] = submitter as u8;
                        let operation = OperationId(operation_id);

                        let transaction = ValidatedTransaction::builder(
                            PrivilegedConstruction::assert_validated(),
                        )
                        .namespace(namespace)
                        .operation(
                            operation,
                            ObjectId(*blake3::hash(&seed).as_bytes()),
                            engine_now_micros() + 600_000_000,
                        )
                        .objects(vec![
                            StagedObject {
                                id: blob,
                                object_type: levcs_core::ObjectType::Blob,
                                raw: blob_raw,
                            },
                            StagedObject {
                                id: tree,
                                object_type: levcs_core::ObjectType::Tree,
                                raw: tree_raw,
                            },
                            StagedObject {
                                id: commit,
                                object_type: levcs_core::ObjectType::Commit,
                                raw: commit_raw,
                            },
                        ])
                        // A real typed ref CAS per commit. The bundle's
                        // validation_flags claim `typed_ref_cas: true`, and at
                        // this gate that claim is only worth anything if the
                        // sequencer actually evaluated one.
                        .refs(vec![levcs_protocol::v2::TypedRefCas {
                            target: levcs_protocol::v2::RefTarget::Branch(branch.clone()),
                            expected,
                            mutation: levcs_protocol::v2::RefMutation::Set(commit),
                            force: false,
                        }])
                        .authority(Some(authority), Some(authority))
                        .evidence(engine_evidence())
                        .build()
                        .expect("a complete push transaction");

                        let call = Instant::now();
                        let outcome =
                            block_on_until(engine.submit(transaction), Duration::from_secs(60));
                        let micros = call.elapsed().as_micros() as u64;
                        match outcome {
                            Some(Ok(receipt)) => {
                                // The fence returned. Acknowledgment is only
                                // permitted once the acknowledgment is itself
                                // durable on an independent journal, so this
                                // happens before anything counts the commit.
                                let record = AckRecord {
                                    repo_id: ObjectId(*namespace.as_bytes()),
                                    operation_id,
                                    operation_digest: ObjectId(*blake3::hash(&seed).as_bytes()),
                                    receipt_digest: ObjectId(
                                        *blake3::hash(&operation_id).as_bytes(),
                                    ),
                                    repo_sequence: receipt.repo_sequence,
                                    blob_ids: vec![blob],
                                    tree_ids: vec![tree],
                                    commit_ids: vec![commit],
                                };
                                {
                                    let mut journal = ack.lock().unwrap_or_else(|p| p.into_inner());
                                    if journal.append_durable(&record).is_err() {
                                        stop.store(true, Ordering::Relaxed);
                                        return;
                                    }
                                }
                                acknowledged.fetch_add(1, Ordering::Relaxed);
                                // The store's own count of the objects this
                                // transaction introduced, not `3` restated by
                                // the harness. `objects_new` derived from the
                                // commit count is what makes
                                // `verification.objects_new_equals_three_per_commit`
                                // a tautology instead of a check.
                                objects_new.fetch_add(receipt.objects_new, Ordering::Relaxed);
                                raw_bytes.fetch_add(bytes, Ordering::Relaxed);
                                latencies
                                    .lock()
                                    .unwrap_or_else(|p| p.into_inner())
                                    .push(micros);
                                results.lock().unwrap_or_else(|p| p.into_inner()).push((
                                    namespace,
                                    operation,
                                    receipt.repo_sequence,
                                    ordinal,
                                ));
                                expected = Some(commit);
                            }
                            Some(Err(error)) => {
                                refused.fetch_add(1, Ordering::Relaxed);
                                let mut slot =
                                    first_refusal.lock().unwrap_or_else(|p| p.into_inner());
                                if slot.is_none() {
                                    *slot = Some(format!("{error:?}"));
                                }
                                stop.store(true, Ordering::Relaxed);
                                return;
                            }
                            None => {
                                refused.fetch_add(1, Ordering::Relaxed);
                                let mut slot =
                                    first_refusal.lock().unwrap_or_else(|p| p.into_inner());
                                if slot.is_none() {
                                    *slot = Some("submit did not complete in 60s".to_string());
                                }
                                stop.store(true, Ordering::Relaxed);
                                return;
                            }
                        }
                    }
                });
            }
        }
    });

    let elapsed = started.elapsed();
    let fences: u64 = (0..shard_count)
        .map(|shard| {
            engine
                .durability_counters(shard)
                .map(|counters| counters.fdatasync)
                .unwrap_or(0)
        })
        .sum();

    let latencies = latencies.into_inner().unwrap_or_else(|p| p.into_inner());
    let results = results.into_inner().unwrap_or_else(|p| p.into_inner());
    let refused = refused.load(Ordering::Relaxed);
    let first_refusal = first_refusal
        .into_inner()
        .unwrap_or_else(|p| p.into_inner());
    let acknowledged = acknowledged.load(Ordering::Relaxed);
    let objects_new = objects_new.load(Ordering::Relaxed);
    let raw_bytes = raw_bytes.load(Ordering::Relaxed);
    let mut signing = signer
        .micros
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    signing.sort_unstable();
    let signings = signing.len() as u64;
    let signing_p50 = percentile(&signing, 0.50) as f64;

    drop(ack);
    drop(engine);

    // The root lock is not always free when `StoreEngine::drop` returns; see
    // the same finding recorded in `tests/support/engine_matrix.rs`. Bounded
    // and reported, never silent.
    let lock_wait_started = Instant::now();
    let mut lock_release_attempts = 0u32;
    let reopened = loop {
        lock_release_attempts += 1;
        match StoreEngine::open(build_options()) {
            Ok(engine) => break engine,
            Err(StoreError::AlreadyLocked)
                if lock_wait_started.elapsed() < Duration::from_secs(30) =>
            {
                std::thread::sleep(Duration::from_micros(200));
            }
            Err(other) => return Err(format!("reopen through production recovery: {other}")),
        }
    };

    // Reconciliation, through the production status read rather than through a
    // sequence-set comparison. Every operation this run acknowledged must read
    // back `Committed` from a store that was closed and recovered.
    let mut acknowledged_loss = 0u64;
    for (namespace, operation, _, _) in &results {
        // Every variant named. A fallback arm here would fold "the store
        // refused the read" into "the operation is missing", and those are
        // different findings: the first invalidates the reconciliation, the
        // second invalidates the run.
        use levcs_store::types::TransactionStatus as Status;
        match reopened.transaction_status(*namespace, *operation) {
            Ok(Status::Committed(_)) => {}
            Ok(Status::Unknown) => acknowledged_loss += 1,
            Ok(Status::Resolving { .. }) => acknowledged_loss += 1,
            Ok(Status::Pending { .. }) => acknowledged_loss += 1,
            Ok(Status::Expired { .. }) => acknowledged_loss += 1,
            Err(error) => {
                return Err(format!(
                    "reading back an acknowledged operation failed: {error}. The \
                     reconciliation cannot distinguish a lost commit from a failed read, \
                     so the run is void rather than counted."
                ))
            }
        }
    }
    drop(reopened);

    // Per-repository sequence integrity, through the one shared checker.
    let mut torn_transactions = 0u64;
    let mut repeated_adoptions = 0u64;
    for namespace in &namespaces {
        let mut sequences: Vec<u64> = results
            .iter()
            .filter(|(candidate, _, _, _)| candidate == namespace)
            .map(|(_, _, sequence, _)| *sequence)
            .collect();
        sequences.sort_unstable();
        let classified = classify_adopted_set(&sequences);
        torn_transactions += classified.missing_sequences;
        repeated_adoptions += classified.repeated_adoptions();
    }

    let records = ExternalAckJournal::recover(ack_path).map_err(|e| format!("ack recover: {e}"))?;

    Ok(EngineRun {
        groups: fences,
        transactions: acknowledged,
        latencies_micros: latencies,
        objects_new,
        raw_bytes,
        elapsed,
        acknowledged,
        acknowledged_loss,
        torn_transactions,
        repeated_adoptions,
        fences,
        signing_micros_p50: signing_p50,
        signings,
        refused,
        first_refusal,
        acknowledged_sequences_reconciled: acknowledged_loss == 0
            && torn_transactions == 0
            && repeated_adoptions == 0
            && records.len() as u64 == acknowledged,
        ack_journal_digest: digest_file(ack_path),
        lock_release_attempts,
    })
}

/// One measured run, whichever path produced it.
///
/// The two paths are the Wave A journal seam and the Wave B production
/// `StoreEngine::submit`. Folding them into one shape here is what keeps the
/// bundle emitter identical for both: the thing that must not differ between a
/// seam measurement and a store measurement is how the measurement is
/// *reported*.
struct MeasuredRun {
    latencies_micros: Vec<u64>,
    groups: u64,
    transactions: u64,
    /// Counted from the objects the store actually staged on the submit path,
    /// and derived as `transactions * 3` on the drive path, where there are no
    /// objects. The difference is why
    /// `verification.objects_new_equals_three_per_commit` stays forbidden at
    /// this gate on the drive path: a derived figure asserted against its own
    /// derivation is a tautology.
    objects_new: u64,
    objects_new_counted: bool,
    bytes: u64,
    elapsed: Duration,
    acknowledged: u64,
    acknowledged_loss: u64,
    torn_transactions: u64,
    repeated_adoptions: u64,
    fences: u64,
    signing_micros_p50: f64,
    signings: u64,
    acknowledged_sequences_reconciled: bool,
    ack_journal_digest: String,
    path: &'static str,
    /// Submits refused or never completed. Non-zero ends the run: a benchmark
    /// that keeps counting past a refusal is measuring a different workload
    /// from the one it names.
    refused: u64,
    first_refusal: Option<String>,
    /// Attempts the post-run reopen needed to acquire the root lock. `1` is the
    /// expected reading; see the note on `run_engine`.
    lock_release_attempts: u32,
}

impl From<SkeletonRun> for MeasuredRun {
    fn from(run: SkeletonRun) -> Self {
        Self {
            groups: run.groups,
            transactions: run.transactions,
            objects_new: run.transactions * OBJECTS_PER_COMMIT,
            objects_new_counted: false,
            bytes: run.bytes,
            elapsed: run.elapsed,
            acknowledged: run.acknowledged,
            acknowledged_loss: run.acknowledged_loss,
            torn_transactions: run.torn_transactions,
            repeated_adoptions: run.repeated_adoptions,
            fences: run.fences,
            signing_micros_p50: 0.0,
            signings: 0,
            acknowledged_sequences_reconciled: run.acknowledged_sequences_reconciled,
            ack_journal_digest: run.ack_journal_digest,
            latencies_micros: run.latencies_micros,
            path: "drive",
            refused: 0,
            first_refusal: None,
            lock_release_attempts: 1,
        }
    }
}

impl From<EngineRun> for MeasuredRun {
    fn from(run: EngineRun) -> Self {
        Self {
            groups: run.groups,
            transactions: run.transactions,
            objects_new: run.objects_new,
            objects_new_counted: true,
            bytes: run.raw_bytes,
            elapsed: run.elapsed,
            acknowledged: run.acknowledged,
            acknowledged_loss: run.acknowledged_loss,
            torn_transactions: run.torn_transactions,
            repeated_adoptions: run.repeated_adoptions,
            fences: run.fences,
            signing_micros_p50: run.signing_micros_p50,
            signings: run.signings,
            acknowledged_sequences_reconciled: run.acknowledged_sequences_reconciled,
            ack_journal_digest: run.ack_journal_digest,
            latencies_micros: run.latencies_micros,
            path: "submit",
            refused: run.refused,
            first_refusal: run.first_refusal,
            lock_release_attempts: run.lock_release_attempts,
        }
    }
}

// ---------------------------------------------------------------------------
// Section 13 stop conditions, measured rather than quoted
// ---------------------------------------------------------------------------

/// The two section 13 stop conditions, measured here.
pub struct IndexCost {
    /// Packed entry bytes per object: what scope 8.2 budgets at 47.
    pub packed_bytes_per_object: f64,
    /// The whole run divided by its objects — header, filter, sections, and
    /// trailer included. Always larger than the packed figure, and it is the
    /// one the device actually holds.
    pub run_bytes_per_object: f64,
    /// Index runs binary-searched to answer one lookup, from a real lookup
    /// against a real multi-run index.
    pub lookup_fanout: f64,
}

/// Build real index runs with A2's builder and perform a real lookup.
///
/// Copying A2's numbers into this emitter would make the bundle's section 13
/// figures a transcription that drifts silently the first time the index
/// changes. The measurement is small — eight runs of 2,048 entries — and it is
/// a measurement.
///
/// It does not measure the benchmark workload's index, because at this gate
/// there is no index in the measured path at all: nothing below `engine.rs`
/// performs a checkpoint lookup. What it measures is the index the store would
/// use, at the shape section 13 names.
fn measure_index_costs() -> Result<IndexCost, String> {
    use levcs_store::index::{
        IndexDelta, IndexKey, IndexLocation, IndexRun, IndexRunBuilder, ObjectIndex,
        INDEX_ENTRY_LEN,
    };
    use std::sync::Arc;

    const RUNS: u64 = 8;
    const ENTRIES_PER_RUN: u64 = 2_048;

    let root_uuid = [0x5au8; 16];
    let mut options = levcs_store::options::StoreOptions::new("/nonexistent/index-cost-probe");
    options.max_index_runs = RUNS as u32;
    options.max_open_index_runs = RUNS as u32;
    let mut index = ObjectIndex::new(&options);
    let namespace = NamespaceId([0x11u8; 32]);

    let object_at = |ordinal: u64| {
        let mut object = [0u8; 32];
        object[..8].copy_from_slice(&ordinal.to_le_bytes());
        ObjectId(object)
    };

    let mut packed_bytes = 0u64;
    let mut run_bytes = 0u64;
    for generation in 0..RUNS {
        let mut delta = IndexDelta::new(ENTRIES_PER_RUN, 1 << 30);
        for i in 0..ENTRIES_PER_RUN {
            let ordinal = generation * ENTRIES_PER_RUN + i;
            delta
                .insert(
                    IndexKey::new(namespace, object_at(ordinal)),
                    IndexLocation {
                        segment_generation: generation,
                        frame_offset: i * 4096,
                        frame_len: 4096,
                        object_type: 1,
                        shard_sequence: ordinal,
                    },
                )
                .map_err(|e| format!("index probe insert: {e}"))?;
        }
        let bytes = IndexRunBuilder::new(root_uuid, generation, generation)
            .build(&delta)
            .map_err(|e| format!("index probe build: {e}"))?;
        let run = IndexRun::from_vec(bytes, &root_uuid)
            .map_err(|e| format!("index probe open: {e:?}"))?;
        packed_bytes += run.entry_count() * INDEX_ENTRY_LEN as u64;
        run_bytes += run.byte_len();
        index
            .push_run(Arc::new(run))
            .map_err(|e| format!("index probe push: {e}"))?;
    }

    // An object in the *oldest* run, so every newer run's filter has to exclude
    // it. A lookup that the delta answered, or one against a single run, would
    // report a fan-out of zero or one for reasons unrelated to filtering.
    let hit = index.lookup(&IndexKey::new(namespace, object_at(7)));
    if hit.location.is_none() {
        return Err("index probe: a present object was not found".into());
    }
    if hit.answered_by_delta {
        return Err("index probe: the delta answered, so no run fan-out was measured".into());
    }

    let objects = (RUNS * ENTRIES_PER_RUN) as f64;
    Ok(IndexCost {
        packed_bytes_per_object: packed_bytes as f64 / objects,
        run_bytes_per_object: run_bytes as f64 / objects,
        lookup_fanout: f64::from(hit.fan_out()),
    })
}

fn percentile(sorted: &[u64], fraction: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = ((sorted.len() as f64 - 1.0) * fraction).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE: &str = "\
store-bench <precheck|emit-skeleton|run> [flags]

  precheck        --root P [--repo-root P] [--target-rate N]
  emit-skeleton   --root P --out P --allow-unsigned [--repo-root P]
                  [--seconds N] [--group-len N] [--skip-attribute-check]
                  [--path submit|drive] [--shards N] [--submitters-per-shard N]
  run             --root P --out-dir P   (P2; blocked, see below)

--path submit is the default and goes through StoreEngine::submit. --path drive
is the Wave A journal seam, kept so the two measurements can be compared rather
than confused; it signs nothing, creates no object, and issues no receipt.

The two prechecks are not optional and are not overridable except by
--skip-attribute-check, which makes the run non-comparable and marks the
bundle accordingly.
";

fn repo_root_of(explicit: Option<&str>) -> PathBuf {
    if let Some(path) = explicit {
        return PathBuf::from(path);
    }
    // `CARGO_MANIFEST_DIR` is crates/levcs-store at compile time.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."))
}

struct Flags(Vec<(String, String)>);

impl Flags {
    fn parse(mut raw: impl Iterator<Item = String>) -> Result<(String, Self), String> {
        let subcommand = raw.next().ok_or("missing subcommand")?;
        let mut values = Vec::new();
        while let Some(flag) = raw.next() {
            let name = flag
                .strip_prefix("--")
                .ok_or_else(|| format!("expected a --flag, got {flag:?}"))?
                .to_string();
            if name == "allow-unsigned" || name == "skip-attribute-check" {
                values.push((name, "true".to_string()));
                continue;
            }
            let value = raw
                .next()
                .ok_or_else(|| format!("--{name} needs a value"))?;
            values.push((name, value));
        }
        Ok((subcommand, Self(values)))
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn required(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn number<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        match self.get(name) {
            Some(value) => value
                .parse::<T>()
                .map_err(|_| format!("--{name} has an invalid value {value:?}")),
            None => Ok(default),
        }
    }
}

fn main() -> ExitCode {
    let (subcommand, flags) = match Flags::parse(std::env::args().skip(1)) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("store-bench: {error}\n\n{USAGE}");
            return ExitCode::from(EX_USAGE);
        }
    };
    match dispatch(&subcommand, &flags) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("store-bench: {error}");
            ExitCode::from(EX_CONFIG)
        }
    }
}

fn dispatch(subcommand: &str, flags: &Flags) -> Result<ExitCode, String> {
    let repo_root = repo_root_of(flags.get("repo-root"));
    let workload = load_frozen_workload(&repo_root.join("bench/workloads/small-commit.toml"))?;
    let profile = load_frozen_profile(&repo_root.join("bench/reference-hardware.toml"))?;

    if subcommand == "precheck" {
        let root = PathBuf::from(flags.required("root")?);
        let target_rate = flags.number::<u64>("target-rate", 75_000)?;
        let requirement = required_free_space(
            workload.warmup_seconds,
            workload.measured_seconds,
            target_rate,
            P2_FRAME_BYTES,
        )?;
        let available = check_free_space(&root, requirement)?;
        println!("precheck_schema=1");
        println!("free_bytes_required={}", requirement.required_bytes);
        println!("free_bytes_available={available}");
        // Scope 8.2: each measured repetition starts from a freshly initialized
        // root, so the requirement above is per repetition and this many fresh
        // roots are written in sequence.
        println!("repetitions={}", workload.repetitions);
        println!("fresh_root_per_repetition=true");
        match check_store_directory_attributes(&root, &profile) {
            Ok(observed) => {
                println!("store_directory_attributes={}", observed.value);
                for (directory, value) in observed.per_directory {
                    println!("attribute:{directory}={value}");
                }
                Ok(ExitCode::SUCCESS)
            }
            Err(error) => {
                println!("store_directory_attributes=mismatch");
                Err(error)
            }
        }
    } else if subcommand == "emit-skeleton" {
        emit_skeleton(&repo_root, &workload, &profile, flags)
    } else if subcommand == "run" {
        Err(
            "the P2 run goes through StoreEngine::submit, which is B1 NamespaceTxn \
             (scope 6-B1). Wave A can produce a P1-micro number and a skeleton \
             bundle; it cannot produce a P2 result."
                .to_string(),
        )
    } else {
        Err(format!("unknown subcommand {subcommand:?}\n\n{USAGE}"))
    }
}

fn emit_skeleton(
    repo_root: &Path,
    workload: &FrozenWorkload,
    profile: &FrozenProfile,
    flags: &Flags,
) -> Result<ExitCode, String> {
    if flags.get("allow-unsigned").is_none() {
        return Err(
            "refusing to emit an unsigned bundle. levcs-store has no Ed25519 \
             dependency and scope section 1 forbids a levcs_identity:: path in \
             this crate, so real attestation signing is an open interface \
             request to the lead. Pass --allow-unsigned to emit a placeholder \
             attestation for schema validation only."
                .to_string(),
        );
    }

    let root = PathBuf::from(flags.required("root")?);
    let out = PathBuf::from(flags.required("out")?);
    let seconds = flags.number::<u64>("seconds", 2)?;
    let group_len = flags.number::<usize>("group-len", 16)?;

    // Precheck 1 runs against the skeleton's own budget, not P2's: the point
    // is to exercise the code path and the arithmetic, and demanding 280 GB
    // for a two-second run would only prove that the formula is large.
    let requirement = required_free_space(0, seconds, 75_000, P2_FRAME_BYTES)?;
    let available = check_free_space(&root, requirement)?;

    let started_at = SystemTime::now();
    let ack_path = root.with_extension("ack-journal");
    // The acknowledgment journal is deliberately outside the store root: plan
    // §10 keeps it on fault-isolated storage precisely so that whatever
    // destroys the store does not also destroy the record of what the store
    // promised. Same device here, different subtree — the strongest isolation
    // an unprivileged in-process harness can give it, and the reason the
    // deployed campaigns of §10 put it on another host.
    let path = flags.get("path").unwrap_or("submit").to_string();
    let run: MeasuredRun = if path == "submit" {
        let shards = flags.number::<u16>("shards", 4)?;
        let submitters = flags.number::<usize>("submitters-per-shard", group_len.max(1))?;
        run_engine(&root, &ack_path, group_len, seconds, shards, submitters)?.into()
    } else if path == "drive" {
        run_skeleton(&root, &ack_path, group_len, seconds)?.into()
    } else {
        return Err(format!(
            "--path must be submit or drive, got {path:?}. `submit` is the production \
             StoreEngine path and the default; `drive` is the Wave A journal seam, kept \
             so the two measurements can be compared rather than confused."
        ));
    };

    if run.refused != 0 {
        return Err(format!(
            "the run was cut short by {} refused or incomplete submit(s); the first was \
             {:?}. A benchmark that keeps counting past a refusal is measuring a \
             different workload from the one it names.",
            run.refused, run.first_refusal
        ));
    }

    // Precheck 2 must run against a root that exists, so it follows the run
    // that creates it. In a P2 run the shard directories are created by
    // `StoreEngine::open` and the check precedes the first measured
    // transaction; here the two are unavoidably in this order.
    let mut attributes_verified = true;
    let attributes = match check_store_directory_attributes(&root, profile) {
        Ok(observed) => observed.value,
        Err(error) => {
            if flags.get("skip-attribute-check").is_none() {
                return Err(error);
            }
            attributes_verified = false;
            eprintln!("store-bench: {error}");
            eprintln!(
                "store-bench: --skip-attribute-check was passed, so this bundle is \
                 explicitly non-comparable"
            );
            format!("unverified ({})", profile.store_directory_attributes)
        }
    };

    // The trim-settle interval between repetitions (scope 8.2). A one-shot
    // skeleton has no second repetition, so the interval is observed as zero
    // and recorded as such rather than omitted.
    let trim_settle = Duration::ZERO;

    let mut sorted = run.latencies_micros.clone();
    sorted.sort_unstable();
    let ended_at = SystemTime::now();

    let rate = if run.elapsed.as_secs_f64() > 0.0 {
        run.transactions as f64 / run.elapsed.as_secs_f64()
    } else {
        0.0
    };

    let mut histogram_input = String::new();
    for value in &sorted {
        let _ = write!(histogram_input, "{value},");
    }

    // Section 13's two stop conditions, measured against A2's index.
    let index_cost = measure_index_costs()?;

    let mut run_id = if run.path == "submit" {
        String::from("engine-wave-b-")
    } else {
        String::from("skeleton-wave-a-")
    };
    run_id.push_str(&digest_hex(histogram_input.as_bytes())[..16]);

    let inputs = BundleInputs {
        run_id,
        repetition: 1,
        warmup_seconds: 0,
        measured_seconds: run.elapsed.as_secs().max(1),
        started_at,
        ended_at,
        counted_commits: run.transactions,
        acknowledged_requests: run.transactions,
        // Derived, and P2 must not keep it that way. The skeleton's payloads
        // are scripted bytes, not a Blob/Tree/Commit triplet, so there is
        // nothing to count and this is the only figure available — which is
        // also precisely why `verification.objects_new_equals_three_per_commit`
        // is forbidden at this gate rather than emitted. A run that computes
        // `objects_new` as `transactions * 3` and then asserts that flag has
        // written a tautology, not a check: the assertion cannot fail. When B1
        // lands `StoreEngine::submit`, `objects_new` must be counted
        // independently — from the objects the store actually staged — before
        // that flag may be emitted at any gate.
        objects_new: run.objects_new,
        raw_bytes: run.bytes,
        application_bytes: run.bytes,
        latency_p50: percentile(&sorted, 0.50),
        latency_p95: percentile(&sorted, 0.95),
        latency_p99: percentile(&sorted, 0.99),
        latency_max: sorted.last().copied().unwrap_or(0),
        histogram_digest: digest_hex(histogram_input.as_bytes()),
        // A run shorter than a minute has no one-minute windows. What is
        // reported is the single whole-run rate, and the percentage is
        // therefore trivially 100 — which is why the bundle's `outcome` is
        // `preliminary` and its own gate verdict `not-applicable`. A P2 run
        // computes real windows; nothing here should be read as having met the
        // section 3 window rule.
        one_minute_windows: vec![rate],
        windows_meeting_target_percent: 100.0,
        ack_journal_digest: run.ack_journal_digest.clone(),
        acknowledged_loss: run.acknowledged_loss,
        torn_transactions: run.torn_transactions,
        repeated_adoptions: run.repeated_adoptions,
        store_directory_attributes: attributes,
        store_directory_attributes_verified: attributes_verified,
        trim_settle_seconds: trim_settle.as_secs_f64(),
        // No signer runs at the drive layer, so the measured cost is zero and
        // is reported as zero. Scope 8.4's ~1.4-of-8-cores figure is a
        // prediction for P2 and must not be copied into a bundle as if it had
        // been measured.
        // Measured, not predicted. The submit path signs every event with a
        // real Ed25519 key and records the cost; the drive path signs nothing
        // and reports a measured zero over zero signings. Scope 8.4's
        // ~1.4-of-8-cores figure is a P2 prediction and is never copied here.
        signing_cores: if run.elapsed.as_secs_f64() > 0.0 {
            (run.signings as f64 * run.signing_micros_p50) / (run.elapsed.as_secs_f64() * 1e6)
        } else {
            0.0
        },
        index_bytes_per_object: index_cost.packed_bytes_per_object,
        index_run_bytes_per_object: index_cost.run_bytes_per_object,
        checkpoint_lookup_fanout: index_cost.lookup_fanout,
        // Nothing signs below engine.rs, so this is a measured zero over zero
        // signings rather than an unmeasured field. `evidence_signings` carries
        // the denominator so a reader can tell the two apart.
        evidence_signing_micros_p50: run.signing_micros_p50,
        evidence_signings: run.signings,
        fences: run.fences,
        transactions: run.transactions,
        free_bytes_available: available,
        free_bytes_required: requirement.required_bytes,
        acknowledged_sequences_reconciled: run.acknowledged_sequences_reconciled,
        skeleton: true,
    };

    let outcome = storage_primitive_outcome(&inputs);
    let bundle = build_bundle(repo_root, workload, &inputs)?;
    std::fs::write(&out, bundle).map_err(|e| format!("writing {}: {e}", out.display()))?;

    println!("bundle_schema=1");
    println!("bundle_path={}", out.display());
    println!("bundle_gate=storage_primitive");
    println!("bundle_promotable=false");
    println!("bundle_skeleton=true");
    println!("bundle_path_driven={}", run.path);
    println!("objects_new={}", run.objects_new);
    println!("objects_new_counted={}", run.objects_new_counted);
    println!("evidence_signings={}", run.signings);
    println!("evidence_signing_micros_p50={:.1}", run.signing_micros_p50);
    println!("lock_release_attempts={}", run.lock_release_attempts);
    println!("bundle_outcome={}", outcome.name());
    println!("groups={}", run.groups);
    println!("transactions={}", run.transactions);
    println!("fences={}", run.fences);
    println!("acknowledged={}", run.acknowledged);
    println!("acknowledged_loss={}", run.acknowledged_loss);
    println!("torn_transactions={}", run.torn_transactions);
    println!("repeated_adoptions={}", run.repeated_adoptions);
    println!(
        "acknowledged_sequences_reconciled={}",
        run.acknowledged_sequences_reconciled
    );
    println!(
        "index_bytes_per_object={:.2}",
        index_cost.packed_bytes_per_object
    );
    println!("checkpoint_lookup_fanout={:.2}", index_cost.lookup_fanout);
    println!("rate_per_second={rate:.1}");
    Ok(ExitCode::SUCCESS)
}

/// Reserved so a future caller can distinguish "unavailable" from
/// "misconfigured" without re-deriving the exit codes.
#[allow(dead_code)]
const _EXIT_CODES: (u8, u8, u8) = (EX_USAGE, EX_UNAVAILABLE, EX_CONFIG);

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_root() -> PathBuf {
        repo_root_of(None)
    }

    #[test]
    fn the_free_space_formula_covers_the_warmup_and_the_index_runs() {
        // Scope 8.2's own arithmetic: 15 measured minutes at 75k/s writes
        // about 170 GB of journal plus about 9.5 GB of index runs, and the
        // warmup adds another 300 s.
        let over_measured_only =
            required_free_space(0, 900, 75_000, P2_FRAME_BYTES).expect("measured only");
        let over_both = required_free_space(300, 900, 75_000, P2_FRAME_BYTES).expect("both");

        assert!(
            over_both.required_bytes > over_measured_only.required_bytes,
            "a precheck over measured time alone is the defect scope 8.2 names"
        );

        // The warmup is a third of the measured window, so including it must
        // raise the requirement by a third, not by a rounding error.
        let ratio = over_both.required_bytes as f64 / over_measured_only.required_bytes as f64;
        assert!(
            (ratio - 4.0 / 3.0).abs() < 0.01,
            "including a 300 s warmup after a 900 s measured window must raise \
             the requirement by exactly a third, got {ratio}"
        );

        // Index runs are a real term, not a rounding allowance.
        assert!(
            over_both.index_run_bytes > 1 << 33,
            "the index run estimate must be tens of gigabytes at this rate, got {}",
            over_both.index_run_bytes
        );
    }

    #[test]
    fn the_free_space_formula_refuses_to_overflow_rather_than_wrapping() {
        let error = required_free_space(u64::MAX, u64::MAX, u64::MAX, u64::MAX)
            .expect_err("must refuse rather than wrap");
        assert!(error.contains("overflow"), "{error}");
    }

    #[test]
    fn a_run_with_no_room_is_refused_rather_than_started() {
        let directory = tempfile::tempdir().expect("tempdir");
        let requirement = SpaceRequirement {
            journal_bytes: u128::MAX / 4,
            index_run_bytes: 0,
            required_bytes: u128::MAX / 4,
        };
        let error = check_free_space(directory.path(), requirement)
            .expect_err("an impossible requirement must refuse");
        assert!(error.contains("refusing to start"), "{error}");
    }

    #[test]
    fn the_precheck_reads_the_frozen_profile_rather_than_restating_it() {
        let profile = load_frozen_profile(&repo_root().join("bench/reference-hardware.toml"))
            .expect("profile");
        assert_eq!(
            profile.store_directory_attributes, "nodatacow",
            "contract review 2026-07-24-B fixes this value"
        );
        assert_eq!(
            profile.store_directories,
            vec![
                "shards/*/active".to_string(),
                "shards/*/segments".to_string()
            ]
        );
    }

    #[test]
    fn the_bundle_uses_the_frozen_seed_and_generator_rather_than_a_copy() {
        let workload = load_frozen_workload(&repo_root().join("bench/workloads/small-commit.toml"))
            .expect("workload");
        assert_eq!(workload.seed, 126_394_451_485_337);
        assert_eq!(
            workload.generator,
            "blake3-xof(seed || repo_ordinal_le || ref_ordinal_le || commit_ordinal_le)",
            "ruling 9.5: an evaluator recomputes every blob from these two fields, \
             so they must be read from the frozen file, never restated here"
        );
        assert_eq!(workload.warmup_seconds, 300);
        assert_eq!(workload.measured_seconds, 900);
        assert_eq!(workload.repetitions, 3);
    }

    #[test]
    fn the_attribute_precheck_refuses_a_pattern_that_matches_nothing() {
        let directory = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(directory.path().join("shards")).expect("mkdir");
        let profile = FrozenProfile {
            store_directory_attributes: "nodatacow".to_string(),
            store_directories: vec!["shards/*/active".to_string()],
        };
        let error = check_store_directory_attributes(directory.path(), &profile)
            .expect_err("an empty expansion must refuse");
        assert!(error.contains("matched nothing"), "{error}");
    }

    #[test]
    fn the_attribute_precheck_refuses_a_datacow_directory() {
        let directory = tempfile::tempdir().expect("tempdir");
        let active = directory.path().join("shards/00/active");
        std::fs::create_dir_all(&active).expect("mkdir");
        let profile = FrozenProfile {
            store_directory_attributes: "nodatacow".to_string(),
            store_directories: vec!["shards/*/active".to_string()],
        };
        match check_store_directory_attributes(directory.path(), &profile) {
            Ok(observed) => {
                // Only possible if the test's temporary directory really is
                // nodatacow, which is legitimate on a btrfs TMPDIR with the
                // attribute inherited.
                assert_eq!(observed.value, "nodatacow");
            }
            Err(error) => {
                assert!(
                    error.contains("refusing to start"),
                    "a mismatch must refuse, not record: {error}"
                );
            }
        }
    }

    // -- schema validation --------------------------------------------------
    //
    // The emitter is checked against `bench/result-schema.json` itself, not
    // against a list of substrings this file also wrote. The substring version
    // of this test passed while the emitter was producing a bundle with four
    // validator errors, because a substring assertion cannot notice a *missing*
    // field and cannot see a conditional at all.
    //
    // There is no JSON Schema crate in the workspace and adding one is a
    // lead-owned `Cargo.toml` change, so validation shells out to `python3` with
    // `jsonschema` — the same validator `scripts/verify-store-recovery.sh`
    // already uses, so the gate and the unit test cannot disagree about what
    // valid means. A missing interpreter or missing module is a test *failure*,
    // never a skip: a validation that silently does not run is the defect this
    // replaces.

    /// Every validator error for `bundle`, or an empty vector.
    fn schema_errors(bundle: &str) -> Vec<String> {
        let directory = tempfile::tempdir().expect("tempdir");
        let instance = directory.path().join("bundle.json");
        std::fs::write(&instance, bundle).expect("write bundle");
        let schema = repo_root().join("bench/result-schema.json");

        let output = std::process::Command::new("python3")
            .arg("-c")
            .arg(VALIDATE_PY)
            .arg(&schema)
            .arg(&instance)
            .output()
            .expect(
                "python3 must be available: this test validates the emitted bundle \
                 against bench/result-schema.json, and a validation that cannot run \
                 is not a passing test",
            );
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        match output.status.code() {
            Some(0) => Vec::new(),
            Some(1) => stdout.lines().map(|line| line.to_string()).collect(),
            other => panic!(
                "the schema validator could not run (exit {other:?}). jsonschema must \
                 be installed; a skipped validation would let the emitter drift from \
                 the schema exactly as it already did.\nstdout: {stdout}\nstderr: {stderr}"
            ),
        }
    }

    /// Exit 0 clean, exit 1 with one error per line on stdout, exit 2 if the
    /// validator itself is unavailable.
    const VALIDATE_PY: &str = "\
import json, sys
try:
    import jsonschema
except ImportError:
    sys.stderr.write('jsonschema is not installed\\n')
    sys.exit(2)
schema = json.load(open(sys.argv[1]))
instance = json.load(open(sys.argv[2]))
validator = jsonschema.Draft202012Validator(
    schema, format_checker=jsonschema.FormatChecker()
)
errors = sorted(validator.iter_errors(instance), key=lambda e: list(e.path))
for error in errors:
    sys.stdout.write(f'{list(error.path)}: {error.message}\\n')
sys.exit(1 if errors else 0)
";

    #[test]
    fn the_emitted_bundle_validates_against_the_frozen_schema() {
        let workload = load_frozen_workload(&repo_root().join("bench/workloads/small-commit.toml"))
            .expect("workload");
        let bundle = build_bundle(&repo_root(), &workload, &skeleton_inputs()).expect("bundle");
        let errors = schema_errors(&bundle);
        assert!(
            errors.is_empty(),
            "the emitted bundle does not satisfy bench/result-schema.json:\n{}",
            errors.join("\n")
        );
    }

    #[test]
    fn a_failing_run_is_representable_rather_than_suppressed() {
        let workload = load_frozen_workload(&repo_root().join("bench/workloads/small-commit.toml"))
            .expect("workload");

        // Per-gate latency ceilings are conditional on `outcome == "pass"`, so
        // a run that misses one is emitted as `fail` and is still a valid
        // bundle. Before the schema carried `outcome`, this run was
        // unrepresentable and the only options were to suppress it or to lie.
        let mut inputs = skeleton_inputs();
        inputs.skeleton = false;
        inputs.latency_p99 = STORAGE_PRIMITIVE_P99_CEILING_MICROS + 1;
        assert_eq!(storage_primitive_outcome(&inputs), Outcome::Fail);
        let bundle = build_bundle(&repo_root(), &workload, &inputs).expect("bundle");
        assert!(bundle.contains("\"outcome\": \"fail\""), "{bundle}");
        let errors = schema_errors(&bundle);
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        // A window rule miss is the same story.
        let mut inputs = skeleton_inputs();
        inputs.skeleton = false;
        inputs.windows_meeting_target_percent = 80.0;
        assert_eq!(storage_primitive_outcome(&inputs), Outcome::Fail);
        let errors =
            schema_errors(&build_bundle(&repo_root(), &workload, &inputs).expect("bundle"));
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        // And a run that met both is a pass under the same conditional.
        let mut inputs = skeleton_inputs();
        inputs.skeleton = false;
        assert_eq!(storage_primitive_outcome(&inputs), Outcome::Pass);
        let bundle = build_bundle(&repo_root(), &workload, &inputs).expect("bundle");
        assert!(bundle.contains("\"outcome\": \"pass\""));
        let errors = schema_errors(&bundle);
        assert!(errors.is_empty(), "{}", errors.join("\n"));
    }

    #[test]
    fn the_schema_check_can_actually_fail() {
        // The negative control. Without it, `schema_errors` returning an empty
        // vector for every input — a validator that never ran, a schema that
        // failed to load — would read as ten passing tests, which is precisely
        // how the substring version of this suite stayed green against a
        // schema-invalid bundle.
        let workload = load_frozen_workload(&repo_root().join("bench/workloads/small-commit.toml"))
            .expect("workload");
        let bundle = build_bundle(&repo_root(), &workload, &skeleton_inputs()).expect("bundle");

        // 1. The conditional: commits_in_recovered_closure must be false at
        //    storage_primitive, because the store cannot traverse a graph.
        let mutated = bundle.replace(
            "\"commits_in_recovered_closure\": false",
            "\"commits_in_recovered_closure\": true",
        );
        assert_ne!(mutated, bundle, "the field must be present to be mutated");
        assert!(
            !schema_errors(&mutated).is_empty(),
            "a bundle claiming graph traversal at storage_primitive must be rejected"
        );

        // 2. A required field removed: the `storage` object, which the emitter
        //    did not produce at all until this review.
        let stripped = bundle.replace("\"storage\": {", "\"storage_typo\": {");
        assert!(
            !schema_errors(&stripped).is_empty(),
            "a bundle missing the required `storage` object must be rejected"
        );

        // 3. A graph claim re-added at a gate that has no graph. This is the
        //    mutation that catches the defect directly: the five neighbours of
        //    `commits_in_recovered_closure` are *forbidden* here, not optional,
        //    so an emitter that drifts back to blanket `true` is rejected
        //    rather than silently accepted.
        let regraphed = bundle.replace(
            "\"commits_in_recovered_closure\": false",
            "\"blobs_recomputed\": true,\n    \"commits_in_recovered_closure\": false",
        );
        assert_ne!(regraphed, bundle, "the mutation must have applied");
        assert!(
            !schema_errors(&regraphed).is_empty(),
            "a storage_primitive bundle claiming blobs_recomputed must be rejected: \
             no object graph exists below engine.rs to recompute anything from"
        );

        // 4. A `pass` that misses the window rule.
        let dishonest = bundle
            .replace("\"outcome\": \"preliminary\"", "\"outcome\": \"pass\"")
            .replace(
                "\"windows_meeting_target_percent\": 100",
                "\"windows_meeting_target_percent\": 42",
            );
        assert!(
            !schema_errors(&dishonest).is_empty(),
            "a passing run that missed the section 3 window rule must be rejected"
        );

        // 5. Coordinated omission is the one claim the schema cannot police
        //    here: it relaxes to `type: boolean` at this gate, so both values
        //    validate and no mutation of the bundle can be made to fail. The
        //    assertion is therefore on the artifact itself. Schema-permitted is
        //    not the same as correct, and a closed-loop driver reporting `true`
        //    would be a silent regression no validator would catch.
        assert!(
            bundle.contains("\"coordinated_omission_corrected\": false"),
            "the skeleton is a closed-loop driver and must report coordinated \
             omission as uncorrected. The schema permits either value at this \
             gate, so nothing but this assertion stands between a closed-loop \
             run and a bundle claiming a correction it never performed.\n{bundle}"
        );
        let permissive = bundle.replace(
            "\"coordinated_omission_corrected\": false",
            "\"coordinated_omission_corrected\": true",
        );
        assert!(
            schema_errors(&permissive).is_empty(),
            "recorded deliberately: the schema does permit `true` here, which is \
             why the assertion above is on the emitted bytes and not on a \
             validator error"
        );
    }

    #[test]
    fn the_bundle_carries_the_pinned_gate_fields() {
        let workload = load_frozen_workload(&repo_root().join("bench/workloads/small-commit.toml"))
            .expect("workload");
        let bundle = build_bundle(&repo_root(), &workload, &skeleton_inputs()).expect("bundle");
        // These are the values the schema cannot pin for us: the frozen seed and
        // generator of ruling 9.5, which must equal the frozen file rather than
        // merely be strings.
        assert!(bundle.contains("\"seed\": 126394451485337"));
        assert!(bundle.contains("blake3-xof(seed"));
        assert!(bundle.contains("\"gate\": \"storage_primitive\""));
    }

    #[test]
    fn the_storage_object_reports_measured_numbers() {
        // Section 13's stop conditions are measured against A2's index, not
        // transcribed from A2's test output.
        let cost = measure_index_costs().expect("index probe");
        assert_eq!(
            cost.packed_bytes_per_object, 47.0,
            "scope 8.2 budgets 47 bytes/entry with the namespace factored out per \
             section; the emitter reports what it measured"
        );
        assert!(
            cost.run_bytes_per_object > cost.packed_bytes_per_object,
            "the whole run carries a header, a filter, sections, and a trailer"
        );
        assert!(
            cost.lookup_fanout >= 1.0 && cost.lookup_fanout <= 2.0,
            "a filtered lookup over eight runs must search about one of them, got {}",
            cost.lookup_fanout
        );
    }

    #[test]
    fn a_bundle_is_refused_when_the_sequences_were_not_reconciled() {
        let workload = load_frozen_workload(&repo_root().join("bench/workloads/small-commit.toml"))
            .expect("workload");
        let mut inputs = skeleton_inputs();
        inputs.acknowledged_sequences_reconciled = false;
        let error = build_bundle(&repo_root(), &workload, &inputs)
            .expect_err("the storage-layer proof may not be asserted unearned");
        assert!(
            error.contains("acknowledged_sequences_reconciled"),
            "{error}"
        );

        let mut inputs = skeleton_inputs();
        inputs.repeated_adoptions = 1;
        let error = build_bundle(&repo_root(), &workload, &inputs)
            .expect_err("a doubly adopted sequence is not publishable");
        assert!(error.contains("more than"), "{error}");
    }

    #[test]
    fn a_bundle_is_refused_when_an_acknowledged_operation_was_lost() {
        let workload = load_frozen_workload(&repo_root().join("bench/workloads/small-commit.toml"))
            .expect("workload");
        let mut inputs = skeleton_inputs();
        inputs.acknowledged_loss = 1;
        let error = build_bundle(&repo_root(), &workload, &inputs)
            .expect_err("acknowledged loss must never be published as a result");
        assert!(error.contains("hardware finding"), "{error}");

        let mut inputs = skeleton_inputs();
        inputs.torn_transactions = 1;
        assert!(build_bundle(&repo_root(), &workload, &inputs).is_err());
    }

    #[test]
    fn rfc3339_matches_the_schema_date_time_format() {
        let epoch = rfc3339(UNIX_EPOCH);
        assert_eq!(epoch, "1970-01-01T00:00:00Z");
        let known = rfc3339(UNIX_EPOCH + Duration::from_secs(1_769_385_600));
        assert_eq!(known, "2026-01-26T00:00:00Z");
    }

    fn skeleton_inputs() -> BundleInputs {
        BundleInputs {
            run_id: "skeleton-wave-a-test".into(),
            repetition: 1,
            warmup_seconds: 0,
            measured_seconds: 1,
            started_at: UNIX_EPOCH,
            ended_at: UNIX_EPOCH + Duration::from_secs(1),
            counted_commits: 3,
            acknowledged_requests: 3,
            objects_new: 9,
            raw_bytes: 4096,
            application_bytes: 4096,
            latency_p50: 100,
            latency_p95: 200,
            latency_p99: 300,
            latency_max: 400,
            histogram_digest: digest_hex(b"test"),
            one_minute_windows: vec![3.0],
            windows_meeting_target_percent: 100.0,
            ack_journal_digest: digest_hex(b"test"),
            acknowledged_loss: 0,
            torn_transactions: 0,
            repeated_adoptions: 0,
            store_directory_attributes: "nodatacow".into(),
            store_directory_attributes_verified: true,
            trim_settle_seconds: 0.0,
            signing_cores: 0.0,
            index_bytes_per_object: INDEX_BYTES_PER_OBJECT as f64,
            index_run_bytes_per_object: INDEX_BYTES_PER_OBJECT as f64 + 1.5,
            checkpoint_lookup_fanout: 1.0,
            evidence_signing_micros_p50: 0.0,
            evidence_signings: 0,
            fences: 1,
            transactions: 3,
            free_bytes_available: 1 << 40,
            free_bytes_required: 1 << 30,
            acknowledged_sequences_reconciled: true,
            skeleton: true,
        }
    }
}
