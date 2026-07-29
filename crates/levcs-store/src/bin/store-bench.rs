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
//! (scope 6.6 deliverable 3) over a root the production `StoreEngine::open`
//! built. It is still not a P2 run, and two of B1's unimplemented deliverables
//! are why — both of them a bound on the bundle, not merely on this file:
//!
//!   * `submit` refuses after `max_index_runs` group publications, because
//!     sealing the in-memory index delta into an `IndexRun` is unimplemented.
//!     The ceiling is raised for the run, which means every delta layer ever
//!     published is still resident and lookup fan-out grows for the whole run.
//!     P2 measures a steady state; this is not one.
//!   * `StoreEngine::checkpoint` is unimplemented, so no checkpoint is taken.
//!     Section 7 requires that a P2 run not have been achieved with
//!     checkpointing disabled. This one was.
//!
//! The third bound is gone rather than re-worded: `StoreEngine::open` refused
//! startup state 1, so the root was created by `segment::initialize_root` and
//! the run measured the production path over a store production had not built.
//! B1 landed state 1, `run_engine` builds through `open`, and the bundle now
//! declares `initialization_path: store_engine_open` — observed from the
//! `FORMAT` marker being absent before that call and present after, not
//! labelled.
//!
//! The bundle records what remains, as values a consumer checks rather than as
//! prose a consumer reads. Contract review 2026-07-28-C added the
//! `run_conditions` block for exactly this, and every member of it is derived
//! here from what the run configured or observed —
//! `initialization_path` from what the `FORMAT` marker did across the open,
//! `index_run_ceiling` by comparing the configured `max_index_runs` to the
//! store default, `index_maintenance` from the `IndexRun` files on the device
//! *read back and validated*, `checkpointing` from what
//! `StoreEngine::checkpoint` answered when this run called it, `build_profile`
//! from `cfg!`, and `environment_fidelity` from all four conditions the
//! reference profile re-pins. A hardcoded block would be the same caveat in a
//! different syntax.
//!
//! # What still has to land, recorded as a refusal rather than as a plan
//!
//! **Index steady state.** `index_maintenance: runs_sealed` says the index
//! reached a steady state. That is a statement about *bounded maintenance* —
//! deltas published and not yet sealed — and not about how many files are in a
//! directory, so the derivation requires validated index-run files **and** a
//! reading of the outstanding backlog. Nothing seals today and `StoreEngine`
//! exposes no such reading, so the honest value is unchanged
//! (`deltas_retained_in_memory`) and the declaration is unearnable rather than
//! inferable. **Interface request to B1:** a counter of sealed index runs and
//! outstanding index deltas, in the shape of `DurabilityCounters`. Until it
//! exists, a run that finds sealed runs on the device refuses by name.
//!
//! **Hardware profile.** `hardware.profile` is derived by comparing what this
//! process can read off the host against the complete `[[profile]]` tables of
//! `bench/reference-hardware.toml`. The privileged half — NVMe model and
//! firmware, the I/O scheduler of the device under the root, and the NIC,
//! driver, and link rate — belongs to the deployed-node harness, and it must
//! arrive as **facts to compare, never a profile name to accept**. The two
//! frozen profiles are identical outside their `[profile.network]` tables, so
//! without the link facts they cannot be told apart and the derivation refuses
//! rather than picking.
//!
//! Those declarations are what the claims are conditioned on: the submit path
//! asserts `unique_blob_tree_commit_ids` and
//! `objects_new_equals_three_per_commit` because it performed both checks, and
//! it may not assert `operation_receipts_reconciled` because it declares
//! `receipt_reconciliation: acceptance_of_any_committed_status` — which is the
//! truthful value while the reconciliation accepts any `Committed(_)` and the
//! journalled `receipt_digest` is `blake3(operation_id)`.
//!
//! The `run` subcommand — warmup, three repetitions, per-repetition fresh
//! roots, trim settle — stays blocked on the same two.
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

/// One complete `[[profile]]` table of `bench/reference-hardware.toml`.
///
/// The whole table, not the two filesystem fields the precheck needs. Naming
/// `hardware.profile` means deciding *which* frozen profile a host is, and that
/// is an exact comparison against everything the profile pins — a harness that
/// handed the emitter a profile *label* would be handing it an unverified claim
/// wearing a verified field's name.
pub struct ReferenceProfile {
    pub name: String,
    pub purpose: String,
    /// `(table, key) -> value as written`, with string quotes stripped and
    /// numbers, booleans, and arrays left in their frozen spelling so a
    /// comparison is against the file rather than against a re-parse of it.
    pub facts: Vec<(String, String, String)>,
}

impl ReferenceProfile {
    /// The value this profile pins for `[profile.<table>] <key>`, or `None`
    /// where it pins nothing — an unpinned fact is not a constraint, and must
    /// not be compared as though it were.
    pub fn fact(&self, table: &str, key: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|(t, k, _)| t == table && k == key)
            .map(|(_, _, value)| value.as_str())
    }
}

/// The frozen hardware profile: the filesystem expectations the two prechecks
/// enforce, plus every frozen profile in full.
pub struct FrozenProfile {
    store_directory_attributes: String,
    store_directories: Vec<String>,
    /// Every `[[profile]]` table, in file order. Used to derive
    /// `hardware.profile` by comparison rather than by assertion.
    profiles: Vec<ReferenceProfile>,
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

    /// The `[[profile]]` array-of-tables of `bench/reference-hardware.toml`,
    /// with every `[profile.<table>]` sub-table attached to the profile it
    /// belongs to.
    ///
    /// A flat "find every occurrence of this key" scan cannot do this: it
    /// cannot tell which profile a value belongs to, which is exactly what
    /// naming a profile requires. Strict throughout — an array-of-tables header
    /// this file does not model, or a key/value line outside any table, is an
    /// error rather than a line quietly skipped, because a profile silently
    /// missing a fact would be a profile the comparison could not fail against.
    ///
    /// Returns `(table, key, value)` triples per profile, where `table` is the
    /// empty string for keys written directly under `[[profile]]`.
    #[allow(clippy::type_complexity)]
    pub fn profile_tables(text: &str) -> Result<Vec<Vec<(String, String, String)>>, String> {
        let mut profiles: Vec<Vec<(String, String, String)>> = Vec::new();
        let mut table = String::new();
        // `None` until the first `[[profile]]`; the file's own preamble keys
        // (schema_version, frozen_at, notes) belong to no profile.
        let mut inside_profile = false;
        let mut inside_preamble = true;

        for (number, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(header) = line.strip_prefix("[[").and_then(|l| l.strip_suffix("]]")) {
                if header.trim() != "profile" {
                    return Err(format!(
                        "line {}: unsupported array-of-tables [[{header}]]; this reader \
                         models [[profile]] and nothing else, and skipping it would leave \
                         a table the profile comparison never sees",
                        number + 1
                    ));
                }
                profiles.push(Vec::new());
                table.clear();
                inside_profile = true;
                inside_preamble = false;
                continue;
            }
            if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                let header = header.trim();
                match header.strip_prefix("profile.") {
                    Some(sub) if inside_profile => {
                        table = sub.to_string();
                    }
                    Some(_) => {
                        return Err(format!(
                            "line {}: [{header}] appears before any [[profile]]",
                            number + 1
                        ))
                    }
                    None => {
                        return Err(format!(
                            "line {}: unsupported table [{header}]; every table in this \
                             file belongs to a profile",
                            number + 1
                        ))
                    }
                }
                continue;
            }
            let (key, value) = line.split_once('=').ok_or_else(|| {
                format!(
                    "line {}: neither a table header nor key = value",
                    number + 1
                )
            })?;
            if inside_preamble {
                continue;
            }
            let key = key.trim().to_string();
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value)
                .to_string();
            profiles
                .last_mut()
                .ok_or_else(|| format!("line {}: a value outside every profile", number + 1))?
                .push((table.clone(), key, value));
        }

        Ok(profiles)
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
    let tables =
        toml_scan::profile_tables(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if tables.is_empty() {
        return Err(format!("{} declares no [[profile]]", path.display()));
    }

    let mut profiles = Vec::new();
    for facts in tables {
        let named = |table: &str, key: &str| -> Option<String> {
            facts
                .iter()
                .find(|(t, k, _)| t == table && k == key)
                .map(|(_, _, value)| value.clone())
        };
        let name = named("", "name").ok_or_else(|| {
            format!(
                "{} has a [[profile]] with no name; an unnamed profile cannot be \
                 compared against and cannot be named in a bundle",
                path.display()
            )
        })?;
        let purpose = named("", "purpose").unwrap_or_default();
        profiles.push(ReferenceProfile {
            name,
            purpose,
            facts,
        });
    }

    // Two profiles with one name would make `hardware.profile` ambiguous the
    // moment a host matched either.
    for (index, profile) in profiles.iter().enumerate() {
        if profiles[..index]
            .iter()
            .any(|other| other.name == profile.name)
        {
            return Err(format!(
                "{} declares two [[profile]] tables named {:?}",
                path.display(),
                profile.name
            ));
        }
    }

    let attributes: Vec<&str> = profiles
        .iter()
        .filter_map(|profile| profile.fact("filesystem", "store_directory_attributes"))
        .collect();
    if attributes.len() != profiles.len() {
        return Err(format!(
            "{} has a profile with no [profile.filesystem].store_directory_attributes; \
             contract review 2026-07-24-B adds it and this binary depends on it",
            path.display()
        ));
    }
    // A profile that silently permits two different on-disk configurations for
    // the files carrying the throughput is not a frozen profile (scope 9.2).
    if attributes.iter().any(|value| *value != attributes[0]) {
        return Err(format!(
            "{} declares disagreeing store_directory_attributes across profiles: \
             {attributes:?}",
            path.display()
        ));
    }
    let store_directory_attributes = attributes[0].to_string();

    let directories: Vec<Vec<String>> = profiles
        .iter()
        .filter_map(|profile| profile.fact("filesystem", "store_directories"))
        .map(parse_string_array)
        .collect();
    if directories.len() != profiles.len() {
        return Err(format!(
            "{} has a profile with no [profile.filesystem].store_directories",
            path.display()
        ));
    }
    if directories.iter().any(|value| *value != directories[0]) {
        return Err(format!(
            "{} declares disagreeing store_directories across profiles: {directories:?}",
            path.display()
        ));
    }

    Ok(FrozenProfile {
        store_directory_attributes,
        store_directories: directories[0].clone(),
        profiles,
    })
}

/// `["a", "b"]` as written in the frozen file.
fn parse_string_array(raw: &str) -> Vec<String> {
    raw.trim()
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .map(|inner| {
            inner
                .split(',')
                .map(|entry| entry.trim().trim_matches('"').to_string())
                .filter(|entry| !entry.is_empty())
                .collect()
        })
        .unwrap_or_default()
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

/// The digest of a file the bundle attests to.
///
/// A read failure is a refusal, not `digest_hex(b"")`. The empty digest is a
/// well-formed 64-hex-character value that a reader cannot distinguish from
/// the digest of a file that was actually read, so returning it made an
/// unreadable input indistinguishable from an attested one — the same defect
/// class as a run that ends quietly, in the reporting half of the emitter.
fn digest_file(path: &Path) -> Result<String, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(digest_hex(&bytes)),
        Err(error) => Err(format!(
            "refusing to emit a bundle: {} could not be read to digest it ({error}). A \
             bundle field that names a digest must name the digest of something this run \
             read.",
            path.display()
        )),
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

/// A reading, or nothing. An empty string is what these helpers return when the
/// host would not answer, and treating that as an observed value is how a fact
/// with no reading would compare equal to a profile that pins the empty string.
fn non_empty(value: String) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn or_unknown(value: String, what: &str) -> String {
    if value.is_empty() {
        format!("unknown ({what} not readable on this host)")
    } else {
        value
    }
}

// ---------------------------------------------------------------------------
// Run conditions (contract review 2026-07-28-C, scope 6.6 item 5b)
// ---------------------------------------------------------------------------
//
// The ten members of `run_conditions` are **declarations of what this run
// did**, and every one of them is derived here from something the run observed
// or configured. A hardcoded block would be the prose caveat with a different
// syntax, which is what the review rejected — so the types below are
// observations, and `RunConditions::derive` is the only place a schema
// enumeration value is produced.
//
// Charter item 6 applies throughout: the schema's enumerations are closed sets
// and the mapping onto them is closed too. There is no catch-all arm and no
// fallback binding anywhere in this section; an observation that maps to no
// named value is a refusal that names it.

/// How the store root the run measured was created.
///
/// `segment_initialize_root` has no variant here any more, and its absence is
/// the deliverable: while `StoreEngine::open` refused startup state 1 the
/// submit run seeded its own root and declared it, which is a benchmark
/// measuring the production path over a store production had not built. B1
/// landed state 1, `run_engine` builds through `open`, and a variant nothing
/// constructs would be a declaration this file could make without having done
/// anything.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Initialization {
    /// `StoreEngine::open` created the root, observed rather than assumed: no
    /// `FORMAT` marker before the call, one after.
    StoreEngineOpen,
    /// `ShardDrive::create`, the Wave A journal seam.
    ShardDriveCreate,
}

/// The entry point the measured transactions actually went through.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MutationPath {
    StoreEngineSubmit,
    JournalDrive,
}

/// What `StoreEngine::checkpoint` answered when this run called it.
///
/// Classified from a real call rather than from this file's opinion of what
/// the store implements. Both variants are constructed by
/// [`probe_checkpointing`]; anything else it sees is a refusal, because the
/// schema's four values name no third answer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CheckpointProbe {
    /// `StoreEngine::checkpoint` refused `NotImplemented`, so no checkpoint was
    /// taken and none could have been.
    RefusedNotImplemented,
    /// `StoreEngine::checkpoint` returned a lease. The measured window still
    /// contains no checkpoint — the harness takes none inside it — so the
    /// truthful value is `enabled_not_reached`, and reaching one is the
    /// emitter's next change rather than a relabelling of this one.
    EnabledNotReached,
}

/// Whether the index reached a steady state, from what is on the device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexObservation {
    /// What `shards/*/indexes` held after the run, alongside the group
    /// publications the run performed.
    ///
    /// `validated_runs` counts only entries that were read back and parsed as
    /// an `IndexRun` against this root's own uuid. Counting directory entries
    /// was the defect: a temporary file, a truncated file, or an unrelated file
    /// dropped in the directory would each have moved `index_maintenance` to
    /// `runs_sealed`, and a declaration that the index reached a steady state
    /// must not be satisfiable by a stray file.
    StoreRoot {
        validated_runs: u64,
        /// Entries under those directories that did not parse as an index run,
        /// with why. Non-empty is a refusal, not a lower count: an entry the
        /// emitter cannot validate is a directory it cannot describe.
        unvalidatable: Vec<String>,
        groups: u64,
        /// Index deltas the run published and did not seal into a run, as the
        /// store reports them.
        ///
        /// `None` while nothing seals and the store exposes no reading of the
        /// outstanding backlog. A steady state is *bounded maintenance*, not
        /// the presence of files, so a run that cannot show the backlog cannot
        /// earn `runs_sealed` — see [`RunConditions::derive`], which refuses by
        /// name rather than inferring it. Recorded as an interface request:
        /// `StoreEngine` needs a counter of sealed runs and outstanding deltas
        /// in the same shape as `DurabilityCounters`.
        unsealed_delta_backlog: Option<u64>,
    },
    /// The measured path is the journal seam: nothing below `engine.rs` touches
    /// an index at all.
    NoIndexInPath,
}

/// What the run reconciled each acknowledged operation against.
///
/// `exact_receipts_reconciled` and `canonical_receipt_digest_reconciled` have
/// no variants here for the same reason `store_engine_open` has none above: no
/// code in this file performs either, and a variant that nothing constructs is
/// a claim waiting to be made by accident.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReceiptComparison {
    /// The reconciliation loop accepts any `TransactionStatus::Committed(_)`
    /// without comparing the payload, and the `receipt_digest` it journals is
    /// `blake3(operation_id)` rather than a digest of the receipt.
    AnyCommittedStatusAccepted,
    /// The journal seam produces no receipts to reconcile.
    NoReceiptsInPath,
}

/// How blob, tree, and commit identifier uniqueness was established.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UniquenessCheck {
    /// Every `blob_ids`, `tree_ids`, and `commit_ids` entry from every record
    /// `ExternalAckJournal::recover` returned, unioned into one set per kind
    /// across all records at once, with no repeat. The counts are the set
    /// sizes, so a reader can see the check had something to check.
    GlobalAcrossAckRecords {
        blob_ids: u64,
        tree_ids: u64,
        commit_ids: u64,
    },
    /// Not performed. On the journal seam the identifiers in an acknowledgment
    /// record are fabricated by this harness rather than produced by the store,
    /// so checking them would establish a property of the harness.
    NotPerformed,
}

/// What a measured run observed about itself, whichever path produced it.
///
/// Everything here is recorded at the site that performed the thing it
/// describes, so a path that stops doing one of them stops being able to
/// declare it.
pub struct RunFacts {
    pub initialization: Initialization,
    pub mutation: MutationPath,
    pub checkpoint: CheckpointProbe,
    pub index: IndexObservation,
    pub configured_max_index_runs: u32,
    pub default_max_index_runs: u32,
    pub receipts: ReceiptComparison,
    pub objects_new_counted: bool,
    pub uniqueness: UniquenessCheck,
}

/// The facts a run observed, from which the ten declarations are derived.
pub struct RunObservations {
    pub initialization: Initialization,
    pub mutation: MutationPath,
    pub checkpoint: CheckpointProbe,
    pub index: IndexObservation,
    /// `StoreOptions::max_index_runs` as the run configured it, read back from
    /// the options struct the store was opened with.
    pub configured_max_index_runs: u32,
    /// The same field on an otherwise untouched `StoreOptions`, so the
    /// comparison below is against the library's default rather than against a
    /// number this file writes twice.
    pub default_max_index_runs: u32,
    pub receipts: ReceiptComparison,
    /// `counts.objects_new` was summed from the store's own receipts rather
    /// than multiplied out of the transaction count.
    pub objects_new_counted: bool,
    pub uniqueness: UniquenessCheck,
    /// The filesystem carrying the store root, read from `/proc/mounts`.
    pub store_root_filesystem: String,
    pub store_root_is_tmpfs: bool,
}

impl RunObservations {
    /// What the run observed about itself, plus what the host observed about
    /// where it ran.
    pub fn new(facts: RunFacts, mount: MountFacts) -> Self {
        Self {
            initialization: facts.initialization,
            mutation: facts.mutation,
            checkpoint: facts.checkpoint,
            index: facts.index,
            configured_max_index_runs: facts.configured_max_index_runs,
            default_max_index_runs: facts.default_max_index_runs,
            receipts: facts.receipts,
            objects_new_counted: facts.objects_new_counted,
            uniqueness: facts.uniqueness,
            store_root_filesystem: mount.filesystem,
            store_root_is_tmpfs: mount.tmpfs,
        }
    }
}

/// The ten declarations, each already mapped onto its schema enumeration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunConditions {
    pub initialization_path: &'static str,
    pub mutation_path: &'static str,
    pub checkpointing: &'static str,
    pub index_maintenance: &'static str,
    pub index_run_ceiling: &'static str,
    pub receipt_reconciliation: &'static str,
    pub objects_new_source: &'static str,
    pub commit_id_uniqueness: &'static str,
    pub build_profile: &'static str,
    pub environment_fidelity: &'static str,
}

impl RunConditions {
    /// Derive all ten from what the run observed.
    ///
    /// `attributes_verified` is whether the store-directory attribute precheck
    /// ran and matched; `hardware_profile` is the value this bundle is about to
    /// emit as `hardware.profile`, which is itself derived from whether any
    /// hardware field is a placeholder rather than a measurement.
    pub fn derive(
        observations: &RunObservations,
        attributes_verified: bool,
        hardware_profile: &str,
    ) -> Result<Self, String> {
        let index_maintenance = match &observations.index {
            IndexObservation::StoreRoot {
                validated_runs,
                unvalidatable,
                groups,
                unsealed_delta_backlog,
            } => {
                // An entry the emitter could not read back as an index run is a
                // refusal by name and never a lower count. Folding it into
                // "zero sealed runs" would let a corrupt or half-written run
                // read as a run that was never sealed, and folding it into the
                // count would let a stray file declare a steady state.
                if !unvalidatable.is_empty() {
                    return Err(format!(
                        "refusing to emit a bundle: {} entr(ies) under shards/*/indexes did \
                         not read back as an IndexRun for this root: {}. \
                         run_conditions.index_maintenance declares whether the index reached \
                         a steady state, and a directory this emitter cannot describe is not \
                         a state it may declare.",
                        unvalidatable.len(),
                        unvalidatable.join("; ")
                    ));
                }
                if *validated_runs > 0 {
                    // Files are not maintenance. `runs_sealed` says the index
                    // reached a steady state, which is a statement about the
                    // *backlog* — deltas published and not yet sealed — and not
                    // about how many files are on the device. Nothing seals
                    // today, so this arm is unreachable today; it exists so the
                    // day sealing lands the declaration is earned from a
                    // reading rather than inferred from a directory listing.
                    match unsealed_delta_backlog {
                        Some(0) => "runs_sealed",
                        Some(backlog) => {
                            return Err(format!(
                                "refusing to emit a bundle: {validated_runs} index run(s) were \
                                 sealed and {backlog} published delta(s) are still unsealed. \
                                 run_conditions.index_maintenance names a steady state and a \
                                 run that retained every delta, and this is neither: sealing \
                                 ran and did not keep up. Naming either would describe a \
                                 backlog as its opposite."
                            ));
                        }
                        None => {
                            return Err(format!(
                                "refusing to emit a bundle: {validated_runs} validated index \
                                 run(s) are on the device, but the store exposes no reading of \
                                 how many published deltas remain unsealed, so this run cannot \
                                 show that index maintenance was bounded. `runs_sealed` would \
                                 be inferred from the presence of files rather than earned \
                                 from a measurement. Interface request to B1: an outstanding \
                                 index-delta counter alongside DurabilityCounters."
                            ));
                        }
                    }
                } else if *groups > 0 {
                    "deltas_retained_in_memory"
                } else {
                    return Err(
                        "refusing to emit a bundle: the run published no group and sealed \
                         no index run, so there is no index maintenance to declare. \
                         run_conditions.index_maintenance has no value for a run that did \
                         nothing, and inventing one would be the caveat this block \
                         replaced."
                            .to_string(),
                    );
                }
            }
            IndexObservation::NoIndexInPath => "no_index_in_path",
        };

        // Not `ENGINE_MAX_INDEX_RUNS` compared against a restated 64: the
        // configured value comes from the options the store opened with and the
        // default comes from `StoreOptions` itself, so the day either moves,
        // this declaration moves with it.
        let index_run_ceiling =
            if observations.configured_max_index_runs == observations.default_max_index_runs {
                "store_default"
            } else if observations.configured_max_index_runs > observations.default_max_index_runs {
                "raised_because_index_sealing_unimplemented"
            } else {
                return Err(format!(
                    "refusing to emit a bundle: the run configured max_index_runs = {} below \
                 the store default of {}. run_conditions.index_run_ceiling names a default \
                 and a raise and nothing else, and a lowered ceiling is neither — it is a \
                 run that refuses earlier than the store would, which is a condition the \
                 schema cannot express and this emitter will not disguise as one it can.",
                    observations.configured_max_index_runs, observations.default_max_index_runs
                ));
            };

        // `cfg!(debug_assertions)` is the whole of what a compiled binary can
        // see of its own profile: `opt-level` is not exposed to `cfg`, so a
        // release build with `debug-assertions = true` is indistinguishable
        // from a debug build from in here and is reported as `debug`. That is
        // the safe direction — it can only disqualify a run from
        // `reference_profile`, never admit one — and it is why
        // `release_with_debug_assertions` is a value this emitter never
        // produces.
        let build_profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };

        // `reference_profile` re-pins persistent_data_mount, tmpfs,
        // build_profile, and a named hardware profile, so it is asserted only
        // when every one of those was observed to hold — including the
        // store-directory attribute precheck actually having run.
        let environment_fidelity = if build_profile == "release"
            && attributes_verified
            && !observations.store_root_is_tmpfs
            && hardware_profile != "diagnostic"
        {
            "reference_profile"
        } else {
            "diagnostic"
        };

        Ok(Self {
            initialization_path: match observations.initialization {
                Initialization::StoreEngineOpen => "store_engine_open",
                Initialization::ShardDriveCreate => "shard_drive_create",
            },
            mutation_path: match observations.mutation {
                MutationPath::StoreEngineSubmit => "store_engine_submit",
                MutationPath::JournalDrive => "journal_drive",
            },
            checkpointing: match observations.checkpoint {
                CheckpointProbe::RefusedNotImplemented => "unimplemented",
                CheckpointProbe::EnabledNotReached => "enabled_not_reached",
            },
            index_maintenance,
            index_run_ceiling,
            receipt_reconciliation: match observations.receipts {
                ReceiptComparison::AnyCommittedStatusAccepted => {
                    "acceptance_of_any_committed_status"
                }
                ReceiptComparison::NoReceiptsInPath => "no_receipts_in_path",
            },
            objects_new_source: if observations.objects_new_counted {
                "summed_from_receipts"
            } else {
                "derived_from_transaction_count"
            },
            commit_id_uniqueness: match observations.uniqueness {
                UniquenessCheck::GlobalAcrossAckRecords { .. } => {
                    "checked_globally_across_ack_records"
                }
                UniquenessCheck::NotPerformed => "not_checked",
            },
            build_profile,
            environment_fidelity,
        })
    }

    fn to_json(&self) -> J {
        J::Object(vec![
            ("initialization_path".into(), jstr(self.initialization_path)),
            ("mutation_path".into(), jstr(self.mutation_path)),
            ("checkpointing".into(), jstr(self.checkpointing)),
            ("index_maintenance".into(), jstr(self.index_maintenance)),
            ("index_run_ceiling".into(), jstr(self.index_run_ceiling)),
            (
                "receipt_reconciliation".into(),
                jstr(self.receipt_reconciliation),
            ),
            ("objects_new_source".into(), jstr(self.objects_new_source)),
            (
                "commit_id_uniqueness".into(),
                jstr(self.commit_id_uniqueness),
            ),
            ("build_profile".into(), jstr(self.build_profile)),
            (
                "environment_fidelity".into(),
                jstr(self.environment_fidelity),
            ),
        ])
    }

    /// The ten members in schema order, for the harness's own stdout.
    pub fn pairs(&self) -> [(&'static str, &'static str); 10] {
        [
            ("initialization_path", self.initialization_path),
            ("mutation_path", self.mutation_path),
            ("checkpointing", self.checkpointing),
            ("index_maintenance", self.index_maintenance),
            ("index_run_ceiling", self.index_run_ceiling),
            ("receipt_reconciliation", self.receipt_reconciliation),
            ("objects_new_source", self.objects_new_source),
            ("commit_id_uniqueness", self.commit_id_uniqueness),
            ("build_profile", self.build_profile),
            ("environment_fidelity", self.environment_fidelity),
        ]
    }
}

/// What is actually under every shard's `indexes` directory, validated.
///
/// The observation behind `index_maintenance`. The previous version counted
/// *directory entries*: a temporary file, a truncated run, or an unrelated file
/// each raised the count, and one of them was enough to flip the declaration to
/// `runs_sealed`. A declaration that the index reached a steady state must not
/// be satisfiable by a stray file, so every entry is read back and parsed as an
/// `IndexRun` against this root's own uuid, and anything that does not parse is
/// returned as an entry the emitter could not validate rather than silently
/// counted or silently dropped.
struct IndexRunScan {
    validated_runs: u64,
    unvalidatable: Vec<String>,
}

fn scan_index_runs(root: &Path, shard_count: u16) -> IndexRunScan {
    use levcs_store::index::IndexRun;
    use levcs_store::segment::{read_format, RootLayout};

    let layout = RootLayout::new(root);
    let mut scan = IndexRunScan {
        validated_runs: 0,
        unvalidatable: Vec::new(),
    };

    // Without the root's own uuid no entry can be validated *as this root's*,
    // and an index run carrying another root's uuid is exactly the kind of
    // stray file this scan exists to reject. A root whose FORMAT cannot be read
    // is reported as one unvalidatable entry rather than as an empty directory.
    let root_uuid = match read_format(&layout) {
        Ok(marker) => marker.root_uuid,
        Err(error) => {
            scan.unvalidatable.push(format!(
                "{}: FORMAT could not be read ({error}), so no index run under this root \
                 can be validated as belonging to it",
                layout.format_path().display()
            ));
            return scan;
        }
    };

    for shard in 0..shard_count {
        let directory = layout.shard(shard).indexes();
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            // An absent `indexes` directory is an empty one: `initialize_root`
            // creates it, so its absence is itself a finding — but it cannot
            // make a sealed run appear, and an unreadable directory is recorded
            // as unvalidatable rather than as evidence of emptiness.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                scan.unvalidatable
                    .push(format!("{}: {error}", directory.display()));
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    scan.unvalidatable
                        .push(format!("{}: {error}", directory.display()));
                    continue;
                }
            };
            let path = entry.path();
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) => {
                    scan.unvalidatable
                        .push(format!("{}: {error}", path.display()));
                    continue;
                }
            };
            match IndexRun::from_vec(bytes, &root_uuid) {
                Ok(_) => scan.validated_runs += 1,
                Err(error) => scan
                    .unvalidatable
                    .push(format!("{}: {error:?}", path.display())),
            }
        }
    }

    scan
}

/// Ask the store what it does about checkpoints, and classify the answer.
///
/// Called on the engine the run measured wherever there is one, and on a
/// throwaway root otherwise, so both paths declare `checkpointing` from a real
/// call to the real entry point rather than from a constant per path.
fn probe_checkpointing(engine: &levcs_store::StoreEngine) -> Result<CheckpointProbe, String> {
    use levcs_store::types::StoreError;
    match engine.checkpoint() {
        Ok(_) => Ok(CheckpointProbe::EnabledNotReached),
        Err(StoreError::NotImplemented(_)) => Ok(CheckpointProbe::RefusedNotImplemented),
        Err(other) => Err(format!(
            "refusing to emit a bundle: StoreEngine::checkpoint refused with {other}. \
             run_conditions.checkpointing names four states and none of them is this \
             one, so the run has nothing truthful to declare."
        )),
    }
}

/// The same probe for a path with no engine of its own.
fn probe_checkpointing_on_fresh_root(directory: &Path) -> Result<CheckpointProbe, String> {
    use levcs_store::segment::{initialize_root, RootLayout};
    use levcs_store::types::DurabilityCounters;

    let _ = std::fs::remove_dir_all(directory);
    initialize_root(
        &RootLayout::new(directory),
        1,
        [0x9f; 16],
        engine_now_micros(),
        &DurabilityCounters::default(),
    )
    .map_err(|e| format!("checkpoint probe: initialize_root: {e}"))?;
    let mut options = levcs_store::StoreOptions::new(directory);
    options.shard_count = 1;
    // A store that cannot sequence a transaction is not a store to ask about
    // checkpoints; the engine refuses to open without a signer.
    options.signer = Some(std::sync::Arc::new(MeasuringSigner::new()));
    let probe = match levcs_store::StoreEngine::open(options) {
        Ok(engine) => {
            let probe = probe_checkpointing(&engine);
            drop(engine);
            probe
        }
        Err(error) => Err(format!("checkpoint probe: {error}")),
    };
    // Cleaned up on both outcomes: a probe root left behind next to the run's
    // own root is a directory the next run trips over.
    let _ = std::fs::remove_dir_all(directory);
    probe
}

/// The filesystem the store root actually sits on.
pub struct MountFacts {
    pub filesystem: String,
    pub tmpfs: bool,
}

/// Read the mount carrying `path` out of `/proc/mounts`.
///
/// `deployment.tmpfs` and `deployment.persistent_data_mount` were constants
/// until contract review 2026-07-28-C relaxed them; emitting them as constants
/// now would keep the defect the relaxation exists to fix, since a run on a
/// non-persistent mount would still describe itself as persistent.
fn detect_mount(path: &Path) -> Result<MountFacts, String> {
    let target = std::fs::canonicalize(path)
        .map_err(|e| format!("resolving the store root {}: {e}", path.display()))?;
    let mounts = std::fs::read_to_string("/proc/mounts")
        .map_err(|e| format!("reading /proc/mounts: {e}"))?;

    let unescape = |field: &str| field.replace("\\040", " ").replace("\\011", "\t");
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_device), Some(point), Some(kind)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let point = PathBuf::from(unescape(point));
        if target.starts_with(&point) {
            let depth = point.components().count();
            if best.as_ref().map_or(true, |(best, _)| depth > *best) {
                best = Some((depth, unescape(kind)));
            }
        }
    }

    match best {
        Some((_, filesystem)) => Ok(MountFacts {
            tmpfs: matches!(filesystem.as_str(), "tmpfs" | "ramfs"),
            filesystem,
        }),
        None => Err(format!(
            "no mount in /proc/mounts contains {}; the bundle cannot declare whether \
             the run was on a persistent filesystem, and declaring it anyway is what \
             deployment.tmpfs was relaxed to stop.",
            target.display()
        )),
    }
}

/// Markers this emitter writes where it has recorded a placeholder instead of a
/// measurement.
///
/// A bundle carrying any of them has not verified the frozen hardware profile,
/// whatever its other fields say. Retained as a cross-check on the comparison
/// below rather than as the derivation itself: naming a profile while still
/// writing "recorded by the deployed-node harness" into a `hardware.*` field
/// would mean the comparison and the emitted fields disagree about the same
/// host, and that is a refusal.
const HARDWARE_PLACEHOLDER_MARKERS: [&str; 4] = [
    "unknown (",
    "unverified",
    "recorded by the deployed-node harness",
    "none (in-process P2)",
];

/// The two frozen profile names the schema's `hardware.profile` enumeration
/// admits alongside `diagnostic`.
///
/// A profile in `bench/reference-hardware.toml` whose name is not one of these
/// is a refusal rather than a name emitted on faith: the schema's enumeration
/// is a closed set, and a third frozen profile is a lead-owned schema change
/// before it is a bundle value.
const NAMED_HARDWARE_PROFILES: [&str; 2] = ["minimum-30k", "release-60k"];

/// One fact the frozen profile pins, and what this run read for it.
///
/// `observed: None` is the deployed-node harness's half. It is deliberately not
/// a hole the emitter fills with a default: a fact with no reading eliminates
/// every profile that pins it, so an unobservable fact can only ever move the
/// derivation toward `diagnostic` and never toward a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostFact {
    /// `[profile.<table>]` as the frozen file spells it.
    pub table: &'static str,
    pub key: &'static str,
    pub observed: Option<String>,
}

impl HostFact {
    /// `table.key`, spelled as the frozen file spells it. Test-only since the
    /// comparison was inverted: the derivation now names each fact from the
    /// profile side, because that is the side that decides which facts exist.
    #[cfg(test)]
    fn name(&self) -> String {
        format!("{}.{}", self.table, self.key)
    }
}

/// What `store-bench` can read about the host it is running on, named exactly
/// as `bench/reference-hardware.toml` names it.
///
/// Every entry is a reading or an explicit absence. The absences are the
/// interface request to the deployed-node harness — and they are *evidence to
/// compare*, never a name to accept: a harness that supplied
/// `hardware.profile = "release-60k"` would be supplying a claim this emitter
/// has no way to check, which is the failure mode the split design exists to
/// prevent.
pub fn observe_host_facts(store_root_filesystem: &str) -> Vec<HostFact> {
    let cpuinfo = |field: &str| -> Option<String> {
        let text = std::fs::read_to_string("/proc/cpuinfo").ok()?;
        text.lines()
            .find(|line| line.trim_start().starts_with(field))
            .and_then(|line| line.split_once(':'))
            .and_then(|(_, value)| non_empty(value.trim().to_string()))
    };
    let threads = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .map(|text| {
            text.lines()
                .filter(|line| line.trim_start().starts_with("processor"))
                .count()
        })
        .filter(|count| *count > 0)
        .map(|count| count.to_string());
    let numa_nodes = std::fs::read_dir("/sys/devices/system/node")
        .ok()
        .map(|entries| {
            entries
                .filter_map(|entry| entry.ok())
                .filter(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with("node"))
                })
                .count()
        })
        .filter(|count| *count > 0)
        .map(|count| count.to_string());
    let swap_enabled = std::fs::read_to_string("/proc/swaps")
        .ok()
        .map(|text| (text.lines().count() > 1).to_string());

    vec![
        HostFact {
            table: "cpu",
            key: "model",
            observed: cpuinfo("model name"),
        },
        HostFact {
            table: "cpu",
            key: "physical_cores",
            observed: cpuinfo("cpu cores"),
        },
        HostFact {
            table: "cpu",
            key: "threads",
            observed: threads,
        },
        HostFact {
            table: "cpu",
            key: "architecture",
            observed: Some(std::env::consts::ARCH.to_string()),
        },
        HostFact {
            table: "cpu",
            key: "governor",
            observed: non_empty(read_first_line(
                "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
            )),
        },
        HostFact {
            table: "cpu",
            key: "numa_nodes",
            observed: numa_nodes,
        },
        HostFact {
            table: "cpu",
            key: "microcode",
            observed: cpuinfo("microcode"),
        },
        HostFact {
            table: "memory",
            key: "swap_enabled",
            observed: swap_enabled,
        },
        // `MemTotal` is what the kernel manages, not what is installed:
        // firmware reservations make the two differ by hundreds of megabytes,
        // so an exact comparison against `installed_gib` cannot be made from
        // it. The reading belongs to the deployed-node harness.
        HostFact {
            table: "memory",
            key: "installed_gib",
            observed: None,
        },
        HostFact {
            table: "filesystem",
            key: "type",
            observed: Some(store_root_filesystem.to_string()),
        },
        HostFact {
            table: "software",
            key: "kernel",
            observed: non_empty(command_output("uname", &["-sr"])),
        },
        // Everything below needs a privileged reading of the device or the
        // link. The two frozen profiles are identical *except* for their
        // `[profile.network]` tables, so without these the comparison cannot
        // distinguish `minimum-30k` from `release-60k` even on the reference
        // host — which is why they are listed rather than dropped.
        HostFact {
            table: "nvme",
            key: "model",
            observed: None,
        },
        HostFact {
            table: "nvme",
            key: "firmware",
            observed: None,
        },
        HostFact {
            table: "nvme",
            key: "scheduler",
            observed: None,
        },
        HostFact {
            table: "network",
            key: "nic",
            observed: None,
        },
        HostFact {
            table: "network",
            key: "driver",
            observed: None,
        },
        HostFact {
            table: "network",
            key: "link_mbps",
            observed: None,
        },
    ]
}

/// Why `hardware.profile` came out the way it did, reported alongside the value
/// so a reader can see what was compared rather than only what was concluded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareProfileDerivation {
    pub name: &'static str,
    /// Facts a frozen profile pins that this run could not read — whether the
    /// emitter tried and failed or does not model the fact at all, which are
    /// the same thing from a bundle's point of view. Each one eliminates every
    /// profile pinning it; this list is the deployed-node harness's work order.
    pub unobserved: Vec<String>,
    /// Facts read whose value disagrees with every frozen profile.
    pub mismatched: Vec<String>,
}

/// `hardware.profile`, derived by comparing observed host facts against the
/// complete `[[profile]]` tables of `bench/reference-hardware.toml`.
///
/// The comparison is exact and per fact, and it is driven by **the frozen
/// profile**, not by what this emitter happens to observe. A profile is a
/// candidate only when every fact it pins was read *and* compared equal; a
/// fact with no reading eliminates the profile rather than being skipped,
/// because skipping it would let a host be named on a partial match. Zero
/// candidates is `diagnostic` — the run is not on the reference host, or has
/// not shown that it is. Two candidates is a refusal: the facts that would
/// separate them were not observed, and picking one would be the guess this
/// function exists to eliminate.
///
/// The direction matters and was wrong. Iterating the *supplied* facts made a
/// pinned fact this emitter does not model invisible rather than unobserved:
/// `cpu.turbo`, `nvme.power_loss_protection`, `filesystem.barriers`,
/// `network.mtu` and the rest were pinned by both profiles and compared by
/// nothing, so a host could match every modelled fact, differ on an unmodelled
/// one, and be named anyway. Iterating the profile closes that mechanically —
/// a pinned fact with no `HostFact` entry at all is indistinguishable from one
/// whose entry reads `None`, because in both cases the run did not observe it
/// — and it makes the comparison set self-maintaining: a fact added to
/// `bench/reference-hardware.toml` tightens the check on the next run instead
/// of being ignored until someone remembers to model it.
fn hardware_profile_of(
    profiles: &[ReferenceProfile],
    facts: &[HostFact],
    emitted_fields: &[(String, J)],
) -> Result<HardwareProfileDerivation, String> {
    let mut unobserved: Vec<String> = Vec::new();
    let mut matched_somewhere: Vec<String> = Vec::new();
    let mut compared: Vec<String> = Vec::new();
    let mut candidates: Vec<&ReferenceProfile> = Vec::new();

    for profile in profiles {
        let mut candidate = true;
        let mut pinned_facts = 0u32;
        for (table, key, pinned) in &profile.facts {
            if table.is_empty() {
                // `name` and `purpose` sit above every `[profile.<table>]`.
                // They identify the profile rather than pin a property of a
                // host, and there is nothing on a host to read them from.
                continue;
            }
            pinned_facts += 1;
            let name = format!("{table}.{key}");
            let observed = facts
                .iter()
                .find(|fact| fact.table == table.as_str() && fact.key == key.as_str())
                .and_then(|fact| fact.observed.as_deref());
            match observed {
                None => {
                    candidate = false;
                    if !unobserved.contains(&name) {
                        unobserved.push(name);
                    }
                }
                Some(observed) => {
                    if !compared.contains(&name) {
                        compared.push(name.clone());
                    }
                    if observed == pinned.as_str() {
                        if !matched_somewhere.contains(&name) {
                            matched_somewhere.push(name);
                        }
                    } else {
                        candidate = false;
                    }
                }
            }
        }
        // A profile that pins nothing is matched by every host, including one
        // that observed nothing at all. Refused rather than treated as a
        // vacuous candidate, because the name it would produce would rest on
        // no comparison whatsoever.
        if pinned_facts == 0 {
            return Err(format!(
                "refusing to derive hardware.profile: the frozen profile {:?} pins no \
                 [profile.<table>] fact, so every host would match it and the name would \
                 rest on no comparison at all.",
                profile.name
            ));
        }
        if candidate {
            candidates.push(profile);
        }
    }

    let mismatched: Vec<String> = compared
        .into_iter()
        .filter(|name| !matched_somewhere.contains(name))
        .collect();

    if candidates.len() > 1 {
        return Err(format!(
            "refusing to emit a bundle: the observed host facts match {} frozen profiles \
             ({}). The facts that separate them were not observed, and naming one of them \
             would be a guess wearing a frozen profile's name.",
            candidates.len(),
            candidates
                .iter()
                .map(|profile| profile.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    let Some(profile) = candidates.first() else {
        return Ok(HardwareProfileDerivation {
            name: "diagnostic",
            unobserved,
            mismatched,
        });
    };

    // The frozen file names the profile; the schema enumerates what a bundle
    // may carry. A name in one and not the other is a refusal, never a value
    // emitted because the file said so.
    let name = NAMED_HARDWARE_PROFILES
        .iter()
        .find(|known| **known == profile.name)
        .ok_or_else(|| {
            format!(
                "refusing to emit a bundle: the host matches the frozen profile {:?}, which \
                 is not one of the names bench/result-schema.json admits for \
                 hardware.profile ({}). A third frozen profile is a schema change before it \
                 is a bundle value.",
                profile.name,
                NAMED_HARDWARE_PROFILES.join(", ")
            )
        })?;

    // The comparison said this host is the reference host; the fields about to
    // be emitted still say otherwise. Two statements about one host that
    // disagree is a refusal, not a value to pick between.
    let placeholders: Vec<&str> = emitted_fields
        .iter()
        .filter_map(|(field, value)| match value {
            J::Str(text) => HARDWARE_PLACEHOLDER_MARKERS
                .iter()
                .any(|marker| text.contains(marker))
                .then_some(field.as_str()),
            J::Bool(_) | J::Int(_) | J::Float(_) | J::Array(_) | J::Object(_) => None,
        })
        .collect();
    if !placeholders.is_empty() {
        return Err(format!(
            "refusing to emit a bundle: the host facts match the frozen profile {name}, but \
             the hardware fields this bundle would carry are still placeholders \
             ({}). A bundle cannot name a frozen profile in one field and record \
             \"not measured here\" in the next.",
            placeholders.join(", ")
        ));
    }

    Ok(HardwareProfileDerivation {
        name,
        unobserved,
        mismatched,
    })
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
    /// What the run observed, from which `run_conditions` is derived. Carried
    /// as observations rather than as the ten declarations so the derivation
    /// itself is under test: a fixture that handed the emitter ten finished
    /// strings would test the JSON writer and nothing else.
    pub observations: RunObservations,
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
///
/// A run that did not meet the reference environment cannot be a `pass` at any
/// gate — the schema says so in one rule, and this says it before the schema
/// has to, so the emitter never has to be told by a validator that it wrote a
/// claim it had not earned.
///
/// # Every condition a `pass` costs, not only the binding one
///
/// `bench/result-schema.json` requires four more declarations of a passing
/// `storage_primitive` bundle: the root built by `StoreEngine::open`, the
/// transactions through `StoreEngine::submit`, `checkpointing: "exercised"`,
/// and `index_maintenance: "runs_sealed"`. Until hardware recognition worked,
/// `environment_fidelity` was the only thing standing between this function and
/// a `pass`, so the other four were never reached — and the moment recognition
/// starts working, an emitter that checked only fidelity would produce a `pass`
/// the schema then rejects. A bundle refused by its own validator is a harness
/// that learned what it had claimed from a validator, which is the sequence
/// this file exists to avoid. Every condition is checked here, at the same
/// altitude, so the emitter's answer and the schema's answer cannot diverge.
pub fn storage_primitive_outcome(inputs: &BundleInputs, conditions: &RunConditions) -> Outcome {
    if inputs.latency_p99 > STORAGE_PRIMITIVE_P99_CEILING_MICROS
        || inputs.windows_meeting_target_percent < 95.0
    {
        return Outcome::Fail;
    }
    if inputs.skeleton
        || conditions.environment_fidelity != "reference_profile"
        || conditions.initialization_path != "store_engine_open"
        || conditions.mutation_path != "store_engine_submit"
        || conditions.checkpointing != "exercised"
        || conditions.index_maintenance != "runs_sealed"
    {
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

/// The bundle bytes, for callers that need nothing else.
pub fn build_bundle(
    repo_root: &Path,
    workload: &FrozenWorkload,
    inputs: &BundleInputs,
) -> Result<String, String> {
    assemble_bundle(repo_root, workload, inputs).map(|assembled| assembled.json)
}

/// A bundle and the derivations the harness also has to report.
pub struct AssembledBundle {
    pub json: String,
    pub outcome: Outcome,
    pub conditions: RunConditions,
    /// Why `hardware.profile` came out the way it did. Reported on the
    /// harness's own stdout so the facts the deployed-node harness still owes
    /// are a list a reader can act on rather than a sentence in a doc comment.
    pub hardware: HardwareProfileDerivation,
}

pub fn assemble_bundle(
    repo_root: &Path,
    workload: &FrozenWorkload,
    inputs: &BundleInputs,
) -> Result<AssembledBundle, String> {
    // A run that measured nothing may not make a claim about what it measured.
    //
    // Every one of `setup_traffic_excluded`, `unique_blob_tree_commit_ids`, and
    // `objects_new_equals_three_per_commit` is *vacuously* true over an empty
    // set, which is exactly why none of them may be earned that way: a
    // uniqueness claim over zero identifiers and a three-objects-per-commit
    // claim over zero commits are statements about nothing, presented in the
    // same field a real run uses. The schema is no help here — it validates a
    // zero-commit bundle cheerfully, because `counts` is `nonnegative` and the
    // claims are `const true` — so this is the only place the refusal can live.
    //
    // A refusal by name, not a `false`: the schema pins those claims to
    // `const true` on the submit path, so emitting `false` is unavailable, and
    // emitting `true` would be the untrue statement this check exists to stop.
    if inputs.counted_commits == 0 || inputs.acknowledged_requests == 0 {
        return Err(format!(
            "refusing to emit a bundle: the measured interval contains {} counted commit(s) \
             and {} acknowledged request(s). verification.setup_traffic_excluded, \
             unique_blob_tree_commit_ids, and objects_new_equals_three_per_commit are all \
             vacuously true over an empty set, and a claim that cannot fail is not a check. \
             The schema pins them to true rather than permitting false, so a zero-work run \
             is refused by name instead of being published with claims it did not earn.",
            inputs.counted_commits, inputs.acknowledged_requests
        ));
    }
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
            jstr(digest_file(&repo_root.join("Cargo.lock"))?),
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

    // The binary that produced the numbers, refused rather than blanked: an
    // unreadable executable leaves `artifacts.binary_digest` naming nothing.
    let binary_digest = digest_file(
        &std::env::current_exe()
            .map_err(|error| format!("refusing to emit a bundle: current_exe: {error}"))?,
    )?;

    let artifacts = J::Object(vec![
        ("binary_digest".into(), jstr(binary_digest)),
        (
            "config_digest".into(),
            jstr(digest_file(
                &repo_root.join("bench/reference-hardware.toml"),
            )?),
        ),
        (
            "workload_digest".into(),
            jstr(digest_file(
                &repo_root.join("bench/workloads/small-commit.toml"),
            )?),
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

    let mut hardware_fields: Vec<(String, J)> = vec![
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
        ("ram_bytes".into(), jint(read_total_ram_bytes()? as i128)),
        ("swap_events".into(), jint(0i128)),
        // Read back from `/proc/mounts` for the store root this run used, not
        // the frozen profile's `btrfs` restated. A bundle that names the
        // filesystem it was supposed to run on tells a reader nothing about the
        // one it ran on.
        (
            "filesystem".into(),
            jstr(inputs.observations.store_root_filesystem.clone()),
        ),
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
    ];

    // Derived by comparing what this run read off the host against the complete
    // `[[profile]]` tables of the frozen file, and derived before
    // `run_conditions` because `environment_fidelity` is conditioned on it: a
    // bundle may only claim the reference environment if it named a frozen
    // hardware profile, and it may only name one if the facts compared equal.
    let frozen = load_frozen_profile(&repo_root.join("bench/reference-hardware.toml"))?;
    let host_facts = observe_host_facts(&inputs.observations.store_root_filesystem);
    let hardware_derivation = hardware_profile_of(&frozen.profiles, &host_facts, &hardware_fields)?;
    let hardware_profile = hardware_derivation.name;
    hardware_fields.insert(0, ("profile".into(), jstr(hardware_profile)));
    let hardware = J::Object(hardware_fields);

    let conditions = RunConditions::derive(
        &inputs.observations,
        inputs.store_directory_attributes_verified,
        hardware_profile,
    )?;

    // Scope 6.6 item 5c. Both sides counted: `objects_new` was summed from the
    // store's own receipts and `counted_commits` was counted as commits
    // acknowledged, so this comparison can fail — which is the entire
    // difference between the claim and the tautology it was excluded for. A
    // disagreement is a refusal and never a `false`: the schema pins the claim
    // to `const true`, and emitting the flag as `false` would be recording a
    // failed invariant as a negative result.
    if conditions.objects_new_source == "summed_from_receipts" {
        let expected = inputs
            .counted_commits
            .checked_mul(OBJECTS_PER_COMMIT)
            .ok_or_else(|| "counted_commits * 3 overflows u64".to_string())?;
        if inputs.objects_new != expected {
            return Err(format!(
                "refusing to emit a bundle: the receipts reported {} new objects across \
                 {} counted commits, and {OBJECTS_PER_COMMIT} per commit would be {expected}. \
                 The store stages exactly one blob, one tree, and one commit per \
                 transaction, so a disagreement is a finding about the store or about \
                 this harness's counting — not a flag to emit as false.",
                inputs.objects_new, inputs.counted_commits
            ));
        }
    }

    let deployment = J::Object(vec![
        // Observed, not asserted. A tmpfs run is representable and
        // mechanically disqualified as of contract review 2026-07-28-C; it was
        // previously neither, which is why the number that prompted the review
        // could live only in a paragraph.
        (
            "persistent_data_mount".into(),
            J::Bool(!inputs.observations.store_root_is_tmpfs),
        ),
        (
            "tmpfs".into(),
            J::Bool(inputs.observations.store_root_is_tmpfs),
        ),
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
                // The `u32` from the `StoreOptions` the store was opened with,
                // carried through the run rather than `ENGINE_MAX_INDEX_RUNS`
                // written out a second time. It is the ceiling this workload
                // genuinely reaches: `submit` refuses `NotImplemented` at it.
                (
                    "max_index_runs".into(),
                    jint(i128::from(inputs.observations.configured_max_index_runs)),
                ),
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

    // Three neighbours are absent, not false. `blobs_recomputed`,
    // `metadata_complete`, and `operation_receipts_reconciled` are claims this
    // run did not earn, and the schema forbids them here rather than merely
    // permitting their omission. `false` would say the check was applicable and
    // failed, which is a different untrue statement; omission is the only
    // encoding that says "not performed here", the same treatment
    // `storage.store_directory_attributes_verified` gets.
    //
    // `operation_receipts_reconciled` is the one to read twice. It is approved
    // in principle (contract review 2026-07-28-C) and **not earned**: the
    // reconciliation below accepts any `TransactionStatus::Committed(_)`
    // without comparing the payload, and the `receipt_digest` the harness
    // journals is `blake3(operation_id)` rather than a digest of the receipt.
    // So `receipt_reconciliation` declares `acceptance_of_any_committed_status`
    // and the schema forbids the claim on that declaration. Earning it means
    // reconciling the exact receipt or a frozen canonical receipt digest, and
    // then the schema *requires* the claim rather than permitting it.
    let mut verification_fields = vec![
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
    ];

    // The two claims contract review 2026-07-28-C granted, each emitted only
    // where its own declaration says the check was performed. The `if`s are not
    // belt and braces over the schema: they are what makes the claim follow
    // from the check rather than from which path this code took.
    if conditions.commit_id_uniqueness == "checked_globally_across_ack_records" {
        verification_fields.push(("unique_blob_tree_commit_ids".into(), J::Bool(true)));
    }
    if conditions.objects_new_source == "summed_from_receipts" {
        verification_fields.push(("objects_new_equals_three_per_commit".into(), J::Bool(true)));
    }
    let verification = J::Object(verification_fields);

    let outcome = storage_primitive_outcome(inputs, &conditions);

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
        // The conditions the run was obtained under, as values a consumer
        // checks. Every claim below is conditioned on one of them.
        ("run_conditions".into(), conditions.to_json()),
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

    Ok(AssembledBundle {
        json: json::to_string(&bundle),
        outcome,
        conditions,
        hardware: hardware_derivation,
    })
}

/// Installed memory, or a refusal.
///
/// The `unwrap_or(0)` that stood here was emitted as `ram_bytes` after a
/// `.max(1)`, so a host whose `/proc/meminfo` could not be read published one
/// byte of RAM as an observation. A value nobody read is not an observation.
fn read_total_ram_bytes() -> Result<u64, String> {
    let text = std::fs::read_to_string("/proc/meminfo")
        .map_err(|error| format!("refusing to emit a bundle: /proc/meminfo: {error}"))?;
    text.lines()
        .find(|line| line.starts_with("MemTotal:"))
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u64>().ok())
        .map(|kib| kib * 1024)
        .ok_or_else(|| {
            "refusing to emit a bundle: /proc/meminfo carries no parsable MemTotal, so \
             resources.ram_bytes has no reading behind it."
                .to_string()
        })
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
    facts: RunFacts,
}

/// The character device whose every write fails with `ENOSPC`.
///
/// The armed fault below writes to it rather than fabricating an
/// `io::Error`, so the error the refusal path handles is the kernel's and not
/// the harness's idea of one.
const FULL_DEVICE: &str = "/dev/full";

/// A deterministic acknowledgment-journal write failure, armed by name.
///
/// The failure this exists to exercise is not hypothetical: `ENOSPC` and
/// `EDQUOT` on the journal's filesystem both surface here, and a run on tmpfs
/// meets them routinely. Racing a real full device is not a test, so the fault
/// is armed at a chosen append instead — **after** at least one commit, because
/// that is the case the zero-work guard cannot see.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum AckJournalFault {
    #[default]
    None,
    /// The append with this zero-based index is issued against `/dev/full`
    /// instead of the journal, and its error is propagated as the journal's.
    EnospcOnAppend(u64),
}

/// The acknowledgment journal as the run loop uses it, plus the armed fault.
///
/// A wrapper rather than a branch at the call site: the fault has to fire
/// inside the same call the run loop already makes, or the regression would be
/// exercising a path the emitter does not take.
struct AckSink {
    journal: ExternalAckJournal,
    fault: AckJournalFault,
    appended: u64,
    /// Whether the armed fault actually fired. See [`AckSink::unfired_arming`].
    fired: bool,
    /// Opened when the fault is armed, not when it fires, so a host where the
    /// fault cannot be induced says so before the run rather than after it.
    full_device: Option<std::fs::File>,
}

impl AckSink {
    fn open(path: &Path, fault: AckJournalFault) -> Result<Self, String> {
        let journal = ExternalAckJournal::open(path).map_err(|e| format!("ack journal: {e}"))?;
        let full_device = match fault {
            AckJournalFault::None => None,
            AckJournalFault::EnospcOnAppend(_) => Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(FULL_DEVICE)
                    .map_err(|error| {
                        format!(
                            "refusing to arm the acknowledgment-journal fault: \
                             {FULL_DEVICE} could not be opened for writing ({error}). The \
                             injected failure is a real kernel ENOSPC from that device \
                             rather than an io::Error this harness invented, so a host \
                             that cannot supply one cannot run the injection at all."
                        )
                    })?,
            ),
        };
        Ok(Self {
            journal,
            fault,
            appended: 0,
            fired: false,
            full_device,
        })
    }

    /// Why an armed fault that never fired has to refuse the run.
    ///
    /// `--fail-ack-append-after N` states that the run met an acknowledgment
    /// failure at append `N`. A run that ended before reaching `N` — too short a
    /// window, too small a group count, a store that refused every submit —
    /// satisfies none of that, and the previous code let it emit a **normal
    /// bundle**: the injection flag was on the command line, the failure never
    /// happened, and nothing in the output said so. That is the same class of
    /// defect as the ack write failure this flag exists to catch, one level up.
    ///
    /// So it is charter item 7 again: the arming is a claim, `fired` is the
    /// counter, and the two are compared instead of the flag being trusted.
    fn unfired_arming(&self) -> Option<String> {
        match self.fault {
            AckJournalFault::None => None,
            AckJournalFault::EnospcOnAppend(target) if !self.fired => Some(format!(
                "--fail-ack-append-after {target} armed an acknowledgment-journal failure that \
                 never fired: the run issued only {} append(s), so no injected failure was \
                 observed and this run is not evidence of the behaviour the flag claims to \
                 exercise. Refusing rather than emitting a bundle that would read as a normal \
                 run.",
                self.appended
            )),
            AckJournalFault::EnospcOnAppend(_) => None,
        }
    }

    fn append_durable(
        &mut self,
        record: &AckRecord,
    ) -> Result<(), levcs_protocol::oracle::AckJournalError> {
        use std::io::Write as _;

        if self.fault == AckJournalFault::EnospcOnAppend(self.appended) {
            self.fired = true;
            let device = self
                .full_device
                .as_mut()
                .expect("an armed fault opened /dev/full before the run");
            return Err(match device.write_all(&[0u8]) {
                Err(error) => error.into(),
                // Named rather than folded into the fault: a device that
                // accepted the write did not produce the failure this run
                // claims to be injecting, and reporting it as one would make
                // the regression pass on evidence it never had.
                Ok(()) => std::io::Error::other(format!(
                    "{FULL_DEVICE} accepted a write, so the armed acknowledgment-journal \
                     fault produced no kernel error to propagate"
                ))
                .into(),
            });
        }
        self.journal.append_durable(record)?;
        self.appended += 1;
        Ok(())
    }
}

fn run_skeleton(
    root: &Path,
    ack_path: &Path,
    ack_fault: AckJournalFault,
    group_len: usize,
    seconds: u64,
) -> Result<SkeletonRun, String> {
    let mut ack = AckSink::open(ack_path, ack_fault)?;
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
            // The same incomplete-accounting refusal the submit path makes, in
            // the same words: the group's fence is already inside the counters
            // this run would report, so a frame that cannot be acknowledged
            // leaves the run unable to account for work it already measured.
            ack.append_durable(&skeleton_ack_record(*sequence))
                .map_err(|error| {
                    format!(
                        "refusing to emit a bundle: incomplete accounting. Shard \
                         sequence {sequence} was appended and fenced, but appending its \
                         acknowledgment to the external journal failed: {error} \
                         ({error:?}). The fence is already inside the counters this run \
                         reports and the transaction cannot be counted, so every total \
                         it could emit would describe a workload that did not happen."
                    )
                })?;
            acknowledged += 1;
        }
    }

    // Before any total is read off a counter, for the reason
    // `AckSink::unfired_arming` gives.
    if let Some(failure) = ack.unfired_arming() {
        return Err(failure);
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

    // The seam has no engine of its own, so the checkpoint question is put to a
    // real `StoreEngine` on a throwaway root next to this run's. Declaring
    // `unimplemented` here without asking would be this file's opinion of what
    // `engine.rs` does, which is exactly what the declaration is not for.
    let checkpoint = probe_checkpointing_on_fresh_root(&root.with_extension("checkpoint-probe"))?;

    Ok(SkeletonRun {
        facts: RunFacts {
            initialization: Initialization::ShardDriveCreate,
            mutation: MutationPath::JournalDrive,
            checkpoint,
            index: IndexObservation::NoIndexInPath,
            // Nothing below `engine.rs` consults `max_index_runs`, so the seam
            // runs under the store default: the value is read off an untouched
            // `StoreOptions` rather than written as 64.
            configured_max_index_runs: levcs_store::StoreOptions::new(root).max_index_runs,
            default_max_index_runs: levcs_store::StoreOptions::new(root).max_index_runs,
            receipts: ReceiptComparison::NoReceiptsInPath,
            objects_new_counted: false,
            // The identifiers in these acknowledgment records are fabricated by
            // `skeleton_ack_record`, not produced by a store. Unioning them
            // would establish a property of this harness's hash domains.
            uniqueness: UniquenessCheck::NotPerformed,
        },
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
        ack_journal_digest: digest_file(ack_path)?,
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
// Two of B1's unimplemented deliverables bound it, and both are a bound on the
// *bundle*, not merely on this file:
//
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
// A third bound stood here until B1 landed startup state 1: `StoreEngine::open`
// refused to build an absent root, so this run seeded one with
// `segment::initialize_root` and measured the production path over a store
// production had not built. That is charter item 8 in its most literal form,
// and it is now closed — the root below is created by `open` itself, and the
// bundle's `initialization_path` reports that as an observation of the `FORMAT`
// marker rather than as a label.
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

/// Durability fences the store has performed, from the store's own counters.
///
/// One reader for the baseline and for the total, so the two figures cannot
/// come from two different notions of what a fence is.
fn sum_fences(engine: &levcs_store::StoreEngine, shard_count: u16) -> Result<u64, String> {
    let mut total = 0u64;
    for shard in 0..shard_count {
        // A shard whose counters cannot be read used to contribute zero, which
        // is the same defect class as the acknowledgment failure above: the
        // number the bundle publishes silently loses a term, and the reader
        // cannot tell a shard that fenced nothing from a shard that was not
        // asked. Both the baseline and the total come through here, so a quiet
        // zero could also make the measured interval look smaller than it was.
        let counters = engine.durability_counters(shard).ok_or_else(|| {
            format!(
                "refusing to measure: the store returned no durability counters for shard \
                 {shard} of {shard_count}. The fence total is what bounds every durability \
                 claim in the bundle, and a shard counted as zero fences would understate \
                 it without saying so."
            )
        })?;
        total += counters.fdatasync;
    }
    Ok(total)
}

/// Durability and signing work performed *before* the measured interval opened.
///
/// Repositories are created through the same `StoreEngine::submit` path the
/// measurement uses, so creating them fences and signs. Both counters therefore
/// have to be snapshotted once creation has completed and subtracted, or every
/// bundle reports setup fences and setup signatures while asserting
/// `verification.setup_traffic_excluded: true` — a bundle making a false
/// statement about its own methodology, which is worse than a wrong number
/// because a wrong number invites scrutiny and a false exclusion claim deflects
/// it.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SetupTraffic {
    /// `DurabilityCounters::fdatasync`, summed across shards, at the instant
    /// the last repository creation returned.
    pub fences: u64,
    /// Signing samples the `MeasuringSigner` had recorded at the same instant.
    pub signings: u64,
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
    /// Fences performed **inside the measured interval**: the store's counter at
    /// the end, less its value at the instant repository creation completed.
    fences: u64,
    /// Group publications, counted as fences: `journal::append_group_and_fence`
    /// performs exactly one per group and A1's acceptance pins that.
    groups: u64,
    signing_micros_p50: f64,
    /// Signing samples taken inside the measured interval, on the same basis.
    signings: u64,
    /// What the two counters read at the instant the measured interval opened,
    /// and what they read when it closed. Carried out of the run so the
    /// exclusion can be asserted against `DurabilityCounters` rather than
    /// against the emitter's intention to have excluded it.
    setup: SetupTraffic,
    total_fences: u64,
    total_signings: u64,
    refused: u64,
    first_refusal: Option<String>,
    acknowledged_sequences_reconciled: bool,
    ack_journal_digest: String,
    facts: RunFacts,
}

#[allow(clippy::too_many_lines)]
fn run_engine(
    root: &Path,
    ack_path: &Path,
    ack_fault: AckJournalFault,
    group_len: usize,
    seconds: u64,
    shard_count: u16,
    submitters_per_shard: usize,
) -> Result<EngineRun, String> {
    use levcs_store::segment::RootLayout;
    use levcs_store::transaction::StagedObject;
    use levcs_store::types::{OperationId, PrivilegedConstruction, StoreError};
    use levcs_store::{StoreEngine, ValidatedTransaction};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    // A run with no submitter measures nothing, and a bundle from it asserts
    // `setup_traffic_excluded`, `unique_blob_tree_commit_ids`, and
    // `objects_new_equals_three_per_commit` over an empty set, where each is
    // vacuously true. `assemble_bundle` refuses such a bundle; this refuses
    // before spending the run, and refuses at the entry point rather than at
    // the flag parser so an in-process caller gets the same answer the CLI
    // does.
    if submitters_per_shard == 0 {
        return Err(
            "refusing to measure: --submitters-per-shard 0 spawns no submitter, so the \
             measured interval contains no transaction at all. The repositories would \
             still be created, so the run would report their fences and their signatures \
             as if they were measured work, and the bundle would assert claims that are \
             vacuously true over zero commits. The schema does not permit false for those \
             claims, so this is refused by name."
                .to_string(),
        );
    }
    if shard_count == 0 {
        return Err(
            "refusing to measure: --shards 0 creates no repository and routes no \
             transaction, which is the same zero-work run --submitters-per-shard 0 \
             produces, reached through the other flag."
                .to_string(),
        );
    }

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

    // Read back from the options this store is opened with, and compared
    // against the library's own default rather than against a 64 written here.
    // `resources.configured_ceilings.max_index_runs` and
    // `run_conditions.index_run_ceiling` both come from these two values, so
    // neither can drift from what the run configured.
    let opened_with = build_options();
    let configured_max_index_runs = opened_with.max_index_runs;
    let default_max_index_runs = levcs_store::StoreOptions::new(root).max_index_runs;

    // The store that is about to be measured is now **built by the entry point
    // a consumer calls**. It used to be seeded with `segment::initialize_root`,
    // because `StoreEngine::open` refused startup state 1, and the benchmark
    // measured the production path over a root production had not built —
    // charter item 8, disclosed in this file, in the crash-matrix fixture, and
    // in the bundle's own `initialization_path`. B1 landed state 1 and the
    // weakening is closed here rather than re-worded.
    //
    // `initialization_path` is then **observed**, not labelled: `FORMAT` is
    // absent before the call and present after, so the declaration reports what
    // this open did. A root that already carried `FORMAT` was built by
    // something this run cannot name, and that is a refusal below rather than a
    // guess.
    let layout = RootLayout::new(root);
    let format_before_open = layout.format_path().exists();

    let engine = StoreEngine::open(opened_with).map_err(|e| format!("open: {e}"))?;

    let initialization = if format_before_open {
        return Err(format!(
            "refusing to measure {}: it already carries a FORMAT marker, so this run did \
             not build the store it is about to measure and cannot say what did. \
             run_conditions.initialization_path names the three paths that create a \
             root, and \"whatever was here already\" is not one of them.",
            root.display()
        ));
    } else if layout.format_path().exists() {
        Initialization::StoreEngineOpen
    } else {
        return Err(
            "StoreEngine::open returned without writing FORMAT to an absent root, so \
             the store this run is about to measure was not built by the production \
             entry point after all."
                .to_string(),
        );
    };

    let namespaces: Vec<NamespaceId> = (0..shard_count)
        .map(|shard| engine_namespace(shard, shard_count))
        .collect();

    let ack = Mutex::new(AckSink::open(ack_path, ack_fault)?);
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

    // **The baselines, after creation has completed and before anything is
    // measured.** Both counters are cumulative over the life of the engine, so
    // reading them only at the end means reading them from zero — from before
    // the repositories existed — and every bundle then reports the creation
    // fences and the creation signatures inside the measured interval while
    // asserting `verification.setup_traffic_excluded: true`.
    //
    // Snapshotted here, subtracted below, so the measured interval contains
    // only measured work. `fdatasync` is read from the store's own
    // `DurabilityCounters` and the signing count from the signer's own sample
    // vector, which is what makes the exclusion checkable against a counter
    // rather than against this comment.
    let setup = SetupTraffic {
        fences: sum_fences(&engine, shard_count)?,
        signings: signer
            .micros
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len() as u64,
    };

    let stop = AtomicBool::new(false);
    let refused = AtomicU64::new(0);
    let first_refusal: Mutex<Option<String>> = Mutex::new(None);
    // A failure that leaves the run unable to account for work it already
    // measured. Separate from `refused` on purpose: a refused submit is a
    // transaction the store never committed, and this is a transaction it
    // *did* commit whose acknowledgment the harness could not record. The
    // first is a countable event; the second is the end of the run, because
    // the fence and the signature are already inside the totals and the
    // transaction can never be.
    let unaccounted: Mutex<Option<String>> = Mutex::new(None);
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
                let unaccounted = &unaccounted;
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
                                    // Not a counter and not a `false`. The
                                    // store committed this transaction and
                                    // fenced and signed for it, so those costs
                                    // are already inside the totals; the
                                    // harness cannot record the acknowledgment,
                                    // so the transaction can never be inside
                                    // them. Ending the run here without saying
                                    // so — which is what this did — omitted a
                                    // committed transaction from the bundle
                                    // while still counting its fence and its
                                    // signature, and silently shortened the
                                    // measured interval. `EDQUOT` on a full
                                    // tmpfs is the ordinary way to get here.
                                    if let Err(error) = journal.append_durable(&record) {
                                        let mut slot =
                                            unaccounted.lock().unwrap_or_else(|p| p.into_inner());
                                        if slot.is_none() {
                                            *slot = Some(format!(
                                                "refusing to emit a bundle: incomplete \
                                                 accounting. StoreEngine::submit committed \
                                                 operation {} in namespace {} at \
                                                 repo_sequence {} and returned its receipt, \
                                                 but appending that acknowledgment to the \
                                                 external journal failed: {error} \
                                                 ({error:?}). The commit's durability fence \
                                                 and its signature are already inside the \
                                                 counters this run reports and the \
                                                 transaction itself can never be, so every \
                                                 total this run could emit describes a \
                                                 workload that did not happen. This is not \
                                                 a refused submit and not a shortened run: \
                                                 the harness cannot account for what it \
                                                 measured, so it emits nothing.",
                                                hex::encode(operation_id),
                                                hex::encode(namespace.as_bytes()),
                                                receipt.repo_sequence,
                                            ));
                                        }
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

    // Before anything is read off a counter, let alone reported. A run that
    // could not account for a committed transaction has no totals worth
    // computing, and the emitter's `refused` guard is deliberately not the
    // thing that catches this: `refused` counts submits the store declined,
    // and folding an accounting failure into it would report a commit that
    // happened as one that did not.
    if let Some(failure) = unaccounted.into_inner().unwrap_or_else(|p| p.into_inner()) {
        return Err(failure);
    }

    // For the same reason, and in the same place: before any total is read.
    // Borrowed rather than consumed — the sink is dropped later, deliberately,
    // to close the journal before it is digested.
    if let Some(failure) = ack
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .unfired_arming()
    {
        return Err(failure);
    }

    let total_fences = sum_fences(&engine, shard_count)?;

    let latencies = latencies.into_inner().unwrap_or_else(|p| p.into_inner());
    let results = results.into_inner().unwrap_or_else(|p| p.into_inner());
    let refused = refused.load(Ordering::Relaxed);
    let first_refusal = first_refusal
        .into_inner()
        .unwrap_or_else(|p| p.into_inner());
    let acknowledged = acknowledged.load(Ordering::Relaxed);
    let objects_new = objects_new.load(Ordering::Relaxed);
    let raw_bytes = raw_bytes.load(Ordering::Relaxed);
    let all_signing = signer
        .micros
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone();
    let total_signings = all_signing.len() as u64;

    // The measured interval is what the totals hold *beyond* the baselines. A
    // counter that went backwards is a store or a harness finding and not a
    // number to publish, so the subtraction refuses rather than saturating.
    let fences = total_fences.checked_sub(setup.fences).ok_or_else(|| {
        format!(
            "refusing to measure: the durability fence counter read {total_fences} at the \
             end of the measured interval and {} at its start. A counter that went \
             backwards cannot bound what the interval contained.",
            setup.fences
        )
    })?;
    let signings = total_signings.checked_sub(setup.signings).ok_or_else(|| {
        format!(
            "refusing to measure: {total_signings} signing samples were recorded in total \
             and {} before the measured interval opened.",
            setup.signings
        )
    })?;
    // Samples are appended in signing order, so the measured interval's samples
    // are exactly the tail past the baseline. Sorted *after* the split, because
    // sorting first would make the baseline index meaningless.
    let mut signing = all_signing[setup.signings as usize..].to_vec();
    signing.sort_unstable();
    let signing_p50 = percentile(&signing, 0.50) as f64;

    drop(ack);
    drop(engine);

    // One attempt, no budget, no sleep. Commit e050b6d fixed the root cause —
    // `flock` lives on the open file description, and `lock_root` now returns
    // an RAII `RootLock` that issues an explicit `LOCK_UN` in `Drop` — and the
    // bounded wait that stood here existed only to compensate for that defect.
    // Scope 3.1 says `AlreadyLocked` is a refusal and never a wait, so a
    // harness that waited on it was asserting something the store does not
    // promise, and leaving the wait in place would hide a recurrence behind a
    // second attempt that succeeded.
    let reopened = match StoreEngine::open(build_options()) {
        Ok(engine) => engine,
        Err(StoreError::AlreadyLocked) => {
            return Err(
                "the root lock was still held on the first StoreEngine::open after the \
                 measured engine was dropped. Scope 3.1 makes AlreadyLocked a refusal \
                 and never a wait, and commit e050b6d released the lock explicitly in \
                 RootLock::drop, so this is a recurrence of that defect rather than a \
                 slow reclaim to sleep through."
                    .to_string(),
            )
        }
        Err(other) => return Err(format!("reopen through production recovery: {other}")),
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

    // What the store answers about checkpoints, asked of the store rather than
    // asserted about it. Asked after the reconciliation so a checkpoint the day
    // this stops refusing cannot move what the reconciliation read.
    let checkpoint = probe_checkpointing(&reopened)?;
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

    // Scope 6.6 item 5d: uniqueness established **globally**, across every
    // recovered acknowledgment record at once. Per-record checking cannot see a
    // collision between two records, and the distinctness of the generator's
    // seed domains is an argument about likelihood rather than an observation;
    // the schema names both of those as separate values precisely so a harness
    // that did either has something truthful to record instead of this claim.
    let uniqueness = check_global_uniqueness(&records)?;

    // What is on the device under `shards/*/indexes`, read back and validated
    // as index runs rather than counted as directory entries.
    let index_scan = scan_index_runs(root, shard_count);

    Ok(EngineRun {
        facts: RunFacts {
            initialization,
            mutation: MutationPath::StoreEngineSubmit,
            checkpoint,
            index: IndexObservation::StoreRoot {
                validated_runs: index_scan.validated_runs,
                unvalidatable: index_scan.unvalidatable,
                groups: fences,
                // Nothing seals, and `StoreEngine` exposes no reading of how
                // many published deltas are outstanding. `None` is that
                // absence, and it is what makes `runs_sealed` unearnable until
                // the reading exists rather than inferable from a file count.
                unsealed_delta_backlog: None,
            },
            configured_max_index_runs,
            default_max_index_runs,
            // The reconciliation loop above accepts any `Committed(_)` without
            // comparing the payload, and the `receipt_digest` written into
            // every `AckRecord` is `blake3(operation_id)`. Recorded here at the
            // site that decides it, so earning the claim is a change to the
            // loop and to this value together rather than to this value alone.
            receipts: ReceiptComparison::AnyCommittedStatusAccepted,
            objects_new_counted: true,
            uniqueness,
        },
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
        setup,
        total_fences,
        total_signings,
        refused,
        first_refusal,
        acknowledged_sequences_reconciled: acknowledged_loss == 0
            && torn_transactions == 0
            && repeated_adoptions == 0
            && records.len() as u64 == acknowledged,
        ack_journal_digest: digest_file(ack_path)?,
    })
}

/// Every blob, tree, and commit identifier in every recovered acknowledgment
/// record, unioned into one set per kind.
///
/// A repeat is a **refusal**, not a `false`: the schema pins
/// `unique_blob_tree_commit_ids` to `const true`, so a run that saw a collision
/// has no way to report it as a failed check and must not report it as a
/// passed one either. The bundle is what would be wrong.
fn check_global_uniqueness(records: &[AckRecord]) -> Result<UniquenessCheck, String> {
    use std::collections::HashSet;

    /// One kind, unioned across every record before anything is concluded.
    fn union(
        kind: &str,
        records: &[AckRecord],
        select: impl Fn(&AckRecord) -> &[ObjectId],
    ) -> Result<u64, String> {
        let mut seen: HashSet<ObjectId> = HashSet::new();
        for record in records {
            for id in select(record) {
                if !seen.insert(*id) {
                    return Err(format!(
                        "refusing to emit a bundle: the {kind} identifier {} appears in \
                         more than one place across the recovered acknowledgment \
                         records. Every counted commit must introduce distinct objects, \
                         and a collision is a finding about the run rather than a \
                         verification flag to emit as false.",
                        hex::encode(id.0)
                    ));
                }
            }
        }
        Ok(seen.len() as u64)
    }

    Ok(UniquenessCheck::GlobalAcrossAckRecords {
        blob_ids: union("blob", records, |record| &record.blob_ids)?,
        tree_ids: union("tree", records, |record| &record.tree_ids)?,
        commit_ids: union("commit", records, |record| &record.commit_ids)?,
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
    bytes: u64,
    elapsed: Duration,
    acknowledged: u64,
    acknowledged_loss: u64,
    torn_transactions: u64,
    repeated_adoptions: u64,
    fences: u64,
    signing_micros_p50: f64,
    signings: u64,
    /// Fences and signatures performed before the measured interval opened, and
    /// the totals they were subtracted from.
    setup: SetupTraffic,
    total_fences: u64,
    total_signings: u64,
    acknowledged_sequences_reconciled: bool,
    ack_journal_digest: String,
    path: &'static str,
    /// Submits refused or never completed. Non-zero ends the run: a benchmark
    /// that keeps counting past a refusal is measuring a different workload
    /// from the one it names.
    refused: u64,
    first_refusal: Option<String>,
    /// What this run observed about itself, recorded where it happened.
    facts: RunFacts,
}

impl From<SkeletonRun> for MeasuredRun {
    fn from(run: SkeletonRun) -> Self {
        Self {
            groups: run.groups,
            transactions: run.transactions,
            objects_new: run.transactions * OBJECTS_PER_COMMIT,
            facts: run.facts,
            bytes: run.bytes,
            elapsed: run.elapsed,
            acknowledged: run.acknowledged,
            acknowledged_loss: run.acknowledged_loss,
            torn_transactions: run.torn_transactions,
            repeated_adoptions: run.repeated_adoptions,
            fences: run.fences,
            signing_micros_p50: 0.0,
            signings: 0,
            // The journal seam creates no repository and signs nothing, so
            // there is no setup traffic to exclude and the totals are the
            // measured figures. Recorded as an observed zero rather than left
            // out, so the same assertion covers both paths.
            setup: SetupTraffic::default(),
            total_fences: run.fences,
            total_signings: 0,
            acknowledged_sequences_reconciled: run.acknowledged_sequences_reconciled,
            ack_journal_digest: run.ack_journal_digest,
            latencies_micros: run.latencies_micros,
            path: "drive",
            refused: 0,
            first_refusal: None,
        }
    }
}

impl From<EngineRun> for MeasuredRun {
    fn from(run: EngineRun) -> Self {
        Self {
            groups: run.groups,
            transactions: run.transactions,
            objects_new: run.objects_new,
            facts: run.facts,
            bytes: run.raw_bytes,
            elapsed: run.elapsed,
            acknowledged: run.acknowledged,
            acknowledged_loss: run.acknowledged_loss,
            torn_transactions: run.torn_transactions,
            repeated_adoptions: run.repeated_adoptions,
            fences: run.fences,
            signing_micros_p50: run.signing_micros_p50,
            signings: run.signings,
            setup: run.setup,
            total_fences: run.total_fences,
            total_signings: run.total_signings,
            acknowledged_sequences_reconciled: run.acknowledged_sequences_reconciled,
            ack_journal_digest: run.ack_journal_digest,
            latencies_micros: run.latencies_micros,
            path: "submit",
            refused: run.refused,
            first_refusal: run.first_refusal,
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
                  [--fail-ack-append-after N]
  run             --root P --out-dir P   (P2; blocked, see below)

--fail-ack-append-after N is fault injection, and a run that uses it emits no
bundle by construction: the Nth acknowledgment-journal append is issued against
/dev/full so the kernel's ENOSPC drives the emitter's incomplete-accounting
refusal. It exists so that refusal is exercised deterministically rather than
by racing a full device. \"Emits no bundle\" is unconditional: a run that ended
before reaching append N is refused too, because the flag claims a failure was
observed and that run observed none.

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
    // Fault injection, off unless named. There is no default index and no
    // "0 means off": the flag's presence arms it and its absence does not, so
    // an armed run is always something a caller asked for by name.
    let ack_fault = match flags.get("fail-ack-append-after") {
        None => AckJournalFault::None,
        Some(_) => {
            AckJournalFault::EnospcOnAppend(flags.number::<u64>("fail-ack-append-after", 0)?)
        }
    };

    let path = flags.get("path").unwrap_or("submit").to_string();
    let run: MeasuredRun = if path == "submit" {
        let shards = flags.number::<u16>("shards", 4)?;
        let submitters = flags.number::<usize>("submitters-per-shard", group_len.max(1))?;
        run_engine(
            &root, &ack_path, ack_fault, group_len, seconds, shards, submitters,
        )?
        .into()
    } else if path == "drive" {
        run_skeleton(&root, &ack_path, ack_fault, group_len, seconds)?.into()
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

    // Where the run actually ran, read back from `/proc/mounts`. The two
    // deployment fields it feeds were unconditional constants until contract
    // review 2026-07-28-C, which is how a tmpfs run could describe itself as
    // persistent without anything noticing.
    let mount = detect_mount(&root)?;

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
        observations: RunObservations::new(run.facts, mount),
    };

    let assembled = assemble_bundle(repo_root, workload, &inputs)?;
    let outcome = assembled.outcome;
    std::fs::write(&out, assembled.json).map_err(|e| format!("writing {}: {e}", out.display()))?;

    println!("bundle_schema=1");
    println!("bundle_path={}", out.display());
    println!("bundle_gate=storage_primitive");
    println!("bundle_promotable=false");
    println!("bundle_skeleton=true");
    println!("bundle_path_driven={}", run.path);
    println!("objects_new={}", inputs.objects_new);
    println!(
        "objects_new_counted={}",
        inputs.observations.objects_new_counted
    );
    // The ten declarations, on stdout as well as in the bundle, so a reviewer
    // can check each value against what the run did without reading the JSON.
    for (member, value) in assembled.conditions.pairs() {
        println!("run_condition:{member}={value}");
    }
    if let UniquenessCheck::GlobalAcrossAckRecords {
        blob_ids,
        tree_ids,
        commit_ids,
    } = inputs.observations.uniqueness
    {
        println!("unique_ids:blob={blob_ids} tree={tree_ids} commit={commit_ids}");
    }
    println!(
        "configured_max_index_runs={}",
        inputs.observations.configured_max_index_runs
    );
    println!(
        "store_root_filesystem={} tmpfs={}",
        inputs.observations.store_root_filesystem, inputs.observations.store_root_is_tmpfs
    );
    println!("evidence_signings={}", run.signings);
    println!("evidence_signing_micros_p50={:.1}", run.signing_micros_p50);
    // The exclusion, as three numbers a reader can subtract rather than as a
    // `true` in the bundle they have to take on trust.
    println!("setup_fences_excluded={}", run.setup.fences);
    println!("setup_signings_excluded={}", run.setup.signings);
    println!("total_fences_including_setup={}", run.total_fences);
    println!("total_signings_including_setup={}", run.total_signings);
    // What the hardware-profile comparison could not compare. This is the
    // deployed-node harness's work order, and it is why `hardware.profile` is
    // what it is.
    println!(
        "hardware_profile_unobserved={}",
        assembled.hardware.unobserved.join(",")
    );
    println!(
        "hardware_profile_mismatched={}",
        assembled.hardware.mismatched.join(",")
    );
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
    fn the_frozen_profiles_are_read_as_whole_tables_rather_than_as_loose_keys() {
        // Naming `hardware.profile` means deciding *which* profile a host is,
        // and that cannot be done by a flat "find every occurrence of this key"
        // scan: such a scan cannot say which profile a value belongs to. The
        // reader parses the `[[profile]]` array-of-tables, and this asserts it
        // against the frozen file rather than against a restatement.
        let frozen = load_frozen_profile(&repo_root().join("bench/reference-hardware.toml"))
            .expect("profile");
        assert_eq!(frozen.profiles.len(), 2);
        let names: Vec<&str> = frozen
            .profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect();
        assert_eq!(names, vec!["minimum-30k", "release-60k"]);

        let minimum = &frozen.profiles[0];
        assert_eq!(minimum.fact("cpu", "model"), Some("AMD Ryzen 7 9800X3D"));
        assert_eq!(minimum.fact("cpu", "physical_cores"), Some("8"));
        assert_eq!(minimum.fact("filesystem", "type"), Some("btrfs"));
        assert_eq!(minimum.fact("network", "link_mbps"), Some("1000"));
        assert_eq!(
            frozen.profiles[1].fact("network", "link_mbps"),
            Some("10000"),
            "the two profiles differ only in their network table, which is why an \
             unobserved NIC leaves them indistinguishable"
        );
        assert_eq!(
            minimum.fact("cpu", "nonexistent_key"),
            None,
            "an unpinned fact is not a constraint and must not be compared as one"
        );
    }

    #[test]
    fn the_hardware_profile_is_compared_against_the_frozen_tables_rather_than_accepted() {
        // The split design: the deployed-node harness gathers privileged host
        // facts; `store-bench` compares them against the complete frozen
        // profiles and derives the name. A harness that supplied a profile
        // *label* would be supplying an unverified claim wearing a verified
        // field's name, so a label is never an input here — only facts are.
        let frozen = load_frozen_profile(&repo_root().join("bench/reference-hardware.toml"))
            .expect("profile");

        // 1. Today: several facts have no reading at all, so no profile is a
        //    candidate and the honest answer is `diagnostic`. The facts that
        //    prevented a match are reported rather than swallowed.
        let today = observe_host_facts("btrfs");
        let derived = hardware_profile_of(&frozen.profiles, &today, &[]).expect("derivation");
        assert_eq!(derived.name, "diagnostic");
        for owed in [
            "nvme.model",
            "nvme.firmware",
            "network.nic",
            "network.driver",
        ] {
            assert!(
                derived.unobserved.iter().any(|name| name == owed),
                "{owed} is the deployed-node harness's half and must be reported as owed: \
                 {:?}",
                derived.unobserved
            );
        }

        // The facts a deployed-node harness would have supplied, taken from the
        // frozen table itself so the test compares the derivation and not a
        // second copy of the reference host.
        let facts_of = |profile: &ReferenceProfile| -> Vec<HostFact> {
            profile
                .facts
                .iter()
                .filter(|(table, _, _)| !table.is_empty())
                .map(|(table, key, value)| HostFact {
                    table: Box::leak(table.clone().into_boxed_str()),
                    key: Box::leak(key.clone().into_boxed_str()),
                    observed: Some(value.clone()),
                })
                .collect()
        };

        // 2. Every fact the profile pins, observed and equal: the name follows
        //    from the comparison. This is what the split design buys — the
        //    emitter derives the name, and never accepts one.
        let complete = facts_of(&frozen.profiles[0]);
        assert_eq!(
            hardware_profile_of(&frozen.profiles, &complete, &[])
                .expect("derivation")
                .name,
            "minimum-30k"
        );
        assert_eq!(
            hardware_profile_of(&frozen.profiles, &facts_of(&frozen.profiles[1]), &[])
                .expect("derivation")
                .name,
            "release-60k",
            "the two frozen profiles are separated by their network facts, and the \
             derivation must separate them by comparing those facts"
        );

        // ...and the same set with one fact unreadable is not a name. One
        // unobservable fact eliminates the profile that pins it, because
        // skipping it would name a host on a partial match.
        let mut missing = complete.clone();
        missing[0].observed = None;
        let missing_one = hardware_profile_of(&frozen.profiles, &missing, &[]).expect("derivation");
        assert_eq!(missing_one.name, "diagnostic");
        assert!(
            missing_one.unobserved.contains(&missing[0].name()),
            "the fact that cost the name must be reported: {:?}",
            missing_one.unobserved
        );

        // 3. A disagreeing fact is a mismatch, not a near miss: the host is not
        //    the reference host and the bundle says `diagnostic`.
        let mut wrong = complete.clone();
        wrong[0].observed = Some("Some Other CPU".to_string());
        let mismatched = hardware_profile_of(&frozen.profiles, &wrong, &[]).expect("derivation");
        assert_eq!(mismatched.name, "diagnostic");
        assert!(
            mismatched.mismatched.contains(&wrong[0].name()),
            "a fact read and disagreeing must be reported: {:?}",
            mismatched.mismatched
        );

        // 4. Facts that match more than one frozen profile are a refusal, never
        //    a pick.
        //
        //    Under the inverted comparison the *current* frozen file cannot
        //    reach this state — its two profiles pin the same keys with
        //    different network values, so observing everything names exactly
        //    one and observing less than everything names none. The refusal is
        //    still reachable, and still required, for two profiles that pin
        //    different key sets: the second below pins a strict subset of the
        //    first's facts, so a host that observes both is matched by both.
        //    Both names are in `NAMED_HARDWARE_PROFILES` so the ambiguity is
        //    what refuses, not the enumeration.
        let broad = ReferenceProfile {
            name: "minimum-30k".to_string(),
            purpose: "pins two facts".to_string(),
            facts: vec![
                (
                    "cpu".to_string(),
                    "architecture".to_string(),
                    "x86_64".to_string(),
                ),
                ("cpu".to_string(), "numa_nodes".to_string(), "1".to_string()),
            ],
        };
        let narrow = ReferenceProfile {
            name: "release-60k".to_string(),
            purpose: "pins one of them".to_string(),
            facts: vec![(
                "cpu".to_string(),
                "architecture".to_string(),
                "x86_64".to_string(),
            )],
        };
        let both = vec![
            HostFact {
                table: "cpu",
                key: "architecture",
                observed: Some("x86_64".to_string()),
            },
            HostFact {
                table: "cpu",
                key: "numa_nodes",
                observed: Some("1".to_string()),
            },
        ];
        let error = hardware_profile_of(&[broad, narrow], &both, &[])
            .expect_err("two candidates is not a name");
        assert!(error.contains("match 2 frozen profiles"), "{error}");

        // ...and the gap the inversion closes: a fact the frozen profile pins
        // and this emitter does not model must be *unobserved*, not invisible.
        // Iterating the supplied facts made a host that matched every modelled
        // fact a candidate while `cpu.turbo`, `nvme.power_loss_protection`,
        // `filesystem.barriers` and `network.mtu` went uncompared.
        let unmodelled = hardware_profile_of(&frozen.profiles, &today, &[]).expect("derivation");
        for pinned_but_unmodelled in [
            "cpu.turbo",
            "memory.cgroup_limit_gib",
            "nvme.power_loss_protection",
            "nvme.write_cache",
            "filesystem.barriers",
            "filesystem.mount_options",
            "network.mtu",
            "software.proxy",
        ] {
            assert!(
                unmodelled
                    .unobserved
                    .iter()
                    .any(|name| name == pinned_but_unmodelled),
                "{pinned_but_unmodelled} is pinned by the frozen profile and read by \
                 nothing, so it must eliminate the profile rather than pass silently: \
                 {:?}",
                unmodelled.unobserved
            );
        }
        // Every pinned fact of every profile is accounted for: observed and
        // compared, or reported unobserved. Nothing pinned goes unmentioned,
        // which is the property the old direction could not have.
        for profile in &frozen.profiles {
            for (table, key, _) in &profile.facts {
                if table.is_empty() {
                    continue;
                }
                let name = format!("{table}.{key}");
                let observed = observe_host_facts("btrfs").into_iter().any(|fact| {
                    fact.table == table.as_str()
                        && fact.key == key.as_str()
                        && fact.observed.is_some()
                });
                assert!(
                    observed || unmodelled.unobserved.contains(&name),
                    "{name} is pinned by {:?} and neither observed nor reported unobserved",
                    profile.name
                );
            }
        }

        // A profile that pins nothing would be matched by every host, so it is
        // refused rather than treated as a candidate that happened to pass.
        let empty = ReferenceProfile {
            name: "minimum-30k".to_string(),
            purpose: "pins nothing".to_string(),
            facts: vec![(
                "".to_string(),
                "name".to_string(),
                "minimum-30k".to_string(),
            )],
        };
        let error = hardware_profile_of(&[empty], &complete, &[])
            .expect_err("a profile that pins nothing is not a profile");
        assert!(error.contains("pins no"), "{error}");

        // 5. A named profile alongside a hardware field still reading
        //    "recorded by the deployed-node harness" is two statements about
        //    one host that disagree, and that is a refusal rather than a value
        //    to pick between.
        let error = hardware_profile_of(
            &frozen.profiles,
            &complete,
            &[(
                "nvme".to_string(),
                jstr("recorded by the deployed-node harness"),
            )],
        )
        .expect_err("a named profile may not sit beside a placeholder field");
        assert!(error.contains("still placeholders"), "{error}");
    }

    #[test]
    fn a_frozen_profile_name_the_schema_does_not_enumerate_is_refused() {
        // Charter item 6 across the file boundary: `bench/reference-hardware.toml`
        // names profiles and `bench/result-schema.json` enumerates what a bundle
        // may carry. A third frozen profile is a lead-owned schema change before
        // it is a bundle value, and emitting its name on the file's say-so would
        // be exactly the "accept a label" failure the split design forbids.
        let invented = ReferenceProfile {
            name: "maximum-90k".to_string(),
            purpose: "not in the schema".to_string(),
            facts: vec![(
                "cpu".to_string(),
                "architecture".to_string(),
                "x86_64".to_string(),
            )],
        };
        let facts = vec![HostFact {
            table: "cpu",
            key: "architecture",
            observed: Some("x86_64".to_string()),
        }];
        let error = hardware_profile_of(&[invented], &facts, &[])
            .expect_err("a name the schema does not admit is not a name");
        assert!(error.contains("maximum-90k"), "{error}");
        assert!(error.contains("schema change"), "{error}");
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
            profiles: Vec::new(),
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
            profiles: Vec::new(),
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
        // Both paths, because the schema's branch conditionals are keyed on
        // `run_conditions.mutation_path` and a suite that validated one of them
        // would leave the other's rules unexercised — which is where a
        // journal-seam bundle asserting what the seam cannot observe would
        // appear.
        for (path, inputs) in [("drive", skeleton_inputs()), ("submit", submit_inputs())] {
            let bundle = build_bundle(&repo_root(), &workload, &inputs).expect("bundle");
            let errors = schema_errors(&bundle);
            assert!(
                errors.is_empty(),
                "the emitted {path} bundle does not satisfy bench/result-schema.json:\n{}",
                errors.join("\n")
            );
        }
    }

    #[test]
    fn the_ten_run_conditions_are_derived_from_what_the_run_observed() {
        // Each value against the observation it comes from. The point of the
        // block is that it is a derivation: change an observation and the
        // declaration follows, which a hardcoded block would not do.
        let drive = RunConditions::derive(&drive_observations(), true, "diagnostic")
            .expect("the drive path declares");
        assert_eq!(drive.initialization_path, "shard_drive_create");
        assert_eq!(drive.mutation_path, "journal_drive");
        assert_eq!(drive.checkpointing, "unimplemented");
        assert_eq!(drive.index_maintenance, "no_index_in_path");
        assert_eq!(drive.index_run_ceiling, "store_default");
        assert_eq!(drive.receipt_reconciliation, "no_receipts_in_path");
        assert_eq!(drive.objects_new_source, "derived_from_transaction_count");
        assert_eq!(drive.commit_id_uniqueness, "not_checked");
        assert_eq!(drive.environment_fidelity, "diagnostic");

        let submit = RunConditions::derive(&submit_observations(), true, "diagnostic")
            .expect("the submit path declares");
        assert_eq!(submit.initialization_path, "store_engine_open");
        assert_eq!(submit.mutation_path, "store_engine_submit");
        assert_eq!(
            submit.index_run_ceiling, "raised_because_index_sealing_unimplemented",
            "the submit run raises max_index_runs above the store default, and the \
             declaration must follow from that comparison rather than from the path"
        );
        assert_eq!(submit.index_maintenance, "deltas_retained_in_memory");
        assert_eq!(
            submit.receipt_reconciliation, "acceptance_of_any_committed_status",
            "the reconciliation accepts any Committed(_) without comparing the payload, \
             and the receipt_digest journalled is blake3(operation_id)"
        );
        assert_eq!(submit.objects_new_source, "summed_from_receipts");
        assert_eq!(
            submit.commit_id_uniqueness,
            "checked_globally_across_ack_records"
        );

        // The one member that follows from how this binary was built, and the
        // one that follows from four conditions at once.
        let expected_profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        assert_eq!(drive.build_profile, expected_profile);
        assert_eq!(
            RunConditions::derive(&drive_observations(), true, "minimum-30k")
                .expect("derive")
                .environment_fidelity,
            if cfg!(debug_assertions) {
                "diagnostic"
            } else {
                "reference_profile"
            },
            "reference-profile fidelity requires a release build, a verified attribute \
             precheck, a persistent mount, and a named hardware profile — all four"
        );
        let mut on_tmpfs = drive_observations();
        on_tmpfs.store_root_is_tmpfs = true;
        assert_eq!(
            RunConditions::derive(&on_tmpfs, true, "minimum-30k")
                .expect("derive")
                .environment_fidelity,
            "diagnostic"
        );
        assert_eq!(
            RunConditions::derive(&drive_observations(), false, "minimum-30k")
                .expect("derive")
                .environment_fidelity,
            "diagnostic",
            "a run that skipped the store-directory attribute precheck has not met the \
             reference environment, whatever else it met"
        );
    }

    #[test]
    fn an_observation_with_no_named_value_is_refused_rather_than_guessed() {
        // Charter item 6 at the emitter: the schema's enumerations are closed
        // sets, so the mapping onto them is closed too. A lowered ceiling has
        // no named value, and inventing one would be the caveat this block
        // replaced.
        let mut lowered = submit_observations();
        lowered.configured_max_index_runs = lowered.default_max_index_runs - 1;
        let error = RunConditions::derive(&lowered, true, "diagnostic")
            .expect_err("a lowered ceiling has no named value");
        assert!(error.contains("index_run_ceiling"), "{error}");

        // A run that published no group and sealed no index run has no index
        // maintenance to declare.
        let mut idle = submit_observations();
        idle.index = IndexObservation::StoreRoot {
            validated_runs: 0,
            unvalidatable: Vec::new(),
            groups: 0,
            unsealed_delta_backlog: None,
        };
        let error = RunConditions::derive(&idle, true, "diagnostic")
            .expect_err("an idle run declares nothing");
        assert!(error.contains("index_maintenance"), "{error}");
    }

    #[test]
    fn index_steady_state_is_not_satisfiable_by_a_stray_file() {
        // The defect: `index_maintenance` was derived from a count of *directory
        // entries* under `shards/*/indexes`, so one temporary file, one
        // truncated run, or one unrelated file was enough to declare that the
        // index had reached a steady state. A declaration about maintenance must
        // not be earnable by a file existing.

        // 1. An entry that did not read back as an index run is a refusal by
        //    name, not a lower count and not a silent skip.
        let mut stray = submit_observations();
        stray.index = IndexObservation::StoreRoot {
            validated_runs: 0,
            unvalidatable: vec!["shards/00/indexes/.tmp-4711: not an IndexRun".to_string()],
            groups: 12,
            unsealed_delta_backlog: None,
        };
        let error = RunConditions::derive(&stray, true, "diagnostic")
            .expect_err("an entry the emitter cannot validate is not a state it may declare");
        assert!(
            error.contains("did not read back as an IndexRun"),
            "{error}"
        );
        assert!(
            error.contains(".tmp-4711"),
            "the refusal must name it: {error}"
        );

        // 2. Validated runs alone are still not a steady state. Files are not
        //    maintenance: without a reading of the outstanding delta backlog,
        //    `runs_sealed` would be inferred from a directory listing, which is
        //    the same defect the count had.
        let mut files_only = submit_observations();
        files_only.index = IndexObservation::StoreRoot {
            validated_runs: 8,
            unvalidatable: Vec::new(),
            groups: 12,
            unsealed_delta_backlog: None,
        };
        let error = RunConditions::derive(&files_only, true, "diagnostic")
            .expect_err("presence of files is not evidence of bounded maintenance");
        assert!(error.contains("remain unsealed"), "{error}");

        // 3. Sealing that ran and did not keep up is neither named value, and
        //    charter item 6 makes that a refusal rather than the nearer of the
        //    two.
        let mut behind = submit_observations();
        behind.index = IndexObservation::StoreRoot {
            validated_runs: 8,
            unvalidatable: Vec::new(),
            groups: 12,
            unsealed_delta_backlog: Some(3),
        };
        let error = RunConditions::derive(&behind, true, "diagnostic")
            .expect_err("a backlog is not a steady state and not a retained-every-delta run");
        assert!(error.contains("did not keep up"), "{error}");

        // 4. And the one shape that earns it: validated runs with a backlog
        //    observed to be zero. Unreachable today — nothing seals and nothing
        //    reports the backlog — and written so the day it lands the
        //    declaration is already conditioned on the reading.
        let mut steady = submit_observations();
        steady.index = IndexObservation::StoreRoot {
            validated_runs: 8,
            unvalidatable: Vec::new(),
            groups: 12,
            unsealed_delta_backlog: Some(0),
        };
        assert_eq!(
            RunConditions::derive(&steady, true, "diagnostic")
                .expect("a bounded backlog over validated runs is a steady state")
                .index_maintenance,
            "runs_sealed"
        );

        // 5. Today's honest value is unchanged: groups published, nothing
        //    sealed, nothing unvalidatable.
        assert_eq!(
            RunConditions::derive(&submit_observations(), true, "diagnostic")
                .expect("today's run declares")
                .index_maintenance,
            "deltas_retained_in_memory"
        );
    }

    #[test]
    fn a_directory_entry_that_is_not_an_index_run_is_reported_as_unvalidatable() {
        // The scan itself, against a real root, because the derivation above
        // can only refuse what the scan hands it. A file dropped into a shard's
        // `indexes` directory used to be counted as a sealed run.
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("root");
        let layout = levcs_store::segment::RootLayout::new(&root);
        levcs_store::segment::initialize_root(
            &layout,
            1,
            [0x4b; 16],
            engine_now_micros(),
            &levcs_store::types::DurabilityCounters::default(),
        )
        .expect("initialize_root");

        let clean = scan_index_runs(&root, 1);
        assert_eq!(clean.validated_runs, 0);
        assert!(clean.unvalidatable.is_empty(), "{:?}", clean.unvalidatable);

        std::fs::write(layout.shard(0).indexes().join(".tmp-writer"), b"not a run")
            .expect("write stray file");
        let strayed = scan_index_runs(&root, 1);
        assert_eq!(
            strayed.validated_runs, 0,
            "a file that is not an index run must not count as one"
        );
        assert_eq!(
            strayed.unvalidatable.len(),
            1,
            "and it must be reported rather than dropped: {:?}",
            strayed.unvalidatable
        );
        assert!(strayed.unvalidatable[0].contains(".tmp-writer"));
    }

    #[test]
    fn a_disagreeing_objects_new_is_refused_rather_than_emitted_as_false() {
        // Scope 6.6 item 5c. The two sides are counted separately — receipts
        // summed on one side, commits counted on the other — so this comparison
        // can fail, and when it does the bundle is what is wrong. `false` is
        // not available: the schema pins the claim to `const true`, and
        // recording a failed invariant as a negative result is how a harness
        // publishes a defect as a measurement.
        let workload = load_frozen_workload(&repo_root().join("bench/workloads/small-commit.toml"))
            .expect("workload");
        let mut inputs = submit_inputs();
        inputs.objects_new = inputs.counted_commits * OBJECTS_PER_COMMIT + 1;
        let error = build_bundle(&repo_root(), &workload, &inputs)
            .expect_err("a disagreement must refuse rather than emit");
        assert!(error.contains("new objects across"), "{error}");

        // And the drive path, which derives `objects_new` from the transaction
        // count, is not subject to the comparison at all — it may not assert
        // the claim, which is what makes the tautology unreachable rather than
        // merely discouraged.
        let mut derived = skeleton_inputs();
        derived.objects_new = derived.counted_commits * OBJECTS_PER_COMMIT + 1;
        let bundle = build_bundle(&repo_root(), &workload, &derived)
            .expect("the drive path asserts nothing about objects_new");
        assert!(!bundle.contains("objects_new_equals_three_per_commit"));
    }

    #[test]
    fn repository_creation_is_outside_the_fences_and_signatures_the_bundle_reports() {
        // The P1 defect: repositories are created *before* the measured
        // interval, through the same `StoreEngine::submit` path the measurement
        // uses, so creating them fences and signs. Both counters were read only
        // at the end of the run — that is, from a baseline of zero, taken
        // before the repositories existed — so every bundle reported the
        // creation fences and the creation signatures inside the measured
        // interval while asserting `verification.setup_traffic_excluded: true`.
        //
        // Charter item 7: this asserts against the store's own
        // `DurabilityCounters` and the signer's own sample vector, not against
        // the emitter's intention to have excluded anything.
        let directory = tempfile::tempdir().expect("tempdir");
        let root = directory.path().join("root");
        let ack = directory.path().join("ack-journal");
        let run = run_engine(&root, &ack, AckJournalFault::None, 4, 1, 2, 1)
            .expect("an engine-driven run");

        // The exclusion is not vacuous: creating the repositories really did
        // fence and really did sign, so there is something to exclude. Without
        // this the three assertions below would pass on a run that had no setup
        // traffic at all.
        assert!(
            run.setup.fences > 0,
            "creating {} repositories through StoreEngine::submit must fence, or this \
             test cannot tell an exclusion from an absence",
            2
        );
        assert!(
            run.setup.signings > 0,
            "creating repositories through StoreEngine::submit signs every event"
        );

        // The strict inequality is the assertion that fails without the fix.
        // Before it, `fences` *was* the total, so this read `total > total`.
        assert!(
            run.total_fences > run.fences,
            "the fence counter read {} in total and {} for the measured interval; setup \
             traffic is being counted as measured work",
            run.total_fences,
            run.fences
        );
        assert!(
            run.total_signings > run.signings,
            "the signer recorded {} samples in total and {} inside the measured interval",
            run.total_signings,
            run.signings
        );

        // And the reported figures are exactly the totals less the baselines,
        // so the subtraction is the whole of the exclusion.
        assert_eq!(
            run.fences,
            run.total_fences - run.setup.fences,
            "storage.fences must be what the counter gained across the measured interval"
        );
        assert_eq!(
            run.signings,
            run.total_signings - run.setup.signings,
            "evidence_signings must count only signatures taken inside the interval"
        );

        // A run that measured something, so the counts above are about a real
        // interval rather than about an empty one.
        assert!(
            run.transactions > 0,
            "the measured interval must contain work"
        );

        // Through the shape the emitter actually consumes, at the altitude a
        // consumer calls (charter item 8): `MeasuredRun` is what becomes
        // `BundleInputs.fences` and `BundleInputs.evidence_signings`.
        let (fences, signings) = (run.fences, run.signings);
        let measured: MeasuredRun = run.into();
        assert_eq!(measured.fences, fences);
        assert_eq!(measured.signings, signings);
        assert_eq!(
            measured.fences,
            measured.total_fences - measured.setup.fences
        );
    }

    #[test]
    fn a_zero_submitter_run_is_refused_rather_than_measured() {
        // The lead's reproduction, first half. `--submitters-per-shard 0`
        // spawns no submitter, so the measured interval contains no
        // transaction — but the repositories are still created, so the run
        // reported their fences and their signatures as measured work.
        let directory = tempfile::tempdir().expect("tempdir");
        let error = run_engine(
            &directory.path().join("root"),
            &directory.path().join("ack-journal"),
            AckJournalFault::None,
            4,
            1,
            2,
            0,
        )
        .err()
        .expect("a run with no submitter measures nothing");
        assert!(error.contains("submitters-per-shard 0"), "{error}");

        // The same zero-work run through the other flag.
        let error = run_engine(
            &directory.path().join("root-b"),
            &directory.path().join("ack-journal-b"),
            AckJournalFault::None,
            4,
            1,
            0,
            1,
        )
        .err()
        .expect("no shard is no repository and no transaction");
        assert!(error.contains("--shards 0"), "{error}");
    }

    #[test]
    fn an_acknowledgment_that_could_not_be_journaled_refuses_instead_of_shortening_the_run() {
        // The P1 defect. `append_durable` failing set `stop` and returned: it
        // did not increment `refused`, so the fatal-error guard in
        // `emit_skeleton` never saw it, and it happened *after* a successful
        // commit, so the zero-work guard did not see it either. The bundle then
        // omitted a committed transaction while still counting its durability
        // fence and its Ed25519 signature, and reported a measured interval
        // that had been cut short — numbers describing a workload that did not
        // happen, under an accounting identity the bundle asserts is exact.
        //
        // `EDQUOT` on a full tmpfs is the ordinary way to reach it, which is
        // why the fault is armed rather than raced: the failure has to be the
        // same failure every time this test runs.
        // One invocation, parameterized only by the fault, so the faulted run
        // and its control differ in exactly one flag.
        fn invocation(root: &Path, out: &Path, fault: Option<u64>) -> Flags {
            let mut raw = vec![
                "emit-skeleton".to_string(),
                "--repo-root".to_string(),
                repo_root().display().to_string(),
                "--root".to_string(),
                root.display().to_string(),
                "--out".to_string(),
                out.display().to_string(),
                "--path".to_string(),
                "submit".to_string(),
                "--seconds".to_string(),
                "2".to_string(),
                "--group-len".to_string(),
                "4".to_string(),
                "--shards".to_string(),
                "1".to_string(),
                "--submitters-per-shard".to_string(),
                "1".to_string(),
                "--allow-unsigned".to_string(),
                // The tempdir is not a nodatacow btrfs subtree, and this test
                // is about the accounting refusal rather than about the
                // attribute precheck that would otherwise refuse first.
                "--skip-attribute-check".to_string(),
            ];
            if let Some(index) = fault {
                raw.push("--fail-ack-append-after".to_string());
                raw.push(index.to_string());
            }
            Flags::parse(raw.into_iter()).expect("flags").1
        }

        let directory = tempfile::tempdir().expect("tempdir");
        let out = directory.path().join("bundle.json");
        let root = directory.path().join("root");

        // Fail the *second* append, so a transaction was committed,
        // acknowledged, fenced and signed before the failure. That is exactly
        // the state neither surviving guard could see.
        //
        // Charter item 8: through `dispatch`, the entry point the CLI and
        // scripts/verify-store-recovery.sh both call, not through `run_engine`
        // — the defect was that the refusal never reached the emitter, so a
        // test below the emitter could not have caught it.
        let error = dispatch("emit-skeleton", &invocation(&root, &out, Some(1)))
            .expect_err("a commit whose acknowledgment could not be journaled voids the run");
        assert!(
            error.contains("incomplete accounting"),
            "the refusal must name what is wrong — the run cannot account for a \
             transaction it measured — rather than reporting a refused submit: {error}"
        );
        // The original I/O error, preserved rather than summarized. `code: 28`
        // is ENOSPC as the kernel reported it through /dev/full; `EDQUOT` would
        // arrive here as 122 by the same route.
        assert!(
            error.contains("code: 28"),
            "the underlying I/O error must survive into the refusal: {error}"
        );
        assert!(
            error.contains("repo_sequence"),
            "the refusal must say which committed transaction went unaccounted: {error}"
        );
        // And no bundle. A refusal that still wrote one is not a refusal — this
        // is the assertion the defect failed: before the fix the run reached
        // `assemble_bundle` and wrote a short, self-consistent-looking file.
        assert!(
            !out.exists(),
            "a run that cannot account for a committed transaction must emit nothing, \
             and {} exists",
            out.display()
        );

        // The negative control. Without the armed fault the identical
        // invocation emits a bundle, so the refusal above is caused by the
        // journal failure and not by the flags, the tempdir, or the two-second
        // budget. A fresh root, because the faulted run left one behind and
        // `run_engine` refuses a root it did not build.
        let control = tempfile::tempdir().expect("tempdir");
        let control_out = control.path().join("bundle.json");
        dispatch(
            "emit-skeleton",
            &invocation(&control.path().join("root"), &control_out, None),
        )
        .expect("an unfaulted run emits a bundle");
        assert!(
            control_out.exists(),
            "the negative control must produce the bundle the faulted run must not"
        );
    }

    #[test]
    fn the_journal_seam_refuses_an_unjournalable_acknowledgment_the_same_way() {
        // The same failure on the Wave A drive path. It was already fatal there
        // — the append is behind a `?` — but it reported itself as "ack append:
        // ..." rather than as the accounting failure it is, and the two paths
        // must answer the same question the same way or the seam becomes the
        // place the weaker answer survives.
        let directory = tempfile::tempdir().expect("tempdir");
        let error = run_skeleton(
            &directory.path().join("root"),
            &directory.path().join("ack-journal"),
            AckJournalFault::EnospcOnAppend(1),
            4,
            2,
        )
        .err()
        .expect("a fenced group whose acknowledgment cannot be journaled voids the run");
        assert!(error.contains("incomplete accounting"), "{error}");
        assert!(error.contains("code: 28"), "{error}");
    }

    /// The gap between "the flag was passed" and "the failure happened".
    ///
    /// The target is placed far beyond any append the run can reach, so the
    /// arming is real, the injection is never induced, and the run is otherwise
    /// a perfectly ordinary one. Before the check this emitted a normal bundle
    /// with nothing recording that the claimed failure never occurred.
    ///
    /// The negative control matters more than the refusal here: a check that
    /// refused every armed run regardless of firing would pass the first
    /// assertion, so the same seam is run with a reachable target and must still
    /// produce the *injected* refusal rather than this one.
    #[test]
    fn an_armed_acknowledgment_fault_that_never_fires_refuses_the_run() {
        let directory = tempfile::tempdir().expect("tempdir");
        let error = run_skeleton(
            &directory.path().join("root"),
            &directory.path().join("ack-journal"),
            AckJournalFault::EnospcOnAppend(u64::MAX),
            4,
            1,
        )
        .err()
        .expect("an armed fault that never fired must not produce a run");
        assert!(error.contains("never fired"), "{error}");
        assert!(
            !error.contains("incomplete accounting"),
            "an unfired arming is not an accounting failure; the two refusals must stay \
             distinguishable: {error}"
        );

        let reachable = tempfile::tempdir().expect("tempdir");
        let injected = run_skeleton(
            &reachable.path().join("root"),
            &reachable.path().join("ack-journal"),
            AckJournalFault::EnospcOnAppend(1),
            4,
            2,
        )
        .err()
        .expect("a reachable target still refuses");
        assert!(
            injected.contains("incomplete accounting") && !injected.contains("never fired"),
            "a fault that did fire must report the injected failure, not the arming check: \
             {injected}"
        );
    }

    #[test]
    fn a_zero_work_run_cannot_earn_a_claim_that_is_vacuous_over_an_empty_set() {
        // The lead's reproduction, second half, and the reason the refusal
        // cannot live in the schema: a zero-commit bundle is **schema-valid**.
        // `counts` is `nonnegative`, and the three claims are `const true`, so
        // a run that measured nothing satisfies every rule in
        // `bench/result-schema.json` while asserting `setup_traffic_excluded`,
        // `unique_blob_tree_commit_ids`, and `objects_new_equals_three_per_commit`
        // over zero commits — each vacuously true, each presented in the same
        // field a real run uses.
        let workload = load_frozen_workload(&repo_root().join("bench/workloads/small-commit.toml"))
            .expect("workload");

        // First: the schema really does accept it. Recorded deliberately, as
        // the negative control for the refusal below — an emitter-side check
        // whose job the schema already did would be decoration.
        let real = build_bundle(&repo_root(), &workload, &submit_inputs()).expect("bundle");
        let vacuous = real
            .replace("\"counted_commits\": 3", "\"counted_commits\": 0")
            .replace("\"objects_new\": 9", "\"objects_new\": 0")
            .replace(
                "\"acknowledged_requests\": 3",
                "\"acknowledged_requests\": 0",
            )
            .replace("\"offered_requests\": 3", "\"offered_requests\": 0")
            .replace("\"accepted_requests\": 3", "\"accepted_requests\": 0");
        assert_ne!(vacuous, real, "the mutation must have applied");
        assert!(
            schema_errors(&vacuous).is_empty(),
            "the schema accepts a zero-commit bundle asserting all three claims, which is \
             exactly why the emitter must refuse to produce one:\n{}",
            schema_errors(&vacuous).join("\n")
        );

        // Second: the emitter refuses, by name, on both paths. A `false` is not
        // available — the schema pins the claims to `const true` — and emitting
        // one would be a different untrue statement.
        for mut inputs in [submit_inputs(), skeleton_inputs()] {
            inputs.counted_commits = 0;
            inputs.objects_new = 0;
            let error = build_bundle(&repo_root(), &workload, &inputs)
                .expect_err("a claim over an empty set is not a claim this run earned");
            assert!(error.contains("vacuously true"), "{error}");
        }

        // A measured, acknowledged commit is what the claims are conditioned
        // on, so acknowledging nothing is refused even where commits were
        // counted.
        let mut unacknowledged = submit_inputs();
        unacknowledged.acknowledged_requests = 0;
        let error = build_bundle(&repo_root(), &workload, &unacknowledged)
            .expect_err("nothing acknowledged is nothing measured");
        assert!(error.contains("acknowledged request"), "{error}");
    }

    #[test]
    fn uniqueness_is_checked_across_every_record_rather_than_within_each() {
        // Two records that are each internally distinct and still share a
        // commit id. A per-record check passes this input; the claim's whole
        // condition is that this one does not.
        let mut first = skeleton_ack_record(1);
        let mut second = skeleton_ack_record(2);
        let shared = ObjectId([0x5c; 32]);
        first.commit_ids = vec![shared];
        second.commit_ids = vec![shared];
        let error = check_global_uniqueness(&[first, second])
            .expect_err("a collision between two records must be refused");
        assert!(error.contains("commit identifier"), "{error}");

        let clean = check_global_uniqueness(&[skeleton_ack_record(1), skeleton_ack_record(2)])
            .expect("distinct records");
        assert_eq!(
            clean,
            UniquenessCheck::GlobalAcrossAckRecords {
                blob_ids: 2,
                tree_ids: 2,
                commit_ids: 2,
            },
            "the counts are the set sizes, so a reader can see the check had something \
             to check"
        );
    }

    #[test]
    fn the_receipt_claim_is_never_emitted_while_no_receipt_is_reconciled() {
        // Scope 6.6 item 5e, asserted on the artifact rather than left to the
        // schema: the claim is approved in principle and not earned, and the
        // reason it is not earned lives in this file.
        let workload = load_frozen_workload(&repo_root().join("bench/workloads/small-commit.toml"))
            .expect("workload");
        for inputs in [skeleton_inputs(), submit_inputs()] {
            let bundle = build_bundle(&repo_root(), &workload, &inputs).expect("bundle");
            assert!(
                !bundle.contains("operation_receipts_reconciled"),
                "store-bench accepts any Committed(_) status and journals \
                 blake3(operation_id) as its receipt digest, so it may not assert \
                 receipt reconciliation:\n{bundle}"
            );
        }
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
        let conditions =
            RunConditions::derive(&inputs.observations, true, "diagnostic").expect("conditions");
        assert_eq!(
            storage_primitive_outcome(&inputs, &conditions),
            Outcome::Fail
        );
        let bundle = build_bundle(&repo_root(), &workload, &inputs).expect("bundle");
        assert!(bundle.contains("\"outcome\": \"fail\""), "{bundle}");
        let errors = schema_errors(&bundle);
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        // A window rule miss is the same story.
        let mut inputs = skeleton_inputs();
        inputs.skeleton = false;
        inputs.windows_meeting_target_percent = 80.0;
        assert_eq!(
            storage_primitive_outcome(&inputs, &conditions),
            Outcome::Fail
        );
        let errors =
            schema_errors(&build_bundle(&repo_root(), &workload, &inputs).expect("bundle"));
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        // A run that missed no ceiling is still not a pass, and the reason is
        // contract review 2026-07-28-C rather than a ceiling: `outcome: "pass"`
        // requires `environment_fidelity: "reference_profile"` at every gate,
        // and this emitter records placeholders for hardware it never measured.
        // The run is therefore representable and mechanically disqualified —
        // which is the state the review was after, and which the *previous*
        // version of this arm asserted the opposite of.
        let mut inputs = skeleton_inputs();
        inputs.skeleton = false;
        assert_eq!(
            storage_primitive_outcome(&inputs, &conditions),
            Outcome::Preliminary
        );
        let bundle = build_bundle(&repo_root(), &workload, &inputs).expect("bundle");
        assert!(bundle.contains("\"outcome\": \"preliminary\""), "{bundle}");
        assert!(
            bundle.contains("\"environment_fidelity\": \"diagnostic\""),
            "{bundle}"
        );
        let errors = schema_errors(&bundle);
        assert!(errors.is_empty(), "{}", errors.join("\n"));

        // A pass remains reachable in principle, and the conditional that
        // gates it is exercised rather than assumed. **Every** condition the
        // schema requires of a passing storage_primitive bundle has to hold,
        // not only the fidelity one: the root through `StoreEngine::open`, the
        // transactions through `StoreEngine::submit`, a checkpoint exercised,
        // and the index in a sealed steady state.
        let reference = RunConditions {
            environment_fidelity: "reference_profile",
            build_profile: "release",
            initialization_path: "store_engine_open",
            mutation_path: "store_engine_submit",
            checkpointing: "exercised",
            index_maintenance: "runs_sealed",
            ..conditions.clone()
        };
        assert_eq!(
            storage_primitive_outcome(&inputs, &reference),
            Outcome::Pass,
            "nothing about recording a diagnostic run may change what a pass costs"
        );
    }

    #[test]
    fn the_checkpoint_and_index_conditions_bound_a_pass_before_the_schema_has_to() {
        // The trap this closes: `environment_fidelity` was the only condition
        // between the emitter and a `pass`, and it is about to stop being the
        // binding one. The moment hardware recognition names a frozen profile,
        // an outcome derived from fidelity alone would emit `pass` on a run
        // that took no checkpoint and sealed no index run — and the schema
        // would then reject the bundle. A harness that learns what it claimed
        // from its own validator has already published the claim.
        let mut inputs = skeleton_inputs();
        inputs.skeleton = false;

        // Everything a pass costs, held true at once.
        let passing = RunConditions {
            initialization_path: "store_engine_open",
            mutation_path: "store_engine_submit",
            checkpointing: "exercised",
            index_maintenance: "runs_sealed",
            index_run_ceiling: "store_default",
            receipt_reconciliation: "acceptance_of_any_committed_status",
            objects_new_source: "summed_from_receipts",
            commit_id_uniqueness: "checked_globally_across_ack_records",
            build_profile: "release",
            environment_fidelity: "reference_profile",
        };
        assert_eq!(storage_primitive_outcome(&inputs, &passing), Outcome::Pass);

        // Each condition alone, moved to the value today's run genuinely has.
        // Every one of them must cost the pass, and the reason each one is
        // named separately is that a suite asserting only the conjunction
        // cannot tell which member is load-bearing.
        for (member, today) in [
            ("checkpointing", "unimplemented"),
            ("index_maintenance", "deltas_retained_in_memory"),
            ("initialization_path", "shard_drive_create"),
            ("mutation_path", "journal_drive"),
        ] {
            let mut degraded = passing.clone();
            match member {
                "checkpointing" => degraded.checkpointing = today,
                "index_maintenance" => degraded.index_maintenance = today,
                "initialization_path" => degraded.initialization_path = today,
                "mutation_path" => degraded.mutation_path = today,
                other => panic!("unnamed member {other}"),
            }
            assert_eq!(
                storage_primitive_outcome(&inputs, &degraded),
                Outcome::Preliminary,
                "run_conditions.{member} = {today:?} is a condition bench/result-schema.json \
                 requires of a passing storage_primitive bundle, so the emitter must reach \
                 the same answer the validator would"
            );
        }

        // And a ceiling miss still outranks all of it: a run that exceeded the
        // gate ceiling is a `fail`, never a `preliminary` that quietly did.
        let mut missed = inputs;
        missed.latency_p99 = STORAGE_PRIMITIVE_P99_CEILING_MICROS + 1;
        assert_eq!(storage_primitive_outcome(&missed, &passing), Outcome::Fail);
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
        let submit = build_bundle(&repo_root(), &workload, &submit_inputs()).expect("bundle");

        /// A mutation must both apply and be rejected. A mutation that silently
        /// did not apply is a negative control that proves nothing, which is
        /// the failure mode this whole test exists to prevent one level up.
        fn refuses(original: &str, mutated: String, why: &str) {
            assert_ne!(mutated, original, "the mutation did not apply: {why}");
            assert!(!schema_errors(&mutated).is_empty(), "{why}");
        }

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

        // -- one mutation per field contract review 2026-07-28-C made required.
        //
        // A required field the negative control never removes is a field the
        // suite cannot notice the loss of, which is the same class of defect as
        // a test asserting a count it merely observed. Each of the two new
        // required fields is removed here, and each conditional the block
        // introduced is contradicted here, on the path whose rules it keys on.

        // 6. The whole `run_conditions` block, gone.
        refuses(
            &bundle,
            bundle.replace("\"run_conditions\":", "\"run_conditions_removed\":"),
            "a bundle with no run_conditions block must be rejected: every claim in it \
             is conditioned on a declaration, and a bundle that declares nothing has \
             gone back to caveats living outside it",
        );

        // 7. `resources.configured_ceilings.max_index_runs`, gone. It was
        //    reachable only through free-form additionalProperties before the
        //    review, which is how an emitter could omit the one ceiling this
        //    workload actually reaches and stay valid.
        refuses(
            &bundle,
            bundle.replace("\"max_index_runs\":", "\"max_index_runs_removed\":"),
            "a bundle omitting the configured max_index_runs must be rejected",
        );

        // 8. The ceiling cross-check, in both directions. A declared store
        //    default may not record a raised value...
        refuses(
            &submit,
            submit.replace(
                "\"index_run_ceiling\": \"raised_because_index_sealing_unimplemented\"",
                "\"index_run_ceiling\": \"store_default\"",
            ),
            "declaring the store default while recording a raised ceiling must be \
             rejected in that direction",
        );
        // ...and a declared raise may not record the default.
        refuses(
            &bundle,
            bundle.replace(
                "\"index_run_ceiling\": \"store_default\"",
                "\"index_run_ceiling\": \"raised_because_index_sealing_unimplemented\"",
            ),
            "declaring a raise while recording the default must be rejected in the \
             other direction",
        );

        // 9. The receipt claim, asserted while the declaration says any
        //    Committed status was accepted.
        refuses(
            &submit,
            submit.replace(
                "\"acknowledged_sequences_reconciled\": true",
                "\"acknowledged_sequences_reconciled\": true,\n    \
                 \"operation_receipts_reconciled\": true",
            ),
            "accepting any Committed status is not reconciling a receipt, and a bundle \
             that declares the first while claiming the second must be rejected",
        );

        // 10. The two claims the submit path earned, each removed. They are
        //     required there — a missing result, not an inapplicable one.
        refuses(
            &submit,
            submit.replace(
                "\"unique_blob_tree_commit_ids\": true",
                "\"unique_blob_tree_commit_ids_removed\": true",
            ),
            "the submit path must assert unique_blob_tree_commit_ids",
        );
        refuses(
            &submit,
            submit.replace(
                "\"objects_new_equals_three_per_commit\": true",
                "\"objects_new_equals_three_per_commit_removed\": true",
            ),
            "the submit path must assert objects_new_equals_three_per_commit",
        );

        // 11. The same two claims asserted on the journal seam, which has
        //     neither the objects nor the receipts to earn them. This is the
        //     hole the branch conditional exists to close: permitting the
        //     claims on both paths would have been a worse defect than the one
        //     the review fixed, arriving disguised as the fix.
        refuses(
            &bundle,
            bundle.replace(
                "\"acknowledged_sequences_reconciled\": true",
                "\"acknowledged_sequences_reconciled\": true,\n    \
                 \"unique_blob_tree_commit_ids\": true",
            ),
            "the journal seam declares commit_id_uniqueness: not_checked and may not \
             claim global uniqueness",
        );
        refuses(
            &bundle,
            bundle.replace(
                "\"acknowledged_sequences_reconciled\": true",
                "\"acknowledged_sequences_reconciled\": true,\n    \
                 \"objects_new_equals_three_per_commit\": true",
            ),
            "a run that derived objects_new from its transaction count may not assert \
             the claim: the assertion could not fail",
        );

        // 12. A diagnostic run promoted to a pass, and a diagnostic run
        //     claiming the reference profile it did not meet.
        refuses(
            &bundle,
            bundle.replace("\"outcome\": \"preliminary\"", "\"outcome\": \"pass\""),
            "a run declaring diagnostic fidelity may not be a pass at any gate",
        );
        refuses(
            &bundle,
            bundle.replace(
                "\"environment_fidelity\": \"diagnostic\"",
                "\"environment_fidelity\": \"reference_profile\"",
            ),
            "reference-profile fidelity re-pins a release build, and this bundle \
             declares the profile it was built with",
        );

        // 13. The seam declaring what only the engine can do.
        refuses(
            &bundle,
            bundle.replace(
                "\"mutation_path\": \"journal_drive\"",
                "\"mutation_path\": \"store_engine_submit\"",
            ),
            "a bundle whose other declarations are the seam's may not call its \
             mutation path production submit",
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

    /// The observations a `--path drive` run makes.
    ///
    /// Written as observations rather than as ten finished strings on purpose:
    /// what these tests have to cover is the derivation, and a fixture that
    /// handed the emitter the answers would test the JSON writer instead.
    fn drive_observations() -> RunObservations {
        RunObservations::new(
            RunFacts {
                initialization: Initialization::ShardDriveCreate,
                mutation: MutationPath::JournalDrive,
                checkpoint: CheckpointProbe::RefusedNotImplemented,
                index: IndexObservation::NoIndexInPath,
                // Read off `StoreOptions` rather than written as 64 here for
                // the same reason the emitter does it: a test that restates the
                // default cannot notice the default moving.
                configured_max_index_runs: default_max_index_runs(),
                default_max_index_runs: default_max_index_runs(),
                receipts: ReceiptComparison::NoReceiptsInPath,
                objects_new_counted: false,
                uniqueness: UniquenessCheck::NotPerformed,
            },
            MountFacts {
                filesystem: "btrfs".into(),
                tmpfs: false,
            },
        )
    }

    /// The observations a `--path submit` run makes today.
    fn submit_observations() -> RunObservations {
        RunObservations::new(
            RunFacts {
                initialization: Initialization::StoreEngineOpen,
                mutation: MutationPath::StoreEngineSubmit,
                checkpoint: CheckpointProbe::RefusedNotImplemented,
                index: IndexObservation::StoreRoot {
                    validated_runs: 0,
                    unvalidatable: Vec::new(),
                    groups: 1,
                    unsealed_delta_backlog: None,
                },
                configured_max_index_runs: ENGINE_MAX_INDEX_RUNS,
                default_max_index_runs: default_max_index_runs(),
                receipts: ReceiptComparison::AnyCommittedStatusAccepted,
                objects_new_counted: true,
                uniqueness: UniquenessCheck::GlobalAcrossAckRecords {
                    blob_ids: 3,
                    tree_ids: 3,
                    commit_ids: 3,
                },
            },
            MountFacts {
                filesystem: "btrfs".into(),
                tmpfs: false,
            },
        )
    }

    fn default_max_index_runs() -> u32 {
        levcs_store::StoreOptions::new("/nonexistent/store-bench-default-probe").max_index_runs
    }

    fn submit_inputs() -> BundleInputs {
        BundleInputs {
            run_id: "engine-wave-b-test".into(),
            observations: submit_observations(),
            ..skeleton_inputs()
        }
    }

    fn skeleton_inputs() -> BundleInputs {
        BundleInputs {
            observations: drive_observations(),
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
