//! Crash-matrix plumbing: fixture loading and child-process driving.
//!
//! The classifier itself is *not* here. It lives in `store-crash-driver`'s
//! `reconcile` subcommand, so the crash matrix and
//! `scripts/verify-store-recovery.sh` classify through the same code reading
//! the same bytes, and so recovery always runs in a fresh process with a fresh
//! descriptor (scope 3.7).

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use levcs_protocol::oracle::RecoveryOutcome;
use levcs_store::failpoints::{Failpoint, Wave};

use super::group_model::{PhysicalStateClass, VictimPlacement};

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

pub const FIXTURE_PATH: &str = "tests/fixtures/phase1-failpoints.json";

/// The `wave` value a row carries when it cannot be driven until B1 lands.
///
/// The same spelling Phase 0 used for its `not-exercised` adversarial rows,
/// and the string `scripts/check-phase1.sh` greps for once `engine.rs` is
/// implemented.
pub const PENDING_WAVE_B: &str = "pending-wave-b";

#[derive(Clone, Debug)]
pub struct DrivePlan {
    pub action: String,
    pub fault: String,
}

#[derive(Clone, Debug)]
pub struct FixtureRow {
    pub failpoint: String,
    pub wave: String,
    pub physical_state_class: String,
    pub required_outcome: String,
    pub victim_placement: String,
    pub drive: Option<DrivePlan>,
    pub pending_reason: Option<String>,
    pub rationale: String,
}

#[derive(Clone, Debug)]
pub struct Fixture {
    pub rows: Vec<FixtureRow>,
    pub wave_a_asserted: Vec<String>,
    pub wave_a_unasserted: Vec<String>,
    pub wave_b_exit_conditions: Vec<String>,
}

fn string_field(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("fixture row is missing a string {key:?}: {value}"))
        .to_string()
}

fn string_list(value: &serde_json::Value) -> Vec<String> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("expected a JSON array, got {value}"))
        .iter()
        .map(|entry| {
            entry
                .as_str()
                .unwrap_or_else(|| panic!("expected a string, got {entry}"))
                .to_string()
        })
        .collect()
}

pub fn load_fixture() -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE_PATH);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
    let document: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("parsing {}: {e}", path.display()));

    assert_eq!(
        document.get("schema_version").and_then(|v| v.as_u64()),
        Some(1),
        "unexpected crash-matrix fixture schema version"
    );

    let scope = document
        .get("wave_a_assertion_scope")
        .expect("the fixture must record which halves Wave A asserts");
    let wave_a_asserted = string_list(scope.get("asserted").expect("asserted"));
    let wave_a_unasserted = string_list(scope.get("unasserted").expect("unasserted"));
    assert!(
        scope
            .get("reason")
            .and_then(|v| v.as_str())
            .is_some_and(|r| !r.is_empty()),
        "the unasserted halves must carry their reason, not merely be listed"
    );

    let wave_b_exit_conditions = string_list(
        document
            .get("wave_b_exit_conditions")
            .expect("wave_b_exit_conditions"),
    );

    let rows = document
        .get("rows")
        .and_then(|v| v.as_array())
        .expect("rows must be an array")
        .iter()
        .map(|row| FixtureRow {
            failpoint: string_field(row, "failpoint"),
            wave: string_field(row, "wave"),
            physical_state_class: string_field(row, "physical_state_class"),
            required_outcome: string_field(row, "required_outcome"),
            victim_placement: string_field(row, "victim_placement"),
            drive: row.get("drive").and_then(|plan| {
                plan.as_object().map(|_| DrivePlan {
                    action: string_field(plan, "action"),
                    fault: string_field(plan, "fault"),
                })
            }),
            pending_reason: row
                .get("pending_reason")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            rationale: string_field(row, "rationale"),
        })
        .collect();

    Fixture {
        rows,
        wave_a_asserted,
        wave_a_unasserted,
        wave_b_exit_conditions,
    }
}

// ---------------------------------------------------------------------------
// Name mapping, without catch-all arms
// ---------------------------------------------------------------------------

/// The fixture spells `Wave::A` as `"A"` and `Wave::B` as `"pending-wave-b"`,
/// because a Wave B row is not merely "later" — it is an outstanding, named
/// obligation, and `check-phase1.sh` greps for that exact string.
pub fn wave_name(wave: Wave) -> &'static str {
    match wave {
        Wave::A => "A",
        Wave::B => PENDING_WAVE_B,
    }
}

pub fn recovery_outcome_name(outcome: RecoveryOutcome) -> &'static str {
    match outcome {
        RecoveryOutcome::AbsentRetriable => "AbsentRetriable",
        RecoveryOutcome::Committed => "Committed",
        RecoveryOutcome::EitherWhole => "EitherWhole",
    }
}

pub const RECOVERY_OUTCOMES: &[RecoveryOutcome] = &[
    RecoveryOutcome::AbsentRetriable,
    RecoveryOutcome::Committed,
    RecoveryOutcome::EitherWhole,
];

/// Parse by searching the enumerated set rather than by a `match` with a
/// fallback binding, so no name can acquire a default meaning.
pub fn recovery_outcome_from_name(name: &str) -> Option<RecoveryOutcome> {
    RECOVERY_OUTCOMES
        .iter()
        .copied()
        .find(|o| recovery_outcome_name(*o) == name)
}

/// The fixture's own view of a row, resolved to typed values.
pub struct ResolvedRow {
    pub point: Failpoint,
    pub class: PhysicalStateClass,
    pub required_outcome: RecoveryOutcome,
    pub placement: VictimPlacement,
}

pub fn resolve(row: &FixtureRow) -> ResolvedRow {
    ResolvedRow {
        point: Failpoint::from_name(&row.failpoint)
            .unwrap_or_else(|| panic!("fixture names an unknown failpoint {:?}", row.failpoint)),
        class: PhysicalStateClass::from_name(&row.physical_state_class).unwrap_or_else(|| {
            panic!(
                "fixture names an unknown physical state class {:?}",
                row.physical_state_class
            )
        }),
        required_outcome: recovery_outcome_from_name(&row.required_outcome).unwrap_or_else(|| {
            panic!(
                "fixture names an unknown recovery outcome {:?}",
                row.required_outcome
            )
        }),
        placement: VictimPlacement::from_name(&row.victim_placement).unwrap_or_else(|| {
            panic!(
                "fixture names an unknown victim placement {:?}",
                row.victim_placement
            )
        }),
    }
}

// ---------------------------------------------------------------------------
// Driving the child
// ---------------------------------------------------------------------------

pub const DRIVER: &str = env!("CARGO_BIN_EXE_store-crash-driver");

/// A child run's machine-readable output plus how it died.
#[derive(Clone, Debug)]
pub struct ChildRun {
    pub keys: BTreeMap<String, String>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stderr: String,
}

impl ChildRun {
    fn from_output(output: Output) -> Self {
        use std::os::unix::process::ExitStatusExt;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let mut keys = BTreeMap::new();
        for line in stdout.lines() {
            if let Some((key, value)) = line.split_once('=') {
                keys.insert(key.to_string(), value.to_string());
            }
        }
        Self {
            keys,
            exit_code: output.status.code(),
            signal: output.status.signal(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.keys.get(key).map(|v| v.as_str())
    }

    /// Sequence list fields are comma separated and may legitimately be empty.
    pub fn sequences(&self, key: &str) -> Vec<u64> {
        match self.get(key) {
            Some(value) if !value.is_empty() => value
                .split(',')
                .map(|entry| {
                    entry
                        .parse::<u64>()
                        .unwrap_or_else(|e| panic!("bad sequence {entry:?} in {key}: {e}"))
                })
                .collect(),
            Some(_) => Vec::new(),
            None => Vec::new(),
        }
    }
}

/// Arguments for one scripted append that is expected to crash.
pub struct AppendRun<'a> {
    pub root: &'a Path,
    pub shard: u16,
    pub shard_count: u16,
    pub seed: u64,
    pub group_len: usize,
    pub victim: usize,
    pub point: Failpoint,
    pub action: &'a str,
    pub fault: &'a str,
    pub ack_journal: &'a Path,
    pub create: bool,
}

pub fn run_append(run: &AppendRun<'_>) -> ChildRun {
    let mut command = Command::new(DRIVER);
    command
        .arg("append")
        .arg("--root")
        .arg(run.root)
        .arg("--shard")
        .arg(run.shard.to_string())
        .arg("--shard-count")
        .arg(run.shard_count.to_string())
        .arg("--seed")
        .arg(run.seed.to_string())
        .arg("--group-len")
        .arg(run.group_len.to_string())
        .arg("--victim")
        .arg(run.victim.to_string())
        .arg("--point")
        .arg(run.point.name())
        .arg("--action")
        .arg(run.action)
        .arg("--fault")
        .arg(run.fault)
        .arg("--ack-journal")
        .arg(run.ack_journal)
        .arg("--path")
        .arg("drive");
    if run.create {
        command.arg("--create");
    }
    ChildRun::from_output(command.output().expect("spawning store-crash-driver"))
}

pub fn run_reconcile(root: &Path, shard: u16, ack_journal: &Path) -> ChildRun {
    let output = Command::new(DRIVER)
        .arg("reconcile")
        .arg("--root")
        .arg(root)
        .arg("--shard")
        .arg(shard.to_string())
        .arg("--ack-journal")
        .arg(ack_journal)
        .output()
        .expect("spawning store-crash-driver reconcile");
    ChildRun::from_output(output)
}

// ---------------------------------------------------------------------------
// The drive-seam tripwire
// ---------------------------------------------------------------------------

/// Whether A1's `drive.rs` bodies have landed.
///
/// Wave A's driving half cannot run against `unimplemented!()`. Rather than
/// silently passing, the matrix's driving test is `#[ignore]`d with a reason
/// and this probe backs a tripwire test that *fails* the moment the seam
/// becomes real, so the ignore cannot be forgotten. That is the same mechanism
/// the `pending-wave-b` rows use, applied to the other blocked dependency.
pub fn drive_seam_is_implemented() -> bool {
    let directory = tempfile::tempdir().expect("tempdir");
    let path = directory.path().to_path_buf();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let probed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = levcs_store::drive::ShardDrive::create(&path, 0, 1);
    }));
    std::panic::set_hook(previous);
    // Any return at all — success or a genuine `StoreError` — means the body
    // exists. Only an `unimplemented!()` unwind means A1 has not landed it.
    probed.is_ok()
}
