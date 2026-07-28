//! Deterministic crash driver (scope 4-A3 deliverable 1).
//!
//! **Owned by A3 StoreHarness.**
//!
//! The parent arms a failpoint by name and a physical fault by name; this
//! child runs a scripted, seed-deterministic workload through the journal-level
//! `drive.rs` seam in Wave A and through `StoreEngine::submit` from Wave B; the
//! failpoint fires (`Fail`, `Panic`, or `HardExit` via `_exit(3)`, which runs
//! no destructor and flushes no buffer); the parent reopens through production
//! recovery and classifies.
//!
//! # One classifier, two submission calls
//!
//! `reconcile` is the classifier, and it is the only place that decides what
//! recovery concluded. It is identical for both waves. The two drive paths
//! differ in exactly one function — [`submit_group`] — and share workload
//! generation, fault arming, acknowledgment journaling, and classification.
//! Running `reconcile` as a separate process is deliberate: scope 3.7 requires
//! recovery to re-read from the device with a *fresh descriptor* before
//! classifying a failed or ambiguous fence, and a separate process cannot
//! accidentally reuse the writer's.
//!
//! # Output
//!
//! Every subcommand prints `key=value` lines on stdout and nothing else, so
//! `scripts/verify-store-recovery.sh` and `tests/crash_matrix.rs` parse the
//! same bytes. Diagnostics go to stderr.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | the scripted workload ran to completion; no fault fired |
//! | 3 | `HardExit`: `_exit(3)` from inside `failpoints::hit` |
//! | 64 | usage error |
//! | 65 | the store returned an error (a `Fail` action, or a real refusal) |
//! | 70 | harness-internal error |
//! | 101 | Rust panic (the `Panic` action, unwinding with destructors) |

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use levcs_core::ObjectId;
use levcs_protocol::oracle::{AckRecord, ExternalAckJournal};
use levcs_store::drive::faults::Fault;
use levcs_store::drive::points::{Failpoint, FailpointAction};
use levcs_store::drive::{DriveRecovery, ShardDrive, DRIVE_PREALLOCATE_BYTES};
use levcs_store::format::{frame_total_len, FRAME_HEADER_LEN, JOURNAL_HEADER_LEN};
use levcs_store::types::NamespaceId;

/// The adopted-sequence property, shared with `store-bench` and with
/// `tests/support/group_model.rs`. See that file for why it is one checker.
#[path = "support/adopted_set.rs"]
mod adopted_set;

use adopted_set::classify_adopted_set;

const EX_USAGE: u8 = 64;
const EX_DATAERR: u8 = 65;
const EX_SOFTWARE: u8 = 70;

/// Payload length of a scripted frame. Fixed so the short-write offset that
/// tears the victim frame is computable without asking A1's encoder, which
/// keeps the tear deterministic across format churn within a storage version.
const SCRIPTED_PAYLOAD_LEN: usize = 512;

// ---------------------------------------------------------------------------
// Deterministic workload
// ---------------------------------------------------------------------------

fn xof(domain: &str, seed: u64, index: u64, out: &mut [u8]) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain.as_bytes());
    hasher.update(&[0u8]);
    hasher.update(&seed.to_le_bytes());
    hasher.update(&index.to_le_bytes());
    hasher.finalize_xof().fill(out);
}

fn object_id_for(domain: &str, seed: u64, index: u64) -> ObjectId {
    let mut bytes = [0u8; 32];
    xof(domain, seed, index, &mut bytes);
    ObjectId(bytes)
}

fn namespace_for(seed: u64) -> NamespaceId {
    let mut bytes = [0u8; 32];
    xof("levcs-store-crash-driver/namespace/v1", seed, 0, &mut bytes);
    NamespaceId(bytes)
}

/// One scripted transaction. Everything about it is a pure function of
/// `(seed, ordinal)`, so the parent can recompute any of it without the child
/// reporting it — which matters because a `HardExit` child reports nothing.
struct ScriptedTransaction {
    ordinal: u64,
    repo_sequence: u64,
    operation_id: [u8; 16],
    payload: Vec<u8>,
}

impl ScriptedTransaction {
    fn new(seed: u64, ordinal: u64) -> Self {
        let mut operation_id = [0u8; 16];
        xof(
            "levcs-store-crash-driver/operation-id/v1",
            seed,
            ordinal,
            &mut operation_id,
        );
        let mut payload = vec![0u8; SCRIPTED_PAYLOAD_LEN];
        xof(
            "levcs-store-crash-driver/payload/v1",
            seed,
            ordinal,
            &mut payload,
        );
        Self {
            ordinal,
            repo_sequence: ordinal + 1,
            operation_id,
            payload,
        }
    }

    /// The acknowledgment record for this transaction.
    ///
    /// `repo_sequence` carries the assigned `shard_sequence`. In the drive
    /// path the two domains coincide one-for-one because the seam drives a
    /// single namespace with one frame per transaction; plan §4 transaction
    /// invariant 8 forbids interchanging them in *store* state, and this is
    /// harness bookkeeping outside the store, recorded here so a reader does
    /// not mistake it for the store conflating the two.
    fn ack_record(&self, seed: u64, shard_sequence: u64) -> AckRecord {
        AckRecord {
            repo_id: ObjectId(*namespace_for(seed).as_bytes()),
            operation_id: self.operation_id,
            operation_digest: object_id_for(
                "levcs-store-crash-driver/operation-digest/v1",
                seed,
                self.ordinal,
            ),
            receipt_digest: object_id_for(
                "levcs-store-crash-driver/receipt-digest/v1",
                seed,
                self.ordinal,
            ),
            repo_sequence: shard_sequence,
            blob_ids: vec![object_id_for(
                "levcs-store-crash-driver/blob/v1",
                seed,
                self.ordinal,
            )],
            tree_ids: vec![object_id_for(
                "levcs-store-crash-driver/tree/v1",
                seed,
                self.ordinal,
            )],
            commit_ids: vec![object_id_for(
                "levcs-store-crash-driver/commit/v1",
                seed,
                self.ordinal,
            )],
        }
    }
}

/// Byte offset at which a short write tears frame `victim` of a group.
///
/// Every frame in the scripted workload has the same payload length, so this
/// is exact arithmetic over the frozen `frame_total_len`, not a guess. Tearing
/// at the midpoint of the victim guarantees the trailer — the bytes that
/// certify the whole frame (scope 3.3) — is absent.
fn short_write_prefix_for(victim: usize) -> usize {
    let one = frame_total_len(SCRIPTED_PAYLOAD_LEN as u64) as usize;
    victim * one + one / 2
}

// ---------------------------------------------------------------------------
// Submission paths
// ---------------------------------------------------------------------------

/// Which API the scripted group goes through.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DrivePath {
    /// Wave A: the `store-internals` journal seam.
    Drive,
    /// Wave B: the production `StoreEngine::submit`.
    Submit,
}

impl DrivePath {
    fn parse(value: &str) -> Option<Self> {
        if value == "drive" {
            Some(DrivePath::Drive)
        } else if value == "submit" {
            Some(DrivePath::Submit)
        } else {
            None
        }
    }
}

/// The single call that differs between the two waves.
///
/// Everything around it — workload generation, arming, acknowledgment
/// journaling, and classification — is shared, which is what scope 4-A3
/// deliverable 1 means by "the two drive paths share one classifier; only the
/// submission call differs".
fn submit_group(
    path: DrivePath,
    drive: &mut ShardDrive,
    group: &[ScriptedTransaction],
    namespace: NamespaceId,
) -> Result<Vec<u64>, String> {
    match path {
        DrivePath::Drive => {
            let mut frames = Vec::with_capacity(group.len());
            for transaction in group {
                let frame = drive
                    .build_frame(
                        namespace,
                        transaction.repo_sequence,
                        transaction.payload.clone(),
                    )
                    .map_err(|e| format!("build_frame: {e}"))?;
                frames.push(frame);
            }
            drive
                .append_group_and_fence(&frames)
                .map_err(|e| format!("append_group_and_fence: {e}"))
        }
        DrivePath::Submit => Err(
            "submit path requires B1 engine.rs; levcs-store also has no async \
             executor dependency, which is an open interface request to the lead"
                .to_string(),
        ),
    }
}

// ---------------------------------------------------------------------------
// Arming
// ---------------------------------------------------------------------------

fn parse_action(value: &str) -> Option<FailpointAction> {
    if value == "continue" {
        Some(FailpointAction::Continue)
    } else if value == "fail" {
        Some(FailpointAction::Fail)
    } else if value == "panic" {
        Some(FailpointAction::Panic)
    } else if value == "hard-exit" {
        Some(FailpointAction::HardExit)
    } else {
        None
    }
}

/// Named physical faults, exactly the set scope 4-A3 deliverable 4 requires:
/// short write, `ENOSPC`, `EIO` on the fence, `EIO` on a positioned read, and
/// the unexpected-cursor condition that a short write plus a resumed append
/// produces. `dm-flakey` and power cuts are the reviewed root-only scripts of
/// plan §10 and belong to Phase 4/5; this is the userspace layer that lets the
/// matrix run unprivileged in CI.
fn parse_fault(value: &str, victim: usize) -> Result<Option<Fault>, String> {
    if value == "none" {
        return Ok(None);
    }
    if value == "short-write-tears-victim" {
        return Ok(Some(Fault::ShortWrite {
            prefix_bytes: short_write_prefix_for(victim),
        }));
    }
    if value == "no-space" {
        return Ok(Some(Fault::NoSpace));
    }
    if value == "fence-eio" {
        return Ok(Some(Fault::FenceEio));
    }
    if value == "read-eio" {
        return Ok(Some(Fault::ReadEio));
    }
    if value == "dir-sync-eio" {
        return Ok(Some(Fault::DirSyncEio));
    }
    if let Some(rest) = value.strip_prefix("short-write:") {
        let prefix_bytes = rest
            .parse::<usize>()
            .map_err(|_| format!("short-write: expects a byte count, got {rest:?}"))?;
        return Ok(Some(Fault::ShortWrite { prefix_bytes }));
    }
    Err(format!("unknown fault {value:?}"))
}

// ---------------------------------------------------------------------------
// Subcommand: append
// ---------------------------------------------------------------------------

struct AppendArgs {
    root: PathBuf,
    shard: u16,
    shard_count: u16,
    seed: u64,
    group_len: usize,
    /// Retained for the record even though the tear offset is computed in
    /// `parse_fault`: a campaign log that does not say which frame was the
    /// victim cannot be replayed.
    victim: usize,
    point: Option<Failpoint>,
    action: FailpointAction,
    fault: Option<Fault>,
    ack_journal: Option<PathBuf>,
    create: bool,
    path: DrivePath,
    /// Seal and install a manifest after the group is acknowledged.
    seal: bool,
    /// A fault armed immediately before that seal, so the seal/rotate/`CURRENT`
    /// ordering points of scope 3.4 and 3.5 can be attacked one at a time.
    seal_fault: Option<Fault>,
}

fn run_append(args: AppendArgs) -> ExitCode {
    let namespace = namespace_for(args.seed);
    let group: Vec<ScriptedTransaction> = (0..args.group_len as u64)
        .map(|ordinal| ScriptedTransaction::new(args.seed, ordinal))
        .collect();

    let mut drive = if args.create {
        match ShardDrive::create(&args.root, args.shard, args.shard_count) {
            Ok(drive) => drive,
            Err(error) => {
                eprintln!("store-crash-driver: create: {error}");
                return ExitCode::from(EX_DATAERR);
            }
        }
    } else {
        match ShardDrive::open_raw(&args.root, args.shard) {
            Ok(drive) => drive,
            Err(error) => {
                eprintln!("store-crash-driver: open_raw: {error}");
                return ExitCode::from(EX_DATAERR);
            }
        }
    };

    // Exclusive use of both registries, held for the rest of the run. This
    // process drives one shard on one thread, so the token is never contended
    // here — but `arm` requires it, and that is the point: the requirement is
    // what makes every arming site in the crate provably guarded rather than
    // guarded by whoever remembered.
    let serial = levcs_store::drive::faults::serial();

    // Arm last, immediately before the call under test, so nothing in setup
    // consumes the one-shot arming.
    if let Some(fault) = args.fault {
        levcs_store::drive::faults::arm(&serial, fault);
    }
    if let Some(point) = args.point {
        levcs_store::drive::points::arm(&serial, point, args.action);
    }

    println!("driver_schema=1");
    println!("driver_phase=submitting");
    println!("victim_frame={}", args.victim);
    println!("group_len={}", args.group_len);

    match submit_group(args.path, &mut drive, &group, namespace) {
        Ok(sequences) => {
            // The fence returned. Acknowledgment is permitted only after the
            // acknowledgment is itself durable, so the ACK journal append and
            // its own fence happen here, before anything counts the operation
            // (scope 4-A3 deliverable 5).
            if let Some(ack_path) = args.ack_journal.as_ref() {
                if let Err(error) = journal_acks(ack_path, args.seed, &group, &sequences) {
                    eprintln!("store-crash-driver: ack journal: {error}");
                    return ExitCode::from(EX_SOFTWARE);
                }
            }
            let rendered: Vec<String> = sequences.iter().map(|s| s.to_string()).collect();
            println!("driver_phase=acknowledged");
            println!("appended_sequences={}", rendered.join(","));
            println!("acknowledged_count={}", sequences.len());

            // Sealing after acknowledgment is where a directory-fsync failure
            // matters: the frames are already durable and already promised, so
            // a seal that fails must not be able to unmake either.
            if args.seal {
                if let Some(fault) = args.seal_fault {
                    levcs_store::drive::faults::arm(&serial, fault);
                }
                match drive.seal_and_install() {
                    Ok(generation) => println!("sealed_generation={generation}"),
                    Err(error) => {
                        eprintln!("store-crash-driver: seal: {error}");
                        println!("driver_phase=seal_failed");
                        return ExitCode::from(EX_DATAERR);
                    }
                }
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("store-crash-driver: {error}");
            println!("driver_phase=failed");
            ExitCode::from(EX_DATAERR)
        }
    }
}

fn journal_acks(
    path: &Path,
    seed: u64,
    group: &[ScriptedTransaction],
    sequences: &[u64],
) -> Result<(), String> {
    if sequences.len() != group.len() {
        return Err(format!(
            "the writer reported {} sequences for a group of {}",
            sequences.len(),
            group.len()
        ));
    }
    let mut journal = ExternalAckJournal::open(path).map_err(|e| e.to_string())?;
    for (transaction, sequence) in group.iter().zip(sequences.iter()) {
        journal
            .append_durable(&transaction.ack_record(seed, *sequence))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommand: damage — deterministic physical crash-image generators
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DamageKind {
    SealedFrameCorruption,
    CrossShardJournalMovement,
}

impl DamageKind {
    fn parse(value: &str) -> Option<Self> {
        if value == "sealed-frame-corruption" {
            Some(Self::SealedFrameCorruption)
        } else if value == "cross-shard-journal-movement" {
            Some(Self::CrossShardJournalMovement)
        } else {
            None
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::SealedFrameCorruption => "sealed-frame-corruption",
            Self::CrossShardJournalMovement => "cross-shard-journal-movement",
        }
    }
}

struct DamageArgs {
    root: PathBuf,
    kind: DamageKind,
    shard: u16,
    source_shard: u16,
    destination_shard: u16,
}

/// Return the only file with `extension` under `directory`.
///
/// These generators deliberately require an unambiguous source image. Picking
/// an arbitrary segment or journal from a larger store would make a passing
/// campaign depend on directory iteration order and could mutate an
/// unreferenced artifact instead of the production authority.
fn only_file_with_extension(directory: &Path, extension: &str) -> Result<PathBuf, String> {
    let mut matches = Vec::new();
    let entries =
        fs::read_dir(directory).map_err(|e| format!("reading {}: {e}", directory.display()))?;
    for entry in entries {
        let path = entry
            .map_err(|e| format!("reading an entry under {}: {e}", directory.display()))?
            .path();
        if path
            .extension()
            .is_some_and(|candidate| candidate == extension)
        {
            matches.push(path);
        }
    }
    matches.sort();
    if matches.len() != 1 {
        return Err(format!(
            "{} must contain exactly one .{extension} file, found {}",
            directory.display(),
            matches.len()
        ));
    }
    Ok(matches.pop().expect("length checked"))
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|e| format!("syncing directory {}: {e}", path.display()))
}

fn run_damage(args: DamageArgs) -> ExitCode {
    println!("damage_schema=1");
    println!("damage_kind={}", args.kind.name());

    let result = match args.kind {
        DamageKind::SealedFrameCorruption => damage_sealed_frame(&args.root, args.shard),
        DamageKind::CrossShardJournalMovement => {
            damage_cross_shard_journal(&args.root, args.source_shard, args.destination_shard)
        }
    };

    match result {
        Ok(path) => {
            println!("damage_phase=complete");
            println!("damaged_path={}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("damage_phase=failed");
            eprintln!("store-crash-driver: damage: {error}");
            ExitCode::from(EX_DATAERR)
        }
    }
}

/// Flip one byte in the first sealed frame's payload and fence the mutation.
///
/// The source must be a real segment created by `ShardDrive::seal_and_install`;
/// the generator does not synthesize a footer, frame, manifest, or checksum.
/// The changed byte lies after both the journal and frame headers, so the
/// segment footer remains structurally valid while production frame
/// verification must reject the referenced authority.
fn damage_sealed_frame(root: &Path, shard: u16) -> Result<PathBuf, String> {
    let segments = root
        .join("shards")
        .join(format!("{shard:02}"))
        .join("segments");
    let segment = only_file_with_extension(&segments, "seg")?;
    let offset = (JOURNAL_HEADER_LEN + FRAME_HEADER_LEN) as u64;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&segment)
        .map_err(|e| format!("opening {}: {e}", segment.display()))?;
    if file
        .metadata()
        .map_err(|e| format!("stat {}: {e}", segment.display()))?
        .len()
        <= offset
    {
        return Err(format!(
            "{} has no first-frame payload byte at offset {offset}",
            segment.display()
        ));
    }
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("seeking {}: {e}", segment.display()))?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)
        .map_err(|e| format!("reading {}: {e}", segment.display()))?;
    byte[0] ^= 0x80;
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| format!("seeking {}: {e}", segment.display()))?;
    file.write_all(&byte)
        .map_err(|e| format!("writing {}: {e}", segment.display()))?;
    file.sync_data()
        .map_err(|e| format!("fencing {}: {e}", segment.display()))?;
    sync_directory(&segments)?;
    Ok(segment)
}

/// Move the only active journal from one shard directory into another.
///
/// This reproduces the Wave A review's same-root cross-shard image. A footer
/// cannot detect it: the journal header's `shard_index` is the authority, and
/// production recovery must bind that value to the directory it is opening.
fn damage_cross_shard_journal(
    root: &Path,
    source_shard: u16,
    destination_shard: u16,
) -> Result<PathBuf, String> {
    if source_shard == destination_shard {
        return Err("source and destination shards must differ".to_string());
    }
    let shards = root.join("shards");
    let source_dir = shards.join(format!("{source_shard:02}")).join("active");
    let destination_dir = shards
        .join(format!("{destination_shard:02}"))
        .join("active");
    let source = only_file_with_extension(&source_dir, "journal")?;
    let name = source
        .file_name()
        .ok_or_else(|| format!("{} has no file name", source.display()))?;
    let destination = destination_dir.join(name);
    if destination.exists() {
        return Err(format!(
            "destination {} is already occupied",
            destination.display()
        ));
    }
    fs::rename(&source, &destination).map_err(|e| {
        format!(
            "moving {} to {}: {e}",
            source.display(),
            destination.display()
        )
    })?;
    sync_directory(&source_dir)?;
    sync_directory(&destination_dir)?;
    Ok(destination)
}

// ---------------------------------------------------------------------------
// Subcommand: soak
// ---------------------------------------------------------------------------

struct SoakArgs {
    root: PathBuf,
    shard: u16,
    shard_count: u16,
    seed: u64,
    group_len: usize,
    ack_journal: PathBuf,
    max_groups: u64,
    path: DrivePath,
}

/// Append groups until something kills the process.
///
/// This is what `scripts/verify-store-recovery.sh` drives for its randomized
/// `SIGKILL` cycles. There is no failpoint and no injected fault: the fault is
/// the signal, and the property under test is that every acknowledgment
/// already in the external journal survives.
fn run_soak(args: SoakArgs) -> ExitCode {
    let namespace = namespace_for(args.seed);

    let mut drive = match ShardDrive::create(&args.root, args.shard, args.shard_count) {
        Ok(drive) => drive,
        Err(_) => match ShardDrive::open_raw(&args.root, args.shard) {
            Ok(drive) => drive,
            Err(error) => {
                eprintln!("store-crash-driver: soak open: {error}");
                return ExitCode::from(EX_DATAERR);
            }
        },
    };

    let mut journal = match ExternalAckJournal::open(&args.ack_journal) {
        Ok(journal) => journal,
        Err(error) => {
            eprintln!("store-crash-driver: soak ack journal: {error}");
            return ExitCode::from(EX_SOFTWARE);
        }
    };

    println!("driver_schema=1");
    println!("driver_phase=soaking");

    let group_bytes = frame_total_len(SCRIPTED_PAYLOAD_LEN as u64) * args.group_len as u64;
    let mut journal_bytes = JOURNAL_HEADER_LEN as u64;

    let mut ordinal = 0u64;
    let mut groups = 0u64;
    while groups < args.max_groups {
        // Rotate rather than stop. A soak that ran out of journal after three
        // seconds would only ever be killed during an append, and the
        // randomized cycles would never sample a kill during a seal or a
        // manifest install — which are the ordering points scope 5 charter
        // item 5 says to attack.
        if journal_bytes + group_bytes > DRIVE_PREALLOCATE_BYTES {
            if let Err(error) = drive.seal_and_install() {
                eprintln!("store-crash-driver: soak seal: {error}");
                return ExitCode::from(EX_DATAERR);
            }
            journal_bytes = JOURNAL_HEADER_LEN as u64;
        }
        journal_bytes += group_bytes;

        let group: Vec<ScriptedTransaction> = (0..args.group_len as u64)
            .map(|offset| ScriptedTransaction::new(args.seed, ordinal + offset))
            .collect();
        let sequences = match submit_group(args.path, &mut drive, &group, namespace) {
            Ok(sequences) => sequences,
            Err(error) => {
                eprintln!("store-crash-driver: soak submit: {error}");
                return ExitCode::from(EX_DATAERR);
            }
        };
        for (transaction, sequence) in group.iter().zip(sequences.iter()) {
            if let Err(error) =
                journal.append_durable(&transaction.ack_record(args.seed, *sequence))
            {
                eprintln!("store-crash-driver: soak ack: {error}");
                return ExitCode::from(EX_SOFTWARE);
            }
        }
        ordinal += args.group_len as u64;
        groups += 1;
    }
    println!("driver_phase=soak_complete");
    println!("soak_groups={groups}");
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Subcommand: reconcile — the shared classifier
// ---------------------------------------------------------------------------

struct ReconcileArgs {
    root: PathBuf,
    shard: u16,
    ack_journal: Option<PathBuf>,
    /// A fault armed immediately before production recovery runs.
    ///
    /// `Fault::ReadEio` is the one that matters: the frozen profile has
    /// `write_cache = enabled` and `power_loss_protection = false`, so the
    /// device can return `EIO` for a write it acknowledged. Scope 3.8 step 5
    /// requires recovery to treat that as "the tail ends here", never as a
    /// fatal store error — getting it wrong turns an ordinary crash into an
    /// unopenable store. Arming it in *this* process rather than the writer's
    /// is not a detail: the fault registry is process-global, and recovery
    /// runs here.
    fault: Option<Fault>,
}

/// What recovery concluded, plus the external reconciliation.
///
/// `acknowledged_loss` is the only detector for a device that lost a *fenced*
/// write (scope 3.8). Recovery cannot distinguish that from an unfenced tail
/// by inspection — nothing on the device says so. A non-zero value here is a
/// hardware finding that invalidates the run; it is never a store bug to
/// tolerate, and the harness must not "handle" it.
fn run_reconcile(args: ReconcileArgs) -> ExitCode {
    println!("reconcile_schema=1");
    println!("shard={}", args.shard);

    // Same token, same reason as `run_append`. Armed before the reopen because
    // that is the call under test here, and nothing in this function reads the
    // funnel ahead of it that could consume the one-shot arming.
    let serial = levcs_store::drive::faults::serial();
    if let Some(fault) = args.fault {
        levcs_store::drive::faults::arm(&serial, fault);
    }

    let recovery: DriveRecovery = match ShardDrive::reopen_through_recovery(&args.root, args.shard)
    {
        Ok(recovery) => recovery,
        Err(error) => {
            println!("recovery_ok=false");
            println!("recovery_error={error}");
            eprintln!("store-crash-driver: recovery: {error}");
            return ExitCode::from(EX_DATAERR);
        }
    };
    println!("recovery_ok=true");

    let adopted = recovery.adopted_shard_sequences.clone();
    let rendered: Vec<String> = adopted.iter().map(|s| s.to_string()).collect();
    println!("adopted_count={}", adopted.len());
    println!("adopted_sequences={}", rendered.join(","));
    match recovery.tail_stop_offset {
        Some(offset) => println!("tail_stop_offset={offset}"),
        None => println!("tail_stop_offset=none"),
    }
    println!("quarantined_bytes={}", recovery.quarantined_bytes);
    println!("used_manifest_fallback={}", recovery.used_manifest_fallback);

    // The adopted set must be a strictly increasing contiguous run. Checking
    // only for forward gaps — the defect this replaces — accepts
    // `0,1,2,3,0,1,2,3` and calls it a contiguous prefix.
    //
    // The three faults are reported apart because they are different findings.
    // A hole means recovery adopted a frame sitting after an incomplete one,
    // which recovery step 6 forbids unconditionally; it is published as
    // `torn_transactions` because what it publishes is a group whose frames are
    // neither wholly present nor wholly absent. A duplicate or a regression
    // means the same frames were adopted twice, which is a different bug — a
    // segment counted alongside the journal that supersedes it, say — and
    // folding it into `torn_transactions` would misname it.
    let sequences = classify_adopted_set(&adopted);
    println!("torn_transactions={}", sequences.missing_sequences);
    println!("adopted_forward_gaps={}", sequences.forward_gaps);
    println!("adopted_duplicates={}", sequences.duplicates);
    println!("adopted_regressions={}", sequences.regressions);
    println!("prefix_contiguous={}", sequences.is_strictly_contiguous());
    match &sequences.first_fault {
        Some(fault) => println!("first_sequence_fault={fault:?}"),
        None => println!("first_sequence_fault=none"),
    }

    let mut acknowledged_loss = 0u64;
    if let Some(ack_path) = args.ack_journal.as_ref() {
        match ExternalAckJournal::recover(ack_path) {
            Ok(records) => {
                let ack_records = records.len() as u64;
                let adopted_set: std::collections::BTreeSet<u64> =
                    adopted.iter().copied().collect();
                let mut lost = Vec::new();
                for record in &records {
                    if !adopted_set.contains(&record.repo_sequence) {
                        acknowledged_loss += 1;
                        lost.push(record.repo_sequence.to_string());
                    }
                }
                println!("ack_records={ack_records}");
                println!("acknowledged_loss={acknowledged_loss}");
                println!("lost_sequences={}", lost.join(","));
            }
            Err(error) => {
                println!("ack_records=0");
                println!("ack_journal_error={error}");
                eprintln!("store-crash-driver: ack journal: {error}");
                return ExitCode::from(EX_SOFTWARE);
            }
        }
    } else {
        println!("ack_records=0");
        println!("acknowledged_loss=0");
        println!("lost_sequences=");
    }

    if acknowledged_loss != 0 {
        eprintln!(
            "store-crash-driver: {acknowledged_loss} acknowledged operation(s) are absent from \
             the recovered store. Per scope 3.8 this is a hardware finding that invalidates the \
             run, not a store bug to tolerate."
        );
        return ExitCode::from(EX_DATAERR);
    }
    if sequences.forward_gaps != 0 {
        eprintln!(
            "store-crash-driver: recovery adopted a frame past a hole ({:?}); recovery step 6 \
             forbids it",
            sequences.first_fault
        );
        return ExitCode::from(EX_DATAERR);
    }
    if sequences.repeated_adoptions() != 0 {
        eprintln!(
            "store-crash-driver: recovery adopted the same sequence twice ({:?}); the adopted set \
             must be strictly increasing, and a repeat means a frame was counted twice rather \
             than a group torn once",
            sequences.first_fault
        );
        return ExitCode::from(EX_DATAERR);
    }
    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

struct Args {
    subcommand: String,
    values: Vec<(String, String)>,
}

impl Args {
    fn parse(mut raw: impl Iterator<Item = String>) -> Result<Self, String> {
        let subcommand = raw.next().ok_or_else(|| "missing subcommand".to_string())?;
        let mut values = Vec::new();
        while let Some(flag) = raw.next() {
            let name = flag
                .strip_prefix("--")
                .ok_or_else(|| format!("expected a --flag, got {flag:?}"))?
                .to_string();
            if name == "create" || name == "seal" {
                values.push((name, "true".to_string()));
                continue;
            }
            let value = raw
                .next()
                .ok_or_else(|| format!("--{name} requires a value"))?;
            values.push((name, value));
        }
        Ok(Self { subcommand, values })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn required(&self, name: &str) -> Result<&str, String> {
        self.get(name)
            .ok_or_else(|| format!("--{name} is required"))
    }

    fn parsed<T: std::str::FromStr>(&self, name: &str, default: T) -> Result<T, String> {
        match self.get(name) {
            Some(value) => value
                .parse::<T>()
                .map_err(|_| format!("--{name} has an invalid value {value:?}")),
            None => Ok(default),
        }
    }
}

const USAGE: &str = "\
store-crash-driver <append|damage|soak|reconcile> [flags]

  append     --root P --shard N [--shard-count N] [--create] --seed U64
             --group-len N [--victim N] [--point NAME] [--action ACTION]
             [--fault FAULT] [--ack-journal P] [--path drive|submit]
             [--seal] [--seal-fault FAULT]
  damage     --root P --kind sealed-frame-corruption [--shard N]
  damage     --root P --kind cross-shard-journal-movement
             [--source-shard N] [--destination-shard N]
  soak       --root P --shard N [--shard-count N] --seed U64 --group-len N
             --ack-journal P [--max-groups N] [--path drive|submit]
  reconcile  --root P --shard N [--ack-journal P] [--fault FAULT]

  ACTION  continue | fail | panic | hard-exit
  FAULT   none | short-write-tears-victim | short-write:BYTES | no-space
          | fence-eio | read-eio | dir-sync-eio
";

fn main() -> ExitCode {
    let args = match Args::parse(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("store-crash-driver: {error}\n\n{USAGE}");
            return ExitCode::from(EX_USAGE);
        }
    };

    match dispatch(&args) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("store-crash-driver: {error}\n\n{USAGE}");
            ExitCode::from(EX_USAGE)
        }
    }
}

fn dispatch(args: &Args) -> Result<ExitCode, String> {
    if args.subcommand == "append" {
        let victim = args.parsed::<usize>("victim", 0)?;
        let point = match args.get("point") {
            Some(name) => Some(
                Failpoint::from_name(name).ok_or_else(|| format!("unknown failpoint {name:?}"))?,
            ),
            None => None,
        };
        let action = match args.get("action") {
            Some(value) => {
                parse_action(value).ok_or_else(|| format!("unknown action {value:?}"))?
            }
            None => FailpointAction::HardExit,
        };
        let fault = parse_fault(args.get("fault").unwrap_or("none"), victim)?;
        let path = DrivePath::parse(args.get("path").unwrap_or("drive"))
            .ok_or_else(|| "--path must be drive or submit".to_string())?;
        return Ok(run_append(AppendArgs {
            root: PathBuf::from(args.required("root")?),
            shard: args.parsed::<u16>("shard", 0)?,
            shard_count: args.parsed::<u16>("shard-count", 1)?,
            seed: args.parsed::<u64>("seed", 0)?,
            group_len: args.parsed::<usize>("group-len", 1)?,
            victim,
            point,
            action,
            fault,
            ack_journal: args.get("ack-journal").map(PathBuf::from),
            create: args.get("create").is_some(),
            path,
            seal: args.get("seal").is_some(),
            seal_fault: parse_fault(args.get("seal-fault").unwrap_or("none"), victim)?,
        }));
    }

    if args.subcommand == "soak" {
        let path = DrivePath::parse(args.get("path").unwrap_or("drive"))
            .ok_or_else(|| "--path must be drive or submit".to_string())?;
        return Ok(run_soak(SoakArgs {
            root: PathBuf::from(args.required("root")?),
            shard: args.parsed::<u16>("shard", 0)?,
            shard_count: args.parsed::<u16>("shard-count", 1)?,
            seed: args.parsed::<u64>("seed", 0)?,
            group_len: args.parsed::<usize>("group-len", 8)?,
            ack_journal: PathBuf::from(args.required("ack-journal")?),
            max_groups: args.parsed::<u64>("max-groups", u64::MAX)?,
            path,
        }));
    }

    if args.subcommand == "damage" {
        let kind_name = args.required("kind")?;
        let kind = DamageKind::parse(kind_name)
            .ok_or_else(|| format!("unknown damage kind {kind_name:?}"))?;
        return Ok(run_damage(DamageArgs {
            root: PathBuf::from(args.required("root")?),
            kind,
            shard: args.parsed::<u16>("shard", 0)?,
            source_shard: args.parsed::<u16>("source-shard", 1)?,
            destination_shard: args.parsed::<u16>("destination-shard", 0)?,
        }));
    }

    if args.subcommand == "reconcile" {
        return Ok(run_reconcile(ReconcileArgs {
            root: PathBuf::from(args.required("root")?),
            shard: args.parsed::<u16>("shard", 0)?,
            ack_journal: args.get("ack-journal").map(PathBuf::from),
            fault: parse_fault(args.get("fault").unwrap_or("none"), 0)?,
        }));
    }

    Err(format!("unknown subcommand {:?}", args.subcommand))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scripted_transactions_are_a_pure_function_of_seed_and_ordinal() {
        let a = ScriptedTransaction::new(7, 3);
        let b = ScriptedTransaction::new(7, 3);
        assert_eq!(a.operation_id, b.operation_id);
        assert_eq!(a.payload, b.payload);
        assert_eq!(a.repo_sequence, b.repo_sequence);

        let other = ScriptedTransaction::new(8, 3);
        assert_ne!(
            a.payload, other.payload,
            "a different seed must give a different workload, or two campaigns \
             would share a corpus"
        );
    }

    #[test]
    fn the_ack_record_is_canonical_and_round_trips() {
        let transaction = ScriptedTransaction::new(11, 0);
        let record = transaction.ack_record(11, 42);
        assert_eq!(record.repo_sequence, 42);
        // `ExternalAckJournal` rejects a record whose triplets are not unique
        // or whose counts disagree; encoding proves this one is canonical.
        ExternalAckJournal::encoded_record_len(&record).expect("record must be canonical");
    }

    #[test]
    fn the_short_write_tears_the_victim_frame_and_leaves_earlier_frames_whole() {
        let one = frame_total_len(SCRIPTED_PAYLOAD_LEN as u64) as usize;
        for victim in 0..8 {
            let prefix = short_write_prefix_for(victim);
            assert_eq!(
                prefix / one,
                victim,
                "the truncation must land inside frame {victim}"
            );
            assert!(
                prefix % one > 0 && prefix % one < one,
                "the victim must be genuinely partial, never absent and never whole"
            );
            assert!(
                prefix % one < one - 48,
                "the tear must remove the 48-byte trailer, which is what makes \
                 the frame incomplete under scope 3.3 condition 4"
            );
        }
    }

    #[test]
    fn every_named_fault_parses_and_an_unknown_one_is_refused() {
        for name in [
            "none",
            "short-write-tears-victim",
            "no-space",
            "fence-eio",
            "read-eio",
            "dir-sync-eio",
            "short-write:17",
        ] {
            parse_fault(name, 0).unwrap_or_else(|e| panic!("{name} must parse: {e}"));
        }
        assert!(parse_fault("dm-flakey", 0).is_err());
    }

    #[test]
    fn every_failpoint_action_parses_by_name() {
        assert_eq!(parse_action("continue"), Some(FailpointAction::Continue));
        assert_eq!(parse_action("fail"), Some(FailpointAction::Fail));
        assert_eq!(parse_action("panic"), Some(FailpointAction::Panic));
        assert_eq!(parse_action("hard-exit"), Some(FailpointAction::HardExit));
        assert_eq!(parse_action("explode"), None);
    }

    #[test]
    fn argument_parsing_refuses_a_bare_positional_and_a_dangling_flag() {
        let owned = |values: &[&str]| values.iter().map(|v| v.to_string()).collect::<Vec<_>>();
        assert!(Args::parse(owned(&["append", "root"]).into_iter()).is_err());
        assert!(Args::parse(owned(&["append", "--root"]).into_iter()).is_err());
        let args = Args::parse(owned(&["append", "--root", "/tmp/x", "--create"]).into_iter())
            .expect("valid");
        assert_eq!(args.get("root"), Some("/tmp/x"));
        assert_eq!(args.get("create"), Some("true"));
    }
}
