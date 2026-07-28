//! Phase-0 durability and visibility reference oracles.
//!
//! These are deliberately small models, not the Phase-1 store. They freeze
//! the externally observable answer at every append-through-response
//! failpoint and provide the fault harness with an independently durable ACK
//! journal.

use std::collections::{BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use levcs_core::ObjectId;
use thiserror::Error;

use crate::v2::{status_tombstone_until, CommitReceiptV1, OperationId, TransactionStatusV1};

/// Small reference model for the plan §7 stage-3 replay guard: a
/// `(public_key, nonce)` reservation with a checked expiry of at least
/// `issued_at_micros + clock_skew_micros + timer_resolution_micros`.
/// Eviction before that instant is forbidden — this oracle only ever evicts
/// entries whose expiry has already passed.
#[derive(Default)]
pub struct ReplayGuardOracle {
    reserved: HashMap<([u8; 32], [u8; 16]), i64>,
}

impl ReplayGuardOracle {
    pub fn new() -> Self {
        Self::default()
    }

    fn evict_expired(&mut self, now_micros: i64) {
        self.reserved
            .retain(|_, expires_at| *expires_at > now_micros);
    }

    /// Attempts to reserve `(public_key, nonce)`. Returns `true` on a fresh
    /// reservation and `false` if the nonce is still live (a replay).
    pub fn reserve(
        &mut self,
        public_key: [u8; 32],
        nonce: [u8; 16],
        issued_at_micros: i64,
        clock_skew_micros: i64,
        timer_resolution_micros: i64,
        now_micros: i64,
    ) -> bool {
        self.evict_expired(now_micros);
        let expires_at = match issued_at_micros
            .checked_add(clock_skew_micros)
            .and_then(|value| value.checked_add(timer_resolution_micros))
        {
            Some(value) => value,
            None => return false,
        };
        if self.reserved.contains_key(&(public_key, nonce)) {
            return false;
        }
        self.reserved.insert((public_key, nonce), expires_at);
        true
    }

    pub fn live_count(&self) -> usize {
        self.reserved.len()
    }
}

const ACK_MAGIC: &[u8; 4] = b"LVAK";
const ACK_VERSION: u32 = 1;
const ACK_FIXED_PAYLOAD_LEN: usize = 32 + 16 + 32 + 32 + 8 + 4;
const ACK_COMMIT_IDS_LEN: usize = 32 * 3;
pub const ACK_MAX_COMMITS: usize = 64;
const ACK_MAX_PAYLOAD_LEN: usize = ACK_FIXED_PAYLOAD_LEN + ACK_MAX_COMMITS * ACK_COMMIT_IDS_LEN;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AppendFailpoint {
    BeforeAppend,
    AfterMarkedResolving,
    DuringFrameWriteTorn,
    AfterFrameWrite,
    EvidenceHandoffFailure,
    BeforeFence,
    FenceFailed,
    FenceAmbiguous,
    AfterSuccessfulFence,
    DuringCommittedRootBuild,
    AllocationFailureBeforePublication,
    BeforeRootCas,
    DuringRootCasRetry,
    WriterPanicBeforeFence,
    WriterPanicAfterFence,
    AfterRootCasBeforeWaiterWake,
    BeforeResponse,
}

pub const APPEND_PUBLICATION_FAILPOINTS: &[AppendFailpoint] = &[
    AppendFailpoint::BeforeAppend,
    AppendFailpoint::AfterMarkedResolving,
    AppendFailpoint::DuringFrameWriteTorn,
    AppendFailpoint::AfterFrameWrite,
    AppendFailpoint::EvidenceHandoffFailure,
    AppendFailpoint::BeforeFence,
    AppendFailpoint::FenceFailed,
    AppendFailpoint::FenceAmbiguous,
    AppendFailpoint::AfterSuccessfulFence,
    AppendFailpoint::DuringCommittedRootBuild,
    AppendFailpoint::AllocationFailureBeforePublication,
    AppendFailpoint::BeforeRootCas,
    AppendFailpoint::DuringRootCasRetry,
    AppendFailpoint::WriterPanicBeforeFence,
    AppendFailpoint::WriterPanicAfterFence,
    AppendFailpoint::AfterRootCasBeforeWaiterWake,
    AppendFailpoint::BeforeResponse,
];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecoveryOutcome {
    AbsentRetriable,
    Committed,
    /// Pre-fence/ambiguous durability is resolved solely by production tail
    /// recovery: a complete valid frame commits; an absent/torn frame does
    /// not. Torn publication is never an allowed outcome.
    EitherWhole,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ImmediateStatus {
    DefinitiveAbsent,
    Resolving,
    Committed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailpointExpectation {
    pub shard_poisoned: bool,
    pub immediate_status: ImmediateStatus,
    pub recovery_outcome: RecoveryOutcome,
    pub acknowledgment_allowed: bool,
    pub later_append_allowed_before_recovery: bool,
}

pub fn append_publication_expectation(point: AppendFailpoint) -> FailpointExpectation {
    use AppendFailpoint::*;
    match point {
        // `EvidenceHandoffFailure` joined this row in contract review
        // 2026-07-26-A. It fires while the sequencer is handing a transaction
        // to the evidence signer — before the group is marked `Resolving` and
        // before any byte is written — so the physical state is `NoBytes` and
        // nothing about the outcome is ambiguous. The original grouping with
        // `AfterMarkedResolving` made a routine `SignerError::Unavailable`
        // poison the shard, taking a whole shard out of service until recovery
        // for a restarting signer and no storage fault at all. Plan §7 governs:
        // a failure before append removes the transient reservation, releases
        // or revalidates the speculative suffix, and wakes every waiter with
        // the error; no durable status reservation is created.
        BeforeAppend | EvidenceHandoffFailure => FailpointExpectation {
            shard_poisoned: false,
            immediate_status: ImmediateStatus::DefinitiveAbsent,
            recovery_outcome: RecoveryOutcome::AbsentRetriable,
            acknowledgment_allowed: false,
            later_append_allowed_before_recovery: true,
        },
        AfterMarkedResolving | DuringFrameWriteTorn => FailpointExpectation {
            shard_poisoned: true,
            immediate_status: ImmediateStatus::Resolving,
            recovery_outcome: RecoveryOutcome::AbsentRetriable,
            acknowledgment_allowed: false,
            later_append_allowed_before_recovery: false,
        },
        // These four all leave a complete, checksum-valid frame written to
        // the device with the fence outcome undetermined (unfenced, failed,
        // ambiguous, or a panic racing the fence call): whether it actually
        // reached durable storage is exactly what production recovery must
        // decide, never something the pre-recovery caller can assume either
        // way.
        AfterFrameWrite | BeforeFence | FenceFailed | FenceAmbiguous | WriterPanicBeforeFence => {
            FailpointExpectation {
                shard_poisoned: true,
                immediate_status: ImmediateStatus::Resolving,
                recovery_outcome: RecoveryOutcome::EitherWhole,
                acknowledgment_allowed: false,
                later_append_allowed_before_recovery: false,
            }
        }
        AfterSuccessfulFence
        | DuringCommittedRootBuild
        | AllocationFailureBeforePublication
        | BeforeRootCas
        | DuringRootCasRetry
        | WriterPanicAfterFence => FailpointExpectation {
            shard_poisoned: true,
            immediate_status: ImmediateStatus::Resolving,
            recovery_outcome: RecoveryOutcome::Committed,
            acknowledgment_allowed: false,
            later_append_allowed_before_recovery: false,
        },
        AfterRootCasBeforeWaiterWake | BeforeResponse => FailpointExpectation {
            shard_poisoned: false,
            immediate_status: ImmediateStatus::Committed,
            recovery_outcome: RecoveryOutcome::Committed,
            acknowledgment_allowed: true,
            later_append_allowed_before_recovery: true,
        },
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecoveredTailFact {
    AbsentOrTorn,
    CompleteChecksumValid,
}

pub const fn resolve_ambiguous_tail(fact: RecoveredTailFact) -> RecoveryOutcome {
    match fact {
        RecoveredTailFact::AbsentOrTorn => RecoveryOutcome::AbsentRetriable,
        RecoveredTailFact::CompleteChecksumValid => RecoveryOutcome::Committed,
    }
}

/// Store-level two-root status read. The second committed read is mandatory
/// after an empty status-root read and closes the torn-read race.
pub fn two_root_status_read(
    committed_a: Option<TransactionStatusV1>,
    status_root: Option<TransactionStatusV1>,
    committed_b: Option<TransactionStatusV1>,
) -> TransactionStatusV1 {
    if let Some(status) = committed_a {
        return status;
    }
    if let Some(status) = status_root {
        return status;
    }
    committed_b.unwrap_or(TransactionStatusV1::Unknown)
}

/// Public status precedence: durable store state is checked before and after
/// the pre-store registry. A stale registry entry can never mask a receipt.
pub fn public_status_read(
    first_store: TransactionStatusV1,
    registry: Option<TransactionStatusV1>,
    second_store: TransactionStatusV1,
) -> TransactionStatusV1 {
    if first_store != TransactionStatusV1::Unknown {
        return first_store;
    }
    if second_store != TransactionStatusV1::Unknown {
        return second_store;
    }
    registry.unwrap_or(TransactionStatusV1::Unknown)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CoalescingDecision {
    BecomeLeader,
    AttachToLeader,
    ReturnDurable(TransactionStatusV1),
    OperationIdMismatch,
}

/// Durable state has precedence over the pre-store registry. While either
/// record exists, the operation ID is bound to exactly one stable digest.
pub fn coalescing_decision(
    durable: TransactionStatusV1,
    registry_digest: Option<ObjectId>,
    incoming_digest: ObjectId,
) -> CoalescingDecision {
    if let Some(durable_digest) = durable.operation_digest() {
        return if durable_digest == incoming_digest {
            CoalescingDecision::ReturnDurable(durable)
        } else {
            CoalescingDecision::OperationIdMismatch
        };
    }
    match registry_digest {
        Some(existing) if existing == incoming_digest => CoalescingDecision::AttachToLeader,
        Some(_) => CoalescingDecision::OperationIdMismatch,
        None => CoalescingDecision::BecomeLeader,
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AppendDeadlinePhase {
    PreAppend,
    AppendStarted,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeadlineDecision {
    ContinuePreAppend,
    RejectReceiptExpired,
    RemainResolving,
}

/// The signed deadline is checked immediately before append. Once append
/// starts, resolution—not the wall clock—controls the operation outcome.
pub const fn deadline_decision(
    now_micros: i64,
    retry_until_micros: i64,
    phase: AppendDeadlinePhase,
) -> DeadlineDecision {
    match phase {
        AppendDeadlinePhase::PreAppend if now_micros > retry_until_micros => {
            DeadlineDecision::RejectReceiptExpired
        }
        AppendDeadlinePhase::PreAppend => DeadlineDecision::ContinuePreAppend,
        AppendDeadlinePhase::AppendStarted => DeadlineDecision::RemainResolving,
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DeadlineExpectation {
    pub decision: DeadlineDecision,
    pub append_allowed: bool,
    pub reservation_retained: bool,
    pub durable_status_created: bool,
}

pub const fn deadline_expectation(
    now_micros: i64,
    retry_until_micros: i64,
    phase: AppendDeadlinePhase,
) -> DeadlineExpectation {
    let decision = deadline_decision(now_micros, retry_until_micros, phase);
    match decision {
        DeadlineDecision::ContinuePreAppend => DeadlineExpectation {
            decision,
            append_allowed: true,
            reservation_retained: true,
            durable_status_created: false,
        },
        DeadlineDecision::RejectReceiptExpired => DeadlineExpectation {
            decision,
            append_allowed: false,
            reservation_retained: false,
            durable_status_created: false,
        },
        DeadlineDecision::RemainResolving => DeadlineExpectation {
            decision,
            append_allowed: false,
            reservation_retained: true,
            durable_status_created: true,
        },
    }
}

pub fn retained_terminal_status(
    receipt: &CommitReceiptV1,
    now_micros: i64,
    status_tombstone_grace_micros: i64,
) -> Result<TransactionStatusV1, crate::v2::V2ValidationError> {
    if now_micros <= receipt.receipt_visible_until_micros {
        return Ok(TransactionStatusV1::Committed(receipt.clone()));
    }
    let tombstone_until = status_tombstone_until(
        receipt.receipt_visible_until_micros,
        status_tombstone_grace_micros,
    )?;
    if now_micros <= tombstone_until {
        return Ok(TransactionStatusV1::Expired {
            operation_digest: receipt.operation_digest,
            retry_until_micros: receipt.retry_until_micros,
            tombstone_until_micros: tombstone_until,
        });
    }
    Ok(TransactionStatusV1::Unknown)
}

pub fn recovered_receipt_visibility(
    retry_until_micros: i64,
    checkpointed_first_visible_at_micros: Option<i64>,
    recovery_publication_micros: i64,
    terminal_status_grace_micros: i64,
) -> Result<(i64, i64), crate::v2::V2ValidationError> {
    let first_visible = checkpointed_first_visible_at_micros.unwrap_or(recovery_publication_micros);
    let visible_until = crate::v2::receipt_visible_until(
        retry_until_micros,
        first_visible,
        terminal_status_grace_micros,
    )?;
    Ok((first_visible, visible_until))
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SnapshotLeasePhase {
    Active,
    Closed,
    Released,
}

/// Small reference model for the signed-generation/token/request-pin split.
/// Closing or expiring a token blocks new admissions immediately but cannot
/// release its base pin until all already-admitted request pins leave.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotLeaseOracle {
    phase: SnapshotLeasePhase,
    request_pins: u32,
}

impl SnapshotLeaseOracle {
    pub const fn new() -> Self {
        Self {
            phase: SnapshotLeasePhase::Active,
            request_pins: 0,
        }
    }

    pub const fn phase(&self) -> SnapshotLeasePhase {
        self.phase
    }

    pub const fn request_pins(&self) -> u32 {
        self.request_pins
    }

    pub fn base_pin_held(&self) -> bool {
        self.phase != SnapshotLeasePhase::Released
    }

    pub fn admit_request(&mut self) -> bool {
        if self.phase != SnapshotLeasePhase::Active {
            return false;
        }
        match self.request_pins.checked_add(1) {
            Some(value) => {
                self.request_pins = value;
                true
            }
            None => false,
        }
    }

    pub fn close_or_expire(&mut self) {
        if self.phase == SnapshotLeasePhase::Active {
            self.phase = if self.request_pins == 0 {
                SnapshotLeasePhase::Released
            } else {
                SnapshotLeasePhase::Closed
            };
        }
    }

    pub fn release_request(&mut self) -> bool {
        if self.request_pins == 0 {
            return false;
        }
        self.request_pins -= 1;
        if self.request_pins == 0 && self.phase == SnapshotLeasePhase::Closed {
            self.phase = SnapshotLeasePhase::Released;
        }
        true
    }
}

impl Default for SnapshotLeaseOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AckRecord {
    pub repo_id: ObjectId,
    pub operation_id: OperationId,
    pub operation_digest: ObjectId,
    pub receipt_digest: ObjectId,
    pub repo_sequence: u64,
    pub blob_ids: Vec<ObjectId>,
    pub tree_ids: Vec<ObjectId>,
    pub commit_ids: Vec<ObjectId>,
}

impl AckRecord {
    fn payload(&self) -> Result<Vec<u8>, AckJournalError> {
        let count = self.commit_ids.len();
        if count == 0
            || count > ACK_MAX_COMMITS
            || self.blob_ids.len() != count
            || self.tree_ids.len() != count
        {
            return Err(AckJournalError::InvalidRecord(
                "canonical ACK record requires 1..=64 Blob/Tree/Commit ID triplets",
            ));
        }
        for ids in [&self.blob_ids, &self.tree_ids, &self.commit_ids] {
            if ids.iter().copied().collect::<BTreeSet<_>>().len() != count {
                return Err(AckJournalError::InvalidRecord(
                    "generated object IDs must be unique within an ACK record",
                ));
            }
        }
        let mut out = Vec::with_capacity(ACK_FIXED_PAYLOAD_LEN + count * ACK_COMMIT_IDS_LEN);
        out.extend_from_slice(self.repo_id.as_bytes());
        out.extend_from_slice(&self.operation_id);
        out.extend_from_slice(self.operation_digest.as_bytes());
        out.extend_from_slice(self.receipt_digest.as_bytes());
        out.extend_from_slice(&self.repo_sequence.to_le_bytes());
        out.extend_from_slice(&(count as u32).to_le_bytes());
        for index in 0..count {
            out.extend_from_slice(self.blob_ids[index].as_bytes());
            out.extend_from_slice(self.tree_ids[index].as_bytes());
            out.extend_from_slice(self.commit_ids[index].as_bytes());
        }
        Ok(out)
    }

    fn from_payload(bytes: &[u8]) -> Result<Self, AckJournalError> {
        if bytes.len() < ACK_FIXED_PAYLOAD_LEN {
            return Err(AckJournalError::InvalidRecord(
                "ACK payload is shorter than its fixed fields",
            ));
        }
        let mut repo_id = [0; 32];
        repo_id.copy_from_slice(&bytes[..32]);
        let mut operation_id = [0; 16];
        operation_id.copy_from_slice(&bytes[32..48]);
        let mut operation_digest = [0; 32];
        operation_digest.copy_from_slice(&bytes[48..80]);
        let mut receipt_digest = [0; 32];
        receipt_digest.copy_from_slice(&bytes[80..112]);
        let mut sequence = [0; 8];
        sequence.copy_from_slice(&bytes[112..120]);
        let mut count = [0; 4];
        count.copy_from_slice(&bytes[120..124]);
        let count = u32::from_le_bytes(count) as usize;
        if count == 0 || count > ACK_MAX_COMMITS {
            return Err(AckJournalError::InvalidRecord(
                "ACK commit count is outside 1..=64",
            ));
        }
        let expected_len = ACK_FIXED_PAYLOAD_LEN
            .checked_add(count.checked_mul(ACK_COMMIT_IDS_LEN).ok_or(
                AckJournalError::InvalidRecord("ACK commit ID length overflow"),
            )?)
            .ok_or(AckJournalError::InvalidRecord(
                "ACK payload length overflow",
            ))?;
        if bytes.len() != expected_len {
            return Err(AckJournalError::InvalidRecord(
                "ACK payload length does not match commit count",
            ));
        }
        let mut blob_ids = Vec::with_capacity(count);
        let mut tree_ids = Vec::with_capacity(count);
        let mut commit_ids = Vec::with_capacity(count);
        let mut cursor = ACK_FIXED_PAYLOAD_LEN;
        for _ in 0..count {
            let mut blob = [0; 32];
            blob.copy_from_slice(&bytes[cursor..cursor + 32]);
            cursor += 32;
            let mut tree = [0; 32];
            tree.copy_from_slice(&bytes[cursor..cursor + 32]);
            cursor += 32;
            let mut commit = [0; 32];
            commit.copy_from_slice(&bytes[cursor..cursor + 32]);
            cursor += 32;
            blob_ids.push(ObjectId(blob));
            tree_ids.push(ObjectId(tree));
            commit_ids.push(ObjectId(commit));
        }
        Ok(Self {
            repo_id: ObjectId(repo_id),
            operation_id,
            operation_digest: ObjectId(operation_digest),
            receipt_digest: ObjectId(receipt_digest),
            repo_sequence: u64::from_le_bytes(sequence),
            blob_ids,
            tree_ids,
            commit_ids,
        })
    }
}

#[derive(Debug, Error)]
pub enum AckJournalError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("invalid acknowledgment journal header")]
    InvalidHeader,
    #[error("invalid acknowledgment record length: {0}")]
    InvalidRecordLength(u32),
    #[error("invalid acknowledgment record: {0}")]
    InvalidRecord(&'static str),
    #[error("acknowledgment record checksum mismatch")]
    Checksum,
}

pub struct ExternalAckJournal {
    file: File,
}

impl ExternalAckJournal {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AckJournalError> {
        let path = path.as_ref();
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)?;
        if file.metadata()?.len() == 0 {
            file.write_all(ACK_MAGIC)?;
            file.write_all(&ACK_VERSION.to_le_bytes())?;
            file.sync_data()?;
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            File::open(parent)?.sync_all()?;
        }
        let mut header = [0; 8];
        file.seek(SeekFrom::Start(0))?;
        file.read_exact(&mut header)?;
        if &header[..4] != ACK_MAGIC || u32::from_le_bytes(header[4..8].try_into().unwrap()) != 1 {
            return Err(AckJournalError::InvalidHeader);
        }
        file.seek(SeekFrom::End(0))?;
        Ok(Self { file })
    }

    /// Append and fence the record before the caller may count the
    /// corresponding server response.
    pub fn append_durable(&mut self, record: &AckRecord) -> Result<(), AckJournalError> {
        let payload = record.payload()?;
        let checksum = blake3::hash(&payload);
        self.file.write_all(&(payload.len() as u32).to_le_bytes())?;
        self.file.write_all(&payload)?;
        self.file.write_all(checksum.as_bytes())?;
        self.file.sync_data()?;
        Ok(())
    }

    pub fn recover(path: impl AsRef<Path>) -> Result<Vec<AckRecord>, AckJournalError> {
        let mut file = File::open(path)?;
        let mut header = [0; 8];
        file.read_exact(&mut header)?;
        if &header[..4] != ACK_MAGIC || u32::from_le_bytes(header[4..8].try_into().unwrap()) != 1 {
            return Err(AckJournalError::InvalidHeader);
        }
        let mut out = Vec::new();
        loop {
            let mut length = [0; 4];
            match file.read_exact(&mut length) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(error) => return Err(error.into()),
            }
            let length = u32::from_le_bytes(length);
            if length as usize > ACK_MAX_PAYLOAD_LEN || (length as usize) < ACK_FIXED_PAYLOAD_LEN {
                return Err(AckJournalError::InvalidRecordLength(length));
            }
            let mut payload = vec![0; length as usize];
            if let Err(error) = file.read_exact(&mut payload) {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(error.into());
            }
            let mut checksum = [0; 32];
            if let Err(error) = file.read_exact(&mut checksum) {
                if error.kind() == io::ErrorKind::UnexpectedEof {
                    break;
                }
                return Err(error.into());
            }
            if checksum != *blake3::hash(&payload).as_bytes() {
                return Err(AckJournalError::Checksum);
            }
            out.push(AckRecord::from_payload(&payload)?);
        }
        Ok(out)
    }

    pub fn encoded_record_len(record: &AckRecord) -> Result<usize, AckJournalError> {
        Ok(4 + record.payload()?.len() + 32)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactRestoreFixture {
    pub format_marker: Vec<u8>,
    pub current_manifest: Vec<u8>,
    pub frames: Vec<Vec<u8>>,
    pub event_count: u64,
    pub receipt_count: u64,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RestoreOracleError {
    #[error("restore changed authoritative bytes")]
    BytesChanged,
    #[error("restore added or removed logical events")]
    EventCountChanged,
    #[error("restore added or removed receipts")]
    ReceiptCountChanged,
    #[error("restore staging and destination must be on the same device")]
    CrossDevice,
    #[error("restore destination must be absent")]
    DestinationOccupied,
    #[error("restore format marker is missing or invalid")]
    InvalidFormatMarker,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RestorePreconditions {
    pub staging_device: u64,
    pub destination_parent_device: u64,
    pub destination_absent: bool,
    pub format_marker_valid: bool,
}

impl RestorePreconditions {
    pub fn validate(self) -> Result<(), RestoreOracleError> {
        if self.staging_device != self.destination_parent_device {
            return Err(RestoreOracleError::CrossDevice);
        }
        if !self.destination_absent {
            return Err(RestoreOracleError::DestinationOccupied);
        }
        if !self.format_marker_valid {
            return Err(RestoreOracleError::InvalidFormatMarker);
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RestoreFailpoint {
    BeforeValidation,
    AfterStagingSync,
    BeforeRenameNoReplace,
    AfterRenameBeforeParentSync,
    AfterParentSyncBeforeProductionRecovery,
    AfterRecoveryBeforeReady,
}

pub const RESTORE_FAILPOINTS: &[RestoreFailpoint] = &[
    RestoreFailpoint::BeforeValidation,
    RestoreFailpoint::AfterStagingSync,
    RestoreFailpoint::BeforeRenameNoReplace,
    RestoreFailpoint::AfterRenameBeforeParentSync,
    RestoreFailpoint::AfterParentSyncBeforeProductionRecovery,
    RestoreFailpoint::AfterRecoveryBeforeReady,
];

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RestoredDestinationOutcome {
    Absent,
    AbsentOrExact,
    ExactNotReady,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RestoreFailpointExpectation {
    pub destination: RestoredDestinationOutcome,
    pub parent_sync_required: bool,
    pub production_recovery_required: bool,
    pub new_transaction_or_event_allowed: bool,
}

pub const fn restore_failpoint_expectation(point: RestoreFailpoint) -> RestoreFailpointExpectation {
    use RestoreFailpoint::*;
    match point {
        BeforeValidation | AfterStagingSync | BeforeRenameNoReplace => {
            RestoreFailpointExpectation {
                destination: RestoredDestinationOutcome::Absent,
                parent_sync_required: false,
                production_recovery_required: false,
                new_transaction_or_event_allowed: false,
            }
        }
        AfterRenameBeforeParentSync => RestoreFailpointExpectation {
            destination: RestoredDestinationOutcome::AbsentOrExact,
            parent_sync_required: true,
            production_recovery_required: true,
            new_transaction_or_event_allowed: false,
        },
        AfterParentSyncBeforeProductionRecovery | AfterRecoveryBeforeReady => {
            RestoreFailpointExpectation {
                destination: RestoredDestinationOutcome::ExactNotReady,
                parent_sync_required: false,
                production_recovery_required: true,
                new_transaction_or_event_allowed: false,
            }
        }
    }
}

pub fn verify_exact_restore(
    exported: &ExactRestoreFixture,
    restored: &ExactRestoreFixture,
) -> Result<(), RestoreOracleError> {
    if exported.format_marker != restored.format_marker
        || exported.current_manifest != restored.current_manifest
        || exported.frames != restored.frames
    {
        return Err(RestoreOracleError::BytesChanged);
    }
    if exported.event_count != restored.event_count {
        return Err(RestoreOracleError::EventCountChanged);
    }
    if exported.receipt_count != restored.receipt_count {
        return Err(RestoreOracleError::ReceiptCountChanged);
    }
    Ok(())
}

pub fn receipt_status(receipt: CommitReceiptV1) -> TransactionStatusV1 {
    TransactionStatusV1::Committed(receipt)
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct VisibilitySurface {
    pub namespace_objects: u64,
    pub refs_changed: u64,
    pub events: u64,
    pub durable_dedupe_records: u64,
    pub receipts: u64,
}

pub const REJECTED_OR_STAGED_VISIBILITY: VisibilitySurface = VisibilitySurface {
    namespace_objects: 0,
    refs_changed: 0,
    events: 0,
    durable_dedupe_records: 0,
    receipts: 0,
};
