//! Manifest and checkpoint fallback, interrupted-seal completion, tail
//! adoption, sequence and event-chain verification, receipt reconstruction,
//! and the readiness result.
//!
//! **Owned by A2 RecoveryIndex** (scope 2.1, 4-A2).
//!
//! Implements the normative algorithm of scope 3.8. Two rules there carry most
//! of the risk and must be asserted individually rather than in aggregate:
//! recovery stops at the first incomplete frame and discards everything after
//! it even when a later frame is complete and checksum-valid (step 6); and the
//! tail scan treats a zeroed region, stale preallocated content, and `EIO`
//! alike as "the tail ends here" rather than as a fatal error (step 5).
//!
//! # One definition of where a journal ends
//!
//! Steps 5 and 7 are **not** implemented here. They are
//! [`crate::journal::scan_journal`] and [`crate::journal::quarantine_tail`],
//! which are the same functions `Journal::open` and `segment::seal_journal`
//! call. A parallel scanner in this module would be a second definition of
//! frame completeness, and the two could drift after the freeze. Step 2's byte
//! reads are likewise [`crate::segment::read_current`],
//! [`crate::segment::read_manifest`], and
//! [`crate::segment::manifest_referents_present`].
//!
//! What this module adds on top is the part that is genuinely A2's:
//!
//! - **which** generation to believe, and a fault taxonomy fine enough to tell
//!   "the pointer does not validate" from "the pointer validates but its
//!   referent does not" (scope 4-A2 forbids collapsing them, and A1's
//!   `load_manifest_with_fallback` returns only a boolean);
//! - validation of a manifest's referents *beyond existence*, which is what the
//!   corrupt-segment acceptance case needs;
//! - the interrupted-seal disposition of scope 3.4 (below);
//! - independent shard-sequence and repository-chain verification;
//! - receipt-visibility promotion against the frozen oracle.
//!
//! A2's independent derivation of the scope 3.3 completeness rule survives as a
//! *test* artifact only — `tests/recovery_reference_frame.rs` plus
//! `tests/recovery_production_codec.rs`, which proves it agrees with
//! `format::verify_complete` over a valid frame, each condition violated alone,
//! every truncation offset, and single-bit mutation. It is no longer on any
//! production path.
//!
//! # The interrupted seal (scope 3.4, link-then-unlink)
//!
//! Sealing links the journal into `segments/` (step 4), installs the manifest
//! generation and swaps `CURRENT` (step 5), and only then unlinks the `active/`
//! name (step 6). Both names therefore exist across the whole install, so no
//! crash point leaves the frames unreachable — which is the hole a *rename*
//! here would open, and the reason 3.4 was amended.
//!
//! The cost is a state recovery must expect, and the two crash points are
//! opposite errors:
//!
//! - **Between 4 and 5** — a segment file exists that *no* manifest generation
//!   references, and the `active/` journal is still the authority. Recovery
//!   must ignore the orphan segment and scan the journal. Treating it as sealed
//!   would drop every frame the manifest does not yet name.
//! - **Between 5 and 6** — a manifest generation *does* reference a segment
//!   whose `journal_id` equals the active journal's. The seal completed; only
//!   its final unlink was lost. Recovery must finish the unlink and take those
//!   frames from the manifest. Replaying the journal as well would adopt every
//!   frame twice and duplicate `shard_sequence` values.
//!
//! Getting these backwards loses acknowledged data in one direction and
//! duplicates it in the other, so they are separate variants of
//! [`ActiveJournalDisposition`] with a dedicated test each.
//!
//! # What recovery never does
//!
//! It never rewrites a journal in place. The validated prefix is sealed into a
//! segment and a fresh journal is opened; the discarded tail bytes are copied
//! to `quarantine/` and the original file is left byte-for-byte as the crash
//! left it. An in-place truncation would destroy the only evidence of what the
//! device actually retained, which is the input A3's external ACK
//! reconciliation needs to catch a device that lied about a flush.

use std::fs::File;
use std::path::{Path, PathBuf};

use levcs_core::ObjectId;
use levcs_protocol::oracle::{self, RecoveredTailFact, RecoveryOutcome};

use crate::checkpoint::{Checkpoint, CheckpointLoad, ReceiptRecord};
use crate::format::{CurrentPointer, FrameError, FrameHeader, JournalHeader, Manifest};
use crate::index::{IndexDelta, IndexKey, IndexLocation, NamespaceCatalog};
use crate::journal::{QuarantinedTail, ScannedFrame, TailScan};
use crate::segment::{self, ShardPaths};
use crate::types::{DurabilityCounters, NamespaceId, OperationId, StoreError};

// ===========================================================================
// Step 2 — CURRENT and the manifest fallback
// ===========================================================================

/// Why a file a manifest names is unusable.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReferencedFileFault {
    #[error("referenced file is missing")]
    Missing,
    #[error("referenced file could not be read: {0}")]
    Unreadable(String),
    #[error("referenced file is shorter than its own fixed structure")]
    TooShort,
    #[error("referenced file failed validation: {0}")]
    Invalid(String),
}

/// Validates one file a manifest references.
///
/// `segment::manifest_referents_present` answers *existence*, deliberately and
/// by its own documentation. Scope 4-A2 keeps "the manifest names a missing
/// segment" and "the manifest names a corrupt segment" distinct, so the second
/// needs a check existence cannot make. This trait is that check, and it is a
/// seam so a caller can supply the full segment-footer validation once it is
/// worth the open on every startup.
pub trait ReferencedFileValidator {
    fn validate(&self, dir: &Path, filename: &str) -> Result<(), ReferencedFileFault>;
}

pub struct PresenceAndLengthValidator {
    pub minimum_len: u64,
}

impl Default for PresenceAndLengthValidator {
    fn default() -> Self {
        // A sealed segment holds at least a journal header and one frame.
        Self {
            minimum_len: crate::format::JOURNAL_HEADER_LEN as u64 + crate::format::MIN_FRAME_LEN,
        }
    }
}

impl ReferencedFileValidator for PresenceAndLengthValidator {
    fn validate(&self, dir: &Path, filename: &str) -> Result<(), ReferencedFileFault> {
        // A manifest is a durable file, but the names inside it are still
        // untrusted input at read time: a path component would let a corrupt
        // manifest point outside the shard directory.
        if filename.is_empty()
            || filename.contains('/')
            || filename.contains('\\')
            || filename == "."
            || filename == ".."
        {
            return Err(ReferencedFileFault::Invalid(
                "manifest filenames may not contain a path".into(),
            ));
        }
        let path = dir.join(filename);
        match std::fs::metadata(&path) {
            Ok(meta) if meta.len() >= self.minimum_len => Ok(()),
            Ok(_) => Err(ReferencedFileFault::TooShort),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(ReferencedFileFault::Missing),
            Err(e) => Err(ReferencedFileFault::Unreadable(e.to_string())),
        }
    }
}

/// Full segment-footer validation, layered on top of the cheap check.
///
/// Opens each referenced segment through `segment::SegmentReader`, which
/// verifies the footer digest, the `root_uuid` binding, and the offset table.
/// Strictly stronger than [`PresenceAndLengthValidator`] and strictly more
/// expensive; it exists so the corrupt-segment case can be exercised against
/// the real reader rather than only against a length.
pub struct SegmentFooterValidator {
    pub root_uuid: [u8; 16],
    pub inner: PresenceAndLengthValidator,
}

impl SegmentFooterValidator {
    pub fn new(root_uuid: [u8; 16]) -> Self {
        Self {
            root_uuid,
            inner: PresenceAndLengthValidator::default(),
        }
    }
}

impl ReferencedFileValidator for SegmentFooterValidator {
    fn validate(&self, dir: &Path, filename: &str) -> Result<(), ReferencedFileFault> {
        self.inner.validate(dir, filename)?;
        if !filename.ends_with(".seg") {
            return Ok(());
        }
        segment::SegmentReader::open(&dir.join(filename), &self.root_uuid)
            .map(|_| ())
            .map_err(|e| ReferencedFileFault::Invalid(e.to_string()))
    }
}

/// Why recovery did not use `CURRENT`'s referent.
///
/// The three acceptance branches of scope 4-A2 are distinct variants and are
/// never collapsed:
///
/// - `CurrentMissing` / `CurrentUnreadable` / `CurrentCorrupt` /
///   `CurrentRootUuidMismatch` — *the pointer does not validate*.
/// - `ReferentMissing` — the pointer validates and names a generation that is
///   not there.
/// - `ReferentCorrupt` — the pointer validates and names a manifest that fails
///   its own checksum.
///
/// The last two are failures the single-`CURRENT` layout could not express;
/// they exist only because the pointer design introduces them, so reporting
/// them as one fault would hide the cost of that design.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ManifestFallbackReason {
    #[error("CURRENT is missing")]
    CurrentMissing,
    #[error("CURRENT could not be read: {0}")]
    CurrentUnreadable(String),
    #[error("CURRENT does not validate: {0}")]
    CurrentCorrupt(FrameError),
    #[error("CURRENT names another store root")]
    CurrentRootUuidMismatch,
    #[error("manifest generation {generation} is not present")]
    ReferentMissing { generation: u64 },
    #[error("manifest generation {generation} does not validate: {cause}")]
    ReferentCorrupt { generation: u64, cause: String },
    #[error(
        "manifest generation {generation} references {filename}, which fails \
         validation: {cause}"
    )]
    ReferentFileInvalid {
        generation: u64,
        filename: String,
        cause: ReferencedFileFault,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestSource {
    /// `CURRENT` validated and its referent validated.
    Current,
    /// `CURRENT` or its referent did not validate; this is the newest valid
    /// generation below it.
    Fallback { reason: ManifestFallbackReason },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestSelection {
    pub manifest: Manifest,
    pub generation: u64,
    pub path: PathBuf,
    pub source: ManifestSource,
    /// Generations attempted and refused, newest first, so an operator sees
    /// what was skipped rather than inferring it from a version number.
    pub rejected: Vec<(u64, ManifestFallbackReason)>,
}

/// Why `segment::read_current` declined the pointer.
///
/// A *diagnostic refinement only*: the decision itself is A1's — this function
/// runs only after `read_current` has already returned `None`, and never
/// overrides it. Re-reading the file to name the reason cannot make recovery
/// select a different generation.
fn classify_current_failure(paths: &ShardPaths, root_uuid: &[u8; 16]) -> ManifestFallbackReason {
    let bytes = match std::fs::read(paths.current()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return ManifestFallbackReason::CurrentMissing
        }
        Err(e) => return ManifestFallbackReason::CurrentUnreadable(e.to_string()),
        Ok(bytes) => bytes,
    };
    match CurrentPointer::decode(&bytes) {
        Err(cause) => ManifestFallbackReason::CurrentCorrupt(cause),
        Ok(pointer) if &pointer.root_uuid != root_uuid => {
            ManifestFallbackReason::CurrentRootUuidMismatch
        }
        Ok(_) => ManifestFallbackReason::CurrentUnreadable(
            "CURRENT decodes and binds to this root but was refused by \
             segment::read_current"
                .into(),
        ),
    }
}

/// Load one generation through A1's reader and then validate its referents
/// beyond existence.
fn load_generation(
    paths: &ShardPaths,
    generation: u64,
    root_uuid: &[u8; 16],
    files: &dyn ReferencedFileValidator,
) -> Result<Manifest, ManifestFallbackReason> {
    if !paths.manifest(generation).exists() {
        return Err(ManifestFallbackReason::ReferentMissing { generation });
    }
    let manifest = segment::read_manifest(paths, generation, root_uuid).map_err(|e| {
        ManifestFallbackReason::ReferentCorrupt {
            generation,
            cause: e.to_string(),
        }
    })?;

    for range in &manifest.retained_tail_ranges {
        files
            .validate(&paths.segments(), &range.filename)
            .map_err(|cause| ManifestFallbackReason::ReferentFileInvalid {
                generation,
                filename: range.filename.clone(),
                cause,
            })?;
    }
    for (_, filename) in &manifest.index_runs {
        files
            .validate(&paths.indexes(), filename)
            .map_err(|cause| ManifestFallbackReason::ReferentFileInvalid {
                generation,
                filename: filename.clone(),
                cause,
            })?;
    }
    for (_, filename) in &manifest.checkpoints {
        files
            .validate(&paths.checkpoints(), filename)
            .map_err(|cause| ManifestFallbackReason::ReferentFileInvalid {
                generation,
                filename: filename.clone(),
                cause,
            })?;
    }
    Ok(manifest)
}

/// Recovery step 2, with the fault taxonomy scope 4-A2 requires.
///
/// The byte reads are `segment::read_current` and `segment::read_manifest`;
/// this function decides *which* generation to believe and *why* the ones above
/// it were refused. `segment::load_manifest_with_fallback` answers the same
/// selection question with a boolean, and `recovery_manifest.rs` asserts the
/// two agree on every fixture — so this is a refinement of A1's answer, never a
/// second opinion about it.
///
/// `Ok(None)` means no generation validated at all: a refusal to open, not a
/// fresh store. A shard directory with manifests present but none usable must
/// never silently become an empty shard.
pub fn resolve_manifest(
    paths: &ShardPaths,
    root_uuid: &[u8; 16],
    files: &dyn ReferencedFileValidator,
    max_candidates: usize,
) -> Result<Option<ManifestSelection>, StoreError> {
    let mut rejected: Vec<(u64, ManifestFallbackReason)> = Vec::new();
    let fallback_reason: Option<ManifestFallbackReason>;

    match segment::read_current(paths, root_uuid)? {
        Some(pointer) => match load_generation(paths, pointer.generation, root_uuid, files) {
            Ok(manifest) => {
                return Ok(Some(ManifestSelection {
                    manifest,
                    generation: pointer.generation,
                    path: paths.manifest(pointer.generation),
                    source: ManifestSource::Current,
                    rejected,
                }))
            }
            Err(reason) => {
                rejected.push((pointer.generation, reason.clone()));
                fallback_reason = Some(reason);
            }
        },
        None => fallback_reason = Some(classify_current_failure(paths, root_uuid)),
    }

    let reason = fallback_reason.expect("a fallback is only reached after a recorded failure");
    let mut generations = segment::list_manifest_generations(paths)?;
    generations.sort_unstable_by(|a, b| b.cmp(a));
    for generation in generations.into_iter().take(max_candidates.max(1)) {
        if rejected.iter().any(|(g, _)| *g == generation) {
            continue;
        }
        match load_generation(paths, generation, root_uuid, files) {
            Ok(manifest) => {
                return Ok(Some(ManifestSelection {
                    manifest,
                    generation,
                    path: paths.manifest(generation),
                    source: ManifestSource::Fallback {
                        reason: reason.clone(),
                    },
                    rejected,
                }))
            }
            Err(cause) => rejected.push((generation, cause)),
        }
    }
    Ok(None)
}

// ===========================================================================
// Step 3 — checkpoint selection
// ===========================================================================

/// Recovery step 3. A thin, named wrapper so the offline-rebuild decision has
/// exactly one call site and the `checkpoint_retain` relation is applied here
/// rather than at each caller.
pub fn load_checkpoint(
    checkpoint_dir: &Path,
    root_uuid: &[u8; 16],
    shard_index: u16,
    checkpoint_retain: u32,
) -> Result<CheckpointLoad, StoreError> {
    // Consider a small multiple of the retention floor: enough to survive
    // several corrupt generations, bounded so a directory that failed to
    // prune cannot turn startup into a linear hunt (plan §5.3).
    let max_candidates = (checkpoint_retain.max(2) as usize) * 4;
    crate::checkpoint::load_newest_valid(checkpoint_dir, root_uuid, shard_index, max_candidates)
}

// ===========================================================================
// Scope 3.4 — the interrupted seal
// ===========================================================================

/// What to do with a journal found under `active/`.
///
/// The two variants are opposite errors if confused, which is why they are
/// variants rather than a bool: adopting `Replay` when the seal completed
/// duplicates every frame in the journal, and adopting `AlreadySealed` when it
/// did not drops every frame the manifest does not yet name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActiveJournalDisposition {
    /// The journal is live. Scan it, adopt its contiguous prefix, quarantine
    /// its tail.
    Replay,
    /// The journal's `journal_id` is already covered by a manifest-referenced
    /// segment: scope 3.4's seal completed through step 5 and only its final
    /// unlink was lost. Finish the unlink and take the frames from the
    /// manifest. **Do not replay.**
    AlreadySealed {
        segment: PathBuf,
        first_shard_sequence: u64,
        last_shard_sequence: u64,
    },
}

/// Decide whether an `active/` journal is live or is the residue of an
/// interrupted seal (scope 3.4 steps 4-6).
///
/// The test is `journal_id`, not the file name, the inode, or the sequence
/// range. `journal_id` is fresh random per journal file and is stamped into the
/// segment footer by the seal that copied it, so it is the only identifier that
/// survives the link and cannot collide with a different journal that happens
/// to cover the same sequences.
///
/// Only segments the selected manifest **references** count. An orphan segment
/// in `segments/` that no generation names is the crash-between-4-and-5 image:
/// the seal never became visible, the journal is still the authority, and this
/// returns `Replay`.
pub fn classify_active_journal(
    paths: &ShardPaths,
    manifest: &Manifest,
    active_journal_id: &[u8; 16],
    root_uuid: &[u8; 16],
) -> Result<ActiveJournalDisposition, StoreError> {
    for range in &manifest.retained_tail_ranges {
        let path = paths.segments().join(&range.filename);
        let reader = match segment::SegmentReader::open(&path, root_uuid) {
            Ok(reader) => reader,
            // A manifest-referenced segment that will not open is a separate
            // fault, and step 2's referent validation is where it is reported.
            // Here it simply cannot prove a seal completed.
            Err(_) => continue,
        };
        if &reader.footer().journal_id == active_journal_id {
            return Ok(ActiveJournalDisposition::AlreadySealed {
                segment: path,
                first_shard_sequence: reader.footer().first_shard_sequence,
                last_shard_sequence: reader.footer().last_shard_sequence,
            });
        }
    }
    Ok(ActiveJournalDisposition::Replay)
}

/// Finish an interrupted seal by dropping the stale `active/` name
/// (scope 3.4 step 6).
///
/// Delegates to `segment::unlink_sealed_journal`, which is the same function
/// the writer's own seal path calls, so completing a seal during recovery and
/// completing it during normal rotation are the same code.
pub fn complete_interrupted_seal(
    active_path: &Path,
    paths: &ShardPaths,
    counters: &DurabilityCounters,
) -> Result<(), StoreError> {
    segment::unlink_sealed_journal(active_path, paths, counters)
}

// ===========================================================================
// Steps 5-7 — adopting a tail scanned by `journal.rs`
// ===========================================================================

/// The frozen oracle's verdict on the frame that began at `offset`, per
/// `oracle::resolve_ambiguous_tail`.
///
/// A frame is `Committed` only if the scan adopted it. Everything at or after
/// the stop offset is `AbsentRetriable`, including a complete checksum-valid
/// frame beyond a hole — step 6 makes the *position*, not the bytes, decisive.
pub fn tail_outcome(scan: &TailScan, offset: u64) -> RecoveryOutcome {
    let fact = if scan.frames.iter().any(|f| f.offset == offset) {
        RecoveredTailFact::CompleteChecksumValid
    } else {
        RecoveredTailFact::AbsentOrTorn
    };
    oracle::resolve_ambiguous_tail(fact)
}

/// Scope 3.8 steps 5 to 7 for one open journal.
///
/// The scan is `journal::scan_journal` and the quarantine is
/// `journal::quarantine_tail`; this function is the ordering between them and
/// the `Result` boundary. There is no error path out of either — a torn tail,
/// a zeroed tail, stale content, and an `EIO` all produce a `TailScan` — so the
/// only errors this can return come from writing the quarantine record.
///
/// The second element is the record that was written, or `None` when writing
/// one would have been wrong (see [`crate::journal::quarantine_tail`] for the
/// three cases). It carries the **path** as well as the byte count because
/// [`ShardRecoveryReport::quarantined`] is where an operator learns where the
/// discarded bytes went, and until this returned the path that field was one
/// no caller could populate.
pub fn recover_journal_tail(
    quarantine_dir: &Path,
    journal: &File,
    header: &JournalHeader,
    from_offset: u64,
    counters: &DurabilityCounters,
) -> Result<(TailScan, Option<QuarantinedTail>), StoreError> {
    let scan = crate::journal::scan_journal(journal, header, from_offset);
    if !scan.stopped_early() {
        return Ok((scan, None));
    }
    let quarantined = crate::journal::quarantine_tail(
        quarantine_dir,
        journal,
        header,
        scan.stop_offset,
        counters,
    )?;
    Ok((scan, quarantined))
}

// ===========================================================================
// Journal identity binding
// ===========================================================================

/// A journal file that does not belong where it was found.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JournalBindingFault {
    #[error("journal root_uuid {found} does not match this store root {expected}")]
    RootUuidMismatch { expected: String, found: String },
    #[error("journal_id {found} is not the one the manifest names ({expected})")]
    JournalIdMismatch { expected: String, found: String },
    #[error("journal belongs to shard {found}, not shard {expected}")]
    ShardIndexMismatch { expected: u16, found: u16 },
    #[error(
        "journal first_shard_sequence {first} is above the checkpointed committed \
         sequence {committed}, so frames are missing between them"
    )]
    SequenceHole { first: u64, committed: u64 },
}

impl From<JournalBindingFault> for StoreError {
    fn from(e: JournalBindingFault) -> Self {
        StoreError::Corruption(format!("journal binding: {e}"))
    }
}

/// Bind a journal header to this root, shard, and expected identity.
///
/// `root_uuid` catches a file copied in from another instance; `journal_id`
/// catches a journal misfiled under the wrong name in a manifest, and a frame
/// from a previous incarnation of a recycled extent.
pub fn validate_journal_binding(
    header: &JournalHeader,
    root_uuid: &[u8; 16],
    shard_index: u16,
    expected_journal_id: Option<&[u8; 16]>,
    checkpointed_committed_sequence: Option<u64>,
) -> Result<(), JournalBindingFault> {
    if &header.root_uuid != root_uuid {
        return Err(JournalBindingFault::RootUuidMismatch {
            expected: hex::encode(root_uuid),
            found: hex::encode(header.root_uuid),
        });
    }
    if header.shard_index != shard_index {
        return Err(JournalBindingFault::ShardIndexMismatch {
            expected: shard_index,
            found: header.shard_index,
        });
    }
    if let Some(expected) = expected_journal_id {
        if &header.journal_id != expected {
            return Err(JournalBindingFault::JournalIdMismatch {
                expected: hex::encode(expected),
                found: hex::encode(header.journal_id),
            });
        }
    }
    if let Some(committed) = checkpointed_committed_sequence {
        if header.first_shard_sequence > committed + 1 {
            return Err(JournalBindingFault::SequenceHole {
                first: header.first_shard_sequence,
                committed,
            });
        }
    }
    Ok(())
}

// ===========================================================================
// Step 9 — independent sequence and chain verification
// ===========================================================================

/// The facts recovery needs about one adopted frame.
///
/// The header supplies `shard_sequence`, `repo_sequence`, `namespace`,
/// `operation_id`, and `operation_digest`. The rest — the event chain, the
/// authority movement, and the object list — lives in the canonical
/// `TransactionFramePayloadV1` payload.
///
/// **Interface note (A2 -> lead).** `format.rs` models a frame as
/// `{ header, payload: Vec<u8> }` with no payload type and no accessor for
/// `previous_event_digest` or `event_digest`, so there is no in-crate way to
/// extract them today. Step 9 is therefore written against this explicit facts
/// struct, and the extractor is a declared seam ([`PayloadFacts`]) rather than
/// an assumption. Filed as an interface change request rather than worked
/// around silently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameFacts {
    pub shard_sequence: u64,
    pub repo_sequence: u64,
    pub namespace: NamespaceId,
    pub operation_id: OperationId,
    pub operation_digest: ObjectId,
    /// Digest of this transaction's event, excluding its signature.
    pub event_digest: ObjectId,
    /// The digest this event chains onto.
    pub previous_event_digest: ObjectId,
    /// True for a repository-create frame, which binds a genesis rather than
    /// chaining onto one.
    pub creates_namespace: bool,
    pub genesis_authority: ObjectId,
    pub current_authority: ObjectId,
    pub retry_until_micros: i64,
    /// Objects this frame introduces, for index reconstruction.
    pub objects: Vec<(ObjectId, u8)>,
}

impl FrameFacts {
    /// The half of the facts the frame header carries. The payload-derived
    /// fields are left at their zero values and must be filled by a
    /// [`PayloadFacts`] implementation before step 9 means anything.
    pub fn from_header(header: &FrameHeader) -> Self {
        Self {
            shard_sequence: header.shard_sequence,
            repo_sequence: header.repo_sequence,
            namespace: NamespaceId(header.namespace),
            operation_id: OperationId(header.operation_id),
            operation_digest: header.operation_digest,
            event_digest: ObjectId([0u8; 32]),
            previous_event_digest: ObjectId([0u8; 32]),
            creates_namespace: false,
            genesis_authority: ObjectId([0u8; 32]),
            current_authority: ObjectId([0u8; 32]),
            retry_until_micros: 0,
            objects: Vec::new(),
        }
    }
}

/// Extracts the payload half of [`FrameFacts`].
pub trait PayloadFacts {
    fn extend(&self, facts: &mut FrameFacts, payload: &[u8]) -> Result<(), StoreError>;
}

/// A shard-sequence fault.
///
/// **A distinct type from [`RepoSequenceFault`].** Scope 4-A2 deliverable 4
/// requires that a shard gap and a repository gap never arrive as the same
/// fault; here the type system guarantees it, because the two verifiers cannot
/// return each other's type.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ShardSequenceFault {
    #[error("shard_sequence gap: expected {expected}, observed {observed}")]
    Gap { expected: u64, observed: u64 },
    #[error("duplicate shard_sequence {shard_sequence}")]
    Duplicate { shard_sequence: u64 },
    #[error("shard_sequence went backwards: {previous} then {observed}")]
    Regression { previous: u64, observed: u64 },
}

/// A per-repository fault. Never reported through [`ShardSequenceFault`].
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RepoSequenceFault {
    #[error(
        "repo_sequence gap in namespace {namespace}: expected {expected}, observed {observed}"
    )]
    Gap {
        namespace: String,
        expected: u64,
        observed: u64,
    },
    #[error("duplicate repo_sequence {repo_sequence} in namespace {namespace}")]
    Duplicate {
        namespace: String,
        repo_sequence: u64,
    },
    #[error("repo_sequence went backwards in namespace {namespace}: {previous} then {observed}")]
    Regression {
        namespace: String,
        previous: u64,
        observed: u64,
    },
    #[error(
        "previous_event_digest mismatch in namespace {namespace} at repo_sequence \
         {repo_sequence}: expected {expected}, observed {observed}"
    )]
    PreviousEventDigestMismatch {
        namespace: String,
        repo_sequence: u64,
        expected: String,
        observed: String,
    },
    #[error("namespace {namespace} appears in a frame without ever being created")]
    UnknownNamespace { namespace: String },
    #[error("namespace {namespace} is created twice")]
    DuplicateCreate { namespace: String },
}

impl From<ShardSequenceFault> for StoreError {
    fn from(e: ShardSequenceFault) -> Self {
        StoreError::Corruption(format!("shard sequence: {e}"))
    }
}

impl From<RepoSequenceFault> for StoreError {
    fn from(e: RepoSequenceFault) -> Self {
        StoreError::Corruption(format!("repository sequence: {e}"))
    }
}

/// Recovery step 9, physical half: contiguity and uniqueness of
/// `shard_sequence`, and nothing else.
///
/// Deliberately knows nothing about repositories. Plan §5.2 makes the two
/// sequence domains independent and never interchangeable, so the check that
/// enforces one must not be able to see the other.
pub fn verify_shard_sequence(
    facts: &[FrameFacts],
    first_expected: u64,
) -> Result<(), ShardSequenceFault> {
    let mut expected = first_expected;
    let mut previous: Option<u64> = None;
    for fact in facts {
        if let Some(previous) = previous {
            if fact.shard_sequence == previous {
                return Err(ShardSequenceFault::Duplicate {
                    shard_sequence: fact.shard_sequence,
                });
            }
            if fact.shard_sequence < previous {
                return Err(ShardSequenceFault::Regression {
                    previous,
                    observed: fact.shard_sequence,
                });
            }
        }
        if fact.shard_sequence != expected {
            return Err(ShardSequenceFault::Gap {
                expected,
                observed: fact.shard_sequence,
            });
        }
        previous = Some(fact.shard_sequence);
        expected = fact.shard_sequence + 1;
    }
    Ok(())
}

/// Recovery step 9, logical half: per-repository contiguity, uniqueness, and
/// the `previous_event_digest` chain.
///
/// `catalog` is the state a checkpoint restored; frames may both extend
/// existing repositories and create new ones.
pub fn verify_repo_chain(
    facts: &[FrameFacts],
    catalog: &NamespaceCatalog,
) -> Result<(), RepoSequenceFault> {
    use std::collections::BTreeMap;

    #[derive(Copy, Clone)]
    struct State {
        repo_sequence: u64,
        previous_event_digest: ObjectId,
    }

    let mut state: BTreeMap<NamespaceId, State> = BTreeMap::new();
    for (namespace, record) in catalog.iter() {
        state.insert(
            *namespace,
            State {
                repo_sequence: record.repo_sequence,
                previous_event_digest: record.previous_event_digest,
            },
        );
    }

    for fact in facts {
        let name = fact.namespace.to_hex();
        if fact.creates_namespace {
            if state.contains_key(&fact.namespace) {
                return Err(RepoSequenceFault::DuplicateCreate { namespace: name });
            }
            if fact.repo_sequence != 0 {
                return Err(RepoSequenceFault::Gap {
                    namespace: name,
                    expected: 0,
                    observed: fact.repo_sequence,
                });
            }
            state.insert(
                fact.namespace,
                State {
                    repo_sequence: fact.repo_sequence,
                    previous_event_digest: fact.event_digest,
                },
            );
            continue;
        }

        let current = *state
            .get(&fact.namespace)
            .ok_or(RepoSequenceFault::UnknownNamespace {
                namespace: name.clone(),
            })?;

        if fact.repo_sequence == current.repo_sequence {
            return Err(RepoSequenceFault::Duplicate {
                namespace: name,
                repo_sequence: fact.repo_sequence,
            });
        }
        if fact.repo_sequence < current.repo_sequence {
            return Err(RepoSequenceFault::Regression {
                namespace: name,
                previous: current.repo_sequence,
                observed: fact.repo_sequence,
            });
        }
        if fact.repo_sequence != current.repo_sequence + 1 {
            return Err(RepoSequenceFault::Gap {
                namespace: name,
                expected: current.repo_sequence + 1,
                observed: fact.repo_sequence,
            });
        }
        if fact.previous_event_digest != current.previous_event_digest {
            return Err(RepoSequenceFault::PreviousEventDigestMismatch {
                namespace: name,
                repo_sequence: fact.repo_sequence,
                expected: hex::encode(current.previous_event_digest.0),
                observed: hex::encode(fact.previous_event_digest.0),
            });
        }

        state.insert(
            fact.namespace,
            State {
                repo_sequence: fact.repo_sequence,
                previous_event_digest: fact.event_digest,
            },
        );
    }
    Ok(())
}

// ===========================================================================
// Step 10 — receipt table reconstruction and visibility promotion
// ===========================================================================

/// What changed about one receipt's retention during recovery.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum VisibilityPromotion {
    /// First visibility was already durably checkpointed. Nothing moves.
    AlreadyDurable,
    /// First visibility was not durable; it becomes recovery publication time
    /// and retention extends.
    PromotedToRecoveryPublication,
}

/// Recovery step 10.
///
/// For every recovered operation whose `first_receipt_visibility_micros` was
/// not in a durable checkpoint, set it to recovery publication time. The
/// computation is delegated to `oracle::recovered_receipt_visibility` so the
/// store cannot disagree with the frozen contract.
///
/// **Retention may only ever extend.** Plan §4 transaction invariant 7 says the
/// reset "only extends" retention. That is enforced here rather than assumed:
/// the new `receipt_visible_until` is the maximum of the stored and the
/// recomputed value, so even a checkpoint carrying an inconsistent stored
/// deadline cannot shorten a live receipt's visibility.
pub fn promote_receipt_visibility(
    receipts: &mut [ReceiptRecord],
    recovery_publication_micros: i64,
    terminal_status_grace_micros: i64,
) -> Result<Vec<VisibilityPromotion>, StoreError> {
    let mut promotions = Vec::with_capacity(receipts.len());
    for receipt in receipts.iter_mut() {
        let was_durable = receipt.first_receipt_visibility_micros.is_some();
        let (first_visible, visible_until) = oracle::recovered_receipt_visibility(
            receipt.retry_until_micros,
            receipt.first_receipt_visibility_micros,
            recovery_publication_micros,
            terminal_status_grace_micros,
        )
        .map_err(|e| {
            StoreError::Corruption(format!(
                "receipt visibility for operation {}: {e}",
                receipt.operation_id.to_hex()
            ))
        })?;

        let previous_until = receipt.receipt_visible_until_micros;
        receipt.first_receipt_visibility_micros = Some(first_visible);
        receipt.receipt_visible_until_micros = visible_until.max(previous_until);

        debug_assert!(
            receipt.receipt_visible_until_micros >= previous_until,
            "recovery may only extend retention"
        );
        promotions.push(if was_durable {
            VisibilityPromotion::AlreadyDurable
        } else {
            VisibilityPromotion::PromotedToRecoveryPublication
        });
    }
    Ok(promotions)
}

// ===========================================================================
// Index reconstruction
// ===========================================================================

/// Insert every object an adopted frame introduces into the delta, keyed by
/// `(namespace, ObjectId)`.
///
/// Namespace comes from the frame header, never from the object, which is what
/// makes isolation a property of the key on the recovery path too.
pub fn index_adopted_frames(
    delta: &mut IndexDelta,
    frames: &[(ScannedFrame, FrameFacts)],
    segment_generation: u64,
) -> Result<u64, StoreError> {
    let mut inserted = 0u64;
    for (frame, facts) in frames {
        let frame_len = u32::try_from(frame.len).map_err(|_| StoreError::LimitExceeded {
            limit: "frame_len",
            observed: frame.len,
            allowed: u32::MAX as u64,
        })?;
        for (object, object_type) in &facts.objects {
            delta.insert(
                IndexKey::new(facts.namespace, *object),
                IndexLocation {
                    segment_generation,
                    frame_offset: frame.offset,
                    frame_len,
                    object_type: *object_type,
                    shard_sequence: facts.shard_sequence,
                },
            )?;
            inserted += 1;
        }
    }
    Ok(inserted)
}

// ===========================================================================
// The report
// ===========================================================================

/// What recovery concluded about one shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardRecoveryReport {
    pub shard_index: u16,
    pub manifest_generation: Option<u64>,
    pub manifest_source: Option<ManifestSource>,
    /// What recovery concluded about the journal found under `active/`
    /// (scope 3.4 link-then-unlink).
    pub active_journal: Option<ActiveJournalDisposition>,
    pub checkpoint_sequence: Option<u64>,
    pub offline_rebuild_required: bool,
    pub adopted_shard_sequences: Vec<u64>,
    pub tail_stop: Option<crate::journal::TailStop>,
    pub quarantined: Option<PathBuf>,
    pub quarantined_bytes: u64,
    pub promotions: Vec<VisibilityPromotion>,
    /// Scope 3.8 step 12: readiness is true only after replay and
    /// catalog/genesis validation complete. A computed field, never a default.
    pub ready: bool,
}

impl ShardRecoveryReport {
    pub fn new(shard_index: u16) -> Self {
        Self {
            shard_index,
            manifest_generation: None,
            manifest_source: None,
            active_journal: None,
            checkpoint_sequence: None,
            offline_rebuild_required: false,
            adopted_shard_sequences: Vec::new(),
            tail_stop: None,
            quarantined: None,
            quarantined_bytes: 0,
            promotions: Vec::new(),
            ready: false,
        }
    }
}

/// Turn a checkpoint load into the state the later steps consume.
///
/// Returns `None` and sets `offline_rebuild_required` when every generation
/// failed, so a caller cannot accidentally treat "all corrupt" as "fresh
/// store": the two produce different reports, and only one of them permits
/// replay from sequence zero.
pub fn checkpoint_for_recovery(
    load: CheckpointLoad,
    root_uuid: &[u8; 16],
    shard_index: u16,
    report: &mut ShardRecoveryReport,
) -> Option<Checkpoint> {
    match load {
        CheckpointLoad::Empty => Some(Checkpoint::empty(*root_uuid, shard_index)),
        CheckpointLoad::Loaded { checkpoint, .. } => {
            report.checkpoint_sequence = Some(checkpoint.shard_committed_sequence);
            Some(*checkpoint)
        }
        CheckpointLoad::OfflineRebuildRequired { .. } => {
            report.offline_rebuild_required = true;
            report.ready = false;
            None
        }
    }
}
