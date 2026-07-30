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

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use im::Vector;
use levcs_core::ObjectId;
use levcs_protocol::oracle::{self, RecoveredTailFact, RecoveryOutcome};
use levcs_protocol::v2::{RefMutation, RefTarget, StagedProjectionInstallV1, TypedRefCas};

use crate::checkpoint::{Checkpoint, CheckpointError, CheckpointLoad, ReceiptRecord, RefRecord};
use crate::format::{
    object_type_code, CurrentPointer, Frame, FrameError, FrameHeader, FrameObjectsV1,
    JournalHeader, Manifest, TailRange, TransactionFramePayloadV1, JOURNAL_HEADER_LEN,
};
use crate::index::{IndexDelta, IndexKey, IndexLocation, IndexRun, NamespaceCatalog};
use crate::journal::{Journal, QuarantinedTail, ScannedFrame, TailScan, TailStop};
use crate::options::StoreOptions;
use crate::roots::{
    GenerationId, IndexDeltaLayer, LayeredObjectIndex, PinnedFile, RetainedGeneration,
    RetainedIndexRun, RetainedProjectionArtifact, RetainedSegment as RootRetainedSegment,
    RetainedTail,
};
use crate::segment::{self, RootLayout, SegmentReader, ShardPaths};
use crate::staging::{
    ProjectionRecoveryResolver, RecoveredProjectionArtifacts, RecoveredProjectionOutcome,
    RecoveredProjectionResolution,
};
use crate::sys;
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

    fn validate_segment(&self, dir: &Path, range: &TailRange) -> Result<(), ReferencedFileFault> {
        self.validate(dir, &range.filename)
    }

    fn validate_index(
        &self,
        dir: &Path,
        generation: u64,
        filename: &str,
    ) -> Result<(), ReferencedFileFault> {
        let _ = generation;
        self.validate(dir, filename)
    }

    fn validate_checkpoint(
        &self,
        dir: &Path,
        shard_sequence: u64,
        filename: &str,
    ) -> Result<(), ReferencedFileFault> {
        let _ = shard_sequence;
        self.validate(dir, filename)
    }
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

/// Full validator used by the production entry point.
///
/// Manifest fallback is decided only after every kind of referent has passed
/// its real reader. Validating index/checkpoint files later would turn a bad
/// `CURRENT` generation into a hard open failure instead of falling back to a
/// valid predecessor, contrary to recovery step 2.
struct ProductionReferentValidator {
    root_uuid: [u8; 16],
    shard_index: u16,
}

impl ReferencedFileValidator for ProductionReferentValidator {
    fn validate(&self, dir: &Path, filename: &str) -> Result<(), ReferencedFileFault> {
        PresenceAndLengthValidator { minimum_len: 1 }.validate(dir, filename)?;
        let path = dir.join(filename);
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("seg") => {
                let reader = SegmentReader::open(&path, &self.root_uuid)
                    .map_err(|error| ReferencedFileFault::Invalid(error.to_string()))?;
                let header = reader
                    .journal_header()
                    .map_err(|error| ReferencedFileFault::Invalid(error.to_string()))?;
                validate_journal_binding(
                    &header,
                    &self.root_uuid,
                    self.shard_index,
                    Some(&reader.footer().journal_id),
                    None,
                )
                .map_err(|error| ReferencedFileFault::Invalid(error.to_string()))
            }
            Some("idx") => IndexRun::open(&path, &self.root_uuid)
                .map(|_| ())
                .map_err(|error| ReferencedFileFault::Invalid(error.to_string())),
            Some(crate::checkpoint::CHECKPOINT_EXTENSION) => {
                let bytes = std::fs::read(&path)
                    .map_err(|error| ReferencedFileFault::Unreadable(error.to_string()))?;
                Checkpoint::decode(&bytes, &self.root_uuid, self.shard_index)
                    .map(|_| ())
                    .map_err(|error| ReferencedFileFault::Invalid(error.to_string()))
            }
            _ => Err(ReferencedFileFault::Invalid(
                "manifest referent has an unknown file extension".into(),
            )),
        }
    }

    fn validate_segment(&self, dir: &Path, range: &TailRange) -> Result<(), ReferencedFileFault> {
        self.validate(dir, &range.filename)?;
        let reader = SegmentReader::open(&dir.join(&range.filename), &self.root_uuid)
            .map_err(|error| ReferencedFileFault::Invalid(error.to_string()))?;
        let footer = reader.footer();
        if footer.generation != range.generation
            || footer.first_shard_sequence != range.first_shard_sequence
            || footer.last_shard_sequence != range.last_shard_sequence
        {
            return Err(ReferencedFileFault::Invalid(format!(
                "segment footer tuple ({}, {}, {}) disagrees with manifest row ({}, {}, {})",
                footer.generation,
                footer.first_shard_sequence,
                footer.last_shard_sequence,
                range.generation,
                range.first_shard_sequence,
                range.last_shard_sequence
            )));
        }
        Ok(())
    }

    fn validate_index(
        &self,
        dir: &Path,
        generation: u64,
        filename: &str,
    ) -> Result<(), ReferencedFileFault> {
        self.validate(dir, filename)?;
        let run = IndexRun::open(&dir.join(filename), &self.root_uuid)
            .map_err(|error| ReferencedFileFault::Invalid(error.to_string()))?;
        if run.generation() != generation {
            return Err(ReferencedFileFault::Invalid(format!(
                "index run declares generation {}, manifest row declares {generation}",
                run.generation()
            )));
        }
        Ok(())
    }

    fn validate_checkpoint(
        &self,
        _dir: &Path,
        _shard_sequence: u64,
        _filename: &str,
    ) -> Result<(), ReferencedFileFault> {
        // Checkpoints are derived state selected in normative recovery step 3.
        // Missing, corrupt, or tuple-mismatched rows fall back within this
        // manifest's ordered checkpoint list; they do not invalidate the
        // transaction-authority tail closure selected in step 2.
        Ok(())
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
    validate_manifest_sequence_coverage(&manifest)
        .map_err(|cause| ManifestFallbackReason::ReferentCorrupt { generation, cause })?;

    for range in &manifest.retained_tail_ranges {
        files
            .validate_segment(&paths.segments(), range)
            .map_err(|cause| ManifestFallbackReason::ReferentFileInvalid {
                generation,
                filename: range.filename.clone(),
                cause,
            })?;
    }
    for (run_generation, filename) in &manifest.index_runs {
        files
            .validate_index(&paths.indexes(), *run_generation, filename)
            .map_err(|cause| ManifestFallbackReason::ReferentFileInvalid {
                generation,
                filename: filename.clone(),
                cause,
            })?;
    }
    for (shard_sequence, filename) in &manifest.checkpoints {
        files
            .validate_checkpoint(&paths.checkpoints(), *shard_sequence, filename)
            .map_err(|cause| ManifestFallbackReason::ReferentFileInvalid {
                generation,
                filename: filename.clone(),
                cause,
            })?;
    }
    Ok(manifest)
}

fn validate_manifest_sequence_coverage(manifest: &Manifest) -> Result<(), String> {
    if manifest.base_generation != 0 {
        return Err(format!(
            "Phase 1 recovery cannot interpret nonzero base_generation {}",
            manifest.base_generation
        ));
    }

    if manifest
        .checkpoints
        .iter()
        .any(|(sequence, _)| *sequence > manifest.committed_shard_sequence)
    {
        return Err("checkpoint row is newer than the manifest's committed sequence".into());
    }

    let ranges = &manifest.retained_tail_ranges;
    if ranges.is_empty() {
        // Contract review 2026-07-29-C, amendment 4. The rule was "an empty
        // shard has no manifest", and it held for as long as the only reason to
        // write a manifest was to name a sealed segment. Index maintenance gives
        // a second reason: a shard that has published an index run but has not
        // yet rotated its journal has a manifest, no retained tail, and a
        // committed prefix that lives entirely in `active/`.
        //
        // `committed_shard_sequence == 0` is what makes that distinguishable
        // from the case the original rule was protecting against — a manifest
        // that claims committed frames while naming nothing that holds them.
        // Recovery replays the active journal from the beginning either way, and
        // the two checks below are consistent with an empty range list: there is
        // no first range to begin at 0 and no last one to end at 0.
        if manifest.committed_shard_sequence != 0 {
            return Err(format!(
                "a manifest with no retained tail commits through {}; nothing names those frames",
                manifest.committed_shard_sequence
            ));
        }
        if manifest.index_runs.is_empty() && manifest.checkpoints.is_empty() {
            return Err(
                "Phase 1 manifests may not have an empty retained tail; an empty shard has no \
                 manifest"
                    .into(),
            );
        }
        return Ok(());
    }
    if ranges[0].first_shard_sequence != 0 {
        return Err(format!(
            "Phase 1 retained tail begins at {}, expected 0",
            ranges[0].first_shard_sequence
        ));
    }
    for pair in ranges.windows(2) {
        let expected = pair[0]
            .last_shard_sequence
            .checked_add(1)
            .ok_or_else(|| "retained tail sequence overflow".to_string())?;
        if pair[1].first_shard_sequence != expected {
            return Err(format!(
                "retained tail gap or overlap: generation {} ends at {}, generation {} begins at {}",
                pair[0].generation,
                pair[0].last_shard_sequence,
                pair[1].generation,
                pair[1].first_shard_sequence
            ));
        }
    }
    let last = ranges.last().expect("non-empty").last_shard_sequence;
    if last != manifest.committed_shard_sequence {
        return Err(format!(
            "retained tail ends at {last}, manifest commits through {}",
            manifest.committed_shard_sequence
        ));
    }
    Ok(())
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
    let current = segment::read_current(paths, root_uuid)?;

    match current {
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
                // A valid pointer naming a missing or corrupt manifest gives
                // recovery no closure to compare with an older generation.
                // Guessing would silently roll back acknowledged transactions.
                let refused_manifest =
                    match segment::read_manifest(paths, pointer.generation, root_uuid) {
                        Ok(manifest) if validate_manifest_sequence_coverage(&manifest).is_ok() => {
                            manifest
                        }
                        Ok(_) | Err(_) => return Ok(None),
                    };

                let mut generations = segment::list_manifest_generations(paths)?;
                generations.sort_unstable_by(|a, b| b.cmp(a));
                for generation in generations.into_iter().take(max_candidates.max(1)) {
                    if generation == pointer.generation {
                        continue;
                    }
                    match load_generation(paths, generation, root_uuid, files) {
                        Ok(manifest)
                            if manifest.committed_shard_sequence
                                == refused_manifest.committed_shard_sequence
                                && manifest.retained_tail_ranges
                                    == refused_manifest.retained_tail_ranges =>
                        {
                            return Ok(Some(ManifestSelection {
                                manifest,
                                generation,
                                path: paths.manifest(generation),
                                source: ManifestSource::Fallback {
                                    reason: reason.clone(),
                                },
                                rejected,
                            }));
                        }
                        Ok(_) => return Ok(None),
                        Err(cause) => rejected.push((generation, cause)),
                    }
                }
                return Ok(None);
            }
        },
        None => {
            let reason = classify_current_failure(paths, root_uuid);
            let mut generations = segment::list_manifest_generations(paths)?;
            generations.sort_unstable_by(|a, b| b.cmp(a));
            let Some(generation) = generations.into_iter().next() else {
                return Ok(None);
            };
            match load_generation(paths, generation, root_uuid, files) {
                Ok(manifest) => Ok(Some(ManifestSelection {
                    manifest,
                    generation,
                    path: paths.manifest(generation),
                    source: ManifestSource::Fallback { reason },
                    rejected,
                })),
                Err(cause) => {
                    rejected.push((generation, cause));
                    Ok(None)
                }
            }
        }
    }
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

/// Load checkpoints only through the selected manifest's authoritative rows.
///
/// A valid file in the directory is not sufficient authority: it may belong
/// to a newer manifest generation that recovery rejected, or may be an orphan
/// left between checkpoint installation and manifest installation. Selecting
/// it would publish derived state beyond the selected journal/segment closure.
fn load_authoritative_checkpoint(
    paths: &ShardPaths,
    selection: Option<&ManifestSelection>,
    root_uuid: &[u8; 16],
    shard_index: u16,
    checkpoint_retain: u32,
) -> Result<CheckpointLoad, StoreError> {
    let Some(selection) = selection else {
        let stray = crate::checkpoint::list_generations(&paths.checkpoints())?;
        if stray.is_empty() {
            return Ok(CheckpointLoad::Empty);
        }
        return Ok(CheckpointLoad::OfflineRebuildRequired {
            rejected: stray
                .into_iter()
                .map(|(_, path)| {
                    (
                        path,
                        CheckpointError::Body(
                            "checkpoint is unreferenced because no authoritative manifest exists",
                        ),
                    )
                })
                .collect(),
        });
    };

    if selection.manifest.checkpoints.is_empty() {
        return Ok(CheckpointLoad::Empty);
    }

    let max_candidates = (checkpoint_retain.max(2) as usize) * 4;
    let mut rejected = Vec::new();
    for (declared_sequence, filename) in selection
        .manifest
        .checkpoints
        .iter()
        .rev()
        .take(max_candidates.max(1))
    {
        let path = paths.checkpoints().join(filename);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) => {
                rejected.push((path, CheckpointError::Unreadable(error.to_string())));
                continue;
            }
        };
        match Checkpoint::decode(&bytes, root_uuid, shard_index) {
            Ok(checkpoint) if checkpoint.shard_committed_sequence == *declared_sequence => {
                return Ok(CheckpointLoad::Loaded {
                    checkpoint: Box::new(checkpoint),
                    path,
                    rejected,
                });
            }
            Ok(_) => rejected.push((
                path,
                CheckpointError::Body(
                    "checkpoint shard sequence disagrees with authoritative manifest row",
                ),
            )),
            Err(error) => rejected.push((path, error)),
        }
    }
    Ok(CheckpointLoad::OfflineRebuildRequired { rejected })
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

/// Payload state needed for complete root reconstruction but not for the
/// sequence-verification seam represented by [`FrameFacts`].
///
/// Kept separate so adding D0-B recovery state does not break Wave A's public
/// `FrameFacts` struct literals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecoveredPayloadFacts {
    pub ref_updates: Vec<TypedRefCas>,
    pub applied_refs: Vec<crate::types::AppliedRef>,
    pub objects_new: u64,
    pub first_receipt_visibility_micros: Option<i64>,
    pub staged_projection_install: Option<StagedProjectionInstallV1>,
    pub objects: Vec<(ObjectId, u8)>,
}

/// Extracts the payload half of [`FrameFacts`].
pub trait PayloadFacts {
    fn extend(&self, facts: &mut FrameFacts, payload: &[u8]) -> Result<(), StoreError>;

    fn recovered(&self, _payload: &[u8]) -> Result<RecoveredPayloadFacts, StoreError> {
        Ok(RecoveredPayloadFacts::default())
    }

    /// The drive seam predates canonical transaction payloads and can create
    /// opaque scripted frames. Production extractors leave this false:
    /// appearing without a repository-create frame is then corruption.
    fn permits_implicit_namespace_anchor(&self) -> bool {
        false
    }
}

/// Production payload extractor.
///
/// A physical frame is complete without interpreting its payload, but a frame
/// cannot enter a recovered logical root until its transaction payload has
/// also passed the canonical decoder. The drive seam injects its explicit
/// scripted-payload extractor through [`RecoveryConfig`]; production callers
/// use this one.
#[derive(Copy, Clone, Debug, Default)]
pub struct CanonicalPayloadFacts;

impl PayloadFacts for CanonicalPayloadFacts {
    fn extend(&self, facts: &mut FrameFacts, payload: &[u8]) -> Result<(), StoreError> {
        let decoded = TransactionFramePayloadV1::decode_canonical(payload)?;
        let extracted = decoded.facts()?;
        if extracted.repo_id.0 != *facts.namespace.as_bytes() {
            return Err(StoreError::Corruption(format!(
                "frame header names namespace {} but its payload names repository {}",
                facts.namespace.to_hex(),
                hex::encode(extracted.repo_id.0)
            )));
        }
        if extracted.repo_sequence != facts.repo_sequence {
            return Err(StoreError::Corruption(format!(
                "frame header carries repo_sequence {} but its payload carries {}",
                facts.repo_sequence, extracted.repo_sequence
            )));
        }

        facts.event_digest = extracted.event_digest;
        facts.previous_event_digest = extracted.previous_event_digest;
        facts.creates_namespace = decoded.repository_create.is_some();
        facts.genesis_authority = decoded
            .repository_create
            .as_ref()
            .map(|create| create.genesis_authority)
            .unwrap_or(extracted.old_authority);
        facts.current_authority = extracted.new_authority;
        facts.retry_until_micros = extracted.retry_until_micros;
        facts.objects = match decoded.objects {
            FrameObjectsV1::Inline(objects) => objects
                .into_iter()
                .map(|object| (object.object_id, object_type_code(object.object_type)))
                .collect(),
            FrameObjectsV1::StagedProjectionInstall(_) => Vec::new(),
        };
        Ok(())
    }

    fn recovered(&self, payload: &[u8]) -> Result<RecoveredPayloadFacts, StoreError> {
        let decoded = TransactionFramePayloadV1::decode_canonical(payload)?;
        let extracted = decoded.facts()?;
        let mut recovered = RecoveredPayloadFacts {
            ref_updates: decoded.ref_cas.clone(),
            applied_refs: decoded.committed.transaction.refs.clone(),
            objects_new: extracted.objects_new,
            first_receipt_visibility_micros: Some(extracted.first_receipt_visibility_micros),
            ..RecoveredPayloadFacts::default()
        };
        match decoded.objects {
            FrameObjectsV1::Inline(objects) => {
                recovered.objects = objects
                    .into_iter()
                    .map(|object| (object.object_id, object_type_code(object.object_type)))
                    .collect();
            }
            FrameObjectsV1::StagedProjectionInstall(install) => {
                recovered.staged_projection_install = Some(install);
            }
        }
        Ok(recovered)
    }
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
    /// Durable hard link to the original active journal, before recovery
    /// copied or sealed any prefix. The inode is byte-for-byte crash evidence.
    pub preserved_journal: Option<PathBuf>,
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
            preserved_journal: None,
            promotions: Vec::new(),
            ready: false,
        }
    }
}

// ===========================================================================
// Production shard recovery
// ===========================================================================

/// Bounded inputs to the shared recovery path.
///
/// Both `StoreEngine::open` and the `store-internals` drive seam call
/// [`recover_shard`] with this type. The payload extractor is the only
/// deliberate variation: production uses [`CanonicalPayloadFacts`], while the
/// drive also supports the opaque scripted frames its writer API predates.
pub struct RecoveryConfig<'a> {
    pub max_manifest_candidates: usize,
    pub manifest_retain: u32,
    pub checkpoint_retain: u32,
    pub journal_preallocate_bytes: u64,
    pub terminal_status_grace_micros: i64,
    pub max_active_index_entries: u64,
    pub max_active_index_bytes: u64,
    pub max_index_runs: u32,
    pub max_open_index_runs: u32,
    pub max_replay_frames: u64,
    pub max_replay_bytes: u64,
    pub payload_facts: &'a dyn PayloadFacts,
    /// Staging-owned read-only resolution and lifecycle seam.
    ///
    /// A canonical committed staged-install frame cannot become ready without
    /// this resolver supplying its exact namespace membership and live
    /// artifact ownership.
    pub(crate) projection_recovery_resolver: Option<&'a dyn ProjectionRecoveryResolver>,
}

impl<'a> RecoveryConfig<'a> {
    pub fn from_store_options(options: &StoreOptions) -> Self {
        static CANONICAL: CanonicalPayloadFacts = CanonicalPayloadFacts;
        Self {
            max_manifest_candidates: options.manifest_retain as usize,
            manifest_retain: options.manifest_retain,
            checkpoint_retain: options.checkpoint_retain,
            journal_preallocate_bytes: options.journal_preallocate_bytes,
            terminal_status_grace_micros: options.terminal_status_grace_micros,
            max_active_index_entries: options.max_active_index_entries,
            max_active_index_bytes: options.max_active_index_bytes,
            max_index_runs: options.max_index_runs,
            max_open_index_runs: options.max_open_index_runs,
            max_replay_frames: options.max_replay_frames,
            max_replay_bytes: options.max_replay_bytes,
            payload_facts: &CANONICAL,
            projection_recovery_resolver: None,
        }
    }

    pub(crate) fn with_projection_recovery_resolver(
        mut self,
        resolver: &'a dyn ProjectionRecoveryResolver,
    ) -> Self {
        self.projection_recovery_resolver = Some(resolver);
        self
    }
}

/// Root-wide recovery and ownership session.
///
/// A store root may contain several shards, but `LOCK` is root-wide. B1 opens
/// one session, recovers every shard through it, and retains the session for
/// the engine's lifetime. That prevents another process from entering between
/// shard recoveries or immediately after readiness. The drive's one-shot
/// [`recover_shard`] wrapper uses the same type and simply drops it afterward.
pub struct RecoverySession {
    layout: RootLayout,
    root_uuid: [u8; 16],
    shard_count: u16,
    /// The root lock, released explicitly when the session drops. Not a bare
    /// `File`: `flock` lives on the open file description, so a concurrently
    /// forked child that inherited this descriptor would keep the lock alive
    /// past the close. See [`segment::RootLock`].
    _lock: segment::RootLock,
}

impl std::fmt::Debug for RecoverySession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoverySession")
            .field("root", &self.layout.root)
            .field("root_uuid", &hex::encode(self.root_uuid))
            .field("shard_count", &self.shard_count)
            .finish_non_exhaustive()
    }
}

impl RecoverySession {
    pub fn open(root: &Path) -> Result<Self, StoreError> {
        let layout = RootLayout::new(root);
        // Validate FORMAT before taking LOCK so an unrecognized root is never
        // modified merely by attempting to open it.
        let marker = segment::read_format(&layout)?;
        let lock = segment::lock_root(&layout)?;
        Ok(Self {
            layout,
            root_uuid: marker.root_uuid,
            shard_count: marker.shard_count,
            _lock: lock,
        })
    }

    pub fn root(&self) -> &Path {
        &self.layout.root
    }

    pub fn root_uuid(&self) -> [u8; 16] {
        self.root_uuid
    }

    pub fn shard_count(&self) -> u16 {
        self.shard_count
    }

    pub fn recover_shard(
        &self,
        shard: u16,
        config: &RecoveryConfig<'_>,
    ) -> Result<RecoveredShard, StoreError> {
        recover_shard_under_lock(self, shard, config)
    }
}

/// One manifest-retained sealed segment, kept open for the recovered root's
/// lifetime.
#[derive(Clone)]
pub struct RecoveredSegment {
    pub generation: u64,
    pub first_shard_sequence: u64,
    pub last_shard_sequence: u64,
    pub path: PathBuf,
    pub reader: Arc<SegmentReader>,
}

impl std::fmt::Debug for RecoveredSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveredSegment")
            .field("generation", &self.generation)
            .field("first_shard_sequence", &self.first_shard_sequence)
            .field("last_shard_sequence", &self.last_shard_sequence)
            .field("path", &self.path)
            .finish()
    }
}

impl PartialEq for RecoveredSegment {
    fn eq(&self, other: &Self) -> bool {
        self.generation == other.generation
            && self.first_shard_sequence == other.first_shard_sequence
            && self.last_shard_sequence == other.last_shard_sequence
            && self.path == other.path
    }
}

impl Eq for RecoveredSegment {}

/// The fresh active journal recovery fenced before reporting write readiness.
#[derive(Clone, Debug)]
pub struct RecoveredTail {
    pub logical_generation: u64,
    pub journal_id: [u8; 16],
    pub path: PathBuf,
    pub validated_through: u64,
    file: Arc<File>,
}

impl RecoveredTail {
    pub fn file(&self) -> &File {
        &self.file
    }
}

impl PartialEq for RecoveredTail {
    fn eq(&self, other: &Self) -> bool {
        self.logical_generation == other.logical_generation
            && self.journal_id == other.journal_id
            && self.path == other.path
            && self.validated_through == other.validated_through
    }
}

impl Eq for RecoveredTail {}

/// Everything needed to construct one shard of `CommittedRoot`.
#[derive(Clone, Debug)]
pub struct RecoveredShard {
    pub shard_index: u16,
    pub catalog: NamespaceCatalog,
    pub refs: Vec<RefRecord>,
    pub receipts: Vec<ReceiptRecord>,
    pub index: LayeredObjectIndex,
    /// Live ownership of every artifact retained by the selected generation.
    pub retained_generation: Arc<RetainedGeneration>,
    pub segments: Vec<RecoveredSegment>,
    pub tail: Option<RecoveredTail>,
    pub manifest_generation: Option<u64>,
    pub manifest_path: Option<PathBuf>,
    pub committed_shard_sequence: Option<u64>,
    pub repo_sequences: BTreeMap<NamespaceId, u64>,
    pub projection_resolutions: Vec<RecoveredProjectionResolution>,
    pub tail_stop_offset: Option<u64>,
    pub report: ShardRecoveryReport,
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

#[derive(Clone, Debug)]
struct ReplayedFrame {
    facts: FrameFacts,
    payload: RecoveredPayloadFacts,
    generation: u64,
    offset: u64,
    len: u64,
}

/// Shared, non-feature-gated production recovery entry point.
///
/// This function is the one ordering of recovery steps 1–12. The engine and
/// drive seam may choose different payload extractors, but neither owns a
/// manifest, checkpoint, tail, sequence, visibility, or index decision.
pub fn recover_shard(
    root: &Path,
    shard: u16,
    config: &RecoveryConfig<'_>,
) -> Result<RecoveredShard, StoreError> {
    RecoverySession::open(root)?.recover_shard(shard, config)
}

fn recover_shard_under_lock(
    session: &RecoverySession,
    shard: u16,
    config: &RecoveryConfig<'_>,
) -> Result<RecoveredShard, StoreError> {
    if shard >= session.shard_count {
        return Err(StoreError::FormatMismatch(format!(
            "shard {shard} is outside the root's frozen topology of {} shards",
            session.shard_count
        )));
    }
    let layout = &session.layout;
    let root_uuid = session.root_uuid;
    let paths = layout.shard(shard);
    let counters = Arc::new(DurabilityCounters::default());
    let mut report = ShardRecoveryReport::new(shard);

    let referents = ProductionReferentValidator {
        root_uuid,
        shard_index: shard,
    };
    let selection = resolve_manifest(
        &paths,
        &root_uuid,
        &referents,
        config.max_manifest_candidates,
    )?;
    let mut selection = match selection {
        Some(selection) => {
            report.manifest_generation = Some(selection.generation);
            report.manifest_source = Some(selection.source.clone());
            Some(selection)
        }
        None if segment::list_manifest_generations(&paths)?.is_empty() => None,
        None => return Err(StoreError::RecoveryRequired),
    };

    let mut segments = Vec::new();
    let mut sealed_runs_newest_first = Vector::new();
    let mut retained_index_runs = Vec::new();
    let mut retained_checkpoints = Vec::new();
    if let Some(selection) = &selection {
        if selection.manifest.index_runs.len() as u64 > config.max_index_runs as u64 {
            return Err(StoreError::LimitExceeded {
                limit: "max_index_runs",
                observed: selection.manifest.index_runs.len() as u64,
                allowed: config.max_index_runs as u64,
            });
        }
        if selection.manifest.index_runs.len() as u64 > config.max_open_index_runs as u64 {
            return Err(StoreError::LimitExceeded {
                limit: "max_open_index_runs",
                observed: selection.manifest.index_runs.len() as u64,
                allowed: config.max_open_index_runs as u64,
            });
        }
        for (generation, filename) in selection.manifest.index_runs.iter().rev() {
            let path = paths.indexes().join(filename);
            let run = Arc::new(IndexRun::open(&path, &root_uuid)?);
            if run.generation() != *generation {
                return Err(StoreError::Corruption(format!(
                    "manifest names index generation {generation}, but {} carries generation {}",
                    path.display(),
                    run.generation()
                )));
            }
            sealed_runs_newest_first.push_back(Arc::clone(&run));
            retained_index_runs.push(RetainedIndexRun::new(path, run));
        }
        for (_, filename) in &selection.manifest.checkpoints {
            let path = paths.checkpoints().join(filename);
            retained_checkpoints.push(PinnedFile::open(path)?);
        }
    }

    let load = load_authoritative_checkpoint(
        &paths,
        selection.as_ref(),
        &root_uuid,
        shard,
        config.checkpoint_retain,
    )?;
    let selected_checkpoint = match &load {
        CheckpointLoad::Loaded {
            checkpoint, path, ..
        } => Some((checkpoint.shard_committed_sequence, path.clone())),
        CheckpointLoad::Empty | CheckpointLoad::OfflineRebuildRequired { .. } => None,
    };
    let checkpoint = match checkpoint_for_recovery(load, &root_uuid, shard, &mut report) {
        Some(checkpoint) => checkpoint,
        None => {
            debug_assert!(report.offline_rebuild_required);
            return Err(StoreError::RecoveryRequired);
        }
    };
    if let Some((_, path)) = selected_checkpoint {
        if !retained_checkpoints
            .iter()
            .any(|entry| entry.path() == path)
        {
            retained_checkpoints.push(PinnedFile::open(path)?);
        }
    }

    let checkpointed = report.checkpoint_sequence.is_some();
    let committed = checkpoint.shard_committed_sequence;
    let mut adopted_shard_sequences = Vec::new();
    let mut replayed = Vec::new();
    let mut replayed_bytes = 0u64;
    let mut retained_segments = Vec::new();
    let mut retained_tails = Vec::new();
    if checkpointed {
        let mut accounted: Vec<u64> = checkpoint
            .receipts
            .iter()
            .map(|receipt| receipt.shard_sequence)
            .filter(|sequence| *sequence <= committed)
            .collect();
        accounted.sort_unstable();
        adopted_shard_sequences.extend(accounted);
    }

    if let Some(selection) = &selection {
        for range in &selection.manifest.retained_tail_ranges {
            let path = paths.segments().join(&range.filename);
            let reader = Arc::new(SegmentReader::open(&path, &root_uuid)?);
            validate_journal_binding(
                &reader.journal_header()?,
                &root_uuid,
                shard,
                Some(&reader.footer().journal_id),
                None,
            )?;
            if reader.footer().generation != range.generation
                || reader.footer().first_shard_sequence != range.first_shard_sequence
                || reader.footer().last_shard_sequence != range.last_shard_sequence
            {
                return Err(StoreError::Corruption(format!(
                    "manifest range does not match sealed segment {}",
                    path.display()
                )));
            }

            if !checkpointed || range.last_shard_sequence > committed {
                for (sequence, offset, len) in reader.footer().offsets.clone() {
                    if checkpointed && sequence <= committed {
                        continue;
                    }
                    let frame = reader.read_frame(sequence)?;
                    let (facts, payload) = frame_facts(&frame, config.payload_facts)?;
                    account_replay(config, &mut replayed_bytes, len, replayed.len() as u64 + 1)?;
                    adopted_shard_sequences.push(sequence);
                    replayed.push(ReplayedFrame {
                        facts,
                        payload,
                        generation: range.generation,
                        offset,
                        len,
                    });
                }
            }
            retained_segments.push(RootRetainedSegment::new(
                range.generation,
                reader.footer().journal_id,
                range.first_shard_sequence,
                range.last_shard_sequence,
                PinnedFile::open(paths.segments().join(&range.filename))?,
            ));
            segments.push(RecoveredSegment {
                generation: range.generation,
                first_shard_sequence: range.first_shard_sequence,
                last_shard_sequence: range.last_shard_sequence,
                path,
                reader,
            });
        }
    }

    let mut tail_stop_offset = None;
    let mut quarantined_bytes = 0;
    let mut recovered_tail = None;
    let mut must_create_fresh = false;
    let mut fresh_preallocation = config.journal_preallocate_bytes;
    if let Some(path) = active_journal_path(&paths)? {
        let file = File::open(&path)?;
        let mut header_bytes = [0u8; JOURNAL_HEADER_LEN];
        sys::pread_exact(&file, 0, &mut header_bytes)?;
        let header = JournalHeader::decode(&header_bytes)?;
        fresh_preallocation = header.preallocated_len;
        let manifest_covered_through = selection.as_ref().and_then(|selected| {
            selected
                .manifest
                .retained_tail_ranges
                .last()
                .map(|range| range.last_shard_sequence)
        });
        let covered_through = if checkpointed {
            Some(manifest_covered_through.unwrap_or(committed).max(committed))
        } else {
            manifest_covered_through
        };
        validate_journal_binding(&header, &root_uuid, shard, None, covered_through)?;

        let disposition = match &selection {
            Some(selection) => classify_active_journal(
                &paths,
                &selection.manifest,
                &header.journal_id,
                &root_uuid,
            )?,
            None => ActiveJournalDisposition::Replay,
        };
        report.active_journal = Some(disposition.clone());
        match disposition {
            ActiveJournalDisposition::AlreadySealed { .. } => {
                report.preserved_journal = Some(preserve_crash_journal(
                    &path,
                    &layout.quarantine_dir(),
                    &header,
                    &counters,
                )?);
                drop(file);
                complete_interrupted_seal(&path, &paths, &counters)?;
                must_create_fresh = true;
            }
            ActiveJournalDisposition::Replay => {
                let recovery_generation = recovery_generation_for_journal(
                    &paths,
                    &root_uuid,
                    &header.journal_id,
                    config,
                )?;
                let from = if checkpointed && checkpoint.active_journal_id == header.journal_id {
                    checkpoint
                        .active_journal_offset
                        .max(JOURNAL_HEADER_LEN as u64)
                } else {
                    JOURNAL_HEADER_LEN as u64
                };
                let full_scan =
                    crate::journal::scan_journal(&file, &header, JOURNAL_HEADER_LEN as u64);
                let resumes_checkpoint_journal =
                    checkpointed && checkpoint.active_journal_id == header.journal_id;
                if !resumes_checkpoint_journal {
                    if let (Some(covered), Some(first)) =
                        (covered_through, full_scan.frames.first())
                    {
                        if first.shard_sequence <= covered {
                            return Err(ShardSequenceFault::Duplicate {
                                shard_sequence: first.shard_sequence,
                            }
                            .into());
                        }
                        let expected = covered.saturating_add(1);
                        if first.shard_sequence != expected {
                            return Err(ShardSequenceFault::Gap {
                                expected,
                                observed: first.shard_sequence,
                            }
                            .into());
                        }
                    }
                }
                let (scan, record) = recover_journal_tail(
                    &layout.quarantine_dir(),
                    &file,
                    &header,
                    from,
                    &counters,
                )?;
                quarantined_bytes = record.as_ref().map(|record| record.bytes).unwrap_or(0);
                report.quarantined = record.map(|record| record.path);
                for scanned in &scan.frames {
                    let mut frame_bytes =
                        vec![0u8; usize::try_from(scanned.len).map_err(|_| FrameError::Length)?];
                    sys::pread_exact(&file, scanned.offset, &mut frame_bytes)?;
                    let frame = Frame::decode(&frame_bytes, &header.journal_id)?;
                    let (facts, payload) = frame_facts(&frame, config.payload_facts)?;
                    account_replay(
                        config,
                        &mut replayed_bytes,
                        scanned.len,
                        replayed.len() as u64 + 1,
                    )?;
                    adopted_shard_sequences.push(scanned.shard_sequence);
                    replayed.push(ReplayedFrame {
                        facts,
                        payload,
                        generation: recovery_generation,
                        offset: scanned.offset,
                        len: scanned.len,
                    });
                }
                tail_stop_offset = match scan.stop {
                    TailStop::EndOfPreallocation => None,
                    TailStop::NotAFrame => (quarantined_bytes > 0).then_some(scan.stop_offset),
                    TailStop::Incomplete(_) | TailStop::ReadError => Some(scan.stop_offset),
                };
                report.tail_stop = Some(scan.stop.clone());

                let damaged = matches!(
                    full_scan.stop,
                    TailStop::Incomplete(_) | TailStop::ReadError | TailStop::EndOfPreallocation
                ) || quarantined_bytes > 0;
                let must_replace = damaged || !full_scan.frames.is_empty();
                if must_replace {
                    report.preserved_journal = Some(preserve_crash_journal(
                        &path,
                        &layout.quarantine_dir(),
                        &header,
                        &counters,
                    )?);

                    if !full_scan.frames.is_empty() {
                        let segment_path = segment::seal_recovered_prefix(
                            &file,
                            &header,
                            &full_scan,
                            &paths,
                            recovery_generation,
                            &counters,
                        )?;
                        let filename = segment_path
                            .file_name()
                            .and_then(|name| name.to_str())
                            .ok_or_else(|| {
                                StoreError::Corruption(
                                    "recovery segment name is not valid UTF-8".into(),
                                )
                            })?
                            .to_string();
                        let first = full_scan.frames.first().expect("non-empty").shard_sequence;
                        let last = full_scan.frames.last().expect("non-empty").shard_sequence;

                        let (mut retained_tail_ranges, index_runs, checkpoints) = selection
                            .as_ref()
                            .map(|selected| {
                                (
                                    selected.manifest.retained_tail_ranges.clone(),
                                    selected.manifest.index_runs.clone(),
                                    selected.manifest.checkpoints.clone(),
                                )
                            })
                            .unwrap_or((Vec::new(), Vec::new(), Vec::new()));
                        retained_tail_ranges.push(TailRange {
                            generation: recovery_generation,
                            first_shard_sequence: first,
                            last_shard_sequence: last,
                            filename,
                        });
                        let manifest = Manifest {
                            root_uuid,
                            generation: recovery_generation,
                            base_generation: 0,
                            retained_tail_ranges,
                            index_runs,
                            checkpoints,
                            committed_shard_sequence: last,
                        };
                        validate_manifest_sequence_coverage(&manifest)
                            .map_err(StoreError::Corruption)?;
                        segment::install_manifest(
                            &paths,
                            &manifest,
                            config.manifest_retain,
                            &counters,
                        )?;

                        let reader = Arc::new(SegmentReader::open(&segment_path, &root_uuid)?);
                        retained_segments.push(RootRetainedSegment::new(
                            recovery_generation,
                            header.journal_id,
                            first,
                            last,
                            PinnedFile::open(segment_path.clone())?,
                        ));
                        segments.push(RecoveredSegment {
                            generation: recovery_generation,
                            first_shard_sequence: first,
                            last_shard_sequence: last,
                            path: segment_path,
                            reader,
                        });

                        let manifest_path = paths.manifest(recovery_generation);
                        selection = Some(ManifestSelection {
                            manifest,
                            generation: recovery_generation,
                            path: manifest_path,
                            source: ManifestSource::Current,
                            rejected: Vec::new(),
                        });
                        report.manifest_generation = Some(recovery_generation);
                    }

                    drop(file);
                    complete_interrupted_seal(&path, &paths, &counters)?;
                    must_create_fresh = true;
                } else {
                    let shared_file = Arc::new(file);
                    let retained_tail =
                        PinnedFile::from_shared(path.clone(), Arc::clone(&shared_file));
                    recovered_tail = Some(RecoveredTail {
                        logical_generation: recovery_generation,
                        journal_id: header.journal_id,
                        path,
                        validated_through: JOURNAL_HEADER_LEN as u64,
                        file: shared_file,
                    });
                    retained_tails.push(RetainedTail::new(recovery_generation, retained_tail));
                }
            }
        }
    } else {
        must_create_fresh = true;
    }

    if must_create_fresh {
        let last_committed = selection
            .as_ref()
            .and_then(|selected| {
                selected
                    .manifest
                    .retained_tail_ranges
                    .last()
                    .map(|range| range.last_shard_sequence)
            })
            .or(checkpointed.then_some(committed));
        let first_shard_sequence = last_committed
            .map(|sequence| sequence.saturating_add(1))
            .unwrap_or(0);
        let logical_generation = selection
            .as_ref()
            .and_then(|selected| {
                selected
                    .manifest
                    .retained_tail_ranges
                    .last()
                    .map(|range| range.generation)
            })
            .unwrap_or(0)
            .saturating_add(1);
        let (tail, retained) = create_fresh_active_journal(
            &paths,
            root_uuid,
            shard,
            first_shard_sequence,
            fresh_preallocation,
            logical_generation,
            Arc::clone(&counters),
        )?;
        recovered_tail = Some(tail);
        retained_tails.push(retained);
    }

    let replayed_facts: Vec<FrameFacts> =
        replayed.iter().map(|frame| frame.facts.clone()).collect();
    let mut catalog = checkpoint.catalog.clone();
    verify_and_apply_catalog(
        &replayed_facts,
        checkpointed.then(|| committed.saturating_add(1)),
        &mut catalog,
        config.payload_facts.permits_implicit_namespace_anchor(),
    )?;

    let recovery_publication_micros = now_micros();
    let mut receipts = checkpoint.receipts.clone();
    for frame in &replayed {
        receipts.push(receipt_for_recovery(frame, recovery_publication_micros));
    }
    report.promotions = promote_receipt_visibility(
        &mut receipts,
        recovery_publication_micros,
        config.terminal_status_grace_micros,
    )?;

    let mut refs = checkpoint.refs.clone();
    apply_recovered_refs(&mut refs, &replayed)?;

    let mut delta = IndexDelta::new(
        config.max_active_index_entries,
        config.max_active_index_bytes,
    );
    for frame in &replayed {
        let frame_len = u32::try_from(frame.len).map_err(|_| StoreError::LimitExceeded {
            limit: "frame_len",
            observed: frame.len,
            allowed: u32::MAX as u64,
        })?;
        for (object, object_type) in &frame.payload.objects {
            delta.insert(
                IndexKey::new(frame.facts.namespace, *object),
                IndexLocation {
                    segment_generation: frame.generation,
                    frame_offset: frame.offset,
                    frame_len,
                    object_type: *object_type,
                    shard_sequence: frame.facts.shard_sequence,
                },
            )?;
        }
    }

    // Resolve committed staged projections newest-first so their membership
    // layers preserve the same first-hit ordering as ordinary replay. A final
    // frame is already authoritative here; missing staging ownership is
    // corruption and cannot be converted into an empty projection.
    let mut committed_sessions = BTreeSet::new();
    let mut recovered_projections: Vec<(u64, RecoveredProjectionArtifacts)> = Vec::new();
    for frame in replayed.iter().rev() {
        let Some(descriptor) = frame.payload.staged_projection_install.as_ref() else {
            continue;
        };
        if !committed_sessions.insert(descriptor.session_id) {
            return Err(StoreError::Corruption(format!(
                "staged projection session {} appears in more than one committed frame",
                hex::encode(descriptor.session_id)
            )));
        }
        let resolver = config.projection_recovery_resolver.ok_or_else(|| {
            StoreError::Corruption(format!(
                "committed staged projection session {} has no recovery resolver",
                hex::encode(descriptor.session_id)
            ))
        })?;
        let artifacts = resolver.resolve_committed(frame.facts.namespace, descriptor)?;
        if artifacts.descriptor() != descriptor {
            return Err(StoreError::Corruption(format!(
                "staging recovery returned a different descriptor for committed session {}",
                hex::encode(descriptor.session_id)
            )));
        }
        recovered_projections.push((frame.facts.shard_sequence, artifacts));
    }

    let mut projection_outcomes = BTreeMap::new();
    if let Some(resolver) = config.projection_recovery_resolver {
        for session_id in resolver.transferred_sessions(shard)?.iter().copied() {
            projection_outcomes
                .entry(session_id)
                .or_insert(RecoveredProjectionOutcome::ProvedAbsent);
        }
    }
    for session_id in committed_sessions {
        projection_outcomes.insert(session_id, RecoveredProjectionOutcome::Committed);
    }
    let projection_resolutions: Vec<_> = projection_outcomes
        .into_iter()
        .map(|(session_id, outcome)| RecoveredProjectionResolution {
            session_id,
            outcome,
        })
        .collect();

    report.adopted_shard_sequences = adopted_shard_sequences;
    report.quarantined_bytes = quarantined_bytes;
    report.ready = !report.offline_rebuild_required && recovered_tail.is_some();
    let committed_shard_sequence = replayed
        .last()
        .map(|frame| frame.facts.shard_sequence)
        .or(checkpointed.then_some(committed))
        .or_else(|| {
            selection.as_ref().and_then(|selected| {
                selected
                    .manifest
                    .retained_tail_ranges
                    .last()
                    .map(|range| range.last_shard_sequence)
            })
        });
    let repo_sequences = catalog
        .iter()
        .map(|(namespace, record)| (*namespace, record.repo_sequence))
        .collect();

    let through_shard_sequence = committed_shard_sequence.unwrap_or(0);
    let mut delta_layers_newest_first = Vector::new();
    if !delta.is_empty() {
        delta_layers_newest_first.push_back(IndexDeltaLayer::new(
            shard,
            through_shard_sequence,
            Arc::new(delta),
        ));
    }
    let mut all_runs_newest_first = Vector::new();
    let mut retained_projection_artifacts = Vec::new();
    for (shard_sequence, artifacts) in &recovered_projections {
        if !artifacts.index_delta().is_empty() {
            delta_layers_newest_first.push_back(IndexDeltaLayer::new(
                shard,
                *shard_sequence,
                Arc::clone(artifacts.index_delta()),
            ));
        }
        for run in artifacts.index_runs_newest_first() {
            all_runs_newest_first.push_back(Arc::clone(run));
        }
        retained_index_runs.extend_from_slice(artifacts.retained_index_runs());
        retained_projection_artifacts.extend_from_slice(artifacts.retained_artifacts());
    }
    for run in sealed_runs_newest_first {
        all_runs_newest_first.push_back(run);
    }
    let open_run_count = u64::try_from(all_runs_newest_first.len()).unwrap_or(u64::MAX);
    if open_run_count > u64::from(config.max_index_runs) {
        return Err(StoreError::LimitExceeded {
            limit: "max_index_runs",
            observed: open_run_count,
            allowed: u64::from(config.max_index_runs),
        });
    }
    if open_run_count > u64::from(config.max_open_index_runs) {
        return Err(StoreError::LimitExceeded {
            limit: "max_open_index_runs",
            observed: open_run_count,
            allowed: u64::from(config.max_open_index_runs),
        });
    }
    validate_retained_object_sources(
        &retained_segments,
        &retained_tails,
        &retained_projection_artifacts,
    )?;
    let index = LayeredObjectIndex::new(delta_layers_newest_first, all_runs_newest_first);
    let generation_id = GenerationId::new(
        shard,
        selection
            .as_ref()
            .map(|selection| selection.generation)
            .unwrap_or(0),
    );
    let retained_generation = Arc::new(RetainedGeneration::new(
        generation_id,
        retained_segments.into(),
        retained_index_runs.into(),
        retained_checkpoints.into(),
        retained_tails.into(),
        retained_projection_artifacts.into(),
    ));

    let recovered = RecoveredShard {
        shard_index: shard,
        catalog,
        refs,
        receipts,
        index,
        retained_generation,
        segments,
        tail: recovered_tail,
        manifest_generation: selection.as_ref().map(|selection| selection.generation),
        manifest_path: selection.as_ref().map(|selection| selection.path.clone()),
        committed_shard_sequence,
        repo_sequences,
        projection_resolutions,
        tail_stop_offset,
        report,
    };

    // Lifecycle notification is last. At this point the complete physical
    // proof, lookup layers, and every live pin are held by `recovered`.
    // Implementations must make notification idempotent because a later
    // notification failure keeps the shard unready and recovery retries.
    if let Some(resolver) = config.projection_recovery_resolver {
        for resolution in recovered.projection_resolutions.iter().copied() {
            resolver.notify_recovered(resolution)?;
        }
    }

    Ok(recovered)
}

fn validate_retained_object_sources(
    segments: &[RootRetainedSegment],
    tails: &[RetainedTail],
    projections: &[RetainedProjectionArtifact],
) -> Result<(), StoreError> {
    let mut generations: BTreeMap<u64, (&'static str, PathBuf)> = BTreeMap::new();
    let mut insert = |generation: u64, kind: &'static str, path: &Path| {
        if let Some((existing_kind, existing_path)) = generations.get(&generation) {
            if *existing_kind != kind || existing_path.as_path() != path {
                return Err(StoreError::Corruption(format!(
                    "logical object generation {generation} names both {existing_kind} {} and \
                     {kind} {}",
                    existing_path.display(),
                    path.display()
                )));
            }
        } else {
            generations.insert(generation, (kind, path.to_path_buf()));
        }
        Ok(())
    };
    for segment in segments {
        insert(segment.logical_generation, "segment", segment.path())?;
    }
    for tail in tails {
        insert(tail.logical_generation, "active tail", tail.path())?;
    }
    for projection in projections {
        insert(
            projection.logical_generation,
            "projection artifact",
            projection.path(),
        )?;
    }
    Ok(())
}

fn account_replay(
    config: &RecoveryConfig<'_>,
    bytes: &mut u64,
    frame_len: u64,
    frames: u64,
) -> Result<(), StoreError> {
    if frames > config.max_replay_frames {
        return Err(StoreError::LimitExceeded {
            limit: "max_replay_frames",
            observed: frames,
            allowed: config.max_replay_frames,
        });
    }
    *bytes = bytes
        .checked_add(frame_len)
        .ok_or(StoreError::LimitExceeded {
            limit: "max_replay_bytes",
            observed: u64::MAX,
            allowed: config.max_replay_bytes,
        })?;
    if *bytes > config.max_replay_bytes {
        return Err(StoreError::LimitExceeded {
            limit: "max_replay_bytes",
            observed: *bytes,
            allowed: config.max_replay_bytes,
        });
    }
    Ok(())
}

fn frame_facts(
    frame: &Frame,
    payload: &dyn PayloadFacts,
) -> Result<(FrameFacts, RecoveredPayloadFacts), StoreError> {
    let mut facts = FrameFacts::from_header(&frame.header);
    payload.extend(&mut facts, &frame.payload)?;
    let recovered = payload.recovered(&frame.payload)?;
    Ok((facts, recovered))
}

fn verify_and_apply_catalog(
    replayed: &[FrameFacts],
    first_expected: Option<u64>,
    catalog: &mut NamespaceCatalog,
    permits_implicit_namespace_anchor: bool,
) -> Result<(), StoreError> {
    if let Some(first_expected) =
        first_expected.or_else(|| replayed.first().map(|f| f.shard_sequence))
    {
        verify_shard_sequence(replayed, first_expected)?;
    }

    if permits_implicit_namespace_anchor {
        let mut anchored = catalog.clone();
        let mut chained = Vec::new();
        for facts in replayed {
            if anchored.get(&facts.namespace).is_none() {
                anchored.bind(crate::index::NamespaceRecord {
                    namespace: facts.namespace,
                    genesis_authority: facts.genesis_authority,
                    current_authority: facts.current_authority,
                    lifecycle: crate::index::NamespaceLifecycle::Active,
                    storage_mode: crate::index::NamespaceStorageMode::Full,
                    repo_sequence: facts.repo_sequence,
                    previous_event_digest: facts.event_digest,
                })?;
            } else {
                chained.push(facts.clone());
            }
        }
        verify_repo_chain(&chained, &anchored)?;
    } else {
        verify_repo_chain(replayed, catalog)?;
    }

    for facts in replayed {
        if catalog.get(&facts.namespace).is_none() {
            if !facts.creates_namespace && !permits_implicit_namespace_anchor {
                return Err(RepoSequenceFault::UnknownNamespace {
                    namespace: facts.namespace.to_hex(),
                }
                .into());
            }
            catalog.bind(crate::index::NamespaceRecord {
                namespace: facts.namespace,
                genesis_authority: facts.genesis_authority,
                current_authority: facts.current_authority,
                lifecycle: crate::index::NamespaceLifecycle::Active,
                storage_mode: crate::index::NamespaceStorageMode::Full,
                repo_sequence: facts.repo_sequence,
                previous_event_digest: facts.event_digest,
            })?;
        } else {
            catalog.advance(
                &facts.namespace,
                facts.current_authority,
                facts.repo_sequence,
                facts.event_digest,
            )?;
        }
    }
    Ok(())
}

fn receipt_for_recovery(frame: &ReplayedFrame, visible_at: i64) -> ReceiptRecord {
    let facts = &frame.facts;
    ReceiptRecord {
        namespace: facts.namespace,
        operation_id: facts.operation_id,
        operation_digest: facts.operation_digest,
        repo_sequence: facts.repo_sequence,
        shard_sequence: facts.shard_sequence,
        current_authority: facts.current_authority,
        refs: frame.payload.applied_refs.clone(),
        objects_new: frame.payload.objects_new,
        retry_until_micros: facts.retry_until_micros,
        // A replayed receipt's original first-visibility instant was not
        // durably checkpointed. Step 10 promotes it to publication below.
        first_receipt_visibility_micros: None,
        receipt_visible_until_micros: visible_at,
    }
}

fn apply_recovered_refs(
    refs: &mut Vec<RefRecord>,
    replayed: &[ReplayedFrame],
) -> Result<(), StoreError> {
    // Keyed by the typed target, not by the physical `(ref_kind, name)` pair.
    // Replay compares a checkpointed record against a frame's `RefTarget`, so
    // whichever side is converted, one of them is being interpreted — and doing
    // it here meant restating the checkpoint's code table in a module that has
    // no way to notice when the two drift.
    let mut state: BTreeMap<(NamespaceId, RefTarget), ObjectId> = refs
        .iter()
        .map(|record| Ok(((record.namespace, record.target()?), record.target)))
        .collect::<Result<_, CheckpointError>>()?;

    for frame in replayed {
        let facts = &frame.facts;
        for update in &frame.payload.ref_updates {
            let key = (facts.namespace, update.target.clone());
            let observed = state.get(&key).copied();
            if observed != update.expected {
                return Err(StoreError::Corruption(format!(
                    "committed ref CAS for namespace {} does not match recovered state",
                    facts.namespace.to_hex()
                )));
            }
            match update.mutation {
                RefMutation::Set(target) => {
                    state.insert(key, target);
                }
                RefMutation::Delete => {
                    state.remove(&key);
                }
            }
        }
    }

    *refs = state
        .into_iter()
        .map(|((namespace, target), object)| RefRecord::from_target(namespace, &target, object))
        .collect();
    Ok(())
}

fn recovery_generation_for_journal(
    paths: &ShardPaths,
    root_uuid: &[u8; 16],
    active_journal_id: &[u8; 16],
    config: &RecoveryConfig<'_>,
) -> Result<u64, StoreError> {
    let per_manifest = usize::try_from(config.max_index_runs)
        .unwrap_or(usize::MAX)
        .saturating_add(config.checkpoint_retain as usize)
        .saturating_add(16);
    let budget = config
        .max_manifest_candidates
        .max(1)
        .saturating_mul(per_manifest)
        .max(64);
    let mut inspected = 0usize;
    let mut maximum = 0u64;
    let mut resumable = BTreeSet::new();

    let manifests = segment::list_manifest_generations(paths)?;
    inspected = inspected.saturating_add(manifests.len());
    if inspected > budget {
        return Err(StoreError::LimitExceeded {
            limit: "recovery_generation_artifacts",
            observed: inspected as u64,
            allowed: budget as u64,
        });
    }
    maximum = maximum.max(manifests.into_iter().max().unwrap_or(0));

    for (dir, extension) in [(paths.segments(), "seg"), (paths.indexes(), "idx")] {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|value| value.to_str()) != Some(extension) {
                continue;
            }
            inspected = inspected.saturating_add(1);
            if inspected > budget {
                return Err(StoreError::LimitExceeded {
                    limit: "recovery_generation_artifacts",
                    observed: inspected as u64,
                    allowed: budget as u64,
                });
            }
            let name = path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| {
                    StoreError::Corruption(format!(
                        "immutable artifact name {} is not UTF-8",
                        path.display()
                    ))
                })?;
            let stem = name.strip_suffix(&format!(".{extension}")).ok_or_else(|| {
                StoreError::Corruption(format!(
                    "immutable artifact {} has an invalid extension",
                    path.display()
                ))
            })?;
            let decoded_generation = if extension == "seg" {
                SegmentReader::open(&path, root_uuid).ok().map(|reader| {
                    if &reader.footer().journal_id == active_journal_id {
                        resumable.insert(reader.footer().generation);
                    }
                    reader.footer().generation
                })
            } else {
                IndexRun::open(&path, root_uuid)
                    .ok()
                    .map(|run| run.generation())
            };
            let generation = decoded_generation
                .or_else(|| {
                    let text = if extension == "seg" {
                        stem.split('-').next().unwrap_or("")
                    } else {
                        stem
                    };
                    text.parse::<u64>().ok()
                })
                .ok_or_else(|| {
                    StoreError::Corruption(format!(
                        "immutable artifact {} is invalid and has no generation in its name",
                        path.display()
                    ))
                })?;
            maximum = maximum.max(generation);
        }
    }

    let prefix = format!(".recovery-{}-", hex::encode(active_journal_id));
    let entries = std::fs::read_dir(paths.segments())?;
    for entry in entries {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(generation_text) = name
            .strip_prefix(&prefix)
            .and_then(|suffix| suffix.strip_suffix(".prefix"))
        else {
            continue;
        };
        inspected = inspected.saturating_add(1);
        if inspected > budget {
            return Err(StoreError::LimitExceeded {
                limit: "recovery_generation_artifacts",
                observed: inspected as u64,
                allowed: budget as u64,
            });
        }
        let generation = generation_text.parse::<u64>().map_err(|_| {
            StoreError::Corruption(format!(
                "recovery prefix {} has an invalid generation",
                path.display()
            ))
        })?;
        maximum = maximum.max(generation);
        resumable.insert(generation);
    }

    if resumable.len() > 1 {
        return Err(StoreError::Corruption(format!(
            "active journal {} has recovery artifacts in multiple generations: {:?}",
            hex::encode(active_journal_id),
            resumable
        )));
    }
    if let Some(generation) = resumable.into_iter().next() {
        if generation != maximum {
            return Err(StoreError::Corruption(format!(
                "recovery artifact generation {generation} for journal {} is below occupied \
                 immutable generation {maximum}",
                hex::encode(active_journal_id)
            )));
        }
        return Ok(generation);
    }

    maximum.checked_add(1).ok_or_else(|| {
        StoreError::Corruption("no generation remains for recovery artifacts".into())
    })
}

fn preserve_crash_journal(
    active_path: &Path,
    quarantine_dir: &Path,
    header: &JournalHeader,
    counters: &DurabilityCounters,
) -> Result<PathBuf, StoreError> {
    use std::os::unix::fs::MetadataExt;

    std::fs::create_dir_all(quarantine_dir)?;
    let evidence = quarantine_dir.join(format!(
        "{}-{}-{}.journal.evidence",
        hex::encode(header.journal_id),
        header.shard_index,
        header.first_shard_sequence
    ));
    match sys::link_noreplace(active_path, &evidence) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let original = std::fs::metadata(active_path)?;
            let retained = std::fs::metadata(&evidence)?;
            if original.dev() != retained.dev() || original.ino() != retained.ino() {
                return Err(StoreError::Corruption(format!(
                    "journal evidence name {} is occupied by another inode",
                    evidence.display()
                )));
            }
        }
        Err(error) => return Err(error.into()),
    }
    sys::fsync_dir(quarantine_dir, counters)?;
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
fn create_fresh_active_journal(
    paths: &ShardPaths,
    root_uuid: [u8; 16],
    shard: u16,
    first_shard_sequence: u64,
    preallocated_len: u64,
    logical_generation: u64,
    counters: Arc<DurabilityCounters>,
) -> Result<(RecoveredTail, RetainedTail), StoreError> {
    let journal_id = fresh_recovery_journal_id(root_uuid, shard, first_shard_sequence);
    let journal = Journal::create(
        &paths.active(),
        journal_id,
        first_shard_sequence,
        shard,
        root_uuid,
        preallocated_len,
        now_micros(),
        Arc::clone(&counters),
    )?;
    let path = journal.path().to_path_buf();
    let shared_file = Arc::new(journal.file().try_clone()?);
    let retained = RetainedTail::new(
        logical_generation,
        PinnedFile::from_shared(path.clone(), Arc::clone(&shared_file)),
    );
    Ok((
        RecoveredTail {
            logical_generation,
            journal_id,
            path,
            validated_through: JOURNAL_HEADER_LEN as u64,
            file: shared_file,
        },
        retained,
    ))
}

fn fresh_recovery_journal_id(
    root_uuid: [u8; 16],
    shard: u16,
    first_shard_sequence: u64,
) -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"levcs-recovery-journal-id/v1\0");
    hasher.update(&root_uuid);
    hasher.update(&shard.to_le_bytes());
    hasher.update(&first_shard_sequence.to_le_bytes());
    hasher.update(&now_micros().to_le_bytes());
    hasher.update(&std::process::id().to_le_bytes());
    hasher.update(&NEXT.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.as_bytes()[..16]);
    out
}

fn active_journal_path(paths: &ShardPaths) -> Result<Option<PathBuf>, StoreError> {
    let dir = match std::fs::read_dir(paths.active()) {
        Ok(dir) => dir,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut found = Vec::new();
    for entry in dir {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "journal")
        {
            found.push(path);
        }
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        count => Err(StoreError::Corruption(format!(
            "shard directory {} holds {count} active journals; exactly one is expected",
            paths.active().display()
        ))),
    }
}

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_micros() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod production_session_tests {
    use std::sync::Mutex;

    use levcs_protocol::v2::ProjectionMode;

    use super::*;
    use crate::format::{frame_total_len, Frame};
    use crate::roots::{ProjectionArtifactFormat, RetainedProjectionArtifact};
    use crate::staging::RecoveredProjectionArtifacts;

    struct StagedFacts {
        descriptor: StagedProjectionInstallV1,
    }

    impl PayloadFacts for StagedFacts {
        fn extend(&self, facts: &mut FrameFacts, _payload: &[u8]) -> Result<(), StoreError> {
            facts.event_digest = ObjectId([12; 32]);
            facts.previous_event_digest = ObjectId([0; 32]);
            facts.creates_namespace = true;
            facts.genesis_authority = ObjectId([13; 32]);
            facts.current_authority = ObjectId([13; 32]);
            facts.retry_until_micros = i64::MAX;
            Ok(())
        }

        fn recovered(&self, _payload: &[u8]) -> Result<RecoveredPayloadFacts, StoreError> {
            Ok(RecoveredPayloadFacts {
                objects_new: self.descriptor.object_count,
                staged_projection_install: Some(self.descriptor.clone()),
                ..RecoveredPayloadFacts::default()
            })
        }
    }

    struct StagedResolver {
        namespace: NamespaceId,
        descriptor: StagedProjectionInstallV1,
        artifacts: RecoveredProjectionArtifacts,
        absent_session: [u8; 16],
        notifications: Mutex<Vec<RecoveredProjectionResolution>>,
    }

    impl ProjectionRecoveryResolver for StagedResolver {
        fn transferred_sessions(&self, _shard_index: u16) -> Result<Arc<[[u8; 16]]>, StoreError> {
            Ok(Arc::from([self.descriptor.session_id, self.absent_session]))
        }

        fn resolve_committed(
            &self,
            namespace: NamespaceId,
            descriptor: &StagedProjectionInstallV1,
        ) -> Result<RecoveredProjectionArtifacts, StoreError> {
            assert_eq!(namespace, self.namespace);
            assert_eq!(descriptor, &self.descriptor);
            Ok(self.artifacts.clone())
        }

        fn notify_recovered(
            &self,
            resolution: RecoveredProjectionResolution,
        ) -> Result<(), StoreError> {
            self.notifications
                .lock()
                .expect("notification mutex")
                .push(resolution);
            Ok(())
        }
    }

    #[test]
    fn one_session_holds_lock_continuously_across_all_shards() {
        let dir = tempfile::tempdir().expect("tempdir");
        let counters = DurabilityCounters::default();
        segment::initialize_root(&RootLayout::new(dir.path()), 2, [7u8; 16], 1, &counters)
            .expect("initialize");

        let mut options = StoreOptions::new(dir.path());
        options.shard_count = 2;
        let config = RecoveryConfig::from_store_options(&options);
        let session = RecoverySession::open(dir.path()).expect("first opener");

        assert!(matches!(
            RecoverySession::open(dir.path()),
            Err(StoreError::AlreadyLocked)
        ));
        let shard0 = session.recover_shard(0, &config).expect("recover shard 0");
        assert!(shard0.report.ready);
        assert!(matches!(
            RecoverySession::open(dir.path()),
            Err(StoreError::AlreadyLocked)
        ));
        let shard1 = session.recover_shard(1, &config).expect("recover shard 1");
        assert!(shard1.report.ready);
        assert!(matches!(
            RecoverySession::open(dir.path()),
            Err(StoreError::AlreadyLocked)
        ));

        drop(session);
        RecoverySession::open(dir.path()).expect("lock released only with session");
    }

    #[test]
    fn committed_staged_projection_is_indexed_pinned_and_notified_before_readiness() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_uuid = [7u8; 16];
        let counters = Arc::new(DurabilityCounters::default());
        let layout = RootLayout::new(dir.path());
        segment::initialize_root(&layout, 1, root_uuid, 1, &counters).expect("initialize");
        let paths = layout.shard(0);

        let namespace = NamespaceId([21; 32]);
        let descriptor = StagedProjectionInstallV1 {
            session_id: [22; 16],
            manifest_digest: ObjectId([23; 32]),
            projection: ProjectionMode::Full,
            object_count: 1,
            object_bytes: 17,
            membership_root: ObjectId([24; 32]),
            artifact_set_digest: ObjectId([25; 32]),
        };
        let object = ObjectId([26; 32]);
        let artifact_path = dir.path().join("staged-projection.chunk");
        let artifact_file = File::create(&artifact_path).expect("artifact");
        let mut staged_delta = IndexDelta::new(8, 4096);
        staged_delta
            .insert(
                IndexKey::new(namespace, object),
                IndexLocation {
                    segment_generation: 55,
                    frame_offset: 0,
                    frame_len: 17,
                    object_type: 1,
                    shard_sequence: 0,
                },
            )
            .expect("index staged object");
        let artifacts = RecoveredProjectionArtifacts::new(
            descriptor.clone(),
            Arc::new(staged_delta),
            Arc::from([]),
            Arc::from([RetainedProjectionArtifact::new(
                55,
                ProjectionArtifactFormat::CanonicalStageChunkV1,
                PinnedFile::new(artifact_path.clone(), artifact_file),
            )]),
        )
        .expect("resolved artifacts");
        let resolver = StagedResolver {
            namespace,
            descriptor: descriptor.clone(),
            artifacts,
            absent_session: [27; 16],
            notifications: Mutex::new(Vec::new()),
        };
        let facts = StagedFacts {
            descriptor: descriptor.clone(),
        };

        let journal_id = [28; 16];
        let mut journal = Journal::create(
            &paths.active(),
            journal_id,
            0,
            0,
            root_uuid,
            1024 * 1024,
            1,
            Arc::clone(&counters),
        )
        .expect("journal");
        let payload = vec![1];
        let frame = Frame {
            header: FrameHeader {
                flags: 0,
                total_len: frame_total_len(payload.len() as u64),
                journal_id,
                shard_sequence: 0,
                repo_sequence: 0,
                namespace: *namespace.as_bytes(),
                operation_id: [29; 16],
                operation_digest: ObjectId([30; 32]),
                payload_len: payload.len() as u64,
                payload_digest: ObjectId([0; 32]),
            },
            payload,
        };
        journal
            .append_group_and_fence(&[frame])
            .expect("append staged frame");
        drop(journal);

        let mut options = StoreOptions::new(dir.path());
        options.shard_count = 1;
        options.journal_preallocate_bytes = 1024 * 1024;
        let mut config = RecoveryConfig::from_store_options(&options);
        config.payload_facts = &facts;
        let config = config.with_projection_recovery_resolver(&resolver);
        let session = RecoverySession::open(dir.path()).expect("recovery session");
        let recovered = session.recover_shard(0, &config).expect("recover");

        assert!(recovered.report.ready);
        let location = recovered
            .index
            .lookup(&IndexKey::new(namespace, object))
            .location
            .expect("staged object membership");
        assert_eq!(location.segment_generation, 55);
        assert_eq!(
            recovered
                .retained_generation
                .projection_artifacts
                .first()
                .expect("projection pin")
                .path(),
            artifact_path
        );
        assert_eq!(
            recovered.projection_resolutions,
            vec![
                RecoveredProjectionResolution {
                    session_id: descriptor.session_id,
                    outcome: RecoveredProjectionOutcome::Committed,
                },
                RecoveredProjectionResolution {
                    session_id: [27; 16],
                    outcome: RecoveredProjectionOutcome::ProvedAbsent,
                },
            ]
        );
        assert_eq!(
            *resolver.notifications.lock().expect("notifications"),
            recovered.projection_resolutions
        );
    }
}
