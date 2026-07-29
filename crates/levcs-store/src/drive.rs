//! Journal-level drive API. Test and benchmark seam only.
//!
//! **Shared file.** Lead owns the signatures (D0); **A1 JournalWriter** fills
//! the bodies; **A3 StoreHarness** consumes it read-only (scope 2.1).
//!
//! # Why this exists
//!
//! A3's `store-crash-driver` and `store-bench` are separate binary crates that
//! see only the public API, and `StoreEngine::submit` returns
//! `NotImplemented` until B1 lands in Wave B. Without this seam neither of
//! A3's Wave A acceptance criteria — a running crash matrix and a P1-micro
//! number — is reachable, and Wave A would ship three packages of which one
//! could not be exercised.
//!
//! # What it is not
//!
//! No engine, no status root, no sequencer, no signer. It appends
//! caller-supplied pre-encoded frames and fences them. B1 does not build on
//! it.
//!
//! # Divergence risk
//!
//! A test-only seam that appends frames without the sequencer can drift from
//! the real append path, at which point the Wave A matrix certifies something
//! the production writer does not do. The mitigation is structural: every
//! function here must call the same `journal.rs` group-append and fence
//! functions `engine.rs` calls, adding only frame construction. A Wave B test
//! asserts that a group submitted through `submit` and the same group driven
//! through this module produce byte-identical journal contents.

#![cfg(feature = "store-internals")]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use levcs_core::ObjectId;

use crate::format::{Frame, FrameHeader, TransactionFramePayloadV1};
use crate::index::{NamespaceCatalog, NamespaceLifecycle, NamespaceRecord, NamespaceStorageMode};
use crate::journal::Journal;
use crate::recovery::{self, FrameFacts, PayloadFacts};
use crate::segment::{self, RootLayout, ShardPaths};
use crate::types::{DurabilityCounterSnapshot, DurabilityCounters, NamespaceId, StoreError};

/// A single shard's journal, opened directly.
pub struct ShardDrive {
    layout: RootLayout,
    paths: ShardPaths,
    shard: u16,
    root_uuid: [u8; 16],
    /// Held for the drive's lifetime. `reopen_through_recovery` takes the same
    /// lock, so a caller must drop the drive before reopening — which is the
    /// point: reopening is a close-and-reopen through recovery, not a peek.
    ///
    /// A [`segment::RootLock`] rather than the `LOCK` file, so the release is
    /// an explicit `LOCK_UN` and not a consequence of closing a descriptor a
    /// concurrently forked child may still share.
    _lock: segment::RootLock,
    journal: Journal,
    counters: Arc<DurabilityCounters>,
    /// Journal preallocation for this drive. Small by default so a crash
    /// campaign does not write a quarter-gigabyte per case.
    preallocate_bytes: u64,
    manifest_retain: u32,
    checkpoint_retain: u32,
}

/// Journal preallocation the drive uses unless told otherwise.
///
/// Deliberately not `StoreOptions::journal_preallocate_bytes`' 256 MiB
/// default: the crash matrix creates a fresh root per row, and preallocating
/// production-sized journals would make an unprivileged CI run write hundreds
/// of gigabytes.
pub const DRIVE_PREALLOCATE_BYTES: u64 = 4 * 1024 * 1024;

/// Checkpoint generations the drive keeps. `StoreOptions` refuses anything
/// below 2 (plan §5.3), and recovery's fallback-to-a-predecessor case needs a
/// predecessor to exist, so this is the floor and not a shrunk-down default.
pub const DRIVE_CHECKPOINT_RETAIN: u32 = 2;

/// Manifest generations recovery will consider below a refused one before it
/// gives up. Bounded so a directory that failed to prune cannot turn a reopen
/// into a linear hunt (plan §5.3).
const DRIVE_MANIFEST_CANDIDATES: usize = 8;

/// `StoreOptions::terminal_status_grace_micros`' default, used for the
/// receipt-visibility promotion of scope 3.8 step 10. The drive takes no
/// `StoreOptions` — it is a journal-level seam — so the one number it needs is
/// named here rather than inferred.
const DRIVE_TERMINAL_STATUS_GRACE_MICROS: i64 = 900_000_000;

/// What recovery concluded about a driven shard after reopening.
#[derive(Clone, Debug)]
pub struct DriveRecovery {
    /// The full recovered state retained by the production entry point.
    ///
    /// The summary fields below are projections only. Keeping this value is
    /// what lets the Wave B equivalence test compare the engine and drive
    /// roots rather than merely comparing a sequence list.
    pub recovered: recovery::RecoveredShard,
    /// Frames recovery adopted, in `shard_sequence` order. Always a contiguous
    /// prefix of what was appended — recovery stops at the first incomplete
    /// frame and discards everything after it, even a syntactically complete
    /// frame beyond the hole (scope 3.8 step 6).
    pub adopted_shard_sequences: Vec<u64>,
    /// Offset at which the tail scan stopped, if it stopped early.
    pub tail_stop_offset: Option<u64>,
    /// Bytes quarantined from the discarded tail.
    pub quarantined_bytes: u64,
    /// Whether the shard needed the manifest fallback path.
    pub used_manifest_fallback: bool,
    /// The full report recovery produced, verbatim.
    ///
    /// The four fields above are a convenience projection of it and nothing
    /// more; [`DriveRecovery::from_recovered`] is the only thing that builds
    /// them, so they cannot disagree with this.
    ///
    /// Added after the Wave A review (record 2026-07-24-D). The seam
    /// previously discarded the recovery *decision* and kept only its
    /// effects, so a test could ask what was adopted but not why. A double
    /// adoption and a correctly-replayed journal produce different
    /// dispositions and — until something asserts on the disposition — the
    /// same observable adoption set. That is how the missing
    /// `classify_active_journal` call stayed invisible while its own unit
    /// tests passed: the property was enforced somewhere, and the seam could
    /// not tell you whether it was enforced *here*.
    pub report: recovery::ShardRecoveryReport,
}

// Preserve the Wave A comparison contract for the diagnostic projection. The
// newly retained `RecoveredShard` contains mmap/file ownership whose identity
// is deliberately not value-comparable.
impl PartialEq for DriveRecovery {
    fn eq(&self, other: &Self) -> bool {
        self.adopted_shard_sequences == other.adopted_shard_sequences
            && self.tail_stop_offset == other.tail_stop_offset
            && self.quarantined_bytes == other.quarantined_bytes
            && self.used_manifest_fallback == other.used_manifest_fallback
            && self.report == other.report
    }
}

impl Eq for DriveRecovery {}

impl DriveRecovery {
    /// Project a recovery report into the seam's shape.
    ///
    /// Deliberately the only constructor: a caller that could set the summary
    /// fields independently could make them lie about the report they claim
    /// to summarise.
    ///
    /// `tail_stop_offset` is passed in rather than derived, because it is the
    /// one summary the report does not contain. `ShardRecoveryReport.tail_stop`
    /// records *why* the scan stopped; whether that stop discarded anything is
    /// a separate judgment (a clean journal always stops at its first unwritten
    /// byte), and only the scan site holds both halves.
    fn from_recovered(recovered: recovery::RecoveredShard) -> Self {
        let report = &recovered.report;
        Self {
            adopted_shard_sequences: report.adopted_shard_sequences.clone(),
            tail_stop_offset: recovered.tail_stop_offset,
            quarantined_bytes: report.quarantined_bytes,
            used_manifest_fallback: matches!(
                report.manifest_source,
                Some(recovery::ManifestSource::Fallback { .. })
            ),
            report: report.clone(),
            recovered,
        }
    }

    /// What recovery concluded about the journal under `active/`.
    ///
    /// `None` means no journal was there to classify — a distinct state from
    /// either disposition, and not one to collapse into `Replay`.
    pub fn active_journal(&self) -> Option<&recovery::ActiveJournalDisposition> {
        self.report.active_journal.as_ref()
    }

    /// True when the seal that crashed between scope 3.4 steps 5 and 6 was
    /// finished by this recovery rather than replayed.
    pub fn completed_interrupted_seal(&self) -> bool {
        matches!(
            self.report.active_journal,
            Some(recovery::ActiveJournalDisposition::AlreadySealed { .. })
        )
    }
}

/// Physical fault injection, exposed to A3 through the sanctioned seam rather
/// than by making `sys` public.
///
/// These are the userspace half of the fault matrix; `dm-flakey`, block-device
/// cache/barrier manipulation, and power cuts live in the reviewed root-only
/// scripts of plan §10 and belong to Phase 4/5. The userspace layer is what
/// lets the matrix run unprivileged in CI.
#[cfg(feature = "failpoints")]
pub mod faults {
    pub use crate::sys::{arm, disarm, serial, Fault, FaultSerial};
}

/// Failpoint arming, likewise.
#[cfg(feature = "failpoints")]
pub mod points {
    pub use crate::failpoints::{arm, disarm, Failpoint, FailpointAction, Wave};
}

impl ShardDrive {
    /// Initialize a fresh store root and open shard `shard` for driving.
    pub fn create(root: &Path, shard: u16, shard_count: u16) -> Result<Self, StoreError> {
        if shard >= shard_count {
            return Err(StoreError::InvalidConfiguration(format!(
                "shard {shard} is outside a topology of {shard_count} shards"
            )));
        }
        let layout = RootLayout::new(root);
        let counters = Arc::new(DurabilityCounters::default());
        let root_uuid = fresh_id(b"root");
        let now = now_micros();
        segment::initialize_root(&layout, shard_count, root_uuid, now, &counters)?;

        let lock = segment::lock_root(&layout)?;
        let paths = layout.shard(shard);
        let journal = Journal::create(
            &paths.active(),
            fresh_id(b"journal"),
            0,
            shard,
            root_uuid,
            DRIVE_PREALLOCATE_BYTES,
            now,
            Arc::clone(&counters),
        )?;

        Ok(Self {
            layout,
            paths,
            shard,
            root_uuid,
            _lock: lock,
            journal,
            counters,
            preallocate_bytes: DRIVE_PREALLOCATE_BYTES,
            manifest_retain: 2,
            checkpoint_retain: DRIVE_CHECKPOINT_RETAIN,
        })
    }

    /// Open an existing root's shard without running recovery. For inspecting
    /// a crash image before deciding what recovery should say about it.
    ///
    /// "Without running recovery" is about publication, not about the tail
    /// scan: establishing the write cursor of an existing journal *is* the
    /// forward scan, and there is no second definition of where a journal
    /// ends. What this skips is the manifest fallback, quarantine, and
    /// classification.
    pub fn open_raw(root: &Path, shard: u16) -> Result<Self, StoreError> {
        let layout = RootLayout::new(root);
        let marker = segment::read_format(&layout)?;
        if shard >= marker.shard_count {
            return Err(StoreError::FormatMismatch(format!(
                "shard {shard} is outside the root's frozen topology of {} shards",
                marker.shard_count
            )));
        }
        let lock = segment::lock_root(&layout)?;
        let paths = layout.shard(shard);
        let counters = Arc::new(DurabilityCounters::default());
        let path = active_journal_path(&paths)?.ok_or_else(|| {
            StoreError::Corruption(format!(
                "shard {shard} has no active journal under {}",
                paths.active().display()
            ))
        })?;
        let (journal, _scan) = Journal::open(&path, &marker.root_uuid, Arc::clone(&counters))?;
        let preallocate_bytes = journal.header().preallocated_len;

        Ok(Self {
            layout,
            paths,
            shard,
            root_uuid: marker.root_uuid,
            _lock: lock,
            journal,
            counters,
            preallocate_bytes,
            manifest_retain: 2,
            checkpoint_retain: DRIVE_CHECKPOINT_RETAIN,
        })
    }

    /// Build one frame for `namespace` carrying `payload`, assigning the next
    /// `shard_sequence` and the given `repo_sequence`.
    ///
    /// Frame construction is the *only* thing this module adds over
    /// `journal.rs`; everything below delegates. The `operation_id` and
    /// `operation_digest` are derived deterministically from the frame's own
    /// identity so a scripted workload is reproducible — the sequencer's real
    /// derivation is B1's and is deliberately not imitated here.
    pub fn build_frame(
        &mut self,
        namespace: NamespaceId,
        repo_sequence: u64,
        payload: Vec<u8>,
    ) -> Result<Frame, StoreError> {
        let shard_sequence = self.journal.assign_shard_sequence();
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"levcs-drive-operation/v1\0");
        hasher.update(namespace.as_bytes());
        hasher.update(&repo_sequence.to_le_bytes());
        hasher.update(&shard_sequence.to_le_bytes());
        hasher.update(&payload);
        let operation_digest = levcs_core::ObjectId(*hasher.finalize().as_bytes());
        let mut operation_id = [0u8; 16];
        operation_id.copy_from_slice(&operation_digest.as_bytes()[..16]);

        let payload_len = payload.len() as u64;
        Ok(Frame {
            header: FrameHeader {
                flags: 0,
                total_len: crate::format::frame_total_len(payload_len),
                journal_id: self.journal.journal_id(),
                shard_sequence,
                repo_sequence,
                namespace: *namespace.as_bytes(),
                operation_id,
                operation_digest,
                payload_len,
                // Derived by `Frame::encode`; carried here so the value a
                // caller inspects is the value that will be written.
                payload_digest: crate::format::digest(
                    crate::format::FRAME_PAYLOAD_DIGEST_DOMAIN,
                    &payload,
                ),
            },
            payload,
        })
    }

    /// Append a group and fence it exactly once, through the same
    /// `journal.rs` entry point `engine.rs` uses.
    ///
    /// Returns the shard sequences appended. Any armed failpoint fires at its
    /// real location inside `journal.rs`, not here — this function contains no
    /// failpoint of its own, which is what keeps the Wave A matrix a statement
    /// about the production append path.
    pub fn append_group_and_fence(&mut self, frames: &[Frame]) -> Result<Vec<u64>, StoreError> {
        self.journal.append_group_and_fence(frames)
    }

    /// Seal the active journal into a segment and install a new manifest
    /// generation.
    ///
    /// The amended scope 3.4/3.5 order, end to end: validate and footer the
    /// journal, **link** it into `segments/`, install the manifest generation
    /// that references it and swap `CURRENT`, and **only then** unlink the
    /// `active/` name. Both names exist across the whole install, so no crash
    /// point leaves the sealed frames unreachable.
    pub fn seal_and_install(&mut self) -> Result<u64, StoreError> {
        let previous = segment::load_manifest_with_fallback(&self.paths, &self.root_uuid)?;
        let generation = previous
            .as_ref()
            .map(|(manifest, _)| manifest.generation + 1)
            .unwrap_or(1);

        let last = self.journal.last_appended_shard_sequence().ok_or_else(|| {
            StoreError::Corruption("sealing refused: nothing has been appended".into())
        })?;
        let first = self.journal.header().first_shard_sequence;
        let active_path = self.journal.path().to_path_buf();
        let destination =
            segment::seal_journal(&mut self.journal, &self.paths, generation, &self.counters)?;
        let filename = destination
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| StoreError::Corruption("segment name is not utf-8".into()))?
            .to_string();

        let mut retained_tail_ranges = previous
            .map(|(manifest, _)| manifest.retained_tail_ranges)
            .unwrap_or_default();
        retained_tail_ranges.push(crate::format::TailRange {
            generation,
            first_shard_sequence: first,
            last_shard_sequence: last,
            filename,
        });

        let manifest = crate::format::Manifest {
            root_uuid: self.root_uuid,
            generation,
            // Phase 1 always writes 0 and no baseline; the field is the seam
            // Phase 4 compaction installs a `BaselineStateV1` through.
            base_generation: 0,
            retained_tail_ranges,
            index_runs: Vec::new(),
            checkpoints: Vec::new(),
            committed_shard_sequence: last,
        };
        segment::install_manifest(&self.paths, &manifest, self.manifest_retain, &self.counters)?;

        // Scope 3.4 step 6, and not one step earlier: the segment is now named
        // by a durable manifest generation that `CURRENT` points at, so
        // dropping the `active/` name can no longer orphan the frames.
        segment::unlink_sealed_journal(&active_path, &self.paths, &self.counters)?;

        self.journal = Journal::create(
            &self.paths.active(),
            fresh_id(b"journal"),
            last + 1,
            self.shard,
            self.root_uuid,
            self.preallocate_bytes,
            now_micros(),
            Arc::clone(&self.counters),
        )?;
        Ok(generation)
    }

    /// Install a durable checkpoint for this shard (scope 3.6) and prune to
    /// the retention floor.
    ///
    /// # Why this exists
    ///
    /// `checkpoint::install` and `checkpoint::prune` had no production caller
    /// anywhere in the crate: only their own tests. Nothing in the drive seam
    /// installed one, so **no crash image the matrix produces had a checkpoint
    /// directory at all**, and recovery step 3 — checkpoint selection, the
    /// fallback past a corrupt generation, and the offline-rebuild decision
    /// when every generation fails — had never run against anything but a
    /// hand-assembled directory. This is the same defect class as the two P1s
    /// in `reopen_through_recovery`, one level further out: a property
    /// asserted only against a fixture is not asserted against the path that
    /// runs.
    ///
    /// # What it does and does not reconstruct
    ///
    /// The content is derived from durable state at call time — the manifest's
    /// segments plus the active journal's scanned frames — and not from
    /// anything this process happens to remember, so a drive that was
    /// `open_raw`ed onto a root another process wrote produces the same
    /// checkpoint as one that wrote it. `refs` is empty: the drive's payloads
    /// are scripted bytes with no typed ref state to project, and inventing
    /// one would make a checkpoint field that recovery trusts into a fiction.
    /// That is a stated limit of the seam, not an oversight; B1's engine
    /// supplies the real ref state.
    pub fn checkpoint(&mut self) -> Result<PathBuf, StoreError> {
        let facts = self.durable_facts()?;
        if facts.is_empty() {
            return Err(StoreError::Conflict(
                "an empty Phase 1 shard has no manifest and cannot install a checkpoint".into(),
            ));
        }
        let created_at_micros = now_micros();

        let mut catalog = NamespaceCatalog::new();
        let mut receipts = Vec::with_capacity(facts.len());
        for (fact, recovered) in &facts {
            if catalog.get(&fact.namespace).is_none() {
                catalog.bind(NamespaceRecord {
                    namespace: fact.namespace,
                    genesis_authority: fact.genesis_authority,
                    current_authority: fact.current_authority,
                    lifecycle: NamespaceLifecycle::Active,
                    storage_mode: NamespaceStorageMode::Full,
                    repo_sequence: fact.repo_sequence,
                    previous_event_digest: fact.event_digest,
                })?;
            } else {
                catalog.advance(
                    &fact.namespace,
                    fact.current_authority,
                    fact.repo_sequence,
                    fact.event_digest,
                )?;
            }
            receipts.push(receipt_for(fact, recovered, created_at_micros)?);
        }

        let checkpoint = crate::checkpoint::Checkpoint {
            root_uuid: self.root_uuid,
            shard_index: self.shard,
            shard_committed_sequence: facts
                .last()
                .map(|(facts, _)| facts.shard_sequence)
                .unwrap_or(0),
            // The resume point of scope 3.6: `journal_id` accompanies the
            // offset because an offset alone is meaningless once the journal
            // has rotated, and recovery checks the identity before it trusts
            // the offset.
            active_journal_id: self.journal.journal_id(),
            active_journal_offset: self.journal.cursor(),
            created_at_micros,
            catalog,
            refs: Vec::new(),
            receipts,
        };

        let path =
            crate::checkpoint::install(&self.paths.checkpoints(), &checkpoint, &self.counters)?;

        // A checkpoint file is derived state, not authority by directory
        // presence. Seal the active frames and publish both the new tail range
        // and this checkpoint row in one manifest generation. Installing an
        // intermediate seal-only generation here would let manifest_retain=2
        // evict the predecessor checkpoint manifest between two checkpoints.
        let previous = segment::load_manifest_with_fallback(&self.paths, &self.root_uuid)?
            .map(|(manifest, _)| manifest);
        let generation = previous
            .as_ref()
            .map(|manifest| manifest.generation.saturating_add(1))
            .unwrap_or(1);
        let mut retained_tail_ranges = previous
            .as_ref()
            .map(|manifest| manifest.retained_tail_ranges.clone())
            .unwrap_or_default();
        let active_path = self.journal.path().to_path_buf();
        let sealed_active = if let Some(last) = self.journal.last_appended_shard_sequence() {
            let first = self.journal.header().first_shard_sequence;
            let destination =
                segment::seal_journal(&mut self.journal, &self.paths, generation, &self.counters)?;
            let filename = destination
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| StoreError::Corruption("segment name is not UTF-8".into()))?
                .to_string();
            retained_tail_ranges.push(crate::format::TailRange {
                generation,
                first_shard_sequence: first,
                last_shard_sequence: last,
                filename,
            });
            true
        } else {
            false
        };

        let filename = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| StoreError::Corruption("checkpoint name is not UTF-8".into()))?
            .to_string();
        let mut checkpoint_rows = previous
            .as_ref()
            .map(|manifest| manifest.checkpoints.clone())
            .unwrap_or_default();
        checkpoint_rows.retain(|(sequence, _)| *sequence != checkpoint.shard_committed_sequence);
        checkpoint_rows.push((checkpoint.shard_committed_sequence, filename));
        let retain = self.checkpoint_retain.max(2) as usize;
        if checkpoint_rows.len() > retain {
            let drop_count = checkpoint_rows.len() - retain;
            checkpoint_rows.drain(..drop_count);
        }
        let manifest = crate::format::Manifest {
            root_uuid: self.root_uuid,
            generation,
            base_generation: previous
                .as_ref()
                .map(|manifest| manifest.base_generation)
                .unwrap_or(0),
            retained_tail_ranges,
            index_runs: previous
                .as_ref()
                .map(|manifest| manifest.index_runs.clone())
                .unwrap_or_default(),
            checkpoints: checkpoint_rows,
            committed_shard_sequence: checkpoint.shard_committed_sequence,
        };
        segment::install_manifest(&self.paths, &manifest, self.manifest_retain, &self.counters)?;

        if sealed_active {
            segment::unlink_sealed_journal(&active_path, &self.paths, &self.counters)?;
            self.journal = Journal::create(
                &self.paths.active(),
                fresh_id(b"journal"),
                checkpoint.shard_committed_sequence.saturating_add(1),
                self.shard,
                self.root_uuid,
                self.preallocate_bytes,
                now_micros(),
                Arc::clone(&self.counters),
            )?;
        }

        // Only after both the checkpoint and its authoritative manifest are
        // fenced, so every retained manifest keeps a retained referent.
        crate::checkpoint::prune(
            &self.paths.checkpoints(),
            self.checkpoint_retain,
            &self.counters,
        )?;
        Ok(path)
    }

    /// Every frame durably reachable in this shard right now, in
    /// `shard_sequence` order, each proved complete by the same readers
    /// recovery uses.
    fn durable_facts(
        &self,
    ) -> Result<Vec<(FrameFacts, recovery::RecoveredPayloadFacts)>, StoreError> {
        let mut facts = Vec::new();
        if let Some((manifest, _)) =
            segment::load_manifest_with_fallback(&self.paths, &self.root_uuid)?
        {
            for range in &manifest.retained_tail_ranges {
                let reader = segment::SegmentReader::open(
                    &self.paths.segments().join(&range.filename),
                    &self.root_uuid,
                )?;
                let sequences: Vec<u64> = reader
                    .footer()
                    .offsets
                    .iter()
                    .map(|(sequence, _, _)| *sequence)
                    .collect();
                for sequence in sequences {
                    facts.push(drive_frame_facts(&reader.read_frame(sequence)?)?);
                }
            }
        }
        for (_, offset, len) in self.journal.frame_index().to_vec() {
            facts.push(drive_frame_facts(&self.journal.read_frame(offset, len)?)?);
        }
        Ok(facts)
    }

    /// Durability counters for this shard. The basis for asserting one fence
    /// per group and no per-object fsync.
    pub fn counters(&self) -> DurabilityCounterSnapshot {
        self.counters.snapshot()
    }

    /// The shard's root identity, so a harness can construct a crash image
    /// that a different root would reject.
    pub fn root_uuid(&self) -> [u8; 16] {
        self.root_uuid
    }

    pub fn journal_id(&self) -> [u8; 16] {
        self.journal.journal_id()
    }

    pub fn journal_path(&self) -> &Path {
        self.journal.path()
    }

    pub fn next_shard_sequence(&self) -> u64 {
        self.journal.next_shard_sequence()
    }

    pub fn poison_cause(&self) -> Option<&str> {
        self.journal.poison_cause()
    }

    pub fn shard_paths(&self) -> &ShardPaths {
        &self.paths
    }

    pub fn layout(&self) -> &RootLayout {
        &self.layout
    }

    /// Close, reopen through production recovery, and report what recovery
    /// concluded. This is the classifier the crash matrix compares against
    /// both the physical-state class and the frozen oracle.
    ///
    /// The caller must have dropped any live `ShardDrive` on this root: this
    /// takes the same exclusive `LOCK`, because reopening through recovery is
    /// exactly a close-and-reopen and not an inspection of a running store.
    ///
    /// # This function implements no recovery of its own
    ///
    /// Every decision below is delegated. The first implementation of this
    /// function walked the manifest's segment footer offset tables and pushed
    /// their `shard_sequence` values straight into the adopted set, then
    /// unconditionally scanned the `active/` journal on top. Both halves were
    /// wrong in ways the crash matrix could not see, because the matrix reads
    /// only what this function returns:
    ///
    /// - a segment footer is *validated*, but the frames it points at were
    ///   not. A corrupted frame inside a manifest-referenced segment, and a
    ///   journal belonging to a different shard of the same root, both
    ///   recovered "successfully" with a full adopted set. The matrix was
    ///   therefore proving that sequence numbers exist, not that valid
    ///   transactions were recovered;
    /// - scanning the active journal *after* adopting the manifest's segments
    ///   is exactly the interrupted-seal double-adoption that scope 3.4
    ///   describes and that [`recovery::classify_active_journal`] exists to
    ///   prevent. A crash between the manifest install and the active-name
    ///   unlink produced `0,1,2,3,0,1,2,3`.
    ///
    /// The rule is now stronger and simpler: this function makes exactly one
    /// call to [`recovery::recover_shard`], the same non-feature-gated entry
    /// point the engine uses. It adds only the scripted-payload extractor and
    /// the `DriveRecovery` summary projection. Manifest/checkpoint selection,
    /// journal classification, replay, sequence verification, receipts,
    /// index layering, and retained generation ownership have no drive-local
    /// implementation to drift.
    pub fn reopen_through_recovery(root: &Path, shard: u16) -> Result<DriveRecovery, StoreError> {
        let payload_facts = DrivePayloadFacts;
        let config = recovery::RecoveryConfig {
            max_manifest_candidates: DRIVE_MANIFEST_CANDIDATES,
            manifest_retain: 2,
            checkpoint_retain: DRIVE_CHECKPOINT_RETAIN,
            journal_preallocate_bytes: DRIVE_PREALLOCATE_BYTES,
            terminal_status_grace_micros: DRIVE_TERMINAL_STATUS_GRACE_MICROS,
            max_active_index_entries: 4_000_000,
            max_active_index_bytes: 512 * 1024 * 1024,
            max_index_runs: 64,
            max_open_index_runs: 32,
            max_replay_frames: u64::MAX,
            max_replay_bytes: u64::MAX,
            payload_facts: &payload_facts,
            projection_recovery_resolver: None,
        };
        recovery::recover_shard(root, shard, &config).map(DriveRecovery::from_recovered)
    }
}

/// A checkpoint/receipt row for one recovered frame.
///
/// Deliberately not a fabrication of anything the frame does not carry:
/// `objects_new` is the object count the payload actually declared, and
/// `retry_until_micros` is the payload's own deadline. Over scripted payloads
/// both are zero, which is the honest answer for bytes that carry no
/// transaction.
fn receipt_for(
    facts: &FrameFacts,
    recovered: &recovery::RecoveredPayloadFacts,
    first_visible_micros: i64,
) -> Result<crate::checkpoint::ReceiptRecord, StoreError> {
    Ok(crate::checkpoint::ReceiptRecord {
        namespace: facts.namespace,
        operation_id: facts.operation_id,
        operation_digest: facts.operation_digest,
        repo_sequence: facts.repo_sequence,
        shard_sequence: facts.shard_sequence,
        current_authority: facts.current_authority,
        refs: recovered.applied_refs.clone(),
        objects_new: recovered.objects_new,
        retry_until_micros: facts.retry_until_micros,
        first_receipt_visibility_micros: Some(first_visible_micros),
        // Recomputed by `recovery::promote_receipt_visibility`, which may only
        // ever extend it. Zero here cannot shorten anything.
        receipt_visible_until_micros: 0,
    })
}

/// Domain separating the drive seam's synthetic event chain from every real
/// digest in the system. Nothing outside this module produces or consumes it.
const DRIVE_EVENT_CHAIN_DOMAIN: &[u8] = b"levcs-drive-event-chain/v1\0";

/// The chain link a drive-built frame with an opaque payload stands for.
///
/// `None` is the genesis link, so `repo_sequence` 0 has a defined predecessor
/// without wrapping.
fn synthetic_event_digest(namespace: &[u8; 32], repo_sequence: Option<u64>) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(DRIVE_EVENT_CHAIN_DOMAIN);
    hasher.update(namespace);
    match repo_sequence {
        Some(sequence) => {
            hasher.update(&[1u8]);
            hasher.update(&sequence.to_le_bytes());
        }
        None => {
            hasher.update(&[0u8]);
        }
    }
    ObjectId(*hasher.finalize().as_bytes())
}

/// Extracts the payload half of [`FrameFacts`] for frames this seam recovers.
///
/// # Two kinds of payload, and no third
///
/// [`ShardDrive::build_frame`] takes `Vec<u8>` — the seam exists so A3 can
/// drive the *writer* with scripted bytes, and it deliberately does not
/// imitate B1's sequencer. So a frame recovered here carries either:
///
/// - a canonical [`TransactionFramePayloadV1`], which is decoded in full and
///   supplies the real `previous_event_digest`/`event_digest` chain. The
///   payload's `repo_id` and `repo_sequence` must agree with the frame
///   header's, because two disagreeing copies of the same fact are worse than
///   one; or
/// - opaque scripted bytes, for which the chain is defined here as a pure
///   function of `(namespace, repo_sequence)`.
///
/// **The second case is a real limit and is stated rather than hidden.** Over
/// opaque payloads `verify_repo_chain`'s `PreviousEventDigestMismatch` cannot
/// fire, because there is no independent chain to disagree with; what the
/// check still enforces is per-repository contiguity and uniqueness, which is
/// what a scripted workload can actually violate. The full chain check runs
/// over canonical payloads, here and — in Wave B — over everything `submit`
/// writes.
struct DrivePayloadFacts;

impl PayloadFacts for DrivePayloadFacts {
    fn extend(&self, facts: &mut FrameFacts, payload: &[u8]) -> Result<(), StoreError> {
        let namespace = *facts.namespace.as_bytes();
        match TransactionFramePayloadV1::decode_canonical(payload) {
            Ok(_) => recovery::CanonicalPayloadFacts.extend(facts, payload),
            Err(_) => {
                facts.event_digest = synthetic_event_digest(&namespace, Some(facts.repo_sequence));
                facts.previous_event_digest =
                    synthetic_event_digest(&namespace, facts.repo_sequence.checked_sub(1));
                // Never `true`: a scripted payload carries no genesis, and
                // claiming one would let a replayed frame move a repository's
                // genesis binding during recovery.
                facts.creates_namespace = false;
                Ok(())
            }
        }
    }

    fn permits_implicit_namespace_anchor(&self) -> bool {
        true
    }

    fn recovered(&self, payload: &[u8]) -> Result<recovery::RecoveredPayloadFacts, StoreError> {
        match TransactionFramePayloadV1::decode_canonical(payload) {
            Ok(_) => recovery::CanonicalPayloadFacts.recovered(payload),
            Err(_) => Ok(recovery::RecoveredPayloadFacts::default()),
        }
    }
}

fn drive_frame_facts(
    frame: &Frame,
) -> Result<(FrameFacts, recovery::RecoveredPayloadFacts), StoreError> {
    let mut facts = FrameFacts::from_header(&frame.header);
    DrivePayloadFacts.extend(&mut facts, &frame.payload)?;
    let recovered = DrivePayloadFacts.recovered(&frame.payload)?;
    Ok((facts, recovered))
}

fn active_journal_path(paths: &ShardPaths) -> Result<Option<PathBuf>, StoreError> {
    let dir = match std::fs::read_dir(paths.active()) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut found: Vec<PathBuf> = Vec::new();
    for entry in dir {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "journal") {
            found.push(path);
        }
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        n => Err(StoreError::Corruption(format!(
            "shard directory {} holds {n} active journals; exactly one is expected",
            paths.active().display()
        ))),
    }
}

fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as i64)
        .unwrap_or(0)
}

/// A fresh 16-byte identifier.
///
/// The crate takes no random-number dependency, so this mixes the wall clock,
/// a monotonic counter, the process id, and the address of a stack local. It
/// is an identity, not a secret: `journal_id` exists to distinguish a live
/// journal from a previous incarnation of a recycled extent, and `root_uuid`
/// to catch a file copied in from another instance.
fn fresh_id(domain: &[u8]) -> [u8; 16] {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let local = 0u8;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"levcs-drive-id/v1\0");
    hasher.update(domain);
    hasher.update(&now_micros().to_le_bytes());
    hasher.update(&COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    hasher.update(&std::process::id().to_le_bytes());
    hasher.update(&(&local as *const u8 as usize).to_le_bytes());
    let mut id = [0u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    id
}
