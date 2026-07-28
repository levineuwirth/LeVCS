//! Active append journal: group formation, `write_vectored`, sequence
//! assignment, the single durability fence, and rotation.
//!
//! **Owned by A1 JournalWriter** (scope 2.1, 4-A1).
//!
//! Implements the normative append ordering of scope 3.7. Every step from
//! frame encoding through publication is the poison window: any error,
//! cancellation, or panic inside it poisons the shard, and a failed
//! `fdatasync` is terminal and never retried.
//!
//! # What lives here and what does not
//!
//! Steps 1 and 4–6 of scope 3.7 are journal-layer work and are implemented
//! here. Steps 2, 3, and 7–10 — the retry-deadline recheck, the status-root
//! `Resolving` marking, the committed-root build, the `ArcSwap` CAS, and
//! waking waiters — need the engine, and their failpoints are exactly the
//! `failpoints::Wave::B` set. Every failpoint whose `wave()` is `Wave::A` is
//! fired from this file, at its real location.
//!
//! `drive.rs` calls exactly the functions here that `engine.rs` will call. It
//! adds frame construction and nothing else, which is what keeps the Wave A
//! crash matrix a statement about the production writer.

use std::fs::File;
use std::io::IoSlice;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::failpoints::{self, Failpoint, FailpointAction};
use crate::format::{
    self, Frame, FrameError, FrameHeader, JournalHeader, FRAME_HEADER_LEN, JOURNAL_HEADER_LEN,
    MIN_FRAME_LEN,
};
use crate::sys;
use crate::types::{DurabilityCounterSnapshot, DurabilityCounters, StoreError};

/// Bytes of a discarded tail copied into `quarantine/` for forensics.
///
/// A journal is preallocated to hundreds of megabytes, so "the discarded tail"
/// is mostly unwritten extent. Copying all of it would turn every ordinary
/// crash into a large write during recovery. The quarantine file is evidence,
/// not a backup: the authoritative copy of the discarded bytes is the journal
/// itself, which recovery never rewrites in place.
pub const MAX_QUARANTINE_BYTES: u64 = 1 << 20;

/// Why a forward scan stopped.
///
/// Every variant is a distinct, individually assertable reason, so a test can
/// state which physical tail shape it produced rather than only that the scan
/// ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TailStop {
    /// The scan consumed every frame and reached the preallocated end without
    /// finding an incomplete frame.
    EndOfPreallocation,
    /// The bytes at the stop offset are not the start of a frame at all — the
    /// ordinary crash image, where the tail reads as zeros or as stale
    /// preallocated content.
    NotAFrame,
    /// The bytes at the stop offset began a frame that is not complete. The
    /// scope 3.3 condition that rejected it is carried, so a test can assert
    /// which one fired.
    Incomplete(FrameError),
    /// A positioned read failed. On the frozen profile this is a device that
    /// lost a write it acknowledged; scope 3.8 step 5 requires it be treated
    /// as "the tail ends here", never as a fatal store error.
    ReadError,
}

/// One frame a forward scan adopted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedFrame {
    pub shard_sequence: u64,
    pub offset: u64,
    pub len: u64,
    pub header: FrameHeader,
}

/// The result of a forward scan.
///
/// `frames` is always a contiguous prefix: the scan stops at the first
/// incomplete frame and never resumes, so a syntactically complete frame past
/// a hole is not in this list (scope 3.8 step 6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailScan {
    pub frames: Vec<ScannedFrame>,
    /// Offset at which scanning stopped. Everything from here on is discarded.
    pub stop_offset: u64,
    pub stop: TailStop,
}

impl TailScan {
    /// Whether the scan stopped before the end of the preallocated region,
    /// which is what makes the remainder a tail to quarantine.
    pub fn stopped_early(&self) -> bool {
        self.stop != TailStop::EndOfPreallocation
    }

    pub fn last_shard_sequence(&self) -> Option<u64> {
        self.frames.last().map(|f| f.shard_sequence)
    }
}

/// Group formation bounded by transactions, bytes, and idle delay
/// (scope 3.7 step 1, plan §5.2 default tuning).
///
/// The idle delay, not the transaction ceiling, is what sets the fence rate at
/// the operating point (scope 8.1), so it is a first-class bound here rather
/// than a timeout bolted onto a size check.
pub struct GroupBuilder {
    max_transactions: u32,
    max_bytes: u64,
    max_idle: Duration,
    frames: Vec<Frame>,
    bytes: u64,
    opened_at: Option<Instant>,
}

impl GroupBuilder {
    pub fn new(max_transactions: u32, max_bytes: u64, max_idle: Duration) -> Self {
        Self {
            max_transactions,
            max_bytes,
            max_idle,
            frames: Vec::new(),
            bytes: 0,
            opened_at: None,
        }
    }

    /// From `StoreOptions`, so the journal and the configured bounds cannot
    /// drift apart.
    pub fn from_options(options: &crate::options::StoreOptions) -> Self {
        Self::new(
            options.max_group_transactions,
            options.max_group_bytes,
            options.max_group_idle,
        )
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Add a frame, or hand it back when it does not fit.
    ///
    /// A frame larger than `max_group_bytes` on its own would otherwise never
    /// be admitted by any group, so a frame is always accepted into an empty
    /// group: the byte bound is a batching bound, not an admission bound.
    pub fn push(&mut self, frame: Frame) -> Result<(), Frame> {
        let frame_bytes = frame.header.total_len;
        if !self.frames.is_empty()
            && (self.frames.len() as u64 >= self.max_transactions as u64
                || self.bytes.saturating_add(frame_bytes) > self.max_bytes)
        {
            return Err(frame);
        }
        if self.frames.is_empty() {
            self.opened_at = Some(Instant::now());
        }
        self.bytes = self.bytes.saturating_add(frame_bytes);
        self.frames.push(frame);
        Ok(())
    }

    /// The group is closed by a bound: transactions, bytes, or idle delay.
    pub fn is_closed(&self) -> bool {
        if self.frames.is_empty() {
            return false;
        }
        self.frames.len() as u64 >= self.max_transactions as u64
            || self.bytes >= self.max_bytes
            || self.is_expired()
    }

    pub fn is_expired(&self) -> bool {
        self.opened_at
            .is_some_and(|opened| opened.elapsed() >= self.max_idle)
    }

    /// Remaining time before the idle bound closes the group, for a shard
    /// thread's channel receive deadline.
    pub fn time_to_close(&self) -> Option<Duration> {
        self.opened_at
            .map(|opened| self.max_idle.saturating_sub(opened.elapsed()))
    }

    pub fn take(&mut self) -> Vec<Frame> {
        self.bytes = 0;
        self.opened_at = None;
        std::mem::take(&mut self.frames)
    }
}

/// One shard's active append journal.
pub struct Journal {
    file: File,
    path: PathBuf,
    header: JournalHeader,
    /// Write cursor: one byte past the last frame this journal wrote or
    /// adopted.
    cursor: u64,
    /// Next sequence handed out by `assign_shard_sequence`.
    next_assign: u64,
    /// Highest sequence actually written, if any.
    last_appended: Option<u64>,
    frames: Vec<(u64, u64, u64)>,
    counters: Arc<DurabilityCounters>,
    poison: Option<String>,
}

impl Journal {
    /// Create and preallocate a fresh journal.
    ///
    /// Preallocation is without `FALLOC_FL_KEEP_SIZE`, so the file has its
    /// full size with unwritten extents and every append is an overwrite
    /// inside an already-sized file. The header is fenced and the directory is
    /// synced before the journal's first append, so recovery can never find a
    /// journal whose name is durable but whose header is not.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        active_dir: &Path,
        journal_id: [u8; 16],
        first_shard_sequence: u64,
        shard_index: u16,
        root_uuid: [u8; 16],
        preallocated_len: u64,
        created_at_micros: i64,
        counters: Arc<DurabilityCounters>,
    ) -> Result<Self, StoreError> {
        if preallocated_len < JOURNAL_HEADER_LEN as u64 + MIN_FRAME_LEN {
            return Err(StoreError::InvalidConfiguration(format!(
                "journal preallocation {preallocated_len} cannot hold a header and one frame"
            )));
        }
        let path = active_dir.join(format!("{first_shard_sequence}.journal"));
        if path.exists() {
            let (journal, scan) = Self::open(&path, &root_uuid, Arc::clone(&counters))?;
            let header = journal.header();
            if header.shard_index != shard_index
                || header.first_shard_sequence != first_shard_sequence
                || header.preallocated_len != preallocated_len
                || !scan.frames.is_empty()
                || scan.stop_offset != JOURNAL_HEADER_LEN as u64
            {
                return Err(StoreError::Corruption(format!(
                    "occupied fresh-journal target {} is not the requested empty journal",
                    path.display()
                )));
            }
            sys::fsync_dir(active_dir, &counters)?;
            return Ok(journal);
        }

        // Target-scoped and deterministic: one interrupted creation can leave
        // at most one invisible construction artifact. Re-entry either reuses
        // a fully fenced empty journal or reconstructs a partial pre-publish
        // file in place; it never allocates another temp name.
        let temporary = active_dir.join(format!(".{first_shard_sequence}.journal.tmp"));
        let requested_header = JournalHeader {
            shard_index,
            root_uuid,
            journal_id,
            first_shard_sequence,
            preallocated_len,
            created_at_micros,
        };
        let existed = temporary.exists();
        let mut file = File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&temporary)?;
        let decoded_header = if existed {
            let mut bytes = [0u8; JOURNAL_HEADER_LEN];
            sys::pread_exact(&file, 0, &mut bytes)
                .ok()
                .and_then(|()| JournalHeader::decode(&bytes).ok())
        } else {
            None
        };
        let header = if let Some(header) = decoded_header {
            if header.root_uuid != root_uuid
                || header.shard_index != shard_index
                || header.first_shard_sequence != first_shard_sequence
                || header.preallocated_len != preallocated_len
            {
                return Err(StoreError::Corruption(format!(
                    "fresh-journal temp {} belongs to a different target",
                    temporary.display()
                )));
            }
            let scan = scan_journal(&file, &header, JOURNAL_HEADER_LEN as u64);
            if !scan.frames.is_empty() || scan.stop_offset != JOURNAL_HEADER_LEN as u64 {
                return Err(StoreError::Corruption(format!(
                    "fresh-journal temp {} is not empty",
                    temporary.display()
                )));
            }
            // Re-fence before publication. Exact bytes in page cache do not
            // prove the previous process reached its fdatasync.
            sys::fdatasync(&file, &counters)?;
            header
        } else {
            // The deterministic temp is unpublished and target-scoped. A bad
            // or partial header can only be an interrupted construction for
            // this missing final name, so finish that construction in place.
            sys::truncate(&file, 0, &counters)?;
            sys::preallocate(&file, preallocated_len)?;
            let encoded = requested_header.encode()?;
            sys::seek_to(&mut file, 0)?;
            sys::write_vectored_all(&mut file, &[IoSlice::new(&encoded)], &counters)?;
            sys::fdatasync(&file, &counters)?;
            requested_header
        };
        if let Err(error) = sys::rename_noreplace(&temporary, &path) {
            return Err(error.into());
        }
        sys::fsync_dir(active_dir, &counters)?;

        Ok(Self {
            file,
            path,
            header,
            cursor: JOURNAL_HEADER_LEN as u64,
            next_assign: first_shard_sequence,
            last_appended: None,
            frames: Vec::new(),
            counters,
            poison: None,
        })
    }

    /// Open an existing journal and establish its write cursor by forward
    /// scan.
    ///
    /// The scan is the production one: recovery's step 5 and reopening for
    /// append are the same walk, so there is no second definition of where the
    /// journal ends.
    pub fn open(
        path: &Path,
        root_uuid: &[u8; 16],
        counters: Arc<DurabilityCounters>,
    ) -> Result<(Self, TailScan), StoreError> {
        let mut file = File::options().read(true).write(true).open(path)?;

        let mut header_bytes = [0u8; JOURNAL_HEADER_LEN];
        sys::pread_exact(&file, 0, &mut header_bytes)?;
        let header = JournalHeader::decode(&header_bytes)?;
        if &header.root_uuid != root_uuid {
            return Err(FrameError::RootUuid.into());
        }

        let scan = scan_journal(&file, &header, JOURNAL_HEADER_LEN as u64);
        let cursor = scan.stop_offset;
        let frames: Vec<(u64, u64, u64)> = scan
            .frames
            .iter()
            .map(|f| (f.shard_sequence, f.offset, f.len))
            .collect();
        let last_appended = scan.last_shard_sequence();
        let next_assign = last_appended
            .map(|s| s.saturating_add(1))
            .unwrap_or(header.first_shard_sequence);
        sys::seek_to(&mut file, cursor)?;

        Ok((
            Self {
                file,
                path: path.to_path_buf(),
                header,
                cursor,
                next_assign,
                last_appended,
                frames,
                counters,
                poison: None,
            },
            scan,
        ))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn header(&self) -> &JournalHeader {
        &self.header
    }

    pub fn journal_id(&self) -> [u8; 16] {
        self.header.journal_id
    }

    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    pub fn frame_index(&self) -> &[(u64, u64, u64)] {
        &self.frames
    }

    pub fn counters(&self) -> DurabilityCounterSnapshot {
        self.counters.snapshot()
    }

    pub fn counters_handle(&self) -> &Arc<DurabilityCounters> {
        &self.counters
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn poison_cause(&self) -> Option<&str> {
        self.poison.as_deref()
    }

    /// Next `shard_sequence`, consumed on call.
    ///
    /// A sequence consumed by a group that then fails to append is not reused:
    /// the shard poisons, and the reopened journal takes its next sequence
    /// from what recovery actually found on the device, so no gap survives a
    /// reopen (scope 3.8 step 9).
    pub fn assign_shard_sequence(&mut self) -> u64 {
        let sequence = self.next_assign;
        self.next_assign = self.next_assign.saturating_add(1);
        sequence
    }

    pub fn next_shard_sequence(&self) -> u64 {
        self.next_assign
    }

    pub fn last_appended_shard_sequence(&self) -> Option<u64> {
        self.last_appended
    }

    /// Whether `bytes` more still fit inside the preallocated region.
    pub fn fits(&self, bytes: u64) -> bool {
        self.cursor
            .checked_add(bytes)
            .is_some_and(|end| end <= self.header.preallocated_len)
    }

    /// Rotation happens when the cursor reaches the preallocated length or the
    /// configured segment size, whichever is first (scope 3.2).
    pub fn should_rotate(&self, segment_max_bytes: u64) -> bool {
        self.cursor >= self.header.preallocated_len || self.cursor >= segment_max_bytes
    }

    fn poison(&mut self, cause: String) -> StoreError {
        if self.poison.is_none() {
            self.poison = Some(cause.clone());
        }
        StoreError::ShardPoisoned {
            shard: self.header.shard_index,
            cause,
        }
    }

    /// **The append path.** Steps 4–6 of scope 3.7, and the only place in the
    /// crate that fences the journal.
    ///
    /// Returns the appended `shard_sequence` values. Exactly one `fdatasync`
    /// runs per call, and a failed one is terminal: it is never retried,
    /// because on Linux the error may be reported once with the dirty pages
    /// already dropped, so a second call can return success while the data is
    /// permanently gone.
    ///
    /// A short write is **not** an error in `sys::write_vectored_all`; it
    /// leaves a durable prefix, and the group's outcome is decided per frame
    /// by completeness (scope 3.3), not by any return value. What this
    /// function does with a short write is refuse to continue and poison —
    /// never rewind the cursor, truncate, or rewrite.
    pub fn append_group_and_fence(&mut self, frames: &[Frame]) -> Result<Vec<u64>, StoreError> {
        if let Some(cause) = &self.poison {
            return Err(StoreError::ShardPoisoned {
                shard: self.header.shard_index,
                cause: cause.clone(),
            });
        }
        if frames.is_empty() {
            return Ok(Vec::new());
        }

        // --- step 4: encode, and prove the group is appendable at all -------
        let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(frames.len());
        let mut sequences = Vec::with_capacity(frames.len());
        let mut expected = self
            .last_appended
            .map(|s| s.saturating_add(1))
            .unwrap_or(self.header.first_shard_sequence);
        for frame in frames {
            if frame.header.journal_id != self.header.journal_id {
                return Err(FrameError::JournalId.into());
            }
            if frame.header.shard_sequence != expected {
                return Err(StoreError::Conflict(format!(
                    "group frame carries shard_sequence {} where the journal expects {}; \
                     shard_sequence is contiguous within one shard",
                    frame.header.shard_sequence, expected
                )));
            }
            expected = expected
                .checked_add(1)
                .ok_or_else(|| StoreError::Corruption("shard_sequence overflow".into()))?;
            sequences.push(frame.header.shard_sequence);
            encoded.push(frame.encode()?);
        }

        let total: u64 = encoded.iter().map(|b| b.len() as u64).sum();
        if !self.fits(total) {
            // Nothing is written, so this is not a poisoning condition: the
            // caller rotates and retries into a fresh journal.
            return Err(StoreError::LimitExceeded {
                limit: "journal_preallocate_bytes",
                observed: self.cursor.saturating_add(total),
                allowed: self.header.preallocated_len,
            });
        }

        // --- scope 3.7 step 4, before any byte reaches the device -----------
        fire(self, Failpoint::BeforeAppend, "failpoint before append")?;

        let start = self.cursor;
        sys::seek_to(&mut self.file, start).map_err(|e| {
            let cause = format!("could not position the write cursor at {start}: {e}");
            self.poison(cause)
        })?;

        // --- step 5: one vectored write, looping on short writes ------------
        let end = self.write_group(&encoded)?;
        // The cursor advances to whatever is actually on the device, including
        // after a short write. Nothing here ever moves it backwards.
        self.cursor = end;
        if end != start.saturating_add(total) {
            let cause = format!(
                "short or misplaced append: expected the cursor at {}, observed {end}; \
                 the durable prefix stands and the shard is poisoned",
                start.saturating_add(total)
            );
            return Err(self.poison(cause));
        }

        // --- whole frames are on the device but unfenced --------------------
        fire(
            self,
            Failpoint::AfterFrameWrite,
            "failpoint after frame write",
        )?;
        fire(self, Failpoint::BeforeFence, "failpoint before fence")?;
        fire(
            self,
            Failpoint::WriterPanicBeforeFence,
            "writer failed before the fence",
        )?;
        fire(
            self,
            Failpoint::FenceFailed,
            "fence failed; terminal for the shard and never retried",
        )?;
        fire(
            self,
            Failpoint::FenceAmbiguous,
            "fence outcome is ambiguous; recovery must re-read from the device",
        )?;

        // --- step 6: THE fence. Exactly one per group, never retried --------
        if let Err(e) = sys::fdatasync(&self.file, &self.counters) {
            let cause = format!(
                "fdatasync failed: {e}. Terminal for the shard and not retried: the kernel \
                 may report the error once with the dirty pages already dropped, so a \
                 second call could return success while the data is permanently gone."
            );
            return Err(self.poison(cause));
        }

        fire(
            self,
            Failpoint::AfterSuccessfulFence,
            "failpoint after a successful fence",
        )?;
        fire(
            self,
            Failpoint::WriterPanicAfterFence,
            "writer failed after the fence",
        )?;

        let mut offset = start;
        for (sequence, bytes) in sequences.iter().zip(encoded.iter()) {
            self.frames.push((*sequence, offset, bytes.len() as u64));
            offset += bytes.len() as u64;
        }
        self.last_appended = sequences.last().copied();
        if let Some(last) = self.last_appended {
            self.next_assign = self.next_assign.max(last.saturating_add(1));
        }
        Ok(sequences)
    }

    /// One `write_vectored` per group in a release build.
    ///
    /// With the `failpoints` feature the group is written as two adjacent
    /// vectored writes with `DuringFrameWriteTorn` between them, so that
    /// failpoint can leave a genuinely partial final frame on the device for
    /// every action — `Fail`, `Panic`, and `HardExit` alike. Evaluating the
    /// failpoint before a single write could not produce a partial frame under
    /// `HardExit`, because `hit` calls `_exit(3)` and never returns. The bytes
    /// written are identical either way; only the syscall count differs, and
    /// the `failpoints` feature is never enabled in a release binary.
    #[cfg(feature = "failpoints")]
    fn write_group(&mut self, encoded: &[Vec<u8>]) -> Result<u64, StoreError> {
        let last = encoded.last().expect("non-empty group");
        // Tear in the middle of the final frame, 8-byte aligned so the prefix
        // is a plausible device-visible boundary.
        let tear_within = last.len() / 2 / 8 * 8;

        let mut head: Vec<IoSlice<'_>> = encoded[..encoded.len() - 1]
            .iter()
            .map(|b| IoSlice::new(b))
            .collect();
        head.push(IoSlice::new(&last[..tear_within]));
        let written = sys::write_vectored_all(&mut self.file, &head, &self.counters);
        let head_end = match written {
            Ok(end) => end,
            Err(e) => return Err(self.io_poison("journal append", e)),
        };

        fire(
            self,
            Failpoint::DuringFrameWriteTorn,
            "writer failed part-way through a frame; the durable prefix is partial",
        )
        .inspect_err(|_| self.cursor = head_end)?;

        let tail = [IoSlice::new(&last[tear_within..])];
        match sys::write_vectored_all(&mut self.file, &tail, &self.counters) {
            Ok(end) => Ok(end),
            Err(e) => Err(self.io_poison("journal append", e)),
        }
    }

    #[cfg(not(feature = "failpoints"))]
    fn write_group(&mut self, encoded: &[Vec<u8>]) -> Result<u64, StoreError> {
        let bufs: Vec<IoSlice<'_>> = encoded.iter().map(|b| IoSlice::new(b)).collect();
        match sys::write_vectored_all(&mut self.file, &bufs, &self.counters) {
            Ok(end) => Ok(end),
            Err(e) => Err(self.io_poison("journal append", e)),
        }
    }

    fn io_poison(&mut self, what: &str, error: std::io::Error) -> StoreError {
        let cause = format!("{what} failed: {error}");
        self.poison(cause)
    }

    /// Forward-validate the whole journal, as sealing step 1 requires.
    pub fn scan_from_start(&self) -> TailScan {
        scan_journal(&self.file, &self.header, JOURNAL_HEADER_LEN as u64)
    }

    /// Read one frame back by offset and length, revalidating completeness.
    pub fn read_frame(&self, offset: u64, len: u64) -> Result<Frame, StoreError> {
        let len = usize::try_from(len).map_err(|_| StoreError::from(FrameError::Length))?;
        let mut bytes = vec![0u8; len];
        sys::pread_exact(&self.file, offset, &mut bytes)?;
        Ok(Frame::decode(&bytes, &self.header.journal_id)?)
    }

    /// Truncate the file to the write cursor, append `footer`, and fence.
    ///
    /// The truncation is what makes a sealed segment self-locating from end of
    /// file: a journal is preallocated to hundreds of megabytes, and the
    /// footer must be the last thing in the file rather than the last thing
    /// before an unwritten remainder. `fdatasync` persists the size change
    /// because `i_size` is metadata required to read the data back, which is
    /// exactly the class `fdatasync` does not omit.
    ///
    /// Called only by `segment::seal_journal`.
    pub(crate) fn truncate_and_append_footer(&mut self, footer: &[u8]) -> Result<(), StoreError> {
        sys::truncate(&self.file, self.cursor, &self.counters)?;
        sys::seek_to(&mut self.file, self.cursor)?;
        let end = sys::write_vectored_all(&mut self.file, &[IoSlice::new(footer)], &self.counters)?;
        if end != self.cursor + footer.len() as u64 {
            let cause = format!("short write while sealing at {}", self.cursor);
            return Err(self.poison(cause));
        }
        sys::fdatasync(&self.file, &self.counters).map_err(|e| {
            let cause = format!("fdatasync failed while sealing: {e}; never retried");
            self.poison(cause)
        })?;
        Ok(())
    }
}

/// Fire a failpoint at its real location, honouring every action.
///
/// `HardExit` is handled inside `failpoints::hit`, which calls `_exit(3)` and
/// does not return, so no destructor runs, no buffer is flushed, and nothing
/// tidies up — the closest in-process approximation of power loss. The arm
/// here exists so the match stays exhaustive and a new action cannot be added
/// without a decision at every call site.
fn fire(journal: &mut Journal, point: Failpoint, cause: &str) -> Result<(), StoreError> {
    match failpoints::hit(point) {
        FailpointAction::Continue => Ok(()),
        FailpointAction::Fail => Err(journal.poison(format!("{}: {cause}", point.name()))),
        FailpointAction::Panic => {
            journal.poison(format!("{}: {cause}", point.name()));
            panic!("failpoint {} panicked the writer thread", point.name())
        }
        FailpointAction::HardExit => {
            unreachable!("HardExit calls _exit(3) inside failpoints::hit and never returns")
        }
    }
}

/// Forward scan from `from_offset` (scope 3.8 step 5).
///
/// At each offset, completeness (scope 3.3) is tested. A complete frame is
/// adopted and the scan advances; **anything else stops the scan, and
/// everything at or after that offset is discarded even if a later region
/// contains a syntactically complete frame** (step 6). Page writeback can
/// persist a later page before an earlier one, so a torn frame *k* followed by
/// a valid frame *k+1* is an ordinary crash image; adopting *k+1* would
/// publish a hole and break `shard_sequence` contiguity.
///
/// All three physical tail shapes end the scan rather than failing it: a
/// zeroed or stale region (`NotAFrame`), a torn frame that fails a
/// completeness condition (`Incomplete`), and an `EIO` from the device
/// (`ReadError`). Getting the last one wrong turns an ordinary crash into an
/// unopenable store.
pub fn scan_journal(file: &File, header: &JournalHeader, from_offset: u64) -> TailScan {
    let mut frames = Vec::new();
    let mut offset = from_offset.max(JOURNAL_HEADER_LEN as u64);

    loop {
        let remaining = match header.preallocated_len.checked_sub(offset) {
            Some(remaining) if remaining >= MIN_FRAME_LEN => remaining,
            _ => {
                return TailScan {
                    frames,
                    stop_offset: offset,
                    stop: TailStop::EndOfPreallocation,
                }
            }
        };

        let mut head = [0u8; FRAME_HEADER_LEN];
        match sys::pread(file, offset, &mut head) {
            Err(_) => {
                return TailScan {
                    frames,
                    stop_offset: offset,
                    stop: TailStop::ReadError,
                }
            }
            Ok(read) if read < FRAME_HEADER_LEN => {
                return TailScan {
                    frames,
                    stop_offset: offset,
                    stop: TailStop::NotAFrame,
                }
            }
            Ok(_) => {}
        }

        // Cheap prefix test first: an unwritten or stale region is the normal
        // shape of a crashed tail and must not cost a full-frame read.
        if head[..8] != format::FRAME_MAGIC {
            return TailScan {
                frames,
                stop_offset: offset,
                stop: TailStop::NotAFrame,
            };
        }
        let declared = u64::from_le_bytes([
            head[16], head[17], head[18], head[19], head[20], head[21], head[22], head[23],
        ]);
        if declared < MIN_FRAME_LEN
            || declared % format::FRAME_ALIGNMENT != 0
            || declared > remaining
        {
            return TailScan {
                frames,
                stop_offset: offset,
                stop: TailStop::Incomplete(FrameError::Length),
            };
        }

        let mut bytes = vec![0u8; declared as usize];
        match sys::pread(file, offset, &mut bytes) {
            Err(_) => {
                return TailScan {
                    frames,
                    stop_offset: offset,
                    stop: TailStop::ReadError,
                }
            }
            Ok(read) if (read as u64) < declared => {
                return TailScan {
                    frames,
                    stop_offset: offset,
                    stop: TailStop::Incomplete(FrameError::Length),
                }
            }
            Ok(_) => {}
        }

        match format::verify_complete(&bytes, &header.journal_id, remaining) {
            Ok(frame_header) => {
                frames.push(ScannedFrame {
                    shard_sequence: frame_header.shard_sequence,
                    offset,
                    len: frame_header.total_len,
                    header: frame_header,
                });
                offset += declared;
            }
            Err(error) => {
                return TailScan {
                    frames,
                    stop_offset: offset,
                    stop: TailStop::Incomplete(error),
                }
            }
        }
    }
}

/// A quarantine record that was actually written.
///
/// The path is not a convenience. Scope 3.8 step 7 exists so an operator — and
/// A3's external ACK reconciliation — can look at what the device retained
/// after a crash, and "some bytes were quarantined" without saying where is
/// evidence nobody can find. `bytes` and `path` are produced together, by the
/// one call that wrote the file, so they cannot describe different records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantinedTail {
    pub path: PathBuf,
    pub bytes: u64,
}

/// Copy the discarded tail into `quarantine/<journal_id>-<offset>.tail`
/// (scope 3.8 step 7) and report the record that was written.
///
/// `Ok(None)` means **no record exists**, and every path that returns it is a
/// case where writing one would be wrong rather than a case where writing one
/// failed:
///
/// - the tail is empty or entirely zeros — the ordinary copy-on-write crash
///   leaves exactly that, and a quarantine file for every clean crash would
///   bury the one that matters;
/// - the tail read returned `EIO` — the case scope 3.8 step 5 exists for.
///   There is nothing to quarantine and nothing to fail about;
/// - the destination name already exists. A second crash at the same offset is
///   separate evidence, not a replacement for the first, so the existing
///   record stands and this one is dropped.
///
/// Returning the path rather than only a byte count is what makes
/// `ShardRecoveryReport.quarantined` settable at all; before this it was a
/// field no caller could populate.
pub fn quarantine_tail(
    quarantine_dir: &Path,
    file: &File,
    header: &JournalHeader,
    stop_offset: u64,
    counters: &DurabilityCounters,
) -> Result<Option<QuarantinedTail>, StoreError> {
    let available = header.preallocated_len.saturating_sub(stop_offset);
    let want = available.min(MAX_QUARANTINE_BYTES);
    if want == 0 {
        return Ok(None);
    }

    let mut bytes = vec![0u8; want as usize];
    let read = match sys::pread(file, stop_offset, &mut bytes) {
        // An `EIO` in the tail region is the case scope 3.8 step 5 exists for.
        // There is nothing to quarantine and nothing to fail about.
        Err(_) => return Ok(None),
        Ok(read) => read,
    };
    bytes.truncate(read);
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Ok(None);
    }

    std::fs::create_dir_all(quarantine_dir)?;
    let stem = format!("{}-{stop_offset}", hex::encode(header.journal_id));
    let path = quarantine_dir.join(format!("{stem}.tail"));
    let tmp = quarantine_dir.join(format!("{stem}.tail.tmp"));
    {
        let mut out = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        sys::write_vectored_all(&mut out, &[IoSlice::new(&bytes)], counters)?;
        sys::fdatasync(&out, counters)?;
    }
    // Never overwrite an existing quarantine record: a second crash at the
    // same offset is separate evidence, not a replacement for the first.
    if sys::rename_noreplace(&tmp, &path).is_err() {
        let _ = sys::unlink(&tmp);
        return Ok(None);
    }
    sys::fsync_dir(quarantine_dir, counters)?;
    Ok(Some(QuarantinedTail {
        path,
        bytes: bytes.len() as u64,
    }))
}
