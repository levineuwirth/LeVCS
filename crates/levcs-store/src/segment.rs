//! Immutable sealed segments: bounded `pread` reads, the open-FD cache, and
//! integrity checks. Also the shard's on-disk layout, the seal/rotate
//! sequence of scope 3.4, and the manifest install of scope 3.5.
//!
//! **Owned by A1 JournalWriter** (scope 2.1, 4-A1).
//!
//! Frames are byte-identical between a journal and the segment it seals into,
//! so one golden frame corpus covers both readers: sealing appends a footer
//! and renames, and never re-encodes a frame byte.

use std::collections::HashMap;
use std::fs::File;
use std::io::IoSlice;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::format::{
    CurrentPointer, Frame, FrameError, JournalHeader, Manifest, SegmentFooter, FORMAT_MARKER_LEN,
    JOURNAL_HEADER_LEN, SEGMENT_FOOTER_LOCATOR_LEN, STORAGE_VERSION,
};
use crate::journal::{Journal, TailScan};
use crate::sys;
use crate::types::{DurabilityCounters, StoreError};

/// The root layout of scope 3.1.
#[derive(Clone, Debug)]
pub struct RootLayout {
    pub root: PathBuf,
}

impl RootLayout {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn format_path(&self) -> PathBuf {
        self.root.join("FORMAT")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.root.join("LOCK")
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.root.join("quarantine")
    }

    pub fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    pub fn shards_dir(&self) -> PathBuf {
        self.root.join("shards")
    }

    /// Shard directories are two-digit for the first hundred and widen after,
    /// so a listing sorts in shard order for the common topologies.
    pub fn shard(&self, shard: u16) -> ShardPaths {
        ShardPaths::new(self.shards_dir().join(format!("{shard:02}")))
    }
}

/// One shard's directories and its `CURRENT` pointer.
#[derive(Clone, Debug)]
pub struct ShardPaths {
    pub dir: PathBuf,
}

impl ShardPaths {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn active(&self) -> PathBuf {
        self.dir.join("active")
    }

    pub fn segments(&self) -> PathBuf {
        self.dir.join("segments")
    }

    pub fn indexes(&self) -> PathBuf {
        self.dir.join("indexes")
    }

    pub fn checkpoints(&self) -> PathBuf {
        self.dir.join("checkpoints")
    }

    pub fn manifests(&self) -> PathBuf {
        self.dir.join("manifests")
    }

    pub fn current(&self) -> PathBuf {
        self.dir.join("CURRENT")
    }

    pub fn manifest(&self, generation: u64) -> PathBuf {
        self.manifests().join(manifest_filename(generation))
    }

    pub fn segment(&self, generation: u64, first: u64, last: u64) -> PathBuf {
        self.segments()
            .join(segment_filename(generation, first, last))
    }
}

pub fn manifest_filename(generation: u64) -> String {
    format!("{generation}.manifest")
}

pub fn segment_filename(generation: u64, first: u64, last: u64) -> String {
    format!("{generation}-{first}-{last}.seg")
}

// ---------------------------------------------------------------------------
// Root initialization
// ---------------------------------------------------------------------------

/// `quarantine/`, `staging/`, `shards/` — the store-invented entries directly
/// beneath a root, in the order [`planned_directories`] lists them. `opened[0]`
/// and `opened[2]` in [`initialize_root`] are `quarantine/` and `shards/`.
const STORE_INVENTED_ROOT_ENTRIES: usize = 3;

/// `<shard>/` plus `active`, `segments`, `indexes`, `checkpoints`, `manifests`.
const DIRS_PER_SHARD: usize = 6;

/// Every directory [`initialize_root`] invents beneath the root, parents first.
///
/// Separated from the creation loop because the refusal rule needs the whole set
/// before any of it is created, and because the fencing below indexes into it
/// positionally.
fn planned_directories(layout: &RootLayout, shard_count: u16) -> Vec<PathBuf> {
    let mut planned =
        Vec::with_capacity(STORE_INVENTED_ROOT_ENTRIES + shard_count as usize * DIRS_PER_SHARD);
    planned.push(layout.quarantine_dir());
    planned.push(layout.staging_dir());
    planned.push(layout.shards_dir());
    debug_assert_eq!(planned.len(), STORE_INVENTED_ROOT_ENTRIES);
    for shard in 0..shard_count {
        let paths = layout.shard(shard);
        let before = planned.len();
        planned.push(paths.dir.clone());
        planned.push(paths.active());
        planned.push(paths.segments());
        planned.push(paths.indexes());
        planned.push(paths.checkpoints());
        planned.push(paths.manifests());
        debug_assert_eq!(planned.len() - before, DIRS_PER_SHARD);
    }
    planned
}

/// A name the store must own as a directory, occupied by something else.
///
/// [`StoreError::UnrecognizedLayout`] rather than an `Io`: the store is being
/// asked to build its tree through an object it did not create, which is the
/// same judgement as any other unrecognized occupant of a root, and the same
/// answer — refuse, modify nothing.
fn not_a_directory(path: &Path) -> StoreError {
    StoreError::UnrecognizedLayout(format!(
        "{} is not a directory; refusing to build the store tree through it",
        path.display()
    ))
}

/// Create the v2 tree and write `FORMAT`, fsyncing every new directory and the
/// root's parent (scope 3.1 startup state 1).
///
/// `shard_count` is frozen here for the life of the root. Opening later with a
/// different configured value is a hard `FormatMismatch` and never a silent
/// reroute: per-repository sequence ownership is only sound while a
/// repository's shard assignment never moves.
pub fn initialize_root(
    layout: &RootLayout,
    shard_count: u16,
    root_uuid: [u8; 16],
    created_at_micros: i64,
    counters: &DurabilityCounters,
) -> Result<crate::format::FormatMarker, StoreError> {
    if shard_count == 0 {
        return Err(StoreError::InvalidConfiguration(
            "shard_count must be nonzero".into(),
        ));
    }
    // The root itself, and everything above it, is the caller's path. Resolving
    // it is explicitly out of scope (§3.1): an operator who configures a root
    // behind a symlink has said where the store goes.
    std::fs::create_dir_all(&layout.root)?;

    // Everything below is a name *the store invents*, and none of it may be
    // reached through a link. Two passes, because a refusal must not leave the
    // tree half-extended: pass one classifies every planned directory and holds
    // a descriptor onto each that already exists, pass two creates the rest.
    // Ordered parents-before-children so pass two never creates through a name
    // pass one did not see.
    let planned = planned_directories(layout, shard_count);
    let mut found = Vec::with_capacity(planned.len());
    for directory in &planned {
        match sys::open_directory_nofollow(directory)? {
            sys::NamedDirectory::Opened(handle) => found.push(Some(handle)),
            sys::NamedDirectory::Absent => found.push(None),
            sys::NamedDirectory::NotDirectory => return Err(not_a_directory(directory)),
        }
    }
    let mut opened = Vec::with_capacity(planned.len());
    for (directory, existing) in planned.iter().zip(found) {
        opened.push(match existing {
            Some(handle) => handle,
            None => sys::create_directory_nofollow(directory)?
                .ok_or_else(|| not_a_directory(directory))?,
        });
    }

    // Fenced through the descriptors just established, not by reopening their
    // names: a second lookup would hand the fence to whatever the name resolves
    // to now rather than to the directory that was validated.
    //
    // The shape of this sequence is load-bearing and unchanged — six directories
    // per shard plus the shard directory again, which `engine.rs` asserts as an
    // exact `fsync_dir` count.
    for shard in 0..shard_count as usize {
        let shard_directories =
            &opened[STORE_INVENTED_ROOT_ENTRIES + shard * DIRS_PER_SHARD..][..DIRS_PER_SHARD];
        for directory in shard_directories {
            sys::fsync_dir_fd(directory, counters)?;
        }
        sys::fsync_dir_fd(&shard_directories[0], counters)?;
    }

    let marker = crate::format::FormatMarker {
        format_version: 2,
        storage_version: STORAGE_VERSION,
        shard_count,
        root_uuid,
        created_at_micros,
    };
    let bytes = marker.encode()?;
    let tmp = layout.root.join("FORMAT.tmp");
    write_fenced(&tmp, &bytes, counters)?;
    sys::rename_noreplace(&tmp, &layout.format_path())?;

    sys::fsync_dir_fd(&opened[2], counters)?;
    sys::fsync_dir_fd(&opened[0], counters)?;
    sys::fsync_dir(&layout.root, counters)?;
    if let Some(parent) = layout.root.parent() {
        sys::fsync_dir(parent, counters)?;
    }
    Ok(marker)
}

/// Read and validate `FORMAT`.
///
/// Three answers, kept distinct because callers act on them differently:
///
/// - **Absent** — `Io(NotFound)`, exactly as `File::open` reported it. An absent
///   `FORMAT` is startup state 1 or 3, not a refusal, and `classify_root` and
///   `drive.rs` both read it that way.
/// - **Not a regular file** — [`StoreError::UnrecognizedLayout`]. A symlink here
///   is the read-only member of the redirection family: following it would let a
///   `FORMAT` outside the root decide this root's `shard_count` and `root_uuid`,
///   and every file in the tree is then validated against a marker the store
///   never wrote. Nothing is destroyed, which is why it was ranked lowest of the
///   four, and it is still an authority the operator did not grant.
/// - **A regular file that does not decode** — unchanged. `FormatMismatch` or a
///   decode error, which is a corrupt marker and a different finding from a
///   redirected one.
pub fn read_format(layout: &RootLayout) -> Result<crate::format::FormatMarker, StoreError> {
    let path = layout.format_path();
    let file = match sys::open_regular_nofollow_classified(&path)? {
        sys::NamedRegularFile::Opened(file) => file,
        sys::NamedRegularFile::Absent => {
            return Err(StoreError::Io(Arc::new(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} not found", path.display()),
            ))))
        }
        sys::NamedRegularFile::NotRegular => {
            return Err(StoreError::UnrecognizedLayout(format!(
                "{} is not a regular file; refusing to read a format marker through it",
                path.display()
            )))
        }
    };
    let mut bytes = [0u8; FORMAT_MARKER_LEN];
    sys::pread_exact(&file, 0, &mut bytes)?;
    Ok(crate::format::FormatMarker::decode(&bytes)?)
}

/// Ownership of `<root>/LOCK`, released explicitly when dropped.
///
/// # Why this is a guard and not a `File`
///
/// `lock_root` used to return the open `File` and let the release fall out of
/// closing it. That is wrong across a concurrent `fork`. `flock` is held by the
/// **open file description**, not by the descriptor; a forked child inherits a
/// descriptor onto the same description, and `FD_CLOEXEC` closes it at `exec`,
/// not at `fork`. So for as long as any concurrently forked child has not yet
/// exec'd, the owner closing its descriptor releases nothing, and the next
/// `lock_root` on that root is refused `AlreadyLocked` — a refusal scope §3.1
/// defines as final and never a wait, produced by a process that no longer
/// exists as far as the store is concerned.
///
/// The fix is not to make closing more prompt. It is to stop making the
/// release a consequence of a descriptor lifetime that a process outside this
/// one can extend: [`RootLock::drop`] issues `LOCK_UN` *before* the descriptor
/// closes, which releases the description's lock regardless of who else holds
/// a descriptor onto it.
pub struct RootLock {
    /// Dropped after `Drop::drop` runs, so the unlock always precedes the
    /// close.
    file: File,
}

/// `LOCK_UN` failures observed in [`RootLock::drop`], where no error can be
/// returned.
///
/// A `Drop` that swallows a failed release would turn this defect back into an
/// intermittent one, and panicking in `Drop` can abort during an unwind. So the
/// failure is counted instead: charter item 7, the same rule the durability
/// counters follow. A non-zero reading means some root lock outlived its owner
/// and the next `lock_root` on that root may be spuriously refused.
static ROOT_LOCK_RELEASE_FAILURES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

impl RootLock {
    /// How many times a [`RootLock`] failed to release in `Drop`. Zero in every
    /// healthy run.
    pub fn release_failures() -> u64 {
        ROOT_LOCK_RELEASE_FAILURES.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl std::fmt::Debug for RootLock {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("RootLock").finish_non_exhaustive()
    }
}

impl Drop for RootLock {
    fn drop(&mut self) {
        match sys::unlock(&self.file) {
            Ok(()) => {}
            Err(_) => {
                ROOT_LOCK_RELEASE_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
    }
}

/// Take the exclusive root lock. Failure is `AlreadyLocked`, never a wait
/// (scope 3.1).
///
/// The returned [`RootLock`] releases explicitly when dropped; see its
/// documentation for why holding a bare `File` was not equivalent.
///
/// # Why the open goes through the no-follow funnel
///
/// Contract review 2026-07-29-A. This used to be
/// `File::options().create(true).read(true).write(true).open(..)`, which
/// traverses a symlink at `LOCK` — and `flock` locks the inode the descriptor
/// reached, not the name that was asked for. A link at `LOCK` therefore put the
/// root lock on a foreign inode while leaving the root itself unlocked, so a
/// second process arriving at that same root took the lock as well and two
/// owners each believed they held it exclusively. Scope 3.1 exclusion is the
/// property the whole engine's single-writer reasoning rests on, so this is a
/// safety defect rather than a data hazard: nothing is destroyed, and everything
/// downstream is permitted to race.
///
/// `classify_root` refuses a non-regular `LOCK` on the `StoreEngine::open` path,
/// but that is not where the guarantee can live. `RecoverySession::open` and
/// `drive.rs` reach here directly, without any classification, and the check has
/// to hold for them too. It is also strictly ordered: the type is established
/// from the descriptor *before* `flock` is attempted, so a refused name is never
/// locked even momentarily.
///
/// A `LOCK` that is not a regular file is [`StoreError::UnrecognizedLayout`] and
/// not [`StoreError::AlreadyLocked`]: the root is not busy, it is malformed, and
/// the two call for opposite operator responses.
pub fn lock_root(layout: &RootLayout) -> Result<RootLock, StoreError> {
    let path = layout.lock_path();
    let file = match sys::open_or_create_regular_nofollow(&path)? {
        Some(file) => file,
        None => {
            return Err(StoreError::UnrecognizedLayout(format!(
                "{} is not a regular file; refusing to take the root lock on it",
                path.display()
            )));
        }
    };
    if sys::try_lock_exclusive(&file)? {
        Ok(RootLock { file })
    } else {
        Err(StoreError::AlreadyLocked)
    }
}

/// Write a file and fence it. The name is not yet durable; the caller renames
/// and syncs the directory.
///
/// # Why the open is not `create(true).truncate(true)`
///
/// Every caller passes a `.tmp` name inside the root — `FORMAT.tmp`,
/// `<generation>.manifest.tmp`, `CURRENT.tmp` — and an `O_TRUNC` open destroys
/// whatever the name holds before anything can look at it. Through a symlink it
/// destroys a file *outside* the root: measured at `INITIALIZING.tmp` earlier in
/// this wave, a 4096-byte file went to 27 bytes with the link removed and the
/// store reporting success. These names are as reachable to an operator as that
/// one was.
///
/// So the open and the truncation are separated: no flag combination truncates
/// only regular files, which is why the type check needs the descriptor first.
/// An existing regular file is **kept and emptied**, not refused — it is residue
/// from an interrupted attempt at this exact write, and reusing the name is how
/// the retry works. Anything else at the name is
/// [`StoreError::UnrecognizedLayout`].
fn write_fenced(
    path: &Path,
    bytes: &[u8],
    counters: &DurabilityCounters,
) -> Result<(), StoreError> {
    let Some(mut file) = sys::open_or_create_regular_truncated_nofollow(path, counters)? else {
        return Err(StoreError::UnrecognizedLayout(format!(
            "{} is not a regular file; refusing to write a store metadata file through it",
            path.display()
        )));
    };
    // Through the funnel, so the counters see every durable byte.
    sys::write_vectored_all(&mut file, &[IoSlice::new(bytes)], counters)?;
    sys::fdatasync(&file, counters)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Sealing (scope 3.4)
// ---------------------------------------------------------------------------

/// Seal a full journal into `segments/<generation>-<first>-<last>.seg`.
///
/// Steps 1–4 of scope 3.4 as amended, in order:
///
/// 1. stop appending and validate the whole file forward;
/// 2. append the segment footer;
/// 3. `fdatasync` the file;
/// 4. **`link`** into `segments/` and `fsync_dir` on `segments/`.
///
/// Not a single frame byte is re-encoded: the forward validation reads the
/// frames back and the footer records where they already are.
///
/// # Why `link`, not `rename`
///
/// The first draft of scope 3.4 said to *rename* here and then, in step 5, to
/// "install a new `CURRENT` naming it and only then unlink the old journal
/// name" — but a rename leaves no old name to unlink, and the window it opens
/// is a real durability hole: a crash between the rename and the manifest
/// install leaves a valid segment that no manifest generation references and
/// no active journal where those frames used to be. Recovery step 2 trusts
/// only manifest-referenced files, so a fenced, acknowledged prefix would be
/// lost, violating plan §4 transaction invariant 3.
///
/// With `link`, both names exist across the whole install, so every crash
/// point leaves the frames reachable through at least one of them. The caller
/// finishes with [`unlink_sealed_journal`] after the manifest is installed.
///
/// The cost is a state recovery must expect: between step 4 and step 6 an
/// `active/` journal exists whose `journal_id` is already covered by a
/// manifest-referenced segment. That is a completed seal whose final unlink
/// was lost — the stale active name is unlinked and the frames are taken from
/// the manifest, never replayed twice.
pub fn seal_journal(
    journal: &mut Journal,
    paths: &ShardPaths,
    generation: u64,
    counters: &DurabilityCounters,
) -> Result<PathBuf, StoreError> {
    // --- step 1: validate the whole file forward ------------------------
    let scan = journal.scan_from_start();
    if scan.stop_offset != journal.cursor() {
        return Err(StoreError::Corruption(format!(
            "sealing refused: forward validation ends at {} but the write cursor is {}",
            scan.stop_offset,
            journal.cursor()
        )));
    }
    let index: Vec<(u64, u64, u64)> = scan
        .frames
        .iter()
        .map(|f| (f.shard_sequence, f.offset, f.len))
        .collect();
    if index.is_empty() {
        return Err(StoreError::Corruption(
            "sealing refused: the journal contains no complete frame".into(),
        ));
    }
    let first = index.first().expect("non-empty").0;
    let last = index.last().expect("non-empty").0;

    // --- steps 2 and 3: append the footer and fence ---------------------
    let footer = SegmentFooter {
        root_uuid: journal.header().root_uuid,
        journal_id: journal.header().journal_id,
        generation,
        first_shard_sequence: first,
        last_shard_sequence: last,
        frame_count: index.len() as u64,
        offsets: index,
    };
    let bytes = footer.encode()?;
    journal.truncate_and_append_footer(&bytes)?;

    // --- step 4: publish the segment name, keeping the active one -------
    let destination = paths.segment(generation, first, last);
    sys::link_noreplace(journal.path(), &destination)?;
    sys::fsync_dir(&paths.segments(), counters)?;
    Ok(destination)
}

/// Seal a recovery-validated prefix without ever modifying its source journal.
///
/// The crash image is forensic evidence. Recovery therefore copies exactly
/// `0..scan.stop_offset` into a uniquely named, fenced artifact, opens that
/// copy through the normal journal scanner, and seals the copy through
/// [`seal_journal`]. The original descriptor is read-only throughout.
///
/// A crash may leave the deterministic final segment installed but not yet
/// referenced by a manifest. Re-recovery accepts that artifact only after its
/// footer, frame index, and every byte of the validated prefix agree with the
/// source. An occupied name with different contents is corruption, never an
/// overwrite.
pub fn seal_recovered_prefix(
    source: &File,
    header: &JournalHeader,
    scan: &TailScan,
    paths: &ShardPaths,
    generation: u64,
    counters: &Arc<DurabilityCounters>,
) -> Result<PathBuf, StoreError> {
    if scan.frames.is_empty() {
        return Err(StoreError::Corruption(
            "recovery sealing refused: the validated prefix contains no frame".into(),
        ));
    }
    if scan.frames.first().map(|frame| frame.offset) != Some(JOURNAL_HEADER_LEN as u64) {
        return Err(StoreError::Corruption(
            "recovery sealing refused: the validated prefix does not start after the header".into(),
        ));
    }
    let last_end = scan
        .frames
        .last()
        .and_then(|frame| frame.offset.checked_add(frame.len))
        .ok_or_else(|| {
            StoreError::Corruption("recovery sealing refused: invalid frame range".into())
        })?;
    if last_end != scan.stop_offset {
        return Err(StoreError::Corruption(format!(
            "recovery sealing refused: frame prefix ends at {last_end}, scan stops at {}",
            scan.stop_offset
        )));
    }

    let first = scan.frames.first().expect("non-empty").shard_sequence;
    let last = scan.frames.last().expect("non-empty").shard_sequence;
    let destination = paths.segment(generation, first, last);
    let artifact = recovery_prefix_path(paths, header, generation);
    if destination.exists() {
        validate_recovered_segment(source, header, scan, &destination, generation)?;
        if artifact.exists() {
            let artifact_file = File::open(&artifact)?;
            let compare_len = artifact_file.metadata()?.len().min(scan.stop_offset);
            compare_prefix(source, &artifact_file, compare_len, &artifact)?;
            sys::unlink(&artifact)?;
            sys::fsync_dir(&paths.segments(), counters)?;
        }
        return Ok(destination);
    }

    let mut copied = File::options()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&artifact)?;
    let existing_len = copied.metadata()?.len();
    let compare_len = existing_len.min(scan.stop_offset);
    compare_prefix(source, &copied, compare_len, &artifact)?;
    if existing_len > scan.stop_offset {
        // A crash after footer append but before publishing the segment may
        // leave a sealed or partially sealed construction artifact. Its exact
        // prefix proves ownership; discard only the construction suffix and
        // run the normal seal again.
        sys::truncate(&copied, scan.stop_offset, counters)?;
    } else if existing_len < scan.stop_offset {
        copy_exact_prefix(
            source,
            &mut copied,
            existing_len,
            scan.stop_offset,
            counters,
        )?;
    }
    sys::fdatasync(&copied, counters)?;
    sys::fsync_dir(&paths.segments(), counters)?;
    drop(copied);

    let (mut journal, copied_scan) =
        Journal::open(&artifact, &header.root_uuid, Arc::clone(counters))?;
    if journal.header() != header
        || copied_scan.frames != scan.frames
        || copied_scan.stop_offset != scan.stop_offset
    {
        return Err(StoreError::Corruption(
            "the fenced recovery prefix did not reopen as the source prefix".into(),
        ));
    }

    let installed = seal_journal(&mut journal, paths, generation, counters)?;
    validate_recovered_segment(source, header, scan, &installed, generation)?;

    // The installed segment is a hard link to the now-sealed copy. Once its
    // own name is fenced the uniquely named construction artifact is dead.
    sys::unlink(&artifact)?;
    sys::fsync_dir(&paths.segments(), counters)?;
    Ok(installed)
}

fn recovery_prefix_path(paths: &ShardPaths, header: &JournalHeader, generation: u64) -> PathBuf {
    paths.segments().join(format!(
        ".recovery-{}-{generation}.prefix",
        hex::encode(header.journal_id)
    ))
}

fn copy_exact_prefix(
    source: &File,
    destination: &mut File,
    from: u64,
    through: u64,
    counters: &DurabilityCounters,
) -> Result<(), StoreError> {
    const COPY_CHUNK: usize = 1 << 20;
    let mut offset = from;
    sys::seek_to(destination, from)?;
    while offset < through {
        let remaining = through - offset;
        let len = usize::try_from(remaining.min(COPY_CHUNK as u64))
            .map_err(|_| StoreError::Corruption("recovery prefix length overflow".into()))?;
        let mut bytes = vec![0u8; len];
        sys::pread_exact(source, offset, &mut bytes)?;
        let end = sys::write_vectored_all(destination, &[IoSlice::new(&bytes)], counters)?;
        let expected = offset
            .checked_add(len as u64)
            .ok_or_else(|| StoreError::Corruption("recovery prefix length overflow".into()))?;
        if end != expected {
            return Err(StoreError::Corruption(format!(
                "short recovery-prefix copy: expected cursor {expected}, got {end}"
            )));
        }
        offset = expected;
    }
    Ok(())
}

fn compare_prefix(
    source: &File,
    artifact: &File,
    through: u64,
    artifact_path: &Path,
) -> Result<(), StoreError> {
    const COMPARE_CHUNK: usize = 1 << 20;
    let mut offset = 0u64;
    while offset < through {
        let remaining = through - offset;
        let len = usize::try_from(remaining.min(COMPARE_CHUNK as u64))
            .map_err(|_| StoreError::Corruption("recovery prefix length overflow".into()))?;
        let mut original = vec![0u8; len];
        let mut retained = vec![0u8; len];
        sys::pread_exact(source, offset, &mut original)?;
        sys::pread_exact(artifact, offset, &mut retained)?;
        if original != retained {
            return Err(StoreError::Corruption(format!(
                "recovery construction artifact {} differs from its source at offset {offset}",
                artifact_path.display()
            )));
        }
        offset += len as u64;
    }
    Ok(())
}

fn validate_recovered_segment(
    source: &File,
    header: &JournalHeader,
    scan: &TailScan,
    destination: &Path,
    generation: u64,
) -> Result<(), StoreError> {
    let reader = SegmentReader::open(destination, &header.root_uuid)?;
    let footer = reader.footer();
    let expected_offsets: Vec<(u64, u64, u64)> = scan
        .frames
        .iter()
        .map(|frame| (frame.shard_sequence, frame.offset, frame.len))
        .collect();
    if reader.journal_header()? != *header
        || footer.journal_id != header.journal_id
        || footer.generation != generation
        || footer.first_shard_sequence != scan.frames.first().expect("non-empty").shard_sequence
        || footer.last_shard_sequence != scan.frames.last().expect("non-empty").shard_sequence
        || footer.offsets != expected_offsets
    {
        return Err(StoreError::Corruption(format!(
            "occupied recovery segment {} does not describe the validated prefix",
            destination.display()
        )));
    }

    const COMPARE_CHUNK: usize = 1 << 20;
    let segment = File::open(destination)?;
    let mut offset = 0u64;
    while offset < scan.stop_offset {
        let remaining = scan.stop_offset - offset;
        let len = usize::try_from(remaining.min(COMPARE_CHUNK as u64))
            .map_err(|_| StoreError::Corruption("recovery prefix length overflow".into()))?;
        let mut original = vec![0u8; len];
        let mut installed = vec![0u8; len];
        sys::pread_exact(source, offset, &mut original)?;
        sys::pread_exact(&segment, offset, &mut installed)?;
        if original != installed {
            return Err(StoreError::Corruption(format!(
                "occupied recovery segment {} differs from the crash prefix at offset {offset}",
                destination.display()
            )));
        }
        offset += len as u64;
    }
    Ok(())
}

/// Step 6 of scope 3.4: drop the `active/` name, now that the manifest
/// generation naming the segment is durable.
///
/// This is the last step of a seal and it must run **after**
/// [`install_manifest`], never before. Until it runs, both names point at the
/// same inode and the frames are reachable either way; after it runs, they are
/// reachable through the manifest. There is no point in between at which they
/// are reachable through neither, which is the entire reason step 4 links
/// rather than renames.
pub fn unlink_sealed_journal(
    active_path: &Path,
    paths: &ShardPaths,
    counters: &DurabilityCounters,
) -> Result<(), StoreError> {
    match sys::unlink(active_path) {
        Ok(()) => {}
        // Already gone: a previous attempt completed and the crash was after
        // the unlink but before its directory fsync. Finishing the fsync is
        // still the right thing to do.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    sys::fsync_dir(&paths.active(), counters)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Manifest install (scope 3.5)
// ---------------------------------------------------------------------------

/// Install a new manifest generation and make `CURRENT` point at it.
///
/// The exact sequence of scope 3.5, and the only place in the crate that uses
/// a replacing rename:
///
/// ```text
/// 1  write manifests/<generation>.manifest.tmp   (never an existing name)
/// 2  fdatasync it
/// 3  rename_noreplace -> manifests/<generation>.manifest
/// 4  fsync_dir manifests/
/// 5  write CURRENT.tmp naming <generation>; fdatasync it
/// 6  rename_replace  -> CURRENT            <-- the one replacing rename
/// 7  fsync_dir the shard directory
/// 8  only now unlink superseded names, then fsync_dir their directories
/// 9  retain >= manifest_retain generations
/// ```
///
/// Step 6 is the visibility boundary. Steps 1–4 are what give recovery a
/// predecessor to fall back to when `CURRENT` or its referent does not
/// validate.
pub fn install_manifest(
    paths: &ShardPaths,
    manifest: &Manifest,
    manifest_retain: u32,
    counters: &DurabilityCounters,
) -> Result<(), StoreError> {
    let manifests = paths.manifests();
    let final_path = paths.manifest(manifest.generation);
    let tmp = manifests.join(format!("{}.tmp", manifest_filename(manifest.generation)));

    let encoded = manifest.encode()?;
    // 1, 2
    if tmp.exists() {
        let existing = std::fs::read(&tmp)?;
        if existing != encoded {
            return Err(StoreError::Corruption(format!(
                "manifest temp for generation {} contains different bytes",
                manifest.generation
            )));
        }
        let file = File::open(&tmp)?;
        // Exact visible bytes do not prove the interrupted attempt reached its
        // fence. Fence them again before publishing the final name.
        sys::fdatasync(&file, counters)?;
    } else {
        write_fenced(&tmp, &encoded, counters)?;
    }
    // 3 — never overwrite an existing generation.
    if let Err(e) = sys::rename_noreplace(&tmp, &final_path) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            let _ = sys::unlink(&tmp);
            return Err(e.into());
        }
        let existing = std::fs::read(&final_path)?;
        let _ = sys::unlink(&tmp);
        if existing != encoded {
            return Err(StoreError::Corruption(format!(
                "manifest generation {} already exists with different contents",
                manifest.generation
            )));
        }
    }
    // 4
    sys::fsync_dir(&manifests, counters)?;

    // 5
    let pointer = CurrentPointer {
        root_uuid: manifest.root_uuid,
        generation: manifest.generation,
    };
    let current_tmp = paths.dir.join("CURRENT.tmp");
    write_fenced(&current_tmp, &pointer.encode()?, counters)?;
    // 6 — the one replacing rename in the crate. `CURRENT` by definition
    // replaces; every other name in the store uses `rename_noreplace`.
    sys::rename_replace(&current_tmp, &paths.current())?;
    // 7
    sys::fsync_dir(&paths.dir, counters)?;

    // 8, 9 — superseded manifests only, and only beyond the retention floor.
    prune_manifests(paths, manifest.generation, manifest_retain, counters)?;
    Ok(())
}

/// Keep at least `manifest_retain` generations at or below the active one.
fn prune_manifests(
    paths: &ShardPaths,
    active: u64,
    manifest_retain: u32,
    counters: &DurabilityCounters,
) -> Result<(), StoreError> {
    let mut generations = list_manifest_generations(paths)?;
    generations.retain(|generation| *generation <= active);
    generations.sort_unstable();
    // `StoreOptions` already refuses a retention below 2, because recovery
    // needs a predecessor to fall back to; the floor is restated here so a
    // caller that bypasses the options cannot delete the last fallback.
    let retain = (manifest_retain.max(2) as usize).min(generations.len());
    if generations.len() <= retain {
        return Ok(());
    }
    let drop_count = generations.len() - retain;
    for generation in &generations[..drop_count] {
        sys::unlink(&paths.manifest(*generation))?;
    }
    sys::fsync_dir(&paths.manifests(), counters)?;
    Ok(())
}

pub fn list_manifest_generations(paths: &ShardPaths) -> Result<Vec<u64>, StoreError> {
    let mut out = Vec::new();
    let dir = match std::fs::read_dir(paths.manifests()) {
        Ok(dir) => dir,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for entry in dir {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_suffix(".manifest") else {
            continue;
        };
        if let Ok(generation) = stem.parse::<u64>() {
            out.push(generation);
        }
    }
    out.sort_unstable();
    Ok(out)
}

/// Read `CURRENT` if it exists and validates.
///
/// A corrupt pointer is `Ok(None)`, not an error: it is precisely the case the
/// durable manifest history exists to survive.
pub fn read_current(
    paths: &ShardPaths,
    root_uuid: &[u8; 16],
) -> Result<Option<CurrentPointer>, StoreError> {
    let file = match File::open(paths.current()) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let mut bytes = vec![0u8; crate::format::CURRENT_POINTER_LEN];
    if sys::pread_exact(&file, 0, &mut bytes).is_err() {
        return Ok(None);
    }
    match CurrentPointer::decode(&bytes) {
        Ok(pointer) if &pointer.root_uuid == root_uuid => Ok(Some(pointer)),
        Ok(_) | Err(_) => Ok(None),
    }
}

pub fn index_run_filename(generation: u64) -> String {
    format!("{generation}.idx")
}

/// What [`install_index_run`] made durable.
#[derive(Clone, Debug)]
pub struct SealedIndexRun {
    /// Where the run now is, for opening and for the generation pin that
    /// retains it.
    pub path: PathBuf,
    pub filename: String,
    /// Identifies the run inside the manifest, and is the generation the run's
    /// own header carries. Equal to `manifest_generation` by construction.
    pub run_generation: u64,
    /// The manifest generation that makes the run authoritative.
    pub manifest_generation: u64,
}

/// Install one index run and the manifest generation that publishes it.
///
/// Granted to B1 as contract review 2026-07-29-C, amendment 1 of 2, and it is
/// where the whole durability sequence of an index seal lives so that `engine.rs`
/// performs none of it directly:
///
/// ```text
/// 1  write indexes/<generation>.idx.tmp, fenced
/// 2  rename_noreplace -> indexes/<generation>.idx
/// 3  fsync_dir indexes/
/// 4  install_manifest with the run appended     <-- publication
/// ```
///
/// # Why the file is not publication
///
/// Steps 1–3 leave a complete, valid run that recovery **ignores**: scope 3.8
/// step 2 trusts only manifest-referenced files, so an interrupted seal leaves an
/// orphan and not a half-published index. Step 4 is the only step that makes the
/// run authoritative, and it is the existing `install_manifest`, unchanged —
/// which is what keeps `CURRENT` the single visibility boundary for a run as it
/// already is for a segment.
///
/// The predecessor manifest is read here rather than reconstructed by the caller.
/// An engine that rebuilt a `Manifest` from its in-memory generation pins would
/// be re-deriving `retained_tail_ranges`, `base_generation` and
/// `committed_shard_sequence` from a lossy projection of them, and any field it
/// got wrong would be a field recovery then trusts. `committed_shard_sequence` is
/// carried forward **unchanged**: sealing an index run makes no journal frame
/// more durable than it already was, and advancing it here would tell recovery
/// to stop replaying frames that are still only in the active journal.
///
/// `next_generation` must be greater than `current_generation` — the manifest's
/// index-run list is strictly ascending, and reusing a generation would either
/// fail to encode or silently shadow a run.
pub fn install_index_run(
    paths: &ShardPaths,
    root_uuid: &[u8; 16],
    current_generation: u64,
    next_generation: u64,
    run_bytes: &[u8],
    manifest_retain: u32,
    counters: &DurabilityCounters,
) -> Result<SealedIndexRun, StoreError> {
    if next_generation <= current_generation {
        return Err(StoreError::Corruption(format!(
            "an index run cannot be installed at generation {next_generation} over current \
             generation {current_generation}"
        )));
    }
    // A shard that has never rotated its journal has a pinned generation and no
    // manifest file: `initialize_root` writes none, and until scope 3.4 seals a
    // segment there is nothing for one to name. Publishing an index run is the
    // second reason to write a manifest, so this is the case where the first one
    // is created — with no retained tail and a committed prefix of zero, which
    // says exactly what is true: every committed frame is still in `active/`.
    //
    // Only absence synthesizes. A manifest that exists and does not decode is a
    // corrupt manifest, and replacing it with a fresh one would erase the
    // predecessor recovery is supposed to fall back to.
    let previous = match read_manifest(paths, current_generation, root_uuid) {
        Ok(manifest) => manifest,
        Err(StoreError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => Manifest {
            root_uuid: *root_uuid,
            generation: current_generation,
            base_generation: 0,
            retained_tail_ranges: Vec::new(),
            index_runs: Vec::new(),
            checkpoints: Vec::new(),
            committed_shard_sequence: 0,
        },
        Err(error) => return Err(error),
    };

    let filename = index_run_filename(next_generation);
    let indexes = paths.indexes();
    let final_path = indexes.join(&filename);
    let tmp = indexes.join(format!("{filename}.tmp"));
    write_fenced(&tmp, run_bytes, counters)?;
    // Never over an existing name: a run generation is used once, and a second
    // run claiming one already published would replace bytes a live reader may
    // hold mapped.
    sys::rename_noreplace(&tmp, &final_path)?;
    sys::fsync_dir(&indexes, counters)?;

    let mut manifest = previous;
    manifest.generation = next_generation;
    manifest
        .index_runs
        .push((next_generation, filename.clone()));
    install_manifest(paths, &manifest, manifest_retain, counters)?;

    Ok(SealedIndexRun {
        path: final_path,
        filename,
        run_generation: next_generation,
        manifest_generation: next_generation,
    })
}

pub fn read_manifest(
    paths: &ShardPaths,
    generation: u64,
    root_uuid: &[u8; 16],
) -> Result<Manifest, StoreError> {
    let path = paths.manifest(generation);
    let bytes = std::fs::read(&path)?;
    let manifest = Manifest::decode(&bytes)?;
    if &manifest.root_uuid != root_uuid {
        return Err(FrameError::RootUuid.into());
    }
    if manifest.generation != generation {
        return Err(StoreError::Corruption(format!(
            "manifest {} declares generation {}",
            path.display(),
            manifest.generation
        )));
    }
    Ok(manifest)
}

/// Whether every file a manifest references exists.
///
/// Existence, not full validation: a manifest naming a missing segment is a
/// different failure from one naming a corrupt segment, and scope 4-A2 keeps
/// those cases distinct.
pub fn manifest_referents_present(paths: &ShardPaths, manifest: &Manifest) -> bool {
    manifest
        .retained_tail_ranges
        .iter()
        .all(|range| paths.segments().join(&range.filename).exists())
        && manifest
            .index_runs
            .iter()
            .all(|(_, name)| paths.indexes().join(name).exists())
        && manifest
            .checkpoints
            .iter()
            .all(|(_, name)| paths.checkpoints().join(name).exists())
}

/// Scope 3.8 step 2: read `CURRENT`; if it is missing or corrupt, or its
/// referenced files do not validate, fall back to the newest valid manifest
/// generation whose referenced files all validate.
///
/// Returns the manifest and whether the fallback path was used, so a test can
/// assert which branch ran rather than only that a manifest was loaded.
pub fn load_manifest_with_fallback(
    paths: &ShardPaths,
    root_uuid: &[u8; 16],
) -> Result<Option<(Manifest, bool)>, StoreError> {
    if let Some(pointer) = read_current(paths, root_uuid)? {
        if let Ok(manifest) = read_manifest(paths, pointer.generation, root_uuid) {
            if manifest_referents_present(paths, &manifest) {
                return Ok(Some((manifest, false)));
            }
        }
    }
    // Either the pointer did not validate, or it validated and its referent
    // did not. Both fall back, but they are distinct branches of step 2 and
    // the scope forbids collapsing them — which is why the pointer read above
    // is a separate step from the manifest read.
    let mut generations = list_manifest_generations(paths)?;
    generations.sort_unstable_by(|a, b| b.cmp(a));
    for generation in generations {
        if let Ok(manifest) = read_manifest(paths, generation, root_uuid) {
            if manifest_referents_present(paths, &manifest) {
                return Ok(Some((manifest, true)));
            }
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Sealed segment reader
// ---------------------------------------------------------------------------

/// A sealed segment, read by offset table plus bounded `pread`.
pub struct SegmentReader {
    file: File,
    path: PathBuf,
    footer: SegmentFooter,
}

impl SegmentReader {
    /// Open and validate a sealed segment.
    ///
    /// Footer presence is what distinguishes a sealed segment from an active
    /// journal, and it is located from end of file through a fixed
    /// self-describing locator rather than by scanning.
    pub fn open(path: &Path, root_uuid: &[u8; 16]) -> Result<Self, StoreError> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        if len < SEGMENT_FOOTER_LOCATOR_LEN as u64 {
            return Err(FrameError::Length.into());
        }
        let mut locator = [0u8; SEGMENT_FOOTER_LOCATOR_LEN];
        sys::pread_exact(&file, len - SEGMENT_FOOTER_LOCATOR_LEN as u64, &mut locator)?;
        let footer_len = SegmentFooter::decode_locator(&locator)?;
        if footer_len > len {
            return Err(FrameError::Length.into());
        }
        let mut bytes = vec![0u8; footer_len as usize];
        sys::pread_exact(&file, len - footer_len, &mut bytes)?;
        let footer = SegmentFooter::decode(&bytes)?;
        if &footer.root_uuid != root_uuid {
            return Err(FrameError::RootUuid.into());
        }
        // Every recorded frame must lie inside the frame region, which ends
        // where the footer begins.
        let frame_region_end = len - footer_len;
        for (_, offset, frame_len) in &footer.offsets {
            if offset.saturating_add(*frame_len) > frame_region_end {
                return Err(FrameError::Length.into());
            }
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            footer,
        })
    }

    pub fn footer(&self) -> &SegmentFooter {
        &self.footer
    }

    /// The journal header the sealed file still carries at offset 0.
    ///
    /// Sealing links the journal file itself into `segments/` and appends a
    /// footer; it never re-encodes and never rewrites the header. The header
    /// is therefore still the authority on which **shard** and which store
    /// root the frames belong to, and it is the only place that binding
    /// survives — the footer carries `root_uuid` and `journal_id` but no
    /// `shard_index`. Recovery needs it to reject a segment that was copied
    /// or moved in from another shard of the same root, which no footer check
    /// can catch.
    pub fn journal_header(&self) -> Result<JournalHeader, StoreError> {
        let mut bytes = [0u8; JOURNAL_HEADER_LEN];
        sys::pread_exact(&self.file, 0, &mut bytes)?;
        Ok(JournalHeader::decode(&bytes)?)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn contains(&self, shard_sequence: u64) -> bool {
        self.locate(shard_sequence).is_some()
    }

    fn locate(&self, shard_sequence: u64) -> Option<(u64, u64)> {
        self.footer
            .offsets
            .binary_search_by_key(&shard_sequence, |(sequence, _, _)| *sequence)
            .ok()
            .map(|at| {
                let (_, offset, len) = self.footer.offsets[at];
                (offset, len)
            })
    }

    /// Read one frame, revalidating completeness against this segment's
    /// `journal_id`. A frame is byte-identical to what the journal held, so
    /// the same completeness definition applies unchanged.
    pub fn read_frame(&self, shard_sequence: u64) -> Result<Frame, StoreError> {
        let (offset, len) = self.locate(shard_sequence).ok_or_else(|| {
            StoreError::Corruption(format!(
                "segment {} does not contain shard_sequence {shard_sequence}",
                self.path.display()
            ))
        })?;
        let mut bytes = vec![0u8; len as usize];
        sys::pread_exact(&self.file, offset, &mut bytes)?;
        Ok(Frame::decode(&bytes, &self.footer.journal_id)?)
    }
}

/// Bounded open-FD cache over sealed segments.
///
/// The ceiling comes from `StoreOptions::open_segment_fd_cache`. Plan §4's
/// resource invariants require the descriptor count be bounded, so eviction is
/// mandatory rather than an optimization.
pub struct SegmentCache {
    limit: usize,
    root_uuid: [u8; 16],
    open: HashMap<PathBuf, (u64, Arc<SegmentReader>)>,
    clock: u64,
}

impl SegmentCache {
    pub fn new(limit: u32, root_uuid: [u8; 16]) -> Self {
        Self {
            limit: (limit as usize).max(1),
            root_uuid,
            open: HashMap::new(),
            clock: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// Least-recently-used eviction at the configured ceiling.
    pub fn get(&mut self, path: &Path) -> Result<Arc<SegmentReader>, StoreError> {
        self.clock += 1;
        if let Some((used, reader)) = self.open.get_mut(path) {
            *used = self.clock;
            return Ok(Arc::clone(reader));
        }
        let reader = Arc::new(SegmentReader::open(path, &self.root_uuid)?);
        while self.open.len() >= self.limit {
            let victim = self
                .open
                .iter()
                .min_by_key(|(_, (used, _))| *used)
                .map(|(path, _)| path.clone());
            match victim {
                Some(victim) => {
                    self.open.remove(&victim);
                }
                None => break,
            }
        }
        self.open
            .insert(path.to_path_buf(), (self.clock, Arc::clone(&reader)));
        Ok(reader)
    }
}

// ---------------------------------------------------------------------------
// Root-lock ownership tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod root_lock_tests {
    use super::*;

    /// The exclusion defect a follow-through open at `LOCK` produced.
    ///
    /// `flock` locks the inode the descriptor reached. So with a symlink at
    /// `LOCK`, the second caller's lock lands on a foreign inode and the root's
    /// own lock file is left unlocked — and *both* callers hold what each
    /// believes is exclusive ownership of one root. That is the scope 3.1
    /// property every single-writer argument above this layer depends on.
    ///
    /// # What this proves, and what it does not
    ///
    /// It proves that a `LOCK` whose name resolves to something other than a
    /// regular file cannot be locked, which closes case 1 of the two in scope
    /// 3.1. It is **not** proof of exclusion against *replacement*: planting a
    /// fresh regular file here instead of a symlink still produces a second
    /// holder, because the second caller opens and locks a new, unlocked inode
    /// and no check at this layer can distinguish that from the first open.
    /// [`replacing_the_lock_file_still_admits_a_second_holder`] pins that limit
    /// deliberately. The lock method here is what is under test; the planting is
    /// only how a wrong-typed name is arranged.
    ///
    /// The first lock is taken before the link is planted, and is still held
    /// when the second is attempted, so the arrangement is a state and not a
    /// race. Against the previous open this test fails by taking the second
    /// lock successfully.
    #[test]
    fn a_symlink_at_lock_cannot_produce_a_second_owner_of_one_root() {
        let dir = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(dir.path());
        let held = lock_root(&layout).expect("the first and only owner");

        // The name is redirected at a file that exists and is unlocked, which is
        // what makes the second `flock` succeed rather than fail for an
        // unrelated reason.
        let outside = tempfile::tempdir().expect("a directory outside the root");
        let foreign = outside.path().join("elsewhere");
        std::fs::write(&foreign, b"not the store's lock\n").expect("the foreign file");
        std::fs::remove_file(layout.lock_path()).expect("unlink the real LOCK");
        std::os::unix::fs::symlink(&foreign, layout.lock_path()).expect("plant the link");

        match lock_root(&layout) {
            Err(StoreError::UnrecognizedLayout(reason)) => {
                assert!(reason.contains("LOCK"), "{reason}");
            }
            Ok(_) => panic!(
                "a second caller took the root lock while the first still held it, because \
                 the symlink at LOCK sent its flock to a foreign inode. A name that does not \
                 resolve to a regular file must be refused before flock."
            ),
            Err(other) => panic!("expected UnrecognizedLayout, got {other:?}"),
        }
        drop(held);
    }

    /// The limit of what a lock on a file inside the root can give, pinned so it
    /// cannot be mistaken for a property.
    ///
    /// Replacing `LOCK` with a fresh **regular** file while a holder holds it
    /// produces a second holder. The no-follow open cannot help: both opens are
    /// of a regular file at exactly the right name, and the only difference is
    /// which inode the name resolved to, which the second caller has no way to
    /// know was ever different. This is true of any regular file at any name.
    ///
    /// Scope 3.1 therefore states the assumption explicitly — no noncooperating
    /// mutation of the root directory's entries while the root is held — and this
    /// test is the machine-readable form of it. It asserts the *current* behavior
    /// on purpose: if a stable locking object is ever adopted (§3.1 names locking
    /// the root directory as the candidate), this test is expected to fail, and
    /// that failure is the signal that the assumption changed.
    #[test]
    fn replacing_the_lock_file_still_admits_a_second_holder() {
        let dir = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(dir.path());
        let held = lock_root(&layout).expect("the first holder");

        std::fs::remove_file(layout.lock_path()).expect("unlink the locked name");
        let second = lock_root(&layout);

        match second {
            Ok(_) => {}
            Err(other) => panic!(
                "a stable locking object appears to have been adopted, or lock_root changed: a \
                 replaced LOCK was refused with {other:?}. If that is intended, scope 3.1's \
                 assumption about noncooperating mutation of the root directory is now \
                 stronger than documented and both should be updated together."
            ),
        }
        drop(held);
    }

    /// The same open, in its destructive form: a *dangling* link at `LOCK` and
    /// `create(true)` brings a file into being outside the root.
    #[test]
    fn a_symlink_at_lock_creates_no_file_outside_the_root() {
        let dir = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(dir.path());
        let outside = tempfile::tempdir().expect("a directory outside the root");
        let absent = outside.path().join("not-there");
        std::os::unix::fs::symlink(&absent, layout.lock_path()).expect("plant the link");

        // The outside file is checked before the refusal is classified, so a
        // regression reports the damage rather than the error type.
        let outcome = lock_root(&layout);
        assert!(
            !absent.exists(),
            "taking the root lock created a file outside the root through a dangling symlink"
        );
        match outcome {
            Err(StoreError::UnrecognizedLayout(_)) => {}
            other => panic!("expected UnrecognizedLayout, got {other:?}"),
        }
    }

    /// Every other non-regular occupant of the name, including the two that
    /// reach different arms of the funnel: a directory refuses `O_RDWR` before
    /// any type check runs, a fifo opens and is refused by the `fstat`.
    ///
    /// The fifo is the `O_NONBLOCK` case. A read-write open of a fifo does not
    /// block on Linux, so what this asserts is the refusal, not the absence of a
    /// hang; the flag carries the intent for the device nodes that would block.
    #[test]
    fn a_non_regular_file_at_lock_is_refused_rather_than_locked() {
        // Both arms always run and both are reported: with one panicking early,
        // the first failure would hide whatever the second did.
        let mut wrong = Vec::new();
        for (label, occupy) in [
            (
                "directory",
                (|path: &Path| std::fs::create_dir(path).expect("mkdir")) as fn(&Path),
            ),
            // Refused by `open(2)` itself with `ENXIO`, so it never reaches the
            // `fstat` — which is why the primitive maps that errno rather than
            // letting it surface as an `Io` the caller would have to know about.
            ("unix socket", |path: &Path| {
                std::os::unix::net::UnixListener::bind(path).expect("bind");
            }),
            ("fifo", |path: &Path| {
                let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
                    .expect("a path with no interior NUL");
                // SAFETY: `name` is a valid NUL-terminated path for the lifetime
                // of the call.
                let made = unsafe { libc::mkfifo(name.as_ptr(), 0o644) };
                assert_eq!(made, 0, "mkfifo: {}", std::io::Error::last_os_error());
            }),
        ] {
            let dir = tempfile::tempdir().expect("temp root");
            let layout = RootLayout::new(dir.path());
            occupy(&layout.lock_path());
            match lock_root(&layout) {
                Err(StoreError::UnrecognizedLayout(_)) => {}
                other => wrong.push(format!("{label} at LOCK: {other:?}")),
            }
        }
        assert!(
            wrong.is_empty(),
            "a non-regular LOCK must be UnrecognizedLayout, not locked and not an untyped \
             errno: {wrong:?}"
        );
    }

    /// A regression guard, not a defect proof: the previous open already passed
    /// `truncate(false)`. It is here because the amended open is the one place
    /// an `O_TRUNC` would be easy to add and impossible to notice — `LOCK` holds
    /// no bytes the store reads, so nothing else would ever complain.
    #[test]
    fn taking_the_lock_does_not_rewrite_an_existing_lock_file() {
        let dir = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(dir.path());
        std::fs::write(layout.lock_path(), b"operator note\n").expect("pre-existing LOCK");

        let held = lock_root(&layout).expect("adopt the existing lock file");
        assert_eq!(
            std::fs::read(layout.lock_path()).expect("read LOCK"),
            b"operator note\n",
            "taking the root lock rewrote bytes it did not write"
        );
        drop(held);
    }

    /// A second holder is refused, never queued (scope 3.1).
    #[test]
    fn a_second_lock_on_a_held_root_is_refused() {
        let dir = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(dir.path());

        let held = lock_root(&layout).expect("first lock");
        match lock_root(&layout) {
            Ok(_) => panic!("a second holder took a lock that is already held"),
            Err(StoreError::AlreadyLocked) => {}
            Err(other) => panic!("expected AlreadyLocked, got {other:?}"),
        }
        drop(held);
    }

    /// The regression this guard exists for.
    ///
    /// A child is forked while the root lock is held, so it inherits a
    /// descriptor onto the *same open file description* — which is where
    /// `flock` lives. The child is then held open, by a pipe handshake rather
    /// than by a sleep, across the parent's release and reopen. So the window
    /// this reproduces is a state, not a race: for the whole duration of the
    /// parent's reopen the child is provably alive and provably holding the
    /// inherited descriptor, because it has written its ready byte and has not
    /// yet been told to exit.
    ///
    /// With [`RootLock`]'s explicit `LOCK_UN`, the reopen succeeds on its
    /// **first attempt**. Remove that unlock and let the release fall out of
    /// closing the descriptor — what `lock_root` did before this amendment —
    /// and this test fails with `AlreadyLocked` every time, because the child's
    /// descriptor keeps the description's lock alive. `FD_CLOEXEC` does not
    /// help: it closes at `exec`, and this child never execs.
    ///
    /// One attempt, not a bounded retry: a spurious `AlreadyLocked` is a
    /// refusal scope §3.1 defines as final, so the only correct assertion is
    /// that the very first reopen succeeds.
    #[test]
    fn a_forked_child_holding_the_inherited_lock_descriptor_cannot_block_a_reopen() {
        let dir = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(dir.path());
        let failures_before = RootLock::release_failures();

        let lock = lock_root(&layout).expect("first lock");

        let mut ready = [-1i32; 2];
        let mut go = [-1i32; 2];
        // SAFETY: both arrays are two `c_int`s, which is what `pipe` writes.
        assert_eq!(unsafe { libc::pipe(ready.as_mut_ptr()) }, 0, "ready pipe");
        // SAFETY: as above.
        assert_eq!(unsafe { libc::pipe(go.as_mut_ptr()) }, 0, "go pipe");

        // SAFETY: the child branch below calls only async-signal-safe
        // functions and terminates with `_exit`, so forking a multi-threaded
        // test process is sound here.
        let child = unsafe { libc::fork() };
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            let mut byte = [1u8; 1];
            // SAFETY: async-signal-safe calls on inherited descriptors only.
            unsafe {
                libc::write(ready[1], byte.as_ptr().cast(), 1);
                // Blocks until the parent has finished its reopen. The
                // inherited LOCK descriptor stays open for exactly that long.
                libc::read(go[0], byte.as_mut_ptr().cast(), 1);
                libc::_exit(0);
            }
        }

        let mut byte = [0u8; 1];
        // SAFETY: reading one byte into a one-byte buffer.
        let read = unsafe { libc::read(ready[0], byte.as_mut_ptr().cast(), 1) };
        assert_eq!(
            read, 1,
            "the child must be alive and holding the inherited LOCK descriptor \
             before the parent releases; without that this test proves nothing"
        );

        // The parent's release. Explicit unlock first, then the close.
        drop(lock);
        let reopened = lock_root(&layout);

        // Release the child only after the reopen has been attempted, so the
        // inherited descriptor was open for the whole of it.
        // SAFETY: writing one byte from a one-byte buffer.
        unsafe { libc::write(go[1], byte.as_ptr().cast(), 1) };
        let mut status = 0i32;
        // SAFETY: `status` is a valid `c_int` out-parameter.
        unsafe { libc::waitpid(child, &mut status, 0) };
        for fd in [ready[0], ready[1], go[0], go[1]] {
            // SAFETY: each descriptor was opened by `pipe` above and is closed once.
            unsafe { libc::close(fd) };
        }

        match reopened {
            Ok(_) => {}
            Err(StoreError::AlreadyLocked) => panic!(
                "reopen was refused AlreadyLocked on its first attempt while a forked child \
                 still held the inherited LOCK descriptor. flock lives on the open file \
                 description, so closing the parent's descriptor is not a release; RootLock \
                 must issue LOCK_UN before the close."
            ),
            Err(other) => panic!("reopen failed for an unrelated reason: {other:?}"),
        }
        assert_eq!(
            RootLock::release_failures(),
            failures_before,
            "a root lock failed to release in Drop"
        );
    }
}

// ---------------------------------------------------------------------------
// Path-redirection tests (contract review 2026-07-29-B)
// ---------------------------------------------------------------------------

/// The three remaining redirection hazards, each exercised at the `segment`
/// entry point that carries it.
///
/// Deliberately **not** through `StoreEngine::open`. Its classifier refuses a
/// redirected root before these are reached, so a test that went in that way
/// would pass whether or not the protection here exists — and `RecoverySession`,
/// `drive.rs` and `store-bench` all arrive here without it. Coverage of the
/// caller is not coverage of the callee.
#[cfg(test)]
mod path_redirection_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn counters() -> DurabilityCounters {
        DurabilityCounters::default()
    }

    /// Every name in a tree with its bytes, for "unchanged" assertions.
    fn tree_image(root: &Path) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        let mut out = Vec::new();
        let mut stack = vec![root.to_path_buf()];
        while let Some(current) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&current) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .expect("inside the tree")
                    .to_path_buf();
                let kind = entry.file_type().expect("file type");
                if kind.is_dir() {
                    stack.push(path);
                    out.push((relative, None));
                } else {
                    out.push((relative, std::fs::read(&path).ok()));
                }
            }
        }
        out.sort();
        out
    }

    fn mkfifo_at(path: &Path) {
        let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .expect("a path with no interior NUL");
        // SAFETY: `name` is a valid NUL-terminated path for the call's duration.
        assert_eq!(
            unsafe { libc::mkfifo(name.as_ptr(), 0o644) },
            0,
            "mkfifo: {}",
            std::io::Error::last_os_error()
        );
    }

    /// Run `body` on another thread and fail if it does not finish.
    ///
    /// A blocking `open(2)` is not a slow refusal, it is an unbounded startup
    /// hang: one `mkfifo` in a configured root, reachable by any operator. The
    /// only assertion that distinguishes the two is a deadline.
    fn must_not_block<T: Send + 'static>(
        what: &str,
        body: impl FnOnce() -> T + Send + 'static,
    ) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(body());
        });
        match receiver.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(value) => value,
            Err(_) => panic!(
                "{what} did not return within ten seconds: the open blocked. A fifo at a store \
                 metadata name must be refused, not waited on."
            ),
        }
    }

    // -----------------------------------------------------------------------
    // write_fenced
    // -----------------------------------------------------------------------

    /// A live link at a temporary name must not reach its target at all.
    #[test]
    fn a_linked_temporary_name_cannot_alter_the_file_it_points_at() {
        let outside = tempfile::tempdir().expect("tempdir");
        let victim = outside.path().join("ledger");
        std::fs::write(&victim, b"balances\n").expect("the file outside the root");
        let root = tempfile::tempdir().expect("temp root");
        let tmp = root.path().join("FORMAT.tmp");
        symlink(&victim, &tmp).expect("plant the link");

        let outcome = write_fenced(&tmp, b"a store metadata marker", &counters());

        // The damage first, so a regression reports what was destroyed rather
        // than which error type came back.
        assert_eq!(
            std::fs::read(&victim).expect("the target still exists"),
            b"balances\n",
            "a fenced write through a symlink truncated and rewrote a file outside the root"
        );
        assert!(
            std::fs::symlink_metadata(&tmp).is_ok(),
            "the link itself must be left alone for the operator to find"
        );
        match outcome {
            Err(StoreError::UnrecognizedLayout(reason)) => {
                assert!(reason.contains("FORMAT.tmp"), "{reason}")
            }
            other => panic!("expected UnrecognizedLayout, got {other:?}"),
        }
    }

    /// The dangling form, which creates rather than destroys.
    #[test]
    fn a_dangling_link_at_a_temporary_name_creates_nothing() {
        let outside = tempfile::tempdir().expect("tempdir");
        let absent = outside.path().join("not-there");
        let root = tempfile::tempdir().expect("temp root");
        let tmp = root.path().join("FORMAT.tmp");
        symlink(&absent, &tmp).expect("plant the link");

        let outcome = write_fenced(&tmp, b"a store metadata marker", &counters());

        assert!(
            !absent.exists(),
            "a fenced write through a dangling symlink created a file outside the root"
        );
        match outcome {
            Err(StoreError::UnrecognizedLayout(_)) => {}
            other => panic!("expected UnrecognizedLayout, got {other:?}"),
        }
    }

    /// Every non-regular occupant, and the one occupant that is legitimate.
    #[test]
    fn a_non_regular_temporary_name_is_refused_and_a_regular_one_is_retried() {
        let mut wrong = Vec::new();
        for (label, occupy) in [
            (
                "directory",
                (|path: &Path| std::fs::create_dir(path).expect("mkdir")) as fn(&Path),
            ),
            ("unix socket", |path: &Path| {
                std::os::unix::net::UnixListener::bind(path).expect("bind");
            }),
            ("fifo", mkfifo_at),
        ] {
            let root = tempfile::tempdir().expect("temp root");
            let tmp = root.path().join("FORMAT.tmp");
            occupy(&tmp);
            let attempt = tmp.clone();
            let outcome = must_not_block(label, move || {
                write_fenced(
                    &attempt,
                    b"a store metadata marker",
                    &DurabilityCounters::default(),
                )
            });
            match outcome {
                Err(StoreError::UnrecognizedLayout(_)) => {}
                other => wrong.push(format!("{label}: {other:?}")),
            }
        }
        assert!(
            wrong.is_empty(),
            "a non-regular temporary name must be UnrecognizedLayout, not written through and \
             not an untyped errno: {wrong:?}"
        );

        // Residue from an interrupted attempt at this same write. Retrying is the
        // point of a `.tmp` name, so it is adopted — and emptied, which the
        // stale tail proves: it is longer than the new contents, so a missing
        // truncation leaves it visible.
        let root = tempfile::tempdir().expect("temp root");
        let tmp = root.path().join("FORMAT.tmp");
        std::fs::write(
            &tmp,
            b"residue from an interrupted attempt, longer than what follows",
        )
        .expect("stale residue");
        write_fenced(&tmp, b"the retry", &counters()).expect("an existing regular temp is retried");
        assert_eq!(
            std::fs::read(&tmp).expect("read the temp"),
            b"the retry",
            "a retried fenced write must leave exactly the new bytes"
        );
    }

    // -----------------------------------------------------------------------
    // read_format
    // -----------------------------------------------------------------------

    /// A valid marker at the far end of a link is still not this root's marker.
    ///
    /// The target holds a real, decodable `FORMAT` — built by `initialize_root`,
    /// not hand-rolled — so the refusal cannot be mistaken for the bytes being
    /// rejected. Read as a regular file the same bytes are accepted, which the
    /// second half asserts: without it this test would pass against an
    /// implementation that had simply broken `read_format`.
    #[test]
    fn a_linked_format_marker_is_never_read_even_when_it_is_valid() {
        let donor = tempfile::tempdir().expect("temp root");
        let donor_layout = RootLayout::new(donor.path());
        initialize_root(&donor_layout, 1, [0x5A; 16], 1, &counters()).expect("a real root");
        let valid = std::fs::read(donor_layout.format_path()).expect("real FORMAT bytes");

        let outside = tempfile::tempdir().expect("tempdir");
        let target = outside.path().join("someone-elses-FORMAT");
        std::fs::write(&target, &valid).expect("a valid marker outside the root");

        let root = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(root.path());
        symlink(&target, layout.format_path()).expect("plant the link");
        match read_format(&layout) {
            Err(StoreError::UnrecognizedLayout(reason)) => {
                assert!(reason.contains("FORMAT"), "{reason}")
            }
            Ok(marker) => panic!(
                "a FORMAT symlink was followed: this root's shard_count and root_uuid would come \
                 from a marker outside it ({marker:?}), and every file in the tree would then be \
                 validated against a marker the store never wrote"
            ),
            Err(other) => panic!("expected UnrecognizedLayout, got {other:?}"),
        }

        // The same bytes, as a regular file, are read.
        std::fs::remove_file(layout.format_path()).expect("remove the link");
        std::fs::write(layout.format_path(), &valid).expect("the same bytes, directly");
        read_format(&layout).expect("a regular FORMAT holding valid bytes must still be read");
    }

    /// The other two answers, which are not refusals and must not become ones.
    #[test]
    fn an_absent_format_is_not_found_and_a_corrupt_one_still_fails_to_decode() {
        let root = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(root.path());
        match read_format(&layout) {
            Err(StoreError::Io(error)) => assert_eq!(
                error.kind(),
                std::io::ErrorKind::NotFound,
                "an absent FORMAT is startup state 1 or 3 and must keep reporting NotFound"
            ),
            other => panic!("expected Io(NotFound), got {other:?}"),
        }

        std::fs::write(layout.format_path(), [0xAB; FORMAT_MARKER_LEN]).expect("garbage");
        match read_format(&layout) {
            Err(StoreError::UnrecognizedLayout(reason)) => panic!(
                "a corrupt *regular* marker is a different finding from a redirected one and \
                 must keep its decode error: {reason}"
            ),
            Err(_) => {}
            Ok(marker) => panic!("garbage decoded as a marker: {marker:?}"),
        }
    }

    /// A fifo at `FORMAT` is the read-side hang. `open(2)` read-only on one
    /// blocks until a writer arrives, so this is the case `O_NONBLOCK` in the
    /// funnel exists for.
    #[test]
    fn a_fifo_at_format_is_refused_rather_than_waited_on() {
        let root = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(root.path());
        mkfifo_at(&layout.format_path());
        let probed = RootLayout::new(root.path().to_path_buf());
        match must_not_block("read_format on a fifo", move || read_format(&probed)) {
            Err(StoreError::UnrecognizedLayout(_)) => {}
            other => panic!("expected UnrecognizedLayout, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // initialize_root
    // -----------------------------------------------------------------------

    /// A link where the store expects to invent a directory.
    ///
    /// Both positions: `shards/` itself, and one subdirectory of one shard. In
    /// each case `create_dir_all` would have followed the link and built the
    /// store's tree at the far end of it.
    #[test]
    fn a_linked_directory_name_creates_nothing_outside_the_root() {
        for position in ["shards", "shards/00/segments"] {
            let outside = tempfile::tempdir().expect("tempdir");
            let elsewhere = outside.path().join("elsewhere");
            std::fs::create_dir(&elsewhere).expect("a directory outside the root");

            let root = tempfile::tempdir().expect("temp root");
            let layout = RootLayout::new(root.path());
            let planted = root.path().join(position);
            if let Some(parent) = planted.parent() {
                std::fs::create_dir_all(parent).expect("the parent the link sits in");
            }
            symlink(&elsewhere, &planted).expect("plant the link");

            let outcome = initialize_root(&layout, 2, [0x11; 16], 1, &counters());

            // The damage first: a regression here is the tree being built
            // somewhere it must never be, not the error type.
            assert_eq!(
                tree_image(&elsewhere),
                Vec::new(),
                "initialize_root built part of the store tree outside the root, through {position}"
            );
            match outcome {
                Err(StoreError::UnrecognizedLayout(reason)) => {
                    assert!(
                        reason.contains(position.rsplit('/').next().expect("name")),
                        "{reason}"
                    )
                }
                other => {
                    panic!("expected UnrecognizedLayout for a link at {position}, got {other:?}")
                }
            }
        }
    }

    /// The preflight, which is what stops a refusal from half-extending a tree.
    ///
    /// The link sits at `shards/00/segments`, and the two names created *before*
    /// it in creation order are `shards/00` (which exists already) and
    /// `shards/00/active` (which does not). A single pass that created as it went
    /// would leave `active` behind; the assertion is that it does not exist, and
    /// that the second shard was never begun.
    #[test]
    fn a_refusal_does_not_extend_the_tree_it_refused() {
        let outside = tempfile::tempdir().expect("tempdir");
        let elsewhere = outside.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("a directory outside the root");

        let root = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(root.path());
        // A partially built tree, as an interrupted initialization leaves.
        std::fs::create_dir_all(layout.quarantine_dir()).expect("quarantine");
        std::fs::write(layout.quarantine_dir().join("keep"), b"forensics\n").expect("residue");
        std::fs::create_dir_all(layout.shard(0).dir).expect("the first shard directory");
        symlink(&elsewhere, layout.shard(0).segments()).expect("plant the link");

        let before = tree_image(root.path());
        match initialize_root(&layout, 2, [0x22; 16], 1, &counters()) {
            Err(StoreError::UnrecognizedLayout(_)) => {}
            other => panic!("expected UnrecognizedLayout, got {other:?}"),
        }

        assert!(
            !layout.shard(0).active().exists(),
            "the refusal created shards/00/active on its way to the link: every existing entry \
             must be classified before any missing one is created"
        );
        assert!(
            !layout.shard(1).dir.exists(),
            "the refusal began a second shard"
        );
        assert_eq!(
            tree_image(root.path()),
            before,
            "a refused initialization must leave the tree it found byte-identical"
        );
    }

    /// A non-directory occupant, and the legitimate case beside it: an existing
    /// partial tree is adopted rather than refused, because that is what resuming
    /// an interrupted initialization requires.
    #[test]
    fn a_non_directory_occupant_is_refused_and_a_real_partial_tree_is_adopted() {
        let root = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(root.path());
        std::fs::create_dir_all(&layout.root).expect("root");
        std::fs::write(layout.shards_dir(), b"not a directory\n").expect("occupy shards");
        match initialize_root(&layout, 1, [0x33; 16], 1, &counters()) {
            Err(StoreError::UnrecognizedLayout(_)) => {}
            other => panic!("expected UnrecognizedLayout for a file at shards/, got {other:?}"),
        }

        let resumable = tempfile::tempdir().expect("temp root");
        let layout = RootLayout::new(resumable.path());
        std::fs::create_dir_all(layout.shard(0).active()).expect("a partial tree");
        std::fs::create_dir_all(layout.staging_dir()).expect("staging");
        let marker = initialize_root(&layout, 1, [0x44; 16], 1, &counters())
            .expect("an existing partial tree is adopted, not refused");
        assert_eq!(marker.shard_count, 1);
        assert!(layout.shard(0).manifests().is_dir());
        read_format(&layout).expect("the marker is installed over an adopted tree");
    }
}
