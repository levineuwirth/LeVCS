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
use crate::journal::Journal;
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
    std::fs::create_dir_all(&layout.root)?;
    std::fs::create_dir_all(layout.quarantine_dir())?;
    std::fs::create_dir_all(layout.staging_dir())?;
    std::fs::create_dir_all(layout.shards_dir())?;

    for shard in 0..shard_count {
        let paths = layout.shard(shard);
        for dir in [
            paths.dir.clone(),
            paths.active(),
            paths.segments(),
            paths.indexes(),
            paths.checkpoints(),
            paths.manifests(),
        ] {
            std::fs::create_dir_all(&dir)?;
            sys::fsync_dir(&dir, counters)?;
        }
        sys::fsync_dir(&paths.dir, counters)?;
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

    sys::fsync_dir(&layout.shards_dir(), counters)?;
    sys::fsync_dir(&layout.quarantine_dir(), counters)?;
    sys::fsync_dir(&layout.root, counters)?;
    if let Some(parent) = layout.root.parent() {
        sys::fsync_dir(parent, counters)?;
    }
    Ok(marker)
}

/// Read and validate `FORMAT`.
pub fn read_format(layout: &RootLayout) -> Result<crate::format::FormatMarker, StoreError> {
    let file = File::open(layout.format_path())?;
    let mut bytes = [0u8; FORMAT_MARKER_LEN];
    sys::pread_exact(&file, 0, &mut bytes)?;
    Ok(crate::format::FormatMarker::decode(&bytes)?)
}

/// Take the exclusive root lock. Failure is `AlreadyLocked`, never a wait
/// (scope 3.1).
pub fn lock_root(layout: &RootLayout) -> Result<File, StoreError> {
    let file = File::options()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(layout.lock_path())?;
    if sys::try_lock_exclusive(&file)? {
        Ok(file)
    } else {
        Err(StoreError::AlreadyLocked)
    }
}

/// Write a file and fence it. The name is not yet durable; the caller renames
/// and syncs the directory.
fn write_fenced(
    path: &Path,
    bytes: &[u8],
    counters: &DurabilityCounters,
) -> Result<(), StoreError> {
    let mut file = File::options()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)?;
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

    // 1, 2
    write_fenced(&tmp, &manifest.encode()?, counters)?;
    // 3 — never overwrite an existing generation.
    if let Err(e) = sys::rename_noreplace(&tmp, &final_path) {
        let _ = sys::unlink(&tmp);
        return Err(e.into());
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
