//! The single funnel for every durability-relevant syscall.
//!
//! Lead-owned (scope 2.3). Nothing else in this crate may call
//! `File::sync_all`, `File::sync_data`, `std::fs::rename`, `remove_file`, or
//! open a directory descriptor, and nothing else may create, link or remove a
//! name. Three reasons:
//!
//! 1. `DurabilityCounters` turns "exactly one fence per group" and "no
//!    per-object fsync" into assertions against observed counts rather than
//!    claims about the code (Phase 1 exit criteria).
//! 2. Fault injection (short write, `ENOSPC`, `EIO` on fence, `EIO` on read)
//!    has exactly one place to live, so the crash matrix runs unprivileged in
//!    CI without `dm-flakey`.
//! 3. The power-loss model ([`power_loss`], `failpoints` only) sees every
//!    write, every change to a directory entry and every fence here, and only
//!    here.
//!
//! The `check-phase1.sh` gate greps the crate for direct calls that bypass
//! this module.

use std::fs::File;
use std::io::{self, IoSlice, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;

use crate::types::DurabilityCounters;

// ---------------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------------

/// A fault the harness can arm on the next matching call.
///
/// Deliberately not a general-purpose filesystem simulator: these are exactly
/// the physical failures plan §10's matrix requires ("short writes, fsync
/// errors, ENOSPC, corrupt index, corrupt segment, torn tail").
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Write only `prefix_bytes` of the requested vector and return `Ok`. A
    /// short write is not an error; it leaves a durable prefix, which is why
    /// `write_vectored_all` loops and why frame completeness — not a return
    /// value — decides an outcome (scope 3.7).
    ShortWrite { prefix_bytes: usize },
    /// Fail the write with `ENOSPC`.
    NoSpace,
    /// Fail the fence with `EIO`. On Linux this may be reported exactly once,
    /// after which the kernel has already dropped the dirty pages, so a retry
    /// can return success while the data is permanently gone. The shard must
    /// poison and must never retry (scope 3.7).
    FenceEio,
    /// Fail a positioned read with `EIO`, modelling a device that lost a write
    /// it acknowledged. Live on the frozen profile because
    /// `power_loss_protection = false` (scope 3.8).
    ///
    /// Unscoped: consumed by whichever positioned read runs first. That is
    /// almost never the one a test means, because reopening a shard reads
    /// `FORMAT`, the manifest, and the journal header before it reaches the
    /// tail — and an `EIO` on those is legitimately fatal. Use
    /// [`Fault::ReadEioAtOrAfter`] to target the tail.
    ReadEio,
    /// Fail a positioned read with `EIO`, but only at or beyond `offset`.
    ///
    /// This exists because the unscoped variant cannot express scope 3.8 step
    /// 5's central claim — that an `EIO` *in the tail region* ends the tail
    /// rather than failing the open. A3 found this by writing that test and
    /// having it fail for the wrong reason: the first `pread` of a reopen ate
    /// the fault. Scoping by offset is the smallest thing that makes the
    /// intended state reachable, and it keeps the distinction the rule turns
    /// on — early read failures stay fatal, tail read failures do not.
    ReadEioAtOrAfter { offset: u64 },
    /// Fail a directory fsync.
    DirSyncEio,
    /// Leave the write cursor somewhere other than where the caller expects,
    /// without failing the write.
    ///
    /// Plan §5.2 names "unexpected file position" as a poisoning condition and
    /// scope 4-A3 requires it be injectable, but no other fault produces it:
    /// `ShortWrite` returns early with a durable prefix and a *consistent*
    /// cursor, which is the correct modelling of a short write and therefore
    /// cannot also model this. Seeks the descriptor after a successful write so
    /// the post-append position check fails.
    CursorSkew { delta: i64 },
}

#[cfg(feature = "failpoints")]
mod fault_state {
    use super::Fault;
    use std::sync::Mutex;

    static ARMED: Mutex<Option<Fault>> = Mutex::new(None);
    static SERIAL: Mutex<()> = Mutex::new(());

    /// Proof that the holder has exclusive use of the fault registry.
    ///
    /// The registry is one process-global slot, so two tests running
    /// concurrently in the same binary contend for it — and the contention is
    /// invisible, because the loser does not fail, it merely has someone
    /// else's fault delivered or its own consumed by an unrelated read. That
    /// produced a 1-in-5 failure rate in `recovery_eio.rs` that read as
    /// flakiness for as long as it went unexplained.
    ///
    /// Requiring this token in [`arm`] is what makes the invariant hold. A
    /// lock a test *may* take is a lock a new test will not take: the file
    /// where this was first diagnosed carried a header saying it was
    /// deliberately the only test in it, and a second test had been added
    /// under that comment anyway. A comment cannot fail a build; a parameter
    /// can.
    ///
    /// Hold it for the **whole test body**, not just across `arm`. The
    /// original defect was a clean `scan_journal` performed *before* arming:
    /// that scan is itself a funnel read, so it consumed the fault another
    /// test had armed. Any funnel traffic outside the lock can do this.
    pub struct FaultSerial(#[allow(dead_code)] std::sync::MutexGuard<'static, ()>);

    /// Take exclusive use of the fault registry, clearing anything left armed.
    ///
    /// Recovers from poisoning rather than propagating it: a test that panics
    /// while holding this has already reported its own failure, and turning
    /// that into a cascade of poison errors in every later test would bury the
    /// real one. Clearing on acquire is the other half — a panicking test
    /// cannot run its own cleanup, so without this its armed fault would be
    /// delivered to whichever test ran next. The power-loss model is cleared
    /// for the same reason.
    pub fn serial() -> FaultSerial {
        let guard = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *ARMED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
        super::power_loss::reset();
        FaultSerial(guard)
    }

    pub fn arm(_serial: &FaultSerial, fault: Fault) {
        *ARMED.lock().expect("fault mutex") = Some(fault);
    }

    pub fn disarm(_serial: &FaultSerial) {
        *ARMED.lock().expect("fault mutex") = None;
    }

    /// Consume the armed fault only if this call site is the one it targets.
    ///
    /// One-shot, but *selective*. An unconditional take was a real bug: the
    /// first `write_vectored_all` of a group consumed a fault armed for the
    /// fence, so `Fault::FenceEio`, `ReadEio`, and `DirSyncEio` could never be
    /// delivered at all — the whole `EIO`-on-fdatasync half of the fault
    /// matrix was unreachable through this seam. Every site now takes only its
    /// own faults, so arming is genuinely positional.
    pub fn take_if(matches: impl Fn(&Fault) -> bool) -> Option<Fault> {
        let mut armed = ARMED.lock().expect("fault mutex");
        match armed.as_ref() {
            Some(fault) if matches(fault) => armed.take(),
            _ => None,
        }
    }
}

// Reached by A3 through `drive::faults` rather than by making `sys` public;
// the module stays private so the funnel invariant holds.
#[cfg(feature = "failpoints")]
pub use fault_state::{arm, disarm, serial, FaultSerial};

#[cfg(feature = "failpoints")]
#[inline]
fn take_fault_if(matches: impl Fn(&Fault) -> bool) -> Option<Fault> {
    fault_state::take_if(matches)
}

#[cfg(not(feature = "failpoints"))]
#[inline(always)]
fn take_fault_if(_matches: impl Fn(&Fault) -> bool) -> Option<Fault> {
    None
}

fn eio(what: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("injected EIO during {what}"))
}

// ---------------------------------------------------------------------------
// Write path
// ---------------------------------------------------------------------------

/// Append a frame group at the file's current position, looping over short
/// writes, and verify the resulting position.
///
/// The caller owns the descriptor exclusively (one shard thread per shard),
/// so the file position is the write cursor. Plan §5.2 names "unexpected file
/// position" as a poisoning condition; that check lives here.
pub(crate) fn write_vectored_all(
    file: &mut File,
    bufs: &[IoSlice<'_>],
    counters: &DurabilityCounters,
) -> io::Result<u64> {
    let total: usize = bufs.iter().map(|b| b.len()).sum();
    let start = file.stream_position()?;
    #[cfg(feature = "failpoints")]
    power_loss::before_write(file, start, total as u64)?;

    // Flatten once. `write_vectored` may consume a partial slice, and
    // re-slicing `IoSlice`s across a partial consume is where short-write
    // handling usually goes wrong; a single owned buffer makes the loop
    // obviously correct at the cost of one copy. A1 may replace this with
    // proper `IoSlice` advancing once the golden vectors pin the bytes.
    let mut flat = Vec::with_capacity(total);
    for buf in bufs {
        flat.extend_from_slice(buf);
    }

    // Only write-path faults. A fault armed for the fence, a read, or a
    // directory sync must survive this call untouched.
    let mut fault = take_fault_if(|f| {
        matches!(
            f,
            Fault::ShortWrite { .. } | Fault::NoSpace | Fault::CursorSkew { .. }
        )
    });
    let mut written = 0usize;
    while written < flat.len() {
        match fault.take() {
            Some(Fault::NoSpace) => {
                return Err(io::Error::new(
                    io::ErrorKind::StorageFull,
                    "injected ENOSPC during journal append",
                ))
            }
            Some(Fault::ShortWrite { prefix_bytes }) => {
                let n = prefix_bytes.min(flat.len() - written);
                let n = file.write(&flat[written..written + n])?;
                written += n;
                counters.write_vectored.fetch_add(1, Relaxed);
                counters.short_writes.fetch_add(1, Relaxed);
                counters.bytes_written.fetch_add(n as u64, Relaxed);
                // The injected short write stands: return with a durable
                // prefix and no error, exactly as the device may behave.
                return Ok(start + written as u64);
            }
            Some(Fault::CursorSkew { delta }) => {
                // The write succeeds; only the resulting position is wrong, so
                // the post-append check below is what must catch it.
                let n = file.write(&flat[written..])?;
                counters.write_vectored.fetch_add(1, Relaxed);
                counters.bytes_written.fetch_add(n as u64, Relaxed);
                written += n;
                let here = file.stream_position()?;
                let moved = here as i64 + delta;
                file.seek(SeekFrom::Start(moved.max(0) as u64))?;
            }
            other => {
                fault = other;
                let n = file.write(&flat[written..])?;
                counters.write_vectored.fetch_add(1, Relaxed);
                counters.bytes_written.fetch_add(n as u64, Relaxed);
                if n == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "journal append made no progress",
                    ));
                }
                if n < flat.len() - written {
                    counters.short_writes.fetch_add(1, Relaxed);
                }
                written += n;
            }
        }
    }

    let end = file.stream_position()?;
    let expected = start + total as u64;
    if end != expected {
        return Err(io::Error::other(format!(
            "unexpected file position after append: expected {expected}, observed {end}"
        )));
    }
    Ok(end)
}

/// The durability fence. Exactly one per group.
///
/// `File::sync_data` is `fdatasync(2)` on Linux. A failure here is terminal
/// for the shard and must never be retried; see `Fault::FenceEio`.
pub(crate) fn fdatasync(file: &File, counters: &DurabilityCounters) -> io::Result<()> {
    if take_fault_if(|f| matches!(f, Fault::FenceEio)).is_some() {
        counters.fdatasync.fetch_add(1, Relaxed);
        return Err(eio("fdatasync"));
    }
    counters.fdatasync.fetch_add(1, Relaxed);
    file.sync_data()?;
    #[cfg(feature = "failpoints")]
    power_loss::after_fence(file)?;
    Ok(())
}

/// Make a directory entry durable. Required after every create, rename, and
/// unlink that recovery depends on.
///
/// Resolves the name, so it is for directories whose path the store already
/// trusts. A caller that has just *established* what a name is holds a
/// descriptor onto that object and should fence it with [`fsync_dir_fd`]
/// instead — re-resolving the name would hand the fence back to whatever the
/// name resolves to now, which is not necessarily what was validated.
pub(crate) fn fsync_dir(path: &Path, counters: &DurabilityCounters) -> io::Result<()> {
    if take_fault_if(|f| matches!(f, Fault::DirSyncEio)).is_some() {
        counters.fsync_dir.fetch_add(1, Relaxed);
        return Err(eio("directory fsync"));
    }
    counters.fsync_dir.fetch_add(1, Relaxed);
    let directory = File::open(path)?;
    directory_fence(&directory)
}

/// [`fsync_dir`] on a directory descriptor the caller already holds.
///
/// Same counter and same injected fault, so the crash matrix reaches this seam
/// exactly as it reaches the by-name one.
pub(crate) fn fsync_dir_fd(directory: &File, counters: &DurabilityCounters) -> io::Result<()> {
    if take_fault_if(|f| matches!(f, Fault::DirSyncEio)).is_some() {
        counters.fsync_dir.fetch_add(1, Relaxed);
        return Err(eio("directory fsync"));
    }
    counters.fsync_dir.fetch_add(1, Relaxed);
    directory_fence(directory)
}

/// The directory fsync both entry points share, seen by the power-loss model.
fn directory_fence(directory: &File) -> io::Result<()> {
    #[cfg(feature = "failpoints")]
    return power_loss::directory_fence(directory, || directory.sync_all());
    #[cfg(not(feature = "failpoints"))]
    directory.sync_all()
}

// ---------------------------------------------------------------------------
// Directory entries
// ---------------------------------------------------------------------------

/// A change to a directory entry, as the power-loss model sees it.
///
/// Every function in this module that brings a name into being, removes one or
/// moves one says which here, and [`entry`] performs it. Without `failpoints`
/// that is the whole story; with the model armed, [`entry`] logs what undoing
/// the change needs before performing it (audit S2, contract review
/// 2026-11-02-D).
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "failpoints"), allow(dead_code))]
pub(crate) enum Entry<'a> {
    /// A regular file at a name, if none is there.
    Create(&'a Path),
    /// A directory at a name, if none is there.
    Mkdir(&'a Path),
    Link {
        existing: &'a Path,
        new: &'a Path,
    },
    Unlink(&'a Path),
    Rmdir(&'a Path),
    Rename {
        from: &'a Path,
        to: &'a Path,
        replace: bool,
    },
}

#[inline]
fn entry<T>(entry: Entry<'_>, perform: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    #[cfg(feature = "failpoints")]
    return power_loss::entry(entry, perform);
    #[cfg(not(feature = "failpoints"))]
    {
        let _ = entry;
        perform()
    }
}

// ---------------------------------------------------------------------------
// Naming
// ---------------------------------------------------------------------------

/// `renameat2(RENAME_NOREPLACE)`. For every name that must never overwrite:
/// new manifests, segments, checkpoints, index runs, and migration/restore
/// siblings. Plan §9 forbids a copy fallback.
///
/// One exception, and it is narrow. A checkpoint whose install was interrupted
/// after this rename and before the manifest that publishes it leaves a
/// finalized file at a name derived from the committed sequence, so the retry
/// can never choose another one and this call would refuse forever. The retry
/// may use [`rename_replace`] over **that** name, and only through
/// `checkpoint::replace_reconciled`, whose own `reconciles_with` proof
/// establishes before the rename that the occupant is a valid
/// checkpoint for the shard agreeing on every durable claim and no stronger
/// than its replacement. Contract review 2026-07-30-F; the rule stands for
/// every other name and for any checkpoint name not proved out that way.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let rename = Entry::Rename {
        from,
        to,
        replace: false,
    };
    entry(rename, || {
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            from,
            rustix::fs::CWD,
            to,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
    })
}

/// Plain atomic replacing rename. Three legitimate call sites, and no others:
///
/// 1. The `CURRENT.tmp` -> `CURRENT` pointer install of scope 3.5, which by
///    definition replaces.
/// 2. `checkpoint::replace_reconciled`, repairing a checkpoint an interrupted
///    install left finalized at a name the retry cannot choose again — and only
///    over an occupant that call has proved reconciles with its replacement.
///    Contract review 2026-07-30-F; see [`rename_noreplace`].
/// 3. `staging::adopt_adoption_marker`, moving one session's adoption marker
///    from `Finalizing` to `Adopted` — the one file in a staging session that
///    legitimately changes — and only after proving the marker on disk is that
///    session's own outstanding pin. Contract review 2026-07-31-A.
///
/// The pattern in 2 and 3 is the same and is the only one that earns this call:
/// the licence to overwrite is bounded by a proof about the occupant, not by a
/// flag on a shared writer. Every other site uses `rename_noreplace`.
pub(crate) fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    let rename = Entry::Rename {
        from,
        to,
        replace: true,
    };
    entry(rename, || std::fs::rename(from, to))
}

/// Hard-link an existing file under a second name, refusing to overwrite.
///
/// Sealing uses this instead of a rename (scope 3.4). A rename would make the
/// journal reachable under exactly one name at every instant, so a crash after
/// the rename and before the manifest install would leave a fenced,
/// acknowledged prefix in a segment that no manifest references and with no
/// active journal to scan — losing acknowledged data. Linking keeps the file
/// reachable under *both* names across the window; the active name is unlinked
/// only after the manifest that references the segment name is durable.
pub(crate) fn link_noreplace(existing: &Path, new_name: &Path) -> io::Result<()> {
    // `link(2)` never replaces an existing destination, so the no-replace
    // property is inherent rather than a flag.
    let link = Entry::Link {
        existing,
        new: new_name,
    };
    entry(link, || std::fs::hard_link(existing, new_name))
}

pub(crate) fn unlink(path: &Path) -> io::Result<()> {
    entry(Entry::Unlink(path), || std::fs::remove_file(path))
}

/// Remove an empty directory.
pub(crate) fn remove_dir(path: &Path) -> io::Result<()> {
    entry(Entry::Rmdir(path), || std::fs::remove_dir(path))
}

/// `std::fs::create_dir`, for a path the caller already trusts.
pub(crate) fn create_dir(path: &Path) -> io::Result<()> {
    entry(Entry::Mkdir(path), || std::fs::create_dir(path))
}

/// `std::fs::create_dir_all`, for a path the caller already trusts.
///
/// One [`create_dir`] per missing directory, shallowest first, so that each
/// new entry is logged once the directory holding it exists.
pub(crate) fn create_dir_all(path: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = Some(path);
    while let Some(directory) = cursor.filter(|directory| !directory.as_os_str().is_empty()) {
        if directory.is_dir() {
            break;
        }
        missing.push(directory);
        cursor = directory.parent();
    }
    for directory in missing.into_iter().rev() {
        match create_dir(directory) {
            Ok(()) => {}
            // Made by someone else since the look, which is what
            // `std::fs::create_dir_all` accepts too.
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && directory.is_dir() => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Open `path` read-write, creating it if absent and never truncating, for a
/// name the caller already trusts.
///
/// The trusting counterpart of [`open_or_create_regular_nofollow`]: it follows
/// a symlink, as the plain `File::options` call it replaces did, and is here so
/// that the power-loss model sees the name it creates.
pub(crate) fn open_or_create(path: &Path) -> io::Result<File> {
    entry(Entry::Create(path), || {
        File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
    })
}

/// Open `path` empty, creating it if absent, for a name the caller already
/// trusts.
///
/// `O_TRUNC`, taken apart: the open never truncates, and a file that was not
/// already empty is cut to zero afterwards, so that the power-loss model sees
/// both the name it creates and the bytes it cuts. Uncounted, as the `O_TRUNC`
/// it replaces was. Readable as well as writable, because the model reads what
/// a truncation cuts through the descriptor that cuts it.
pub(crate) fn create_truncated(path: &Path) -> io::Result<File> {
    let file = entry(Entry::Create(path), || {
        File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
    })?;
    if file.metadata()?.len() != 0 {
        #[cfg(feature = "failpoints")]
        power_loss::before_resize(&file, 0)?;
        file.set_len(0)?;
    }
    Ok(file)
}

// ---------------------------------------------------------------------------
// Opening a name this process does not yet own
// ---------------------------------------------------------------------------
//
// These exist for the paths where the store has to look at, and then write
// into, a directory it has not established is its own — startup state 1, and
// `lock_root` on every path. Plain `File::open` and
// `File::options().create(true)` both traverse a symlink at the final
// component, so either one at a name an operator can occupy is a write to a
// path outside the root. `open`/`stat` are therefore not available on those
// paths at all; these are.

/// Open `path` read-only for *verification*, refusing to traverse a symlink at
/// the final component and refusing anything that is not a regular file.
///
/// `Ok(None)` means "there is no regular file at exactly this path": absent, a
/// symlink, a directory, a fifo, a socket, a device. Every caller is asking
/// whether the bytes at a name are its own, and for all of those the answer is
/// no — so they collapse into one variant rather than being distinguished by a
/// caller that would treat them identically.
///
/// `O_NOFOLLOW` is what makes the symlink case an error rather than a read of
/// somebody else's file, and the `fstat` is what makes it a *regular file*
/// rather than a name that merely opened: `O_NOFOLLOW` says nothing about
/// directories or fifos. The type is read from the descriptor already opened,
/// not from a second path lookup, so the answer is about the object this call
/// holds and cannot be changed underneath it.
///
/// `O_NONBLOCK` is load-bearing rather than incidental. Opening a fifo for
/// reading blocks until a writer arrives, so without it a fifo left in a
/// configured root would hang startup indefinitely — a denial of service
/// reached by `mkfifo`, and one this function exists to be immune to because
/// its whole job is to look at names it does not trust.
pub(crate) fn open_regular_nofollow(path: &Path) -> io::Result<Option<File>> {
    Ok(match open_regular_nofollow_classified(path)? {
        NamedRegularFile::Opened(file) => Some(file),
        NamedRegularFile::Absent | NamedRegularFile::NotRegular => None,
    })
}

/// What a name held, for the callers that must tell "absent" from "occupied by
/// something else".
///
/// [`open_regular_nofollow`] collapses the two, which is right for a caller
/// asking "are the bytes at this name mine" — every non-regular answer means no.
/// It is wrong for `segment::read_format`, where an absent `FORMAT` is an
/// ordinary startup state that must keep reporting `NotFound`, and a `FORMAT`
/// that is a symlink is a refusal. Two questions, so two answers.
pub(crate) enum NamedRegularFile {
    Opened(File),
    Absent,
    /// A symlink, a directory, a fifo, a socket, or a device.
    NotRegular,
}

/// [`open_regular_nofollow`], keeping absence and wrong-type apart.
pub(crate) fn open_regular_nofollow_classified(path: &Path) -> io::Result<NamedRegularFile> {
    use rustix::fs::{FileType, Mode, OFlags};
    let fd = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) => return Ok(NamedRegularFile::Absent),
        // A non-directory component *within* the path, which is not this name
        // being absent — the store cannot create through it either.
        Err(rustix::io::Errno::NOTDIR) => return Ok(NamedRegularFile::NotRegular),
        // `O_NOFOLLOW` on a symlink is `ELOOP` on Linux and `EMLINK` on some
        // BSDs. Both mean "the final component is a symlink", which is exactly
        // the answer this function is being asked for.
        Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::MLINK) => {
            return Ok(NamedRegularFile::NotRegular)
        }
        // A socket refuses `open(2)` outright; see
        // [`open_or_create_regular_nofollow`] for why this is mapped rather than
        // returned as an `Io`.
        Err(rustix::io::Errno::NXIO) => return Ok(NamedRegularFile::NotRegular),
        Err(e) => return Err(io::Error::from_raw_os_error(e.raw_os_error())),
    };
    let file = File::from(fd);
    let stat =
        rustix::fs::fstat(&file).map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
        Ok(NamedRegularFile::Opened(file))
    } else {
        Ok(NamedRegularFile::NotRegular)
    }
}

/// Create `path` as a **new** regular file, or report that the name is taken.
///
/// `Ok(None)` means the name already exists — as anything at all, including a
/// symlink. `O_CREAT | O_EXCL` is specified to fail with `EEXIST` on a symlink
/// whether or not the link resolves, so this can never create or truncate a
/// file outside the directory it names; `O_NOFOLLOW` is passed as well so the
/// intent survives someone later relaxing the `O_EXCL`.
///
/// This is the only way anything in this crate may bring a new name into a
/// directory the store has not yet established is its own. `create(true)` plus
/// `truncate(true)` is the operation it replaces, and the difference is that
/// this one cannot destroy a byte it did not write.
pub(crate) fn create_new_nofollow(path: &Path) -> io::Result<Option<File>> {
    use rustix::fs::{Mode, OFlags};
    let opened = entry(Entry::Create(path), || {
        Ok(rustix::fs::open(
            path,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        ))
    })?;
    match opened {
        Ok(fd) => Ok(Some(File::from(fd))),
        Err(rustix::io::Errno::EXIST) => Ok(None),
        Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
    }
}

/// Open `path` read-write, creating it if absent, refusing to traverse a
/// symlink at the final component and refusing anything that is not a regular
/// file. Never truncates.
///
/// `Ok(None)` means "the name is occupied by something that is not a regular
/// file": a symlink, a directory, a fifo, a socket, a device. Absent is not one
/// of them — absent is the create case, and it returns the new file.
///
/// This is the shape [`open_regular_nofollow`] and [`create_new_nofollow`] do
/// not cover: a name the store must *own and keep*, where an existing file is
/// adopted rather than replaced and an absent one is brought into being. The
/// only caller is `segment::lock_root`, which needs exactly this because
/// `<root>/LOCK` is created as a side effect of asking whether a root is busy.
///
/// # Why the type check is not cosmetic here
///
/// `flock` locks the *inode*, not the name. A symlink at `LOCK` that a
/// follow-through open traverses therefore takes the root lock on a foreign
/// inode, and the root's own lock file is left unlocked — so a second process
/// arriving at the same root takes it too, and both hold what each believes is
/// exclusive ownership. That defeats the exclusion scope 3.1 is built on, which
/// no amount of care at the `flock` call itself can restore. `O_NOFOLLOW` plus
/// this `fstat` is what makes the locked inode the one the caller's *name*
/// resolved to.
///
/// It does not make the binding permanent, and scope 3.1 is explicit about the
/// difference: a name replaced with a fresh regular file while a holder holds it
/// still yields a second holder, because both opens are then of a regular file at
/// exactly the right name. That case is an assumption about the deployment, not a
/// property this function can supply.
///
/// One `O_CREAT` open, not an `O_EXCL` create followed by a plain open on
/// `EEXIST`: the single call has no window between deciding the name is taken
/// and opening what is there, so there is nothing for an adversary replacing
/// the name to land in.
///
/// # What this still permits
///
/// A device node at the name receives one `open(2)` before the `fstat` refuses
/// it. `O_NONBLOCK` is passed so that open cannot hang — the fifo case is a
/// startup denial of service otherwise — but a driver that acts on being opened
/// has still been opened. Closing that would need `O_PATH` for classification
/// and a re-open of the same inode, which is more machinery than the hazard
/// warrants: reaching it requires the privilege to `mknod` inside a configured
/// store root. Recorded rather than silently accepted.
pub(crate) fn open_or_create_regular_nofollow(path: &Path) -> io::Result<Option<File>> {
    Ok(open_or_create_regular_nofollow_sized(path)?.map(|(file, _)| file))
}

/// [`open_or_create_regular_nofollow`], also reporting the length it found.
///
/// The length is what lets [`open_or_create_regular_truncated_nofollow`] leave
/// the durability counters alone when there was nothing to truncate.
fn open_or_create_regular_nofollow_sized(path: &Path) -> io::Result<Option<(File, u64)>> {
    use rustix::fs::{FileType, Mode, OFlags};
    let opened = entry(Entry::Create(path), || {
        Ok(rustix::fs::open(
            path,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o644),
        ))
    })?;
    let fd = match opened {
        Ok(fd) => fd,
        // A symlink at the final component: `ELOOP` on Linux, `EMLINK` on some
        // BSDs. `O_CREAT` through a *dangling* link is the same refusal, which
        // is what stops this call from creating a file outside the root.
        Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::MLINK) => return Ok(None),
        // A directory refuses `O_RDWR` before any type check runs, and a Unix
        // socket refuses `open(2)` with `ENXIO` — so neither ever reaches the
        // `fstat`. Both are mapped here rather than left to surface as `Io`,
        // because "the name is occupied by something that is not a regular file"
        // is precisely what they mean, and a caller that has to handle that
        // answer in two shapes will handle one of them wrongly. `ENXIO` on a
        // deviceless device node says the same thing.
        Err(rustix::io::Errno::ISDIR) | Err(rustix::io::Errno::NXIO) => return Ok(None),
        Err(e) => return Err(io::Error::from_raw_os_error(e.raw_os_error())),
    };
    let file = File::from(fd);
    let stat =
        rustix::fs::fstat(&file).map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
        Ok(Some((file, stat.st_size as u64)))
    } else {
        Ok(None)
    }
}

/// [`open_or_create_regular_nofollow`], left empty and ready to be rewritten.
///
/// For the temporary names a fenced write installs from — `FORMAT.tmp`,
/// `<generation>.manifest.tmp`, `CURRENT.tmp`. The operation these replace is
/// `File::options().create(true).write(true).truncate(true)`, whose `O_TRUNC`
/// destroys whatever the name held **before** anything can look at it, and
/// through a symlink destroys it outside the root entirely. Splitting the open
/// from the truncation is what makes the type check possible at all: there is
/// no flag combination that truncates only regular files.
///
/// An existing regular file here is legitimate — it is residue from an
/// interrupted attempt at exactly this write, and reusing the name is how a
/// retry works — so it is adopted and emptied rather than refused.
///
/// The truncation goes through [`truncate`] and is therefore counted, because a
/// truncation is a durability-relevant mutation; it is skipped when the file is
/// already empty, which is every freshly created one, so the common path adds no
/// syscall and no counter movement.
pub(crate) fn open_or_create_regular_truncated_nofollow(
    path: &Path,
    counters: &DurabilityCounters,
) -> io::Result<Option<File>> {
    let Some((file, length)) = open_or_create_regular_nofollow_sized(path)? else {
        return Ok(None);
    };
    if length != 0 {
        truncate(&file, 0, counters)?;
    }
    Ok(Some(file))
}

/// What a name held, for the directories the store invents beneath a root.
pub(crate) enum NamedDirectory {
    Opened(File),
    Absent,
    /// A symlink — including one that resolves to a perfectly good directory —
    /// a regular file, or any other non-directory.
    NotDirectory,
}

/// Open `path` as a directory, refusing to traverse a symlink at the final
/// component.
///
/// `O_DIRECTORY` is the type check here and it happens in the kernel, before the
/// descriptor exists: there is no window in which a non-directory is open. A
/// symlink *to* a directory is refused as firmly as a symlink to anything else,
/// which is the whole point — `create_dir_all` follows one and builds the store's
/// tree wherever it leads.
pub(crate) fn open_directory_nofollow(path: &Path) -> io::Result<NamedDirectory> {
    use rustix::fs::{Mode, OFlags};
    match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(NamedDirectory::Opened(File::from(fd))),
        Err(rustix::io::Errno::NOENT) => Ok(NamedDirectory::Absent),
        // `ENOTDIR` is the name holding a non-directory, or a non-directory
        // component within the path; `ELOOP`/`EMLINK` is a symlink at the final
        // component. The store may build through none of them.
        Err(rustix::io::Errno::NOTDIR)
        | Err(rustix::io::Errno::LOOP)
        | Err(rustix::io::Errno::MLINK) => Ok(NamedDirectory::NotDirectory),
        Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
    }
}

/// Create `path` as a directory and open it, or report that the name is taken
/// by something that is not one.
///
/// `mkdir(2)` never follows a symlink at the final component — a name occupied
/// by one fails `EEXIST` whether or not it resolves — so this cannot create a
/// directory outside the directory it names. `Ok(None)` is that `EEXIST` where
/// the occupant turns out not to be a directory; an occupant that *is* one is
/// adopted, because two callers racing to create the same tree is ordinary.
pub(crate) fn create_directory_nofollow(path: &Path) -> io::Result<Option<File>> {
    use rustix::fs::Mode;
    let made = entry(Entry::Mkdir(path), || {
        Ok(rustix::fs::mkdir(path, Mode::from_raw_mode(0o755)))
    })?;
    match made {
        Ok(()) => {}
        Err(rustix::io::Errno::EXIST) => {}
        Err(e) => return Err(io::Error::from_raw_os_error(e.raw_os_error())),
    }
    Ok(match open_directory_nofollow(path)? {
        NamedDirectory::Opened(file) => Some(file),
        NamedDirectory::NotDirectory => None,
        // Unlinked between the `mkdir` and the open. Nothing was created that
        // survives, and the caller's tree is not what it asked for, so this is
        // the same answer as a name it may not use.
        NamedDirectory::Absent => None,
    })
}

/// Truncate a file to `len`.
///
/// In the funnel because it changes what is durable. `journal.rs` was calling
/// `File::set_len` directly, which the original guard did not scan for — a
/// truncation is a durability-relevant mutation as surely as a write, and one
/// that recovery reasons about directly.
pub(crate) fn truncate(file: &File, len: u64, counters: &DurabilityCounters) -> io::Result<()> {
    if take_fault_if(|f| matches!(f, Fault::NoSpace)).is_some() {
        return Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "injected ENOSPC during truncate",
        ));
    }
    #[cfg(feature = "failpoints")]
    power_loss::before_resize(file, len)?;
    counters.write_vectored.fetch_add(1, Relaxed);
    file.set_len(len)
}

// ---------------------------------------------------------------------------
// Read path and allocation
// ---------------------------------------------------------------------------

/// Whether an armed read fault applies to a read at `offset`.
///
/// An unscoped `ReadEio` fires anywhere; a scoped one fires only at or beyond
/// its offset and is left armed until a read actually reaches that far, so a
/// reopen's early metadata reads cannot consume a fault aimed at the tail.
fn read_fault_fires(offset: u64) -> bool {
    take_fault_if(|f| match f {
        Fault::ReadEio => true,
        Fault::ReadEioAtOrAfter { offset: at } => offset >= *at,
        Fault::ShortWrite { .. }
        | Fault::NoSpace
        | Fault::FenceEio
        | Fault::DirSyncEio
        | Fault::CursorSkew { .. } => false,
    })
    .is_some()
}

/// Bounded positioned read. Segment and journal readers use only this.
pub(crate) fn pread_exact(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<()> {
    if read_fault_fires(offset) {
        return Err(eio("positioned read"));
    }
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buf, offset)
}

/// Positioned read that reports a short read rather than failing, so a tail
/// scanner can distinguish "the file ends here" from an I/O error.
pub(crate) fn pread(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    if read_fault_fires(offset) {
        return Err(eio("positioned read"));
    }
    use std::os::unix::fs::FileExt;
    file.read_at(buf, offset)
}

/// Preallocate without `FALLOC_FL_KEEP_SIZE`, so the file has its full size
/// with unwritten extents and appends become overwrites within an already
/// sized file (scope 3.2).
pub(crate) fn preallocate(file: &File, len: u64) -> io::Result<()> {
    #[cfg(feature = "failpoints")]
    power_loss::before_resize(file, len)?;
    rustix::fs::fallocate(file, rustix::fs::FallocateFlags::empty(), 0, len)
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
}

/// Non-blocking exclusive lock for `<root>/LOCK`. Failure is refusal, never a
/// wait (scope 3.1).
pub(crate) fn try_lock_exclusive(file: &File) -> io::Result<bool> {
    match rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::WOULDBLOCK) => Ok(false),
        Err(e) => Err(io::Error::from_raw_os_error(e.raw_os_error())),
    }
}

/// Release a `flock` held on `file`'s **open file description**.
///
/// This is not redundant with closing the descriptor. `flock` is a property of
/// the open file description, not of the descriptor: any descriptor that
/// shares the description keeps the lock alive, and `fork` hands the child
/// exactly such a descriptor. `FD_CLOEXEC` closes it at `exec`, not at `fork`,
/// so between a concurrent fork and that child's `exec` — or for as long as a
/// forked child runs without exec'ing — the parent closing its own descriptor
/// releases nothing. Releasing must therefore be an explicit act.
///
/// Locking already lives in this module; unlocking stays beside it so the
/// durability funnel remains the only place that issues the syscall.
pub(crate) fn unlock(file: &File) -> io::Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::Unlock)
        .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
}

/// Read the file position without moving it.
pub(crate) fn cursor(file: &mut File) -> io::Result<u64> {
    file.stream_position()
}

pub(crate) fn seek_to(file: &mut File, offset: u64) -> io::Result<()> {
    file.seek(SeekFrom::Start(offset)).map(|_| ())
}

// ---------------------------------------------------------------------------
// Power loss (failpoints only)
// ---------------------------------------------------------------------------

/// A userspace model of what a power loss discards: audit finding S2, contract
/// reviews 2026-11-02-C (file contents) and 2026-11-02-D (directory entries).
///
/// `_exit` and `SIGKILL` both leave the page cache intact, so a crash suite that
/// only kills the writer cannot see a missing fence: an unfenced write is still
/// there when the next process reads it, and every suite passed with
/// `fdatasync` turned into a counted no-op. With the model armed, every write
/// through this funnel first logs the bytes it is about to overwrite, a resize
/// logs the length that was durable, and a successful [`fdatasync`] logs that
/// the file is durable as it stands. [`apply`](power_loss::apply), run once the
/// writer is gone and before recovery, puts back everything no fence covered —
/// the worst case a power loss allows — so a missing fence loses exactly the
/// data it should have made durable.
///
/// Directory entries are modelled the same way. Every create, link, unlink,
/// rename, `mkdir` and `rmdir` through the funnel logs, before it runs, what
/// undoing it needs; a directory fsync logs that the directory's entries are
/// durable; and `apply` undoes, newest first, every change no fsync of its
/// directory covered. That is the worst case POSIX allows — `fsync(2)` on a
/// file says nothing about the entry that names it — so a missing directory
/// fsync loses the name it should have made durable, and the data behind the
/// name. A rename between directories, or of a directory, is refused rather
/// than modelled; the store makes neither.
///
/// The model is armed for one root and ignores everything outside it, so a
/// test process can arm it while other tests write elsewhere. The log lives
/// beside the root and outlives a writer, as a machine's page cache does: a
/// writer that exits normally leaves its unfenced changes logged for the next
/// writer to add to, and `apply` is the power loss and the reboot together,
/// consuming the log.
///
/// Each record is appended before the change it describes, so a writer killed
/// at any instant leaves a log `apply` can use, and a torn last record is
/// ignored. A fence is logged after it returns: a writer killed between the two
/// is treated as unfenced, which is pessimistic only about work it had not yet
/// acknowledged.
#[cfg(feature = "failpoints")]
pub mod power_loss {
    use std::collections::hash_map::Entry as Slot;
    use std::collections::HashMap;
    use std::ffi::OsStr;
    use std::fs::{File, Metadata, OpenOptions};
    use std::io::{self, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::path::{Component, Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    use super::{Entry, FaultSerial};

    const MAGIC: &[u8; 8] = b"LVPWRLS1";
    const SEEN: u8 = 1;
    const PRE_IMAGE: u8 = 2;
    const FENCED: u8 = 3;
    const DIRECTORY_FENCED: u8 = 4;
    const ENTRY: u8 = 5;

    // What an `ENTRY` record changed.
    const CREATE: u8 = 1;
    const MKDIR: u8 = 2;
    const LINK: u8 = 3;
    const UNLINK: u8 = 4;
    const RMDIR: u8 = 5;
    const RENAME: u8 = 6;

    /// A file by device and inode, which outlives its names.
    type Inode = (u64, u64);

    /// Which fences the model takes at their word.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Fences {
        /// Every fence: the power loss a correct store survives.
        Honoured,
        /// None: the self-test that a crash suite catches a missing fence.
        Ignored,
        /// Every `fdatasync` but no directory fsync: the self-test that a crash
        /// suite catches a missing directory fsync.
        DirectoriesIgnored,
    }

    impl Fences {
        fn files(self) -> bool {
            self != Fences::Ignored
        }

        fn directories(self) -> bool {
            self == Fences::Honoured
        }
    }

    struct Model {
        log: Log,
        fences: Fences,
        scope: Scope,
        /// Where a file that loses a name is kept, by a hard link, so that
        /// `apply` can give the name back with the same inode — and therefore
        /// with whatever the log says about the inode's contents.
        graveyard: PathBuf,
        /// The next name in the graveyard.
        buried: u64,
        /// Files this process changed since their last fence.
        dirty: HashMap<Inode, Dirty>,
    }

    struct Log {
        file: File,
        /// Where the next record starts.
        end: u64,
    }

    impl Log {
        /// One record, in one write.
        fn record(&mut self, tag: u8, inode: Inode, body: &[u8]) -> io::Result<()> {
            let mut bytes = Vec::with_capacity(1 + 16 + body.len());
            bytes.push(tag);
            bytes.extend_from_slice(&inode.0.to_le_bytes());
            bytes.extend_from_slice(&inode.1.to_le_bytes());
            bytes.extend_from_slice(body);
            self.file.write_all(&bytes)?;
            self.end += bytes.len() as u64;
            Ok(())
        }
    }

    struct Dirty {
        /// The length that was durable when this process first changed it.
        durable_len: u64,
        /// Ranges, half-open, whose pre-image this process has logged.
        logged: Vec<(u64, u64)>,
    }

    /// The root the model is armed for, by the path its callers name it with
    /// and by the path the kernel resolves that to, and the directory holding
    /// its entry, resolved.
    struct Scope {
        given: PathBuf,
        resolved: PathBuf,
        parent: PathBuf,
    }

    impl Scope {
        fn new(root: &Path) -> io::Result<Self> {
            let given = std::path::absolute(root)?;
            let (Some(parent), Some(name)) = (given.parent(), given.file_name()) else {
                return Err(io::Error::other(format!(
                    "power-loss model: {} cannot be a modelled root",
                    root.display()
                )));
            };
            let parent = std::fs::canonicalize(parent)?;
            // A root that does not exist yet will be made at this name.
            let resolved = match std::fs::canonicalize(&given) {
                Ok(resolved) => resolved,
                Err(error) if error.kind() == io::ErrorKind::NotFound => parent.join(name),
                Err(error) => return Err(error),
            };
            Ok(Self {
                given,
                resolved,
                parent,
            })
        }

        /// `path` relative to the root, if it is at or under it.
        fn relative(&self, path: &Path) -> io::Result<Option<PathBuf>> {
            let path = std::path::absolute(path)?;
            let Ok(relative) = path
                .strip_prefix(&self.given)
                .or_else(|_| path.strip_prefix(&self.resolved))
            else {
                return Ok(None);
            };
            if relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
            {
                Ok(Some(relative.to_path_buf()))
            } else {
                Err(io::Error::other(format!(
                    "power-loss model: cannot name {} relative to its root",
                    path.display()
                )))
            }
        }

        /// Where the kernel says an open file is. `None` when it cannot say,
        /// which every caller takes as in scope: the model would rather log a
        /// stranger than miss one of its own.
        fn located(file: &File) -> Option<PathBuf> {
            let path = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()?;
            // An unlinked file reads back as "<path> (deleted)".
            let bytes = path.as_os_str().as_bytes();
            let bytes = bytes.strip_suffix(b" (deleted)").unwrap_or(bytes);
            Some(PathBuf::from(OsStr::from_bytes(bytes)))
        }

        fn holds(&self, file: &File) -> bool {
            Self::located(file).is_none_or(|path| {
                path.starts_with(&self.resolved) || path.starts_with(&self.given)
            })
        }

        /// Whether a fence on `directory` can cover an entry in scope: the
        /// root, a directory under it, or the directory naming the root.
        fn fences(&self, directory: &File) -> bool {
            Self::located(directory).is_none_or(|path| {
                path.starts_with(&self.resolved)
                    || path.starts_with(&self.given)
                    || path == self.parent
            })
        }
    }

    static MODEL: Mutex<Option<Model>> = Mutex::new(None);

    fn model() -> MutexGuard<'static, Option<Model>> {
        MODEL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The graveyard beside `log`.
    fn graveyard(log: &Path) -> PathBuf {
        let mut name = log.as_os_str().to_owned();
        name.push(".d");
        PathBuf::from(name)
    }

    /// Start modelling `root`, appending to `log`.
    pub fn arm(_serial: &FaultSerial, log: &Path, root: &Path, fences: Fences) -> io::Result<()> {
        let scope = Scope::new(root)?;
        let graveyard = graveyard(log);
        std::fs::create_dir_all(&graveyard)?;
        // A hard link cannot leave its filesystem, so the graveyard has to be
        // on the root's.
        let root_device = match lstat(&scope.resolved)? {
            Some(root) => root.dev(),
            None => std::fs::metadata(&scope.parent)?.dev(),
        };
        if std::fs::metadata(&graveyard)?.dev() != root_device {
            return Err(io::Error::other(format!(
                "power-loss model: {} is not on the filesystem of {}, so it cannot keep the \
                 files the root unlinks",
                graveyard.display(),
                root.display()
            )));
        }
        // One past the highest grave an earlier writer of this log left.
        let mut buried = 0;
        for grave in std::fs::read_dir(&graveyard)? {
            if let Some(number) = grave?
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u64>().ok())
            {
                buried = buried.max(number + 1);
            }
        }

        let mut file = OpenOptions::new().create(true).append(true).open(log)?;
        let existing = std::fs::read(log)?;
        if MAGIC.starts_with(&existing) {
            // Empty, or a writer died writing the magic.
            file.set_len(0)?;
            file.write_all(MAGIC)?;
        } else {
            // A writer killed mid-record left a torn last record. Appending
            // after it would put every later record out of step, and `apply`
            // would misread them, missing among others a later writer's fence.
            let (_, whole) = parse(log, &existing)?;
            if whole < existing.len() {
                file.set_len(whole as u64)?;
            }
        }
        let end = file.metadata()?.len();
        *model() = Some(Model {
            log: Log { file, end },
            fences,
            scope,
            graveyard,
            buried,
            dirty: HashMap::new(),
        });
        Ok(())
    }

    pub fn disarm(_serial: &FaultSerial) {
        *model() = None;
    }

    /// [`disarm`] for [`serial`](super::serial), which holds no token yet.
    pub(super) fn reset() {
        *model() = None;
    }

    fn identify(file: &File) -> io::Result<(Inode, u64)> {
        let metadata = file.metadata()?;
        Ok(((metadata.dev(), metadata.ino()), metadata.len()))
    }

    fn inode_of(metadata: &Metadata) -> Inode {
        (metadata.dev(), metadata.ino())
    }

    fn lstat(path: &Path) -> io::Result<Option<Metadata>> {
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The directory holding `path`'s entry: the one whose fsync makes it
    /// durable.
    fn parent_of(path: &Path) -> io::Result<Inode> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        Ok(inode_of(&std::fs::metadata(parent)?))
    }

    // -- File contents -------------------------------------------------------

    /// Log the pre-image of whatever part of `[from, to)` lies within the
    /// durable length and has not been logged since the file's last fence. The
    /// first change since a fence also logs that durable length.
    fn log_pre_image(model: &mut Model, file: &File, from: u64, to: u64) -> io::Result<()> {
        let (inode, len) = identify(file)?;
        let Model {
            log, dirty, scope, ..
        } = model;
        let entry = match dirty.entry(inode) {
            Slot::Occupied(entry) => entry.into_mut(),
            Slot::Vacant(entry) => {
                if !scope.holds(file) {
                    return Ok(());
                }
                log.record(SEEN, inode, &len.to_le_bytes())?;
                entry.insert(Dirty {
                    durable_len: len,
                    logged: Vec::new(),
                })
            }
        };
        let to = to.min(entry.durable_len);
        let mut at = from;
        while at < to {
            if let Some(&(_, end)) = entry.logged.iter().find(|&&(s, e)| s <= at && at < e) {
                at = end;
                continue;
            }
            let next = entry
                .logged
                .iter()
                .map(|&(start, _)| start)
                .filter(|&start| start > at)
                .min()
                .unwrap_or(to)
                .min(to);
            let mut bytes = vec![0u8; (next - at) as usize];
            let read = file.read_at(&mut bytes, at)?;
            bytes.truncate(read);
            let mut body = Vec::with_capacity(16 + bytes.len());
            body.extend_from_slice(&at.to_le_bytes());
            body.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            body.extend_from_slice(&bytes);
            log.record(PRE_IMAGE, inode, &body)?;
            entry.logged.push((at, next));
            at = next;
        }
        Ok(())
    }

    /// Before a write of `len` bytes at `offset`.
    pub(crate) fn before_write(file: &File, offset: u64, len: u64) -> io::Result<()> {
        match model().as_mut() {
            Some(model) => log_pre_image(model, file, offset, offset.saturating_add(len)),
            None => Ok(()),
        }
    }

    /// Before a truncation or an allocation to `new_len`. Growth needs no
    /// pre-image, since putting the durable length back drops it; a shrink logs
    /// what it is about to cut.
    pub(crate) fn before_resize(file: &File, new_len: u64) -> io::Result<()> {
        match model().as_mut() {
            Some(model) => log_pre_image(model, file, new_len, u64::MAX),
            None => Ok(()),
        }
    }

    /// After a successful `fdatasync`: the file is durable as it stands.
    pub(crate) fn after_fence(file: &File) -> io::Result<()> {
        let mut guard = model();
        let Some(model) = guard.as_mut() else {
            return Ok(());
        };
        if !model.fences.files() {
            return Ok(());
        }
        let (inode, _) = identify(file)?;
        // A file this writer never changed is still logged: its fence may cover
        // an earlier writer's changes.
        if model.dirty.remove(&inode).is_none() && !model.scope.holds(file) {
            return Ok(());
        }
        model.log.record(FENCED, inode, &[])
    }

    // -- Directory entries ---------------------------------------------------

    /// One change to a directory entry, as logged.
    #[derive(Debug)]
    struct Change {
        kind: u8,
        /// The file the change was about, where one existed before it: what a
        /// link names again, an unlink removes or a rename moves. Zero for a
        /// creation.
        subject: Inode,
        /// The directory whose fsync makes the change durable. One, because a
        /// rename between directories is refused rather than modelled.
        parent: Inode,
        /// Relative to the root; a rename's source.
        name: PathBuf,
        /// A rename's destination, relative to the root; empty otherwise.
        to: PathBuf,
        /// The grave keeping the file an unlink removed or a rename replaced.
        grave: Option<String>,
    }

    impl Change {
        fn encode(&self) -> Vec<u8> {
            let mut body = vec![self.kind];
            body.extend_from_slice(&self.parent.0.to_le_bytes());
            body.extend_from_slice(&self.parent.1.to_le_bytes());
            let grave = self.grave.as_deref().unwrap_or("");
            for bytes in [
                self.name.as_os_str().as_bytes(),
                self.to.as_os_str().as_bytes(),
                grave.as_bytes(),
            ] {
                body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                body.extend_from_slice(bytes);
            }
            body
        }
    }

    /// A change to a directory entry. What undoing it needs is logged before
    /// `perform` runs, and `perform` runs under the model's lock, so that no
    /// directory fence can begin between the record and the change.
    pub(crate) fn entry<T>(
        entry: Entry<'_>,
        perform: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let mut guard = model();
        let Some(model) = guard.as_mut() else {
            drop(guard);
            return perform();
        };
        model.log_entry(entry)?;
        perform()
    }

    impl Model {
        /// Log `entry` if it is in scope and will change anything. A change the
        /// kernel is about to refuse — a name already taken, a source that is
        /// not there — is not logged, so that `apply` never undoes something
        /// the change did not do.
        fn log_entry(&mut self, entry: Entry<'_>) -> io::Result<()> {
            match entry {
                Entry::Create(path) => self.log_creation(CREATE, path),
                Entry::Mkdir(path) => self.log_creation(MKDIR, path),
                Entry::Link { existing, new } => {
                    let Some(name) = self.scope.relative(new)? else {
                        return Ok(());
                    };
                    // `link(2)` never replaces, so a taken name is a refusal.
                    if lstat(new)?.is_some() {
                        return Ok(());
                    }
                    let Some(subject) = lstat(existing)? else {
                        return Ok(());
                    };
                    self.log_change(Change {
                        kind: LINK,
                        subject: inode_of(&subject),
                        parent: parent_of(new)?,
                        name,
                        to: PathBuf::new(),
                        grave: None,
                    })
                }
                Entry::Unlink(path) => {
                    let Some(name) = self.scope.relative(path)? else {
                        return Ok(());
                    };
                    let Some(subject) = lstat(path)?.filter(|found| !found.is_dir()) else {
                        return Ok(());
                    };
                    let grave = self.bury(path)?;
                    self.log_change(Change {
                        kind: UNLINK,
                        subject: inode_of(&subject),
                        parent: parent_of(path)?,
                        name,
                        to: PathBuf::new(),
                        grave: Some(grave),
                    })
                }
                Entry::Rmdir(path) => {
                    let Some(name) = self.scope.relative(path)? else {
                        return Ok(());
                    };
                    let Some(subject) = lstat(path)?.filter(Metadata::is_dir) else {
                        return Ok(());
                    };
                    self.log_change(Change {
                        kind: RMDIR,
                        subject: inode_of(&subject),
                        parent: parent_of(path)?,
                        name,
                        to: PathBuf::new(),
                        grave: None,
                    })
                }
                Entry::Rename { from, to, replace } => {
                    let (name, destination) =
                        match (self.scope.relative(from)?, self.scope.relative(to)?) {
                            (Some(name), Some(destination)) => (name, destination),
                            (None, None) => return Ok(()),
                            _ => {
                                return Err(io::Error::other(format!(
                                    "power-loss model: a rename from {} to {} crosses the edge \
                                     of the modelled root",
                                    from.display(),
                                    to.display()
                                )))
                            }
                        };
                    let Some(subject) = lstat(from)? else {
                        return Ok(());
                    };
                    // Neither is modelled, and the store makes neither: every
                    // rename it makes moves a file within one directory. A
                    // rename between directories is durable in two places,
                    // and a directory's rename moves every name beneath it, so
                    // the model refuses both rather than undo them wrongly.
                    let parent = parent_of(from)?;
                    if parent_of(to)? != parent || subject.is_dir() {
                        return Err(io::Error::other(format!(
                            "power-loss model: a rename from {} to {} moves a directory or \
                             crosses directories, which the model does not cover",
                            from.display(),
                            to.display()
                        )));
                    }
                    let grave = match lstat(to)? {
                        None => None,
                        // Refused.
                        Some(_) if !replace => return Ok(()),
                        // Two names for one file: the rename changes nothing.
                        Some(occupant) if inode_of(&occupant) == inode_of(&subject) => {
                            return Ok(())
                        }
                        Some(occupant) if occupant.is_dir() => {
                            return Err(io::Error::other(format!(
                                "power-loss model: cannot keep the directory {} a rename \
                                 replaces",
                                to.display()
                            )))
                        }
                        Some(_) => Some(self.bury(to)?),
                    };
                    self.log_change(Change {
                        kind: RENAME,
                        subject: inode_of(&subject),
                        parent,
                        name,
                        to: destination,
                        grave,
                    })
                }
            }
        }

        /// A new file or directory at `path`, if nothing is there yet.
        fn log_creation(&mut self, kind: u8, path: &Path) -> io::Result<()> {
            let Some(name) = self.scope.relative(path)? else {
                return Ok(());
            };
            if lstat(path)?.is_some() {
                return Ok(());
            }
            self.log_change(Change {
                kind,
                subject: (0, 0),
                parent: parent_of(path)?,
                name,
                to: PathBuf::new(),
                grave: None,
            })
        }

        fn log_change(&mut self, change: Change) -> io::Result<()> {
            self.log.record(ENTRY, change.subject, &change.encode())
        }

        /// Keep the file at `path` alive under a name in the graveyard. Linked
        /// before the record that names the grave is written, so a record never
        /// names a grave that is not there.
        fn bury(&mut self, path: &Path) -> io::Result<String> {
            let grave = self.buried.to_string();
            self.buried += 1;
            std::fs::hard_link(path, self.graveyard.join(&grave)).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!(
                        "power-loss model: keeping {} in {}: {error}",
                        path.display(),
                        self.graveyard.display()
                    ),
                )
            })?;
            Ok(grave)
        }
    }

    /// A directory fsync, `sync`, run outside the model's lock. Its record
    /// covers only the changes logged before `sync` began, since a change made
    /// while it ran may have missed it.
    pub(crate) fn directory_fence(
        directory: &File,
        sync: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        let began = {
            let guard = model();
            match guard.as_ref() {
                Some(model) if model.fences.directories() && model.scope.fences(directory) => {
                    Some(model.log.end)
                }
                _ => None,
            }
        };
        sync()?;
        let Some(began) = began else {
            return Ok(());
        };
        let (inode, _) = identify(directory)?;
        match model().as_mut() {
            Some(model) => model
                .log
                .record(DIRECTORY_FENCED, inode, &began.to_le_bytes()),
            None => Ok(()),
        }
    }

    // -- The log, read back --------------------------------------------------

    enum Record {
        Seen {
            inode: Inode,
            durable_len: u64,
        },
        PreImage {
            inode: Inode,
            offset: u64,
            data: Vec<u8>,
        },
        Fenced {
            inode: Inode,
        },
        DirectoryFenced {
            inode: Inode,
            /// Where the log ended when the fsync began.
            began: u64,
        },
        Entry(Change),
    }

    struct Reader<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl<'a> Reader<'a> {
        fn take(&mut self, len: usize) -> Option<&'a [u8]> {
            let taken = self.bytes.get(self.at..self.at.checked_add(len)?)?;
            self.at += len;
            Some(taken)
        }

        fn u8(&mut self) -> Option<u8> {
            self.take(1).map(|bytes| bytes[0])
        }

        fn u64(&mut self) -> Option<u64> {
            self.take(8)
                .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
        }

        fn sized(&mut self) -> Option<&'a [u8]> {
            let len = self
                .take(4)
                .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap()))?;
            self.take(usize::try_from(len).ok()?)
        }
    }

    /// A log's whole records, each with the offset it starts at, and the length
    /// they end at. A torn last record is where a writer died, so it ends the
    /// log: `apply` ignores it and `arm` cuts it off before appending.
    fn parse(log: &Path, bytes: &[u8]) -> io::Result<(Vec<(u64, Record)>, usize)> {
        if bytes.get(..MAGIC.len()) != Some(&MAGIC[..]) {
            return Err(io::Error::other(format!(
                "{} is not a power-loss log",
                log.display()
            )));
        }
        let mut records = Vec::new();
        let mut whole = MAGIC.len();
        loop {
            let mut reader = Reader { bytes, at: whole };
            let record = read_record(&mut reader).map_err(|error| {
                io::Error::other(format!("{}: at byte {whole}: {error}", log.display()))
            })?;
            let Some(record) = record else {
                break;
            };
            records.push((whole as u64, record));
            whole = reader.at;
        }
        Ok((records, whole))
    }

    /// One record, or `None` where the log ends inside it.
    fn read_record(reader: &mut Reader<'_>) -> Result<Option<Record>, String> {
        let (Some(tag), Some(device), Some(number)) = (reader.u8(), reader.u64(), reader.u64())
        else {
            return Ok(None);
        };
        let inode = (device, number);
        let record = match tag {
            SEEN => {
                let Some(durable_len) = reader.u64() else {
                    return Ok(None);
                };
                Record::Seen { inode, durable_len }
            }
            PRE_IMAGE => {
                let (Some(offset), Some(len)) = (reader.u64(), reader.u64()) else {
                    return Ok(None);
                };
                let Some(data) = usize::try_from(len).ok().and_then(|len| reader.take(len)) else {
                    return Ok(None);
                };
                Record::PreImage {
                    inode,
                    offset,
                    data: data.to_vec(),
                }
            }
            FENCED => Record::Fenced { inode },
            DIRECTORY_FENCED => {
                let Some(began) = reader.u64() else {
                    return Ok(None);
                };
                Record::DirectoryFenced { inode, began }
            }
            ENTRY => match read_change(reader, inode)? {
                Some(change) => Record::Entry(change),
                None => return Ok(None),
            },
            other => return Err(format!("unknown power-loss record {other}")),
        };
        Ok(Some(record))
    }

    fn read_change(reader: &mut Reader<'_>, subject: Inode) -> Result<Option<Change>, String> {
        let (Some(kind), Some(device), Some(number)) = (reader.u8(), reader.u64(), reader.u64())
        else {
            return Ok(None);
        };
        let (Some(name), Some(to), Some(grave)) = (reader.sized(), reader.sized(), reader.sized())
        else {
            return Ok(None);
        };
        if !(CREATE..=RENAME).contains(&kind) {
            return Err(format!("unknown directory change {kind}"));
        }
        let grave = match grave {
            [] => None,
            grave => {
                let grave = std::str::from_utf8(grave)
                    .ok()
                    .filter(|grave| grave.bytes().all(|byte| byte.is_ascii_digit()))
                    .ok_or("a grave that is not a number")?;
                Some(grave.to_string())
            }
        };
        if kind == UNLINK && grave.is_none() {
            return Err("an unlink with no grave".into());
        }
        Ok(Some(Change {
            kind,
            subject,
            parent: (device, number),
            name: plain(name)?,
            to: plain(to)?,
            grave,
        }))
    }

    /// A path a record may name: relative, and made of nothing but names, so
    /// that `apply` can only ever join it to the root.
    fn plain(bytes: &[u8]) -> Result<PathBuf, String> {
        let path = Path::new(OsStr::from_bytes(bytes));
        if path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        {
            Ok(path.to_path_buf())
        } else {
            Err(format!("{} is not a plain relative path", path.display()))
        }
    }

    // -- The power loss ------------------------------------------------------

    /// What [`apply`] put back.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct Applied {
        /// Files returned to their durable length and content.
        pub files: u64,
        /// Bytes of pre-image written back.
        pub bytes: u64,
        /// Changed files no name under the root reaches any more, so nothing a
        /// recovery could read; counted, not restored.
        pub unreachable: u64,
        /// Changes to directory entries undone.
        pub entries: u64,
        /// Whole records the log held: everything the model saw, whether or
        /// not a fence covered it.
        pub records: u64,
    }

    /// The power loss: undo, under `root`, every change to a directory entry and
    /// every write the log says no fence covered, then remove the log and its
    /// graveyard. No log is no loss.
    pub fn apply(root: &Path, log: &Path) -> io::Result<Applied> {
        let graveyard = graveyard(log);
        let bytes = match std::fs::read(log) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                remove_graveyard(&graveyard)?;
                return Ok(Applied::default());
            }
            Err(error) => return Err(error),
        };
        struct Unfenced {
            durable_len: u64,
            pre_images: Vec<(u64, Vec<u8>)>,
        }
        /// A change to an entry no fence has covered yet.
        struct Pending {
            at: u64,
            change: Change,
        }
        let mut unfenced: HashMap<Inode, Unfenced> = HashMap::new();
        let mut pending: Vec<Pending> = Vec::new();
        let records = parse(log, &bytes)?.0;
        let mut applied = Applied {
            records: records.len() as u64,
            ..Applied::default()
        };
        for (at, record) in records {
            match record {
                // The first since the last fence wins: a later writer saw this
                // writer's unfenced length, not the durable one.
                Record::Seen { inode, durable_len } => {
                    unfenced.entry(inode).or_insert(Unfenced {
                        durable_len,
                        pre_images: Vec::new(),
                    });
                }
                Record::PreImage {
                    inode,
                    offset,
                    data,
                } => {
                    if let Some(entry) = unfenced.get_mut(&inode) {
                        entry.pre_images.push((offset, data));
                    }
                }
                Record::Fenced { inode } => {
                    unfenced.remove(&inode);
                }
                Record::Entry(change) => pending.push(Pending { at, change }),
                Record::DirectoryFenced { inode, began } => {
                    pending
                        .retain(|pending| !(pending.at < began && pending.change.parent == inode));
                }
            }
        }

        // Newest first, so each change is undone from the state it left.
        let mut recreated = HashMap::new();
        for pending in pending.iter().rev() {
            if undo(root, &graveyard, &pending.change, &mut recreated)? {
                applied.entries += 1;
            }
        }

        let mut paths = HashMap::new();
        if lstat(root)?.is_some() {
            walk(root, &mut paths)?;
        }
        for (inode, entry) in unfenced {
            let Some(path) = paths.get(&inode) else {
                applied.unreachable += 1;
                continue;
            };
            let file = OpenOptions::new().write(true).open(path)?;
            file.set_len(entry.durable_len)?;
            // Newest first, so the oldest pre-image of each byte is the one left.
            for (offset, data) in entry.pre_images.iter().rev() {
                if *offset >= entry.durable_len {
                    continue;
                }
                let len = data.len().min((entry.durable_len - offset) as usize);
                file.write_all_at(&data[..len], *offset)?;
                applied.bytes += len as u64;
            }
            applied.files += 1;
        }
        std::fs::remove_file(log)?;
        remove_graveyard(&graveyard)?;
        Ok(applied)
    }

    fn remove_graveyard(graveyard: &Path) -> io::Result<()> {
        match std::fs::remove_dir_all(graveyard) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }

    /// Undo one change to a directory entry, if it was made. Whether it was.
    ///
    /// `recreated` maps each directory an `rmdir` undone here removed to the
    /// directory this made in its place.
    fn undo(
        root: &Path,
        graveyard: &Path,
        change: &Change,
        recreated: &mut HashMap<Inode, Inode>,
    ) -> io::Result<bool> {
        let at = |relative: &Path| {
            if relative.as_os_str().is_empty() {
                root.to_path_buf()
            } else {
                root.join(relative)
            }
        };
        let name = at(&change.name);
        let to = (change.kind == RENAME).then(|| at(&change.to));
        // Only in the directory the change was made in, found by inode. A
        // directory that is gone, or that is now another directory under the
        // same name, was removed durably, and every name in it is unreachable
        // whatever its entry says; one this `apply` recreated stands in for
        // the one it gives back. Found in review, twice: undoing by path alone
        // acted on whichever directory had the name by then, and trusting a
        // logged `rmdir` to say a directory was removed also trusted one the
        // kernel refused, or one its writer died before making. A rename
        // never crosses directories, so `to` is in the same one.
        let directory = name.parent().unwrap_or(root);
        let made_in = recreated
            .get(&change.parent)
            .copied()
            .unwrap_or(change.parent);
        match std::fs::metadata(directory) {
            Ok(found) if inode_of(&found) == made_in => {}
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
        let grave = || {
            change
                .grave
                .as_ref()
                .map(|grave| graveyard.join(grave))
                .ok_or_else(|| io::Error::other("a directory change with no grave"))
        };
        let found = lstat(&name)?;
        Ok(match change.kind {
            // Nothing was at the name when the change was logged, and any later
            // change at that name was in the same directory and undone first.
            CREATE | MKDIR => match found {
                None => false,
                Some(found) if found.is_dir() => {
                    std::fs::remove_dir_all(&name)?;
                    true
                }
                Some(_) => {
                    std::fs::remove_file(&name)?;
                    true
                }
            },
            LINK => match found {
                Some(found) if inode_of(&found) == change.subject => {
                    std::fs::remove_file(&name)?;
                    true
                }
                _ => false,
            },
            UNLINK => match found {
                None => {
                    std::fs::hard_link(grave()?, &name)?;
                    true
                }
                Some(_) => false,
            },
            RMDIR => match found {
                None => {
                    std::fs::create_dir(&name)?;
                    recreated.insert(change.subject, inode_of(&std::fs::metadata(&name)?));
                    true
                }
                Some(_) => false,
            },
            RENAME => {
                let to = to.expect("a rename has a destination");
                match (found, lstat(&to)?) {
                    (None, Some(moved)) if inode_of(&moved) == change.subject => {
                        std::fs::rename(&to, &name)?;
                        if change.grave.is_some() {
                            std::fs::hard_link(grave()?, &to)?;
                        }
                        true
                    }
                    _ => false,
                }
            }
            other => {
                return Err(io::Error::other(format!(
                    "unknown directory change {other}"
                )))
            }
        })
    }

    /// Every regular file under `dir`, by inode, at the first name found.
    fn walk(dir: &Path, paths: &mut HashMap<Inode, PathBuf>) -> io::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            let metadata = std::fs::symlink_metadata(&path)?;
            if metadata.is_dir() {
                walk(&path, paths)?;
            } else if metadata.is_file() {
                paths
                    .entry((metadata.dev(), metadata.ino()))
                    .or_insert(path);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn temp() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("j");
        (dir, path)
    }

    #[test]
    fn write_vectored_all_counts_bytes_and_verifies_position() {
        let (_dir, path) = temp();
        let mut file = File::options()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open");
        let counters = DurabilityCounters::default();

        let a = [1u8; 100];
        let b = [2u8; 156];
        let end = write_vectored_all(&mut file, &[IoSlice::new(&a), IoSlice::new(&b)], &counters)
            .expect("append");

        assert_eq!(end, 256);
        assert_eq!(counters.snapshot().bytes_written, 256);
        assert_eq!(counters.snapshot().fdatasync, 0, "append must not fence");
    }

    #[test]
    fn one_fence_per_group_is_observable() {
        let (_dir, path) = temp();
        let file = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open");
        let counters = DurabilityCounters::default();

        for _ in 0..7 {
            fdatasync(&file, &counters).expect("fence");
        }
        assert_eq!(counters.snapshot().fdatasync, 7);
    }

    #[test]
    fn preallocated_region_reads_back_as_zeros() {
        let (_dir, path) = temp();
        let file = File::options()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open");
        preallocate(&file, 8192).expect("fallocate");

        assert_eq!(file.metadata().expect("stat").len(), 8192);
        let mut buf = [0xAAu8; 64];
        pread_exact(&file, 4096, &mut buf).expect("read");
        assert!(
            buf.iter().all(|b| *b == 0),
            "the region past the write cursor must read as zeros, \
             which is what stops a tail scan cleanly"
        );
    }

    #[test]
    fn rename_noreplace_refuses_an_occupied_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let from = dir.path().join("a");
        let to = dir.path().join("b");
        std::fs::write(&from, b"new").expect("write");
        std::fs::write(&to, b"existing").expect("write");

        let err = rename_noreplace(&from, &to).expect_err("must refuse");
        assert_eq!(err.raw_os_error(), Some(libc_eexist()));

        let mut kept = String::new();
        File::open(&to)
            .expect("open")
            .read_to_string(&mut kept)
            .expect("read");
        assert_eq!(kept, "existing", "the destination must be untouched");
    }

    #[test]
    fn rename_replace_installs_over_an_existing_pointer() {
        let dir = tempfile::tempdir().expect("tempdir");
        let from = dir.path().join("CURRENT.tmp");
        let to = dir.path().join("CURRENT");
        std::fs::write(&from, b"new").expect("write");
        std::fs::write(&to, b"old").expect("write");

        rename_replace(&from, &to).expect("install");
        assert_eq!(std::fs::read(&to).expect("read"), b"new");
    }

    #[test]
    fn exclusive_lock_refuses_a_second_holder_without_waiting() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("LOCK");
        let a = File::options()
            .create(true)
            .write(true)
            .open(&path)
            .expect("open a");
        let b = File::options()
            .create(true)
            .write(true)
            .open(&path)
            .expect("open b");

        assert!(try_lock_exclusive(&a).expect("lock a"));
        assert!(
            !try_lock_exclusive(&b).expect("lock b"),
            "a second holder must be refused, not blocked"
        );
    }

    fn libc_eexist() -> i32 {
        17
    }
}

#[cfg(all(test, feature = "failpoints"))]
mod power_loss_tests {
    use super::*;
    use power_loss::Fences;
    use std::io::Seek;

    struct Machine {
        _dir: tempfile::TempDir,
        root: std::path::PathBuf,
        log: std::path::PathBuf,
        counters: DurabilityCounters,
    }

    /// A root holding one durable file, `f`, of eight `A`s, and a log beside it.
    fn machine() -> (Machine, File) {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().join("root");
        std::fs::create_dir(&root).expect("root");
        let path = root.join("f");
        std::fs::write(&path, b"AAAAAAAA").expect("durable content");
        let file = File::options()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open");
        let log = dir.path().join("root.power-loss");
        let machine = Machine {
            _dir: dir,
            root,
            log,
            counters: DurabilityCounters::default(),
        };
        (machine, file)
    }

    fn write_at(file: &mut File, offset: u64, bytes: &[u8], counters: &DurabilityCounters) {
        file.seek(SeekFrom::Start(offset)).expect("seek");
        write_vectored_all(file, &[IoSlice::new(bytes)], counters).expect("write");
    }

    fn content(machine: &Machine) -> Vec<u8> {
        std::fs::read(machine.root.join("f")).expect("read")
    }

    #[test]
    fn a_fenced_write_survives_and_an_unfenced_one_is_put_back() {
        let serial = serial();
        let (machine, mut file) = machine();
        power_loss::arm(&serial, &machine.log, &machine.root, Fences::Honoured).expect("arm");
        write_at(&mut file, 0, b"BBBB", &machine.counters);
        fdatasync(&file, &machine.counters).expect("fence");
        write_at(&mut file, 4, b"CCCCCCCC", &machine.counters);
        power_loss::disarm(&serial);
        assert_eq!(content(&machine), b"BBBBCCCCCCCC");

        let applied = power_loss::apply(&machine.root, &machine.log).expect("apply");
        assert_eq!(content(&machine), b"BBBBAAAA");
        assert_eq!(applied.files, 1);
        assert_eq!(applied.bytes, 4);
        assert!(!machine.log.exists(), "the log is consumed");
    }

    #[test]
    fn a_shrink_and_an_allocation_are_put_back() {
        let serial = serial();
        let (machine, file) = machine();
        power_loss::arm(&serial, &machine.log, &machine.root, Fences::Honoured).expect("arm");
        truncate(&file, 2, &machine.counters).expect("shrink");
        preallocate(&file, 16).expect("allocate");
        power_loss::disarm(&serial);
        assert_eq!(content(&machine).len(), 16);

        power_loss::apply(&machine.root, &machine.log).expect("apply");
        assert_eq!(content(&machine), b"AAAAAAAA");
    }

    #[test]
    fn ignoring_fences_puts_back_fenced_writes_too() {
        let serial = serial();
        let (machine, mut file) = machine();
        power_loss::arm(&serial, &machine.log, &machine.root, Fences::Ignored).expect("arm");
        write_at(&mut file, 0, b"BBBB", &machine.counters);
        fdatasync(&file, &machine.counters).expect("fence");
        power_loss::disarm(&serial);

        power_loss::apply(&machine.root, &machine.log).expect("apply");
        assert_eq!(content(&machine), b"AAAAAAAA");
    }

    /// The page cache outlives a writer that exits normally: a second writer
    /// sees the first one's unfenced bytes and length, and must not have them
    /// taken for durable.
    #[test]
    fn a_second_writer_does_not_move_what_was_durable() {
        let serial = serial();
        let (machine, mut file) = machine();
        power_loss::arm(&serial, &machine.log, &machine.root, Fences::Honoured)
            .expect("arm the first writer");
        write_at(&mut file, 0, b"BBBBBBBBBBBB", &machine.counters);
        power_loss::disarm(&serial);

        power_loss::arm(&serial, &machine.log, &machine.root, Fences::Honoured)
            .expect("arm the second writer");
        write_at(&mut file, 0, b"CCCC", &machine.counters);
        power_loss::disarm(&serial);

        power_loss::apply(&machine.root, &machine.log).expect("apply");
        assert_eq!(content(&machine), b"AAAAAAAA");
    }

    #[test]
    fn a_fence_by_a_later_writer_covers_an_earlier_one() {
        let serial = serial();
        let (machine, mut file) = machine();
        power_loss::arm(&serial, &machine.log, &machine.root, Fences::Honoured)
            .expect("arm the first writer");
        write_at(&mut file, 0, b"BBBB", &machine.counters);
        power_loss::disarm(&serial);

        power_loss::arm(&serial, &machine.log, &machine.root, Fences::Honoured)
            .expect("arm the second writer");
        fdatasync(&file, &machine.counters).expect("fence");
        power_loss::disarm(&serial);

        power_loss::apply(&machine.root, &machine.log).expect("apply");
        assert_eq!(content(&machine), b"BBBBAAAA");
    }

    /// A writer killed mid-record leaves a torn last record, which is where the
    /// log ends; everything before it still applies.
    #[test]
    fn a_torn_last_record_is_where_the_log_ends() {
        let serial = serial();
        let (machine, mut file) = machine();
        power_loss::arm(&serial, &machine.log, &machine.root, Fences::Honoured).expect("arm");
        write_at(&mut file, 0, b"BBBB", &machine.counters);
        power_loss::disarm(&serial);
        let mut log = File::options()
            .append(true)
            .open(&machine.log)
            .expect("the log");
        std::io::Write::write_all(&mut log, &[2, 0, 0, 0]).expect("a torn record");
        drop(log);

        power_loss::apply(&machine.root, &machine.log).expect("apply");
        assert_eq!(content(&machine), b"AAAAAAAA");
    }

    /// Found in review: a writer that arms after a torn record must not append
    /// behind it, or every later record is misread and a later fence is
    /// missed, putting back data that fence made durable.
    #[test]
    fn a_writer_after_a_torn_record_keeps_its_own_fence() {
        let serial = serial();
        let (machine, mut file) = machine();
        power_loss::arm(&serial, &machine.log, &machine.root, Fences::Honoured)
            .expect("arm the first writer");
        write_at(&mut file, 0, b"BBBB", &machine.counters);
        power_loss::disarm(&serial);
        let mut log = File::options()
            .append(true)
            .open(&machine.log)
            .expect("the log");
        std::io::Write::write_all(&mut log, &[2, 0, 0, 0]).expect("a torn record");
        drop(log);

        power_loss::arm(&serial, &machine.log, &machine.root, Fences::Honoured)
            .expect("arm the second writer");
        write_at(&mut file, 4, b"CCCC", &machine.counters);
        fdatasync(&file, &machine.counters).expect("fence");
        power_loss::disarm(&serial);

        power_loss::apply(&machine.root, &machine.log).expect("apply");
        assert_eq!(content(&machine), b"BBBBCCCC");
    }

    #[test]
    fn no_log_is_no_loss() {
        let (machine, _file) = machine();
        assert_eq!(
            power_loss::apply(&machine.root, &machine.log).expect("apply"),
            power_loss::Applied::default()
        );
        assert_eq!(content(&machine), b"AAAAAAAA");
    }

    #[test]
    fn an_unarmed_funnel_logs_nothing() {
        let serial = serial();
        power_loss::disarm(&serial);
        let (machine, mut file) = machine();
        write_at(&mut file, 0, b"BBBB", &machine.counters);
        assert!(!machine.log.exists());
    }

    // -- Directory entries ---------------------------------------------------

    fn arm(serial: &FaultSerial, machine: &Machine, fences: Fences) {
        power_loss::arm(serial, &machine.log, &machine.root, fences).expect("arm");
    }

    fn apply(machine: &Machine) -> power_loss::Applied {
        let applied = power_loss::apply(&machine.root, &machine.log).expect("apply");
        let mut graveyard = machine.log.clone().into_os_string();
        graveyard.push(".d");
        assert!(
            !std::path::Path::new(&graveyard).exists(),
            "the graveyard goes with the log"
        );
        applied
    }

    /// Everything under the root, relative to it, directories with a slash.
    fn names(machine: &Machine) -> Vec<String> {
        fn walk(root: &Path, dir: &Path, names: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("read_dir") {
                let path = entry.expect("entry").path();
                let name = path.strip_prefix(root).unwrap().display().to_string();
                if path.is_dir() {
                    names.push(format!("{name}/"));
                    walk(root, &path, names);
                } else {
                    names.push(name);
                }
            }
        }
        let mut names = Vec::new();
        if machine.root.exists() {
            walk(&machine.root, &machine.root, &mut names);
        }
        names.sort();
        names
    }

    fn read(machine: &Machine, name: &str) -> Vec<u8> {
        std::fs::read(machine.root.join(name)).expect("read")
    }

    #[test]
    fn an_unfenced_creation_is_lost_and_a_fenced_one_kept() {
        let serial = serial();
        let (machine, _file) = machine();
        arm(&serial, &machine, Fences::Honoured);
        create_new_nofollow(&machine.root.join("kept"))
            .expect("create")
            .expect("a new name");
        fsync_dir(&machine.root, &machine.counters).expect("fence");
        create_new_nofollow(&machine.root.join("lost"))
            .expect("create")
            .expect("a new name");
        create_dir(&machine.root.join("lost-directory")).expect("mkdir");
        power_loss::disarm(&serial);

        let applied = apply(&machine);
        assert_eq!(names(&machine), ["f", "kept"]);
        assert_eq!(applied.entries, 2);
    }

    #[test]
    fn an_unfenced_rename_is_undone() {
        let serial = serial();
        let (machine, _file) = machine();
        std::fs::write(machine.root.join("tmp"), b"new").expect("durable temporary");
        arm(&serial, &machine, Fences::Honoured);
        rename_noreplace(&machine.root.join("tmp"), &machine.root.join("final")).expect("rename");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["f", "tmp"]);
        assert_eq!(read(&machine, "tmp"), b"new");
    }

    #[test]
    fn an_unfenced_replacing_rename_gives_back_what_it_replaced() {
        let serial = serial();
        let (machine, _file) = machine();
        std::fs::write(machine.root.join("CURRENT"), b"old").expect("durable pointer");
        std::fs::write(machine.root.join("CURRENT.tmp"), b"new").expect("durable temporary");
        arm(&serial, &machine, Fences::Honoured);
        rename_replace(
            &machine.root.join("CURRENT.tmp"),
            &machine.root.join("CURRENT"),
        )
        .expect("install");
        power_loss::disarm(&serial);
        assert_eq!(read(&machine, "CURRENT"), b"new");

        apply(&machine);
        assert_eq!(names(&machine), ["CURRENT", "CURRENT.tmp", "f"]);
        assert_eq!(read(&machine, "CURRENT"), b"old");
        assert_eq!(read(&machine, "CURRENT.tmp"), b"new");
    }

    #[test]
    fn a_fenced_replacing_rename_is_kept() {
        let serial = serial();
        let (machine, _file) = machine();
        std::fs::write(machine.root.join("CURRENT"), b"old").expect("durable pointer");
        std::fs::write(machine.root.join("CURRENT.tmp"), b"new").expect("durable temporary");
        arm(&serial, &machine, Fences::Honoured);
        rename_replace(
            &machine.root.join("CURRENT.tmp"),
            &machine.root.join("CURRENT"),
        )
        .expect("install");
        fsync_dir(&machine.root, &machine.counters).expect("fence");
        power_loss::disarm(&serial);

        assert_eq!(apply(&machine).entries, 0);
        assert_eq!(names(&machine), ["CURRENT", "f"]);
        assert_eq!(read(&machine, "CURRENT"), b"new");
    }

    /// The file comes back as the same inode, so the log's account of its
    /// contents still applies to it.
    #[test]
    fn an_unfenced_unlink_gives_the_file_back_with_its_durable_contents() {
        let serial = serial();
        let (machine, mut file) = machine();
        arm(&serial, &machine, Fences::Honoured);
        write_at(&mut file, 0, b"BBBB", &machine.counters);
        unlink(&machine.root.join("f")).expect("unlink");
        power_loss::disarm(&serial);

        let applied = apply(&machine);
        assert_eq!(names(&machine), ["f"]);
        assert_eq!(content(&machine), b"AAAAAAAA");
        assert_eq!((applied.entries, applied.files), (1, 1));
    }

    #[test]
    fn a_fenced_unlink_is_kept() {
        let serial = serial();
        let (machine, _file) = machine();
        arm(&serial, &machine, Fences::Honoured);
        unlink(&machine.root.join("f")).expect("unlink");
        fsync_dir(&machine.root, &machine.counters).expect("fence");
        power_loss::disarm(&serial);

        apply(&machine);
        assert!(names(&machine).is_empty());
    }

    #[test]
    fn an_unfenced_link_is_undone() {
        let serial = serial();
        let (machine, _file) = machine();
        arm(&serial, &machine, Fences::Honoured);
        link_noreplace(&machine.root.join("f"), &machine.root.join("g")).expect("link");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["f"]);
        assert_eq!(content(&machine), b"AAAAAAAA");
    }

    /// A directory whose own entry was never fenced takes everything in it,
    /// however durable that was inside it.
    #[test]
    fn an_unfenced_directory_takes_what_was_fenced_inside_it() {
        let serial = serial();
        let (machine, _file) = machine();
        arm(&serial, &machine, Fences::Honoured);
        let directory = machine.root.join("d");
        create_directory_nofollow(&directory)
            .expect("mkdir")
            .expect("a directory");
        let mut inner = create_new_nofollow(&directory.join("x"))
            .expect("create")
            .expect("a new name");
        write_at(&mut inner, 0, b"xx", &machine.counters);
        fdatasync(&inner, &machine.counters).expect("fence the data");
        fsync_dir(&directory, &machine.counters).expect("fence the inner entry");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["f"]);
    }

    #[test]
    fn an_unfenced_rmdir_is_undone() {
        let serial = serial();
        let (machine, _file) = machine();
        std::fs::create_dir(machine.root.join("d")).expect("durable directory");
        arm(&serial, &machine, Fences::Honoured);
        remove_dir(&machine.root.join("d")).expect("rmdir");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["d/", "f"]);
    }

    /// Each directory `create_dir_all` makes is its own entry: the deepest is
    /// durable once its parent is fenced, and is still lost with that parent.
    #[test]
    fn create_dir_all_logs_every_directory_it_makes() {
        let serial = serial();
        let (machine, _file) = machine();
        arm(&serial, &machine, Fences::Honoured);
        create_dir_all(&machine.root.join("a/b/c")).expect("mkdir -p");
        fsync_dir(&machine.root.join("a/b"), &machine.counters).expect("fence c");
        power_loss::disarm(&serial);

        let applied = apply(&machine);
        assert_eq!(names(&machine), ["f"]);
        assert_eq!(
            applied.entries, 2,
            "a and b were undone; c was durable in b"
        );
    }

    #[test]
    fn a_fence_on_another_directory_covers_nothing_here() {
        let serial = serial();
        let (machine, _file) = machine();
        std::fs::create_dir(machine.root.join("a")).expect("durable directory");
        std::fs::create_dir(machine.root.join("b")).expect("durable directory");
        arm(&serial, &machine, Fences::Honoured);
        create_new_nofollow(&machine.root.join("a/x"))
            .expect("create")
            .expect("a new name");
        fsync_dir(&machine.root.join("b"), &machine.counters).expect("fence b");
        fsync_dir(&machine.root, &machine.counters).expect("fence the root");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["a/", "b/", "f"]);
    }

    #[test]
    fn a_fence_by_descriptor_covers_like_a_fence_by_name() {
        let serial = serial();
        let (machine, _file) = machine();
        arm(&serial, &machine, Fences::Honoured);
        create_new_nofollow(&machine.root.join("x"))
            .expect("create")
            .expect("a new name");
        let root = File::open(&machine.root).expect("open the root");
        fsync_dir_fd(&root, &machine.counters).expect("fence");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["f", "x"]);
    }

    /// A change made while a directory fsync runs may have missed it, so the
    /// fsync's record covers only what was logged before it began.
    #[test]
    fn a_fence_that_began_before_a_change_does_not_cover_it() {
        let serial = serial();
        let (machine, _file) = machine();
        arm(&serial, &machine, Fences::Honoured);
        let root = File::open(&machine.root).expect("open the root");
        power_loss::directory_fence(&root, || {
            create_new_nofollow(&machine.root.join("during"))
                .expect("create")
                .expect("a new name");
            root.sync_all()
        })
        .expect("fence");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["f"]);
    }

    /// The store makes neither, and the model would undo either wrongly, so it
    /// refuses both before the rename runs.
    #[test]
    fn a_rename_between_directories_or_of_a_directory_is_refused() {
        let serial = serial();
        let (machine, _file) = machine();
        std::fs::create_dir(machine.root.join("a")).expect("durable directory");
        std::fs::create_dir(machine.root.join("b")).expect("durable directory");
        std::fs::write(machine.root.join("a/x"), b"x").expect("durable file");
        arm(&serial, &machine, Fences::Honoured);
        rename_noreplace(&machine.root.join("a/x"), &machine.root.join("b/x"))
            .expect_err("between directories");
        rename_noreplace(&machine.root.join("a"), &machine.root.join("c"))
            .expect_err("a directory");
        power_loss::disarm(&serial);

        assert_eq!(apply(&machine).records, 0);
        assert_eq!(names(&machine), ["a/", "a/x", "b/", "f"]);
    }

    /// Found in review. The old `d`'s unlink was never fenced, but `d`'s own
    /// removal was, so nothing of the old `d` may come back into the new one.
    #[test]
    fn a_recreated_directory_does_not_receive_the_old_ones_files() {
        let serial = serial();
        let (machine, _file) = machine();
        let d = machine.root.join("d");
        std::fs::create_dir(&d).expect("durable directory");
        std::fs::write(d.join("y"), b"old").expect("durable file");
        arm(&serial, &machine, Fences::Honoured);
        unlink(&d.join("y")).expect("unlink, unfenced in the old d");
        remove_dir(&d).expect("rmdir");
        fsync_dir(&machine.root, &machine.counters).expect("the rmdir is durable");
        create_dir(&d).expect("mkdir again");
        fsync_dir(&machine.root, &machine.counters).expect("the new d is durable");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["d/", "f"]);
    }

    /// Found in review. Every step of the new `x` is fenced; only the old
    /// `d`'s history is not, and undoing it must not reach the new `x`.
    #[test]
    fn a_fenced_file_in_a_recreated_directory_survives() {
        let serial = serial();
        let (machine, _file) = machine();
        let d = machine.root.join("d");
        std::fs::create_dir(&d).expect("durable directory");
        arm(&serial, &machine, Fences::Honoured);
        create_new_nofollow(&d.join("x"))
            .expect("create")
            .expect("a new name");
        unlink(&d.join("x")).expect("unlink");
        remove_dir(&d).expect("rmdir");
        fsync_dir(&machine.root, &machine.counters).expect("the rmdir is durable");
        create_dir(&d).expect("mkdir again");
        fsync_dir(&machine.root, &machine.counters).expect("the new d is durable");
        let mut x = create_new_nofollow(&d.join("x"))
            .expect("create")
            .expect("a new name");
        write_at(&mut x, 0, b"new", &machine.counters);
        fdatasync(&x, &machine.counters).expect("fence the data");
        fsync_dir(&d, &machine.counters).expect("fence the entry");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["d/", "d/x", "f"]);
        assert_eq!(read(&machine, "d/x"), b"new");
    }

    /// Found in review: an `rmdir` the kernel refuses is still logged, and a
    /// fence on its parent covers the record. That must not stand for the
    /// directory's removal, or the unfenced change inside it survives.
    #[test]
    fn a_refused_rmdir_does_not_take_the_changes_inside_it() {
        let serial = serial();
        let (machine, _file) = machine();
        let d = machine.root.join("d");
        std::fs::create_dir(&d).expect("durable directory");
        arm(&serial, &machine, Fences::Honoured);
        create_new_nofollow(&d.join("x"))
            .expect("create")
            .expect("a new name");
        let error = remove_dir(&d).expect_err("a directory with a file in it");
        assert_eq!(error.raw_os_error(), Some(libc::ENOTEMPTY));
        fsync_dir(&machine.root, &machine.counters).expect("fence the parent only");
        power_loss::disarm(&serial);

        let applied = apply(&machine);
        assert_eq!(names(&machine), ["d/", "f"], "{applied:?}");
        assert_eq!(applied.entries, 1);
    }

    /// The same, for a writer killed between logging an `rmdir` and making it.
    #[test]
    fn an_rmdir_logged_but_never_made_does_not_take_the_changes_inside_it() {
        let serial = serial();
        let (machine, _file) = machine();
        let d = machine.root.join("d");
        std::fs::create_dir(&d).expect("durable directory");
        arm(&serial, &machine, Fences::Honoured);
        create_new_nofollow(&d.join("x"))
            .expect("create")
            .expect("a new name");
        power_loss::entry(Entry::Rmdir(&d), || Ok(())).expect("logged");
        fsync_dir(&machine.root, &machine.counters).expect("fence the parent only");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["d/", "f"]);
    }

    /// A directory the power loss gives back is made again, as a new inode,
    /// and the older changes inside it must still be undone there.
    #[test]
    fn an_unfenced_rmdir_gives_back_what_was_unlinked_inside_it() {
        let serial = serial();
        let (machine, _file) = machine();
        let d = machine.root.join("d");
        std::fs::create_dir(&d).expect("durable directory");
        std::fs::write(d.join("y"), b"y").expect("durable file");
        arm(&serial, &machine, Fences::Honoured);
        unlink(&d.join("y")).expect("unlink");
        remove_dir(&d).expect("rmdir");
        power_loss::disarm(&serial);

        assert_eq!(apply(&machine).entries, 2);
        assert_eq!(names(&machine), ["d/", "d/y", "f"]);
        assert_eq!(read(&machine, "d/y"), b"y");
    }

    /// The root's own entry is in the directory that holds it, and a fence
    /// there keeps it.
    #[test]
    fn a_root_fenced_in_its_parent_is_kept() {
        let serial = serial();
        let (machine, _file) = machine();
        std::fs::remove_dir_all(&machine.root).expect("no root yet");
        arm(&serial, &machine, Fences::Honoured);
        create_dir_all(&machine.root).expect("the root");
        let parent = machine.root.parent().expect("a parent");
        fsync_dir(parent, &machine.counters).expect("fence the root's entry");
        power_loss::disarm(&serial);

        apply(&machine);
        assert!(machine.root.is_dir());
    }

    /// Found in review: a writer killed in the middle of a directory change's
    /// record. The next writer's arm cuts it, and its own fence still covers
    /// what came before.
    #[test]
    fn a_torn_directory_change_is_cut_by_the_next_writer() {
        let serial = serial();
        let (machine, _file) = machine();
        arm(&serial, &machine, Fences::Honoured);
        create_new_nofollow(&machine.root.join("x"))
            .expect("create")
            .expect("a new name");
        power_loss::disarm(&serial);
        // An ENTRY record that ends inside its name.
        let mut torn = vec![5u8];
        torn.extend([0u8; 16]);
        torn.push(1);
        torn.extend([0u8; 16]);
        torn.extend(5u32.to_le_bytes());
        torn.extend(b"ab");
        let mut log = File::options()
            .append(true)
            .open(&machine.log)
            .expect("the log");
        std::io::Write::write_all(&mut log, &torn).expect("a torn record");
        drop(log);

        arm(&serial, &machine, Fences::Honoured);
        create_new_nofollow(&machine.root.join("y"))
            .expect("create")
            .expect("a new name");
        fsync_dir(&machine.root, &machine.counters).expect("fence");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["f", "x", "y"]);
    }

    /// Found in review: the lock discipline the fence-begin rule rests on. A
    /// fence that starts while a change is logged but not yet made must wait
    /// for the change, so its sync can only run once the change is on disk.
    #[test]
    fn a_fence_cannot_slip_between_a_record_and_its_change() {
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        use std::sync::{Arc, Barrier};
        let serial = serial();
        let (machine, _file) = machine();
        arm(&serial, &machine, Fences::Honoured);
        let made = Arc::new(AtomicBool::new(false));
        let logged = Arc::new(Barrier::new(2));
        let x = machine.root.join("x");
        let writer = {
            let (made, logged, x) = (made.clone(), logged.clone(), x.clone());
            std::thread::spawn(move || {
                power_loss::entry(Entry::Create(&x), || {
                    logged.wait();
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    std::fs::write(&x, b"x")?;
                    made.store(true, SeqCst);
                    Ok(())
                })
                .expect("create");
            })
        };
        logged.wait();
        let root = File::open(&machine.root).expect("open the root");
        let mut made_before_the_sync = None;
        power_loss::directory_fence(&root, || {
            made_before_the_sync = Some(made.load(SeqCst));
            root.sync_all()
        })
        .expect("fence");
        writer.join().expect("the writer");
        power_loss::disarm(&serial);

        assert_eq!(
            made_before_the_sync,
            Some(true),
            "the fence's sync began between the change's record and the change"
        );
        apply(&machine);
        assert_eq!(names(&machine), ["f", "x"]);
    }

    /// A change the kernel refuses changed nothing, so it is never undone.
    #[test]
    fn a_refused_change_is_not_undone() {
        let serial = serial();
        let (machine, _file) = machine();
        std::fs::write(machine.root.join("g"), b"g").expect("durable file");
        arm(&serial, &machine, Fences::Honoured);
        let f = machine.root.join("f");
        let g = machine.root.join("g");
        rename_noreplace(&f, &g).expect_err("a taken name");
        link_noreplace(&f, &g).expect_err("a taken name");
        assert!(create_new_nofollow(&g).expect("create").is_none());
        create_dir(&g).expect_err("a taken name");
        power_loss::disarm(&serial);

        assert_eq!(apply(&machine).entries, 0);
        assert_eq!(names(&machine), ["f", "g"]);
        assert_eq!(read(&machine, "g"), b"g");
    }

    /// A writer killed between logging a change and making it: the record is
    /// there and the change is not, and `apply` must see that.
    #[test]
    fn a_change_logged_but_never_made_is_not_undone() {
        let serial = serial();
        let (machine, _file) = machine();
        std::fs::write(machine.root.join("tmp"), b"tmp").expect("durable file");
        arm(&serial, &machine, Fences::Honoured);
        let f = machine.root.join("f");
        let tmp = machine.root.join("tmp");
        let never = |entry: Entry<'_>| power_loss::entry(entry, || Ok(())).expect("logged");
        never(Entry::Unlink(&f));
        never(Entry::Rename {
            from: &tmp,
            to: &f,
            replace: true,
        });
        never(Entry::Link {
            existing: &f,
            new: &machine.root.join("g"),
        });
        never(Entry::Create(&machine.root.join("h")));
        power_loss::disarm(&serial);

        assert_eq!(apply(&machine).entries, 0);
        assert_eq!(names(&machine), ["f", "tmp"]);
        assert_eq!(content(&machine), b"AAAAAAAA");
    }

    #[test]
    fn entries_outside_the_root_are_not_modelled() {
        let serial = serial();
        let (machine, _file) = machine();
        let outside = machine.root.parent().expect("a parent").join("outside");
        arm(&serial, &machine, Fences::Honoured);
        create_new_nofollow(&outside)
            .expect("create")
            .expect("a new name");
        power_loss::disarm(&serial);

        assert_eq!(apply(&machine).entries, 0);
        assert!(outside.exists());
    }

    /// The model is armed for one root, so another test's writes elsewhere in
    /// the same process are not its business.
    #[test]
    fn writes_outside_the_root_are_not_modelled() {
        let serial = serial();
        let (machine, _file) = machine();
        let outside = machine.root.parent().expect("a parent").join("outside");
        std::fs::write(&outside, b"durable").expect("a file outside the root");
        let mut file = File::options()
            .read(true)
            .write(true)
            .open(&outside)
            .expect("open");
        arm(&serial, &machine, Fences::Honoured);
        write_at(&mut file, 0, b"unfenced", &machine.counters);
        fdatasync(&file, &machine.counters).expect("fence");
        power_loss::disarm(&serial);

        assert_eq!(apply(&machine).records, 0);
    }

    /// A test that panics while armed cannot disarm, so the next to take the
    /// token must not inherit its model.
    #[test]
    fn taking_the_serial_token_disarms_the_model() {
        let (machine, mut file) = machine();
        {
            let serial = serial();
            arm(&serial, &machine, Fences::Honoured);
        }
        let _serial = serial();
        write_at(&mut file, 0, b"BBBB", &machine.counters);

        assert_eq!(apply(&machine).records, 0);
        assert_eq!(content(&machine), b"BBBBAAAA");
    }

    /// The self-test mode: file fences hold, directory fences do not.
    #[test]
    fn ignoring_directory_fences_keeps_fenced_data() {
        let serial = serial();
        let (machine, mut file) = machine();
        arm(&serial, &machine, Fences::DirectoriesIgnored);
        create_new_nofollow(&machine.root.join("x"))
            .expect("create")
            .expect("a new name");
        fsync_dir(&machine.root, &machine.counters).expect("fence");
        write_at(&mut file, 0, b"BBBB", &machine.counters);
        fdatasync(&file, &machine.counters).expect("fence");
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(names(&machine), ["f"]);
        assert_eq!(content(&machine), b"BBBBAAAA");
    }

    /// The root's own entry is in its parent, and modelled like any other.
    #[test]
    fn an_unfenced_root_is_lost_with_everything_in_it() {
        let serial = serial();
        let (machine, _file) = machine();
        std::fs::remove_dir_all(&machine.root).expect("no root yet");
        arm(&serial, &machine, Fences::Honoured);
        create_dir_all(&machine.root).expect("the root");
        create_new_nofollow(&machine.root.join("x"))
            .expect("create")
            .expect("a new name");
        fsync_dir(&machine.root, &machine.counters).expect("fence inside the root");
        power_loss::disarm(&serial);

        apply(&machine);
        assert!(!machine.root.exists());
    }

    /// A later writer of the same log numbers its graves after the earlier
    /// writer's, and the two unlinks of one name undo in order.
    #[test]
    fn a_second_writer_keeps_its_own_graves() {
        let serial = serial();
        let (machine, _file) = machine();
        let f = machine.root.join("f");
        arm(&serial, &machine, Fences::Honoured);
        unlink(&f).expect("unlink the durable file");
        power_loss::disarm(&serial);

        arm(&serial, &machine, Fences::Honoured);
        let mut again = create_new_nofollow(&f)
            .expect("create")
            .expect("a new name");
        write_at(&mut again, 0, b"new", &machine.counters);
        unlink(&f).expect("unlink the new file");
        power_loss::disarm(&serial);

        assert_eq!(apply(&machine).entries, 3);
        assert_eq!(names(&machine), ["f"]);
        assert_eq!(content(&machine), b"AAAAAAAA");
    }

    #[test]
    fn create_truncated_logs_what_it_cuts() {
        let serial = serial();
        let (machine, _file) = machine();
        arm(&serial, &machine, Fences::Honoured);
        let file = create_truncated(&machine.root.join("f")).expect("open");
        assert_eq!(file.metadata().expect("stat").len(), 0);
        power_loss::disarm(&serial);

        apply(&machine);
        assert_eq!(content(&machine), b"AAAAAAAA");
    }
}
