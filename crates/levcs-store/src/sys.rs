//! The single funnel for every durability-relevant syscall.
//!
//! Lead-owned (scope 2.3). Nothing else in this crate may call
//! `File::sync_all`, `File::sync_data`, `std::fs::rename`, `remove_file`, or
//! open a directory descriptor. Two reasons:
//!
//! 1. `DurabilityCounters` turns "exactly one fence per group" and "no
//!    per-object fsync" into assertions against observed counts rather than
//!    claims about the code (Phase 1 exit criteria).
//! 2. Fault injection (short write, `ENOSPC`, `EIO` on fence, `EIO` on read)
//!    has exactly one place to live, so the crash matrix runs unprivileged in
//!    CI without `dm-flakey`.
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
    /// delivered to whichever test ran next.
    pub fn serial() -> FaultSerial {
        let guard = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *ARMED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
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
    File::open(path)?.sync_all()
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
    directory.sync_all()
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
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        from,
        rustix::fs::CWD,
        to,
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))
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
    std::fs::rename(from, to)
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
    std::fs::hard_link(existing, new_name)
}

pub(crate) fn unlink(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path)
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
    match rustix::fs::open(
        path,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::from_raw_mode(0o644),
    ) {
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
    let fd = match rustix::fs::open(
        path,
        OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::from_raw_mode(0o644),
    ) {
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
    match rustix::fs::mkdir(path, Mode::from_raw_mode(0o755)) {
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

/// A userspace model of the page cache a power loss discards: audit finding
/// S2, contract review 2026-11-02-C.
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
/// The log lives outside the store root and outlives a writer, as a machine's
/// page cache does: a writer that exits normally leaves its unfenced writes
/// logged for the next writer to add to, and `apply` is the power loss and the
/// reboot together, consuming the log.
///
/// Each record is appended before the write it describes, so a writer killed at
/// any instant leaves a log `apply` can use, and a torn last record is ignored.
/// A fence is logged after it returns: a writer killed between the two is
/// treated as unfenced, which is pessimistic only about work it had not yet
/// acknowledged.
///
/// Directory entries are not modelled: a missing directory fsync is still
/// invisible to the crash suites.
#[cfg(feature = "failpoints")]
pub mod power_loss {
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::os::unix::fs::{FileExt, MetadataExt};
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, MutexGuard};

    use super::FaultSerial;

    const MAGIC: &[u8; 8] = b"LVPWRLS1";
    const SEEN: u8 = 1;
    const PRE_IMAGE: u8 = 2;
    const FENCED: u8 = 3;
    const RECORD_HEAD: usize = 1 + 8 + 8;

    /// A file by device and inode, which outlives its names.
    type Inode = (u64, u64);

    struct Model {
        log: File,
        honour_fences: bool,
        /// Files this process changed since their last fence.
        dirty: HashMap<Inode, Dirty>,
    }

    struct Dirty {
        /// The length that was durable when this process first changed it.
        durable_len: u64,
        /// Ranges, half-open, whose pre-image this process has logged.
        logged: Vec<(u64, u64)>,
    }

    static MODEL: Mutex<Option<Model>> = Mutex::new(None);

    fn model() -> MutexGuard<'static, Option<Model>> {
        MODEL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Start modelling, appending to `log`. With `honour_fences` false the model
    /// ignores every fence: the self-test that a crash suite catches a missing
    /// one.
    pub fn arm(_serial: &FaultSerial, log: &Path, honour_fences: bool) -> io::Result<()> {
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
        *model() = Some(Model {
            log: file,
            honour_fences,
            dirty: HashMap::new(),
        });
        Ok(())
    }

    pub fn disarm(_serial: &FaultSerial) {
        *model() = None;
    }

    fn identify(file: &File) -> io::Result<(Inode, u64)> {
        let metadata = file.metadata()?;
        Ok(((metadata.dev(), metadata.ino()), metadata.len()))
    }

    /// One record, in one write.
    fn record(log: &mut File, tag: u8, inode: Inode, body: &[u8]) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(RECORD_HEAD + body.len());
        bytes.push(tag);
        bytes.extend_from_slice(&inode.0.to_le_bytes());
        bytes.extend_from_slice(&inode.1.to_le_bytes());
        bytes.extend_from_slice(body);
        log.write_all(&bytes)
    }

    /// Log the pre-image of whatever part of `[from, to)` lies within the
    /// durable length and has not been logged since the file's last fence. The
    /// first change since a fence also logs that durable length.
    fn log_pre_image(model: &mut Model, file: &File, from: u64, to: u64) -> io::Result<()> {
        let (inode, len) = identify(file)?;
        let Model { log, dirty, .. } = model;
        let entry = match dirty.entry(inode) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                record(log, SEEN, inode, &len.to_le_bytes())?;
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
            record(log, PRE_IMAGE, inode, &body)?;
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
        if !model.honour_fences {
            return Ok(());
        }
        let (inode, _) = identify(file)?;
        model.dirty.remove(&inode);
        record(&mut model.log, FENCED, inode, &[])
    }

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
    }

    /// A log's whole records, and the length they end at. A torn last record
    /// is where a writer died, so it ends the log: `apply` ignores it and `arm`
    /// cuts it off before appending.
    fn parse(log: &Path, bytes: &[u8]) -> io::Result<(Vec<Record>, usize)> {
        if bytes.get(..MAGIC.len()) != Some(&MAGIC[..]) {
            return Err(io::Error::other(format!(
                "{} is not a power-loss log",
                log.display()
            )));
        }
        let u64_at = |at: usize| -> Option<u64> {
            bytes
                .get(at..at.checked_add(8)?)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        };
        let mut records = Vec::new();
        let mut at = MAGIC.len();
        while at + RECORD_HEAD <= bytes.len() {
            let inode = (u64_at(at + 1).unwrap(), u64_at(at + 9).unwrap());
            let body = at + RECORD_HEAD;
            let (record, next) = match bytes[at] {
                SEEN => {
                    let Some(durable_len) = u64_at(body) else {
                        break;
                    };
                    (Record::Seen { inode, durable_len }, body + 8)
                }
                PRE_IMAGE => {
                    let (Some(offset), Some(len)) = (u64_at(body), u64_at(body + 8)) else {
                        break;
                    };
                    let data_at = body + 16;
                    let Some(data) = usize::try_from(len)
                        .ok()
                        .and_then(|len| bytes.get(data_at..data_at.checked_add(len)?))
                    else {
                        break;
                    };
                    let next = data_at + data.len();
                    (
                        Record::PreImage {
                            inode,
                            offset,
                            data: data.to_vec(),
                        },
                        next,
                    )
                }
                FENCED => (Record::Fenced { inode }, body),
                other => {
                    return Err(io::Error::other(format!(
                        "{}: unknown power-loss record {other} at byte {at}",
                        log.display()
                    )))
                }
            };
            records.push(record);
            at = next;
        }
        Ok((records, at))
    }

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
    }

    /// The power loss: put back, in the files under `root`, everything the log
    /// says no fence covered, then remove the log. No log is no loss.
    pub fn apply(root: &Path, log: &Path) -> io::Result<Applied> {
        let bytes = match std::fs::read(log) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Applied::default()),
            Err(error) => return Err(error),
        };
        struct Unfenced {
            durable_len: u64,
            pre_images: Vec<(u64, Vec<u8>)>,
        }
        let mut unfenced: HashMap<Inode, Unfenced> = HashMap::new();
        for record in parse(log, &bytes)?.0 {
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
            }
        }

        let mut paths = HashMap::new();
        walk(root, &mut paths)?;
        let mut applied = Applied::default();
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
        Ok(applied)
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
        power_loss::arm(&serial, &machine.log, true).expect("arm");
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
        power_loss::arm(&serial, &machine.log, true).expect("arm");
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
        power_loss::arm(&serial, &machine.log, false).expect("arm");
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
        power_loss::arm(&serial, &machine.log, true).expect("arm the first writer");
        write_at(&mut file, 0, b"BBBBBBBBBBBB", &machine.counters);
        power_loss::disarm(&serial);

        power_loss::arm(&serial, &machine.log, true).expect("arm the second writer");
        write_at(&mut file, 0, b"CCCC", &machine.counters);
        power_loss::disarm(&serial);

        power_loss::apply(&machine.root, &machine.log).expect("apply");
        assert_eq!(content(&machine), b"AAAAAAAA");
    }

    #[test]
    fn a_fence_by_a_later_writer_covers_an_earlier_one() {
        let serial = serial();
        let (machine, mut file) = machine();
        power_loss::arm(&serial, &machine.log, true).expect("arm the first writer");
        write_at(&mut file, 0, b"BBBB", &machine.counters);
        power_loss::disarm(&serial);

        power_loss::arm(&serial, &machine.log, true).expect("arm the second writer");
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
        power_loss::arm(&serial, &machine.log, true).expect("arm");
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
        power_loss::arm(&serial, &machine.log, true).expect("arm the first writer");
        write_at(&mut file, 0, b"BBBB", &machine.counters);
        power_loss::disarm(&serial);
        let mut log = File::options()
            .append(true)
            .open(&machine.log)
            .expect("the log");
        std::io::Write::write_all(&mut log, &[2, 0, 0, 0]).expect("a torn record");
        drop(log);

        power_loss::arm(&serial, &machine.log, true).expect("arm the second writer");
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
}
