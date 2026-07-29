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
    file.sync_data()
}

/// Make a directory entry durable. Required after every create, rename, and
/// unlink that recovery depends on.
pub(crate) fn fsync_dir(path: &Path, counters: &DurabilityCounters) -> io::Result<()> {
    if take_fault_if(|f| matches!(f, Fault::DirSyncEio)).is_some() {
        counters.fsync_dir.fetch_add(1, Relaxed);
        return Err(eio("directory fsync"));
    }
    counters.fsync_dir.fetch_add(1, Relaxed);
    File::open(path)?.sync_all()
}

// ---------------------------------------------------------------------------
// Naming
// ---------------------------------------------------------------------------

/// `renameat2(RENAME_NOREPLACE)`. For every name that must never overwrite:
/// new manifests, segments, checkpoints, index runs, and migration/restore
/// siblings. Plan §9 forbids a copy fallback.
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

/// Plain atomic replacing rename. Exactly one legitimate call site: the
/// `CURRENT.tmp` -> `CURRENT` pointer install of scope 3.5, which by
/// definition replaces. Every other site uses `rename_noreplace`.
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
// Both of these exist for startup state 1, where the store has to look at, and
// then write into, a directory it has not established is its own. Plain
// `File::open` and `File::options().create(true).truncate(true)` both traverse a
// symlink at the final component, so either one at a name an operator can
// occupy is a write to a path outside the root. `open`/`stat` are therefore not
// available on that path at all; these are.

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
    use rustix::fs::{FileType, Mode, OFlags};
    let fd = match rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(rustix::io::Errno::NOENT) | Err(rustix::io::Errno::NOTDIR) => return Ok(None),
        // `O_NOFOLLOW` on a symlink is `ELOOP` on Linux and `EMLINK` on some
        // BSDs. Both mean "the final component is a symlink", which is exactly
        // the answer this function is being asked for.
        Err(rustix::io::Errno::LOOP) | Err(rustix::io::Errno::MLINK) => return Ok(None),
        Err(e) => return Err(io::Error::from_raw_os_error(e.raw_os_error())),
    };
    let file = File::from(fd);
    let stat =
        rustix::fs::fstat(&file).map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
        Ok(Some(file))
    } else {
        Ok(None)
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
