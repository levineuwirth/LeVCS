//! The repository lock: one exclusive advisory lock on `.levcs/lock`.
//!
//! Every command that mutates the index, a ref, or the working tree holds it
//! from its first read of repository state through its last write. Without
//! it, two commits read the same parent, both write their commit, and the
//! later ref write silently discards the earlier commit while both report
//! success; two `track` calls each rewrite the whole index and the slower one
//! erases the other's entry. A repository written by several sessions at once
//! needs those operations to be serial, and this is what makes them so.
//!
//! The lock is `flock(2)` through `std::fs::File::lock`. It is released when
//! the guard is dropped or the process exits, including by a crash, so a dead
//! holder never wedges the repository. It serializes repository mutations
//! only: it says nothing about who edited which bytes of a working-tree file
//! that several sessions are writing at once.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

use crate::error::{Error, IoExt, Result};

/// Not `lock`: before this lock existed, the advised workaround was to wrap
/// each call as `flock .levcs/lock levcs …`. A binary that locked the same
/// file would wait forever on its own wrapper. On a different file, a
/// leftover wrapper is merely redundant.
pub const LOCK_FILE: &str = "repo.lock";

/// Held for as long as a command may mutate repository state.
#[derive(Debug)]
pub struct RepoLock {
    _file: File,
    path: PathBuf,
}

impl RepoLock {
    fn open(levcs_dir: &Path) -> Result<(File, PathBuf)> {
        let path = levcs_dir.join(LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .ctx(path.clone())?;
        Ok((file, path))
    }

    /// Take the lock if it is free; `None` if another process holds it.
    pub fn try_acquire(levcs_dir: &Path) -> Result<Option<Self>> {
        let (file, path) = Self::open(levcs_dir)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file, path })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(e)) => Err(Error::Io {
                path: Some(path),
                source: e,
            }),
        }
    }

    /// Take the lock, waiting for any other holder to release it.
    pub fn acquire(levcs_dir: &Path) -> Result<Self> {
        let (file, path) = Self::open(levcs_dir)?;
        file.lock().ctx(path.clone())?;
        Ok(Self { _file: file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "levcs-lock-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_held_lock_excludes_another_holder_until_dropped() {
        let d = dir("exclude");
        let first = RepoLock::try_acquire(&d).unwrap().expect("free lock");
        assert!(
            RepoLock::try_acquire(&d).unwrap().is_none(),
            "a second holder got the lock while the first held it"
        );
        drop(first);
        assert!(RepoLock::try_acquire(&d).unwrap().is_some());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn acquire_waits_for_the_holder() {
        let d = dir("wait");
        let held = RepoLock::acquire(&d).unwrap();
        let d2 = d.clone();
        let waiter = std::thread::spawn(move || {
            let t = std::time::Instant::now();
            let _l = RepoLock::acquire(&d2).unwrap();
            t.elapsed()
        });
        std::thread::sleep(std::time::Duration::from_millis(150));
        drop(held);
        let waited = waiter.join().unwrap();
        assert!(
            waited >= std::time::Duration::from_millis(100),
            "acquire returned after {waited:?} while the lock was held"
        );
        let _ = std::fs::remove_dir_all(d);
    }
}
