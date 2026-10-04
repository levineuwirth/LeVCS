//! Durable file replacement shared by the index, refs, and object store.
//!
//! Every writer used to stage through one fixed temporary name per target
//! (`index.tmp`, `.tmp.<ref>`, `tmp.<object id>`). Two processes writing the
//! same target then shared a temporary file: one renamed it away while the
//! other was still writing or about to rename, and the second rename failed
//! with ENOENT after the command had already done its work. A temporary name
//! unique to this process and call removes that interference, and the fsyncs
//! make the replacement survive power loss in the order callers rely on.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{IoExt, Result};

static NEXT: AtomicU64 = AtomicU64::new(0);

/// A temporary path in `dir`, unique to this process and call. The prefix
/// starts with `tmp.` so `store::cleanup_temp` recognizes leftovers.
pub fn unique_tmp(dir: &Path, stem: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    dir.join(format!(
        "tmp.{stem}.{}.{}.{nanos}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

/// fsync a directory so that a rename into it is durable.
pub fn fsync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .ctx(dir.to_path_buf())
}

/// `create_dir_all`, then fsync the parent of every directory it created, so
/// that a new directory's entry survives power loss before anything that
/// depends on it (an object in a new shard, a ref under a new namespace) is
/// published. Existing directories cost nothing.
pub fn create_dir_all_durable(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    let mut missing = Vec::new();
    let mut cur = Some(dir);
    while let Some(d) = cur {
        if d.is_dir() {
            break;
        }
        missing.push(d.to_path_buf());
        cur = d.parent();
    }
    fs::create_dir_all(dir).ctx(dir.to_path_buf())?;
    // Outermost new directory first: its parent already existed.
    for d in missing.iter().rev() {
        if let Some(parent) = d.parent() {
            if !parent.as_os_str().is_empty() {
                fsync_dir(parent)?;
            }
        }
    }
    Ok(())
}

/// Replace `path` with `bytes`: write a unique temporary file in the same
/// directory, fsync it, rename it over `path`, and fsync the directory.
/// Readers see either the old content or the new, never a mixture.
pub fn replace_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    replace_file_staged(path, bytes, parent)
}

/// [`replace_file`], staging the temporary file in `staging` rather than
/// beside `path`. Refs use this: every name is a valid ref, so a temporary
/// left beside a ref by a crash would be listed as a branch. `staging` must
/// be on the same filesystem as `path` for the rename to stay atomic.
pub fn replace_file_staged(path: &Path, bytes: &[u8], staging: &Path) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    create_dir_all_durable(parent)?;
    fs::create_dir_all(staging).ctx(staging.to_path_buf())?;
    let stem = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = unique_tmp(staging, &stem);
    let written = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e).ctx(tmp);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).ctx(path.to_path_buf());
    }
    fsync_dir(parent)
}
