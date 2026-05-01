//! Cached releases (§4.4).
//!
//! A working repository may keep release objects (and their reachable
//! trees + blobs) in `.levcs/cache/releases/` to accelerate
//! `construct`, `diff`, and `merge` against released versions without
//! having to re-resolve everything from the loose object store. Each
//! cache entry is one file at `cache/releases/<release_hex>` whose
//! contents are the release object's raw bytes; LRU is decided by the
//! file's mtime.
//!
//! The cache is purely a performance hint — every entry is also
//! present in the loose object store. Eviction is therefore safe
//! without consulting reachability: a deleted cache file just makes
//! the next `construct --release` slightly slower.

use std::path::PathBuf;

use crate::error::{IoExt, Result};
use crate::hash::ObjectId;
use crate::repo::Repository;

/// Spec default cap of 1 GiB before LRU eviction kicks in.
pub const DEFAULT_CACHE_CAP_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct EvictReport {
    pub evicted_files: usize,
    pub evicted_bytes: u64,
    /// Total bytes remaining after eviction.
    pub remaining_bytes: u64,
}

fn cache_dir(repo: &Repository) -> PathBuf {
    repo.levcs_dir.join("cache").join("releases")
}

/// Write a cache entry for `release_id`. The on-disk shape is one
/// flat file per release, named by the hex hash. Subsequent calls
/// for the same id touch the file's mtime so LRU sorts treat it as
/// "most recently used" — a side effect of the read path that
/// callers should remember.
pub fn cache_release(repo: &Repository, release_id: ObjectId) -> Result<()> {
    let dir = cache_dir(repo);
    std::fs::create_dir_all(&dir).ctx(dir.clone())?;
    let bytes = repo.objects.read_raw(release_id)?;
    let path = dir.join(release_id.to_hex());
    // Atomic write so a Ctrl-C halfway through doesn't leave a
    // half-written cache entry. The eviction path can also race here;
    // worst case is that a sibling process re-evicts what we just
    // wrote, which is fine.
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes).ctx(tmp.clone())?;
    std::fs::rename(&tmp, &path).ctx(path)?;
    Ok(())
}

/// Mark `release_id` as freshly accessed so it survives the next
/// LRU pass. Equivalent to `touch -m`. Returns Ok(()) silently if no
/// cache entry exists — call sites don't need to know whether a
/// release was previously cached.
pub fn touch(repo: &Repository, release_id: ObjectId) -> Result<()> {
    let path = cache_dir(repo).join(release_id.to_hex());
    if !path.exists() {
        return Ok(());
    }
    // SystemTime::now() is fine on every supported platform; we don't
    // need filetime crate granularity here.
    let now = std::time::SystemTime::now();
    let f = std::fs::File::options()
        .write(true)
        .open(&path)
        .ctx(path.clone())?;
    f.set_modified(now).ctx(path)?;
    Ok(())
}

/// Walk every cache entry, sort by mtime ascending (oldest first),
/// and delete entries until the total size is at or below `cap`.
/// Files whose mtime can't be read are treated as the oldest — they
/// go first.
pub fn evict_to(repo: &Repository, cap: u64) -> Result<EvictReport> {
    let dir = cache_dir(repo);
    if !dir.is_dir() {
        return Ok(EvictReport::default());
    }
    let mut entries: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();
    let mut total: u64 = 0;
    for ent in std::fs::read_dir(&dir).ctx(dir.clone())? {
        let ent = ent.ctx(dir.clone())?;
        let path = ent.path();
        let meta = match ent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() {
            continue;
        }
        // Skip the in-flight `.tmp` files that `cache_release` writes;
        // they belong to a concurrent caller and aren't ours to evict.
        if path.extension().and_then(|s| s.to_str()) == Some("tmp") {
            continue;
        }
        let size = meta.len();
        let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
        total += size;
        entries.push((path, size, mtime));
    }
    if total <= cap {
        return Ok(EvictReport {
            evicted_files: 0,
            evicted_bytes: 0,
            remaining_bytes: total,
        });
    }
    // Oldest first.
    entries.sort_by(|a, b| a.2.cmp(&b.2));

    let mut evicted_files = 0usize;
    let mut evicted_bytes: u64 = 0;
    let mut remaining = total;
    for (path, size, _) in entries {
        if remaining <= cap {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            evicted_files += 1;
            evicted_bytes += size;
            remaining = remaining.saturating_sub(size);
        }
    }
    Ok(EvictReport {
        evicted_files,
        evicted_bytes,
        remaining_bytes: remaining,
    })
}

/// Total bytes currently held in the release cache. Used by
/// observability and by tests.
pub fn current_size_bytes(repo: &Repository) -> Result<u64> {
    let dir = cache_dir(repo);
    if !dir.is_dir() {
        return Ok(0);
    }
    let mut total = 0u64;
    for ent in std::fs::read_dir(&dir).ctx(dir.clone())? {
        let ent = ent.ctx(dir.clone())?;
        let meta = match ent.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        if meta.is_file() && ent.path().extension().and_then(|s| s.to_str()) != Some("tmp") {
            total += meta.len();
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    fn tempdir() -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("levcs-cache-test-{n}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// Drop `count` files into `dir`, each `size` bytes, with mtimes
    /// staggered so the first is oldest. Returns the paths in the
    /// same order (so `paths[0]` is the oldest).
    fn populate(dir: &Path, count: usize, size: u64) -> Vec<std::path::PathBuf> {
        std::fs::create_dir_all(dir).unwrap();
        let mut paths = Vec::with_capacity(count);
        let now = SystemTime::now();
        for i in 0..count {
            let p = dir.join(format!("entry-{i:02}"));
            std::fs::write(&p, vec![0u8; size as usize]).unwrap();
            // Stagger mtimes by a clear margin so the sort is
            // deterministic regardless of filesystem resolution.
            let f = std::fs::File::options().write(true).open(&p).unwrap();
            let t = now - Duration::from_secs(((count - i) * 10) as u64);
            f.set_modified(t).unwrap();
            paths.push(p);
        }
        paths
    }

    #[test]
    fn evict_keeps_everything_when_under_cap() {
        let work = tempdir();
        let repo = Repository::init_skeleton(&work).unwrap();
        populate(&cache_dir(&repo), 3, 100);
        let report = evict_to(&repo, 10_000).unwrap();
        assert_eq!(report.evicted_files, 0);
        assert_eq!(report.remaining_bytes, 300);
        std::fs::remove_dir_all(&work).ok();
    }

    #[test]
    fn evict_removes_oldest_first_until_under_cap() {
        let work = tempdir();
        let repo = Repository::init_skeleton(&work).unwrap();
        let dir = cache_dir(&repo);
        let paths = populate(&dir, 5, 100); // total 500
                                            // Cap at 250 → must evict 3 oldest (250 left).
        let report = evict_to(&repo, 250).unwrap();
        assert_eq!(report.evicted_files, 3);
        assert!(report.remaining_bytes <= 250);
        // Oldest three deleted, newest two kept.
        assert!(!paths[0].exists(), "oldest must go first");
        assert!(!paths[1].exists());
        assert!(!paths[2].exists());
        assert!(paths[3].exists(), "newer entries must survive");
        assert!(paths[4].exists());
        std::fs::remove_dir_all(&work).ok();
    }

    #[test]
    fn evict_skips_tmp_files() {
        // `cache_release` writes via `<hex>.tmp` then renames; we
        // mustn't evict an in-flight write under us.
        let work = tempdir();
        let repo = Repository::init_skeleton(&work).unwrap();
        let dir = cache_dir(&repo);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.tmp"), vec![0u8; 9_000]).unwrap();
        std::fs::write(dir.join("real-entry"), vec![0u8; 100]).unwrap();
        let report = evict_to(&repo, 0).unwrap();
        // `real-entry` is the only thing eligible for eviction.
        assert_eq!(report.evicted_files, 1);
        assert!(dir.join("a.tmp").is_file());
        std::fs::remove_dir_all(&work).ok();
    }

    #[test]
    fn current_size_excludes_tmp_files() {
        let work = tempdir();
        let repo = Repository::init_skeleton(&work).unwrap();
        let dir = cache_dir(&repo);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("entry"), vec![0u8; 100]).unwrap();
        std::fs::write(dir.join("entry.tmp"), vec![0u8; 9_000]).unwrap();
        assert_eq!(current_size_bytes(&repo).unwrap(), 100);
        std::fs::remove_dir_all(&work).ok();
    }
}
