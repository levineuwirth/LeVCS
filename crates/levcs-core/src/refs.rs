//! References. Stored under `.levcs/refs/` as small text files containing one
//! hex hash and a trailing newline. `HEAD` is at the top level of `.levcs/`.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, IoExt, Result};
use crate::hash::ObjectId;

#[derive(Clone, Debug)]
pub struct Refs {
    pub levcs_dir: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Head {
    /// HEAD points at a branch (e.g., `refs/branches/main`).
    Branch(String),
    /// Detached HEAD pointing directly at a commit.
    Detached(ObjectId),
}

impl Refs {
    pub fn new(levcs_dir: impl Into<PathBuf>) -> Self {
        Self {
            levcs_dir: levcs_dir.into(),
        }
    }

    pub fn refs_dir(&self) -> PathBuf {
        self.levcs_dir.join("refs")
    }
    pub fn head_path(&self) -> PathBuf {
        self.levcs_dir.join("HEAD")
    }

    pub fn ref_path(&self, name: &str) -> Result<PathBuf> {
        validate_ref_name(name)?;
        Ok(self.levcs_dir.join(name))
    }

    pub fn read(&self, name: &str) -> Result<Option<ObjectId>> {
        let path = self.ref_path(name)?;
        match fs::read_to_string(&path) {
            Ok(s) => Ok(Some(parse_ref_value(&s)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io {
                path: Some(path),
                source: e,
            }),
        }
    }

    pub fn write(&self, name: &str, id: ObjectId) -> Result<()> {
        let path = self.ref_path(name)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ctx(parent.to_path_buf())?;
        }
        self.atomic_write(&path, format!("{}\n", id.to_hex()).as_bytes())
    }

    /// Write `name` only if it still holds `expected` (`None`: absent).
    ///
    /// The comparison and the replacement are separate steps, so this is a
    /// defensive check, not an atomic compare-and-swap. Under the repository
    /// lock nothing cooperating can move the ref between them. A writer that
    /// does not take the lock (an older binary) can still move it inside
    /// that window and be overwritten, which is why a rollout must drain old
    /// writers before relying on the lock.
    pub fn compare_and_write(
        &self,
        name: &str,
        expected: Option<ObjectId>,
        new: ObjectId,
    ) -> Result<()> {
        let actual = self.read(name)?;
        if actual != expected {
            let show =
                |v: Option<ObjectId>| v.map(|i| i.to_hex()).unwrap_or_else(|| "nothing".into());
            return Err(Error::RefChanged {
                name: name.to_string(),
                expected: show(expected),
                actual: show(actual),
            });
        }
        self.write(name, new)
    }

    /// Replace a ref file atomically. The temporary file is staged in
    /// `.levcs/tmp/`, outside `refs/`, so one left behind by a crash can
    /// never be read back as a ref.
    fn atomic_write(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        if path.parent().is_none() {
            return Err(Error::Other(format!("ref path has no parent: {path:?}")));
        }
        crate::fsutil::replace_file_staged(path, bytes, &self.levcs_dir.join("tmp"))
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        let path = self.ref_path(name)?;
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::Io {
                path: Some(path),
                source: e,
            }),
        }
    }

    pub fn read_head(&self) -> Result<Option<Head>> {
        let path = self.head_path();
        match fs::read_to_string(&path) {
            Ok(s) => Ok(Some(parse_head(&s)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::Io {
                path: Some(path),
                source: e,
            }),
        }
    }

    pub fn write_head(&self, head: &Head) -> Result<()> {
        let s = match head {
            Head::Branch(name) => {
                validate_ref_name(name)?;
                format!("ref: {}\n", name)
            }
            Head::Detached(id) => format!("{}\n", id.to_hex()),
        };
        self.atomic_write(&self.head_path(), s.as_bytes())
    }

    /// Resolve HEAD to a commit hash, if any. None if HEAD points to a branch
    /// that does not exist (i.e., empty repository).
    pub fn resolve_head(&self) -> Result<Option<ObjectId>> {
        match self.read_head()? {
            None => Ok(None),
            Some(Head::Detached(id)) => Ok(Some(id)),
            Some(Head::Branch(name)) => self.read(&name),
        }
    }

    /// List every ref under `refs/`. Returns `(name, id)` pairs.
    pub fn list_all(&self) -> Result<Vec<(String, ObjectId)>> {
        let mut out = Vec::new();
        let dir = self.refs_dir();
        if !dir.is_dir() {
            return Ok(out);
        }
        // Walked with a stack of directories, not by recursion: a ref name
        // can be nested deeper than a thread's stack goes.
        let mut dirs = vec![dir.clone()];
        while let Some(d) = dirs.pop() {
            for ent in fs::read_dir(&d).ctx(d.clone())? {
                let ent = ent.ctx(d.clone())?;
                let path = ent.path();
                if path.is_dir() {
                    dirs.push(path);
                } else {
                    let rel = path.strip_prefix(dir.parent().unwrap()).unwrap();
                    let name = rel.to_string_lossy().replace('\\', "/").to_string();
                    // A ref that cannot be read or parsed is an error, never
                    // skipped: `verify` and `gc` take their roots from here,
                    // and a skipped root made `gc` delete the history it held.
                    let txt = fs::read_to_string(&path).ctx(path.clone())?;
                    let id = parse_ref_value(&txt)
                        .map_err(|e| Error::InvalidReference(format!("{}: {e}", path.display())))?;
                    out.push((name, id));
                }
            }
        }
        Ok(out)
    }

    pub fn list_branches(&self) -> Result<Vec<(String, ObjectId)>> {
        self.list_under("branches")
    }

    pub fn list_releases(&self) -> Result<Vec<(String, ObjectId)>> {
        self.list_under("releases")
    }

    /// The refs under `refs/<kind>/`, at any depth, by their names under it:
    /// `feature/x` for `refs/branches/feature/x`. A ref that does not parse
    /// is left out, as it always was. Only the top level used to be read: a
    /// nested branch's directory was read as a ref, and failed, and a nested
    /// release was left out. A link is skipped, never followed: levcs does not
    /// write one. Walked with a stack of directories, not by recursion: a
    /// ref name can be nested deeper than a thread's stack goes, and the
    /// walk recursed once per directory.
    fn list_under(&self, kind: &str) -> Result<Vec<(String, ObjectId)>> {
        let base = self.refs_dir().join(kind);
        let mut out = Vec::new();
        let mut dirs = Vec::new();
        if base.is_dir() {
            dirs.push(base.clone());
        }
        while let Some(dir) = dirs.pop() {
            for ent in fs::read_dir(&dir).ctx(dir.clone())? {
                let ent = ent.ctx(dir.clone())?;
                let path = ent.path();
                let kind = ent.file_type().ctx(path.clone())?;
                if kind.is_symlink() {
                    continue;
                }
                if kind.is_dir() {
                    dirs.push(path);
                    continue;
                }
                let name = path
                    .strip_prefix(&base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                let txt = fs::read_to_string(&path).ctx(path.clone())?;
                if let Ok(id) = parse_ref_value(&txt) {
                    out.push((name, id));
                }
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }
}

pub fn validate_ref_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::InvalidReference("empty".into()));
    }
    for comp in name.split('/') {
        if comp.is_empty() {
            return Err(Error::InvalidReference(format!(
                "empty component in {name}"
            )));
        }
        if comp == "." || comp == ".." {
            return Err(Error::InvalidReference(format!(
                "reserved component: {comp}"
            )));
        }
        if comp.contains('\0') {
            return Err(Error::InvalidReference("null byte".into()));
        }
    }
    if name.contains("//") || name.starts_with('/') || name.ends_with('/') {
        return Err(Error::InvalidReference(format!("malformed path: {name}")));
    }
    Ok(())
}

fn parse_ref_value(s: &str) -> Result<ObjectId> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidReference("empty ref body".into()));
    }
    ObjectId::from_hex(trimmed)
}

fn parse_head(s: &str) -> Result<Head> {
    let trimmed = s.trim();
    if let Some(rest) = trimmed.strip_prefix("ref:") {
        let name = rest.trim();
        validate_ref_name(name)?;
        Ok(Head::Branch(name.to_string()))
    } else {
        Ok(Head::Detached(ObjectId::from_hex(trimmed)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Remove `root` and everything under it without recursion, however
    /// deep it goes.
    fn remove_deep(root: &Path) {
        let mut stack = vec![(root.to_path_buf(), false)];
        while let Some((path, leaving)) = stack.pop() {
            if leaving {
                let _ = fs::remove_dir(&path);
                continue;
            }
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => {
                    stack.push((path.clone(), true));
                    for e in fs::read_dir(&path).into_iter().flatten().flatten() {
                        stack.push((e.path(), false));
                    }
                }
                _ => {
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }

    /// A ref nested deeper than a thread's stack goes is listed, by
    /// `list_all` and by `list_branches`: both walks recursed once per
    /// directory, and an instance listing a branch 1,200 directories deep
    /// aborted. The listing runs in a child process, on a 128 KiB stack, so
    /// that an overflow fails this test rather than aborting its binary.
    #[test]
    fn a_deeply_nested_ref_is_listed_without_recursion() {
        if let Some(d) = std::env::var_os("LEVCS_DEEP_REFS_CHILD") {
            let refs = Refs::new(std::path::PathBuf::from(d));
            let name = format!("refs/branches/{}tip", "x/".repeat(1200));
            refs.write(&name, ObjectId([1; 32])).unwrap();
            let listed = std::thread::Builder::new()
                .stack_size(128 << 10)
                .spawn(move || {
                    (
                        refs.list_all().unwrap().len(),
                        refs.list_branches().unwrap().len(),
                    )
                })
                .unwrap()
                .join()
                .unwrap();
            assert_eq!(listed, (1, 1));
            return;
        }
        let d = std::env::temp_dir().join(format!(
            "levcs-refs-deep-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "refs::tests::a_deeply_nested_ref_is_listed_without_recursion",
                "--nocapture",
            ])
            .env("LEVCS_DEEP_REFS_CHILD", &d)
            .output()
            .unwrap();
        remove_deep(&d);
        assert!(
            out.status.success(),
            "the listing failed: {}; {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Branches and releases are listed at any depth, by their names under
    /// `refs/branches/` and `refs/releases/`; a link is skipped. Only the top
    /// level was read: a nested branch failed the whole listing, and a nested
    /// release was left out.
    #[cfg(unix)]
    #[test]
    fn branches_and_releases_are_listed_at_any_depth() {
        let d = std::env::temp_dir().join(format!(
            "levcs-refs-nested-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let refs = Refs::new(&d);
        let (a, b, c) = (ObjectId([1; 32]), ObjectId([2; 32]), ObjectId([3; 32]));
        refs.write("refs/branches/main", a).unwrap();
        refs.write("refs/branches/feature/deep/x", b).unwrap();
        refs.write("refs/releases/series/test", c).unwrap();
        refs.write("refs/releases/v1", a).unwrap();
        std::os::unix::fs::symlink(
            d.join("refs/branches/feature"),
            d.join("refs/branches/linked"),
        )
        .unwrap();
        assert_eq!(
            refs.list_branches().unwrap(),
            vec![("feature/deep/x".into(), b), ("main".into(), a)]
        );
        assert_eq!(
            refs.list_releases().unwrap(),
            vec![("series/test".into(), c), ("v1".into(), a)]
        );
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn compare_and_write_refuses_a_moved_ref_and_leaves_it_alone() {
        let d = std::env::temp_dir().join(format!(
            "levcs-refs-cas-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let refs = Refs::new(&d);
        let (a, b, c) = (ObjectId([1; 32]), ObjectId([2; 32]), ObjectId([3; 32]));
        let name = "refs/branches/main";
        refs.compare_and_write(name, None, a).unwrap();
        assert!(matches!(
            refs.compare_and_write(name, None, b),
            Err(Error::RefChanged { .. })
        ));
        // Someone else advanced it to b; a writer still expecting a loses.
        refs.write(name, b).unwrap();
        assert!(matches!(
            refs.compare_and_write(name, Some(a), c),
            Err(Error::RefChanged { .. })
        ));
        assert_eq!(refs.read(name).unwrap(), Some(b));
        refs.compare_and_write(name, Some(b), c).unwrap();
        assert_eq!(refs.read(name).unwrap(), Some(c));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn invalid_names_rejected() {
        for n in ["", ".", "..", "a/", "/a", "a//b", "a/.."] {
            assert!(validate_ref_name(n).is_err(), "should reject: {n}");
        }
    }

    #[test]
    fn valid_names_accepted() {
        for n in [
            "refs/branches/main",
            "refs/releases/v1.0",
            "refs/authority/current",
        ] {
            validate_ref_name(n).unwrap();
        }
    }
}
