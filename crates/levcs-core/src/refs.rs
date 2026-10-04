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
        walk(&dir, &dir, &mut out)?;
        return Ok(out);

        fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, ObjectId)>) -> Result<()> {
            for ent in fs::read_dir(dir).ctx(dir.to_path_buf())? {
                let ent = ent.ctx(dir.to_path_buf())?;
                let path = ent.path();
                if path.is_dir() {
                    walk(base, &path, out)?;
                } else {
                    let rel = path.strip_prefix(base.parent().unwrap()).unwrap();
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
            Ok(())
        }
    }

    pub fn list_branches(&self) -> Result<Vec<(String, ObjectId)>> {
        let dir = self.refs_dir().join("branches");
        let mut out = Vec::new();
        if !dir.is_dir() {
            return Ok(out);
        }
        for ent in fs::read_dir(&dir).ctx(dir.clone())? {
            let ent = ent.ctx(dir.clone())?;
            let name = ent.file_name().to_string_lossy().to_string();
            let txt = fs::read_to_string(ent.path()).ctx(ent.path())?;
            if let Ok(id) = parse_ref_value(&txt) {
                out.push((name, id));
            }
        }
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    pub fn list_releases(&self) -> Result<Vec<(String, ObjectId)>> {
        let dir = self.refs_dir().join("releases");
        let mut out = Vec::new();
        if !dir.is_dir() {
            return Ok(out);
        }
        for ent in fs::read_dir(&dir).ctx(dir.clone())? {
            let ent = ent.ctx(dir.clone())?;
            let name = ent.file_name().to_string_lossy().to_string();
            let txt = fs::read_to_string(ent.path()).ctx(ent.path())?;
            if let Ok(id) = parse_ref_value(&txt) {
                out.push((name, id));
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
