//! Repository: top-level structure that bundles object store, refs, index,
//! and working-tree access. The on-disk layout per §2.6 is:
//!
//! ```text
//! .levcs/
//!   config
//!   HEAD
//!   index
//!   merge.toml
//!   objects/
//!   refs/
//!     branches/
//!     releases/
//!     remote/
//!     authority/
//!   cache/
//!   hooks/
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{Error, IoExt, Result};
use crate::hash::{blake3_hash, ObjectId};
use crate::ignore::{always_ignored, Ignore};
use crate::index::{Index, IndexEntry, IndexEntryFlags};
use crate::object::{ObjectType, RawObject, SignedObject};
use crate::refs::{Head, Refs};
use crate::store::ObjectStore;
use crate::tree::{EntryType, FileMode, Tree, TreeEntry};

pub const LEVCS_DIR: &str = ".levcs";

#[derive(Clone, Debug)]
pub struct Repository {
    pub workdir: PathBuf,
    pub levcs_dir: PathBuf,
    pub objects: ObjectStore,
    pub refs: Refs,
}

impl Repository {
    /// Create a new empty repository skeleton at `workdir/.levcs/`. Does not
    /// write an authority object — that is the responsibility of the
    /// `levcs init` command in `levcs-cli` (which needs identity bits).
    pub fn init_skeleton(workdir: impl Into<PathBuf>) -> Result<Self> {
        let workdir = workdir.into();
        let levcs_dir = workdir.join(LEVCS_DIR);
        if levcs_dir.exists() {
            return Err(Error::RepositoryExists(levcs_dir));
        }
        for sub in [
            "objects",
            "refs/branches",
            "refs/releases",
            "refs/remote",
            "refs/authority",
            "cache/releases",
            "hooks",
        ] {
            let p = levcs_dir.join(sub);
            fs::create_dir_all(&p).ctx(p)?;
        }
        // Default config (empty TOML)
        let config_path = levcs_dir.join("config");
        if !config_path.exists() {
            fs::write(&config_path, b"# levcs repository config\n").ctx(config_path)?;
        }
        Ok(Self::open_at(workdir, levcs_dir))
    }

    /// Search upward from `start` for a `.levcs/` directory.
    pub fn discover(start: impl AsRef<Path>) -> Result<Self> {
        let start = start.as_ref();
        let mut cur = if start.is_absolute() {
            start.to_path_buf()
        } else {
            std::env::current_dir()?.join(start)
        };
        if let Ok(c) = cur.canonicalize() {
            cur = c;
        }
        loop {
            let candidate = cur.join(LEVCS_DIR);
            if candidate.is_dir() {
                let workdir = cur.clone();
                return Ok(Self::open_at(workdir, candidate));
            }
            if !cur.pop() {
                return Err(Error::NotARepository);
            }
        }
    }

    fn open_at(workdir: PathBuf, levcs_dir: PathBuf) -> Self {
        let objects = ObjectStore::new(levcs_dir.join("objects"));
        let refs = Refs::new(levcs_dir.clone());
        Self { workdir, levcs_dir, objects, refs }
    }

    pub fn index_path(&self) -> PathBuf { self.levcs_dir.join("index") }
    pub fn config_path(&self) -> PathBuf { self.levcs_dir.join("config") }
    pub fn ignore_path(&self) -> PathBuf { self.workdir.join(".levcsignore") }

    pub fn read_index(&self) -> Result<Index> {
        Index::read_from(&self.index_path())
    }

    pub fn write_index(&self, idx: &Index) -> Result<()> {
        idx.write_to(&self.index_path())
    }

    pub fn read_ignore(&self) -> Ignore {
        match fs::read_to_string(self.ignore_path()) {
            Ok(s) => Ignore::parse(&s),
            Err(_) => Ignore::parse(""),
        }
    }

    /// Hash a working-tree file as a blob (without writing to the store).
    pub fn hash_blob(bytes: &[u8]) -> ObjectId {
        // Reproduces the framing logic without depending on Blob to avoid a
        // circular feel. Same logic as Blob::serialize().
        let blob = crate::blob::Blob::new(bytes.to_vec());
        blob.object_id()
    }

    /// Read the current authority hash from `refs/authority/current`.
    pub fn current_authority(&self) -> Result<Option<ObjectId>> {
        self.refs.read("refs/authority/current")
    }

    pub fn set_current_authority(&self, id: ObjectId) -> Result<()> {
        self.refs.write("refs/authority/current", id)
    }

    pub fn genesis_authority(&self) -> Result<Option<ObjectId>> {
        self.refs.read("refs/authority/genesis")
    }

    pub fn set_genesis_authority(&self, id: ObjectId) -> Result<()> {
        self.refs.write("refs/authority/genesis", id)
    }

    /// Iterate over all working-tree files (excluding `.levcs/` and ignored).
    pub fn walk_workdir(&self) -> Result<Vec<PathBuf>> {
        let mut out = Vec::new();
        let ignore = self.read_ignore();
        walk(&self.workdir, &self.workdir, &ignore, &mut out)?;
        out.sort();
        return Ok(out);

        fn walk(base: &Path, dir: &Path, ig: &Ignore, out: &mut Vec<PathBuf>) -> Result<()> {
            for ent in fs::read_dir(dir).ctx(dir.to_path_buf())? {
                let ent = ent.ctx(dir.to_path_buf())?;
                let path = ent.path();
                let rel = path.strip_prefix(base).unwrap();
                if always_ignored(rel) {
                    continue;
                }
                let rel_str = rel.to_string_lossy().replace('\\', "/");
                if ig.is_ignored(&rel_str) {
                    continue;
                }
                let ft = ent.file_type().ctx(path.clone())?;
                if ft.is_dir() {
                    walk(base, &path, ig, out)?;
                } else if ft.is_file() || ft.is_symlink() {
                    out.push(path);
                }
            }
            Ok(())
        }
    }

    /// Build a `Tree` object for a single directory level given a sorted set
    /// of (relative_path, blob_hash, mode) entries representing the files
    /// staged at and below `prefix`. Recursive: returns the root tree's id.
    pub fn build_tree_from_index(&self, idx: &Index) -> Result<ObjectId> {
        // Group entries by directory, build trees bottom-up.
        let mut node = TreeBuilder::default();
        for e in &idx.entries {
            if !e.flags.is_tracked() {
                continue;
            }
            node.insert(&e.path, e.blob_hash, mode_from_index(e.mode));
        }
        node.write(self)
    }

    /// Build a tree from a working directory directly (used when no index is
    /// available). All files are added as regular blobs.
    pub fn build_tree_from_workdir(&self) -> Result<ObjectId> {
        let mut node = TreeBuilder::default();
        for path in self.walk_workdir()? {
            let rel = path.strip_prefix(&self.workdir).unwrap();
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let bytes = fs::read(&path).ctx(path.clone())?;
            let blob = crate::blob::Blob::new(bytes);
            let id = self.objects.write_raw(&blob.serialize())?;
            node.insert(&rel_str, id, FileMode::REGULAR);
        }
        node.write(self)
    }

    /// Materialize a tree into the working directory at `prefix`. Existing
    /// files are overwritten. The top-level `.levcs` entry (if any) is
    /// skipped so authority-modifying commits do not clobber the repository's
    /// own metadata directory; that entry exists only for verification.
    pub fn checkout_tree(&self, tree_id: ObjectId, prefix: &Path) -> Result<()> {
        self.checkout_tree_inner(tree_id, prefix, true)
    }

    fn checkout_tree_inner(&self, tree_id: ObjectId, prefix: &Path, top_level: bool) -> Result<()> {
        let raw = self.objects.read_typed(tree_id, ObjectType::Tree)?;
        let tree = Tree::parse_body(&raw.body)?;
        for e in &tree.entries {
            if top_level && e.name == ".levcs" {
                continue;
            }
            let target = prefix.join(&e.name);
            match e.entry_type {
                EntryType::Tree => {
                    fs::create_dir_all(&target).ctx(target.clone())?;
                    self.checkout_tree_inner(e.hash, &target, false)?;
                }
                EntryType::Blob => {
                    let blob = self.objects.read_typed(e.hash, ObjectType::Blob)?;
                    if let Some(parent) = target.parent() {
                        fs::create_dir_all(parent).ctx(parent.to_path_buf())?;
                    }
                    fs::write(&target, &blob.body).ctx(target.clone())?;
                    #[cfg(unix)]
                    if e.mode.is_executable() {
                        use std::os::unix::fs::PermissionsExt;
                        let mut perms = fs::metadata(&target).ctx(target.clone())?.permissions();
                        perms.set_mode(0o755);
                        fs::set_permissions(&target, perms).ctx(target.clone())?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn read_signed(&self, id: ObjectId) -> Result<SignedObject> {
        let bytes = self.objects.read_raw(id)?;
        SignedObject::parse(&bytes)
    }

    pub fn read_raw_object(&self, id: ObjectId) -> Result<RawObject> {
        self.objects.read_object(id)
    }

    pub fn write_signed(&self, signed: &SignedObject) -> Result<ObjectId> {
        let bytes = signed.serialize();
        let id = blake3_hash(&bytes);
        self.objects.write_at(id, &bytes)?;
        Ok(id)
    }

    /// Find the path within a tree (recursively) and return (entry_type, hash).
    pub fn lookup_path(&self, tree_id: ObjectId, path: &str) -> Result<Option<(EntryType, ObjectId)>> {
        let raw = self.objects.read_typed(tree_id, ObjectType::Tree)?;
        let tree = Tree::parse_body(&raw.body)?;
        let mut comps = path.split('/').filter(|c| !c.is_empty());
        let first = match comps.next() {
            Some(c) => c,
            None => return Ok(None),
        };
        let entry = match tree.find(first) {
            Some(e) => e,
            None => return Ok(None),
        };
        let rest: Vec<&str> = comps.collect();
        if rest.is_empty() {
            Ok(Some((entry.entry_type, entry.hash)))
        } else {
            match entry.entry_type {
                EntryType::Tree => self.lookup_path(entry.hash, &rest.join("/")),
                EntryType::Blob => Ok(None),
            }
        }
    }

    pub fn current_branch(&self) -> Result<Option<String>> {
        match self.refs.read_head()? {
            Some(Head::Branch(name)) => Ok(Some(name)),
            _ => Ok(None),
        }
    }
}

fn mode_from_index(m: u8) -> FileMode {
    let mut bits = 0u8;
    if m & 0o111 != 0 { bits |= 0b01; }
    FileMode(bits)
}

#[derive(Default)]
struct TreeBuilder {
    files: Vec<(String, ObjectId, FileMode)>,
    dirs: std::collections::BTreeMap<String, TreeBuilder>,
}

impl TreeBuilder {
    fn insert(&mut self, path: &str, hash: ObjectId, mode: FileMode) {
        let mut comps = path.splitn(2, '/');
        let first = comps.next().unwrap();
        match comps.next() {
            None => {
                self.files.push((first.to_string(), hash, mode));
            }
            Some(rest) => {
                self.dirs.entry(first.to_string()).or_default().insert(rest, hash, mode);
            }
        }
    }

    fn write(self, repo: &Repository) -> Result<ObjectId> {
        let mut tree = Tree::new();
        for (name, hash, mode) in self.files {
            tree.entries.push(TreeEntry { name, entry_type: EntryType::Blob, mode, hash });
        }
        for (name, sub) in self.dirs {
            let sub_id = sub.write(repo)?;
            tree.entries.push(TreeEntry {
                name,
                entry_type: EntryType::Tree,
                mode: FileMode::REGULAR,
                hash: sub_id,
            });
        }
        tree.sort_and_validate()?;
        let bytes = tree.serialize();
        repo.objects.write_raw(&bytes)
    }
}

#[allow(dead_code)]
fn _index_entry_keep(_: &IndexEntry, _: IndexEntryFlags) {}
