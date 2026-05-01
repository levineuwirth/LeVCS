//! Filesystem object store, sharded by the first two hex characters of the
//! object hash. Objects with hash `abcd1234...` live at
//! `.levcs/objects/ab/cd1234...`.

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

use crate::error::{Error, IoExt, Result};
use crate::hash::{blake3_hash, ObjectId};
use crate::object::{ObjectType, RawObject};

#[derive(Clone, Debug)]
pub struct ObjectStore {
    pub root: PathBuf,
}

impl ObjectStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.root).ctx(self.root.clone())?;
        Ok(())
    }

    pub fn path_for(&self, id: ObjectId) -> PathBuf {
        let hex = id.to_hex();
        self.root.join(&hex[0..2]).join(&hex[2..])
    }

    pub fn contains(&self, id: ObjectId) -> bool {
        self.path_for(id).is_file()
    }

    /// Persist raw object bytes. Returns the BLAKE3 hash of the bytes.
    /// Verifies that the bytes are at least a parseable object before
    /// writing.
    pub fn write_raw(&self, bytes: &[u8]) -> Result<ObjectId> {
        // Validate framing.
        let _ = RawObject::parse(bytes)?;
        let id = blake3_hash(bytes);
        self.write_at(id, bytes)
    }

    /// Persist raw bytes at a known hash. The caller asserts that
    /// `blake3(bytes) == id`; this is checked.
    pub fn write_at(&self, id: ObjectId, bytes: &[u8]) -> Result<ObjectId> {
        let actual = blake3_hash(bytes);
        if actual != id {
            return Err(Error::HashMismatch {
                expected: id.to_hex(),
                actual: actual.to_hex(),
            });
        }
        let path = self.path_for(id);
        if path.is_file() {
            return Ok(id);
        }
        let parent = path.parent().expect("sharded path has parent");
        fs::create_dir_all(parent).ctx(parent.to_path_buf())?;
        // Write to a temp file in the same directory, then atomically rename.
        let tmp = parent.join(format!("tmp.{}", id.to_hex()));
        {
            let mut f = fs::File::create(&tmp).ctx(tmp.clone())?;
            f.write_all(bytes).ctx(tmp.clone())?;
            f.sync_all().ctx(tmp.clone())?;
        }
        fs::rename(&tmp, &path).ctx(path.clone())?;
        Ok(id)
    }

    pub fn read_raw(&self, id: ObjectId) -> Result<Vec<u8>> {
        let path = self.path_for(id);
        let mut f = fs::File::open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                Error::NotFound(id.to_hex())
            } else {
                Error::Io { path: Some(path.clone()), source: e }
            }
        })?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).ctx(path.clone())?;
        // Verify integrity.
        let actual = blake3_hash(&buf);
        if actual != id {
            return Err(Error::HashMismatch {
                expected: id.to_hex(),
                actual: actual.to_hex(),
            });
        }
        Ok(buf)
    }

    pub fn read_object(&self, id: ObjectId) -> Result<RawObject> {
        let bytes = self.read_raw(id)?;
        RawObject::parse(&bytes)
    }

    pub fn read_typed(&self, id: ObjectId, expected: ObjectType) -> Result<RawObject> {
        let obj = self.read_object(id)?;
        if obj.object_type != expected {
            return Err(Error::MalformedObject(format!(
                "expected {}, got {}", expected.name(), obj.object_type.name()
            )));
        }
        Ok(obj)
    }

    /// Iterate all object IDs currently on disk (used by gc/verify). Returns
    /// loose objects only.
    pub fn iter_ids(&self) -> Result<Vec<ObjectId>> {
        let mut out = Vec::new();
        if !self.root.is_dir() {
            return Ok(out);
        }
        for shard in fs::read_dir(&self.root).ctx(self.root.clone())? {
            let shard = shard.ctx(self.root.clone())?;
            let shard_name = shard.file_name();
            let shard_str = match shard_name.to_str() {
                Some(s) if s.len() == 2 => s.to_string(),
                _ => continue,
            };
            for ent in fs::read_dir(shard.path()).ctx(shard.path())? {
                let ent = ent.ctx(shard.path())?;
                let name = ent.file_name();
                let name_str = match name.to_str() {
                    Some(s) => s,
                    None => continue,
                };
                if name_str.starts_with("tmp.") {
                    continue;
                }
                let full = format!("{}{}", shard_str, name_str);
                if let Ok(id) = ObjectId::from_hex(&full) {
                    out.push(id);
                }
            }
        }
        Ok(out)
    }
}

/// Convenience: clean up any orphan tmp.* files left by interrupted writes.
pub fn cleanup_temp(store: &ObjectStore) -> Result<()> {
    if !store.root.is_dir() {
        return Ok(());
    }
    for shard in fs::read_dir(&store.root).ctx(store.root.clone())? {
        let shard = shard.ctx(store.root.clone())?;
        for ent in fs::read_dir(shard.path()).ctx(shard.path())? {
            let ent = ent.ctx(shard.path())?;
            let name = ent.file_name();
            if name.to_string_lossy().starts_with("tmp.") {
                let _ = fs::remove_file(ent.path());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob::Blob;

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let n: u64 = blake3::hash(format!("{:?}-{}", std::time::SystemTime::now(), std::process::id()).as_bytes())
            .as_bytes()
            .iter()
            .take(8)
            .fold(0u64, |acc, b| (acc << 8) | *b as u64);
        p.push(format!("levcs-store-test-{n}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn roundtrip_blob() {
        let dir = tempdir();
        let store = ObjectStore::new(dir.join("objects"));
        store.ensure_dirs().unwrap();
        let blob = Blob::new(b"hello".to_vec());
        let bytes = blob.serialize();
        let id = store.write_raw(&bytes).unwrap();
        assert!(store.contains(id));
        let read = store.read_raw(id).unwrap();
        assert_eq!(read, bytes);
        let _ = std::fs::remove_dir_all(dir);
    }
}
