//! Index file at `.levcs/index`. Format from §2.5.
//!
//! magic       4 bytes   "LVIX"
//! version     4 bytes   format version (1)
//! entry_count 4 bytes   LE uint32
//! entries     variable  sequence of index entries
//!
//! Each entry:
//!   path_len  2 bytes
//!   path      N bytes (UTF-8, /-separated, repository-relative)
//!   blob_hash 32 bytes
//!   mode      1 byte
//!   flags     1 byte (bit 0 tracked, bit 1 cached, bit 2 conflicted)
//!   mtime     8 bytes  i64 LE microseconds since UNIX epoch
//!   size      8 bytes  u64 LE

use std::fs;
use std::path::PathBuf;

use byteorder::{ByteOrder, LittleEndian};

use crate::error::{Error, Result};
use crate::hash::ObjectId;

pub const INDEX_MAGIC: [u8; 4] = *b"LVIX";
pub const INDEX_VERSION: u32 = 1;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexEntryFlags(pub u8);

impl IndexEntryFlags {
    pub const TRACKED: IndexEntryFlags = IndexEntryFlags(0b001);
    pub const CACHED: IndexEntryFlags = IndexEntryFlags(0b010);
    pub const CONFLICTED: IndexEntryFlags = IndexEntryFlags(0b100);

    pub fn is_tracked(self) -> bool {
        self.0 & 0b001 != 0
    }
    pub fn is_cached(self) -> bool {
        self.0 & 0b010 != 0
    }
    pub fn is_conflicted(self) -> bool {
        self.0 & 0b100 != 0
    }

    pub fn with(self, mask: IndexEntryFlags) -> IndexEntryFlags {
        IndexEntryFlags(self.0 | mask.0)
    }

    pub fn without(self, mask: IndexEntryFlags) -> IndexEntryFlags {
        IndexEntryFlags(self.0 & !mask.0)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub path: String,
    pub blob_hash: ObjectId,
    pub mode: u8,
    pub flags: IndexEntryFlags,
    pub mtime_micros: i64,
    pub size: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Index {
    pub entries: Vec<IndexEntry>,
}

impl Index {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn find(&self, path: &str) -> Option<&IndexEntry> {
        self.entries.iter().find(|e| e.path == path)
    }

    pub fn find_mut(&mut self, path: &str) -> Option<&mut IndexEntry> {
        self.entries.iter_mut().find(|e| e.path == path)
    }

    pub fn upsert(&mut self, entry: IndexEntry) {
        if let Some(slot) = self.find_mut(&entry.path) {
            *slot = entry;
        } else {
            self.entries.push(entry);
        }
        self.entries.sort_by(|a, b| a.path.cmp(&b.path));
    }

    pub fn remove(&mut self, path: &str) -> bool {
        if let Some(i) = self.entries.iter().position(|e| e.path == path) {
            self.entries.remove(i);
            true
        } else {
            false
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&INDEX_MAGIC);
        let mut v = [0u8; 4];
        LittleEndian::write_u32(&mut v, INDEX_VERSION);
        out.extend_from_slice(&v);
        let mut c = [0u8; 4];
        LittleEndian::write_u32(&mut c, self.entries.len() as u32);
        out.extend_from_slice(&c);
        for e in &self.entries {
            let path_bytes = e.path.as_bytes();
            let mut pl = [0u8; 2];
            LittleEndian::write_u16(&mut pl, path_bytes.len() as u16);
            out.extend_from_slice(&pl);
            out.extend_from_slice(path_bytes);
            out.extend_from_slice(e.blob_hash.as_bytes());
            out.push(e.mode);
            out.push(e.flags.0);
            let mut mt = [0u8; 8];
            LittleEndian::write_i64(&mut mt, e.mtime_micros);
            out.extend_from_slice(&mt);
            let mut sz = [0u8; 8];
            LittleEndian::write_u64(&mut sz, e.size);
            out.extend_from_slice(&sz);
        }
        out
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 12 {
            return Err(Error::InvalidIndex("index file too short".into()));
        }
        if &bytes[0..4] != INDEX_MAGIC.as_ref() {
            return Err(Error::InvalidIndex("bad magic".into()));
        }
        let version = LittleEndian::read_u32(&bytes[4..8]);
        if version != INDEX_VERSION {
            return Err(Error::InvalidIndex(format!(
                "unsupported version {version}"
            )));
        }
        let count = LittleEndian::read_u32(&bytes[8..12]) as usize;
        let mut entries = Vec::with_capacity(count);
        let mut p = 12usize;
        for _ in 0..count {
            if bytes.len() < p + 2 {
                return Err(Error::InvalidIndex("entry truncated".into()));
            }
            let pl = LittleEndian::read_u16(&bytes[p..p + 2]) as usize;
            p += 2;
            if bytes.len() < p + pl + 32 + 1 + 1 + 8 + 8 {
                return Err(Error::InvalidIndex("entry truncated".into()));
            }
            let path = std::str::from_utf8(&bytes[p..p + pl])
                .map_err(|_| Error::InvalidIndex("path not UTF-8".into()))?
                .to_string();
            p += pl;
            let mut h = [0u8; 32];
            h.copy_from_slice(&bytes[p..p + 32]);
            p += 32;
            let mode = bytes[p];
            p += 1;
            let flags = IndexEntryFlags(bytes[p]);
            p += 1;
            let mtime_micros = LittleEndian::read_i64(&bytes[p..p + 8]);
            p += 8;
            let size = LittleEndian::read_u64(&bytes[p..p + 8]);
            p += 8;
            entries.push(IndexEntry {
                path,
                blob_hash: ObjectId(h),
                mode,
                flags,
                mtime_micros,
                size,
            });
        }
        if p != bytes.len() {
            return Err(Error::InvalidIndex("trailing bytes after entries".into()));
        }
        Ok(Self { entries })
    }

    pub fn read_from(path: &PathBuf) -> Result<Self> {
        match fs::read(path) {
            Ok(bytes) => Index::parse(&bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Index::new()),
            Err(e) => Err(Error::Io {
                path: Some(path.clone()),
                source: e,
            }),
        }
    }

    pub fn write_to(&self, path: &PathBuf) -> Result<()> {
        crate::fsutil::replace_file(path, &self.serialize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_roundtrip() {
        let mut idx = Index::new();
        idx.upsert(IndexEntry {
            path: "src/main.rs".into(),
            blob_hash: ObjectId([1; 32]),
            mode: 0,
            flags: IndexEntryFlags::TRACKED,
            mtime_micros: 1234,
            size: 99,
        });
        idx.upsert(IndexEntry {
            path: "README".into(),
            blob_hash: ObjectId([2; 32]),
            mode: 0,
            flags: IndexEntryFlags::TRACKED,
            mtime_micros: 4321,
            size: 1,
        });
        let bytes = idx.serialize();
        let idx2 = Index::parse(&bytes).unwrap();
        assert_eq!(idx.entries, idx2.entries);
    }
}
