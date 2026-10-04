//! Tree object: an ordered set of (name, type, hash, mode) entries.
//!
//! Per §2.3.2, each entry is:
//!   2 bytes: name length (LE u16, max 255)
//!   N bytes: name (UTF-8, no null terminator)
//!   1 byte:  entry type (1=Blob, 2=Tree)
//!   1 byte:  mode bits (bit 0 executable, bit 1 symlink)
//!   32 bytes: object hash (raw BLAKE3)
//!
//! Entries are sorted byte-wise by name. Names must not contain '/', null,
//! or be `.` or `..`.

use byteorder::{ByteOrder, LittleEndian};

use crate::error::Error;
use crate::hash::{blake3_hash, ObjectId};
use crate::object::{frame_unsigned, ObjectType};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryType {
    Blob = 1,
    Tree = 2,
}

impl EntryType {
    pub fn from_u8(b: u8) -> Result<Self, Error> {
        Ok(match b {
            1 => Self::Blob,
            2 => Self::Tree,
            n => return Err(Error::MalformedObject(format!("bad tree entry type {n}"))),
        })
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FileMode(pub u8);

impl FileMode {
    pub const REGULAR: FileMode = FileMode(0);
    pub const EXECUTABLE: FileMode = FileMode(0b01);
    pub const SYMLINK: FileMode = FileMode(0b10);

    pub fn is_executable(self) -> bool {
        self.0 & 0b01 != 0
    }
    pub fn is_symlink(self) -> bool {
        self.0 & 0b10 != 0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeEntry {
    pub name: String,
    pub entry_type: EntryType,
    pub mode: FileMode,
    pub hash: ObjectId,
}

impl TreeEntry {
    pub fn validate_name(name: &str) -> Result<(), Error> {
        if name.is_empty() {
            return Err(Error::InvalidPath("empty tree-entry name".into()));
        }
        if name.len() > 255 {
            return Err(Error::InvalidPath(format!(
                "name too long ({} bytes)",
                name.len()
            )));
        }
        if name == "." || name == ".." {
            return Err(Error::InvalidPath(format!("reserved name: {name}")));
        }
        if name.contains('/') {
            return Err(Error::InvalidPath(format!("name contains '/': {name}")));
        }
        if name.bytes().any(|b| b == 0) {
            return Err(Error::InvalidPath("name contains null byte".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sort entries by name (byte-wise) and validate; required for hash
    /// determinism.
    pub fn sort_and_validate(&mut self) -> Result<(), Error> {
        for e in &self.entries {
            TreeEntry::validate_name(&e.name)?;
        }
        self.entries
            .sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        // detect duplicate names
        for w in self.entries.windows(2) {
            if w[0].name == w[1].name {
                return Err(Error::MalformedObject(format!(
                    "duplicate tree entry name: {}",
                    w[0].name
                )));
            }
        }
        Ok(())
    }

    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.entries.len() * 64);
        for e in &self.entries {
            let n = e.name.len() as u16;
            let mut len_buf = [0u8; 2];
            LittleEndian::write_u16(&mut len_buf, n);
            out.extend_from_slice(&len_buf);
            out.extend_from_slice(e.name.as_bytes());
            out.push(e.entry_type as u8);
            out.push(e.mode.0);
            out.extend_from_slice(e.hash.as_bytes());
        }
        out
    }

    pub fn serialize(&self) -> Vec<u8> {
        frame_unsigned(ObjectType::Tree, &self.body())
    }

    pub fn object_id(&self) -> ObjectId {
        blake3_hash(&self.serialize())
    }

    pub fn parse_body(body: &[u8]) -> Result<Self, Error> {
        let mut entries = Vec::new();
        let mut p = 0usize;
        while p < body.len() {
            if body.len() < p + 2 {
                return Err(Error::MalformedObject(
                    "tree entry: short name length".into(),
                ));
            }
            let n = LittleEndian::read_u16(&body[p..p + 2]) as usize;
            p += 2;
            if body.len() < p + n + 1 + 1 + 32 {
                return Err(Error::MalformedObject("tree entry truncated".into()));
            }
            let name = std::str::from_utf8(&body[p..p + n])
                .map_err(|_| Error::MalformedObject("tree name not UTF-8".into()))?
                .to_string();
            p += n;
            let entry_type = EntryType::from_u8(body[p])?;
            p += 1;
            let mode = FileMode(body[p]);
            p += 1;
            let mut h = [0u8; 32];
            h.copy_from_slice(&body[p..p + 32]);
            p += 32;
            // Parse what writing forbids: a name that is empty, `.`, `..`,
            // or contains `/` or NUL, mode bits beyond executable and
            // symlink, and entries out of order or repeated. Trees were
            // validated only when written, so a tree from elsewhere could
            // name `../outside` and have checkout write it there.
            TreeEntry::validate_name(&name)?;
            if mode.0 & !(FileMode::EXECUTABLE.0 | FileMode::SYMLINK.0) != 0 {
                return Err(Error::MalformedObject(format!(
                    "tree entry {name:?} has unknown mode bits {:#x}",
                    mode.0
                )));
            }
            if let Some(prev) = entries.last() {
                let prev: &TreeEntry = prev;
                if prev.name.as_bytes() >= name.as_bytes() {
                    return Err(Error::MalformedObject(format!(
                        "tree entries are not strictly sorted: {:?} then {name:?}",
                        prev.name
                    )));
                }
            }
            entries.push(TreeEntry {
                name,
                entry_type,
                mode,
                hash: ObjectId(h),
            });
        }
        Ok(Tree { entries })
    }

    pub fn find(&self, name: &str) -> Option<&TreeEntry> {
        self.entries.iter().find(|e| e.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_roundtrip() {
        let mut t = Tree::new();
        t.entries.push(TreeEntry {
            name: "b.txt".into(),
            entry_type: EntryType::Blob,
            mode: FileMode::REGULAR,
            hash: ObjectId([1; 32]),
        });
        t.entries.push(TreeEntry {
            name: "a.txt".into(),
            entry_type: EntryType::Blob,
            mode: FileMode::EXECUTABLE,
            hash: ObjectId([2; 32]),
        });
        t.sort_and_validate().unwrap();
        let body = t.body();
        let t2 = Tree::parse_body(&body).unwrap();
        assert_eq!(t.entries, t2.entries);
        // sorted: a then b
        assert_eq!(t.entries[0].name, "a.txt");
    }

    #[test]
    fn rejects_dot_dotdot_slash_null() {
        for n in [".", "..", "a/b", "x\0y", ""] {
            assert!(TreeEntry::validate_name(n).is_err());
        }
    }
}
