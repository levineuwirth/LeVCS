//! Commit object body, per the v1.1 trust-root revision §2.2.
//!
//! Field           Type         Description
//! tree            32 bytes     Hash of the root tree
//! parent_count    1 byte
//! parents         32*N bytes
//! authority       32 bytes     Hash of the authority object in effect
//! author_key      32 bytes     Public key (Ed25519) of the author
//! timestamp       8 bytes      Unix microseconds, LE int64
//! flags           1 byte       Bit 0: modifies authority
//!                              Bit 1: fork commit
//! message_len     4 bytes
//! message         N bytes      UTF-8

use byteorder::{ByteOrder, LittleEndian};

use crate::error::Error;
use crate::hash::ObjectId;
use crate::object::{ObjectType, SignatureEntry, SignedObject};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CommitFlags(pub u8);

impl CommitFlags {
    pub const NONE: CommitFlags = CommitFlags(0);
    pub const MODIFIES_AUTHORITY: CommitFlags = CommitFlags(0b01);
    pub const FORK: CommitFlags = CommitFlags(0b10);

    pub fn modifies_authority(self) -> bool { self.0 & 0b01 != 0 }
    pub fn is_fork(self) -> bool { self.0 & 0b10 != 0 }

    pub fn raw(self) -> u8 { self.0 }

    pub fn validate(self) -> Result<(), Error> {
        if self.0 & !0b11 != 0 {
            return Err(Error::MalformedObject(format!(
                "commit flags has reserved bits set: {:#x}", self.0
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Commit {
    pub tree: ObjectId,
    pub parents: Vec<ObjectId>,
    pub authority: ObjectId,
    pub author_key: [u8; 32],
    pub timestamp_micros: i64,
    pub flags: CommitFlags,
    pub message: String,
}

impl Commit {
    pub fn body(&self) -> Result<Vec<u8>, Error> {
        if self.parents.len() > 255 {
            return Err(Error::MalformedObject("too many parents".into()));
        }
        if self.message.len() > u32::MAX as usize {
            return Err(Error::MalformedObject("message too large".into()));
        }
        self.flags.validate()?;
        let mut out = Vec::with_capacity(
            32 + 1 + self.parents.len() * 32 + 32 + 32 + 8 + 1 + 4 + self.message.len(),
        );
        out.extend_from_slice(self.tree.as_bytes());
        out.push(self.parents.len() as u8);
        for p in &self.parents {
            out.extend_from_slice(p.as_bytes());
        }
        out.extend_from_slice(self.authority.as_bytes());
        out.extend_from_slice(&self.author_key);
        let mut ts = [0u8; 8];
        LittleEndian::write_i64(&mut ts, self.timestamp_micros);
        out.extend_from_slice(&ts);
        out.push(self.flags.0);
        let mut len = [0u8; 4];
        LittleEndian::write_u32(&mut len, self.message.len() as u32);
        out.extend_from_slice(&len);
        out.extend_from_slice(self.message.as_bytes());
        Ok(out)
    }

    pub fn parse_body(body: &[u8]) -> Result<Self, Error> {
        let need = 32 + 1;
        if body.len() < need {
            return Err(Error::MalformedObject("commit body too short for tree+parent_count".into()));
        }
        let mut tree = [0u8; 32];
        tree.copy_from_slice(&body[0..32]);
        let parent_count = body[32] as usize;
        let parents_end = 33 + parent_count * 32;
        if body.len() < parents_end + 32 + 32 + 8 + 1 + 4 {
            return Err(Error::MalformedObject("commit body truncated".into()));
        }
        let mut parents = Vec::with_capacity(parent_count);
        for i in 0..parent_count {
            let off = 33 + i * 32;
            let mut p = [0u8; 32];
            p.copy_from_slice(&body[off..off + 32]);
            parents.push(ObjectId(p));
        }
        let mut p = parents_end;
        let mut authority = [0u8; 32];
        authority.copy_from_slice(&body[p..p + 32]);
        p += 32;
        let mut author_key = [0u8; 32];
        author_key.copy_from_slice(&body[p..p + 32]);
        p += 32;
        let timestamp_micros = LittleEndian::read_i64(&body[p..p + 8]);
        p += 8;
        let flags = CommitFlags(body[p]);
        flags.validate()?;
        p += 1;
        let msg_len = LittleEndian::read_u32(&body[p..p + 4]) as usize;
        p += 4;
        if body.len() < p + msg_len {
            return Err(Error::MalformedObject("commit message truncated".into()));
        }
        let message = std::str::from_utf8(&body[p..p + msg_len])
            .map_err(|_| Error::MalformedObject("commit message not UTF-8".into()))?
            .to_string();
        p += msg_len;
        if p != body.len() {
            return Err(Error::MalformedObject(format!(
                "trailing {} byte(s) after commit message", body.len() - p
            )));
        }
        Ok(Self {
            tree: ObjectId(tree),
            parents,
            authority: ObjectId(authority),
            author_key,
            timestamp_micros,
            flags,
            message,
        })
    }

    pub fn into_signed(self) -> Result<SignedObject, Error> {
        Ok(SignedObject::new(ObjectType::Commit, self.body()?))
    }

    /// Parse from a complete signed-object's components.
    pub fn from_signed(s: &SignedObject) -> Result<Self, Error> {
        if s.object_type != ObjectType::Commit {
            return Err(Error::MalformedObject(format!(
                "expected commit, got {}", s.object_type.name()
            )));
        }
        if s.signatures.len() != 1 {
            return Err(Error::MalformedObject(format!(
                "commit must have exactly 1 signature, got {}", s.signatures.len()
            )));
        }
        let c = Commit::parse_body(&s.body)?;
        if c.author_key != s.signatures[0].public_key {
            return Err(Error::MalformedObject(
                "commit author_key disagrees with trailer signature key".into(),
            ));
        }
        Ok(c)
    }

    /// Convenience: produce a partial signature entry with just the key set;
    /// callers fill in `signature` after computing the Ed25519 signature.
    pub fn signature_template(&self) -> SignatureEntry {
        SignatureEntry { public_key: self.author_key, signature: [0u8; 64] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_body_roundtrip() {
        let c = Commit {
            tree: ObjectId([1; 32]),
            parents: vec![ObjectId([2; 32]), ObjectId([3; 32])],
            authority: ObjectId([4; 32]),
            author_key: [5; 32],
            timestamp_micros: 1_700_000_000_000_000,
            flags: CommitFlags::NONE,
            message: "hello world".into(),
        };
        let body = c.body().unwrap();
        let c2 = Commit::parse_body(&body).unwrap();
        assert_eq!(c.tree, c2.tree);
        assert_eq!(c.parents, c2.parents);
        assert_eq!(c.message, c2.message);
        assert_eq!(c.flags.0, c2.flags.0);
    }
}
