//! Release object body, per the v1.1 trust-root revision §2.3.
//!
//! Field             Type         Description
//! tree              32 bytes
//! parent_release    32 bytes     (zero for first release)
//! predecessor       32 bytes     hash of the commit being released
//! authority         32 bytes
//! declarer_key      32 bytes
//! timestamp         8 bytes      Unix microseconds, LE int64
//! label_len         2 bytes      uint16 LE, max 256
//! label             N bytes      UTF-8
//! notes_len         4 bytes      uint32 LE
//! notes             N bytes      UTF-8

use byteorder::{ByteOrder, LittleEndian};

use crate::error::Error;
use crate::hash::ObjectId;
use crate::object::{ObjectType, SignedObject};

#[derive(Clone, Debug)]
pub struct Release {
    pub tree: ObjectId,
    pub parent_release: ObjectId,
    pub predecessor: ObjectId,
    pub authority: ObjectId,
    pub declarer_key: [u8; 32],
    pub timestamp_micros: i64,
    pub label: String,
    pub notes: String,
}

impl Release {
    pub fn body(&self) -> Result<Vec<u8>, Error> {
        if self.label.len() > 256 {
            return Err(Error::MalformedObject("release label too long".into()));
        }
        if self.notes.len() > u32::MAX as usize {
            return Err(Error::MalformedObject("release notes too large".into()));
        }
        let mut out = Vec::with_capacity(32 * 4 + 32 + 8 + 2 + self.label.len() + 4 + self.notes.len());
        out.extend_from_slice(self.tree.as_bytes());
        out.extend_from_slice(self.parent_release.as_bytes());
        out.extend_from_slice(self.predecessor.as_bytes());
        out.extend_from_slice(self.authority.as_bytes());
        out.extend_from_slice(&self.declarer_key);
        let mut ts = [0u8; 8];
        LittleEndian::write_i64(&mut ts, self.timestamp_micros);
        out.extend_from_slice(&ts);
        let mut ll = [0u8; 2];
        LittleEndian::write_u16(&mut ll, self.label.len() as u16);
        out.extend_from_slice(&ll);
        out.extend_from_slice(self.label.as_bytes());
        let mut nl = [0u8; 4];
        LittleEndian::write_u32(&mut nl, self.notes.len() as u32);
        out.extend_from_slice(&nl);
        out.extend_from_slice(self.notes.as_bytes());
        Ok(out)
    }

    pub fn parse_body(body: &[u8]) -> Result<Self, Error> {
        let min = 32 * 5 + 8 + 2;
        if body.len() < min {
            return Err(Error::MalformedObject("release body truncated".into()));
        }
        let mut p = 0usize;
        let take32 = |p: &mut usize| -> [u8; 32] {
            let mut h = [0u8; 32];
            h.copy_from_slice(&body[*p..*p + 32]);
            *p += 32;
            h
        };
        let tree = ObjectId(take32(&mut p));
        let parent_release = ObjectId(take32(&mut p));
        let predecessor = ObjectId(take32(&mut p));
        let authority = ObjectId(take32(&mut p));
        let declarer_key = take32(&mut p);
        let timestamp_micros = LittleEndian::read_i64(&body[p..p + 8]);
        p += 8;
        let label_len = LittleEndian::read_u16(&body[p..p + 2]) as usize;
        p += 2;
        if body.len() < p + label_len + 4 {
            return Err(Error::MalformedObject("release label/notes truncated".into()));
        }
        let label = std::str::from_utf8(&body[p..p + label_len])
            .map_err(|_| Error::MalformedObject("release label not UTF-8".into()))?
            .to_string();
        p += label_len;
        let notes_len = LittleEndian::read_u32(&body[p..p + 4]) as usize;
        p += 4;
        if body.len() < p + notes_len {
            return Err(Error::MalformedObject("release notes truncated".into()));
        }
        let notes = std::str::from_utf8(&body[p..p + notes_len])
            .map_err(|_| Error::MalformedObject("release notes not UTF-8".into()))?
            .to_string();
        p += notes_len;
        if p != body.len() {
            return Err(Error::MalformedObject("trailing bytes after release notes".into()));
        }
        Ok(Self {
            tree, parent_release, predecessor, authority, declarer_key,
            timestamp_micros, label, notes,
        })
    }

    pub fn into_signed(self) -> Result<SignedObject, Error> {
        Ok(SignedObject::new(ObjectType::Release, self.body()?))
    }

    pub fn from_signed(s: &SignedObject) -> Result<Self, Error> {
        if s.object_type != ObjectType::Release {
            return Err(Error::MalformedObject(format!(
                "expected release, got {}", s.object_type.name()
            )));
        }
        if s.signatures.is_empty() {
            return Err(Error::MalformedObject("release must have at least one signature".into()));
        }
        let r = Release::parse_body(&s.body)?;
        if r.declarer_key != s.signatures[0].public_key {
            return Err(Error::MalformedObject(
                "release declarer_key disagrees with first signature key".into(),
            ));
        }
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_body_roundtrip() {
        let r = Release {
            tree: ObjectId([1; 32]),
            parent_release: ObjectId([0; 32]),
            predecessor: ObjectId([2; 32]),
            authority: ObjectId([3; 32]),
            declarer_key: [4; 32],
            timestamp_micros: 1_700_000_000_000_000,
            label: "v0.1.0".into(),
            notes: "first release".into(),
        };
        let body = r.body().unwrap();
        let r2 = Release::parse_body(&body).unwrap();
        assert_eq!(r.label, r2.label);
        assert_eq!(r.notes, r2.notes);
        assert_eq!(r.tree, r2.tree);
    }
}
