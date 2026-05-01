//! Generic LeVCS on-disk object framing.
//!
//! Per the v1.1 trust-root revision §2.1, every object on disk is laid out as:
//!
//! ```text
//! Offset      Size     Field
//! 0           4        Magic: "LVCS"
//! 4           1        Object type
//! 5           1        Format version (1)
//! 6           2        Reserved (zero)
//! 8           8        Body length (LE uint64)
//! 16          body_len Body
//! 16+body_len 1        Signature count (uint8)   -- signed objects only
//! 17+body_len 96*N     Signature entries         -- signed objects only
//! ```
//!
//! Blobs and trees are *not* signed objects (§2.1 lists Commit, Release, and
//! Authority as signed object types) and have no trailer. For uniformity the
//! parser exposes both header and trailer; the trailer is always zero-length
//! for blobs and trees.

use byteorder::{ByteOrder, LittleEndian};

use crate::error::Error;
use crate::hash::{blake3_hash, ObjectId};

pub const MAGIC: [u8; 4] = *b"LVCS";
pub const FORMAT_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 16;
pub const SIGNATURE_ENTRY_SIZE: usize = 96;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectType {
    Blob = 1,
    Tree = 2,
    Commit = 3,
    Release = 4,
    Authority = 5,
}

impl ObjectType {
    pub fn from_u8(b: u8) -> Result<Self, Error> {
        Ok(match b {
            1 => Self::Blob,
            2 => Self::Tree,
            3 => Self::Commit,
            4 => Self::Release,
            5 => Self::Authority,
            n => return Err(Error::UnknownObjectType(n)),
        })
    }

    pub fn is_signed(self) -> bool {
        matches!(self, Self::Commit | Self::Release | Self::Authority)
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Blob => "blob",
            Self::Tree => "tree",
            Self::Commit => "commit",
            Self::Release => "release",
            Self::Authority => "authority",
        }
    }
}

/// Decoded fixed-size object header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ObjectHeader {
    pub object_type: ObjectType,
    pub format_version: u8,
    pub body_len: u64,
}

impl ObjectHeader {
    pub fn encode(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0..4].copy_from_slice(&MAGIC);
        buf[4] = self.object_type as u8;
        buf[5] = self.format_version;
        // bytes 6..8 reserved (zero)
        LittleEndian::write_u64(&mut buf[8..16], self.body_len);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::MalformedObject(format!(
                "header truncated: got {} bytes, need {}",
                bytes.len(),
                HEADER_SIZE
            )));
        }
        if &bytes[0..4] != MAGIC.as_ref() {
            return Err(Error::MalformedObject("bad magic".into()));
        }
        let object_type = ObjectType::from_u8(bytes[4])?;
        let format_version = bytes[5];
        if format_version != FORMAT_VERSION {
            return Err(Error::UnsupportedFormatVersion(format_version));
        }
        if bytes[6] != 0 || bytes[7] != 0 {
            return Err(Error::MalformedObject("reserved bytes nonzero".into()));
        }
        let body_len = LittleEndian::read_u64(&bytes[8..16]);
        Ok(Self {
            object_type,
            format_version,
            body_len,
        })
    }
}

/// One entry in a signature trailer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SignatureEntry {
    pub public_key: [u8; 32],
    pub signature: [u8; 64],
}

impl SignatureEntry {
    pub fn encode(&self) -> [u8; SIGNATURE_ENTRY_SIZE] {
        let mut buf = [0u8; SIGNATURE_ENTRY_SIZE];
        buf[0..32].copy_from_slice(&self.public_key);
        buf[32..96].copy_from_slice(&self.signature);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < SIGNATURE_ENTRY_SIZE {
            return Err(Error::InvalidSignatureTrailer);
        }
        let mut pk = [0u8; 32];
        let mut sg = [0u8; 64];
        pk.copy_from_slice(&bytes[0..32]);
        sg.copy_from_slice(&bytes[32..96]);
        Ok(Self {
            public_key: pk,
            signature: sg,
        })
    }
}

/// A `SignedObject` is an object whose body has been augmented with a
/// signature trailer. The signature is computed over `BLAKE3(header || body)`
/// and stored after the body. Object hashes cover the entire signed object.
#[derive(Clone, Debug)]
pub struct SignedObject {
    pub object_type: ObjectType,
    pub body: Vec<u8>,
    pub signatures: Vec<SignatureEntry>,
}

impl SignedObject {
    pub fn new(object_type: ObjectType, body: Vec<u8>) -> Self {
        Self {
            object_type,
            body,
            signatures: Vec::new(),
        }
    }

    /// The 32-byte hash that signers sign: BLAKE3(header || body).
    pub fn signing_hash(&self) -> ObjectId {
        let header = ObjectHeader {
            object_type: self.object_type,
            format_version: FORMAT_VERSION,
            body_len: self.body.len() as u64,
        }
        .encode();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&header);
        hasher.update(&self.body);
        ObjectId(*hasher.finalize().as_bytes())
    }

    /// Serialize to the on-disk representation including signature trailer.
    pub fn serialize(&self) -> Vec<u8> {
        let header = ObjectHeader {
            object_type: self.object_type,
            format_version: FORMAT_VERSION,
            body_len: self.body.len() as u64,
        }
        .encode();
        let n = self.signatures.len();
        assert!(n <= 255, "too many signatures");
        let mut out =
            Vec::with_capacity(HEADER_SIZE + self.body.len() + 1 + n * SIGNATURE_ENTRY_SIZE);
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.body);
        out.push(n as u8);
        for s in &self.signatures {
            out.extend_from_slice(&s.encode());
        }
        out
    }

    /// Content hash (over the entire serialized object).
    pub fn object_id(&self) -> ObjectId {
        blake3_hash(&self.serialize())
    }

    /// Parse a signed object from its on-disk bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let header = ObjectHeader::decode(bytes)?;
        if !header.object_type.is_signed() {
            return Err(Error::MalformedObject(format!(
                "object type {} is not a signed object",
                header.object_type.name()
            )));
        }
        // Bounds-check every offset arithmetic step. A hostile peer can
        // set body_len or the trailer count to values that, when cast to
        // usize and summed, overflow — turning what should be a graceful
        // "body truncated" error into a panic. Use `checked_*` throughout.
        let body_start = HEADER_SIZE;
        let body_len = usize::try_from(header.body_len)
            .map_err(|_| Error::MalformedObject("body_len exceeds usize".into()))?;
        let body_end = body_start
            .checked_add(body_len)
            .ok_or_else(|| Error::MalformedObject("body offset overflow".into()))?;
        if bytes.len() < body_end + 1 {
            return Err(Error::MalformedObject("body truncated".into()));
        }
        let body = bytes[body_start..body_end].to_vec();
        let count = bytes[body_end] as usize;
        let trailer_start = body_end
            .checked_add(1)
            .ok_or_else(|| Error::MalformedObject("trailer offset overflow".into()))?;
        let trailer_size = count
            .checked_mul(SIGNATURE_ENTRY_SIZE)
            .ok_or(Error::InvalidSignatureTrailer)?;
        let trailer_end = trailer_start
            .checked_add(trailer_size)
            .ok_or(Error::InvalidSignatureTrailer)?;
        if bytes.len() < trailer_end {
            return Err(Error::InvalidSignatureTrailer);
        }
        let mut signatures = Vec::with_capacity(count);
        for i in 0..count {
            let off = trailer_start + i * SIGNATURE_ENTRY_SIZE;
            signatures.push(SignatureEntry::decode(
                &bytes[off..off + SIGNATURE_ENTRY_SIZE],
            )?);
        }
        if bytes.len() != trailer_end {
            return Err(Error::MalformedObject(format!(
                "trailing garbage after signed object: {} extra byte(s)",
                bytes.len() - trailer_end
            )));
        }
        Ok(Self {
            object_type: header.object_type,
            body,
            signatures,
        })
    }
}

/// A `RawObject` is a parsed but un-typed object. Useful when reading an
/// object from disk and dispatching by type.
#[derive(Clone, Debug)]
pub struct RawObject {
    pub object_type: ObjectType,
    pub body: Vec<u8>,
    pub signatures: Vec<SignatureEntry>,
}

impl RawObject {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let header = ObjectHeader::decode(bytes)?;
        // Same overflow concern as SignedObject::parse — see the note
        // there. Same checked-arithmetic discipline applied here.
        let body_start = HEADER_SIZE;
        let body_len = usize::try_from(header.body_len)
            .map_err(|_| Error::MalformedObject("body_len exceeds usize".into()))?;
        let body_end = body_start
            .checked_add(body_len)
            .ok_or_else(|| Error::MalformedObject("body offset overflow".into()))?;
        if bytes.len() < body_end {
            return Err(Error::MalformedObject("body truncated".into()));
        }
        let body = bytes[body_start..body_end].to_vec();
        let signatures = if header.object_type.is_signed() {
            if bytes.len() < body_end + 1 {
                return Err(Error::MalformedObject("missing signature trailer".into()));
            }
            let count = bytes[body_end] as usize;
            let trailer_start = body_end
                .checked_add(1)
                .ok_or_else(|| Error::MalformedObject("trailer offset overflow".into()))?;
            let trailer_size = count
                .checked_mul(SIGNATURE_ENTRY_SIZE)
                .ok_or(Error::InvalidSignatureTrailer)?;
            let trailer_end = trailer_start
                .checked_add(trailer_size)
                .ok_or(Error::InvalidSignatureTrailer)?;
            if bytes.len() < trailer_end {
                return Err(Error::InvalidSignatureTrailer);
            }
            let mut sigs = Vec::with_capacity(count);
            for i in 0..count {
                let off = trailer_start + i * SIGNATURE_ENTRY_SIZE;
                sigs.push(SignatureEntry::decode(
                    &bytes[off..off + SIGNATURE_ENTRY_SIZE],
                )?);
            }
            sigs
        } else {
            Vec::new()
        };
        Ok(Self {
            object_type: header.object_type,
            body,
            signatures,
        })
    }

    /// Serialize a raw object (with empty trailer for unsigned types).
    pub fn serialize(&self) -> Vec<u8> {
        let header = ObjectHeader {
            object_type: self.object_type,
            format_version: FORMAT_VERSION,
            body_len: self.body.len() as u64,
        }
        .encode();
        let signed = self.object_type.is_signed();
        let n = self.signatures.len();
        let trailer_size = if signed {
            1 + n * SIGNATURE_ENTRY_SIZE
        } else {
            0
        };
        let mut out = Vec::with_capacity(HEADER_SIZE + self.body.len() + trailer_size);
        out.extend_from_slice(&header);
        out.extend_from_slice(&self.body);
        if signed {
            out.push(n as u8);
            for s in &self.signatures {
                out.extend_from_slice(&s.encode());
            }
        }
        out
    }

    pub fn object_id(&self) -> ObjectId {
        blake3_hash(&self.serialize())
    }
}

/// Helper used by unsigned object types (Blob, Tree) to wrap a body in the
/// fixed object framing.
pub fn frame_unsigned(object_type: ObjectType, body: &[u8]) -> Vec<u8> {
    debug_assert!(!object_type.is_signed());
    let header = ObjectHeader {
        object_type,
        format_version: FORMAT_VERSION,
        body_len: body.len() as u64,
    }
    .encode();
    let mut out = Vec::with_capacity(HEADER_SIZE + body.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = ObjectHeader {
            object_type: ObjectType::Blob,
            format_version: 1,
            body_len: 42,
        };
        let bytes = h.encode();
        let h2 = ObjectHeader::decode(&bytes).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn signed_object_roundtrip() {
        let mut so = SignedObject::new(ObjectType::Commit, b"hello".to_vec());
        so.signatures.push(SignatureEntry {
            public_key: [7u8; 32],
            signature: [9u8; 64],
        });
        let bytes = so.serialize();
        let so2 = SignedObject::parse(&bytes).unwrap();
        assert_eq!(so.object_type, so2.object_type);
        assert_eq!(so.body, so2.body);
        assert_eq!(so.signatures, so2.signatures);
    }

    #[test]
    fn unknown_type_rejected() {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(&MAGIC);
        bytes[4] = 99;
        bytes[5] = 1;
        assert!(ObjectHeader::decode(&bytes).is_err());
    }
}
