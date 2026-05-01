use std::fmt;
use std::str::FromStr;

use crate::error::Error;

/// 32-byte BLAKE3 content-address.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct ObjectId(pub [u8; 32]);

pub const ZERO_ID: ObjectId = ObjectId([0u8; 32]);

impl ObjectId {
    pub const fn from_bytes(b: [u8; 32]) -> Self { Self(b) }

    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    pub fn to_hex(&self) -> String { hex::encode(self.0) }

    pub fn is_zero(&self) -> bool { self.0 == [0u8; 32] }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(Error::InvalidHex(format!(
                "expected 32 bytes (64 hex chars), got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(ObjectId(arr))
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.to_hex())
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for ObjectId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> { Self::from_hex(s) }
}

/// Compute a BLAKE3 hash with no key, returning an `ObjectId`.
pub fn blake3_hash(data: &[u8]) -> ObjectId {
    let h = blake3::hash(data);
    ObjectId(*h.as_bytes())
}

/// Streaming BLAKE3 hasher for incremental hashing.
pub struct Hasher(blake3::Hasher);

impl Hasher {
    pub fn new() -> Self { Self(blake3::Hasher::new()) }
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.0.update(data);
        self
    }
    pub fn finalize(self) -> ObjectId {
        ObjectId(*self.0.finalize().as_bytes())
    }
}

impl Default for Hasher {
    fn default() -> Self { Self::new() }
}
