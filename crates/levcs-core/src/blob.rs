//! Blob object: an immutable byte sequence representing the contents of a
//! single file. The blob body is the raw file contents byte-for-byte.

use crate::hash::{blake3_hash, ObjectId};
use crate::object::{frame_unsigned, ObjectType};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blob {
    pub bytes: Vec<u8>,
}

impl Blob {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn serialize(&self) -> Vec<u8> {
        frame_unsigned(ObjectType::Blob, &self.bytes)
    }

    pub fn object_id(&self) -> ObjectId {
        blake3_hash(&self.serialize())
    }

    pub fn from_body(body: Vec<u8>) -> Self {
        Self { bytes: body }
    }
}
