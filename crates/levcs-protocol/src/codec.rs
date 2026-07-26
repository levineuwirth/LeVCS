//! Small checked canonical-binary codec used by the frozen v2 contracts.
//!
//! This deliberately does not use serde. Signed protocol bytes must have one
//! representation, reject trailing data, and reject hostile lengths before
//! allocation.

use thiserror::Error;

pub const MAX_CANONICAL_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_CANONICAL_ITEMS: usize = 1_000_000;
pub const MAX_CANONICAL_STRING: usize = 4 * 1024;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CodecError {
    #[error("unexpected end of canonical input")]
    UnexpectedEof,
    #[error("trailing canonical bytes: {0}")]
    TrailingBytes(usize),
    #[error("invalid discriminant {value} for {kind}")]
    InvalidDiscriminant { kind: &'static str, value: u8 },
    #[error("{field} exceeds limit: {actual} > {limit}")]
    Limit {
        field: &'static str,
        actual: u64,
        limit: u64,
    },
    #[error("invalid canonical field {field}: {reason}")]
    Invalid {
        field: &'static str,
        reason: &'static str,
    },
    #[error("integer overflow while decoding {0}")]
    Overflow(&'static str),
    #[error("canonical string is not UTF-8")]
    Utf8,
}

pub type CodecResult<T> = Result<T, CodecError>;

#[derive(Default)]
pub(crate) struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn i64(&mut self, value: i64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn bytes(&mut self, field: &'static str, value: &[u8]) -> CodecResult<()> {
        self.bounded_bytes(field, value, MAX_CANONICAL_BYTES)
    }

    pub(crate) fn bounded_bytes(
        &mut self,
        field: &'static str,
        value: &[u8],
        limit: usize,
    ) -> CodecResult<()> {
        if value.len() > limit {
            return Err(CodecError::Limit {
                field,
                actual: value.len() as u64,
                limit: limit as u64,
            });
        }
        let len = u32::try_from(value.len()).map_err(|_| CodecError::Limit {
            field,
            actual: value.len() as u64,
            limit: u32::MAX as u64,
        })?;
        self.u32(len);
        self.fixed(value);
        Ok(())
    }

    pub(crate) fn string(&mut self, field: &'static str, value: &str) -> CodecResult<()> {
        self.bounded_bytes(field, value.as_bytes(), MAX_CANONICAL_STRING)
    }

    pub(crate) fn count(&mut self, field: &'static str, count: usize) -> CodecResult<()> {
        if count > MAX_CANONICAL_ITEMS {
            return Err(CodecError::Limit {
                field,
                actual: count as u64,
                limit: MAX_CANONICAL_ITEMS as u64,
            });
        }
        let count = u32::try_from(count).map_err(|_| CodecError::Limit {
            field,
            actual: count as u64,
            limit: u32::MAX as u64,
        })?;
        self.u32(count);
        Ok(())
    }

    pub(crate) fn finish(self) -> CodecResult<Vec<u8>> {
        if self.bytes.len() > MAX_CANONICAL_BYTES {
            return Err(CodecError::Limit {
                field: "canonical message",
                actual: self.bytes.len() as u64,
                limit: MAX_CANONICAL_BYTES as u64,
            });
        }
        Ok(self.bytes)
    }
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> CodecResult<Self> {
        if bytes.len() > MAX_CANONICAL_BYTES {
            return Err(CodecError::Limit {
                field: "canonical message",
                actual: bytes.len() as u64,
                limit: MAX_CANONICAL_BYTES as u64,
            });
        }
        Ok(Self { bytes, cursor: 0 })
    }

    pub(crate) fn remaining(&self) -> usize {
        self.bytes.len() - self.cursor
    }

    fn take(&mut self, len: usize) -> CodecResult<&'a [u8]> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(CodecError::Overflow("canonical offset"))?;
        let out = self
            .bytes
            .get(self.cursor..end)
            .ok_or(CodecError::UnexpectedEof)?;
        self.cursor = end;
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> CodecResult<u8> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn bool(&mut self, field: &'static str) -> CodecResult<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CodecError::Invalid {
                field,
                reason: "boolean must be 0 or 1",
            }),
        }
    }

    pub(crate) fn u16(&mut self) -> CodecResult<u16> {
        let mut value = [0; 2];
        value.copy_from_slice(self.take(2)?);
        Ok(u16::from_le_bytes(value))
    }

    pub(crate) fn u32(&mut self) -> CodecResult<u32> {
        let mut value = [0; 4];
        value.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(value))
    }

    pub(crate) fn u64(&mut self) -> CodecResult<u64> {
        let mut value = [0; 8];
        value.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(value))
    }

    pub(crate) fn i64(&mut self) -> CodecResult<i64> {
        let mut value = [0; 8];
        value.copy_from_slice(self.take(8)?);
        Ok(i64::from_le_bytes(value))
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> CodecResult<[u8; N]> {
        let mut value = [0; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    pub(crate) fn bytes(&mut self, field: &'static str) -> CodecResult<Vec<u8>> {
        self.bounded_bytes(field, MAX_CANONICAL_BYTES)
    }

    pub(crate) fn bounded_bytes(
        &mut self,
        field: &'static str,
        limit: usize,
    ) -> CodecResult<Vec<u8>> {
        let len = usize::try_from(self.u32()?).map_err(|_| CodecError::Overflow(field))?;
        if len > limit {
            return Err(CodecError::Limit {
                field,
                actual: len as u64,
                limit: limit as u64,
            });
        }
        Ok(self.take(len)?.to_vec())
    }

    pub(crate) fn string(&mut self, field: &'static str) -> CodecResult<String> {
        let bytes = self.bounded_bytes(field, MAX_CANONICAL_STRING)?;
        String::from_utf8(bytes).map_err(|_| CodecError::Utf8)
    }

    pub(crate) fn count(&mut self, field: &'static str) -> CodecResult<usize> {
        let count = usize::try_from(self.u32()?).map_err(|_| CodecError::Overflow(field))?;
        if count > MAX_CANONICAL_ITEMS {
            return Err(CodecError::Limit {
                field,
                actual: count as u64,
                limit: MAX_CANONICAL_ITEMS as u64,
            });
        }
        Ok(count)
    }

    pub(crate) fn finish(self) -> CodecResult<()> {
        if self.cursor != self.bytes.len() {
            return Err(CodecError::TrailingBytes(self.bytes.len() - self.cursor));
        }
        Ok(())
    }
}

pub trait CanonicalCodec: Sized {
    fn encode_canonical(&self) -> CodecResult<Vec<u8>>;
    fn decode_canonical(bytes: &[u8]) -> CodecResult<Self>;
}

pub fn domain_digest(domain: &'static [u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}
