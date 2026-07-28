//! Physical on-disk format: frames, journal headers, segment footers,
//! manifests, and checkpoints.
//!
//! **Shared file.** The lead owns the type definitions, constants, domain
//! strings, and function signatures in this file (D0). **A1 JournalWriter**
//! fills the bodies and owns the golden vectors. **A2 RecoveryIndex** consumes
//! this file read-only and files an interface change request rather than
//! editing it. That split is what keeps A1 and A2 genuinely parallel
//! (scope 2.1).
//!
//! Plan §13 keeps the physical format internal: nothing outside this crate
//! binds to these bytes, and future workflow code binds only to logical
//! snapshots and events.

use levcs_core::{ObjectId, ObjectType};
use levcs_protocol::v2::{
    ProjectionMode, RefMutation, RefTarget, SignedCommittedTransactionV1, SourceKindV1,
    StagedProjectionInstallV1, TransactionEvidenceV1, TypedRefCas, MAX_REF_UPDATES,
};
use levcs_protocol::CanonicalCodec;

use crate::types::StoreError;

// ---------------------------------------------------------------------------
// Constants — frozen in D0. Changing any of these invalidates the golden
// frame corpus and the crash fixtures.
// ---------------------------------------------------------------------------

pub const STORAGE_VERSION: u16 = 1;

pub const FRAME_MAGIC: [u8; 8] = *b"LVCSFRM\0";
pub const FRAME_TRAILER_MAGIC: [u8; 8] = *b"LVCSEND\0";
pub const JOURNAL_MAGIC: [u8; 8] = *b"LVCSJRN\0";
pub const SEGMENT_FOOTER_MAGIC: [u8; 8] = *b"LVCSSEG\0";
pub const MANIFEST_MAGIC: [u8; 8] = *b"LVCSMAN\0";
pub const CURRENT_MAGIC: [u8; 8] = *b"LVCSCUR\0";
pub const CHECKPOINT_MAGIC: [u8; 8] = *b"LVCSCKP\0";
pub const FORMAT_MAGIC: [u8; 8] = *b"LVCSFMT\0";

pub const FRAME_HEADER_LEN: usize = 176;
pub const FRAME_TRAILER_LEN: usize = 48;
pub const MIN_FRAME_LEN: u64 = (FRAME_HEADER_LEN + FRAME_TRAILER_LEN) as u64;
pub const FRAME_ALIGNMENT: u64 = 8;

pub const JOURNAL_HEADER_LEN: usize = 512;

/// Domain-separated digest inputs. Distinct domains keep a frame digest from
/// ever equalling a payload digest over related bytes.
pub const FRAME_DIGEST_DOMAIN: &[u8] = b"levcs-frame/v1\0";
pub const FRAME_PAYLOAD_DIGEST_DOMAIN: &[u8] = b"levcs-frame-payload/v1\0";
pub const JOURNAL_HEADER_DIGEST_DOMAIN: &[u8] = b"levcs-journal-header/v1\0";
pub const SEGMENT_FOOTER_DIGEST_DOMAIN: &[u8] = b"levcs-segment-footer/v1\0";
pub const MANIFEST_DIGEST_DOMAIN: &[u8] = b"levcs-manifest/v1\0";
pub const CURRENT_DIGEST_DOMAIN: &[u8] = b"levcs-current/v1\0";
pub const CHECKPOINT_DIGEST_DOMAIN: &[u8] = b"levcs-checkpoint/v1\0";
pub const FORMAT_DIGEST_DOMAIN: &[u8] = b"levcs-format/v1\0";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a byte sequence is not a valid frame.
///
/// One variant per completeness condition, so a test can assert *which*
/// condition rejected a mutation rather than only that something did. The
/// scope 5 charter forbids a catch-all arm; this taxonomy is what makes
/// individual assertion possible.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("frame length is malformed or exceeds the containing file")]
    Length,
    #[error("frame header magic or storage version does not match")]
    HeaderMagic,
    #[error("frame header_len is not the value for this storage version")]
    HeaderLen,
    #[error("frame journal_id does not match the containing file")]
    JournalId,
    #[error("frame trailer magic or repeated total_len does not match")]
    Trailer,
    #[error("frame digest does not recompute")]
    FrameDigest,
    #[error("payload digest does not recompute")]
    PayloadDigest,
    #[error("frame flags must be zero in storage version 1")]
    Flags,
    #[error("frame padding must be zero")]
    Padding,
    #[error("frame payload is not canonical: {0}")]
    Payload(&'static str),
    #[error("root uuid does not match this store root")]
    RootUuid,
}

impl From<FrameError> for StoreError {
    fn from(e: FrameError) -> Self {
        StoreError::Corruption(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

/// Fixed 176-byte frame header. Field order and offsets are frozen; see
/// scope 3.3 for the byte table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameHeader {
    /// Must be zero in storage version 1. Any set bit rejects: without this,
    /// 2^32 flag values yield a frame satisfying every other condition that
    /// the writer never produced.
    pub flags: u32,
    /// Header + payload + padding + trailer.
    pub total_len: u64,
    pub journal_id: [u8; 16],
    pub shard_sequence: u64,
    pub repo_sequence: u64,
    pub namespace: [u8; 32],
    pub operation_id: [u8; 16],
    pub operation_digest: ObjectId,
    pub payload_len: u64,
    pub payload_digest: ObjectId,
}

/// A whole frame: header, canonical payload, and the trailer that certifies
/// both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub header: FrameHeader,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Encode to the exact on-disk bytes.
    ///
    /// Deterministic: every field is written from `self`, the padding is
    /// zeros, and both digests are recomputed rather than carried, so the same
    /// `Frame` yields identical bytes on every run. That is what makes the
    /// golden corpus stable.
    ///
    /// `total_len` and `payload_len` in `self.header` are **derived, not
    /// trusted**: they are recomputed from `self.payload` and any disagreement
    /// is rejected rather than silently corrected. A writer that could hand in
    /// a header whose lengths disagree with its payload could produce a frame
    /// that fails its own completeness check after the fence.
    ///
    /// There is no `root_uuid` parameter and no `root_uuid` field: the
    /// storage-version-1 header table of scope 3.3 has neither. Root binding
    /// is already sound without one — a frame carries `journal_id`, the
    /// journal header carries `root_uuid`, and a frame is only ever read out
    /// of a file whose header was validated against the root that opened it.
    /// Adding a header field would change the frozen 176-byte table for no
    /// gain. (The D0 signature took a `root_uuid` it could not use; the lead
    /// approved dropping it.)
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.header.flags != 0 {
            return Err(FrameError::Flags);
        }
        let payload_len = self.payload.len() as u64;
        if self.header.payload_len != payload_len {
            return Err(FrameError::Length);
        }
        let total_len = frame_total_len(payload_len);
        if self.header.total_len != total_len {
            return Err(FrameError::Length);
        }
        let total = usize::try_from(total_len).map_err(|_| FrameError::Length)?;
        let padding = frame_padding_len(payload_len) as usize;

        let mut bytes = vec![0u8; total];
        {
            let header = &mut bytes[..FRAME_HEADER_LEN];
            header[off::MAGIC..off::MAGIC + 8].copy_from_slice(&FRAME_MAGIC);
            header[off::STORAGE_VERSION..off::STORAGE_VERSION + 2]
                .copy_from_slice(&STORAGE_VERSION.to_le_bytes());
            header[off::HEADER_LEN..off::HEADER_LEN + 2]
                .copy_from_slice(&(FRAME_HEADER_LEN as u16).to_le_bytes());
            header[off::FLAGS..off::FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());
            header[off::TOTAL_LEN..off::TOTAL_LEN + 8].copy_from_slice(&total_len.to_le_bytes());
            header[off::JOURNAL_ID..off::JOURNAL_ID + 16].copy_from_slice(&self.header.journal_id);
            header[off::SHARD_SEQUENCE..off::SHARD_SEQUENCE + 8]
                .copy_from_slice(&self.header.shard_sequence.to_le_bytes());
            header[off::REPO_SEQUENCE..off::REPO_SEQUENCE + 8]
                .copy_from_slice(&self.header.repo_sequence.to_le_bytes());
            header[off::NAMESPACE..off::NAMESPACE + 32].copy_from_slice(&self.header.namespace);
            header[off::OPERATION_ID..off::OPERATION_ID + 16]
                .copy_from_slice(&self.header.operation_id);
            header[off::OPERATION_DIGEST..off::OPERATION_DIGEST + 32]
                .copy_from_slice(self.header.operation_digest.as_bytes());
            header[off::PAYLOAD_LEN..off::PAYLOAD_LEN + 8]
                .copy_from_slice(&payload_len.to_le_bytes());
            header[off::PAYLOAD_DIGEST..off::PAYLOAD_DIGEST + 32]
                .copy_from_slice(digest(FRAME_PAYLOAD_DIGEST_DOMAIN, &self.payload).as_bytes());
        }

        let payload_end = FRAME_HEADER_LEN + self.payload.len();
        bytes[FRAME_HEADER_LEN..payload_end].copy_from_slice(&self.payload);
        // The padding stays as the zeros `vec![0u8; total]` already wrote;
        // condition 8 pins it, so it is never a covert region.
        debug_assert!(bytes[payload_end..payload_end + padding]
            .iter()
            .all(|b| *b == 0));

        let trailer_at = total - FRAME_TRAILER_LEN;
        bytes[trailer_at + off::TRAILER_MAGIC..trailer_at + off::TRAILER_MAGIC + 8]
            .copy_from_slice(&FRAME_TRAILER_MAGIC);
        bytes[trailer_at + off::TRAILER_TOTAL_LEN..trailer_at + off::TRAILER_TOTAL_LEN + 8]
            .copy_from_slice(&total_len.to_le_bytes());

        // The frame digest is the last thing written and covers everything
        // before it, so the final bytes on the device certify the whole frame.
        let digest_at = trailer_at + off::TRAILER_DIGEST;
        let frame_digest = digest(FRAME_DIGEST_DOMAIN, &bytes[..digest_at]);
        bytes[digest_at..].copy_from_slice(frame_digest.as_bytes());

        Ok(bytes)
    }

    /// Decode a frame from exactly its own bytes.
    ///
    /// `bytes.len()` must equal the frame's `total_len`: a caller that has a
    /// larger buffer proves completeness with [`verify_complete`] first and
    /// then slices. Trailing bytes are a rejection, in the Phase 0 discipline.
    pub fn decode(bytes: &[u8], journal_id: &[u8; 16]) -> Result<Self, FrameError> {
        let header = verify_complete(bytes, journal_id, bytes.len() as u64)?;
        if bytes.len() as u64 != header.total_len {
            return Err(FrameError::Length);
        }
        let payload_len = header.payload_len as usize;
        let payload = bytes[FRAME_HEADER_LEN..FRAME_HEADER_LEN + payload_len].to_vec();
        Ok(Self { header, payload })
    }
}

/// Prove a byte range is a complete frame.
///
/// **This is the definition recovery uses and the first thing the scope 5
/// charter directs an adversarial reviewer to attack.** All conditions in
/// scope 3.3 must hold; each rejection returns its own `FrameError` variant so
/// that a test can assert which condition fired.
///
/// The trailer exists precisely so a torn write cannot leave a
/// self-consistent frame: the last bytes written are the ones that certify the
/// whole.
///
/// `bytes` may be longer than the frame — a tail scanner hands in whatever it
/// read — but never shorter: a short buffer is condition 1 failing.
/// `file_remaining` is the number of bytes between this frame's offset and the
/// journal's preallocated length.
///
/// # Evaluation order
///
/// The conditions are **not** evaluated in the order scope 3.3 lists them, and
/// they cannot be. `frame_digest` (condition 5) covers the header, the
/// padding, and the trailer, so it also fails for any mutation of `flags`
/// (condition 7), of the padding (condition 8), of `journal_id` (condition 3),
/// or of the trailer (condition 4). Evaluating in the listed order would
/// report `FrameDigest` for every one of them, and scope 4-A1 deliverable 7
/// requires each condition to be independently assertable. Every condition
/// whose bytes the digest covers is therefore checked *before* the digest.
/// This is an evaluation-order requirement the scope document does not state;
/// see the A1 report.
pub fn verify_complete(
    bytes: &[u8],
    journal_id: &[u8; 16],
    file_remaining: u64,
) -> Result<FrameHeader, FrameError> {
    // --- condition 1 (partial): enough bytes to read a header at all -------
    if bytes.len() < FRAME_HEADER_LEN {
        return Err(FrameError::Length);
    }
    let header = &bytes[..FRAME_HEADER_LEN];

    // --- condition 2: header magic and storage version --------------------
    if header[off::MAGIC..off::MAGIC + 8] != FRAME_MAGIC {
        return Err(FrameError::HeaderMagic);
    }
    if u16::from_le_bytes([
        header[off::STORAGE_VERSION],
        header[off::STORAGE_VERSION + 1],
    ]) != STORAGE_VERSION
    {
        return Err(FrameError::HeaderMagic);
    }

    // --- condition 2 (header_len half), given its own variant --------------
    if u16::from_le_bytes([header[off::HEADER_LEN], header[off::HEADER_LEN + 1]])
        != FRAME_HEADER_LEN as u16
    {
        return Err(FrameError::HeaderLen);
    }

    // --- condition 1: total_len is well formed and inside the file ---------
    let total_len = read_u64(header, off::TOTAL_LEN);
    let payload_len = read_u64(header, off::PAYLOAD_LEN);
    if total_len < MIN_FRAME_LEN
        || total_len % FRAME_ALIGNMENT != 0
        || total_len > file_remaining
        || total_len > bytes.len() as u64
    {
        return Err(FrameError::Length);
    }
    // The three declared lengths must agree exactly. Without this the padding
    // region of condition 8 would not have a single well-defined extent.
    if payload_len > total_len || frame_total_len(payload_len) != total_len {
        return Err(FrameError::Length);
    }
    let total = total_len as usize;
    let payload_end = FRAME_HEADER_LEN + payload_len as usize;
    let trailer_at = total - FRAME_TRAILER_LEN;

    // --- condition 3: journal identity ------------------------------------
    if header[off::JOURNAL_ID..off::JOURNAL_ID + 16] != journal_id[..] {
        return Err(FrameError::JournalId);
    }

    // --- condition 4: trailer magic and the repeated total_len ------------
    let trailer = &bytes[trailer_at..total];
    if trailer[off::TRAILER_MAGIC..off::TRAILER_MAGIC + 8] != FRAME_TRAILER_MAGIC {
        return Err(FrameError::Trailer);
    }
    if read_u64(trailer, off::TRAILER_TOTAL_LEN) != total_len {
        return Err(FrameError::Trailer);
    }

    // --- condition 7: flags -----------------------------------------------
    // Checked before the digest so that a frame whose only defect is a set
    // flag bit reports `Flags` and not `FrameDigest`.
    let flags = u32::from_le_bytes([
        header[off::FLAGS],
        header[off::FLAGS + 1],
        header[off::FLAGS + 2],
        header[off::FLAGS + 3],
    ]);
    if flags != 0 {
        return Err(FrameError::Flags);
    }

    // --- condition 8: padding ---------------------------------------------
    if bytes[payload_end..trailer_at].iter().any(|b| *b != 0) {
        return Err(FrameError::Padding);
    }

    // --- condition 5: the frame digest ------------------------------------
    let digest_at = trailer_at + off::TRAILER_DIGEST;
    if digest(FRAME_DIGEST_DOMAIN, &bytes[..digest_at]).as_bytes() != &bytes[digest_at..total] {
        return Err(FrameError::FrameDigest);
    }

    // --- condition 6: the payload digest ----------------------------------
    let payload_digest = digest(
        FRAME_PAYLOAD_DIGEST_DOMAIN,
        &bytes[FRAME_HEADER_LEN..payload_end],
    );
    if payload_digest.as_bytes() != &header[off::PAYLOAD_DIGEST..off::PAYLOAD_DIGEST + 32] {
        return Err(FrameError::PayloadDigest);
    }

    Ok(FrameHeader {
        flags,
        total_len,
        journal_id: *journal_id,
        shard_sequence: read_u64(header, off::SHARD_SEQUENCE),
        repo_sequence: read_u64(header, off::REPO_SEQUENCE),
        namespace: read_array::<32>(header, off::NAMESPACE),
        operation_id: read_array::<16>(header, off::OPERATION_ID),
        operation_digest: ObjectId(read_array::<32>(header, off::OPERATION_DIGEST)),
        payload_len,
        payload_digest,
    })
}

fn read_u64(bytes: &[u8], at: usize) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[at..at + 8]);
    u64::from_le_bytes(value)
}

fn read_array<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    let mut value = [0u8; N];
    value.copy_from_slice(&bytes[at..at + N]);
    value
}

/// Zero-padding count placing the trailer on an 8-byte boundary.
pub const fn frame_padding_len(payload_len: u64) -> u64 {
    let unpadded = FRAME_HEADER_LEN as u64 + payload_len;
    (FRAME_ALIGNMENT - (unpadded % FRAME_ALIGNMENT)) % FRAME_ALIGNMENT
}

/// Total on-disk length for a payload of `payload_len` bytes.
pub const fn frame_total_len(payload_len: u64) -> u64 {
    FRAME_HEADER_LEN as u64
        + payload_len
        + frame_padding_len(payload_len)
        + FRAME_TRAILER_LEN as u64
}

// ---------------------------------------------------------------------------
// Journal file header
// ---------------------------------------------------------------------------

/// 512-byte journal file header.
///
/// `journal_id` is fresh random per file and appears in every frame. It is the
/// defense against a frame from a previous incarnation of a recycled or
/// non-zeroing extent being accepted as live, and it also catches a segment or
/// journal misfiled under the wrong name in a manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalHeader {
    pub shard_index: u16,
    pub root_uuid: [u8; 16],
    pub journal_id: [u8; 16],
    pub first_shard_sequence: u64,
    pub preallocated_len: u64,
    pub created_at_micros: i64,
}

impl JournalHeader {
    /// Every byte of the 512 that is not a named field is padding and is
    /// written as zero; `header_digest` covers the whole 512 with the digest
    /// field itself zeroed. Leaving reserved space unconstrained is how a
    /// format acquires undocumented variants, so the padding is part of the
    /// authenticated image.
    pub fn encode(&self) -> Result<[u8; JOURNAL_HEADER_LEN], FrameError> {
        let mut bytes = [0u8; JOURNAL_HEADER_LEN];
        bytes[joff::MAGIC..joff::MAGIC + 8].copy_from_slice(&JOURNAL_MAGIC);
        bytes[joff::STORAGE_VERSION..joff::STORAGE_VERSION + 2]
            .copy_from_slice(&STORAGE_VERSION.to_le_bytes());
        bytes[joff::HEADER_LEN..joff::HEADER_LEN + 2]
            .copy_from_slice(&(JOURNAL_HEADER_LEN as u16).to_le_bytes());
        bytes[joff::SHARD_INDEX..joff::SHARD_INDEX + 2]
            .copy_from_slice(&self.shard_index.to_le_bytes());
        bytes[joff::ROOT_UUID..joff::ROOT_UUID + 16].copy_from_slice(&self.root_uuid);
        bytes[joff::JOURNAL_ID..joff::JOURNAL_ID + 16].copy_from_slice(&self.journal_id);
        bytes[joff::FIRST_SHARD_SEQUENCE..joff::FIRST_SHARD_SEQUENCE + 8]
            .copy_from_slice(&self.first_shard_sequence.to_le_bytes());
        bytes[joff::PREALLOCATED_LEN..joff::PREALLOCATED_LEN + 8]
            .copy_from_slice(&self.preallocated_len.to_le_bytes());
        bytes[joff::CREATED_AT_MICROS..joff::CREATED_AT_MICROS + 8]
            .copy_from_slice(&self.created_at_micros.to_le_bytes());

        // Digest over the full 512 with the digest field zeroed, which it
        // already is.
        let header_digest = digest(JOURNAL_HEADER_DIGEST_DOMAIN, &bytes);
        bytes[joff::HEADER_DIGEST..joff::HEADER_DIGEST + 32]
            .copy_from_slice(header_digest.as_bytes());
        Ok(bytes)
    }

    /// Rejects a wrong magic or version, a wrong `header_len`, a non-zero
    /// padding byte anywhere in the 512, and a digest that does not recompute.
    ///
    /// `root_uuid` is returned rather than checked: the caller knows the root
    /// it opened and compares, returning [`FrameError::RootUuid`].
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() != JOURNAL_HEADER_LEN {
            return Err(FrameError::Length);
        }
        if bytes[joff::MAGIC..joff::MAGIC + 8] != JOURNAL_MAGIC {
            return Err(FrameError::HeaderMagic);
        }
        if u16::from_le_bytes([
            bytes[joff::STORAGE_VERSION],
            bytes[joff::STORAGE_VERSION + 1],
        ]) != STORAGE_VERSION
        {
            return Err(FrameError::HeaderMagic);
        }
        if u16::from_le_bytes([bytes[joff::HEADER_LEN], bytes[joff::HEADER_LEN + 1]])
            != JOURNAL_HEADER_LEN as u16
        {
            return Err(FrameError::HeaderLen);
        }
        if bytes[joff::PAD0..joff::ROOT_UUID].iter().any(|b| *b != 0)
            || bytes[joff::PAD1..].iter().any(|b| *b != 0)
        {
            return Err(FrameError::Padding);
        }

        let mut zeroed = [0u8; JOURNAL_HEADER_LEN];
        zeroed.copy_from_slice(bytes);
        zeroed[joff::HEADER_DIGEST..joff::HEADER_DIGEST + 32].fill(0);
        if digest(JOURNAL_HEADER_DIGEST_DOMAIN, &zeroed).as_bytes()
            != &bytes[joff::HEADER_DIGEST..joff::HEADER_DIGEST + 32]
        {
            return Err(FrameError::FrameDigest);
        }

        Ok(Self {
            shard_index: u16::from_le_bytes([
                bytes[joff::SHARD_INDEX],
                bytes[joff::SHARD_INDEX + 1],
            ]),
            root_uuid: read_array::<16>(bytes, joff::ROOT_UUID),
            journal_id: read_array::<16>(bytes, joff::JOURNAL_ID),
            first_shard_sequence: read_u64(bytes, joff::FIRST_SHARD_SEQUENCE),
            preallocated_len: read_u64(bytes, joff::PREALLOCATED_LEN),
            created_at_micros: i64::from_le_bytes(read_array::<8>(bytes, joff::CREATED_AT_MICROS)),
        })
    }
}

// ---------------------------------------------------------------------------
// Segment footer
// ---------------------------------------------------------------------------

/// Appended when a journal is sealed. Its presence distinguishes a sealed
/// segment from an active journal.
///
/// Frames are byte-identical between journal and segment: sealing appends this
/// footer and renames, and never re-encodes. One golden frame corpus therefore
/// covers both readers (scope 2.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentFooter {
    pub root_uuid: [u8; 16],
    pub journal_id: [u8; 16],
    pub generation: u64,
    pub first_shard_sequence: u64,
    pub last_shard_sequence: u64,
    pub frame_count: u64,
    /// `shard_sequence -> (offset, len)`, ascending by sequence.
    pub offsets: Vec<(u64, u64, u64)>,
}

/// Bytes at the end of every digested variable-length structure: the digest
/// itself.
const TRAILING_DIGEST_LEN: usize = 32;

/// Bytes a segment-footer locator occupies at end of file: `footer_len`, the
/// repeated magic, and the digest.
pub const SEGMENT_FOOTER_LOCATOR_LEN: usize = 8 + 8 + TRAILING_DIGEST_LEN;

/// Start a digested structure: magic, storage version, and a zero reserved
/// half-word so the body begins 8-byte aligned.
fn begin_digested(magic: [u8; 8], capacity: usize) -> W {
    let mut writer = W::with_capacity(capacity);
    writer.fixed(&magic);
    writer.u16(STORAGE_VERSION);
    writer.u16(0);
    writer
}

/// Finish a digested structure by appending the digest over everything before
/// it.
fn finish_digested(writer: W, domain: &'static [u8]) -> Vec<u8> {
    let mut bytes = writer.bytes;
    let value = digest(domain, &bytes);
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

/// Open a digested structure: verify length, magic, version, reserved zeros,
/// and the digest, then return a reader over the body only.
fn open_digested<'a>(
    bytes: &'a [u8],
    magic: [u8; 8],
    domain: &'static [u8],
) -> Result<R<'a>, FrameError> {
    if bytes.len() < 12 + TRAILING_DIGEST_LEN {
        return Err(FrameError::Length);
    }
    if bytes[0..8] != magic {
        return Err(FrameError::HeaderMagic);
    }
    let body_end = bytes.len() - TRAILING_DIGEST_LEN;
    if digest(domain, &bytes[..body_end]).as_bytes() != &bytes[body_end..] {
        return Err(FrameError::FrameDigest);
    }
    let mut reader = R::new(&bytes[..body_end]);
    let _magic = reader.fixed::<8>()?;
    if reader.u16()? != STORAGE_VERSION {
        return Err(FrameError::HeaderMagic);
    }
    if reader.u16()? != 0 {
        return Err(FrameError::Padding);
    }
    Ok(reader)
}

impl SegmentFooter {
    /// The footer is self-locating from the end of the file: its final 48
    /// bytes are `footer_len`, the repeated magic, and the digest, so a reader
    /// can find the footer start with one bounded `pread` of
    /// [`SEGMENT_FOOTER_LOCATOR_LEN`] bytes and never has to scan.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.offsets.len() as u64 != self.frame_count {
            return Err(FrameError::Payload(
                "segment frame_count disagrees with the offset table",
            ));
        }
        if self.frame_count > MAX_TABLE_ENTRIES as u64 {
            return Err(FrameError::Length);
        }
        let mut previous: Option<u64> = None;
        for (sequence, offset, len) in &self.offsets {
            if let Some(previous) = previous {
                if *sequence <= previous {
                    return Err(FrameError::Payload("segment offsets must strictly ascend"));
                }
            }
            previous = Some(*sequence);
            if *len < MIN_FRAME_LEN || len % FRAME_ALIGNMENT != 0 {
                return Err(FrameError::Length);
            }
            offset.checked_add(*len).ok_or(FrameError::Length)?;
        }
        if self.frame_count > 0 {
            let first = self.offsets.first().expect("non-empty").0;
            let last = self.offsets.last().expect("non-empty").0;
            if first != self.first_shard_sequence || last != self.last_shard_sequence {
                return Err(FrameError::Payload(
                    "segment range disagrees with the offset table",
                ));
            }
        }

        let mut writer = begin_digested(SEGMENT_FOOTER_MAGIC, 128 + self.offsets.len() * 24);
        writer.fixed(&self.root_uuid);
        writer.fixed(&self.journal_id);
        writer.u64(self.generation);
        writer.u64(self.first_shard_sequence);
        writer.u64(self.last_shard_sequence);
        writer.u64(self.frame_count);
        writer.count(self.offsets.len())?;
        for (sequence, offset, len) in &self.offsets {
            writer.u64(*sequence);
            writer.u64(*offset);
            writer.u64(*len);
        }
        // Self-locating tail. `footer_len` counts itself, the repeated magic,
        // and the digest.
        let footer_len = (writer.bytes.len() + SEGMENT_FOOTER_LOCATOR_LEN) as u64;
        writer.u64(footer_len);
        writer.fixed(&SEGMENT_FOOTER_MAGIC);
        Ok(finish_digested(writer, SEGMENT_FOOTER_DIGEST_DOMAIN))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        let mut reader = open_digested(bytes, SEGMENT_FOOTER_MAGIC, SEGMENT_FOOTER_DIGEST_DOMAIN)?;
        let root_uuid = reader.fixed::<16>()?;
        let journal_id = reader.fixed::<16>()?;
        let generation = reader.u64()?;
        let first_shard_sequence = reader.u64()?;
        let last_shard_sequence = reader.u64()?;
        let frame_count = reader.u64()?;
        let count = reader.count(24)?;
        if count as u64 != frame_count {
            return Err(FrameError::Payload(
                "segment frame_count disagrees with the offset table",
            ));
        }
        let mut offsets = Vec::with_capacity(count);
        let mut previous: Option<u64> = None;
        for _ in 0..count {
            let sequence = reader.u64()?;
            let offset = reader.u64()?;
            let len = reader.u64()?;
            if let Some(previous) = previous {
                if sequence <= previous {
                    return Err(FrameError::Payload("segment offsets must strictly ascend"));
                }
            }
            previous = Some(sequence);
            if len < MIN_FRAME_LEN || len % FRAME_ALIGNMENT != 0 {
                return Err(FrameError::Length);
            }
            offset.checked_add(len).ok_or(FrameError::Length)?;
            offsets.push((sequence, offset, len));
        }
        if reader.u64()? != bytes.len() as u64 {
            return Err(FrameError::Length);
        }
        if reader.fixed::<8>()? != SEGMENT_FOOTER_MAGIC {
            return Err(FrameError::Trailer);
        }
        reader.finish()?;

        let out = Self {
            root_uuid,
            journal_id,
            generation,
            first_shard_sequence,
            last_shard_sequence,
            frame_count,
            offsets,
        };
        if out.frame_count > 0 {
            let first = out.offsets.first().expect("non-empty").0;
            let last = out.offsets.last().expect("non-empty").0;
            if first != out.first_shard_sequence || last != out.last_shard_sequence {
                return Err(FrameError::Payload(
                    "segment range disagrees with the offset table",
                ));
            }
        }
        Ok(out)
    }

    /// Parse the fixed tail every sealed segment ends with, returning the
    /// footer's total length. The caller then reads exactly that many bytes
    /// ending at end of file and hands them to [`SegmentFooter::decode`].
    pub fn decode_locator(tail: &[u8]) -> Result<u64, FrameError> {
        if tail.len() != SEGMENT_FOOTER_LOCATOR_LEN {
            return Err(FrameError::Length);
        }
        if tail[8..16] != SEGMENT_FOOTER_MAGIC {
            return Err(FrameError::HeaderMagic);
        }
        let footer_len = read_u64(tail, 0);
        if footer_len < SEGMENT_FOOTER_LOCATOR_LEN as u64 + 12 {
            return Err(FrameError::Length);
        }
        Ok(footer_len)
    }
}

// ---------------------------------------------------------------------------
// Manifest and CURRENT
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TailRange {
    pub generation: u64,
    pub first_shard_sequence: u64,
    pub last_shard_sequence: u64,
    pub filename: String,
}

/// A durable, immutable, versioned shard manifest.
///
/// Written under a new `<generation>` name with `rename_noreplace`, with at
/// least `manifest_retain` generations kept. `CURRENT` is the atomically
/// replaced pointer naming the active generation; recovery falls back to the
/// newest valid manifest when `CURRENT` or its referent does not validate
/// (scope 3.1, 3.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub root_uuid: [u8; 16],
    pub generation: u64,
    /// Always 0 in Phase 1. The field is the seam for Phase 4 compaction's
    /// `BaselineStateV1` base plus retained tails, so installing a baseline
    /// later needs no format change.
    pub base_generation: u64,
    pub retained_tail_ranges: Vec<TailRange>,
    pub index_runs: Vec<(u64, String)>,
    pub checkpoints: Vec<(u64, String)>,
    pub committed_shard_sequence: u64,
}

impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut writer = begin_digested(MANIFEST_MAGIC, 256);
        writer.fixed(&self.root_uuid);
        writer.u64(self.generation);
        writer.u64(self.base_generation);
        writer.u64(self.committed_shard_sequence);

        // Every list is strictly ascending by its key, so one manifest state
        // has exactly one encoding and a duplicate generation cannot hide.
        writer.count(self.retained_tail_ranges.len())?;
        let mut previous: Option<u64> = None;
        for range in &self.retained_tail_ranges {
            if previous.is_some_and(|p| range.generation <= p) {
                return Err(FrameError::Payload("tail ranges must strictly ascend"));
            }
            previous = Some(range.generation);
            if range.last_shard_sequence < range.first_shard_sequence {
                return Err(FrameError::Payload("tail range is inverted"));
            }
            writer.u64(range.generation);
            writer.u64(range.first_shard_sequence);
            writer.u64(range.last_shard_sequence);
            writer.name(&range.filename)?;
        }

        writer.count(self.index_runs.len())?;
        let mut previous: Option<u64> = None;
        for (generation, filename) in &self.index_runs {
            if previous.is_some_and(|p| *generation <= p) {
                return Err(FrameError::Payload("index runs must strictly ascend"));
            }
            previous = Some(*generation);
            writer.u64(*generation);
            writer.name(filename)?;
        }

        writer.count(self.checkpoints.len())?;
        let mut previous: Option<u64> = None;
        for (shard_sequence, filename) in &self.checkpoints {
            if previous.is_some_and(|p| *shard_sequence <= p) {
                return Err(FrameError::Payload("checkpoints must strictly ascend"));
            }
            previous = Some(*shard_sequence);
            writer.u64(*shard_sequence);
            writer.name(filename)?;
        }

        Ok(finish_digested(writer, MANIFEST_DIGEST_DOMAIN))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        let mut reader = open_digested(bytes, MANIFEST_MAGIC, MANIFEST_DIGEST_DOMAIN)?;
        let root_uuid = reader.fixed::<16>()?;
        let generation = reader.u64()?;
        let base_generation = reader.u64()?;
        let committed_shard_sequence = reader.u64()?;

        let count = reader.count(29)?;
        let mut retained_tail_ranges = Vec::with_capacity(count);
        let mut previous: Option<u64> = None;
        for _ in 0..count {
            let range = TailRange {
                generation: reader.u64()?,
                first_shard_sequence: reader.u64()?,
                last_shard_sequence: reader.u64()?,
                filename: reader.name()?,
            };
            if previous.is_some_and(|p| range.generation <= p) {
                return Err(FrameError::Payload("tail ranges must strictly ascend"));
            }
            previous = Some(range.generation);
            if range.last_shard_sequence < range.first_shard_sequence {
                return Err(FrameError::Payload("tail range is inverted"));
            }
            retained_tail_ranges.push(range);
        }

        let count = reader.count(13)?;
        let mut index_runs = Vec::with_capacity(count);
        let mut previous: Option<u64> = None;
        for _ in 0..count {
            let generation = reader.u64()?;
            let filename = reader.name()?;
            if previous.is_some_and(|p| generation <= p) {
                return Err(FrameError::Payload("index runs must strictly ascend"));
            }
            previous = Some(generation);
            index_runs.push((generation, filename));
        }

        let count = reader.count(13)?;
        let mut checkpoints = Vec::with_capacity(count);
        let mut previous: Option<u64> = None;
        for _ in 0..count {
            let shard_sequence = reader.u64()?;
            let filename = reader.name()?;
            if previous.is_some_and(|p| shard_sequence <= p) {
                return Err(FrameError::Payload("checkpoints must strictly ascend"));
            }
            previous = Some(shard_sequence);
            checkpoints.push((shard_sequence, filename));
        }

        reader.finish()?;
        Ok(Self {
            root_uuid,
            generation,
            base_generation,
            retained_tail_ranges,
            index_runs,
            checkpoints,
            committed_shard_sequence,
        })
    }
}

/// The `CURRENT` pointer: names the active manifest generation and nothing
/// else. Small on purpose — the less it carries, the less a corrupt pointer
/// costs.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CurrentPointer {
    pub root_uuid: [u8; 16],
    pub generation: u64,
}

/// Exact encoded length of a `CURRENT` pointer: 12 header + 16 root_uuid +
/// 8 generation + 32 digest.
pub const CURRENT_POINTER_LEN: usize = 68;

impl CurrentPointer {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let mut writer = begin_digested(CURRENT_MAGIC, CURRENT_POINTER_LEN);
        writer.fixed(&self.root_uuid);
        writer.u64(self.generation);
        let bytes = finish_digested(writer, CURRENT_DIGEST_DOMAIN);
        debug_assert_eq!(bytes.len(), CURRENT_POINTER_LEN);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() != CURRENT_POINTER_LEN {
            return Err(FrameError::Length);
        }
        let mut reader = open_digested(bytes, CURRENT_MAGIC, CURRENT_DIGEST_DOMAIN)?;
        let out = Self {
            root_uuid: reader.fixed::<16>()?,
            generation: reader.u64()?,
        };
        reader.finish()?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// FORMAT
// ---------------------------------------------------------------------------

/// The root format marker. `shard_count` is frozen here at initialization and
/// is immutable for the life of the root: opening with a different configured
/// value is a hard `FormatMismatch`, never a silent reroute (scope 2.5).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FormatMarker {
    pub format_version: u16,
    pub storage_version: u16,
    pub shard_count: u16,
    pub root_uuid: [u8; 16],
    pub created_at_micros: i64,
}

/// Exact encoded length of `FORMAT`: 12 header + 2 format_version +
/// 2 shard_count + 4 reserved + 16 root_uuid + 8 created_at + 32 digest.
pub const FORMAT_MARKER_LEN: usize = 76;

impl FormatMarker {
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        if self.storage_version != STORAGE_VERSION {
            return Err(FrameError::HeaderMagic);
        }
        if self.shard_count == 0 {
            return Err(FrameError::Payload("shard_count must be nonzero"));
        }
        // `begin_digested` already writes the storage version; `format_version`
        // is the separate root-layout version and follows it.
        let mut writer = begin_digested(FORMAT_MAGIC, FORMAT_MARKER_LEN);
        writer.u16(self.format_version);
        writer.u16(self.shard_count);
        writer.u32(0);
        writer.fixed(&self.root_uuid);
        writer.i64(self.created_at_micros);
        let bytes = finish_digested(writer, FORMAT_DIGEST_DOMAIN);
        debug_assert_eq!(bytes.len(), FORMAT_MARKER_LEN);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() != FORMAT_MARKER_LEN {
            return Err(FrameError::Length);
        }
        let mut reader = open_digested(bytes, FORMAT_MAGIC, FORMAT_DIGEST_DOMAIN)?;
        let format_version = reader.u16()?;
        let shard_count = reader.u16()?;
        if reader.u32()? != 0 {
            return Err(FrameError::Padding);
        }
        let out = Self {
            format_version,
            storage_version: STORAGE_VERSION,
            shard_count,
            root_uuid: reader.fixed::<16>()?,
            created_at_micros: reader.i64()?,
        };
        reader.finish()?;
        if out.shard_count == 0 {
            return Err(FrameError::Payload("shard_count must be nonzero"));
        }
        Ok(out)
    }
}

/// Domain-separated BLAKE3 over `bytes`.
pub fn digest(domain: &'static [u8], bytes: &[u8]) -> ObjectId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(bytes);
    ObjectId(*hasher.finalize().as_bytes())
}

// ---------------------------------------------------------------------------
// A1 additions: bounds and the checked canonical codec
//
// Additive only. No lead-authored type, constant, domain string, or signature
// above this point is modified.
// ---------------------------------------------------------------------------

/// Maximum bytes in one on-disk name recorded in a manifest.
pub const MAX_STORE_NAME_LEN: usize = 255;
/// Maximum inline objects in one frame payload. Matches the default
/// `max_objects_per_transaction` and the frozen `MAX_EVENT_OBJECT_IDS`.
pub const MAX_FRAME_OBJECTS: usize = 65_536;
/// Maximum raw bytes of one inline object in a frame payload.
pub const MAX_FRAME_OBJECT_BYTES: usize = levcs_protocol::codec::MAX_CANONICAL_BYTES;
/// Maximum entries in a segment footer offset table, a manifest tail range
/// list, an index-run list, or a checkpoint list.
pub const MAX_TABLE_ENTRIES: usize = 16_000_000;

/// Byte offsets of the frozen 176-byte frame header (scope 3.3).
mod off {
    pub(super) const MAGIC: usize = 0;
    pub(super) const STORAGE_VERSION: usize = 8;
    pub(super) const HEADER_LEN: usize = 10;
    pub(super) const FLAGS: usize = 12;
    pub(super) const TOTAL_LEN: usize = 16;
    pub(super) const JOURNAL_ID: usize = 24;
    pub(super) const SHARD_SEQUENCE: usize = 40;
    pub(super) const REPO_SEQUENCE: usize = 48;
    pub(super) const NAMESPACE: usize = 56;
    pub(super) const OPERATION_ID: usize = 88;
    pub(super) const OPERATION_DIGEST: usize = 104;
    pub(super) const PAYLOAD_LEN: usize = 136;
    pub(super) const PAYLOAD_DIGEST: usize = 144;

    pub(super) const TRAILER_MAGIC: usize = 0;
    pub(super) const TRAILER_TOTAL_LEN: usize = 8;
    pub(super) const TRAILER_DIGEST: usize = 16;
}

/// Byte offsets of the frozen 512-byte journal header (scope 3.2).
mod joff {
    pub(super) const MAGIC: usize = 0;
    pub(super) const STORAGE_VERSION: usize = 8;
    pub(super) const HEADER_LEN: usize = 10;
    pub(super) const SHARD_INDEX: usize = 12;
    pub(super) const PAD0: usize = 14;
    pub(super) const ROOT_UUID: usize = 16;
    pub(super) const JOURNAL_ID: usize = 32;
    pub(super) const FIRST_SHARD_SEQUENCE: usize = 48;
    pub(super) const PREALLOCATED_LEN: usize = 56;
    pub(super) const CREATED_AT_MICROS: usize = 64;
    pub(super) const HEADER_DIGEST: usize = 72;
    /// Everything from here to 512 is padding and must be zero.
    pub(super) const PAD1: usize = 104;
}

/// A small checked canonical binary codec, in the Phase 0 discipline: no
/// `serde`, one representation per value, every length checked before it is
/// used to allocate, and trailing bytes rejected.
///
/// It is deliberately a second implementation rather than a re-export of
/// `levcs_protocol::codec`, whose `Reader`/`Writer` are `pub(crate)` to that
/// crate. Where a protocol type is embedded it is embedded as its own
/// canonical bytes and re-decoded through `CanonicalCodec`, so the protocol's
/// representation is never restated here.
mod wire {
    use super::{FrameError, MAX_STORE_NAME_LEN, MAX_TABLE_ENTRIES};

    pub(super) struct W {
        pub(super) bytes: Vec<u8>,
    }

    impl W {
        pub(super) fn with_capacity(capacity: usize) -> Self {
            Self {
                bytes: Vec::with_capacity(capacity),
            }
        }

        pub(super) fn u8(&mut self, value: u8) {
            self.bytes.push(value);
        }

        pub(super) fn u16(&mut self, value: u16) {
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }

        pub(super) fn u32(&mut self, value: u32) {
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }

        pub(super) fn u64(&mut self, value: u64) {
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }

        pub(super) fn i64(&mut self, value: i64) {
            self.bytes.extend_from_slice(&value.to_le_bytes());
        }

        pub(super) fn fixed(&mut self, value: &[u8]) {
            self.bytes.extend_from_slice(value);
        }

        pub(super) fn bool(&mut self, value: bool) {
            self.u8(u8::from(value));
        }

        pub(super) fn count(&mut self, count: usize) -> Result<(), FrameError> {
            if count > MAX_TABLE_ENTRIES {
                return Err(FrameError::Length);
            }
            self.u32(count as u32);
            Ok(())
        }

        pub(super) fn blob(&mut self, value: &[u8], limit: usize) -> Result<(), FrameError> {
            if value.len() > limit || value.len() > u32::MAX as usize {
                return Err(FrameError::Length);
            }
            self.u32(value.len() as u32);
            self.fixed(value);
            Ok(())
        }

        /// A single path component recorded in a manifest.
        ///
        /// A manifest names files inside one shard directory. A name carrying
        /// `/`, `..`, NUL, or a leading `.` would let a corrupt or hostile
        /// manifest reference a file outside the shard, so the constraint is
        /// enforced on the encode side as well as the decode side.
        pub(super) fn name(&mut self, value: &str) -> Result<(), FrameError> {
            validate_name(value)?;
            self.blob(value.as_bytes(), MAX_STORE_NAME_LEN)
        }
    }

    pub(super) fn validate_name(value: &str) -> Result<(), FrameError> {
        if value.is_empty() || value.len() > MAX_STORE_NAME_LEN {
            return Err(FrameError::Payload("store name length"));
        }
        if value.starts_with('.') {
            return Err(FrameError::Payload("store name starts with a dot"));
        }
        for byte in value.bytes() {
            let ok = byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_');
            if !ok {
                return Err(FrameError::Payload("store name character"));
            }
        }
        Ok(())
    }

    pub(super) struct R<'a> {
        bytes: &'a [u8],
        cursor: usize,
    }

    impl<'a> R<'a> {
        pub(super) fn new(bytes: &'a [u8]) -> Self {
            Self { bytes, cursor: 0 }
        }

        pub(super) fn remaining(&self) -> usize {
            self.bytes.len() - self.cursor
        }

        fn take(&mut self, len: usize) -> Result<&'a [u8], FrameError> {
            let end = self.cursor.checked_add(len).ok_or(FrameError::Length)?;
            let out = self.bytes.get(self.cursor..end).ok_or(FrameError::Length)?;
            self.cursor = end;
            Ok(out)
        }

        pub(super) fn u8(&mut self) -> Result<u8, FrameError> {
            Ok(self.take(1)?[0])
        }

        pub(super) fn u16(&mut self) -> Result<u16, FrameError> {
            Ok(u16::from_le_bytes(self.fixed::<2>()?))
        }

        pub(super) fn u32(&mut self) -> Result<u32, FrameError> {
            Ok(u32::from_le_bytes(self.fixed::<4>()?))
        }

        pub(super) fn u64(&mut self) -> Result<u64, FrameError> {
            Ok(u64::from_le_bytes(self.fixed::<8>()?))
        }

        pub(super) fn i64(&mut self) -> Result<i64, FrameError> {
            Ok(i64::from_le_bytes(self.fixed::<8>()?))
        }

        pub(super) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], FrameError> {
            let mut out = [0u8; N];
            out.copy_from_slice(self.take(N)?);
            Ok(out)
        }

        pub(super) fn bool(&mut self) -> Result<bool, FrameError> {
            match self.u8()? {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(FrameError::Payload("boolean must be 0 or 1")),
            }
        }

        /// Element count, bounded before it is used to reserve. The second
        /// bound — one element cannot be smaller than `min_element_bytes` —
        /// is what stops a four-byte count from reserving gigabytes.
        pub(super) fn count(&mut self, min_element_bytes: usize) -> Result<usize, FrameError> {
            let count = self.u32()? as usize;
            if count > MAX_TABLE_ENTRIES {
                return Err(FrameError::Length);
            }
            let affordable = self.remaining() / min_element_bytes.max(1);
            if count > affordable {
                return Err(FrameError::Length);
            }
            Ok(count)
        }

        pub(super) fn blob(&mut self, limit: usize) -> Result<Vec<u8>, FrameError> {
            let len = self.u32()? as usize;
            if len > limit || len > self.remaining() {
                return Err(FrameError::Length);
            }
            Ok(self.take(len)?.to_vec())
        }

        pub(super) fn name(&mut self) -> Result<String, FrameError> {
            let bytes = self.blob(MAX_STORE_NAME_LEN)?;
            let value = String::from_utf8(bytes).map_err(|_| FrameError::Payload("name utf-8"))?;
            validate_name(&value)?;
            Ok(value)
        }

        /// Trailing-byte rejection. A canonical encoding has exactly one
        /// representation, so unconsumed input is a rejection and never a
        /// tolerated extension.
        pub(super) fn finish(self) -> Result<(), FrameError> {
            if self.cursor == self.bytes.len() {
                Ok(())
            } else {
                Err(FrameError::Length)
            }
        }
    }
}

use wire::{R, W};

/// The single in-crate statement of the store's object-type codes.
///
/// `pub(crate)` rather than private because `recovery.rs` and the engine both
/// have to write the same code into an index entry, and a private mapping does
/// not prevent a second table — it only guarantees the second table is written
/// somewhere else and compared to this one by review. The recovered index entry
/// and the submitted object are compared end to end by reopening a store, and
/// that comparison is only meaningful while there is one table to disagree
/// with.
pub(crate) fn object_type_code(value: ObjectType) -> u8 {
    // Exhaustive on purpose: a new object type must break this build rather
    // than acquire an undocumented on-disk code.
    match value {
        ObjectType::Blob => 1,
        ObjectType::Tree => 2,
        ObjectType::Commit => 3,
        ObjectType::Release => 4,
        ObjectType::Authority => 5,
    }
}

fn object_type_from_code(code: u8) -> Result<ObjectType, FrameError> {
    match code {
        1 => Ok(ObjectType::Blob),
        2 => Ok(ObjectType::Tree),
        3 => Ok(ObjectType::Commit),
        4 => Ok(ObjectType::Release),
        5 => Ok(ObjectType::Authority),
        _ => Err(FrameError::Payload("object type discriminant")),
    }
}

fn projection_code(value: ProjectionMode) -> u8 {
    match value {
        ProjectionMode::Full => 1,
        ProjectionMode::Release => 2,
        ProjectionMode::Metadata => 3,
    }
}

fn projection_from_code(code: u8) -> Result<ProjectionMode, FrameError> {
    match code {
        1 => Ok(ProjectionMode::Full),
        2 => Ok(ProjectionMode::Release),
        3 => Ok(ProjectionMode::Metadata),
        _ => Err(FrameError::Payload("projection mode discriminant")),
    }
}

// ---------------------------------------------------------------------------
// Frame payload
// ---------------------------------------------------------------------------

/// One inline new object: embedded type, ObjectId, exact raw length, exact raw
/// bytes (plan §5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameObjectV1 {
    pub object_type: ObjectType,
    pub object_id: ObjectId,
    pub raw: Vec<u8>,
}

/// A frame carries **either** inline new objects **or** exactly one
/// `StagedProjectionInstallV1` descriptor — never both, and the encoding makes
/// the exclusivity structural rather than a checked invariant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameObjectsV1 {
    Inline(Vec<FrameObjectV1>),
    StagedProjectionInstall(StagedProjectionInstallV1),
}

/// Repository-create metadata, present only on the transaction that creates a
/// repository.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RepositoryCreateV1 {
    pub genesis_authority: ObjectId,
    pub genesis_len: u64,
    pub genesis_hash: ObjectId,
    pub projection: ProjectionMode,
}

/// The deterministic receipt fields a frame carries so that a receipt survives
/// recovery without consulting anything else.
///
/// `refs`, `current_authority`, and `repo_sequence` are not repeated here: they
/// are already in the embedded `CommittedTransactionV1` and the frame header,
/// and a second copy could disagree with the first.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FrameReceiptFieldsV1 {
    pub objects_new: u64,
    pub retry_until_micros: i64,
    pub first_receipt_visibility_micros: i64,
}

/// The canonical frame payload of scope 3.3.
///
/// Embedded frozen protocol values are stored as their own canonical bytes and
/// re-decoded through `CanonicalCodec` on the way out, so this codec never
/// restates a frozen representation and cannot drift from one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransactionFramePayloadV1 {
    pub repository_create: Option<RepositoryCreateV1>,
    pub objects: FrameObjectsV1,
    pub ref_cas: Vec<TypedRefCas>,
    pub expected_authority: ObjectId,
    pub new_authority: ObjectId,
    pub evidence: TransactionEvidenceV1,
    pub committed: SignedCommittedTransactionV1,
    pub receipt: FrameReceiptFieldsV1,
}

/// Store-local encoding of the typed ref CAS set.
///
/// `TypedRefCas`, `RefTarget`, and `RefMutation` are frozen protocol types
/// whose canonical codecs are private to `levcs-protocol` — they implement no
/// public `CanonicalCodec`. The store therefore has to define its own physical
/// encoding for the "complete typed ref CAS set" the frame must carry. Plan
/// §13 keeps the physical format internal, so this is a store-private byte
/// layout and not a second protocol encoding; the *validation* rules are not
/// restated, they are delegated to `levcs_core::refs::validate_ref_name`, the
/// same function the protocol delegates to.
fn encode_ref_target(writer: &mut W, target: &RefTarget) -> Result<(), FrameError> {
    let (tag, name) = match target {
        RefTarget::Branch(name) => (1u8, name),
        RefTarget::Release(name) => (2u8, name),
    };
    validate_ref_name(name)?;
    writer.u8(tag);
    writer.blob(name.as_bytes(), MAX_STORE_NAME_LEN)
}

fn validate_ref_name(name: &str) -> Result<(), FrameError> {
    if name.is_empty() || name.len() > MAX_STORE_NAME_LEN {
        return Err(FrameError::Payload("ref name length"));
    }
    if name.as_bytes().contains(&0) {
        return Err(FrameError::Payload("ref name contains NUL"));
    }
    levcs_core::refs::validate_ref_name(name).map_err(|_| FrameError::Payload("ref name"))
}

fn decode_ref_target(reader: &mut R<'_>) -> Result<RefTarget, FrameError> {
    let tag = reader.u8()?;
    let bytes = reader.blob(MAX_STORE_NAME_LEN)?;
    let name = String::from_utf8(bytes).map_err(|_| FrameError::Payload("ref name utf-8"))?;
    validate_ref_name(&name)?;
    match tag {
        1 => Ok(RefTarget::Branch(name)),
        2 => Ok(RefTarget::Release(name)),
        _ => Err(FrameError::Payload("ref target discriminant")),
    }
}

fn encode_optional_id(writer: &mut W, value: Option<ObjectId>) {
    match value {
        Some(id) => {
            writer.u8(1);
            writer.fixed(id.as_bytes());
        }
        None => writer.u8(0),
    }
}

fn decode_optional_id(reader: &mut R<'_>) -> Result<Option<ObjectId>, FrameError> {
    match reader.u8()? {
        0 => Ok(None),
        1 => Ok(Some(ObjectId(reader.fixed::<32>()?))),
        _ => Err(FrameError::Payload("optional object id discriminant")),
    }
}

fn encode_ref_cas(writer: &mut W, updates: &[TypedRefCas]) -> Result<(), FrameError> {
    if updates.len() > MAX_REF_UPDATES {
        return Err(FrameError::Length);
    }
    // Duplicate targets in one transaction would make "exact same-ref winner"
    // (Phase 1 exit) ambiguous inside a single frame, so the canonical form
    // forbids them.
    let mut seen = std::collections::BTreeSet::new();
    for update in updates {
        if !seen.insert(update.target.clone()) {
            return Err(FrameError::Payload("duplicate ref target"));
        }
        if update.mutation == RefMutation::Delete && update.expected.is_none() {
            return Err(FrameError::Payload("delete requires an expected object"));
        }
    }
    writer.count(updates.len())?;
    for update in updates {
        encode_ref_target(writer, &update.target)?;
        encode_optional_id(writer, update.expected);
        match update.mutation {
            RefMutation::Set(id) => {
                writer.u8(1);
                writer.fixed(id.as_bytes());
            }
            RefMutation::Delete => writer.u8(2),
        }
        writer.bool(update.force);
    }
    Ok(())
}

fn decode_ref_cas(reader: &mut R<'_>) -> Result<Vec<TypedRefCas>, FrameError> {
    // Smallest possible element: tag + 4-byte name length + 1 name byte +
    // absent-expected + Delete tag + force = 9 bytes.
    let count = reader.count(9)?;
    if count > MAX_REF_UPDATES {
        return Err(FrameError::Length);
    }
    let mut updates = Vec::with_capacity(count);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..count {
        let target = decode_ref_target(reader)?;
        let expected = decode_optional_id(reader)?;
        let mutation = match reader.u8()? {
            1 => RefMutation::Set(ObjectId(reader.fixed::<32>()?)),
            2 => RefMutation::Delete,
            _ => return Err(FrameError::Payload("ref mutation discriminant")),
        };
        let force = reader.bool()?;
        if mutation == RefMutation::Delete && expected.is_none() {
            return Err(FrameError::Payload("delete requires an expected object"));
        }
        if !seen.insert(target.clone()) {
            return Err(FrameError::Payload("duplicate ref target"));
        }
        updates.push(TypedRefCas {
            target,
            expected,
            mutation,
            force,
        });
    }
    Ok(updates)
}

/// The facts recovery and the crash matrix need out of a frame payload,
/// extracted once so neither has to reach into the embedded protocol values
/// and neither can disagree with the other about where they live.
///
/// Interface change request from A2 RecoveryIndex, approved by the lead:
/// recovery step 9 verifies the per-repository event chain and needs
/// `previous_event_digest` and `event_digest`; the matrix needs `source_kind`.
/// Everything here is read off the embedded canonical
/// `CommittedTransactionV1` or the receipt fields — nothing is recomputed from
/// a second source, so a fact cannot disagree with the bytes it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadFacts {
    pub source_kind: SourceKindV1,
    pub repo_id: ObjectId,
    pub repo_sequence: u64,
    /// The chain link recovery step 9 walks.
    pub previous_event_digest: ObjectId,
    /// `BLAKE3("levcs-event/v1\0" || canonical CommittedTransactionV1)`, from
    /// the frozen protocol function. The event digest excludes its signature,
    /// so later reservations chain deterministically (plan §5.2).
    pub event_digest: ObjectId,
    pub resulting_state_digest: ObjectId,
    pub old_authority: ObjectId,
    pub new_authority: ObjectId,
    pub source_key_epoch: u64,
    pub objects_new: u64,
    pub retry_until_micros: i64,
    pub first_receipt_visibility_micros: i64,
}

impl TransactionFramePayloadV1 {
    /// The source of the mutation, as recorded in the embedded event.
    pub fn source_kind(&self) -> SourceKindV1 {
        self.committed.transaction.source_kind
    }

    /// The previous link in this repository's event chain.
    pub fn previous_event_digest(&self) -> ObjectId {
        self.committed.transaction.previous_event_digest
    }

    /// This frame's event digest, computed by the frozen protocol function
    /// rather than restated here.
    pub fn event_digest(&self) -> Result<ObjectId, FrameError> {
        self.committed
            .transaction
            .event_digest()
            .map_err(|_| FrameError::Payload("event digest"))
    }

    pub fn repo_id(&self) -> ObjectId {
        self.committed.transaction.repo_id
    }

    pub fn repo_sequence(&self) -> u64 {
        self.committed.transaction.repo_sequence
    }

    pub fn resulting_state_digest(&self) -> ObjectId {
        self.committed.transaction.resulting_state_digest
    }

    /// Everything the recovery chain check and the crash matrix bind to.
    pub fn facts(&self) -> Result<PayloadFacts, FrameError> {
        let transaction = &self.committed.transaction;
        Ok(PayloadFacts {
            source_kind: transaction.source_kind,
            repo_id: transaction.repo_id,
            repo_sequence: transaction.repo_sequence,
            previous_event_digest: transaction.previous_event_digest,
            event_digest: self.event_digest()?,
            resulting_state_digest: transaction.resulting_state_digest,
            old_authority: transaction.old_authority,
            new_authority: transaction.new_authority,
            source_key_epoch: self.committed.source_key_epoch,
            objects_new: self.receipt.objects_new,
            retry_until_micros: self.receipt.retry_until_micros,
            first_receipt_visibility_micros: self.receipt.first_receipt_visibility_micros,
        })
    }

    /// Decode a payload and extract its facts in one step.
    ///
    /// This is a full canonical decode, not a partial one: a payload whose
    /// facts are read is a payload the protocol crate also accepts, so a
    /// recovered frame can never contribute a chain link that came out of
    /// bytes nothing revalidated.
    pub fn decode_facts(bytes: &[u8]) -> Result<PayloadFacts, FrameError> {
        Self::decode_canonical(bytes)?.facts()
    }

    /// Canonical payload bytes.
    ///
    /// This is deliberately *not* invoked by `Frame::encode` or
    /// `Frame::decode`: a `Frame` carries opaque payload bytes so that
    /// completeness (scope 3.3) stays a purely physical property and recovery
    /// never has to parse a payload to decide whether a frame is whole.
    /// Interpretation is a separate, revalidating step.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, FrameError> {
        let mut writer = W::with_capacity(1024);

        match &self.repository_create {
            None => writer.u8(0),
            Some(create) => {
                writer.u8(1);
                writer.fixed(create.genesis_authority.as_bytes());
                writer.u64(create.genesis_len);
                writer.fixed(create.genesis_hash.as_bytes());
                writer.u8(projection_code(create.projection));
            }
        }

        match &self.objects {
            FrameObjectsV1::Inline(objects) => {
                if objects.len() > MAX_FRAME_OBJECTS {
                    return Err(FrameError::Length);
                }
                let mut previous: Option<&ObjectId> = None;
                for object in objects {
                    // Strictly ascending by ObjectId: one membership set has
                    // exactly one encoding, and a duplicate cannot hide in it.
                    if let Some(previous) = previous {
                        if object.object_id.as_bytes() <= previous.as_bytes() {
                            return Err(FrameError::Payload("frame objects must strictly ascend"));
                        }
                    }
                    previous = Some(&object.object_id);
                }
                writer.u8(1);
                writer.count(objects.len())?;
                for object in objects {
                    writer.u8(object_type_code(object.object_type));
                    writer.fixed(object.object_id.as_bytes());
                    writer.blob(&object.raw, MAX_FRAME_OBJECT_BYTES)?;
                }
            }
            FrameObjectsV1::StagedProjectionInstall(install) => {
                writer.u8(2);
                let bytes = install
                    .encode_canonical()
                    .map_err(|_| FrameError::Payload("staged projection install"))?;
                writer.blob(&bytes, MAX_FRAME_OBJECT_BYTES)?;
            }
        }

        encode_ref_cas(&mut writer, &self.ref_cas)?;
        writer.fixed(self.expected_authority.as_bytes());
        writer.fixed(self.new_authority.as_bytes());

        let evidence = self
            .evidence
            .encode_canonical()
            .map_err(|_| FrameError::Payload("transaction evidence"))?;
        writer.blob(&evidence, MAX_FRAME_OBJECT_BYTES)?;

        let committed = self
            .committed
            .encode_canonical()
            .map_err(|_| FrameError::Payload("signed committed transaction"))?;
        writer.blob(&committed, MAX_FRAME_OBJECT_BYTES)?;

        writer.u64(self.receipt.objects_new);
        writer.i64(self.receipt.retry_until_micros);
        writer.i64(self.receipt.first_receipt_visibility_micros);

        Ok(writer.bytes)
    }

    /// Decode and revalidate. Every embedded frozen value is re-decoded
    /// through its own canonical codec, so a payload that decodes here is one
    /// the protocol crate also accepts.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, FrameError> {
        let mut reader = R::new(bytes);

        let repository_create = match reader.u8()? {
            0 => None,
            1 => Some(RepositoryCreateV1 {
                genesis_authority: ObjectId(reader.fixed::<32>()?),
                genesis_len: reader.u64()?,
                genesis_hash: ObjectId(reader.fixed::<32>()?),
                projection: projection_from_code(reader.u8()?)?,
            }),
            _ => return Err(FrameError::Payload("repository create discriminant")),
        };

        let objects = match reader.u8()? {
            1 => {
                // Smallest inline object: type + id + 4-byte length = 37.
                let count = reader.count(37)?;
                if count > MAX_FRAME_OBJECTS {
                    return Err(FrameError::Length);
                }
                let mut objects = Vec::with_capacity(count);
                let mut previous: Option<ObjectId> = None;
                for _ in 0..count {
                    let object_type = object_type_from_code(reader.u8()?)?;
                    let object_id = ObjectId(reader.fixed::<32>()?);
                    if let Some(previous) = previous {
                        if object_id.as_bytes() <= previous.as_bytes() {
                            return Err(FrameError::Payload("frame objects must strictly ascend"));
                        }
                    }
                    previous = Some(object_id);
                    let raw = reader.blob(MAX_FRAME_OBJECT_BYTES)?;
                    objects.push(FrameObjectV1 {
                        object_type,
                        object_id,
                        raw,
                    });
                }
                FrameObjectsV1::Inline(objects)
            }
            2 => {
                let bytes = reader.blob(MAX_FRAME_OBJECT_BYTES)?;
                FrameObjectsV1::StagedProjectionInstall(
                    StagedProjectionInstallV1::decode_canonical(&bytes)
                        .map_err(|_| FrameError::Payload("staged projection install"))?,
                )
            }
            _ => return Err(FrameError::Payload("frame objects discriminant")),
        };

        let ref_cas = decode_ref_cas(&mut reader)?;
        let expected_authority = ObjectId(reader.fixed::<32>()?);
        let new_authority = ObjectId(reader.fixed::<32>()?);

        let evidence_bytes = reader.blob(MAX_FRAME_OBJECT_BYTES)?;
        let evidence = TransactionEvidenceV1::decode_canonical(&evidence_bytes)
            .map_err(|_| FrameError::Payload("transaction evidence"))?;

        let committed_bytes = reader.blob(MAX_FRAME_OBJECT_BYTES)?;
        let committed = SignedCommittedTransactionV1::decode_canonical(&committed_bytes)
            .map_err(|_| FrameError::Payload("signed committed transaction"))?;

        let receipt = FrameReceiptFieldsV1 {
            objects_new: reader.u64()?,
            retry_until_micros: reader.i64()?,
            first_receipt_visibility_micros: reader.i64()?,
        };

        reader.finish()?;

        Ok(Self {
            repository_create,
            objects,
            ref_cas,
            expected_authority,
            new_authority,
            evidence,
            committed,
            receipt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The header table in scope 3.3 sums to exactly 176 and the minimum frame
    /// to 224. Pinning the arithmetic here means a field added without
    /// resizing the header breaks the build rather than the format.
    #[test]
    fn fixed_lengths_are_pinned() {
        assert_eq!(FRAME_HEADER_LEN, 176);
        assert_eq!(FRAME_TRAILER_LEN, 48);
        assert_eq!(MIN_FRAME_LEN, 224);
        assert_eq!(JOURNAL_HEADER_LEN, 512);
    }

    #[test]
    fn padding_places_the_trailer_on_an_eight_byte_boundary() {
        for payload_len in 0u64..64 {
            let total = frame_total_len(payload_len);
            assert_eq!(
                total % FRAME_ALIGNMENT,
                0,
                "total_len must be 8-aligned for payload_len {payload_len}"
            );
            assert!(total >= MIN_FRAME_LEN);
            let pad = frame_padding_len(payload_len);
            assert!(pad < FRAME_ALIGNMENT);
            assert_eq!(
                FRAME_HEADER_LEN as u64 + payload_len + pad + FRAME_TRAILER_LEN as u64,
                total
            );
        }
    }

    #[test]
    fn every_domain_string_is_distinct_and_nul_terminated() {
        let domains = [
            FRAME_DIGEST_DOMAIN,
            FRAME_PAYLOAD_DIGEST_DOMAIN,
            JOURNAL_HEADER_DIGEST_DOMAIN,
            SEGMENT_FOOTER_DIGEST_DOMAIN,
            MANIFEST_DIGEST_DOMAIN,
            CURRENT_DIGEST_DOMAIN,
            CHECKPOINT_DIGEST_DOMAIN,
            FORMAT_DIGEST_DOMAIN,
        ];
        let unique: std::collections::BTreeSet<_> = domains.iter().collect();
        assert_eq!(unique.len(), domains.len(), "domains must be distinct");
        for domain in domains {
            assert_eq!(
                domain.last(),
                Some(&0u8),
                "domain {:?} must be NUL-terminated so no domain is a prefix of another",
                std::str::from_utf8(domain).unwrap_or("<non-utf8>")
            );
        }
    }

    #[test]
    fn every_file_magic_is_distinct() {
        let magics = [
            FRAME_MAGIC,
            FRAME_TRAILER_MAGIC,
            JOURNAL_MAGIC,
            SEGMENT_FOOTER_MAGIC,
            MANIFEST_MAGIC,
            CURRENT_MAGIC,
            CHECKPOINT_MAGIC,
            FORMAT_MAGIC,
        ];
        let unique: std::collections::BTreeSet<_> = magics.iter().collect();
        assert_eq!(unique.len(), magics.len(), "magics must be distinct");
    }

    #[test]
    fn digest_is_domain_separated() {
        let a = digest(FRAME_DIGEST_DOMAIN, b"same bytes");
        let b = digest(FRAME_PAYLOAD_DIGEST_DOMAIN, b"same bytes");
        assert_ne!(a, b, "identical bytes under different domains must differ");
    }
}
