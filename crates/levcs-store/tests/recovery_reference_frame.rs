//! An independent reference implementation of the scope 3.3 frame, the scope
//! 3.5 `CURRENT`/manifest codec, and the physical-image builders A2's
//! acceptance tests need.
//!
//! **Owned by A2 RecoveryIndex.** Included by the other `recovery_*` test files
//! with `#[path]`, and compiled as a test target in its own right so its
//! self-tests run.
//!
//! # Why a second implementation exists
//!
//! `format.rs`'s codec belongs to A1 and is frozen by the same Wave A gate that
//! freezes recovery. Two things follow:
//!
//! 1. A2's stopping and selection logic must be provable *independently* of
//!    A1's bodies, or a defect in either package shows up as a failure in the
//!    other.
//! 2. The scope 5 charter asks the reviewer to attack the completeness
//!    definition directly. A second derivation of it, written from the
//!    specification text rather than from A1's code, is exactly the artifact
//!    that makes "the two agree" a checkable claim —
//!    `recovery_production_codec.rs` checks it.
//!
//! This file therefore implements every one of the eight conditions of scope
//! 3.3 from the specification, not from `format.rs`.

#![allow(dead_code)]

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use levcs_core::ObjectId;
use levcs_store::format::{
    self, CurrentPointer, Frame, FrameError, FrameHeader, JournalHeader, Manifest, TailRange,
    FRAME_ALIGNMENT, FRAME_DIGEST_DOMAIN, FRAME_HEADER_LEN, FRAME_MAGIC,
    FRAME_PAYLOAD_DIGEST_DOMAIN, FRAME_TRAILER_LEN, FRAME_TRAILER_MAGIC, JOURNAL_HEADER_LEN,
    MIN_FRAME_LEN, STORAGE_VERSION,
};
use levcs_store::journal::{scan_journal, TailScan};
use levcs_store::segment::ShardPaths;

pub const ROOT_UUID: [u8; 16] = [0x11; 16];
pub const JOURNAL_ID: [u8; 16] = [0x22; 16];

// ---------------------------------------------------------------------------
// Frame
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct FrameSpec {
    pub journal_id: [u8; 16],
    pub shard_sequence: u64,
    pub repo_sequence: u64,
    pub namespace: [u8; 32],
    pub operation_id: [u8; 16],
    pub operation_digest: [u8; 32],
    pub payload: Vec<u8>,
    /// Deliberate defects, so a test can make exactly one condition fail.
    pub flags: u32,
    pub pad_byte: u8,
}

impl FrameSpec {
    pub fn new(shard_sequence: u64) -> Self {
        Self {
            journal_id: JOURNAL_ID,
            shard_sequence,
            repo_sequence: shard_sequence,
            namespace: [1u8; 32],
            operation_id: [0u8; 16],
            operation_digest: [0u8; 32],
            // A payload length that is not a multiple of 8, so every frame
            // exercises the padding region rather than skipping it.
            payload: format!("frame payload {shard_sequence}").into_bytes(),
            flags: 0,
            pad_byte: 0,
        }
    }

    pub fn with_journal_id(mut self, journal_id: [u8; 16]) -> Self {
        self.journal_id = journal_id;
        self
    }

    pub fn with_namespace(mut self, namespace: [u8; 32]) -> Self {
        self.namespace = namespace;
        self
    }

    pub fn with_repo_sequence(mut self, repo_sequence: u64) -> Self {
        self.repo_sequence = repo_sequence;
        self
    }

    pub fn encode(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u64;
        let pad = format::frame_padding_len(payload_len);
        let total_len = format::frame_total_len(payload_len);

        let mut out = Vec::with_capacity(total_len as usize);
        out.extend_from_slice(&FRAME_MAGIC);
        out.extend_from_slice(&STORAGE_VERSION.to_le_bytes());
        out.extend_from_slice(&(FRAME_HEADER_LEN as u16).to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&total_len.to_le_bytes());
        out.extend_from_slice(&self.journal_id);
        out.extend_from_slice(&self.shard_sequence.to_le_bytes());
        out.extend_from_slice(&self.repo_sequence.to_le_bytes());
        out.extend_from_slice(&self.namespace);
        out.extend_from_slice(&self.operation_id);
        out.extend_from_slice(&self.operation_digest);
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&format::digest(FRAME_PAYLOAD_DIGEST_DOMAIN, &self.payload).0);
        assert_eq!(out.len(), FRAME_HEADER_LEN);

        out.extend_from_slice(&self.payload);
        out.extend(std::iter::repeat_n(self.pad_byte, pad as usize));
        out.extend_from_slice(&FRAME_TRAILER_MAGIC);
        out.extend_from_slice(&total_len.to_le_bytes());
        let at = out.len();
        out.extend_from_slice(&format::digest(FRAME_DIGEST_DOMAIN, &out[..at]).0);
        assert_eq!(out.len() as u64, total_len);
        out
    }
    /// The same frame as a `format::Frame`, for the paths that append through
    /// `journal::append_group_and_fence` rather than writing bytes directly.
    ///
    /// Encoding still goes through A1's `Frame::encode`; only the field values
    /// come from here.
    pub fn to_frame(&self) -> Frame {
        let payload_len = self.payload.len() as u64;
        Frame {
            header: FrameHeader {
                flags: self.flags,
                total_len: format::frame_total_len(payload_len),
                journal_id: self.journal_id,
                shard_sequence: self.shard_sequence,
                repo_sequence: self.repo_sequence,
                namespace: self.namespace,
                operation_id: self.operation_id,
                operation_digest: ObjectId(self.operation_digest),
                payload_len,
                payload_digest: format::digest(FRAME_PAYLOAD_DIGEST_DOMAIN, &self.payload),
            },
            payload: self.payload.clone(),
        }
    }
}

pub fn frame(shard_sequence: u64) -> Vec<u8> {
    FrameSpec::new(shard_sequence).encode()
}

/// Reseal the whole-frame digest, so a mutation that a test made deliberately
/// is the *only* remaining defect.
pub fn reseal_frame_digest(bytes: &mut [u8]) {
    let at = bytes.len() - 32;
    let digest = format::digest(FRAME_DIGEST_DOMAIN, &bytes[..at]);
    bytes[at..].copy_from_slice(&digest.0);
}

/// The scope 3.3 completeness definition, implemented from the specification
/// text. Conditions are checked in the order 3.3 lists them, and each returns
/// its own `FrameError`.
pub fn reference_verify(
    bytes: &[u8],
    journal_id: &[u8; 16],
    file_remaining: u64,
) -> Result<FrameHeader, FrameError> {
    if bytes.len() < MIN_FRAME_LEN as usize {
        return Err(FrameError::Length);
    }
    let total_len = u64::from_le_bytes(bytes[16..24].try_into().expect("8"));

    // 1. total_len >= 224, 8-aligned, and within the readable region.
    if total_len < MIN_FRAME_LEN
        || total_len % FRAME_ALIGNMENT != 0
        || total_len > file_remaining
        || total_len as usize > bytes.len()
    {
        return Err(FrameError::Length);
    }
    let bytes = &bytes[..total_len as usize];

    // 2. header magic and storage version; header_len.
    if bytes[0..8] != FRAME_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().expect("2")) != STORAGE_VERSION
    {
        return Err(FrameError::HeaderMagic);
    }
    if u16::from_le_bytes(bytes[10..12].try_into().expect("2")) as usize != FRAME_HEADER_LEN {
        return Err(FrameError::HeaderLen);
    }

    // 3. journal_id equals the containing file's.
    if bytes[24..40] != journal_id[..] {
        return Err(FrameError::JournalId);
    }

    // 4. trailer magic and the repeated total_len.
    let trailer_at = (total_len - FRAME_TRAILER_LEN as u64) as usize;
    if bytes[trailer_at..trailer_at + 8] != FRAME_TRAILER_MAGIC
        || u64::from_le_bytes(
            bytes[trailer_at + 8..trailer_at + 16]
                .try_into()
                .expect("8"),
        ) != total_len
    {
        return Err(FrameError::Trailer);
    }

    // 5. frame_digest recomputes.
    let digest_at = (total_len - 32) as usize;
    if bytes[digest_at..] != format::digest(FRAME_DIGEST_DOMAIN, &bytes[..digest_at]).0[..] {
        return Err(FrameError::FrameDigest);
    }

    // 6. payload_digest recomputes.
    let payload_len = u64::from_le_bytes(bytes[136..144].try_into().expect("8"));
    let payload_end = FRAME_HEADER_LEN as u64 + payload_len;
    if payload_end > trailer_at as u64 {
        return Err(FrameError::Length);
    }
    let payload = &bytes[FRAME_HEADER_LEN..payload_end as usize];
    if bytes[144..176] != format::digest(FRAME_PAYLOAD_DIGEST_DOMAIN, payload).0[..] {
        return Err(FrameError::PayloadDigest);
    }

    // 7. flags == 0.
    if u32::from_le_bytes(bytes[12..16].try_into().expect("4")) != 0 {
        return Err(FrameError::Flags);
    }

    // 8. every padding byte between payload and trailer is zero.
    if bytes[payload_end as usize..trailer_at]
        .iter()
        .any(|b| *b != 0)
    {
        return Err(FrameError::Padding);
    }

    Ok(FrameHeader {
        flags: 0,
        total_len,
        journal_id: bytes[24..40].try_into().expect("16"),
        shard_sequence: u64::from_le_bytes(bytes[40..48].try_into().expect("8")),
        repo_sequence: u64::from_le_bytes(bytes[48..56].try_into().expect("8")),
        namespace: bytes[56..88].try_into().expect("32"),
        operation_id: bytes[88..104].try_into().expect("16"),
        operation_digest: ObjectId(bytes[104..136].try_into().expect("32")),
        payload_len,
        payload_digest: ObjectId(bytes[144..176].try_into().expect("32")),
    })
}

// ---------------------------------------------------------------------------
// Physical images
// ---------------------------------------------------------------------------

/// A real shard journal file: a `format::JournalHeader` at offset 0, frames
/// from 512, and the remainder of the preallocated region filled with `fill`.
///
/// `fill` is what distinguishes the two normal copy-on-write crash images: a
/// zeroed tail (a freshly preallocated extent) from stale preallocated content
/// (an extent recycled from an earlier file). The file is a real journal so the
/// tests drive `journal::scan_journal` — the production scanner — rather than a
/// parallel one.
pub struct JournalImage {
    pub dir: tempfile::TempDir,
    pub path: PathBuf,
    pub header: JournalHeader,
    pub content_end: u64,
}

pub const PREALLOCATED: u64 = 64 * 1024;

impl JournalImage {
    pub fn build(frames: &[u8], preallocated_len: u64, fill: u8) -> Self {
        Self::build_with_journal_id(frames, preallocated_len, fill, JOURNAL_ID)
    }

    pub fn build_with_journal_id(
        frames: &[u8],
        preallocated_len: u64,
        fill: u8,
        journal_id: [u8; 16],
    ) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        Self::build_at(dir, "0.journal", frames, preallocated_len, fill, journal_id)
    }

    pub fn build_at(
        dir: tempfile::TempDir,
        name: &str,
        frames: &[u8],
        preallocated_len: u64,
        fill: u8,
        journal_id: [u8; 16],
    ) -> Self {
        let header = JournalHeader {
            shard_index: 0,
            root_uuid: ROOT_UUID,
            journal_id,
            first_shard_sequence: 0,
            preallocated_len,
            created_at_micros: 1,
        };
        let mut bytes = vec![fill; preallocated_len as usize];
        bytes[..JOURNAL_HEADER_LEN].copy_from_slice(&header.encode().expect("encode header"));
        bytes[JOURNAL_HEADER_LEN..JOURNAL_HEADER_LEN + frames.len()].copy_from_slice(frames);

        let path = dir.path().join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        let mut file = File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("create");
        file.write_all(&bytes).expect("write");
        file.sync_all().expect("sync");

        Self {
            dir,
            path,
            header,
            content_end: (JOURNAL_HEADER_LEN + frames.len()) as u64,
        }
    }

    pub fn zeroed_tail(frames: &[u8], preallocated_len: u64) -> Self {
        Self::build(frames, preallocated_len, 0)
    }

    /// Stale content that is emphatically not a frame start and not zeros.
    pub fn stale_tail(frames: &[u8], preallocated_len: u64) -> Self {
        Self::build(frames, preallocated_len, 0xA7)
    }

    pub fn open(&self) -> File {
        File::open(&self.path).expect("open journal")
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    pub fn bytes(&self) -> Vec<u8> {
        std::fs::read(&self.path).expect("read journal")
    }

    /// Offset of the frame that starts after `frames_before` bytes of frames.
    pub fn frame_offset(frames_before: usize) -> u64 {
        (JOURNAL_HEADER_LEN + frames_before) as u64
    }

    /// Run the production scanner over this image.
    pub fn scan(&self) -> TailScan {
        scan_journal(&self.open(), &self.header, JOURNAL_HEADER_LEN as u64)
    }
}

// ---------------------------------------------------------------------------
// Shard directory fixture
// ---------------------------------------------------------------------------

/// A shard directory laid out exactly as `segment::ShardPaths` expects, whose
/// manifests and `CURRENT` are written with A1's frozen codec.
///
/// There is deliberately no reference manifest codec here. An earlier draft had
/// one; it was a second implementation of bytes A1 owns, which is the thing the
/// Wave A review is meant to prevent. The frame codec is different: a second
/// derivation of scope 3.3 is an explicit review artifact, and lives above.
pub struct ShardDir {
    pub dir: tempfile::TempDir,
    pub paths: ShardPaths,
}

impl Default for ShardDir {
    fn default() -> Self {
        Self::new()
    }
}

impl ShardDir {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let paths = ShardPaths::new(dir.path());
        for sub in [
            paths.active(),
            paths.segments(),
            paths.indexes(),
            paths.checkpoints(),
            paths.manifests(),
        ] {
            std::fs::create_dir_all(sub).expect("mkdir");
        }
        Self { dir, paths }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// A segment file long enough to pass the presence-and-length validator
    /// but with no valid footer — enough for step 2's cheap referent check.
    pub fn write_placeholder_segment(&self, filename: &str, len: usize) {
        std::fs::write(self.paths.segments().join(filename), vec![0u8; len])
            .expect("write segment");
    }

    pub fn write_manifest(&self, manifest: &Manifest) -> PathBuf {
        let path = self.paths.manifest(manifest.generation);
        std::fs::write(&path, manifest.encode().expect("encode manifest")).expect("write");
        path
    }

    pub fn write_current(&self, generation: u64, root_uuid: [u8; 16]) -> PathBuf {
        let path = self.paths.current();
        let pointer = CurrentPointer {
            root_uuid,
            generation,
        };
        std::fs::write(&path, pointer.encode().expect("encode CURRENT")).expect("write");
        path
    }

    /// Flip a byte in a file relative to the shard directory.
    pub fn corrupt(&self, relative: &str, at: usize) {
        let path = self.path().join(relative);
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[at] ^= 0xFF;
        std::fs::write(&path, bytes).expect("write");
    }
}

pub fn manifest(generation: u64, segment: &str) -> Manifest {
    Manifest {
        root_uuid: ROOT_UUID,
        generation,
        base_generation: 0,
        retained_tail_ranges: vec![TailRange {
            generation,
            first_shard_sequence: 0,
            last_shard_sequence: 9,
            filename: segment.to_string(),
        }],
        index_runs: Vec::new(),
        checkpoints: Vec::new(),
        committed_shard_sequence: 9,
    }
}

// ---------------------------------------------------------------------------
// Self-tests for the reference implementation
// ---------------------------------------------------------------------------

#[cfg(test)]
mod reference_self_tests {
    use super::*;

    #[test]
    fn a_well_formed_reference_frame_satisfies_every_condition() {
        let bytes = frame(7);
        let header = reference_verify(&bytes, &JOURNAL_ID, bytes.len() as u64).expect("valid");
        assert_eq!(header.shard_sequence, 7);
        assert_eq!(header.repo_sequence, 7);
        assert_eq!(header.total_len, bytes.len() as u64);
        assert_eq!(header.flags, 0);
    }

    #[test]
    fn each_of_the_eight_conditions_is_independently_violable() {
        let good = frame(1);
        let remaining = good.len() as u64;

        // 1. total_len not 8-aligned.
        let mut length = good.clone();
        let total = u64::from_le_bytes(length[16..24].try_into().unwrap());
        length[16..24].copy_from_slice(&(total + 1).to_le_bytes());
        assert_eq!(
            reference_verify(&length, &JOURNAL_ID, remaining),
            Err(FrameError::Length)
        );

        // 2. header magic.
        let mut magic = good.clone();
        magic[0] ^= 0xFF;
        reseal_frame_digest(&mut magic);
        assert_eq!(
            reference_verify(&magic, &JOURNAL_ID, remaining),
            Err(FrameError::HeaderMagic)
        );

        // 2b. header_len.
        let mut header_len = good.clone();
        header_len[10..12].copy_from_slice(&99u16.to_le_bytes());
        reseal_frame_digest(&mut header_len);
        assert_eq!(
            reference_verify(&header_len, &JOURNAL_ID, remaining),
            Err(FrameError::HeaderLen)
        );

        // 3. journal_id.
        assert_eq!(
            reference_verify(&good, &[0xEE; 16], remaining),
            Err(FrameError::JournalId)
        );

        // 4. trailer magic.
        let mut trailer = good.clone();
        let at = trailer.len() - FRAME_TRAILER_LEN;
        trailer[at] ^= 0xFF;
        reseal_frame_digest(&mut trailer);
        assert_eq!(
            reference_verify(&trailer, &JOURNAL_ID, remaining),
            Err(FrameError::Trailer)
        );

        // 5. frame digest.
        let mut digest = good.clone();
        let at = digest.len() - 1;
        digest[at] ^= 0xFF;
        assert_eq!(
            reference_verify(&digest, &JOURNAL_ID, remaining),
            Err(FrameError::FrameDigest)
        );

        // 6. payload digest.
        let mut payload = good.clone();
        payload[FRAME_HEADER_LEN] ^= 0xFF;
        reseal_frame_digest(&mut payload);
        assert_eq!(
            reference_verify(&payload, &JOURNAL_ID, remaining),
            Err(FrameError::PayloadDigest)
        );

        // 7. flags.
        let mut flags = FrameSpec::new(1);
        flags.flags = 1;
        let flags = flags.encode();
        assert_eq!(
            reference_verify(&flags, &JOURNAL_ID, flags.len() as u64),
            Err(FrameError::Flags),
            "a non-zero flags value must reject even though every digest recomputes"
        );

        // 8. padding.
        let mut padded = FrameSpec::new(1);
        padded.pad_byte = 0xFF;
        let padded = padded.encode();
        assert!(
            format::frame_padding_len(FrameSpec::new(1).payload.len() as u64) > 0,
            "the fixture payload must actually require padding"
        );
        assert_eq!(
            reference_verify(&padded, &JOURNAL_ID, padded.len() as u64),
            Err(FrameError::Padding),
            "a non-zero padding byte must reject even though every digest recomputes"
        );
    }

    #[test]
    fn truncation_at_every_offset_is_rejected_without_panic() {
        let good = frame(3);
        for cut in 0..good.len() {
            assert!(
                reference_verify(&good[..cut], &JOURNAL_ID, cut as u64).is_err(),
                "truncation at {cut} must be rejected"
            );
        }
    }
}
