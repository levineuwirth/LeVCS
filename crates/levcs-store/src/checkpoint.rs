//! Rebuildable object, ref, and receipt checkpoints, and their atomic
//! installation.
//!
//! **Owned by A2 RecoveryIndex** (scope 2.1, 4-A2).
//!
//! At least `checkpoint_retain` independently validated generations are kept.
//! If all of them fail validation, startup enters explicit offline rebuild
//! mode rather than an unbounded normal-readiness scan (plan §5.3).
//!
//! # Derived, never authoritative
//!
//! Plan §5.3: "Ref state and namespace metadata are derived/checkpointed;
//! journal/segment frames remain authoritative." A checkpoint is therefore only
//! ever a *replay start point*. Losing every generation costs replay time, not
//! data — which is exactly why the correct response to "all generations are
//! corrupt" is an explicit offline rebuild rather than an error, and equally
//! why it may never be a silent unbounded scan during normal readiness.
//!
//! # Where the codec lives
//!
//! `format.rs`'s doc header lists checkpoints among the things it covers, but
//! D0 landed only `CHECKPOINT_MAGIC` and `CHECKPOINT_DIGEST_DOMAIN` there — no
//! checkpoint type and no signature. The checkpoint body is entirely A2-owned
//! derived state, so its codec lives here and reuses the lead's frozen magic
//! and digest domain. This is recorded as an interface note rather than worked
//! around silently.

use std::io::IoSlice;
use std::path::{Path, PathBuf};

use levcs_core::ObjectId;
use levcs_protocol::v2::{RefTarget, MAX_REF_UPDATES};

use crate::format::{CHECKPOINT_DIGEST_DOMAIN, CHECKPOINT_MAGIC, STORAGE_VERSION};
use crate::index::{NamespaceCatalog, NamespaceLifecycle, NamespaceRecord, NamespaceStorageMode};
use crate::types::{AppliedRef, DurabilityCounters, NamespaceId, OperationId, StoreError};

/// 88 bytes of named fields, zero padding to 96, then a 32-byte header digest.
/// Every byte that is not a named field must be zero, for the same reason
/// scope 3.3 pins the frame's padding.
pub const CHECKPOINT_HEADER_LEN: usize = 128;
const CHECKPOINT_HEADER_FIELDS_LEN: usize = 88;
pub const CHECKPOINT_TRAILER_LEN: usize = 48;
pub const CHECKPOINT_EXTENSION: &str = "checkpoint";

/// Decode-side ceilings. A checkpoint is derived state read back from disk, so
/// its counts are attacker-adjacent in exactly the sense Phase 0's checked
/// readers were: `with_capacity` is never called on an unvalidated count.
const MAX_CHECKPOINT_NAMESPACES: u32 = 4_000_000;
const MAX_CHECKPOINT_REFS: u32 = 64_000_000;
const MAX_CHECKPOINT_RECEIPTS: u32 = 64_000_000;
const MAX_REF_NAME_LEN: u16 = 1024;

/// Checkpoint-body capability: every retained receipt carries its complete
/// applied-ref result.
///
/// Checkpoints are derived and independently versioned by their flags within
/// storage version 1. A version-1 checkpoint with flags zero predates this
/// capability. It remains readable only when it has no retained receipts;
/// otherwise accepting it would publish a receipt with an invented empty ref
/// result. Such generations are rejected and recovery enters its existing
/// explicit offline-rebuild path when no newer complete generation exists.
const CHECKPOINT_FLAG_RECEIPT_REFS: u32 = 1 << 0;
const CHECKPOINT_KNOWN_FLAGS: u32 = CHECKPOINT_FLAG_RECEIPT_REFS;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a checkpoint generation is not usable.
///
/// Individually asserted, never collapsed: "the checkpoint did not load" is
/// not a finding, and a reviewer cannot tell a truncated file from a file that
/// belongs to a different store root if both arrive as one variant.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CheckpointError {
    #[error("checkpoint is shorter than its fixed header and trailer")]
    Truncated,
    #[error("checkpoint magic does not match")]
    Magic,
    #[error("checkpoint storage version {0} is not readable")]
    StorageVersion(u16),
    #[error("checkpoint has unknown flags or non-zero reserved fields")]
    Flags,
    #[error("checkpoint predates complete applied-ref receipt retention")]
    ReceiptRefsUnavailable,
    #[error("checkpoint header digest does not recompute")]
    HeaderDigest,
    #[error("checkpoint trailer magic or repeated total_len does not match")]
    Trailer,
    #[error("checkpoint body digest does not recompute")]
    BodyDigest,
    #[error("checkpoint root uuid does not match this store root")]
    RootUuid,
    #[error("checkpoint belongs to shard {found}, not shard {expected}")]
    ShardIndex { expected: u16, found: u16 },
    #[error("checkpoint declares a count beyond its decode ceiling: {0}")]
    CountCeiling(&'static str),
    #[error("checkpoint body is malformed: {0}")]
    Body(&'static str),
    /// Named separately from [`CheckpointError::Body`] because the offending
    /// value is the whole diagnosis: a ref kind is one byte, and "which byte"
    /// is the difference between a torn write and a reader that never learned
    /// about a kind a newer writer emits.
    #[error("checkpoint carries unknown ref kind {0}")]
    RefKind(u8),
    #[error("checkpoint has trailing bytes after its declared body")]
    TrailingBytes,
    #[error("checkpoint file name is not <shard_sequence>.checkpoint")]
    FileName,
    #[error("checkpoint file could not be read: {0}")]
    Unreadable(String),
}

impl From<CheckpointError> for StoreError {
    fn from(e: CheckpointError) -> Self {
        StoreError::Corruption(format!("checkpoint: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

/// One typed ref binding, as of the checkpoint's `shard_committed_sequence`.
///
/// The physical `(ref_kind, name)` pair stays public because the checkpoint
/// body encodes it directly, but nothing outside this module should ever
/// interpret it: use [`RefRecord::from_target`] and [`RefRecord::target`].
/// Every consumer that decodes `ref_kind` itself is restating a table this
/// module owns, and the copy is only ever discovered when the two disagree —
/// which, for a derived-but-authoritative ref table, means a reopened store
/// silently resolving a branch as a release.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefRecord {
    pub namespace: NamespaceId,
    pub ref_kind: u8,
    pub name: Vec<u8>,
    pub target: ObjectId,
}

impl RefRecord {
    /// Builds the physical record for a typed ref binding.
    pub fn from_target(namespace: NamespaceId, target: &RefTarget, object: ObjectId) -> Self {
        let (ref_kind, name) = ref_target_parts(target);
        Self {
            namespace,
            ref_kind,
            name: name.as_bytes().to_vec(),
            target: object,
        }
    }

    /// The typed binding this record encodes.
    ///
    /// Fallible on purpose. A checkpoint is derived state read back from disk,
    /// so `ref_kind` and `name` are attacker-adjacent in exactly the sense the
    /// rest of this module's readers are: an unknown kind is refused by name,
    /// never defaulted to `Branch` and never dropped. Defaulting would turn a
    /// corrupt byte into a plausible ref that the next checkpoint would then
    /// write back as if it had always been there.
    pub fn target(&self) -> Result<RefTarget, CheckpointError> {
        let name = std::str::from_utf8(&self.name)
            .map_err(|_| CheckpointError::Body("ref record name utf-8"))?;
        ref_target_from_kind_code(self.ref_kind, name)
    }
}

/// A retained operation/receipt row.
///
/// `first_receipt_visibility_micros` is the field recovery step 10 promotes.
/// It is `Option` on purpose: "not yet durably captured" and "captured as zero"
/// are different facts, and conflating them is exactly how a retention window
/// gets shortened by a crash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptRecord {
    pub namespace: NamespaceId,
    pub operation_id: OperationId,
    pub operation_digest: ObjectId,
    pub repo_sequence: u64,
    pub shard_sequence: u64,
    pub current_authority: ObjectId,
    /// The exact per-transaction result, including deletions and force.
    ///
    /// This cannot be reconstructed from the checkpoint's current ref table:
    /// that table has neither the old value nor transaction membership, and a
    /// deleted ref is absent from it entirely.
    pub refs: Vec<AppliedRef>,
    pub objects_new: u64,
    pub retry_until_micros: i64,
    /// `None` when the crash preceded a durable capture of first visibility.
    pub first_receipt_visibility_micros: Option<i64>,
    pub receipt_visible_until_micros: i64,
}

/// Derived shard state through `shard_committed_sequence`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub root_uuid: [u8; 16],
    pub shard_index: u16,
    pub shard_committed_sequence: u64,
    /// The active journal at checkpoint time, and how far into it this
    /// checkpoint already accounts for. Recovery resumes its forward scan
    /// here (scope 3.8 step 5) rather than from the file header, which is
    /// what keeps replay bounded.
    pub active_journal_id: [u8; 16],
    pub active_journal_offset: u64,
    pub created_at_micros: i64,
    pub catalog: NamespaceCatalog,
    pub refs: Vec<RefRecord>,
    pub receipts: Vec<ReceiptRecord>,
}

impl Checkpoint {
    pub fn empty(root_uuid: [u8; 16], shard_index: u16) -> Self {
        Self {
            root_uuid,
            shard_index,
            shard_committed_sequence: 0,
            active_journal_id: [0u8; 16],
            active_journal_offset: 0,
            created_at_micros: 0,
            catalog: NamespaceCatalog::new(),
            refs: Vec::new(),
            receipts: Vec::new(),
        }
    }

    pub fn file_name(&self) -> String {
        format!("{}.{}", self.shard_committed_sequence, CHECKPOINT_EXTENSION)
    }
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_i64(out: &mut Vec<u8>, v: i64) {
    out.extend_from_slice(&v.to_le_bytes());
}

/// A bounds-checked forward reader. Every read is fallible and every length is
/// validated before it is used, in the Phase 0 checked-reader style.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], CheckpointError> {
        let end = self
            .at
            .checked_add(n)
            .ok_or(CheckpointError::Body("length overflow"))?;
        if end > self.bytes.len() {
            return Err(CheckpointError::Body(what));
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn u8(&mut self, what: &'static str) -> Result<u8, CheckpointError> {
        Ok(self.take(1, what)?[0])
    }

    fn u16(&mut self, what: &'static str) -> Result<u16, CheckpointError> {
        Ok(u16::from_le_bytes(
            self.take(2, what)?.try_into().expect("2 bytes"),
        ))
    }

    fn u32(&mut self, what: &'static str) -> Result<u32, CheckpointError> {
        Ok(u32::from_le_bytes(
            self.take(4, what)?.try_into().expect("4 bytes"),
        ))
    }

    fn u64(&mut self, what: &'static str) -> Result<u64, CheckpointError> {
        Ok(u64::from_le_bytes(
            self.take(8, what)?.try_into().expect("8 bytes"),
        ))
    }

    fn i64(&mut self, what: &'static str) -> Result<i64, CheckpointError> {
        Ok(i64::from_le_bytes(
            self.take(8, what)?.try_into().expect("8 bytes"),
        ))
    }

    fn bytes32(&mut self, what: &'static str) -> Result<[u8; 32], CheckpointError> {
        Ok(self.take(32, what)?.try_into().expect("32 bytes"))
    }

    fn bytes16(&mut self, what: &'static str) -> Result<[u8; 16], CheckpointError> {
        Ok(self.take(16, what)?.try_into().expect("16 bytes"))
    }

    fn finished(&self) -> bool {
        self.at == self.bytes.len()
    }
}

/// `Option<i64>` on the wire: a presence byte then the value. Not a sentinel —
/// a sentinel would make "unset" a legal timestamp.
fn put_optional_i64(out: &mut Vec<u8>, v: Option<i64>) {
    match v {
        Some(value) => {
            out.push(1);
            put_i64(out, value);
        }
        None => {
            out.push(0);
            put_i64(out, 0);
        }
    }
}

fn read_optional_i64(
    r: &mut Reader<'_>,
    what: &'static str,
) -> Result<Option<i64>, CheckpointError> {
    let present = r.u8(what)?;
    let value = r.i64(what)?;
    match present {
        0 => Ok(None),
        1 => Ok(Some(value)),
        _ => Err(CheckpointError::Body(
            "optional presence byte must be 0 or 1",
        )),
    }
}

fn put_optional_object_id(out: &mut Vec<u8>, value: Option<ObjectId>) {
    match value {
        Some(value) => {
            out.push(1);
            out.extend_from_slice(value.as_bytes());
        }
        None => out.push(0),
    }
}

fn read_optional_object_id(
    r: &mut Reader<'_>,
    what: &'static str,
) -> Result<Option<ObjectId>, CheckpointError> {
    match r.u8(what)? {
        0 => Ok(None),
        1 => Ok(Some(ObjectId(r.bytes32(what)?))),
        _ => Err(CheckpointError::Body(
            "optional object-id presence byte must be 0 or 1",
        )),
    }
}

/// The checkpoint body's ref-kind codes, encode side.
///
/// Paired with [`ref_target_from_kind_code`], and the only place in the crate
/// that assigns these two codes. `format.rs` has its own table for the *frame*
/// encoding; that is not a duplicate, because the two physical formats are
/// versioned independently and each is self-consistent — a frame code is only
/// ever compared to a frame code. The copies that mattered were the ones that
/// decoded a `RefRecord` this module produced, and those are now gone.
fn ref_target_parts(target: &RefTarget) -> (u8, &str) {
    match target {
        RefTarget::Branch(name) => (1, name),
        RefTarget::Release(name) => (2, name),
    }
}

/// The checkpoint body's ref-kind codes, decode side.
///
/// Rejects an unknown code by value rather than defaulting: a ref table is
/// derived state, and a silently reclassified ref would be written back into
/// the next checkpoint as though it were authoritative.
fn ref_target_from_kind_code(kind: u8, name: &str) -> Result<RefTarget, CheckpointError> {
    if name.is_empty()
        || name.len() > MAX_REF_NAME_LEN as usize
        || name.as_bytes().contains(&0)
        || levcs_core::refs::validate_ref_name(name).is_err()
    {
        return Err(CheckpointError::Body("ref target name"));
    }
    match kind {
        1 => Ok(RefTarget::Branch(name.to_owned())),
        2 => Ok(RefTarget::Release(name.to_owned())),
        unknown => Err(CheckpointError::RefKind(unknown)),
    }
}

fn validate_ref_target(name: &str) -> Result<(), StoreError> {
    if name.len() > MAX_REF_NAME_LEN as usize {
        return Err(StoreError::LimitExceeded {
            limit: "checkpoint_receipt_ref_name_len",
            observed: name.len() as u64,
            allowed: MAX_REF_NAME_LEN as u64,
        });
    }
    if name.is_empty()
        || name.as_bytes().contains(&0)
        || levcs_core::refs::validate_ref_name(name).is_err()
    {
        return Err(StoreError::Corruption(
            "checkpoint receipt contains an invalid applied-ref target".into(),
        ));
    }
    Ok(())
}

/// Checkpoint-local physical encoding of the frozen `AppliedRefV1` value.
///
/// The protocol codec intentionally keeps its element codec private. Plan
/// §13 keeps these checkpoint bytes internal, so this codec delegates name
/// validation to the same `levcs-core` function and pins the complete logical
/// value rather than reaching through a private protocol implementation.
fn put_applied_refs(out: &mut Vec<u8>, refs: &[AppliedRef]) -> Result<(), StoreError> {
    if refs.len() > MAX_REF_UPDATES {
        return Err(StoreError::LimitExceeded {
            limit: "checkpoint_receipt_applied_refs",
            observed: refs.len() as u64,
            allowed: MAX_REF_UPDATES as u64,
        });
    }
    let mut targets = std::collections::BTreeSet::new();
    put_u32(out, refs.len() as u32);
    for applied in refs {
        if !targets.insert(applied.target.clone()) {
            return Err(StoreError::Corruption(
                "checkpoint receipt contains duplicate applied-ref targets".into(),
            ));
        }
        let (kind, name) = ref_target_parts(&applied.target);
        validate_ref_target(name)?;
        out.push(kind);
        put_u16(out, name.len() as u16);
        out.extend_from_slice(name.as_bytes());
        put_optional_object_id(out, applied.old);
        put_optional_object_id(out, applied.new);
        out.push(u8::from(applied.force));
    }
    Ok(())
}

fn read_applied_refs(r: &mut Reader<'_>) -> Result<Vec<AppliedRef>, CheckpointError> {
    let count = r.u32("receipt applied-ref count")?;
    if count as usize > MAX_REF_UPDATES {
        return Err(CheckpointError::CountCeiling("receipt applied refs"));
    }
    // Seven bytes is the smallest valid record: kind, name length, one-byte
    // name, two absent object IDs, and force.
    let mut refs = Vec::with_capacity((count as usize).min(r.bytes.len() / 7 + 1));
    let mut targets = std::collections::BTreeSet::new();
    for _ in 0..count {
        let kind = r.u8("receipt ref target kind")?;
        let name_len = r.u16("receipt ref target name length")?;
        if name_len > MAX_REF_NAME_LEN {
            return Err(CheckpointError::CountCeiling(
                "receipt ref target name length",
            ));
        }
        if name_len == 0 {
            return Err(CheckpointError::Body("receipt ref target name length"));
        }
        let name = std::str::from_utf8(r.take(name_len as usize, "receipt ref target name")?)
            .map_err(|_| CheckpointError::Body("receipt ref target name utf-8"))?;
        let target = ref_target_from_kind_code(kind, name)?;
        if !targets.insert(target.clone()) {
            return Err(CheckpointError::Body(
                "duplicate receipt applied-ref target",
            ));
        }
        let old = read_optional_object_id(r, "receipt old ref object")?;
        let new = read_optional_object_id(r, "receipt new ref object")?;
        let force = match r.u8("receipt applied-ref force")? {
            0 => false,
            1 => true,
            _ => return Err(CheckpointError::Body("receipt applied-ref force")),
        };
        refs.push(AppliedRef {
            target,
            old,
            new,
            force,
        });
    }
    Ok(refs)
}

impl Checkpoint {
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        self.encode_with_receipt_refs(true)
    }

    fn encode_with_receipt_refs(&self, include_receipt_refs: bool) -> Result<Vec<u8>, StoreError> {
        if self.catalog.len() as u64 > MAX_CHECKPOINT_NAMESPACES as u64 {
            return Err(StoreError::LimitExceeded {
                limit: "checkpoint_namespaces",
                observed: self.catalog.len() as u64,
                allowed: MAX_CHECKPOINT_NAMESPACES as u64,
            });
        }
        if self.refs.len() as u64 > MAX_CHECKPOINT_REFS as u64 {
            return Err(StoreError::LimitExceeded {
                limit: "checkpoint_refs",
                observed: self.refs.len() as u64,
                allowed: MAX_CHECKPOINT_REFS as u64,
            });
        }
        if self.receipts.len() as u64 > MAX_CHECKPOINT_RECEIPTS as u64 {
            return Err(StoreError::LimitExceeded {
                limit: "checkpoint_receipts",
                observed: self.receipts.len() as u64,
                allowed: MAX_CHECKPOINT_RECEIPTS as u64,
            });
        }

        let mut body = Vec::new();

        put_u32(&mut body, self.catalog.len() as u32);
        for (_, record) in self.catalog.iter() {
            body.extend_from_slice(&record.namespace.0);
            body.extend_from_slice(&record.genesis_authority.0);
            body.extend_from_slice(&record.current_authority.0);
            body.push(record.lifecycle.code());
            body.push(record.storage_mode.code());
            put_u16(&mut body, 0); // reserved, must be zero
            put_u64(&mut body, record.repo_sequence);
            body.extend_from_slice(&record.previous_event_digest.0);
        }

        put_u32(&mut body, self.refs.len() as u32);
        for r in &self.refs {
            if r.name.len() > MAX_REF_NAME_LEN as usize {
                return Err(StoreError::LimitExceeded {
                    limit: "checkpoint_ref_name_len",
                    observed: r.name.len() as u64,
                    allowed: MAX_REF_NAME_LEN as u64,
                });
            }
            body.extend_from_slice(&r.namespace.0);
            body.push(r.ref_kind);
            put_u16(&mut body, r.name.len() as u16);
            body.push(0); // reserved, must be zero
            body.extend_from_slice(&r.name);
            body.extend_from_slice(&r.target.0);
        }

        put_u32(&mut body, self.receipts.len() as u32);
        for rec in &self.receipts {
            body.extend_from_slice(&rec.namespace.0);
            body.extend_from_slice(&rec.operation_id.0);
            body.extend_from_slice(&rec.operation_digest.0);
            put_u64(&mut body, rec.repo_sequence);
            put_u64(&mut body, rec.shard_sequence);
            body.extend_from_slice(&rec.current_authority.0);
            if include_receipt_refs {
                put_applied_refs(&mut body, &rec.refs)?;
            }
            put_u64(&mut body, rec.objects_new);
            put_i64(&mut body, rec.retry_until_micros);
            put_optional_i64(&mut body, rec.first_receipt_visibility_micros);
            put_i64(&mut body, rec.receipt_visible_until_micros);
        }

        let total_len = (CHECKPOINT_HEADER_LEN + body.len() + CHECKPOINT_TRAILER_LEN) as u64;

        let mut header = Vec::with_capacity(CHECKPOINT_HEADER_LEN);
        header.extend_from_slice(&CHECKPOINT_MAGIC);
        put_u16(&mut header, STORAGE_VERSION);
        put_u16(&mut header, CHECKPOINT_HEADER_LEN as u16);
        put_u32(
            &mut header,
            if include_receipt_refs {
                CHECKPOINT_FLAG_RECEIPT_REFS
            } else {
                0
            },
        );
        header.extend_from_slice(&self.root_uuid);
        put_u16(&mut header, self.shard_index);
        put_u16(&mut header, 0); // reserved
        put_u32(&mut header, 0); // reserved
        put_u64(&mut header, self.shard_committed_sequence);
        header.extend_from_slice(&self.active_journal_id);
        put_u64(&mut header, self.active_journal_offset);
        put_i64(&mut header, self.created_at_micros);
        put_u64(&mut header, body.len() as u64);
        debug_assert_eq!(header.len(), CHECKPOINT_HEADER_FIELDS_LEN);
        header.resize(CHECKPOINT_HEADER_LEN - 32, 0);
        let header_digest = crate::format::digest(CHECKPOINT_DIGEST_DOMAIN, &header);
        header.extend_from_slice(&header_digest.0);
        debug_assert_eq!(header.len(), CHECKPOINT_HEADER_LEN);

        let mut out = Vec::with_capacity(total_len as usize);
        out.extend_from_slice(&header);
        out.extend_from_slice(&body);
        let body_digest = crate::format::digest(CHECKPOINT_DIGEST_DOMAIN, &out);
        out.extend_from_slice(&CHECKPOINT_MAGIC);
        put_u64(&mut out, total_len);
        out.extend_from_slice(&body_digest.0);
        debug_assert_eq!(out.len() as u64, total_len);
        Ok(out)
    }

    pub fn decode(
        bytes: &[u8],
        root_uuid: &[u8; 16],
        shard_index: u16,
    ) -> Result<Self, CheckpointError> {
        if bytes.len() < CHECKPOINT_HEADER_LEN + CHECKPOINT_TRAILER_LEN {
            return Err(CheckpointError::Truncated);
        }
        if bytes[0..8] != CHECKPOINT_MAGIC {
            return Err(CheckpointError::Magic);
        }
        let mut head = Reader::new(&bytes[..CHECKPOINT_HEADER_LEN]);
        head.take(8, "magic")?;
        let storage_version = head.u16("storage_version")?;
        if storage_version != STORAGE_VERSION {
            return Err(CheckpointError::StorageVersion(storage_version));
        }
        if head.u16("header_len")? as usize != CHECKPOINT_HEADER_LEN {
            return Err(CheckpointError::Body("header_len"));
        }
        let checkpoint_flags = head.u32("flags")?;
        if checkpoint_flags & !CHECKPOINT_KNOWN_FLAGS != 0 {
            return Err(CheckpointError::Flags);
        }
        let has_receipt_refs = checkpoint_flags & CHECKPOINT_FLAG_RECEIPT_REFS != 0;
        let file_root_uuid = head.bytes16("root_uuid")?;
        let file_shard = head.u16("shard_index")?;
        if head.u16("reserved")? != 0 || head.u32("reserved")? != 0 {
            return Err(CheckpointError::Flags);
        }
        let shard_committed_sequence = head.u64("shard_committed_sequence")?;
        let active_journal_id = head.bytes16("active_journal_id")?;
        let active_journal_offset = head.u64("active_journal_offset")?;
        let created_at_micros = head.i64("created_at_micros")?;
        let body_len = head.u64("body_len")?;
        if bytes[CHECKPOINT_HEADER_FIELDS_LEN..CHECKPOINT_HEADER_LEN - 32]
            .iter()
            .any(|b| *b != 0)
        {
            return Err(CheckpointError::Flags);
        }

        let stored_header_digest: [u8; 32] = bytes
            [CHECKPOINT_HEADER_LEN - 32..CHECKPOINT_HEADER_LEN]
            .try_into()
            .expect("32 bytes");
        if crate::format::digest(
            CHECKPOINT_DIGEST_DOMAIN,
            &bytes[..CHECKPOINT_HEADER_LEN - 32],
        )
        .0 != stored_header_digest
        {
            return Err(CheckpointError::HeaderDigest);
        }

        let expected_total = (CHECKPOINT_HEADER_LEN as u64)
            .checked_add(body_len)
            .and_then(|v| v.checked_add(CHECKPOINT_TRAILER_LEN as u64))
            .ok_or(CheckpointError::Body("total_len overflow"))?;
        if expected_total != bytes.len() as u64 {
            return Err(CheckpointError::Body("body_len disagrees with file length"));
        }

        let trailer = &bytes[bytes.len() - CHECKPOINT_TRAILER_LEN..];
        if trailer[0..8] != CHECKPOINT_MAGIC
            || u64::from_le_bytes(trailer[8..16].try_into().expect("8 bytes")) != expected_total
        {
            return Err(CheckpointError::Trailer);
        }
        let stored_body_digest: [u8; 32] = trailer[16..48].try_into().expect("32 bytes");
        if crate::format::digest(
            CHECKPOINT_DIGEST_DOMAIN,
            &bytes[..bytes.len() - CHECKPOINT_TRAILER_LEN],
        )
        .0 != stored_body_digest
        {
            return Err(CheckpointError::BodyDigest);
        }

        // Identity binding is checked only after the file has been proved
        // internally consistent, so a corrupt file cannot masquerade as a
        // foreign-root file or vice versa.
        if &file_root_uuid != root_uuid {
            return Err(CheckpointError::RootUuid);
        }
        if file_shard != shard_index {
            return Err(CheckpointError::ShardIndex {
                expected: shard_index,
                found: file_shard,
            });
        }

        let body = &bytes[CHECKPOINT_HEADER_LEN..bytes.len() - CHECKPOINT_TRAILER_LEN];
        let mut r = Reader::new(body);

        let namespace_count = r.u32("namespace_count")?;
        if namespace_count > MAX_CHECKPOINT_NAMESPACES {
            return Err(CheckpointError::CountCeiling("namespaces"));
        }
        let mut catalog = NamespaceCatalog::new();
        for _ in 0..namespace_count {
            let namespace = NamespaceId(r.bytes32("namespace")?);
            let genesis_authority = ObjectId(r.bytes32("genesis_authority")?);
            let current_authority = ObjectId(r.bytes32("current_authority")?);
            let lifecycle = NamespaceLifecycle::from_code(r.u8("lifecycle")?)
                .ok_or(CheckpointError::Body("unknown namespace lifecycle"))?;
            let storage_mode = NamespaceStorageMode::from_code(r.u8("storage_mode")?)
                .ok_or(CheckpointError::Body("unknown namespace storage mode"))?;
            if r.u16("reserved")? != 0 {
                return Err(CheckpointError::Flags);
            }
            let repo_sequence = r.u64("repo_sequence")?;
            let previous_event_digest = ObjectId(r.bytes32("previous_event_digest")?);
            catalog
                .bind(NamespaceRecord {
                    namespace,
                    genesis_authority,
                    current_authority,
                    lifecycle,
                    storage_mode,
                    repo_sequence,
                    previous_event_digest,
                })
                .map_err(|_| CheckpointError::Body("duplicate namespace in catalog"))?;
        }

        let ref_count = r.u32("ref_count")?;
        if ref_count > MAX_CHECKPOINT_REFS {
            return Err(CheckpointError::CountCeiling("refs"));
        }
        // Bound the reservation by what the remaining bytes could possibly
        // hold: the smallest encodable ref is 68 bytes.
        let mut refs = Vec::with_capacity((ref_count as usize).min(body.len() / 68 + 1));
        for _ in 0..ref_count {
            let namespace = NamespaceId(r.bytes32("ref namespace")?);
            let ref_kind = r.u8("ref_kind")?;
            let name_len = r.u16("ref name_len")?;
            if name_len > MAX_REF_NAME_LEN {
                return Err(CheckpointError::CountCeiling("ref name length"));
            }
            if r.u8("reserved")? != 0 {
                return Err(CheckpointError::Flags);
            }
            let name = r.take(name_len as usize, "ref name")?.to_vec();
            let target = ObjectId(r.bytes32("ref target")?);
            refs.push(RefRecord {
                namespace,
                ref_kind,
                name,
                target,
            });
        }

        let receipt_count = r.u32("receipt_count")?;
        if receipt_count > MAX_CHECKPOINT_RECEIPTS {
            return Err(CheckpointError::CountCeiling("receipts"));
        }
        let minimum_receipt_len = if has_receipt_refs { 165 } else { 161 };
        let mut receipts =
            Vec::with_capacity((receipt_count as usize).min(body.len() / minimum_receipt_len + 1));
        for _ in 0..receipt_count {
            receipts.push(ReceiptRecord {
                namespace: NamespaceId(r.bytes32("receipt namespace")?),
                operation_id: OperationId(r.bytes16("operation_id")?),
                operation_digest: ObjectId(r.bytes32("operation_digest")?),
                repo_sequence: r.u64("repo_sequence")?,
                shard_sequence: r.u64("shard_sequence")?,
                current_authority: ObjectId(r.bytes32("current_authority")?),
                refs: if has_receipt_refs {
                    read_applied_refs(&mut r)?
                } else {
                    Vec::new()
                },
                objects_new: r.u64("objects_new")?,
                retry_until_micros: r.i64("retry_until_micros")?,
                first_receipt_visibility_micros: read_optional_i64(&mut r, "first_visibility")?,
                receipt_visible_until_micros: r.i64("receipt_visible_until")?,
            });
        }

        if !r.finished() {
            return Err(CheckpointError::TrailingBytes);
        }
        if !has_receipt_refs && !receipts.is_empty() {
            return Err(CheckpointError::ReceiptRefsUnavailable);
        }

        Ok(Self {
            root_uuid: file_root_uuid,
            shard_index: file_shard,
            shard_committed_sequence,
            active_journal_id,
            active_journal_offset,
            created_at_micros,
            catalog,
            refs,
            receipts,
        })
    }
}

// ---------------------------------------------------------------------------
// Installation and selection
// ---------------------------------------------------------------------------

/// What loading the checkpoint directory concluded.
///
/// `Empty` and `OfflineRebuildRequired` are deliberately different: a fresh
/// root has no checkpoints and is perfectly healthy, while a root whose every
/// generation fails validation must not silently behave like a fresh one and
/// replay from sequence zero. Collapsing them would turn the plan §5.3 rule
/// into a no-op on exactly the input it exists for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointLoad {
    /// No generation exists yet. Replay starts at the beginning.
    Empty,
    Loaded {
        checkpoint: Box<Checkpoint>,
        path: PathBuf,
        /// Generations newer than the loaded one that failed validation, so an
        /// operator sees that a fallback happened rather than inferring it.
        rejected: Vec<(PathBuf, CheckpointError)>,
    },
    /// Every generation present failed validation. Startup must enter offline
    /// rebuild explicitly rather than performing an unbounded scan.
    OfflineRebuildRequired {
        rejected: Vec<(PathBuf, CheckpointError)>,
    },
}

/// Parse `<shard_sequence>.checkpoint`. Anything else in the directory is not
/// a candidate — recovery never guesses at a name it did not write.
fn parse_generation(path: &Path) -> Result<u64, CheckpointError> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or(CheckpointError::FileName)?;
    let stem = name
        .strip_suffix(&format!(".{CHECKPOINT_EXTENSION}"))
        .ok_or(CheckpointError::FileName)?;
    if stem.is_empty() || !stem.bytes().all(|b| b.is_ascii_digit()) {
        return Err(CheckpointError::FileName);
    }
    stem.parse::<u64>().map_err(|_| CheckpointError::FileName)
}

/// Candidate generations, newest first.
pub fn list_generations(dir: &Path) -> Result<Vec<(u64, PathBuf)>, StoreError> {
    let mut found = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let path = entry?.path();
        if let Ok(generation) = parse_generation(&path) {
            found.push((generation, path));
        }
    }
    found.sort_by_key(|(generation, _)| std::cmp::Reverse(*generation));
    Ok(found)
}

/// Load the newest validated generation, considering at most
/// `max_candidates` of them.
///
/// The candidate cap is what keeps this bounded. Plan §5.3 forbids an
/// unbounded normal-readiness scan; a directory that has accumulated thousands
/// of unpruned generations must not turn startup into a linear validation of
/// all of them before it gives up.
pub fn load_newest_valid(
    dir: &Path,
    root_uuid: &[u8; 16],
    shard_index: u16,
    max_candidates: usize,
) -> Result<CheckpointLoad, StoreError> {
    let generations = list_generations(dir)?;
    if generations.is_empty() {
        return Ok(CheckpointLoad::Empty);
    }

    let mut rejected = Vec::new();
    for (_, path) in generations.iter().take(max_candidates.max(1)) {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => {
                rejected.push((path.clone(), CheckpointError::Unreadable(e.to_string())));
                continue;
            }
        };
        match Checkpoint::decode(&bytes, root_uuid, shard_index) {
            Ok(checkpoint) => {
                return Ok(CheckpointLoad::Loaded {
                    checkpoint: Box::new(checkpoint),
                    path: path.clone(),
                    rejected,
                })
            }
            Err(e) => rejected.push((path.clone(), e)),
        }
    }
    Ok(CheckpointLoad::OfflineRebuildRequired { rejected })
}

/// Write a checkpoint durably under a name that never overwrites.
///
/// Ordering matches scope 3.5's shape for any new immutable artifact: write a
/// temporary, fence it, `rename_noreplace` into place, then fsync the
/// directory. A reader can never see a partially written generation under its
/// final name because the final name only ever appears after the fence.
///
/// The body goes through `sys::write_vectored_all` rather than
/// `File::write_all`, and that is not a style preference. Review found this
/// call site writing directly: checkpoint bytes and short writes were invisible
/// to `DurabilityCounters`, and — worse — the `ENOSPC` / short-write /
/// cursor-skew seam could not reach checkpoint installation at all, so no fault
/// campaign could exercise it. A funnel that covers the fence but not the bytes
/// being fenced is not a funnel.
///
/// A short write is not an error at the syscall layer; it leaves a durable
/// prefix. Completeness — not a return value — decides the outcome, so an
/// incomplete body fails the install here and the temporary is never renamed.
/// The prefix that survives on disk is a `.tmp`, which `parse_generation`
/// refuses, and it would fail its trailer digest even if it were renamed.
pub fn install(
    dir: &Path,
    checkpoint: &Checkpoint,
    counters: &DurabilityCounters,
) -> Result<PathBuf, StoreError> {
    install_at(dir, checkpoint, counters, false)
}

/// A checkpoint reduced to what it durably *claims*, with the values a crash and
/// the recovery after it are entitled to move erased.
///
/// This is a comparison aid, never a description of what may be published.
/// Three things come out, and `reconciles_with` re-imposes a rule on two of
/// them rather than letting them go:
///
/// * `created_at_micros` — when the image was built, not what it says. This one
///   really is free.
/// * The resume point, which the found image records against the journal that
///   was active before the crash.
/// * Per-receipt visibility, which recovery re-derives and extends.
///
/// Everything left is a claim about the state below the horizon: catalog, refs,
/// and every durable field of every receipt. `receipt_for_recovery` rebuilds all
/// of those from the frame's own facts, so a faithful pre-crash image and a
/// post-recovery rebuild agree on them exactly, and anything that does not agree
/// is describing something else.
pub(crate) fn durable_claims(checkpoint: &Checkpoint) -> Checkpoint {
    let mut claims = checkpoint.clone();
    claims.created_at_micros = 0;
    claims.active_journal_id = [0u8; 16];
    claims.active_journal_offset = 0;
    for receipt in claims.receipts.iter_mut() {
        receipt.first_receipt_visibility_micros = None;
        receipt.receipt_visible_until_micros = 0;
    }
    claims
}

/// Whether `candidate` may replace the finalized `existing` at their shared
/// name — the whole safety argument for overwriting a checkpoint.
///
/// `Err` carries the clause for the refusal message. Three tests, and the last
/// two exist because erasing a field from [`durable_claims`] is not the same as
/// deciding it does not matter.
///
/// 1. **Same durable claims.** Otherwise the file describes state this shard
///    cannot produce, and overwriting it would destroy the only evidence of
///    however that happened.
/// 2. **The resume point may differ only by naming a different journal.** A
///    checkpoint whose `active_journal_id` matches the surviving journal is
///    trusted for its *offset* by recovery, without a derivation of its own, so
///    a matching identity at a disagreeing offset is a claim about live state
///    that this shard did not make — it reopens as `recovered through sequence
///    N but its active journal resumes at N+1`. The ordinary strand passes
///    freely: it names the journal the crash left behind, recovery sealed that
///    journal away, and the candidate names the fresh one.
/// 3. **The replacement may not shorten retention.** Recovery may extend a
///    receipt's first-visibility and deadline and never reduce them (plan
///    invariant 7), so the candidate — built after that recovery — must be at or
///    beyond the found image on both. A `None` first-visibility is the weakest
///    value there is and is therefore always allowed on the found side; on the
///    candidate's side it means the promotion this rule exists to preserve never
///    happened.
///
/// Receipts are compared pairwise by position, which is sound only because rule
/// 1 has already established that both sides carry the same receipts in the same
/// canonical order.
pub(crate) fn reconciles_with(existing: &Checkpoint, candidate: &Checkpoint) -> Result<(), String> {
    if durable_claims(existing) != durable_claims(candidate) {
        return Err(format!(
            "describes different state than this shard would checkpoint at {}; publishing it \
             would suppress replay of frames it does not describe",
            candidate.shard_committed_sequence
        ));
    }

    if existing.active_journal_id == candidate.active_journal_id
        && existing.active_journal_offset != candidate.active_journal_offset
    {
        return Err(format!(
            "resumes the journal this shard is still writing at offset {}, which is not where \
             this shard would resume it ({}); recovery trusts that offset without deriving it",
            existing.active_journal_offset, candidate.active_journal_offset
        ));
    }

    for (found, ours) in existing.receipts.iter().zip(candidate.receipts.iter()) {
        let regressed = match (
            found.first_receipt_visibility_micros,
            ours.first_receipt_visibility_micros,
        ) {
            (Some(found_first), Some(our_first)) => our_first < found_first,
            (Some(_), None) => true,
            (None, _) => false,
        };
        if regressed || ours.receipt_visible_until_micros < found.receipt_visible_until_micros {
            return Err(format!(
                "holds receipt retention for operation {} that this shard's image would \
                 shorten; recovery may extend a receipt's visibility and never reduce it",
                found.operation_id.to_hex()
            ));
        }
    }

    Ok(())
}

/// [`install`] over a name a crash already finalized, and only over one this
/// call has just proved out.
///
/// A directory fence failure lands *after* the rename, so an interrupted
/// checkpoint leaves a whole, validating file at its published name that no
/// manifest references. Its name comes from the committed sequence, so the
/// retry cannot choose another one, and `rename_noreplace` refuses forever.
///
/// The retry cannot simply publish what it finds, either: it happens after the
/// recovery the crash forced, and recovery legitimately moves values the found
/// image still holds at their pre-crash settings — the resume point, and receipt
/// visibility, which recovery may only ever extend. Publishing the older image
/// would walk those backwards. So the shard writes its own and replaces.
///
/// **This is the one name in the store that may be overwritten**, and the proof
/// that licenses it is [`reconciles_with`], which is why the two are one
/// operation rather than two. Exposing the replacement separately would put an
/// unproved checkpoint overwrite on this module's surface, and the proof is the
/// entire safety argument: the occupant must read back as a valid checkpoint for
/// this shard, agree on every durable claim, and be no *stronger* than the image
/// replacing it. Because the two then differ only where the replacement is the
/// better of the pair, and because the rename is atomic, a manifest that names
/// this file holds a valid referent at every instant — before, during, and
/// after.
///
/// `existing` is the occupant as *this store* read it back, not as the caller
/// wishes it were; the caller is responsible for having loaded it through
/// [`load_newest_valid`] at this exact path. Frozen-seam amendment recorded as
/// contract review 2026-07-30-F; the `rename_noreplace` rule stands everywhere
/// else, including for a checkpoint name no such proof covers.
pub(crate) fn replace_reconciled(
    dir: &Path,
    existing: &Checkpoint,
    checkpoint: &Checkpoint,
    counters: &DurabilityCounters,
) -> Result<PathBuf, StoreError> {
    reconciles_with(existing, checkpoint).map_err(|reason| {
        StoreError::Corruption(format!(
            "{} already exists and {reason}; it is left untouched",
            dir.join(checkpoint.file_name()).display()
        ))
    })?;
    install_at(dir, checkpoint, counters, true)
}

fn install_at(
    dir: &Path,
    checkpoint: &Checkpoint,
    counters: &DurabilityCounters,
    replace: bool,
) -> Result<PathBuf, StoreError> {
    std::fs::create_dir_all(dir)?;
    let bytes = checkpoint.encode()?;
    let final_path = dir.join(checkpoint.file_name());
    let tmp_path = dir.join(format!("{}.tmp", checkpoint.file_name()));

    {
        // Through the no-follow funnel, not `File::options`. A checkpoint
        // installer that was unreachable from production could afford to open
        // its temporary by name; this one cannot. A symlink planted at
        // `<sequence>.checkpoint.tmp` made `install` overwrite whatever it
        // pointed at and then publish the link — the same redirection family
        // `segment.rs` closed, reopened here the moment this path acquired a
        // production caller (contract review 2026-07-30-D).
        let Some(mut file) =
            crate::sys::open_or_create_regular_truncated_nofollow(&tmp_path, counters)?
        else {
            return Err(StoreError::UnrecognizedLayout(format!(
                "{} is not a regular file; refusing to build a checkpoint through it",
                tmp_path.display()
            )));
        };
        let end = crate::sys::write_vectored_all(&mut file, &[IoSlice::new(&bytes)], counters)
            .map_err(|e| {
                StoreError::from(std::io::Error::new(
                    e.kind(),
                    format!("checkpoint body write failed: {e}"),
                ))
            })?;
        if end != bytes.len() as u64 {
            return Err(StoreError::from(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!(
                    "short write installing checkpoint: wrote {end} of {} bytes; \
                     the temporary is left behind and never renamed",
                    bytes.len()
                ),
            )));
        }
        crate::sys::fdatasync(&file, counters)?;
    }
    let renamed = if replace {
        crate::sys::rename_replace(&tmp_path, &final_path)
    } else {
        crate::sys::rename_noreplace(&tmp_path, &final_path)
    };
    renamed.map_err(|e| {
        // Leave the temporary behind for forensics rather than unlinking it
        // on a path that already surprised us.
        StoreError::from(e)
    })?;
    crate::sys::fsync_dir(dir, counters)?;
    Ok(final_path)
}

/// Unlink generations older than the newest `retain`.
///
/// `retain` is `checkpoint_retain`, which `options.rs` refuses below 2. Pruning
/// happens only after a successful install, so the store is never below its
/// retention floor at any instant a crash could observe.
pub fn prune(dir: &Path, retain: u32, counters: &DurabilityCounters) -> Result<usize, StoreError> {
    let generations = list_generations(dir)?;
    let keep = retain.max(2) as usize;
    if generations.len() <= keep {
        return Ok(0);
    }
    let mut removed = 0;
    for (_, path) in generations.iter().skip(keep) {
        crate::sys::unlink(path)?;
        removed += 1;
    }
    if removed > 0 {
        crate::sys::fsync_dir(dir, counters)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 16] = [3u8; 16];
    const SHARD: u16 = 2;

    fn ns(b: u8) -> NamespaceId {
        NamespaceId([b; 32])
    }

    fn oid(b: u8) -> ObjectId {
        ObjectId([b; 32])
    }

    fn sample() -> Checkpoint {
        let mut catalog = NamespaceCatalog::new();
        for i in 1..=3u8 {
            catalog
                .bind(NamespaceRecord {
                    namespace: ns(i),
                    genesis_authority: oid(0x10 + i),
                    current_authority: oid(0x20 + i),
                    lifecycle: NamespaceLifecycle::Active,
                    storage_mode: NamespaceStorageMode::Full,
                    repo_sequence: i as u64 * 7,
                    previous_event_digest: oid(0x30 + i),
                })
                .expect("bind");
        }
        Checkpoint {
            root_uuid: ROOT,
            shard_index: SHARD,
            shard_committed_sequence: 4242,
            active_journal_id: [9u8; 16],
            active_journal_offset: 512 + 224 * 3,
            created_at_micros: 1_700_000_000_000_000,
            catalog,
            refs: vec![
                RefRecord {
                    namespace: ns(1),
                    ref_kind: 1,
                    name: b"refs/heads/main".to_vec(),
                    target: oid(0x40),
                },
                RefRecord {
                    namespace: ns(2),
                    ref_kind: 2,
                    name: Vec::new(),
                    target: oid(0x41),
                },
            ],
            receipts: vec![
                ReceiptRecord {
                    namespace: ns(1),
                    operation_id: OperationId([1u8; 16]),
                    operation_digest: oid(0x50),
                    repo_sequence: 7,
                    shard_sequence: 4241,
                    current_authority: oid(0x21),
                    refs: vec![
                        AppliedRef {
                            target: RefTarget::Branch("refs/branches/main".into()),
                            old: Some(oid(0x60)),
                            new: Some(oid(0x61)),
                            force: false,
                        },
                        AppliedRef {
                            target: RefTarget::Release("refs/releases/old".into()),
                            old: Some(oid(0x62)),
                            new: None,
                            force: true,
                        },
                    ],
                    objects_new: 3,
                    retry_until_micros: 1_700_000_900_000_000,
                    first_receipt_visibility_micros: Some(1_700_000_000_500_000),
                    receipt_visible_until_micros: 1_700_000_900_000_000,
                },
                ReceiptRecord {
                    namespace: ns(2),
                    operation_id: OperationId([2u8; 16]),
                    operation_digest: oid(0x51),
                    repo_sequence: 14,
                    shard_sequence: 4242,
                    current_authority: oid(0x22),
                    refs: Vec::new(),
                    objects_new: 0,
                    retry_until_micros: 1_700_000_900_000_000,
                    first_receipt_visibility_micros: None,
                    receipt_visible_until_micros: 1_700_000_900_000_000,
                },
            ],
        }
    }

    #[test]
    fn a_checkpoint_round_trips_every_field() {
        let checkpoint = sample();
        let bytes = checkpoint.encode().expect("encode");
        let decoded = Checkpoint::decode(&bytes, &ROOT, SHARD).expect("decode");
        assert_eq!(decoded, checkpoint);
        assert_eq!(
            decoded.receipts[0].refs, checkpoint.receipts[0].refs,
            "old/new values, deletion, force, target kind, and order are receipt data"
        );
    }

    #[test]
    fn a_ref_record_round_trips_through_its_typed_target() {
        for target in [
            RefTarget::Branch("refs/heads/main".into()),
            RefTarget::Release("refs/releases/v1".into()),
        ] {
            let record = RefRecord::from_target(ns(1), &target, oid(0x40));
            assert_eq!(record.target().expect("a record we built decodes"), target);
        }
    }

    #[test]
    fn an_unknown_ref_kind_is_refused_by_value_and_never_defaulted() {
        let mut record = RefRecord::from_target(
            ns(1),
            &RefTarget::Branch("refs/heads/main".into()),
            oid(0x40),
        );
        for kind in [0u8, 3, 255] {
            record.ref_kind = kind;
            assert_eq!(
                record.target().unwrap_err(),
                CheckpointError::RefKind(kind),
                "an unreadable ref must not resolve as a branch: the next checkpoint would \
                 write the guess back as though it were recovered state"
            );
        }
    }

    #[test]
    fn a_legacy_checkpoint_with_receipts_requires_offline_rebuild() {
        let legacy = sample()
            .encode_with_receipt_refs(false)
            .expect("legacy fixture");
        assert_eq!(
            Checkpoint::decode(&legacy, &ROOT, SHARD).unwrap_err(),
            CheckpointError::ReceiptRefsUnavailable,
            "inventing an empty applied-ref result would turn a committed receipt into a lie"
        );
    }

    #[test]
    fn a_legacy_checkpoint_without_receipts_remains_readable() {
        let mut checkpoint = sample();
        checkpoint.receipts.clear();
        let legacy = checkpoint
            .encode_with_receipt_refs(false)
            .expect("legacy fixture");
        assert_eq!(
            Checkpoint::decode(&legacy, &ROOT, SHARD).expect("no receipt information is missing"),
            checkpoint
        );
    }

    #[test]
    fn a_directory_of_legacy_receipt_checkpoints_enters_offline_rebuild() {
        let dir = tempfile::tempdir().expect("tempdir");
        let checkpoint = sample();
        let legacy = checkpoint
            .encode_with_receipt_refs(false)
            .expect("legacy fixture");
        std::fs::write(dir.path().join(checkpoint.file_name()), legacy).expect("write fixture");
        match load_newest_valid(dir.path(), &ROOT, SHARD, 8).expect("load") {
            CheckpointLoad::OfflineRebuildRequired { rejected } => {
                assert_eq!(rejected.len(), 1);
                assert_eq!(rejected[0].1, CheckpointError::ReceiptRefsUnavailable);
            }
            other => panic!("missing receipt data must require offline rebuild, got {other:?}"),
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        let checkpoint = sample();
        assert_eq!(
            checkpoint.encode().expect("a"),
            checkpoint.encode().expect("b"),
            "a non-deterministic encoding cannot be checksum-compared across generations"
        );
    }

    #[test]
    fn unset_first_visibility_survives_the_round_trip_as_unset() {
        // The whole of recovery step 10 depends on being able to tell "not yet
        // durably captured" from "captured". A sentinel would lose that.
        let checkpoint = sample();
        let bytes = checkpoint.encode().expect("encode");
        let decoded = Checkpoint::decode(&bytes, &ROOT, SHARD).expect("decode");
        assert_eq!(
            decoded.receipts[0].first_receipt_visibility_micros,
            Some(1_700_000_000_500_000)
        );
        assert_eq!(decoded.receipts[1].first_receipt_visibility_micros, None);
    }

    #[test]
    fn each_corruption_is_rejected_by_its_own_condition() {
        let good = sample().encode().expect("encode");

        let mut magic = good.clone();
        magic[0] ^= 0xFF;
        assert_eq!(
            Checkpoint::decode(&magic, &ROOT, SHARD).unwrap_err(),
            CheckpointError::Magic
        );

        let mut version = good.clone();
        version[8] = 7;
        assert_eq!(
            Checkpoint::decode(&version, &ROOT, SHARD).unwrap_err(),
            CheckpointError::StorageVersion(7)
        );

        let mut flags = good.clone();
        flags[12] |= 2;
        assert_eq!(
            Checkpoint::decode(&flags, &ROOT, SHARD).unwrap_err(),
            CheckpointError::Flags
        );

        let mut header = good.clone();
        header[40] ^= 0x01;
        assert_eq!(
            Checkpoint::decode(&header, &ROOT, SHARD).unwrap_err(),
            CheckpointError::HeaderDigest
        );

        let mut body = good.clone();
        let at = CHECKPOINT_HEADER_LEN + 8;
        body[at] ^= 0x01;
        assert_eq!(
            Checkpoint::decode(&body, &ROOT, SHARD).unwrap_err(),
            CheckpointError::BodyDigest
        );

        let mut trailer = good.clone();
        let at = good.len() - CHECKPOINT_TRAILER_LEN;
        trailer[at] ^= 0xFF;
        assert_eq!(
            Checkpoint::decode(&trailer, &ROOT, SHARD).unwrap_err(),
            CheckpointError::Trailer
        );

        assert_eq!(
            Checkpoint::decode(&good[..CHECKPOINT_HEADER_LEN], &ROOT, SHARD).unwrap_err(),
            CheckpointError::Truncated
        );
    }

    #[test]
    fn a_checkpoint_from_another_store_root_is_refused() {
        let good = sample().encode().expect("encode");
        assert_eq!(
            Checkpoint::decode(&good, &[8u8; 16], SHARD).unwrap_err(),
            CheckpointError::RootUuid
        );
    }

    #[test]
    fn a_checkpoint_from_another_shard_is_refused() {
        let good = sample().encode().expect("encode");
        assert_eq!(
            Checkpoint::decode(&good, &ROOT, SHARD + 1).unwrap_err(),
            CheckpointError::ShardIndex {
                expected: SHARD + 1,
                found: SHARD,
            }
        );
    }

    #[test]
    fn truncation_at_every_offset_is_rejected_without_panic() {
        let good = sample().encode().expect("encode");
        for cut in 0..good.len() {
            assert!(
                Checkpoint::decode(&good[..cut], &ROOT, SHARD).is_err(),
                "truncation at {cut} must be rejected"
            );
        }
    }

    #[test]
    fn single_bit_mutation_never_validates() {
        let good = sample().encode().expect("encode");
        for byte in (0..good.len()).step_by(7) {
            for bit in [0u8, 3, 7] {
                let mut mutated = good.clone();
                mutated[byte] ^= 1 << bit;
                assert!(
                    Checkpoint::decode(&mutated, &ROOT, SHARD).is_err(),
                    "flipping bit {bit} of byte {byte} must not validate"
                );
            }
        }
    }

    // -- installation and selection ----------------------------------------

    fn counters() -> DurabilityCounters {
        DurabilityCounters::default()
    }

    #[test]
    fn install_is_durable_and_never_overwrites_a_generation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = counters();
        let checkpoint = sample();
        let path = install(dir.path(), &checkpoint, &c).expect("install");
        assert_eq!(path.file_name().expect("name"), "4242.checkpoint");
        assert!(c.snapshot().fdatasync >= 1, "the file must be fenced");
        assert!(c.snapshot().fsync_dir >= 1, "the directory must be synced");

        let err = install(dir.path(), &checkpoint, &c)
            .expect_err("a second install of the same generation must be refused");
        match err {
            StoreError::Io(e) => assert_eq!(e.raw_os_error(), Some(17), "EEXIST"),
            other => panic!("expected an EEXIST io error, got {other:?}"),
        }
    }

    #[test]
    fn an_empty_directory_is_empty_not_offline_rebuild() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            load_newest_valid(dir.path(), &ROOT, SHARD, 8).expect("load"),
            CheckpointLoad::Empty,
            "a fresh root has no checkpoints and is healthy; it must not be \
             confused with a root whose generations are all corrupt"
        );
    }

    #[test]
    fn the_newest_valid_generation_wins() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = counters();
        for sequence in [10u64, 20, 30] {
            let mut checkpoint = sample();
            checkpoint.shard_committed_sequence = sequence;
            install(dir.path(), &checkpoint, &c).expect("install");
        }
        match load_newest_valid(dir.path(), &ROOT, SHARD, 8).expect("load") {
            CheckpointLoad::Loaded {
                checkpoint,
                rejected,
                ..
            } => {
                assert_eq!(checkpoint.shard_committed_sequence, 30);
                assert!(rejected.is_empty());
            }
            other => panic!("expected Loaded, got {other:?}"),
        }
    }

    #[test]
    fn one_corrupt_generation_falls_back_to_the_next() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = counters();
        for sequence in [10u64, 20] {
            let mut checkpoint = sample();
            checkpoint.shard_committed_sequence = sequence;
            install(dir.path(), &checkpoint, &c).expect("install");
        }
        let newest = dir.path().join("20.checkpoint");
        let mut bytes = std::fs::read(&newest).expect("read");
        bytes[CHECKPOINT_HEADER_LEN + 4] ^= 0xFF;
        std::fs::write(&newest, &bytes).expect("write");

        match load_newest_valid(dir.path(), &ROOT, SHARD, 8).expect("load") {
            CheckpointLoad::Loaded {
                checkpoint,
                rejected,
                ..
            } => {
                assert_eq!(checkpoint.shard_committed_sequence, 10);
                assert_eq!(rejected.len(), 1);
                assert_eq!(rejected[0].1, CheckpointError::BodyDigest);
            }
            other => panic!("expected a fallback to generation 10, got {other:?}"),
        }
    }

    #[test]
    fn all_generations_corrupt_enters_offline_rebuild_rather_than_replaying_from_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = counters();
        for sequence in [10u64, 20] {
            let mut checkpoint = sample();
            checkpoint.shard_committed_sequence = sequence;
            install(dir.path(), &checkpoint, &c).expect("install");
        }
        for sequence in [10u64, 20] {
            let path = dir.path().join(format!("{sequence}.checkpoint"));
            let mut bytes = std::fs::read(&path).expect("read");
            bytes[CHECKPOINT_HEADER_LEN + 4] ^= 0xFF;
            std::fs::write(&path, &bytes).expect("write");
        }

        match load_newest_valid(dir.path(), &ROOT, SHARD, 8).expect("load") {
            CheckpointLoad::OfflineRebuildRequired { rejected } => {
                assert_eq!(rejected.len(), 2);
                for (_, e) in rejected {
                    assert_eq!(e, CheckpointError::BodyDigest);
                }
            }
            other => panic!("expected OfflineRebuildRequired, got {other:?}"),
        }
    }

    #[test]
    fn a_foreign_root_generation_is_rejected_with_its_own_variant() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = counters();
        let mut foreign = sample();
        foreign.root_uuid = [0xEE; 16];
        install(dir.path(), &foreign, &c).expect("install");

        match load_newest_valid(dir.path(), &ROOT, SHARD, 8).expect("load") {
            CheckpointLoad::OfflineRebuildRequired { rejected } => {
                assert_eq!(rejected[0].1, CheckpointError::RootUuid);
            }
            other => panic!("expected OfflineRebuildRequired, got {other:?}"),
        }
    }

    #[test]
    fn the_candidate_scan_is_bounded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = counters();
        // Twenty corrupt newer generations above one good one. With a
        // candidate cap of four, the good generation must NOT be reached:
        // plan §5.3 asks for a bounded attempt, not a linear hunt.
        let mut good = sample();
        good.shard_committed_sequence = 1;
        install(dir.path(), &good, &c).expect("install");
        for sequence in 2..=21u64 {
            let mut checkpoint = sample();
            checkpoint.shard_committed_sequence = sequence;
            let path = install(dir.path(), &checkpoint, &c).expect("install");
            let mut bytes = std::fs::read(&path).expect("read");
            bytes[CHECKPOINT_HEADER_LEN + 4] ^= 0xFF;
            std::fs::write(&path, &bytes).expect("write");
        }

        match load_newest_valid(dir.path(), &ROOT, SHARD, 4).expect("load") {
            CheckpointLoad::OfflineRebuildRequired { rejected } => {
                assert_eq!(rejected.len(), 4, "exactly the cap must be attempted");
            }
            other => panic!("expected a bounded give-up, got {other:?}"),
        }

        match load_newest_valid(dir.path(), &ROOT, SHARD, 64).expect("load") {
            CheckpointLoad::Loaded { checkpoint, .. } => {
                assert_eq!(checkpoint.shard_committed_sequence, 1)
            }
            other => panic!("with a larger cap the good generation must be found, got {other:?}"),
        }
    }

    #[test]
    fn pruning_never_drops_below_the_retention_floor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = counters();
        for sequence in 1..=6u64 {
            let mut checkpoint = sample();
            checkpoint.shard_committed_sequence = sequence;
            install(dir.path(), &checkpoint, &c).expect("install");
        }
        let removed = prune(dir.path(), 2, &c).expect("prune");
        assert_eq!(removed, 4);
        let remaining = list_generations(dir.path()).expect("list");
        assert_eq!(
            remaining.iter().map(|(g, _)| *g).collect::<Vec<_>>(),
            vec![6, 5]
        );

        // A retain value below the floor is clamped up, not honoured: the
        // whole point of two generations is that one corrupt one is survivable.
        let removed = prune(dir.path(), 0, &c).expect("prune");
        assert_eq!(removed, 0);
        assert_eq!(list_generations(dir.path()).expect("list").len(), 2);
    }

    #[test]
    fn unrelated_files_are_not_candidates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let c = counters();
        install(dir.path(), &sample(), &c).expect("install");
        std::fs::write(dir.path().join("notes.txt"), b"hello").expect("write");
        std::fs::write(dir.path().join("abc.checkpoint"), b"garbage").expect("write");
        std::fs::write(dir.path().join("12.checkpoint.tmp"), b"garbage").expect("write");

        let generations = list_generations(dir.path()).expect("list");
        assert_eq!(generations.len(), 1);
        assert_eq!(generations[0].0, 4242);
    }

    #[test]
    fn a_declared_count_beyond_the_ceiling_is_refused_before_any_allocation() {
        let mut bytes = sample().encode().expect("encode");
        // Overwrite namespace_count with a value past the ceiling and reseal
        // both digests, so the ceiling check is what fires.
        let at = CHECKPOINT_HEADER_LEN;
        bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let end = bytes.len() - CHECKPOINT_TRAILER_LEN;
        let digest = crate::format::digest(CHECKPOINT_DIGEST_DOMAIN, &bytes[..end]);
        bytes[end + 16..end + 48].copy_from_slice(&digest.0);

        assert_eq!(
            Checkpoint::decode(&bytes, &ROOT, SHARD).unwrap_err(),
            CheckpointError::CountCeiling("namespaces")
        );
    }
}
