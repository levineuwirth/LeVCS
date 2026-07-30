//! `(namespace, ObjectId) -> location` index: bounded in-memory delta,
//! immutable memory-mapped sorted runs with Bloom filters, and the namespace
//! catalog.
//!
//! **Owned by A2 RecoveryIndex** (scope 2.1, 4-A2).
//!
//! Namespace is part of the key. That is what makes isolation a property of
//! the lookup rather than of a check that could be forgotten: identical bytes
//! in private repository A are simply not present under repository B.
//!
//! # Why the filter is written here rather than taken from a crate
//!
//! The filter lives inside a frozen on-disk format (scope 2.4). A third-party
//! filter would put a dependency's serialization, hash choice, and parameter
//! derivation inside bytes recovery must read back forever. It is implemented
//! here, documented, seeded, and versioned, so a change to it is a storage
//! version change rather than a `Cargo.lock` change.
//!
//! # Entry cost (plan §13 stop condition, scope 3.6/8.2)
//!
//! `namespace` is factored out into a per-run *section*, so an entry on disk is
//! 32 bytes of `ObjectId` plus a 15-byte packed location:
//!
//! | field | bytes | bound enforced at build |
//! |---|---|---|
//! | `segment_generation` delta from the section base | 2 | `<= 2^16 - 1` |
//! | `frame_offset` | 5 | `< 2^40` (1 TiB per segment file) |
//! | `frame_len` | 4 | `< 2^32` |
//! | `object_type` | 1 | — |
//! | `shard_sequence` delta from the section base | 3 | `< 2^24` |
//!
//! 47 bytes per entry, matching the scope 8.2 budget exactly. Every one of the
//! widths is a *refusal* at build time, never a truncation:
//! [`IndexRunBuilder::build`] returns `LimitExceeded` rather than writing a
//! narrowed value, because a silently narrowed offset is an index that points
//! at the wrong bytes and reports success.
//!
//! The in-memory delta is deliberately *not* 47 bytes per entry and this
//! module does not pretend otherwise — see [`IndexDelta::memory_bytes`] and the
//! figure printed by the `index_cost_is_reported` test.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use levcs_core::ObjectId;

use crate::types::{NamespaceId, StoreError};

// ---------------------------------------------------------------------------
// Frozen on-disk constants for an index run
// ---------------------------------------------------------------------------

/// `format.rs` defines no index-run magic or domain: its doc header enumerates
/// frames, journal headers, segment footers, manifests, and checkpoints. The
/// index run is A2-owned in full, so its constants live here and are frozen by
/// the same Wave A gate.
pub const INDEX_RUN_MAGIC: [u8; 8] = *b"LVCSIDX\0";
pub const INDEX_RUN_TRAILER_MAGIC: [u8; 8] = *b"LVCSIDE\0";

pub const INDEX_RUN_DIGEST_DOMAIN: &[u8] = b"levcs-index-run/v1\0";
pub const INDEX_BLOOM_DOMAIN: &[u8] = b"levcs-index-bloom/v1\0";

/// 112 bytes of named fields, zero padding to 128, then a 32-byte header
/// digest. Every byte that is not a named field must be zero, for the same
/// reason scope 3.3 pins the frame's padding: unconstrained reserved space is
/// a covert region the digest authenticates but nothing else bounds.
pub const INDEX_RUN_HEADER_LEN: usize = 160;
const INDEX_RUN_HEADER_FIELDS_LEN: usize = 112;
pub const INDEX_RUN_TRAILER_LEN: usize = 48;
pub const INDEX_SECTION_LEN: usize = 64;
pub const INDEX_ENTRY_LEN: usize = 47;

/// Versioned so a filter parameter change is a format change. A reader takes
/// the version out of the header and refuses a run it cannot interpret rather
/// than probing a filter it does not understand.
pub const INDEX_BLOOM_VERSION: u16 = 1;

pub const INDEX_STORAGE_VERSION: u16 = 1;

const MAX_SEGMENT_GENERATION_DELTA: u64 = u16::MAX as u64;
const MAX_FRAME_OFFSET: u64 = 1 << 40;
const MAX_SHARD_SEQUENCE_DELTA: u64 = 1 << 24;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why an index run is not usable.
///
/// One variant per rejected condition. The scope 5 charter forbids a catch-all
/// arm in an expectation test, which is only possible if the taxonomy is fine
/// enough to assert against.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum IndexError {
    #[error("index run is shorter than its fixed header and trailer")]
    Truncated,
    #[error("index run magic does not match")]
    Magic,
    #[error("index run storage version {0} is not readable")]
    StorageVersion(u16),
    #[error("index run bloom filter version {0} is not readable")]
    BloomVersion(u16),
    #[error("index run flags and reserved fields must be zero")]
    Flags,
    #[error("index run header digest does not recompute")]
    HeaderDigest,
    #[error("index run trailer magic or repeated total_len does not match")]
    Trailer,
    #[error("index run body digest does not recompute")]
    BodyDigest,
    #[error("index run root uuid does not match this store root")]
    RootUuid,
    #[error("index run internal offsets are inconsistent")]
    Layout,
    #[error("index run sections are not strictly ascending by namespace")]
    SectionOrder,
    #[error("index run entries are not strictly ascending within a section")]
    EntryOrder,
}

impl From<IndexError> for StoreError {
    fn from(e: IndexError) -> Self {
        StoreError::Corruption(format!("index run: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Keys and locations
// ---------------------------------------------------------------------------

/// The index key. Namespace first, so the sort order groups a namespace
/// contiguously and a run section is a contiguous slice.
///
/// There is no constructor taking only an `ObjectId`. A lookup that forgot its
/// namespace does not compile, which is what plan §4's resource invariant —
/// "namespace membership, not global object existence, controls reads" —
/// requires of a key type.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IndexKey {
    pub namespace: NamespaceId,
    pub object: ObjectId,
}

impl IndexKey {
    pub const fn new(namespace: NamespaceId, object: ObjectId) -> Self {
        Self { namespace, object }
    }
}

/// Where the certified storage record carrying an object lives.
///
/// For inline transactions the record is a complete journal frame. For an
/// adopted projection it is a canonical, digest-bound staged chunk retained
/// by the same committed generation. In both cases the location names the
/// whole certified record, never the object bytes inside it: a reader
/// validates the frame or chunk first and only then extracts the object.
/// Pointing straight at object bytes would let a reader return bytes from a
/// record it never proved complete.
///
/// The physical field names remain `frame_offset`/`frame_len` in storage
/// version 1. Source kind is resolved from the generation pin in the captured
/// `CommittedRoot`, so the packed index bytes do not need a new discriminant.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IndexLocation {
    pub segment_generation: u64,
    pub frame_offset: u64,
    pub frame_len: u32,
    pub object_type: u8,
    pub shard_sequence: u64,
}

// ---------------------------------------------------------------------------
// Namespace catalog
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NamespaceLifecycle {
    Active,
    ReadOnly,
    Deleted,
}

impl NamespaceLifecycle {
    pub const fn code(self) -> u8 {
        match self {
            NamespaceLifecycle::Active => 0,
            NamespaceLifecycle::ReadOnly => 1,
            NamespaceLifecycle::Deleted => 2,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(NamespaceLifecycle::Active),
            1 => Some(NamespaceLifecycle::ReadOnly),
            2 => Some(NamespaceLifecycle::Deleted),
            _ => None,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NamespaceStorageMode {
    Full,
    Reduced,
}

impl NamespaceStorageMode {
    pub const fn code(self) -> u8 {
        match self {
            NamespaceStorageMode::Full => 0,
            NamespaceStorageMode::Reduced => 1,
        }
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(NamespaceStorageMode::Full),
            1 => Some(NamespaceStorageMode::Reduced),
            _ => None,
        }
    }
}

/// One namespace's permanently bound identity plus its mutable lifecycle.
///
/// `genesis_authority` is bound at repository initialization and never changes
/// (plan §4 identity invariant 2); the catalog refuses to rebind it.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct NamespaceRecord {
    pub namespace: NamespaceId,
    pub genesis_authority: ObjectId,
    pub current_authority: ObjectId,
    pub lifecycle: NamespaceLifecycle,
    pub storage_mode: NamespaceStorageMode,
    pub repo_sequence: u64,
    pub previous_event_digest: ObjectId,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NamespaceCatalog {
    entries: BTreeMap<NamespaceId, NamespaceRecord>,
}

impl NamespaceCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, namespace: &NamespaceId) -> Option<&NamespaceRecord> {
        self.entries.get(namespace)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&NamespaceId, &NamespaceRecord)> {
        self.entries.iter()
    }

    /// Bind a repository for the first time. Refuses a second binding of the
    /// same namespace: plan §4 makes `repo_id`/genesis binding permanent, and
    /// silently rebinding during recovery would let a replayed create frame
    /// move a repository's genesis.
    pub fn bind(&mut self, record: NamespaceRecord) -> Result<(), StoreError> {
        if let Some(existing) = self.entries.get(&record.namespace) {
            return Err(StoreError::Conflict(format!(
                "namespace {} is already bound to genesis {}; refusing to rebind to {}",
                record.namespace.to_hex(),
                hex::encode(existing.genesis_authority.0),
                hex::encode(record.genesis_authority.0),
            )));
        }
        self.entries.insert(record.namespace, record);
        Ok(())
    }

    /// Advance the mutable half of a record. The genesis is not a parameter,
    /// so no call site can move it.
    pub fn advance(
        &mut self,
        namespace: &NamespaceId,
        current_authority: ObjectId,
        repo_sequence: u64,
        previous_event_digest: ObjectId,
    ) -> Result<(), StoreError> {
        let record = self.entries.get_mut(namespace).ok_or_else(|| {
            StoreError::Corruption(format!(
                "namespace {} advanced before it was bound",
                namespace.to_hex()
            ))
        })?;
        record.current_authority = current_authority;
        record.repo_sequence = repo_sequence;
        record.previous_event_digest = previous_event_digest;
        Ok(())
    }

    pub fn set_lifecycle(
        &mut self,
        namespace: &NamespaceId,
        lifecycle: NamespaceLifecycle,
    ) -> Result<(), StoreError> {
        let record = self.entries.get_mut(namespace).ok_or_else(|| {
            StoreError::Corruption(format!("namespace {} is not bound", namespace.to_hex()))
        })?;
        record.lifecycle = lifecycle;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Bloom filter — versioned, seeded, in-crate
// ---------------------------------------------------------------------------

/// Filter parameters, stored in the run header so a reader never derives them
/// from anything it cannot see.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BloomParams {
    pub version: u16,
    pub hashes: u16,
    pub seed: u64,
    pub bits: u64,
}

impl BloomParams {
    /// ~10 bits per entry with 7 hashes: about 0.8% false positives, the
    /// classic near-optimum at that density. A zero-entry run still gets a
    /// byte of filter so the layout has no special case.
    pub fn for_entries(entry_count: u64, seed: u64) -> Self {
        let bits = (entry_count.max(1) * 10).next_multiple_of(8);
        Self {
            version: INDEX_BLOOM_VERSION,
            hashes: 7,
            seed,
            bits,
        }
    }

    pub const fn byte_len(&self) -> u64 {
        self.bits.div_ceil(8)
    }
}

/// The two independent 64-bit hashes the double-hashing scheme needs.
///
/// Domain-separated and seeded, over the *whole* key including the namespace.
/// Hashing only the `ObjectId` would make one namespace's filter answer for
/// another's, which is exactly the isolation this module exists to keep.
fn bloom_hashes(params: &BloomParams, key: &IndexKey) -> (u64, u64) {
    let mut hasher = blake3::Hasher::new();
    hasher.update(INDEX_BLOOM_DOMAIN);
    hasher.update(&params.seed.to_le_bytes());
    hasher.update(&key.namespace.0);
    hasher.update(&key.object.0);
    let out = *hasher.finalize().as_bytes();
    let h1 = u64::from_le_bytes(out[0..8].try_into().expect("8 bytes"));
    // `| 1` keeps the stride odd, so with any bit count the k probes never
    // collapse onto a single position.
    let h2 = u64::from_le_bytes(out[8..16].try_into().expect("8 bytes")) | 1;
    (h1, h2)
}

fn bloom_insert(bitmap: &mut [u8], params: &BloomParams, key: &IndexKey) {
    let (h1, h2) = bloom_hashes(params, key);
    let bits = params.bits.max(1);
    for i in 0..params.hashes as u64 {
        let pos = h1.wrapping_add(i.wrapping_mul(h2)) % bits;
        bitmap[(pos / 8) as usize] |= 1 << (pos % 8);
    }
}

fn bloom_may_contain(bitmap: &[u8], params: &BloomParams, key: &IndexKey) -> bool {
    let (h1, h2) = bloom_hashes(params, key);
    let bits = params.bits.max(1);
    for i in 0..params.hashes as u64 {
        let pos = h1.wrapping_add(i.wrapping_mul(h2)) % bits;
        if bitmap[(pos / 8) as usize] & (1 << (pos % 8)) == 0 {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// In-memory delta
// ---------------------------------------------------------------------------

/// What the caller must do about the delta's occupancy.
///
/// Plan §5.3: admission backpressures *before* a bound is exceeded, and the
/// shard synchronously seals and checkpoints when necessary. Those are two
/// different actions, and this enum keeps them distinguishable — collapsing
/// them into a bool would make the soft watermark unobservable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeltaPressure {
    Ok,
    /// Above the soft watermark: admit, but backpressure new work.
    Backpressure,
    /// At or above a hard ceiling: seal and checkpoint synchronously before
    /// admitting more.
    SealRequired,
}

/// The encoded cost of `entries` entries spread over `namespaces` sections.
///
/// [`IndexDelta::encoded_bytes`] is this function over its own occupancy. Split
/// out for the same reason as [`delta_pressure`]: the shard writer has to ask
/// what a delta it has not built yet *would* cost — the one recovery will
/// rebuild, including a transaction not yet admitted — and multiplying by
/// `INDEX_ENTRY_LEN` at that call site would put the encoding's shape in a file
/// that has no business knowing it.
///
/// Granted to B1 as contract review 2026-07-29-D, amendment 2 of 2.
pub fn encoded_bytes_for(entries: u64, namespaces: u64) -> u64 {
    entries * INDEX_ENTRY_LEN as u64 + namespaces * INDEX_SECTION_LEN as u64
}

/// The rule of plan §5.3, over an occupancy and the ceilings it is measured
/// against.
///
/// A free function because the shard writer has to ask the same question about
/// an accumulation that is *not* one `IndexDelta`: its unsealed backlog is
/// several delta layers in the committed root, and it decides whether to seal
/// from their total. Restating `>= max_entries || >= max_bytes` at that call
/// site would be two implementations of one watermark, and the one in
/// `engine.rs` would be the one nobody thinks to change.
/// [`IndexDelta::pressure`] is this function over its own fields.
///
/// Granted to B1 as contract review 2026-07-29-C, amendment 2 of 2. Read-only
/// and introduces no new rule.
pub fn delta_pressure(
    entry_count: u64,
    encoded_bytes: u64,
    max_entries: u64,
    max_bytes: u64,
) -> DeltaPressure {
    const SOFT_WATERMARK_NUMERATOR: u64 = 3;
    const SOFT_WATERMARK_DENOMINATOR: u64 = 4;
    if entry_count >= max_entries || encoded_bytes >= max_bytes {
        return DeltaPressure::SealRequired;
    }
    let soft_entries = max_entries * SOFT_WATERMARK_NUMERATOR / SOFT_WATERMARK_DENOMINATOR;
    let soft_bytes = max_bytes * SOFT_WATERMARK_NUMERATOR / SOFT_WATERMARK_DENOMINATOR;
    if entry_count >= soft_entries || encoded_bytes >= soft_bytes {
        return DeltaPressure::Backpressure;
    }
    DeltaPressure::Ok
}

/// Namespace-partitioned so the namespace is stored once per namespace rather
/// than once per entry, mirroring the run's section layout.
#[derive(Clone, Debug)]
pub struct IndexDelta {
    by_namespace: BTreeMap<NamespaceId, BTreeMap<ObjectId, IndexLocation>>,
    entry_count: u64,
    max_entries: u64,
    max_bytes: u64,
    soft_watermark_numerator: u64,
    soft_watermark_denominator: u64,
}

impl IndexDelta {
    pub fn new(max_entries: u64, max_bytes: u64) -> Self {
        Self {
            by_namespace: BTreeMap::new(),
            entry_count: 0,
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            soft_watermark_numerator: 3,
            soft_watermark_denominator: 4,
        }
    }

    pub fn from_options(options: &crate::options::StoreOptions) -> Self {
        Self::new(
            options.max_active_index_entries,
            options.max_active_index_bytes,
        )
    }

    pub fn len(&self) -> u64 {
        self.entry_count
    }

    pub fn is_empty(&self) -> bool {
        self.entry_count == 0
    }

    pub fn namespace_count(&self) -> usize {
        self.by_namespace.len()
    }

    /// On-disk cost of the current contents, which is what the byte ceiling is
    /// expressed in and what scope 8.2 budgets.
    pub fn encoded_bytes(&self) -> u64 {
        encoded_bytes_for(self.entry_count, self.by_namespace.len() as u64)
    }

    /// A deliberately honest estimate of *resident* cost, which is larger than
    /// [`Self::encoded_bytes`] and is the figure plan §13's stop condition
    /// actually cares about at sustained rates. `BTreeMap` nodes hold up to 11
    /// entries and are not full; 11/16 is the usual steady-state occupancy for
    /// random insertion order.
    pub fn memory_bytes(&self) -> u64 {
        const KEY_VALUE_BYTES: u64 =
            (std::mem::size_of::<ObjectId>() + std::mem::size_of::<IndexLocation>()) as u64;
        let node_overhead = KEY_VALUE_BYTES * 16 / 11 - KEY_VALUE_BYTES;
        self.entry_count * (KEY_VALUE_BYTES + node_overhead) + self.by_namespace.len() as u64 * 128
    }

    pub fn pressure(&self) -> DeltaPressure {
        debug_assert_eq!(
            (
                self.soft_watermark_numerator,
                self.soft_watermark_denominator
            ),
            (3, 4),
            "the watermark now lives in `delta_pressure`; a per-delta value has no effect"
        );
        delta_pressure(
            self.entry_count,
            self.encoded_bytes(),
            self.max_entries,
            self.max_bytes,
        )
    }

    /// Insert, refusing rather than growing past a hard ceiling.
    ///
    /// Re-inserting an existing key is idempotent when the location is
    /// identical and a `Conflict` otherwise: recovery replays frames, and a
    /// replay that changed an object's location would mean two frames claim
    /// the same content address in the same namespace at different places.
    pub fn insert(&mut self, key: IndexKey, location: IndexLocation) -> Result<(), StoreError> {
        if let Some(existing) = self
            .by_namespace
            .get(&key.namespace)
            .and_then(|m| m.get(&key.object))
        {
            if *existing == location {
                return Ok(());
            }
            return Err(StoreError::Conflict(format!(
                "object {} in namespace {} is already indexed at \
                 (generation {}, offset {}) and cannot move to (generation {}, offset {})",
                hex::encode(key.object.0),
                key.namespace.to_hex(),
                existing.segment_generation,
                existing.frame_offset,
                location.segment_generation,
                location.frame_offset,
            )));
        }

        if self.entry_count >= self.max_entries {
            return Err(StoreError::LimitExceeded {
                limit: "max_active_index_entries",
                observed: self.entry_count + 1,
                allowed: self.max_entries,
            });
        }
        let new_section = !self.by_namespace.contains_key(&key.namespace);
        let projected = self.encoded_bytes()
            + INDEX_ENTRY_LEN as u64
            + if new_section {
                INDEX_SECTION_LEN as u64
            } else {
                0
            };
        if projected > self.max_bytes {
            return Err(StoreError::LimitExceeded {
                limit: "max_active_index_bytes",
                observed: projected,
                allowed: self.max_bytes,
            });
        }

        self.by_namespace
            .entry(key.namespace)
            .or_default()
            .insert(key.object, location);
        self.entry_count += 1;
        Ok(())
    }

    /// The whole point of the module: a lookup that names a namespace can only
    /// ever see that namespace's map.
    pub fn get(&self, key: &IndexKey) -> Option<IndexLocation> {
        self.by_namespace
            .get(&key.namespace)
            .and_then(|m| m.get(&key.object))
            .copied()
    }

    pub fn iter(&self) -> impl Iterator<Item = (IndexKey, IndexLocation)> + '_ {
        self.by_namespace.iter().flat_map(|(ns, objects)| {
            objects
                .iter()
                .map(move |(object, loc)| (IndexKey::new(*ns, *object), *loc))
        })
    }

    pub fn clear(&mut self) {
        self.by_namespace.clear();
        self.entry_count = 0;
    }
}

// ---------------------------------------------------------------------------
// Immutable sorted run
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct SectionHeader {
    namespace: NamespaceId,
    base_segment_generation: u64,
    base_shard_sequence: u64,
    first_entry: u64,
    entry_count: u64,
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn get_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(bytes[at..at + 2].try_into().expect("2 bytes"))
}

fn get_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"))
}

fn get_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"))
}

fn get_u40(bytes: &[u8], at: usize) -> u64 {
    let mut wide = [0u8; 8];
    wide[..5].copy_from_slice(&bytes[at..at + 5]);
    u64::from_le_bytes(wide)
}

fn get_u24(bytes: &[u8], at: usize) -> u64 {
    let mut wide = [0u8; 4];
    wide[..3].copy_from_slice(&bytes[at..at + 3]);
    u32::from_le_bytes(wide) as u64
}

/// Builds one immutable run from a delta.
pub struct IndexRunBuilder {
    root_uuid: [u8; 16],
    generation: u64,
    seed: u64,
}

impl IndexRunBuilder {
    pub fn new(root_uuid: [u8; 16], generation: u64, seed: u64) -> Self {
        Self {
            root_uuid,
            generation,
            seed,
        }
    }

    /// Encode `delta` into run bytes.
    ///
    /// Every packed-field width is checked here. A value that does not fit is
    /// `LimitExceeded`, never a truncation: an index that silently narrows an
    /// offset points at the wrong bytes and reports success.
    pub fn build(&self, delta: &IndexDelta) -> Result<Vec<u8>, StoreError> {
        let entry_count = delta.len();
        let params = BloomParams::for_entries(entry_count, self.seed);

        let mut bitmap = vec![0u8; params.byte_len() as usize];
        let mut sections: Vec<SectionHeader> = Vec::with_capacity(delta.namespace_count());
        let mut entries: Vec<u8> = Vec::with_capacity(entry_count as usize * INDEX_ENTRY_LEN);

        let mut first_entry = 0u64;
        for (namespace, objects) in &delta.by_namespace {
            let base_segment_generation = objects
                .values()
                .map(|l| l.segment_generation)
                .min()
                .unwrap_or(0);
            let base_shard_sequence = objects
                .values()
                .map(|l| l.shard_sequence)
                .min()
                .unwrap_or(0);

            for (object, location) in objects {
                let key = IndexKey::new(*namespace, *object);
                bloom_insert(&mut bitmap, &params, &key);
                entries.extend_from_slice(&object.0);
                pack_location(
                    &mut entries,
                    location,
                    base_segment_generation,
                    base_shard_sequence,
                )?;
            }

            sections.push(SectionHeader {
                namespace: *namespace,
                base_segment_generation,
                base_shard_sequence,
                first_entry,
                entry_count: objects.len() as u64,
            });
            first_entry += objects.len() as u64;
        }

        let mut section_bytes = Vec::with_capacity(sections.len() * INDEX_SECTION_LEN);
        for section in &sections {
            section_bytes.extend_from_slice(&section.namespace.0);
            put_u64(&mut section_bytes, section.base_segment_generation);
            put_u64(&mut section_bytes, section.base_shard_sequence);
            put_u64(&mut section_bytes, section.first_entry);
            put_u64(&mut section_bytes, section.entry_count);
        }
        debug_assert_eq!(section_bytes.len(), sections.len() * INDEX_SECTION_LEN);

        let bloom_offset = INDEX_RUN_HEADER_LEN as u64;
        let sections_offset = bloom_offset + params.byte_len();
        let entries_offset = sections_offset + section_bytes.len() as u64;
        let total_len = entries_offset + entries.len() as u64 + INDEX_RUN_TRAILER_LEN as u64;

        let mut header = Vec::with_capacity(INDEX_RUN_HEADER_LEN);
        header.extend_from_slice(&INDEX_RUN_MAGIC);
        put_u16(&mut header, INDEX_STORAGE_VERSION);
        put_u16(&mut header, INDEX_RUN_HEADER_LEN as u16);
        put_u32(&mut header, 0); // flags: must be zero
        header.extend_from_slice(&self.root_uuid);
        put_u64(&mut header, self.generation);
        put_u64(&mut header, sections.len() as u64);
        put_u64(&mut header, entry_count);
        put_u16(&mut header, params.version);
        put_u16(&mut header, params.hashes);
        put_u32(&mut header, 0); // reserved: must be zero
        put_u64(&mut header, params.seed);
        put_u64(&mut header, params.bits);
        put_u64(&mut header, bloom_offset);
        put_u64(&mut header, sections_offset);
        put_u64(&mut header, entries_offset);
        put_u64(&mut header, total_len);
        debug_assert_eq!(header.len(), INDEX_RUN_HEADER_FIELDS_LEN);
        header.resize(INDEX_RUN_HEADER_LEN - 32, 0);
        let header_digest = crate::format::digest(INDEX_RUN_DIGEST_DOMAIN, &header);
        header.extend_from_slice(&header_digest.0);
        debug_assert_eq!(header.len(), INDEX_RUN_HEADER_LEN);

        let mut out = Vec::with_capacity(total_len as usize);
        out.extend_from_slice(&header);
        out.extend_from_slice(&bitmap);
        out.extend_from_slice(&section_bytes);
        out.extend_from_slice(&entries);

        let body_digest = crate::format::digest(INDEX_RUN_DIGEST_DOMAIN, &out);
        out.extend_from_slice(&INDEX_RUN_TRAILER_MAGIC);
        put_u64(&mut out, total_len);
        out.extend_from_slice(&body_digest.0);
        debug_assert_eq!(out.len() as u64, total_len);
        Ok(out)
    }
}

fn pack_location(
    out: &mut Vec<u8>,
    location: &IndexLocation,
    base_segment_generation: u64,
    base_shard_sequence: u64,
) -> Result<(), StoreError> {
    let generation_delta = location
        .segment_generation
        .checked_sub(base_segment_generation)
        .ok_or_else(|| StoreError::Corruption("segment generation below section base".into()))?;
    if generation_delta > MAX_SEGMENT_GENERATION_DELTA {
        return Err(StoreError::LimitExceeded {
            limit: "index_run_segment_generation_span",
            observed: generation_delta,
            allowed: MAX_SEGMENT_GENERATION_DELTA,
        });
    }
    if location.frame_offset >= MAX_FRAME_OFFSET {
        return Err(StoreError::LimitExceeded {
            limit: "index_run_frame_offset",
            observed: location.frame_offset,
            allowed: MAX_FRAME_OFFSET - 1,
        });
    }
    let sequence_delta = location
        .shard_sequence
        .checked_sub(base_shard_sequence)
        .ok_or_else(|| StoreError::Corruption("shard sequence below section base".into()))?;
    if sequence_delta >= MAX_SHARD_SEQUENCE_DELTA {
        return Err(StoreError::LimitExceeded {
            limit: "index_run_shard_sequence_span",
            observed: sequence_delta,
            allowed: MAX_SHARD_SEQUENCE_DELTA - 1,
        });
    }

    let before = out.len();
    out.extend_from_slice(&(generation_delta as u16).to_le_bytes());
    out.extend_from_slice(&location.frame_offset.to_le_bytes()[..5]);
    out.extend_from_slice(&location.frame_len.to_le_bytes());
    out.push(location.object_type);
    out.extend_from_slice(&(sequence_delta as u32).to_le_bytes()[..3]);
    debug_assert_eq!(out.len() - before, INDEX_ENTRY_LEN - 32);
    Ok(())
}

/// The backing bytes of a run: a mapping in production, an owned buffer when a
/// caller already holds the bytes.
enum RunBytes {
    Mapped(memmap2::Mmap),
    Owned(Vec<u8>),
}

impl std::ops::Deref for RunBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            RunBytes::Mapped(m) => m,
            RunBytes::Owned(v) => v,
        }
    }
}

/// An immutable, memory-mapped sorted run.
pub struct IndexRun {
    bytes: RunBytes,
    generation: u64,
    params: BloomParams,
    section_count: u64,
    entry_count: u64,
    bloom_offset: usize,
    sections_offset: usize,
    entries_offset: usize,
}

impl std::fmt::Debug for IndexRun {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexRun")
            .field("generation", &self.generation)
            .field("sections", &self.section_count)
            .field("entries", &self.entry_count)
            .finish()
    }
}

impl IndexRun {
    /// Memory-map and validate a run file.
    pub fn open(path: &Path, root_uuid: &[u8; 16]) -> Result<Self, StoreError> {
        let file = File::open(path)?;
        // SAFETY: index runs are immutable once installed under
        // `rename_noreplace`; nothing in this crate rewrites or truncates a
        // named run, which is the condition a mapping requires.
        let map = unsafe { memmap2::Mmap::map(&file) }?;
        Self::from_bytes(RunBytes::Mapped(map), root_uuid).map_err(Into::into)
    }

    /// Validate run bytes already in memory.
    pub fn from_vec(bytes: Vec<u8>, root_uuid: &[u8; 16]) -> Result<Self, IndexError> {
        Self::from_bytes(RunBytes::Owned(bytes), root_uuid)
    }

    fn from_bytes(bytes: RunBytes, root_uuid: &[u8; 16]) -> Result<Self, IndexError> {
        let len = bytes.len();
        if len < INDEX_RUN_HEADER_LEN + INDEX_RUN_TRAILER_LEN {
            return Err(IndexError::Truncated);
        }
        if bytes[0..8] != INDEX_RUN_MAGIC {
            return Err(IndexError::Magic);
        }
        let storage_version = get_u16(&bytes, 8);
        if storage_version != INDEX_STORAGE_VERSION {
            return Err(IndexError::StorageVersion(storage_version));
        }
        if get_u16(&bytes, 10) as usize != INDEX_RUN_HEADER_LEN {
            return Err(IndexError::Layout);
        }
        if get_u32(&bytes, 12) != 0 {
            return Err(IndexError::Flags);
        }
        if bytes[INDEX_RUN_HEADER_FIELDS_LEN..INDEX_RUN_HEADER_LEN - 32]
            .iter()
            .any(|b| *b != 0)
        {
            return Err(IndexError::Flags);
        }

        let mut header = bytes[..INDEX_RUN_HEADER_LEN].to_vec();
        let stored_header_digest: [u8; 32] = header[INDEX_RUN_HEADER_LEN - 32..]
            .try_into()
            .expect("32 bytes");
        header.truncate(INDEX_RUN_HEADER_LEN - 32);
        if crate::format::digest(INDEX_RUN_DIGEST_DOMAIN, &header).0 != stored_header_digest {
            return Err(IndexError::HeaderDigest);
        }

        let file_root_uuid: [u8; 16] = bytes[16..32].try_into().expect("16 bytes");
        if &file_root_uuid != root_uuid {
            return Err(IndexError::RootUuid);
        }

        let generation = get_u64(&bytes, 32);
        let section_count = get_u64(&bytes, 40);
        let entry_count = get_u64(&bytes, 48);
        let bloom_version = get_u16(&bytes, 56);
        if bloom_version != INDEX_BLOOM_VERSION {
            return Err(IndexError::BloomVersion(bloom_version));
        }
        let hashes = get_u16(&bytes, 58);
        if get_u32(&bytes, 60) != 0 {
            return Err(IndexError::Flags);
        }
        let seed = get_u64(&bytes, 64);
        let bits = get_u64(&bytes, 72);
        let bloom_offset = get_u64(&bytes, 80);
        let sections_offset = get_u64(&bytes, 88);
        let entries_offset = get_u64(&bytes, 96);
        let total_len = get_u64(&bytes, 104);

        if hashes == 0 || bits == 0 || total_len != len as u64 {
            return Err(IndexError::Layout);
        }

        let params = BloomParams {
            version: bloom_version,
            hashes,
            seed,
            bits,
        };

        let expected_bloom = INDEX_RUN_HEADER_LEN as u64;
        let expected_sections = expected_bloom + params.byte_len();
        let expected_entries = expected_sections
            .checked_add(
                section_count
                    .checked_mul(INDEX_SECTION_LEN as u64)
                    .ok_or(IndexError::Layout)?,
            )
            .ok_or(IndexError::Layout)?;
        let expected_total = expected_entries
            .checked_add(
                entry_count
                    .checked_mul(INDEX_ENTRY_LEN as u64)
                    .ok_or(IndexError::Layout)?,
            )
            .and_then(|v| v.checked_add(INDEX_RUN_TRAILER_LEN as u64))
            .ok_or(IndexError::Layout)?;
        if bloom_offset != expected_bloom
            || sections_offset != expected_sections
            || entries_offset != expected_entries
            || total_len != expected_total
        {
            return Err(IndexError::Layout);
        }

        let trailer = &bytes[len - INDEX_RUN_TRAILER_LEN..];
        if trailer[0..8] != INDEX_RUN_TRAILER_MAGIC || get_u64(trailer, 8) != total_len {
            return Err(IndexError::Trailer);
        }
        let stored_body_digest: [u8; 32] = trailer[16..48].try_into().expect("32 bytes");
        if crate::format::digest(
            INDEX_RUN_DIGEST_DOMAIN,
            &bytes[..len - INDEX_RUN_TRAILER_LEN],
        )
        .0 != stored_body_digest
        {
            return Err(IndexError::BodyDigest);
        }

        let run = Self {
            bytes,
            generation,
            params,
            section_count,
            entry_count,
            bloom_offset: bloom_offset as usize,
            sections_offset: sections_offset as usize,
            entries_offset: entries_offset as usize,
        };
        run.validate_order()?;
        Ok(run)
    }

    /// Sortedness is load-bearing: the binary searches below are only correct
    /// if it holds, and it is cheap to prove once at open rather than to
    /// assume forever.
    fn validate_order(&self) -> Result<(), IndexError> {
        let mut previous_namespace: Option<NamespaceId> = None;
        let mut expected_first = 0u64;
        for i in 0..self.section_count {
            let section = self.section(i);
            if let Some(previous) = previous_namespace {
                if section.namespace <= previous {
                    return Err(IndexError::SectionOrder);
                }
            }
            if section.first_entry != expected_first {
                return Err(IndexError::Layout);
            }
            expected_first = section
                .first_entry
                .checked_add(section.entry_count)
                .ok_or(IndexError::Layout)?;
            if expected_first > self.entry_count {
                return Err(IndexError::Layout);
            }

            let mut previous_object: Option<ObjectId> = None;
            for j in 0..section.entry_count {
                let object = self.entry_object(section.first_entry + j);
                if let Some(previous) = previous_object {
                    if object <= previous {
                        return Err(IndexError::EntryOrder);
                    }
                }
                previous_object = Some(object);
            }
            previous_namespace = Some(section.namespace);
        }
        if expected_first != self.entry_count {
            return Err(IndexError::Layout);
        }
        Ok(())
    }

    fn section(&self, i: u64) -> SectionHeader {
        let at = self.sections_offset + i as usize * INDEX_SECTION_LEN;
        let namespace: [u8; 32] = self.bytes[at..at + 32].try_into().expect("32 bytes");
        SectionHeader {
            namespace: NamespaceId(namespace),
            base_segment_generation: get_u64(&self.bytes, at + 32),
            base_shard_sequence: get_u64(&self.bytes, at + 40),
            first_entry: get_u64(&self.bytes, at + 48),
            entry_count: get_u64(&self.bytes, at + 56),
        }
    }

    fn entry_object(&self, i: u64) -> ObjectId {
        let at = self.entries_offset + i as usize * INDEX_ENTRY_LEN;
        ObjectId(self.bytes[at..at + 32].try_into().expect("32 bytes"))
    }

    fn entry_location(&self, i: u64, section: &SectionHeader) -> IndexLocation {
        let at = self.entries_offset + i as usize * INDEX_ENTRY_LEN + 32;
        IndexLocation {
            segment_generation: section.base_segment_generation + get_u16(&self.bytes, at) as u64,
            frame_offset: get_u40(&self.bytes, at + 2),
            frame_len: get_u32(&self.bytes, at + 7),
            object_type: self.bytes[at + 11],
            shard_sequence: section.base_shard_sequence + get_u24(&self.bytes, at + 12),
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub fn byte_len(&self) -> u64 {
        self.bytes.len() as u64
    }

    pub fn bloom_params(&self) -> BloomParams {
        self.params
    }

    /// Probe the filter. `false` is definitive; `true` means "search".
    pub fn may_contain(&self, key: &IndexKey) -> bool {
        let end = self.bloom_offset + self.params.byte_len() as usize;
        bloom_may_contain(&self.bytes[self.bloom_offset..end], &self.params, key)
    }

    pub fn get(&self, key: &IndexKey) -> Option<IndexLocation> {
        let section = self.find_section(&key.namespace)?;
        let mut lo = section.first_entry;
        let mut hi = section.first_entry + section.entry_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.entry_object(mid).cmp(&key.object) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(self.entry_location(mid, &section)),
            }
        }
        None
    }

    /// Does any entry in this run name `generation` as its logical segment
    /// generation?
    ///
    /// Granted to recovery by contract review 2026-07-30-B, which has the one
    /// caller: before recovery seals a journal under a generation other than
    /// the identity its frames already carry, it must know whether a published
    /// run holds locations against the identity it is about to displace. A run
    /// like that stays authoritative through the manifest while resolving to
    /// nothing, so recovery refuses instead of opening the store.
    ///
    /// Read-only and exact rather than a range test. A section's entries store
    /// a 16-bit delta from its base, so `[base, base + u16::MAX]` bounds what
    /// the section *could* name and skips the sections that could not name it
    /// at all — but a section covering the range does not mean an entry in it
    /// does, and answering `true` on the range alone would turn recoverable
    /// roots into outages for a generation no entry mentions.
    pub fn references_segment_generation(&self, generation: u64) -> bool {
        for i in 0..self.section_count {
            let section = self.section(i);
            let Some(delta) = generation.checked_sub(section.base_segment_generation) else {
                continue;
            };
            if delta > u64::from(u16::MAX) {
                continue;
            }
            for j in 0..section.entry_count {
                if self
                    .entry_location(section.first_entry + j, &section)
                    .segment_generation
                    == generation
                {
                    return true;
                }
            }
        }
        false
    }

    fn find_section(&self, namespace: &NamespaceId) -> Option<SectionHeader> {
        let mut lo = 0u64;
        let mut hi = self.section_count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let section = self.section(mid);
            match section.namespace.cmp(namespace) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
                std::cmp::Ordering::Equal => return Some(section),
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// The composed index
// ---------------------------------------------------------------------------

/// What a lookup cost, so plan §13's "checkpoint lookup fan-out" reporting
/// requirement is a measurement rather than an estimate.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct LookupResult {
    pub location: Option<IndexLocation>,
    /// Runs whose filter said "maybe" and were therefore binary-searched.
    pub runs_searched: u32,
    /// Runs the filter excluded without touching their entries.
    pub runs_filtered: u32,
    /// True when the delta answered and no run was consulted.
    pub answered_by_delta: bool,
}

impl LookupResult {
    pub const fn fan_out(&self) -> u32 {
        self.runs_searched
    }
}

/// Delta plus runs, oldest run first in storage order and probed newest first.
pub struct ObjectIndex {
    delta: IndexDelta,
    runs: Vec<Arc<IndexRun>>,
    max_index_runs: u32,
    max_open_index_runs: u32,
    catalog: NamespaceCatalog,
}

impl ObjectIndex {
    pub fn new(options: &crate::options::StoreOptions) -> Self {
        Self {
            delta: IndexDelta::from_options(options),
            runs: Vec::new(),
            max_index_runs: options.max_index_runs,
            max_open_index_runs: options.max_open_index_runs,
            catalog: NamespaceCatalog::new(),
        }
    }

    pub fn delta(&self) -> &IndexDelta {
        &self.delta
    }

    pub fn delta_mut(&mut self) -> &mut IndexDelta {
        &mut self.delta
    }

    pub fn catalog(&self) -> &NamespaceCatalog {
        &self.catalog
    }

    pub fn catalog_mut(&mut self) -> &mut NamespaceCatalog {
        &mut self.catalog
    }

    pub fn run_count(&self) -> usize {
        self.runs.len()
    }

    /// Attach a run. Refuses past the configured ceiling rather than letting
    /// fan-out grow without bound — plan §13 names unbounded run fan-out as a
    /// redesign trigger, so reaching it silently must be impossible.
    pub fn push_run(&mut self, run: Arc<IndexRun>) -> Result<(), StoreError> {
        let projected = self.runs.len() as u64 + 1;
        if projected > self.max_index_runs as u64 {
            return Err(StoreError::LimitExceeded {
                limit: "max_index_runs",
                observed: projected,
                allowed: self.max_index_runs as u64,
            });
        }
        if projected > self.max_open_index_runs as u64 {
            return Err(StoreError::LimitExceeded {
                limit: "max_open_index_runs",
                observed: projected,
                allowed: self.max_open_index_runs as u64,
            });
        }
        self.runs.push(run);
        Ok(())
    }

    pub fn insert(&mut self, key: IndexKey, location: IndexLocation) -> Result<(), StoreError> {
        self.delta.insert(key, location)
    }

    /// Delta first, then runs newest to oldest. The first hit wins because a
    /// newer generation supersedes an older one.
    pub fn lookup(&self, key: &IndexKey) -> LookupResult {
        if let Some(location) = self.delta.get(key) {
            return LookupResult {
                location: Some(location),
                runs_searched: 0,
                runs_filtered: 0,
                answered_by_delta: true,
            };
        }
        let mut result = LookupResult::default();
        for run in self.runs.iter().rev() {
            if !run.may_contain(key) {
                result.runs_filtered += 1;
                continue;
            }
            result.runs_searched += 1;
            if let Some(location) = run.get(key) {
                result.location = Some(location);
                return result;
            }
        }
        result
    }

    pub fn contains(&self, key: &IndexKey) -> bool {
        self.lookup(key).location.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: [u8; 16] = [7u8; 16];

    fn ns(byte: u8) -> NamespaceId {
        NamespaceId([byte; 32])
    }

    fn oid(byte: u8) -> ObjectId {
        ObjectId([byte; 32])
    }

    fn loc(sequence: u64) -> IndexLocation {
        IndexLocation {
            segment_generation: 3,
            frame_offset: 4096 * sequence,
            frame_len: 512,
            object_type: 2,
            shard_sequence: sequence,
        }
    }

    fn delta_with(pairs: &[(NamespaceId, ObjectId, IndexLocation)]) -> IndexDelta {
        let mut delta = IndexDelta::new(1_000_000, 1 << 30);
        for (namespace, object, location) in pairs {
            delta
                .insert(IndexKey::new(*namespace, *object), *location)
                .expect("insert");
        }
        delta
    }

    /// Recompute the header digest in place, so a test can isolate one
    /// validation condition instead of always tripping the digest first.
    fn reseal_header(bytes: &mut [u8]) {
        let digest =
            crate::format::digest(INDEX_RUN_DIGEST_DOMAIN, &bytes[..INDEX_RUN_HEADER_LEN - 32]);
        bytes[INDEX_RUN_HEADER_LEN - 32..INDEX_RUN_HEADER_LEN].copy_from_slice(&digest.0);
    }

    fn reseal_body(bytes: &mut [u8]) {
        let end = bytes.len() - INDEX_RUN_TRAILER_LEN;
        let digest = crate::format::digest(INDEX_RUN_DIGEST_DOMAIN, &bytes[..end]);
        bytes[end + 16..end + 48].copy_from_slice(&digest.0);
    }

    // -- namespace isolation, Phase 1 exit criterion ------------------------

    #[test]
    fn byte_identical_object_in_namespace_a_is_absent_from_namespace_b_in_the_delta() {
        let object = oid(0xAB);
        let delta = delta_with(&[(ns(1), object, loc(10))]);

        assert_eq!(
            delta.get(&IndexKey::new(ns(1), object)),
            Some(loc(10)),
            "the object must be present under the namespace that holds it"
        );
        assert_eq!(
            delta.get(&IndexKey::new(ns(2), object)),
            None,
            "identical bytes in namespace A must not be reachable through namespace B"
        );
    }

    #[test]
    fn byte_identical_object_in_namespace_a_is_absent_from_namespace_b_in_a_run() {
        let object = oid(0xAB);
        let delta = delta_with(&[(ns(1), object, loc(10))]);
        let bytes = IndexRunBuilder::new(ROOT, 1, 0xFEED)
            .build(&delta)
            .expect("build");
        let run = IndexRun::from_vec(bytes, &ROOT).expect("open");

        assert_eq!(run.get(&IndexKey::new(ns(1), object)), Some(loc(10)));
        assert_eq!(
            run.get(&IndexKey::new(ns(2), object)),
            None,
            "a sorted run must not answer for a namespace it does not contain"
        );
    }

    #[test]
    fn the_bloom_filter_is_keyed_on_the_namespace_too() {
        // A filter hashed over the ObjectId alone would say "maybe" for both
        // namespaces. It must be able to say "definitely not" for B.
        let mut delta = IndexDelta::new(1000, 1 << 20);
        for i in 0..200u8 {
            delta
                .insert(IndexKey::new(ns(1), oid(i)), loc(i as u64))
                .expect("insert");
        }
        let bytes = IndexRunBuilder::new(ROOT, 1, 1)
            .build(&delta)
            .expect("build");
        let run = IndexRun::from_vec(bytes, &ROOT).expect("open");

        let mut excluded = 0;
        for i in 0..200u8 {
            if !run.may_contain(&IndexKey::new(ns(2), oid(i))) {
                excluded += 1;
            }
        }
        assert!(
            excluded > 150,
            "the filter must exclude the great majority of namespace-B probes for \
             objects present in namespace A; it excluded only {excluded}/200"
        );
    }

    #[test]
    fn the_composed_index_keeps_namespaces_apart_across_delta_and_runs() {
        let mut options = crate::options::StoreOptions::new("/tmp/x");
        options.max_index_runs = 8;
        options.max_open_index_runs = 8;
        let mut index = ObjectIndex::new(&options);

        let object = oid(0x5A);
        let sealed = delta_with(&[(ns(1), object, loc(1))]);
        let bytes = IndexRunBuilder::new(ROOT, 1, 9)
            .build(&sealed)
            .expect("build");
        index
            .push_run(Arc::new(IndexRun::from_vec(bytes, &ROOT).expect("open")))
            .expect("push");
        index
            .insert(IndexKey::new(ns(3), oid(0x11)), loc(2))
            .expect("insert");

        assert!(index.contains(&IndexKey::new(ns(1), object)));
        assert!(!index.contains(&IndexKey::new(ns(2), object)));
        assert!(!index.contains(&IndexKey::new(ns(3), object)));
        assert!(index.contains(&IndexKey::new(ns(3), oid(0x11))));
        assert!(!index.contains(&IndexKey::new(ns(1), oid(0x11))));
    }

    // -- run codec ----------------------------------------------------------

    #[test]
    fn a_run_round_trips_every_entry_it_was_built_from() {
        let mut delta = IndexDelta::new(10_000, 1 << 24);
        let mut expected = Vec::new();
        for namespace in 0..5u8 {
            for object in 0..40u8 {
                let key = IndexKey::new(ns(namespace), oid(object));
                let location = IndexLocation {
                    segment_generation: 100 + namespace as u64,
                    frame_offset: (1 << 20) | (object as u64 * 8),
                    frame_len: 4096 + object as u32,
                    object_type: object % 7,
                    shard_sequence: 900 + object as u64,
                };
                delta.insert(key, location).expect("insert");
                expected.push((key, location));
            }
        }
        let bytes = IndexRunBuilder::new(ROOT, 42, 0x1234)
            .build(&delta)
            .expect("build");
        let run = IndexRun::from_vec(bytes, &ROOT).expect("open");

        assert_eq!(run.generation(), 42);
        assert_eq!(run.entry_count(), 200);
        for (key, location) in expected {
            assert_eq!(run.get(&key), Some(location), "round trip {key:?}");
            assert!(
                run.may_contain(&key),
                "the filter must never say no to a member"
            );
        }
    }

    #[test]
    fn an_empty_run_is_valid_and_answers_nothing() {
        let delta = IndexDelta::new(10, 1024);
        let bytes = IndexRunBuilder::new(ROOT, 0, 5)
            .build(&delta)
            .expect("build");
        let run = IndexRun::from_vec(bytes, &ROOT).expect("open");
        assert_eq!(run.entry_count(), 0);
        assert_eq!(run.get(&IndexKey::new(ns(1), oid(1))), None);
    }

    #[test]
    fn a_run_from_another_store_root_is_refused() {
        let delta = delta_with(&[(ns(1), oid(1), loc(1))]);
        let bytes = IndexRunBuilder::new(ROOT, 1, 1)
            .build(&delta)
            .expect("build");
        assert_eq!(
            IndexRun::from_vec(bytes, &[9u8; 16]).unwrap_err(),
            IndexError::RootUuid,
            "root_uuid binding is what catches a run copied in from another instance"
        );
    }

    #[test]
    fn each_corruption_is_rejected_by_its_own_condition() {
        let delta = delta_with(&[(ns(1), oid(1), loc(1)), (ns(2), oid(2), loc(2))]);
        let good = IndexRunBuilder::new(ROOT, 1, 1)
            .build(&delta)
            .expect("build");

        let mut magic = good.clone();
        magic[0] ^= 0xFF;
        assert_eq!(
            IndexRun::from_vec(magic, &ROOT).unwrap_err(),
            IndexError::Magic
        );

        let mut version = good.clone();
        version[8] = 9;
        assert_eq!(
            IndexRun::from_vec(version, &ROOT).unwrap_err(),
            IndexError::StorageVersion(9)
        );

        let mut flags = good.clone();
        flags[12] = 1;
        assert_eq!(
            IndexRun::from_vec(flags, &ROOT).unwrap_err(),
            IndexError::Flags
        );

        // A header field mutated below the digest must fail the header digest,
        // not merely a layout check.
        let mut header = good.clone();
        header[33] ^= 0x01;
        assert_eq!(
            IndexRun::from_vec(header, &ROOT).unwrap_err(),
            IndexError::HeaderDigest
        );

        let mut bloom_version = good.clone();
        bloom_version[56] = 77;
        reseal_header(&mut bloom_version);
        assert_eq!(
            IndexRun::from_vec(bloom_version, &ROOT).unwrap_err(),
            IndexError::BloomVersion(77)
        );

        let mut reserved = good.clone();
        reserved[60] = 1;
        reseal_header(&mut reserved);
        assert_eq!(
            IndexRun::from_vec(reserved, &ROOT).unwrap_err(),
            IndexError::Flags
        );

        let mut body = good.clone();
        let entry = good.len() - INDEX_RUN_TRAILER_LEN - INDEX_ENTRY_LEN;
        body[entry] ^= 0x01;
        assert_eq!(
            IndexRun::from_vec(body, &ROOT).unwrap_err(),
            IndexError::BodyDigest
        );

        let mut trailer = good.clone();
        let at = good.len() - INDEX_RUN_TRAILER_LEN;
        trailer[at] ^= 0xFF;
        assert_eq!(
            IndexRun::from_vec(trailer, &ROOT).unwrap_err(),
            IndexError::Trailer
        );

        let mut truncated = good.clone();
        truncated.truncate(INDEX_RUN_HEADER_LEN + INDEX_RUN_TRAILER_LEN - 1);
        assert_eq!(
            IndexRun::from_vec(truncated, &ROOT).unwrap_err(),
            IndexError::Truncated
        );

        let mut short = good.clone();
        short.pop();
        assert_eq!(
            IndexRun::from_vec(short, &ROOT).unwrap_err(),
            IndexError::Layout,
            "a run whose total_len disagrees with its length is a layout fault"
        );
    }

    #[test]
    fn out_of_order_entries_are_rejected_even_with_valid_digests() {
        // The binary search is only correct on sorted entries, so an attacker
        // or a bug that reorders them must be caught at open rather than
        // producing silent misses.
        let delta = delta_with(&[(ns(1), oid(1), loc(1)), (ns(1), oid(2), loc(2))]);
        let good = IndexRunBuilder::new(ROOT, 1, 1)
            .build(&delta)
            .expect("build");

        let mut swapped = good.clone();
        let entries_at = swapped.len() - INDEX_RUN_TRAILER_LEN - 2 * INDEX_ENTRY_LEN;
        let (first, second) = (
            swapped[entries_at..entries_at + INDEX_ENTRY_LEN].to_vec(),
            swapped[entries_at + INDEX_ENTRY_LEN..entries_at + 2 * INDEX_ENTRY_LEN].to_vec(),
        );
        swapped[entries_at..entries_at + INDEX_ENTRY_LEN].copy_from_slice(&second);
        swapped[entries_at + INDEX_ENTRY_LEN..entries_at + 2 * INDEX_ENTRY_LEN]
            .copy_from_slice(&first);
        reseal_body(&mut swapped);

        assert_eq!(
            IndexRun::from_vec(swapped, &ROOT).unwrap_err(),
            IndexError::EntryOrder
        );
    }

    #[test]
    fn out_of_order_sections_are_rejected_even_with_valid_digests() {
        let delta = delta_with(&[(ns(1), oid(1), loc(1)), (ns(2), oid(2), loc(2))]);
        let good = IndexRunBuilder::new(ROOT, 1, 1)
            .build(&delta)
            .expect("build");

        // Swap only the two namespace fields, leaving `first_entry` and the
        // counts consistent, so the ordering check is what fires rather than
        // the layout check.
        let mut swapped = good.clone();
        let sections_at = get_u64(&swapped, 88) as usize;
        let first = swapped[sections_at..sections_at + 32].to_vec();
        let second =
            swapped[sections_at + INDEX_SECTION_LEN..sections_at + INDEX_SECTION_LEN + 32].to_vec();
        swapped[sections_at..sections_at + 32].copy_from_slice(&second);
        swapped[sections_at + INDEX_SECTION_LEN..sections_at + INDEX_SECTION_LEN + 32]
            .copy_from_slice(&first);
        reseal_body(&mut swapped);

        assert_eq!(
            IndexRun::from_vec(swapped, &ROOT).unwrap_err(),
            IndexError::SectionOrder
        );
    }

    #[test]
    fn truncation_at_every_offset_is_rejected_without_panic() {
        let delta = delta_with(&[(ns(1), oid(1), loc(1)), (ns(1), oid(2), loc(2))]);
        let good = IndexRunBuilder::new(ROOT, 1, 1)
            .build(&delta)
            .expect("build");
        for cut in 0..good.len() {
            let mut bytes = good.clone();
            bytes.truncate(cut);
            assert!(
                IndexRun::from_vec(bytes, &ROOT).is_err(),
                "truncation at {cut} must be rejected"
            );
        }
    }

    // -- packed-width refusals ---------------------------------------------

    #[test]
    fn an_offset_past_the_packed_width_is_refused_rather_than_narrowed() {
        let mut delta = IndexDelta::new(10, 1 << 20);
        delta
            .insert(
                IndexKey::new(ns(1), oid(1)),
                IndexLocation {
                    segment_generation: 0,
                    frame_offset: MAX_FRAME_OFFSET,
                    frame_len: 1,
                    object_type: 0,
                    shard_sequence: 0,
                },
            )
            .expect("insert");
        let err = IndexRunBuilder::new(ROOT, 1, 1)
            .build(&delta)
            .expect_err("must refuse");
        match err {
            StoreError::LimitExceeded { limit, .. } => assert_eq!(limit, "index_run_frame_offset"),
            other => panic!("expected LimitExceeded on the offset width, got {other:?}"),
        }
    }

    #[test]
    fn a_shard_sequence_span_past_the_packed_width_is_refused() {
        let mut delta = IndexDelta::new(10, 1 << 20);
        for (i, sequence) in [0u64, MAX_SHARD_SEQUENCE_DELTA].into_iter().enumerate() {
            delta
                .insert(
                    IndexKey::new(ns(1), oid(i as u8)),
                    IndexLocation {
                        segment_generation: 0,
                        frame_offset: 0,
                        frame_len: 1,
                        object_type: 0,
                        shard_sequence: sequence,
                    },
                )
                .expect("insert");
        }
        let err = IndexRunBuilder::new(ROOT, 1, 1)
            .build(&delta)
            .expect_err("must refuse");
        match err {
            StoreError::LimitExceeded { limit, .. } => {
                assert_eq!(limit, "index_run_shard_sequence_span")
            }
            other => panic!("expected LimitExceeded on the sequence width, got {other:?}"),
        }
    }

    #[test]
    fn a_segment_generation_span_past_the_packed_width_is_refused() {
        let mut delta = IndexDelta::new(10, 1 << 20);
        for (i, generation) in [0u64, MAX_SEGMENT_GENERATION_DELTA + 1]
            .into_iter()
            .enumerate()
        {
            delta
                .insert(
                    IndexKey::new(ns(1), oid(i as u8)),
                    IndexLocation {
                        segment_generation: generation,
                        frame_offset: 0,
                        frame_len: 1,
                        object_type: 0,
                        shard_sequence: 0,
                    },
                )
                .expect("insert");
        }
        let err = IndexRunBuilder::new(ROOT, 1, 1)
            .build(&delta)
            .expect_err("must refuse");
        match err {
            StoreError::LimitExceeded { limit, .. } => {
                assert_eq!(limit, "index_run_segment_generation_span")
            }
            other => panic!("expected LimitExceeded on the generation width, got {other:?}"),
        }
    }

    /// Recovery refuses an open on the answer this gives, so a `true` it does
    /// not owe is an outage on a healthy root.
    ///
    /// Both directions, and the one that matters is the negative: generation 5
    /// sits *inside* the packed span of a section based at 4, so a range test
    /// over the section header alone would claim it. No entry names it.
    #[test]
    fn a_run_reports_only_the_segment_generations_its_entries_actually_name() {
        let mut delta = IndexDelta::new(1_000, 1 << 20);
        for (i, generation) in [4u64, 6, 40].into_iter().enumerate() {
            delta
                .insert(
                    IndexKey::new(ns(1), oid(i as u8)),
                    IndexLocation {
                        segment_generation: generation,
                        frame_offset: 0,
                        frame_len: 1,
                        object_type: 0,
                        shard_sequence: i as u64,
                    },
                )
                .expect("insert");
        }
        let bytes = IndexRunBuilder::new(ROOT, 1, 0xFEED)
            .build(&delta)
            .expect("build");
        let run = IndexRun::from_vec(bytes, &ROOT).expect("open");

        for named in [4u64, 6, 40] {
            assert!(
                run.references_segment_generation(named),
                "generation {named} is named by an entry in this run"
            );
        }
        for unnamed in [0u64, 3, 5, 7, 39, 41, u64::MAX] {
            assert!(
                !run.references_segment_generation(unnamed),
                "no entry names generation {unnamed}; claiming it would refuse a \
                 recovery that has nothing to lose"
            );
        }
    }

    // -- ceilings -----------------------------------------------------------

    #[test]
    fn the_delta_backpressures_before_it_refuses() {
        let mut delta = IndexDelta::new(8, 1 << 20);
        assert_eq!(delta.pressure(), DeltaPressure::Ok);
        for i in 0..6u8 {
            delta
                .insert(IndexKey::new(ns(1), oid(i)), loc(i as u64))
                .expect("insert");
        }
        assert_eq!(
            delta.pressure(),
            DeltaPressure::Backpressure,
            "the soft watermark must be reachable before the hard ceiling"
        );
        for i in 6..8u8 {
            delta
                .insert(IndexKey::new(ns(1), oid(i)), loc(i as u64))
                .expect("insert");
        }
        assert_eq!(delta.pressure(), DeltaPressure::SealRequired);
        let err = delta
            .insert(IndexKey::new(ns(1), oid(9)), loc(9))
            .expect_err("must refuse past the ceiling");
        match err {
            StoreError::LimitExceeded { limit, .. } => {
                assert_eq!(limit, "max_active_index_entries")
            }
            other => panic!("expected LimitExceeded, got {other:?}"),
        }
    }

    #[test]
    fn the_delta_byte_ceiling_is_enforced_independently_of_the_entry_ceiling() {
        let mut delta =
            IndexDelta::new(1_000_000, (INDEX_SECTION_LEN + INDEX_ENTRY_LEN * 2) as u64);
        delta
            .insert(IndexKey::new(ns(1), oid(1)), loc(1))
            .expect("first fits");
        delta
            .insert(IndexKey::new(ns(1), oid(2)), loc(2))
            .expect("second fits exactly");
        let err = delta
            .insert(IndexKey::new(ns(1), oid(3)), loc(3))
            .expect_err("third must not fit");
        match err {
            StoreError::LimitExceeded { limit, .. } => assert_eq!(limit, "max_active_index_bytes"),
            other => panic!("expected LimitExceeded on bytes, got {other:?}"),
        }
    }

    #[test]
    fn the_run_ceiling_refuses_rather_than_letting_fan_out_grow() {
        let mut options = crate::options::StoreOptions::new("/tmp/x");
        options.max_index_runs = 2;
        options.max_open_index_runs = 2;
        let mut index = ObjectIndex::new(&options);
        let delta = delta_with(&[(ns(1), oid(1), loc(1))]);
        for generation in 0..2 {
            let bytes = IndexRunBuilder::new(ROOT, generation, 1)
                .build(&delta)
                .expect("build");
            index
                .push_run(Arc::new(IndexRun::from_vec(bytes, &ROOT).expect("open")))
                .expect("push");
        }
        let bytes = IndexRunBuilder::new(ROOT, 2, 1)
            .build(&delta)
            .expect("build");
        let err = index
            .push_run(Arc::new(IndexRun::from_vec(bytes, &ROOT).expect("open")))
            .expect_err("must refuse");
        match err {
            StoreError::LimitExceeded { limit, .. } => assert_eq!(limit, "max_index_runs"),
            other => panic!("expected LimitExceeded on run count, got {other:?}"),
        }
    }

    #[test]
    fn an_object_may_not_silently_move_within_a_namespace() {
        let mut delta = IndexDelta::new(10, 1 << 20);
        let key = IndexKey::new(ns(1), oid(1));
        delta.insert(key, loc(1)).expect("insert");
        delta.insert(key, loc(1)).expect("idempotent re-insert");
        let err = delta.insert(key, loc(2)).expect_err("must refuse a move");
        match err {
            StoreError::Conflict(_) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }
    }

    // -- catalog ------------------------------------------------------------

    #[test]
    fn the_catalog_refuses_to_rebind_a_genesis() {
        let mut catalog = NamespaceCatalog::new();
        let record = NamespaceRecord {
            namespace: ns(1),
            genesis_authority: oid(0xA0),
            current_authority: oid(0xA0),
            lifecycle: NamespaceLifecycle::Active,
            storage_mode: NamespaceStorageMode::Full,
            repo_sequence: 0,
            previous_event_digest: ObjectId([0u8; 32]),
        };
        catalog.bind(record).expect("first bind");
        let err = catalog
            .bind(NamespaceRecord {
                genesis_authority: oid(0xB0),
                ..record
            })
            .expect_err("must refuse");
        match err {
            StoreError::Conflict(_) => {}
            other => panic!("expected Conflict, got {other:?}"),
        }
        assert_eq!(
            catalog.get(&ns(1)).expect("bound").genesis_authority,
            oid(0xA0)
        );
    }

    #[test]
    fn advancing_a_namespace_cannot_move_its_genesis() {
        let mut catalog = NamespaceCatalog::new();
        catalog
            .bind(NamespaceRecord {
                namespace: ns(1),
                genesis_authority: oid(0xA0),
                current_authority: oid(0xA0),
                lifecycle: NamespaceLifecycle::Active,
                storage_mode: NamespaceStorageMode::Full,
                repo_sequence: 0,
                previous_event_digest: ObjectId([0u8; 32]),
            })
            .expect("bind");
        catalog
            .advance(&ns(1), oid(0xC0), 5, oid(0xD0))
            .expect("advance");
        let record = *catalog.get(&ns(1)).expect("bound");
        assert_eq!(record.genesis_authority, oid(0xA0));
        assert_eq!(record.current_authority, oid(0xC0));
        assert_eq!(record.repo_sequence, 5);
    }

    #[test]
    fn advancing_an_unbound_namespace_is_corruption_not_a_silent_create() {
        let mut catalog = NamespaceCatalog::new();
        match catalog.advance(&ns(1), oid(1), 1, oid(1)) {
            Err(StoreError::Corruption(_)) => {}
            other => panic!("expected Corruption, got {other:?}"),
        }
    }

    #[test]
    fn lifecycle_and_storage_mode_codes_round_trip_and_reject_unknowns() {
        for lifecycle in [
            NamespaceLifecycle::Active,
            NamespaceLifecycle::ReadOnly,
            NamespaceLifecycle::Deleted,
        ] {
            assert_eq!(
                NamespaceLifecycle::from_code(lifecycle.code()),
                Some(lifecycle)
            );
        }
        assert_eq!(NamespaceLifecycle::from_code(3), None);
        for mode in [NamespaceStorageMode::Full, NamespaceStorageMode::Reduced] {
            assert_eq!(NamespaceStorageMode::from_code(mode.code()), Some(mode));
        }
        assert_eq!(NamespaceStorageMode::from_code(2), None);
    }

    // -- cost reporting (plan §13) -----------------------------------------

    #[test]
    fn index_cost_is_reported() {
        let mut delta = IndexDelta::new(1_000_000, 1 << 30);
        let entries = 20_000u64;
        for i in 0..entries {
            let mut object = [0u8; 32];
            object[..8].copy_from_slice(&i.to_le_bytes());
            let mut namespace = [0u8; 32];
            namespace[0] = (i % 8) as u8;
            delta
                .insert(
                    IndexKey::new(NamespaceId(namespace), ObjectId(object)),
                    IndexLocation {
                        segment_generation: 1,
                        frame_offset: i * 3000,
                        frame_len: 3000,
                        object_type: 1,
                        shard_sequence: i,
                    },
                )
                .expect("insert");
        }
        let bytes = IndexRunBuilder::new(ROOT, 1, 1)
            .build(&delta)
            .expect("build");
        let run = IndexRun::from_vec(bytes, &ROOT).expect("open");

        let packed_per_entry = (run.entry_count() * INDEX_ENTRY_LEN as u64) as f64 / entries as f64;
        let whole_run_per_entry = run.byte_len() as f64 / entries as f64;
        let resident_per_entry = delta.memory_bytes() as f64 / entries as f64;

        println!(
            "index cost: {packed_per_entry:.2} B/entry packed; \
             {whole_run_per_entry:.2} B/entry for the whole run (header, filter, \
             sections, trailer); delta resident ~{resident_per_entry:.1} B/entry"
        );
        assert_eq!(
            packed_per_entry, 47.0,
            "scope 8.2 budgets 47 bytes/entry with namespace factored out per section"
        );
        assert!(
            whole_run_per_entry < 49.0,
            "whole-run cost {whole_run_per_entry:.2} B/entry exceeds the budget by \
             more than the filter's ~1.25 B/entry"
        );
    }

    #[test]
    fn lookup_fan_out_is_measured_and_bounded_by_the_run_count() {
        let mut options = crate::options::StoreOptions::new("/tmp/x");
        options.max_index_runs = 16;
        options.max_open_index_runs = 16;
        let mut index = ObjectIndex::new(&options);

        for generation in 0..8u64 {
            let mut delta = IndexDelta::new(1000, 1 << 20);
            for i in 0..50u64 {
                let mut object = [0u8; 32];
                object[..8].copy_from_slice(&(generation * 1000 + i).to_le_bytes());
                delta
                    .insert(IndexKey::new(ns(1), ObjectId(object)), loc(i))
                    .expect("insert");
            }
            let bytes = IndexRunBuilder::new(ROOT, generation, generation)
                .build(&delta)
                .expect("build");
            index
                .push_run(Arc::new(IndexRun::from_vec(bytes, &ROOT).expect("open")))
                .expect("push");
        }

        // Present in the oldest run: every newer run's filter should exclude
        // it, so fan-out is one, not eight.
        let mut object = [0u8; 32];
        object[..8].copy_from_slice(&7u64.to_le_bytes());
        let hit = index.lookup(&IndexKey::new(ns(1), ObjectId(object)));
        assert!(hit.location.is_some());
        assert!(
            hit.fan_out() <= 2,
            "fan-out {} is too high for a filtered lookup",
            hit.fan_out()
        );
        assert!(!hit.answered_by_delta);

        let miss = index.lookup(&IndexKey::new(ns(1), oid(0xEE)));
        assert_eq!(miss.location, None);
        assert_eq!(
            miss.runs_searched + miss.runs_filtered,
            8,
            "every run must be accounted for on a miss"
        );
        println!(
            "checkpoint lookup fan-out: hit searched {} filtered {}; \
             miss searched {} filtered {}",
            hit.runs_searched, hit.runs_filtered, miss.runs_searched, miss.runs_filtered
        );
    }

    #[test]
    fn the_filter_never_denies_a_member() {
        // A false negative would make a present object unreadable, which is a
        // durability fault rather than a performance one.
        let mut delta = IndexDelta::new(20_000, 1 << 24);
        let mut keys = Vec::new();
        for i in 0..5000u64 {
            let mut object = [0u8; 32];
            object[..8].copy_from_slice(&i.to_le_bytes());
            let key = IndexKey::new(ns((i % 4) as u8), ObjectId(object));
            delta.insert(key, loc(i)).expect("insert");
            keys.push(key);
        }
        let bytes = IndexRunBuilder::new(ROOT, 1, 0xABCD)
            .build(&delta)
            .expect("build");
        let run = IndexRun::from_vec(bytes, &ROOT).expect("open");
        for key in keys {
            assert!(run.may_contain(&key), "false negative for {key:?}");
            assert!(run.get(&key).is_some());
        }
    }

    #[test]
    fn the_filter_false_positive_rate_stays_near_its_design_point() {
        let mut delta = IndexDelta::new(20_000, 1 << 24);
        for i in 0..5000u64 {
            let mut object = [0u8; 32];
            object[..8].copy_from_slice(&i.to_le_bytes());
            delta
                .insert(IndexKey::new(ns(1), ObjectId(object)), loc(i))
                .expect("insert");
        }
        let bytes = IndexRunBuilder::new(ROOT, 1, 0x5EED)
            .build(&delta)
            .expect("build");
        let run = IndexRun::from_vec(bytes, &ROOT).expect("open");

        let mut false_positives = 0u64;
        let probes = 20_000u64;
        for i in 1_000_000..1_000_000 + probes {
            let mut object = [0u8; 32];
            object[..8].copy_from_slice(&i.to_le_bytes());
            if run.may_contain(&IndexKey::new(ns(1), ObjectId(object))) {
                false_positives += 1;
            }
        }
        let rate = false_positives as f64 / probes as f64;
        println!("bloom false-positive rate: {rate:.4}");
        assert!(
            rate < 0.03,
            "10 bits/entry with 7 hashes should sit near 0.008; observed {rate:.4}"
        );
    }

    #[test]
    fn a_different_seed_produces_a_different_filter() {
        let delta = delta_with(&[(ns(1), oid(1), loc(1))]);
        let a = IndexRunBuilder::new(ROOT, 1, 1)
            .build(&delta)
            .expect("build");
        let b = IndexRunBuilder::new(ROOT, 1, 2)
            .build(&delta)
            .expect("build");
        assert_ne!(a, b, "the seed must reach the bytes");
        let run_a = IndexRun::from_vec(a, &ROOT).expect("open");
        let run_b = IndexRun::from_vec(b, &ROOT).expect("open");
        assert_eq!(run_a.bloom_params().seed, 1);
        assert_eq!(run_b.bloom_params().seed, 2);
        assert_eq!(run_a.bloom_params().version, INDEX_BLOOM_VERSION);
    }

    #[test]
    fn a_mapped_run_reads_identically_to_an_in_memory_one() {
        let delta = delta_with(&[(ns(1), oid(1), loc(1)), (ns(2), oid(2), loc(2))]);
        let bytes = IndexRunBuilder::new(ROOT, 3, 3)
            .build(&delta)
            .expect("build");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("3.idx");
        std::fs::write(&path, &bytes).expect("write");

        let mapped = IndexRun::open(&path, &ROOT).expect("open mapped");
        let owned = IndexRun::from_vec(bytes, &ROOT).expect("open owned");
        for key in [IndexKey::new(ns(1), oid(1)), IndexKey::new(ns(2), oid(2))] {
            assert_eq!(mapped.get(&key), owned.get(&key));
        }
        assert_eq!(mapped.get(&IndexKey::new(ns(1), oid(2))), None);
    }
}
