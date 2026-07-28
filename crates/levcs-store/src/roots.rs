//! Immutable publication roots for committed and in-flight store state.
//!
//! **Lead-owned (D0-B).** The types in this file are the boundary between the
//! shard writers and every reader. Writers build a complete [`ShardSubtree`],
//! merge it into the last root they loaded, and publish the resulting
//! [`CommittedRoot`] through `ArcSwap`. Nothing reachable from an already
//! published root is mutated.
//!
//! The persistent collections are intentional. A group touching a few
//! repositories, receipts, or refs must share the untouched majority rather
//! than clone it. Typed refs use [`im::OrdMap`] because their canonical order
//! feeds checkpoint/digest construction; hot lookup tables use
//! [`im::HashMap`].

use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use im::{HashMap, OrdMap, Vector};
use levcs_core::ObjectId;
use levcs_protocol::v2::RefTarget;

use crate::index::{
    IndexDelta, IndexKey, IndexLocation, IndexRun, LookupResult, NamespaceLifecycle,
    NamespaceStorageMode,
};
use crate::types::{
    CommitReceipt, NamespaceId, OperationId, PendingPhase, StoreError, TransactionStatus,
};

/// Key shared by the committed terminal table and the transient status root.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct OperationKey {
    pub namespace: NamespaceId,
    pub operation_id: OperationId,
}

impl OperationKey {
    pub const fn new(namespace: NamespaceId, operation_id: OperationId) -> Self {
        Self {
            namespace,
            operation_id,
        }
    }
}

/// Canonically ordered typed refs.
///
/// Ref order is observable anywhere a state digest or checkpoint is encoded,
/// so this is the one hot publication map for which `OrdMap`, rather than the
/// faster unordered HAMT, is required.
pub type TypedRefMap = OrdMap<RefTarget, ObjectId>;

/// One repository's complete logical state at a committed publication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoState {
    pub repo_sequence: u64,
    pub current_authority: ObjectId,
    pub genesis_authority: ObjectId,
    pub refs: TypedRefMap,
    pub lifecycle: NamespaceLifecycle,
    pub storage_mode: NamespaceStorageMode,
    pub previous_event_digest: ObjectId,
}

/// A committed operation retained while its receipt remains visible.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedReceipt {
    pub operation_digest: ObjectId,
    pub receipt: CommitReceipt,
    pub shard_sequence: u64,
    pub retry_until_micros: i64,
    pub first_visible_at_micros: i64,
    pub receipt_visible_until_micros: i64,
}

/// A committed operation whose receipt aged out but whose ID/digest tombstone
/// still prevents ambiguous reuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptTombstone {
    pub operation_digest: ObjectId,
    pub retry_until_micros: i64,
    pub tombstone_until_micros: i64,
}

/// Durable terminal state for one `(namespace, operation ID)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalStatusEntry {
    Committed(RetainedReceipt),
    Expired(ReceiptTombstone),
}

impl TerminalStatusEntry {
    pub fn operation_digest(&self) -> ObjectId {
        match self {
            Self::Committed(receipt) => receipt.operation_digest,
            Self::Expired(tombstone) => tombstone.operation_digest,
        }
    }

    pub fn transaction_status(&self) -> TransactionStatus {
        match self {
            Self::Committed(receipt) => TransactionStatus::Committed(receipt.receipt.clone()),
            Self::Expired(tombstone) => TransactionStatus::Expired {
                operation_digest: tombstone.operation_digest,
                retry_until_micros: tombstone.retry_until_micros,
                tombstone_until_micros: tombstone.tombstone_until_micros,
            },
        }
    }
}

/// A file pin retained by a committed generation.
///
/// The live `File`, not the path, is the ownership. On the supported Unix
/// storage targets it keeps the inode alive even after reclamation removes a
/// directory entry. The path remains for diagnostics and reference proofs.
#[derive(Clone, Debug)]
pub struct PinnedFile {
    path: PathBuf,
    file: Arc<File>,
}

impl PinnedFile {
    pub fn new(path: PathBuf, file: File) -> Self {
        Self {
            path,
            file: Arc::new(file),
        }
    }

    pub fn from_shared(path: PathBuf, file: Arc<File>) -> Self {
        Self { path, file }
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        let file = File::open(&path)?;
        Ok(Self::new(path, file))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file(&self) -> &Arc<File> {
        &self.file
    }
}

/// A validated immutable index run together with its installed name.
///
/// `IndexRun` owns its mapping; retaining the `Arc` therefore retains the
/// mapped inode. Keeping the path alongside it makes adoption cleanup's
/// committed-root reference proof possible without consulting mutable
/// staging bookkeeping.
#[derive(Clone, Debug)]
pub struct RetainedIndexRun {
    path: PathBuf,
    run: Arc<IndexRun>,
}

impl RetainedIndexRun {
    pub fn new(path: PathBuf, run: Arc<IndexRun>) -> Self {
        Self { path, run }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn run(&self) -> &Arc<IndexRun> {
        &self.run
    }
}

/// A validated sealed segment addressed by the generation stored in index
/// locations.
///
/// The pin keeps the inode alive; the logical generation is what lets a
/// reader resolve `IndexLocation::segment_generation` without parsing a file
/// name or consulting mutable manifest state.
#[derive(Clone, Debug)]
pub struct RetainedSegment {
    pub logical_generation: u64,
    pub journal_id: [u8; 16],
    pub first_shard_sequence: u64,
    pub last_shard_sequence: u64,
    pub file: PinnedFile,
}

impl RetainedSegment {
    pub fn new(
        logical_generation: u64,
        journal_id: [u8; 16],
        first_shard_sequence: u64,
        last_shard_sequence: u64,
        file: PinnedFile,
    ) -> Self {
        Self {
            logical_generation,
            journal_id,
            first_shard_sequence,
            last_shard_sequence,
            file,
        }
    }

    pub fn path(&self) -> &Path {
        self.file.path()
    }
}

/// A validated active journal prefix addressed as one logical segment.
///
/// Replayed index entries use `IndexLocation::segment_generation`, so the
/// generation assigned during recovery must travel with the file pin into
/// every committed root. A bare `PinnedFile` would keep the bytes alive but
/// leave readers unable to resolve those locations without reopening or
/// guessing a path.
#[derive(Clone, Debug)]
pub struct RetainedTail {
    pub logical_generation: u64,
    pub file: PinnedFile,
}

impl RetainedTail {
    pub fn new(logical_generation: u64, file: PinnedFile) -> Self {
        Self {
            logical_generation,
            file,
        }
    }

    pub fn path(&self) -> &Path {
        self.file.path()
    }
}

/// Physical encoding used by an adopted projection artifact.
///
/// Staged chunks are independently canonical and checksummed; they are not
/// transaction frames. The source kind therefore travels with the generation
/// pin so a reader never applies the journal-frame decoder to chunk bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProjectionArtifactFormat {
    CanonicalStageChunkV1,
}

/// One adopted projection artifact addressable by index locations.
#[derive(Clone, Debug)]
pub struct RetainedProjectionArtifact {
    pub logical_generation: u64,
    pub format: ProjectionArtifactFormat,
    pub file: PinnedFile,
}

impl RetainedProjectionArtifact {
    pub fn new(
        logical_generation: u64,
        format: ProjectionArtifactFormat,
        file: PinnedFile,
    ) -> Self {
        Self {
            logical_generation,
            format,
            file,
        }
    }

    pub fn path(&self) -> &Path {
        self.file.path()
    }
}

/// The physical record decoder selected by one index generation.
#[derive(Copy, Clone, Debug)]
pub enum RetainedObjectSource<'a> {
    Segment(&'a RetainedSegment),
    ActiveTail(&'a RetainedTail),
    ProjectionArtifact(&'a RetainedProjectionArtifact),
}

impl RetainedObjectSource<'_> {
    pub fn path(&self) -> &Path {
        match self {
            Self::Segment(source) => source.path(),
            Self::ActiveTail(source) => source.path(),
            Self::ProjectionArtifact(source) => source.path(),
        }
    }
}

/// Stable identity of one retained manifest generation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct GenerationId {
    pub shard_index: u16,
    pub manifest_generation: u64,
}

impl GenerationId {
    pub const fn new(shard_index: u16, manifest_generation: u64) -> Self {
        Self {
            shard_index,
            manifest_generation,
        }
    }
}

/// Live ownership of every artifact retained by one manifest generation.
///
/// Recovery constructs this only after validating all referents. Moving it
/// into a root leaves no interval where the artifacts are merely named but
/// unowned and therefore reclaimable.
#[derive(Clone, Debug)]
pub struct RetainedGeneration {
    pub id: GenerationId,
    pub segments: Arc<[RetainedSegment]>,
    pub index_runs: Arc<[RetainedIndexRun]>,
    pub checkpoints: Arc<[PinnedFile]>,
    pub active_tails: Arc<[RetainedTail]>,
    pub projection_artifacts: Arc<[RetainedProjectionArtifact]>,
}

impl RetainedGeneration {
    pub fn new(
        id: GenerationId,
        segments: Arc<[RetainedSegment]>,
        index_runs: Arc<[RetainedIndexRun]>,
        checkpoints: Arc<[PinnedFile]>,
        active_tails: Arc<[RetainedTail]>,
        projection_artifacts: Arc<[RetainedProjectionArtifact]>,
    ) -> Self {
        Self {
            id,
            segments,
            index_runs,
            checkpoints,
            active_tails,
            projection_artifacts,
        }
    }

    pub fn references_path(&self, path: &Path) -> bool {
        self.segments.iter().any(|segment| segment.path() == path)
            || self.index_runs.iter().any(|run| run.path() == path)
            || self.checkpoints.iter().any(|file| file.path() == path)
            || self.active_tails.iter().any(|tail| tail.path() == path)
            || self
                .projection_artifacts
                .iter()
                .any(|artifact| artifact.path() == path)
    }

    pub fn retained_tail(&self, logical_generation: u64) -> Option<&RetainedTail> {
        self.active_tails
            .iter()
            .find(|tail| tail.logical_generation == logical_generation)
    }

    pub fn retained_segment(&self, logical_generation: u64) -> Option<&RetainedSegment> {
        self.segments
            .iter()
            .find(|segment| segment.logical_generation == logical_generation)
    }

    pub fn retained_projection_artifact(
        &self,
        logical_generation: u64,
    ) -> Option<&RetainedProjectionArtifact> {
        self.projection_artifacts
            .iter()
            .find(|artifact| artifact.logical_generation == logical_generation)
    }
}

/// Immutable object-index layering captured by every reader.
///
/// Both vectors are newest-first. Group deltas sit above sealed runs, and the
/// first hit wins. Each layer/run is `Arc`-shared, so a merge adds only the
/// new group's layer and shares every older one. Delta layers carry their
/// shard and upper sequence so installing a sealed run can discard exactly
/// the layers that run covers instead of allowing lookup fan-out to grow once
/// per committed group forever.
#[derive(Clone, Debug)]
pub struct IndexDeltaLayer {
    pub shard_index: u16,
    pub through_shard_sequence: u64,
    pub delta: Arc<IndexDelta>,
}

impl IndexDeltaLayer {
    pub fn new(shard_index: u16, through_shard_sequence: u64, delta: Arc<IndexDelta>) -> Self {
        Self {
            shard_index,
            through_shard_sequence,
            delta,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct LayeredObjectIndex {
    delta_layers_newest_first: Vector<IndexDeltaLayer>,
    sealed_runs_newest_first: Vector<Arc<IndexRun>>,
}

impl LayeredObjectIndex {
    pub fn new(
        delta_layers_newest_first: Vector<IndexDeltaLayer>,
        sealed_runs_newest_first: Vector<Arc<IndexRun>>,
    ) -> Self {
        Self {
            delta_layers_newest_first,
            sealed_runs_newest_first,
        }
    }

    /// Construct the complete recovery lookup stack: replayed tail above the
    /// selected generation's already ordered sealed runs.
    pub fn from_recovery(
        shard_index: u16,
        through_shard_sequence: u64,
        replayed_delta: Arc<IndexDelta>,
        sealed_runs_newest_first: Vector<Arc<IndexRun>>,
    ) -> Self {
        let mut delta_layers = Vector::new();
        if !replayed_delta.is_empty() {
            delta_layers.push_back(IndexDeltaLayer::new(
                shard_index,
                through_shard_sequence,
                replayed_delta,
            ));
        }
        Self::new(delta_layers, sealed_runs_newest_first)
    }

    pub fn delta_layers(&self) -> &Vector<IndexDeltaLayer> {
        &self.delta_layers_newest_first
    }

    pub fn sealed_runs(&self) -> &Vector<Arc<IndexRun>> {
        &self.sealed_runs_newest_first
    }

    pub fn delta_layer_count(&self) -> usize {
        self.delta_layers_newest_first.len()
    }

    pub fn sealed_run_count(&self) -> usize {
        self.sealed_runs_newest_first.len()
    }

    pub fn lookup(&self, key: &IndexKey) -> LookupResult {
        for layer in &self.delta_layers_newest_first {
            if let Some(location) = layer.delta.get(key) {
                return LookupResult {
                    location: Some(location),
                    runs_searched: 0,
                    runs_filtered: 0,
                    answered_by_delta: true,
                };
            }
        }

        let mut result = LookupResult::default();
        for run in &self.sealed_runs_newest_first {
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

    pub fn get(&self, key: &IndexKey) -> Option<IndexLocation> {
        self.lookup(key).location
    }

    fn with_subtree(&self, subtree: &ShardSubtree) -> Self {
        let mut next = self.clone();
        if let Some(sealed_through) = subtree.sealed_through_shard_sequence {
            next.delta_layers_newest_first.retain(|layer| {
                layer.shard_index != subtree.shard_index
                    || layer.through_shard_sequence > sealed_through
            });
        }
        let delta_is_sealed = subtree
            .sealed_through_shard_sequence
            .is_some_and(|sealed_through| sealed_through >= subtree.shard_committed_sequence);
        if !delta_is_sealed && !subtree.index_delta.is_empty() {
            next.delta_layers_newest_first
                .push_front(IndexDeltaLayer::new(
                    subtree.shard_index,
                    subtree.shard_committed_sequence,
                    Arc::clone(&subtree.index_delta),
                ));
        }
        // `subtree` is already newest-first. Pushing from its back preserves
        // that order at the front of the composed stack.
        for run in subtree.sealed_runs_newest_first.iter().rev() {
            next.sealed_runs_newest_first.push_front(Arc::clone(run));
        }
        next
    }
}

pub type RepoMap = HashMap<NamespaceId, Arc<RepoState>>;
pub type TerminalStatusMap = HashMap<OperationKey, TerminalStatusEntry>;
pub type ShardSequenceMap = HashMap<u16, u64>;
pub type GenerationMap = HashMap<GenerationId, Arc<RetainedGeneration>>;

/// The immutable visibility boundary for all committed reads.
#[derive(Clone, Debug, Default)]
pub struct CommittedRoot {
    repositories: RepoMap,
    index: LayeredObjectIndex,
    terminal_statuses: TerminalStatusMap,
    shard_committed_sequences: ShardSequenceMap,
    retained_generations: GenerationMap,
}

impl CommittedRoot {
    pub fn new(
        repositories: RepoMap,
        index: LayeredObjectIndex,
        terminal_statuses: TerminalStatusMap,
        shard_committed_sequences: ShardSequenceMap,
        retained_generations: GenerationMap,
    ) -> Self {
        Self {
            repositories,
            index,
            terminal_statuses,
            shard_committed_sequences,
            retained_generations,
        }
    }

    pub fn repositories(&self) -> &RepoMap {
        &self.repositories
    }

    pub fn repo(&self, namespace: &NamespaceId) -> Option<&Arc<RepoState>> {
        self.repositories.get(namespace)
    }

    pub fn index(&self) -> &LayeredObjectIndex {
        &self.index
    }

    pub fn terminal_statuses(&self) -> &TerminalStatusMap {
        &self.terminal_statuses
    }

    pub fn terminal_status(&self, key: &OperationKey) -> Option<&TerminalStatusEntry> {
        self.terminal_statuses.get(key)
    }

    pub fn shard_committed_sequences(&self) -> &ShardSequenceMap {
        &self.shard_committed_sequences
    }

    pub fn shard_committed_sequence(&self, shard_index: u16) -> Option<u64> {
        self.shard_committed_sequences.get(&shard_index).copied()
    }

    pub fn retained_generations(&self) -> &GenerationMap {
        &self.retained_generations
    }

    /// Reference proof used by finalized-staging cleanup.
    ///
    /// The answer comes from the captured committed root's live generation
    /// ownership, never from staging's mutable bookkeeping.
    pub fn references_path(&self, path: &Path) -> bool {
        self.retained_generations
            .values()
            .any(|generation| generation.references_path(path))
    }

    /// Staging-facing spelling of [`Self::references_path`].
    pub fn references_artifact(&self, path: &Path) -> bool {
        self.references_path(path)
    }

    pub fn references_generation(&self, id: GenerationId) -> bool {
        self.retained_generations.contains_key(&id)
    }

    /// Resolve a replayed active-tail index generation to its retained pin.
    pub fn retained_tail(
        &self,
        shard_index: u16,
        logical_generation: u64,
    ) -> Option<&RetainedTail> {
        self.retained_generations
            .values()
            .filter(|generation| generation.id.shard_index == shard_index)
            .find_map(|generation| generation.retained_tail(logical_generation))
    }

    /// Resolve a sealed-run index generation to its retained segment pin.
    pub fn retained_segment(
        &self,
        shard_index: u16,
        logical_generation: u64,
    ) -> Option<&RetainedSegment> {
        self.retained_generations
            .values()
            .filter(|generation| generation.id.shard_index == shard_index)
            .find_map(|generation| generation.retained_segment(logical_generation))
    }

    /// Resolve an adopted projection generation to its retained artifact.
    pub fn retained_projection_artifact(
        &self,
        shard_index: u16,
        logical_generation: u64,
    ) -> Option<&RetainedProjectionArtifact> {
        self.retained_generations
            .values()
            .filter(|generation| generation.id.shard_index == shard_index)
            .find_map(|generation| generation.retained_projection_artifact(logical_generation))
    }

    /// Resolve the decoder and live pin for an index location.
    ///
    /// A logical generation may be retained by several manifest generations,
    /// but every occurrence must name the same path and source kind. A
    /// segment/chunk collision is corruption, never an arbitrary lookup
    /// preference.
    pub fn object_source(
        &self,
        shard_index: u16,
        logical_generation: u64,
    ) -> Result<Option<RetainedObjectSource<'_>>, StoreError> {
        let mut found: Option<RetainedObjectSource<'_>> = None;
        for generation in self
            .retained_generations
            .values()
            .filter(|generation| generation.id.shard_index == shard_index)
        {
            let candidates = [
                generation
                    .retained_segment(logical_generation)
                    .map(RetainedObjectSource::Segment),
                generation
                    .retained_tail(logical_generation)
                    .map(RetainedObjectSource::ActiveTail),
                generation
                    .retained_projection_artifact(logical_generation)
                    .map(RetainedObjectSource::ProjectionArtifact),
            ];
            for candidate in candidates.into_iter().flatten() {
                if let Some(existing) = found {
                    if std::mem::discriminant(&existing) != std::mem::discriminant(&candidate)
                        || existing.path() != candidate.path()
                    {
                        return Err(StoreError::Corruption(format!(
                            "shard {shard_index} generation {logical_generation} names \
                             multiple object sources"
                        )));
                    }
                } else {
                    found = Some(candidate);
                }
            }
        }
        Ok(found)
    }

    /// Purely merge one fenced shard publication into this root.
    ///
    /// Reapplying a subtree whose shard sequence is already present is a
    /// no-op. This makes the CAS retry path idempotent in effect while still
    /// allowing a subtree from another shard to merge against a newer root.
    /// No object reachable through `self` is mutated.
    pub fn merge(&self, subtree: &ShardSubtree) -> CommittedRoot {
        if self
            .shard_committed_sequence(subtree.shard_index)
            .is_some_and(|published| published >= subtree.shard_committed_sequence)
        {
            return self.clone();
        }

        let mut repositories = self.repositories.clone();
        for (namespace, state) in &subtree.repositories {
            repositories.insert(*namespace, Arc::clone(state));
        }

        let mut terminal_statuses = self.terminal_statuses.clone();
        for key in &subtree.terminal_status_removals {
            terminal_statuses.remove(key);
        }
        for (key, status) in &subtree.terminal_statuses {
            terminal_statuses.insert(*key, status.clone());
        }

        let mut shard_committed_sequences = self.shard_committed_sequences.clone();
        shard_committed_sequences.insert(subtree.shard_index, subtree.shard_committed_sequence);

        let mut retained_generations = self.retained_generations.clone();
        for id in &subtree.retained_generation_removals {
            retained_generations.remove(id);
        }
        for (id, generation) in &subtree.retained_generations {
            retained_generations.insert(*id, Arc::clone(generation));
        }

        Self {
            repositories,
            index: self.index.with_subtree(subtree),
            terminal_statuses,
            shard_committed_sequences,
            retained_generations,
        }
    }
}

/// Complete immutable output of one fenced group, before root merge.
#[derive(Clone, Debug)]
pub struct ShardSubtree {
    pub shard_index: u16,
    pub shard_committed_sequence: u64,
    pub index_delta: Arc<IndexDelta>,
    /// When present, the newly installed sealed runs cover every delta layer
    /// from this shard through the named sequence, including this subtree's
    /// delta when the value reaches `shard_committed_sequence`.
    pub sealed_through_shard_sequence: Option<u64>,
    /// Any newly installed runs, newest-first. Most groups leave this empty.
    pub sealed_runs_newest_first: Vector<Arc<IndexRun>>,
    pub repositories: RepoMap,
    /// Terminal rows whose tombstone horizon has ended. Removals are applied
    /// before replacements, which keeps retrying the same subtree idempotent.
    pub terminal_status_removals: Vector<OperationKey>,
    pub terminal_statuses: TerminalStatusMap,
    /// Generation pins released by the same publication after every newer
    /// root/index reference has been installed.
    pub retained_generation_removals: Vector<GenerationId>,
    pub retained_generations: GenerationMap,
}

impl ShardSubtree {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        shard_index: u16,
        shard_committed_sequence: u64,
        index_delta: Arc<IndexDelta>,
        sealed_through_shard_sequence: Option<u64>,
        sealed_runs_newest_first: Vector<Arc<IndexRun>>,
        repositories: RepoMap,
        terminal_statuses: TerminalStatusMap,
        retained_generations: GenerationMap,
    ) -> Self {
        Self {
            shard_index,
            shard_committed_sequence,
            index_delta,
            sealed_through_shard_sequence,
            sealed_runs_newest_first,
            repositories,
            terminal_status_removals: Vector::new(),
            terminal_statuses,
            retained_generation_removals: Vector::new(),
            retained_generations,
        }
    }
}

/// Phase stored in the bounded transient status root.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StatusPhase {
    Pending(PendingPhase),
    Resolving,
}

/// One transient operation reservation.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StatusEntry {
    pub operation_digest: ObjectId,
    pub retry_until_micros: i64,
    pub phase: StatusPhase,
    pub shard_sequence: Option<u64>,
}

impl StatusEntry {
    pub fn pending(
        operation_digest: ObjectId,
        retry_until_micros: i64,
        phase: PendingPhase,
    ) -> Self {
        Self {
            operation_digest,
            retry_until_micros,
            phase: StatusPhase::Pending(phase),
            shard_sequence: None,
        }
    }

    pub fn resolving(
        operation_digest: ObjectId,
        retry_until_micros: i64,
        shard_sequence: Option<u64>,
    ) -> Self {
        Self {
            operation_digest,
            retry_until_micros,
            phase: StatusPhase::Resolving,
            shard_sequence,
        }
    }

    pub fn transaction_status(self) -> TransactionStatus {
        match self.phase {
            StatusPhase::Pending(phase) => TransactionStatus::Pending {
                operation_digest: self.operation_digest,
                retry_until_micros: self.retry_until_micros,
                phase,
            },
            StatusPhase::Resolving => TransactionStatus::Resolving {
                operation_digest: self.operation_digest,
                retry_until_micros: self.retry_until_micros,
                shard_sequence: self.shard_sequence,
            },
        }
    }
}

/// Result of atomically reconsidering a reservation against one status root.
///
/// The engine reruns this operation after an `ArcSwap` CAS failure. Existing
/// IDs are examined before the capacity bound, preserving attachment and
/// mismatch semantics under overload.
#[derive(Clone, Debug)]
pub enum StatusReservation {
    Attached(StatusEntry),
    OperationIdMismatch {
        existing_digest: ObjectId,
        submitted_digest: ObjectId,
    },
    AtCapacity {
        limit: u64,
    },
    Inserted(OperationStatusRoot),
}

/// Observable capacity metrics for the status-root CAS owner.
///
/// These counters deliberately live beside, not inside, the immutable root.
/// The engine records occupancy only after a successful CAS and records a
/// rejection only after the retry loop reaches a final `AtCapacity` result;
/// speculative CAS attempts therefore cannot inflate either value.
#[derive(Debug, Default)]
pub struct OperationStatusMetrics {
    occupancy: AtomicU64,
    rejections: AtomicU64,
}

impl OperationStatusMetrics {
    pub fn record_published(&self, root: &OperationStatusRoot) {
        self.occupancy.store(root.len() as u64, Ordering::Relaxed);
    }

    pub fn record_rejection(&self) {
        self.rejections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> OperationStatusMetricSnapshot {
        OperationStatusMetricSnapshot {
            occupancy: self.occupancy.load(Ordering::Relaxed),
            rejections: self.rejections.load(Ordering::Relaxed),
        }
    }
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct OperationStatusMetricSnapshot {
    pub occupancy: u64,
    pub rejections: u64,
}

/// Bounded immutable map of operations that have not reached terminal state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationStatusRoot {
    entries: HashMap<OperationKey, StatusEntry>,
    max_entries: u64,
}

impl OperationStatusRoot {
    pub fn new(max_entries: u64) -> Self {
        assert!(
            max_entries > 0,
            "max_status_entries is validated as nonzero at startup"
        );
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    pub fn entries(&self) -> &HashMap<OperationKey, StatusEntry> {
        &self.entries
    }

    pub fn get(&self, key: &OperationKey) -> Option<&StatusEntry> {
        self.entries.get(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn max_entries(&self) -> u64 {
        self.max_entries
    }

    /// Reconsider and, when possible, immutably insert one reservation.
    ///
    /// The caller must publish an `Inserted` root with CAS and retry this
    /// method on contention. That retry is what makes the bound and insertion
    /// atomic under concurrent reservations.
    pub fn reserve(&self, key: OperationKey, entry: StatusEntry) -> StatusReservation {
        if let Some(existing) = self.entries.get(&key).copied() {
            if existing.operation_digest == entry.operation_digest {
                return StatusReservation::Attached(existing);
            }
            return StatusReservation::OperationIdMismatch {
                existing_digest: existing.operation_digest,
                submitted_digest: entry.operation_digest,
            };
        }

        if self.entries.len() as u64 >= self.max_entries {
            return StatusReservation::AtCapacity {
                limit: self.max_entries,
            };
        }

        let mut entries = self.entries.clone();
        entries.insert(key, entry);
        StatusReservation::Inserted(Self {
            entries,
            max_entries: self.max_entries,
        })
    }

    /// Replace an already reserved entry without applying the admission
    /// bound. In particular, a transition to `Resolving` can never be evicted
    /// or refused because unrelated entries filled the root afterward.
    pub fn replace_existing(&self, key: OperationKey, entry: StatusEntry) -> Option<Self> {
        let existing = self.entries.get(&key)?;
        if existing.operation_digest != entry.operation_digest {
            return None;
        }
        let mut entries = self.entries.clone();
        entries.insert(key, entry);
        Some(Self {
            entries,
            max_entries: self.max_entries,
        })
    }

    pub fn without(&self, key: &OperationKey) -> Self {
        let mut entries = self.entries.clone();
        entries.remove(key);
        Self {
            entries,
            max_entries: self.max_entries,
        }
    }

    pub fn without_all<'a>(&self, keys: impl IntoIterator<Item = &'a OperationKey>) -> Self {
        let mut entries = self.entries.clone();
        for key in keys {
            entries.remove(key);
        }
        Self {
            entries,
            max_entries: self.max_entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::{IndexKey, IndexLocation};

    fn id(byte: u8) -> ObjectId {
        ObjectId([byte; 32])
    }

    fn namespace(byte: u8) -> NamespaceId {
        NamespaceId([byte; 32])
    }

    fn operation(byte: u8) -> OperationId {
        OperationId([byte; 16])
    }

    fn repo(sequence: u64) -> Arc<RepoState> {
        Arc::new(RepoState {
            repo_sequence: sequence,
            current_authority: id(1),
            genesis_authority: id(2),
            refs: TypedRefMap::new(),
            lifecycle: NamespaceLifecycle::Active,
            storage_mode: NamespaceStorageMode::Full,
            previous_event_digest: id(3),
        })
    }

    fn delta(namespace: NamespaceId, object: ObjectId, location: IndexLocation) -> Arc<IndexDelta> {
        let mut delta = IndexDelta::new(100, 1 << 20);
        delta
            .insert(IndexKey::new(namespace, object), location)
            .expect("insert");
        Arc::new(delta)
    }

    fn subtree(
        shard: u16,
        shard_sequence: u64,
        namespace: NamespaceId,
        repo_sequence: u64,
        index_delta: Arc<IndexDelta>,
    ) -> ShardSubtree {
        let mut repositories = RepoMap::new();
        repositories.insert(namespace, repo(repo_sequence));
        ShardSubtree::new(
            shard,
            shard_sequence,
            index_delta,
            None,
            Vector::new(),
            repositories,
            TerminalStatusMap::new(),
            GenerationMap::new(),
        )
    }

    #[test]
    fn duplicate_subtree_is_idempotent_in_effect() {
        let ns = namespace(1);
        let object = id(7);
        let location = IndexLocation {
            segment_generation: 3,
            frame_offset: 40,
            frame_len: 50,
            object_type: 1,
            shard_sequence: 9,
        };
        let mut subtree = subtree(0, 9, ns, 1, delta(ns, object, location));
        let key = OperationKey::new(ns, operation(4));
        subtree.terminal_statuses.insert(
            key,
            TerminalStatusEntry::Expired(ReceiptTombstone {
                operation_digest: id(8),
                retry_until_micros: 100,
                tombstone_until_micros: 200,
            }),
        );

        let once = CommittedRoot::default().merge(&subtree);
        let twice = once.merge(&subtree);

        assert_eq!(twice.repositories().len(), 1);
        assert_eq!(twice.terminal_statuses().len(), 1);
        assert_eq!(twice.index().delta_layer_count(), 1);
        assert_eq!(twice.shard_committed_sequence(0), Some(9));
        assert_eq!(
            twice.index().get(&IndexKey::new(ns, object)),
            Some(location)
        );
    }

    #[test]
    fn subtree_can_prune_terminal_rows_without_rebuilding_the_table() {
        let ns = namespace(1);
        let removed = OperationKey::new(ns, operation(4));
        let retained = OperationKey::new(ns, operation(5));
        let mut statuses = TerminalStatusMap::new();
        for key in [removed, retained] {
            statuses.insert(
                key,
                TerminalStatusEntry::Expired(ReceiptTombstone {
                    operation_digest: id(key.operation_id.0[0]),
                    retry_until_micros: 100,
                    tombstone_until_micros: 200,
                }),
            );
        }
        let root = CommittedRoot::new(
            RepoMap::new(),
            LayeredObjectIndex::default(),
            statuses,
            ShardSequenceMap::new(),
            GenerationMap::new(),
        );
        let mut prune = subtree(0, 1, ns, 1, Arc::new(IndexDelta::new(10, 1024)));
        prune.terminal_status_removals.push_back(removed);

        let merged = root.merge(&prune);
        assert!(merged.terminal_status(&removed).is_none());
        assert!(merged.terminal_status(&retained).is_some());
    }

    #[test]
    fn concurrent_shards_merge_without_losing_the_other_subtree() {
        let ns_a = namespace(1);
        let ns_b = namespace(2);
        let empty_a = Arc::new(IndexDelta::new(10, 1024));
        let empty_b = Arc::new(IndexDelta::new(10, 1024));
        let a = subtree(0, 4, ns_a, 4, empty_a);
        let b = subtree(1, 8, ns_b, 7, empty_b);

        let after_a = CommittedRoot::default().merge(&a);
        let after_b_retry = after_a.merge(&b);

        assert_eq!(after_b_retry.repo(&ns_a).unwrap().repo_sequence, 4);
        assert_eq!(after_b_retry.repo(&ns_b).unwrap().repo_sequence, 7);
        assert_eq!(after_b_retry.shard_committed_sequence(0), Some(4));
        assert_eq!(after_b_retry.shard_committed_sequence(1), Some(8));
    }

    #[test]
    fn sealed_publication_discards_only_covered_layers_from_its_shard() {
        let ns_a = namespace(1);
        let ns_b = namespace(2);
        let a = subtree(
            0,
            1,
            ns_a,
            1,
            delta(
                ns_a,
                id(10),
                IndexLocation {
                    segment_generation: 1,
                    frame_offset: 1,
                    frame_len: 1,
                    object_type: 1,
                    shard_sequence: 1,
                },
            ),
        );
        let b = subtree(
            1,
            1,
            ns_b,
            1,
            delta(
                ns_b,
                id(11),
                IndexLocation {
                    segment_generation: 1,
                    frame_offset: 2,
                    frame_len: 1,
                    object_type: 1,
                    shard_sequence: 1,
                },
            ),
        );
        let root = CommittedRoot::default().merge(&a).merge(&b);
        assert_eq!(root.index().delta_layer_count(), 2);

        let mut seal = subtree(0, 2, ns_a, 2, Arc::new(IndexDelta::new(10, 1024)));
        seal.sealed_through_shard_sequence = Some(2);
        let sealed = root.merge(&seal);

        assert_eq!(sealed.index().delta_layer_count(), 1);
        let survivor = sealed.index().delta_layers().front().unwrap();
        assert_eq!(survivor.shard_index, 1);
    }

    #[test]
    fn untouched_repository_arc_is_shared_across_merge() {
        let untouched_namespace = namespace(1);
        let changed_namespace = namespace(2);
        let untouched = repo(5);
        let mut repositories = RepoMap::new();
        repositories.insert(untouched_namespace, Arc::clone(&untouched));
        let root = CommittedRoot::new(
            repositories,
            LayeredObjectIndex::default(),
            TerminalStatusMap::new(),
            ShardSequenceMap::new(),
            GenerationMap::new(),
        );
        let update = subtree(
            1,
            1,
            changed_namespace,
            1,
            Arc::new(IndexDelta::new(10, 1024)),
        );

        let merged = root.merge(&update);
        assert!(Arc::ptr_eq(
            merged.repo(&untouched_namespace).unwrap(),
            &untouched
        ));
    }

    #[test]
    fn status_reservation_checks_identity_before_capacity() {
        let ns = namespace(1);
        let key = OperationKey::new(ns, operation(1));
        let entry = StatusEntry::pending(id(1), 100, PendingPhase::Queued);
        let root = match OperationStatusRoot::new(1).reserve(key, entry) {
            StatusReservation::Inserted(root) => root,
            other => panic!("expected insertion, got {other:?}"),
        };

        assert!(matches!(
            root.reserve(key, entry),
            StatusReservation::Attached(found) if found == entry
        ));
        assert!(matches!(
            root.reserve(key, StatusEntry::pending(id(2), 100, PendingPhase::Queued)),
            StatusReservation::OperationIdMismatch { .. }
        ));
        assert!(matches!(
            root.reserve(
                OperationKey::new(ns, operation(2)),
                StatusEntry::pending(id(3), 100, PendingPhase::Queued)
            ),
            StatusReservation::AtCapacity { limit: 1 }
        ));
    }

    #[test]
    fn resolving_transition_is_not_subject_to_the_capacity_bound() {
        let ns = namespace(1);
        let key = OperationKey::new(ns, operation(1));
        let root = match OperationStatusRoot::new(1).reserve(
            key,
            StatusEntry::pending(id(1), 100, PendingPhase::Sequenced),
        ) {
            StatusReservation::Inserted(root) => root,
            other => panic!("expected insertion, got {other:?}"),
        };

        let resolving = StatusEntry::resolving(id(1), 100, Some(9));
        let root = root
            .replace_existing(key, resolving)
            .expect("existing reservations transition despite full capacity");
        assert_eq!(root.get(&key), Some(&resolving));
    }

    #[test]
    fn status_metrics_observe_only_final_publications_and_rejections() {
        let metrics = OperationStatusMetrics::default();
        let root = OperationStatusRoot::new(1);
        metrics.record_published(&root);
        metrics.record_rejection();
        metrics.record_rejection();
        assert_eq!(
            metrics.snapshot(),
            OperationStatusMetricSnapshot {
                occupancy: 0,
                rejections: 2,
            }
        );
    }

    #[test]
    fn retained_generation_reference_proof_uses_the_committed_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        let segment_path = temp.path().join("1-1-1.seg");
        let tail_path = temp.path().join("2.journal");
        let projection_path = temp.path().join("3.stage-chunk");
        std::fs::write(&segment_path, b"segment").expect("write");
        std::fs::write(&tail_path, b"tail").expect("write");
        std::fs::write(&projection_path, b"projection").expect("write");
        let pinned = RetainedSegment::new(
            1,
            [7; 16],
            1,
            1,
            PinnedFile::open(segment_path.clone()).expect("pin"),
        );
        let tail = RetainedTail::new(
            2,
            PinnedFile::open(tail_path.clone()).expect("pin active tail"),
        );
        let generation = Arc::new(RetainedGeneration::new(
            GenerationId::new(0, 1),
            Arc::from([pinned]),
            Arc::from([]),
            Arc::from([]),
            Arc::from([tail]),
            Arc::from([RetainedProjectionArtifact::new(
                3,
                ProjectionArtifactFormat::CanonicalStageChunkV1,
                PinnedFile::open(projection_path.clone()).expect("pin projection artifact"),
            )]),
        ));
        let mut generations = GenerationMap::new();
        generations.insert(generation.id, generation);
        let root = CommittedRoot::new(
            RepoMap::new(),
            LayeredObjectIndex::default(),
            TerminalStatusMap::new(),
            ShardSequenceMap::new(),
            generations,
        );

        assert!(root.references_path(&segment_path));
        assert!(root.references_path(&tail_path));
        assert!(root.references_path(&projection_path));
        assert!(root.references_generation(GenerationId::new(0, 1)));
        assert_eq!(
            root.retained_tail(0, 2).map(RetainedTail::path),
            Some(tail_path.as_path())
        );
        assert_eq!(
            root.retained_segment(0, 1).map(RetainedSegment::path),
            Some(segment_path.as_path())
        );
        assert_eq!(
            root.retained_projection_artifact(0, 3)
                .map(RetainedProjectionArtifact::path),
            Some(projection_path.as_path())
        );
        assert!(matches!(
            root.object_source(0, 3).expect("unambiguous source"),
            Some(RetainedObjectSource::ProjectionArtifact(_))
        ));
        assert!(root.retained_tail(1, 2).is_none());
        assert!(root.retained_segment(1, 1).is_none());
        assert!(!root.references_path(&temp.path().join("unreferenced.seg")));
    }
}
