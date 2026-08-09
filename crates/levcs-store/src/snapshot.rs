//! `RepoSnapshot`: an immutable committed repository view sharing persistent
//! substructures with the committed root.
//!
//! **Shared file.** Lead owns the signatures (D0); **B1 NamespaceTxn** fills
//! the bodies (scope 2.1, 6-B1).
//!
//! A snapshot must not clone the index; plan §5.1 requires reads to retain the
//! committed generation and share structure, so a snapshot is cheap enough to
//! take per request.
//!
//! # What a capture costs, and why that is a correctness property
//!
//! Capturing is two `Arc` clones and one hash lookup. It is not "fast because
//! the maps are small" — it is O(1) in the number of objects, namespaces, and
//! generations the root holds, and `snapshot_capture_allocates_nothing` below
//! measures it as a byte figure rather than asserting it in a comment. §5.3
//! makes this correctness and not performance: a per-request read that copied
//! the index would make the index's size a per-request cost, and the read path
//! would degrade as the store filled rather than at a bound anyone configured.
//!
//! # What holding one guarantees
//!
//! An `ObjectLocation` names a physical place — a generation, an offset, a
//! length. That is only answerable while the artifact carrying it is still on
//! disk, and compaction is entitled to remove artifacts no committed root
//! references. Retaining the whole `CommittedRoot` is what closes that: every
//! `RetainedGeneration` behind every location this snapshot can return is
//! pinned for as long as the snapshot lives, so a reader cannot be handed an
//! offset into a segment that is deleted before it reads.

use std::sync::Arc;

use levcs_core::{ObjectId, ObjectType};

use crate::index::{IndexKey, NamespaceLifecycle, NamespaceStorageMode};
use crate::roots::{CommittedRoot, RepoState, RetainedObjectSource};
use crate::types::{NamespaceId, StoreError};

/// One repository's committed logical state at one generation.
pub struct RepoSnapshot {
    /// The whole visibility boundary, retained — see the module note on what
    /// holding it guarantees. Capturing it is one atomic increment and never a
    /// traversal.
    root: Arc<CommittedRoot>,
    namespace: NamespaceId,
    /// The shard this namespace routes to, which is the space its logical
    /// generation numbers are unique within. Carried so
    /// [`RepoSnapshot::object_source`] can resolve a location without the
    /// caller re-deriving the routing.
    shard_index: u16,
    /// Resolved once, at capture. `RepoMap` holds each `RepoState` behind its
    /// own `Arc`, so this shares that allocation rather than copying the refs
    /// map, and it takes the hash lookup off every accessor below.
    ///
    /// Resolving it eagerly is also what makes the accessors total: a
    /// `RepoSnapshot` that exists at all has a `RepoState`, so `repo_sequence`
    /// and the two authorities have something to return without an `Option`
    /// the frozen signatures do not have.
    state: Arc<RepoState>,
}

/// Deliberately hand-written and deliberately small. A derived `Debug` would
/// reach through the retained `CommittedRoot` and render the entire index, so
/// one stray `{:?}` in a read path would serialize the store into a log line.
/// What identifies a snapshot is which repository it is of and which
/// generation it caught, and that is what this prints.
impl std::fmt::Debug for RepoSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoSnapshot")
            .field("namespace", &self.namespace)
            .field("repo_sequence", &self.state.repo_sequence)
            .field("lifecycle", &self.state.lifecycle)
            .finish_non_exhaustive()
    }
}

/// Where an object lives, for a reader holding a snapshot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ObjectLocation {
    pub segment_generation: u64,
    pub offset: u64,
    pub len: u64,
    pub object_type: ObjectType,
    pub shard_sequence: u64,
}

impl RepoSnapshot {
    /// Capture `namespace` against `root`.
    ///
    /// The absent-repository rule lives here rather than at the call site so
    /// that every way of obtaining a snapshot obeys it, and so that the
    /// invariant the accessors depend on — a live `RepoSnapshot` always has a
    /// `RepoState` — is established by the only constructor.
    ///
    /// Contract review 2026-08-07-A: an unbound namespace is
    /// `StoreError::NoSuchRepository`, an inability to answer. A namespace
    /// that is bound and retired is a lifecycle, is reported through
    /// [`RepoSnapshot::lifecycle`], and is captured normally — refusing it
    /// here would make a deleted repository indistinguishable from one that
    /// never existed, and the two have different answers to every question
    /// below.
    ///
    /// `shard_index` is supplied rather than derived because deriving it needs
    /// the shard count, which lives in [`crate::StoreOptions`] and not in the
    /// root. It is well defined for a snapshot: a namespace routes to exactly
    /// one shard, so every frame and every index entry it owns lives in that
    /// shard's generations.
    pub(crate) fn capture(
        root: Arc<CommittedRoot>,
        namespace: NamespaceId,
        shard_index: u16,
    ) -> Result<Self, StoreError> {
        let Some(state) = root.repo(&namespace) else {
            return Err(StoreError::NoSuchRepository { namespace });
        };
        let state = Arc::clone(state);
        Ok(Self {
            root,
            namespace,
            shard_index,
            state,
        })
    }

    pub fn namespace(&self) -> NamespaceId {
        self.namespace
    }

    /// The logical federation cursor value, never the physical
    /// `shard_sequence` (plan §4 transaction invariant 8).
    pub fn repo_sequence(&self) -> u64 {
        self.state.repo_sequence
    }

    pub fn current_authority(&self) -> ObjectId {
        self.state.current_authority
    }

    pub fn genesis_authority(&self) -> ObjectId {
        self.state.genesis_authority
    }

    /// Whether this repository is `Active`, `ReadOnly`, or `Deleted` at the
    /// captured generation.
    ///
    /// Added by contract review 2026-08-07-A. Without it a reader holding a
    /// snapshot cannot tell a live repository from a retired one, and §4 makes
    /// that distinction observable; `NoSuchRepository` deliberately does not
    /// cover it, because a retired repository still has a state and still
    /// answers every other question here.
    pub fn lifecycle(&self) -> NamespaceLifecycle {
        self.state.lifecycle
    }

    /// Added by contract review 2026-08-07-A, for the same reason as
    /// [`RepoSnapshot::lifecycle`].
    pub fn storage_mode(&self) -> NamespaceStorageMode {
        self.state.storage_mode
    }

    /// Locate an object *within this namespace*. Namespace membership, not
    /// global object existence, controls reads: identical bytes in private
    /// repository A do not make an object readable through repository B
    /// (plan §4 resource invariants).
    ///
    /// The isolation is structural rather than checked: [`IndexKey`] has no
    /// constructor that omits a namespace, so the only key this can build is
    /// one scoped to `self.namespace`. There is no branch here that a future
    /// edit could invert.
    ///
    /// `Ok(None)` is "this namespace does not contain that object" and is not
    /// a statement about whether the object exists anywhere in the store —
    /// answering the second question is precisely what the invariant forbids.
    pub fn locate(&self, id: ObjectId) -> Result<Option<ObjectLocation>, StoreError> {
        let Some(location) = self.root.index().get(&IndexKey::new(self.namespace, id)) else {
            return Ok(None);
        };

        // The index stores the type as a code because the packed run format is
        // bytes; the frozen `ObjectLocation` hands back a typed value. An
        // undefined code is not a missing object and must not be reported as
        // one: the entry was written by this store, so a code no version of it
        // ever assigned means the run or the delta behind it is damaged.
        let object_type = ObjectType::from_u8(location.object_type).map_err(|_| {
            StoreError::Corruption(format!(
                "index entry for object {} in namespace {} carries object type code {}, \
                 which names no defined object type; the index run or delta holding it \
                 is damaged",
                hex::encode(id.0),
                self.namespace.to_hex(),
                location.object_type,
            ))
        })?;

        Ok(Some(ObjectLocation {
            segment_generation: location.segment_generation,
            offset: location.frame_offset,
            len: u64::from(location.frame_len),
            object_type,
            shard_sequence: location.shard_sequence,
        }))
    }

    /// Resolve a location's decoder and live pin.
    ///
    /// [`Self::locate`] answers *which generation*, which is not enough to read
    /// anything: a logical generation is a segment, an active journal tail, or
    /// an adopted projection artifact, and the three are different files in
    /// different formats. Before adoption existed every location a reader could
    /// hold was a frame in this shard's journal, so the distinction was
    /// invisible and the generation number alone was serviceable. An adopted
    /// object is indexed at its artifact's generation and its bytes are not in
    /// the frame that installed it, so answering "where" without answering
    /// "what kind" is now an answer a reader cannot act on.
    ///
    /// `Ok(None)` means no retained generation in this shard claims that
    /// number. For a location this snapshot just produced that is corruption in
    /// waiting, not an ordinary absence — but it is reported the same way the
    /// root reports it, because the root is what decides retention and this is
    /// a view onto the root, not a second opinion about it.
    pub fn object_source(
        &self,
        location: &ObjectLocation,
    ) -> Result<Option<RetainedObjectSource<'_>>, StoreError> {
        self.root
            .object_source(self.shard_index, location.segment_generation)
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    use std::sync::Arc;

    use im::Vector;

    use super::*;
    use crate::index::{IndexDelta, IndexLocation};
    use crate::roots::{
        GenerationMap, IndexDeltaLayer, LayeredObjectIndex, RepoMap, ShardSequenceMap,
        TerminalStatusMap, TypedRefMap,
    };

    /// The shard every root below is built in. Nothing here asserts about
    /// generation resolution, so the value only has to be the one constant
    /// these hand-built roots agree on.
    const SHARD: u16 = 0;

    // -----------------------------------------------------------------------
    // A thread-local allocation meter
    // -----------------------------------------------------------------------
    //
    // Scope 6-B1 deliverable 8 asks for "a measured assertion that taking a
    // snapshot allocates no index copy -- a count or a byte figure, not a
    // comment", and for a test that fails if someone clones. Counting bytes
    // through the global allocator is the only form of that which cannot be
    // satisfied by a cheaper clone: `Arc::clone` allocates nothing, and every
    // way of copying an index -- `Vector`, `HashMap`, `Vec<u8>` -- allocates
    // something.
    //
    // The counter is thread-local rather than global because the test binary
    // runs tests in parallel, and a global counter would measure whatever else
    // happened to be allocating at the same moment. That would make this test
    // flaky in the direction that matters least (spurious failure) and, worse,
    // would tempt someone to widen the bound until it stopped failing.

    thread_local! {
        static MEASURING: Cell<bool> = const { Cell::new(false) };
        static ALLOCATED_BYTES: Cell<usize> = const { Cell::new(0) };
    }

    struct MeteredAllocator;

    unsafe impl GlobalAlloc for MeteredAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // `MEASURING` gates the accounting so that the thread-local access
            // itself -- which may allocate on first touch -- cannot recurse
            // into the counter it is trying to update.
            if MEASURING.get() {
                ALLOCATED_BYTES.set(ALLOCATED_BYTES.get() + layout.size());
            }
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: MeteredAllocator = MeteredAllocator;

    /// Bytes allocated on this thread while `body` ran.
    fn allocated_bytes<T>(body: impl FnOnce() -> T) -> (T, usize) {
        // Touch both thread-locals before arming, so their own lazy
        // initialization is never part of the measurement.
        MEASURING.set(false);
        ALLOCATED_BYTES.set(0);
        MEASURING.set(true);
        let value = body();
        MEASURING.set(false);
        (value, ALLOCATED_BYTES.get())
    }

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn namespace(seed: u8) -> NamespaceId {
        NamespaceId::from_bytes([seed; 32])
    }

    fn object(seed: u8) -> ObjectId {
        ObjectId([seed; 32])
    }

    fn repo_state(sequence: u64, lifecycle: NamespaceLifecycle) -> Arc<RepoState> {
        Arc::new(RepoState {
            repo_sequence: sequence,
            current_authority: object(0xc0),
            genesis_authority: object(0x6e),
            refs: TypedRefMap::new(),
            lifecycle,
            storage_mode: NamespaceStorageMode::Full,
            previous_event_digest: object(0xed),
        })
    }

    fn location(object_type: u8) -> IndexLocation {
        IndexLocation {
            segment_generation: 3,
            frame_offset: 4_096,
            frame_len: 512,
            object_type,
            shard_sequence: 7,
        }
    }

    /// A root binding `repos`, with `entries` in a single delta layer.
    fn root_with(
        repos: &[(NamespaceId, Arc<RepoState>)],
        entries: &[(NamespaceId, ObjectId, IndexLocation)],
    ) -> Arc<CommittedRoot> {
        let mut repositories = RepoMap::new();
        for (ns, state) in repos {
            repositories.insert(*ns, Arc::clone(state));
        }

        let mut delta = IndexDelta::new(4_096, 1 << 20);
        for (ns, id, location) in entries {
            delta
                .insert(IndexKey::new(*ns, *id), *location)
                .expect("delta accepts the fixture entries");
        }
        let mut layers = Vector::new();
        layers.push_back(IndexDeltaLayer::new(0, 1, Arc::new(delta)));

        Arc::new(CommittedRoot::new(
            repositories,
            LayeredObjectIndex::new(layers, Vector::new()),
            TerminalStatusMap::new(),
            ShardSequenceMap::new(),
            GenerationMap::new(),
        ))
    }

    // -----------------------------------------------------------------------
    // Capture
    // -----------------------------------------------------------------------

    #[test]
    fn capture_reports_the_state_bound_at_the_captured_generation() {
        let ns = namespace(1);
        let root = root_with(&[(ns, repo_state(42, NamespaceLifecycle::Active))], &[]);

        let snapshot = RepoSnapshot::capture(root, ns, SHARD).expect("the namespace is bound");

        assert_eq!(snapshot.namespace(), ns);
        assert_eq!(snapshot.repo_sequence(), 42);
        assert_eq!(snapshot.current_authority(), object(0xc0));
        assert_eq!(snapshot.genesis_authority(), object(0x6e));
        assert_eq!(snapshot.lifecycle(), NamespaceLifecycle::Active);
        assert_eq!(snapshot.storage_mode(), NamespaceStorageMode::Full);
    }

    #[test]
    fn capture_refuses_a_namespace_no_repository_is_bound_for() {
        let bound = namespace(1);
        let unbound = namespace(2);
        let root = root_with(&[(bound, repo_state(1, NamespaceLifecycle::Active))], &[]);

        let error =
            RepoSnapshot::capture(root, unbound, SHARD).expect_err("nothing is bound for it");

        // Asserted by name and by payload: contract review 2026-08-07-A makes
        // the identity part of the error, so a caller can recover what it
        // asked for without parsing the message.
        match error {
            StoreError::NoSuchRepository { namespace } => assert_eq!(namespace, unbound),
            other => panic!("expected NoSuchRepository, got {other:?}"),
        }
    }

    /// The distinction contract review 2026-08-07-A turns on. A retired
    /// repository still has a state and still answers; only an unbound one is
    /// an inability to answer. Refusing both would erase the difference.
    #[test]
    fn a_deleted_repository_captures_and_reports_its_lifecycle() {
        let ns = namespace(1);
        let root = root_with(&[(ns, repo_state(9, NamespaceLifecycle::Deleted))], &[]);

        let snapshot =
            RepoSnapshot::capture(root, ns, SHARD).expect("a retired repository is bound");

        assert_eq!(snapshot.lifecycle(), NamespaceLifecycle::Deleted);
        assert_eq!(snapshot.repo_sequence(), 9);
    }

    // -----------------------------------------------------------------------
    // Namespace isolation
    // -----------------------------------------------------------------------

    #[test]
    fn locate_answers_for_its_own_namespace() {
        let ns = namespace(1);
        let id = object(0xa1);
        let root = root_with(
            &[(ns, repo_state(1, NamespaceLifecycle::Active))],
            &[(ns, id, location(ObjectType::Commit as u8))],
        );

        let found = RepoSnapshot::capture(root, ns, SHARD)
            .expect("bound")
            .locate(id)
            .expect("a defined type code decodes")
            .expect("the entry is in this namespace");

        assert_eq!(
            found,
            ObjectLocation {
                segment_generation: 3,
                offset: 4_096,
                len: 512,
                object_type: ObjectType::Commit,
                shard_sequence: 7,
            }
        );
    }

    /// §7's namespace-isolation exit criterion, at the index-key level:
    /// *identical bytes* in A are not readable through B. The same `ObjectId`
    /// is indexed under both namespaces at deliberately different locations,
    /// so a leak would return B's row rather than nothing and the assertion
    /// distinguishes the two failures.
    #[test]
    fn identical_bytes_in_another_namespace_are_not_readable_through_this_one() {
        let a = namespace(1);
        let b = namespace(2);
        let shared = object(0xa1);
        let only_in_b = object(0xb2);

        let root = root_with(
            &[
                (a, repo_state(1, NamespaceLifecycle::Active)),
                (b, repo_state(1, NamespaceLifecycle::Active)),
            ],
            &[
                (a, shared, location(ObjectType::Blob as u8)),
                (b, shared, location(ObjectType::Tree as u8)),
                (b, only_in_b, location(ObjectType::Blob as u8)),
            ],
        );

        let through_a = RepoSnapshot::capture(Arc::clone(&root), a, SHARD).expect("bound");

        // The object present in both resolves to A's row, not B's.
        let found = through_a
            .locate(shared)
            .expect("decodes")
            .expect("present in A");
        assert_eq!(
            found.object_type,
            ObjectType::Blob,
            "A's snapshot resolved the shared id through B's index row"
        );

        // The object present only in B is invisible through A.
        assert_eq!(
            through_a.locate(only_in_b).expect("decodes"),
            None,
            "an object stored only in B was readable through A"
        );
    }

    #[test]
    fn locate_reports_a_miss_rather_than_an_error() {
        let ns = namespace(1);
        let root = root_with(&[(ns, repo_state(1, NamespaceLifecycle::Active))], &[]);

        assert_eq!(
            RepoSnapshot::capture(root, ns, SHARD)
                .expect("bound")
                .locate(object(0xff))
                .expect("an absent object is not a failure"),
            None
        );
    }

    #[test]
    fn an_undefined_object_type_code_is_corruption_and_not_a_miss() {
        let ns = namespace(1);
        let id = object(0xa1);
        // 0 and 6 are outside `ObjectType`'s 1..=5; no version of this store
        // ever wrote either, so an entry carrying one is damaged.
        let root = root_with(
            &[(ns, repo_state(1, NamespaceLifecycle::Active))],
            &[(ns, id, location(6))],
        );

        let error = RepoSnapshot::capture(root, ns, SHARD)
            .expect("bound")
            .locate(id)
            .expect_err("an undefined type code must not be reported as absence");

        match error {
            StoreError::Corruption(message) => {
                assert!(message.contains("object type code 6"), "{message}");
            }
            other => panic!("expected Corruption, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Scope 6-B1 deliverable 8: the measured no-copy assertion
    // -----------------------------------------------------------------------

    /// *Accept:* "a measured assertion that taking a snapshot allocates no
    /// index copy — a count or a byte figure, not a comment".
    ///
    /// The figure is bytes allocated on this thread across the capture. It is
    /// asserted at exactly zero rather than at a threshold: `Arc::clone` is
    /// two atomic increments and allocates nothing at all, so any nonzero
    /// reading is a structure someone copied, and a threshold would be a
    /// budget for copying rather than a prohibition on it.
    ///
    /// The index is large enough that a clone is unmissable — 4,000 entries
    /// across two namespaces — so this fails loudly if `capture` ever stops
    /// sharing.
    #[test]
    fn snapshot_capture_allocates_nothing() {
        let ns = namespace(1);
        let other = namespace(2);
        let entries: Vec<_> = (0..2_000u32)
            .flat_map(|i| {
                let mut id = [0u8; 32];
                id[..4].copy_from_slice(&i.to_le_bytes());
                [
                    (ns, ObjectId(id), location(ObjectType::Blob as u8)),
                    (other, ObjectId(id), location(ObjectType::Blob as u8)),
                ]
            })
            .collect();
        let root = root_with(
            &[
                (ns, repo_state(1, NamespaceLifecycle::Active)),
                (other, repo_state(1, NamespaceLifecycle::Active)),
            ],
            &entries,
        );

        // Prove the meter can see a copy at all before trusting it to report
        // zero. A test whose instrument is never shown to move is a test that
        // passes when the instrument is broken.
        //
        // The control materializes the same entry set into a `std` map, which
        // is what copying an index actually costs.
        //
        // **`(*root).clone()` does not work as a control, and neither does
        // cloning the index.** Two earlier versions of this test tried each and
        // both read zero: `CommittedRoot` is built entirely from `im`
        // persistent structures — `im::HashMap`, `im::Vector`, `im::OrdMap` —
        // whose clones are O(1) and allocate nothing. That is the structure
        // sharing §5.3 asks for, working. It also means **a byte figure alone
        // cannot fail on a clone in this crate**, because here a clone *is*
        // sharing; the `Arc::ptr_eq` assertion below is what covers that case,
        // and the byte figure covers materialization. See the carry-forward in
        // scope §6.4 deliverable 8.
        let (copied, copy_bytes) = allocated_bytes(|| {
            entries
                .iter()
                .map(|(ns, id, location)| (IndexKey::new(*ns, *id), *location))
                .collect::<std::collections::HashMap<_, _>>()
        });
        assert!(
            copy_bytes > 0,
            "the allocation meter read zero while materializing a copy of the \
             index, so it cannot be trusted to report zero below"
        );
        drop(copied);

        let (snapshot, capture_bytes) =
            allocated_bytes(|| RepoSnapshot::capture(Arc::clone(&root), ns, SHARD));
        let snapshot = snapshot.expect("bound");

        assert_eq!(
            capture_bytes, 0,
            "capturing a snapshot allocated {capture_bytes} bytes; it must share \
             the committed root's substructures, not copy them (plan §5.3). \
             Copying this root costs {copy_bytes} bytes."
        );

        // The byte figure says nothing was built. This says what was retained
        // is the caller's own root and not an equal one: same allocation, so
        // there is no traversal anywhere behind the capture, whatever the
        // allocator happened to see.
        assert!(
            Arc::ptr_eq(&snapshot.root, &root),
            "the snapshot retained a different CommittedRoot allocation than \
             the one it was given"
        );

        // ...and the shared index still answers, so "allocated nothing" is not
        // "captured nothing".
        let mut id = [0u8; 32];
        id[..4].copy_from_slice(&7u32.to_le_bytes());
        assert!(snapshot.locate(ObjectId(id)).expect("decodes").is_some());
    }

    /// Reads are answered from the generation the snapshot captured, so a
    /// later root cannot change what an existing snapshot returns (plan §5.3:
    /// "readers never observe an index entry newer than their captured root").
    #[test]
    fn a_snapshot_is_unaffected_by_a_later_root() {
        let ns = namespace(1);
        let added_later = object(0xbb);
        let before = root_with(&[(ns, repo_state(1, NamespaceLifecycle::Active))], &[]);
        let snapshot = RepoSnapshot::capture(before, ns, SHARD).expect("bound");

        // A newer root binds the same namespace and indexes a new object.
        let _after = root_with(
            &[(ns, repo_state(2, NamespaceLifecycle::Active))],
            &[(ns, added_later, location(ObjectType::Blob as u8))],
        );

        assert_eq!(snapshot.repo_sequence(), 1);
        assert_eq!(snapshot.locate(added_later).expect("decodes"), None);
    }
}
