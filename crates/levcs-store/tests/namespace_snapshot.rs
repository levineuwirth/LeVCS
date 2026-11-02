//! Scope 6-B1 deliverable 8 and §7's namespace-isolation exit criterion,
//! asserted through the public surface.
//!
//! `snapshot.rs`'s unit tests already assert isolation at the index-key level,
//! against a `CommittedRoot` the test built. This file asserts it against a
//! root **the store built**: every namespace here is created by
//! `StoreEngine::submit`, every object is staged through a real transaction,
//! and every read goes through `StoreEngine::snapshot` and
//! `RepoSnapshot::locate`.
//!
//! That distinction is scope 5 charter item 8 — "assert against the path that
//! runs, not the helper". A hand-built root proves the lookup rule; it cannot
//! prove that the writer files entries under the namespace it was given, which
//! is the half of the isolation property that lives in the write path.
//!
//! The exit criterion says *identical bytes*, so the shared object here is
//! genuinely identical in both repositories: `push_transaction` stages
//! `ObjectId([blob; 32])` with `raw: vec![blob; 64]`, so the same `blob` seed
//! in two namespaces produces the same id over the same bytes. Isolation that
//! held only because the two repositories held different objects would not be
//! isolation at all.

// Gated on all three features because `engine_matrix` arms failpoints and
// reaches `drive.rs`, so it compiles only under the full set. This file needs
// neither, and the alternative was a second copy of the transaction builders
// and the shard-routing search inside a B1-owned test — duplicating a
// B4-owned harness to avoid a feature gate is the worse trade. The Phase 1
// gate runs exactly this combination, so these tests run on every gate run.
#![cfg(all(
    feature = "store-privileged",
    feature = "store-internals",
    feature = "failpoints"
))]

use levcs_core::ObjectId;
use levcs_store::types::{NamespaceId, StoreError};

// Only the submit harness, by path: `support/mod.rs` also carries the crash
// driver's plumbing, and this file needs none of it.
#[path = "support/engine_matrix.rs"]
mod engine_matrix;

use engine_matrix::{
    create_transaction, namespace_on_shard, open_absent_root, push_transaction, submit,
    DEFAULT_MAX_INDEX_RUNS,
};

const SHARD_COUNT: u16 = 2;

/// Present in both repositories, as the same id over the same bytes.
const SHARED_BLOB: u8 = 0x7a;
/// Present only in B.
const ONLY_IN_B_BLOB: u8 = 0x5b;

fn blob_id(seed: u8) -> ObjectId {
    ObjectId([seed; 32])
}

/// Two repositories **on the same shard**, each holding `SHARED_BLOB`; B also
/// holds `ONLY_IN_B_BLOB`.
///
/// Same shard deliberately. Two repositories on different shards write to
/// different journals, seal into different segment-generation spaces, and land
/// in different index deltas, so isolation between them holds by construction
/// and a namespace-blind lookup would still pass. Co-locating them puts both
/// repositories' frames in one journal and both their entries in one index,
/// which is the only arrangement where the namespace component of the key is
/// load-bearing.
fn store_with_two_repositories(
    root: &std::path::Path,
) -> (levcs_store::StoreEngine, NamespaceId, NamespaceId) {
    let engine = open_absent_root(root, SHARD_COUNT, DEFAULT_MAX_INDEX_RUNS);
    let a = namespace_on_shard(0, SHARD_COUNT, 1);
    let b = namespace_on_shard(0, SHARD_COUNT, 2);
    assert_ne!(a, b, "the two repositories must be distinct");

    for (operation, namespace) in [(1u8, a), (2, b)] {
        submit(&engine, create_transaction(namespace, operation))
            .receipt()
            .expect("the repository is created");
    }
    for (operation, namespace, blob) in [
        (3u8, a, SHARED_BLOB),
        (4, b, SHARED_BLOB),
        (5, b, ONLY_IN_B_BLOB),
    ] {
        submit(&engine, push_transaction(namespace, operation, blob))
            .receipt()
            .expect("the push commits");
    }

    (engine, a, b)
}

/// §7: "identical bytes in A not readable through B".
#[test]
fn an_object_stored_only_in_one_repository_is_invisible_through_the_other() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (engine, a, b) = store_with_two_repositories(dir.path());

    let through_a = engine.snapshot(a).expect("A is bound");
    let through_b = engine.snapshot(b).expect("B is bound");

    // The control: B really does hold it, so the assertion below is about
    // visibility and not about a push that silently failed.
    assert!(
        through_b
            .locate(blob_id(ONLY_IN_B_BLOB))
            .expect("a committed object decodes")
            .is_some(),
        "B does not hold the object this test is about; the fixture is wrong, \
         not the store"
    );

    assert_eq!(
        through_a
            .locate(blob_id(ONLY_IN_B_BLOB))
            .expect("a miss is not a failure"),
        None,
        "an object committed only to B was readable through A's snapshot"
    );
}

/// The same bytes committed to both repositories resolve through each, and
/// each answer names its own repository's write.
///
/// This is the case a namespace-blind index would *pass* by accident, so the
/// assertion is on the physical record each answer names. Both repositories sit
/// on one shard, so their frames share a journal and a generation space and the
/// two offsets are directly comparable: A and B were separate transactions, so
/// a snapshot returning the other's row is detectable even though the object id
/// and the staged bytes are identical.
///
/// `(segment_generation, offset)` is compared rather than `segment_generation`
/// alone because generations are **per shard**, not global — the same pair
/// occurs in every shard's journal. That is not ambiguity in `ObjectLocation`:
/// a location is only ever read through a snapshot, and the snapshot's
/// namespace determines the shard. It does mean a cross-shard comparison
/// asserts nothing, which is the other reason these two repositories are
/// co-located.
#[test]
fn identical_bytes_in_both_repositories_resolve_independently() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (engine, a, b) = store_with_two_repositories(dir.path());

    let from_a = engine
        .snapshot(a)
        .expect("A is bound")
        .locate(blob_id(SHARED_BLOB))
        .expect("decodes")
        .expect("A holds it");
    let from_b = engine
        .snapshot(b)
        .expect("B is bound")
        .locate(blob_id(SHARED_BLOB))
        .expect("decodes")
        .expect("B holds it");

    assert_eq!(from_a.object_type, levcs_core::ObjectType::Blob);
    assert_eq!(from_b.object_type, levcs_core::ObjectType::Blob);
    assert_ne!(
        (from_a.segment_generation, from_a.offset),
        (from_b.segment_generation, from_b.offset),
        "both repositories resolved the shared id to the same physical record, \
         so one of them is reading the other's write"
    );
}

/// Contract review 2026-08-07-A, through the entry point a consumer calls.
#[test]
fn snapshot_refuses_a_namespace_no_repository_is_bound_for() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (engine, _a, _b) = store_with_two_repositories(dir.path());
    let never_created = namespace_on_shard(0, SHARD_COUNT, 99);

    match engine.snapshot(never_created) {
        Err(StoreError::NoSuchRepository { namespace }) => {
            assert_eq!(namespace, never_created)
        }
        Err(other) => panic!("expected NoSuchRepository, got {other:?}"),
        Ok(_) => panic!("snapshot returned a view of a repository that was never created"),
    }
}

/// A snapshot is taken against one generation and keeps answering from it, so
/// a later commit cannot change what an already-taken snapshot reports
/// (plan §5.3).
#[test]
fn a_snapshot_does_not_observe_a_commit_that_followed_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (engine, a, _b) = store_with_two_repositories(dir.path());

    let before = engine.snapshot(a).expect("A is bound");
    let sequence_before = before.repo_sequence();

    const LATER: u8 = 0x9c;
    submit(&engine, push_transaction(a, 6, LATER))
        .receipt()
        .expect("the later push commits");

    assert_eq!(
        before.locate(blob_id(LATER)).expect("decodes"),
        None,
        "a snapshot observed an object committed after it was taken"
    );
    assert_eq!(before.repo_sequence(), sequence_before);

    // ...and a snapshot taken now does see it, so the assertion above is about
    // the captured generation and not about a push that never landed.
    assert!(engine
        .snapshot(a)
        .expect("A is bound")
        .locate(blob_id(LATER))
        .expect("decodes")
        .is_some());
}
