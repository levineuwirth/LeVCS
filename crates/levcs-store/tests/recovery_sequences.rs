//! Scope 4-A2 acceptance: recovery step 9, independent shard-sequence and
//! repository-sequence/event-chain verification.
//!
//! Deliverable 4 requires that a shard gap and a repository gap not be
//! reported as the same fault. Here the two verifiers return two unrelated
//! error types, so a test can assert that one passes while the other fails on
//! the same input — which is the only way to demonstrate independence rather
//! than assert it.

#[path = "recovery_reference_frame.rs"]
mod reference;

use levcs_core::ObjectId;
use levcs_store::index::{
    NamespaceCatalog, NamespaceLifecycle, NamespaceRecord, NamespaceStorageMode,
};
use levcs_store::recovery::{
    verify_repo_chain, verify_shard_sequence, FrameFacts, RepoSequenceFault, ShardSequenceFault,
};
use levcs_store::types::{NamespaceId, OperationId};

fn ns(b: u8) -> NamespaceId {
    NamespaceId([b; 32])
}

fn oid(b: u8) -> ObjectId {
    ObjectId([b; 32])
}

fn fact(
    shard_sequence: u64,
    repo_sequence: u64,
    namespace: u8,
    previous_event_digest: ObjectId,
    event_digest: ObjectId,
) -> FrameFacts {
    FrameFacts {
        shard_sequence,
        repo_sequence,
        namespace: ns(namespace),
        operation_id: OperationId([0u8; 16]),
        operation_digest: oid(0),
        event_digest,
        previous_event_digest,
        creates_namespace: false,
        genesis_authority: oid(0xA0),
        current_authority: oid(0xA1),
        retry_until_micros: 0,
        objects: Vec::new(),
    }
}

fn catalog(namespace: u8, repo_sequence: u64, previous: ObjectId) -> NamespaceCatalog {
    let mut catalog = NamespaceCatalog::new();
    catalog
        .bind(NamespaceRecord {
            namespace: ns(namespace),
            genesis_authority: oid(0xA0),
            current_authority: oid(0xA1),
            lifecycle: NamespaceLifecycle::Active,
            storage_mode: NamespaceStorageMode::Full,
            repo_sequence,
            previous_event_digest: previous,
        })
        .expect("bind");
    catalog
}

// ===========================================================================
// The healthy path
// ===========================================================================

#[test]
fn a_well_formed_replay_passes_both_verifiers() {
    let catalog = catalog(1, 4, oid(0x10));
    let facts = [
        fact(100, 5, 1, oid(0x10), oid(0x11)),
        fact(101, 6, 1, oid(0x11), oid(0x12)),
        fact(102, 7, 1, oid(0x12), oid(0x13)),
    ];
    verify_shard_sequence(&facts, 100).expect("contiguous");
    verify_repo_chain(&facts, &catalog).expect("chained");
}

// ===========================================================================
// Shard-sequence duplicate
// ===========================================================================

#[test]
fn a_shard_sequence_duplicate_is_its_own_fault() {
    let facts = [
        fact(100, 5, 1, oid(0x10), oid(0x11)),
        fact(100, 6, 1, oid(0x11), oid(0x12)),
    ];
    assert_eq!(
        verify_shard_sequence(&facts, 100),
        Err(ShardSequenceFault::Duplicate {
            shard_sequence: 100
        })
    );
}

#[test]
fn a_shard_sequence_gap_is_reported_as_a_gap_not_a_duplicate() {
    let facts = [
        fact(100, 5, 1, oid(0x10), oid(0x11)),
        fact(103, 6, 1, oid(0x11), oid(0x12)),
    ];
    assert_eq!(
        verify_shard_sequence(&facts, 100),
        Err(ShardSequenceFault::Gap {
            expected: 101,
            observed: 103
        })
    );
}

#[test]
fn a_shard_sequence_regression_is_reported_as_a_regression() {
    let facts = [
        fact(100, 5, 1, oid(0x10), oid(0x11)),
        fact(99, 6, 1, oid(0x11), oid(0x12)),
    ];
    assert_eq!(
        verify_shard_sequence(&facts, 100),
        Err(ShardSequenceFault::Regression {
            previous: 100,
            observed: 99
        })
    );
}

#[test]
fn a_replay_that_does_not_start_where_the_checkpoint_ended_is_a_gap() {
    let facts = [fact(105, 5, 1, oid(0x10), oid(0x11))];
    assert_eq!(
        verify_shard_sequence(&facts, 100),
        Err(ShardSequenceFault::Gap {
            expected: 100,
            observed: 105
        }),
        "the first replayed frame must continue the checkpointed sequence"
    );
}

// ===========================================================================
// Repo-sequence gap
// ===========================================================================

#[test]
fn a_repo_sequence_gap_is_its_own_fault() {
    let catalog = catalog(1, 4, oid(0x10));
    let facts = [fact(100, 7, 1, oid(0x10), oid(0x11))];
    assert_eq!(
        verify_repo_chain(&facts, &catalog),
        Err(RepoSequenceFault::Gap {
            namespace: ns(1).to_hex(),
            expected: 5,
            observed: 7
        })
    );
}

#[test]
fn a_repo_sequence_duplicate_is_reported_as_a_duplicate() {
    let catalog = catalog(1, 5, oid(0x10));
    let facts = [fact(100, 5, 1, oid(0x10), oid(0x11))];
    assert_eq!(
        verify_repo_chain(&facts, &catalog),
        Err(RepoSequenceFault::Duplicate {
            namespace: ns(1).to_hex(),
            repo_sequence: 5
        })
    );
}

#[test]
fn a_repo_sequence_regression_is_reported_as_a_regression() {
    let catalog = catalog(1, 5, oid(0x10));
    let facts = [fact(100, 3, 1, oid(0x10), oid(0x11))];
    assert_eq!(
        verify_repo_chain(&facts, &catalog),
        Err(RepoSequenceFault::Regression {
            namespace: ns(1).to_hex(),
            previous: 5,
            observed: 3
        })
    );
}

// ===========================================================================
// previous_event_digest mismatch
// ===========================================================================

#[test]
fn a_previous_event_digest_mismatch_is_its_own_fault() {
    let catalog = catalog(1, 4, oid(0x10));
    let facts = [fact(100, 5, 1, oid(0xEE), oid(0x11))];
    assert_eq!(
        verify_repo_chain(&facts, &catalog),
        Err(RepoSequenceFault::PreviousEventDigestMismatch {
            namespace: ns(1).to_hex(),
            repo_sequence: 5,
            expected: hex::encode(oid(0x10).0),
            observed: hex::encode(oid(0xEE).0),
        }),
        "a broken chain is not a sequence gap; deletion and reordering are \
         detected by the chain, contiguity by the sequence"
    );
}

#[test]
fn the_chain_is_checked_frame_to_frame_and_not_only_against_the_checkpoint() {
    let catalog = catalog(1, 4, oid(0x10));
    let facts = [
        fact(100, 5, 1, oid(0x10), oid(0x11)),
        // Chains onto the checkpointed digest again instead of onto frame 5's
        // event digest.
        fact(101, 6, 1, oid(0x10), oid(0x12)),
    ];
    assert_eq!(
        verify_repo_chain(&facts, &catalog),
        Err(RepoSequenceFault::PreviousEventDigestMismatch {
            namespace: ns(1).to_hex(),
            repo_sequence: 6,
            expected: hex::encode(oid(0x11).0),
            observed: hex::encode(oid(0x10).0),
        })
    );
}

// ===========================================================================
// Independence — the deliverable-4 requirement
// ===========================================================================

#[test]
fn a_shard_gap_and_a_repository_gap_are_never_the_same_fault() {
    // Case A: shard sequence contiguous, repository sequence gapped.
    let catalog_a = catalog(1, 4, oid(0x10));
    let facts_a = [
        fact(100, 5, 1, oid(0x10), oid(0x11)),
        fact(101, 9, 1, oid(0x11), oid(0x12)),
    ];
    verify_shard_sequence(&facts_a, 100)
        .expect("the physical sequence is intact and must be reported so");
    assert_eq!(
        verify_repo_chain(&facts_a, &catalog_a),
        Err(RepoSequenceFault::Gap {
            namespace: ns(1).to_hex(),
            expected: 6,
            observed: 9
        })
    );

    // Case B: shard sequence gapped, repository chain intact.
    let catalog_b = catalog(1, 4, oid(0x10));
    let facts_b = [
        fact(100, 5, 1, oid(0x10), oid(0x11)),
        fact(109, 6, 1, oid(0x11), oid(0x12)),
    ];
    assert_eq!(
        verify_shard_sequence(&facts_b, 100),
        Err(ShardSequenceFault::Gap {
            expected: 101,
            observed: 109
        })
    );
    verify_repo_chain(&facts_b, &catalog_b)
        .expect("the logical chain is intact and must be reported so");
}

#[test]
fn two_repositories_interleaved_in_one_shard_advance_independently() {
    let mut catalog = catalog(1, 0, oid(0x10));
    catalog
        .bind(NamespaceRecord {
            namespace: ns(2),
            genesis_authority: oid(0xB0),
            current_authority: oid(0xB1),
            lifecycle: NamespaceLifecycle::Active,
            storage_mode: NamespaceStorageMode::Full,
            repo_sequence: 0,
            previous_event_digest: oid(0x20),
        })
        .expect("bind");

    let facts = [
        fact(0, 1, 1, oid(0x10), oid(0x11)),
        fact(1, 1, 2, oid(0x20), oid(0x21)),
        fact(2, 2, 1, oid(0x11), oid(0x12)),
        fact(3, 2, 2, oid(0x21), oid(0x22)),
    ];
    verify_shard_sequence(&facts, 0).expect("one contiguous physical order");
    verify_repo_chain(&facts, &catalog).expect("two independent logical chains");

    // Breaking one repository's chain must not disturb the other's verdict,
    // and must not be reported through the shard-sequence channel.
    let broken = [
        fact(0, 1, 1, oid(0x10), oid(0x11)),
        fact(1, 1, 2, oid(0xEE), oid(0x21)),
    ];
    verify_shard_sequence(&broken, 0).expect("the physical order is untouched");
    assert_eq!(
        verify_repo_chain(&broken, &catalog),
        Err(RepoSequenceFault::PreviousEventDigestMismatch {
            namespace: ns(2).to_hex(),
            repo_sequence: 1,
            expected: hex::encode(oid(0x20).0),
            observed: hex::encode(oid(0xEE).0),
        })
    );
}

// ===========================================================================
// Namespace binding on the replay path
// ===========================================================================

#[test]
fn a_frame_for_a_namespace_that_was_never_created_is_refused() {
    let catalog = NamespaceCatalog::new();
    assert_eq!(
        verify_repo_chain(&[fact(0, 1, 9, oid(0), oid(1))], &catalog),
        Err(RepoSequenceFault::UnknownNamespace {
            namespace: ns(9).to_hex()
        })
    );
}

#[test]
fn a_repository_create_binds_the_namespace_and_a_second_create_is_refused() {
    let catalog = NamespaceCatalog::new();
    let mut create = fact(0, 0, 7, oid(0), oid(0x71));
    create.creates_namespace = true;
    let follow = fact(1, 1, 7, oid(0x71), oid(0x72));
    verify_repo_chain(&[create.clone(), follow], &catalog).expect("create then extend");

    let mut second = create.clone();
    second.shard_sequence = 1;
    assert_eq!(
        verify_repo_chain(&[create, second], &catalog),
        Err(RepoSequenceFault::DuplicateCreate {
            namespace: ns(7).to_hex()
        }),
        "plan §4 identity invariant 2 binds repo_id and genesis permanently; a \
         replayed create must not rebind them"
    );
}

#[test]
fn a_repository_create_must_carry_repo_sequence_zero() {
    let catalog = NamespaceCatalog::new();
    let mut create = fact(0, 3, 7, oid(0), oid(0x71));
    create.creates_namespace = true;
    assert_eq!(
        verify_repo_chain(&[create], &catalog),
        Err(RepoSequenceFault::Gap {
            namespace: ns(7).to_hex(),
            expected: 0,
            observed: 3
        })
    );
}

// ===========================================================================
// Facts derived from a real frame header
// ===========================================================================

#[test]
fn facts_taken_from_a_frame_header_carry_the_header_half_verbatim() {
    use reference::{reference_verify, FrameSpec, JOURNAL_ID};

    let bytes = FrameSpec::new(42)
        .with_repo_sequence(7)
        .with_namespace([0x5A; 32])
        .encode();
    let header = reference_verify(&bytes, &JOURNAL_ID, bytes.len() as u64).expect("valid");
    let facts = FrameFacts::from_header(&header);

    assert_eq!(facts.shard_sequence, 42);
    assert_eq!(facts.repo_sequence, 7);
    assert_eq!(facts.namespace, NamespaceId([0x5A; 32]));
    assert_eq!(
        facts.previous_event_digest,
        ObjectId([0u8; 32]),
        "the payload half is not derivable from the header and must stay at its \
         zero value until a PayloadFacts extractor fills it"
    );
}
