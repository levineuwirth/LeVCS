//! `RepoSnapshot`: an immutable committed repository view sharing persistent
//! substructures with the committed root.
//!
//! **Shared file.** Lead owns the signatures (D0); **B1 NamespaceTxn** fills
//! the bodies (scope 2.1, 6-B1).
//!
//! A snapshot must not clone the index; plan §5.1 requires reads to retain the
//! committed generation and share structure, so a snapshot is cheap enough to
//! take per request.

use levcs_core::{ObjectId, ObjectType};

use crate::types::{NamespaceId, StoreError};

/// One repository's committed logical state at one generation.
pub struct RepoSnapshot {
    _private: (),
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
    pub fn namespace(&self) -> NamespaceId {
        unimplemented!("B1 NamespaceTxn: scope 6-B1 deliverable 8")
    }

    /// The logical federation cursor value, never the physical
    /// `shard_sequence` (plan §4 transaction invariant 8).
    pub fn repo_sequence(&self) -> u64 {
        unimplemented!("B1 NamespaceTxn: scope 6-B1 deliverable 8")
    }

    pub fn current_authority(&self) -> ObjectId {
        unimplemented!("B1 NamespaceTxn: scope 6-B1 deliverable 8")
    }

    pub fn genesis_authority(&self) -> ObjectId {
        unimplemented!("B1 NamespaceTxn: scope 6-B1 deliverable 8")
    }

    /// Locate an object *within this namespace*. Namespace membership, not
    /// global object existence, controls reads: identical bytes in private
    /// repository A do not make an object readable through repository B
    /// (plan §4 resource invariants).
    pub fn locate(&self, _id: ObjectId) -> Result<Option<ObjectLocation>, StoreError> {
        Err(StoreError::NotImplemented(
            "RepoSnapshot::locate — B1 NamespaceTxn, scope 6-B1 deliverable 8",
        ))
    }
}
