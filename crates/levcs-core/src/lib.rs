//! levcs-core: object model, hashing, and content-addressed object store
//! for the LeVCS specification (v1.1 trust-root revision).

pub mod blob;
pub mod commit;
pub mod error;
pub mod hash;
pub mod ignore;
pub mod index;
pub mod object;
pub mod refs;
pub mod release;
pub mod release_cache;
pub mod repo;
pub mod store;
pub mod tree;

pub use blob::Blob;
pub use commit::{Commit, CommitFlags};
pub use error::{Error, Result};
pub use hash::{blake3_hash, ObjectId, ZERO_ID};
pub use index::{Index, IndexEntry, IndexEntryFlags};
pub use object::{
    ObjectHeader, ObjectType, RawObject, SignatureEntry, SignedObject, FORMAT_VERSION, HEADER_SIZE,
    MAGIC, SIGNATURE_ENTRY_SIZE,
};
pub use refs::Refs;
pub use release::Release;
pub use repo::Repository;
pub use store::ObjectStore;
pub use tree::{EntryType, FileMode, Tree, TreeEntry};
