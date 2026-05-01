//! levcs-core: object model, hashing, and content-addressed object store
//! for the LeVCS specification (v1.1 trust-root revision).

pub mod error;
pub mod hash;
pub mod object;
pub mod blob;
pub mod tree;
pub mod commit;
pub mod release;
pub mod store;
pub mod refs;
pub mod index;
pub mod repo;
pub mod ignore;
pub mod release_cache;

pub use error::{Error, Result};
pub use hash::{ObjectId, ZERO_ID, blake3_hash};
pub use object::{
    ObjectType, ObjectHeader, SignatureEntry, SignedObject, RawObject,
    HEADER_SIZE, MAGIC, FORMAT_VERSION, SIGNATURE_ENTRY_SIZE,
};
pub use blob::Blob;
pub use tree::{Tree, TreeEntry, EntryType, FileMode};
pub use commit::{Commit, CommitFlags};
pub use release::Release;
pub use store::ObjectStore;
pub use refs::Refs;
pub use index::{Index, IndexEntry, IndexEntryFlags};
pub use repo::Repository;
