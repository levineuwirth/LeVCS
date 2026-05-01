//! levcs-identity: keychains, authority objects, signing, verification.

pub mod authority;
pub mod error;
pub mod keychain;
pub mod keys;
pub mod sign;
pub mod verify;

pub use authority::{
    parse_toml_authority, render_toml_authority, AuthorityBody, MemberEntry, PolicyEntry, Role,
    AUTHORITY_SCHEMA_VERSION,
};
pub use error::IdentityError;
pub use keychain::{Keychain, KeychainEntry};
pub use keys::{KeyLabel, PublicKey, SecretKey};
pub use sign::{sign_authority, sign_commit, sign_message, sign_release};
pub use verify::{
    verify_authority_chain, verify_commit, verify_genesis, verify_signed_object, Verification,
    VerifyError,
};
