//! levcs-identity: keychains, authority objects, signing, verification.

pub mod error;
pub mod keys;
pub mod keychain;
pub mod authority;
pub mod sign;
pub mod verify;

pub use error::IdentityError;
pub use keys::{KeyLabel, PublicKey, SecretKey};
pub use keychain::{Keychain, KeychainEntry};
pub use authority::{
    AuthorityBody, MemberEntry, PolicyEntry, Role, AUTHORITY_SCHEMA_VERSION,
    parse_toml_authority, render_toml_authority,
};
pub use sign::{sign_commit, sign_release, sign_authority, sign_message};
pub use verify::{
    verify_signed_object, verify_commit, verify_authority_chain, verify_genesis,
    Verification, VerifyError,
};
