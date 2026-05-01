//! Signing helpers for commits, releases, and authority objects.

use levcs_core::object::{ObjectType, SignatureEntry, SignedObject};
use levcs_core::{Commit, Release};

use crate::authority::AuthorityBody;
use crate::error::{IdentityError, Result};
use crate::keys::SecretKey;

/// Sign an arbitrary message with `sk` and return the 64-byte signature.
pub fn sign_message(sk: &SecretKey, msg: &[u8]) -> [u8; 64] {
    sk.sign(msg)
}

/// Sign a commit, returning a SignedObject with exactly one signature entry.
pub fn sign_commit(commit: Commit, sk: &SecretKey) -> Result<SignedObject> {
    if sk.public().0 != commit.author_key {
        return Err(IdentityError::Other(
            "secret key does not match commit author_key".into(),
        ));
    }
    let mut signed = commit.into_signed().map_err(IdentityError::from)?;
    let h = signed.signing_hash();
    let signature = sk.sign(h.as_bytes());
    signed.signatures.push(SignatureEntry {
        public_key: sk.public().0,
        signature,
    });
    Ok(signed)
}

/// Sign a release. The first signature is the declarer; additional signatures
/// can be added with `add_cosigner_signature`.
pub fn sign_release(release: Release, sk: &SecretKey) -> Result<SignedObject> {
    if sk.public().0 != release.declarer_key {
        return Err(IdentityError::Other(
            "secret key does not match release declarer_key".into(),
        ));
    }
    let mut signed = release.into_signed().map_err(IdentityError::from)?;
    let h = signed.signing_hash();
    let signature = sk.sign(h.as_bytes());
    signed.signatures.push(SignatureEntry {
        public_key: sk.public().0,
        signature,
    });
    Ok(signed)
}

/// Sign an authority object, appending the signature to the trailer.
pub fn sign_authority(body: &AuthorityBody, sk: &SecretKey) -> Result<SignedObject> {
    let mut signed = body.to_signed()?;
    debug_assert_eq!(signed.object_type, ObjectType::Authority);
    let h = signed.signing_hash();
    let signature = sk.sign(h.as_bytes());
    signed.signatures.push(SignatureEntry {
        public_key: sk.public().0,
        signature,
    });
    Ok(signed)
}

/// Append an additional signature to an already-signed object (used for
/// release cosignatures and threshold authorities).
pub fn add_cosigner_signature(signed: &mut SignedObject, sk: &SecretKey) {
    let h = signed.signing_hash();
    let signature = sk.sign(h.as_bytes());
    signed.signatures.push(SignatureEntry {
        public_key: sk.public().0,
        signature,
    });
}
