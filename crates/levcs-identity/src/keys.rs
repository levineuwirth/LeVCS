//! Ed25519 key wrappers used throughout LeVCS. Public keys are 32-byte
//! arrays; secret keys are 32-byte seeds, expanded as needed.

use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use crate::error::{IdentityError, Result};

/// 32-byte raw Ed25519 public key.
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn from_bytes(b: [u8; 32]) -> Self { Self(b) }

    pub fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    pub fn to_levcs(&self) -> String { format!("ed25519:{}", hex::encode(self.0)) }

    pub fn parse_levcs(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix("ed25519:")
            .ok_or_else(|| IdentityError::InvalidKey(format!("missing ed25519: prefix in {s}")))?;
        let bytes = hex::decode(rest)?;
        if bytes.len() != 32 {
            return Err(IdentityError::InvalidKey(format!(
                "expected 32 bytes, got {}", bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    pub fn verify(&self, msg: &[u8], signature: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(&self.0)
            .map_err(|e| IdentityError::Crypto(format!("public key: {e}")))?;
        let sig = Signature::from_bytes(signature);
        vk.verify(msg, &sig).map_err(|_| IdentityError::BadSignature)?;
        Ok(())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", self.to_levcs())
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_levcs())
    }
}

/// 32-byte secret seed. Wrapped to keep zeroization centralized and to
/// prevent accidental Display/Debug leaks.
pub struct SecretKey {
    seed: [u8; 32],
}

impl SecretKey {
    pub fn from_seed(seed: [u8; 32]) -> Self { Self { seed } }

    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self { seed }
    }

    pub fn seed(&self) -> &[u8; 32] { &self.seed }

    pub fn public(&self) -> PublicKey {
        let sk = SigningKey::from_bytes(&self.seed);
        PublicKey(sk.verifying_key().to_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sk = SigningKey::from_bytes(&self.seed);
        let sig: Signature = sk.sign(msg);
        sig.to_bytes()
    }

    pub fn to_levcs(&self) -> String { format!("ed25519:{}", hex::encode(self.seed)) }

    pub fn parse_levcs(s: &str) -> Result<Self> {
        let rest = s
            .strip_prefix("ed25519:")
            .ok_or_else(|| IdentityError::InvalidKey("missing ed25519: prefix".into()))?;
        let bytes = hex::decode(rest)?;
        if bytes.len() != 32 {
            return Err(IdentityError::InvalidKey(format!(
                "expected 32 bytes, got {}", bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(Self { seed })
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(<redacted>)")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Human-readable key label used in the keychain (e.g., "personal").
pub type KeyLabel = String;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let sk = SecretKey::generate();
        let pk = sk.public();
        let msg = b"hello LeVCS";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig).unwrap();
        // Tampered message rejected.
        let mut tampered = msg.to_vec();
        tampered[0] ^= 1;
        assert!(pk.verify(&tampered, &sig).is_err());
    }

    #[test]
    fn key_string_roundtrip() {
        let sk = SecretKey::generate();
        let pk = sk.public();
        let pk2 = PublicKey::parse_levcs(&pk.to_levcs()).unwrap();
        assert_eq!(pk, pk2);
        let sk2 = SecretKey::parse_levcs(&sk.to_levcs()).unwrap();
        assert_eq!(sk.seed(), sk2.seed());
    }
}
