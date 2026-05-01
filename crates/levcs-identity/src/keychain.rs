//! Keychain file at `$XDG_CONFIG_HOME/levcs/keys.toml` (or per platform).
//! Entries may be plaintext (`private = "ed25519:..."`) or encrypted
//! (`private_encrypted = { ... }` with XChaCha20-Poly1305 + Argon2id).

use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::error::{IdentityError, Result};
use crate::keys::{PublicKey, SecretKey};

pub const KEYCHAIN_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Keychain {
    pub schema_version: u32,
    #[serde(rename = "key", default)]
    pub keys: Vec<KeychainEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeychainEntry {
    pub label: String,
    pub public: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_encrypted: Option<EncryptedKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedKey {
    pub algorithm: String,
    pub kdf_params: KdfParams,
    pub ciphertext: String,
    /// 24-byte XChaCha20 nonce, base64-encoded.
    pub nonce: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KdfParams {
    pub salt: String,
    pub memory: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            salt: String::new(),
            // OWASP-recommended Argon2id minimums (m=19 MiB, t=2, p=1).
            memory: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }
}

impl Keychain {
    pub fn new() -> Self {
        Self { schema_version: KEYCHAIN_SCHEMA_VERSION, keys: Vec::new() }
    }

    pub fn default_path() -> PathBuf {
        if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
            PathBuf::from(xdg).join("levcs").join("keys.toml")
        } else if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(".config").join("levcs").join("keys.toml")
        } else {
            PathBuf::from("/tmp").join("levcs").join("keys.toml")
        }
    }

    pub fn load_or_default(path: &Path) -> Result<Self> {
        match fs::read_to_string(path) {
            Ok(s) => Ok(toml::from_str(&s)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::new()),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(parent)?.permissions();
                let mode = perms.mode() & 0o777;
                if mode & 0o077 != 0 {
                    perms.set_mode(0o700);
                    let _ = fs::set_permissions(parent, perms);
                }
            }
        }
        let text = toml::to_string(self)?;
        fs::write(path, text)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(path, perms)?;
        }
        Ok(())
    }

    pub fn entry(&self, label: &str) -> Option<&KeychainEntry> {
        self.keys.iter().find(|k| k.label == label)
    }

    pub fn entry_mut(&mut self, label: &str) -> Option<&mut KeychainEntry> {
        self.keys.iter_mut().find(|k| k.label == label)
    }

    pub fn public(&self, label: &str) -> Result<PublicKey> {
        let e = self
            .entry(label)
            .ok_or_else(|| IdentityError::UnknownKey(label.to_string()))?;
        PublicKey::parse_levcs(&e.public)
    }

    /// Decrypt or load the secret seed for `label`. If the key is encrypted
    /// the passphrase callback is used.
    pub fn secret(
        &self,
        label: &str,
        mut passphrase: impl FnMut() -> Result<String>,
    ) -> Result<SecretKey> {
        let e = self
            .entry(label)
            .ok_or_else(|| IdentityError::UnknownKey(label.to_string()))?;
        if let Some(s) = &e.private {
            return SecretKey::parse_levcs(s);
        }
        if let Some(enc) = &e.private_encrypted {
            let pp = passphrase()?;
            return decrypt_secret(enc, pp.as_bytes());
        }
        Err(IdentityError::Other(
            "key entry has neither plaintext nor encrypted private material".into(),
        ))
    }

    pub fn add_plaintext(&mut self, label: &str, sk: &SecretKey) -> Result<()> {
        if self.entry(label).is_some() {
            return Err(IdentityError::Other(format!("key already exists: {label}")));
        }
        self.keys.push(KeychainEntry {
            label: label.to_string(),
            public: sk.public().to_levcs(),
            private: Some(sk.to_levcs()),
            private_encrypted: None,
            created: Some(now_rfc3339()),
        });
        Ok(())
    }

    pub fn add_encrypted(
        &mut self,
        label: &str,
        sk: &SecretKey,
        passphrase: &[u8],
    ) -> Result<()> {
        if self.entry(label).is_some() {
            return Err(IdentityError::Other(format!("key already exists: {label}")));
        }
        let enc = encrypt_secret(sk, passphrase)?;
        self.keys.push(KeychainEntry {
            label: label.to_string(),
            public: sk.public().to_levcs(),
            private: None,
            private_encrypted: Some(enc),
            created: Some(now_rfc3339()),
        });
        Ok(())
    }

    pub fn remove(&mut self, label: &str) -> Result<()> {
        let pos = self
            .keys
            .iter()
            .position(|k| k.label == label)
            .ok_or_else(|| IdentityError::UnknownKey(label.into()))?;
        self.keys.remove(pos);
        Ok(())
    }

    pub fn rename(&mut self, old: &str, new: &str) -> Result<()> {
        if self.entry(new).is_some() {
            return Err(IdentityError::Other(format!("destination already exists: {new}")));
        }
        let e = self
            .entry_mut(old)
            .ok_or_else(|| IdentityError::UnknownKey(old.into()))?;
        e.label = new.to_string();
        Ok(())
    }
}

fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    // crude RFC3339 (no tzdb dependency): seconds since epoch as Z time.
    let secs = dur.as_secs() as i64;
    // y/m/d via integer math.
    let (y, mo, d) = days_to_ymd(secs / 86400);
    let s = secs.rem_euclid(86400);
    let h = s / 3600;
    let mi = (s % 3600) / 60;
    let se = s % 60;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, se)
}

fn days_to_ymd(mut days: i64) -> (i32, u32, u32) {
    // Days since 1970-01-01.
    days += 719468;
    let era = days.div_euclid(146097);
    let doe = days.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = y + if m <= 2 { 1 } else { 0 };
    (y as i32, m, d)
}

fn encrypt_secret(sk: &SecretKey, passphrase: &[u8]) -> Result<EncryptedKey> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    use rand_core::{OsRng, RngCore};

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let params = KdfParams {
        salt: B64.encode(salt),
        ..KdfParams::default()
    };
    let key = derive_key(passphrase, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(XNonce::from_slice(&nonce), sk.seed().as_ref())
        .map_err(|e| IdentityError::Crypto(format!("encrypt: {e}")))?;
    Ok(EncryptedKey {
        algorithm: "xchacha20poly1305-argon2id".into(),
        kdf_params: params,
        ciphertext: B64.encode(ciphertext),
        nonce: B64.encode(nonce),
    })
}

fn decrypt_secret(enc: &EncryptedKey, passphrase: &[u8]) -> Result<SecretKey> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit},
        XChaCha20Poly1305, XNonce,
    };
    if enc.algorithm != "xchacha20poly1305-argon2id" {
        return Err(IdentityError::Crypto(format!(
            "unknown algorithm: {}", enc.algorithm
        )));
    }
    let salt = B64
        .decode(enc.kdf_params.salt.as_bytes())
        .map_err(|e| IdentityError::Base64(e.to_string()))?;
    let nonce_bytes = B64
        .decode(enc.nonce.as_bytes())
        .map_err(|e| IdentityError::Base64(e.to_string()))?;
    if nonce_bytes.len() != 24 {
        return Err(IdentityError::Crypto("nonce wrong length".into()));
    }
    let ciphertext = B64
        .decode(enc.ciphertext.as_bytes())
        .map_err(|e| IdentityError::Base64(e.to_string()))?;
    let key = derive_key(passphrase, &salt, &enc.kdf_params)?;
    let cipher = XChaCha20Poly1305::new((&key).into());
    let plaintext = cipher
        .decrypt(XNonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|e| IdentityError::Crypto(format!("decrypt: {e}")))?;
    if plaintext.len() != 32 {
        return Err(IdentityError::Crypto("seed wrong length".into()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    Ok(SecretKey::from_seed(seed))
}

fn derive_key(passphrase: &[u8], salt: &[u8], params: &KdfParams) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let p = Params::new(params.memory, params.iterations, params.parallelism, Some(32))
        .map_err(|e| IdentityError::Argon2(e.to_string()))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| IdentityError::Argon2(e.to_string()))?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keychain_plaintext_roundtrip() {
        let mut kc = Keychain::new();
        let sk = SecretKey::generate();
        kc.add_plaintext("personal", &sk).unwrap();
        let s = toml::to_string(&kc).unwrap();
        let kc2: Keychain = toml::from_str(&s).unwrap();
        let pk2 = kc2.public("personal").unwrap();
        assert_eq!(pk2, sk.public());
    }

    #[test]
    fn keychain_encryption_roundtrip() {
        let mut kc = Keychain::new();
        let sk = SecretKey::generate();
        kc.add_encrypted("locked", &sk, b"correct horse battery staple").unwrap();
        let s = toml::to_string(&kc).unwrap();
        let kc2: Keychain = toml::from_str(&s).unwrap();
        let unlocked = kc2
            .secret("locked", || Ok("correct horse battery staple".into()))
            .unwrap();
        assert_eq!(unlocked.seed(), sk.seed());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let mut kc = Keychain::new();
        let sk = SecretKey::generate();
        kc.add_encrypted("locked", &sk, b"good").unwrap();
        let result = kc.secret("locked", || Ok("bad".into()));
        assert!(result.is_err());
    }
}
