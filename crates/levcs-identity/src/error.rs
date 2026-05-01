use thiserror::Error;

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error(transparent)]
    Core(#[from] levcs_core::Error),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("toml parse: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("toml encode: {0}")]
    TomlEncode(#[from] toml::ser::Error),

    #[error("invalid key encoding: {0}")]
    InvalidKey(String),

    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("base64 decode: {0}")]
    Base64(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("malformed authority: {0}")]
    MalformedAuthority(String),

    #[error("unknown key label: {0}")]
    UnknownKey(String),

    #[error("ed25519 verify failed")]
    BadSignature,

    #[error("encrypted key requires passphrase")]
    EncryptedKey,

    #[error("argon2: {0}")]
    Argon2(String),

    #[error("zero hash where expected non-zero")]
    UnexpectedZeroHash,

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, IdentityError>;
