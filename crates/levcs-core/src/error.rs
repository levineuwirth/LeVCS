use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error at {path:?}: {source}")]
    Io {
        path: Option<PathBuf>,
        #[source]
        source: std::io::Error,
    },

    #[error("malformed object: {0}")]
    MalformedObject(String),

    #[error("unsupported object format version: {0}")]
    UnsupportedFormatVersion(u8),

    #[error("unknown object type: {0}")]
    UnknownObjectType(u8),

    #[error("object hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },

    #[error("object not found: {0}")]
    NotFound(String),

    #[error("invalid signature trailer")]
    InvalidSignatureTrailer,

    #[error("invalid hex: {0}")]
    InvalidHex(String),

    #[error("invalid path component: {0}")]
    InvalidPath(String),

    #[error("not a levcs repository (or any of the parent directories)")]
    NotARepository,

    #[error("repository already exists at {0:?}")]
    RepositoryExists(PathBuf),

    #[error("invalid reference: {0}")]
    InvalidReference(String),

    #[error("invalid index file: {0}")]
    InvalidIndex(String),

    #[error("ref {name} moved during this operation: expected {expected}, found {actual}")]
    RefChanged {
        name: String,
        expected: String,
        actual: String,
    },

    #[error("{0}")]
    Other(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io {
            path: None,
            source: e,
        }
    }
}

impl From<hex::FromHexError> for Error {
    fn from(e: hex::FromHexError) -> Self {
        Error::InvalidHex(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub trait IoExt<T> {
    fn ctx(self, path: impl Into<PathBuf>) -> Result<T>;
}

impl<T> IoExt<T> for std::result::Result<T, std::io::Error> {
    fn ctx(self, path: impl Into<PathBuf>) -> Result<T> {
        self.map_err(|e| Error::Io {
            path: Some(path.into()),
            source: e,
        })
    }
}
