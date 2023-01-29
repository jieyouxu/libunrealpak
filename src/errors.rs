use thiserror::Error;

#[derive(Debug, Error)]
pub enum UnrealpakError {
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("unrecognized input: validation for {0} failed")]
    ValidationError(&'static str),
    #[error("found invalid bool representation {0}")]
    Bool(u64),
    #[error("{0}")]
    FromUtf16Error(#[from] std::string::FromUtf16Error),
    #[error("{0}")]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
    #[error("version {0} is not a known version")]
    UnknownVersion(u32),
    #[error("version mismatch: expected version {expected} but found {actual}")]
    VersionMismatch { expected: u32, actual: u32 },
    #[error("detected invalid offset: {0}")]
    InvalidOffset(i64),
    #[error("unsupported version")]
    UnsupportedVersion,
    #[error("missing key to decrypt encrypted pak")]
    Encrypted,
}
