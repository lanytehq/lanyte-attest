use std::path::PathBuf;

use base64::DecodeError;
use rusqlite::Error as SqliteError;
use seclusor_crypto::CryptoError;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, AttestError>;

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("HOME is not set and LANYTE_ATTEST_HOME is not provided")]
    MissingHome,

    #[error("{0} is set but empty")]
    EmptyEnvVar(&'static str),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Base64(#[from] DecodeError),

    #[error(transparent)]
    Sqlite(#[from] SqliteError),

    #[error("key material already exists at {0}")]
    KeyMaterialAlreadyExists(PathBuf),

    #[error("directory permissions for {path} must be 0700 on unix (actual: {actual:o})")]
    InsecureDirectoryPermissions { path: PathBuf, actual: u32 },

    #[error("file permissions for {path} must be {required:o} on unix (actual: {actual:o})")]
    InsecureFilePermissions {
        path: PathBuf,
        actual: u32,
        required: u32,
    },

    #[error("expected directory at {0}")]
    RootPathNotDirectory(PathBuf),

    #[error("expected file at {0}")]
    ExpectedFilePath(PathBuf),

    #[error("trust config not found at {0}")]
    MissingTrustConfig(PathBuf),

    #[error("token must contain exactly three segments")]
    InvalidTokenFormat,

    #[error("token {0} segment is empty")]
    EmptyTokenSegment(&'static str),

    #[error("token header alg must be EdDSA")]
    InvalidTokenAlgorithm,

    #[error("token header typ must be JWT")]
    InvalidTokenType,

    #[error("token expired at {exp} (now: {now})")]
    TokenExpired { exp: u64, now: u64 },

    #[error("token issued in the future at {iat} (now: {now})")]
    TokenIssuedInFuture { iat: u64, now: u64 },

    #[error("issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },

    #[error("role mismatch: expected {expected}, got {actual}")]
    RoleMismatch { expected: String, actual: String },

    #[error("scope mismatch: expected {expected}, got {actual}")]
    ScopeMismatch { expected: String, actual: String },

    #[error("{claim} must be a UUID")]
    InvalidUuidClaim { claim: &'static str },

    #[error("ctx_hash must match sha256:<lowercase-hex>")]
    InvalidContextHash,

    #[error("session {jti} was not found in the registry")]
    SessionNotFound { jti: String },

    #[error("revocation registry not found at {0}")]
    MissingRevocationRegistry(PathBuf),

    #[error("session {jti} is {status} and cannot be used for {action}")]
    SessionNotUsable {
        jti: String,
        status: &'static str,
        action: &'static str,
    },

    #[error("LANYTE_SESSION_TOKEN is not set")]
    MissingSessionToken,

    #[error("invalid TTL '{0}'")]
    InvalidTtl(String),

    #[error("child process exited with code {0}")]
    ChildProcessFailed(i32),

    #[error("child process terminated by signal")]
    ChildProcessTerminated,

    #[error("{0}")]
    Validation(String),

    #[error("{0} is not implemented yet in this checkpoint")]
    Unsupported(&'static str),
}

impl AttestError {
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::MissingHome | Self::EmptyEnvVar(_) | Self::Io(_) => 1,
            Self::Unsupported(_) => 2,
            Self::Crypto(_)
            | Self::Base64(_)
            | Self::Sqlite(_)
            | Self::KeyMaterialAlreadyExists(_)
            | Self::InsecureDirectoryPermissions { .. }
            | Self::InsecureFilePermissions { .. }
            | Self::RootPathNotDirectory(_)
            | Self::ExpectedFilePath(_)
            | Self::MissingTrustConfig(_)
            | Self::InvalidTokenFormat
            | Self::EmptyTokenSegment(_)
            | Self::InvalidTokenAlgorithm
            | Self::InvalidTokenType
            | Self::TokenExpired { .. }
            | Self::TokenIssuedInFuture { .. }
            | Self::IssuerMismatch { .. }
            | Self::RoleMismatch { .. }
            | Self::ScopeMismatch { .. }
            | Self::InvalidUuidClaim { .. }
            | Self::InvalidContextHash
            | Self::SessionNotFound { .. }
            | Self::MissingRevocationRegistry(_)
            | Self::SessionNotUsable { .. }
            | Self::MissingSessionToken
            | Self::InvalidTtl(_)
            | Self::Validation(_) => 3,
            Self::ChildProcessFailed(code) => *code,
            Self::ChildProcessTerminated => 1,
        }
    }
}
