use thiserror::Error;

/// Errors produced by the core crate.
///
/// The `service` crate maps these to HTTP responses. Messages never contain
/// secrets (tokens, passwords, keys).
#[derive(Debug, Error)]
pub enum Error {
    #[error("not found: {0}")]
    NotFound(&'static str),
    #[error("already exists: {0}")]
    Conflict(String),
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("database error: {0}")]
    Db(#[from] mongodb::error::Error),
    #[error("key error: {0}")]
    Key(String),
    #[error("token error: {0}")]
    Token(#[from] jsonwebtoken::errors::Error),
    #[error("password hashing error")]
    Hash,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl Error {
    pub fn is_duplicate_key(err: &mongodb::error::Error) -> bool {
        use mongodb::error::{ErrorKind, WriteFailure};
        match err.kind.as_ref() {
            ErrorKind::Write(WriteFailure::WriteError(e)) => e.code == 11000,
            ErrorKind::Command(e) => e.code == 11000,
            _ => false,
        }
    }
}
