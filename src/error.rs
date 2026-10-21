//! Crate-wide error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(#[source] Box<redb::Error>),

    #[error("database error: {0}")]
    Database(#[from] redb::DatabaseError),

    #[error("transaction error: {0}")]
    Transaction(#[source] Box<redb::TransactionError>),

    #[error("table error: {0}")]
    Table(#[from] redb::TableError),

    #[error("storage error: {0}")]
    StorageError(#[from] redb::StorageError),

    #[error("commit error: {0}")]
    Commit(#[from] redb::CommitError),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("config error: {0}")]
    Config(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("consensus error: {0}")]
    Consensus(String),

    #[error("invalid block: {0}")]
    InvalidBlock(String),

    #[error("not in sync: {0}")]
    NotSynced(String),

    #[error("crypto error: {0}")]
    Crypto(String),
}

impl From<redb::Error> for Error {
    fn from(err: redb::Error) -> Self {
        Error::Storage(Box::new(err))
    }
}

impl From<redb::TransactionError> for Error {
    fn from(err: redb::TransactionError) -> Self {
        Error::Transaction(Box::new(err))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
