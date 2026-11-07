//! One error for the server, and how each maps to an HTTP status.

use axum::http::StatusCode;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The request was malformed or named something that doesn't exist.
    #[error("{0}")]
    BadRequest(String),
    /// The address isn't known, isn't approved yet, or the view key doesn't fit it.
    #[error("not authorized")]
    Forbidden,
    /// Account creation is off on this server.
    #[error("account creation is not allowed")]
    NoCreate,
    /// Subaddresses are off, or the request would pass the limit.
    #[error("{0}")]
    Conflict(String),
    /// The account doesn't hold what was asked for (`/get_unspent_outs`).
    #[error("insufficient funds")]
    InsufficientFunds,
    /// The daemon failed us.
    #[error("daemon: {0}")]
    Daemon(String),
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    #[error("{0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn status(&self) -> StatusCode {
        match self {
            Error::BadRequest(_) => StatusCode::BAD_REQUEST,
            Error::Forbidden => StatusCode::FORBIDDEN,
            Error::NoCreate => StatusCode::NOT_IMPLEMENTED,
            Error::Conflict(_) => StatusCode::CONFLICT,
            Error::InsufficientFunds => StatusCode::BAD_REQUEST,
            Error::Daemon(_) => StatusCode::SERVICE_UNAVAILABLE,
            Error::Db(_) | Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Daemon(e.to_string())
    }
}

impl From<monero_wallet::interface::InterfaceError> for Error {
    fn from(e: monero_wallet::interface::InterfaceError) -> Self {
        Error::Daemon(format!("{e:?}"))
    }
}

pub fn bad(what: impl Into<String>) -> Error {
    Error::BadRequest(what.into())
}
