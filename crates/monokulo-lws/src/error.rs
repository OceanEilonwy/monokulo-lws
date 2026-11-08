//! One error for the server, and how each maps to an HTTP status.
//!
//! What a client sees is [`Error::public_message`]: for the server's own
//! failures (database, node, internal) a fixed sentence, never the detail,
//! which can hold file paths, SQL or the node's URL. The detail goes to the
//! log, which never holds a view key or an address either: no variant
//! carries one.

use std::time::Duration;

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
    /// The body is over the endpoint's limit.
    #[error("the request is too large")]
    TooLarge,
    /// Not `Content-Type: application/json`.
    #[error("the request must be application/json")]
    NotJson,
    /// Too many requests from this client (or, for account creation, from
    /// everyone); try again after the duration.
    #[error("too many requests")]
    RateLimited(Duration),
    /// Busy: the request queue is full or the request took too long.
    #[error("{0}")]
    Busy(&'static str),
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
            Error::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Error::NotJson => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Error::RateLimited(_) => StatusCode::TOO_MANY_REQUESTS,
            Error::Busy(_) => StatusCode::SERVICE_UNAVAILABLE,
            Error::Daemon(_) => StatusCode::SERVICE_UNAVAILABLE,
            Error::Db(_) | Error::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// What the client is told: the server's own failures in a fixed
    /// sentence, the rest as they are (they describe the request only).
    pub fn public_message(&self) -> String {
        match self {
            Error::Daemon(_) => "the node is unavailable; try again later".into(),
            Error::Db(_) | Error::Internal(_) => "internal error".into(),
            other => other.to_string(),
        }
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        // Without the URL: the log needn't carry the node's address on
        // every failure, and the client never sees this anyway.
        Error::Daemon(e.without_url().to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_failures_say_nothing_of_their_detail() {
        let e = Error::Daemon("error sending request for url (http://10.0.0.5:18081/json_rpc)".into());
        assert!(!e.public_message().contains("10.0.0.5"));
        let e = Error::Internal("/var/lib/monokulo-lws/lws.sqlite: no such table".into());
        assert!(!e.public_message().contains("/var/lib"));
        let e = Error::Db(rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(1),
            Some("near \"SELECT\": syntax error".into()),
        ));
        assert_eq!(e.public_message(), "internal error");
        assert_eq!(bad("count must be 1 to 20").public_message(), "count must be 1 to 20");
    }
}
