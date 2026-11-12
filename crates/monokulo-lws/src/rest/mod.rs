//! The HTTP side: the wallet API on one listener, the admin API on another.
//!
//! Every request goes through [`guard`]: the client address is found
//! (`limits::ClientIpConfig`), the per-client rate limits are applied, the
//! request gets a time limit, and the response gets security headers.
//! Bodies are read by [`ApiJson`], with a size limit per endpoint and errors
//! that never echo what was sent.

pub mod admin;
pub mod wallet;

#[cfg(test)]
mod tests;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, FromRequest, Request, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, post},
};
use serde::de::DeserializeOwned;
use tokio::sync::Mutex;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::daemon::{Daemon, FeeEstimate, Info};
use crate::db::AsyncDb;
use crate::decoys::Picker;
use crate::error::{Error, bad};
use crate::limits::{ClientIp, Limits};
use crate::scanner::Scanner;

/// How accounts come to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Policy {
    /// Refused.
    Off,
    /// Done at once.
    Auto,
    /// Queued for an admin to accept.
    Approve,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub create: Policy,
    pub import: Policy,
    pub max_subaddresses: u32,
    pub lookahead: u32,
    pub admin_auth: bool,
    pub access_control_origins: Vec<String>,
    /// Time a request may take, body read and answer included.
    pub request_timeout: Duration,
    /// Whether the listeners speak TLS themselves (then HSTS is sent).
    pub tls: bool,
}

/// What every handler reaches.
pub struct App {
    /// The store, reached only off the tokio workers (`AsyncDb::call`).
    pub db: AsyncDb,
    pub daemon: Daemon,
    pub scanner: Arc<Scanner>,
    pub config: Config,
    pub limits: Limits,
    pub fee: Mutex<Option<(Instant, FeeEstimate)>>,
    pub info: Mutex<Option<(Instant, Info)>>,
    pub picker: Picker,
}

/// How long the node's `get_info` answers the unauthenticated endpoints:
/// they don't make a node call each.
const INFO_FRESH_FOR: Duration = Duration::from_secs(5);

impl App {
    /// The fee estimate, at most a minute old.
    pub async fn fee(&self) -> crate::error::Result<FeeEstimate> {
        let mut cached = self.fee.lock().await;
        if let Some((at, fee)) = cached.as_ref()
            && at.elapsed() < Duration::from_secs(60)
        {
            return Ok(fee.clone());
        }
        let fee = self.daemon.fee_estimate().await?;
        *cached = Some((Instant::now(), fee.clone()));
        Ok(fee)
    }

    /// The node's `get_info`, at most a few seconds old. One caller asks the
    /// node at a time; the others wait for its answer.
    pub async fn info(&self) -> crate::error::Result<Info> {
        let mut cached = self.info.lock().await;
        if let Some((at, info)) = cached.as_ref()
            && at.elapsed() < INFO_FRESH_FOR
        {
            return Ok(info.clone());
        }
        let info = self.daemon.info().await?;
        *cached = Some((Instant::now(), info.clone()));
        Ok(info)
    }
}

pub struct ApiError(pub Error);

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.0.status();
        if status == StatusCode::INTERNAL_SERVER_ERROR || matches!(self.0, Error::Daemon(_)) {
            // The detail is for the operator; the client gets a sentence.
            tracing::warn!("request failed: {}", self.0);
        }
        let mut response = (status, self.0.public_message()).into_response();
        if let Error::RateLimited(wait) = self.0 {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(wait.as_secs().max(1)));
        }
        response
    }
}

/// `axum::Json`, but a rejection says only where the JSON went wrong (line
/// and column), never what it held: serde's messages quote values, and the
/// values here are view keys and addresses.
pub struct ApiJson<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        if !is_json(req.headers()) {
            return Err(Error::NotJson.into());
        }
        let bytes = Bytes::from_request(req, state).await.map_err(|r| {
            if r.status() == StatusCode::PAYLOAD_TOO_LARGE {
                Error::TooLarge
            } else {
                bad("the request body couldn't be read")
            }
        })?;
        parse_json(&bytes).map(ApiJson).map_err(ApiError)
    }
}

pub fn parse_json<T: DeserializeOwned>(bytes: &[u8]) -> crate::error::Result<T> {
    serde_json::from_slice(bytes).map_err(|e| json_error(&e))
}

pub fn parse_value<T: DeserializeOwned>(value: serde_json::Value) -> crate::error::Result<T> {
    serde_json::from_value(value).map_err(|e| json_error(&e))
}

fn json_error(e: &serde_json::Error) -> Error {
    use serde_json::error::Category;
    match e.classify() {
        Category::Data => bad(format!(
            "the request's fields don't fit this call (line {}, column {})",
            e.line(),
            e.column()
        )),
        Category::Syntax | Category::Eof | Category::Io => {
            bad(format!("malformed JSON (line {}, column {})", e.line(), e.column()))
        }
    }
}

fn is_json(headers: &axum::http::HeaderMap) -> bool {
    let Some(value) = headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let mime = value.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
    mime == "application/json" || (mime.starts_with("application/") && mime.ends_with("+json"))
}

fn cors(origins: &[String]) -> Option<CorsLayer> {
    if origins.is_empty() {
        return None;
    }
    let allow = if origins.iter().any(|o| o == "*") {
        AllowOrigin::any()
    } else {
        AllowOrigin::list(origins.iter().filter_map(|o| HeaderValue::from_str(o).ok()))
    };
    Some(
        CorsLayer::new()
            .allow_origin(allow)
            .allow_methods([Method::POST, Method::GET, Method::OPTIONS])
            .allow_headers([header::CONTENT_TYPE]),
    )
}

/// Body limits, in bytes. Every login-shaped request is a few hundred bytes;
/// monero-lws allows 2 KiB for them.
const SMALL_BODY: usize = 4 * 1024;
const RANDOM_OUTS_BODY: usize = 16 * 1024;
const SUBADDRS_BODY: usize = 64 * 1024;
const ADMIN_BODY: usize = 64 * 1024;
/// monerod's own cap on a transaction, as hex, and room for the JSON.
pub const MAX_TX_BYTES: usize = 1_000_000;
const SUBMIT_BODY: usize = 2 * MAX_TX_BYTES + 4 * 1024;

/// Endpoints with the strict per-client limit on every call. `/login` takes
/// it only when it would create an account (in the handler).
const STRICT_PATHS: &[&str] = &[
    "/import_wallet_request",
    "/import_request",
    "/submit_raw_tx",
    "/get_random_outs",
];

fn limited<S: Clone + Send + Sync + 'static>(route: MethodRouter<S>, limit: usize) -> MethodRouter<S> {
    route.layer(DefaultBodyLimit::max(limit))
}

pub fn wallet_router(app: Arc<App>) -> Router {
    let router = Router::new()
        .route("/login", limited(post(wallet::login), SMALL_BODY))
        .route("/get_address_info", limited(post(wallet::get_address_info), SMALL_BODY))
        .route("/get_address_txs", limited(post(wallet::get_address_txs), SMALL_BODY))
        .route("/get_unspent_outs", limited(post(wallet::get_unspent_outs), SMALL_BODY))
        .route(
            "/get_random_outs",
            limited(post(wallet::get_random_outs), RANDOM_OUTS_BODY),
        )
        .route("/submit_raw_tx", limited(post(wallet::submit_raw_tx), SUBMIT_BODY))
        .route(
            "/import_wallet_request",
            limited(post(wallet::import_wallet_request), SMALL_BODY),
        )
        .route(
            "/import_request",
            limited(post(wallet::import_wallet_request), SMALL_BODY),
        )
        .route("/get_subaddrs", limited(post(wallet::get_subaddrs), SMALL_BODY))
        .route(
            "/upsert_subaddrs",
            limited(post(wallet::upsert_subaddrs), SUBADDRS_BODY),
        )
        .route(
            "/provision_subaddrs",
            limited(post(wallet::provision_subaddrs), SMALL_BODY),
        )
        .route(
            "/get_version",
            limited(get(wallet::get_version).post(wallet::get_version), SMALL_BODY),
        )
        .route(
            "/daemon_status",
            limited(get(wallet::daemon_status).post(wallet::daemon_status), SMALL_BODY),
        );
    finish(router, app, STRICT_PATHS)
}

pub fn admin_router(app: Arc<App>) -> Router {
    let router = Router::new().route("/{command}", limited(post(admin::command), ADMIN_BODY));
    finish(router, app, &[])
}

#[derive(Clone)]
struct Guard {
    app: Arc<App>,
    strict: &'static [&'static str],
}

/// The layers every router shares, innermost first: panics become a bare
/// 500, then the guard, then CORS (outermost, so a refusal still carries
/// the CORS headers a browser needs to read it).
fn finish(router: Router<Arc<App>>, app: Arc<App>, strict: &'static [&'static str]) -> Router {
    let guard_state = Guard {
        app: app.clone(),
        strict,
    };
    let mut router = router
        .fallback(not_found)
        .layer(CatchPanicLayer::custom(|_: Box<dyn std::any::Any + Send>| {
            // The panic itself is logged by the hook in main, without its
            // message; the client learns nothing.
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }))
        .layer(middleware::from_fn_with_state(guard_state, guard));
    if let Some(cors) = cors(&app.config.access_control_origins) {
        router = router.layer(cors);
    }
    router.with_state(app)
}

async fn not_found() -> Response {
    (StatusCode::NOT_FOUND, "no such method").into_response()
}

/// Finds the client, applies the rate limits and the time limit, and sets
/// the response headers.
async fn guard(State(g): State<Guard>, mut req: Request, next: Next) -> Response {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0)
        .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let ip = g.app.limits.client_ip.client_ip(peer, req.headers());
    req.extensions_mut().insert(ClientIp(ip));

    let mut response = if let Err(wait) = g.app.limits.general.check(ip) {
        tracing::debug!("rate limited a client");
        ApiError(Error::RateLimited(wait)).into_response()
    } else if g.strict.contains(&req.uri().path())
        && let Err(wait) = g.app.limits.strict.check(ip)
    {
        tracing::debug!("rate limited a client on {}", req.uri().path());
        ApiError(Error::RateLimited(wait)).into_response()
    } else {
        match tokio::time::timeout(g.app.config.request_timeout, next.run(req)).await {
            Ok(response) => response,
            Err(_) => ApiError(Error::Busy("the request took too long")).into_response(),
        }
    };
    set_security_headers(response.headers_mut(), g.app.config.tls);
    response
}

fn set_security_headers(headers: &mut axum::http::HeaderMap, tls: bool) {
    let set = |headers: &mut axum::http::HeaderMap, name: HeaderName, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };
    set(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(headers, header::CACHE_CONTROL, "no-store");
    set(headers, header::REFERRER_POLICY, "no-referrer");
    set(headers, header::X_FRAME_OPTIONS, "DENY");
    set(
        headers,
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; frame-ancestors 'none'",
    );
    set(
        headers,
        HeaderName::from_static("cross-origin-resource-policy"),
        "same-origin",
    );
    if tls {
        set(headers, header::STRICT_TRANSPORT_SECURITY, "max-age=31536000");
    }
    headers.remove(header::SERVER);
}
