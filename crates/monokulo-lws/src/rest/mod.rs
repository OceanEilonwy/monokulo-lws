//! The HTTP side: the wallet API on one listener, the admin API on another
//! (or under a prefix of the same one).

pub mod admin;
pub mod wallet;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    Router,
    http::{HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use tokio::sync::Mutex;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

use crate::daemon::{Daemon, FeeEstimate};
use crate::db::Db;
use crate::decoys::Picker;
use crate::error::Error;
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
}

/// What every handler reaches.
pub struct App {
    pub db: Arc<Db>,
    pub daemon: Daemon,
    pub scanner: Arc<Scanner>,
    pub config: Config,
    pub fee: Mutex<Option<(Instant, FeeEstimate)>>,
    pub picker: Mutex<Picker>,
}

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
        if status == StatusCode::INTERNAL_SERVER_ERROR || status == StatusCode::SERVICE_UNAVAILABLE {
            tracing::warn!("request failed: {}", self.0);
        }
        (status, self.0.to_string()).into_response()
    }
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
            .allow_headers([axum::http::header::CONTENT_TYPE]),
    )
}

pub fn wallet_router(app: Arc<App>) -> Router {
    let mut router = Router::new()
        .route("/login", post(wallet::login))
        .route("/get_address_info", post(wallet::get_address_info))
        .route("/get_address_txs", post(wallet::get_address_txs))
        .route("/get_unspent_outs", post(wallet::get_unspent_outs))
        .route("/get_random_outs", post(wallet::get_random_outs))
        .route("/submit_raw_tx", post(wallet::submit_raw_tx))
        .route("/import_wallet_request", post(wallet::import_wallet_request))
        .route("/import_request", post(wallet::import_wallet_request))
        .route("/get_subaddrs", post(wallet::get_subaddrs))
        .route("/upsert_subaddrs", post(wallet::upsert_subaddrs))
        .route("/provision_subaddrs", post(wallet::provision_subaddrs))
        .route("/get_version", get(wallet::get_version).post(wallet::get_version))
        .route("/daemon_status", get(wallet::daemon_status).post(wallet::daemon_status))
        .layer(RequestBodyLimitLayer::new(4 * 1024 * 1024));
    if let Some(cors) = cors(&app.config.access_control_origins) {
        router = router.layer(cors);
    }
    router.with_state(app)
}

pub fn admin_router(app: Arc<App>) -> Router {
    let mut router = Router::new()
        .route("/{command}", post(admin::command))
        .layer(RequestBodyLimitLayer::new(1024 * 1024));
    if let Some(cors) = cors(&app.config.access_control_origins) {
        router = router.layer(cors);
    }
    router.with_state(app)
}
