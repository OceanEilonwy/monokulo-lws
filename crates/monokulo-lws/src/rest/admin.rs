//! The admin API: `POST /<command>` with `{"auth": key, "params": {...}}`.
//! Commands and shapes follow monero-lws's admin REST API; webhooks aren't
//! built yet and answer 501.
//!
//! It is served only on the admin listener (`--admin-listen`); the wallet
//! listener has no route to it. The key is checked against the stored
//! hashes in constant time (`admin_keys`).

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use lws_api::admin::*;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{ApiError, ApiJson, App, parse_value};
use crate::address::Address;
use crate::db::{Accepted, Status};
use crate::error::{Error, Result, bad};
use crate::{admin_keys, crypto};

async fn authorize(app: &App, auth: Option<lws_api::AdminKey>) -> Result<()> {
    if !app.config.admin_auth {
        return Ok(());
    }
    let Some(key) = auth else { return Err(Error::Forbidden) };
    if app.db.call(move |db| admin_keys::verify(db, &key)).await? {
        Ok(())
    } else {
        tracing::warn!("an admin request with a wrong key");
        Err(Error::Forbidden)
    }
}

fn params<P: DeserializeOwned>(value: &Value) -> Result<P> {
    parse_value(value.clone())
}

/// The addresses a command names, each parsed as a primary address on this
/// network. One that doesn't parse fails the whole command (400), as in
/// monero-lws; the error doesn't quote it.
fn addresses(app: &App, list: &[String]) -> Result<Vec<Address>> {
    list.iter()
        .map(|a| {
            Address::parse(app.scanner.config.network, a)
                .map_err(|_| bad("an address isn't a primary address on this network"))
        })
        .collect()
}

pub async fn command(
    State(app): State<Arc<App>>,
    Path(command): Path<String>,
    ApiJson(req): ApiJson<Request<Value>>,
) -> std::result::Result<Response, ApiError> {
    authorize(&app, req.auth).await?;
    let out = match command.as_str() {
        "accept_requests" => return Ok(accept(&app, params(&req.params)?).await?),
        "reject_requests" => reject(&app, params(&req.params)?).await?,
        "add_account" => add_account(&app, params(&req.params)?).await?,
        "list_accounts" => list_accounts(&app).await?,
        "list_requests" => list_requests(&app).await?,
        "modify_account_status" => modify_status(&app, params(&req.params)?).await?,
        "rescan" => rescan(&app, params(&req.params)?).await?,
        "remove_accounts" => remove(&app, params(&req.params)?).await?,
        "validate" => validate(&app, params(&req.params)?)?,
        "webhook_add" | "webhook_delete" | "webhook_delete_uuid" | "webhook_list" => {
            return Ok((StatusCode::NOT_IMPLEMENTED, "webhooks aren't built yet").into_response());
        }
        _ => return Ok((StatusCode::NOT_FOUND, "no such admin command").into_response()),
    };
    Ok(Json(out).into_response())
}

/// All or nothing: if any named create request's address already has an
/// account, 409 with those addresses and nothing is accepted.
async fn accept(app: &App, p: Requests) -> Result<Response> {
    let named = addresses(app, &p.addresses)?;
    match app.db.call(move |db| db.accept_requests(p.kind, &named)).await? {
        Accepted::Done(done) => {
            app.scanner.wake.notify_one();
            Ok(Json(json!({ "updated": done })).into_response())
        }
        Accepted::Exists(exists) => Ok((
            StatusCode::CONFLICT,
            Json(json!({
                "error": "these addresses already have an account; nothing was accepted",
                "exists": exists,
            })),
        )
            .into_response()),
    }
}

async fn reject(app: &App, p: Requests) -> Result<Value> {
    let named = addresses(app, &p.addresses)?;
    let taken = app.db.call(move |db| db.take_requests(p.kind, &named)).await?;
    Ok(json!({ "updated": taken.into_iter().map(|n| n.address).collect::<Vec<_>>() }))
}

async fn add_account(app: &App, p: AddAccount) -> Result<Value> {
    // A key that isn't the address's is the operator's mistake, not a
    // failed login: a 400 with the reason, and 403 stays the admin key's.
    let checked = crypto::check_login(app.scanner.config.network, &p.address, p.key).map_err(|e| match e {
        Error::Forbidden => bad("the view key doesn't belong to the address"),
        other => other,
    })?;
    let height = app.scanner.status().chain_height;
    let new = checked.into_new_account(height.saturating_sub(1), false);
    let address = new.address.clone();
    app.db.call(move |db| db.add_account(&new, Status::Active)).await?;
    app.scanner.wake.notify_one();
    Ok(json!({ "updated": [address] }))
}

async fn list_accounts(app: &App) -> Result<Value> {
    let mut out = Accounts::default();
    for a in app.db.call(|db| db.accounts(None)).await? {
        let row = AccountRow {
            address: a.address.as_str().to_owned(),
            scan_height: a.scan_height,
            access_time: a.access_time,
        };
        match a.status {
            Status::Active => out.active.push(row),
            Status::Inactive => out.inactive.push(row),
            Status::Hidden => out.hidden.push(row),
        }
    }
    Ok(serde_json::to_value(out).expect("json"))
}

async fn list_requests(app: &App) -> Result<Value> {
    let mut out = PendingRequests::default();
    for (kind, new) in app.db.call(|db| db.requests()).await? {
        let row = RequestRow {
            address: new.address.as_str().to_owned(),
            start_height: new.start_height,
        };
        match kind {
            RequestKind::Create => out.create.push(row),
            RequestKind::Import => out.import.push(row),
        }
    }
    Ok(serde_json::to_value(out).expect("json"))
}

async fn modify_status(app: &App, p: ModifyStatus) -> Result<Value> {
    let status = Status::parse(&p.status).ok_or_else(|| bad("status must be active, inactive or hidden"))?;
    let named = addresses(app, &p.addresses)?;
    let done = app.db.call(move |db| db.set_status(&named, status)).await?;
    app.scanner.wake.notify_one();
    Ok(json!({ "updated": done }))
}

async fn rescan(app: &App, p: Rescan) -> Result<Value> {
    let named = addresses(app, &p.addresses)?;
    let done = app.db.call(move |db| db.rescan(&named, p.height)).await?;
    app.scanner.wake.notify_one();
    Ok(json!({ "updated": done }))
}

/// Not in monero-lws's API, which only hides an account: forgets these
/// accounts and everything scanned for them.
async fn remove(app: &App, p: Addresses) -> Result<Value> {
    let named = addresses(app, &p.addresses)?;
    let done = app.db.call(move |db| db.remove_accounts(&named)).await?;
    app.scanner.wake.notify_one();
    Ok(json!({ "removed": done }))
}

fn validate(app: &App, p: Validate) -> Result<Value> {
    use monero_wallet::ed25519::CompressedPoint;
    let spend_point = CompressedPoint::from(p.spend_public_hex.0)
        .decompress()
        .ok_or_else(|| bad("spend_public_hex isn't a point"))?;
    let view_point = CompressedPoint::from(p.view_public_hex.0)
        .decompress()
        .ok_or_else(|| bad("view_public_hex isn't a point"))?;
    let address = Address::from_keys(app.scanner.config.network, spend_point, view_point);
    match crypto::check_key(address, p.view_key_hex) {
        Ok(checked) => Ok(json!({ "address": checked.address() })),
        Err(e) => Ok(json!({ "error": e.to_string() })),
    }
}
