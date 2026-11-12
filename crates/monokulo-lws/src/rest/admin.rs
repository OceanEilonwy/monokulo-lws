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
use crate::db::{Accepted, NewAccount, Status};
use crate::error::{Error, Result, bad};
use crate::{admin_keys, crypto};

fn authorize(app: &App, auth: Option<&lws_api::Hex32>) -> Result<()> {
    if !app.config.admin_auth {
        return Ok(());
    }
    let Some(auth) = auth else { return Err(Error::Forbidden) };
    if admin_keys::verify(&app.db, &auth.0)? {
        Ok(())
    } else {
        tracing::warn!("an admin request with a wrong key");
        Err(Error::Forbidden)
    }
}

fn params<P: DeserializeOwned>(value: &Value) -> Result<P> {
    parse_value(value.clone())
}

pub async fn command(
    State(app): State<Arc<App>>,
    Path(command): Path<String>,
    ApiJson(req): ApiJson<Request<Value>>,
) -> std::result::Result<Response, ApiError> {
    authorize(&app, req.auth.as_ref())?;
    let out = match command.as_str() {
        "accept_requests" => return Ok(accept(&app, params(&req.params)?)?),
        "reject_requests" => reject(&app, params(&req.params)?)?,
        "add_account" => add_account(&app, params(&req.params)?)?,
        "list_accounts" => list_accounts(&app)?,
        "list_requests" => list_requests(&app)?,
        "modify_account_status" => modify_status(&app, params(&req.params)?)?,
        "rescan" => rescan(&app, params(&req.params)?)?,
        "remove_accounts" => remove(&app, params(&req.params)?)?,
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
fn accept(app: &App, p: Requests) -> Result<Response> {
    match app.db.accept_requests(p.kind, &p.addresses)? {
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

fn reject(app: &App, p: Requests) -> Result<Value> {
    let taken = app.db.take_requests(p.kind, &p.addresses)?;
    Ok(json!({ "updated": taken.into_iter().map(|n| n.address).collect::<Vec<_>>() }))
}

fn add_account(app: &App, p: AddAccount) -> Result<Value> {
    // A key that isn't the address's is the operator's mistake, not a
    // failed login: a 400 with the reason, and 403 stays the admin key's.
    let checked = crypto::check_login(app.scanner.config.network, &p.address, &p.key.0).map_err(|e| match e {
        Error::Forbidden => bad("the view key doesn't belong to the address"),
        other => other,
    })?;
    let height = app.scanner.status().chain_height;
    let new = NewAccount {
        address: checked.address.clone(),
        view_key: checked.view_key,
        spend_pub: checked.spend_pub,
        view_pub: checked.view_pub,
        start_height: height.saturating_sub(1),
        generated_locally: false,
    };
    app.db.add_account(&new, Status::Active)?;
    app.scanner.wake.notify_one();
    Ok(json!({ "updated": [checked.address.clone()] }))
}

fn list_accounts(app: &App) -> Result<Value> {
    let mut out = Accounts::default();
    for a in app.db.accounts(None)? {
        let row = AccountRow {
            address: a.address,
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

fn list_requests(app: &App) -> Result<Value> {
    let mut out = PendingRequests::default();
    for (kind, new) in app.db.requests()? {
        let row = RequestRow {
            address: new.address,
            start_height: new.start_height,
        };
        match kind {
            RequestKind::Create => out.create.push(row),
            RequestKind::Import => out.import.push(row),
        }
    }
    Ok(serde_json::to_value(out).expect("json"))
}

fn modify_status(app: &App, p: ModifyStatus) -> Result<Value> {
    let status = Status::parse(&p.status).ok_or_else(|| bad("status must be active, inactive or hidden"))?;
    let done = app.db.set_status(&p.addresses, status)?;
    app.scanner.wake.notify_one();
    Ok(json!({ "updated": done }))
}

fn rescan(app: &App, p: Rescan) -> Result<Value> {
    let done = app.db.rescan(&p.addresses, p.height)?;
    app.scanner.wake.notify_one();
    Ok(json!({ "updated": done }))
}

/// Not in monero-lws's API, which only hides an account: forgets these
/// accounts and everything scanned for them.
fn remove(app: &App, p: Addresses) -> Result<Value> {
    let done = app.db.remove_accounts(&p.addresses)?;
    app.scanner.wake.notify_one();
    Ok(json!({ "removed": done }))
}

fn validate(app: &App, p: Validate) -> Result<Value> {
    use monero_wallet::address::{AddressType, MoneroAddress};
    use monero_wallet::ed25519::CompressedPoint;
    let key = |s: &str, what: &str| -> Result<[u8; 32]> {
        crate::daemon::hex32(s).ok_or_else(|| bad(format!("{what} must be 64 hex characters")))
    };
    let spend = key(&p.spend_public_hex, "spend_public_hex")?;
    let view_pub = key(&p.view_public_hex, "view_public_hex")?;
    let view_key = key(&p.view_key_hex, "view_key_hex")?;
    let spend_point = CompressedPoint::from(spend)
        .decompress()
        .ok_or_else(|| bad("spend_public_hex isn't a point"))?;
    let view_point = CompressedPoint::from(view_pub)
        .decompress()
        .ok_or_else(|| bad("view_public_hex isn't a point"))?;
    let address =
        MoneroAddress::new(app.scanner.config.network, AddressType::Legacy, spend_point, view_point).to_string();
    match crypto::check_login(app.scanner.config.network, &address, &view_key) {
        Ok(_) => Ok(json!({ "address": address })),
        Err(e) => Ok(json!({ "error": e.to_string() })),
    }
}
