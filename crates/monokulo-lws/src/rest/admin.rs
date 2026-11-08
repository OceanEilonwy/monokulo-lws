//! The admin API: `POST /<command>` with `{"auth": key, "params": {...}}`.
//! Commands and shapes follow monero-lws's admin REST API; webhooks aren't
//! built yet and answer 501.

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
use subtle::ConstantTimeEq;

use super::{ApiError, App};
use crate::crypto;
use crate::db::{NewAccount, Status};
use crate::error::{Error, Result, bad};

fn authorize(app: &App, auth: Option<&lws_api::Hex32>) -> Result<()> {
    if !app.config.admin_auth {
        return Ok(());
    }
    let Some(auth) = auth else { return Err(Error::Forbidden) };
    let mut ok = 0u8;
    for key in app.db.admin_keys()? {
        ok |= key.ct_eq(&auth.0).unwrap_u8();
    }
    if ok == 1 { Ok(()) } else { Err(Error::Forbidden) }
}

fn params<P: DeserializeOwned>(value: &Value) -> Result<P> {
    serde_json::from_value(value.clone()).map_err(|e| bad(format!("params: {e}")))
}

pub async fn command(
    State(app): State<Arc<App>>,
    Path(command): Path<String>,
    Json(req): Json<Request<Value>>,
) -> std::result::Result<Response, ApiError> {
    authorize(&app, req.auth.as_ref())?;
    let out = match command.as_str() {
        "accept_requests" => accept(&app, params(&req.params)?)?,
        "reject_requests" => reject(&app, params(&req.params)?)?,
        "add_account" => add_account(&app, params(&req.params)?)?,
        "list_accounts" => list_accounts(&app)?,
        "list_requests" => list_requests(&app)?,
        "modify_account_status" => modify_status(&app, params(&req.params)?)?,
        "rescan" => rescan(&app, params(&req.params)?)?,
        "validate" => validate(&app, params(&req.params)?)?,
        "webhook_add" | "webhook_delete" | "webhook_delete_uuid" | "webhook_list" => {
            return Ok((StatusCode::NOT_IMPLEMENTED, "webhooks aren't built yet").into_response());
        }
        _ => return Ok((StatusCode::NOT_FOUND, "no such admin command").into_response()),
    };
    Ok(Json(out).into_response())
}

fn accept(app: &App, p: Requests) -> Result<Value> {
    let taken = app.db.take_requests(&p.kind, &p.addresses)?;
    let mut done = vec![];
    for new in taken {
        match p.kind.as_str() {
            "create" => {
                app.db.add_account(&new, Status::Active)?;
            }
            "import" => {
                app.db.rescan(std::slice::from_ref(&new.address), 0)?;
            }
            _ => return Err(bad("type must be \"create\" or \"import\"")),
        }
        done.push(new.address);
    }
    app.scanner.wake.notify_one();
    Ok(json!({ "updated": done }))
}

fn reject(app: &App, p: Requests) -> Result<Value> {
    if p.kind != "create" && p.kind != "import" {
        return Err(bad("type must be \"create\" or \"import\""));
    }
    let taken = app.db.take_requests(&p.kind, &p.addresses)?;
    Ok(json!({ "updated": taken.into_iter().map(|n| n.address).collect::<Vec<_>>() }))
}

fn add_account(app: &App, p: AddAccount) -> Result<Value> {
    let checked = crypto::check_login(app.scanner.config.network, &p.address, &p.key.0)?;
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
    Ok(json!({ "updated": [checked.address] }))
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
        if kind == "create" {
            out.create.push(row)
        } else {
            out.import.push(row)
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
