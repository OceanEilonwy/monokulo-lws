//! The wallet API handlers.

use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::IntoResponse,
};
use lws_api::*;
use serde_json::json;
use subtle::ConstantTimeEq;

use super::{ApiError, ApiJson, App, MAX_TX_BYTES, Policy};
use crate::crypto;
use crate::db::{Account, NewAccount, OutputRow, Status, TxRow};
use crate::error::{Error, Result, bad};
use crate::limits::ClientIp;
use crate::scanner::{PoolReceipt, PoolSpend, unlocked};

type Reply<T> = std::result::Result<Json<T>, ApiError>;

/// The account a login names, once the address parses, the key fits it and
/// the account is here and not hidden. Hidden, unknown, pending and a key
/// that doesn't fit all look the same: 403 and the same body. A wrong key
/// is refused by `check_login` before the database is asked, so neither the
/// answer nor its timing says whether an address has an account.
async fn authorize(app: &App, login: &Login) -> Result<Account> {
    let checked = crypto::check_login(app.scanner.config.network, &login.address, &login.view_key.0)?;
    let Some(account) = app.db.account(&checked.address)? else {
        return Err(Error::Forbidden);
    };
    if account.status == Status::Hidden || account.view_key.ct_eq(&checked.view_key).unwrap_u8() == 0 {
        return Err(Error::Forbidden);
    }
    app.db.touch(account.id)?;
    Ok(account)
}

/// As [`authorize`], for a call that changes the account (an import, new
/// subaddresses): an inactive account is served what was scanned but not
/// changed.
async fn authorize_active(app: &App, login: &Login) -> Result<Account> {
    let account = authorize(app, login).await?;
    if account.status != Status::Active {
        return Err(Error::Forbidden);
    }
    Ok(account)
}

/// The strict per-client limit, for a call that would make an account or a
/// request, and the global one on new accounts and requests.
fn creation_allowed(app: &App, client: Option<&Extension<ClientIp>>) -> Result<()> {
    if let Some(Extension(ClientIp(ip))) = client {
        app.limits.strict.check(*ip).map_err(Error::RateLimited)?;
    }
    app.limits.creation.check().map_err(|wait| {
        tracing::warn!("the limit on new accounts and requests an hour was reached");
        Error::RateLimited(wait)
    })
}

/// Refuses a new create or import request when the queue is full
/// (monero-lws's `--create-queue-max`).
fn queue_has_room(app: &App) -> Result<()> {
    let pending = app
        .db
        .read(|c| Ok(c.query_row("SELECT COUNT(*) FROM requests", [], |r| r.get::<_, i64>(0))? as u64))?;
    if pending >= app.limits.max_pending_requests {
        tracing::warn!("the queue of pending requests is full ({pending}): accept or reject some");
        return Err(Error::Busy("too many pending requests; try again later"));
    }
    Ok(())
}

fn lookahead(app: &App) -> Option<AddressMeta> {
    (app.config.lookahead > 0).then_some(AddressMeta {
        maj_i: 1,
        min_i: app.config.lookahead,
    })
}

fn meta(maj: u32, min: u32) -> AddressMeta {
    AddressMeta { maj_i: maj, min_i: min }
}

fn chain_height(app: &App) -> u64 {
    app.scanner.status().chain_height
}

/// The chain height a new account starts below: the scanner's last word, or
/// the node's if the scanner has not heard from it yet. Never 0 for want of
/// an answer, which would mean a scan of the whole chain.
async fn creation_height(app: &App) -> Result<u64> {
    match chain_height(app) {
        0 => Ok(app.info().await?.height),
        h => Ok(h),
    }
}

/// The fee served for a transaction, as monero-lws serves it: a
/// `uint64-string`, `"0"` for a coinbase transaction (stored as 0).
fn fee_of(fee: u64) -> Option<Amount> {
    Some(Amount(fee))
}

fn spend_of(o: &OutputRow, key_image: [u8; 32], mixin: u32) -> Spend {
    Spend {
        amount: Amount(o.amount),
        key_image: Hex(key_image),
        tx_pub_key: Hex(o.tx_pub_key),
        out_index: o.out_index,
        mixin,
        sender: Some(meta(o.maj, o.min)),
    }
}

/// Candidate spends of an account's outputs, by the spending transaction.
fn spends_by_tx(app: &App, account: &Account, outputs: &HashMap<i64, OutputRow>) -> Result<HashMap<i64, Vec<Spend>>> {
    let mut by_tx: HashMap<i64, Vec<Spend>> = HashMap::new();
    for s in app.db.spends(account.id)? {
        let Some(o) = outputs.get(&s.output) else { continue };
        by_tx.entry(s.tx).or_default().push(spend_of(o, s.key_image, s.mixin));
    }
    Ok(by_tx)
}

/// `/login`. The view key must fit the address (`check_login`) before
/// anything is looked up or stored. With `--create off` a new address gets
/// 501, as the community spec says; monero-lws has no such mode (it always
/// queues or accepts). Logs name accounts by row id, never by address.
pub async fn login(
    State(app): State<Arc<App>>,
    client: Option<Extension<ClientIp>>,
    ApiJson(req): ApiJson<LoginRequest>,
) -> Reply<LoginResponse> {
    let checked = crypto::check_login(app.scanner.config.network, &req.login.address, &req.login.view_key.0)?;
    if let Some(account) = app.db.account(&checked.address)? {
        if account.status == Status::Hidden || account.view_key.ct_eq(&checked.view_key).unwrap_u8() == 0 {
            return Err(Error::Forbidden.into());
        }
        app.db.touch(account.id)?;
        return Ok(Json(LoginResponse {
            new_address: false,
            generated_locally: Some(account.generated_locally),
            start_height: Some(account.start_height),
            lookahead: lookahead(&app),
        }));
    }
    if !req.create_account {
        return Err(Error::Forbidden.into());
    }
    if app.config.create == Policy::Off {
        return Err(Error::NoCreate.into());
    }
    creation_allowed(&app, client.as_ref())?;
    let height = creation_height(&app).await?;
    let new = NewAccount {
        address: checked.address.clone(),
        view_key: checked.view_key,
        spend_pub: checked.spend_pub,
        view_pub: checked.view_pub,
        start_height: height.saturating_sub(1),
        generated_locally: req.generated_locally,
    };
    match app.config.create {
        Policy::Off => Err(Error::NoCreate.into()),
        Policy::Auto => {
            let account = app.db.add_account(&new, Status::Active)?;
            app.scanner.wake.notify_one();
            tracing::info!("new account #{} from height {}", account.id, new.start_height);
            Ok(Json(LoginResponse {
                new_address: true,
                generated_locally: Some(req.generated_locally),
                start_height: Some(new.start_height),
                lookahead: lookahead(&app),
            }))
        }
        Policy::Approve => {
            queue_has_room(&app)?;
            if !app.db.add_request("create", &new)? {
                // Asked before and not yet accepted.
                return Err(Error::Forbidden.into());
            }
            tracing::info!("a new account request is waiting for approval");
            Ok(Json(LoginResponse {
                new_address: true,
                generated_locally: Some(req.generated_locally),
                start_height: Some(new.start_height),
                lookahead: lookahead(&app),
            }))
        }
    }
}

pub async fn get_address_info(State(app): State<Arc<App>>, ApiJson(login): ApiJson<Login>) -> Reply<AddressInfo> {
    let account = authorize(&app, &login).await?;
    let chain = chain_height(&app);
    let now = crate::db::now();
    let txs: HashMap<i64, TxRow> = app.db.txs(account.id)?.into_iter().map(|t| (t.id, t)).collect();
    let outputs: HashMap<i64, OutputRow> = app.db.outputs(account.id)?.into_iter().map(|o| (o.id, o)).collect();
    let mut total_received = 0u64;
    let mut locked = 0u64;
    for o in outputs.values() {
        total_received = total_received.saturating_add(o.amount);
        let tx = &txs[&o.tx];
        if !unlocked(o.height, tx.coinbase, tx.unlock_time, chain, now) {
            locked = locked.saturating_add(o.amount);
        }
    }
    let spent_outputs: Vec<Spend> = spends_by_tx(&app, &account, &outputs)?
        .into_values()
        .flatten()
        .collect();
    let total_sent = spent_outputs.iter().map(|s| s.amount.0).fold(0u64, u64::saturating_add);
    Ok(Json(AddressInfo {
        locked_funds: Amount(locked),
        total_received: Amount(total_received),
        total_sent: Amount(total_sent),
        scanned_height: account.scan_height,
        scanned_block_height: account.scan_height,
        start_height: account.start_height,
        transaction_height: account.scan_height,
        blockchain_height: chain,
        spent_outputs,
        lookahead: lookahead(&app),
        rates: None,
    }))
}

/// A stored proof as the wire carries it: the block, and the pruned parts
/// for a transaction other than the miner's.
fn proof_of(row: crate::db::ProofRow) -> Proof {
    let (tx_prefix, rct_base, prunable_hash) = match row.parts {
        Some(p) => (
            Some(HexBytes(p.prefix)),
            Some(HexBytes(p.rct_base)),
            p.prunable_hash.map(Hex),
        ),
        None => (None, None, None),
    };
    Proof {
        block: HexBytes(row.block),
        tx_prefix,
        rct_base,
        prunable_hash,
    }
}

pub async fn get_address_txs(State(app): State<Arc<App>>, ApiJson(login): ApiJson<Login>) -> Reply<AddressTxs> {
    let account = authorize(&app, &login).await?;
    let chain = chain_height(&app);
    let rows = app.db.txs(account.id)?;
    let outputs: HashMap<i64, OutputRow> = app.db.outputs(account.id)?.into_iter().map(|o| (o.id, o)).collect();
    let mut receives_by_tx: HashMap<i64, Vec<ReceivedOutput>> = HashMap::new();
    for o in outputs.values() {
        receives_by_tx.entry(o.tx).or_default().push(ReceivedOutput {
            commitment: o.commitment.map(Hex),
            amount: Amount(o.amount),
            public_key: Hex(o.public_key),
            index: o.out_index,
            global_index: o.global_index,
            tx_pub_key: Hex(o.tx_pub_key),
            rct: o.mask.map(Hex),
            recipient: meta(o.maj, o.min),
        });
    }
    let mut spends = spends_by_tx(&app, &account, &outputs)?;
    let mut proofs = app.db.proofs(account.id)?;
    let mut total_received = outputs.values().map(|o| o.amount).fold(0u64, u64::saturating_add);
    let mined: std::collections::HashSet<[u8; 32]> = rows.iter().map(|t| t.hash).collect();
    let mut transactions: Vec<Transaction> = rows
        .into_iter()
        .map(|t| {
            let mut receives = receives_by_tx.remove(&t.id).unwrap_or_default();
            receives.sort_by_key(|r| r.index);
            Transaction {
                proof: proofs.remove(&t.id).map(proof_of),
                fee: fee_of(t.fee),
                id: t.id as u64,
                hash: Hex(t.hash),
                timestamp: Some(Timestamp::from_unix(t.timestamp)),
                total_received: Amount(t.total_received),
                total_sent: Amount(t.total_sent),
                unlock_time: t.unlock_time,
                height: Some(t.height),
                spent_outputs: spends.remove(&t.id).unwrap_or_default(),
                receives,
                payment_id: t.payment_id.map(HexBytes),
                coinbase: t.coinbase,
                mempool: false,
                mixin: t.mixin,
            }
        })
        .collect();
    // What is still in the pool, one transaction per pool transaction. One
    // mined since the pool was last looked at is listed mined only.
    let (pool, pool_spends) = {
        let pool = app.scanner.mempool.lock().unwrap_or_else(|e| e.into_inner());
        (pool.for_account(account.id), pool.spends_for(account.id))
    };
    let mut pooled: Vec<([u8; 32], Vec<PoolReceipt>, Vec<PoolSpend>)> = vec![];
    let entry = |pooled: &mut Vec<([u8; 32], Vec<PoolReceipt>, Vec<PoolSpend>)>, hash: [u8; 32]| -> usize {
        match pooled.iter().position(|(h, _, _)| *h == hash) {
            Some(i) => i,
            None => {
                pooled.push((hash, vec![], vec![]));
                pooled.len() - 1
            }
        }
    };
    for r in pool.into_iter().filter(|r| !mined.contains(&r.tx_hash)) {
        let i = entry(&mut pooled, r.tx_hash);
        pooled[i].1.push(r);
    }
    for s in pool_spends.into_iter().filter(|s| !mined.contains(&s.tx_hash)) {
        if !outputs.contains_key(&s.output) {
            continue;
        }
        let i = entry(&mut pooled, s.tx_hash);
        pooled[i].2.push(s);
    }
    let next_id = transactions.iter().map(|t| t.id + 1).max().unwrap_or(1);
    for (n, (hash, mut receipts, spent)) in pooled.into_iter().enumerate() {
        receipts.sort_by_key(|r| r.out_index);
        let received = receipts.iter().map(|r| r.amount).fold(0, u64::saturating_add);
        // As monero-lws: a pool transaction's outputs count in the total.
        total_received = total_received.saturating_add(received);
        let spent_outputs: Vec<Spend> = spent
            .iter()
            .map(|s| spend_of(&outputs[&s.output], s.key_image, s.mixin))
            .collect();
        let (unlock_time, mixin, fee, payment_id) = match (receipts.first(), spent.first()) {
            (Some(r), _) => (r.unlock_time, r.mixin, r.fee, r.payment_id.clone()),
            (None, Some(s)) => (s.unlock_time, s.mixin, s.fee, None),
            (None, None) => continue,
        };
        transactions.push(Transaction {
            proof: None,
            fee: Some(Amount(fee)),
            id: next_id + n as u64,
            hash: Hex(hash),
            timestamp: None,
            total_received: Amount(received),
            total_sent: Amount(spent_outputs.iter().map(|s| s.amount.0).fold(0, u64::saturating_add)),
            unlock_time,
            height: None,
            spent_outputs,
            receives: receipts
                .iter()
                .map(|r| ReceivedOutput {
                    commitment: r.commitment.map(Hex),
                    amount: Amount(r.amount),
                    public_key: Hex(r.public_key),
                    index: r.out_index,
                    global_index: 0,
                    tx_pub_key: Hex(r.tx_pub_key),
                    rct: r.mask.map(Hex),
                    recipient: meta(r.maj, r.min),
                })
                .collect(),
            payment_id: payment_id.map(HexBytes),
            coinbase: false,
            mempool: true,
            mixin,
        });
    }
    Ok(Json(AddressTxs {
        total_received: Amount(total_received),
        scanned_height: account.scan_height,
        scanned_block_height: account.scan_height,
        start_height: account.start_height,
        transaction_height: account.scan_height,
        blockchain_height: chain,
        transactions,
        lookahead: lookahead(&app),
    }))
}

pub async fn get_unspent_outs(
    State(app): State<Arc<App>>,
    ApiJson(req): ApiJson<UnspentOutsRequest>,
) -> Reply<UnspentOuts> {
    let account = authorize(&app, &req.login).await?;
    let fee = app.fee().await?;
    let txs: HashMap<i64, TxRow> = app.db.txs(account.id)?.into_iter().map(|t| (t.id, t)).collect();
    let outputs = app.db.outputs(account.id)?;
    let mut images: HashMap<i64, Vec<Hex32>> = HashMap::new();
    for s in app.db.spends(account.id)? {
        images.entry(s.output).or_default().push(Hex(s.key_image));
    }
    let dust = if req.use_dust {
        0
    } else {
        req.dust_threshold.map(|d| d.0).unwrap_or(0)
    };
    let mut total = 0u64;
    let mut listed = vec![];
    for o in outputs {
        let tx = &txs[&o.tx];
        // As monero-lws: an output is left out when its transaction's mixin
        // is below the one asked for (a coinbase transaction's is 0, so any
        // mixin leaves coinbase outputs out) or its amount is below the
        // dust threshold. Locked outputs are listed; the client decides.
        if tx.mixin < req.mixin || o.amount < dust {
            continue;
        }
        total = total.saturating_add(o.amount);
        let rct = o.mask.and_then(|mask| {
            if tx.coinbase {
                Some(crypto::coinbase_rct())
            } else {
                // The commitment the chain holds for the output (the same as
                // monero-lws's `commit(amount, mask)` for a sound output).
                let commitment = o.commitment.unwrap_or_else(|| crypto::commit(&mask, o.amount));
                crypto::legacy_rct(
                    &account.view_key,
                    &o.tx_pub_key,
                    o.out_index as u64,
                    &commitment,
                    &mask,
                    o.amount,
                )
            }
            .map(|b| HexBytes(b.to_vec()))
        });
        listed.push(Output {
            amount: Amount(o.amount),
            public_key: Hex(o.public_key),
            index: o.out_index,
            global_index: Amount(o.global_index),
            // monero-lws writes the global index here too.
            tx_id: o.global_index,
            tx_hash: Hex(tx.hash),
            tx_prefix_hash: Hex(tx.prefix_hash),
            tx_pub_key: Hex(o.tx_pub_key),
            timestamp: Timestamp::from_unix(tx.timestamp),
            height: o.height,
            spend_key_images: images.remove(&o.id).unwrap_or_default(),
            rct,
            recipient: Some(meta(o.maj, o.min)),
        });
    }
    if total < req.amount.0 {
        return Err(Error::InsufficientFunds.into());
    }
    // monero-lws refuses a zero mask: every fee would be rounded to nothing.
    if fee.quantization_mask == 0 {
        return Err(Error::Daemon("get_fee_estimate: a zero quantization mask".into()).into());
    }
    Ok(Json(UnspentOuts {
        per_byte_fee: Amount(fee.fee),
        fee_mask: Amount(fee.quantization_mask),
        amount: Amount(total),
        lookahead_fail: None,
        outputs: listed,
        fees: fee.fees,
    }))
}

/// Ring members a ring and rings a request, at most: monero-lws's limits.
pub const MAX_RING_SIZE: u32 = 20;
pub const MAX_RINGS: usize = 150;

/// `/get_random_outs`, as monero-lws answers it: `count` members for every
/// ring, picked as wallet2 picks them (`decoys`), each unlocked by the
/// node's word, none twice in a ring, sorted by global index, with `rct`
/// the commitment and 64 zero bytes. Only RingCT (amount 0) is served;
/// monero-lws also serves pre-RingCT amounts from the node's histogram.
pub async fn get_random_outs(
    State(app): State<Arc<App>>,
    ApiJson(req): ApiJson<RandomOutsRequest>,
) -> Reply<RandomOuts> {
    if req.count > MAX_RING_SIZE {
        return Err(bad(format!("count must be at most {MAX_RING_SIZE}")).into());
    }
    if req.amounts.len() > MAX_RINGS {
        return Err(bad(format!("at most {MAX_RINGS} amounts")).into());
    }
    if req.amounts.iter().any(|a| a.0 != 0) {
        return Err(bad("only RingCT (amount 0) outputs are served").into());
    }
    // As monero-lws: nothing to pick, an empty ring for each amount, and the
    // node isn't asked.
    if req.count == 0 || req.amounts.is_empty() {
        return Ok(Json(RandomOuts {
            amount_outs: req
                .amounts
                .iter()
                .map(|_| RandomOutputs {
                    amount: Amount(0),
                    outputs: vec![],
                })
                .collect(),
        }));
    }
    let rings = app
        .picker
        .rings(&app.daemon, req.count as usize, req.amounts.len(), chain_height(&app))
        .await?;
    Ok(Json(RandomOuts {
        amount_outs: rings
            .into_iter()
            .map(|members| RandomOutputs {
                amount: Amount(0),
                outputs: members
                    .into_iter()
                    .map(|m| {
                        let mut rct = m.commitment.to_vec();
                        rct.resize(96, 0);
                        RandomOutput {
                            global_index: Amount(m.global_index),
                            public_key: Hex(m.public_key),
                            rct: HexBytes(rct),
                        }
                    })
                    .collect(),
            })
            .collect(),
    }))
}

/// The longest reason passed on from the node; monerod's are a few words.
const MAX_REASON: usize = 256;

/// Why the node refused a transaction, in the words monero-lws uses (those
/// of monerod's ZMQ `send_raw_tx_hex`, which it relays): the verification
/// flags joined with " and ", else the node's own reason, else monerod's
/// catch-all. Only printable ASCII of the node's text is kept, and not
/// much of it: it says what is wrong with the transaction, nothing more.
fn refusal_reason(r: &crate::daemon::SendResult) -> String {
    if r.status == "BUSY" {
        // monerod's JSON for an unsynchronised node; its ZMQ words for it.
        return "Not ready to accept transactions; try again later".into();
    }
    let flags = [
        (r.low_mixin, "mixin too low"),
        (r.double_spend, "double spend"),
        (r.invalid_input, "invalid input"),
        (r.invalid_output, "invalid output"),
        (r.too_big, "too big"),
        (r.overspend, "overspend"),
        (r.fee_too_low, "fee too low"),
        (r.too_few_outputs, "too few outputs"),
        (r.tx_extra_too_big, "tx_extra too long"),
        (r.nonzero_unlock_time, "non-zero unlock time"),
    ];
    let joined = flags
        .iter()
        .filter(|(set, _)| *set)
        .map(|(_, why)| *why)
        .collect::<Vec<_>>()
        .join(" and ");
    if !joined.is_empty() {
        return joined;
    }
    let own: String = r
        .reason
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(MAX_REASON)
        .collect();
    match own.trim() {
        "" => "an unknown issue was found with the transaction".into(),
        own => own.into(),
    }
}

/// `/submit_raw_tx`, answered as monero-lws answers it (see
/// [`SubmitResponse`]). The transaction must parse (its prefix and RingCT
/// base) or it is refused with 400 before the node sees it. Once the node
/// has taken and relayed it, it is scanned at once into the pool view for
/// the account it came from, so a client polling right after sees it in
/// `/get_address_txs` with `mempool: true`.
pub async fn submit_raw_tx(
    State(app): State<Arc<App>>,
    ApiJson(req): ApiJson<SubmitRequest>,
) -> std::result::Result<axum::response::Response, ApiError> {
    if req.tx.0.is_empty() {
        return Err(bad("an empty transaction").into());
    }
    if req.tx.0.len() > MAX_TX_BYTES {
        return Err(bad(format!("a transaction is at most {MAX_TX_BYTES} bytes")).into());
    }
    let Some((hash, tx)) = crate::scanner::parse_submitted(&req.tx.0) else {
        return Err(bad("not a transaction").into());
    };
    let result = app.daemon.send_raw(&hex::encode(&req.tx.0)).await?;
    if result.status == "OK" {
        if result.not_relayed {
            return Ok(Json(SubmitResponse {
                status: "OK".into(),
                reason: Some("Not relayed".into()),
                not_relayed: Some(true),
            })
            .into_response());
        }
        if let Err(e) = app.scanner.add_submitted(hash, tx).await {
            // The next look at the pool finds it anyway.
            tracing::warn!("a submitted transaction wasn't added to the pool view: {e}");
        }
        app.scanner.wake.notify_one();
        return Ok(Json(SubmitResponse {
            status: "OK".into(),
            reason: None,
            not_relayed: None,
        })
        .into_response());
    }
    Ok((
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(SubmitResponse {
            status: "Failed".into(),
            reason: Some(refusal_reason(&result)),
            not_relayed: None,
        }),
    )
        .into_response())
}

pub async fn import_wallet_request(
    State(app): State<Arc<App>>,
    client: Option<Extension<ClientIp>>,
    ApiJson(login): ApiJson<Login>,
) -> Reply<ImportResponse> {
    let account = authorize_active(&app, &login).await?;
    let reply = |new_request, request_fulfilled, status: &str| {
        Json(ImportResponse {
            payment_address: None,
            payment_id: None,
            import_fee: None,
            new_request,
            request_fulfilled,
            status: status.into(),
        })
    };
    match app.config.import {
        Policy::Off => Err(Error::NoCreate.into()),
        Policy::Auto => {
            // Nothing to do for an account that starts at 0, or whose
            // import hasn't got past block 0 yet.
            if account.start_height == 0 || account.scan_height == 0 {
                return Ok(reply(false, true, "Approved"));
            }
            creation_allowed(&app, client.as_ref())?;
            app.db.import(std::slice::from_ref(&account.address))?;
            app.scanner.wake.notify_one();
            tracing::info!("import for account #{}: scanning from 0", account.id);
            Ok(reply(true, true, "Approved"))
        }
        Policy::Approve => {
            let new = NewAccount {
                address: account.address.clone(),
                view_key: account.view_key,
                spend_pub: account.spend_pub,
                view_pub: account.view_pub,
                start_height: 0,
                generated_locally: account.generated_locally,
            };
            if app
                .db
                .requests()?
                .iter()
                .any(|(k, r)| k == "import" && r.address == new.address)
            {
                return Ok(reply(false, false, "Already requested"));
            }
            queue_has_room(&app)?;
            creation_allowed(&app, client.as_ref())?;
            let added = app.db.add_request("import", &new)?;
            Ok(reply(added, false, if added { "Pending" } else { "Already requested" }))
        }
    }
}

fn subaddresses_on(app: &App) -> Result<u64> {
    if app.config.max_subaddresses == 0 {
        return Err(Error::Conflict("subaddresses are off on this server".into()));
    }
    Ok(u64::from(app.config.max_subaddresses))
}

/// Ranges an `/upsert_subaddrs` may carry, at most, in all majors.
const MAX_RANGES: usize = 1_000;

/// An `/upsert_subaddrs` request's ranges, checked before the database sees
/// them: not too many, each the right way round, and not more minors in all
/// than an account may have (the database then checks the total with what
/// the account already has).
fn check_ranges(ranges: &[SubaddrRanges], max: u64) -> Result<()> {
    let count: usize = ranges.iter().map(|r| r.value.len()).sum();
    if count > MAX_RANGES {
        return Err(bad(format!("at most {MAX_RANGES} ranges a request")));
    }
    let mut minors = 0u64;
    for r in ranges {
        for &[lo, hi] in &r.value {
            if lo > hi {
                return Err(bad("a subaddress range runs backwards"));
            }
            minors += u64::from(hi - lo) + 1;
        }
    }
    if minors > max {
        return Err(Error::Conflict(format!("asking for more than the limit of {max}")));
    }
    Ok(())
}

pub async fn get_subaddrs(State(app): State<Arc<App>>, ApiJson(login): ApiJson<Login>) -> Reply<Subaddrs> {
    let max = subaddresses_on(&app)?;
    let account = authorize(&app, &login).await?;
    Ok(Json(Subaddrs {
        all_subaddrs: app.db.subaddrs(account.id)?,
        max_subaddrs: Some(max),
    }))
}

pub async fn upsert_subaddrs(
    State(app): State<Arc<App>>,
    ApiJson(req): ApiJson<UpsertSubaddrsRequest>,
) -> Reply<NewSubaddrs> {
    let max = subaddresses_on(&app)?;
    check_ranges(&req.subaddrs, max)?;
    let account = authorize_active(&app, &req.login).await?;
    let new_subaddrs = app.db.upsert_subaddrs(account.id, &req.subaddrs, max)?;
    let all_subaddrs = req.get_all.then(|| app.db.subaddrs(account.id)).transpose()?;
    Ok(Json(NewSubaddrs {
        new_subaddrs,
        all_subaddrs,
    }))
}

pub async fn provision_subaddrs(
    State(app): State<Arc<App>>,
    ApiJson(req): ApiJson<ProvisionSubaddrsRequest>,
) -> Reply<NewSubaddrs> {
    let max = subaddresses_on(&app)?;
    let account = authorize_active(&app, &req.login).await?;
    let maj_i = req.maj_i.unwrap_or(0);
    let n_maj = req.n_maj.unwrap_or(1).max(1);
    let n_min = req.n_min.unwrap_or(1).max(1);
    if u64::from(n_maj) * u64::from(n_min) > max {
        return Err(Error::Conflict(format!("asking for more than the limit of {max}")).into());
    }
    let have = app.db.subaddrs(account.id)?;
    let mut wanted = vec![];
    for maj in maj_i..maj_i.saturating_add(n_maj) {
        let next = have
            .iter()
            .find(|r| r.key == maj)
            .and_then(|r| r.value.iter().map(|[_, hi]| hi + 1).max())
            .unwrap_or(0);
        let lo = req.min_i.unwrap_or(next).max(next);
        wanted.push(SubaddrRanges {
            key: maj,
            value: vec![[lo, lo.saturating_add(n_min - 1)]],
        });
    }
    let new_subaddrs = app.db.upsert_subaddrs(account.id, &wanted, max)?;
    let all_subaddrs = req.get_all.then(|| app.db.subaddrs(account.id)).transpose()?;
    Ok(Json(NewSubaddrs {
        new_subaddrs,
        all_subaddrs,
    }))
}

pub async fn get_version(State(app): State<Arc<App>>) -> Reply<Version> {
    let status = app.scanner.status();
    let info = app.info().await.ok();
    let network = app.scanner.config.network;
    Ok(Json(Version {
        server_type: "monokulo-lws".into(),
        last_git_commit_hash: option_env!("MONOKULO_LWS_COMMIT").map(String::from),
        last_commit_date: None,
        monero_version_full: info.as_ref().map(|i| i.version.clone()).unwrap_or_default(),
        blockchain_height: info.map(|i| i.height).unwrap_or(status.chain_height),
        api: 2,
        max_subaddresses: app.config.max_subaddresses,
        network: crypto::network_name(network).into(),
        testnet: network != monero_wallet::address::Network::Mainnet,
    }))
}

/// Not in any spec: how the scanner and the daemon are doing. Public, so it
/// says nothing of where the node is.
pub async fn daemon_status(State(app): State<Arc<App>>) -> Reply<serde_json::Value> {
    let status = app.scanner.status();
    let info = app.info().await;
    Ok(Json(json!({
        "server": env!("CARGO_PKG_VERSION"),
        "network": crypto::network_name(app.scanner.config.network),
        "daemon_reachable": info.is_ok(),
        "daemon_height": info.as_ref().map(|i| i.height).unwrap_or(status.chain_height),
        "daemon_synced": info.as_ref().map(|i| i.synchronized).unwrap_or(false),
        "scanner_height": status.scanner_height,
        // Whether the last step failed; what failed is in the server's log
        // (it can name the node, which a public endpoint shouldn't).
        "scanner_error": status.last_error.as_ref().map(|_| "the last scan step failed; see the server log"),
        "scanner_seconds_ago": status.last_step.map(|t| t.elapsed().as_secs()),
        // What finds the outputs: the GPU's prefilter, or monero-oxide alone and why.
        "scanner_engine": match monokulo_8ar::engine() {
            monokulo_8ar::Engine::Gpu { name } => json!({ "gpu": true, "name": name }),
            monokulo_8ar::Engine::Cpu { reason } => json!({ "gpu": false, "reason": format!("{reason:?}") }),
        },
        "live_lane_height": status.scanner_height,
        "catch_up_lanes": status.lanes,
    })))
}
