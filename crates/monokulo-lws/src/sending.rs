//! The sending endpoints end to end, without a node or a GPU:
//! `/get_unspent_outs` over blocks made by `testkit`, `/get_random_outs` and
//! `/submit_raw_tx` against a fake node, each answer checked against what
//! monero-lws sends.

use std::sync::Arc;
use std::time::Instant;

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use curve25519_dalek::scalar::Scalar as DScalar;
use lws_api::{Amount, HexBytes, RandomOuts, RandomOutsRequest, SubmitRequest, UnspentOuts, UnspentOutsRequest};
use monero_wallet::{
    Scanner as OxideScanner,
    ed25519::CompressedPoint,
    primitives::keccak256,
    ringct::{EncryptedAmount, RctType},
    transaction::Transaction,
};
use serde_json::{Value, json};

use crate::crypto;
use crate::daemon::FeeEstimate;
use crate::db::Db;
use crate::error::Error;
use crate::rest::{ApiJson, App, wallet};
use crate::testkit::*;

fn request(w: &Wallet, amount: u64, mixin: u32, use_dust: bool, dust: Option<u64>) -> UnspentOutsRequest {
    UnspentOutsRequest {
        login: w.login(),
        amount: Amount(amount),
        mixin,
        use_dust,
        dust_threshold: dust.map(Amount),
    }
}

async fn unspent(app: &Arc<App>, req: UnspentOutsRequest) -> Result<UnspentOuts, Error> {
    match wallet::get_unspent_outs(State(app.clone()), ApiJson(req)).await {
        Ok(Json(v)) => Ok(v),
        Err(e) => Err(e.0),
    }
}

/// A ring of `n` far-off members (nobody's here).
fn ring_of(n: u64, key_image: u8) -> monero_wallet::transaction::Input {
    ring(&(1..=n).map(|i| i << 30).collect::<Vec<_>>(), key_image)
}

/// Block 100 for `w`: the miner pays it 600 XMR (global index 5,000), a
/// transaction with rings of 16 pays it 7,000,000 (5,001), one with rings
/// of 11 pays it 5,000 (5,002).
fn three_outputs(w: &Wallet) -> Made {
    let (_, mk) = tx_key(2);
    let miner = Tx::new(mk, vec![w.pay(&mk, 0, 0, 0, 600_000_000_000)]).miner(100);
    let (_, ka) = tx_key(3);
    let mut a = Tx::new(ka, vec![w.pay(&ka, 0, 0, 0, 7_000_000)]);
    a.inputs = vec![ring_of(16, 1)];
    let (_, kb) = tx_key(4);
    let mut b = Tx::new(kb, vec![w.pay(&kb, 0, 0, 0, 5_000)]);
    b.inputs = vec![ring_of(11, 2)];
    block(100, [0; 32], miner, vec![a.build(), b.build()], 5_000, 0)
}

fn indexes(outs: &UnspentOuts) -> Vec<u64> {
    outs.outputs.iter().map(|o| o.global_index.0).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn unspent_outs_filter_as_monero_lws() {
    let w = Wallet::new(300);
    let db = Arc::new(Db::in_memory());
    let account = w.add(&db, 100);
    write(&db, &[account], vec![three_outputs(&w)], 100, true, None);
    let app = app(db, 200);
    let all = 600_000_000_000 + 7_000_000 + 5_000;

    let outs = unspent(&app, request(&w, 0, 0, false, None)).await.unwrap();
    assert_eq!(indexes(&outs), [5_000, 5_001, 5_002]);
    assert_eq!(outs.amount, Amount(all));
    // A mixin leaves out the transactions with smaller rings, and coinbase
    // outputs (a miner transaction's mixin is 0).
    let outs = unspent(&app, request(&w, 0, 15, false, None)).await.unwrap();
    assert_eq!(indexes(&outs), [5_001]);
    assert_eq!(outs.amount, Amount(7_000_000), "the sum of what is listed");
    let outs = unspent(&app, request(&w, 0, 10, false, None)).await.unwrap();
    assert_eq!(indexes(&outs), [5_001, 5_002]);
    // The dust threshold, unless `use_dust`.
    let outs = unspent(&app, request(&w, 0, 0, false, Some(6_000))).await.unwrap();
    assert_eq!(indexes(&outs), [5_000, 5_001]);
    let outs = unspent(&app, request(&w, 0, 0, true, Some(6_000))).await.unwrap();
    assert_eq!(indexes(&outs), [5_000, 5_001, 5_002]);
    // `amount` only checks: every output comes back, or a 400.
    let outs = unspent(&app, request(&w, 1, 0, false, None)).await.unwrap();
    assert_eq!(outs.outputs.len(), 3, "not a selection reaching the amount");
    assert!(unspent(&app, request(&w, all, 0, false, None)).await.is_ok());
    let short = unspent(&app, request(&w, all + 1, 0, false, None)).await.unwrap_err();
    assert!(matches!(short, Error::InsufficientFunds));
    assert_eq!(short.status(), StatusCode::BAD_REQUEST);
    let short = unspent(&app, request(&w, 7_000_001, 15, false, None))
        .await
        .unwrap_err();
    assert!(matches!(short, Error::InsufficientFunds), "counted after the filters");

    // The wire shape: the fees as numbers, lowest priority first; the index
    // a number and again as `tx_id`; no `spend_key_images` when there are
    // none; the recipient.
    let outs = unspent(&app, request(&w, 0, 0, false, None)).await.unwrap();
    let json = serde_json::to_value(&outs).unwrap();
    assert_eq!(json["per_byte_fee"], json!(20_000));
    assert_eq!(json["fee_mask"], json!(10_000));
    assert_eq!(json["fees"], json!([20_000, 80_000, 320_000, 4_000_000]));
    assert_eq!(json["amount"], json!(all.to_string()));
    let first = &json["outputs"][1];
    assert_eq!(first["global_index"], json!(5_001));
    assert_eq!(first["tx_id"], json!(5_001));
    assert_eq!(first["amount"], json!("7000000"));
    assert_eq!(first["recipient"], json!({ "maj_i": 0, "min_i": 0 }));
    assert!(first.get("spend_key_images").is_none());
    assert_eq!(first["rct"].as_str().unwrap().len(), 192);
    assert!(json.get("lookahead_fail").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn unspent_outs_for_nothing_and_a_bad_fee() {
    let w = Wallet::new(302);
    let db = Arc::new(Db::in_memory());
    w.add(&db, 100);
    let app = app(db, 200);
    let outs = unspent(&app, request(&w, 0, 0, false, None)).await.unwrap();
    // As monero-lws: `{"per_byte_fee":..,"fee_mask":..,"amount":"0","fees":[..]}`.
    assert_eq!(
        serde_json::to_string(&outs).unwrap(),
        r#"{"per_byte_fee":20000,"fee_mask":10000,"amount":"0","fees":[20000,80000,320000,4000000]}"#
    );
    // A zero quantization mask from the node is refused, as monero-lws does.
    *app.fee.lock().await = Some((
        Instant::now(),
        FeeEstimate {
            fee: 20_000,
            quantization_mask: 0,
            fees: vec![],
        },
    ));
    let e = unspent(&app, request(&w, 0, 0, false, None)).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::SERVICE_UNAVAILABLE);
}

/// The `rct` blob of a regular output, put in a transaction whose amounts
/// are encrypted the original way (`RCTTypeBulletproof`: the mask and the
/// amount as 32-byte encrypted scalars) in place of the output's own, is
/// opened by monero-oxide's `Scanner`, which decrypts it as Monero does and
/// checks the result against the blob's commitment: it yields the stored
/// mask and amount.
#[tokio::test(flavor = "multi_thread")]
async fn the_rct_blob_opens_with_monero_oxide() {
    let w = Wallet::new(301);
    let db = Arc::new(Db::in_memory());
    let account = w.add(&db, 100);
    let (_, key) = tx_key(31);
    let paid = w.pay(&key, 0, 0, 1, 7_000_000);
    let tx = Tx::new(key, vec![stranger(5), paid.clone()]);
    let made = block(100, [0; 32], dull_miner(100), vec![tx.build()], 5_000, 0);
    write(&db, &[account], vec![made], 100, true, None);
    let app = app(db, 200);
    let outs = unspent(&app, request(&w, 0, 0, false, None)).await.unwrap();
    assert_eq!(outs.outputs.len(), 1);
    let blob = outs.outputs[0].rct.clone().unwrap().0;
    assert_eq!(&blob[..32], &paid.commitment);
    assert_ne!(&blob[32..64], &paid.mask, "the mask is encrypted");

    let mut old = tx.build();
    let Transaction::V2 {
        prefix,
        proofs: Some(proofs),
    } = &mut old
    else {
        unreachable!()
    };
    for o in &mut prefix.outputs {
        o.view_tag = None;
    }
    proofs.rct_type = RctType::MlsagBulletproofs;
    proofs.base.encrypted_amounts = vec![
        EncryptedAmount::Original {
            mask: [0; 32],
            amount: [0; 32],
        },
        EncryptedAmount::Original {
            mask: blob[32..64].try_into().unwrap(),
            amount: blob[64..].try_into().unwrap(),
        },
    ];
    proofs.base.commitments[1] = CompressedPoint::from(<[u8; 32]>::try_from(&blob[..32]).unwrap());
    let made = block(101, [1; 32], dull_miner(101), vec![old], 6_000, 0);
    let pair = crypto::view_pair(&w.spend_pub().compress().to_bytes(), &w.view_key()).unwrap();
    let found = OxideScanner::new(pair)
        .scan(made.block)
        .unwrap()
        .ignore_additional_timelock();
    assert_eq!(found.len(), 1, "opened, and the commitment matched");
    assert_eq!(found[0].commitment().amount, 7_000_000);
    let mask: DScalar = found[0].commitment().mask.into();
    assert_eq!(mask.to_bytes(), paid.mask);
}

/// A transaction as a client submits it: the pruned parts the testkit
/// makes, then bytes standing for the prunable part; and its hash.
fn submitted(tx: &Tx) -> (Vec<u8>, [u8; 32]) {
    let pruned = tx.build();
    let prunable = vec![0xab; 200];
    let hash = pruned.hash_with_prunable_hash(keccak256(&prunable)).unwrap();
    let mut bytes = pruned.serialize();
    bytes.extend(prunable);
    (bytes, hash)
}

async fn submit(app: &Arc<App>, tx: &[u8]) -> (StatusCode, String) {
    let request = SubmitRequest {
        tx: HexBytes(tx.to_vec()),
    };
    let response = match wallet::submit_raw_tx(State(app.clone()), ApiJson(request)).await {
        Ok(r) => r,
        Err(e) => e.into_response(),
    };
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

/// `w` with an output of 7,000,000 at global index 5,001 (block 100).
fn funded(w: &Wallet, node: &str) -> (Arc<App>, crate::db::Account) {
    let db = Arc::new(Db::in_memory());
    let account = w.add(&db, 100);
    write(
        &db,
        std::slice::from_ref(&account),
        vec![three_outputs(w)],
        100,
        true,
        None,
    );
    let account = db.account(&w.address()).unwrap().unwrap();
    (app_with_node(db, 200, node), account)
}

/// `w` spending its output 5,001 (in a ring with a stranger's) and paying
/// itself 2,000,000 change.
fn spend(w: &Wallet) -> Tx {
    let (_, k) = tx_key(77);
    let mut tx = Tx::new(k, vec![stranger(9), w.pay(&k, 0, 0, 1, 2_000_000)]);
    tx.inputs = vec![ring(&[17, 5_001], 0x42)];
    tx.fee = 12_345;
    tx
}

#[tokio::test(flavor = "multi_thread")]
async fn a_submitted_transaction_is_in_the_pool_view_at_once() {
    let node = fake_node(|route, _| match route {
        "send_raw_transaction" => json!({ "status": "OK", "not_relayed": false, "reason": "" }),
        _ => json!({}),
    })
    .await;
    let w = Wallet::new(303);
    let (app, account) = funded(&w, &node.url);
    app.scanner.as_if_live(std::slice::from_ref(&account));
    let (bytes, hash) = submitted(&spend(&w));

    let (status, body) = submit(&app, &bytes).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, r#"{"status":"OK"}"#));
    let sent = node.calls.lock().unwrap()[0].clone();
    assert_eq!(sent.0, "send_raw_transaction");
    assert_eq!(sent.1["tx_as_hex"], json!(hex::encode(&bytes)));
    assert_eq!(sent.1["do_not_relay"], json!(false));

    // Polled right after: the spend and the change, in the pool.
    let pooled = || async {
        let txs = wallet::get_address_txs(State(app.clone()), ApiJson(w.login()))
            .await
            .unwrap_or_else(|e| panic!("{}", e.0))
            .0;
        txs.transactions.into_iter().filter(|t| t.mempool).collect::<Vec<_>>()
    };
    let listed = pooled().await;
    assert_eq!(listed.len(), 1);
    let t = &listed[0];
    assert_eq!(t.hash.0, hash, "monerod's hash, prunable part included");
    assert_eq!(t.spent_outputs.len(), 1);
    assert_eq!(t.total_sent, Amount(7_000_000));
    assert_eq!(t.spent_outputs[0].key_image.0, [0x42; 32]);
    assert_eq!(t.total_received, Amount(2_000_000));
    assert_eq!(t.fee, Some(Amount(12_345)));
    assert!(t.height.is_none() && t.timestamp.is_none());

    // Submitted again (the node takes it again, as monerod does for a
    // transaction it already holds): the same answer, listed once.
    let (status, body) = submit(&app, &bytes).await;
    assert_eq!((status, body.as_str()), (StatusCode::OK, r#"{"status":"OK"}"#));
    assert_eq!(pooled().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn submit_answers_as_monero_lws() {
    let w = Wallet::new(304);
    let (bytes, _) = submitted(&spend(&w));
    // (the node's answer, the status and body monero-lws sends for it)
    let cases = [
        (
            json!({ "status": "Failed", "reason": "", "double_spend": true, "fee_too_low": true }),
            StatusCode::UNPROCESSABLE_ENTITY,
            r#"{"status":"Failed","reason":"double spend and fee too low"}"#,
        ),
        (
            json!({ "status": "OK", "reason": "Not relayed", "not_relayed": true }),
            StatusCode::OK,
            r#"{"status":"OK","reason":"Not relayed","not_relayed":true}"#,
        ),
        (
            json!({ "status": "Failed", "reason": "Sanity check failed", "sanity_check_failed": true }),
            StatusCode::UNPROCESSABLE_ENTITY,
            r#"{"status":"Failed","reason":"Sanity check failed"}"#,
        ),
        (
            json!({ "status": "Failed", "low_mixin": true, "tx_extra_too_big": true, "nonzero_unlock_time": true }),
            StatusCode::UNPROCESSABLE_ENTITY,
            r#"{"status":"Failed","reason":"mixin too low and tx_extra too long and non-zero unlock time"}"#,
        ),
        (
            json!({ "status": "BUSY" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            r#"{"status":"Failed","reason":"Not ready to accept transactions; try again later"}"#,
        ),
        (
            json!({ "status": "Failed" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            r#"{"status":"Failed","reason":"an unknown issue was found with the transaction"}"#,
        ),
        (
            json!({ "status": "Failed", "reason": "bad\u{1b}[31m\nthing" }),
            StatusCode::UNPROCESSABLE_ENTITY,
            r#"{"status":"Failed","reason":"bad[31mthing"}"#,
        ),
    ];
    for (answer, status, body) in cases {
        let node = fake_node(move |_, _| answer.clone()).await;
        let (app, account) = funded(&w, &node.url);
        app.scanner.as_if_live(std::slice::from_ref(&account));
        let got = submit(&app, &bytes).await;
        assert_eq!(got, (status, body.to_string()));
        let txs = wallet::get_address_txs(State(app.clone()), ApiJson(w.login()))
            .await
            .unwrap_or_else(|e| panic!("{}", e.0))
            .0;
        assert!(
            txs.transactions.iter().all(|t| !t.mempool),
            "not pooled unless relayed: {body}"
        );
    }

    // Not a transaction: 400, and the node isn't asked.
    let node = fake_node(|_, _| json!({ "status": "OK" })).await;
    let (app, _) = funded(&w, &node.url);
    for junk in [vec![1, 2, 3], bytes[..bytes.len() / 3].to_vec(), vec![]] {
        let (status, _) = submit(&app, &junk).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    assert!(node.routes().is_empty());
    // A miner transaction can't be submitted.
    let miner = dull_miner(5).serialize();
    assert_eq!(submit(&app, &miner).await.0, StatusCode::BAD_REQUEST);

    // An unreachable node: 503, and nothing of where it is.
    let (app, _) = funded(&w, "http://user:hunter2@127.0.0.1:9");
    let (status, body) = submit(&app, &bytes).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, "the node is unavailable; try again later");
}

/// A node with `blocks` blocks of ten RingCT outputs each, where an output
/// is locked when `locked` says so.
async fn node_with_outputs(blocks: u64, locked: fn(u64) -> bool) -> FakeNode {
    fake_node(move |route, body| match route {
        "get_output_distribution" => json!({
            "status": "OK",
            "distributions": [{
                "amount": 0,
                "start_height": 0,
                "base": 0,
                "distribution": (1..=blocks).map(|b| b * 10).collect::<Vec<_>>(),
            }],
        }),
        "get_outs" => {
            let outs: Vec<Value> = body["outputs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| {
                    let i = o["index"].as_u64().unwrap();
                    json!({
                        "key": format!("{i:064x}"),
                        "mask": format!("{:064x}", i + (1 << 60)),
                        "unlocked": !locked(i),
                        "height": i / 10,
                    })
                })
                .collect();
            json!({ "status": "OK", "outs": outs })
        }
        _ => json!({}),
    })
    .await
}

/// `/get_random_outs` as a client would call it: the limits are checked when
/// the JSON is read, as `ApiJson` reads it.
async fn random_outs(app: &Arc<App>, count: u32, amounts: Vec<u64>) -> Result<RandomOuts, Error> {
    let amounts: Vec<String> = amounts.iter().map(u64::to_string).collect();
    let body = json!({ "count": count, "amounts": amounts }).to_string();
    let req: RandomOutsRequest = crate::rest::parse_json(body.as_bytes())?;
    match wallet::get_random_outs(State(app.clone()), ApiJson(req)).await {
        Ok(Json(v)) => Ok(v),
        Err(e) => Err(e.0),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn random_outs_fill_every_ring_with_distinct_unlocked_members() {
    let node = node_with_outputs(2_000, |i| i % 7 == 0).await;
    let app = app_with_node(Arc::new(Db::in_memory()), 2_000, &node.url);
    let outs = random_outs(&app, 16, vec![0; 150]).await.unwrap();
    assert_eq!(outs.amount_outs.len(), 150);
    // Spendable: the outputs of all but the last nine blocks.
    let spendable = 1_991 * 10;
    for ring in &outs.amount_outs {
        assert_eq!(ring.amount, Amount(0));
        assert_eq!(ring.outputs.len(), 16, "never fewer than asked");
        let idx: Vec<u64> = ring.outputs.iter().map(|o| o.global_index.0).collect();
        assert!(idx.windows(2).all(|w| w[0] < w[1]), "sorted, no repeats: {idx:?}");
        for o in &ring.outputs {
            let i = o.global_index.0;
            assert!(i % 7 != 0, "a locked output");
            assert!(i < spendable, "too young to spend");
            assert_eq!(o.public_key.to_string(), format!("{i:064x}"));
            // The commitment, then 64 zero bytes, as monero-lws.
            assert_eq!(o.rct.0.len(), 96);
            assert_eq!(hex::encode(&o.rct.0[..32]), format!("{:064x}", i + (1 << 60)));
            assert!(o.rct.0[32..].iter().all(|b| *b == 0));
        }
    }
    let json = serde_json::to_value(&outs).unwrap();
    assert!(json["amount_outs"][0]["outputs"][0]["global_index"].is_string());

    // One distribution, and few `get_outs` (each round asks once for every
    // ring, in chunks of at most 1,000).
    let calls = node.calls.lock().unwrap().clone();
    let gets: Vec<&Value> = calls.iter().filter(|(r, _)| r == "get_outs").map(|(_, b)| b).collect();
    assert_eq!(calls.iter().filter(|(r, _)| r == "get_output_distribution").count(), 1);
    assert!(gets.len() <= 15, "{} get_outs", gets.len());
    assert!(gets.iter().all(|b| b["outputs"].as_array().unwrap().len() <= 1_000));
    let asked: usize = gets.iter().map(|b| b["outputs"].as_array().unwrap().len()).sum();
    assert!(asked < 150 * 16 * 2, "about what the rings lack, not more: {asked}");

    // The distribution is shared while it is fresh.
    random_outs(&app, 16, vec![0]).await.unwrap();
    let fetched = node.routes().iter().filter(|r| *r == "get_output_distribution").count();
    assert_eq!(fetched, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn random_outs_limits_and_edges() {
    let node = node_with_outputs(2_000, |_| false).await;
    let app = app_with_node(Arc::new(Db::in_memory()), 2_000, &node.url);
    // monero-lws's caps; pre-RingCT amounts aren't served.
    for (count, amounts) in [(21, vec![0]), (16, vec![0; 151]), (16, vec![0, 5_000])] {
        let e = random_outs(&app, count, amounts).await.unwrap_err();
        assert_eq!(e.status(), StatusCode::BAD_REQUEST);
    }
    // Nothing to pick: empty rings, and the node isn't asked.
    let outs = random_outs(&app, 0, vec![0, 0]).await.unwrap();
    assert_eq!(outs.amount_outs.len(), 2);
    assert!(outs.amount_outs.iter().all(|r| r.outputs.is_empty()));
    assert!(random_outs(&app, 16, vec![]).await.unwrap().amount_outs.is_empty());
    assert!(node.routes().is_empty());
    // The maximum works.
    let outs = random_outs(&app, 20, vec![0; 3]).await.unwrap();
    assert!(outs.amount_outs.iter().all(|r| r.outputs.len() == 20));

    // A chain with fewer spendable outputs than asked: no rings, as
    // monero-lws drops them; with exactly as many: all of them.
    // Ten blocks: the first block's ten outputs are spendable.
    let tiny = node_with_outputs(10, |_| false).await;
    let app = app_with_node(Arc::new(Db::in_memory()), 10, &tiny.url);
    assert!(random_outs(&app, 16, vec![0]).await.unwrap().amount_outs.is_empty());
    // Eleven: twenty.
    let small = node_with_outputs(11, |_| false).await;
    let app = app_with_node(Arc::new(Db::in_memory()), 11, &small.url);
    let outs = random_outs(&app, 20, vec![0]).await.unwrap();
    let idx: Vec<u64> = outs.amount_outs[0].outputs.iter().map(|o| o.global_index.0).collect();
    assert_eq!(idx, (0..20).collect::<Vec<_>>());

    // Nothing unlocked: after monero-lws's 64 rounds, 503, saying nothing
    // of the node.
    let locked = node_with_outputs(2_000, |_| true).await;
    let app = app_with_node(Arc::new(Db::in_memory()), 2_000, &locked.url);
    let e = random_outs(&app, 16, vec![0]).await.unwrap_err();
    assert_eq!(e.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!e.public_message().contains("127.0.0.1"), "{}", e.public_message());
    let rounds = locked.routes().iter().filter(|r| *r == "get_outs").count();
    assert!(rounds <= 64, "{rounds}");
}
