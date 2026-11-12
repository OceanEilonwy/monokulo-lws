//! What the server answers, end to end without a node or a GPU: blocks made
//! by `testkit` go through the scanner's writing (unfiltered, as without a
//! GPU, and with a hit for every transaction, as the keyring's stand-in
//! blocks are scanned) and the wallet handlers are called on the result.

use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;

use axum::{Json, extract::State};

use crate::rest::ApiJson;
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar as DScalar};
use lws_api::{AddressInfo, AddressTxs, Amount, LoginRequest, Timestamp, UnspentOuts, UnspentOutsRequest};
use monero_wallet::{
    Scanner as OxideScanner,
    ed25519::{CompressedPoint, Scalar},
    extra::Extra,
    interface::ScannableBlock,
    ringct::{EncryptedAmount, PrunedRctProofs, RctBase, RctType},
    transaction::{Timelock, Transaction},
};

use crate::crypto;
use crate::db::{Account, Db, ScanWriter, Status};
use crate::error::Error;
use crate::rest::{App, wallet};
use crate::scanner::{Batch, Ring, pool_block, record_batch, scan_pool_block, stand_in};
use crate::testkit::*;

fn unwrap<T>(r: std::result::Result<Json<T>, crate::rest::ApiError>) -> T {
    match r {
        Ok(Json(v)) => v,
        Err(e) => panic!("{}", e.0),
    }
}

async fn txs(app: &Arc<App>, w: &Wallet) -> AddressTxs {
    unwrap(wallet::get_address_txs(State(app.clone()), ApiJson(w.login())).await)
}

async fn info(app: &Arc<App>, w: &Wallet) -> AddressInfo {
    unwrap(wallet::get_address_info(State(app.clone()), ApiJson(w.login())).await)
}

async fn unspent(app: &Arc<App>, w: &Wallet) -> UnspentOuts {
    unwrap(
        wallet::get_unspent_outs(
            State(app.clone()),
            ApiJson(UnspentOutsRequest {
                login: w.login(),
                amount: Amount(0),
                mixin: 0,
                use_dust: true,
                dust_threshold: None,
            }),
        )
        .await,
    )
}

/// What each way of scanning writes for these accounts: (account, global
/// index, out index, amount, height), sorted.
fn outputs_of(db: &Db, accounts: &[Account]) -> Vec<(i64, u64, u16, u64, u64)> {
    let mut all: Vec<_> = accounts
        .iter()
        .flat_map(|a| {
            db.outputs(a.id)
                .unwrap()
                .into_iter()
                .map(move |o| (a.id, o.global_index, o.out_index, o.amount, o.height))
        })
        .collect();
    all.sort();
    all
}

/// The same blocks written for fresh accounts with the same keys, unfiltered
/// and with a hit for every transaction: both write exactly the same rows.
fn both_ways(wallets: &[&Wallet], start: u64, make: impl Fn() -> Vec<Made>) -> (Db, Vec<Account>) {
    let unfiltered = Db::in_memory();
    let accounts: Vec<Account> = wallets.iter().map(|w| w.add(&unfiltered, start)).collect();
    write(&unfiltered, &accounts, make(), start, true, None);
    let filtered = Db::in_memory();
    let accounts_f: Vec<Account> = wallets.iter().map(|w| w.add(&filtered, start)).collect();
    write(&filtered, &accounts_f, make(), start, true, Some(&every_hit));
    assert_eq!(
        outputs_of(&unfiltered, &accounts),
        outputs_of(&filtered, &accounts_f),
        "stand-in blocks write what whole blocks write"
    );
    for (a, b) in accounts.iter().zip(&accounts_f) {
        assert_eq!(
            unfiltered.spends(a.id).unwrap().len(),
            filtered.spends(b.id).unwrap().len()
        );
        assert_eq!(unfiltered.txs(a.id).unwrap().len(), filtered.txs(b.id).unwrap().len());
    }
    (unfiltered, accounts)
}

fn found(w: &Wallet, block: ScannableBlock) -> Vec<(u64, [u8; 32], u64)> {
    let pair = crypto::view_pair(&w.spend_pub().compress().to_bytes(), &w.view.to_bytes()).unwrap();
    let mut scanner = OxideScanner::new(pair);
    let mut out: Vec<_> = scanner
        .scan(block)
        .unwrap()
        .ignore_additional_timelock()
        .iter()
        .map(|o| (o.index_on_blockchain(), o.transaction(), o.commitment().amount))
        .collect();
    out.sort();
    out
}

/// A block of a paying miner transaction and fifteen others of one to five
/// outputs (and one of none), `a` paid in the 1st, 7th and last, `b` in the
/// 7th too.
fn busy_block(a: &Wallet, b: &Wallet, number: usize, first: u64) -> Made {
    let (_, mk) = tx_key(500);
    let miner = Tx::new(mk, vec![stranger(1).plain(), a.pay(&mk, 0, 0, 1, 1_000_000)]).miner(number);
    let mut txs = vec![];
    for i in 1..=16usize {
        let (_, key) = tx_key(600 + i as u64);
        let count = if i == 9 { 0 } else { 1 + i % 5 };
        let mut outs: Vec<Out> = (0..count).map(|o| stranger((i * 10 + o) as u64)).collect();
        if i == 1 || i == 7 || i == 16 {
            let at = outs.len() - 1;
            outs[at] = a.pay(&key, 0, 0, at as u64, 100 + i as u64);
        }
        if i == 7 {
            outs[0] = b.pay(&key, 0, 0, 0, 7_000);
        }
        txs.push(Tx::new(key, outs).build());
    }
    block(number, [0; 32], miner, txs, first, 0)
}

#[test]
fn a_stand_in_block_numbers_outputs_as_the_whole_block_does() {
    let (a, b) = (Wallet::new(1), Wallet::new(2));
    let made = busy_block(&a, &b, 300, 70_000);
    for w in [&a, &b] {
        let whole = found(w, made.block.clone());
        let mut parts = vec![];
        for tx in 0..=made.block.transactions.len() {
            parts.extend(found(w, stand_in(&made.block, &made.first_indexes, tx).unwrap()));
        }
        parts.sort();
        assert_eq!(whole, parts, "every transaction alone finds what the block finds");
    }
    let whole = found(&a, made.block.clone());
    assert_eq!(whole.len(), 4, "the miner's and three others");
    // Global indexes from the chain's count: the miner's two, then 1 + i % 5 a transaction.
    let mut expected = vec![70_001];
    let mut next = 70_002u64;
    for i in 1..=16u64 {
        let count = if i == 9 { 0 } else { 1 + i % 5 };
        if i == 1 || i == 7 || i == 16 {
            expected.push(next + count - 1);
        }
        next += count;
    }
    assert_eq!(whole.iter().map(|w| w.0).collect::<Vec<_>>(), expected);
    let (db, accounts) = both_ways(&[&a, &b], 300, || vec![busy_block(&a, &b, 300, 70_000)]);
    assert_eq!(outputs_of(&db, &accounts).len(), 5);
}

/// The mainnet fixture (monokulo-8ar's
/// prototypes/fixtures/mainnet-3797000-2000.bin, outside this repository)
/// if it is at `path`. Missing, it fails the test when `required`
/// (LWS_REQUIRE_FIXTURE=1, as CI sets it, so the test can't pass without
/// running); otherwise the test is skipped, and says so.
fn find_fixture(path: std::path::PathBuf, required: bool) -> Option<std::path::PathBuf> {
    if path.exists() {
        return Some(path);
    }
    assert!(
        !required,
        "no fixture at {} and LWS_REQUIRE_FIXTURE=1: set LWS_FIXTURE to monokulo-8ar's \
         prototypes/fixtures/mainnet-3797000-2000.bin",
        path.display()
    );
    eprintln!(
        "SKIPPED: no fixture at {}, so the mainnet-shaped test did not run; set LWS_FIXTURE to monokulo-8ar's \
         prototypes/fixtures/mainnet-3797000-2000.bin (LWS_REQUIRE_FIXTURE=1 makes a missing fixture fail)",
        path.display()
    );
    None
}

#[test]
#[should_panic(expected = "LWS_REQUIRE_FIXTURE=1")]
fn a_missing_fixture_fails_when_it_is_required() {
    find_fixture("/nonexistent/mainnet-3797000-2000.bin".into(), true);
}

#[test]
fn a_missing_fixture_is_skipped_when_it_is_not_required() {
    assert!(find_fixture("/nonexistent/mainnet-3797000-2000.bin".into(), false).is_none());
    let here = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    assert_eq!(find_fixture(here.clone(), true), Some(here));
}

/// The fixture's first blocks, mainnet-shaped (about 57 transactions a
/// block), with payments to `w` planted in some transactions: each planted
/// output gets the transaction's own key and RingCT parts.
fn fixture_with_payments(w: &Wallet) -> Option<(Vec<Made>, Vec<u64>)> {
    let path = std::env::var("LWS_FIXTURE")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../../monokulo-8ar/prototypes/fixtures/mainnet-3797000-2000.bin")
        });
    let required = std::env::var("LWS_REQUIRE_FIXTURE").is_ok_and(|v| v == "1");
    let path = find_fixture(path, required)?;
    let (blocks, firsts, _) = crate::scanner::fixture_blocks(&path).unwrap();
    let mut made = vec![];
    let mut expected = vec![];
    for (b, (mut block, first_indexes)) in blocks.into_iter().zip(firsts).take(40).enumerate() {
        let n = block.transactions.len();
        let plant: BTreeSet<usize> = [1, n / 2, n].into_iter().filter(|&t| t >= 1 && b % 3 == 0).collect();
        for &t in &plant {
            let tx = &block.transactions[t - 1];
            let prefix = tx.prefix().clone();
            let extra = Extra::read(&mut prefix.extra.as_slice()).unwrap();
            let key = extra.keys().unwrap().0[0];
            let key: curve25519_dalek::EdwardsPoint = key.into();
            let Some(at) = prefix.outputs.iter().position(|o| o.key != CompressedPoint::IDENTITY) else {
                continue;
            };
            let paid = w.pay(&key, 0, 0, at as u64, 1_000 + (b * 100 + t) as u64);
            let mut outputs = prefix.outputs.clone();
            outputs[at] = paid.output.clone();
            let strangers: Vec<Out> = (0..outputs.len()).map(|i| stranger(i as u64 + 1)).collect();
            let mut commitments: Vec<CompressedPoint> =
                strangers.iter().map(|s| CompressedPoint::from(s.commitment)).collect();
            let mut encrypted: Vec<EncryptedAmount> = strangers.iter().map(|s| s.encrypted.clone()).collect();
            commitments[at] = CompressedPoint::from(paid.commitment);
            encrypted[at] = paid.encrypted.clone();
            block.transactions[t - 1] = Transaction::V2 {
                prefix: monero_wallet::transaction::TransactionPrefix { outputs, ..prefix },
                proofs: Some(PrunedRctProofs {
                    rct_type: RctType::ClsagBulletproofPlus,
                    base: RctBase {
                        fee: 1,
                        pseudo_outs: vec![],
                        encrypted_amounts: encrypted,
                        commitments,
                    },
                }),
            };
            expected.push(first_indexes[t].unwrap() + at as u64);
        }
        made.push(Made {
            block,
            first_indexes,
            next: 0,
            raw: None,
        });
    }
    expected.sort();
    Some((made, expected))
}

#[test]
fn stand_in_blocks_keep_global_indexes_on_mainnet_shaped_blocks() {
    let w = Wallet::new(3);
    let Some((_, expected)) = fixture_with_payments(&w) else {
        return;
    };
    assert!(expected.len() >= 30, "payments planted");
    let (db, accounts) = both_ways(&[&w], 3_797_000, || fixture_with_payments(&w).unwrap().0);
    let got: Vec<u64> = db
        .outputs(accounts[0].id)
        .unwrap()
        .iter()
        .map(|o| o.global_index)
        .collect();
    let mut got_sorted = got.clone();
    got_sorted.sort();
    assert_eq!(
        got_sorted, expected,
        "each output at its transaction's first index plus its own"
    );
}

/// Block 100: a miner transaction paying `w` 0.6 XMR, and a transaction
/// paying a stranger and `w` 7,000,000 with a fee of 30,000,000.
fn paying_block(w: &Wallet) -> (Made, Out, Out) {
    let (_, mk) = tx_key(2);
    let mined = w.pay(&mk, 0, 0, 0, 600_000_000_000);
    let miner = Tx::new(mk, vec![mined.clone()]).miner(100);
    let (_, key) = tx_key(1);
    let paid = w.pay(&key, 0, 0, 1, 7_000_000);
    let tx = Tx::new(key, vec![stranger(5), paid.clone()]);
    (block(100, [0; 32], miner, vec![tx.build()], 5_000, 0), mined, paid)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_served_commitment_is_the_chains_and_heads_the_rct_blob() {
    let w = Wallet::new(1);
    let db = Arc::new(Db::in_memory());
    let account = w.add(&db, 100);
    let (made, mined, paid) = paying_block(&w);
    write(&db, &[account], vec![made], 100, true, Some(&every_hit));
    let app = app(db, 200);

    let txs = txs(&app, &w).await;
    assert_eq!(txs.transactions.len(), 2);
    let coinbase = &txs.transactions[0];
    let payment = &txs.transactions[1];
    assert!(coinbase.coinbase && !payment.coinbase);
    let r = &payment.receives[0];
    assert_eq!(r.global_index, 5_002, "after the miner's output and the stranger's");
    assert_eq!(r.amount, Amount(7_000_000));
    let commitment = r.commitment.expect("served").0;
    assert_eq!(commitment, paid.commitment, "the transaction's outPk");
    let mask = r.rct.expect("the mask").0;
    assert_eq!(mask, paid.mask);
    let amount_h: curve25519_dalek::EdwardsPoint =
        monero_wallet::ed25519::Commitment::new(Scalar::from(DScalar::ZERO), 7_000_000)
            .commit()
            .into();
    let opened = &DScalar::from_bytes_mod_order(mask) * ED25519_BASEPOINT_TABLE + amount_h;
    assert_eq!(opened.compress().to_bytes(), commitment, "mask·G + amount·H");

    let m = &coinbase.receives[0];
    assert_eq!(m.global_index, 5_000);
    assert_eq!(m.amount, Amount(mined.amount));
    assert_eq!(m.rct.unwrap().0, *DScalar::ONE.as_bytes(), "a miner output's mask is 1");
    assert_eq!(
        m.commitment.unwrap().0,
        crypto::commit(DScalar::ONE.as_bytes(), mined.amount),
        "G + amount·H, the chain's commitment for a miner output"
    );

    // The fee, as monero-lws serves it: a decimal string, none on a coinbase.
    assert_eq!(payment.fee, Some(Amount(30_000_000)));
    assert_eq!(
        coinbase.fee,
        Some(Amount(0)),
        "a coinbase pays none, served as monero-lws does"
    );
    let json = serde_json::to_value(&txs).unwrap();
    assert_eq!(json["transactions"][1]["fee"], "30000000");
    assert_eq!(json["transactions"][0]["fee"], "0");
    assert_eq!(
        json["transactions"][1]["receives"][0]["commitment"],
        hex::encode(paid.commitment)
    );

    let outs = unspent(&app, &w).await;
    assert_eq!(outs.outputs.len(), 2);
    for o in &outs.outputs {
        let blob = &o.rct.as_ref().expect("RingCT").0;
        assert_eq!(blob.len(), 96);
        let served = txs
            .transactions
            .iter()
            .flat_map(|t| &t.receives)
            .find(|r| r.public_key == o.public_key)
            .unwrap();
        if o.global_index == Amount(5_000) {
            // As monero-lws and the spec: zeros, the identity mask, zeros.
            assert_eq!(blob[..], crypto::coinbase_rct()[..]);
            assert_eq!(&blob[32..64], DScalar::ONE.as_bytes());
        } else {
            assert_eq!(
                &blob[..32],
                &served.commitment.unwrap().0,
                "the blob starts with the chain's commitment"
            );
        }
    }
    // The regular output's blob decrypts to its mask and amount.
    let o = outs.outputs.iter().find(|o| o.global_index == Amount(5_002)).unwrap();
    let blob = &o.rct.as_ref().unwrap().0;
    let shared = crypto::shared_scalar(&w.view.to_bytes(), &o.tx_pub_key.0, o.index as u64).unwrap();
    let s1: DScalar = Scalar::hash(shared.as_bytes()).into();
    let s2: DScalar = Scalar::hash(s1.as_bytes()).into();
    assert_eq!(
        DScalar::from_bytes_mod_order(blob[32..64].try_into().unwrap()) - s1,
        DScalar::from_bytes_mod_order(paid.mask)
    );
    assert_eq!(
        DScalar::from_bytes_mod_order(blob[64..].try_into().unwrap()) - s2,
        DScalar::from(7_000_000u64)
    );
}

#[test]
fn several_accounts_in_one_transaction_and_one_paid_twice() {
    let (a, b, c) = (Wallet::new(10), Wallet::new(11), Wallet::new(12));
    let make = || {
        let (_, key) = tx_key(40);
        let tx = Tx::new(
            key,
            vec![
                a.pay(&key, 0, 0, 0, 10),
                b.pay(&key, 0, 0, 1, 20),
                a.pay(&key, 0, 0, 2, 30),
                stranger(9),
            ],
        );
        vec![block(100, [0; 32], dull_miner(100), vec![tx.build()], 900, 0)]
    };
    let (db, accounts) = both_ways(&[&a, &b, &c], 100, make);
    let a_out = db.outputs(accounts[0].id).unwrap();
    assert_eq!(
        a_out
            .iter()
            .map(|o| (o.out_index, o.global_index, o.amount))
            .collect::<Vec<_>>(),
        vec![(0, 901, 10), (2, 903, 30)]
    );
    let a_txs = db.txs(accounts[0].id).unwrap();
    assert_eq!(a_txs.len(), 1, "one transaction row");
    assert_eq!(a_txs[0].total_received, 40);
    assert_eq!(db.outputs(accounts[1].id).unwrap().len(), 1);
    assert!(db.outputs(accounts[2].id).unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn subaddresses_through_additional_keys_and_the_lookahead() {
    let w = Wallet::new(20);
    // Outputs to (0, 2), in the lookahead; to the primary address; to (1, 5),
    // not registered; to (0, 7), past the lookahead. Each with its own key.
    let make = || {
        let (_, main) = tx_key(70);
        let rs: Vec<DScalar> = (0..4).map(|i| tx_key(71 + i).0).collect();
        let targets = [(0, 2), (0, 0), (1, 5), (0, 7)];
        let additional: Vec<_> = rs
            .iter()
            .zip(targets)
            .map(|(r, (maj, min))| match (maj, min) {
                // A primary address's additional key is r·G, a subaddress's r·D.
                (0, 0) => r * ED25519_BASEPOINT_TABLE,
                _ => r * w.sub_spend(maj, min),
            })
            .collect();
        let outs = targets
            .iter()
            .enumerate()
            .map(|(i, &(maj, min))| w.pay(&additional[i], maj, min, i as u64, 100 + i as u64))
            .collect();
        let mut tx = Tx::new(main, outs);
        tx.additional = additional;
        vec![block(100, [0; 32], dull_miner(100), vec![tx.build()], 50, 0)]
    };
    let (db, accounts) = both_ways(&[&w], 100, make);
    let outs = db.outputs(accounts[0].id).unwrap();
    assert_eq!(
        outs.iter().map(|o| (o.maj, o.min, o.global_index)).collect::<Vec<_>>(),
        vec![(0, 2, 51), (0, 0, 52)]
    );
    let (_, main) = tx_key(70);
    let r0 = tx_key(71).0;
    assert_eq!(
        outs[0].tx_pub_key,
        (r0 * w.sub_spend(0, 2)).compress().to_bytes(),
        "the additional key it came by"
    );
    let r1 = tx_key(72).0;
    assert_eq!(
        outs[1].tx_pub_key,
        (&r1 * ED25519_BASEPOINT_TABLE).compress().to_bytes()
    );
    assert_ne!(outs[1].tx_pub_key, main.compress().to_bytes());

    // Registering (1, 5) and scanning again finds it.
    let db = Arc::new(db);
    db.upsert_subaddrs(
        accounts[0].id,
        &[lws_api::SubaddrRanges {
            key: 1,
            value: vec![[5, 5]],
        }],
        100,
    )
    .unwrap();
    db.rescan(&[w.address()], 100).unwrap();
    let account = db.account(&w.address()).unwrap().unwrap();
    write(&db, &[account], make(), 100, true, Some(&every_hit));
    let outs = db.outputs(accounts[0].id).unwrap();
    assert_eq!(
        outs.iter().map(|o| (o.maj, o.min)).collect::<Vec<_>>(),
        vec![(0, 2), (0, 0), (1, 5)]
    );
    let app = app(db, 200);
    let txs = txs(&app, &w).await;
    let recipients: Vec<(u32, u32)> = txs.transactions[0]
        .receives
        .iter()
        .map(|r| (r.recipient.maj_i, r.recipient.min_i))
        .collect();
    assert_eq!(recipients, vec![(0, 2), (0, 0), (1, 5)]);
}

/// Block 100 pays `a` and `b`; block 101 spends from a ring holding both
/// outputs and a stranger's.
fn pay_then_ring() -> impl Fn(&Wallet, &Wallet) -> Vec<Made> {
    |a: &Wallet, b: &Wallet| {
        let (_, k1) = tx_key(80);
        let pays = Tx::new(k1, vec![a.pay(&k1, 0, 0, 0, 500), b.pay(&k1, 0, 0, 1, 600)]);
        let first = block(100, [0; 32], dull_miner(100), vec![pays.build()], 1_000, 0);
        let (_, k2) = tx_key(81);
        let mut spend = Tx::new(k2, vec![stranger(30), stranger(31)]);
        spend.inputs = vec![ring(&[1_001, 1_002, 400], 7)];
        let second = block(
            101,
            first.block.block.hash(),
            dull_miner(101),
            vec![spend.build()],
            first.next,
            0,
        );
        vec![first, second]
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn candidate_spends_are_found_for_every_account_in_the_ring() {
    let (a, b, c) = (Wallet::new(30), Wallet::new(31), Wallet::new(32));
    let make = pay_then_ring();
    let (db, accounts) = both_ways(&[&a, &b, &c], 100, || make(&a, &b));
    assert_eq!(db.spends(accounts[0].id).unwrap().len(), 1);
    assert_eq!(db.spends(accounts[1].id).unwrap().len(), 1);
    assert!(db.spends(accounts[2].id).unwrap().is_empty());
    let app = app(Arc::new(db), 200);
    let info_a = info(&app, &a).await;
    assert_eq!(info_a.total_received, Amount(500));
    assert_eq!(info_a.total_sent, Amount(500));
    assert_eq!(info_a.spent_outputs[0].key_image.0, [7; 32]);
    let txs_b = txs(&app, &b).await;
    assert_eq!(txs_b.transactions.len(), 2);
    assert_eq!(txs_b.transactions[1].total_sent, Amount(600));
    assert_eq!(txs_b.transactions[1].spent_outputs[0].out_index, 1);
    assert_eq!(txs_b.transactions[1].mixin, 2);
    assert_eq!(txs_b.transactions[1].fee, Some(Amount(30_000_000)));
}

#[test]
fn a_reorg_drops_what_the_orphaned_blocks_held_and_the_new_chain_is_scanned() {
    let (a, b) = (Wallet::new(40), Wallet::new(41));
    let db = Db::in_memory();
    let accounts = vec![a.add(&db, 100), b.add(&db, 100)];
    write(&db, &accounts, pay_then_ring()(&a, &b), 100, true, None);
    assert_eq!(db.spends(accounts[0].id).unwrap().len(), 1);
    assert!(db.block_hash(101).unwrap().is_some());

    // Block 101 is orphaned: the spend goes, the outputs of 100 stay.
    db.rewind(101).unwrap();
    assert!(db.spends(accounts[0].id).unwrap().is_empty());
    assert_eq!(db.txs(accounts[0].id).unwrap().len(), 1);
    assert_eq!(db.txs(accounts[0].id).unwrap()[0].total_sent, 0);
    assert!(db.block_hash(101).unwrap().is_none());
    assert_eq!(db.account(&a.address()).unwrap().unwrap().scan_height, 101);

    // Then 100 too: and the new 100 pays `a` at another index.
    db.rewind(100).unwrap();
    assert!(db.outputs(accounts[0].id).unwrap().is_empty());
    assert!(db.txs(accounts[0].id).unwrap().is_empty());
    let accounts: Vec<Account> = [&a, &b]
        .iter()
        .map(|w| db.account(&w.address()).unwrap().unwrap())
        .collect();
    assert_eq!(accounts[0].scan_height, 100);
    let (_, k) = tx_key(90);
    let other = Tx::new(k, vec![stranger(1), stranger(2), a.pay(&k, 0, 0, 2, 555)]);
    let new_100 = block(100, [9; 32], dull_miner(100), vec![other.build()], 1_000, 1);
    let hash = new_100.block.block.hash();
    write(&db, &accounts, vec![new_100], 100, true, None);
    let outs = db.outputs(accounts[0].id).unwrap();
    assert_eq!(
        outs.iter().map(|o| (o.global_index, o.amount)).collect::<Vec<_>>(),
        vec![(1_003, 555)]
    );
    assert!(db.outputs(accounts[1].id).unwrap().is_empty());
    assert_eq!(db.block_hash(100).unwrap(), Some(hash));
}

/// Every block's hash is kept while under `KEEP_HASHES` behind the tip (the
/// pruning past it is `db::tests::set_block_keeps_only_the_last_hashes`).
#[test]
fn block_hashes_are_kept_behind_the_tip() {
    let w = Wallet::new(42);
    let db = Db::in_memory();
    let mut account = w.add(&db, 1);
    let mut previous = [0; 32];
    let mut first = 0;
    for start in (1..=250u64).step_by(50) {
        let mut blocks = vec![];
        for n in start..start + 50 {
            let made = block(n as usize, previous, dull_miner(n as usize), vec![], first, 0);
            previous = made.block.block.hash();
            first = made.next;
            blocks.push(made);
        }
        write(&db, std::slice::from_ref(&account), blocks, start, true, None);
        account = db.account(&w.address()).unwrap().unwrap();
    }
    let kept = db.recent_blocks().unwrap();
    const { assert!(crate::scanner::KEEP_HASHES > 250) };
    assert_eq!(kept.first().unwrap().0, 250);
    assert_eq!(kept.last().unwrap().0, 1);
    assert_eq!(kept.len(), 250);
    assert_eq!(account.scan_height, 251);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_pool_is_served_once_and_gives_way_to_the_mined_transaction() {
    let w = Wallet::new(50);
    let db = Arc::new(Db::in_memory());
    let account = w.add(&db, 100);
    let (made, _, paid) = paying_block(&w);
    let last = made.block.block.clone();
    write(&db, std::slice::from_ref(&account), vec![made], 100, true, None);
    let account = db.account(&w.address()).unwrap().unwrap();
    let app = app(db.clone(), 101);

    // In the pool: one transaction paying `w`, one spending from a ring with its output.
    let (_, k) = tx_key(60);
    let incoming = Tx::new(k, vec![w.pay(&k, 0, 0, 0, 42_000), stranger(3)]);
    let (_, k2) = tx_key(61);
    let mut outgoing = Tx::new(k2, vec![stranger(4), stranger(5)]);
    outgoing.inputs = vec![ring(&[5_002, 17], 9)];
    outgoing.fee = 12_345;
    let incoming_hash = tx_hash(&incoming.build(), 101, 0, 0);
    let outgoing_hash = [0xee; 32];
    let pool = pool_block(
        &last,
        vec![(incoming_hash, incoming.build()), (outgoing_hash, outgoing.build())],
    )
    .unwrap();
    let look = || {
        let mut slot = None;
        db.write(|tx| {
            let sw = ScanWriter::new(tx);
            let ring = Ring::get(
                &mut slot,
                tx,
                std::slice::from_ref(&account),
                LOOKAHEAD,
                &monokulo_8ar::Arena::new(),
            )?;
            scan_pool_block(&sw, ring, LOOKAHEAD, std::slice::from_ref(&account), &pool, None, 0)
        })
        .unwrap()
    };
    let hashes = [incoming_hash, outgoing_hash];
    app.scanner.mempool.lock().unwrap().reset(vec![account.id]);
    app.scanner.mempool.lock().unwrap().add(&hashes, look());
    // Looked at again (as after a lost race): nothing twice.
    app.scanner.mempool.lock().unwrap().add(&hashes, look());

    let served = txs(&app, &w).await;
    let pooled: Vec<_> = served.transactions.iter().filter(|t| t.mempool).collect();
    assert_eq!(pooled.len(), 2);
    let inc = pooled.iter().find(|t| t.hash.0 == incoming_hash).unwrap();
    assert_eq!((inc.height, inc.timestamp.as_ref()), (None, None));
    assert!(inc.proof.is_none(), "nothing to prove in the pool");
    assert_eq!(inc.receives.len(), 1);
    assert_eq!(inc.total_received, Amount(42_000));
    assert!(inc.receives[0].commitment.is_some());
    assert_eq!(inc.fee, Some(Amount(30_000_000)));
    let out = pooled.iter().find(|t| t.hash.0 == outgoing_hash).unwrap();
    assert_eq!(out.spent_outputs.len(), 1, "a spend seen in the pool");
    assert_eq!(out.total_sent, Amount(paid.amount));
    assert_eq!(out.fee, Some(Amount(12_345)));
    assert_eq!(out.mixin, 1);
    let ids: HashSet<u64> = served.transactions.iter().map(|t| t.id).collect();
    assert_eq!(ids.len(), served.transactions.len(), "ids are unique");

    // Mined in 101 before the pool is looked at again: listed once, mined.
    let (_, mk) = tx_key(62);
    let mined = block(
        101,
        last.hash(),
        Tx::new(mk, vec![stranger(8).plain()]).miner(101),
        vec![incoming.build()],
        6_000,
        0,
    );
    assert_eq!(mined.block.block.transactions[0], incoming_hash);
    let mined_hash = mined.block.block.hash();
    write(&db, std::slice::from_ref(&account), vec![mined], 101, true, None);
    let served = txs(&app, &w).await;
    let same: Vec<_> = served
        .transactions
        .iter()
        .filter(|t| t.hash.0 == incoming_hash)
        .collect();
    assert_eq!(same.len(), 1);
    assert_eq!((same[0].mempool, same[0].height), (false, Some(101)));
    assert_eq!(same[0].receives[0].global_index, 6_001);
    check_proof(same[0], mined_hash);

    // Then dropped from the pool: the outgoing one goes.
    app.scanner
        .mempool
        .lock()
        .unwrap()
        .retain(&HashSet::from([incoming_hash]));
    let served = txs(&app, &w).await;
    assert!(served.transactions.iter().all(|t| !t.mempool));
    assert_eq!(served.transactions.len(), 3);
}

#[test]
fn a_batch_leaves_alone_an_account_rescanned_or_hidden_meanwhile() {
    let (a, b, c) = (Wallet::new(60), Wallet::new(61), Wallet::new(62));
    let db = Db::in_memory();
    let accounts = vec![a.add(&db, 100), b.add(&db, 100), c.add(&db, 100)];
    // The batch is planned, then (while it is fetched) `a` is rescanned from 0
    // and `c` hidden.
    db.rescan(&[a.address()], 0).unwrap();
    db.set_status(&[c.address()], Status::Hidden).unwrap();
    write(&db, &accounts, pay_then_ring()(&a, &b), 100, true, Some(&every_hit));
    assert_eq!(
        db.account(&a.address()).unwrap().unwrap().scan_height,
        0,
        "the rescan holds"
    );
    assert!(db.outputs(accounts[0].id).unwrap().is_empty());
    assert_eq!(db.account(&b.address()).unwrap().unwrap().scan_height, 102);
    assert_eq!(db.outputs(accounts[1].id).unwrap().len(), 1);
    assert_eq!(db.account(&c.address()).unwrap().unwrap().scan_height, 100);
}

#[test]
fn an_account_joining_mid_batch_sees_only_its_own_blocks() {
    let (a, b) = (Wallet::new(70), Wallet::new(71));
    let make = || {
        let mut blocks = vec![];
        let mut first = 2_000;
        let mut previous = [0; 32];
        for n in 100..103usize {
            let (_, k) = tx_key(700 + n as u64);
            let tx = Tx::new(k, vec![a.pay(&k, 0, 0, 0, n as u64), b.pay(&k, 0, 0, 1, n as u64)]);
            let made = block(n, previous, dull_miner(n), vec![tx.build()], first, 0);
            previous = made.block.block.hash();
            first = made.next;
            blocks.push(made);
        }
        blocks
    };
    for hits in [
        None,
        Some(&every_hit as &dyn Fn(&Ring, &Batch) -> Vec<monokulo_8ar::Hit>),
    ] {
        let db = Db::in_memory();
        let accounts = vec![a.add(&db, 100), b.add(&db, 102)];
        write(&db, &accounts, make(), 100, false, hits);
        assert_eq!(db.outputs(accounts[0].id).unwrap().len(), 3);
        let b_outs = db.outputs(accounts[1].id).unwrap();
        assert_eq!(b_outs.iter().map(|o| o.height).collect::<Vec<_>>(), vec![102]);
        assert_eq!(db.account(&b.address()).unwrap().unwrap().scan_height, 103);
        assert!(db.block_hash(100).unwrap().is_none(), "a catch-up lane keeps no hashes");
    }
}

#[test]
fn a_batch_cut_short_leaves_nothing_behind() {
    let w = Wallet::new(80);
    let db = Db::in_memory();
    let account = w.add(&db, 100);
    let (made, _, _) = paying_block(&w);
    let batch = Batch {
        first_indexes: vec![made.first_indexes],
        blocks: vec![made.block],
        raw: vec![made.raw],
    };
    let mut slot = None;
    let result: crate::error::Result<()> = db.write(|tx| {
        let sw = ScanWriter::new(tx);
        let ring = Ring::get(
            &mut slot,
            tx,
            std::slice::from_ref(&account),
            LOOKAHEAD,
            &monokulo_8ar::Arena::new(),
        )?;
        record_batch(
            &sw,
            ring,
            LOOKAHEAD,
            std::slice::from_ref(&account),
            &batch,
            100,
            None,
            true,
        )?;
        Err(Error::Internal("killed mid-batch".into()))
    });
    assert!(result.is_err());
    assert!(db.outputs(account.id).unwrap().is_empty());
    assert!(db.txs(account.id).unwrap().is_empty());
    assert!(db.block_hash(100).unwrap().is_none());
    assert_eq!(db.scanner_height().unwrap(), None);
    assert_eq!(db.account(&w.address()).unwrap().unwrap().scan_height, 100);
}

#[tokio::test(flavor = "multi_thread")]
async fn totals_locks_unlock_times_and_timestamps() {
    let w = Wallet::new(90);
    let db = Arc::new(Db::in_memory());
    let account = w.add(&db, 100);
    let mut blocks = vec![];
    let mut first = 3_000;
    let mut previous = [0; 32];
    for n in 100..=195usize {
        let (_, k) = tx_key(900 + n as u64);
        let txs = match n {
            // Old enough, and spent later.
            100 => vec![Tx::new(k, vec![w.pay(&k, 0, 0, 0, 1)]).build()],
            // Locked until block 10,000.
            101 => {
                let mut tx = Tx::new(k, vec![w.pay(&k, 0, 0, 0, 10)]);
                tx.unlock = Timelock::Block(10_000);
                vec![tx.build()]
            }
            // Locked until a time long past: unlocked.
            102 => {
                let mut tx = Tx::new(k, vec![w.pay(&k, 0, 0, 0, 100)]);
                tx.unlock = Timelock::Time(1_600_000_000);
                vec![tx.build()]
            }
            // Spends the first from a ring.
            120 => {
                let mut tx = Tx::new(k, vec![stranger(1)]);
                tx.inputs = vec![ring(&[3_001, 10], 3)];
                vec![tx.build()]
            }
            // Too recent at 200.
            195 => vec![Tx::new(k, vec![w.pay(&k, 0, 0, 0, 1_000)]).build()],
            _ => vec![],
        };
        let miner = if n == 150 {
            // A mined reward: unlocked at 210.
            let (_, mk) = tx_key(950);
            Tx::new(mk, vec![w.pay(&mk, 0, 0, 0, 10_000)]).miner(n)
        } else {
            dull_miner(n)
        };
        let made = block(n, previous, miner, txs, first, 0);
        previous = made.block.block.hash();
        first = made.next;
        blocks.push(made);
    }
    write(&db, &[account], blocks, 100, true, None);
    let app = app(db, 200);
    let info = info(&app, &w).await;
    assert_eq!(info.total_received, Amount(11_111));
    assert_eq!(info.total_sent, Amount(1));
    assert_eq!(info.locked_funds, Amount(10 + 1_000 + 10_000));
    assert_eq!(
        (info.scanned_height, info.blockchain_height, info.start_height),
        (196, 200, 100)
    );

    let txs = txs(&app, &w).await;
    let locked = txs.transactions.iter().find(|t| t.height == Some(101)).unwrap();
    assert_eq!(locked.unlock_time, 10_000, "served for the client to decide");
    let coinbase = txs.transactions.iter().find(|t| t.coinbase).unwrap();
    assert_eq!(coinbase.unlock_time, 210);
    assert_eq!(
        coinbase.timestamp,
        Some(Timestamp::from_unix(1_700_000_000 + 150 * 120))
    );
    assert_eq!(coinbase.timestamp.as_ref().unwrap().0, "2023-11-15T03:13:20Z");
    // As monero-lws: every received output is listed, locked or not, and the
    // client decides from the transaction's unlock time.
    let outs = unspent(&app, &w).await;
    assert_eq!(outs.outputs.len(), 5);
    assert_eq!(outs.amount, Amount(11_111));
    let spent = outs.outputs.iter().find(|o| o.height == 100).unwrap();
    assert_eq!(spent.spend_key_images.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_starts_a_new_account_at_the_top_block() {
    let w = Wallet::new(100);
    let db = Arc::new(Db::in_memory());
    let app = app(db.clone(), 1_000);
    let request = |create_account| LoginRequest {
        login: w.login(),
        create_account,
        generated_locally: false,
    };
    assert!(
        wallet::login(State(app.clone()), None, ApiJson(request(false)))
            .await
            .is_err(),
        "unknown, not created"
    );
    let made = unwrap(wallet::login(State(app.clone()), None, ApiJson(request(true))).await);
    assert!(made.new_address);
    assert_eq!(made.start_height, Some(999), "the top block, scanned too");
    let account = db.account(&w.address()).unwrap().unwrap();
    assert_eq!((account.start_height, account.scan_height), (999, 999));
    let again = unwrap(wallet::login(State(app.clone()), None, ApiJson(request(true))).await);
    assert!(!again.new_address);
    assert_eq!(again.start_height, Some(999));

    // Before the scanner has heard from the node, the node is asked; with no
    // node, nothing is made (rather than an account scanning from block 0).
    let other = Wallet::new(101);
    let db = Arc::new(Db::in_memory());
    let app0 = crate::testkit::app(db.clone(), 0);
    let request = LoginRequest {
        login: other.login(),
        create_account: true,
        generated_locally: false,
    };
    assert!(wallet::login(State(app0), None, ApiJson(request)).await.is_err());
    assert!(db.account(&other.address()).unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_import_starts_the_account_at_block_zero() {
    let w = Wallet::new(110);
    let db = Arc::new(Db::in_memory());
    w.add(&db, 500);
    let app = app(db.clone(), 1_000);
    let reply = unwrap(wallet::import_wallet_request(State(app.clone()), None, ApiJson(w.login())).await);
    assert!(reply.request_fulfilled && reply.new_request);
    let account = db.account(&w.address()).unwrap().unwrap();
    assert_eq!((account.start_height, account.scan_height), (0, 0));
    assert_eq!(info(&app, &w).await.start_height, 0);
    let again = unwrap(wallet::import_wallet_request(State(app.clone()), None, ApiJson(w.login())).await);
    assert!(!again.new_request, "already from 0: nothing more to do");
}

/// What a client does with a served proof: the block's hash from its blob
/// (which must be `block_hash`, as a node would say), and the transaction's
/// hash from its parts (or, for the miner's, from the blob), which must be
/// the served hash and in the block. Gives the block read from the blob.
fn check_proof(t: &lws_api::Transaction, block_hash: [u8; 32]) -> monero_wallet::block::Block {
    let proof = t.proof.as_ref().expect("a mined transaction that pays has a proof");
    let block = monero_wallet::block::Block::read(&mut proof.block.0.as_slice()).expect("the blob reads");
    assert_eq!(block.hash(), block_hash, "the blob hashes to the block's hash");
    match (&proof.tx_prefix, &proof.rct_base, &proof.prunable_hash) {
        (Some(prefix), Some(base), Some(prunable)) => {
            assert!(!t.coinbase);
            let hash = crate::proof::tx_hash(&prefix.0, &base.0, &prunable.0);
            assert_eq!(hash, t.hash.0, "the parts hash to the served hash");
            assert!(block.transactions.contains(&hash), "and the block lists it");
            // What the client checks the receives against is in the parts.
            for r in &t.receives {
                assert!(prefix.0.windows(32).any(|w| w == r.public_key.0), "the one-time key");
                let commitment = r.commitment.expect("served").0;
                assert!(base.0.windows(32).any(|w| w == commitment), "the commitment");
            }
        }
        (None, None, None) => {
            assert!(t.coinbase, "only the miner's transaction comes without parts");
            assert_eq!(
                block.miner_transaction().hash(),
                t.hash.0,
                "the block's miner transaction"
            );
        }
        _ => panic!("the parts come together or not at all"),
    }
    block
}

#[tokio::test(flavor = "multi_thread")]
async fn a_mined_receive_comes_with_a_proof_of_its_block() {
    let w = Wallet::new(120);
    for hits in [
        None,
        Some(&every_hit as &dyn Fn(&Ring, &Batch) -> Vec<monokulo_8ar::Hit>),
    ] {
        let db = Arc::new(Db::in_memory());
        let account = w.add(&db, 100);
        let (made, _, _) = paying_block(&w);
        let hash = made.block.block.hash();
        write(&db, &[account], vec![made], 100, true, hits);
        let (kept_hash, blob) = db.kept_block(100).unwrap().expect("the paying block is kept");
        assert_eq!(kept_hash, hash);
        assert_eq!(db.block_hash(100).unwrap(), Some(hash), "the hash the live lane keeps");
        assert_eq!(
            crate::proof::block_hash(&blob),
            Some(hash),
            "the kept blob hashes to it"
        );
        assert_eq!(
            db.kept_counts().unwrap(),
            (1, 1),
            "the block and its one other transaction"
        );

        let served = txs(&app(db, 200), &w).await;
        assert_eq!(served.transactions.len(), 2);
        let coinbase = &served.transactions[0];
        assert!(coinbase.coinbase);
        let block = check_proof(coinbase, hash);
        let payment = &served.transactions[1];
        check_proof(payment, hash);
        assert_eq!(block.transactions, vec![payment.hash.0]);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn proofs_are_kept_only_where_an_account_is_paid() {
    let (a, b) = (Wallet::new(121), Wallet::new(122));
    let db = Arc::new(Db::in_memory());
    let accounts = vec![a.add(&db, 100), b.add(&db, 100)];
    // A catch-up lane (no hashes kept) keeps proofs all the same.
    write(&db, &accounts, pay_then_ring()(&a, &b), 100, false, Some(&every_hit));
    assert!(db.block_hash(100).unwrap().is_none());
    assert!(db.kept_block(100).unwrap().is_some(), "100 pays both");
    assert!(db.kept_block(101).unwrap().is_none(), "101 only spends from a ring");
    assert_eq!(db.kept_counts().unwrap(), (1, 1), "one transaction pays both");
    let app = app(db.clone(), 200);
    let served = txs(&app, &a).await;
    assert_eq!(served.transactions.len(), 2);
    let block = pay_then_ring()(&a, &b)[0].block.block.hash();
    check_proof(&served.transactions[0], block);
    assert!(
        served.transactions[1].proof.is_none(),
        "a candidate spend has none: its key image can't be forged"
    );

    // A rescan of one account leaves what the other still needs, and a
    // rescan of both lets it go.
    db.rescan(&[a.address()], 0).unwrap();
    assert_eq!(db.kept_counts().unwrap(), (1, 1));
    check_proof(&txs(&app, &b).await.transactions[0], block);
    db.rescan(&[b.address()], 50).unwrap();
    assert_eq!(db.kept_counts().unwrap(), (0, 0));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reorg_drops_the_kept_block_and_the_new_one_is_proved() {
    let w = Wallet::new(123);
    let db = Arc::new(Db::in_memory());
    let account = w.add(&db, 100);
    let (made, _, _) = paying_block(&w);
    write(&db, &[account], vec![made], 100, true, None);
    assert_eq!(db.kept_counts().unwrap(), (1, 1));
    db.rewind(100).unwrap();
    assert!(db.kept_block(100).unwrap().is_none());
    assert_eq!(db.kept_counts().unwrap(), (0, 0));

    let account = db.account(&w.address()).unwrap().unwrap();
    let (_, k) = tx_key(91);
    let other = Tx::new(k, vec![w.pay(&k, 0, 0, 0, 555)]);
    let new_100 = block(100, [9; 32], dull_miner(100), vec![other.build()], 1_000, 1);
    let hash = new_100.block.block.hash();
    write(&db, &[account], vec![new_100], 100, true, None);
    assert_eq!(db.kept_block(100).unwrap().map(|k| k.0), Some(hash));
    let served = txs(&app(db, 200), &w).await;
    assert_eq!(served.transactions.len(), 1);
    check_proof(&served.transactions[0], hash);
}

/// A node that answers every request with `body`, one connection at a time.
async fn node_answering(body: String) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            let mut buf = vec![0u8; 64 * 1024];
            let _ = s.read(&mut buf).await;
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = s.write_all(reply.as_bytes()).await;
        }
    });
    format!("http://{addr}")
}

/// A node that sends no prunable hash in `get_blocks.bin`
/// (monero-project/monero#10120): the parts are kept pending and served
/// without a proof until `get_transactions` gives the hash, which is kept
/// only if the parts hash to the transaction's hash with it.
#[tokio::test(flavor = "multi_thread")]
async fn a_missing_prunable_hash_is_filled_in_from_the_node() {
    let w = Wallet::new(124);
    for right in [true, false] {
        let db = Arc::new(Db::in_memory());
        let account = w.add(&db, 100);
        let (mut made, _, _) = paying_block(&w);
        let hash = made.block.block.hash();
        let tx_hash = made.block.block.transactions[0];
        made.raw.as_mut().unwrap().txs[0].prunable_hash = [0; 32];
        write(&db, &[account], vec![made], 100, true, None);
        assert_eq!(db.kept_counts().unwrap(), (1, 1));
        assert_eq!(db.pending_proofs(10).unwrap().len(), 1);
        let app = app(db.clone(), 200);
        let served = txs(&app, &w).await;
        check_proof(&served.transactions[0], hash);
        assert!(served.transactions[1].proof.is_none(), "pending: no proof yet");

        let prunable = if right { prunable_hash(100, 0, 0) } else { [7; 32] };
        let node = node_answering(format!(
            r#"{{"status":"OK","txs":[{{"tx_hash":"{}","prunable_hash":"{}"}}]}}"#,
            hex::encode(tx_hash),
            hex::encode(prunable)
        ))
        .await;
        let scanner = crate::scanner::Scanner::new(
            db.clone(),
            crate::daemon::Daemon::new(&node).unwrap(),
            app.scanner.config.clone(),
        );
        scanner.complete_proofs().await;
        assert!(db.pending_proofs(10).unwrap().is_empty());
        let served = txs(&app, &w).await;
        if right {
            check_proof(&served.transactions[1], hash);
            assert_eq!(db.kept_counts().unwrap(), (1, 1));
        } else {
            assert!(
                served.transactions[1].proof.is_none(),
                "a hash that doesn't fit is dropped"
            );
            assert_eq!(db.kept_counts().unwrap(), (1, 0), "the block stays for the miner's");
        }
    }
}

/// A database made before proofs were kept: it opens, its transactions are
/// served without a proof, and what is scanned from then on has one.
#[tokio::test(flavor = "multi_thread")]
async fn a_database_from_before_proofs_serves_old_rows_without_one() {
    let w = Wallet::new(125);
    let path = std::env::temp_dir().join(format!(
        "lws-proof-migration-{}-{}.sqlite",
        std::process::id(),
        crate::db::now()
    ));
    {
        // The schema as it was: no blocks_kept, no txs_kept.
        let old = crate::db::SCHEMA
            .split("CREATE TABLE IF NOT EXISTS blocks_kept")
            .next()
            .unwrap();
        assert!(!old.contains("txs_kept"));
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(old).unwrap();
    }
    let db = Arc::new(crate::db::Db::open(&path).unwrap());
    let account = w.add(&db, 99);
    // Block 99 as an older version wrote it: rows, no proof.
    let (_, k) = tx_key(92);
    let early = Tx::new(k, vec![w.pay(&k, 0, 0, 0, 1_234)]);
    let mut b99 = block(99, [0; 32], dull_miner(99), vec![early.build()], 4_000, 0);
    b99.raw = None;
    write(&db, &[account], vec![b99], 99, true, None);
    let account = db.account(&w.address()).unwrap().unwrap();
    let (made, _, _) = paying_block(&w);
    let hash = made.block.block.hash();
    write(&db, &[account], vec![made], 100, true, None);
    drop(db);

    let db = Arc::new(crate::db::Db::open(&path).unwrap());
    let served = txs(&app(db, 200), &w).await;
    assert_eq!(served.transactions.len(), 3);
    assert_eq!(served.transactions[0].height, Some(99));
    assert!(
        served.transactions[0].proof.is_none(),
        "scanned before: no proof until a rescan"
    );
    check_proof(&served.transactions[1], hash);
    check_proof(&served.transactions[2], hash);
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}
