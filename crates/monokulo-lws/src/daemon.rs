//! The connection to monerod: blocks through `get_blocks.bin`, the rest
//! through its JSON endpoints.
//!
//! The `get_blocks.bin` request and reader are adapted from Fob
//! (`fob-chain/src/fetch.rs`, GPL-3.0), itself adapted from monero-oxide's
//! `monero-daemon-rpc` (MIT). monero-oxide's own reader gives up on a
//! response whose transactions carry an all-zero `prunable_hash`
//! (monero-project/monero#10120), which nodes send for pruned blocks; a
//! scanner doesn't need that hash, so this one accepts it, as wallet2 does.

use std::time::Duration;

use monero_epee::{Epee, HEADER, Type, VERSION};
use monero_wallet::{
    block::Block,
    interface::ScannableBlock,
    transaction::{Pruned, Transaction},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{Error, Result};

/// The most one `get_blocks.bin` response may be.
const MAX_BLOCKS_RESPONSE: usize = 200 * 1024 * 1024;
const MAX_JSON_RESPONSE: usize = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct Daemon {
    client: reqwest::Client,
    base: String,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct Info {
    pub height: u64,
    #[serde(default)]
    pub target_height: u64,
    #[serde(default)]
    pub nettype: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub top_block_hash: String,
    #[serde(default)]
    pub synchronized: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct FeeEstimate {
    pub fee: u64,
    #[serde(default = "one")]
    pub quantization_mask: u64,
    #[serde(default)]
    pub fees: Vec<u64>,
}

fn one() -> u64 {
    1
}

/// The cumulative count of RingCT outputs at the end of each block from
/// `start_height` on.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct Distribution {
    pub start_height: u64,
    pub cumulative: Vec<u64>,
}

#[derive(Clone, Debug, Deserialize)]
#[allow(dead_code)]
pub struct OutInfo {
    pub key: String,
    pub mask: String,
    pub unlocked: bool,
    pub height: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SendResult {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub not_relayed: bool,
}

#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<Value>,
}

impl Daemon {
    pub fn new(url: &str) -> Result<Daemon> {
        let base = url.trim_end_matches('/').to_string();
        if !(base.starts_with("http://") || base.starts_with("https://")) {
            return Err(Error::Internal(format!(
                "daemon URL must start with http:// or https://: {url}"
            )));
        }
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .read_timeout(Duration::from_secs(60))
            .pool_idle_timeout(Duration::from_secs(8))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Daemon { client, base })
    }

    pub fn url(&self) -> &str {
        &self.base
    }

    async fn post(&self, route: &str, body: Vec<u8>, json: bool, limit: usize) -> Result<Vec<u8>> {
        let mut request = self.client.post(format!("{}/{route}", self.base)).body(body);
        if json {
            request = request.header("Content-Type", "application/json");
        }
        let response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Daemon(format!("{route}: HTTP {status}")));
        }
        if let Some(len) = response.content_length() {
            if len as usize > limit {
                return Err(Error::Daemon(format!("{route}: response of {len} bytes is too large")));
            }
        }
        let bytes = response.bytes().await?;
        if bytes.len() > limit {
            return Err(Error::Daemon(format!(
                "{route}: response of {} bytes is too large",
                bytes.len()
            )));
        }
        Ok(bytes.to_vec())
    }

    async fn rpc<T: for<'de> Deserialize<'de>>(&self, route: &str, params: Value) -> Result<T> {
        let body = self
            .post(
                route,
                serde_json::to_vec(&params).expect("json"),
                true,
                MAX_JSON_RESPONSE,
            )
            .await?;
        serde_json::from_slice(&body).map_err(|e| Error::Daemon(format!("{route}: {e}")))
    }

    async fn json_rpc<T: for<'de> Deserialize<'de>>(&self, method: &str, params: Value) -> Result<T> {
        let request = json!({ "jsonrpc": "2.0", "id": "0", "method": method, "params": params });
        let body = self
            .post(
                "json_rpc",
                serde_json::to_vec(&request).expect("json"),
                true,
                MAX_JSON_RESPONSE,
            )
            .await?;
        let response: JsonRpcResponse<T> =
            serde_json::from_slice(&body).map_err(|e| Error::Daemon(format!("{method}: {e}")))?;
        if let Some(error) = response.error {
            return Err(Error::Daemon(format!("{method}: {error}")));
        }
        response
            .result
            .ok_or_else(|| Error::Daemon(format!("{method}: no result")))
    }

    pub async fn info(&self) -> Result<Info> {
        self.json_rpc("get_info", json!({})).await
    }

    /// The hash of the block at `height`.
    pub async fn block_hash(&self, height: u64) -> Result<[u8; 32]> {
        #[derive(Deserialize)]
        struct Header {
            hash: String,
        }
        #[derive(Deserialize)]
        struct R {
            block_header: Header,
        }
        let r: R = self
            .json_rpc("get_block_header_by_height", json!({ "height": height }))
            .await?;
        hex32(&r.block_header.hash).ok_or_else(|| Error::Daemon("get_block_header_by_height: bad hash".into()))
    }

    pub async fn fee_estimate(&self) -> Result<FeeEstimate> {
        self.json_rpc("get_fee_estimate", json!({ "grace_blocks": 10 })).await
    }

    /// The RingCT output distribution, cumulative, from the first block
    /// with such outputs.
    pub async fn output_distribution(&self) -> Result<Distribution> {
        #[derive(Deserialize)]
        struct Entry {
            start_height: u64,
            distribution: Vec<u64>,
            #[serde(default)]
            base: u64,
        }
        #[derive(Deserialize)]
        struct R {
            distributions: Vec<Entry>,
        }
        let r: R = self
            .json_rpc(
                "get_output_distribution",
                json!({ "amounts": [0], "cumulative": true, "from_height": 0, "binary": false, "compress": false }),
            )
            .await?;
        let e = r
            .distributions
            .into_iter()
            .next()
            .ok_or_else(|| Error::Daemon("get_output_distribution: empty".into()))?;
        let cumulative = e.distribution.into_iter().map(|d| d + e.base).collect();
        Ok(Distribution {
            start_height: e.start_height,
            cumulative,
        })
    }

    /// Keys, commitments and lock state for RingCT outputs by global index.
    pub async fn outs(&self, indexes: &[u64]) -> Result<Vec<OutInfo>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(default)]
            outs: Vec<OutInfo>,
            #[serde(default)]
            status: String,
        }
        let outputs: Vec<Value> = indexes.iter().map(|i| json!({ "amount": 0, "index": i })).collect();
        let r: R = self
            .rpc("get_outs", json!({ "outputs": outputs, "get_txid": false }))
            .await?;
        if r.status != "OK" {
            return Err(Error::Daemon(format!("get_outs: {}", r.status)));
        }
        if r.outs.len() != indexes.len() {
            return Err(Error::Daemon("get_outs: answered a different count".into()));
        }
        Ok(r.outs)
    }

    pub async fn send_raw(&self, tx_hex: &str) -> Result<SendResult> {
        self.rpc(
            "send_raw_transaction",
            json!({ "tx_as_hex": tx_hex, "do_not_relay": false }),
        )
        .await
    }

    pub async fn pool_hashes(&self) -> Result<Vec<[u8; 32]>> {
        #[derive(Deserialize)]
        struct R {
            #[serde(default)]
            tx_hashes: Vec<String>,
        }
        let r: R = self.rpc("get_transaction_pool_hashes", json!({})).await?;
        Ok(r.tx_hashes.iter().filter_map(|h| hex32(h)).collect())
    }

    /// Transactions by hash, pruned. Ones the node no longer has are left out.
    pub async fn transactions(&self, hashes: &[[u8; 32]]) -> Result<Vec<([u8; 32], Transaction<Pruned>)>> {
        #[derive(Deserialize)]
        struct Tx {
            tx_hash: String,
            #[serde(default)]
            pruned_as_hex: String,
            #[serde(default)]
            as_hex: String,
        }
        #[derive(Deserialize)]
        struct R {
            #[serde(default)]
            txs: Vec<Tx>,
        }
        if hashes.is_empty() {
            return Ok(vec![]);
        }
        let hex_hashes: Vec<String> = hashes.iter().map(hex::encode).collect();
        let r: R = self
            .rpc("get_transactions", json!({ "txs_hashes": hex_hashes, "prune": true }))
            .await?;
        let mut out = vec![];
        for tx in r.txs {
            let Some(hash) = hex32(&tx.tx_hash) else { continue };
            let blob = if tx.pruned_as_hex.is_empty() {
                &tx.as_hex
            } else {
                &tx.pruned_as_hex
            };
            let bytes = hex::decode(blob).map_err(|e| Error::Daemon(format!("get_transactions: {e}")))?;
            let parsed = Transaction::<Pruned>::read(&mut bytes.as_slice())
                .map_err(|e| Error::Daemon(format!("get_transactions: transaction: {e}")))?;
            out.push((hash, parsed));
        }
        Ok(out)
    }

    /// Up to `count` blocks from `start` (at least 1: monerod ignores a zero
    /// start height), with their pruned transactions and each transaction's
    /// first RingCT output index. The node may send fewer than asked.
    pub async fn blocks(&self, start: u64, count: u64) -> Result<Vec<Fetched>> {
        let start = start.max(1);
        let response = self
            .post("get_blocks.bin", request(start, count), false, MAX_BLOCKS_RESPONSE)
            .await?;
        parse(&response)
    }
}

/// A block as the scanner takes it: what monero-oxide's `Scanner` reads,
/// and the global index of each transaction's first RingCT output (the miner
/// transaction first, then the block's others in order; `None` for one with
/// no RingCT outputs), for stand-in blocks of one transaction.
#[derive(Clone, Debug)]
pub struct Fetched {
    pub block: ScannableBlock,
    pub first_indexes: Vec<Option<u64>>,
}

pub fn hex32(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    (s.len() == 64 && hex::decode_to_slice(s, &mut out).is_ok()).then_some(out)
}

fn invalid(what: impl Into<String>) -> Error {
    Error::Daemon(what.into())
}

fn epee_err(e: monero_epee::EpeeError) -> Error {
    invalid(format!("get_blocks.bin: {e:?}"))
}

fn key(request: &mut Vec<u8>, name: &str, kind: Type) {
    request.push(name.len() as u8);
    request.extend(name.as_bytes());
    request.push(kind as u8);
}

fn request(start: u64, count: u64) -> Vec<u8> {
    let mut request = Vec::with_capacity(80);
    request.extend(HEADER);
    request.push(VERSION);
    // Three fields, as an epee varint.
    request.push(3 << 2);
    key(&mut request, "prune", Type::Bool);
    request.push(1);
    key(&mut request, "start_height", Type::Uint64);
    request.extend(start.to_le_bytes());
    key(&mut request, "max_block_count", Type::Uint64);
    request.extend(count.to_le_bytes());
    request
}

fn parse(response: &[u8]) -> Result<Vec<Fetched>> {
    let mut epee = Epee::new(response).map_err(epee_err)?;
    let mut fields = epee.entry().map_err(epee_err)?.fields().map_err(epee_err)?;
    let mut blocks = vec![];
    let mut output_indexes = vec![];
    let mut status_ok = false;
    while let Some(field) = fields.next() {
        let (name, value) = field.map_err(epee_err)?;
        match name.consume() {
            b"status" => status_ok = value.to_str().map_err(epee_err)?.consume() == b"OK",
            b"blocks" => {
                let mut entries = value.iterate().map_err(epee_err)?;
                while let Some(entry) = entries.next() {
                    let mut entry = entry.map_err(epee_err)?.fields().map_err(epee_err)?;
                    let mut block = None;
                    let mut transactions = vec![];
                    while let Some(field) = entry.next() {
                        let (name, value) = field.map_err(epee_err)?;
                        match name.consume() {
                            b"block" => {
                                let mut bytes = value.to_str().map_err(epee_err)?.consume();
                                block = Some(Block::read(&mut bytes).map_err(|e| invalid(format!("block: {e:?}")))?);
                            }
                            b"txs" => {
                                let mut txs = value.iterate().map_err(epee_err)?;
                                while let Some(tx) = txs.next() {
                                    let mut tx = tx.map_err(epee_err)?.fields().map_err(epee_err)?;
                                    while let Some(field) = tx.next() {
                                        let (name, value) = field.map_err(epee_err)?;
                                        if name.consume() == b"blob" {
                                            let mut bytes = value.to_str().map_err(epee_err)?.consume();
                                            transactions.push(
                                                Transaction::<Pruned>::read(&mut bytes)
                                                    .map_err(|e| invalid(format!("transaction: {e:?}")))?,
                                            );
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    let block = block.ok_or_else(|| invalid("a block entry without its block"))?;
                    if block.transactions.len() != transactions.len() {
                        return Err(invalid("a block's transactions are missing"));
                    }
                    blocks.push((block, transactions));
                }
            }
            b"output_indices" => {
                let mut per_block = value.iterate().map_err(epee_err)?;
                while let Some(block) = per_block.next() {
                    let mut block_fields = block.map_err(epee_err)?.fields().map_err(epee_err)?;
                    while let Some(field) = block_fields.next() {
                        let (name, value) = field.map_err(epee_err)?;
                        if name.consume() != b"indices" {
                            continue;
                        }
                        let mut per_tx = value.iterate().map_err(epee_err)?;
                        while let Some(tx) = per_tx.next() {
                            let mut tx_fields = tx.map_err(epee_err)?.fields().map_err(epee_err)?;
                            while let Some(field) = tx_fields.next() {
                                let (name, value) = field.map_err(epee_err)?;
                                if name.consume() != b"indices" {
                                    continue;
                                }
                                let mut indexes = value.iterate().map_err(epee_err)?;
                                while let Some(index) = indexes.next() {
                                    output_indexes.push(index.map_err(epee_err)?.to_u64().map_err(epee_err)?);
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if !status_ok {
        return Err(invalid("get_blocks.bin: the node's status wasn't OK"));
    }

    // Output indexes come flattened, miner transaction first in each block;
    // keep the first index of a RingCT output per transaction, and the
    // block's first.
    let mut indexes = output_indexes.as_slice();
    let mut res = Vec::with_capacity(blocks.len());
    for (block, transactions) in blocks {
        let miner: Transaction<Pruned> = block.miner_transaction().clone().into();
        let mut first_indexes = Vec::with_capacity(transactions.len() + 1);
        for tx in std::iter::once(&miner).chain(&transactions) {
            let outputs = tx.prefix().outputs.len();
            if indexes.len() < outputs {
                return Err(invalid("get_blocks.bin left out output indexes"));
            }
            first_indexes.push((!matches!(tx, Transaction::V1 { .. }) && outputs != 0).then(|| indexes[0]));
            indexes = &indexes[outputs..];
        }
        let first_ringct = first_indexes.iter().flatten().next().copied();
        res.push(Fetched {
            block: ScannableBlock {
                block,
                transactions,
                output_index_for_first_ringct_output: first_ringct,
            },
            first_indexes,
        });
    }
    if !indexes.is_empty() {
        return Err(invalid("get_blocks.bin sent more output indexes than outputs"));
    }
    Ok(res)
}
