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

/// The most one `get_blocks.bin` response may be; the body is read in
/// chunks and given up on as soon as it passes this, whatever
/// `Content-Length` said.
const MAX_BLOCKS_RESPONSE: usize = 200 * 1024 * 1024;
const MAX_JSON_RESPONSE: usize = 64 * 1024 * 1024;
/// Time a JSON call may take in all, and a `get_blocks.bin` call (up to
/// 200 MB from a node that may be across the world).
const JSON_TIMEOUT: Duration = Duration::from_secs(60);
const BLOCKS_TIMEOUT: Duration = Duration::from_secs(300);
/// More blocks than this in one `get_blocks.bin` the server never asks for.
pub const MAX_BLOCKS_PER_REQUEST: u64 = 1_000;
/// Transactions in one block, at most, before the reader gives up. A block
/// is bounded by weight to a few hundred today; this only stops a node from
/// making the reader hold millions.
const MAX_TXS_PER_BLOCK: usize = 100_000;
/// Output indexes in one response, at most (64 MB of them).
const MAX_OUTPUT_INDEXES: usize = 8 * 1024 * 1024;

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
                "daemon URL must start with http:// or https://: {}",
                redact_userinfo(url)
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

    /// The node's URL for the log, without a `user:password@` in it.
    pub fn display_url(&self) -> String {
        redact_userinfo(&self.base)
    }

    async fn post(&self, route: &str, body: Vec<u8>, json: bool, limit: usize) -> Result<Vec<u8>> {
        let timeout = if json { JSON_TIMEOUT } else { BLOCKS_TIMEOUT };
        let mut request = self
            .client
            .post(format!("{}/{route}", self.base))
            .timeout(timeout)
            .body(body);
        if json {
            request = request.header("Content-Type", "application/json");
        }
        let mut response = request.send().await?;
        let status = response.status();
        if !status.is_success() {
            return Err(Error::Daemon(format!("{route}: HTTP {status}")));
        }
        let too_large = || Error::Daemon(format!("{route}: the response is over {limit} bytes"));
        let declared = response.content_length().unwrap_or(0);
        if declared > limit as u64 {
            return Err(too_large());
        }
        // Read in chunks so a node that sends more than it declared (or
        // declares nothing) is cut off at the limit, not buffered whole.
        let mut body = Vec::with_capacity((declared as usize).min(limit));
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > limit {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
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
        Ok(Distribution {
            start_height: e.start_height,
            cumulative: checked_cumulative(e.distribution, e.base)?,
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
        let count = count.clamp(1, MAX_BLOCKS_PER_REQUEST);
        let response = self
            .post("get_blocks.bin", request(start, count), false, MAX_BLOCKS_RESPONSE)
            .await?;
        parse(&response, count as usize)
    }
}

/// `user:password@` in a URL as `***@`.
fn redact_userinfo(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{scheme}://***@{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

/// The node's cumulative distribution plus its base, refused unless it
/// never goes down (the picker relies on that) and never overflows.
fn checked_cumulative(distribution: Vec<u64>, base: u64) -> Result<Vec<u64>> {
    let mut last = 0u64;
    let mut out = Vec::with_capacity(distribution.len());
    for d in distribution {
        let c = d
            .checked_add(base)
            .ok_or_else(|| Error::Daemon("get_output_distribution: overflows".into()))?;
        if c < last {
            return Err(Error::Daemon("get_output_distribution: not cumulative".into()));
        }
        last = c;
        out.push(c);
    }
    Ok(out)
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

/// Reads a `get_blocks.bin` response, from a node that may be malicious:
/// every count is bounded before anything is kept for it (`max_blocks`
/// blocks, `MAX_TXS_PER_BLOCK` transactions a block, `MAX_OUTPUT_INDEXES`
/// indexes), nothing is indexed unchecked, and anything malformed is an
/// error, never a panic. monero-epee reads without allocating and
/// monero-oxide grows its vectors as it reads, so memory follows the bytes
/// actually sent, which `post` caps.
fn parse(response: &[u8], max_blocks: usize) -> Result<Vec<Fetched>> {
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
                    if blocks.len() >= max_blocks {
                        return Err(invalid("get_blocks.bin sent more blocks than asked for"));
                    }
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
                                            if transactions.len() >= MAX_TXS_PER_BLOCK {
                                                return Err(invalid(
                                                    "get_blocks.bin: too many transactions in a block",
                                                ));
                                            }
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
                                    if output_indexes.len() >= MAX_OUTPUT_INDEXES {
                                        return Err(invalid("get_blocks.bin: too many output indexes"));
                                    }
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
            let Some((these, rest)) = indexes.split_at_checked(outputs) else {
                return Err(invalid("get_blocks.bin left out output indexes"));
            };
            let first = these.first().copied();
            first_indexes.push(first.filter(|_| !matches!(tx, Transaction::V1 { .. })));
            indexes = rest;
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

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng, rngs::StdRng};

    /// `get_blocks.bin` from a mainnet node for blocks 3,300,000 to
    /// 3,300,002, pruned, as monerod answers it.
    const FIXTURE: &[u8] = include_bytes!("../fixtures/get_blocks-mainnet-3300000-3.bin");

    #[test]
    fn the_fixture_reads() {
        let blocks = parse(FIXTURE, 3).unwrap();
        assert_eq!(blocks.len(), 3);
        for (i, f) in blocks.iter().enumerate() {
            assert_eq!(f.block.block.number(), 3_300_000 + i);
            assert_eq!(f.first_indexes.len(), f.block.transactions.len() + 1);
        }
        assert!(parse(FIXTURE, 2).is_err(), "more blocks than asked for is an error");
    }

    /// A little fuzzing: thousands of random mutations of a real response,
    /// each of which must come back as `Ok` or `Err`, never a panic (an
    /// allocation the size of a forged length would abort the test).
    #[test]
    fn mutated_responses_are_errors_not_panics() {
        let mut rng = StdRng::seed_from_u64(0x6c77_735f_6675_7a7a);
        let mut errors = 0;
        for round in 0..4_000 {
            let mut m = FIXTURE.to_vec();
            for _ in 0..rng.gen_range(1..4) {
                mutate(&mut m, &mut rng);
            }
            let result = std::panic::catch_unwind(|| parse(&m, MAX_BLOCKS_PER_REQUEST as usize));
            match result {
                Ok(Ok(_)) => {}
                Ok(Err(_)) => errors += 1,
                Err(_) => panic!("round {round}: the reader panicked"),
            }
        }
        assert!(errors > 1_000, "the mutations mostly break the response ({errors})");
    }

    fn mutate(m: &mut Vec<u8>, rng: &mut StdRng) {
        if m.is_empty() {
            m.push(rng.r#gen());
            return;
        }
        let at = rng.gen_range(0..m.len());
        match rng.gen_range(0..7) {
            // Flip a few bits.
            0 => {
                for _ in 0..rng.gen_range(1..8) {
                    let i = rng.gen_range(0..m.len());
                    m[i] ^= 1 << rng.gen_range(0..8);
                }
            }
            // A run of 0xff: the largest epee varints and monero varints.
            1 => {
                for b in m.iter_mut().skip(at).take(rng.gen_range(1..10)) {
                    *b = 0xff;
                }
            }
            // An 8-byte epee varint of a huge count, where a count may be.
            2 => {
                let huge = (u64::MAX >> 2) << 2 | 3;
                for (i, b) in huge.to_le_bytes().into_iter().enumerate() {
                    if let Some(slot) = m.get_mut(at + i) {
                        *slot = b;
                    }
                }
            }
            // Cut short.
            3 => m.truncate(at),
            // A slice repeated.
            4 => {
                let len = rng.gen_range(1..256).min(m.len() - at);
                let slice = m[at..at + len].to_vec();
                let to = rng.gen_range(0..m.len());
                m.splice(to..to, slice);
            }
            // A slice gone.
            5 => {
                let len = rng.gen_range(1..256).min(m.len() - at);
                m.drain(at..at + len);
            }
            // Random bytes.
            _ => {
                for b in m.iter_mut().skip(at).take(rng.gen_range(1..32)) {
                    *b = rng.r#gen();
                }
            }
        }
    }

    #[test]
    fn forged_counts_are_errors() {
        // A response that is only a header and a section claiming 2^60 fields.
        let mut m = HEADER.to_vec();
        m.push(VERSION);
        m.extend(((1u64 << 60) << 2 | 3).to_le_bytes());
        assert!(parse(&m, 10).is_err());
        assert!(parse(&[], 10).is_err());
        assert!(parse(&FIXTURE[..FIXTURE.len() / 2], 10).is_err());
    }

    #[test]
    fn distributions_must_be_cumulative() {
        assert_eq!(checked_cumulative(vec![1, 2, 2, 5], 10).unwrap(), vec![11, 12, 12, 15]);
        assert!(checked_cumulative(vec![1, 3, 2], 0).is_err());
        assert!(checked_cumulative(vec![u64::MAX], 1).is_err());
    }

    #[test]
    fn credentials_in_the_node_url_stay_out_of_the_log() {
        assert_eq!(
            redact_userinfo("http://user:secret@node.example:18081"),
            "http://***@node.example:18081"
        );
        assert_eq!(redact_userinfo("http://127.0.0.1:18081"), "http://127.0.0.1:18081");
        assert_eq!(
            redact_userinfo("https://node.example/path@x"),
            "https://node.example/path@x"
        );
        let d = Daemon::new("http://u:p@127.0.0.1:1").unwrap();
        assert!(!d.display_url().contains("p@"));
    }

    /// A node that sends more than the limit, without a `Content-Length`, is
    /// cut off: the body isn't buffered whole.
    #[tokio::test]
    async fn an_oversized_response_is_cut_off() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf).await;
            let _ = s.write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n").await;
            let chunk = vec![0u8; 64 * 1024];
            for _ in 0..64 {
                if s.write_all(&chunk).await.is_err() {
                    return;
                }
            }
        });
        let d = Daemon::new(&format!("http://{addr}")).unwrap();
        let e = d.post("get_blocks.bin", vec![], false, 100 * 1024).await.unwrap_err();
        assert!(e.to_string().contains("over"), "{e}");
    }
}
