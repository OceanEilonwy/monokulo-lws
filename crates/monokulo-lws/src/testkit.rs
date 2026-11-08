//! Blocks made to pay test wallets, for the tests: real one-time keys, view
//! tags, compact encrypted amounts and Pedersen commitments, as a sender's
//! wallet makes them, so monero-oxide's `Scanner` finds and opens them exactly
//! as it would on the chain. Nothing here needs a node or a GPU.

use std::sync::Arc;
use std::time::{Duration, Instant};

use curve25519_dalek::{EdwardsPoint, constants::ED25519_BASEPOINT_TABLE, scalar::Scalar as DScalar};
use lws_api::{Hex, Login};
use monero_wallet::{
    address::{AddressType, MoneroAddress, Network},
    block::{Block, BlockHeader},
    ed25519::CompressedPoint,
    interface::ScannableBlock,
    primitives::keccak256,
    ringct::{EncryptedAmount, PrunedRctProofs, RctBase, RctType},
    transaction::{Input, Output, Pruned, Timelock, Transaction, TransactionPrefix},
};
use tokio::sync::Mutex;

use crate::crypto;
use crate::daemon::{Daemon, FeeEstimate};
use crate::db::{Account, Db, NewAccount, ScanWriter, Status};
use crate::decoys::Picker;
use crate::lanes::Join;
use crate::rest::{App, Config, Policy};
use crate::scanner::{Batch, LaneConfig, Ring, ScanConfig, Scanner, record_batch};

/// The lookahead the tests scan with: minors 1 and 2 of major 0.
pub const LOOKAHEAD: u32 = 3;

pub fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn scalar(label: &[u8], seed: u64) -> DScalar {
    let mut data = label.to_vec();
    data.extend(seed.to_le_bytes());
    DScalar::from_bytes_mod_order(keccak256(&data))
}

/// A wallet's keys.
pub struct Wallet {
    pub view: DScalar,
    pub spend: DScalar,
}

impl Wallet {
    pub fn new(seed: u64) -> Wallet {
        Wallet {
            view: scalar(b"test view", seed),
            spend: scalar(b"test spend", seed),
        }
    }

    pub fn spend_pub(&self) -> EdwardsPoint {
        &self.spend * ED25519_BASEPOINT_TABLE
    }

    pub fn view_pub(&self) -> EdwardsPoint {
        &self.view * ED25519_BASEPOINT_TABLE
    }

    /// A subaddress's spend key `D`; the primary spend key for (0, 0).
    pub fn sub_spend(&self, major: u32, minor: u32) -> EdwardsPoint {
        self.spend_pub() + &crypto::subaddress_derivation(self.view.as_bytes(), major, minor) * ED25519_BASEPOINT_TABLE
    }

    pub fn address(&self) -> String {
        MoneroAddress::new(
            Network::Stagenet,
            AddressType::Legacy,
            monero_wallet::ed25519::Point::from(self.spend_pub()),
            monero_wallet::ed25519::Point::from(self.view_pub()),
        )
        .to_string()
    }

    pub fn login(&self) -> Login {
        Login {
            address: self.address(),
            view_key: Hex(self.view.to_bytes()),
        }
    }

    pub fn add(&self, db: &Db, start: u64) -> Account {
        db.add_account(
            &NewAccount {
                address: self.address(),
                view_key: self.view.to_bytes(),
                spend_pub: self.spend_pub().compress().to_bytes(),
                view_pub: self.view_pub().compress().to_bytes(),
                start_height: start,
                generated_locally: false,
            },
            Status::Active,
        )
        .unwrap()
    }

    /// Output `index` of a transaction whose key (as this wallet derives
    /// from) is `key`, to the subaddress (`major`, `minor`) (the primary
    /// address for (0, 0)), for `amount`.
    pub fn pay(&self, key: &EdwardsPoint, major: u32, minor: u32, index: u64, amount: u64) -> Out {
        let derivation = (self.view * key).mul_by_cofactor().compress().to_bytes();
        let mut tagged = b"view_tag".to_vec();
        tagged.extend_from_slice(&derivation);
        varint(index, &mut tagged);
        let mut shared = derivation.to_vec();
        varint(index, &mut shared);
        let shared = DScalar::from_bytes_mod_order(keccak256(&shared));
        let one_time = &shared * ED25519_BASEPOINT_TABLE + self.sub_spend(major, minor);
        let mut mask = b"commitment_mask".to_vec();
        mask.extend_from_slice(shared.as_bytes());
        let mask = DScalar::from_bytes_mod_order(keccak256(&mask));
        let mut pad = b"amount".to_vec();
        pad.extend_from_slice(shared.as_bytes());
        let pad = keccak256(&pad);
        let encrypted = amount ^ u64::from_le_bytes(pad[..8].try_into().unwrap());
        Out {
            output: Output {
                amount: None,
                key: CompressedPoint::from(one_time.compress().to_bytes()),
                view_tag: Some(keccak256(&tagged)[0]),
            },
            encrypted: EncryptedAmount::Compact {
                amount: encrypted.to_le_bytes(),
            },
            commitment: crypto::commit(mask.as_bytes(), amount),
            mask: mask.to_bytes(),
            amount,
        }
    }
}

/// An output with its RingCT parts.
#[derive(Clone)]
pub struct Out {
    pub output: Output,
    pub encrypted: EncryptedAmount,
    pub commitment: [u8; 32],
    pub mask: [u8; 32],
    pub amount: u64,
}

impl Out {
    /// The same output with its amount in the clear, as a miner pays.
    pub fn plain(mut self) -> Out {
        self.output.amount = Some(self.amount);
        self
    }
}

/// An output nobody here owns.
pub fn stranger(seed: u64) -> Out {
    let key = &scalar(b"stranger", seed) * ED25519_BASEPOINT_TABLE;
    let commitment = (&scalar(b"stranger commitment", seed) * ED25519_BASEPOINT_TABLE)
        .compress()
        .to_bytes();
    Out {
        output: Output {
            amount: None,
            key: CompressedPoint::from(key.compress().to_bytes()),
            view_tag: Some(seed as u8),
        },
        encrypted: EncryptedAmount::Compact {
            amount: seed.to_le_bytes(),
        },
        commitment,
        mask: [0; 32],
        amount: 0,
    }
}

/// A transaction key `r·G` (or `r·base`) for seed `r`.
pub fn tx_key(r: u64) -> (DScalar, EdwardsPoint) {
    let r = scalar(b"tx key", r);
    (r, &r * ED25519_BASEPOINT_TABLE)
}

/// A transaction made of its parts.
pub struct Tx {
    pub key: EdwardsPoint,
    pub additional: Vec<EdwardsPoint>,
    pub outs: Vec<Out>,
    pub inputs: Vec<Input>,
    pub fee: u64,
    pub unlock: Timelock,
}

impl Tx {
    pub fn new(key: EdwardsPoint, outs: Vec<Out>) -> Tx {
        Tx {
            key,
            additional: vec![],
            outs,
            inputs: vec![],
            fee: 30_000_000,
            unlock: Timelock::None,
        }
    }

    fn extra(&self) -> Vec<u8> {
        let mut extra = vec![1];
        extra.extend_from_slice(&self.key.compress().to_bytes());
        if !self.additional.is_empty() {
            extra.push(4);
            varint(self.additional.len() as u64, &mut extra);
            for k in &self.additional {
                extra.extend_from_slice(&k.compress().to_bytes());
            }
        }
        extra
    }

    pub fn build(&self) -> Transaction<Pruned> {
        Transaction::V2 {
            prefix: TransactionPrefix {
                additional_timelock: self.unlock,
                inputs: self.inputs.clone(),
                outputs: self.outs.iter().map(|o| o.output.clone()).collect(),
                extra: self.extra(),
            },
            proofs: Some(PrunedRctProofs {
                rct_type: RctType::ClsagBulletproofPlus,
                base: RctBase {
                    fee: self.fee,
                    pseudo_outs: vec![],
                    encrypted_amounts: self.outs.iter().map(|o| o.encrypted.clone()).collect(),
                    commitments: self.outs.iter().map(|o| CompressedPoint::from(o.commitment)).collect(),
                },
            }),
        }
    }

    /// A miner transaction for block `number`, its outputs' amounts in the
    /// clear and unlocked 60 blocks on, as the chain has them.
    pub fn miner(&self, number: usize) -> Transaction {
        Transaction::V2 {
            prefix: TransactionPrefix {
                additional_timelock: Timelock::Block(number + 60),
                inputs: vec![Input::Gen(number)],
                outputs: self.outs.iter().map(|o| o.clone().plain().output).collect(),
                extra: self.extra(),
            },
            proofs: None,
        }
    }
}

/// An input spending from a ring of these global indexes.
pub fn ring(members: &[u64], key_image: u8) -> Input {
    let mut sorted = members.to_vec();
    sorted.sort_unstable();
    let mut last = 0;
    let key_offsets = sorted
        .into_iter()
        .map(|m| {
            let offset = m - last;
            last = m;
            offset
        })
        .collect();
    Input::ToKey {
        amount: None,
        key_offsets,
        key_image: CompressedPoint::from([key_image; 32]),
    }
}

/// A transaction hash for transaction `i` of block `number`.
pub fn tx_hash(number: usize, i: usize, salt: u8) -> [u8; 32] {
    let mut data = b"tx".to_vec();
    data.extend((number as u64).to_le_bytes());
    data.extend((i as u64).to_le_bytes());
    data.push(salt);
    keccak256(&data)
}

/// Block `number` after `previous`: `miner`, then `txs`, output indexes from
/// `first`. Returns the block and its transactions' first output indexes;
/// the next block's `first` is the last output index plus one, as `next`.
pub struct Made {
    pub block: ScannableBlock,
    pub first_indexes: Vec<Option<u64>>,
    pub next: u64,
}

pub fn block(
    number: usize,
    previous: [u8; 32],
    miner: Transaction,
    txs: Vec<Transaction<Pruned>>,
    first: u64,
    salt: u8,
) -> Made {
    let mut first_indexes = vec![];
    let mut next = first;
    let miner_pruned: Transaction<Pruned> = miner.clone().into();
    for tx in std::iter::once(&miner_pruned).chain(&txs) {
        let outputs = tx.prefix().outputs.len() as u64;
        first_indexes.push((outputs != 0).then_some(next));
        next += outputs;
    }
    let header = BlockHeader {
        hardfork_version: 16,
        hardfork_signal: 16,
        timestamp: 1_700_000_000 + number as u64 * 120,
        previous,
        nonce: salt as u32,
    };
    let hashes = (0..txs.len()).map(|i| tx_hash(number, i, salt)).collect();
    let block = Block::new(header, miner, hashes).expect("a miner transaction");
    Made {
        block: ScannableBlock {
            block,
            transactions: txs,
            output_index_for_first_ringct_output: first_indexes.iter().flatten().next().copied(),
        },
        first_indexes,
        next,
    }
}

/// A miner transaction paying strangers.
pub fn dull_miner(number: usize) -> Transaction {
    let (_, key) = tx_key(1_000_000 + number as u64);
    Tx::new(key, vec![stranger(number as u64 * 3 + 1).plain()]).miner(number)
}

/// What gives the prefilter's hits for a batch, faked.
pub type HitsFor<'a> = Option<&'a dyn Fn(&Ring, &Batch) -> Vec<monokulo_8ar::Hit>>;

/// Writes `blocks` (from `start`) for `accounts` as a lane would, unfiltered
/// (`hits` none) or with the hits `hits` gives.
pub fn write(db: &Db, accounts: &[Account], blocks: Vec<Made>, start: u64, live: bool, hits: HitsFor) {
    let batch = Batch {
        first_indexes: blocks.iter().map(|m| m.first_indexes.clone()).collect(),
        blocks: blocks.into_iter().map(|m| m.block).collect(),
    };
    let mut slot = None;
    db.write(|tx| {
        let w = ScanWriter::new(tx);
        let ring = Ring::get(&mut slot, &w, accounts, LOOKAHEAD, &monokulo_8ar::Arena::new())?;
        let hits = hits.map(|f| f(ring, &batch));
        record_batch(&w, ring, LOOKAHEAD, accounts, &batch, start, hits.as_deref(), live)
    })
    .unwrap();
}

/// A hit for every account in every transaction of every block: each
/// transaction scanned alone in its stand-in block.
pub fn every_hit(ring: &Ring, batch: &Batch) -> Vec<monokulo_8ar::Hit> {
    let mut hits = vec![];
    for (b, block) in batch.blocks.iter().enumerate() {
        for tx in 0..=block.transactions.len() {
            for account in ring.keyring_ids() {
                hits.push(monokulo_8ar::Hit { account, block: b, tx });
            }
        }
    }
    hits
}

/// An `App` over `db` whose node is nowhere (anything that asks it fails),
/// with a fee estimate cached and the chain at `chain_height`.
pub fn app(db: Arc<Db>, chain_height: u64) -> Arc<App> {
    let daemon = Daemon::new("http://127.0.0.1:9").unwrap();
    let scanner = Scanner::new(
        db.clone(),
        daemon.clone(),
        ScanConfig {
            network: Network::Stagenet,
            lookahead: LOOKAHEAD,
            interval: Duration::from_secs(10),
            lanes: LaneConfig {
                lanes: 1,
                join: Join::Follow,
                blocks: 100,
                in_flight: 1,
                arenas: 1,
            },
        },
    );
    scanner.status.write().unwrap().chain_height = chain_height;
    Arc::new(App {
        db,
        daemon,
        scanner,
        config: Config {
            create: Policy::Auto,
            import: Policy::Auto,
            max_subaddresses: 100,
            lookahead: LOOKAHEAD,
            admin_auth: true,
            access_control_origins: vec![],
        },
        fee: Mutex::new(Some((
            Instant::now(),
            FeeEstimate {
                fee: 20_000,
                quantization_mask: 10_000,
                fees: vec![20_000, 80_000, 320_000, 4_000_000],
            },
        ))),
        picker: Mutex::new(Picker::new()),
    })
}
