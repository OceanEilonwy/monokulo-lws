//! Proofs of inclusion (`lws_api::Proof`): what is kept of a block and of a
//! transaction that pays an account, so a client can recompute the
//! transaction's hash and the block's hash itself and check the block's hash
//! against any node.
//!
//! The bytes are the node's own (`daemon::RawBlock`), not a serialisation
//! made again here. A transaction's parts are served only once its hash,
//! recomputed from them, is the one its block lists, so a proof that is
//! served always checks out. `get_blocks.bin` usually carries no prunable
//! hash (all zeros, monero-project/monero#10120); the parts are then kept
//! pending, and the scanner fills the hash in from `get_transactions`
//! (`Scanner::complete_proofs`).

use monero_wallet::{primitives::keccak256, transaction::TransactionPrefix};

use crate::daemon::RawTx;

/// A pruned transaction in the parts a proof carries: the prefix (version
/// included, as the prefix hash takes it), the RingCT base, and the hash of
/// the prunable part, `None` while it is not known yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxParts {
    pub prefix: Vec<u8>,
    pub rct_base: Vec<u8>,
    pub prunable_hash: Option<[u8; 32]>,
}

/// A version 2 transaction's hash from its parts:
/// keccak(keccak(prefix) ‖ keccak(rct_base) ‖ prunable_hash).
pub fn tx_hash(prefix: &[u8], rct_base: &[u8], prunable_hash: &[u8; 32]) -> [u8; 32] {
    let mut hashes = Vec::with_capacity(96);
    hashes.extend(keccak256(prefix));
    hashes.extend(keccak256(rct_base));
    hashes.extend(prunable_hash);
    keccak256(hashes)
}

/// A block blob's hash, as a client works it out from the blob: `None` if
/// the blob doesn't read as a block.
#[cfg(test)]
pub fn block_hash(blob: &[u8]) -> Option<[u8; 32]> {
    monero_wallet::block::Block::read(&mut &blob[..]).ok().map(|b| b.hash())
}

/// `raw` split into its parts if it is a version 2 transaction: with its
/// prunable hash if the node sent one that makes the parts hash to `hash`,
/// without (pending) if the node sent zeros. `None` for a pre-RingCT
/// transaction (whose hash takes its signatures, which a pruned blob
/// doesn't carry), for a blob that doesn't read, and for parts that don't
/// hash to `hash` with the prunable hash the node sent.
pub fn split(raw: &RawTx, hash: &[u8; 32]) -> Option<TxParts> {
    // Version 2 is one varint byte.
    let (&2, rest) = raw.pruned.split_first()? else {
        return None;
    };
    let mut reader = rest;
    TransactionPrefix::read(&mut reader, 2).ok()?;
    let prefix_len = raw.pruned.len() - reader.len();
    let (prefix, rct_base) = raw.pruned.split_at(prefix_len);
    if rct_base.is_empty() {
        return None;
    }
    let prunable_hash = match raw.prunable_hash {
        zeros if zeros == [0; 32] => None,
        given if tx_hash(prefix, rct_base, &given) == *hash => Some(given),
        _ => return None,
    };
    Some(TxParts {
        prefix: prefix.to_vec(),
        rct_base: rct_base.to_vec(),
        prunable_hash,
    })
}

/// The bytes of a block made here rather than fetched (the tests): monero-oxide's
/// serialisation, with the prunable hash given for each transaction (zeros
/// where none is given, as a node sends them).
#[cfg(test)]
pub fn raw_of(
    block: &monero_wallet::interface::ScannableBlock,
    prunable_hashes: &[[u8; 32]],
) -> crate::daemon::RawBlock {
    crate::daemon::RawBlock {
        blob: block.block.serialize(),
        txs: block
            .transactions
            .iter()
            .enumerate()
            .map(|(i, tx)| RawTx {
                pruned: tx.serialize(),
                prunable_hash: prunable_hashes.get(i).copied().unwrap_or([0; 32]),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monero_wallet::transaction::{NotPruned, Transaction};
    use std::collections::HashMap;

    fn hex32(s: &str) -> Option<[u8; 32]> {
        crate::types::TxHash::from_hex(s).map(|h| h.0)
    }

    /// `get_blocks.bin` from a mainnet node for blocks 3,300,000 to 3,300,002.
    const BLOCKS: &[u8] = include_bytes!("../fixtures/get_blocks-mainnet-3300000-3.bin");
    /// The hashes of those blocks, from a mainnet node's
    /// `get_block_header_by_height`.
    const MAINNET_HASHES: [&str; 3] = [
        "b6bf8a453addd8e2b6a234fd5c3815afe90607b9eb215891cbb4961a526f3585",
        "28196a34c6c78689ec686a9272f58fd093a44b29ac9bf02bdac5dacae54954fb",
        "a7b35eaa91595fce7e14d70d8dcb0427673002fbd500b444bf9ddca04660f24f",
    ];
    /// Each of those blocks' transactions' hash and prunable hash, from a
    /// mainnet node's `get_transactions` (the `get_blocks.bin` response
    /// carries zeros for the latter).
    const MAINNET_PRUNABLE: &str = include_str!("../fixtures/mainnet-3300000-3-prunable.txt");

    fn prunable_hashes() -> HashMap<[u8; 32], [u8; 32]> {
        MAINNET_PRUNABLE
            .lines()
            .map(|l| {
                let (tx, prunable) = l.split_once(' ').unwrap();
                (hex32(tx).unwrap(), hex32(prunable).unwrap())
            })
            .collect()
    }

    /// Real mainnet blocks as the node sent them: each block blob hashes to
    /// the chain's hash for its height (the miner transaction, held whole in
    /// the blob, is in that hash's Merkle root), and every other transaction's
    /// hash from its pruned parts and its prunable hash is the one its block
    /// lists.
    #[test]
    fn mainnet_blocks_and_transactions_hash_from_the_nodes_bytes() {
        let fetched = crate::daemon::parse(BLOCKS, 3).unwrap();
        let prunable = prunable_hashes();
        let mut checked = 0;
        for (f, expected) in fetched.iter().zip(MAINNET_HASHES) {
            let expected = hex32(expected).unwrap();
            assert_eq!(
                block_hash(&f.raw.blob),
                Some(expected),
                "the blob hashes to the chain's hash"
            );
            assert_eq!(f.block.block.hash(), expected);
            assert_eq!(f.raw.txs.len(), f.block.block.transactions.len());
            for (raw, hash) in f.raw.txs.iter().zip(&f.block.block.transactions) {
                assert_eq!(raw.prunable_hash, [0; 32], "this node sends no prunable hash");
                let pending = split(raw, hash).expect("a version 2 transaction");
                assert_eq!(pending.prunable_hash, None);
                assert_eq!([pending.prefix.as_slice(), &pending.rct_base].concat(), raw.pruned);
                let with = RawTx {
                    pruned: raw.pruned.clone(),
                    prunable_hash: prunable[hash],
                };
                let parts = split(&with, hash).expect("the parts hash to the listed hash");
                assert_eq!(parts.prunable_hash, Some(prunable[hash]));
                assert_eq!(tx_hash(&parts.prefix, &parts.rct_base, &prunable[hash]), *hash);
                // Another transaction's prunable hash doesn't do.
                let wrong = RawTx {
                    pruned: raw.pruned.clone(),
                    prunable_hash: keccak256(hash),
                };
                assert_eq!(split(&wrong, hash), None);
                checked += 1;
            }
        }
        assert_eq!(checked, 91);
    }

    /// A whole stagenet transaction (from `get_transactions`, unpruned):
    /// monero-oxide's hash of it is its hash, and the formula over its pruned
    /// parts gives the same.
    #[test]
    fn the_formula_is_the_hash_of_a_whole_transaction() {
        let whole = hex::decode(include_str!("../fixtures/stagenet-tx-2245514.hex").trim()).unwrap();
        let expected = hex32(include_str!("../fixtures/stagenet-tx-2245514.hash").trim()).unwrap();
        let tx = Transaction::<NotPruned>::read(&mut whole.as_slice()).unwrap();
        assert_eq!(tx.hash(), expected);
        let prunable_hash = tx.prunable_hash().unwrap();
        let (pruned, prunable) = tx.pruned_with_prunable();
        assert_eq!(keccak256(&prunable), prunable_hash);
        let pruned_blob = pruned.serialize();
        assert_eq!(
            [pruned_blob.as_slice(), &prunable].concat(),
            whole,
            "the whole blob is the pruned one and the prunable part"
        );
        let raw = RawTx {
            pruned: pruned_blob,
            prunable_hash,
        };
        let parts = split(&raw, &expected).expect("the formula gives the hash");
        assert_eq!(tx_hash(&parts.prefix, &parts.rct_base, &prunable_hash), expected);
        assert_eq!(keccak256(&parts.prefix), crate::scanner::prefix_hash(&pruned));
    }

    /// A miner transaction (RingCT type null) isn't split: the block blob
    /// holds it whole, and its hash, as monero-oxide works it out, is the
    /// formula over its prefix, the one zero byte of a null RingCT base and a
    /// zero prunable hash.
    #[test]
    fn a_miner_transaction_hashes_with_a_null_base() {
        let fetched = crate::daemon::parse(BLOCKS, 3).unwrap();
        for f in &fetched {
            let miner = f.block.block.miner_transaction();
            let blob = miner.serialize();
            assert_eq!(blob.last(), Some(&0), "a null RingCT base is one zero byte");
            let prefix = &blob[..blob.len() - 1];
            assert_eq!(tx_hash(prefix, &[0], &[0; 32]), miner.hash());
            assert!(
                f.raw.blob.windows(blob.len()).any(|w| w == blob),
                "the block blob carries the miner transaction"
            );
        }
    }
}
