# How it works

- Blocks come from `get_blocks.bin`, 100 at a time, pruned. The reader is
  Fob's: it accepts the all-zero prunable hash public nodes send, which
  monero-oxide's own reader refuses.
- A keyring of every account (`monokulo-8ar`, the prefilter lifted out of
  Fob) has the GPU work out `8·a·R` for every transaction key with every
  account's view key in one pass, 32,768 at a time, and the cores check view
  tags and spend keys. Only a transaction that really pays an account goes
  to monero-oxide's `Scanner`, for that account alone, in a stand-in block
  holding just that transaction with its own first output index, so global
  indices stay right. A block the prefilter can't vouch for is read whole.
  Without a usable GPU, each block is scanned once per account with the
  `Scanner`, as monero-lws does. With one, every batch goes to it, however
  small.
- Accounts are scanned in lanes: the live lane follows the tip with every
  caught-up account (and looks at the pool and keeps block hashes); an
  account with history (a restore, an import, a rescan) is caught up in a
  catch-up lane with a keyring and GPU arena of its own, and joins the live
  lane when it reaches it. Nothing about lanes is stored: an account's scan
  height says where it is.
- Candidate spends: every RingCT input's ring, resolved to global indices,
  looked up once per ring member in one map of every account's outputs.
- 200 block hashes are kept; a batch whose first block doesn't follow the
  last kept one, or (once caught up) a top block whose hash isn't the one
  kept for that height, means a reorg: outputs, candidate spends and
  transactions from the fork on are dropped for every account, accounts
  past it move back to it, what the pool held is forgotten and looked at
  again, and the new blocks are scanned with the node's global indices.
- One SQLite transaction per batch: outputs, spends, block hashes and scan
  heights land together or not at all, so a kill mid-batch leaves every
  account at a height it really scanned to. A batch writes only for the
  accounts still where it was planned from: one rescanned (admin `rescan`,
  `/import_wallet_request`), rewound by a reorg or hidden while its blocks
  were fetched is left for the next batch, so no block is lost or written
  twice.
- Proofs: when a transaction pays an account, the block's blob and the
  transaction's pruned bytes, as the node sent them, are kept in the same
  SQLite transaction as the output (`blocks_kept`, `txs_kept`). Nodes send
  `get_blocks.bin` without prunable hashes (all zeros,
  monero-project/monero#10120), so a kept transaction waits for its
  prunable hash from `get_transactions`, asked for after each batch; until
  then it is served without a proof. A reorg drops kept rows from the fork
  on with everything else; a rescan drops those no account needs any more.
  The cost is in `docs/scanning.md`.
- Ring members for `/get_random_outs` are drawn from the RingCT output
  distribution with wallet2's gamma over age, fetched with `get_outs`, and
  kept only if unlocked.
- Storage is one SQLite file in WAL mode.

Cost on the GPU is accounts × transaction keys derivations: on an RX 6800
XT about 2.6 million a second, so the replay of 2,000 mainnet blocks
(`monokulo-lws replay`, in the README's
[Build from source](../README.md#build-from-source)) runs at:

| accounts | blocks/s | account-blocks/s |
|---|---|---|
| 1 | 9,960 | 9,960 |
| 10 | 3,400 | 34,000 |
| 100 | 461 | 46,100 |
| 1,000 | 47 | 47,300 |

A day of mainnet (720 blocks) for 1,000 accounts is about 15 s. Without a
GPU the cost is accounts × blocks of monero-oxide scans: fine for a shop, a
family or a few dozen wallets. See `docs/scanning.md`.

Not built yet: webhooks, the `/feed` websocket, fiat `rates`, pre-RingCT
outputs and spends (monero-oxide's `Scanner` reads only RingCT
transactions, so outputs from before 2017's RingCT fork are not found and
`rct` is never left out for that reason), import fees, remote scanning,
`get_tree_path`.

A database made before `outputs.commitment` existed is brought up to date
on opening: the column is added and each output's commitment is worked out
from its stored mask and amount, which is the on-chain one, since the
scanner only keeps an output whose `mask·G + amount·H` equals the
transaction's `outPk`. No rescan is needed. Fees were stored from the
start.

Proofs are different: a database made before `blocks_kept` and `txs_kept`
existed gains the two tables, empty, on opening, and what was scanned
before is served with `proof` absent, since the block and transaction bytes
were never kept and can't be worked out from the rows. New blocks get
proofs at once; for the history, rescan the accounts (admin `rescan` with
a height at or below their start height).
