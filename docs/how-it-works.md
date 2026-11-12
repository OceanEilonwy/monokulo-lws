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
- 10,000 block hashes are kept (catch-up lanes keep theirs too once within
  that of the tip); a batch whose blocks don't follow, or aren't, the ones
  kept, or (once caught up) a top block whose hash isn't the one kept for
  that height, means a reorg. The fork is found by bisecting the kept
  hashes, and outputs, candidate spends and transactions from it on are
  dropped for every account, accounts past it move back to it (catch-up
  accounts too), what the pool held is forgotten and looked at again, and
  the new blocks are scanned with the node's global indices. A batch
  fetched before a reorg was unwound is not written. Besides the last
  10,000, every 1,000th block's hash is kept for good (a checkpoint, by
  whichever lane scanned it, and checked by catch-up lanes far below the
  tip): a reorg deeper than the last 10,000 is bracketed by bisecting them
  and unwound from just above the highest checkpoint still on the node's
  chain, by itself. A reorg deeper than every checkpoint too (or a node on
  another chain) stops scanning with an error in the log and
  `/daemon_status`, rewinding nothing, and marks every account there is to
  be rescanned; the API goes on serving. Rescan every active account
  (admin `rescan`) from below the lowest checkpoint and scanning resumes
  by itself once none is left (a hidden or inactive account still marked
  then starts again from the lowest height it held anything at). Reorgs that keep ending at the same fork with nothing
  scanned between (a node whose blocks and headers disagree) are retried
  after a wait, from a second doubling to a minute, logged at warn.
- A batch is written in chunks of about 50 ms, each one SQLite transaction
  with its own reorg checks: a chunk's outputs, spends, block hashes and
  scan heights land together or not at all, so a kill mid-batch leaves
  every account at a height it really scanned to, and a client's write
  waits for the writer at most about a chunk (writes take it in turn,
  first come, first served). A batch writes only for the
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
- Storage is one SQLite file in WAL mode: one writer connection, and a
  few read-only connections the API reads through, so reads never wait
  for the scanner's batch. Every database call from async code runs on
  tokio's blocking threads.

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
