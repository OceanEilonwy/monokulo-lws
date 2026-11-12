# Scanning for many accounts at once

How monokulo-lws will scan when it has hundreds of accounts: with
`monokulo-8ar`, the prefilter lifted out of Fob's `fob-scanner`, one GPU
pass for every account, and monero-oxide only for
the transactions that are really someone's. Status: built (monokulo-8ar
`1de7768`), all but phase B; see "What is built" at the end.

## What monokulo-8ar does

`monokulo-8ar` is a prefilter, not a scanner. For a batch of blocks it:

1. collects one job per transaction public key (and per additional key),
   about 57 a mainnet block;
2. computes `D = 8·a·R` for each, on the GPU (Vulkan, a GLSL compute shader
   in three stages: decompress `R` and build a 1R..8R table; sixteen window
   passes over the view key's 64 signed base-16 digits; a final ×8, then
   the point compressed on the GPU) in batches of 32,768 keys; the CPU
   finishes batch *n* while the GPU does *n*+1;
3. for each output of each transaction, with curve25519-dalek on the CPU:
   if it has a view tag, checks `Keccak("view_tag" ‖ D ‖ i)[0]`, which 1 in
   256 pass; then checks the real condition, `P − H_s(D ‖ i)·G` is one of
   the spend keys it watches (the primary one and every registered
   subaddress);
4. flags the block on the first hit.

It is GPU-only. There is no CPU prefilter (its own field code was the
riskiest code to maintain and never the bottleneck: fetching is). Where no
usable Vulkan GPU is there, `flag` answers `None` and the caller scans
every block with monero-oxide. There is no batch size below which the GPU
is skipped (Fob's decision 370: a few milliseconds a batch was not worth a
second path); every batch goes to it when it is there. Any Vulkan GPU does, integrated ones included; Apple goes
through MoltenVK.

Fob then runs monero-oxide's `Scanner` on flagged blocks only. Measured in
Fob (decisions 350, 351): 5,000 mainnet blocks for one wallet in 0.29 s on
an RX 6800 XT; 39 MB of GPU state per batch; a
batch costs at least 3.7 ms, so batches smaller than 32,768 don't pay.

Before the keyring the kernel took one view key per dispatch, as push
constants, and every work item multiplied a different `R` by the same `a`.

## The change in monokulo-8ar: a keyring

A server has few `R`s and many `a`s. The kernel turns around:

- `Keyring::add(pair, view) -> AccountId`, `Keyring::watch(id, pair,
  subaddress)`, `Keyring::flag_many(blocks, threads, min_keys) ->
  Option<Vec<Hit { account, block, tx }>>` (`tx` 0 the miner transaction, 1
  on the others, `Hit::WHOLE_BLOCK` a block to read whole; `None` as for
  `flag`: no usable GPU, too few keys, or a failure). `Prefilter` (one key,
  one bool per block) stays as a keyring of one.
- A storage buffer of account digits, 64 bytes an account, replaces the
  push-constant digits. Push constants carry `tx_count` and `first_item`;
  work item `i` takes `R[(first_item + i) mod tx_count]` and the digits of
  account `(first_item + i) div tx_count`. The accounts × keys grid is a
  virtual one: the input buffer holds each `R` once, and a batch of 32,768
  items is a slab of the grid. Per-item state (1,200 B) and output (100 B)
  are unchanged, so GPU memory doesn't grow with accounts.
- `finish` and `pays_us` take the item's account's spend set. The CPU's
  share is accounts × outputs Keccaks (about 135 outputs a block), spread
  over cores.
- Phase B moves compression and the view-tag Keccak onto the GPU and
  returns tag hits only; the CPU then does one scalar multiplication per
  hit, 1 in 256 outputs per account.

Everything else carries over as it is: `warm_up` with the self-test vectors
(now run per account key as `check_wallet` does), the 20–30 s shader
compile with its pipeline cache, and retiring the GPU on any failure, after
which the caller scans with monero-oxide. The one
structural change is splitting the process-wide `Gpu` into a shared
`Device` and per-caller `Arena`s, so several lanes use the GPU at once
(Lanes, below).

## The change in monokulo-lws

`scanner.rs`'s step becomes:

1. Fetch 100 blocks from `get_blocks.bin`, keeping each transaction's first
   output index (the reader has them; today it keeps only each block's).
2. Build the keyring from every active account, cached until an account or
   a subaddress range changes.
3. `flag_many(blocks)` → hits.
4. Per hit: monero-oxide's `Scanner` for that account alone, on a stand-in
   `ScannableBlock` holding only that transaction with its own first output
   index, so `index_on_blockchain` stays right. Its `WalletOutput`s become
   rows as today. A miner transaction hit is a stand-in block with the real
   miner transaction and no others.
5. Candidate spends through one map, `global index → (account, output id)`,
   over every account: one lookup per ring member, not one per account.
   Outputs found in the batch are added as they come.
6. The pool: a stand-in block through the same keyring.
7. Fallbacks: a block the prefilter won't vouch for (a hard fork it
   doesn't know, transactions missing) is a `Hit::WHOLE_BLOCK` for every
   account and read whole; v1 transactions and blocks without RingCT
   outputs hold nothing the `Scanner` would find either; outputs without a
   view tag (before August 2022) skip the tag and take the full derivation.

Command line: nothing to choose. The GPU is used when it is usable, for
every batch, else every block goes to monero-oxide, and `/daemon_status`
says which. `--cache-dir` holds the pipeline cache.

## Lanes: a wallet joining with history

A wallet made at the tip costs nothing: `Keyring::add` appends 64 bytes of
digits, and the account rides the next batch. A wallet with history (a
restore, `/import_wallet_request`, an admin `rescan`) starts far below the
tip, and the first version's loop handles that badly: a step starts at the
lowest height any account stands at, so one import from 2019 drags
fetching back to 2019 and every other account sees no new block until it
has caught up. The design is lanes:

- **The live lane**: the keyring of every caught-up account. Follows the
  tip block by block, looks at the mempool, keeps the last 10,000 block
  hashes and handles reorgs. Its batches are small (about 57 keys × accounts a block),
  so it is never starved.
- **Catch-up lanes**: each one fetches from the lowest start height of the
  accounts queued for it, with its own keyring of only those accounts. An
  account whose start height is above a running lane's cursor joins that
  lane's keyring when the cursor passes it (`follow`); one below the cursor
  waits for the next run (`wait`). When a lane's cursor reaches the live
  lane's height, its accounts move into the live keyring and the lane ends;
  if anything is queued, a new run starts. A catch-up lane writes a batch
  only if it follows the hashes kept and no reorg was unwound while it was
  fetched; within 10,000 blocks of the tip it keeps its blocks' hashes, so
  the live lane can check what it merges, and blocks that don't follow the
  kept hashes make the live lane look for a reorg, accounts or not.
  Every lane also keeps every 1,000th block's hash for good (`checkpoints`,
  about 150 KB for all of mainnet) and checks its blocks against those
  below the last 10,000. A reorg deeper than the last 10,000 hashes
  (`find_fork`: the lowest kept hash isn't the node's) is bracketed by
  bisecting the checkpoints below them, a dozen header requests, and
  unwound like any other from just above the highest one still on the
  node's chain: up to 1,000 blocks more than the real fork, as no other
  hash of the orphaned chain is known there, so nothing orphaned is left
  for any account, catch-up accounts already past the fork included. Every
  write checks the reorg generation in its own transaction, so a catch-up
  lane's batch fetched before the rewind is never written, and a lane that
  merges later brings in only what it scanned after it. Only when even the
  lowest checkpoint isn't the node's does scanning stop (`halted_below`),
  with every account there is marked in `rescan_due`; an admin `rescan`
  from below the lowest checkpoint clears an account's mark, and scanning
  resumes once no active account is marked, dropping everything from that
  height on (and wiping, back to the lowest height it held, a hidden or
  inactive account still marked).
- **Shared**: one daemon connection, the live lane's requests first. One
  GPU device, but an *arena* per lane. Today `fob-scanner` keeps one device
  and one arena (the 39 MB state buffer, the output buffer, a command buffer
  and a fence) behind one mutex held for a whole batch, so two lanes would
  take turns at batch granularity and the GPU would idle while the lock
  holder uploads or finishes. The split: a `Device` (instance, logical
  device, queues, pipeline and its cache, self-test state), one per
  process, and an `Arena` per lane, about 43 MB each (state, output, input,
  command buffer, fence). The lock shrinks to the microseconds around
  `vkQueueSubmit`, which Vulkan needs per queue; where the GPU exposes
  several compute queues, arenas take their own, round-robin, and nothing is
  locked at all. Each lane records, submits and waits its own fence, and
  keeps its own CPU pipelining (finish batch *n* while the GPU does *n*+1).
  A live-lane batch lands at most one catch-up batch behind. Fob keeps one
  device, one arena, unchanged.
- **Nothing new in the database**: an account's `scan_height` says which
  lane it is in. Clients see `scanned_height` below `blockchain_height`
  until the merge; Fob's chip reads "Server scanning from 2019".

Configurable, all with `monokulo-lws serve`:

| Option | Default | What |
|---|---|---|
| `--catch-up-lanes N` | 1 | Catch-up lanes that may run at once. `0` is the first version's one loop from the lowest height (fine for a handful of wallets, no GPU needed). |
| `--catch-up-join follow\|wait` | `follow` | Whether a queued account joins a running lane when its cursor passes the account's start height, or always waits for the next run. |
| `--catch-up-blocks N` | 100 | Blocks a catch-up lane asks the daemon for at a time. |
| `--catch-up-in-flight N` | 2 | Catch-up requests in flight at once; the live lane's request always goes first. |
| `--scan-interval SECS` | 10 | How often the live lane looks at the node once caught up (as today). |
| `--gpu-arenas N` | lanes + 1 | GPU arenas (about 43 MB each): one for the live lane and one per catch-up lane, so lanes never wait on each other's batch. |
| `--gpu-memory-mb MB` | | A cap instead: arenas = MB ÷ 43, at least 1. |

With several lanes, a new catch-up account opens a lane if one is free;
otherwise, with `follow`, it joins the running lane whose cursor is nearest
below its start height; otherwise it waits. The same shape as monero-lws's
"split synced threads" scanning.

## Budget

From about a million derivations a second on a desktop GPU (decision 350),
to be measured with the 2,000-block mainnet fixture at 1, 10, 100 and
1,000 keys:

| | derivations | about |
|---|---|---|
| 1,000 accounts, a day of mainnet (720 × 57) | 41 M | 40 s |
| one new account, a year of mainnet | 15 M | 15 s |
| 100 accounts imported from 2022 | 150 M | minutes |
| GPU memory | | 39 MB a batch, any account count |

## Dependency

`monokulo-lws` takes `monokulo-8ar` (its own repository beside this one,
also what Fob's `fob-scanner` builds on) as a git dependency pinned to a
revision until the crate is on crates.io. Fob's `scan.rs` (reader threads,
the monero-oxide fan-out) stays Fob's.

## What is built

- **monokulo-8ar** (`1de7768`): the keyring, the digits buffer and the push
  constants `tx_count`, `first_item`, `count`, `digit_at`, `op`; the grid
  taken a slab at a time with the cores finishing slab *n* while the GPU
  does *n*+1; each item checked against its own account's spend keys. The
  `Device`/`Arena` split: one `gpu::Device` (instance, logical device, up to
  four compute queues, pipelines and cache) and a `gpu::Arena` per caller
  (buffers, command buffer, fence, descriptor pool); an arena locks a queue
  only around `vkQueueSubmit`, and arenas take queues round-robin. The
  crate-level `Arena` handle is what a keyring is given; `Prefilter`,
  `Keyring::new` and `check_wallet` share one, so Fob is unchanged. The
  startup vectors add every view key at once over the same keys. Tests: *n*
  copies of one key (1, 3, 50) flag what one key flags, each account in a
  mixed keyring has only its own hits, two keyrings in two arenas at once on
  the GPU.
- **monokulo-lws**: per-transaction first output indexes from the reader;
  the keyring per lane, cached until an account or a subaddress range
  changes; `flag_many`; per hit, the `Scanner` for that account on a
  stand-in block of that one transaction (a miner hit: the real miner
  transaction alone; a whole-block hit: the block); candidate spends through
  one map of every lane account's outputs; the pool through the live
  keyring; the lanes, with every option in the table above; `/daemon_status`
  gives `scanner_engine` and `catch_up_lanes` (each lane's cursor).
- Choices the code made: every batch goes to the GPU when it is usable,
  the live lane's one-block batches included (no threshold, as Fob's
  decision 370). The live lane's cursor starts at the highest scan height of any active account; an
  account below it is queued for a catch-up lane. A lane that reaches the
  live cursor waits for the live lane to take its accounts in at the start
  of its next step; if the live lane moved on meanwhile, the lane catches up
  the difference first. With no account of its own the live lane only keeps
  its cursor at the tip. A joining account (`follow`) is in the lane's
  keyring at once and skipped in blocks below its height, which comes to
  the same thing as joining when the cursor passes it. A keyring is rebuilt
  whole when its accounts change (about 7 s for 1,000 accounts with a
  lookahead of 200).
- Measured (RX 6800 XT, Ryzen 9 5950X): about 2.65 million derivations a
  second at any account count. monokulo-8ar's `scan_speed --keys N` on the
  2,000-block fixture: 44,300, 4,660, 466 and 46 blocks/s for 1, 10, 100
  and 1,000 keys. `monokulo-lws replay` of the same blocks through the
  scanner, 100 blocks a step: 9,960, 3,400, 461 and 47 blocks/s. So the
  budget's first line, 1,000 accounts and a day of mainnet, is about 15 s.

- Correctness, held by tests that need neither a node nor a GPU
  (`src/correctness.rs`): a stand-in block numbers outputs exactly as the
  whole block does, wherever the transaction sits (the miner transaction, the
  last of sixteen, after one with no outputs), checked on made blocks and on
  the mainnet fixture with payments planted; a block's hits are taken once
  per transaction and account, and an account whose block is read whole is
  not also scanned per transaction. Each found output's commitment is taken
  from the transaction's RingCT base (`outPk`; `G + amount·H` for a miner
  output) and stored with it, as is the fee. A batch is scanned first (the
  prefilter, then monero-oxide on what it flags), with no hold on the
  database's writer, and then written in chunks: each chunk is one SQLite
  transaction of as many blocks as fit in 50 ms (one at least), holding
  only that chunk's checks (no reorg unwound since the fetch, its blocks
  follow the hashes kept) and inserts, and moving its accounts' scan
  heights to its end. The writer is taken first come, first served, so a
  client's write (a new account, a request, subaddresses, an import, a
  rescan) waits at most about one chunk, not a batch: a catch-up batch of
  1,000 busy blocks for 1,000 accounts held the writer for about 1.7 s in
  one transaction on a Ryzen 5950X, which a router would make well over
  ten (`correctness::measure_write_hold`). It writes only for the accounts still at
  the height it was planned from (or where its earlier chunks left them), so an admin `rescan`, an import, a reorg's rewind or a
  status change made while the batch was being fetched is never undone by
  it. The pool's scan finds candidate spends as well as outputs (one map of
  the live accounts' outputs), is redone whenever the live lane's accounts
  change or a reorg happens, never adds a transaction twice, and a pool
  transaction already mined is served mined. Once caught up, the live lane
  compares the node's top block hash with the one it kept, so a reorg that
  replaces the top block without lengthening the chain is noticed at once.

Still planned: phase B (the view-tag Keccak, and returning only tag hits,
on the GPU); incremental keyring updates.

## Proofs of inclusion: what is kept, and what it costs

Each mined transaction that pays an account is served with a proof (README,
`docs/security.md`). What it is made of is kept at scan time, in the batch's
SQLite transaction, and only where an account is paid:

- `blocks_kept` (height, hash, blob): the block blob exactly as
  `get_blocks.bin` sent it, for every block holding a transaction that pays
  an account (the miner's included). One row however many accounts the
  block pays.
- `txs_kept` (hash, height, prefix, rct_base, prunable_hash): the pruned
  transaction as the node sent it, split where its prefix ends, for every
  transaction other than a miner's that pays an account. Again one row
  however many accounts it pays.

The reader keeps each block's and transaction's raw bytes beside the parsed
ones (`daemon::RawBlock`), so the stored bytes hash to the chain's hashes
rather than to a serialisation made again. A transaction is split only when
its parts hash to the hash its block lists. `get_blocks.bin` comes without
prunable hashes (all zeros, monero-project/monero#10120: the mainnet node
the reader's fixture came from and the stagenet node the live check used
both send zeros), so the row is written with `prunable_hash` empty and
`Scanner::complete_proofs` fills it in after the batch from
`get_transactions` (100 transactions a request, as a restricted node
allows), keeping it only if the parts then hash to the transaction's hash.
A row the node can't complete is dropped; a node that fails leaves the row
for the next batch. Until then the transaction is served without a proof.

A reorg drops both tables' rows from the fork on, with the outputs, spends
and transactions; a rescan drops the rows from its height on that no
account's transactions still need.

Candidate spends are not given proofs: an invented one can't carry the key
image the client computes, and since each output is a ring member about as
often as there are members in a ring (16; inputs and outputs are about as
many), an account has about sixteen candidate spends for each output it
receives, most in a block that pays it nothing, so proving them would
multiply the cost below by about sixteen.

Sizes, from the mainnet fixture (`get_blocks.bin` for 3,300,000 to
3,300,002) and the stagenet live check:

| What | Bytes |
|---|---|
| Block: header and miner transaction | about 150 |
| Block: each other transaction | 32 (its hash) |
| A mainnet block of 36, 55 transactions | 1,302, 1,910 |
| A typical kept block (30 to 300 transactions) | 1 to 10 KB |
| A pruned transaction, 1 or 2 inputs and 2 outputs | 270 to 300 (prefix about 190, RingCT base about 85) |
| A pruned transaction with many inputs | up to a few KB (about 100 a 16-member input) |
| Per kept row, besides | about 70 (hashes, height, SQLite's own) |

So an account that receives a payment costs about 2 to 10 KB more for it,
and less when the block or transaction is shared with another account. A
shop with 10,000 payments a year keeps about 20 to 100 MB a year for
proofs. `/get_address_txs` serves each block once per transaction, as hex,
so the response grows by about twice those sizes per paying transaction.

## Order of work

1. `monokulo-8ar`: the keyring API, the digits buffer and the two push
   constants, vectors per account, and a test that a keyring of *n* copies
   of one key flags exactly what the single key flags.
2. `monokulo-lws`: per-transaction output indices from the reader,
   `flag_many`, stand-in blocks per hit, the global spend map; the
   benchmark above.
3. View-tag Keccak on the GPU (phase B, not built).

Steps 1 and 2 are built.
