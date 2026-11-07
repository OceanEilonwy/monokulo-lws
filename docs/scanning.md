# Scanning for many accounts at once

How monokulo-lws will scan when it has hundreds of accounts: with Fob's
`fob-scanner`, one GPU pass for every account, and monero-oxide only for
the transactions that are really someone's. Status: design; the first
version scans each block once per account with monero-oxide alone.

## What fob-scanner does

`fob-scanner` is a prefilter, not a scanner. For a batch of blocks it:

1. collects one job per transaction public key (and per additional key),
   about 57 a mainnet block;
2. computes `D = 8·a·R` for each, on the GPU (Vulkan, a GLSL compute shader
   in three stages: decompress `R` and build a 1R..8R table; sixteen window
   passes over the view key's 64 signed base-16 digits; a final ×8) in
   batches of 32,768 keys, or on CPU threads with its own radix-2^51 field
   code; the CPU finishes batch *n* while the GPU does *n*+1;
3. compresses the points with one field inversion per 64;
4. for each output of each transaction: if it has a view tag, checks
   `Keccak("view_tag" ‖ D ‖ i)[0]`, which 1 in 256 pass; then checks the
   real condition, `P − H_s(D ‖ i)·G` is one of the spend keys it watches
   (the primary one and every registered subaddress);
5. flags the block on the first hit.

Fob then runs monero-oxide's `Scanner` on flagged blocks only. Measured in
Fob (decisions 350, 351): 5,000 mainnet blocks for one wallet in 0.29 s on
an RX 6800 XT, 0.89 s on 16 CPU threads; 39 MB of GPU state per batch; a
batch costs at least 3.7 ms, so batches smaller than 32,768 don't pay.

The kernel today takes one view key per dispatch, as push constants. Every
work item multiplies a different `R` by the same `a`.

## The change in fob-scanner: a keyring

A server has few `R`s and many `a`s. The kernel turns around:

- `Keyring::add(pair, view) -> AccountId`, `Keyring::watch(id, pair,
  subaddress)`, `Keyring::flag_many(blocks, threads, gpu_allowed) -> Vec<Hit
  { account, block, tx }>`. `Prefilter` (one key, one bool per block) stays
  as a keyring of one.
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
compile with its pipeline cache, `Mode::{Gpu, Auto, Cpu}`, and retiring the
GPU on any failure with the remaining jobs going to the CPU. The one
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
7. Fallbacks: a block `fob-scanner` won't vouch for (v1 transactions, no
   RingCT outputs, a hard fork it doesn't know) is scanned the old way for
   every account; outputs without a view tag (before August 2022) skip the
   tag and take the full derivation.

Command line: `--scan gpu|cpu|auto` (default auto: the GPU from 512 keys a
batch, as Fob's policy), `--cache-dir` for the pipeline cache.

## Lanes: a wallet joining with history

A wallet made at the tip costs nothing: `Keyring::add` appends 64 bytes of
digits, and the account rides the next batch. A wallet with history (a
restore, `/import_wallet_request`, an admin `rescan`) starts far below the
tip, and the first version's loop handles that badly: a step starts at the
lowest height any account stands at, so one import from 2019 drags
fetching back to 2019 and every other account sees no new block until it
has caught up. The design is lanes:

- **The live lane**: the keyring of every caught-up account. Follows the
  tip block by block, looks at the mempool, keeps the 200 block hashes and
  handles reorgs. Its batches are small (about 57 keys × accounts a block),
  so it is never starved.
- **Catch-up lanes**: each one fetches from the lowest start height of the
  accounts queued for it, with its own keyring of only those accounts. An
  account whose start height is above a running lane's cursor joins that
  lane's keyring when the cursor passes it (`follow`); one below the cursor
  waits for the next run (`wait`). When a lane's cursor reaches the live
  lane's height, its accounts move into the live keyring and the lane ends;
  if anything is queued, a new run starts. Catch-up lanes are below the
  reorg window by construction until they merge, so they don't check
  hashes.
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
| `--catch-up-scan gpu\|cpu\|auto` | as `--scan` | Which engine catch-up lanes use; `cpu` keeps the GPU for the live lane on a machine where the GPU is slow to share. |
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

`monokulo-lws` takes `fob-scanner` as a git dependency pinned to a revision
of `monokulo-fob` until the crate is on crates.io (`publish = false` today).
The direction is server → Fob: Fob gains no tie to Monokulo.

## Order of work

1. `fob-scanner`: the keyring API, the digits buffer and the two push
   constants, vectors per account, and a test that a keyring of *n* copies
   of one key flags exactly what the single key flags.
2. `monokulo-lws`: per-transaction output indices from the reader,
   `flag_many`, stand-in blocks per hit, the global spend map; the
   benchmark above.
3. View-tag Keccak on the GPU.
