# What it answers

`/login`, `/get_address_info`, `/get_address_txs`, `/get_unspent_outs`,
`/get_random_outs`, `/submit_raw_tx`, `/import_wallet_request`,
`/get_subaddrs`, `/upsert_subaddrs`, `/provision_subaddrs`, `/get_version`,
and `/daemon_status` (not in any spec: how the scanner and node are doing).

Things beyond the community API worth knowing:

- **The mempool is reported**, as monero-lws does. A pool transaction that
  pays the account, or whose ring holds one of its outputs, appears in
  `/get_address_txs` with `mempool: true`, no height and no timestamp (its
  outputs counted in `total_received`, its candidate spends in
  `spent_outputs`), and goes away when dropped. Once mined it is listed
  once, mined, with its height, even before the pool is looked at again.
- **Outputs come on each transaction** (`receives`, as monero-lws 1.0 adds):
  amount, one-time key, index, global index, the transaction key the output
  was derived from (the additional one for a subaddress), the RingCT mask,
  the subaddress, and the output's **commitment as the chain holds it**
  (the RingCT base's `outPk`; `G + amount·H` for a miner output, which is
  what the chain's output set holds for it). A client can check `mask·G +
  amount·H` against it rather than trust the server's amount and mask, and
  build a spendable output without `/get_unspent_outs`. monero-lws does not
  send `commitment`.
- **Each transaction carries its fee** (`fee`, a decimal string, as
  monero-lws writes it): the RingCT base's fee, or inputs less outputs for a
  pre-RingCT transaction, and `"0"` for a coinbase transaction, as
  monero-lws writes it. Pool transactions carry theirs too.
- `/get_address_info`'s `locked_funds` counts outputs by wallet2's rules
  (10 blocks; an `unlock_time` below 500,000,000 is a height, else a time
  with 120 s of leeway).

The three endpoints a client sends with answer as monero-lws does, field
for field (monero-lws's own REST test responses parse and write back byte
for byte through `lws-api`):

- **`/get_unspent_outs`** lists every received output, locked ones included
  (by age, by `unlock_time`, or a coinbase not yet 60 blocks deep), spent or
  not: the client decides from the transaction's `unlock_time` in
  `/get_address_txs` and from `spend_key_images`. `amount` is a check, not a
  selection: every listed output comes back, or HTTP 400 when they add up
  to less. An output is left out when its transaction's mixin is below
  `mixin` (a coinbase transaction's is 0, so any `mixin` above 0 leaves
  coinbase outputs out, as monero-lws does) or its amount is below
  `dust_threshold` (unless `use_dust`). `per_byte_fee` and `fee_mask` are
  the node's `get_fee_estimate` (10 grace blocks) `fee` and
  `quantization_mask`, `fees` its four per-priority fees, lowest first; as
  monero-lws writes them, all three are JSON numbers, not strings, and an
  output's `global_index` is a number too, repeated as `tx_id`. The 96-byte
  `rct` is the output's on-chain commitment, then its mask and its amount
  each encrypted the original (`ecdhEncode` v1) way, `mask + H_s(s)` and
  `amount + H_s(H_s(s))` with `s = H_s(8·a·R ‖ index)`; for a coinbase
  output it is 32 zero bytes, the identity mask, 32 zero bytes, and the
  client computes the commitment (`G + amount·H`) itself.
- **`/get_random_outs`** picks `count` (at most 20) ring members for each
  of up to 150 rings as wallet2's `gamma_picker` does (shape 19.28, scale
  1/1.61, ages moved back by the 10-block unlock time, the youngest drawn
  from the 15-block recent window, the newest nine blocks never), keeps
  only members the node says are unlocked, never repeats one in a ring, and
  sorts each ring by global index. Every ring comes back full, or the
  request fails with 503 after monero-lws's 64 rounds. `count` members are
  all decoys: a client making rings of 16 asks for 16 and drops one (the
  output it spends, if it was picked). `rct` is the commitment then 64 zero
  bytes. Only RingCT (amount `"0"`) is served; monero-lws also serves
  pre-RingCT amounts.
- **`/submit_raw_tx`** relays through the node's `send_raw_transaction`
  (`do_not_relay: false`) and answers `{"status":"OK"}`; `{"status":"OK",
  "reason":"Not relayed","not_relayed":true}` when the node kept it without
  relaying it; and HTTP 422 `{"status":"Failed","reason":"..."}` when it
  refused it, the reason in monerod's words (`"double spend and fee too
  low"`). A transaction that doesn't parse is HTTP 400 before the node sees
  it. A relayed transaction is scanned into the pool view at once, so a
  client polling `/get_address_txs` right after sees its spend and change
  with `mempool: true`.
- A new account made by `/login` starts at the chain's top block, which is
  scanned for it too. `/login` takes no start height (nor does monero-lws's);
  an operator gives one with `admin add-account --start-height` or `rescan`.
- **Each mined transaction that pays the account carries a proof of
  inclusion** (`proof`, an extension monero-lws does not have): the block as
  Monero serialises it (header, miner transaction, the other transactions'
  hashes) and, for a transaction other than the miner's, the pruned
  transaction in three parts, `tx_prefix`, `rct_base` and `prunable_hash`.
  A client recomputes the transaction's hash as keccak(keccak(`tx_prefix`) ‖
  keccak(`rct_base`) ‖ `prunable_hash`) (the miner transaction's from the
  block, which holds it whole), finds it in the block, works out the block's
  hash and asks a node of its own choosing for the block hash at that
  height. The prefix holds the transaction keys, the one-time keys and the
  `unlock_time`; the RingCT base holds the commitments, the encrypted
  amounts and the fee. So a server that holds the view key can no longer
  invent an output: whatever it reports must be on the chain. Pool
  transactions have no proof (`proof` is absent) until they are mined, and
  neither do candidate spends (see below). The bytes are the node's own, as
  `get_blocks.bin` sent them, and a transaction's parts are served only once
  they hash to its hash.

Spends are **candidates**: an input whose ring holds one of the account's
outputs. The server can't tell a real spend from a decoy use; the client
computes the key image of the output named (`tx_pub_key`, `out_index`) and
compares. A candidate spend comes without a proof: a server that invents
one cannot give it the key image the client computes (that takes the spend
key), so the client ignores it anyway, and an output turns up in about as
many rings as there are ring members (16), so proving candidate spends would
cost about sixteen times the storage of proving receives.
