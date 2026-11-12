# monokulo-lws

A Monero light wallet server in Rust. It scans the chain for every view key
registered with it and answers the [light wallet REST
API](https://github.com/monero-project/meta/blob/master/api/lightwallet_rest.md),
the one MyMonero defined and [monero-lws](https://github.com/vtnerd/monero-lws)
implements, with monero-lws's subaddress extensions. A client keeps its
spend key and signs on its own; the server only sees what the view key
reveals.

Built for [Fob](https://github.com/OceanEilonwy/monokulo-fob)'s Light Wallet
mode and for Monokular shops that run a node already, but any client that
speaks the API can use it.

- `crates/lws-api`: the wire types (serde), usable by clients and servers.
- `crates/monokulo-lws`: the server. One binary: `serve` scans and answers,
  `admin` manages the database directly.

## Running

You need a `monerod` to ask for blocks (any version with `get_blocks.bin`,
which is all of them; a public node works for trying it out).

```sh
cargo build --release
./target/release/monokulo-lws serve \
    --daemon http://127.0.0.1:18081 \
    --db /var/lib/monokulo-lws/lws.sqlite \
    --listen 127.0.0.1:8443
```

The wallet API is then at `http://127.0.0.1:8443`. Put TLS in front of it
(nginx, caddy), with `--trusted-proxies` set to the proxy's address, or give
`--tls-cert` and `--tls-key`: every request carries a view key in its body.
Listening anywhere but loopback takes `--confirm-external-bind`.

On an OpenWrt router, install the package instead: every push to main
builds `monokulo-lws` for aarch64 and x86_64 with a LuCI page, Services >
Light Wallet Server, that holds every setting below and the wallets the
server scans ([docs/openwrt.md](docs/openwrt.md)).

Options that matter:

| Option | Default | What |
|---|---|---|
| `--create off\|auto\|approve` | `auto` | What `/login` with `create_account` does: refuse (501), make the account at once, or queue it for `accept_requests`. |
| `--import auto\|approve` | `approve` | What `/import_wallet_request` (a scan from block 0) does. |
| `--max-subaddresses N` | 10000 | Subaddresses an account may register; 0 turns the endpoints off. |
| `--lookahead N` | 200 | Minors `0..N` of account 0 are watched for every account without being asked. |
| `--scan-interval SECS` | 10 | How often to look at the node once caught up. |
| `--admin-listen ADDR` | off | Where the admin API listens (an address of its own; the wallet listener never serves it). |
| `--disable-admin-auth` | | Skip the admin key check. Only for a loopback `--admin-listen`, unless `--confirm-unauthenticated-admin` is given too. |
| `--confirm-unauthenticated-admin` | | Let `--disable-admin-auth` apply off loopback (only behind something else that checks). |
| `--confirm-external-bind` | | Allow a listener on an address other than loopback. |
| `--tls-cert FILE`, `--tls-key FILE` | | PEM certificate chain and key: the listeners speak TLS 1.2 and 1.3 themselves (rustls). A reverse proxy is still the recommended setup. |
| `--trusted-proxies CIDR,...` | | Reverse proxies whose client-address header is believed; without it the header is ignored. |
| `--client-ip-header NAME` | `X-Forwarded-For` | The header a trusted proxy puts the client's address in (the rightmost untrusted entry is the client). |
| `--rate-limit N` | 300 | Requests a minute from one client (an IPv4 address or IPv6 /64); 0 is no limit. |
| `--strict-rate-limit N` | 12 | Requests a minute from one client for account creation, imports, `/submit_raw_tx` and `/get_random_outs`; 0 is no limit. |
| `--rate-limit-per-48 N` | 4 × `--rate-limit` | Requests a minute from one IPv6 /48, on top of the per-/64 limit; 0 is no limit. |
| `--strict-rate-limit-per-48 N` | 4 × `--strict-rate-limit` | As `--strict-rate-limit`, per IPv6 /48; 0 is no limit. |
| `--max-new-accounts-per-hour N` | 1000 | New accounts and import requests an hour, across all clients; 0 is no limit. |
| `--max-pending-requests N` | 10000 | Pending create and import requests at most (monero-lws's `--create-queue-max`). |
| `--max-connections N` | 1024 | Open connections at most, per listener. |
| `--max-connections-per-ip N` | 64 | Open connections from one client (an IPv4 address or IPv6 /64) at most (a trusted proxy is exempt); 0 is no limit. |
| `--request-timeout SECS` | 30 | Time a request may take, body and answer included. Headers must arrive within 10 s. |
| `--access-control-origin ORIGIN` | | A browser origin allowed to call the API; repeat, or `*`. |
| `--network main\|stage\|test` | | Refuse to start if the node is on another network. |
| `--cache-dir DIR` | | Where the GPU's compiled shader is kept (the first compile takes 20 to 30 s). |
| `--catch-up-lanes N` | 1 | Catch-up lanes that may run at once, for accounts with history. `0` is one loop from the lowest height any account stands at. |
| `--catch-up-join follow\|wait` | `follow` | Whether a queued account joins a running lane whose cursor is below its start height, or waits for a lane of its own. |
| `--catch-up-blocks N` | 100 | Blocks a catch-up lane asks the node for at a time. |
| `--catch-up-in-flight N` | 2 | Catch-up requests in flight at once; the live lane's never waits for them. |
| `--gpu-arenas N` | lanes + 1 | GPU arenas, about 43 MB each: one for the live lane, the rest shared by the catch-up lanes. |
| `--gpu-memory-mb MB` | | A cap instead: at most MB / 43 arenas, at least 1. |

There is nothing to choose about the engine: the GPU is used when one is
usable (any Vulkan GPU, integrated included), else every block goes to
monero-oxide, and `/daemon_status` says which (`scanner_engine`) along with
each catch-up lane's cursor.

Every option is also an environment variable (`LWS_DAEMON`, `LWS_DB`,
`LWS_LISTEN`, `LWS_ADMIN_LISTEN`, `LWS_TLS_CERT`, `LWS_TLS_KEY`,
`LWS_TRUSTED_PROXIES`, `LWS_CLIENT_IP_HEADER`, `LWS_CONFIRM_EXTERNAL_BIND`).

### Security

The server holds every account's private view key, so read
[`docs/security.md`](docs/security.md) before putting it on the internet:
the threat model (internet clients, account holders, the node, someone who
reads the database, operator mistakes), the controls, how it compares with
monero-lws, and what the operator has to do. In short:

- The view keys are stored in the clear in the database, as monero-lws
  stores them (the scanner needs them for every block). The file is made
  `0600`; keep it on an encrypted disk and run the server as its own user.
- The server trusts its node, as monero-lws does: run your own.
- Admin keys are stored hashed and work only on the admin listener.
- Requests are limited in size, time and rate, per client and in all; the
  defaults above suit a shop or a small public server.
- No view key or address is written to the log at any level.

### Accounts

With `--create auto` a client registers itself through `/login`. Otherwise:

```sh
monokulo-lws admin add-account --db lws.sqlite --network stage \
    --address 5A... --start-height 2200000     # asks for the view key on stdin
monokulo-lws admin list --db lws.sqlite
```

(`--view-key` or `LWS_VIEW_KEY` work too, but a key on the command line ends
up in the process list and the shell's history.)

The admin REST API (monero-lws's: `POST /<command>` with
`{"auth": "<key>", "params": {...}}`) needs a key, printed once by
`create-key` (only its hash is stored):

```sh
monokulo-lws admin create-key --db lws.sqlite
curl -X POST http://127.0.0.1:8444/list_accounts -H 'Content-Type: application/json' \
    -d '{"auth":"<key>"}'
```

Commands: `accept_requests`, `reject_requests` (`{"type":"create"|"import",
"addresses":[...]}`), `add_account`, `list_accounts`, `list_requests`,
`modify_account_status` (`active`, `inactive`, `hidden`), `rescan`
(`{"height":..., "addresses":[...]}`), `validate`; and one of its own,
`remove_accounts` (`{"addresses":[...]}`), which forgets the accounts and
everything scanned for them, where monero-lws only hides (`admin
remove-account` does the same on the command line). Webhooks answer 501 for
now. `accept_requests` is all or nothing: if any named create request's
address already has an account it answers 409 with those addresses under
`exists`, and accepts none.

## What it answers

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

## How it works

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
(`monokulo-lws replay`, below) runs at:

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

## Developing

```sh
cargo test --workspace
cargo test -p monokulo-lws fresh_stagenet_wallet -- --ignored --nocapture   # a throwaway stagenet wallet to try with
RUST_LOG=debug cargo run -- serve --daemon http://stagenet.xmr-tw.org:38081 --db /tmp/lws.sqlite --create auto
cargo test -p monokulo-lws -- --ignored the_gpu   # the keyring on a real GPU
cargo run --release -- replay ../monokulo-8ar/prototypes/fixtures/mainnet-3797000-2000.bin --accounts 1,10,100,1000
```

`cargo test` needs neither a node nor a GPU: `src/testkit.rs` makes blocks
with real one-time keys, view tags, encrypted amounts and commitments, and
`src/correctness.rs` puts them through the scanner (unfiltered, and as
stand-in blocks for every transaction, which must write the same rows) and
calls the wallet handlers on the result. One test plants payments in
monokulo-8ar's mainnet fixture (`../monokulo-8ar/prototypes/fixtures/`, or
`LWS_FIXTURE`) and is skipped when it is absent.

`replay` rebuilds blocks from monokulo-8ar's 2,000-block mainnet fixture
(each transaction key with its outputs' view tags and keys, one transaction
per key) and puts them through the scanner as a catch-up lane would, 100
blocks a step, for the fixture's own view key and random others: it
measures the prefilter and the writing, not fetching.

Licence: GPL-3.0-only, as Fob and Monokular.
