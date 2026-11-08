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
| `--max-new-accounts-per-hour N` | 1000 | New accounts and import requests an hour, across all clients; 0 is no limit. |
| `--max-pending-requests N` | 10000 | Pending create and import requests at most (monero-lws's `--create-queue-max`). |
| `--max-connections N` | 1024 | Open connections at most, per listener. |
| `--max-connections-per-ip N` | 64 | Open connections from one address at most (a trusted proxy is exempt); 0 is no limit. |
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
(`{"height":..., "addresses":[...]}`), `validate`. Webhooks answer 501 for
now.

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
- `/get_unspent_outs`'s 96-byte `rct` starts with that same on-chain
  commitment, then the mask and the amount encrypted the original way. As
  with monero-lws, every received output is listed, locked ones included
  (by age, by `unlock_time`, or a coinbase not yet 60 blocks deep): the
  client decides from the transaction's `unlock_time` in
  `/get_address_txs`. `/get_address_info`'s `locked_funds` counts them by
  wallet2's rules (10 blocks; an `unlock_time` below 500,000,000 is a
  height, else a time with 120 s of leeway).
- A new account made by `/login` starts at the chain's top block, which is
  scanned for it too. `/login` takes no start height (nor does monero-lws's);
  an operator gives one with `admin add-account --start-height` or `rescan`.

Spends are **candidates**: an input whose ring holds one of the account's
outputs. The server can't tell a real spend from a decoy use; the client
computes the key image of the output named (`tx_pub_key`, `out_index`) and
compares.

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
- Ring members for `/get_random_outs` are drawn from the RingCT output
  distribution with wallet2's gamma over age, fetched with `get_outs`, and
  kept only if unlocked.
- Storage is one SQLite file in WAL mode.

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
