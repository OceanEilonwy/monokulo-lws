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
(nginx, caddy): every request carries a view key in its body.

Options that matter:

| Option | Default | What |
|---|---|---|
| `--create off\|auto\|approve` | `auto` | What `/login` with `create_account` does: refuse (501), make the account at once, or queue it for `accept_requests`. |
| `--import auto\|approve` | `approve` | What `/import_wallet_request` (a scan from block 0) does. |
| `--max-subaddresses N` | 10000 | Subaddresses an account may register; 0 turns the endpoints off. |
| `--lookahead N` | 200 | Minors `0..N` of account 0 are watched for every account without being asked. |
| `--scan-interval SECS` | 10 | How often to look at the node once caught up. |
| `--admin-listen ADDR` | off | Where the admin API listens. |
| `--disable-admin-auth` | | Skip the admin key check (only behind something else that checks). |
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
`LWS_LISTEN`, `LWS_ADMIN_LISTEN`).

### Accounts

With `--create auto` a client registers itself through `/login`. Otherwise:

```sh
monokulo-lws admin add-account --db lws.sqlite --network stage \
    --address 5A... --view-key <64 hex> --start-height 2200000
monokulo-lws admin list --db lws.sqlite
```

The admin REST API (monero-lws's: `POST /<command>` with
`{"auth": "<key>", "params": {...}}`) needs a key:

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

Two things beyond the community API worth knowing:

- **The mempool is reported.** monero-lws never lists pool transactions over
  REST. Here a pool transaction to the account appears in `/get_address_txs`
  with `mempool: true` and no height, and goes away when mined (and comes
  back with a height) or dropped.
- **Outputs come on each transaction** (`receives`, as monero-lws 1.0 adds):
  amount, one-time key, index, global index, the transaction key the output
  was derived from (the additional one for a subaddress), the RingCT mask
  and the subaddress. A client can build a spendable output from these
  without `/get_unspent_outs`.

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
  Without a usable GPU, or for a batch under 512 derivations, each block is
  scanned once per account with the `Scanner`, as monero-lws does.
- Accounts are scanned in lanes: the live lane follows the tip with every
  caught-up account (and looks at the pool and keeps block hashes); an
  account with history (a restore, an import, a rescan) is caught up in a
  catch-up lane with a keyring and GPU arena of its own, and joins the live
  lane when it reaches it. Nothing about lanes is stored: an account's scan
  height says where it is.
- Candidate spends: every RingCT input's ring, resolved to global indices,
  looked up once per ring member in one map of every account's outputs.
- 200 block hashes are kept; a batch whose first block doesn't follow the
  last kept one means a reorg, and everything from the fork on is dropped
  and scanned again.
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
spends, import fees, remote scanning, `get_tree_path`, TLS on the listener.

## Developing

```sh
cargo test --workspace
cargo test -p monokulo-lws fresh_stagenet_wallet -- --ignored --nocapture   # a throwaway stagenet wallet to try with
RUST_LOG=debug cargo run -- serve --daemon http://stagenet.xmr-tw.org:38081 --db /tmp/lws.sqlite --create auto
cargo test -p monokulo-lws -- --ignored the_gpu   # the keyring on a real GPU
cargo run --release -- replay ../monokulo-8ar/prototypes/fixtures/mainnet-3797000-2000.bin --accounts 1,10,100,1000
```

`replay` rebuilds blocks from monokulo-8ar's 2,000-block mainnet fixture
(each transaction key with its outputs' view tags and keys, one transaction
per key) and puts them through the scanner as a catch-up lane would, 100
blocks a step, for the fixture's own view key and random others: it
measures the prefilter and the writing, not fetching.

Licence: GPL-3.0-only, as Fob and Monokular.
