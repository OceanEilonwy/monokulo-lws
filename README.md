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

Planned, with the monokulo-8ar engine (`docs/scanning.md`): the GPU when
one is usable, else monero-oxide for every block, nothing to choose;
`--cache-dir` for the shader cache, `--gpu-arenas`, and the catch-up lanes a
wallet with history scans in (`--catch-up-lanes`, `--catch-up-join
follow|wait`, `--catch-up-blocks`, `--catch-up-in-flight`).

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
- Each block is scanned once per active account with monero-oxide's
  `Scanner` (view tags first). An account behind the rest (new, or asked to
  rescan) is caught up by the same loop: a round starts at the lowest height
  any account stands at and scans a block only for the accounts that haven't
  passed it.
- Candidate spends: every RingCT input's ring, resolved to global indices,
  matched against the account's outputs.
- 200 block hashes are kept; a batch whose first block doesn't follow the
  last kept one means a reorg, and everything from the fork on is dropped
  and scanned again.
- Ring members for `/get_random_outs` are drawn from the RingCT output
  distribution with wallet2's gamma over age, fetched with `get_outs`, and
  kept only if unlocked.
- Storage is one SQLite file in WAL mode.

Cost today is accounts × blocks: fine for a shop, a family or a few dozen
wallets. The planned engine for more is `monokulo-8ar`, the prefilter lifted out of Fob: one GPU pass
computes `8·a·R` for every (account, transaction key) pair, 32,768 at a
time, and only real hits reach monero-oxide. See `docs/scanning.md`.

Not built yet: webhooks, the `/feed` websocket, fiat `rates`, pre-RingCT
spends, import fees, remote scanning, `get_tree_path`, TLS on the listener.

## Developing

```sh
cargo test --workspace
cargo test -p monokulo-lws fresh_stagenet_wallet -- --ignored --nocapture   # a throwaway stagenet wallet to try with
RUST_LOG=debug cargo run -- serve --daemon http://stagenet.xmr-tw.org:38081 --db /tmp/lws.sqlite --create auto
```

Licence: GPL-3.0-only, as Fob and Monokular.
