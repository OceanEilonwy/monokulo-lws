<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/lws-mark-on-dark.svg">
    <img src="docs/brand/lws-mark.svg" width="128" height="128" alt="monokulo-lws">
  </picture>
</p>

<h1 align="center">monokulo-lws</h1>

<p align="center">
  <strong>A Monero light wallet server you run yourself, on a computer or a router.</strong><br>
  It scans the chain for every view key registered with it and answers the light wallet REST API.<br>
  Wallets keep their spend keys and sign on their own: the server sees only what a view key reveals.
</p>

<p align="center">
  <a href="https://github.com/OceanEilonwy/monokulo-lws/actions/workflows/ci.yml"><img src="https://github.com/OceanEilonwy/monokulo-lws/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/OceanEilonwy/monokulo-lws/actions/workflows/openwrt.yml"><img src="https://github.com/OceanEilonwy/monokulo-lws/actions/workflows/openwrt.yml/badge.svg?branch=main" alt="OpenWrt package"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0-informational" alt="GPL-3.0"></a>
</p>

<p align="center">
  <a href="#on-an-openwrt-router"><b>OpenWrt router</b></a> ·
  <a href="#on-a-computer"><b>Computer</b></a> ·
  <a href="docs/security.md"><b>Security</b></a> ·
  <a href="docs/api.md"><b>API</b></a> ·
  <a href="#build-from-source"><b>Build from source</b></a>
</p>

## Why monokulo-lws

- **Speaks the light wallet API.** The [REST API](https://github.com/monero-project/meta/blob/master/api/lightwallet_rest.md) MyMonero defined and [monero-lws](https://github.com/vtnerd/monero-lws) implements, with monero-lws's subaddress extensions; the endpoints a wallet sends with answer field for field as monero-lws does. Built for [Fob](https://github.com/OceanEilonwy/monokulo-fob)'s Light Wallet mode and for Monokular shops that run a node already, but any client that speaks the API can use it.
- **Proves what it reports.** Each output comes with the commitment the chain holds for it, and each mined transaction that pays a wallet with a proof of inclusion: the block and the pruned transaction, so a client can hash it into a block it checks against a node of its own. A server holding the view key can't invent or inflate a payment.
- **Scans on the GPU.** The [monokulo-8ar](https://github.com/OceanEilonwy/monokulo-8ar) keyring works out 8·a·R for every transaction key with every wallet's view key in one pass: a day of mainnet for 1,000 wallets in about 15 seconds on an RX 6800 XT. Without a usable GPU every block goes to monero-oxide, which is plenty for a shop, a family or a few dozen wallets.
- **Runs on a router.** An OpenWrt package with a LuCI page, Services › Light Wallet Server, is built on every push to main for aarch64 and x86_64 and published as a [signed apk repository](https://oceaneilonwy.github.io/monokulo-lws/). Mainnet, stagenet and testnet run side by side, each turned on with one switch.
- **Careful by default.** Loopback only until told otherwise, TLS of its own or behind a proxy, limits on request size, time and rate, admin keys stored hashed and served on a listener of their own, and no view key or address in the log at any level.
- **One small program.** One binary and one SQLite file. A kill mid-batch leaves every wallet at a height it really scanned to, and reorgs are rolled back for every wallet at once.

## Get started

The server needs a `monerod` to ask for blocks: your own, since it trusts its node as monero-lws does.
Any version works; a public node is fine for trying it out.

### On an OpenWrt router

The packages are in a signed apk repository: **<https://oceaneilonwy.github.io/monokulo-lws/>** says how to
add it in LuCI. Over SSH on the router:

```sh
wget -O /etc/apk/keys/monokulo.pem https://oceaneilonwy.github.io/monokulo-lws/monokulo.pem
. /etc/openwrt_release
echo "https://oceaneilonwy.github.io/monokulo-lws/openwrt/${DISTRIB_RELEASE%.*}/$DISTRIB_ARCH/packages.adb" >> /etc/apk/repositories.d/customfeeds.list
apk update && apk add monokulo-lws
```

Then open **Services › Light Wallet Server** in LuCI: each network's status, the wallets it scans and every
setting. Mainnet runs at first; stagenet and testnet each run beside it with a tick under Networks. The whole
story, from the firewall rule to backups, is in [docs/openwrt.md](docs/openwrt.md).

### On a computer

```sh
cargo build --release
./target/release/monokulo-lws serve \
    --daemon http://127.0.0.1:18081 \
    --db /var/lib/monokulo-lws/lws.sqlite \
    --listen 127.0.0.1:8443
```

The wallet API is then at `http://127.0.0.1:8443`. Every request carries a view key in its body, so put TLS
in front of it (nginx, caddy) with `--trusted-proxies` set to the proxy's address, or give `--tls-cert` and
`--tls-key`. Listening anywhere but loopback takes `--confirm-external-bind`.

Two options decide who gets an account: `--create off|auto|approve` (what `/login` with `create_account`
does; `auto` by default) and `--import auto|approve` (what a scan from block 0 does; `approve` by default).
Every other option, from rate limits to GPU memory, is in [docs/options.md](docs/options.md), and each is
also an environment variable (`LWS_DAEMON`, `LWS_DB`, `LWS_LISTEN`…).

### Accounts

With `--create auto` a wallet registers itself through `/login`. Otherwise add it yourself:

```sh
monokulo-lws admin add-account --db lws.sqlite --network stage \
    --address 5A... --start-height 2200000     # asks for the view key on stdin
monokulo-lws admin list --db lws.sqlite
```

(`--view-key` or `LWS_VIEW_KEY` work too, but a key on the command line ends up in the process list and the
shell's history.)

The admin REST API is monero-lws's (`POST /<command>` with `{"auth": "<key>", "params": {...}}`), on its own
`--admin-listen` address, with a key printed once by `create-key` (only its hash is stored):

```sh
monokulo-lws admin create-key --db lws.sqlite
curl -X POST http://127.0.0.1:8444/list_accounts -H 'Content-Type: application/json' \
    -d '{"auth":"<key>"}'
```

Commands: `accept_requests`, `reject_requests` (`{"type":"create"|"import", "addresses":[...]}`),
`add_account`, `list_accounts`, `list_requests`, `modify_account_status` (`active`, `inactive`, `hidden`),
`rescan` (`{"height":..., "addresses":[...]}`), `validate`; and one of its own, `remove_accounts`
(`{"addresses":[...]}`), which forgets the accounts and everything scanned for them, where monero-lws only
hides (`admin remove-account` does the same on the command line). Webhooks answer 501 for now.
`accept_requests` is all or nothing: if any named create request's address already has an account it answers 409
with those addresses under `exists`, and accepts none.

## Security

The server holds every wallet's private view key, so read [docs/security.md](docs/security.md) before
putting it on the internet: the threat model, the controls, how it compares with monero-lws, and what the
operator has to do. In short:

- The view keys are stored in the clear in the database, as monero-lws stores them (the scanner needs them
  for every block). The file is made `0600`; keep it on an encrypted disk and run the server as its own user.
- The server trusts its node, as monero-lws does: run your own.
- Admin keys are stored hashed and work only on the admin listener.
- Requests are limited in size, time and rate, per client and in all; the defaults suit a shop or a small
  public server.
- No view key or address is written to the log at any level.

## Build from source

```sh
cargo test --workspace
cargo test -p monokulo-lws fresh_stagenet_wallet -- --ignored --nocapture   # a throwaway stagenet wallet to try with
RUST_LOG=debug cargo run -- serve --daemon http://stagenet.xmr-tw.org:38081 --db /tmp/lws.sqlite --create auto
cargo test -p monokulo-lws -- --ignored the_gpu   # the keyring on a real GPU
cargo run --release -- replay ../monokulo-8ar/prototypes/fixtures/mainnet-3797000-2000.bin --accounts 1,10,100,1000
```

`cargo test` needs neither a node nor a GPU: `src/testkit.rs` makes blocks with real one-time keys, view
tags, encrypted amounts and commitments, and `src/correctness.rs` puts them through the scanner (unfiltered,
and as stand-in blocks for every transaction, which must write the same rows) and calls the wallet handlers
on the result. One test plants payments in monokulo-8ar's mainnet fixture
(`../monokulo-8ar/prototypes/fixtures/`, or `LWS_FIXTURE`) and is skipped when it is absent.

`replay` rebuilds blocks from monokulo-8ar's 2,000-block mainnet fixture (each transaction key with its
outputs' view tags and keys, one transaction per key) and puts them through the scanner as a catch-up lane
would, 100 blocks a step, for the fixture's own view key and random others: it measures the prefilter and
the writing, not fetching.

The OpenWrt package builds with `scripts/build-openwrt.sh` and is checked in the x86_64 rootfs by
`scripts/test-openwrt.sh` ([docs/openwrt.md](docs/openwrt.md)).

### How it fits together

- `crates/lws-api`: the wire types (serde), usable by clients and servers.
- `crates/monokulo-lws`: the server. One binary: `serve` scans and answers, `admin` manages the database
  directly, `replay` measures the scanner.
- `openwrt/monokulo-lws`: the OpenWrt package, its init script and the LuCI page.
- [docs/api.md](docs/api.md): every endpoint, and where it goes beyond or differs from monero-lws.
- [docs/how-it-works.md](docs/how-it-works.md): fetching, the GPU keyring, catch-up lanes, reorgs, proofs,
  and what isn't built yet.
- [docs/scanning.md](docs/scanning.md): what scanning costs, on the GPU and off it.
- [docs/brand/](docs/brand/): the mark, a lantern whose glass is a rose window cut from Monokulo's lens.

Licence: GPL-3.0-only, as Fob and Monokular.
