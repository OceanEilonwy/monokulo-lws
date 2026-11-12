# Security

monokulo-lws holds the private view keys of every account registered with
it and answers a REST API that is usually on the open internet. A view key
cannot spend, but it reveals every output an account receives, the amounts,
and (through key images the server cannot verify) which outputs may have
been spent: the whole incoming history of a wallet. This document says who
can attack the server, what each attacker can and cannot do, which controls
stand in the way, what an audit of the code found, and how the server
compares with [monero-lws](https://github.com/vtnerd/monero-lws).

## What is being protected

| Asset | Where it lives | Why it matters |
|---|---|---|
| Private view keys | The database (`accounts.view_key`, `requests.view_key`), the scanner's memory, request bodies in flight | Disclosure reveals an account's incoming history forever (keys can't be rotated) |
| Addresses | The database, request bodies | Linking an address to a client IP or to activity is a privacy loss |
| Admin API keys | Handed to the operator once; only a hash is stored | The admin API lists every account and can add, hide and rescan them |
| Availability | The process, the database, the node | Wallets that depend on the server stop working |
| The node | Its RPC port, reachable from the server | The server must not become a free amplifier against it |

## Attackers

### Anyone on the internet calling the wallet API

**Can:** call every wallet endpoint; generate unlimited valid address and
view-key pairs for free (so with `--create auto`, "has an account" is no
barrier); open many connections; send slow or oversized requests; send
malformed JSON; spoof `X-Forwarded-For`.

**Cannot (controls):**

- *Read an account without its view key.* Every account-scoped call goes
  through `crypto::check_login`, which derives the public view key from the
  presented private key and compares it with the address (constant time)
  before the database is consulted. There is no other way in.
- *Learn whether an address has an account.* A key that doesn't fit the
  address is refused by `check_login` before any lookup; unknown, hidden,
  pending and wrong-key all answer `403 not authorized` with the same body.
  Only the holder of the right view key can tell whether the account exists,
  and that holder owns it anyway. (`rest::tests::unknown_accounts_and_wrong_keys_look_the_same`)
- *Fill the database or the scanner.* Account creation and import requests
  take a token from a strict per-client bucket (`--strict-rate-limit`,
  default 12 a minute) and from a global bucket (`--max-new-accounts-per-hour`,
  default 1,000); pending requests are capped (`--max-pending-requests`,
  default 10,000, monero-lws's `--create-queue-max`); subaddresses are capped
  per account (`--max-subaddresses`).
- *Exhaust connections or memory.* Per listener: at most
  `--max-connections` open connections (1,024) and `--max-connections-per-ip`
  from one client (64; a client is an IPv4 address or an IPv6 /64, as for
  the rate limits, so a host can't take a slot per address of its /64); request headers must arrive within 10 s (this also
  closes idle keep-alive connections) in at most 16 KiB; the TLS handshake
  within 10 s; a whole request, body included, within `--request-timeout`
  (30 s). Bodies are capped per endpoint: 4 KiB for login-shaped calls,
  16 KiB for `/get_random_outs`, 64 KiB for `/upsert_subaddrs`, 2 MB for
  `/submit_raw_tx` (a transaction at most 1,000,000 bytes, monerod's own
  cap). JSON nesting is limited by serde_json (128 levels).
- *Flood the server or the node.* Every request takes a token from a
  per-client bucket (`--rate-limit`, 300 a minute); `/submit_raw_tx`,
  `/get_random_outs`, `/import_wallet_request` and account creation also
  take one from the strict bucket. A client is an IPv4 address or an IPv6
  /64. `/get_random_outs` is capped at monero-lws's limits (20 members a
  ring, 150 rings) and needs no account. Each round draws only what every
  ring still lacks and asks the node for all of it in one `get_outs` (in
  chunks of 1,000), so the most a request asks for in its first round is
  3,000 outputs in three calls; later rounds replace only the members the
  node called locked (the newest outputs, a few in a hundred), and after
  monero-lws's 64 rounds the request fails. The output distribution is
  shared between requests and fetched again only when the chain has grown
  past it (at most every 5 s) or after two minutes. `/submit_raw_tx` parses
  the transaction before the node sees it, so junk costs no node call; a
  transaction the node relays is scanned once more for the live accounts
  with the live keyring (one transaction: moments), and relaying one costs
  its sender a real fee. `get_info` for the public `/get_version` and
  `/daemon_status` is cached for 5 s, so those endpoints don't make a node
  call each.
- *Pick their own client address.* `X-Forwarded-For` (or the header named
  by `--client-ip-header`) is read only when the TCP peer is in
  `--trusted-proxies`; the client is then the rightmost address in it that is
  not itself a trusted proxy. Without `--trusted-proxies` the header is
  ignored. (`limits::tests`, `rest::tests::a_forwarded_for_header_counts_only_from_a_trusted_proxy`)
- *Learn the server's internals.* Database, node and internal failures
  answer a fixed sentence (`internal error`, `the node is unavailable`); the
  detail goes to the log only. `/daemon_status` doesn't say where the node is
  and reports a failed scan step without its message. Panics in a handler
  become a bare `500`. There is no `Server` header; `/get_version` reports
  the server type and, if it was built with one, the commit, as the spec
  asks.
- *Make the server echo or log a key.* A rejected body is answered with the
  line and column where it went wrong, never with serde's message (which
  quotes values). See "Logs" below.
- *Use the server from a malicious web page.* CORS is off unless
  `--access-control-origin` is given. Requests must be
  `Content-Type: application/json`, which a browser can't send cross-origin
  without a CORS preflight. Responses carry `nosniff`, `no-store`,
  `no-referrer`, `X-Frame-Options: DENY`, a `default-src 'none'` content
  security policy and `Cross-Origin-Resource-Policy: same-origin`, and HSTS
  when the server speaks TLS itself.
- *Reach the admin API through the wallet listener.* The wallet router has
  no admin routes; the admin API exists only on `--admin-listen`, which must
  be a different address.

**Can still:** use the server within its limits like any client; create up
to the configured number of accounts an hour (each costs scanning time);
observe the server's public status (chain height, scanner height, whether
the GPU is used, catch-up lanes' cursors). Many clients behind one NAT share
one bucket; raise the limits if that is the common case.

### A malicious client with a real account

Can do everything above, plus read its own account. Cannot read another
account (that takes the other view key), cannot pass `--max-subaddresses`
(checked before the database sees the request, with at most 1,000 ranges a
request, and again against what is stored), and cannot restart its own scan
from 0 at will (an import of an account that starts at 0, or whose import
is still at block 0, is a no-op, and each import takes a strict and a global
token). An inactive account
is served what was scanned but can't import or add subaddresses; a hidden
account is refused everywhere.

`/get_random_outs` and `/submit_raw_tx` take no account at all: what they
answer (ring members, the node's verdict on a transaction) is public chain
data, the same for anyone. A refusal's reason is rebuilt from the node's
verification flags in monerod's own words, or else the node's reason cut to
printable ASCII and 256 characters; a node that can't be reached is the
fixed "the node is unavailable" sentence.

### A malicious or compromised node

The server trusts its node, as monero-lws does (monero-lws's
`--untrusted-daemon` checks proof of work; monokulo-lws has no such mode).
The node decides what the chain is.

**Can:** feed a fake chain or hide transactions, so balances and histories
shown to clients are wrong (a fake incoming payment, a missing spend); lie
about the output distribution or ring members, which weakens the privacy of
transactions built with `/get_random_outs` (decoys the node chose); refuse
or drop submitted transactions; reorganise the chain at will, forcing
rescans; observe the server's requests (which blocks, which outputs, which
transactions are submitted, from which server). With `/submit_raw_tx`, the
node sees the transaction come from the server's address, not the client's.

**Cannot:** learn any view key (none is ever sent to the node); crash the
server or make it allocate without bound. The `get_blocks.bin` reader
bounds every count before keeping anything (blocks no more than asked for,
at most 1,000 a request; at most 100,000 transactions a block; at most 8 Mi
output indexes), indexes nothing unchecked, and turns anything malformed
into an error; monero-epee reads without allocating and monero-oxide grows
its vectors as it reads, so memory follows the bytes actually received.
Responses are read in chunks and cut off at 200 MB (`get_blocks.bin`) or
64 MB (JSON), whatever `Content-Length` says, and each call has an overall
time limit (300 s and 60 s) besides the connect and read timeouts. The output
distribution is refused unless it is cumulative and doesn't overflow.
Redirects are not followed. (`daemon::tests::mutated_responses_are_errors_not_panics`
runs 4,000 random mutations of a captured mainnet response through the
reader; `forged_counts_are_errors`, `an_oversized_response_is_cut_off`,
`distributions_must_be_cumulative`.)

**What to do:** run your own node, on the same host or a private network,
over a link you control (HTTPS, or a tunnel, if it is remote). A public
node is fine for trying the server out, not for serving wallets. Don't put
credentials in `--daemon` you would mind in a process list; they are kept
out of the log.

A fake incoming payment from a lying node reaches the server's clients with
a proof of inclusion in a block the node made up; a client that checks the
proof against a node of its own sees that the block hash isn't the chain's
(see the next section). Hidden transactions and lies about decoys are not
caught that way.

**Decoys in particular.** `/get_random_outs` rests entirely on the node:
the output distribution (`get_output_distribution`) decides which ages and
blocks are drawn from, and `get_outs` decides each member's key, commitment
and whether it counts as unlocked. The server checks only that the
distribution is cumulative and the keys are hex. A node that lies can bias
every ring: a distribution that puts most outputs in blocks it chose draws
members from there (outputs it made itself, or ones it can otherwise
trace), and marking the rest locked makes the server draw again until it
gets them. Such rings still verify, so nothing fails; the transactions
are just less private, against whoever controls the node. A wrong key or
commitment, by contrast, makes the transaction invalid, and the network
refuses it. The server can't detect this (the distribution and lock state
are chain facts only a node knows), so the control is the same: a node
the operator runs. A client that wants no such trust picks its own ring
members against a node of its own, as wallet2 does; the light wallet API
leaves this to the server.

### The server, as its clients see it

A light wallet server holds every account's view key and public spend key,
which is enough to make an output whole: a one-time key the account
recognises, an encrypted amount, a mask and a commitment that all agree. The
commitment check (`mask·G + amount·H` against the served `commitment`)
cannot tell such an output from a real one, since the server chose all
three. A server (or a node behind it) could show a wallet a payment that
never happened, and a merchant might ship against it.

**A client can now verify** that each received output is on the chain.
Every mined transaction that pays an account is served with a `proof`
(`lws_api::Proof`): the block as Monero serialises it and, for a transaction
other than the miner's, the pruned transaction's prefix, RingCT base and
prunable hash. The client recomputes the transaction's hash
(keccak(keccak(prefix) ‖ keccak(base) ‖ prunable hash), or the miner
transaction's from the block, which holds it whole), checks that the block
lists it, recomputes the block's hash, and asks a node it trusts (not one
the server names) for the hash of the block at the served height. If they
match, the transaction is in the chain at that height, and everything the
prefix and base hold is the chain's: the transaction keys and one-time keys
(so the client can derive the output itself and check that it is its own),
the `unlock_time`, the encrypted amounts, the commitments (so the commitment
check is against the chain's `outPk`), and the fee. The block header gives
the timestamp. Forging a proof means finding a Keccak collision or a block
the network accepted.

**A client still cannot verify:**

- *Global indices.* An output's global index (the position in the chain's
  output set that a ring refers to) is in neither the block nor the
  transaction, so the proof says nothing about it. A server that lies about
  it makes the client build a ring around the wrong output, and the node
  refuses the transaction. A client can check an index with a node's
  `get_outs` (the key and commitment at that index must be the output's
  own).
- *The tip height and the scanned height* (`blockchain_height`,
  `scanned_height`): the server can claim to be behind or ahead; a client
  that wants the chain's height asks its own node.
- *What is left out.* A proof shows that what is reported is on the chain,
  not that everything on the chain is reported: a server can still hide a
  payment or a spend.
- *Candidate spends*, which carry no proof. Little is lost: the client
  confirms a spend by computing the key image, which the server cannot
  produce without the spend key, so an invented candidate spend is ignored.
- *Pool transactions*, which have no block yet; the proof comes when they
  are mined.
- *Transactions scanned before proofs were kept* (an older database), which
  are served without one until the account is rescanned, and those whose
  prunable hash the node has not given yet, served without one meanwhile.

Because of the last point, a client that wants proofs should treat a mined
receive without one as unverified rather than as false.

**What sending tells the server.** The server already knows which outputs
are an account's. When a client sends, the server also hands out the ring
members (`/get_random_outs`) and then sees the transaction
(`/submit_raw_tx`, from the same client address): the member of each ring
it didn't hand out, and that is one of the account's outputs, is the real
spend, and the transaction's outputs that pay the account are its change.
This is the light wallet API's design, in monero-lws as here; a server (or
whoever reads its memory) can link an account's spends, though not prove
them to anyone else. The server keeps none of it: neither request is
logged with its contents, ring members are not stored, and a submitted
transaction is held only in the pool view until it leaves the pool. A
client that wants to hide its spends from the server picks its ring
members and relays its transactions through a node of its own, using the
server only to find its outputs.

### Someone who reads the database file

The view keys are stored in the clear, as monero-lws stores them: the
scanner needs every key for every block, so there is nothing to unlock them
with that wouldn't sit next to them. Whoever reads the file (or its `-wal`
and `-shm` companions, or a backup) learns every account's history, past
and future.

**Controls:** the file is created `0600` (SQLite gives the companions the
same mode); an existing file or companion open to other users is set to
`0600` with a warning; a database directory that other users can write to
is warned about (they could replace the database). Admin keys are stored as
`SHA3-256("monokulo-lws admin key v1" ‖ key)`, so the file doesn't hold a
key that opens the admin API (a 256-bit random key needs no slow hash); keys
from before hashing are hashed in place on first start.

**What an operator should do:** run the server as its own user; keep the
database on an encrypted disk (LUKS, an encrypted ZFS dataset, the cloud
provider's disk encryption); encrypt backups; don't copy the file around;
treat a leaked database as leaking every account's view key, and tell the
users (a view key can't be changed; only a new wallet escapes it).

### An operator mistake

| Mistake | What stops it |
|---|---|
| Listening on a public address by accident | A non-loopback `--listen` or `--admin-listen` needs `--confirm-external-bind`, as in monero-lws |
| Serving plain HTTP on the internet | The startup error for a public bind says to put TLS in front or give `--tls-cert`/`--tls-key` |
| An admin API without a key on a public address | `--disable-admin-auth` is refused for a non-loopback `--admin-listen` unless `--confirm-unauthenticated-admin` is given too |
| The admin API on the wallet listener | Refused: it needs an address of its own |
| Trusting `X-Forwarded-For` from anyone | The header is ignored unless the peer is in `--trusted-proxies` |
| A world-readable database or TLS key | Tightened (database) or warned about (key) at start |
| A view key on the command line | `admin add-account` reads it from standard input (or `LWS_VIEW_KEY`) when `--view-key` is left out |
| An admin key with no way to see it again | Printed once by `admin create-key`; only the hash is kept, so a lost key is replaced, not recovered |

## Logs

No view key and no address appears in the log at any level:

- The types that hold them (`Login`, `admin::AddAccount`, `admin::Validate`,
  `admin::Request`, `db::Account`, `db::NewAccount`, `crypto::Checked`) print
  `<redacted>` for both in `Debug`.
- Accounts are named by row id in log lines (`new account #12`), never by
  address, not even shortened.
- No error variant carries a key or an address; a request that fails
  validation is logged (if at all) by kind, not content. serde errors are
  reduced to line and column. The lws-api deserializers don't quote the
  value they reject, and read escaped strings instead of failing with a
  message that quotes them.
- The panic hook logs where a panic happened, and its message only when it
  is a string literal; a formatted message could carry anything.
- Client addresses (IPs) are logged only at `debug` (rate-limit refusals).
- The node's URL is logged at start without any `user:password@`; reqwest
  errors are logged without their URL.

`rest::tests::logs_never_hold_view_keys_or_addresses` captures every log
line, at `TRACE`, while accounts are made, logged into, refused, imported
and handled by the admin API, and checks that no key and no address (or
part of one) is in it.

## TLS

The recommended setup is a reverse proxy (nginx, caddy) terminating TLS in
front of a loopback listener, with `--trusted-proxies` set to the proxy's
address. The server can also speak TLS itself: `--tls-cert` (a PEM chain)
and `--tls-key` (a PEM key, which should be `0600`) turn it on for both
listeners. It uses rustls with ring, TLS 1.2 and 1.3 only, ECDHE key
exchange and AEAD ciphers only (rustls's defaults), HTTP/1.1, and sends
HSTS. The certificate is read at start; restart to renew.

## Memory

`crypto::Checked`, which carries a copy of the presented view key through a
request, wipes it when dropped; the admin CLI wipes the keys it reads and
prints. Beyond that, keys are where they must be: in the database's pages
and SQLite's cache, in the scanner's keyring and monero-oxide scanners for
as long as an account is scanned, and in request buffers until they're
freed. Wiping every transient copy would not change what someone who can
read the process's memory learns.

## Dependencies

- No `unsafe` code: both crates are `#![forbid(unsafe_code)]`.
- `cargo audit` runs in CI (`.github/workflows/ci.yml`), along with
  `cargo fmt --check`, `cargo clippy -D warnings` and the tests.
- One advisory is ignored, with the reason, in `.cargo/audit.toml`:
  RUSTSEC-2026-0387 (crypto-bigint 0.5.5, timing variability in
  operations meant to be constant time). It comes in through monero-oxide's
  monero-ed25519, which uses it only for hash-to-point on public data
  (output keys); no secret of this server goes through it, and the fix is in
  crypto-bigint 0.7, which monero-oxide doesn't use yet.
- The dependencies added for these controls are pinned to exact versions:
  hyper 1.12.0, hyper-util 0.1.21, rustls 0.23.46, rustls-pki-types 1.15.1,
  tokio-rustls 0.26.6, tower 0.5.3, sha3 0.10.9 (all already in the tree
  through reqwest, axum or monero-oxide).

## Compared with monero-lws

| | monero-lws | monokulo-lws |
|---|---|---|
| Wrong key vs unknown account | Wrong key 500 (`bad_view_key` isn't mapped), unknown 403: still no enumeration, since the key check needs no lookup | Both 403 with the same body |
| Body limits | Per endpoint: 2 KiB login family, 10 KiB upsert, 512 KiB submit | Per endpoint: 4 KiB, 64 KiB, 2 MB (monerod's 1 MB transaction cap) |
| Timeouts | Handshake 5 s, first request 5 s, after login 5 min, response 15 s | Headers 10 s (idle included), handshake 10 s, whole request 30 s |
| Connection caps | None | Per listener and per address |
| Rate limits | None | Per client (IPv4 or IPv6 /64), strict class, global creation cap |
| Pending requests | `--create-queue-max` 10,000 | `--max-pending-requests` 10,000 |
| `/get_random_outs` | 20 a ring, 150 rings | The same |
| `/get_random_outs` over the caps | 500 (`exceeded_rest_request_limit` isn't mapped) | 400 with a sentence |
| `/get_random_outs` without enough unlocked members after 64 rounds | 500 | 503 with a sentence |
| Pre-RingCT amounts in `/get_random_outs` | Served from the node's histogram | 400: only amount `0` |
| `/submit_raw_tx` that doesn't parse | 400, empty body | 400 with a sentence |
| Client address behind a proxy | Not used | `--trusted-proxies` + header, rightmost untrusted hop |
| TLS | `https://` listeners with `--rest-ssl-key`/`--rest-ssl-certificate` | `--tls-cert`/`--tls-key`, rustls, TLS 1.2+ |
| External bind | `--confirm-external-bind` | `--confirm-external-bind` |
| Admin auth | An admin account's view key, looked up by its public key | A random 256-bit key, stored as a SHA3-256 hash, compared in constant time |
| `--disable-admin-auth` | Anywhere | Loopback only, unless confirmed with a second flag |
| Admin API on the wallet port | Can share a port under a prefix | Only on its own listener |
| Error bodies | Empty, status only | A short sentence; server failures fixed text |
| `Server` header | Beast's version string | None |
| Security headers | None | `nosniff`, `no-store`, CSP, frame and referrer policy, HSTS with TLS |
| View keys at rest | In the clear (LMDB) | In the clear (SQLite, 0600) |
| Untrusted node | `--untrusted-daemon` (checks PoW) | Not built: the node is trusted |
| Proof that a receive is on the chain | None | Block and pruned transaction on each mined transaction that pays, checked against the client's own node |
| `create_account` refused | No such mode (always queued or accepted) | `--create off`: 501, as the community spec says |

## Audit of the code before these changes

An audit of `main` at `0fca96c` against the model above found the
following. Every finding is fixed on the branch that added this document,
except where it says otherwise.

| # | Severity | Finding | Fix |
|---|---|---|---|
| 1 | High | No limits on connections or time: no header read timeout, no request timeout, no connection cap. One client could hold every connection open (slowloris) | `server.rs`: header read timeout, TLS handshake timeout, per-listener and per-address connection caps; whole-request timeout in the guard |
| 2 | High | No rate limits and no cap on account creation: with the default `--create auto` anyone could register unlimited accounts (each a scanning cost and rows in the database); with `approve` the request queue was unbounded | Per-client and strict buckets, a global hourly cap on new accounts and requests, `--max-pending-requests` |
| 3 | High | The database file was created with the process's umask (usually `0644`): any local user could read every view key | Created `0600`, existing files tightened, directory checked |
| 4 | High | `/upsert_subaddrs` accepted 4 MiB of ranges and merged them in quadratic time before the limit was checked: one request could take minutes of CPU (an account is free to make) | 64 KiB body, at most 1,000 ranges, the minors counted against the limit before the database |
| 5 | Medium | Unauthenticated amplification to the node: `/get_random_outs` (up to 128 rings, each up to eight sequential `get_outs` calls, all serialized behind one mutex held across node calls, and a copy of the whole output distribution, tens of MB on mainnet, per request); `/get_version` and `/daemon_status` made a `get_info` call each | Rings batched into one `get_outs` per round, distribution shared, no lock across node calls, monero-lws's caps, strict rate limit, `get_info` cached 5 s |
| 6 | Medium | Error responses carried internal detail: database errors (SQL), node errors (reqwest messages with the node's URL, credentials included if the URL had them). `/daemon_status` published the node's URL and the scanner's raw error | Fixed sentences for server failures; no URL in `/daemon_status`; reqwest errors without URL; URL credentials redacted in the log |
| 7 | Medium | A rejected request could echo a view key: the hex deserializer borrowed `&str`, so an escaped JSON string failed with serde's "invalid type: string \"…\"", which axum's JSON rejection returned in the body | `ApiJson` answers line and column only; lws-api reads escaped strings and never quotes values in its errors |
| 8 | Medium | Admin keys were stored in the clear in the database | Stored as SHA3-256 hashes, migrated in place, compared in constant time over every stored hash |
| 9 | Medium | `--disable-admin-auth` applied to any admin listener, public ones included | Refused off loopback without `--confirm-unauthenticated-admin`; the admin API must have its own address |
| 10 | Medium | The node client buffered a whole response before checking its size when there was no `Content-Length`, and had no overall time limit (a node dripping bytes could stall a call forever) | Chunked read cut off at the limit; overall timeouts per call |
| 11 | Medium | `/import_wallet_request` with `--import auto` restarted the account's scan from 0 on every call, unlimited | No-op for an account that starts at 0 or is still at block 0; a strict and a global token per import |
| 12 | Low | `Debug` derived on `Login`, `Account`, `NewAccount`, `Checked` and the admin request types would print view keys (no call site did yet) | Redacting `Debug` impls, tested |
| 13 | Low | Addresses (shortened to 8 + 4 characters) were logged at `info` on account creation, requests and imports | Accounts named by row id |
| 14 | Low | A malicious node could make the reader hold more blocks than asked for and unbounded transaction and index counts (bounded only by the 200 MB cap); `--catch-up-blocks` could ask the node for any count | Counts bounded; requests clamped to 1,000 blocks; fuzz test |
| 15 | Low | The output distribution from the node was trusted to be cumulative: an overflow or a decreasing entry made `pick` underflow (a panic in a debug build, nonsense in release) | Refused unless cumulative and in range |
| 16 | Low | Account status was enforced only as "hidden": an inactive account could still import and add subaddresses | Inactive accounts are read-only |
| 17 | Low | `/submit_raw_tx` took any size up to the 4 MiB body limit | 1,000,000-byte cap (monerod's) |
| 18 | Low | The listener could bind a public address without any confirmation | `--confirm-external-bind`, as monero-lws |
| 19 | Low | `admin add-account --view-key` put the key on the command line (process list, shell history) | Read from standard input or `LWS_VIEW_KEY` when not given |
| 20 | Low | A handler panic dropped the connection and the default hook printed the panic message whole | `CatchPanicLayer` answers a bare 500; the hook withholds formatted messages |
| 21 | Low | No security headers | Set on every response, no `Server` header |
| 22 | Low | No TLS option on the listener | `--tls-cert`/`--tls-key` with rustls |
| 23 | Low | One RustSec advisory in the tree (crypto-bigint 0.5.5, see above) | Not reachable; ignored with the reason; CI runs `cargo audit` |
| 24 | Info | No CI | GitHub Actions: fmt, clippy, tests, audit |
| 25 | Info | Login enumeration: none found; `check_login` runs before any lookup | Kept, with a test |

## Not done, and why

- **View keys encrypted at rest.** The scanner needs every key for every
  block, so the decryption key would have to be on the same machine, in the
  same process, all the time; monero-lws doesn't either. Disk encryption is
  the control.
- **An untrusted-node mode.** Checking proof of work for every block (as
  monero-lws's `--untrusted-daemon`) is a large piece of work and still
  doesn't stop a node from hiding transactions; the node is trusted and run
  by the operator.
- **A write timeout for clients that read slowly.** hyper has none; such a
  connection is bounded by the connection caps and TCP's own timeouts.
- **PROXY protocol.** Only a header from a trusted proxy is supported.
- **Reloading the TLS certificate without a restart.** Not needed at the
  rates the server restarts; a reverse proxy does it if wanted.
- **Wiping every transient copy of a view key.** See "Memory".
