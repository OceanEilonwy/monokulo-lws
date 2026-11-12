# monokulo-lws on an OpenWrt router

The server runs well on a router beside a node on the same network: it is
one static binary, its database is small (what each wallet received), and
scanning on the CPU keeps up with the chain's two-minute blocks with room
to spare; only catching an old wallet up takes a while. The package
`monokulo-lws` carries the server, its init script and a LuCI page,
**Services > Light Wallet Server**, that manages it. It is built for
OpenWrt 25.12 on aarch64_cortex-a53 (the GL.iNet Flint 2 and its kin) and
x86_64, by [`openwrt.yml`](../.github/workflows/openwrt.yml) on every push
to main, and signed with the same key as
[monokulo](https://github.com/OceanEilonwy/monokulo)'s own packages.

## Installing

Take the `monokulo-lws-openwrt-<release>-<arch>` artifact of the newest
[openwrt package run](https://github.com/OceanEilonwy/monokulo-lws/actions/workflows/openwrt.yml)
on main, and on the router:

```sh
# Once: trust the key the packages are signed with.
wget -O /etc/apk/keys/monokulo.pem https://raw.githubusercontent.com/OceanEilonwy/monokulo-lws/main/openwrt/keys/monokulo.pem
# The package from the artifact (scp it over, or LuCI: System > Software > Upload Package).
apk add ./monokulo-lws-*.apk
```

Installing makes the user `monokulo-lws`, a firewall rule
`Allow-monokulo-lws` (off), and starts the server with the settings in
`/etc/config/monokulo-lws`. The first start makes the data folder
`/srv/monokulo-lws` (the database, every wallet's view key in it; back it
up) and the admin key the LuCI page uses, in
`/etc/monokulo-lws/secrets/`, root's alone. Removing the package leaves
all three: they are yours to delete.

The server needs a `monerod` to ask for blocks: yours, on the same network
(the default is `http://127.0.0.1:18081`, a node on the router itself).

## The page

**Services > Light Wallet Server** has three parts.

**Status**: whether the server runs and which build; what it says of
itself and its node (`/daemon_status`): the node's height and network, the
block the scanner stands at and how far behind the node it is, that the
CPU scans (a router has no Vulkan GPU, which is as expected), how many
wallets with history are being caught up; the wallet API's address, to
give a wallet (in Fob, Settings › Sync through); the last lines of its log;
a Restart button. When the init script refuses a setting (a data folder in
memory, the admin port set to the wallet API's, a TLS file missing) the
reason is here, and a running server keeps running on its earlier
settings. What the server itself refuses is in the log.

**Wallets**: the wallets the server scans, each listed by its address with
its state, the block it is scanned to and when a wallet last asked. Add a
wallet with its address, its private view key and the block to scan from
(empty: the chain's top, right for a new wallet; a restored wallet gives
the block of its first payment, or a little before). Each wallet can be
paused (served as it stands, not scanned), hidden (neither, as if it
weren't there; its history kept), rescanned from a block, or removed,
which forgets it whole: its view key and everything scanned for it. With
the create or import policy set to "held for your approval", wallets that
asked the server for an account or an import wait here for Accept or
Reject. All of it goes through the server's own admin API, on
`127.0.0.1` alone, with the key in `/etc/monokulo-lws/secrets/`; if the
database stops knowing that key (restored from a backup, say), the page
says so and offers to make a new one, which stops and starts the server.

**Settings**, in tabs, every one of them a command line option of
`monokulo-lws serve` (its `--help` describes them), passed only when set:

- General: the node, the network guard, where the wallet API listens
  (this router, the LAN or everything) and its port, the admin API's port,
  the data folder, the log level, and the server's niceness and CPUs so
  that catching up leaves the router its CPU for routing.
- Wallets: what `/login` with `create_account` and `/import_wallet_request`
  get (made at once, held for approval, refused), subaddresses per wallet,
  the lookahead and the scan interval.
- Access: TLS (a PEM chain and key on the router; the data folder is a good
  place for them), trusted reverse proxies and their client-address header,
  browser origins (CORS).
- Limits: requests a minute per client, costly requests a minute, new
  accounts an hour, requests held, connections, the request timeout.
- Scanning: catch-up lanes and how they take blocks, and the GPU settings
  for completeness.

Save & Apply writes `/etc/config/monokulo-lws` and restarts the server on
it.

## Reaching it from wallets

Every request to the wallet API carries a wallet's private view key, so by
default the server listens on `127.0.0.1` alone, for a TLS reverse proxy
on the router in front of it. For wallets on your own network, "LAN only"
over plain HTTP is a reasonable choice; for wallets on the internet, give
the server TLS (Access) or a proxy, and turn on the firewall rule
`Allow-monokulo-lws` (Network > Firewall > Traffic Rules), or open the
proxy's port instead. Read [security.md](security.md) before that.

## How it is built

[`scripts/build-openwrt.sh`](../scripts/build-openwrt.sh) cross-compiles
the server with cargo for the OpenWrt target, with the C parts (SQLite,
ring) compiled by the gcc from the official OpenWrt SDK image, checks that
the result is a static executable, then runs the SDK in Docker to package
it with [`openwrt/monokulo-lws`](../openwrt/monokulo-lws). Signing the
package and the repository index is a separate step (`build-openwrt.sh
sign`) that runs on the host, not in any container, and runs nothing with
the key but `openssl` and `apk`: the signing key is never in the
environment while cargo, a dependency's build script or the SDK's own
build runs, and no Docker image, however pinned, ever sees it. That `apk`
is apk-tools built from its upstream source
([gitlab.alpinelinux.org/alpine/apk-tools](https://gitlab.alpinelinux.org/alpine/apk-tools))
at a pinned commit, the release the SDK's own `apk` is (3.0.5 for 25.12),
checked after the fetch; `build-openwrt.sh apk-tools` builds it into
`~/.cache/monokulo-lws/apk-tools/<commit>/` once (`sign` and `all` do too
when it is missing), which needs git, a C compiler, meson, ninja,
pkg-config and the openssl, zlib and zstd headers. `APK_TOOLS=/path/to/apk`
uses another apk-tools 3.0.5 binary instead. CI builds in one job without
the secret and signs in another, on a fresh runner, which builds apk-tools
afresh, from the pinned commit, in a step before the one with the secret
(never from a cache, so no stored binary is trusted with the key). Every
Docker image is pinned by digest and every action by commit. A local
`build-openwrt.sh all` keeps the key out of cargo's environment, but that
is no defence against a malicious dependency: its build script runs as
you and can read your key file, or the key in your shell's environment
through `/proc`. Sign with the real key only in CI, or as a separate user
the build never runs as.
`scripts/test-openwrt.sh` boots the official x86_64 rootfs image in Docker
and installs, starts (against a stand-in node), drives through the LuCI
backend, upgrades and removes the package there; CI runs it after the
x86_64 build. Both run locally too, given Docker, rustup and apk-tools'
build tools: without the signing key the package is signed with a
throwaway one, which the test trusts.

The LuCI page's backend is an rpcd ucode plugin
([`rpcd.uc`](../openwrt/monokulo-lws/files/rpcd.uc), the ubus object
`monokulo-lws`) that reads the server's status, lists and changes the
wallets through the admin API, and restarts the service, so a LuCI login
needs only the page's ACL (`luci-app-monokulo-lws`), not the power to run
any init script or read root's files. Its HTTP requests go through a small
ucode program of its own ([`http.uc`](../openwrt/monokulo-lws/files/http.uc)),
because `uclient-fetch` drops the body of an answer with an error status,
and the server's refusals are in that body.
