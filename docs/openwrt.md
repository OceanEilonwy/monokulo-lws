# monokulo-lws on an OpenWrt router

The server runs well on a router beside a node on the same network: it is
one static binary, its database is small (what each wallet received), and
scanning on the CPU keeps up with the chain's two-minute blocks with room
to spare; only catching an old wallet up takes a while. The package
`monokulo-lws` carries the server, its init script and a LuCI page,
**Services > Light Wallet Server**, that manages it. It runs a server for
each Monero network turned on, mainnet, stagenet and testnet side by side,
each with its own switch. It is built for
OpenWrt 25.12 on aarch64_cortex-a53 (the GL.iNet Flint 2 and its kin) and
x86_64, by [`openwrt.yml`](../.github/workflows/openwrt.yml) on every push
to main, and signed with the same key as
[monokulo](https://github.com/OceanEilonwy/monokulo)'s own packages.

## Installing

The packages are in a signed apk repository on GitHub Pages, one per
OpenWrt release and architecture, with an install page that walks through
LuCI too: <https://oceaneilonwy.github.io/monokulo-lws/>. Over SSH:

```sh
# Once: trust the key the packages are signed with, and add the repository
# for this router's release and architecture.
wget -O /etc/apk/keys/monokulo.pem https://oceaneilonwy.github.io/monokulo-lws/monokulo.pem
. /etc/openwrt_release
echo "https://oceaneilonwy.github.io/monokulo-lws/openwrt/${DISTRIB_RELEASE%.*}/$DISTRIB_ARCH/packages.adb" >> /etc/apk/repositories.d/customfeeds.list
apk update
apk add monokulo-lws
```

`apk upgrade monokulo-lws` then takes each new build from main. The
`monokulo-lws-openwrt-<release>-<arch>` artifact of an
[openwrt package run](https://github.com/OceanEilonwy/monokulo-lws/actions/workflows/openwrt.yml)
holds the same package, for `apk add ./monokulo-lws-*.apk`.

Installing makes the user `monokulo-lws`, a firewall rule
`Allow-monokulo-lws` (off, for mainnet's port 8443), and starts mainnet's
server with the settings in `/etc/config/monokulo-lws`. The first start of
each network's server makes its data folder (the database, every wallet's
view key in it; back it up) and the admin key the LuCI page uses, in
`/etc/monokulo-lws/secrets/<network>/`, root's alone. Removing the package
leaves all of them: they are yours to delete.

## Networks

Each network has a section of its own in `/etc/config/monokulo-lws`, and
a server of its own when it is on, as a procd instance named after it:

| Network | On at first | Node | Wallet API | Admin API | Data folder |
| --- | --- | --- | --- | --- | --- |
| `mainnet` | yes | `http://127.0.0.1:18081` | 8443 | 8444 | `/srv/monokulo-lws` |
| `stagenet` | no | `http://127.0.0.1:38081` | 38443 | 38444 | `/srv/monokulo-lws-stagenet` |
| `testnet` | no | `http://127.0.0.1:28081` | 28443 | 28444 | `/srv/monokulo-lws-testnet` |

Each server needs a `monerod` on its network to ask for blocks: yours. It
is started with `--network`, so it refuses a node on another network, and
the init script refuses networks turned on that would share a port or a
data folder (or one inside another's). Turn one on in LuCI (Settings ›
Networks, the *On* box) or over SSH:

```sh
uci set monokulo-lws.stagenet.enabled=1
uci set monokulo-lws.stagenet.daemon=http://127.0.0.1:38081
uci commit monokulo-lws
service monokulo-lws reload
```

The main section's settings (where the wallet APIs listen, TLS, the
policies, limits and scanning) are shared by every server, and its
`enabled` turns them all off. `service monokulo-lws admin_key stagenet`
makes a new admin key for one network's server, leaving the others
running.

Settings from a version with one server (the node, ports and data folder
in the main section) move to a network's section at the first start: the
one its network guard named, or else the one its node says it is on, or
else the one its node's port suggests (38081 stagenet, 28081 testnet),
or else mainnet. That network is on, the others off, and its admin key
moves to its folder. `service monokulo-lws migrate` does it by hand.

## The page

**Services > Light Wallet Server** has four parts.

**Status**: for each network, whether its server is off, runs or
didn't start; what it says of itself and its node (`/daemon_status`): the
node's height and network, the block the scanner stands at and how far
behind the node it is, that the CPU scans (a router has no Vulkan GPU,
which is as expected), how many wallets with history are being caught up;
its wallet API's address, to give a wallet (in Fob, Settings › Sync
through). Then the build installed, the last lines of the log and a
Restart button. When the init script refuses a setting (a data folder in
memory, two networks on one port, a TLS file missing) the reason is here,
for every network or for one, and running servers keep running on their
earlier settings. What a server itself refuses (a node on another network,
say) is in the log.

**Wallets**: one network's wallets at a time, picked above the table when
more than one is on; each server has wallets of its own. They are listed
by address with
its state, the block it is scanned to and when a wallet last asked. Add a
wallet with its address, its private view key and the block to scan from
(empty: the chain's top, right for a new wallet; a restored wallet gives
the block of its first payment, or a little before). Each wallet can be
paused (served as it stands, not scanned), hidden (neither, as if it
weren't there; its history kept), rescanned from a block, or removed,
which forgets it whole: its view key and everything scanned for it. With
the create or import policy set to "held for your approval", wallets that
asked the server for an account or an import wait here for Accept or
Reject. All of it goes through that server's own admin API, on
`127.0.0.1` alone, with the key in `/etc/monokulo-lws/secrets/<network>/`; if the
database stops knowing that key (restored from a backup, say), the page
says so and offers to make a new one, which stops and starts the server.

**Networks**: mainnet, stagenet and testnet, each with its *On* box,
its node, its wallet API's and admin API's ports and its data folder. The
page refuses ports or data folders two networks would share.

**Settings**, shared by every network's server, in tabs, every one of
them a command line option of `monokulo-lws serve` (its `--help`
describes them), passed only when set:

- General: the service's switch, where the wallet APIs listen (this
  router, the LAN or everything), the log level, and the servers'
  niceness and CPUs so that catching up leaves the router its CPU for
  routing.
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

Save & Apply writes `/etc/config/monokulo-lws` and restarts the servers
on it.

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
([gitlab.alpinelinux.org/alpine/apk-tools](https://gitlab.alpinelinux.org/alpine/apk-tools),
fetched from its GitHub mirror, which CI runners can reach)
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
and installs, starts (against stand-in mainnet and stagenet nodes, both
servers side by side), drives through the LuCI backend, migrates older
settings, upgrades and removes the package there; CI runs it after the
x86_64 build. On main the pages job then publishes every signed repository
and the install page to GitHub Pages (`scripts/build-pages.sh`, from
`pages/index.html`). Both run locally too, given Docker, rustup and apk-tools'
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
