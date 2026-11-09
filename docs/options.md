# Options

Every option of `monokulo-lws serve`, with its default. What you need
to start is in the [README](../README.md#on-a-computer).


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
