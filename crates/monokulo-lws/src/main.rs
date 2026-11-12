//! monokulo-lws: a Monero light wallet server.
//!
//! `monokulo-lws serve` scans the chain for every registered view key and
//! answers the light wallet REST API; `monokulo-lws admin ...` manages
//! accounts and keys straight in the database.

#![forbid(unsafe_code)]

mod address;
mod admin_keys;
mod at_rest;
#[cfg(test)]
mod correctness;
mod crypto;
mod daemon;
mod db;
mod decoys;
mod error;
mod lanes;
mod limits;
mod proof;
mod redact;
mod rest;
mod scanner;
#[cfg(test)]
mod sending;
mod server;
#[cfg(test)]
mod testkit;
mod types;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use monero_wallet::address::Network;
use tokio::sync::Mutex;

use crate::daemon::Daemon;
use crate::db::{Db, Status};
use crate::limits::{Cidr, ClientIpConfig, Limits, PER_48_FACTOR};
use crate::rest::{App, Config, Policy};
use crate::scanner::{LaneConfig, ScanConfig, Scanner};
use crate::server::ListenerConfig;

#[derive(Parser)]
#[command(name = "monokulo-lws", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan and serve.
    Serve(Box<ServeArgs>),
    /// Manage accounts and admin keys in the database directly.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// For development: replay a scan-bench fixture (monokulo-8ar's
    /// prototypes/fixtures) through the scanner for synthetic accounts, and
    /// print blocks a second.
    Replay {
        fixture: PathBuf,
        /// Account counts to try, comma-separated.
        #[arg(long, value_delimiter = ',', default_value = "1,10,100,1000")]
        accounts: Vec<usize>,
        /// Minors 0..N of major 0 watched for every account.
        #[arg(long, default_value_t = 200)]
        lookahead: u32,
        /// Blocks a step, as a catch-up lane takes them.
        #[arg(long, default_value_t = 100)]
        blocks: usize,
        #[arg(long, env = "LWS_CACHE_DIR")]
        cache_dir: Option<PathBuf>,
    },
}

#[derive(Parser)]
struct ServeArgs {
    /// monerod's RPC address.
    #[arg(long, env = "LWS_DAEMON", default_value = "http://127.0.0.1:18081")]
    daemon: String,
    /// The database file.
    #[arg(long, env = "LWS_DB", default_value = "monokulo-lws.sqlite")]
    db: PathBuf,
    /// Where the wallet API listens.
    #[arg(long, env = "LWS_LISTEN", default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    /// Where the admin API listens; off unless given.
    #[arg(long, env = "LWS_ADMIN_LISTEN")]
    admin_listen: Option<SocketAddr>,
    /// Allow a listener on an address other than loopback (as monero-lws's
    /// --confirm-external-bind).
    #[arg(long, env = "LWS_CONFIRM_EXTERNAL_BIND")]
    confirm_external_bind: bool,
    /// Skip the admin key check. Taken only for a loopback --admin-listen,
    /// unless --confirm-unauthenticated-admin is given too.
    #[arg(long)]
    disable_admin_auth: bool,
    /// Let --disable-admin-auth apply to an admin listener that isn't on
    /// loopback (only behind something else that checks).
    #[arg(long, requires = "disable_admin_auth")]
    confirm_unauthenticated_admin: bool,
    /// PEM certificate chain: the listeners speak TLS themselves (TLS 1.2 and
    /// 1.3). A reverse proxy in front is still the recommended setup.
    #[arg(long, env = "LWS_TLS_CERT", requires = "tls_key")]
    tls_cert: Option<PathBuf>,
    /// PEM private key for --tls-cert.
    #[arg(long, env = "LWS_TLS_KEY", requires = "tls_cert")]
    tls_key: Option<PathBuf>,
    /// Reverse proxies (addresses or CIDR ranges, comma-separated) whose
    /// client-address header is believed. Without it the header is ignored.
    #[arg(long, env = "LWS_TRUSTED_PROXIES", value_delimiter = ',')]
    trusted_proxies: Vec<Cidr>,
    /// The header a trusted proxy puts the client's address in.
    #[arg(long, env = "LWS_CLIENT_IP_HEADER", default_value = "X-Forwarded-For")]
    client_ip_header: String,
    /// Requests a minute from one client (an IPv4 address or IPv6 /64); 0 is
    /// no limit.
    #[arg(long, default_value_t = 300)]
    rate_limit: u32,
    /// Requests a minute from one client for account creation, imports,
    /// /submit_raw_tx and /get_random_outs; 0 is no limit.
    #[arg(long, default_value_t = 12)]
    strict_rate_limit: u32,
    /// Requests a minute from one IPv6 /48, on top of --rate-limit per /64;
    /// 0 is no limit. Default: 4 × --rate-limit.
    #[arg(long)]
    rate_limit_per_48: Option<u32>,
    /// As --strict-rate-limit, per IPv6 /48; 0 is no limit. Default:
    /// 4 × --strict-rate-limit.
    #[arg(long)]
    strict_rate_limit_per_48: Option<u32>,
    /// New accounts and import requests an hour across all clients; 0 is no
    /// limit.
    #[arg(long, default_value_t = 1000)]
    max_new_accounts_per_hour: u32,
    /// Pending create and import requests at most (monero-lws's
    /// --create-queue-max).
    #[arg(long, default_value_t = 10_000)]
    max_pending_requests: u64,
    /// Open connections at most, per listener.
    #[arg(long, default_value_t = 1024)]
    max_connections: usize,
    /// Open connections from one client (an IPv4 address or IPv6 /64) at
    /// most (a trusted proxy is exempt); 0 is no limit.
    #[arg(long, default_value_t = 64)]
    max_connections_per_ip: usize,
    /// Seconds a request may take, reading its body and answering included.
    #[arg(long, default_value_t = 30)]
    request_timeout: u64,
    /// What `/login` with `create_account` does.
    #[arg(long, value_enum, default_value = "auto")]
    create: Policy,
    /// What `/import_wallet_request` does.
    #[arg(long, value_enum, default_value = "approve")]
    import: Policy,
    /// Subaddresses an account may register; 0 turns the endpoints off.
    #[arg(long, default_value_t = 10_000)]
    max_subaddresses: u32,
    /// Minors 0..N of major 0 watched for every account, registered or not.
    #[arg(long, default_value_t = 200)]
    lookahead: u32,
    /// Seconds between looks at the node once caught up.
    #[arg(long, default_value_t = 10)]
    scan_interval: u64,
    /// A browser origin allowed to call the API (repeat, or `*`).
    #[arg(long = "access-control-origin")]
    access_control_origins: Vec<String>,
    /// Refuse to start if the node is on another network.
    #[arg(long, value_parser = parse_network)]
    network: Option<Network>,
    /// Catch-up lanes that may run at once, for accounts with history; 0 is
    /// one loop from the lowest height any account stands at.
    #[arg(long, default_value_t = 1)]
    catch_up_lanes: usize,
    /// Whether a queued account joins a running lane whose cursor passes its
    /// start height, or waits for a lane of its own.
    #[arg(long, value_enum, default_value = "follow")]
    catch_up_join: lanes::Join,
    /// Blocks a catch-up lane asks the node for at a time.
    #[arg(long, default_value_t = 100)]
    catch_up_blocks: u64,
    /// Catch-up requests in flight at once; the live lane's never waits for them.
    #[arg(long, default_value_t = 2)]
    catch_up_in_flight: usize,
    /// GPU arenas, about 43 MB each: the live lane's and one per catch-up lane
    /// unless given.
    #[arg(long)]
    gpu_arenas: Option<usize>,
    /// A cap on GPU memory instead: arenas = MB / 43, at least 1.
    #[arg(long)]
    gpu_memory_mb: Option<u64>,
    /// Where the GPU's compiled shader is kept (the first compile takes 20-30 s).
    #[arg(long, env = "LWS_CACHE_DIR")]
    cache_dir: Option<PathBuf>,
}

/// About what one GPU arena takes.
const ARENA_MB: u64 = 43;

#[derive(Subcommand)]
enum AdminCommand {
    /// Make an admin key for the admin REST API and print it.
    CreateKey {
        #[arg(long, env = "LWS_DB", default_value = "monokulo-lws.sqlite")]
        db: PathBuf,
    },
    /// Add an account to scan.
    AddAccount {
        #[arg(long, env = "LWS_DB", default_value = "monokulo-lws.sqlite")]
        db: PathBuf,
        #[arg(long, value_parser = parse_network)]
        network: Network,
        #[arg(long)]
        address: String,
        /// The private view key, hex. Read from standard input when not
        /// given (better: a key on the command line is in `ps` and the
        /// shell's history).
        #[arg(long, env = "LWS_VIEW_KEY", hide_env_values = true)]
        view_key: Option<String>,
        /// The block to start from.
        #[arg(long, default_value_t = 0)]
        start_height: u64,
    },
    /// Forget an account and everything scanned for it.
    RemoveAccount {
        #[arg(long, env = "LWS_DB", default_value = "monokulo-lws.sqlite")]
        db: PathBuf,
        #[arg(long)]
        address: String,
    },
    /// List accounts and pending requests.
    List {
        #[arg(long, env = "LWS_DB", default_value = "monokulo-lws.sqlite")]
        db: PathBuf,
    },
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s {
        "main" | "mainnet" => Ok(Network::Mainnet),
        "stage" | "stagenet" => Ok(Network::Stagenet),
        "test" | "testnet" => Ok(Network::Testnet),
        _ => Err("main, stage or test".into()),
    }
}

/// A panic is logged with where it happened, and its message only when the
/// message is a literal: a formatted one could carry anything the code had
/// in hand. Request handlers' panics become a bare 500 (`rest::finish`).
fn panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "an unknown place".into());
        let message = info
            .payload()
            .downcast_ref::<&'static str>()
            .copied()
            .unwrap_or("(message withheld)");
        tracing::error!("panic at {location}: {message}");
    }));
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    panic_hook();
    match Cli::parse().command {
        Command::Serve(args) => serve(*args).await,
        Command::Admin { command } => admin(command),
        Command::Replay {
            fixture,
            accounts,
            lookahead,
            blocks,
            cache_dir,
        } => {
            if let Some(dir) = cache_dir {
                std::fs::create_dir_all(&dir)?;
                monokulo_8ar::set_cache_dir(dir);
            }
            tokio::task::block_in_place(|| scanner::replay(&fixture, &accounts, lookahead, blocks.max(1)))
        }
    }
}

/// Opens the database: made 0600 if new, tightened and warned about if
/// open to others, plain admin keys from an older version hashed.
fn open_db(path: &std::path::Path) -> anyhow::Result<Db> {
    at_rest::prepare_db_file(path).with_context(|| format!("preparing {}", path.display()))?;
    let db = Db::open(path).with_context(|| format!("opening {}", path.display()))?;
    admin_keys::migrate(&db)?;
    Ok(db)
}

/// The listeners' safety checks, before anything starts.
fn check_listeners(args: &ServeArgs) -> anyhow::Result<()> {
    for addr in std::iter::once(args.listen).chain(args.admin_listen) {
        if !addr.ip().is_loopback() && !args.confirm_external_bind {
            bail!(
                "{addr} isn't a loopback address: give --confirm-external-bind to listen there (and put TLS in \
                 front, or give --tls-cert and --tls-key)"
            );
        }
    }
    if let Some(admin) = args.admin_listen {
        if admin == args.listen {
            bail!("the admin API needs a listener of its own, not the wallet API's {admin}");
        }
        if args.disable_admin_auth && !admin.ip().is_loopback() && !args.confirm_unauthenticated_admin {
            bail!(
                "--disable-admin-auth with the admin API on {admin}, which isn't loopback: anyone who reaches it \
                 could read every account. Give --confirm-unauthenticated-admin as well if something in front \
                 checks."
            );
        }
    }
    if args.client_ip_header.parse::<axum::http::HeaderName>().is_err() {
        bail!("--client-ip-header {:?} isn't a header name", args.client_ip_header);
    }
    Ok(())
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    check_listeners(&args)?;
    let tls = match (&args.tls_cert, &args.tls_key) {
        (Some(cert), Some(key)) => Some(server::tls_acceptor(cert, key)?),
        _ => None,
    };
    let db = Arc::new(open_db(&args.db)?);
    let daemon = Daemon::new(&args.daemon)?;
    let info = daemon
        .info()
        .await
        .with_context(|| format!("asking {} for get_info", daemon.display_url()))?;
    let network = crypto::network_from_daemon(&info.nettype)
        .with_context(|| format!("the node's network is {:?}", info.nettype))?;
    if let Some(wanted) = args.network
        && wanted != network
    {
        bail!(
            "the node is on {} but --network asks for {}",
            crypto::network_name(network),
            crypto::network_name(wanted)
        );
    }
    tracing::info!(
        "node {} on {} at height {} ({})",
        daemon.display_url(),
        crypto::network_name(network),
        info.height,
        info.version
    );

    // The GPU starts in the background; until it's ready (or if it can't be
    // used) every block is scanned with monero-oxide.
    if let Some(dir) = &args.cache_dir {
        std::fs::create_dir_all(dir).with_context(|| format!("making {}", dir.display()))?;
        monokulo_8ar::set_cache_dir(dir.clone());
    }
    monokulo_8ar::warm_up();
    let mut arenas = args.gpu_arenas.unwrap_or(args.catch_up_lanes + 1);
    if let Some(mb) = args.gpu_memory_mb {
        arenas = arenas.min((mb / ARENA_MB) as usize);
    }
    let lanes = LaneConfig {
        lanes: args.catch_up_lanes,
        join: args.catch_up_join,
        blocks: args.catch_up_blocks.clamp(1, daemon::MAX_BLOCKS_PER_REQUEST),
        in_flight: args.catch_up_in_flight.max(1),
        arenas: arenas.max(1),
    };
    let scanner = Scanner::new(
        db.clone(),
        daemon.clone(),
        ScanConfig {
            network,
            lookahead: args.lookahead,
            interval: Duration::from_secs(args.scan_interval.max(1)),
            lanes,
        },
    );
    tracing::info!("database {} with {} read connections", args.db.display(), db.readers());
    let app = Arc::new(App {
        db: crate::db::AsyncDb::new(db),
        daemon,
        scanner: scanner.clone(),
        config: Config {
            create: args.create,
            import: args.import,
            max_subaddresses: args.max_subaddresses,
            lookahead: args.lookahead,
            admin_auth: !args.disable_admin_auth,
            access_control_origins: args.access_control_origins,
            request_timeout: Duration::from_secs(args.request_timeout.max(1)),
            tls: tls.is_some(),
        },
        limits: Limits::with_per_48(
            ClientIpConfig {
                trusted_proxies: args.trusted_proxies.clone(),
                header: args.client_ip_header.to_ascii_lowercase(),
            },
            [
                args.rate_limit,
                args.rate_limit_per_48
                    .unwrap_or(args.rate_limit.saturating_mul(PER_48_FACTOR)),
            ],
            [
                args.strict_rate_limit,
                args.strict_rate_limit_per_48
                    .unwrap_or(args.strict_rate_limit.saturating_mul(PER_48_FACTOR)),
            ],
            args.max_new_accounts_per_hour,
            args.max_pending_requests,
        ),
        fee: Mutex::new(None),
        info: Mutex::new(None),
        picker: decoys::Picker::new(),
    });
    let listener_config = ListenerConfig {
        tls,
        max_connections: args.max_connections,
        max_connections_per_ip: args.max_connections_per_ip,
        trusted_proxies: args.trusted_proxies,
    };
    let scheme = if listener_config.tls.is_some() { "https" } else { "http" };

    let scan_task = tokio::spawn(scanner.run());

    let wallet = tokio::net::TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("listening on {}", args.listen))?;
    tracing::info!("wallet API on {scheme}://{}", args.listen);
    let wallet_task = tokio::spawn(server::serve(
        wallet,
        rest::wallet_router(app.clone()),
        listener_config.clone(),
    ));

    let admin_task = match args.admin_listen {
        Some(addr) => {
            let listener = tokio::net::TcpListener::bind(addr)
                .await
                .with_context(|| format!("listening on {addr}"))?;
            if app.config.admin_auth && app.db.call(admin_keys::count).await? == 0 {
                tracing::warn!("admin API on but no admin key yet: run `monokulo-lws admin create-key`");
            }
            if !app.config.admin_auth {
                tracing::warn!("admin API on {addr} without a key check (--disable-admin-auth)");
            }
            tracing::info!("admin API on {scheme}://{addr}");
            Some(tokio::spawn(server::serve(
                listener,
                rest::admin_router(app.clone()),
                listener_config,
            )))
        }
        None => None,
    };

    tokio::signal::ctrl_c().await?;
    tracing::info!("stopping");
    scan_task.abort();
    wallet_task.abort();
    if let Some(t) = admin_task {
        t.abort();
    }
    // Not out of the process with the GPU's warm-up still in the driver.
    monokulo_8ar::settle(Duration::from_secs(60));
    Ok(())
}

fn admin(command: AdminCommand) -> anyhow::Result<()> {
    match command {
        AdminCommand::CreateKey { db } => {
            let db = open_db(&db)?;
            let key = admin_keys::create(&db)?;
            // Shown once: only its hash is kept.
            println!("{}", zeroize::Zeroizing::new(hex::encode(*key)).as_str());
        }
        AdminCommand::AddAccount {
            db,
            network,
            address,
            view_key,
            start_height,
        } => {
            let db = open_db(&db)?;
            let view_key = match view_key {
                Some(k) => zeroize::Zeroizing::new(k),
                None => {
                    eprintln!("the private view key (64 hex characters):");
                    let mut line = zeroize::Zeroizing::new(String::new());
                    std::io::stdin().read_line(&mut line)?;
                    zeroize::Zeroizing::new(line.trim().to_string())
                }
            };
            let key = lws_api::PrivateViewKey::from_hex(&view_key).context("the view key must be 64 hex characters")?;
            let checked = crypto::check_login(network, &address, key)?;
            let account = db.add_account(
                &checked.into_new_account(types::Height::new(start_height), false),
                Status::Active,
            )?;
            println!(
                "added {} from height {}",
                account.address.as_str(),
                account.start_height
            );
        }
        AdminCommand::RemoveAccount { db, address } => {
            let db = open_db(&db)?;
            let address = address::Address::parse_any_network(&address)?;
            if db.remove_accounts(std::slice::from_ref(&address))?.is_empty() {
                bail!("no account with that address");
            }
            println!("removed {}", address.as_str());
        }
        AdminCommand::List { db } => {
            let db = open_db(&db)?;
            for a in db.accounts(None)? {
                println!("{:<8} {:>9} {}", a.status.as_str(), a.scan_height, a.address.as_str());
            }
            for (kind, r) in db.requests()? {
                println!(
                    "request {:<7} {:>9} {}",
                    kind.as_str(),
                    r.start_height,
                    r.address.as_str()
                );
            }
        }
    }
    Ok(())
}
