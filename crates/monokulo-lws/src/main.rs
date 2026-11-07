//! monokulo-lws: a Monero light wallet server.
//!
//! `monokulo-lws serve` scans the chain for every registered view key and
//! answers the light wallet REST API; `monokulo-lws admin ...` manages
//! accounts and keys straight in the database.

mod crypto;
mod daemon;
mod db;
mod decoys;
mod error;
mod rest;
mod scanner;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};
use monero_wallet::address::Network;
use tokio::sync::Mutex;

use crate::daemon::Daemon;
use crate::db::{Db, NewAccount, Status};
use crate::rest::{App, Config, Policy};
use crate::scanner::{ScanConfig, Scanner};

#[derive(Parser)]
#[command(name = "monokulo-lws", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan and serve.
    Serve(ServeArgs),
    /// Manage accounts and admin keys in the database directly.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
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
    /// Skip the admin key check (only behind something else that checks).
    #[arg(long)]
    disable_admin_auth: bool,
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
}

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
        /// The private view key, hex.
        #[arg(long)]
        view_key: String,
        /// The block to start from.
        #[arg(long, default_value_t = 0)]
        start_height: u64,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();
    match Cli::parse().command {
        Command::Serve(args) => serve(args).await,
        Command::Admin { command } => admin(command),
    }
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    let db = Arc::new(Db::open(&args.db).with_context(|| format!("opening {}", args.db.display()))?);
    let daemon = Daemon::new(&args.daemon)?;
    let info = daemon.info().await.with_context(|| format!("asking {} for get_info", args.daemon))?;
    let network = crypto::network_from_daemon(&info.nettype).with_context(|| format!("the node's network is {:?}", info.nettype))?;
    if let Some(wanted) = args.network {
        if wanted != network {
            bail!("the node is on {} but --network asks for {}", crypto::network_name(network), crypto::network_name(wanted));
        }
    }
    tracing::info!("node {} on {} at height {} ({})", args.daemon, crypto::network_name(network), info.height, info.version);

    let scanner = Scanner::new(
        db.clone(),
        daemon.clone(),
        ScanConfig { network, lookahead: args.lookahead, interval: Duration::from_secs(args.scan_interval.max(1)) },
    );
    let app = Arc::new(App {
        db,
        daemon,
        scanner: scanner.clone(),
        config: Config {
            create: args.create,
            import: args.import,
            max_subaddresses: args.max_subaddresses,
            lookahead: args.lookahead,
            admin_auth: !args.disable_admin_auth,
            access_control_origins: args.access_control_origins,
        },
        fee: Mutex::new(None),
        picker: Mutex::new(decoys::Picker::new()),
    });

    let scan_task = tokio::spawn(scanner.run());

    let wallet = tokio::net::TcpListener::bind(args.listen).await.with_context(|| format!("listening on {}", args.listen))?;
    tracing::info!("wallet API on http://{}", args.listen);
    let wallet_task = tokio::spawn(axum::serve(wallet, rest::wallet_router(app.clone())).into_future());

    let admin_task = match args.admin_listen {
        Some(addr) => {
            let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("listening on {addr}"))?;
            if app.config.admin_auth && app.db.admin_keys()?.is_empty() {
                tracing::warn!("admin API on but no admin key yet: run `monokulo-lws admin create-key`");
            }
            tracing::info!("admin API on http://{addr}");
            Some(tokio::spawn(axum::serve(listener, rest::admin_router(app.clone())).into_future()))
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
    Ok(())
}

fn admin(command: AdminCommand) -> anyhow::Result<()> {
    match command {
        AdminCommand::CreateKey { db } => {
            let db = Db::open(&db)?;
            let mut key = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
            db.add_admin_key(&key)?;
            println!("{}", hex::encode(key));
        }
        AdminCommand::AddAccount { db, network, address, view_key, start_height } => {
            let db = Db::open(&db)?;
            let key = daemon::hex32(&view_key).context("the view key must be 64 hex characters")?;
            let checked = crypto::check_login(network, &address, &key)?;
            let account = db.add_account(
                &NewAccount {
                    address: checked.address,
                    view_key: checked.view_key,
                    spend_pub: checked.spend_pub,
                    view_pub: checked.view_pub,
                    start_height,
                    generated_locally: false,
                },
                Status::Active,
            )?;
            println!("added {} from height {}", account.address, account.start_height);
        }
        AdminCommand::List { db } => {
            let db = Db::open(&db)?;
            for a in db.accounts(None)? {
                println!("{:<8} {:>9} {}", a.status.as_str(), a.scan_height, a.address);
            }
            for (kind, r) in db.requests()? {
                println!("request {kind:<7} {:>9} {}", r.start_height, r.address);
            }
        }
    }
    Ok(())
}
