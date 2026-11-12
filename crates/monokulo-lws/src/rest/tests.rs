//! The REST layer's controls, end to end through the routers (and, for the
//! listener's own limits and TLS, through a real socket).

use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Request, StatusCode};
use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};
use monero_wallet::address::{AddressType, MoneroAddress, Network};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower::ServiceExt;

use super::*;
use crate::address::Address;
use crate::db::{Db, Status};
use crate::limits::{ClientIpConfig, Limits};
use crate::scanner::{LaneConfig, ScanConfig, Scanner};
use lws_api::PrivateViewKey;

/// A stagenet wallet: its address and private view key.
fn wallet(seed: u64) -> (String, [u8; 32]) {
    let spend = Scalar::from(1_000 + 2 * seed);
    let view = Scalar::from(1_001 + 2 * seed);
    let point = |s: &Scalar| monero_wallet::ed25519::Point::from(s * ED25519_BASEPOINT_TABLE);
    let address = MoneroAddress::new(Network::Stagenet, AddressType::Legacy, point(&spend), point(&view)).to_string();
    (address, view.to_bytes())
}

struct Setup {
    create: Policy,
    import: Policy,
    limits: Limits,
    admin_auth: bool,
    daemon: String,
    request_timeout: Duration,
}

impl Default for Setup {
    fn default() -> Self {
        Setup {
            create: Policy::Auto,
            import: Policy::Approve,
            limits: Limits::none(),
            admin_auth: true,
            // Nothing listens there: a call to the node fails at once.
            daemon: "http://127.0.0.1:9".into(),
            request_timeout: Duration::from_secs(30),
        }
    }
}

fn app(setup: Setup) -> Arc<App> {
    // A file, so the handlers read through the read pool as when served.
    let db = Arc::new(Db::scratch());
    let daemon = Daemon::new(&setup.daemon).unwrap();
    let scanner = Scanner::new(
        db.clone(),
        daemon.clone(),
        ScanConfig {
            network: Network::Stagenet,
            lookahead: 0,
            interval: Duration::from_secs(10),
            lanes: LaneConfig {
                lanes: 1,
                join: crate::lanes::Join::Follow,
                blocks: 100,
                in_flight: 1,
                arenas: 1,
            },
        },
    );
    // As if the scanner had heard from the node: a new account starts below this.
    scanner.status.write().unwrap().chain_height = 1_000;
    Arc::new(App {
        db: crate::db::AsyncDb::new(db),
        daemon,
        scanner,
        config: Config {
            create: setup.create,
            import: setup.import,
            max_subaddresses: 100,
            lookahead: 0,
            admin_auth: setup.admin_auth,
            access_control_origins: vec![],
            request_timeout: setup.request_timeout,
            tls: false,
        },
        limits: setup.limits,
        fee: Mutex::new(None),
        info: Mutex::new(None),
        picker: Picker::new(),
    })
}

fn add(app: &App, seed: u64, status: Status) -> (String, [u8; 32]) {
    let (address, key) = wallet(seed);
    let checked = crate::crypto::check_login(Network::Stagenet, &address, PrivateViewKey::from_bytes(&key)).unwrap();
    app.db
        .add_account(&checked.into_new_account(10, false), status)
        .unwrap();
    (address, key)
}

/// A wallet's address as the server holds it.
fn parsed(address: &str) -> Address {
    Address::parse(Network::Stagenet, address).unwrap()
}

fn login_body(address: &str, key: &[u8; 32]) -> Value {
    json!({ "address": address, "view_key": hex::encode(key) })
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

async fn call_from(router: &Router, path: &str, body: &str, peer: &str, headers: &[(&str, &str)]) -> Reply {
    let mut request = Request::post(path).header("content-type", "application/json");
    for (k, v) in headers {
        request = request.header(*k, *v);
    }
    let mut request = request.body(Body::from(body.to_string())).unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<SocketAddr>().unwrap()));
    let response = router.clone().oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    Reply {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

async fn call(router: &Router, path: &str, body: &Value) -> Reply {
    call_from(router, path, &body.to_string(), "198.51.100.1:5000", &[]).await
}

#[tokio::test]
async fn bodies_over_the_limit_and_non_json_are_refused() {
    let app = app(Setup::default());
    let router = wallet_router(app);
    let (address, key) = wallet(1);
    let mut body = login_body(&address, &key);
    body["padding"] = json!("x".repeat(8 * 1024));
    let r = call(&router, "/login", &body).await;
    assert_eq!(r.status, StatusCode::PAYLOAD_TOO_LARGE);

    let mut request = Request::post("/login")
        .header("content-type", "text/plain")
        .body(Body::from(login_body(&address, &key).to_string()))
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo("198.51.100.1:5000".parse::<SocketAddr>().unwrap()));
    let r = router.clone().oneshot(request).await.unwrap();
    assert_eq!(r.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);

    // A transaction past monerod's size cap.
    let r = call(
        &router,
        "/submit_raw_tx",
        &json!({ "tx": "00".repeat(MAX_TX_BYTES + 1) }),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(r.body.contains("at most"), "{}", r.body);
}

#[tokio::test]
async fn deep_json_is_refused() {
    let router = wallet_router(app(Setup::default()));
    let deep = format!("{}{}", "[".repeat(1_000), "]".repeat(1_000));
    let r = call_from(&router, "/login", &deep, "198.51.100.1:5000", &[]).await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rejections_never_echo_the_request() {
    let router = wallet_router(app(Setup::default()));
    let (address, key) = wallet(2);
    let hex_key = hex::encode(key);
    for body in [
        // Wrong types and shapes.
        json!({ "address": address, "view_key": 5 }).to_string(),
        json!({ "address": 7, "view_key": hex_key }).to_string(),
        json!({ "address": address, "view_key": format!("{hex_key}00") }).to_string(),
        json!({ "address": address, "view_key": [hex_key] }).to_string(),
        // Broken JSON with the key in it.
        format!("{{\"address\": \"{address}\", \"view_key\": \"{hex_key}\""),
        // An escaped key, which a borrowing reader would quote back.
        format!(
            "{{\"address\": \"{address}\", \"view_key\": \"\\u0030{}\", \"x\": [}}",
            &hex_key[1..]
        ),
    ] {
        let r = call_from(&router, "/get_address_info", &body, "198.51.100.1:5000", &[]).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{body}");
        assert!(!r.body.contains(&hex_key[..16]), "{}", r.body);
        assert!(!r.body.contains(&address[..16]), "{}", r.body);
    }
}

#[tokio::test]
async fn unknown_accounts_and_wrong_keys_look_the_same() {
    let app = app(Setup::default());
    let router = wallet_router(app.clone());
    let (known, known_key) = add(&app, 3, Status::Active);
    let (unknown, unknown_key) = wallet(4);
    let (_, other_key) = wallet(5);

    let ok = call(&router, "/get_address_info", &login_body(&known, &known_key)).await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.body);

    let unknown_right_key = call(&router, "/get_address_info", &login_body(&unknown, &unknown_key)).await;
    let known_wrong_key = call(&router, "/get_address_info", &login_body(&known, &other_key)).await;
    let unknown_wrong_key = call(&router, "/get_address_info", &login_body(&unknown, &other_key)).await;
    for r in [&unknown_right_key, &known_wrong_key, &unknown_wrong_key] {
        assert_eq!(r.status, StatusCode::FORBIDDEN);
        assert_eq!(r.body, known_wrong_key.body);
    }
    // /login without create_account: the same.
    let a = call(&router, "/login", &login_body(&known, &other_key)).await;
    let b = call(&router, "/login", &login_body(&unknown, &other_key)).await;
    assert_eq!((a.status, &a.body), (b.status, &b.body));
    assert_eq!(a.status, StatusCode::FORBIDDEN);
    // A wrong key never creates anything.
    let mut create = login_body(&unknown, &other_key);
    create["create_account"] = json!(true);
    assert_eq!(call(&router, "/login", &create).await.status, StatusCode::FORBIDDEN);
    assert!(app.db.account(&parsed(&unknown)).unwrap().is_none());
}

#[tokio::test]
async fn hidden_accounts_are_refused_everywhere_and_inactive_ones_are_read_only() {
    let app = app(Setup {
        import: Policy::Auto,
        ..Setup::default()
    });
    let router = wallet_router(app.clone());
    let (hidden, hidden_key) = add(&app, 6, Status::Hidden);
    let (inactive, inactive_key) = add(&app, 7, Status::Inactive);

    let calls = |address: &str, key: &[u8; 32]| {
        let login = login_body(address, key);
        let mut upsert = login.clone();
        upsert["subaddrs"] = json!([{ "key": 0, "value": [[1, 2]] }]);
        let mut provision = login.clone();
        provision["n_min"] = json!(2);
        vec![
            ("/login", login.clone()),
            ("/get_address_info", login.clone()),
            ("/get_address_txs", login.clone()),
            ("/get_subaddrs", login.clone()),
            ("/import_wallet_request", login.clone()),
            ("/upsert_subaddrs", upsert),
            ("/provision_subaddrs", provision),
        ]
    };
    for (path, body) in calls(&hidden, &hidden_key) {
        let r = call(&router, path, &body).await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "hidden {path}");
    }
    for (path, body) in calls(&inactive, &inactive_key) {
        let r = call(&router, path, &body).await;
        let changes = matches!(
            path,
            "/import_wallet_request" | "/upsert_subaddrs" | "/provision_subaddrs"
        );
        let wanted = if changes { StatusCode::FORBIDDEN } else { StatusCode::OK };
        assert_eq!(r.status, wanted, "inactive {path}: {}", r.body);
    }
    // /get_unspent_outs asks the node for the fee only after the account
    // is checked: a hidden one never gets that far.
    let r = call(&router, "/get_unspent_outs", &login_body(&hidden, &hidden_key)).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_off_answers_501_and_creation_is_capped() {
    let off = wallet_router(app(Setup {
        create: Policy::Off,
        ..Setup::default()
    }));
    let (address, key) = wallet(8);
    let mut body = login_body(&address, &key);
    body["create_account"] = json!(true);
    assert_eq!(call(&off, "/login", &body).await.status, StatusCode::NOT_IMPLEMENTED);

    // Two new accounts an hour across everyone.
    let capped = app(Setup {
        limits: Limits::new(ClientIpConfig::default(), 0, 0, 2, u64::MAX),
        ..Setup::default()
    });
    let router = wallet_router(capped.clone());
    for seed in 9..11 {
        let (address, key) = wallet(seed);
        let mut body = login_body(&address, &key);
        body["create_account"] = json!(true);
        let r = call_from(
            &router,
            "/login",
            &body.to_string(),
            &format!("198.51.100.{seed}:1"),
            &[],
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }
    let (address, key) = wallet(11);
    let mut body = login_body(&address, &key);
    body["create_account"] = json!(true);
    let r = call_from(&router, "/login", &body.to_string(), "198.51.100.99:1", &[]).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    assert!(r.headers.contains_key("retry-after"));
    assert!(capped.db.account(&parsed(&address)).unwrap().is_none());

    // The approval queue holds one.
    let queued = app(Setup {
        create: Policy::Approve,
        limits: Limits::new(ClientIpConfig::default(), 0, 0, 0, 1),
        ..Setup::default()
    });
    let router = wallet_router(queued.clone());
    let (a, ka) = wallet(12);
    let (b, kb) = wallet(13);
    let mut first = login_body(&a, &ka);
    first["create_account"] = json!(true);
    assert_eq!(call(&router, "/login", &first).await.status, StatusCode::OK);
    let mut second = login_body(&b, &kb);
    second["create_account"] = json!(true);
    assert_eq!(
        call(&router, "/login", &second).await.status,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(queued.db.requests().unwrap().len(), 1);
}

#[tokio::test]
async fn the_per_client_limits_trigger() {
    let router = wallet_router(app(Setup {
        limits: Limits::new(ClientIpConfig::default(), 10, 2, 0, u64::MAX),
        ..Setup::default()
    }));
    // The strict limit: two /get_random_outs (refused for their count, but
    // counted), then 429.
    let bad_count = json!({ "count": 21, "amounts": ["0"] });
    for _ in 0..2 {
        let r = call(&router, "/get_random_outs", &bad_count).await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
    }
    let r = call(&router, "/get_random_outs", &bad_count).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    // The general limit: ten in all from this client (three used), then 429.
    for _ in 0..7 {
        let r = call(&router, "/get_version", &json!({})).await;
        assert_ne!(r.status, StatusCode::TOO_MANY_REQUESTS);
    }
    let r = call(&router, "/get_version", &json!({})).await;
    assert_eq!(r.status, StatusCode::TOO_MANY_REQUESTS);
    // Another client isn't affected.
    let r = call_from(&router, "/get_version", "{}", "198.51.100.2:1", &[]).await;
    assert_ne!(r.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn login_with_create_takes_the_strict_limit() {
    let router = wallet_router(app(Setup {
        limits: Limits::new(ClientIpConfig::default(), 0, 1, 0, u64::MAX),
        ..Setup::default()
    }));
    for (seed, wanted) in [(20, StatusCode::OK), (21, StatusCode::TOO_MANY_REQUESTS)] {
        let (address, key) = wallet(seed);
        let mut body = login_body(&address, &key);
        body["create_account"] = json!(true);
        assert_eq!(call(&router, "/login", &body).await.status, wanted);
    }
    // A plain login of the account just made isn't held back by it.
    let (address, key) = wallet(20);
    assert_eq!(
        call(&router, "/login", &login_body(&address, &key)).await.status,
        StatusCode::OK
    );
}

/// One /48 can't spend a strict bucket per /64: its own /48 bucket (four
/// /64s' worth by default) runs out first.
#[tokio::test]
async fn a_slash_48_shares_a_strict_bucket() {
    let app = app(Setup {
        limits: Limits::new(ClientIpConfig::default(), 0, 1, 0, u64::MAX),
        ..Setup::default()
    });
    let router = wallet_router(app.clone());
    for n in 1..=5u64 {
        let (address, key) = wallet(60 + n);
        let mut body = login_body(&address, &key);
        body["create_account"] = json!(true);
        let r = call_from(
            &router,
            "/login",
            &body.to_string(),
            &format!("[2001:db8:7:{n}::1]:1"),
            &[],
        )
        .await;
        let wanted = if n <= 4 {
            StatusCode::OK
        } else {
            StatusCode::TOO_MANY_REQUESTS
        };
        assert_eq!(r.status, wanted, "/64 number {n}: {}", r.body);
    }
    // Another /48 isn't held back.
    let (address, key) = wallet(70);
    let mut body = login_body(&address, &key);
    body["create_account"] = json!(true);
    let r = call_from(&router, "/login", &body.to_string(), "[2001:db8:8:1::1]:1", &[]).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

#[tokio::test]
async fn a_forwarded_for_header_counts_only_from_a_trusted_proxy() {
    let limits = || Limits::new(ClientIpConfig::default(), 1, 0, 0, u64::MAX);
    // Untrusted: the header is ignored, so changing it doesn't escape the limit.
    let router = wallet_router(app(Setup {
        limits: limits(),
        ..Setup::default()
    }));
    let mut statuses = vec![];
    for i in 0..12 {
        let xff = format!("203.0.113.{i}");
        let r = call_from(
            &router,
            "/get_version",
            "{}",
            "198.51.100.1:1",
            &[("x-forwarded-for", &xff)],
        )
        .await;
        statuses.push(r.status);
    }
    assert!(statuses.contains(&StatusCode::TOO_MANY_REQUESTS));

    // Trusted: each forwarded client has its own bucket.
    let mut limits = limits();
    limits.client_ip = ClientIpConfig {
        trusted_proxies: vec!["10.0.0.0/8".parse().unwrap()],
        header: "x-forwarded-for".into(),
    };
    let router = wallet_router(app(Setup {
        limits,
        ..Setup::default()
    }));
    for i in 0..12 {
        let xff = format!("203.0.113.{i}");
        let r = call_from(
            &router,
            "/get_version",
            "{}",
            "10.0.0.2:1",
            &[("x-forwarded-for", &xff)],
        )
        .await;
        assert_ne!(r.status, StatusCode::TOO_MANY_REQUESTS);
    }
}

#[tokio::test]
async fn a_slow_request_times_out() {
    // A node that accepts and never answers.
    let node = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = node.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = vec![];
        while let Ok((s, _)) = node.accept().await {
            held.push(s);
        }
    });
    let router = wallet_router(app(Setup {
        daemon: format!("http://{addr}"),
        request_timeout: Duration::from_millis(200),
        ..Setup::default()
    }));
    let started = std::time::Instant::now();
    let r = call(&router, "/daemon_status", &json!({})).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn errors_and_status_say_nothing_of_the_node() {
    let router = wallet_router(app(Setup {
        daemon: "http://user:hunter2@127.0.0.1:9".into(),
        ..Setup::default()
    }));
    let r = call(&router, "/daemon_status", &json!({})).await;
    assert_eq!(r.status, StatusCode::OK);
    assert!(
        !r.body.contains("127.0.0.1") && !r.body.contains("hunter2"),
        "{}",
        r.body
    );
    let r = call(&router, "/get_random_outs", &json!({ "count": 16, "amounts": ["0"] })).await;
    assert_eq!(r.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !r.body.contains("127.0.0.1") && !r.body.contains("hunter2"),
        "{}",
        r.body
    );
}

#[tokio::test]
async fn responses_carry_security_headers_and_no_server_header() {
    let router = wallet_router(app(Setup::default()));
    for path in ["/get_version", "/no_such_thing", "/login"] {
        let r = call(&router, path, &json!({})).await;
        assert_eq!(r.headers["x-content-type-options"], "nosniff", "{path}");
        assert_eq!(r.headers["cache-control"], "no-store");
        assert_eq!(r.headers["x-frame-options"], "DENY");
        assert!(r.headers.contains_key("content-security-policy"));
        assert!(!r.headers.contains_key("server"));
        assert!(
            !r.headers.contains_key("access-control-allow-origin"),
            "CORS stays opt-in"
        );
    }
}

#[tokio::test]
async fn the_admin_api_is_only_on_its_listener_and_needs_the_key() {
    let app = app(Setup::default());
    let key = crate::admin_keys::create(&app.db).unwrap();
    let wallet = wallet_router(app.clone());
    let admin = admin_router(app.clone());
    let with_key = json!({ "auth": hex::encode(*key) });

    // The wallet listener has no admin routes, key or not.
    for path in ["/list_accounts", "/add_account", "/admin/list_accounts"] {
        assert_eq!(
            call(&wallet, path, &with_key).await.status,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    assert_eq!(call(&admin, "/list_accounts", &with_key).await.status, StatusCode::OK);
    let mut wrong = *key;
    wrong[0] ^= 0x80;
    let r = call(&admin, "/list_accounts", &json!({ "auth": hex::encode(wrong) })).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    assert_eq!(
        call(&admin, "/list_accounts", &json!({})).await.status,
        StatusCode::FORBIDDEN
    );
    // The stored hash is not a key.
    let hashed = crate::admin_keys::hash(&key);
    let r = call(&admin, "/list_accounts", &json!({ "auth": hex::encode(hashed) })).await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);

    let open = admin_router(self::app(Setup {
        admin_auth: false,
        ..Setup::default()
    }));
    assert_eq!(call(&open, "/list_accounts", &json!({})).await.status, StatusCode::OK);
}

#[derive(Clone, Default)]
struct Captured(Arc<StdMutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Everything logged, at every level, while accounts are made, logged into,
/// refused, imported and handled by the admin API: no view key and no
/// address in it, whole or in part.
#[tokio::test]
async fn logs_never_hold_view_keys_or_addresses() {
    let captured = Captured::default();
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    // The global default, not a scoped one: callsites already seen by
    // tests on other threads would otherwise keep a cached "not interested".
    // Every other test's logs land here too, which only widens the check.
    tracing::subscriber::set_global_default(subscriber).expect("the only test that sets it");

    let app = app(Setup {
        import: Policy::Auto,
        ..Setup::default()
    });
    let wallet_router = wallet_router(app.clone());
    let admin = admin_router(app.clone());
    let admin_key = crate::admin_keys::create(&app.db).unwrap();
    let (address, key) = wallet(30);
    let (other, other_key) = wallet(31);

    let mut create = login_body(&address, &key);
    create["create_account"] = json!(true);
    assert_eq!(call(&wallet_router, "/login", &create).await.status, StatusCode::OK);
    assert_eq!(
        call(&wallet_router, "/login", &login_body(&address, &key)).await.status,
        StatusCode::OK
    );
    call(&wallet_router, "/login", &login_body(&address, &other_key)).await;
    call(&wallet_router, "/get_address_info", &login_body(&other, &other_key)).await;
    call(&wallet_router, "/import_wallet_request", &login_body(&address, &key)).await;
    call(&wallet_router, "/get_unspent_outs", &login_body(&address, &key)).await;
    call_from(
        &wallet_router,
        "/login",
        &format!("{{\"address\":\"{address}\",\"view_key\":\"{}\"", hex::encode(key)),
        "198.51.100.1:1",
        &[],
    )
    .await;
    call(
        &admin,
        "/add_account",
        &json!({ "auth": hex::encode(*admin_key), "params": { "address": other, "key": hex::encode(other_key) } }),
    )
    .await;
    call(
        &admin,
        "/modify_account_status",
        &json!({ "auth": hex::encode(*admin_key), "params": { "status": "hidden", "addresses": [address] } }),
    )
    .await;
    call(&admin, "/list_accounts", &json!({ "auth": hex::encode(key) })).await;

    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(log.contains("new account"), "the capture works: {log}");
    for secret in [hex::encode(key), hex::encode(other_key), hex::encode(*admin_key)] {
        assert!(!log.contains(&secret[..16]), "a key in the log: {log}");
    }
    for a in [&address, &other] {
        assert!(!log.contains(&a[..12]), "an address in the log: {log}");
        assert!(!log.contains(&a[a.len() - 8..]), "an address in the log: {log}");
    }
}

/// The listener itself: a cap on connections from one address, and TLS.
#[tokio::test]
async fn the_listener_caps_connections_per_address() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = wallet_router(app(Setup::default()));
    tokio::spawn(crate::server::serve(
        listener,
        router,
        crate::server::ListenerConfig {
            tls: None,
            max_connections: 16,
            max_connections_per_ip: 1,
            trusted_proxies: vec![],
        },
    ));
    let _first = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut second = tokio::net::TcpStream::connect(addr).await.unwrap();
    let _ = second.write_all(b"GET /get_version HTTP/1.1\r\nHost: x\r\n\r\n").await;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), second.read(&mut buf))
        .await
        .expect("the second connection is closed, not left hanging")
        .unwrap_or(0);
    assert_eq!(n, 0, "the second connection got an answer");
}

#[tokio::test]
async fn the_listener_speaks_tls() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/tls");
    let acceptor = crate::server::tls_acceptor(&dir.join("cert.pem"), &dir.join("key.pem")).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(crate::server::serve(
        listener,
        wallet_router(app(Setup::default())),
        crate::server::ListenerConfig {
            tls: Some(acceptor),
            max_connections: 16,
            max_connections_per_ip: 0,
            trusted_proxies: vec![],
        },
    ));
    let cert = reqwest::Certificate::from_pem(&std::fs::read(dir.join("cert.pem")).unwrap()).unwrap();
    let client = reqwest::Client::builder()
        .add_root_certificate(cert)
        .resolve("localhost", SocketAddr::from(([127, 0, 0, 1], port)))
        .build()
        .unwrap();
    let r = client
        .post(format!("https://localhost:{port}/get_version"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    // A large body (a big transaction) goes through hyper whole: refused by
    // the handler (it isn't a transaction), not by the listener.
    let r = client
        .post(format!("https://localhost:{port}/submit_raw_tx"))
        .header("content-type", "application/json")
        .body(json!({ "tx": "ab".repeat(900_000) }).to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert_eq!(r.text().await.unwrap(), "not a transaction");
    // Plain HTTP to the TLS port gets nowhere.
    let plain = reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/get_version"))
        .body("{}")
        .send()
        .await;
    assert!(plain.is_err() || !plain.unwrap().status().is_success());

    assert!(crate::server::tls_acceptor(&dir.join("missing.pem"), &dir.join("key.pem")).is_err());
    assert!(crate::server::tls_acceptor(&dir.join("key.pem"), &dir.join("key.pem")).is_err());
}

/// `remove_accounts`, ours: the accounts named go whole, with their rows
/// and a request waiting under their address; the others stay; an address
/// that isn't an account is passed over. And `add_account` with a key that
/// isn't the address's is a 400 that says so, not the admin key's 403.
#[tokio::test]
async fn remove_accounts_forgets_the_accounts_whole() {
    let app = app(Setup {
        create: Policy::Approve,
        ..Setup::default()
    });
    let wallets = wallet_router(app.clone());
    let admin = admin_router(app.clone());
    let auth = hex::encode(*crate::admin_keys::create(&app.db).unwrap());
    let (address, key) = wallet(40);
    let (kept, kept_key) = wallet(41);
    let (asking, asking_key) = wallet(42);
    for (a, k) in [(&address, &key), (&kept, &kept_key)] {
        let r = call(
            &admin,
            "/add_account",
            &json!({ "auth": auth, "params": { "address": a, "key": hex::encode(k) } }),
        )
        .await;
        assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    }
    let r = call(
        &admin,
        "/add_account",
        &json!({ "auth": auth, "params": { "address": asking, "key": hex::encode(key) } }),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert_eq!(r.body, "the view key doesn't belong to the address");
    let mut create = login_body(&asking, &asking_key);
    create["create_account"] = json!(true);
    assert_eq!(call(&wallets, "/login", &create).await.status, StatusCode::OK);
    let listed: Value =
        serde_json::from_str(&call(&admin, "/list_requests", &json!({ "auth": auth })).await.body).unwrap();
    assert_eq!(listed["create"].as_array().unwrap().len(), 1);

    // A name that isn't an address fails the whole command, unquoted.
    let r = call(
        &admin,
        "/remove_accounts",
        &json!({ "auth": auth, "params": { "addresses": [address, "not an address"] } }),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    assert!(!r.body.contains("not an address"), "{}", r.body);
    assert!(
        app.db.account(&parsed(&address)).unwrap().is_some(),
        "nothing was removed"
    );
    // An address without an account is passed over.
    let (unknown, _) = wallet(43);
    let r = call(
        &admin,
        "/remove_accounts",
        &json!({ "auth": auth, "params": { "addresses": [address, asking, unknown] } }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let removed: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(removed["removed"], json!([address]));

    let accounts: Value =
        serde_json::from_str(&call(&admin, "/list_accounts", &json!({ "auth": auth })).await.body).unwrap();
    let active: Vec<&str> = accounts["active"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["address"].as_str().unwrap())
        .collect();
    assert_eq!(active, [kept.as_str()]);
    let listed: Value =
        serde_json::from_str(&call(&admin, "/list_requests", &json!({ "auth": auth })).await.body).unwrap();
    // An empty list is left out of the answer.
    assert!(
        listed.get("create").is_none(),
        "the request under the address went too: {listed}"
    );
    assert!(app.db.account(&parsed(&address)).unwrap().is_none());
    // The removed wallet asks afresh, as any new one.
    let mut create = login_body(&address, &key);
    create["create_account"] = json!(true);
    assert_eq!(call(&wallets, "/login", &create).await.status, StatusCode::OK);
    // Without the admin key, nothing.
    let r = call(
        &admin,
        "/remove_accounts",
        &json!({ "params": { "addresses": [kept] } }),
    )
    .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
}

/// An output whose transaction row isn't there (what a scanner commit
/// between two reads used to look like) is answered around, not a panic.
#[tokio::test]
async fn an_output_without_its_transaction_is_no_panic() {
    let app = app(Setup::default());
    let router = wallet_router(app.clone());
    let (address, key) = add(&app, 95, Status::Active);
    let id = app.db.account(&parsed(&address)).unwrap().unwrap().id;
    app.db
        .raw_writer(|c| {
            c.execute_batch("PRAGMA foreign_keys=OFF;")?;
            c.execute(
                "INSERT INTO outputs (account, tx, out_index, global_index, amount, public_key, tx_pub_key, height, maj, min) VALUES (?1, 999, 0, 5, 7, ?2, ?2, 20, 0, 0)",
                rusqlite::params![id, [3u8; 32].as_slice()],
            )?;
            c.execute_batch("PRAGMA foreign_keys=ON;")?;
            Ok(())
        })
        .unwrap();
    for path in ["/get_address_info", "/get_address_txs"] {
        let r = call(&router, path, &login_body(&address, &key)).await;
        assert_eq!(r.status, StatusCode::OK, "{path}: {}", r.body);
    }
}

/// A major whose highest minor is u32::MAX has no room: 409, not an
/// overflow (a panic in a debug build, minors from 0 in a release one).
#[tokio::test]
async fn provisioning_a_full_major_is_a_conflict() {
    let app = app(Setup::default());
    let router = wallet_router(app.clone());
    let (address, key) = add(&app, 96, Status::Active);
    let mut body = login_body(&address, &key);
    body["subaddrs"] = json!([{ "key": 0, "value": [[4294967295u32, 4294967295u32]] }]);
    let r = call(&router, "/upsert_subaddrs", &body).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let mut body = login_body(&address, &key);
    body["maj_i"] = json!(0);
    body["n_min"] = json!(5);
    let r = call(&router, "/provision_subaddrs", &body).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    // Nor can a range be asked for that runs past the top.
    let mut body = login_body(&address, &key);
    body["maj_i"] = json!(1);
    body["min_i"] = json!(4294967294u32);
    body["n_min"] = json!(5);
    let r = call(&router, "/provision_subaddrs", &body).await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    // Another major still has room.
    let mut body = login_body(&address, &key);
    body["maj_i"] = json!(2);
    body["n_min"] = json!(5);
    let r = call(&router, "/provision_subaddrs", &body).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
}

/// `upsert_subaddrs` against a plain set of minors, over random requests,
/// and fast on a large account: 10,000 stored singletons and 1,000
/// requested ones used to take ~1e8 comparisons under the database lock.
#[test]
fn subaddress_upserts_match_a_set_and_scale() {
    use lws_api::SubaddrRanges;
    use std::collections::BTreeSet;
    let db = Db::in_memory();
    let (address, key) = wallet(97);
    let checked = crate::crypto::check_login(Network::Stagenet, &address, PrivateViewKey::from_bytes(&key)).unwrap();
    let account = db
        .add_account(&checked.into_new_account(0, false), Status::Active)
        .unwrap()
        .id;
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = |n: u64| {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (seed >> 33) % n
    };
    let mut model: BTreeSet<(u32, u32)> = BTreeSet::new();
    let ranges_of = |minors: Vec<(u32, u32)>| -> Vec<SubaddrRanges> {
        let mut out: Vec<SubaddrRanges> = vec![];
        for (maj, min) in minors {
            match out.last_mut() {
                Some(r) if r.key == maj && r.value.last().unwrap()[1] + 1 == min => {
                    r.value.last_mut().unwrap()[1] = min
                }
                Some(r) if r.key == maj => r.value.push([min, min]),
                _ => out.push(SubaddrRanges {
                    key: maj,
                    value: vec![[min, min]],
                }),
            }
        }
        out
    };
    for _ in 0..200 {
        let mut wanted: Vec<SubaddrRanges> = vec![];
        for _ in 0..1 + next(4) {
            let lo = next(60) as u32;
            let hi = lo + next(8) as u32;
            wanted.push(SubaddrRanges {
                key: next(3) as u32,
                value: vec![[lo, hi]],
            });
        }
        let mut fresh = BTreeSet::new();
        for w in &wanted {
            for &[lo, hi] in &w.value {
                for m in lo..=hi {
                    if !model.contains(&(w.key, m)) {
                        fresh.insert((w.key, m));
                    }
                }
            }
        }
        let added = db.upsert_subaddrs(account, &wanted, 1_000).unwrap();
        assert_eq!(added, ranges_of(fresh.iter().copied().collect()), "{wanted:?}");
        model.extend(fresh);
        assert_eq!(
            db.subaddrs(account).unwrap(),
            ranges_of(model.iter().copied().collect())
        );
    }

    // Large: every other minor of major 5 stored, then 1,000 more asked for.
    let stored: Vec<[u32; 2]> = (0..10_000u32).map(|i| [i * 2, i * 2]).collect();
    db.upsert_subaddrs(account, &[SubaddrRanges { key: 5, value: stored }], 100_000)
        .unwrap();
    let asked: Vec<[u32; 2]> = (0..1_000u32).map(|i| [i * 20 + 1, i * 20 + 1]).collect();
    let started = std::time::Instant::now();
    let added = db
        .upsert_subaddrs(
            account,
            &[SubaddrRanges {
                key: 5,
                value: asked.clone(),
            }],
            100_000,
        )
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    assert_eq!(added, vec![SubaddrRanges { key: 5, value: asked }]);
    // A minor at the very top is new once and covered after.
    let top = [SubaddrRanges {
        key: 9,
        value: vec![[u32::MAX - 1, u32::MAX]],
    }];
    assert_eq!(db.upsert_subaddrs(account, &top, 100_000).unwrap().len(), 1);
    assert!(db.upsert_subaddrs(account, &top, 100_000).unwrap().is_empty());
}

/// A rescan height past i64::MAX is a 400, not stored as -1 (which deleted
/// everything and left the account never scanning again); an import is one
/// transaction that starts the account at 0.
#[tokio::test]
async fn rescan_heights_past_i64_are_refused() {
    let app = app(Setup::default());
    let admin = admin_router(app.clone());
    let auth = hex::encode(*crate::admin_keys::create(&app.db).unwrap());
    let (address, _) = add(&app, 98, Status::Active);
    for height in [u64::MAX, i64::MAX as u64 + 1] {
        let r = call(
            &admin,
            "/rescan",
            &json!({ "auth": auth, "params": { "height": height, "addresses": [address] } }),
        )
        .await;
        assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
    }
    assert_eq!(app.db.account(&parsed(&address)).unwrap().unwrap().scan_height, 10);
    let r = call(
        &admin,
        "/rescan",
        &json!({ "auth": auth, "params": { "height": 5, "addresses": [address] } }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(app.db.account(&parsed(&address)).unwrap().unwrap().scan_height, 5);
    assert_eq!(app.db.import(&[parsed(&address)]).unwrap(), vec![parsed(&address)]);
    let a = app.db.account(&parsed(&address)).unwrap().unwrap();
    assert_eq!((a.start_height, a.scan_height), (0, 0));
    // A new account can't start there either.
    let (other, key) = wallet(99);
    let checked = crate::crypto::check_login(Network::Stagenet, &other, PrivateViewKey::from_bytes(&key)).unwrap();
    let new = checked.into_new_account(u64::MAX, false);
    assert!(matches!(
        app.db.add_account(&new, Status::Active),
        Err(crate::error::Error::BadRequest(_))
    ));
    assert!(app.db.account(&parsed(&other)).unwrap().is_none());
}

/// A repeated create request is refused before it takes a token from the
/// global bucket, so it can't drain it for everyone.
#[tokio::test]
async fn a_repeated_request_spends_no_global_token() {
    let app = app(Setup {
        create: Policy::Approve,
        limits: Limits::new(ClientIpConfig::default(), 0, 0, 2, u64::MAX),
        ..Setup::default()
    });
    let router = wallet_router(app.clone());
    let (a, ka) = wallet(90);
    let mut create = login_body(&a, &ka);
    create["create_account"] = json!(true);
    assert_eq!(call(&router, "/login", &create).await.status, StatusCode::OK);
    for _ in 0..5 {
        assert_eq!(call(&router, "/login", &create).await.status, StatusCode::FORBIDDEN);
    }
    let (b, kb) = wallet(91);
    let mut create = login_body(&b, &kb);
    create["create_account"] = json!(true);
    let r = call(&router, "/login", &create).await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(app.db.requests().unwrap().len(), 2);
}

/// The queue's cap holds under concurrent requests: the count and the
/// insert are one transaction.
#[test]
fn the_request_queue_cap_is_exact_under_concurrency() {
    use crate::db::Queued;
    use lws_api::admin::RequestKind;
    let db = Arc::new(Db::in_memory());
    let new = |seed: u64| {
        let (address, key) = wallet(seed);
        let checked =
            crate::crypto::check_login(Network::Stagenet, &address, PrivateViewKey::from_bytes(&key)).unwrap();
        checked.into_new_account(0, false)
    };
    let threads: Vec<_> = (0..16u64)
        .map(|i| {
            let db = db.clone();
            let n = new(100 + i);
            std::thread::spawn(move || db.add_request(RequestKind::Create, &n, 5).unwrap())
        })
        .collect();
    let outcomes: Vec<Queued> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|q| **q == Queued::Added).count(), 5);
    assert_eq!(db.requests().unwrap().len(), 5);
    let first = new(200);
    let db = Db::in_memory();
    assert_eq!(db.add_request(RequestKind::Import, &first, 1).unwrap(), Queued::Added);
    assert_eq!(
        db.add_request(RequestKind::Import, &first, 1).unwrap(),
        Queued::Duplicate
    );
    assert!(db.has_request(RequestKind::Import, &first.address).unwrap());
    assert!(!db.has_request(RequestKind::Create, &first.address).unwrap());
    assert_eq!(db.add_request(RequestKind::Create, &first, 1).unwrap(), Queued::Full(1));
}

/// `accept_requests` is all or nothing: one address that already has an
/// account means 409 naming it, and no request is taken or accepted. An
/// unknown type is refused before anything is looked at.
#[tokio::test]
async fn accept_requests_is_all_or_nothing() {
    let app = app(Setup {
        create: Policy::Approve,
        ..Setup::default()
    });
    let wallets = wallet_router(app.clone());
    let admin = admin_router(app.clone());
    let auth = hex::encode(*crate::admin_keys::create(&app.db).unwrap());
    let (a, ka) = wallet(80);
    let (b, kb) = wallet(81);
    let (c, kc) = wallet(82);
    for (address, key) in [(&a, &ka), (&b, &kb), (&c, &kc)] {
        let mut create = login_body(address, key);
        create["create_account"] = json!(true);
        assert_eq!(call(&wallets, "/login", &create).await.status, StatusCode::OK);
    }
    // The operator adds one of them by hand meanwhile.
    let r = call(
        &admin,
        "/add_account",
        &json!({ "auth": auth, "params": { "address": a, "key": hex::encode(ka) } }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);

    let r = call(
        &admin,
        "/accept_requests",
        &json!({ "auth": auth, "params": { "type": "imports", "addresses": [b] } }),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST, "{}", r.body);
    assert_eq!(app.db.requests().unwrap().len(), 3);

    let r = call(
        &admin,
        "/accept_requests",
        &json!({ "auth": auth, "params": { "type": "create", "addresses": [a, b, c] } }),
    )
    .await;
    assert_eq!(r.status, StatusCode::CONFLICT, "{}", r.body);
    let body: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(body["exists"], json!([a]));
    assert_eq!(app.db.requests().unwrap().len(), 3, "nothing was taken");
    assert!(app.db.account(&parsed(&b)).unwrap().is_none());
    assert!(app.db.account(&parsed(&c)).unwrap().is_none());

    let r = call(
        &admin,
        "/accept_requests",
        &json!({ "auth": auth, "params": { "type": "create", "addresses": [b, c, b] } }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let body: Value = serde_json::from_str(&r.body).unwrap();
    assert_eq!(body["updated"], json!([b, c]));
    assert_eq!(app.db.account(&parsed(&b)).unwrap().unwrap().status, Status::Active);
    assert!(app.db.account(&parsed(&c)).unwrap().is_some());
    let left: Vec<String> = app
        .db
        .requests()
        .unwrap()
        .into_iter()
        .map(|(_, n)| n.address.as_str().to_owned())
        .collect();
    assert_eq!(left, vec![a.clone()]);

    // Rejecting takes the request away; an unknown type is a 400 there too.
    let r = call(
        &admin,
        "/reject_requests",
        &json!({ "auth": auth, "params": { "type": "nope", "addresses": [a] } }),
    )
    .await;
    assert_eq!(r.status, StatusCode::BAD_REQUEST);
    let r = call(
        &admin,
        "/reject_requests",
        &json!({ "auth": auth, "params": { "type": "create", "addresses": [a] } }),
    )
    .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(app.db.requests().unwrap().is_empty());
}
