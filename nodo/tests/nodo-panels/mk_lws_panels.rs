//! The light wallet server's shipped panel, run on data shaped like what its service returns.
//!
//! Copied into monokulo-nodo's crates/nodo-panels/tests by its app-release workflow, beside the
//! pinned recipe in packages/, so the paths below resolve there.

use nodo_manifest::{Manifest, PanelSource};
use nodo_panels::{run_panel, Status};
use serde_json::json;

const LWS_MANIFEST: &str = include_str!("../../../packages/mk-lws/files/manifest.toml");
const LWS_PANEL: &str = include_str!("../../../packages/mk-lws/files/panels/scan.lua");

/// monokulo-lws's GET /daemon_status, as crates/monokulo-lws/src/rest/wallet.rs writes it.
fn daemon_status(reachable: bool, chain: u64, scanned: u64, lanes: serde_json::Value) -> serde_json::Value {
    json!({
        "server": "0.1.0", "network": "main", "daemon_reachable": reachable, "daemon_height": chain,
        "daemon_synced": reachable, "scanner_height": scanned, "scanner_error": null,
        "scanner_seconds_ago": 4, "scanner_engine": { "gpu": false, "reason": "NoVulkan" },
        "live_lane_height": scanned, "catch_up_lanes": lanes,
    })
}

#[test]
fn the_light_wallet_servers_manifest_and_panel() {
    let manifest = Manifest::parse(&LWS_MANIFEST.replace("@VERSION@", "0.1.0")).unwrap();
    assert_eq!(manifest.panels[0].source, PanelSource::Http { url: "http://127.0.0.1:8443/daemon_status".into() });

    let caught_up = run_panel(LWS_PANEL, "lws/scan", &daemon_status(true, 3_478_120, 3_478_119, json!([])), &[]).unwrap();
    assert_eq!(caught_up.big.as_deref(), Some("3,478,119"));
    assert_eq!(caught_up.status, Some(Status::Ok));
    assert!(caught_up.rows.contains(&("engine".into(), "CPU".into())), "{:?}", caught_up.rows);

    let lanes = json!([{ "id": 1, "cursor": 3_100_000, "accounts": 2 }, { "id": 2, "cursor": 3_300_000, "accounts": 1 }]);
    let behind = run_panel(LWS_PANEL, "lws/scan", &daemon_status(true, 3_478_120, 1_739_060, lanes), &[50.0]).unwrap();
    assert_eq!(behind.big.as_deref(), Some("50%"));
    assert_eq!(behind.status, Some(Status::Busy));
    assert!(behind.rows.contains(&("catching up".into(), "3 wallets".into())), "{:?}", behind.rows);
    assert!(behind.rows.contains(&("behind".into(), "1,739,060 blocks".into())));

    let down = run_panel(LWS_PANEL, "lws/scan", &daemon_status(false, 3_478_119, 3_478_119, json!([])), &[]).unwrap();
    assert_eq!(down.status, Some(Status::Error));
    assert_eq!(down.note.as_deref(), Some("the node does not answer"));

    let mut failed = daemon_status(true, 3_478_120, 3_478_120, json!([]));
    failed["scanner_error"] = json!("the last scan step failed; see the server log");
    failed["scanner_engine"] = json!({ "gpu": true, "name": "Mali-G610" });
    let failed = run_panel(LWS_PANEL, "lws/scan", &failed, &[]).unwrap();
    assert_eq!(failed.status, Some(Status::Warn));
    assert!(failed.rows.contains(&("engine".into(), "GPU".into())));

    let starting = run_panel(LWS_PANEL, "lws/scan", &daemon_status(true, 0, 0, json!([])), &[]).unwrap();
    assert_eq!(starting.big.as_deref(), Some("--"));
}
