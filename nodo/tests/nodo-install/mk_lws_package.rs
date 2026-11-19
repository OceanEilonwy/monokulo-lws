//! The light wallet server recipe's own files, checked with the same code the device uses.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use nodo_install::{Permission, Permissions};
use nodo_manifest::{HealthCheck, Manifest, Outbound};
use nodo_settings::{load_settings, Access, Dependency, Installed, InstalledPackage, Limits, NetworkGrant, PortProtocol, Value};

fn files() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packages/mk-lws/files")
}

fn manifest() -> Manifest {
    let text = std::fs::read_to_string(files().join("manifest.toml")).unwrap();
    Manifest::parse(&text.replace("@VERSION@", "0.1.0pre20261112")).unwrap()
}

fn cuprated() -> InstalledPackage {
    let manifest = Manifest::parse_system(
        "api_version = 1\nid = \"cuprated\"\nversion = \"0.1.0\"\nexec = [\"/usr/bin/cuprated\"]\n\
         provides = [\"monero-daemon\"]\n[[network.inbound]]\nport = 18081\nprotocol = \"tcp\"\nscope = \"local\"\n",
    )
    .unwrap();
    let settings = load_settings(
        r#"return { api_version = 1, settings = {
            { name = "rpc_url", type = "url", label = "RPC", default = "http://127.0.0.1:18081",
              public = "public_rpc_url", endpoint = "tcp" },
        } }"#,
        Limits::default(),
    )
    .unwrap();
    InstalledPackage { manifest, schema: settings.schema().clone(), values: BTreeMap::new() }
}

#[test]
fn the_manifest_passes_feed_validation_and_names_its_files() {
    let m = manifest();
    assert_eq!(m.id, "mk-lws");
    assert_eq!(m.exec[0], "bin/monokulo-lws");
    assert!(files().join("monokulo-lws").exists());
    assert_eq!(m.needs, ["monero-daemon"]);
    assert!(m.storage.encrypted, "it holds every wallet's view key");
    assert_eq!(m.network.outbound, Outbound::None, "it only talks to the node on this device");
    assert!(!m.devices.gpu, "the GPU is optional and not asked for");
    assert_eq!(m.health, Some(HealthCheck::Tcp { port: 8443 }));
    for panel in &m.panels {
        assert!(files().join(&panel.script).exists(), "{}", panel.script);
    }
    let p = Permissions::of(&m, &[]);
    assert!(!p.granted.contains(&Permission::OutboundInternet));
    assert!(!p.granted.contains(&Permission::UnencryptedStorage));
}

#[test]
fn settings_resolve_against_the_node_role() {
    let source = std::fs::read_to_string(files().join("settings.lua")).unwrap();
    let loaded = load_settings(&source, Limits::default()).unwrap();
    let schema = loaded.schema().clone();
    let mut installed = Installed::default();
    installed.packages.insert("cuprated".into(), cuprated());
    installed.packages.insert("mk-lws".into(), InstalledPackage { manifest: manifest(), schema, values: BTreeMap::new() });
    let resolved = installed.resolve("mk-lws").unwrap();

    assert_eq!(resolved.values["daemon_url"], Value::Url("http://127.0.0.1:18081".into()));
    for arg in ["--daemon=http://127.0.0.1:18081", "--create=auto", "--import=approve"] {
        assert!(resolved.exec.contains(&arg.to_string()), "{arg}: {:?}", resolved.exec);
    }
    assert_eq!(
        resolved.dependencies.iter().collect::<Vec<_>>(),
        [&Dependency { package: "cuprated".into(), role: Some("monero-daemon".into()) }]
    );
    assert_eq!(
        resolved.network.iter().collect::<Vec<_>>(),
        [&NetworkGrant {
            consumer: "mk-lws".into(),
            provider: "cuprated".into(),
            access: Access::Port { protocol: PortProtocol::Tcp, port: 18081 },
        }]
    );
    assert!(loaded.validate_values(&resolved.values).is_empty());
    let mut bad = resolved.values.clone();
    bad.insert("daemon_url".into(), Value::Url("http://node.example.com:18081".into()));
    assert_eq!(loaded.validate_values(&bad).len(), 1, "a node elsewhere is unreachable without internet access");
}

#[test]
fn the_launcher_runs_serve_with_the_database_in_home() {
    let dir = tempfile::tempdir().unwrap();
    let (bin, libexec, home) = (dir.path().join("bin"), dir.path().join("libexec"), dir.path().join("home"));
    for d in [&bin, &libexec, &home] {
        std::fs::create_dir(d).unwrap();
    }
    std::fs::copy(files().join("monokulo-lws"), bin.join("monokulo-lws")).unwrap();
    let stand_in = libexec.join("monokulo-lws");
    std::fs::write(&stand_in, "#!/bin/sh\nfor a do echo \"arg:$a\"; done\necho \"pwd:$(pwd)\"\n").unwrap();
    std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = Command::new("sh")
        .arg("bin/monokulo-lws")
        .arg("--listen")
        .arg("127.0.0.1:8443")
        .current_dir(dir.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &home)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let home = std::fs::canonicalize(&home).unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout).replace(home.to_str().unwrap(), "$HOME");
    assert_eq!(stdout, "arg:serve\narg:--db\narg:$HOME/lws.sqlite\narg:--listen\narg:127.0.0.1:8443\npwd:$HOME\n");
}
