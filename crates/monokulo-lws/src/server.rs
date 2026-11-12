//! The listeners: hyper's HTTP/1.1 server under an accept loop of our own,
//! for what `axum::serve` doesn't do: a cap on connections (in all and per
//! client address), a time limit on reading a request's headers and on the
//! TLS handshake, small header buffers, and TLS itself.
//!
//! Each connection's peer address goes into the request's extensions as
//! `ConnectInfo<SocketAddr>`, for the middleware that finds the client
//! address and applies the rate limits (`rest::guard`).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tower::ServiceExt;

use crate::limits::{Cidr, client_key};

/// Time a client has to send a request's headers, from the moment the
/// connection is ready for one (so it bounds an idle keep-alive connection
/// too).
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Time a client has for the TLS handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// hyper's read buffer, which bounds the request line and headers (its
/// minimum is 8 KiB; monero-lws's parser buffer is 16 KiB).
const MAX_HEADER_BUFFER: usize = 16 * 1024;

#[derive(Clone)]
pub struct ListenerConfig {
    pub tls: Option<tokio_rustls::TlsAcceptor>,
    /// Open connections at most; more wait in the kernel's backlog.
    pub max_connections: usize,
    /// Open connections from one client (an IPv4 address or IPv6 /64) at
    /// most, except from a trusted proxy. 0 is no cap.
    pub max_connections_per_ip: usize,
    pub trusted_proxies: Vec<Cidr>,
}

/// Loads a PEM certificate chain and private key, for TLS 1.2 and 1.3 with
/// rustls's defaults (ECDHE key exchange and AEAD ciphers only), HTTP/1.1.
pub fn tls_acceptor(cert: &Path, key: &Path) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{CertificateDer, PrivateKeyDer};

    crate::at_rest::check_key_file(key);
    let certs = CertificateDer::pem_file_iter(cert)
        .with_context(|| format!("reading the certificate {}", cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("reading the certificate {}", cert.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificate in {}", cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(key).with_context(|| format!("reading the TLS key {}", key.display()))?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("the TLS certificate and key don't go together")?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Counts connections per client, keyed as the rate limiter keys them
/// (`limits::client_key`: an IPv4 address or an IPv6 /64, so one host with a
/// routed /64 can't take a slot per address); a slot is given back when its
/// guard goes.
#[derive(Clone, Default)]
struct PerIp(Arc<Mutex<HashMap<IpAddr, usize>>>);

struct PerIpSlot {
    map: PerIp,
    ip: IpAddr,
}

impl PerIp {
    fn take(&self, ip: IpAddr, max: usize) -> Option<PerIpSlot> {
        let ip = client_key(ip);
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let n = map.entry(ip).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(PerIpSlot { map: self.clone(), ip })
    }
}

impl Drop for PerIpSlot {
    fn drop(&mut self) {
        let mut map = self.map.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = map.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Accepts connections until the task is dropped.
pub async fn serve(listener: TcpListener, router: Router, config: ListenerConfig) {
    let open = Arc::new(Semaphore::new(config.max_connections.max(1)));
    let per_ip = PerIp::default();
    loop {
        let permit = open
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Out of file descriptors, most likely: don't spin.
                tracing::warn!("accept: {e}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let ip = peer.ip();
        let slot = if config.max_connections_per_ip == 0 || config.trusted_proxies.iter().any(|c| c.contains(ip)) {
            None
        } else {
            match per_ip.take(ip, config.max_connections_per_ip) {
                Some(slot) => Some(slot),
                None => {
                    tracing::debug!("refused a connection: too many from one address");
                    continue;
                }
            }
        };
        let _ = stream.set_nodelay(true);
        let router = router.clone();
        let tls = config.tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _slot = slot;
            match tls {
                Some(acceptor) => match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                    Ok(Ok(stream)) => connection(TokioIo::new(stream), router, peer).await,
                    Ok(Err(e)) => tracing::debug!("TLS handshake failed: {e}"),
                    Err(_) => tracing::debug!("TLS handshake timed out"),
                },
                None => connection(TokioIo::new(stream), router, peer).await,
            }
        });
    }
}

async fn connection<I>(io: I, router: Router, peer: SocketAddr)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = hyper::service::service_fn(move |mut request: hyper::Request<Incoming>| {
        request.extensions_mut().insert(ConnectInfo(peer));
        router.clone().oneshot(request.map(axum::body::Body::new))
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_TIMEOUT)
        .max_buf_size(MAX_HEADER_BUFFER)
        .keep_alive(true);
    if let Err(e) = builder.serve_connection(io, service).await {
        tracing::debug!("connection ended: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_ip_slots_cap_and_come_back() {
        let per_ip = PerIp::default();
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let a = per_ip.take(ip, 2).unwrap();
        let _b = per_ip.take(ip, 2).unwrap();
        assert!(per_ip.take(ip, 2).is_none());
        assert!(per_ip.take("198.51.100.2".parse().unwrap(), 2).is_some());
        drop(a);
        assert!(per_ip.take(ip, 2).is_some());
    }

    #[test]
    fn an_ipv6_slash_64_shares_one_set_of_slots() {
        let per_ip = PerIp::default();
        let _a = per_ip.take("2001:db8:1:2::1".parse().unwrap(), 2).unwrap();
        let _b = per_ip.take("2001:db8:1:2::2".parse().unwrap(), 2).unwrap();
        assert!(
            per_ip.take("2001:db8:1:2:ffff::9".parse().unwrap(), 2).is_none(),
            "another address in the same /64 is the same client"
        );
        assert!(per_ip.take("2001:db8:1:3::1".parse().unwrap(), 2).is_some());
        // An IPv4-mapped address is its IPv4 address.
        let _c = per_ip.take("198.51.100.7".parse().unwrap(), 1).unwrap();
        assert!(per_ip.take("::ffff:198.51.100.7".parse().unwrap(), 1).is_none());
    }
}
