//! Who is asking, and how often they may: the client address (from the
//! socket, or from a header set by a trusted reverse proxy), per-client
//! token buckets, and a global bucket for new accounts and import requests.
//!
//! A client is an IPv4 address or an IPv6 /64, since one IPv6 host usually
//! holds a whole /64.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;

/// An address range, `10.0.0.0/8` or `fd00::/8`; a bare address is a /32 or /128.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    bits: u8,
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Cidr, String> {
        let (addr, bits) = match s.split_once('/') {
            Some((a, b)) => (a, Some(b)),
            None => (s, None),
        };
        let net: IpAddr = addr.trim().parse().map_err(|_| format!("not an IP address: {addr}"))?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let bits = match bits {
            Some(b) => b
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|b| *b <= max)
                .ok_or_else(|| format!("not a prefix length: {b}"))?,
            None => max,
        };
        Ok(Cidr { net, bits })
    }
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, canonical(ip)) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.bits)).unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.bits)).unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

/// An IPv4-mapped IPv6 address as the IPv4 address it is.
fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

/// How the client address is found.
#[derive(Clone, Debug, Default)]
pub struct ClientIpConfig {
    /// Peers whose header is believed. Empty: the header is never read.
    pub trusted_proxies: Vec<Cidr>,
    /// The header a trusted proxy sets, lowercase (`x-forwarded-for`,
    /// `x-real-ip`, `forwarded` is not supported).
    pub header: String,
}

impl ClientIpConfig {
    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.iter().any(|c| c.contains(ip))
    }

    /// The client's address: the peer's, unless the peer is a trusted proxy,
    /// in which case the rightmost address in the header that is not itself
    /// a trusted proxy (what the first trusted hop saw). A header from an
    /// untrusted peer is ignored, so a client can't pick its own address.
    pub fn client_ip(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        let peer = canonical(peer.ip());
        if !self.is_trusted(peer) {
            return peer;
        }
        // Repeated headers read as one list, in order.
        let entries: Vec<&str> = headers
            .get_all(self.header.as_str())
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .collect();
        for entry in entries.iter().rev() {
            match parse_entry(entry) {
                Some(ip) if self.is_trusted(ip) => continue,
                Some(ip) => return ip,
                // Garbage where an address should be: don't guess past it.
                None => return peer,
            }
        }
        // Every hop was a trusted proxy (or there was no header): the
        // innermost one is all there is.
        entries.first().and_then(|e| parse_entry(e)).unwrap_or(peer)
    }
}

/// An address as proxies write them: `1.2.3.4`, `1.2.3.4:5678`, `::1`,
/// `[::1]:5678`.
fn parse_entry(entry: &str) -> Option<IpAddr> {
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    entry.parse::<SocketAddr>().ok().map(|s| canonical(s.ip()))
}

/// The key a client's buckets are kept under: the address, or its /64.
pub fn client_key(ip: IpAddr) -> IpAddr {
    match canonical(ip) {
        IpAddr::V6(v6) => {
            let masked = u128::from(v6) & (u128::MAX << 64);
            IpAddr::V6(Ipv6Addr::from(masked))
        }
        v4 => v4,
    }
}

/// A token bucket: `burst` tokens, refilled at `per_minute` a minute.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// Per-client buckets of one kind. `per_minute` 0 turns it off.
pub struct RateLimiter {
    per_minute: u32,
    burst: u32,
    buckets: Mutex<HashMap<IpAddr, Bucket>>,
}

/// More clients than this and idle buckets are swept before a new one is made.
const SWEEP_AT: usize = 100_000;

impl RateLimiter {
    pub fn new(per_minute: u32, burst: u32) -> RateLimiter {
        RateLimiter {
            per_minute,
            burst: burst.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.per_minute > 0
    }

    /// Takes a token for `ip`, or says how long until there is one.
    pub fn check(&self, ip: IpAddr) -> Result<(), Duration> {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        if !self.enabled() {
            return Ok(());
        }
        let rate = f64::from(self.per_minute) / 60.0;
        let burst = f64::from(self.burst);
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        if buckets.len() >= SWEEP_AT {
            // A bucket that has refilled is the same as no bucket.
            buckets.retain(|_, b| b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * rate < burst);
        }
        let bucket = buckets
            .entry(client_key(ip))
            .or_insert(Bucket { tokens: burst, at: now });
        let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(((1.0 - bucket.tokens) / rate).max(1.0)))
        }
    }
}

/// One bucket for everyone: new accounts and import requests an hour.
pub struct GlobalLimiter {
    per_hour: u32,
    bucket: Mutex<Bucket>,
}

impl GlobalLimiter {
    pub fn new(per_hour: u32) -> GlobalLimiter {
        GlobalLimiter {
            per_hour,
            bucket: Mutex::new(Bucket {
                tokens: f64::from(per_hour),
                at: Instant::now(),
            }),
        }
    }

    pub fn check(&self) -> Result<(), Duration> {
        self.check_at(Instant::now())
    }

    fn check_at(&self, now: Instant) -> Result<(), Duration> {
        if self.per_hour == 0 {
            return Ok(());
        }
        let rate = f64::from(self.per_hour) / 3600.0;
        let mut b = self.bucket.lock().unwrap_or_else(|e| e.into_inner());
        let elapsed = now.saturating_duration_since(b.at).as_secs_f64();
        b.tokens = (b.tokens + elapsed * rate).min(f64::from(self.per_hour));
        b.at = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            Err(Duration::from_secs_f64(((1.0 - b.tokens) / rate).max(1.0)))
        }
    }
}

/// Per-client limits on one listener.
pub struct Limits {
    pub client_ip: ClientIpConfig,
    /// Every request.
    pub general: RateLimiter,
    /// Account creation, imports, `/submit_raw_tx`, `/get_random_outs`.
    pub strict: RateLimiter,
    /// New accounts and import requests, across all clients.
    pub creation: GlobalLimiter,
    /// Pending create and import requests at most.
    pub max_pending_requests: u64,
}

impl Limits {
    pub fn new(
        client_ip: ClientIpConfig,
        per_minute: u32,
        strict_per_minute: u32,
        creations_per_hour: u32,
        max_pending_requests: u64,
    ) -> Limits {
        Limits {
            client_ip,
            // A burst of a minute's worth, at least a few.
            general: RateLimiter::new(per_minute, per_minute.max(10)),
            strict: RateLimiter::new(strict_per_minute, strict_per_minute.clamp(1, 10)),
            creation: GlobalLimiter::new(creations_per_hour),
            max_pending_requests,
        }
    }

    /// No limits at all, for tests.
    #[cfg(test)]
    pub fn none() -> Limits {
        Limits::new(ClientIpConfig::default(), 0, 0, 0, u64::MAX)
    }
}

/// The client address of a request, put in its extensions by the middleware.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub IpAddr);

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        }
        h
    }

    fn config(trusted: &[&str]) -> ClientIpConfig {
        ClientIpConfig {
            trusted_proxies: trusted.iter().map(|c| c.parse().unwrap()).collect(),
            header: "x-forwarded-for".into(),
        }
    }

    #[test]
    fn cidrs_parse_and_match() {
        let c: Cidr = "10.1.0.0/16".parse().unwrap();
        assert!(c.contains("10.1.200.3".parse().unwrap()));
        assert!(!c.contains("10.2.0.1".parse().unwrap()));
        assert!(c.contains("::ffff:10.1.0.9".parse().unwrap()), "mapped addresses count");
        let one: Cidr = "127.0.0.1".parse().unwrap();
        assert!(one.contains("127.0.0.1".parse().unwrap()));
        assert!(!one.contains("127.0.0.2".parse().unwrap()));
        let v6: Cidr = "fd00::/8".parse().unwrap();
        assert!(v6.contains("fd12::1".parse().unwrap()));
        assert!(!v6.contains("10.1.0.1".parse().unwrap()));
        let all: Cidr = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
        assert!("10.0.0.0/33".parse::<Cidr>().is_err());
        assert!("nonsense".parse::<Cidr>().is_err());
    }

    #[test]
    fn the_header_counts_only_from_a_trusted_proxy() {
        let peer: SocketAddr = "203.0.113.5:4000".parse().unwrap();
        let spoofed = headers(&["1.1.1.1"]);
        // No proxies trusted: the header is ignored.
        assert_eq!(config(&[]).client_ip(peer, &spoofed), peer.ip());
        // A peer that isn't the trusted proxy: still ignored.
        assert_eq!(config(&["10.0.0.0/8"]).client_ip(peer, &spoofed), peer.ip());
    }

    #[test]
    fn behind_a_proxy_the_rightmost_untrusted_hop_is_the_client() {
        let proxy: SocketAddr = "10.0.0.2:4000".parse().unwrap();
        let c = config(&["10.0.0.0/8"]);
        // The client put a fake address first; the proxy appended the real one.
        let h = headers(&["6.6.6.6, 198.51.100.7"]);
        assert_eq!(c.client_ip(proxy, &h), "198.51.100.7".parse::<IpAddr>().unwrap());
        // Two trusted hops.
        let h = headers(&["6.6.6.6, 198.51.100.7, 10.0.0.9"]);
        assert_eq!(c.client_ip(proxy, &h), "198.51.100.7".parse::<IpAddr>().unwrap());
        // Repeated headers read as one list.
        let h = headers(&["6.6.6.6", "198.51.100.7:555"]);
        assert_eq!(c.client_ip(proxy, &h), "198.51.100.7".parse::<IpAddr>().unwrap());
        // Garbage: the proxy itself.
        let h = headers(&["6.6.6.6, not-an-ip"]);
        assert_eq!(c.client_ip(proxy, &h), proxy.ip());
        // No header: the proxy itself.
        assert_eq!(c.client_ip(proxy, &HeaderMap::new()), proxy.ip());
    }

    #[test]
    fn buckets_refuse_past_the_burst_and_refill() {
        let r = RateLimiter::new(60, 3);
        let ip: IpAddr = "198.51.100.1".parse().unwrap();
        let t = Instant::now();
        for _ in 0..3 {
            assert!(r.check_at(ip, t).is_ok());
        }
        let wait = r.check_at(ip, t).unwrap_err();
        assert!(wait >= Duration::from_secs(1));
        // Someone else is unaffected.
        assert!(r.check_at("198.51.100.2".parse().unwrap(), t).is_ok());
        // A second later there is a token again.
        assert!(r.check_at(ip, t + Duration::from_secs(1)).is_ok());
        assert!(r.check_at(ip, t + Duration::from_secs(1)).is_err());
        // Off.
        let off = RateLimiter::new(0, 0);
        for _ in 0..1000 {
            assert!(off.check_at(ip, t).is_ok());
        }
    }

    #[test]
    fn an_ipv6_slash_64_is_one_client() {
        let r = RateLimiter::new(60, 1);
        let t = Instant::now();
        assert!(r.check_at("2001:db8:1:2::1".parse().unwrap(), t).is_ok());
        assert!(r.check_at("2001:db8:1:2:ffff::9".parse().unwrap(), t).is_err());
        assert!(r.check_at("2001:db8:1:3::1".parse().unwrap(), t).is_ok());
    }

    #[test]
    fn the_global_bucket_caps_everyone() {
        let g = GlobalLimiter::new(2);
        let t = Instant::now();
        assert!(g.check_at(t).is_ok());
        assert!(g.check_at(t).is_ok());
        assert!(g.check_at(t).is_err());
        assert!(g.check_at(t + Duration::from_secs(1800)).is_ok());
    }
}
