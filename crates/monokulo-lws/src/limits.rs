//! Who is asking, and how often they may: the client address (from the
//! socket, or from a header set by a trusted reverse proxy), per-client
//! token buckets, and a global bucket for new accounts and import requests.
//!
//! A client is an IPv4 address or an IPv6 /64, since one IPv6 host usually
//! holds a whole /64. Since one site usually holds a whole /48, each IPv6
//! /48 has buckets of its own too, and a request must pass both.

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
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 64))),
        v4 => v4,
    }
}

/// The key of a client's wider network, for the second tier of buckets: an
/// IPv6 address's /48 (a site's usual allocation, so one holder of a /48
/// can't spend 65,536 /64 buckets). An IPv4 address has none: its own
/// bucket is already as narrow as an address gets.
pub fn network_key(ip: IpAddr) -> Option<IpAddr> {
    match canonical(ip) {
        IpAddr::V6(v6) => Some(IpAddr::V6(Ipv6Addr::from(u128::from(v6) & (u128::MAX << 80)))),
        IpAddr::V4(_) => None,
    }
}

/// A token bucket: `burst` tokens, refilled at `per_minute` a minute.
#[derive(Clone, Copy, Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

/// Buckets kept per tier at most. Past it the least recently used tenth go
/// (a bucket that is gone is a full one, so eviction can only be generous,
/// and an attacker who forces it needs this many /64s or /48s at once).
pub const MAX_BUCKETS: usize = 200_000;
/// Below this many buckets a tier is never swept.
const SWEEP_FLOOR: usize = 1_024;

/// One tier's rate and how it keys a client.
struct Tier {
    per_minute: u32,
    burst: u32,
    key: fn(IpAddr) -> Option<IpAddr>,
}

impl Tier {
    fn enabled(&self) -> bool {
        self.per_minute > 0
    }

    fn rate(&self) -> f64 {
        f64::from(self.per_minute) / 60.0
    }

    fn key(&self, ip: IpAddr) -> Option<IpAddr> {
        if self.enabled() { (self.key)(ip) } else { None }
    }
}

/// One tier's buckets. Sweeps are amortised: the map is swept of refilled
/// buckets only once it has doubled since the last sweep (so each sweep is
/// paid for by as many new buckets as it walks), and when it reaches its cap
/// the least recently used tenth are dropped too. No `check` walks the map
/// on every call.
struct Buckets {
    map: HashMap<IpAddr, Bucket>,
    sweep_at: usize,
    cap: usize,
}

impl Buckets {
    fn new(cap: usize) -> Buckets {
        Buckets {
            map: HashMap::new(),
            sweep_at: SWEEP_FLOOR.min(cap),
            cap,
        }
    }

    /// Makes room for one more bucket, if the map has reached a threshold.
    fn make_room(&mut self, tier: &Tier, now: Instant) {
        if self.map.len() < self.sweep_at {
            return;
        }
        let rate = tier.rate();
        let burst = f64::from(tier.burst);
        // A bucket that has refilled is the same as no bucket.
        self.map
            .retain(|_, b| b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * rate < burst);
        if self.map.len() >= self.cap {
            // Still full of live buckets: drop the least recently used tenth.
            let drop = (self.cap / 10).max(1);
            let mut ages: Vec<Instant> = self.map.values().map(|b| b.at).collect();
            let (_, cutoff, _) = ages.select_nth_unstable(drop - 1);
            let cutoff = *cutoff;
            let mut dropped = 0;
            self.map.retain(|_, b| {
                if dropped < drop && b.at <= cutoff {
                    dropped += 1;
                    false
                } else {
                    true
                }
            });
            tracing::warn!(
                "the rate limiter is full ({} clients): dropped the {dropped} idlest",
                self.cap
            );
        }
        self.sweep_at = (self.map.len() * 2).clamp(SWEEP_FLOOR.min(self.cap), self.cap);
    }

    /// The bucket for `key`, refilled to `now`.
    fn refill(&mut self, tier: &Tier, key: IpAddr, now: Instant) -> &mut Bucket {
        if !self.map.contains_key(&key) {
            self.make_room(tier, now);
        }
        let burst = f64::from(tier.burst);
        let bucket = self.map.entry(key).or_insert(Bucket { tokens: burst, at: now });
        let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * tier.rate()).min(burst);
        bucket.at = now;
        bucket
    }
}

/// Per-client buckets of one kind, in two tiers: per client (an IPv4
/// address or IPv6 /64) and per IPv6 /48. A request takes a token from
/// both or from neither. A tier with `per_minute` 0 is off.
pub struct RateLimiter {
    tiers: [Tier; 2],
    buckets: Mutex<[Buckets; 2]>,
}

impl RateLimiter {
    /// One tier only: per client.
    #[cfg(test)]
    pub fn new(per_minute: u32, burst: u32) -> RateLimiter {
        RateLimiter::tiered(per_minute, burst, 0, 0)
    }

    /// Per client and per IPv6 /48.
    pub fn tiered(per_minute: u32, burst: u32, per_48_minute: u32, burst_48: u32) -> RateLimiter {
        RateLimiter::with_cap(per_minute, burst, per_48_minute, burst_48, MAX_BUCKETS)
    }

    fn with_cap(per_minute: u32, burst: u32, per_48_minute: u32, burst_48: u32, cap: usize) -> RateLimiter {
        RateLimiter {
            tiers: [
                Tier {
                    per_minute,
                    burst: burst.max(1),
                    key: |ip| Some(client_key(ip)),
                },
                Tier {
                    per_minute: per_48_minute,
                    burst: burst_48.max(1),
                    key: network_key,
                },
            ],
            buckets: Mutex::new([Buckets::new(cap), Buckets::new(cap)]),
        }
    }

    pub fn enabled(&self) -> bool {
        self.tiers.iter().any(Tier::enabled)
    }

    /// Takes a token for `ip`, or says how long until there is one.
    pub fn check(&self, ip: IpAddr) -> Result<(), Duration> {
        self.check_at(ip, Instant::now())
    }

    fn check_at(&self, ip: IpAddr, now: Instant) -> Result<(), Duration> {
        if !self.enabled() {
            return Ok(());
        }
        let mut buckets = self.buckets.lock().unwrap_or_else(|e| e.into_inner());
        // First see whether every tier has a token, then take them: a
        // request refused by one tier costs nothing in the other.
        let mut wait: Option<Duration> = None;
        for (tier, buckets) in self.tiers.iter().zip(buckets.iter_mut()) {
            let Some(key) = tier.key(ip) else { continue };
            let bucket = buckets.refill(tier, key, now);
            if bucket.tokens < 1.0 {
                let w = Duration::from_secs_f64(((1.0 - bucket.tokens) / tier.rate()).max(1.0));
                wait = Some(wait.map_or(w, |o| o.max(w)));
            }
        }
        if let Some(wait) = wait {
            return Err(wait);
        }
        for (tier, buckets) in self.tiers.iter().zip(buckets.iter_mut()) {
            if let Some(key) = tier.key(ip)
                && let Some(bucket) = buckets.map.get_mut(&key)
            {
                bucket.tokens -= 1.0;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn len(&self) -> [usize; 2] {
        let b = self.buckets.lock().unwrap();
        [b[0].map.len(), b[1].map.len()]
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

/// What a /48 may do by default against what one /64 may: four /64s' worth.
pub const PER_48_FACTOR: u32 = 4;

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
    /// The /48 tiers at their defaults, `PER_48_FACTOR` times the /64's.
    #[cfg(test)]
    pub fn new(
        client_ip: ClientIpConfig,
        per_minute: u32,
        strict_per_minute: u32,
        creations_per_hour: u32,
        max_pending_requests: u64,
    ) -> Limits {
        Limits::with_per_48(
            client_ip,
            [per_minute, per_minute.saturating_mul(PER_48_FACTOR)],
            [strict_per_minute, strict_per_minute.saturating_mul(PER_48_FACTOR)],
            creations_per_hour,
            max_pending_requests,
        )
    }

    /// `general` and `strict` are a minute's requests per client and per
    /// IPv6 /48.
    pub fn with_per_48(
        client_ip: ClientIpConfig,
        general: [u32; 2],
        strict: [u32; 2],
        creations_per_hour: u32,
        max_pending_requests: u64,
    ) -> Limits {
        let [per_minute, per_48_minute] = general;
        let [strict_per_minute, strict_per_48_minute] = strict;
        Limits {
            client_ip,
            // A burst of a minute's worth, at least a few.
            general: RateLimiter::tiered(per_minute, per_minute.max(10), per_48_minute, per_48_minute.max(10)),
            strict: RateLimiter::tiered(
                strict_per_minute,
                strict_per_minute.clamp(1, 10),
                strict_per_48_minute,
                strict_per_48_minute.clamp(1, 10 * PER_48_FACTOR),
            ),
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
    fn an_ipv6_slash_48_has_its_own_bucket() {
        // One a minute per /64, two per /48.
        let r = RateLimiter::tiered(60, 1, 60, 2);
        let t = Instant::now();
        assert!(r.check_at("2001:db8:1:1::1".parse().unwrap(), t).is_ok());
        assert!(r.check_at("2001:db8:1:2::1".parse().unwrap(), t).is_ok());
        let wait = r.check_at("2001:db8:1:3::1".parse().unwrap(), t).unwrap_err();
        assert!(wait >= Duration::from_secs(1));
        // Another /48 is not held back.
        assert!(r.check_at("2001:db8:2:1::1".parse().unwrap(), t).is_ok());
        // IPv4 has no /48 tier: only its own bucket counts.
        assert!(r.check_at("198.51.100.1".parse().unwrap(), t).is_ok());
        assert!(r.check_at("198.51.100.2".parse().unwrap(), t).is_ok());
        assert!(r.check_at("198.51.100.3".parse().unwrap(), t).is_ok());
    }

    #[test]
    fn a_refusal_by_one_tier_costs_nothing_in_the_other() {
        let r = RateLimiter::tiered(60, 1, 60, 3);
        let t = Instant::now();
        let a: IpAddr = "2001:db8:1:1::1".parse().unwrap();
        assert!(r.check_at(a, t).is_ok());
        // Refused by its /64 bucket, several times: the /48 keeps its tokens.
        for _ in 0..5 {
            assert!(r.check_at(a, t).is_err());
        }
        assert!(r.check_at("2001:db8:1:2::1".parse().unwrap(), t).is_ok());
        assert!(r.check_at("2001:db8:1:3::1".parse().unwrap(), t).is_ok());
        assert!(r.check_at("2001:db8:1:4::1".parse().unwrap(), t).is_err());
    }

    #[test]
    fn the_bucket_map_has_a_hard_cap() {
        let r = RateLimiter::with_cap(1, 1, 0, 0, 2_000);
        let t = Instant::now();
        let v4 = |i: u32| IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000 + i));
        // Every bucket is still refilling (a token takes a minute), so the
        // sweep of refilled buckets can't help; the cap holds anyway.
        for i in 0..10_000u32 {
            assert!(r.check_at(v4(i), t + Duration::from_millis(u64::from(i))).is_ok());
            assert!(r.len()[0] <= 2_000);
        }
        // The newest client's bucket survived the evictions.
        assert!(r.check_at(v4(9_999), t + Duration::from_millis(10_000)).is_err());
        // Refilled buckets are swept once the map has grown.
        let r = RateLimiter::with_cap(60_000, 1, 0, 0, 100_000);
        for i in 0..5_000u32 {
            // Two milliseconds refill a bucket at 1,000 a second.
            assert!(r.check_at(v4(i), t + Duration::from_millis(u64::from(i) * 2)).is_ok());
        }
        assert!(r.len()[0] < 2_100, "{:?}", r.len());
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
