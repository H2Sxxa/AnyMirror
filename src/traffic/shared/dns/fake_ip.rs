use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow};
use ipnet::{Ipv4Net, Ipv6Net};

#[derive(Debug, Clone)]
pub struct FakeIpStore {
    inner: Arc<Mutex<FakeIpStoreInner>>,
}

#[derive(Debug)]
struct FakeIpStoreInner {
    domain_to_entry_v4: HashMap<String, FakeIpv4Entry>,
    ip_to_domain_v4: HashMap<Ipv4Addr, String>,
    next_candidate_v4: u32,
    fake_ipv4_range: Ipv4Net,
    domain_to_entry_v6: HashMap<String, FakeIpv6Entry>,
    ip_to_domain_v6: HashMap<Ipv6Addr, String>,
    next_candidate_v6: u128,
    fake_ipv6_range: Ipv6Net,
}

#[derive(Debug, Clone)]
struct FakeIpv4Entry {
    ip: Ipv4Addr,
    expires_at: Instant,
}

#[derive(Debug, Clone)]
struct FakeIpv6Entry {
    ip: Ipv6Addr,
    expires_at: Instant,
}

impl FakeIpStore {
    pub fn new(fake_ipv4_range: Ipv4Net, fake_ipv6_range: Ipv6Net) -> Self {
        Self {
            inner: Arc::new(Mutex::new(FakeIpStoreInner {
                domain_to_entry_v4: HashMap::new(),
                ip_to_domain_v4: HashMap::new(),
                next_candidate_v4: first_usable_ipv4(fake_ipv4_range),
                fake_ipv4_range,
                domain_to_entry_v6: HashMap::new(),
                ip_to_domain_v6: HashMap::new(),
                next_candidate_v6: first_usable_ipv6(fake_ipv6_range),
                fake_ipv6_range,
            })),
        }
    }

    pub fn allocate_or_refresh_ipv4(
        &self,
        domain: &str,
        ttl: Duration,
        now: Instant,
    ) -> Result<Ipv4Addr> {
        let normalized_domain = normalize_domain(domain);
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow!("fake-ip store lock poisoned"))?;
        prune_expired_entries(&mut inner, now);

        if let Some(entry) = inner.domain_to_entry_v4.get_mut(&normalized_domain) {
            entry.expires_at = now + ttl;
            return Ok(entry.ip);
        }

        let fake_ip = allocate_next_ipv4(&mut inner)
            .ok_or_else(|| anyhow!("fake-ip pool exhausted for {}", inner.fake_ipv4_range))?;
        inner.domain_to_entry_v4.insert(
            normalized_domain.clone(),
            FakeIpv4Entry {
                ip: fake_ip,
                expires_at: now + ttl,
            },
        );
        inner.ip_to_domain_v4.insert(fake_ip, normalized_domain);
        Ok(fake_ip)
    }

    pub fn allocate_or_refresh_ipv6(
        &self,
        domain: &str,
        ttl: Duration,
        now: Instant,
    ) -> Result<Ipv6Addr> {
        let normalized_domain = normalize_domain(domain);
        let mut inner = self
            .inner
            .lock()
            .map_err(|_| anyhow!("fake-ip store lock poisoned"))?;
        prune_expired_entries(&mut inner, now);

        if let Some(entry) = inner.domain_to_entry_v6.get_mut(&normalized_domain) {
            entry.expires_at = now + ttl;
            return Ok(entry.ip);
        }

        let fake_ip = allocate_next_ipv6(&mut inner)
            .ok_or_else(|| anyhow!("fake-ip pool exhausted for {}", inner.fake_ipv6_range))?;
        inner.domain_to_entry_v6.insert(
            normalized_domain.clone(),
            FakeIpv6Entry {
                ip: fake_ip,
                expires_at: now + ttl,
            },
        );
        inner.ip_to_domain_v6.insert(fake_ip, normalized_domain);
        Ok(fake_ip)
    }

    pub fn resolve_domain(&self, ip: IpAddr, now: Instant) -> Option<String> {
        let mut inner = self.inner.lock().ok()?;
        prune_expired_entries(&mut inner, now);

        match ip {
            IpAddr::V4(ipv4) => {
                let domain = inner.ip_to_domain_v4.get(&ipv4)?.clone();
                let entry = inner.domain_to_entry_v4.get(&domain)?;
                (entry.expires_at > now).then_some(domain)
            }
            IpAddr::V6(ipv6) => {
                let domain = inner.ip_to_domain_v6.get(&ipv6)?.clone();
                let entry = inner.domain_to_entry_v6.get(&domain)?;
                (entry.expires_at > now).then_some(domain)
            }
        }
    }
}

fn allocate_next_ipv4(inner: &mut FakeIpStoreInner) -> Option<Ipv4Addr> {
    let first = first_usable_ipv4(inner.fake_ipv4_range);
    let last = last_usable_ipv4(inner.fake_ipv4_range)?;
    if first > last {
        return None;
    }

    let start = clamp_ipv4_candidate(inner.next_candidate_v4, first, last);
    let mut candidate_u32 = start;
    loop {
        let candidate = Ipv4Addr::from(candidate_u32);
        if !inner.ip_to_domain_v4.contains_key(&candidate) {
            inner.next_candidate_v4 = advance_ipv4_candidate(candidate_u32, first, last);
            return Some(candidate);
        }

        candidate_u32 = advance_ipv4_candidate(candidate_u32, first, last);
        if candidate_u32 == start {
            return None;
        }
    }
}

fn allocate_next_ipv6(inner: &mut FakeIpStoreInner) -> Option<Ipv6Addr> {
    let first = first_usable_ipv6(inner.fake_ipv6_range);
    let last = last_usable_ipv6(inner.fake_ipv6_range)?;
    if first > last {
        return None;
    }

    let start = clamp_ipv6_candidate(inner.next_candidate_v6, first, last);
    let mut candidate_u128 = start;
    loop {
        let candidate = Ipv6Addr::from(candidate_u128);
        if !inner.ip_to_domain_v6.contains_key(&candidate) {
            inner.next_candidate_v6 = advance_ipv6_candidate(candidate_u128, first, last);
            return Some(candidate);
        }

        candidate_u128 = advance_ipv6_candidate(candidate_u128, first, last);
        if candidate_u128 == start {
            return None;
        }
    }
}

fn prune_expired_entries(inner: &mut FakeIpStoreInner, now: Instant) {
    let expired_domains_v4 = inner
        .domain_to_entry_v4
        .iter()
        .filter_map(|(domain, entry)| (entry.expires_at <= now).then_some(domain.clone()))
        .collect::<Vec<_>>();
    let expired_domains_v6 = inner
        .domain_to_entry_v6
        .iter()
        .filter_map(|(domain, entry)| (entry.expires_at <= now).then_some(domain.clone()))
        .collect::<Vec<_>>();

    for domain in expired_domains_v4 {
        if let Some(entry) = inner.domain_to_entry_v4.remove(&domain) {
            inner.ip_to_domain_v4.remove(&entry.ip);
        }
    }

    for domain in expired_domains_v6 {
        if let Some(entry) = inner.domain_to_entry_v6.remove(&domain) {
            inner.ip_to_domain_v6.remove(&entry.ip);
        }
    }
}

fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

fn first_usable_ipv4(fake_ipv4_range: Ipv4Net) -> u32 {
    u32::from(fake_ipv4_range.network()).saturating_add(1)
}

fn last_usable_ipv4(fake_ipv4_range: Ipv4Net) -> Option<u32> {
    let broadcast = fake_ipv4_range.broadcast();
    let broadcast_u32 = u32::from(broadcast);
    (broadcast_u32 > u32::from(fake_ipv4_range.network())).then_some(broadcast_u32 - 1)
}

fn clamp_ipv4_candidate(candidate: u32, first: u32, last: u32) -> u32 {
    if candidate < first || candidate > last {
        first
    } else {
        candidate
    }
}

fn advance_ipv4_candidate(candidate: u32, first: u32, last: u32) -> u32 {
    if candidate >= last {
        first
    } else {
        candidate + 1
    }
}

fn first_usable_ipv6(fake_ipv6_range: Ipv6Net) -> u128 {
    ipv6_to_u128(fake_ipv6_range.network()).saturating_add(1)
}

fn last_usable_ipv6(fake_ipv6_range: Ipv6Net) -> Option<u128> {
    let network = ipv6_to_u128(fake_ipv6_range.network());
    let host_bits = 128u32.saturating_sub(u32::from(fake_ipv6_range.prefix_len()));
    let host_mask = match host_bits {
        0 => 0,
        128 => u128::MAX,
        bits => (1u128 << bits) - 1,
    };
    let last = network | host_mask;
    (last >= first_usable_ipv6(fake_ipv6_range)).then_some(last)
}

fn clamp_ipv6_candidate(candidate: u128, first: u128, last: u128) -> u128 {
    if candidate < first || candidate > last {
        first
    } else {
        candidate
    }
}

fn advance_ipv6_candidate(candidate: u128, first: u128, last: u128) -> u128 {
    if candidate >= last {
        first
    } else {
        candidate + 1
    }
}

fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv6Addr},
        time::{Duration, Instant},
    };

    use ipnet::{Ipv4Net, Ipv6Net};

    use super::FakeIpStore;

    #[test]
    fn allocates_and_resolves_fake_ip() {
        let store = FakeIpStore::new(
            Ipv4Net::new("198.18.0.0".parse().unwrap(), 24).unwrap(),
            Ipv6Net::new("fd00:198:18::".parse().unwrap(), 64).unwrap(),
        );
        let now = Instant::now();
        let fake_ip = store
            .allocate_or_refresh_ipv4("example.com", Duration::from_secs(60), now)
            .unwrap();

        let resolved = store.resolve_domain(IpAddr::V4(fake_ip), now).unwrap();
        assert_eq!(resolved, "example.com");
    }

    #[test]
    fn reuses_existing_mapping_before_expiry() {
        let store = FakeIpStore::new(
            Ipv4Net::new("198.18.1.0".parse().unwrap(), 24).unwrap(),
            Ipv6Net::new("fd00:198:19::".parse().unwrap(), 64).unwrap(),
        );
        let now = Instant::now();
        let first = store
            .allocate_or_refresh_ipv4("example.com", Duration::from_secs(30), now)
            .unwrap();
        let second = store
            .allocate_or_refresh_ipv4("example.com", Duration::from_secs(60), now)
            .unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn allocates_and_resolves_fake_ipv6() {
        let store = FakeIpStore::new(
            Ipv4Net::new("198.18.2.0".parse().unwrap(), 24).unwrap(),
            Ipv6Net::new("fd00:198:20::".parse().unwrap(), 64).unwrap(),
        );
        let now = Instant::now();
        let fake_ip = store
            .allocate_or_refresh_ipv6("example.com", Duration::from_secs(60), now)
            .unwrap();

        let resolved = store.resolve_domain(IpAddr::V6(fake_ip), now).unwrap();
        assert_eq!(resolved, "example.com");
        assert_ne!(fake_ip, Ipv6Addr::UNSPECIFIED);
    }
}
