use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::sync::mpsc::UnboundedSender;

use super::dns::DnsResolvedTarget;

pub const BOOTSTRAP_TARGET_TTL: Duration = Duration::from_secs(300);
pub const TARGET_STORE_CLEANUP_INTERVAL: Duration = Duration::from_secs(5);
pub const NAT_ENTRY_ESTABLISHED_TTL: Duration = Duration::from_secs(300);
pub const NAT_ENTRY_CLOSING_TTL: Duration = Duration::from_secs(30);
pub const NAT_TABLE_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
pub const REQUEST_GENERATION_DEBOUNCE: Duration = Duration::from_secs(2);
pub const REQUEST_GENERATION_GRACE_PERIOD: Duration = Duration::from_secs(20);
pub const REQUEST_PRIORITY_BASE: i16 = 100;

pub type TransparentTargetChangeTx = UnboundedSender<()>;

#[derive(Debug, Clone)]
pub struct TransparentTargetStore {
    entries: Arc<Mutex<HashMap<IpAddr, TransparentTargetEntry>>>,
}

#[derive(Debug, Clone)]
struct TransparentTargetEntry {
    expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct TransparentNatEntryV4 {
    pub destination_ip: Ipv4Addr,
    pub destination_port: u16,
    pub expires_at: Instant,
}

#[derive(Debug, Clone)]
pub struct TransparentNatEntryV6 {
    pub destination_ip: Ipv6Addr,
    pub destination_port: u16,
    pub expires_at: Instant,
}

pub type TransparentNatTableV4 = Arc<Mutex<HashMap<(Ipv4Addr, u16), TransparentNatEntryV4>>>;
pub type TransparentNatTableV6 = Arc<Mutex<HashMap<(Ipv6Addr, u16), TransparentNatEntryV6>>>;

impl TransparentTargetStore {
    pub fn from_bootstrap(target_ips: impl IntoIterator<Item = IpAddr>, now: Instant) -> Self {
        let expires_at = now + BOOTSTRAP_TARGET_TTL;
        let entries = target_ips
            .into_iter()
            .map(|ip| (ip, TransparentTargetEntry { expires_at }))
            .collect::<HashMap<_, _>>();

        Self {
            entries: Arc::new(Mutex::new(entries)),
        }
    }

    pub fn snapshot_active_ips(&self, now: Instant) -> Vec<IpAddr> {
        let mut ips = self
            .entries
            .lock()
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|(ip, entry)| (entry.expires_at > now).then_some(*ip))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        ips.sort_by_key(|ip| ip.to_string());
        ips
    }

    pub fn contains(&self, ip: &IpAddr, now: Instant) -> bool {
        self.entries
            .lock()
            .ok()
            .and_then(|entries| entries.get(ip).map(|entry| entry.expires_at > now))
            .unwrap_or(false)
    }

    pub fn insert_dns_targets(&self, targets: &[DnsResolvedTarget], now: Instant) -> Vec<IpAddr> {
        let mut inserted_targets = Vec::new();
        let Ok(mut entries) = self.entries.lock() else {
            return inserted_targets;
        };

        for target in targets {
            let expires_at = now + target.ttl;
            match entries.get_mut(&target.ip) {
                Some(entry) => {
                    let was_active = entry.expires_at > now;
                    if expires_at > entry.expires_at {
                        entry.expires_at = expires_at;
                    }
                    if !was_active && entry.expires_at > now {
                        inserted_targets.push(target.ip);
                    }
                }
                None => {
                    entries.insert(target.ip, TransparentTargetEntry { expires_at });
                    inserted_targets.push(target.ip);
                }
            }
        }

        inserted_targets.sort_by_key(|ip| ip.to_string());
        inserted_targets.dedup();
        inserted_targets
    }

    pub fn prune_expired(&self, now: Instant) -> Vec<IpAddr> {
        let Ok(mut entries) = self.entries.lock() else {
            return Vec::new();
        };

        let expired_ips = entries
            .iter()
            .filter_map(|(ip, entry)| (entry.expires_at <= now).then_some(*ip))
            .collect::<Vec<_>>();

        for ip in &expired_ips {
            entries.remove(ip);
        }

        expired_ips
    }
}

pub fn spawn_target_store_cleanup_task(
    target_store: TransparentTargetStore,
    target_change_tx: Option<TransparentTargetChangeTx>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(TARGET_STORE_CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            let expired_ips = target_store.prune_expired(Instant::now());
            if expired_ips.is_empty() {
                continue;
            }

            tracing::info!(expired_ips = ?expired_ips, "Expired DNS target IPs were pruned");

            if let Some(target_change_tx) = target_change_tx.as_ref() {
                let _ = target_change_tx.send(());
            }
        }
    });
}

pub fn new_transparent_nat_table_v4() -> TransparentNatTableV4 {
    Arc::new(Mutex::new(HashMap::new()))
}

pub fn new_transparent_nat_table_v6() -> TransparentNatTableV6 {
    Arc::new(Mutex::new(HashMap::new()))
}

pub fn spawn_nat_cleanup_task(
    nat_table_v4: TransparentNatTableV4,
    nat_table_v6: TransparentNatTableV6,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(NAT_TABLE_CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            let now = Instant::now();
            let expired_v4 = prune_nat_table_v4(&nat_table_v4, now);
            let expired_v6 = prune_nat_table_v6(&nat_table_v6, now);
            if expired_v4 > 0 || expired_v6 > 0 {
                tracing::debug!(
                    expired_v4,
                    expired_v6,
                    "Pruned expired transparent NAT mappings"
                );
            }
        }
    });
}

pub fn upsert_nat_mapping_v4(
    nat_table: &TransparentNatTableV4,
    client_ip: Ipv4Addr,
    client_port: u16,
    destination_ip: Ipv4Addr,
    destination_port: u16,
    expires_at: Instant,
) -> bool {
    let Ok(mut nat_table) = nat_table.lock() else {
        return false;
    };

    nat_table.insert(
        (client_ip, client_port),
        TransparentNatEntryV4 {
            destination_ip,
            destination_port,
            expires_at,
        },
    );
    true
}

pub fn upsert_nat_mapping_v6(
    nat_table: &TransparentNatTableV6,
    client_ip: Ipv6Addr,
    client_port: u16,
    destination_ip: Ipv6Addr,
    destination_port: u16,
    expires_at: Instant,
) -> bool {
    let Ok(mut nat_table) = nat_table.lock() else {
        return false;
    };

    nat_table.insert(
        (client_ip, client_port),
        TransparentNatEntryV6 {
            destination_ip,
            destination_port,
            expires_at,
        },
    );
    true
}

pub fn touch_nat_mapping_v4(
    nat_table: &TransparentNatTableV4,
    client_ip: Ipv4Addr,
    client_port: u16,
    now: Instant,
    expires_at: Instant,
) -> Option<(Ipv4Addr, u16)> {
    let Ok(mut nat_table) = nat_table.lock() else {
        return None;
    };

    let key = (client_ip, client_port);
    let entry = nat_table.get_mut(&key)?;
    if entry.expires_at <= now {
        nat_table.remove(&key);
        return None;
    }

    entry.expires_at = expires_at;
    Some((entry.destination_ip, entry.destination_port))
}

pub fn touch_nat_mapping_v6(
    nat_table: &TransparentNatTableV6,
    client_ip: Ipv6Addr,
    client_port: u16,
    now: Instant,
    expires_at: Instant,
) -> Option<(Ipv6Addr, u16)> {
    let Ok(mut nat_table) = nat_table.lock() else {
        return None;
    };

    let key = (client_ip, client_port);
    let entry = nat_table.get_mut(&key)?;
    if entry.expires_at <= now {
        nat_table.remove(&key);
        return None;
    }

    entry.expires_at = expires_at;
    Some((entry.destination_ip, entry.destination_port))
}

fn prune_nat_table_v4(nat_table: &TransparentNatTableV4, now: Instant) -> usize {
    let Ok(mut nat_table) = nat_table.lock() else {
        return 0;
    };

    let before = nat_table.len();
    nat_table.retain(|_, entry| entry.expires_at > now);
    before.saturating_sub(nat_table.len())
}

fn prune_nat_table_v6(nat_table: &TransparentNatTableV6, now: Instant) -> usize {
    let Ok(mut nat_table) = nat_table.lock() else {
        return 0;
    };

    let before = nat_table.len();
    nat_table.retain(|_, entry| entry.expires_at > now);
    before.saturating_sub(nat_table.len())
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        time::{Duration, Instant},
    };

    use crate::traffic::windivert::dns::DnsResolvedTarget;

    use super::{
        new_transparent_nat_table_v4, touch_nat_mapping_v4, upsert_nat_mapping_v4,
        TransparentTargetStore,
    };

    #[test]
    fn target_store_prunes_expired_entries() {
        let now = Instant::now();
        let store = TransparentTargetStore::from_bootstrap(
            [IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))],
            now,
        );

        let dns_targets = vec![DnsResolvedTarget {
            ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
            ttl: Duration::from_secs(10),
        }];
        let inserted = store.insert_dns_targets(&dns_targets, now);
        assert_eq!(inserted, vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))]);

        let active_ips = store.snapshot_active_ips(now + Duration::from_secs(9));
        assert!(active_ips.contains(&IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))));

        let expired_ips = store.prune_expired(now + Duration::from_secs(11));
        assert_eq!(
            expired_ips,
            vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))]
        );
    }

    #[test]
    fn nat_mapping_touch_respects_expiration() {
        let now = Instant::now();
        let nat_table = new_transparent_nat_table_v4();

        assert!(upsert_nat_mapping_v4(
            &nat_table,
            Ipv4Addr::new(10, 0, 0, 2),
            50000,
            Ipv4Addr::new(203, 0, 113, 5),
            443,
            now + Duration::from_secs(30),
        ));

        let destination = touch_nat_mapping_v4(
            &nat_table,
            Ipv4Addr::new(10, 0, 0, 2),
            50000,
            now + Duration::from_secs(5),
            now + Duration::from_secs(60),
        );
        assert_eq!(destination, Some((Ipv4Addr::new(203, 0, 113, 5), 443)));

        let missing_destination = touch_nat_mapping_v4(
            &nat_table,
            Ipv4Addr::new(10, 0, 0, 2),
            50000,
            now + Duration::from_secs(61),
            now + Duration::from_secs(90),
        );
        assert!(missing_destination.is_none());
    }
}
