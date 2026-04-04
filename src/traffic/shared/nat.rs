use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::{spawn, time};

pub const NAT_ENTRY_ESTABLISHED_TTL: Duration = Duration::from_secs(300);
pub const NAT_ENTRY_CLOSING_TTL: Duration = Duration::from_secs(30);
pub const NAT_TABLE_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

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
    spawn(async move {
        let mut interval = time::interval(NAT_TABLE_CLEANUP_INTERVAL);
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
    use std::time::{Duration, Instant};

    use super::{new_transparent_nat_table_v4, touch_nat_mapping_v4, upsert_nat_mapping_v4};

    #[test]
    fn nat_mapping_touch_respects_expiration() {
        let now = Instant::now();
        let nat_table = new_transparent_nat_table_v4();

        assert!(upsert_nat_mapping_v4(
            &nat_table,
            "10.0.0.2".parse().unwrap(),
            50000,
            "203.0.113.5".parse().unwrap(),
            443,
            now + Duration::from_secs(30),
        ));

        let destination = touch_nat_mapping_v4(
            &nat_table,
            "10.0.0.2".parse().unwrap(),
            50000,
            now + Duration::from_secs(5),
            now + Duration::from_secs(60),
        );
        assert_eq!(destination, Some(("203.0.113.5".parse().unwrap(), 443)));

        let missing_destination = touch_nat_mapping_v4(
            &nat_table,
            "10.0.0.2".parse().unwrap(),
            50000,
            now + Duration::from_secs(61),
            now + Duration::from_secs(90),
        );
        assert!(missing_destination.is_none());
    }
}
