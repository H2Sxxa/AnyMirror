use std::{
    collections::HashMap,
    hash::Hash,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use tokio::{spawn, time};

pub const NAT_ENTRY_ESTABLISHED_TTL: Duration = Duration::from_secs(300);
pub const NAT_ENTRY_CLOSING_TTL: Duration = Duration::from_secs(30);
pub const NAT_TABLE_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct TransparentNatEntry<Addr> {
    pub destination_ip: Addr,
    pub destination_port: u16,
    pub expires_at: Instant,
}

type TransparentNatKey<Addr> = (Addr, u16);
pub type TransparentNatTable<Addr> =
    Arc<Mutex<HashMap<TransparentNatKey<Addr>, TransparentNatEntry<Addr>>>>;
pub type TransparentNatTableV4 = TransparentNatTable<Ipv4Addr>;
pub type TransparentNatTableV6 = TransparentNatTable<Ipv6Addr>;

pub fn new_transparent_nat_table<Addr>() -> TransparentNatTable<Addr>
where
    Addr: Eq + Hash,
{
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
            let expired_v4 = prune_nat_table(&nat_table_v4, now);
            let expired_v6 = prune_nat_table(&nat_table_v6, now);
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

pub fn upsert_nat_mapping<Addr>(
    nat_table: &TransparentNatTable<Addr>,
    client_ip: Addr,
    client_port: u16,
    destination_ip: Addr,
    destination_port: u16,
    expires_at: Instant,
) -> bool
where
    Addr: Copy + Eq + Hash,
{
    let Ok(mut nat_table) = nat_table.lock() else {
        return false;
    };

    nat_table.insert(
        (client_ip, client_port),
        TransparentNatEntry {
            destination_ip,
            destination_port,
            expires_at,
        },
    );
    true
}

pub fn touch_nat_mapping<Addr>(
    nat_table: &TransparentNatTable<Addr>,
    client_ip: Addr,
    client_port: u16,
    now: Instant,
    expires_at: Instant,
) -> Option<(Addr, u16)>
where
    Addr: Copy + Eq + Hash,
{
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

fn prune_nat_table<Addr>(nat_table: &TransparentNatTable<Addr>, now: Instant) -> usize
where
    Addr: Eq + Hash,
{
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

    use super::{
        new_transparent_nat_table, touch_nat_mapping, upsert_nat_mapping, TransparentNatTableV4,
    };

    #[test]
    fn nat_mapping_touch_respects_expiration() {
        let now = Instant::now();
        let nat_table: TransparentNatTableV4 = new_transparent_nat_table();

        assert!(upsert_nat_mapping(
            &nat_table,
            "10.0.0.2".parse().unwrap(),
            50000,
            "203.0.113.5".parse().unwrap(),
            443,
            now + Duration::from_secs(30),
        ));

        let destination = touch_nat_mapping(
            &nat_table,
            "10.0.0.2".parse().unwrap(),
            50000,
            now + Duration::from_secs(5),
            now + Duration::from_secs(60),
        );
        assert_eq!(destination, Some(("203.0.113.5".parse().unwrap(), 443)));

        let missing_destination = touch_nat_mapping(
            &nat_table,
            "10.0.0.2".parse().unwrap(),
            50000,
            now + Duration::from_secs(61),
            now + Duration::from_secs(90),
        );
        assert!(missing_destination.is_none());
    }
}
