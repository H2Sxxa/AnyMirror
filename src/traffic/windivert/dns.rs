use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    time::Duration,
};

use hickory_proto::{
    op::{Message, MessageType, ResponseCode},
    rr::RData,
};

/// Parse DNS response and extract resolved IPs matching origin_hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResolvedTarget {
    pub ip: IpAddr,
    pub ttl: Duration,
}

pub fn parse_dns_response(
    payload: &[u8],
    origin_hosts: &HashSet<String>,
) -> Option<Vec<DnsResolvedTarget>> {
    let message = Message::from_vec(payload).ok()?;
    if message.message_type() != MessageType::Response {
        return None;
    }
    if message.response_code() != ResponseCode::NoError {
        return None;
    }

    let normalized_origin_hosts = origin_hosts
        .iter()
        .map(|host| normalize_dns_name(host))
        .collect::<HashSet<_>>();

    let mut alias_map = HashMap::new();
    let mut owner_ips = HashMap::new();

    for answer in message.answers() {
        let owner_name = normalize_dns_name(&answer.name().to_utf8());
        let ttl = Duration::from_secs(answer.ttl().into());
        match answer.data() {
            RData::A(record) => {
                owner_ips
                    .entry(owner_name)
                    .or_insert_with(Vec::new)
                    .push(DnsResolvedTarget {
                        ip: IpAddr::V4(record.0),
                        ttl,
                    });
            }
            RData::AAAA(record) => {
                owner_ips
                    .entry(owner_name)
                    .or_insert_with(Vec::new)
                    .push(DnsResolvedTarget {
                        ip: IpAddr::V6(record.0),
                        ttl,
                    });
            }
            RData::CNAME(record) => {
                alias_map.insert(owner_name, (normalize_dns_name(&record.to_utf8()), ttl));
            }
            _ => {}
        }
    }

    let mut seed_names = message
        .queries()
        .iter()
        .map(|query| normalize_dns_name(&query.name().to_utf8()))
        .filter(|name| matches_origin_host(name, &normalized_origin_hosts))
        .collect::<Vec<_>>();

    seed_names.extend(
        owner_ips
            .keys()
            .filter(|name| matches_origin_host(name, &normalized_origin_hosts))
            .cloned(),
    );
    seed_names.extend(
        alias_map
            .keys()
            .filter(|name| matches_origin_host(name, &normalized_origin_hosts))
            .cloned(),
    );

    let mut resolved_targets = HashMap::<IpAddr, Duration>::new();
    for seed_name in seed_names {
        let mut current_name = seed_name;
        let mut visited_names = HashSet::new();
        let mut inherited_ttl = None;

        loop {
            if !visited_names.insert(current_name.clone()) {
                break;
            }

            if let Some(targets) = owner_ips.get(&current_name) {
                for target in targets {
                    let effective_ttl = inherited_ttl
                        .map(|ttl: Duration| ttl.min(target.ttl))
                        .unwrap_or(target.ttl);
                    resolved_targets
                        .entry(target.ip)
                        .and_modify(|ttl| {
                            if effective_ttl > *ttl {
                                *ttl = effective_ttl;
                            }
                        })
                        .or_insert(effective_ttl);
                }
            }

            let Some((next_name, cname_ttl)) = alias_map.get(&current_name) else {
                break;
            };
            inherited_ttl = Some(
                inherited_ttl
                    .map(|ttl: Duration| ttl.min(*cname_ttl))
                    .unwrap_or(*cname_ttl),
            );
            current_name = next_name.clone();
        }
    }

    if resolved_targets.is_empty() {
        None
    } else {
        Some(
            resolved_targets
                .into_iter()
                .map(|(ip, ttl)| DnsResolvedTarget { ip, ttl })
                .collect(),
        )
    }
}

fn normalize_dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn matches_origin_host(name: &str, origin_hosts: &HashSet<String>) -> bool {
    origin_hosts.iter().any(|origin_host| {
        name == origin_host
            || name
                .strip_suffix(origin_host)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use std::{
        collections::HashSet,
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME};
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    use super::{parse_dns_response, DnsResolvedTarget};

    #[test]
    fn parses_direct_a_and_aaaa_answers() {
        let payload = Message::new()
            .set_message_type(MessageType::Response)
            .set_response_code(ResponseCode::NoError)
            .add_query(Query::query(
                Name::from_ascii("example.com.").unwrap(),
                RecordType::A,
            ))
            .add_answer(Record::from_rdata(
                Name::from_ascii("example.com.").unwrap(),
                60,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 10))),
            ))
            .add_answer(Record::from_rdata(
                Name::from_ascii("example.com.").unwrap(),
                60,
                RData::AAAA(AAAA(Ipv6Addr::from_str("2001:db8::10").unwrap())),
            ))
            .to_vec()
            .unwrap();

        let origin_hosts = HashSet::from([String::from("example.com")]);
        let resolved_ips = parse_dns_response(&payload, &origin_hosts).unwrap();

        assert!(resolved_ips.contains(&DnsResolvedTarget {
            ip: std::net::IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            ttl: Duration::from_secs(60),
        }));
        assert!(resolved_ips.contains(&DnsResolvedTarget {
            ip: std::net::IpAddr::V6(Ipv6Addr::from_str("2001:db8::10").unwrap()),
            ttl: Duration::from_secs(60),
        }));
    }

    #[test]
    fn follows_cname_chains_for_matching_queries() {
        let payload = Message::new()
            .set_message_type(MessageType::Response)
            .set_response_code(ResponseCode::NoError)
            .add_query(Query::query(
                Name::from_ascii("assets.example.com.").unwrap(),
                RecordType::A,
            ))
            .add_answer(Record::from_rdata(
                Name::from_ascii("assets.example.com.").unwrap(),
                60,
                RData::CNAME(CNAME(Name::from_ascii("edge.example.net.").unwrap())),
            ))
            .add_answer(Record::from_rdata(
                Name::from_ascii("edge.example.net.").unwrap(),
                60,
                RData::A(A(Ipv4Addr::new(198, 51, 100, 42))),
            ))
            .to_vec()
            .unwrap();

        let origin_hosts = HashSet::from([String::from("example.com")]);
        let resolved_ips = parse_dns_response(&payload, &origin_hosts).unwrap();

        assert_eq!(
            resolved_ips,
            vec![DnsResolvedTarget {
                ip: std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)),
                ttl: Duration::from_secs(60),
            }]
        );
    }
}
