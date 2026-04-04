use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use url::Url;

use super::super::matcher::normalize_host;
use super::super::types::{HostPattern, IpPattern, Rule, RuleAction, RuleMatcher};
use super::tree::{DnsSuffixTrie, HostSuffixTrie, Ipv4CidrTrie, Ipv6CidrTrie, PrefixPathTrie};

#[derive(Debug, Clone)]
pub(super) struct RulePool {
    pub(super) exact_urls: HashMap<ExactUrlKey, Vec<usize>>,
    pub(super) prefix_origins: HashMap<OriginKey, PrefixPathTrie>,
    pub(super) exact_hosts: HashMap<String, Vec<usize>>,
    pub(super) suffix_hosts: HostSuffixTrie,
    pub(super) exact_ips: HashMap<IpAddr, Vec<usize>>,
    pub(super) ipv4_cidr_ips: Ipv4CidrTrie,
    pub(super) ipv6_cidr_ips: Ipv6CidrTrie,
    pub(super) dns_exact_hosts: HashSet<String>,
    pub(super) dns_suffix_hosts: DnsSuffixTrie,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct OriginKey {
    scheme: String,
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Eq)]
pub(super) struct ExactUrlKey {
    origin: OriginKey,
    path: String,
    query: Option<String>,
}

#[derive(Default)]
struct RuleDnsKeys {
    exact_hosts: Vec<String>,
    suffix_hosts: Vec<String>,
}

impl PartialEq for ExactUrlKey {
    fn eq(&self, other: &Self) -> bool {
        self.origin == other.origin && self.path == other.path && self.query == other.query
    }
}

impl Hash for ExactUrlKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.origin.hash(state);
        self.path.hash(state);
        self.query.hash(state);
    }
}

impl RulePool {
    pub(super) fn compile(entries: &[Rule]) -> Self {
        let mut exact_urls = HashMap::new();
        let mut prefix_origins = HashMap::new();
        let mut exact_hosts = HashMap::new();
        let mut suffix_hosts = HostSuffixTrie::default();
        let mut exact_ips = HashMap::new();
        let mut ipv4_cidr_ips = Ipv4CidrTrie::default();
        let mut ipv6_cidr_ips = Ipv6CidrTrie::default();
        let mut dns_exact_hosts = HashSet::new();
        let mut dns_suffix_hosts = DnsSuffixTrie::default();

        for (index, rule) in entries.iter().enumerate() {
            match &rule.matcher {
                RuleMatcher::ExactUrl { origin } => {
                    exact_urls
                        .entry(ExactUrlKey::from_url(origin))
                        .or_insert_with(Vec::new)
                        .push(index);
                }
                RuleMatcher::PrefixUrl { origin } => {
                    prefix_origins
                        .entry(OriginKey::from_url(origin))
                        .or_insert_with(PrefixPathTrie::default)
                        .insert(origin.path(), index);
                }
                RuleMatcher::Host(host_matcher) => match &host_matcher.pattern {
                    HostPattern::Exact(host) => {
                        exact_hosts
                            .entry(host.clone())
                            .or_insert_with(Vec::new)
                            .push(index);
                    }
                    HostPattern::AnyOf(hosts) => {
                        for host in hosts {
                            exact_hosts
                                .entry(host.clone())
                                .or_insert_with(Vec::new)
                                .push(index);
                        }
                    }
                    HostPattern::Suffix(suffix) => suffix_hosts.insert(suffix, index),
                },
                RuleMatcher::Ip(ip_matcher) => match &ip_matcher.pattern {
                    IpPattern::Exact(ip) => {
                        exact_ips.entry(*ip).or_insert_with(Vec::new).push(index);
                    }
                    IpPattern::Cidr(ipnet::IpNet::V4(cidr)) => ipv4_cidr_ips.insert(*cidr, index),
                    IpPattern::Cidr(ipnet::IpNet::V6(cidr)) => ipv6_cidr_ips.insert(*cidr, index),
                },
            }

            let dns_keys = dns_host_keys(rule);
            dns_exact_hosts.extend(dns_keys.exact_hosts);
            for suffix in dns_keys.suffix_hosts {
                dns_suffix_hosts.insert(&suffix);
            }
        }

        Self {
            exact_urls,
            prefix_origins,
            exact_hosts,
            suffix_hosts,
            exact_ips,
            ipv4_cidr_ips,
            ipv6_cidr_ips,
            dns_exact_hosts,
            dns_suffix_hosts,
        }
    }
}

impl OriginKey {
    pub(super) fn from_url(url: &Url) -> Self {
        Self {
            scheme: url.scheme().to_string(),
            host: normalize_host(url.host_str().unwrap_or_default())
                .unwrap_or_else(|_| String::new()),
            port: url.port_or_known_default().unwrap_or_default(),
        }
    }
}

impl ExactUrlKey {
    pub(super) fn from_url(url: &Url) -> Self {
        Self {
            origin: OriginKey::from_url(url),
            path: url.path().to_string(),
            query: url.query().map(str::to_string),
        }
    }
}

fn dns_host_keys(rule: &Rule) -> RuleDnsKeys {
    if matches!(rule.action, RuleAction::Direct) {
        return RuleDnsKeys::default();
    }

    match &rule.matcher {
        RuleMatcher::ExactUrl { origin } | RuleMatcher::PrefixUrl { origin } => origin
            .host_str()
            .and_then(|host| normalize_host(host).ok())
            .map(|host| RuleDnsKeys {
                exact_hosts: vec![host],
                suffix_hosts: Vec::new(),
            })
            .unwrap_or_default(),
        RuleMatcher::Host(host_matcher) => match &host_matcher.pattern {
            HostPattern::Exact(host) => RuleDnsKeys {
                exact_hosts: vec![host.clone()],
                suffix_hosts: Vec::new(),
            },
            HostPattern::AnyOf(hosts) => RuleDnsKeys {
                exact_hosts: hosts.clone(),
                suffix_hosts: Vec::new(),
            },
            HostPattern::Suffix(suffix) => RuleDnsKeys {
                exact_hosts: Vec::new(),
                suffix_hosts: vec![suffix.clone()],
            },
        },
        RuleMatcher::Ip(_) => RuleDnsKeys::default(),
    }
}
