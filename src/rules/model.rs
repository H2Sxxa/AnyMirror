use std::net::IpAddr;

use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone)]
pub struct Rule {
    pub kind: RuleKind,
    pub matcher: RuleMatcher,
    pub action: RuleAction,
}

#[derive(Debug, Clone)]
pub enum RuleMatcher {
    ExactUrl { origin: Url },
    PrefixUrl { origin: Url },
    Host(HostRuleMatcher),
    Ip(IpRuleMatcher),
}

#[derive(Debug, Clone)]
pub struct HostRuleMatcher {
    pub pattern: HostPattern,
    pub scheme: Option<String>,
    pub port: Option<u16>,
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone)]
pub struct IpRuleMatcher {
    pub pattern: IpPattern,
    pub scheme: Option<String>,
    pub port: Option<u16>,
    pub path_prefix: Option<String>,
}

#[derive(Debug, Clone)]
pub enum HostPattern {
    Exact(String),
    AnyOf(Vec<String>),
    Suffix(String),
}

#[derive(Debug, Clone)]
pub enum IpPattern {
    Exact(IpAddr),
    Cidr(IpNet),
}

#[derive(Debug, Clone)]
pub enum RuleAction {
    Mirror(UpstreamPlan),
    Direct,
    Plugin(String),
    Reject(RejectRuleAction),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleActionKind {
    Mirror,
    Direct,
    Plugin,
    Reject,
}

#[derive(Debug, Clone)]
pub enum ResolvedRuleAction {
    Mirror(UpstreamPlan),
    Direct(UpstreamPlan),
    Plugin(String),
    Reject(RejectRuleAction),
}

#[derive(Debug, Clone)]
pub struct UpstreamPlan {
    pub url: Url,
    pub sni: Option<String>,
    pub host: Option<String>,
    pub connect_host: Option<String>,
    pub connect_ip: Option<IpAddr>,
    pub dns: Option<DnsPlan>,
}

#[derive(Debug, Clone)]
pub struct DnsPlan {
    pub mode: DnsMode,
    pub server: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RejectRuleAction {
    pub status: u16,
    pub message: String,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleKind {
    Exact,
    Prefix,
    Host,
    Hosts,
    HostSuffix,
    Ip,
    IpCidr,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    System,
    Udp,
    Dot,
    Doh,
}
