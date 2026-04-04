use std::net::IpAddr;

use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone)]
pub struct Rules {
    pub(crate) entries: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct RuleMatch<'a> {
    pub action: ResolvedRuleAction,
    pub rule: &'a Rule,
}

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
}

#[derive(Debug, Clone)]
pub struct HostRuleMatcher {
    pub pattern: HostPattern,
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
pub enum RuleAction {
    Mirror(UpstreamPlan),
    Direct,
    Reject(RejectRuleAction),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleActionKind {
    Mirror,
    Direct,
    Reject,
}

#[derive(Debug, Clone)]
pub enum ResolvedRuleAction {
    Mirror(UpstreamPlan),
    Direct(UpstreamPlan),
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
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    System,
    Udp,
    Dot,
    Doh,
}

#[derive(Debug, Deserialize)]
pub struct RawRule {
    #[serde(rename = "match")]
    pub matcher: RawRuleMatcher,
    pub action: RawRuleAction,
}

#[derive(Debug, Deserialize)]
pub struct RawRuleMatcher {
    pub exact: Option<String>,
    pub prefix: Option<String>,
    pub host: Option<String>,
    pub hosts: Option<Vec<String>>,
    pub host_suffix: Option<String>,
    pub scheme: Option<String>,
    pub port: Option<u16>,
    pub path_prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum RawRuleAction {
    Mirror {
        upstream: RawUpstreamPlan,
    },
    Direct,
    Reject {
        status: Option<u16>,
        message: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
pub struct RawUpstreamPlan {
    pub url: String,
    pub sni: Option<String>,
    pub host: Option<String>,
    pub connect_host: Option<String>,
    pub connect_ip: Option<IpAddr>,
    pub dns: Option<RawDnsPlan>,
}

#[derive(Debug, Deserialize)]
pub struct RawDnsPlan {
    pub mode: DnsMode,
    pub server: Option<String>,
}
