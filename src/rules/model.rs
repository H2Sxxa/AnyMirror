use axum::http::HeaderMap;
use bytes::Bytes;
use std::net::IpAddr;
use std::path::PathBuf;

use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone)]
pub struct Rule {
    pub kind: RuleKind,
    pub matcher: RuleMatcher,
    pub action: RuleAction,
    pub priority: RulePriority,
    pub spread: bool,
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
    Respond(RespondRuleAction),
    Plugin(String),
    Reject(RejectRuleAction),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleActionKind {
    Mirror,
    Direct,
    Respond,
    Plugin,
    Reject,
}

#[derive(Debug, Clone)]
pub enum ResolvedRuleAction {
    Mirror(UpstreamPlan),
    Direct(UpstreamPlan),
    Respond(RespondRuleAction),
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

#[derive(Debug, Clone)]
pub struct RespondRuleAction {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: RespondBodySource,
}

#[derive(Debug, Clone)]
pub enum RespondBodySource {
    Inline(Bytes),
    File(PathBuf),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RulePriority(i32);

impl RulePriority {
    pub const XLOW: Self = Self(-200);
    pub const LOW: Self = Self(-100);
    pub const MEDIUM: Self = Self(0);
    pub const HIGH: Self = Self(100);
    pub const XHIGH: Self = Self(200);

    pub fn from_value(value: i32) -> Self {
        Self(value)
    }

    pub fn value(self) -> i32 {
        self.0
    }

    pub fn semantic_name(self) -> Option<&'static str> {
        match self {
            Self::XLOW => Some("xlow"),
            Self::LOW => Some("low"),
            Self::MEDIUM => Some("medium"),
            Self::HIGH => Some("high"),
            Self::XHIGH => Some("xhigh"),
            _ => None,
        }
    }
}

impl Default for RulePriority {
    fn default() -> Self {
        Self::MEDIUM
    }
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    System,
    Udp,
    Dot,
    Doh,
}
