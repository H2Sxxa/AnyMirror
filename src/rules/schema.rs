use serde::Deserialize;

use crate::rules::types::DnsMode;

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
    pub ip: Option<std::net::IpAddr>,
    pub ip_cidr: Option<String>,
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
    pub connect_ip: Option<std::net::IpAddr>,
    pub dns: Option<RawDnsPlan>,
}

#[derive(Debug, Deserialize)]
pub struct RawDnsPlan {
    pub mode: DnsMode,
    pub server: Option<String>,
}
