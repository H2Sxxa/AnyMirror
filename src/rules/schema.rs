use serde::Deserialize;

use crate::rules::model::DnsMode;

#[derive(Debug, Deserialize)]
pub struct RuleSchema {
    #[serde(rename = "match")]
    pub matcher: RuleMatcherSchema,
    pub action: RuleActionSchema,
}

#[derive(Debug, Deserialize)]
pub struct RuleMatcherSchema {
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
pub enum RuleActionSchema {
    Mirror {
        upstream: UpstreamPlanSchema,
    },
    Direct,
    Plugin {
        name: String,
    },
    Reject {
        status: Option<u16>,
        message: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
pub struct UpstreamPlanSchema {
    pub url: String,
    pub sni: Option<String>,
    pub host: Option<String>,
    pub connect_host: Option<String>,
    pub connect_ip: Option<std::net::IpAddr>,
    pub dns: Option<DnsPlanSchema>,
}

#[derive(Debug, Deserialize)]
pub struct DnsPlanSchema {
    pub mode: DnsMode,
    pub server: Option<String>,
}
