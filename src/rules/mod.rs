mod matcher;

use std::{collections::HashSet, net::IpAddr};

use anyhow::{bail, ensure, Context, Result};
use serde::Deserialize;
use url::Url;

use self::matcher::{infer_rule_kind, join_paths, path_has_prefix, same_origin, same_url};

#[derive(Debug, Clone)]
pub struct Rules {
    entries: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct RuleMatch<'a> {
    pub upstream: UpstreamPlan,
    pub rule: &'a Rule,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub kind: RuleKind,
    pub origin: Url,
    pub upstream: UpstreamPlan,
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

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Exact,
    Prefix,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsMode {
    System,
    Udp,
    Doh,
}

#[derive(Debug, Deserialize)]
pub struct RawRule {
    pub kind: Option<RuleKind>,
    pub origin: String,
    pub upstream: RawUpstreamPlan,
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

impl Rules {
    pub fn resolve(&self, original: &Url) -> Option<RuleMatch<'_>> {
        self.entries.iter().find_map(|rule| {
            rule.resolve(original)
                .map(|upstream| RuleMatch { upstream, rule })
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn origin_hosts(&self) -> HashSet<String> {
        self.entries
            .iter()
            .filter_map(|rule| rule.origin.host_str().map(|value| value.to_string()))
            .collect()
    }
}

impl TryFrom<Vec<RawRule>> for Rules {
    type Error = anyhow::Error;

    fn try_from(value: Vec<RawRule>) -> Result<Self> {
        let mut entries = Vec::with_capacity(value.len());
        for raw_rule in value {
            entries.push(Rule::try_from(raw_rule)?);
        }
        Ok(Self { entries })
    }
}

impl TryFrom<RawRule> for Rule {
    type Error = anyhow::Error;

    fn try_from(value: RawRule) -> Result<Self> {
        let origin = Url::parse(&value.origin)
            .with_context(|| format!("invalid origin url `{}`", value.origin))?;
        let kind = value
            .kind
            .unwrap_or_else(|| infer_rule_kind(&origin, &value.origin));
        let upstream = UpstreamPlan::try_from(value.upstream)?;

        if matches!(kind, RuleKind::Prefix)
            && (origin.query().is_some() || upstream.url.query().is_some())
        {
            bail!(
                "prefix rules cannot contain query strings: `{}` -> `{}`",
                origin,
                upstream.url
            );
        }

        Ok(Self {
            kind,
            origin,
            upstream,
        })
    }
}

impl TryFrom<RawUpstreamPlan> for UpstreamPlan {
    type Error = anyhow::Error;

    fn try_from(value: RawUpstreamPlan) -> Result<Self> {
        let url = Url::parse(&value.url)
            .with_context(|| format!("invalid upstream url `{}`", value.url))?;
        let plan = Self {
            url,
            sni: value.sni.filter(|value| !value.is_empty()),
            host: value.host.filter(|value| !value.is_empty()),
            connect_host: value.connect_host.filter(|value| !value.is_empty()),
            connect_ip: value.connect_ip,
            dns: value.dns.map(DnsPlan::try_from).transpose()?,
        };

        plan.validate()?;
        Ok(plan)
    }
}

impl TryFrom<RawDnsPlan> for DnsPlan {
    type Error = anyhow::Error;

    fn try_from(value: RawDnsPlan) -> Result<Self> {
        let plan = Self {
            mode: value.mode,
            server: value.server.filter(|value| !value.is_empty()),
        };

        match plan.mode {
            DnsMode::System => ensure!(
                plan.server.is_none(),
                "dns.server must be omitted when dns.mode=system"
            ),
            DnsMode::Udp | DnsMode::Doh => ensure!(
                plan.server.is_some(),
                "dns.server is required when dns.mode is udp or doh"
            ),
        }

        Ok(plan)
    }
}

impl UpstreamPlan {
    fn validate(&self) -> Result<()> {
        ensure!(
            !(self.connect_host.is_some() && self.connect_ip.is_some()),
            "upstream.connect_host and upstream.connect_ip are mutually exclusive"
        );
        ensure!(
            !(self.connect_ip.is_some() && self.dns.is_some()),
            "upstream.dns cannot be used together with upstream.connect_ip"
        );
        Ok(())
    }
}

impl Rule {
    pub fn resolve(&self, original: &Url) -> Option<UpstreamPlan> {
        match self.kind {
            RuleKind::Exact => self.resolve_exact(original),
            RuleKind::Prefix => self.resolve_prefix(original),
        }
    }

    fn resolve_exact(&self, original: &Url) -> Option<UpstreamPlan> {
        if same_url(original, &self.origin) {
            Some(self.upstream.clone())
        } else {
            None
        }
    }

    fn resolve_prefix(&self, original: &Url) -> Option<UpstreamPlan> {
        if !same_origin(original, &self.origin) {
            return None;
        }

        let origin_path = self.origin.path();
        let original_path = original.path();

        if !path_has_prefix(original_path, origin_path) {
            return None;
        }

        let suffix = original_path
            .strip_prefix(origin_path)
            .or_else(|| original_path.strip_prefix('/'))
            .unwrap_or_default();

        let mut upstream = self.upstream.clone();
        upstream
            .url
            .set_path(&join_paths(self.upstream.url.path(), suffix));
        upstream.url.set_query(original.query());
        upstream.url.set_fragment(None);

        Some(upstream)
    }
}

#[cfg(test)]
mod tests {
    use super::{Rule, RuleKind, Rules, UpstreamPlan};
    use url::Url;

    #[test]
    fn rewrites_prefix_rule_from_root_path() {
        let rules = Rules {
            entries: vec![Rule {
                kind: RuleKind::Prefix,
                origin: Url::parse("https://libraries.minecraft.net/").unwrap(),
                upstream: UpstreamPlan {
                    url: Url::parse("https://bmclapi2.bangbang93.com/maven/").unwrap(),
                    sni: None,
                    host: None,
                    connect_host: None,
                    connect_ip: None,
                    dns: None,
                },
            }],
        };

        let original =
            Url::parse("https://libraries.minecraft.net/com/example/demo/1.0/demo-1.0.jar")
                .unwrap();
        let resolved = rules.resolve(&original).unwrap();

        assert_eq!(
            resolved.upstream.url.as_str(),
            "https://bmclapi2.bangbang93.com/maven/com/example/demo/1.0/demo-1.0.jar"
        );
    }

    #[test]
    fn preserves_query_string_for_prefix_rules() {
        let rule = Rule {
            kind: RuleKind::Prefix,
            origin: Url::parse("https://resources.download.minecraft.net/").unwrap(),
            upstream: UpstreamPlan {
                url: Url::parse("https://bmclapi2.bangbang93.com/assets/").unwrap(),
                sni: None,
                host: None,
                connect_host: None,
                connect_ip: None,
                dns: None,
            },
        };
        let original =
            Url::parse("https://resources.download.minecraft.net/ab/cd?download=1").unwrap();

        let resolved = rule.resolve(&original).unwrap();

        assert_eq!(
            resolved.url.as_str(),
            "https://bmclapi2.bangbang93.com/assets/ab/cd?download=1"
        );
    }

    #[test]
    fn exact_rule_requires_full_url_match() {
        let rule = Rule {
            kind: RuleKind::Exact,
            origin: Url::parse("https://launchermeta.mojang.com/mc/game/version_manifest.json")
                .unwrap(),
            upstream: UpstreamPlan {
                url: Url::parse("https://bmclapi2.bangbang93.com/mc/game/version_manifest.json")
                    .unwrap(),
                sni: None,
                host: None,
                connect_host: None,
                connect_ip: None,
                dns: None,
            },
        };
        let unmatched =
            Url::parse("https://launchermeta.mojang.com/mc/game/version_manifest.json?v=2")
                .unwrap();

        assert!(rule.resolve(&unmatched).is_none());
    }
}
