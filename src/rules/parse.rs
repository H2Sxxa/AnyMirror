use anyhow::{ensure, Context, Result};
use url::Url;

use super::matcher::{
    normalize_host, normalize_host_suffix, normalize_path_prefix, normalize_scheme,
};
use super::types::{
    DnsPlan, HostPattern, HostRuleMatcher, RawDnsPlan, RawRule, RawRuleAction, RawRuleMatcher,
    RawUpstreamPlan, RejectRuleAction, Rule, RuleAction, RuleMatcher, Rules, UpstreamPlan,
};

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
        Rule::from_structured_rule(value)
    }
}

impl TryFrom<RawRuleMatcher> for RuleMatcher {
    type Error = anyhow::Error;

    fn try_from(value: RawRuleMatcher) -> Result<Self> {
        let RawRuleMatcher {
            exact,
            prefix,
            host,
            hosts,
            host_suffix,
            scheme,
            port,
            path_prefix,
        } = value;

        let scheme = scheme
            .as_deref()
            .map(normalize_scheme)
            .transpose()?
            .map(str::to_string);
        let path_prefix = path_prefix
            .as_deref()
            .map(normalize_path_prefix)
            .transpose()?
            .map(str::to_string);

        let exact_count = usize::from(exact.is_some())
            + usize::from(prefix.is_some())
            + usize::from(host.is_some())
            + usize::from(hosts.is_some())
            + usize::from(host_suffix.is_some());
        ensure!(
            exact_count == 1,
            "rule.match must contain exactly one of exact, prefix, host, hosts, or host_suffix"
        );

        if let Some(origin) = exact {
            ensure!(
                scheme.is_none() && port.is_none() && path_prefix.is_none(),
                "rule.match.exact cannot be combined with scheme, port, or path_prefix"
            );
            let origin = Url::parse(&origin)
                .with_context(|| format!("invalid match.exact url `{}`", origin))?;
            return Ok(Self::ExactUrl { origin });
        }

        if let Some(origin) = prefix {
            ensure!(
                scheme.is_none() && port.is_none() && path_prefix.is_none(),
                "rule.match.prefix cannot be combined with scheme, port, or path_prefix"
            );
            let origin = Url::parse(&origin)
                .with_context(|| format!("invalid match.prefix url `{}`", origin))?;
            return Ok(Self::PrefixUrl { origin });
        }

        if let Some(host) = host {
            return Ok(Self::Host(HostRuleMatcher {
                pattern: HostPattern::Exact(normalize_host(&host)?),
                scheme,
                port,
                path_prefix,
            }));
        }

        if let Some(hosts) = hosts {
            ensure!(
                !hosts.is_empty(),
                "rule.match.hosts must not be empty when provided"
            );
            let normalized_hosts = hosts
                .into_iter()
                .map(|value| normalize_host(&value))
                .collect::<Result<Vec<_>>>()?;
            return Ok(Self::Host(HostRuleMatcher {
                pattern: HostPattern::AnyOf(normalized_hosts),
                scheme,
                port,
                path_prefix,
            }));
        }

        Ok(Self::Host(HostRuleMatcher {
            pattern: HostPattern::Suffix(normalize_host_suffix(
                &host_suffix.expect("validated by exact_count"),
            )?),
            scheme,
            port,
            path_prefix,
        }))
    }
}

impl TryFrom<RawRuleAction> for RuleAction {
    type Error = anyhow::Error;

    fn try_from(value: RawRuleAction) -> Result<Self> {
        match value {
            RawRuleAction::Mirror { upstream } => {
                Ok(Self::Mirror(UpstreamPlan::try_from(upstream)?))
            }
            RawRuleAction::Direct => Ok(Self::Direct),
            RawRuleAction::Reject { status, message } => {
                let status = status.unwrap_or(403);
                ensure!(
                    (100..=599).contains(&status),
                    "reject.status must be a valid HTTP status code, got {}",
                    status
                );
                let message = message
                    .unwrap_or_else(|| "request rejected by rule".to_string())
                    .trim()
                    .to_string();
                ensure!(
                    !message.is_empty(),
                    "reject.message must not be empty when provided"
                );
                Ok(Self::Reject(RejectRuleAction { status, message }))
            }
        }
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
            super::types::DnsMode::System => ensure!(
                plan.server.is_none(),
                "dns.server must be omitted when dns.mode=system"
            ),
            super::types::DnsMode::Udp
            | super::types::DnsMode::Dot
            | super::types::DnsMode::Doh => ensure!(
                plan.server.is_some(),
                "dns.server is required when dns.mode is udp, dot, or doh"
            ),
        }

        Ok(plan)
    }
}
