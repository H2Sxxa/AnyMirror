use anyhow::{ensure, Result};
use url::Url;

use super::matcher::{join_paths, normalize_host, path_has_prefix, same_origin, same_url};
use super::types::{
    HostPattern, HostRuleMatcher, RejectRuleAction, ResolvedRuleAction, Rule, RuleAction,
    RuleActionKind, RuleKind, RuleMatch, RuleMatcher, Rules, UpstreamPlan,
};

impl Rules {
    pub fn resolve(&self, original: &Url) -> Option<RuleMatch<'_>> {
        self.entries.iter().find_map(|rule| {
            rule.resolve(original)
                .map(|action| RuleMatch { action, rule })
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn matches_dns_host(&self, host: &str) -> bool {
        let normalized_host = normalize_host(host).ok();
        self.entries.iter().any(|rule| {
            !matches!(rule.action, RuleAction::Direct)
                && normalized_host
                    .as_deref()
                    .is_some_and(|value| rule.matches_dns_host(value))
        })
    }
}

impl RuleMatch<'_> {
    pub fn action_kind(&self) -> RuleActionKind {
        self.action.kind()
    }

    pub fn upstream(&self) -> Option<&UpstreamPlan> {
        self.action.upstream()
    }

    pub fn reject(&self) -> Option<&RejectRuleAction> {
        self.action.reject()
    }
}

impl ResolvedRuleAction {
    pub fn kind(&self) -> RuleActionKind {
        match self {
            Self::Mirror(_) => RuleActionKind::Mirror,
            Self::Direct(_) => RuleActionKind::Direct,
            Self::Reject(_) => RuleActionKind::Reject,
        }
    }

    pub fn upstream(&self) -> Option<&UpstreamPlan> {
        match self {
            Self::Mirror(upstream) | Self::Direct(upstream) => Some(upstream),
            Self::Reject(_) => None,
        }
    }

    pub fn reject(&self) -> Option<&RejectRuleAction> {
        match self {
            Self::Reject(reject) => Some(reject),
            Self::Mirror(_) | Self::Direct(_) => None,
        }
    }
}

impl Rule {
    pub(crate) fn from_structured_rule(value: super::types::RawRule) -> Result<Self> {
        let matcher = RuleMatcher::try_from(value.matcher)?;
        let action = RuleAction::try_from(value.action)?;
        Self::validate_matcher_action(&matcher, &action)?;

        Ok(Self {
            kind: matcher.kind(),
            matcher,
            action,
        })
    }

    fn validate_matcher_action(matcher: &RuleMatcher, action: &RuleAction) -> Result<()> {
        if let (RuleMatcher::PrefixUrl { origin }, RuleAction::Mirror(upstream)) = (matcher, action)
        {
            ensure!(
                origin.query().is_none() && upstream.url.query().is_none(),
                "prefix rules cannot contain query strings: `{}` -> `{}`",
                origin,
                upstream.url
            );
        }

        if let (RuleMatcher::Host(host_matcher), RuleAction::Mirror(upstream)) = (matcher, action) {
            if host_matcher.path_prefix.is_some() {
                ensure!(
                    upstream.url.query().is_none(),
                    "host rules with path_prefix cannot use upstream.url query strings: `{}`",
                    upstream.url
                );
            }
        }

        Ok(())
    }

    pub fn resolve(&self, original: &Url) -> Option<ResolvedRuleAction> {
        self.matcher
            .resolve(original)
            .map(|path_suffix| match &self.action {
                RuleAction::Mirror(upstream) => ResolvedRuleAction::Mirror(
                    resolve_mirror_upstream(upstream, original, path_suffix),
                ),
                RuleAction::Direct => ResolvedRuleAction::Direct(UpstreamPlan::direct(original)),
                RuleAction::Reject(reject) => ResolvedRuleAction::Reject(reject.clone()),
            })
    }

    fn matches_dns_host(&self, host: &str) -> bool {
        self.matcher.matches_dns_host(host)
    }
}

impl RuleMatcher {
    fn kind(&self) -> RuleKind {
        match self {
            Self::ExactUrl { .. } => RuleKind::Exact,
            Self::PrefixUrl { .. } => RuleKind::Prefix,
            Self::Host(HostRuleMatcher {
                pattern: HostPattern::Exact(_),
                ..
            }) => RuleKind::Host,
            Self::Host(HostRuleMatcher {
                pattern: HostPattern::AnyOf(_),
                ..
            }) => RuleKind::Hosts,
            Self::Host(HostRuleMatcher {
                pattern: HostPattern::Suffix(_),
                ..
            }) => RuleKind::HostSuffix,
        }
    }

    fn resolve<'a>(&'a self, original: &'a Url) -> Option<Option<&'a str>> {
        match self {
            Self::ExactUrl { origin } => same_url(original, origin).then_some(None),
            Self::PrefixUrl { origin } => {
                if !same_origin(original, origin) {
                    return None;
                }

                let origin_path = origin.path();
                let original_path = original.path();
                if !path_has_prefix(original_path, origin_path) {
                    return None;
                }

                let suffix = original_path
                    .strip_prefix(origin_path)
                    .or_else(|| original_path.strip_prefix('/'))
                    .unwrap_or_default();

                Some(Some(suffix))
            }
            Self::Host(host_matcher) => host_matcher
                .matches_url(original)
                .then_some(host_matcher.path_suffix(original)),
        }
    }

    fn matches_dns_host(&self, host: &str) -> bool {
        match self {
            Self::ExactUrl { origin } | Self::PrefixUrl { origin } => origin
                .host_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(host)),
            Self::Host(host_matcher) => host_matcher.matches_host(host),
        }
    }
}

impl HostRuleMatcher {
    fn matches_url(&self, original: &Url) -> bool {
        if let Some(expected_scheme) = self.scheme.as_deref() {
            if original.scheme() != expected_scheme {
                return false;
            }
        }

        if let Some(expected_port) = self.port {
            if original.port_or_known_default() != Some(expected_port) {
                return false;
            }
        }

        let Some(original_host) = original.host_str() else {
            return false;
        };
        let host = normalize_host(original_host).ok();
        let Some(host) = host.as_deref() else {
            return false;
        };
        if !self.matches_host(host) {
            return false;
        }

        match self.path_prefix.as_deref() {
            Some(path_prefix) => path_has_prefix(original.path(), path_prefix),
            None => true,
        }
    }

    fn matches_host(&self, host: &str) -> bool {
        match &self.pattern {
            HostPattern::Exact(expected) => expected == host,
            HostPattern::AnyOf(expected) => expected.iter().any(|value| value == host),
            HostPattern::Suffix(expected) => {
                host == expected
                    || host
                        .strip_suffix(expected)
                        .is_some_and(|value| value.ends_with('.'))
            }
        }
    }

    fn path_suffix<'a>(&'a self, original: &'a Url) -> Option<&'a str> {
        let original_path = original.path();
        Some(self.path_prefix.as_deref().map_or_else(
            || original_path.strip_prefix('/').unwrap_or_default(),
            |prefix| {
                original_path
                    .strip_prefix(prefix)
                    .or_else(|| original_path.strip_prefix('/'))
                    .unwrap_or_default()
            },
        ))
    }
}

impl UpstreamPlan {
    pub fn direct(original: &Url) -> Self {
        Self {
            url: original.clone(),
            sni: None,
            host: None,
            connect_host: None,
            connect_ip: None,
            dns: None,
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
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

fn resolve_mirror_upstream(
    upstream: &UpstreamPlan,
    original: &Url,
    path_suffix: Option<&str>,
) -> UpstreamPlan {
    let Some(path_suffix) = path_suffix else {
        return upstream.clone();
    };

    let mut resolved = upstream.clone();
    resolved
        .url
        .set_path(&join_paths(upstream.url.path(), path_suffix));
    resolved.url.set_query(original.query());
    resolved.url.set_fragment(None);
    resolved
}
