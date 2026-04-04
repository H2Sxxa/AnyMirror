use std::net::IpAddr;

use url::Url;

use super::super::matcher::{join_paths, normalize_host, path_has_prefix, same_origin, same_url};
use super::super::types::{
    HostPattern, HostRuleMatcher, IpPattern, IpRuleMatcher, ResolvedRuleAction, Rule, RuleAction,
    RuleKind, RuleMatcher, UpstreamPlan,
};
use super::RuleMatch;
use super::index::{ExactUrlKey, OriginKey, RulePool};

impl Rule {
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
}

impl RuleMatcher {
    pub(crate) fn kind(&self) -> RuleKind {
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
            Self::Ip(IpRuleMatcher {
                pattern: IpPattern::Exact(_),
                ..
            }) => RuleKind::Ip,
            Self::Ip(IpRuleMatcher {
                pattern: IpPattern::Cidr(_),
                ..
            }) => RuleKind::IpCidr,
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
            Self::Ip(ip_matcher) => ip_matcher
                .matches_url(original)
                .then_some(ip_matcher.path_suffix(original)),
        }
    }
}

impl HostRuleMatcher {
    fn matches_url(&self, original: &Url) -> bool {
        if !matches_common_url_parts(
            self.scheme.as_deref(),
            self.port,
            self.path_prefix.as_deref(),
            original,
        ) {
            return false;
        }

        let Some(original_host) = original.host_str() else {
            return false;
        };
        let host = normalize_host(original_host).ok();
        let Some(host) = host.as_deref() else {
            return false;
        };

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
        Some(resolve_path_suffix(self.path_prefix.as_deref(), original))
    }
}

impl IpRuleMatcher {
    fn matches_url(&self, original: &Url) -> bool {
        if !matches_common_url_parts(
            self.scheme.as_deref(),
            self.port,
            self.path_prefix.as_deref(),
            original,
        ) {
            return false;
        }

        let Some(original_ip) = original.host_str().and_then(parse_host_ip) else {
            return false;
        };

        match &self.pattern {
            IpPattern::Exact(expected) => expected == &original_ip,
            IpPattern::Cidr(expected) => expected.contains(&original_ip),
        }
    }

    fn path_suffix<'a>(&'a self, original: &'a Url) -> Option<&'a str> {
        Some(resolve_path_suffix(self.path_prefix.as_deref(), original))
    }
}

impl RulePool {
    pub(super) fn resolve<'a>(&self, entries: &'a [Rule], original: &Url) -> Option<RuleMatch<'a>> {
        let mut best_match = None;
        let mut best_index = None;

        if let Some(indices) = self.exact_urls.get(&ExactUrlKey::from_url(original)) {
            consider_rule_indices(indices, entries, original, &mut best_match, &mut best_index);
        }

        if let Some(prefixes) = self.prefix_origins.get(&OriginKey::from_url(original)) {
            prefixes.visit_matches(original.path(), |index| {
                consider_rule_index(index, entries, original, &mut best_match, &mut best_index);
            });
        }

        if let Some(host) = original
            .host_str()
            .and_then(|host| normalize_host(host).ok())
        {
            if let Some(indices) = self.exact_hosts.get(&host) {
                consider_rule_indices(indices, entries, original, &mut best_match, &mut best_index);
            }

            self.suffix_hosts.visit_matches(&host, |index| {
                consider_rule_index(index, entries, original, &mut best_match, &mut best_index);
            });
        }

        if let Some(ip) = original.host_str().and_then(parse_host_ip) {
            if let Some(indices) = self.exact_ips.get(&ip) {
                consider_rule_indices(indices, entries, original, &mut best_match, &mut best_index);
            }

            match ip {
                IpAddr::V4(ipv4) => self.ipv4_cidr_ips.visit_matches(ipv4, |index| {
                    consider_rule_index(index, entries, original, &mut best_match, &mut best_index);
                }),
                IpAddr::V6(ipv6) => self.ipv6_cidr_ips.visit_matches(ipv6, |index| {
                    consider_rule_index(index, entries, original, &mut best_match, &mut best_index);
                }),
            }
        }

        best_match
    }

    pub(super) fn matches_dns_host(&self, host: &str) -> bool {
        let Ok(normalized_host) = normalize_host(host) else {
            return false;
        };

        self.dns_exact_hosts.contains(&normalized_host)
            || self.dns_suffix_hosts.matches(&normalized_host)
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

fn consider_rule_indices<'a>(
    indices: &[usize],
    entries: &'a [Rule],
    original: &Url,
    best_match: &mut Option<RuleMatch<'a>>,
    best_index: &mut Option<usize>,
) {
    for index in indices {
        if best_index.is_some_and(|current_best| *index >= current_best) {
            break;
        }
        consider_rule_index(*index, entries, original, best_match, best_index);
    }
}

fn consider_rule_index<'a>(
    index: usize,
    entries: &'a [Rule],
    original: &Url,
    best_match: &mut Option<RuleMatch<'a>>,
    best_index: &mut Option<usize>,
) {
    if best_index.is_some_and(|current_best| index >= current_best) {
        return;
    }

    let rule = &entries[index];
    if let Some(action) = rule.resolve(original) {
        *best_match = Some(RuleMatch { action, rule });
        *best_index = Some(index);
    }
}

fn matches_common_url_parts(
    expected_scheme: Option<&str>,
    expected_port: Option<u16>,
    path_prefix: Option<&str>,
    original: &Url,
) -> bool {
    if let Some(expected_scheme) = expected_scheme {
        if original.scheme() != expected_scheme {
            return false;
        }
    }

    if let Some(expected_port) = expected_port {
        if original.port_or_known_default() != Some(expected_port) {
            return false;
        }
    }

    match path_prefix {
        Some(path_prefix) => path_has_prefix(original.path(), path_prefix),
        None => true,
    }
}

fn resolve_path_suffix<'a>(path_prefix: Option<&str>, original: &'a Url) -> &'a str {
    let original_path = original.path();
    path_prefix.map_or_else(
        || original_path.strip_prefix('/').unwrap_or_default(),
        |prefix| {
            original_path
                .strip_prefix(prefix)
                .or_else(|| original_path.strip_prefix('/'))
                .unwrap_or_default()
        },
    )
}

fn parse_host_ip(host: &str) -> Option<IpAddr> {
    host.parse::<IpAddr>().ok()
}
