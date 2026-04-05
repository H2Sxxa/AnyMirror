use std::borrow::Cow;
use std::net::IpAddr;

use url::Url;

use super::super::matching::{
    join_paths, normalize_host_cow, path_has_prefix, same_origin, same_url,
};
use super::super::model::{
    HostPattern, HostRuleMatcher, IpPattern, IpRuleMatcher, ResolvedRuleAction, Rule, RuleAction,
    RuleKind, RuleMatcher, UpstreamPlan,
};
use super::MatchedRule;
use super::compiled::{CompiledRuleIndex, ExactUrlKey, OriginKey};

struct LookupContext<'a> {
    exact_url_key: ExactUrlKey,
    origin_key: OriginKey,
    scheme: &'a str,
    port: Option<u16>,
    path: &'a str,
    normalized_host: Option<Cow<'a, str>>,
    ip: Option<IpAddr>,
}

impl Rule {
    #[cfg(test)]
    pub fn resolve(&self, original: &Url) -> Option<ResolvedRuleAction> {
        let lookup = LookupContext::from_url(original);
        self.resolve_with_lookup(original, &lookup)
    }

    fn resolve_with_lookup(
        &self,
        original: &Url,
        lookup: &LookupContext<'_>,
    ) -> Option<ResolvedRuleAction> {
        self.matcher
            .resolve_with_lookup(original, lookup)
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

    fn resolve_with_lookup<'a>(
        &'a self,
        original: &'a Url,
        lookup: &LookupContext<'a>,
    ) -> Option<Option<&'a str>> {
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
                .matches_lookup(lookup)
                .then_some(host_matcher.path_suffix(lookup)),
            Self::Ip(ip_matcher) => ip_matcher
                .matches_lookup(lookup)
                .then_some(ip_matcher.path_suffix(lookup)),
        }
    }
}

impl HostRuleMatcher {
    fn matches_lookup(&self, lookup: &LookupContext<'_>) -> bool {
        if !matches_common_lookup_parts(
            self.scheme.as_deref(),
            self.port,
            self.path_prefix.as_deref(),
            lookup,
        ) {
            return false;
        }

        let Some(host) = lookup.normalized_host.as_deref() else {
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

    fn path_suffix<'a>(&'a self, lookup: &LookupContext<'a>) -> Option<&'a str> {
        Some(resolve_path_suffix(
            self.path_prefix.as_deref(),
            lookup.path,
        ))
    }
}

impl IpRuleMatcher {
    fn matches_lookup(&self, lookup: &LookupContext<'_>) -> bool {
        if !matches_common_lookup_parts(
            self.scheme.as_deref(),
            self.port,
            self.path_prefix.as_deref(),
            lookup,
        ) {
            return false;
        }

        let Some(original_ip) = lookup.ip else {
            return false;
        };

        match &self.pattern {
            IpPattern::Exact(expected) => expected == &original_ip,
            IpPattern::Cidr(expected) => expected.contains(&original_ip),
        }
    }

    fn path_suffix<'a>(&'a self, lookup: &LookupContext<'a>) -> Option<&'a str> {
        Some(resolve_path_suffix(
            self.path_prefix.as_deref(),
            lookup.path,
        ))
    }
}

impl CompiledRuleIndex {
    pub(super) fn resolve<'rules, 'url>(
        &self,
        entries: &'rules [Rule],
        original: &'url Url,
    ) -> Option<MatchedRule<'rules>> {
        let lookup = LookupContext::from_url(original);
        let mut best_match = None;
        let mut best_index = None;

        if let Some(indices) = self.exact_urls.get(&lookup.exact_url_key) {
            consider_rule_indices(
                indices,
                entries,
                original,
                &lookup,
                &mut best_match,
                &mut best_index,
            );
        }

        if let Some(prefixes) = self.prefix_origins.get(&lookup.origin_key) {
            prefixes.visit_matches(original.path(), best_index, |index| {
                consider_rule_index(
                    index,
                    entries,
                    original,
                    &lookup,
                    &mut best_match,
                    &mut best_index,
                );
            });
        }

        if let Some(host) = lookup.normalized_host.as_deref() {
            if let Some(indices) = self.exact_hosts.get(host) {
                consider_rule_indices(
                    indices,
                    entries,
                    original,
                    &lookup,
                    &mut best_match,
                    &mut best_index,
                );
            }

            self.suffix_hosts
                .visit_rule_matches(host, best_index, |index| {
                    consider_rule_index(
                        index,
                        entries,
                        original,
                        &lookup,
                        &mut best_match,
                        &mut best_index,
                    );
                });
        }

        if let Some(ip) = lookup.ip {
            if let Some(indices) = self.exact_ips.get(&ip) {
                consider_rule_indices(
                    indices,
                    entries,
                    original,
                    &lookup,
                    &mut best_match,
                    &mut best_index,
                );
            }

            match ip {
                IpAddr::V4(ipv4) => self.ipv4_cidr_ips.visit_matches(ipv4, best_index, |index| {
                    consider_rule_index(
                        index,
                        entries,
                        original,
                        &lookup,
                        &mut best_match,
                        &mut best_index,
                    );
                }),
                IpAddr::V6(ipv6) => self.ipv6_cidr_ips.visit_matches(ipv6, best_index, |index| {
                    consider_rule_index(
                        index,
                        entries,
                        original,
                        &lookup,
                        &mut best_match,
                        &mut best_index,
                    );
                }),
            }
        }

        best_match
    }

    pub(super) fn matches_dns_host(&self, host: &str) -> bool {
        let Ok(normalized_host) = normalize_host_cow(host) else {
            return false;
        };

        self.dns_exact_hosts.contains(normalized_host.as_ref())
            || self.suffix_hosts.matches(normalized_host.as_ref())
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
    lookup: &LookupContext<'_>,
    best_match: &mut Option<MatchedRule<'a>>,
    best_index: &mut Option<usize>,
) {
    for index in indices {
        if best_index.is_some_and(|current_best| *index >= current_best) {
            break;
        }
        consider_rule_index(*index, entries, original, lookup, best_match, best_index);
    }
}

fn consider_rule_index<'a>(
    index: usize,
    entries: &'a [Rule],
    original: &Url,
    lookup: &LookupContext<'_>,
    best_match: &mut Option<MatchedRule<'a>>,
    best_index: &mut Option<usize>,
) {
    if best_index.is_some_and(|current_best| index >= current_best) {
        return;
    }

    let rule = &entries[index];
    if let Some(action) = rule.resolve_with_lookup(original, lookup) {
        *best_match = Some(MatchedRule { action, rule });
        *best_index = Some(index);
    }
}

fn matches_common_lookup_parts(
    expected_scheme: Option<&str>,
    expected_port: Option<u16>,
    path_prefix: Option<&str>,
    lookup: &LookupContext<'_>,
) -> bool {
    if let Some(expected_scheme) = expected_scheme {
        if lookup.scheme != expected_scheme {
            return false;
        }
    }

    if let Some(expected_port) = expected_port {
        if lookup.port != Some(expected_port) {
            return false;
        }
    }

    match path_prefix {
        Some(path_prefix) => path_has_prefix(lookup.path, path_prefix),
        None => true,
    }
}

fn resolve_path_suffix<'a>(path_prefix: Option<&str>, original_path: &'a str) -> &'a str {
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

impl LookupContext<'_> {
    fn from_url<'a>(original: &'a Url) -> LookupContext<'a> {
        let host = original.host_str();
        LookupContext {
            exact_url_key: ExactUrlKey::from_url(original),
            origin_key: OriginKey::from_url(original),
            scheme: original.scheme(),
            port: original.port_or_known_default(),
            path: original.path(),
            normalized_host: host.and_then(|value| normalize_host_cow(value).ok()),
            ip: host.and_then(parse_host_ip),
        }
    }
}
