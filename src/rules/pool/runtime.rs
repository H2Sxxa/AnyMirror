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
use super::compiled::{CompiledRuleIndex, ExactUrlKey, OriginKey};
use super::{
    MatchedRule, RuleExplainCandidate, RuleExplainPriority, RuleExplainPriorityGroup,
    RuleExplainPropagation, RuleExplainTrace, RuleExplainWinner, resolved_action_kind_name,
    rule_action_kind_name, rule_matcher_kind_name,
};

struct LookupContext<'a> {
    exact_url_key: ExactUrlKey,
    origin_key: OriginKey,
    scheme: &'a str,
    port: Option<u16>,
    path: &'a str,
    normalized_host: Option<Cow<'a, str>>,
    ip: Option<IpAddr>,
}

enum RuleMatchExplain<'a> {
    Matched(Option<&'a str>),
    Mismatch(String),
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
        match self.matcher.explain_with_lookup(original, lookup) {
            RuleMatchExplain::Matched(path_suffix) => Some(match &self.action {
                RuleAction::Mirror(upstream) => ResolvedRuleAction::Mirror(
                    resolve_mirror_upstream(upstream, original, path_suffix),
                ),
                RuleAction::Direct => ResolvedRuleAction::Direct(UpstreamPlan::direct(original)),
                RuleAction::Respond(respond) => ResolvedRuleAction::Respond(respond.clone()),
                RuleAction::Plugin(plugin) => ResolvedRuleAction::Plugin(plugin.clone()),
                RuleAction::Reject(reject) => ResolvedRuleAction::Reject(reject.clone()),
            }),
            RuleMatchExplain::Mismatch(_) => None,
        }
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

    fn explain_with_lookup<'a>(
        &'a self,
        original: &'a Url,
        lookup: &LookupContext<'a>,
    ) -> RuleMatchExplain<'a> {
        match self {
            Self::ExactUrl { origin } => {
                if same_url(original, origin) {
                    RuleMatchExplain::Matched(None)
                } else {
                    RuleMatchExplain::Mismatch(format!(
                        "exact URL mismatch: expected `{origin}`, got `{original}`"
                    ))
                }
            }
            Self::PrefixUrl { origin } => {
                if !same_origin(original, origin) {
                    return RuleMatchExplain::Mismatch(format!(
                        "origin mismatch: expected origin `{origin}`, got `{}`",
                        original.origin().ascii_serialization()
                    ));
                }

                let origin_path = origin.path();
                let original_path = original.path();
                if !path_has_prefix(original_path, origin_path) {
                    return RuleMatchExplain::Mismatch(format!(
                        "path prefix mismatch: expected prefix `{origin_path}`, got `{original_path}`"
                    ));
                }

                let suffix = original_path
                    .strip_prefix(origin_path)
                    .or_else(|| original_path.strip_prefix('/'))
                    .unwrap_or_default();

                RuleMatchExplain::Matched(Some(suffix))
            }
            Self::Host(host_matcher) => host_matcher.explain_match(lookup),
            Self::Ip(ip_matcher) => ip_matcher.explain_match(lookup),
        }
    }
}

impl HostRuleMatcher {
    fn explain_match<'a>(&'a self, lookup: &LookupContext<'a>) -> RuleMatchExplain<'a> {
        if let Err(reason) = explain_common_lookup_parts(
            self.scheme.as_deref(),
            self.port,
            self.path_prefix.as_deref(),
            lookup,
        ) {
            return RuleMatchExplain::Mismatch(reason);
        }

        let Some(host) = lookup.normalized_host.as_deref() else {
            return RuleMatchExplain::Mismatch(
                "request URL does not contain a hostname".to_string(),
            );
        };

        let matched = match &self.pattern {
            HostPattern::Exact(expected) => {
                if expected == host {
                    true
                } else {
                    return RuleMatchExplain::Mismatch(format!(
                        "host mismatch: expected `{expected}`, got `{host}`"
                    ));
                }
            }
            HostPattern::AnyOf(expected) => {
                if expected.iter().any(|value| value == host) {
                    true
                } else {
                    return RuleMatchExplain::Mismatch(format!(
                        "host mismatch: expected one of [{}], got `{host}`",
                        expected.join(", ")
                    ));
                }
            }
            HostPattern::Suffix(expected) => {
                if host == expected
                    || host
                        .strip_suffix(expected)
                        .is_some_and(|value| value.ends_with('.'))
                {
                    true
                } else {
                    return RuleMatchExplain::Mismatch(format!(
                        "host suffix mismatch: expected suffix `{expected}`, got `{host}`"
                    ));
                }
            }
        };

        if matched {
            RuleMatchExplain::Matched(self.path_suffix(lookup))
        } else {
            unreachable!("host matcher explanation must return earlier on mismatch")
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
    fn explain_match<'a>(&'a self, lookup: &LookupContext<'a>) -> RuleMatchExplain<'a> {
        if let Err(reason) = explain_common_lookup_parts(
            self.scheme.as_deref(),
            self.port,
            self.path_prefix.as_deref(),
            lookup,
        ) {
            return RuleMatchExplain::Mismatch(reason);
        }

        let Some(original_ip) = lookup.ip else {
            return RuleMatchExplain::Mismatch(
                "request URL host is not a literal IP address".to_string(),
            );
        };

        let matched = match &self.pattern {
            IpPattern::Exact(expected) => {
                if expected == &original_ip {
                    true
                } else {
                    return RuleMatchExplain::Mismatch(format!(
                        "ip mismatch: expected `{expected}`, got `{original_ip}`"
                    ));
                }
            }
            IpPattern::Cidr(expected) => {
                if expected.contains(&original_ip) {
                    true
                } else {
                    return RuleMatchExplain::Mismatch(format!(
                        "ip cidr mismatch: expected `{expected}`, got `{original_ip}`"
                    ));
                }
            }
        };

        if matched {
            RuleMatchExplain::Matched(self.path_suffix(lookup))
        } else {
            unreachable!("ip matcher explanation must return earlier on mismatch")
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
        let mut candidate_indices = self.collect_candidate_indices(original, &lookup);
        candidate_indices
            .sort_unstable_by(|left, right| compare_candidate_order(entries, *left, *right));
        candidate_indices.dedup();

        resolve_candidates(entries, original, &lookup, &candidate_indices)
    }

    pub(super) fn explain(&self, entries: &[Rule], original: &Url) -> RuleExplainTrace {
        let lookup = LookupContext::from_url(original);
        let mut candidate_indices = self.collect_candidate_indices(original, &lookup);
        candidate_indices
            .sort_unstable_by(|left, right| compare_candidate_order(entries, *left, *right));
        candidate_indices.dedup();

        explain_candidates(entries, original, &lookup, &candidate_indices)
    }

    fn collect_candidate_indices(&self, original: &Url, lookup: &LookupContext<'_>) -> Vec<usize> {
        let mut candidate_indices = Vec::new();

        if let Some(indices) = self.exact_urls.get(&lookup.exact_url_key) {
            candidate_indices.extend_from_slice(indices);
        }

        if let Some(prefixes) = self.prefix_origins.get(&lookup.origin_key) {
            prefixes.visit_matches(original.path(), None, |index| {
                candidate_indices.push(index);
            });
        }

        if let Some(host) = lookup.normalized_host.as_deref() {
            if let Some(indices) = self.exact_hosts.get(host) {
                candidate_indices.extend_from_slice(indices);
            }

            self.suffix_hosts.visit_rule_matches(host, None, |index| {
                candidate_indices.push(index);
            });
        }

        if let Some(ip) = lookup.ip {
            if let Some(indices) = self.exact_ips.get(&ip) {
                candidate_indices.extend_from_slice(indices);
            }

            match ip {
                IpAddr::V4(ipv4) => self.ipv4_cidr_ips.visit_matches(ipv4, None, |index| {
                    candidate_indices.push(index);
                }),
                IpAddr::V6(ipv6) => self.ipv6_cidr_ips.visit_matches(ipv6, None, |index| {
                    candidate_indices.push(index);
                }),
            }
        }

        candidate_indices
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

fn resolve_candidates<'a>(
    entries: &'a [Rule],
    original: &Url,
    lookup: &LookupContext<'_>,
    candidate_indices: &[usize],
) -> Option<MatchedRule<'a>> {
    let mut propagated_match: Option<MatchedRule<'a>> = None;
    let mut active_priority = None;
    let mut priority_match: Option<MatchedRule<'a>> = None;

    for index in candidate_indices {
        let rule = &entries[*index];
        if active_priority != Some(rule.priority) {
            if let Some(matched) = priority_match.take() {
                if !matched.rule.spread {
                    return Some(matched);
                }
                propagated_match = Some(matched);
            }
            active_priority = Some(rule.priority);
        }

        if priority_match.is_some() {
            continue;
        }

        if let Some(action) = rule.resolve_with_lookup(original, lookup) {
            priority_match = Some(MatchedRule { action, rule });
        }
    }

    if let Some(matched) = priority_match {
        if !matched.rule.spread {
            return Some(matched);
        }
        propagated_match = Some(matched);
    }

    propagated_match
}

fn compare_candidate_order(entries: &[Rule], left: usize, right: usize) -> std::cmp::Ordering {
    entries[right]
        .priority
        .cmp(&entries[left].priority)
        .then_with(|| left.cmp(&right))
}

fn explain_candidates(
    entries: &[Rule],
    original: &Url,
    lookup: &LookupContext<'_>,
    candidate_indices: &[usize],
) -> RuleExplainTrace {
    let mut priority_groups = Vec::new();
    let mut current_priority = None;
    let mut current_candidates = Vec::new();
    let mut current_winner = None;
    let mut final_winner = None;

    for index in candidate_indices {
        let rule = &entries[*index];
        if current_priority != Some(rule.priority) {
            finalize_explain_group(
                &mut priority_groups,
                &mut current_priority,
                &mut current_candidates,
                &mut current_winner,
                &mut final_winner,
            );
            current_priority = Some(rule.priority);
        }

        if current_winner.is_some() {
            current_candidates.push(RuleExplainCandidate {
                rule_index: *index,
                matcher_kind: rule_matcher_kind_name(rule),
                action_kind: rule_action_kind_name(&rule.action),
                priority: RuleExplainPriority::from(rule.priority),
                spread: rule.spread,
                matched: None,
                mismatch_reason: None,
            });
            continue;
        }

        match rule.matcher.explain_with_lookup(original, lookup) {
            RuleMatchExplain::Matched(path_suffix) => {
                let action = match &rule.action {
                    RuleAction::Mirror(upstream) => ResolvedRuleAction::Mirror(
                        resolve_mirror_upstream(upstream, original, path_suffix),
                    ),
                    RuleAction::Direct => {
                        ResolvedRuleAction::Direct(UpstreamPlan::direct(original))
                    }
                    RuleAction::Respond(respond) => ResolvedRuleAction::Respond(respond.clone()),
                    RuleAction::Plugin(plugin) => ResolvedRuleAction::Plugin(plugin.clone()),
                    RuleAction::Reject(reject) => ResolvedRuleAction::Reject(reject.clone()),
                };
                current_candidates.push(RuleExplainCandidate {
                    rule_index: *index,
                    matcher_kind: rule_matcher_kind_name(rule),
                    action_kind: resolved_action_kind_name(&action),
                    priority: RuleExplainPriority::from(rule.priority),
                    spread: rule.spread,
                    matched: Some(true),
                    mismatch_reason: None,
                });
                current_winner = Some(RuleExplainWinner {
                    rule_index: *index,
                    matcher_kind: rule_matcher_kind_name(rule),
                    action_kind: resolved_action_kind_name(&action),
                    priority: RuleExplainPriority::from(rule.priority),
                    spread: rule.spread,
                    upstream_url: action.upstream().map(|upstream| upstream.url.to_string()),
                });
            }
            RuleMatchExplain::Mismatch(reason) => {
                current_candidates.push(RuleExplainCandidate {
                    rule_index: *index,
                    matcher_kind: rule_matcher_kind_name(rule),
                    action_kind: rule_action_kind_name(&rule.action),
                    priority: RuleExplainPriority::from(rule.priority),
                    spread: rule.spread,
                    matched: Some(false),
                    mismatch_reason: Some(reason),
                });
            }
        }
    }

    finalize_explain_group(
        &mut priority_groups,
        &mut current_priority,
        &mut current_candidates,
        &mut current_winner,
        &mut final_winner,
    );

    RuleExplainTrace {
        priority_groups,
        final_match: final_winner,
    }
}

fn finalize_explain_group(
    priority_groups: &mut Vec<RuleExplainPriorityGroup>,
    current_priority: &mut Option<super::super::model::RulePriority>,
    current_candidates: &mut Vec<RuleExplainCandidate>,
    current_winner: &mut Option<RuleExplainWinner>,
    final_winner: &mut Option<RuleExplainWinner>,
) {
    let Some(priority) = current_priority.take() else {
        return;
    };

    let winner = current_winner.take();
    let propagation = match winner.as_ref() {
        Some(winner) if winner.spread => {
            *final_winner = Some(winner.clone());
            RuleExplainPropagation::Continue
        }
        Some(winner) => {
            *final_winner = Some(winner.clone());
            RuleExplainPropagation::Stop
        }
        None => RuleExplainPropagation::NoMatch,
    };

    priority_groups.push(RuleExplainPriorityGroup {
        priority: RuleExplainPriority::from(priority),
        candidates: std::mem::take(current_candidates),
        winner,
        propagation,
    });
}

fn explain_common_lookup_parts(
    expected_scheme: Option<&str>,
    expected_port: Option<u16>,
    path_prefix: Option<&str>,
    lookup: &LookupContext<'_>,
) -> Result<(), String> {
    if let Some(expected_scheme) = expected_scheme {
        if lookup.scheme != expected_scheme {
            return Err(format!(
                "scheme mismatch: expected `{expected_scheme}`, got `{}`",
                lookup.scheme
            ));
        }
    }

    if let Some(expected_port) = expected_port {
        if lookup.port != Some(expected_port) {
            let actual_port = lookup
                .port
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_string());
            return Err(format!(
                "port mismatch: expected `{expected_port}`, got `{actual_port}`"
            ));
        }
    }

    if let Some(path_prefix) = path_prefix {
        if !path_has_prefix(lookup.path, path_prefix) {
            return Err(format!(
                "path prefix mismatch: expected prefix `{path_prefix}`, got `{}`",
                lookup.path
            ));
        }
    }

    Ok(())
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
