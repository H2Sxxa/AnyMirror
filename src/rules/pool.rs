use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};

use url::Url;

use super::matcher::{join_paths, normalize_host, path_has_prefix, same_origin, same_url};
use super::types::{
    HostPattern, HostRuleMatcher, RejectRuleAction, ResolvedRuleAction, Rule, RuleAction,
    RuleActionKind, RuleKind, RuleMatcher, UpstreamPlan,
};

#[derive(Debug, Clone)]
pub struct Rules {
    entries: Vec<Rule>,
    pool: RulePool,
}

#[derive(Debug, Clone)]
pub struct LiveRules {
    inner: Arc<RwLock<Arc<Rules>>>,
}

#[derive(Debug, Clone)]
pub struct RuleMatch<'a> {
    pub action: ResolvedRuleAction,
    pub rule: &'a Rule,
}

#[derive(Debug, Clone)]
struct RulePool {
    exact_urls: HashMap<ExactUrlKey, Vec<usize>>,
    prefix_origins: HashMap<OriginKey, Vec<usize>>,
    exact_hosts: HashMap<String, Vec<usize>>,
    suffix_hosts: HashMap<String, Vec<usize>>,
    dns_exact_hosts: HashSet<String>,
    dns_suffix_hosts: HashSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct OriginKey {
    scheme: String,
    host: String,
    port: u16,
}

#[derive(Debug, Clone, Eq)]
struct ExactUrlKey {
    origin: OriginKey,
    path: String,
    query: Option<String>,
}

impl PartialEq for ExactUrlKey {
    fn eq(&self, other: &Self) -> bool {
        self.origin == other.origin && self.path == other.path && self.query == other.query
    }
}

impl Hash for ExactUrlKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.origin.hash(state);
        self.path.hash(state);
        self.query.hash(state);
    }
}

impl Rules {
    pub(crate) fn new(entries: Vec<Rule>) -> Self {
        let pool = RulePool::compile(&entries);
        Self { entries, pool }
    }

    pub fn resolve(&self, original: &Url) -> Option<RuleMatch<'_>> {
        self.pool.resolve(&self.entries, original)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn matches_dns_host(&self, host: &str) -> bool {
        self.pool.matches_dns_host(host)
    }
}

impl LiveRules {
    pub fn new(rules: Rules) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(rules))),
        }
    }

    pub fn snapshot(&self) -> Arc<Rules> {
        self.inner
            .read()
            .expect("live rules read lock poisoned")
            .clone()
    }

    pub fn replace(&self, rules: Rules) -> usize {
        let rule_count = rules.len();
        let mut guard = self.inner.write().expect("live rules write lock poisoned");
        *guard = Arc::new(rules);
        rule_count
    }

    pub fn matches_dns_host(&self, host: &str) -> bool {
        self.snapshot().matches_dns_host(host)
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

    fn dns_host_keys(&self) -> RuleDnsKeys {
        if matches!(self.action, RuleAction::Direct) {
            return RuleDnsKeys::default();
        }

        match &self.matcher {
            RuleMatcher::ExactUrl { origin } | RuleMatcher::PrefixUrl { origin } => origin
                .host_str()
                .and_then(|host| normalize_host(host).ok())
                .map(|host| RuleDnsKeys {
                    exact_hosts: vec![host],
                    suffix_hosts: Vec::new(),
                })
                .unwrap_or_default(),
            RuleMatcher::Host(host_matcher) => match &host_matcher.pattern {
                HostPattern::Exact(host) => RuleDnsKeys {
                    exact_hosts: vec![host.clone()],
                    suffix_hosts: Vec::new(),
                },
                HostPattern::AnyOf(hosts) => RuleDnsKeys {
                    exact_hosts: hosts.clone(),
                    suffix_hosts: Vec::new(),
                },
                HostPattern::Suffix(suffix) => RuleDnsKeys {
                    exact_hosts: Vec::new(),
                    suffix_hosts: vec![suffix.clone()],
                },
            },
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

impl RulePool {
    fn compile(entries: &[Rule]) -> Self {
        let mut exact_urls = HashMap::new();
        let mut prefix_origins = HashMap::new();
        let mut exact_hosts = HashMap::new();
        let mut suffix_hosts = HashMap::new();
        let mut dns_exact_hosts = HashSet::new();
        let mut dns_suffix_hosts = HashSet::new();

        for (index, rule) in entries.iter().enumerate() {
            match &rule.matcher {
                RuleMatcher::ExactUrl { origin } => {
                    exact_urls
                        .entry(ExactUrlKey::from_url(origin))
                        .or_insert_with(Vec::new)
                        .push(index);
                }
                RuleMatcher::PrefixUrl { origin } => {
                    prefix_origins
                        .entry(OriginKey::from_url(origin))
                        .or_insert_with(Vec::new)
                        .push(index);
                }
                RuleMatcher::Host(host_matcher) => match &host_matcher.pattern {
                    HostPattern::Exact(host) => {
                        exact_hosts
                            .entry(host.clone())
                            .or_insert_with(Vec::new)
                            .push(index);
                    }
                    HostPattern::AnyOf(hosts) => {
                        for host in hosts {
                            exact_hosts
                                .entry(host.clone())
                                .or_insert_with(Vec::new)
                                .push(index);
                        }
                    }
                    HostPattern::Suffix(suffix) => {
                        suffix_hosts
                            .entry(suffix.clone())
                            .or_insert_with(Vec::new)
                            .push(index);
                    }
                },
            }

            let dns_keys = rule.dns_host_keys();
            dns_exact_hosts.extend(dns_keys.exact_hosts);
            dns_suffix_hosts.extend(dns_keys.suffix_hosts);
        }

        Self {
            exact_urls,
            prefix_origins,
            exact_hosts,
            suffix_hosts,
            dns_exact_hosts,
            dns_suffix_hosts,
        }
    }

    fn resolve<'a>(&self, entries: &'a [Rule], original: &Url) -> Option<RuleMatch<'a>> {
        let mut candidates = BTreeSet::new();

        if let Some(indices) = self.exact_urls.get(&ExactUrlKey::from_url(original)) {
            candidates.extend(indices.iter().copied());
        }

        if let Some(indices) = self.prefix_origins.get(&OriginKey::from_url(original)) {
            candidates.extend(indices.iter().copied());
        }

        if let Some(host) = original
            .host_str()
            .and_then(|host| normalize_host(host).ok())
        {
            if let Some(indices) = self.exact_hosts.get(&host) {
                candidates.extend(indices.iter().copied());
            }

            for suffix in host_suffix_candidates(&host) {
                if let Some(indices) = self.suffix_hosts.get(suffix) {
                    candidates.extend(indices.iter().copied());
                }
            }
        }

        candidates.into_iter().find_map(|index| {
            let rule = &entries[index];
            rule.resolve(original)
                .map(|action| RuleMatch { action, rule })
        })
    }

    fn matches_dns_host(&self, host: &str) -> bool {
        let Ok(normalized_host) = normalize_host(host) else {
            return false;
        };

        if self.dns_exact_hosts.contains(&normalized_host) {
            return true;
        }

        host_suffix_candidates(&normalized_host)
            .into_iter()
            .any(|suffix| self.dns_suffix_hosts.contains(suffix))
    }
}

#[derive(Default)]
struct RuleDnsKeys {
    exact_hosts: Vec<String>,
    suffix_hosts: Vec<String>,
}

impl OriginKey {
    fn from_url(url: &Url) -> Self {
        Self {
            scheme: url.scheme().to_string(),
            host: normalize_host(url.host_str().unwrap_or_default())
                .unwrap_or_else(|_| String::new()),
            port: url.port_or_known_default().unwrap_or_default(),
        }
    }
}

impl ExactUrlKey {
    fn from_url(url: &Url) -> Self {
        Self {
            origin: OriginKey::from_url(url),
            path: url.path().to_string(),
            query: url.query().map(str::to_string),
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

fn host_suffix_candidates(host: &str) -> Vec<&str> {
    let mut suffixes = Vec::new();
    let mut current = host;
    loop {
        suffixes.push(current);
        let Some((_, rest)) = current.split_once('.') else {
            break;
        };
        current = rest;
    }
    suffixes
}
