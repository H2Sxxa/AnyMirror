mod compiled;
mod runtime;
mod trie;

use std::sync::Arc;

use arc_swap::ArcSwap;
use url::Url;

use self::compiled::CompiledRuleIndex;
use super::model::{RejectRuleAction, ResolvedRuleAction, Rule, RuleActionKind, UpstreamPlan};

#[derive(Debug, Clone)]
pub struct RuleSet {
    entries: Vec<Rule>,
    index: CompiledRuleIndex,
}

#[derive(Debug, Clone)]
pub struct LiveRuleSet {
    inner: Arc<ArcSwap<RuleSet>>,
}

#[derive(Debug, Clone)]
pub struct MatchedRule<'a> {
    pub action: ResolvedRuleAction,
    pub rule: &'a Rule,
}

impl RuleSet {
    pub(crate) fn new(entries: Vec<Rule>) -> Self {
        let index = CompiledRuleIndex::compile(&entries);
        Self { entries, index }
    }

    pub fn resolve(&self, original: &Url) -> Option<MatchedRule<'_>> {
        self.index.resolve(&self.entries, original)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.entries.iter()
    }

    pub fn matches_dns_host(&self, host: &str) -> bool {
        self.index.matches_dns_host(host)
    }
}

impl LiveRuleSet {
    pub fn new(rules: RuleSet) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(rules)),
        }
    }

    pub fn snapshot(&self) -> Arc<RuleSet> {
        self.inner.load_full()
    }

    pub fn replace(&self, rules: RuleSet) -> usize {
        let rule_count = rules.len();
        self.inner.store(Arc::new(rules));
        rule_count
    }

    pub fn matches_dns_host(&self, host: &str) -> bool {
        self.snapshot().matches_dns_host(host)
    }
}

impl MatchedRule<'_> {
    pub fn action_kind(&self) -> RuleActionKind {
        self.action.kind()
    }

    pub fn upstream(&self) -> Option<&UpstreamPlan> {
        self.action.upstream()
    }

    pub fn reject(&self) -> Option<&RejectRuleAction> {
        self.action.reject()
    }

    pub fn plugin(&self) -> Option<&str> {
        self.action.plugin()
    }
}

impl ResolvedRuleAction {
    pub fn kind(&self) -> RuleActionKind {
        match self {
            Self::Mirror(_) => RuleActionKind::Mirror,
            Self::Direct(_) => RuleActionKind::Direct,
            Self::Plugin(_) => RuleActionKind::Plugin,
            Self::Reject(_) => RuleActionKind::Reject,
        }
    }

    pub fn upstream(&self) -> Option<&UpstreamPlan> {
        match self {
            Self::Mirror(upstream) | Self::Direct(upstream) => Some(upstream),
            Self::Plugin(_) | Self::Reject(_) => None,
        }
    }

    pub fn reject(&self) -> Option<&RejectRuleAction> {
        match self {
            Self::Reject(reject) => Some(reject),
            Self::Mirror(_) | Self::Direct(_) | Self::Plugin(_) => None,
        }
    }

    pub fn plugin(&self) -> Option<&str> {
        match self {
            Self::Plugin(plugin) => Some(plugin.as_str()),
            Self::Mirror(_) | Self::Direct(_) | Self::Reject(_) => None,
        }
    }
}
