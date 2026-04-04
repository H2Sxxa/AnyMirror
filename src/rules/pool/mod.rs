mod index;
mod resolve;
mod tree;

use std::sync::{Arc, RwLock};

use url::Url;

use self::index::RulePool;
use super::types::{RejectRuleAction, ResolvedRuleAction, Rule, RuleActionKind, UpstreamPlan};

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
