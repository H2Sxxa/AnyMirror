mod compiled;
mod runtime;
mod trie;

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::Serialize;
use url::Url;

use self::compiled::CompiledRuleIndex;
use super::model::{
    RejectRuleAction, ResolvedRuleAction, RespondRuleAction, Rule, RuleAction, RuleActionKind,
    RuleKind, RulePriority, UpstreamPlan,
};

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

#[derive(Debug, Clone, Serialize)]
pub struct RuleExplainTrace {
    pub priority_groups: Vec<RuleExplainPriorityGroup>,
    pub final_match: Option<RuleExplainWinner>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleExplainPriorityGroup {
    pub priority: RuleExplainPriority,
    pub candidates: Vec<RuleExplainCandidate>,
    pub winner: Option<RuleExplainWinner>,
    pub propagation: RuleExplainPropagation,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleExplainCandidate {
    pub rule_index: usize,
    pub matcher_kind: &'static str,
    pub action_kind: &'static str,
    pub priority: RuleExplainPriority,
    pub spread: bool,
    pub matched: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleExplainWinner {
    pub rule_index: usize,
    pub matcher_kind: &'static str,
    pub action_kind: &'static str,
    pub priority: RuleExplainPriority,
    pub spread: bool,
    pub upstream_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct RuleExplainPriority {
    pub value: i32,
    pub semantic: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuleExplainPropagation {
    NoMatch,
    Continue,
    Stop,
}

impl RuleSet {
    pub(crate) fn new(entries: Vec<Rule>) -> Self {
        let index = CompiledRuleIndex::compile(&entries);
        Self { entries, index }
    }

    pub fn resolve(&self, original: &Url) -> Option<MatchedRule<'_>> {
        self.index.resolve(&self.entries, original)
    }

    pub fn explain(&self, original: &Url) -> RuleExplainTrace {
        self.index.explain(&self.entries, original)
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

    pub fn respond(&self) -> Option<&RespondRuleAction> {
        self.action.respond()
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
            Self::Respond(_) => RuleActionKind::Respond,
            Self::Plugin(_) => RuleActionKind::Plugin,
            Self::Reject(_) => RuleActionKind::Reject,
        }
    }

    pub fn upstream(&self) -> Option<&UpstreamPlan> {
        match self {
            Self::Mirror(upstream) | Self::Direct(upstream) => Some(upstream),
            Self::Respond(_) | Self::Plugin(_) | Self::Reject(_) => None,
        }
    }

    pub fn reject(&self) -> Option<&RejectRuleAction> {
        match self {
            Self::Reject(reject) => Some(reject),
            Self::Mirror(_) | Self::Direct(_) | Self::Respond(_) | Self::Plugin(_) => None,
        }
    }

    pub fn respond(&self) -> Option<&RespondRuleAction> {
        match self {
            Self::Respond(respond) => Some(respond),
            Self::Mirror(_) | Self::Direct(_) | Self::Plugin(_) | Self::Reject(_) => None,
        }
    }

    pub fn plugin(&self) -> Option<&str> {
        match self {
            Self::Plugin(plugin) => Some(plugin.as_str()),
            Self::Mirror(_) | Self::Direct(_) | Self::Respond(_) | Self::Reject(_) => None,
        }
    }
}

impl From<RulePriority> for RuleExplainPriority {
    fn from(value: RulePriority) -> Self {
        Self {
            value: value.value(),
            semantic: value.semantic_name(),
        }
    }
}

pub(crate) fn rule_matcher_kind_name(rule: &Rule) -> &'static str {
    match rule.kind {
        RuleKind::Exact => "exact",
        RuleKind::Prefix => "prefix",
        RuleKind::Host => "host",
        RuleKind::Hosts => "hosts",
        RuleKind::HostSuffix => "host-suffix",
        RuleKind::Ip => "ip",
        RuleKind::IpCidr => "ip-cidr",
    }
}

pub(crate) fn rule_action_kind_name(action: &RuleAction) -> &'static str {
    match action {
        RuleAction::Mirror(_) => "mirror",
        RuleAction::Direct => "direct",
        RuleAction::Respond(_) => "respond",
        RuleAction::Plugin(_) => "plugin",
        RuleAction::Reject(_) => "reject",
    }
}

pub(crate) fn resolved_action_kind_name(action: &ResolvedRuleAction) -> &'static str {
    match action {
        ResolvedRuleAction::Mirror(_) => "mirror",
        ResolvedRuleAction::Direct(_) => "direct",
        ResolvedRuleAction::Respond(_) => "respond",
        ResolvedRuleAction::Plugin(_) => "plugin",
        ResolvedRuleAction::Reject(_) => "reject",
    }
}
