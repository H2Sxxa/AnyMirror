use anyhow::{Context, Result, bail};
use serde::Deserialize;
use url::Url;

#[derive(Debug, Clone)]
pub struct Rules {
    entries: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct Rewrite<'a> {
    pub target: Url,
    pub rule: &'a Rule,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub kind: RuleKind,
    pub from: Url,
    pub to: Url,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Exact,
    Prefix,
}

#[derive(Debug, Deserialize)]
pub struct RawRule {
    pub kind: Option<RuleKind>,
    pub from: String,
    pub to: String,
}

impl Rules {
    pub fn rewrite(&self, original: &Url) -> Option<Rewrite<'_>> {
        self.entries.iter().find_map(|rule| {
            rule.rewrite(original)
                .map(|target| Rewrite { target, rule })
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn target_hosts(&self) -> std::collections::HashSet<String> {
        self.entries
            .iter()
            .filter_map(|r| r.from.host_str().map(|s| s.to_string()))
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
        let from = Url::parse(&value.from)
            .with_context(|| format!("invalid from url `{}`", value.from))?;
        let to = Url::parse(&value.to).with_context(|| format!("invalid to url `{}`", value.to))?;

        let kind = value
            .kind
            .unwrap_or_else(|| infer_rule_kind(&from, &value.from));

        if matches!(kind, RuleKind::Prefix) && (from.query().is_some() || to.query().is_some()) {
            bail!(
                "prefix rules cannot contain query strings: `{}` -> `{}`",
                value.from,
                value.to
            );
        }

        Ok(Self { kind, from, to })
    }
}

impl Rule {
    pub fn rewrite(&self, original: &Url) -> Option<Url> {
        match self.kind {
            RuleKind::Exact => self.rewrite_exact(original),
            RuleKind::Prefix => self.rewrite_prefix(original),
        }
    }

    fn rewrite_exact(&self, original: &Url) -> Option<Url> {
        if same_url(original, &self.from) {
            Some(self.to.clone())
        } else {
            None
        }
    }

    fn rewrite_prefix(&self, original: &Url) -> Option<Url> {
        if !same_origin(original, &self.from) {
            return None;
        }

        let from_path = self.from.path();
        let original_path = original.path();

        if !path_has_prefix(original_path, from_path) {
            return None;
        }

        let suffix = original_path
            .strip_prefix(from_path)
            .or_else(|| original_path.strip_prefix('/'))
            .unwrap_or_default();

        let mut target = self.to.clone();
        target.set_path(&join_paths(self.to.path(), suffix));
        target.set_query(original.query());
        target.set_fragment(None);

        Some(target)
    }
}

fn infer_rule_kind(from: &Url, raw_from: &str) -> RuleKind {
    if from.path() == "/" || raw_from.ends_with('/') {
        RuleKind::Prefix
    } else {
        RuleKind::Exact
    }
}

fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn same_url(left: &Url, right: &Url) -> bool {
    same_origin(left, right) && left.path() == right.path() && left.query() == right.query()
}

fn path_has_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return true;
    }

    if !path.starts_with(prefix) {
        return false;
    }

    if prefix.ends_with('/') {
        return true;
    }

    matches!(path.as_bytes().get(prefix.len()), None | Some(b'/'))
}

fn join_paths(base: &str, suffix: &str) -> String {
    let mut result = base.trim_end_matches('/').to_string();
    let suffix = suffix.trim_start_matches('/');

    if result.is_empty() {
        result.push('/');
    }

    if !suffix.is_empty() {
        if !result.ends_with('/') {
            result.push('/');
        }
        result.push_str(suffix);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::{Rule, RuleKind, Rules};
    use url::Url;

    #[test]
    fn rewrites_prefix_rule_from_root_path() {
        let rules = Rules {
            entries: vec![Rule {
                kind: RuleKind::Prefix,
                from: Url::parse("https://libraries.minecraft.net/").unwrap(),
                to: Url::parse("https://bmclapi2.bangbang93.com/maven/").unwrap(),
            }],
        };

        let original =
            Url::parse("https://libraries.minecraft.net/com/example/demo/1.0/demo-1.0.jar")
                .unwrap();
        let rewritten = rules.rewrite(&original).unwrap().target;

        assert_eq!(
            rewritten.as_str(),
            "https://bmclapi2.bangbang93.com/maven/com/example/demo/1.0/demo-1.0.jar"
        );
    }

    #[test]
    fn preserves_query_string_for_prefix_rules() {
        let rule = Rule {
            kind: RuleKind::Prefix,
            from: Url::parse("https://resources.download.minecraft.net/").unwrap(),
            to: Url::parse("https://bmclapi2.bangbang93.com/assets/").unwrap(),
        };
        let original =
            Url::parse("https://resources.download.minecraft.net/ab/cd?download=1").unwrap();

        let rewritten = rule.rewrite(&original).unwrap();

        assert_eq!(
            rewritten.as_str(),
            "https://bmclapi2.bangbang93.com/assets/ab/cd?download=1"
        );
    }

    #[test]
    fn exact_rule_requires_full_url_match() {
        let rule = Rule {
            kind: RuleKind::Exact,
            from: Url::parse("https://launchermeta.mojang.com/mc/game/version_manifest.json")
                .unwrap(),
            to: Url::parse("https://bmclapi2.bangbang93.com/mc/game/version_manifest.json")
                .unwrap(),
        };
        let unmatched =
            Url::parse("https://launchermeta.mojang.com/mc/game/version_manifest.json?v=2")
                .unwrap();

        assert!(rule.rewrite(&unmatched).is_none());
    }
}
