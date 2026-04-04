use url::Url;

use crate::rules::pool::Rules;
use crate::rules::schema::RawRule;
use crate::rules::types::{
    HostPattern, HostRuleMatcher, Rule, RuleAction, RuleActionKind, RuleKind, RuleMatcher,
    UpstreamPlan,
};

#[test]
fn rewrites_prefix_rule_from_root_path() {
    let rules = Rules::new(vec![Rule {
            kind: RuleKind::Prefix,
            matcher: RuleMatcher::PrefixUrl {
                origin: Url::parse("https://libraries.minecraft.net/").unwrap(),
            },
            action: RuleAction::Mirror(UpstreamPlan {
                url: Url::parse("https://bmclapi2.bangbang93.com/maven/").unwrap(),
                sni: None,
                host: None,
                connect_host: None,
                connect_ip: None,
                dns: None,
            }),
        }]);

    let original =
        Url::parse("https://libraries.minecraft.net/com/example/demo/1.0/demo-1.0.jar").unwrap();
    let resolved = rules.resolve(&original).unwrap();

    assert_eq!(
        resolved.upstream().unwrap().url.as_str(),
        "https://bmclapi2.bangbang93.com/maven/com/example/demo/1.0/demo-1.0.jar"
    );
}

#[test]
fn preserves_query_string_for_prefix_rules() {
    let rule = Rule {
        kind: RuleKind::Prefix,
        matcher: RuleMatcher::PrefixUrl {
            origin: Url::parse("https://resources.download.minecraft.net/").unwrap(),
        },
        action: RuleAction::Mirror(UpstreamPlan {
            url: Url::parse("https://bmclapi2.bangbang93.com/assets/").unwrap(),
            sni: None,
            host: None,
            connect_host: None,
            connect_ip: None,
            dns: None,
        }),
    };
    let original = Url::parse("https://resources.download.minecraft.net/ab/cd?download=1").unwrap();

    let resolved = rule.resolve(&original).unwrap();

    assert_eq!(
        resolved.upstream().unwrap().url.as_str(),
        "https://bmclapi2.bangbang93.com/assets/ab/cd?download=1"
    );
}

#[test]
fn exact_rule_requires_full_url_match() {
    let rule = Rule {
        kind: RuleKind::Exact,
        matcher: RuleMatcher::ExactUrl {
            origin: Url::parse("https://launchermeta.mojang.com/mc/game/version_manifest.json")
                .unwrap(),
        },
        action: RuleAction::Mirror(UpstreamPlan {
            url: Url::parse("https://bmclapi2.bangbang93.com/mc/game/version_manifest.json")
                .unwrap(),
            sni: None,
            host: None,
            connect_host: None,
            connect_ip: None,
            dns: None,
        }),
    };
    let unmatched =
        Url::parse("https://launchermeta.mojang.com/mc/game/version_manifest.json?v=2").unwrap();

    assert!(rule.resolve(&unmatched).is_none());
}

#[test]
fn structured_host_rule_rewrites_full_path() {
    let raw_rule: RawRule = serde_yaml::from_str(
        r#"
match:
  host: meta.fabricmc.net
action:
  type: mirror
  upstream:
    url: https://bmclapi2.bangbang93.com/fabric-meta/
"#,
    )
    .unwrap();
    let rules = Rules::try_from(vec![raw_rule]).unwrap();

    let original = Url::parse("https://meta.fabricmc.net/v2/versions/loader/1.20.1").unwrap();
    let resolved = rules.resolve(&original).unwrap();

    assert_eq!(
        resolved.upstream().unwrap().url.as_str(),
        "https://bmclapi2.bangbang93.com/fabric-meta/v2/versions/loader/1.20.1"
    );
    assert_eq!(resolved.rule.kind, RuleKind::Host);
    assert_eq!(resolved.action_kind(), RuleActionKind::Mirror);
}

#[test]
fn structured_host_suffix_rule_matches_dns_hosts() {
    let rules = Rules::new(vec![Rule {
            kind: RuleKind::HostSuffix,
            matcher: RuleMatcher::Host(HostRuleMatcher {
                pattern: HostPattern::Suffix("example.com".to_string()),
                scheme: None,
                port: None,
                path_prefix: None,
            }),
            action: RuleAction::Mirror(UpstreamPlan {
                url: Url::parse("https://mirror.example.com/").unwrap(),
                sni: None,
                host: None,
                connect_host: None,
                connect_ip: None,
                dns: None,
            }),
        }]);

    assert!(rules.matches_dns_host("api.example.com"));
    assert!(rules.matches_dns_host("example.com"));
    assert!(!rules.matches_dns_host("example.net"));
}

#[test]
fn direct_action_returns_original_upstream() {
    let raw_rule: RawRule = serde_yaml::from_str(
        r#"
match:
  host: download.example.com
  path_prefix: /passthrough/
action:
  type: direct
"#,
    )
    .unwrap();
    let rule = Rule::try_from(raw_rule).unwrap();
    let original = Url::parse("https://download.example.com/passthrough/file.zip").unwrap();

    let resolved = rule.resolve(&original).unwrap();

    assert_eq!(resolved.upstream().unwrap().url, original);
    assert_eq!(resolved.kind(), RuleActionKind::Direct);
}

#[test]
fn structured_prefix_rule_rewrites_like_legacy_prefix() {
    let raw_rule: RawRule = serde_yaml::from_str(
        r#"
match:
  prefix: https://libraries.minecraft.net/
action:
  type: mirror
  upstream:
    url: https://bmclapi2.bangbang93.com/maven/
"#,
    )
    .unwrap();
    let rules = Rules::try_from(vec![raw_rule]).unwrap();
    let original =
        Url::parse("https://libraries.minecraft.net/com/example/demo/1.0/demo-1.0.jar").unwrap();

    let resolved = rules.resolve(&original).unwrap();

    assert_eq!(
        resolved.upstream().unwrap().url.as_str(),
        "https://bmclapi2.bangbang93.com/maven/com/example/demo/1.0/demo-1.0.jar"
    );
    assert_eq!(resolved.rule.kind, RuleKind::Prefix);
}

#[test]
fn reject_action_returns_reject_plan() {
    let raw_rule: RawRule = serde_yaml::from_str(
        r#"
match:
  host: blocked.example.com
action:
  type: reject
  status: 451
  message: blocked for policy reasons
"#,
    )
    .unwrap();
    let rules = Rules::try_from(vec![raw_rule]).unwrap();
    let original = Url::parse("https://blocked.example.com/file.zip").unwrap();

    let resolved = rules.resolve(&original).unwrap();

    assert_eq!(resolved.action_kind(), RuleActionKind::Reject);
    assert!(resolved.upstream().is_none());
    let reject = resolved.reject().unwrap();
    assert_eq!(reject.status, 451);
    assert_eq!(reject.message, "blocked for policy reasons");
}
