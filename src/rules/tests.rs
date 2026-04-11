use axum::http::header::CONTENT_TYPE;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

use crate::rules::model::{
    HostPattern, HostRuleMatcher, RespondBodySource, Rule, RuleAction, RuleActionKind, RuleKind,
    RuleMatcher, UpstreamPlan,
};
use crate::rules::pool::RuleSet;
use crate::rules::schema::RuleSchema;

#[test]
fn rewrites_prefix_rule_from_root_path() {
    let rules = RuleSet::new(vec![Rule {
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
    let rule_schema: RuleSchema = serde_yaml::from_str(
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
    let rules = RuleSet::try_from(vec![rule_schema]).unwrap();

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
    let rules = RuleSet::new(vec![Rule {
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
    let rule_schema: RuleSchema = serde_yaml::from_str(
        r#"
match:
  host: download.example.com
  path_prefix: /passthrough/
action:
  type: direct
"#,
    )
    .unwrap();
    let rule = Rule::try_from(rule_schema).unwrap();
    let original = Url::parse("https://download.example.com/passthrough/file.zip").unwrap();

    let resolved = rule.resolve(&original).unwrap();

    assert_eq!(resolved.upstream().unwrap().url, original);
    assert_eq!(resolved.kind(), RuleActionKind::Direct);
}

#[test]
fn structured_prefix_rule_rewrites_like_legacy_prefix() {
    let rule_schema: RuleSchema = serde_yaml::from_str(
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
    let rules = RuleSet::try_from(vec![rule_schema]).unwrap();
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
fn prefix_rule_with_trailing_slash_does_not_match_parent_path() {
    let rule_schema: RuleSchema = serde_yaml::from_str(
        r#"
match:
  prefix: https://meta.fabricmc.net/v2/
action:
  type: mirror
  upstream:
    url: https://mirror.example.com/v2/
"#,
    )
    .unwrap();
    let rules = RuleSet::try_from(vec![rule_schema]).unwrap();
    let unmatched = Url::parse("https://meta.fabricmc.net/v2").unwrap();

    assert!(rules.resolve(&unmatched).is_none());
}

#[test]
fn reject_action_returns_reject_plan() {
    let rule_schema: RuleSchema = serde_yaml::from_str(
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
    let rules = RuleSet::try_from(vec![rule_schema]).unwrap();
    let original = Url::parse("https://blocked.example.com/file.zip").unwrap();

    let resolved = rules.resolve(&original).unwrap();

    assert_eq!(resolved.action_kind(), RuleActionKind::Reject);
    assert!(resolved.upstream().is_none());
    let reject = resolved.reject().unwrap();
    assert_eq!(reject.status, 451);
    assert_eq!(reject.message, "blocked for policy reasons");
}

#[test]
fn respond_action_returns_local_response_plan() {
    let rule_schema: RuleSchema = serde_yaml::from_str(
        r#"
match:
  host: api.example.com
action:
  type: respond
  status: 200
  body:
    json:
      ok: true
"#,
    )
    .unwrap();
    let rules = RuleSet::try_from(vec![rule_schema]).unwrap();
    let original = Url::parse("https://api.example.com/ping").unwrap();

    let resolved = rules.resolve(&original).unwrap();

    assert_eq!(resolved.action_kind(), RuleActionKind::Respond);
    let respond = resolved.respond().unwrap();
    assert_eq!(respond.status, 200);
    assert_eq!(
        respond.headers.get(CONTENT_TYPE).unwrap(),
        "application/json"
    );
    match &respond.body {
        RespondBodySource::Inline(body) => assert_eq!(body.as_ref(), br#"{"ok":true}"#),
        RespondBodySource::File(_) => panic!("expected inline respond body"),
    }
}

#[test]
fn respond_action_requires_single_body_source() {
    let rule_schema: RuleSchema = serde_yaml::from_str(
        r#"
match:
  host: api.example.com
action:
  type: respond
  body:
    text: hello
    base64: aGVsbG8=
"#,
    )
    .unwrap();

    let error = Rule::try_from(rule_schema).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("respond.body must contain exactly one of text, json, base64, or file")
    );
}

#[test]
fn respond_action_accepts_body_file() {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("anymirror-respond-{suffix}.txt"));
    fs::write(&path, "hello file").unwrap();

    let yaml = format!(
        r#"
match:
  host: api.example.com
action:
  type: respond
  body:
    file: {}
"#,
        path.to_string_lossy()
    );
    let rule_schema: RuleSchema = serde_yaml::from_str(&yaml).unwrap();
    let rules = RuleSet::try_from(vec![rule_schema]).unwrap();
    let original = Url::parse("https://api.example.com/file").unwrap();

    let resolved = rules.resolve(&original).unwrap();
    let respond = resolved.respond().unwrap();
    match &respond.body {
        RespondBodySource::File(file) => assert_eq!(file, &path),
        RespondBodySource::Inline(_) => panic!("expected file-backed respond body"),
    }

    fs::remove_file(path).unwrap();
}

#[test]
fn ip_rule_matches_literal_ip_requests() {
    let rule_schema: RuleSchema = serde_yaml::from_str(
        r#"
match:
  ip: 203.0.113.10
action:
  type: mirror
  upstream:
    url: https://mirror.example.com/
"#,
    )
    .unwrap();
    let rules = RuleSet::try_from(vec![rule_schema]).unwrap();
    let original = Url::parse("https://203.0.113.10/file.zip").unwrap();

    let resolved = rules.resolve(&original).unwrap();

    assert_eq!(
        resolved.upstream().unwrap().url.as_str(),
        "https://mirror.example.com/file.zip"
    );
    assert_eq!(resolved.rule.kind, RuleKind::Ip);
}

#[test]
fn ip_cidr_rule_matches_literal_ip_requests_in_range() {
    let rule_schema: RuleSchema = serde_yaml::from_str(
        r#"
match:
  ip_cidr: 203.0.113.0/24
  port: 443
action:
  type: direct
"#,
    )
    .unwrap();
    let rules = RuleSet::try_from(vec![rule_schema]).unwrap();
    let matched = Url::parse("https://203.0.113.42/index.html").unwrap();
    let unmatched = Url::parse("https://203.0.114.42/index.html").unwrap();

    assert!(rules.resolve(&matched).is_some());
    assert!(rules.resolve(&unmatched).is_none());
}
