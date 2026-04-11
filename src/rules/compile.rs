use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use axum::http::{
    HeaderMap, HeaderName, HeaderValue,
    header::{CONTENT_LENGTH, CONTENT_TYPE},
};
use base64::Engine as _;
use bytes::Bytes;
use ipnet::IpNet;
use url::Url;

use super::matching::{
    normalize_host, normalize_host_suffix, normalize_path_prefix, normalize_scheme,
};
use super::model::{
    DnsMode, DnsPlan, HostPattern, HostRuleMatcher, IpPattern, IpRuleMatcher, RejectRuleAction,
    RespondBodySource, RespondRuleAction, Rule, RuleAction, RuleMatcher, UpstreamPlan,
};
use super::pool::RuleSet;
use super::schema::{
    DnsPlanSchema, RespondBodySchema, RuleActionSchema, RuleMatcherSchema, RuleSchema,
    UpstreamPlanSchema,
};

impl TryFrom<Vec<RuleSchema>> for RuleSet {
    type Error = anyhow::Error;

    fn try_from(value: Vec<RuleSchema>) -> Result<Self> {
        let mut entries = Vec::with_capacity(value.len());
        for rule_schema in value {
            entries.push(Rule::try_from(rule_schema)?);
        }
        Ok(Self::new(entries))
    }
}

impl TryFrom<RuleSchema> for Rule {
    type Error = anyhow::Error;

    fn try_from(value: RuleSchema) -> Result<Self> {
        let matcher = RuleMatcher::try_from(value.matcher)?;
        let action = RuleAction::try_from(value.action)?;
        Rule::validate_matcher_action(&matcher, &action)?;

        Ok(Self {
            kind: matcher.kind(),
            matcher,
            action,
        })
    }
}

impl TryFrom<RuleMatcherSchema> for RuleMatcher {
    type Error = anyhow::Error;

    fn try_from(value: RuleMatcherSchema) -> Result<Self> {
        let RuleMatcherSchema {
            exact,
            prefix,
            host,
            hosts,
            host_suffix,
            ip,
            ip_cidr,
            scheme,
            port,
            path_prefix,
        } = value;

        let scheme = scheme
            .as_deref()
            .map(normalize_scheme)
            .transpose()?
            .map(str::to_string);
        let path_prefix = path_prefix
            .as_deref()
            .map(normalize_path_prefix)
            .transpose()?
            .map(str::to_string);

        let exact_count = usize::from(exact.is_some())
            + usize::from(prefix.is_some())
            + usize::from(host.is_some())
            + usize::from(hosts.is_some())
            + usize::from(host_suffix.is_some())
            + usize::from(ip.is_some())
            + usize::from(ip_cidr.is_some());
        ensure!(
            exact_count == 1,
            "rule.match must contain exactly one of exact, prefix, host, hosts, host_suffix, ip, or ip_cidr"
        );

        if let Some(origin) = exact {
            ensure!(
                scheme.is_none() && port.is_none() && path_prefix.is_none(),
                "rule.match.exact cannot be combined with scheme, port, or path_prefix"
            );
            let origin = Url::parse(&origin)
                .with_context(|| format!("invalid match.exact url `{}`", origin))?;
            return Ok(Self::ExactUrl { origin });
        }

        if let Some(origin) = prefix {
            ensure!(
                scheme.is_none() && port.is_none() && path_prefix.is_none(),
                "rule.match.prefix cannot be combined with scheme, port, or path_prefix"
            );
            let origin = Url::parse(&origin)
                .with_context(|| format!("invalid match.prefix url `{}`", origin))?;
            return Ok(Self::PrefixUrl { origin });
        }

        if let Some(host) = host {
            return Ok(Self::Host(HostRuleMatcher {
                pattern: HostPattern::Exact(normalize_host(&host)?),
                scheme,
                port,
                path_prefix,
            }));
        }

        if let Some(hosts) = hosts {
            ensure!(
                !hosts.is_empty(),
                "rule.match.hosts must not be empty when provided"
            );
            let normalized_hosts = hosts
                .into_iter()
                .map(|value| normalize_host(&value))
                .collect::<Result<Vec<_>>>()?;
            return Ok(Self::Host(HostRuleMatcher {
                pattern: HostPattern::AnyOf(normalized_hosts),
                scheme,
                port,
                path_prefix,
            }));
        }

        if let Some(ip) = ip {
            return Ok(Self::Ip(IpRuleMatcher {
                pattern: IpPattern::Exact(ip),
                scheme,
                port,
                path_prefix,
            }));
        }

        if let Some(ip_cidr) = ip_cidr {
            let cidr = ip_cidr
                .parse::<IpNet>()
                .with_context(|| format!("invalid match.ip_cidr `{}`", ip_cidr))?;
            return Ok(Self::Ip(IpRuleMatcher {
                pattern: IpPattern::Cidr(cidr),
                scheme,
                port,
                path_prefix,
            }));
        }

        Ok(Self::Host(HostRuleMatcher {
            pattern: HostPattern::Suffix(normalize_host_suffix(
                &host_suffix.expect("validated by exact_count"),
            )?),
            scheme,
            port,
            path_prefix,
        }))
    }
}

impl TryFrom<RuleActionSchema> for RuleAction {
    type Error = anyhow::Error;

    fn try_from(value: RuleActionSchema) -> Result<Self> {
        match value {
            RuleActionSchema::Mirror { upstream } => {
                Ok(Self::Mirror(UpstreamPlan::try_from(upstream)?))
            }
            RuleActionSchema::Direct => Ok(Self::Direct),
            RuleActionSchema::Respond {
                status,
                headers,
                content_type,
                body,
            } => Ok(Self::Respond(compile_respond_action(
                status,
                headers.unwrap_or_default(),
                content_type,
                body,
            )?)),
            RuleActionSchema::Plugin { name } => {
                ensure!(
                    !name.trim().is_empty(),
                    "plugin action name must not be empty"
                );
                Ok(Self::Plugin(name))
            }
            RuleActionSchema::Reject { status, message } => {
                let status = status.unwrap_or(403);
                ensure!(
                    (100..=599).contains(&status),
                    "reject.status must be a valid HTTP status code, got {}",
                    status
                );
                let message = message
                    .unwrap_or_else(|| "request rejected by rule".to_string())
                    .trim()
                    .to_string();
                ensure!(
                    !message.is_empty(),
                    "reject.message must not be empty when provided"
                );
                Ok(Self::Reject(RejectRuleAction { status, message }))
            }
        }
    }
}

impl TryFrom<UpstreamPlanSchema> for UpstreamPlan {
    type Error = anyhow::Error;

    fn try_from(value: UpstreamPlanSchema) -> Result<Self> {
        let url = Url::parse(&value.url)
            .with_context(|| format!("invalid upstream url `{}`", value.url))?;
        let plan = Self {
            url,
            sni: value.sni.filter(|value| !value.is_empty()),
            host: value.host.filter(|value| !value.is_empty()),
            connect_host: value.connect_host.filter(|value| !value.is_empty()),
            connect_ip: value.connect_ip,
            dns: value.dns.map(DnsPlan::try_from).transpose()?,
        };

        plan.validate()?;
        Ok(plan)
    }
}

fn compile_respond_action(
    status: Option<u16>,
    headers: std::collections::HashMap<String, String>,
    content_type: Option<String>,
    body: Option<RespondBodySchema>,
) -> Result<RespondRuleAction> {
    let status = status.unwrap_or(200);
    ensure!(
        (100..=599).contains(&status),
        "respond.status must be a valid HTTP status code, got {}",
        status
    );

    let mut compiled_headers = HeaderMap::new();
    for (name, value) in headers {
        let header_name = HeaderName::from_bytes(name.as_bytes())
            .with_context(|| format!("invalid respond header name `{name}`"))?;
        ensure!(
            header_name != CONTENT_LENGTH,
            "respond.headers must not contain `content-length`; it is computed automatically"
        );
        ensure!(
            header_name != CONTENT_TYPE,
            "respond.headers must not contain `content-type`; use respond.content_type instead"
        );
        let header_value = HeaderValue::from_str(&value)
            .with_context(|| format!("invalid respond header value for `{header_name}`"))?;
        compiled_headers.insert(header_name, header_value);
    }

    let compiled_body = compile_respond_body(body)?;

    if let Some(content_type) = content_type {
        let trimmed = content_type.trim();
        ensure!(
            !trimmed.is_empty(),
            "respond.content_type must not be empty"
        );
        compiled_headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_str(trimmed)
                .with_context(|| format!("invalid respond.content_type `{trimmed}`"))?,
        );
    } else if let Some(content_type) = compiled_body.default_content_type {
        compiled_headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    }

    Ok(RespondRuleAction {
        status,
        headers: compiled_headers,
        body: compiled_body.source,
    })
}

struct CompiledRespondBody {
    source: RespondBodySource,
    default_content_type: Option<&'static str>,
}

fn compile_respond_body(body: Option<RespondBodySchema>) -> Result<CompiledRespondBody> {
    let Some(body) = body else {
        return Ok(CompiledRespondBody {
            source: RespondBodySource::Inline(Bytes::new()),
            default_content_type: None,
        });
    };

    let source_count = usize::from(body.text.is_some())
        + usize::from(body.json.is_some())
        + usize::from(body.base64.is_some())
        + usize::from(body.file.is_some());
    ensure!(
        source_count == 1,
        "respond.body must contain exactly one of text, json, base64, or file"
    );

    if let Some(text) = body.text {
        return Ok(CompiledRespondBody {
            source: RespondBodySource::Inline(Bytes::from(text.into_bytes())),
            default_content_type: Some("text/plain; charset=utf-8"),
        });
    }

    if let Some(json) = body.json {
        let bytes = serde_json::to_vec(&json).context("failed to serialize respond.body.json")?;
        return Ok(CompiledRespondBody {
            source: RespondBodySource::Inline(Bytes::from(bytes)),
            default_content_type: Some("application/json"),
        });
    }

    if let Some(file) = body.file {
        let trimmed = file.trim();
        ensure!(!trimmed.is_empty(), "respond.body.file must not be empty");
        let path = PathBuf::from(trimmed);
        let metadata = fs::metadata(&path)
            .with_context(|| format!("failed to read respond.body.file `{}`", path.display()))?;
        ensure!(
            metadata.is_file(),
            "respond.body.file `{}` must point to a regular file",
            path.display()
        );

        return Ok(CompiledRespondBody {
            source: RespondBodySource::File(path.clone()),
            default_content_type: infer_file_content_type(&path),
        });
    }

    let encoded = body
        .base64
        .expect("validated by source_count and previous branches");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .context("failed to decode respond.body.base64")?;

    Ok(CompiledRespondBody {
        source: RespondBodySource::Inline(Bytes::from(decoded)),
        default_content_type: Some("application/octet-stream"),
    })
}

fn infer_file_content_type(path: &Path) -> Option<&'static str> {
    mime_guess::from_path(path).first_raw()
}

impl TryFrom<DnsPlanSchema> for DnsPlan {
    type Error = anyhow::Error;

    fn try_from(value: DnsPlanSchema) -> Result<Self> {
        let plan = Self {
            mode: value.mode,
            server: value.server.filter(|value| !value.is_empty()),
        };

        match plan.mode {
            DnsMode::System => ensure!(
                plan.server.is_none(),
                "dns.server must be omitted when dns.mode=system"
            ),
            DnsMode::Udp | DnsMode::Dot | DnsMode::Doh => ensure!(
                plan.server.is_some(),
                "dns.server is required when dns.mode is udp, dot, or doh"
            ),
        }

        Ok(plan)
    }
}

impl Rule {
    fn validate_matcher_action(matcher: &RuleMatcher, action: &RuleAction) -> Result<()> {
        if let (RuleMatcher::PrefixUrl { origin }, RuleAction::Mirror(upstream)) = (matcher, action)
        {
            ensure!(
                origin.query().is_none() && upstream.url.query().is_none(),
                "prefix rules cannot contain query strings: `{}` -> `{}`",
                origin,
                upstream.url
            );
        }

        if let (RuleMatcher::Host(host_matcher), RuleAction::Mirror(upstream)) = (matcher, action) {
            if host_matcher.path_prefix.is_some() {
                ensure!(
                    upstream.url.query().is_none(),
                    "host rules with path_prefix cannot use upstream.url query strings: `{}`",
                    upstream.url
                );
            }
        }

        if let (RuleMatcher::Ip(ip_matcher), RuleAction::Mirror(upstream)) = (matcher, action) {
            if ip_matcher.path_prefix.is_some() {
                ensure!(
                    upstream.url.query().is_none(),
                    "ip rules with path_prefix cannot use upstream.url query strings: `{}`",
                    upstream.url
                );
            }
        }

        Ok(())
    }
}

impl UpstreamPlan {
    fn validate(&self) -> Result<()> {
        ensure!(
            !(self.connect_host.is_some() && self.connect_ip.is_some()),
            "upstream.connect_host and upstream.connect_ip are mutually exclusive"
        );
        ensure!(
            !(self.connect_ip.is_some() && self.dns.is_some()),
            "upstream.dns cannot be used together with upstream.connect_ip"
        );
        Ok(())
    }
}
