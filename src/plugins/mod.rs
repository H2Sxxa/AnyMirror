mod model;
mod quickjs;

use anyhow::{Context, Result, bail, ensure};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use url::Url;

use crate::config::{PluginDefinition, PluginEngine, PluginRuntimeOptions};
use crate::rules::model::{DnsMode, DnsPlan, RejectRuleAction, RuleAction, UpstreamPlan};
use crate::rules::pool::RuleSet;
use crate::workers::Workers;

pub use model::{
    PluginBodyInput, PluginHeaderInput, PluginHeaderPatch, PluginMatchAction, PluginMatchContext,
    PluginMatchDns, PluginMatchUpstream, PluginPermissionContext, PluginRequestContext,
    PluginRequestPatch, PluginRequestPlan, PluginRequestStageContext, PluginResolvedOutcome,
    PluginResponseContext, PluginResponsePatch, PluginResponsePlan, PluginResponseStageContext,
};

pub struct LivePluginRegistry {
    inner: Arc<ArcSwap<PluginRegistry>>,
}

#[derive(Default)]
pub struct PluginRegistry {
    plugins: HashMap<String, ActivePlugin>,
    disabled_plugins: HashSet<String>,
    missing_plugins: HashSet<String>,
}

struct ActivePlugin {
    definition: PluginDefinition,
    request_stage: Option<PluginStageSource>,
    response_stage: Option<PluginStageSource>,
    runtime: Arc<dyn ScriptRuntimePool>,
    state: Value,
    program: Value,
    compiled_rules: Vec<CompiledPluginRule>,
}

struct PluginStageSources {
    on_load: Option<PluginStageSource>,
    on_compile: Option<PluginStageSource>,
    on_request: Option<PluginStageSource>,
    on_response: Option<PluginStageSource>,
}

#[derive(Clone)]
struct PluginStageSource {
    module_name: String,
    source: String,
}

struct CompiledPluginRule {
    index: usize,
    matcher: CompiledPluginMatcher,
    action: PluginResolvedOutcome,
}

enum CompiledPluginMatcher {
    ExactUrl(Url),
    PrefixUrl(Url),
    Host(CompiledPluginHostMatcher),
}

struct CompiledPluginHostMatcher {
    pattern: PluginHostPattern,
    scheme: Option<String>,
    port: Option<u16>,
    path_prefix: Option<String>,
    path_suffix: Option<String>,
}

enum PluginHostPattern {
    Exact(String),
    AnyOf(Vec<String>),
    Suffix(String),
}

#[async_trait]
trait ScriptRuntimePool: Send + Sync {
    async fn execute(
        &self,
        plugin_name: &str,
        stage: PluginStage,
        plugin_root: &Path,
        entry_module_name: &str,
        source: &str,
        input: &Value,
    ) -> Result<Value>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PluginStage {
    Load,
    Compile,
    Request,
    Response,
}

#[derive(Debug, Serialize)]
struct PluginLoadInput {
    plugin: PluginLoadDescriptor,
}

#[derive(Debug, Serialize)]
struct PluginCompileInput {
    plugin: PluginCompileDescriptor,
}

#[derive(Debug, Clone, Serialize)]
struct PluginLoadDescriptor {
    name: String,
    engine: &'static str,
    permissions: PluginPermissionContext,
    config: Value,
}

#[derive(Debug, Clone, Serialize)]
struct PluginCompileDescriptor {
    name: String,
    engine: &'static str,
    permissions: PluginPermissionContext,
    config: Value,
    state: Value,
}

#[derive(Debug, Deserialize)]
struct PluginLoadOutput {
    #[serde(default)]
    state: Value,
}

#[derive(Debug, Deserialize)]
struct PluginCompileOutput {
    #[serde(default)]
    program: Value,
}

#[derive(Debug, Deserialize)]
struct PluginRuleSchema {
    #[serde(rename = "match")]
    matcher: PluginMatcherSchema,
    action: PluginActionSchema,
}

#[derive(Debug, Deserialize)]
struct PluginMatcherSchema {
    exact: Option<String>,
    prefix: Option<String>,
    host: Option<String>,
    hosts: Option<Vec<String>>,
    host_suffix: Option<String>,
    scheme: Option<String>,
    port: Option<u16>,
    path_prefix: Option<String>,
    path_suffix: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum PluginActionSchema {
    Mirror {
        upstream: PluginUpstreamPlanSchema,
    },
    Direct,
    Reject {
        status: Option<u16>,
        message: Option<String>,
    },
}

#[derive(Debug, Clone, Deserialize)]
struct PluginUpstreamPlanSchema {
    url: String,
    sni: Option<String>,
    host: Option<String>,
    connect_host: Option<String>,
    connect_ip: Option<std::net::IpAddr>,
    dns: Option<PluginDnsPlanSchema>,
}

#[derive(Debug, Clone, Deserialize)]
struct PluginDnsPlanSchema {
    mode: DnsMode,
    server: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PluginRequestOutput {
    #[serde(default)]
    action: Option<PluginActionSchema>,
    #[serde(default)]
    request: Option<PluginRequestPatchSchema>,
}

#[derive(Debug, Deserialize)]
struct PluginResponseOutput {
    #[serde(default)]
    status: Option<u16>,
    #[serde(default)]
    headers: Option<HashMap<String, Option<String>>>,
    #[serde(default)]
    body: Option<PluginBodyPatchSchema>,
}

#[derive(Debug, Deserialize)]
struct PluginRequestPatchSchema {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    headers: Option<HashMap<String, Option<String>>>,
    #[serde(default)]
    body: Option<PluginBodyPatchSchema>,
}

#[derive(Debug, Deserialize)]
struct PluginBodyPatchSchema {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    json: Option<Value>,
    #[serde(default)]
    base64: Option<String>,
}

impl LivePluginRegistry {
    pub fn new(registry: PluginRegistry) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(registry)),
        }
    }

    pub fn snapshot(&self) -> Arc<PluginRegistry> {
        self.inner.load_full()
    }

    pub fn replace(&self, registry: PluginRegistry) {
        self.inner.store(Arc::new(registry));
    }

    pub fn len(&self) -> usize {
        self.snapshot().len()
    }
}

impl Clone for LivePluginRegistry {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl PluginRegistry {
    pub fn len(&self) -> usize {
        self.plugins.len()
    }
}

impl PluginRegistry {
    pub async fn build(
        options: &PluginRuntimeOptions,
        rules: &RuleSet,
        workers: &Workers,
    ) -> Result<Self> {
        if !options.enabled {
            if !options.definitions.is_empty() {
                tracing::warn!(
                    configured_plugins = options.definitions.len(),
                    "Plugin runtime is disabled; configured plugins will be skipped"
                );
            }
            return Ok(Self::default());
        }

        let runtimes = build_runtime_pools(options, workers)?;
        let mut plugins = HashMap::new();
        let mut disabled_plugins = HashSet::new();

        for definition in &options.definitions {
            if !definition.enabled {
                tracing::warn!(
                    plugin = %definition.name,
                    engine = definition.engine.label(),
                    root = %definition.root.display(),
                    "Plugin is disabled; it will be skipped"
                );
                disabled_plugins.insert(definition.name.clone());
                continue;
            }

            let runtime = runtimes.get(&definition.engine).cloned().with_context(|| {
                format!(
                    "no runtime pool is available for plugin `{}` with engine `{}`",
                    definition.name,
                    definition.engine.label()
                )
            })?;
            let stage_sources = load_stage_sources(definition).with_context(|| {
                format!(
                    "failed to load stage files for plugin `{}`",
                    definition.name
                )
            })?;

            let state = execute_load_stage(runtime.clone(), definition, &stage_sources).await?;
            let program =
                execute_compile_stage(runtime.clone(), definition, &stage_sources, &state).await?;
            let compiled_rules = extract_compiled_rules(&program).with_context(|| {
                format!(
                    "failed to compile program rules for plugin `{}`",
                    definition.name
                )
            })?;

            tracing::info!(
                plugin = %definition.name,
                engine = definition.engine.label(),
                root = %definition.root.display(),
                compiled_rules = compiled_rules.len(),
                "Plugin loaded and compiled successfully"
            );

            plugins.insert(
                definition.name.clone(),
                ActivePlugin {
                    definition: definition.clone(),
                    request_stage: stage_sources.on_request.clone(),
                    response_stage: stage_sources.on_response.clone(),
                    runtime,
                    state,
                    program,
                    compiled_rules,
                },
            );
        }

        let referenced_plugins = rules
            .iter()
            .filter_map(|rule| match &rule.action {
                RuleAction::Plugin(plugin_name) => Some(plugin_name.clone()),
                RuleAction::Mirror(_) | RuleAction::Direct | RuleAction::Reject(_) => None,
            })
            .collect::<HashSet<_>>();

        let mut missing_plugins = HashSet::new();
        for plugin_name in referenced_plugins {
            if plugins.contains_key(&plugin_name) || disabled_plugins.contains(&plugin_name) {
                continue;
            }
            tracing::warn!(
                plugin = %plugin_name,
                "Rule references a plugin that is not loaded; matching requests will skip plugin execution"
            );
            missing_plugins.insert(plugin_name);
        }

        Ok(Self {
            plugins,
            disabled_plugins,
            missing_plugins,
        })
    }

    pub fn request_body_access(&self, plugin_name: &str) -> bool {
        self.plugins.get(plugin_name).is_some_and(|plugin| {
            plugin.request_stage.is_some() && plugin.definition.permissions.allows_request_body()
        })
    }

    pub fn response_body_access(&self, plugin_name: &str) -> bool {
        self.plugins.get(plugin_name).is_some_and(|plugin| {
            plugin.response_stage.is_some() && plugin.definition.permissions.allows_response_body()
        })
    }

    pub async fn resolve_request(
        &self,
        plugin_name: &str,
        context: PluginRequestStageContext,
    ) -> Result<Option<PluginRequestPlan>> {
        if self.disabled_plugins.contains(plugin_name) {
            return Ok(None);
        }
        if self.missing_plugins.contains(plugin_name) {
            return Ok(None);
        }

        let Some(plugin) = self.plugins.get(plugin_name) else {
            return Ok(None);
        };

        let matched_rule = plugin
            .compiled_rules
            .iter()
            .find(|rule| rule.matcher.matches(context.request()))
            .map(PluginMatchContext::from_rule);

        let Some(stage_source) = plugin.request_stage.as_ref() else {
            return Ok(matched_rule.map(PluginRequestPlan::from_match));
        };

        let input = serde_json::to_value(context.with_plugin_state(
            plugin.definition.name.clone(),
            plugin.definition.engine.label().to_string(),
            plugin.definition.permissions.into(),
            plugin.definition.config.clone(),
            plugin.state.clone(),
            plugin.program.clone(),
            matched_rule.clone(),
        ))
        .context("failed to serialize plugin resolve context")?;
        let output = plugin
            .runtime
            .execute(
                plugin_name,
                PluginStage::Request,
                &plugin.definition.root,
                &stage_source.module_name,
                &stage_source.source,
                &input,
            )
            .await
            .with_context(|| format!("failed to execute on_request for plugin `{plugin_name}`"))?;

        if output.is_null() {
            return Ok(matched_rule.map(PluginRequestPlan::from_match));
        }

        let resolved: PluginRequestOutput = serde_json::from_value(output).with_context(|| {
            format!("plugin `{plugin_name}` returned an invalid request-stage payload")
        })?;

        let outcome = match resolved.action {
            Some(action) => PluginResolvedOutcome::try_from(action)?,
            None => match matched_rule {
                Some(ref matched) => matched.clone().into_outcome()?,
                None => return Ok(None),
            },
        };

        let request_patch = match resolved.request {
            Some(request_patch) => {
                let request_patch = PluginRequestPatch::try_from(request_patch)?;
                ensure_body_patch_permission(
                    plugin.definition.permissions.allows_request_body(),
                    request_patch.body.as_ref(),
                    plugin_name,
                    "on_request.body",
                    "request-stage",
                )?;
                request_patch
            }
            None => PluginRequestPatch::default(),
        };

        Ok(Some(PluginRequestPlan {
            outcome,
            matched: matched_rule,
            request_patch,
        }))
    }

    pub async fn resolve_response(
        &self,
        plugin_name: &str,
        context: PluginResponseStageContext,
    ) -> Result<Option<PluginResponsePlan>> {
        if self.disabled_plugins.contains(plugin_name) {
            return Ok(None);
        }
        if self.missing_plugins.contains(plugin_name) {
            return Ok(None);
        }

        let Some(plugin) = self.plugins.get(plugin_name) else {
            return Ok(None);
        };
        let Some(stage_source) = plugin.response_stage.as_ref() else {
            return Ok(None);
        };

        let matched = context.matched();
        let input = serde_json::to_value(context.with_plugin_state(
            plugin.definition.name.clone(),
            plugin.definition.engine.label().to_string(),
            plugin.definition.permissions.into(),
            plugin.definition.config.clone(),
            plugin.state.clone(),
            plugin.program.clone(),
            matched,
        ))
        .context("failed to serialize plugin response-stage context")?;
        let output = plugin
            .runtime
            .execute(
                plugin_name,
                PluginStage::Response,
                &plugin.definition.root,
                &stage_source.module_name,
                &stage_source.source,
                &input,
            )
            .await
            .with_context(|| format!("failed to execute on_response for plugin `{plugin_name}`"))?;

        if output.is_null() {
            return Ok(None);
        }

        let resolved: PluginResponseOutput = serde_json::from_value(output).with_context(|| {
            format!("plugin `{plugin_name}` returned an invalid response-stage payload")
        })?;

        if resolved.status.is_none() && resolved.headers.is_none() && resolved.body.is_none() {
            return Ok(None);
        }

        Ok(Some(PluginResponsePlan {
            patch: {
                let patch = PluginResponsePatch::try_from(resolved)?;
                ensure_body_patch_permission(
                    plugin.definition.permissions.allows_response_body(),
                    patch.body.as_ref(),
                    plugin_name,
                    "on_response.body",
                    "response-stage",
                )?;
                patch
            },
        }))
    }
}

impl PluginMatchContext {
    fn from_rule(rule: &CompiledPluginRule) -> Self {
        Self {
            index: rule.index,
            action: PluginMatchAction::from_outcome(&rule.action),
        }
    }
}

impl PluginMatchAction {
    pub(crate) fn from_outcome(outcome: &PluginResolvedOutcome) -> Self {
        match outcome {
            PluginResolvedOutcome::Direct => Self::Direct,
            PluginResolvedOutcome::Reject(reject) => Self::Reject {
                status: reject.status,
                message: reject.message.clone(),
            },
            PluginResolvedOutcome::Mirror(upstream) => Self::Mirror {
                upstream: PluginMatchUpstream {
                    url: upstream.url.to_string(),
                    sni: upstream.sni.clone(),
                    host: upstream.host.clone(),
                    connect_host: upstream.connect_host.clone(),
                    connect_ip: upstream.connect_ip,
                    dns: upstream.dns.as_ref().map(|dns| PluginMatchDns {
                        mode: match dns.mode {
                            DnsMode::System => "system",
                            DnsMode::Udp => "udp",
                            DnsMode::Dot => "dot",
                            DnsMode::Doh => "doh",
                        },
                        server: dns.server.clone(),
                    }),
                },
            },
        }
    }
}

fn build_runtime_pools(
    options: &PluginRuntimeOptions,
    workers: &Workers,
) -> Result<HashMap<PluginEngine, Arc<dyn ScriptRuntimePool>>> {
    let mut runtimes: HashMap<PluginEngine, Arc<dyn ScriptRuntimePool>> = HashMap::new();

    if options
        .definitions
        .iter()
        .any(|definition| definition.engine == PluginEngine::QuickJs)
    {
        let pool = quickjs::QuickJsPool::new(options.workers, workers.clone())
            .context("failed to initialize QuickJS plugin worker pool")?;
        runtimes.insert(PluginEngine::QuickJs, Arc::new(pool));
    }

    Ok(runtimes)
}

async fn execute_load_stage(
    runtime: Arc<dyn ScriptRuntimePool>,
    definition: &PluginDefinition,
    stage_sources: &PluginStageSources,
) -> Result<Value> {
    let Some(stage_source) = stage_sources.on_load.as_ref() else {
        return Ok(Value::Null);
    };

    let input = serde_json::to_value(PluginLoadInput {
        plugin: PluginLoadDescriptor {
            name: definition.name.clone(),
            engine: definition.engine.label(),
            permissions: definition.permissions.into(),
            config: definition.config.clone(),
        },
    })
    .context("failed to serialize plugin on_load input")?;

    let output = runtime
        .execute(
            &definition.name,
            PluginStage::Load,
            &definition.root,
            &stage_source.module_name,
            &stage_source.source,
            &input,
        )
        .await
        .with_context(|| format!("failed to execute on_load for plugin `{}`", definition.name))?;
    if output.is_null() {
        return Ok(Value::Null);
    }

    let result: PluginLoadOutput = serde_json::from_value(output).with_context(|| {
        format!(
            "plugin `{}` returned an invalid on_load payload",
            definition.name
        )
    })?;
    Ok(result.state)
}

async fn execute_compile_stage(
    runtime: Arc<dyn ScriptRuntimePool>,
    definition: &PluginDefinition,
    stage_sources: &PluginStageSources,
    state: &Value,
) -> Result<Value> {
    let Some(stage_source) = stage_sources.on_compile.as_ref() else {
        return Ok(Value::Null);
    };

    let input = serde_json::to_value(PluginCompileInput {
        plugin: PluginCompileDescriptor {
            name: definition.name.clone(),
            engine: definition.engine.label(),
            permissions: definition.permissions.into(),
            config: definition.config.clone(),
            state: state.clone(),
        },
    })
    .context("failed to serialize plugin on_compile input")?;

    let output = runtime
        .execute(
            &definition.name,
            PluginStage::Compile,
            &definition.root,
            &stage_source.module_name,
            &stage_source.source,
            &input,
        )
        .await
        .with_context(|| {
            format!(
                "failed to execute on_compile for plugin `{}`",
                definition.name
            )
        })?;
    if output.is_null() {
        return Ok(Value::Null);
    }

    let result: PluginCompileOutput = serde_json::from_value(output).with_context(|| {
        format!(
            "plugin `{}` returned an invalid on_compile payload",
            definition.name
        )
    })?;
    Ok(result.program)
}

fn extract_compiled_rules(program: &Value) -> Result<Vec<CompiledPluginRule>> {
    let Some(rule_value) = program.get("rules") else {
        return Ok(Vec::new());
    };
    let schemas: Vec<PluginRuleSchema> = serde_json::from_value(rule_value.clone())
        .context("plugin program.rules must be an array of plugin rules")?;

    schemas
        .into_iter()
        .enumerate()
        .map(|(index, rule)| CompiledPluginRule::try_from_schema(index, rule))
        .collect()
}

impl CompiledPluginRule {
    fn try_from_schema(index: usize, value: PluginRuleSchema) -> Result<Self> {
        Ok(Self {
            index,
            matcher: CompiledPluginMatcher::try_from(value.matcher)?,
            action: PluginResolvedOutcome::try_from(value.action)?,
        })
    }
}

impl CompiledPluginMatcher {
    fn try_from(value: PluginMatcherSchema) -> Result<Self> {
        let exact_count = usize::from(value.exact.is_some())
            + usize::from(value.prefix.is_some())
            + usize::from(value.host.is_some())
            + usize::from(value.hosts.is_some())
            + usize::from(value.host_suffix.is_some());
        ensure!(
            exact_count == 1,
            "plugin rule.match must contain exactly one of exact, prefix, host, hosts, or host_suffix"
        );

        let scheme = value
            .scheme
            .as_deref()
            .map(normalize_scheme)
            .transpose()?
            .map(str::to_string);
        let path_prefix = value
            .path_prefix
            .as_deref()
            .map(normalize_path_prefix)
            .transpose()?
            .map(str::to_string);
        let path_suffix = value
            .path_suffix
            .as_deref()
            .map(normalize_path_suffix)
            .transpose()?
            .map(str::to_string);

        if let Some(exact) = value.exact {
            ensure!(
                scheme.is_none()
                    && value.port.is_none()
                    && path_prefix.is_none()
                    && path_suffix.is_none(),
                "plugin rule.match.exact cannot be combined with scheme, port, path_prefix, or path_suffix"
            );
            return Ok(Self::ExactUrl(Url::parse(&exact).with_context(|| {
                format!("invalid plugin match.exact url `{exact}`")
            })?));
        }

        if let Some(prefix) = value.prefix {
            ensure!(
                scheme.is_none()
                    && value.port.is_none()
                    && path_prefix.is_none()
                    && path_suffix.is_none(),
                "plugin rule.match.prefix cannot be combined with scheme, port, path_prefix, or path_suffix"
            );
            return Ok(Self::PrefixUrl(Url::parse(&prefix).with_context(|| {
                format!("invalid plugin match.prefix url `{prefix}`")
            })?));
        }

        let pattern = if let Some(host) = value.host {
            PluginHostPattern::Exact(normalize_host(&host)?)
        } else if let Some(hosts) = value.hosts {
            ensure!(
                !hosts.is_empty(),
                "plugin rule.match.hosts must not be empty when provided"
            );
            PluginHostPattern::AnyOf(
                hosts
                    .into_iter()
                    .map(|host| normalize_host(&host))
                    .collect::<Result<Vec<_>>>()?,
            )
        } else {
            PluginHostPattern::Suffix(normalize_host_suffix(
                &value
                    .host_suffix
                    .ok_or_else(|| anyhow::anyhow!("validated host suffix is present"))?,
            )?)
        };

        Ok(Self::Host(CompiledPluginHostMatcher {
            pattern,
            scheme,
            port: value.port,
            path_prefix,
            path_suffix,
        }))
    }

    fn matches(&self, request: &PluginRequestContext) -> bool {
        match self {
            Self::ExactUrl(expected) => request.url == expected.as_str(),
            Self::PrefixUrl(expected) => {
                request.scheme == expected.scheme()
                    && request.host.as_deref() == expected.host_str()
                    && request.port == expected.port_or_known_default()
                    && path_has_prefix(&request.path, expected.path())
            }
            Self::Host(host_matcher) => host_matcher.matches(request),
        }
    }
}

impl CompiledPluginHostMatcher {
    fn matches(&self, request: &PluginRequestContext) -> bool {
        if self
            .scheme
            .as_deref()
            .is_some_and(|scheme| scheme != request.scheme)
        {
            return false;
        }
        if self.port.is_some_and(|port| Some(port) != request.port) {
            return false;
        }
        if self
            .path_prefix
            .as_deref()
            .is_some_and(|prefix| !path_has_prefix(&request.path, prefix))
        {
            return false;
        }
        if self
            .path_suffix
            .as_deref()
            .is_some_and(|suffix| !request.path.ends_with(suffix))
        {
            return false;
        }

        let Some(host) = request.host.as_deref() else {
            return false;
        };

        match &self.pattern {
            PluginHostPattern::Exact(expected) => expected == host,
            PluginHostPattern::AnyOf(expected) => expected.iter().any(|entry| entry == host),
            PluginHostPattern::Suffix(expected) => {
                host == expected
                    || host
                        .strip_suffix(expected)
                        .is_some_and(|value| value.ends_with('.'))
            }
        }
    }
}

impl TryFrom<PluginActionSchema> for PluginResolvedOutcome {
    type Error = anyhow::Error;

    fn try_from(value: PluginActionSchema) -> Result<Self> {
        match value {
            PluginActionSchema::Mirror { upstream } => {
                Ok(Self::Mirror(UpstreamPlan::try_from(upstream)?))
            }
            PluginActionSchema::Direct => Ok(Self::Direct),
            PluginActionSchema::Reject { status, message } => Ok(Self::Reject(RejectRuleAction {
                status: status.unwrap_or(403),
                message: message.unwrap_or_else(|| "request rejected by plugin".to_string()),
            })),
        }
    }
}

impl TryFrom<PluginUpstreamPlanSchema> for UpstreamPlan {
    type Error = anyhow::Error;

    fn try_from(value: PluginUpstreamPlanSchema) -> Result<Self> {
        let url = Url::parse(&value.url)
            .with_context(|| format!("invalid plugin upstream url `{}`", value.url))?;
        let plan = Self {
            url,
            sni: value.sni.filter(|value| !value.is_empty()),
            host: value.host.filter(|value| !value.is_empty()),
            connect_host: value.connect_host.filter(|value| !value.is_empty()),
            connect_ip: value.connect_ip,
            dns: value.dns.map(DnsPlan::try_from).transpose()?,
        };
        plan.validate_plugin_plan()?;
        Ok(plan)
    }
}

impl TryFrom<PluginDnsPlanSchema> for DnsPlan {
    type Error = anyhow::Error;

    fn try_from(value: PluginDnsPlanSchema) -> Result<Self> {
        let plan = Self {
            mode: value.mode,
            server: value.server.filter(|value| !value.is_empty()),
        };

        match plan.mode {
            DnsMode::System => {
                if plan.server.is_some() {
                    bail!("plugin dns.server must be omitted when dns.mode=system");
                }
            }
            DnsMode::Udp | DnsMode::Dot | DnsMode::Doh => {
                if plan.server.is_none() {
                    bail!("plugin dns.server is required when dns.mode is udp, dot, or doh");
                }
            }
        }

        Ok(plan)
    }
}

impl TryFrom<PluginRequestPatchSchema> for PluginRequestPatch {
    type Error = anyhow::Error;

    fn try_from(value: PluginRequestPatchSchema) -> Result<Self> {
        Ok(Self {
            method: value.method.filter(|entry| !entry.is_empty()),
            url: value.url.filter(|entry| !entry.is_empty()),
            headers: parse_header_patches(value.headers.unwrap_or_default()),
            body: parse_body_patch(value.body)?,
        })
    }
}

impl TryFrom<PluginResponseOutput> for PluginResponsePatch {
    type Error = anyhow::Error;

    fn try_from(value: PluginResponseOutput) -> Result<Self> {
        Ok(Self {
            status: value.status,
            headers: parse_header_patches(value.headers.unwrap_or_default()),
            body: parse_body_patch(value.body)?,
        })
    }
}

fn parse_header_patches(headers: HashMap<String, Option<String>>) -> Vec<PluginHeaderPatch> {
    headers
        .into_iter()
        .map(|(name, value)| PluginHeaderPatch { name, value })
        .collect()
}

fn ensure_body_patch_permission(
    is_allowed: bool,
    body: Option<&Bytes>,
    plugin_name: &str,
    required_permission: &str,
    stage: &str,
) -> Result<()> {
    if body.is_none() {
        return Ok(());
    }

    ensure!(
        is_allowed,
        "plugin `{}` returned a {} body patch without the `{}` permission",
        plugin_name,
        stage,
        required_permission
    );

    Ok(())
}

fn parse_body_patch(body: Option<PluginBodyPatchSchema>) -> Result<Option<Bytes>> {
    let Some(body) = body else {
        return Ok(None);
    };

    let variants = usize::from(body.text.is_some())
        + usize::from(body.json.is_some())
        + usize::from(body.base64.is_some());
    ensure!(
        variants == 1,
        "plugin body patch must contain exactly one of text, json, or base64"
    );

    if let Some(text) = body.text {
        return Ok(Some(Bytes::from(text.into_bytes())));
    }

    if let Some(json) = body.json {
        let bytes =
            serde_json::to_vec(&json).context("failed to serialize plugin body patch json")?;
        return Ok(Some(Bytes::from(bytes)));
    }

    if let Some(base64) = body.base64 {
        let bytes = BASE64_STANDARD
            .decode(base64)
            .context("failed to decode plugin body patch base64")?;
        return Ok(Some(Bytes::from(bytes)));
    }

    bail!("plugin body patch is missing a supported payload")
}

impl UpstreamPlan {
    fn validate_plugin_plan(&self) -> Result<()> {
        if self.connect_host.is_some() && self.connect_ip.is_some() {
            bail!("plugin upstream.connect_host and upstream.connect_ip are mutually exclusive");
        }
        if self.connect_ip.is_some() && self.dns.is_some() {
            bail!("plugin upstream.dns cannot be used together with upstream.connect_ip");
        }
        Ok(())
    }
}

fn load_stage_sources(definition: &PluginDefinition) -> Result<PluginStageSources> {
    if !definition.root.is_dir() {
        bail!(
            "plugin root directory does not exist or is not a directory: {}",
            definition.root.display()
        );
    }

    let on_load = load_stage_source(&definition.root, definition.engine, PluginStage::Load)?;
    let on_compile = load_stage_source(&definition.root, definition.engine, PluginStage::Compile)?;
    let on_request = load_stage_source(&definition.root, definition.engine, PluginStage::Request)?;
    let on_response =
        load_stage_source(&definition.root, definition.engine, PluginStage::Response)?;

    if on_load.is_none() && on_compile.is_none() && on_request.is_none() && on_response.is_none() {
        bail!(
            "plugin root `{}` does not contain any stage files; expected at least one of: {}, {}, {}, {}",
            definition.root.display(),
            stage_file_name(definition.engine, PluginStage::Load),
            stage_file_name(definition.engine, PluginStage::Compile),
            stage_file_name(definition.engine, PluginStage::Request),
            stage_file_name(definition.engine, PluginStage::Response)
        );
    }

    Ok(PluginStageSources {
        on_load,
        on_compile,
        on_request,
        on_response,
    })
}

fn load_stage_source(
    root: &Path,
    engine: PluginEngine,
    stage: PluginStage,
) -> Result<Option<PluginStageSource>> {
    let stage_path = root.join(stage_file_name(engine, stage));
    if !stage_path.exists() {
        return Ok(None);
    }

    let source = fs::read_to_string(&stage_path).with_context(|| {
        format!(
            "failed to read plugin stage file `{}`",
            stage_path.display()
        )
    })?;
    if source.trim().is_empty() {
        bail!(
            "plugin stage file `{}` must not be empty",
            stage_path.display()
        );
    }

    let module_name = normalize_stage_module_name(&stage_path)?;

    Ok(Some(PluginStageSource {
        module_name,
        source,
    }))
}

fn stage_file_name(engine: PluginEngine, stage: PluginStage) -> &'static str {
    match (engine, stage) {
        (PluginEngine::QuickJs, PluginStage::Load) => "on_load.js",
        (PluginEngine::QuickJs, PluginStage::Compile) => "on_compile.js",
        (PluginEngine::QuickJs, PluginStage::Request) => "on_request.js",
        (PluginEngine::QuickJs, PluginStage::Response) => "on_response.js",
    }
}

fn normalize_stage_module_name(stage_path: &Path) -> Result<String> {
    let canonical = stage_path.canonicalize().with_context(|| {
        format!(
            "failed to canonicalize plugin stage file `{}`",
            stage_path.display()
        )
    })?;
    Ok(canonical.to_string_lossy().replace('\\', "/"))
}

fn normalize_host(value: &str) -> Result<String> {
    let trimmed = value.trim().trim_end_matches('.');
    ensure!(!trimmed.is_empty(), "plugin host matcher must not be empty");
    ensure!(
        !trimmed.contains("://") && !trimmed.contains('/'),
        "plugin host matcher must be a bare hostname: `{}`",
        value
    );
    Ok(trimmed.to_ascii_lowercase())
}

fn normalize_host_suffix(value: &str) -> Result<String> {
    let normalized = value.trim().trim_matches('.').to_ascii_lowercase();
    ensure!(
        !normalized.is_empty(),
        "plugin host_suffix matcher must not be empty"
    );
    ensure!(
        !normalized.contains("://") && !normalized.contains('/'),
        "plugin host_suffix matcher must be a bare hostname suffix: `{}`",
        value
    );
    Ok(normalized)
}

fn normalize_scheme(value: &str) -> Result<&str> {
    match value {
        "http" | "https" => Ok(value),
        _ => bail!(
            "plugin rule.match.scheme must be `http` or `https`, got `{}`",
            value
        ),
    }
}

fn normalize_path_prefix(value: &str) -> Result<&str> {
    ensure!(
        value.starts_with('/'),
        "plugin rule.match.path_prefix must start with `/`, got `{}`",
        value
    );
    Ok(value)
}

fn normalize_path_suffix(value: &str) -> Result<&str> {
    ensure!(
        value.starts_with('.')
            || value.starts_with('/')
            || value
                .chars()
                .all(|char| char.is_ascii_alphanumeric() || char == '-' || char == '_'),
        "plugin rule.match.path_suffix must look like a suffix, got `{}`",
        value
    );
    Ok(value)
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
