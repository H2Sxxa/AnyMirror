use bytes::Bytes;
use serde::Serialize;

use crate::config::PluginPermissions;
use crate::rules::model::{RejectRuleAction, UpstreamPlan};

#[derive(Debug, Clone)]
pub struct PluginRequestPlan {
    pub outcome: PluginResolvedOutcome,
    pub matched: Option<PluginMatchContext>,
    pub request_patch: PluginRequestPatch,
}

#[derive(Debug, Clone)]
pub struct PluginResponsePlan {
    pub patch: PluginResponsePatch,
}

#[derive(Debug, Clone)]
pub enum PluginResolvedOutcome {
    Mirror(UpstreamPlan),
    Direct,
    Reject(RejectRuleAction),
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginRequestStageContext {
    plugin: PluginResolvePluginState,
    request: PluginRequestContext,
    matched: Option<PluginMatchContext>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginResponseStageContext {
    plugin: PluginResolvePluginState,
    request: PluginRequestContext,
    matched: Option<PluginMatchContext>,
    resolved_action: PluginMatchAction,
    response: PluginResponseContext,
}

#[derive(Debug, Clone, Serialize)]
struct PluginResolvePluginState {
    name: String,
    engine: String,
    permissions: PluginPermissionContext,
    config: serde_json::Value,
    state: serde_json::Value,
    program: serde_json::Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginPermissionContext {
    on_request: PluginStagePermissionContext,
    on_response: PluginStagePermissionContext,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginStagePermissionContext {
    body: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginRequestContext {
    pub source: String,
    pub method: String,
    pub url: String,
    pub scheme: String,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub path: String,
    pub query: Option<String>,
    pub headers: Vec<PluginHeaderInput>,
    pub body: Option<PluginBodyInput>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginHeaderInput {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginResponseContext {
    pub status: u16,
    pub headers: Vec<PluginHeaderInput>,
    pub body: Option<PluginBodyInput>,
}

#[derive(Debug, Clone, Default)]
pub struct PluginRequestPatch {
    pub method: Option<String>,
    pub url: Option<String>,
    pub headers: Vec<PluginHeaderPatch>,
    pub body: Option<Bytes>,
}

#[derive(Debug, Clone, Default)]
pub struct PluginResponsePatch {
    pub status: Option<u16>,
    pub headers: Vec<PluginHeaderPatch>,
    pub body: Option<Bytes>,
}

#[derive(Debug, Clone)]
pub struct PluginHeaderPatch {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginBodyInput {
    pub kind: &'static str,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginMatchContext {
    pub index: usize,
    pub action: PluginMatchAction,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum PluginMatchAction {
    Mirror { upstream: PluginMatchUpstream },
    Direct,
    Reject { status: u16, message: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginMatchUpstream {
    pub url: String,
    pub sni: Option<String>,
    pub host: Option<String>,
    pub connect_host: Option<String>,
    pub connect_ip: Option<std::net::IpAddr>,
    pub dns: Option<PluginMatchDns>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginMatchDns {
    pub mode: &'static str,
    pub server: Option<String>,
}

impl PluginRequestStageContext {
    pub fn new(request: PluginRequestContext) -> Self {
        Self {
            plugin: PluginResolvePluginState {
                name: String::new(),
                engine: String::new(),
                permissions: PluginPermissionContext::default(),
                config: serde_json::Value::Null,
                state: serde_json::Value::Null,
                program: serde_json::Value::Null,
            },
            request,
            matched: None,
        }
    }

    pub(crate) fn with_plugin_state(
        mut self,
        name: String,
        engine: String,
        permissions: PluginPermissionContext,
        config: serde_json::Value,
        state: serde_json::Value,
        program: serde_json::Value,
        matched: Option<PluginMatchContext>,
    ) -> Self {
        self.plugin = PluginResolvePluginState {
            name,
            engine,
            permissions,
            config,
            state,
            program,
        };
        self.matched = matched;
        self
    }

    pub(crate) fn request(&self) -> &PluginRequestContext {
        &self.request
    }
}

impl PluginResponseStageContext {
    pub fn new(
        request: PluginRequestContext,
        resolved_action: PluginMatchAction,
        response: PluginResponseContext,
    ) -> Self {
        Self {
            plugin: PluginResolvePluginState {
                name: String::new(),
                engine: String::new(),
                permissions: PluginPermissionContext::default(),
                config: serde_json::Value::Null,
                state: serde_json::Value::Null,
                program: serde_json::Value::Null,
            },
            request,
            matched: None,
            resolved_action,
            response,
        }
    }

    pub(crate) fn with_plugin_state(
        mut self,
        name: String,
        engine: String,
        permissions: PluginPermissionContext,
        config: serde_json::Value,
        state: serde_json::Value,
        program: serde_json::Value,
        matched: Option<PluginMatchContext>,
    ) -> Self {
        self.plugin = PluginResolvePluginState {
            name,
            engine,
            permissions,
            config,
            state,
            program,
        };
        self.matched = matched;
        self
    }

    pub(crate) fn matched(&self) -> Option<PluginMatchContext> {
        self.matched.clone()
    }

    pub(crate) fn with_matched(mut self, matched: Option<PluginMatchContext>) -> Self {
        self.matched = matched;
        self
    }
}

impl Default for PluginPermissionContext {
    fn default() -> Self {
        Self {
            on_request: PluginStagePermissionContext { body: false },
            on_response: PluginStagePermissionContext { body: false },
        }
    }
}

impl From<PluginPermissions> for PluginPermissionContext {
    fn from(value: PluginPermissions) -> Self {
        Self {
            on_request: PluginStagePermissionContext {
                body: value.on_request_body,
            },
            on_response: PluginStagePermissionContext {
                body: value.on_response_body,
            },
        }
    }
}

impl PluginRequestPlan {
    pub fn from_match(matched: PluginMatchContext) -> Self {
        Self {
            outcome: matched
                .clone()
                .into_outcome()
                .expect("plugin matched action should always convert into an outcome"),
            matched: Some(matched),
            request_patch: PluginRequestPatch::default(),
        }
    }
}

impl PluginMatchContext {
    pub fn into_outcome(self) -> anyhow::Result<PluginResolvedOutcome> {
        self.action.into_outcome()
    }
}

impl PluginMatchAction {
    pub fn into_outcome(self) -> anyhow::Result<PluginResolvedOutcome> {
        match self {
            Self::Direct => Ok(PluginResolvedOutcome::Direct),
            Self::Reject { status, message } => {
                Ok(PluginResolvedOutcome::Reject(RejectRuleAction {
                    status,
                    message,
                }))
            }
            Self::Mirror { upstream } => Ok(PluginResolvedOutcome::Mirror(UpstreamPlan {
                url: url::Url::parse(&upstream.url)?,
                sni: upstream.sni,
                host: upstream.host,
                connect_host: upstream.connect_host,
                connect_ip: upstream.connect_ip,
                dns: upstream.dns.map(|dns| crate::rules::model::DnsPlan {
                    mode: match dns.mode {
                        "system" => crate::rules::model::DnsMode::System,
                        "udp" => crate::rules::model::DnsMode::Udp,
                        "dot" => crate::rules::model::DnsMode::Dot,
                        "doh" => crate::rules::model::DnsMode::Doh,
                        _ => crate::rules::model::DnsMode::System,
                    },
                    server: dns.server,
                }),
            })),
        }
    }
}
