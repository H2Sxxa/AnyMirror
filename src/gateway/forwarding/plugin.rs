use axum::{
    body::Body,
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{CONTENT_ENCODING, CONTENT_LENGTH},
    },
    response::Response,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use bytes::Bytes;
use http_body_util::BodyExt;
use tracing::{Instrument, Span, field};
use url::Url;

use super::super::{
    http::responses::{json_error, reject_response},
    state::AppState,
    upstream::executors::UpstreamExecutor,
};
use crate::plugins::{
    PluginBodyInput, PluginHeaderInput, PluginHeaderPatch, PluginMatchAction, PluginMatchContext,
    PluginRegistry, PluginRequestContext, PluginRequestPatch, PluginRequestPlan,
    PluginRequestStageContext, PluginResolvedOutcome, PluginResponseContext, PluginResponsePlan,
    PluginResponseStageContext,
};
use crate::rules::model::UpstreamPlan;

struct BufferedUpstreamResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

enum PluginIncomingRequestBody {
    Streaming(Body),
    Buffered(Bytes),
}

impl PluginIncomingRequestBody {
    fn bytes(&self) -> Option<&Bytes> {
        match self {
            Self::Streaming(_) => None,
            Self::Buffered(bytes) => Some(bytes),
        }
    }

    fn into_body(self) -> Body {
        match self {
            Self::Streaming(body) => body,
            Self::Buffered(bytes) => Body::from(bytes),
        }
    }
}

struct PreparedPluginRequest {
    method: Method,
    headers: HeaderMap,
    body: PluginIncomingRequestBody,
    context: PluginRequestContext,
    outcome: PluginResolvedOutcome,
    matched: Option<PluginMatchContext>,
}

pub(super) async fn forward_plugin_request<E: UpstreamExecutor>(
    state: &AppState<E>,
    method: Method,
    request_headers: &HeaderMap,
    body: Body,
    original: Url,
    source: Option<&str>,
    plugin_name: &str,
) -> Response {
    let request_span = Span::current();
    let plugins = state.plugins.snapshot();
    let request_body_access = plugins.request_body_access(plugin_name);
    let response_body_access = plugins.response_body_access(plugin_name);
    let request_source = source.unwrap_or("explicit");

    let plugin_span = tracing::info_span!(
        "plugin.forward",
        plugin = plugin_name,
        source = request_source,
        original_url = %original,
        request_body_access,
        response_body_access,
        outcome = field::Empty,
        upstream_url = field::Empty,
        upstream_status = field::Empty
    );

    async {
        let request_body = match collect_plugin_request_body(body, request_body_access)
            .instrument(tracing::info_span!(
                "plugin.request_body.collect",
                plugin = plugin_name,
                buffered = request_body_access
            ))
            .await
        {
            Ok(body) => body,
            Err(error) => return json_error(StatusCode::BAD_GATEWAY, error),
        };

        let initial_request = build_plugin_request_context(
            request_source,
            &method,
            &original,
            request_headers,
            request_body.bytes(),
        );

        let request_plan = match plugins
            .resolve_request(
                plugin_name,
                PluginRequestStageContext::new(initial_request.clone()),
            )
            .instrument(tracing::info_span!(
                "plugin.request_stage",
                plugin = plugin_name
            ))
            .await
        {
            Ok(request_plan) => request_plan,
            Err(error) => {
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    format!("plugin resolution failed: {error}"),
                );
            }
        };

        let prepared = match prepare_plugin_request(
            method,
            request_headers,
            request_body,
            initial_request,
            request_plan,
        ) {
            Ok(prepared) => prepared,
            Err(error) => return json_error(StatusCode::BAD_GATEWAY, error),
        };

        let outcome_name = plugin_outcome_name(&prepared.outcome);
        Span::current().record("outcome", outcome_name);
        request_span.record("action", outcome_name);

        if let PluginResolvedOutcome::Reject(reject) = &prepared.outcome {
            tracing::info!(
                plugin = %plugin_name,
                original_url = %original,
                reject_status = reject.status,
                reject_message = %reject.message,
                "Plugin rejected request"
            );
            return reject_response(reject.status, &reject.message);
        }

        let (upstream, response_source) =
            resolve_plugin_upstream(&prepared.outcome, &prepared.context, source);

        Span::current().record("upstream_url", field::display(upstream.url.as_str()));
        request_span.record("upstream_url", field::display(upstream.url.as_str()));
        tracing::info!(
            plugin = %plugin_name,
            original_url = %original,
            upstream_url = %upstream.url,
            "Plugin resolved request to upstream"
        );

        let executed = match state
            .executor
            .execute(
                prepared.method,
                &prepared.headers,
                original.as_str(),
                &upstream,
                prepared.body.into_body(),
            )
            .await
        {
            Ok(executed) => executed,
            Err(error) => {
                return json_error(
                    StatusCode::BAD_GATEWAY,
                    format!("plugin upstream request failed: {error}"),
                );
            }
        };

        if response_body_access {
            let buffered = match collect_upstream_response(executed.response)
                .instrument(tracing::info_span!(
                    "plugin.response_body.collect",
                    plugin = plugin_name,
                    buffered = true
                ))
                .await
            {
                Ok(buffered) => buffered,
                Err(error) => return json_error(StatusCode::BAD_GATEWAY, error),
            };

            Span::current().record("upstream_status", buffered.status.as_u16());
            let response_plan = run_plugin_response_stage(
                plugins.as_ref(),
                plugin_name,
                prepared.context,
                prepared.matched,
                &prepared.outcome,
                buffered.status,
                &buffered.headers,
                Some(&buffered.body),
            )
            .instrument(tracing::info_span!(
                "plugin.response_stage",
                plugin = plugin_name,
                buffered_body = true,
                upstream_status = buffered.status.as_u16()
            ))
            .await;

            return finalize_buffered_plugin_response(
                buffered,
                response_plan,
                response_source,
                upstream.url.as_str(),
            );
        }

        let response_status = executed.response.status();
        let response_headers = executed.response.headers().clone();
        Span::current().record("upstream_status", response_status.as_u16());
        let response_plan = run_plugin_response_stage(
            plugins.as_ref(),
            plugin_name,
            prepared.context,
            prepared.matched,
            &prepared.outcome,
            response_status,
            &response_headers,
            None,
        )
        .instrument(tracing::info_span!(
            "plugin.response_stage",
            plugin = plugin_name,
            buffered_body = false,
            upstream_status = response_status.as_u16()
        ))
        .await;

        finalize_streaming_plugin_response(
            executed.response,
            response_plan,
            response_source,
            upstream.url.as_str(),
        )
    }
    .instrument(plugin_span)
    .await
}

fn build_plugin_headers(headers: &HeaderMap) -> Vec<PluginHeaderInput> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value.to_str().ok().map(|value| PluginHeaderInput {
                name: name.as_str().to_string(),
                value: value.to_string(),
            })
        })
        .collect()
}

fn build_plugin_body(bytes: Option<&Bytes>) -> Option<PluginBodyInput> {
    let Some(bytes) = bytes else {
        return None;
    };

    if bytes.is_empty() {
        return None;
    }

    match std::str::from_utf8(bytes) {
        Ok(text) => Some(PluginBodyInput {
            kind: "text",
            value: text.to_string(),
        }),
        Err(_) => Some(PluginBodyInput {
            kind: "base64",
            value: BASE64_STANDARD.encode(bytes),
        }),
    }
}

fn build_plugin_request_context(
    source: &str,
    method: &Method,
    url: &Url,
    headers: &HeaderMap,
    body: Option<&Bytes>,
) -> PluginRequestContext {
    PluginRequestContext {
        source: source.to_string(),
        method: method.to_string(),
        url: url.to_string(),
        scheme: url.scheme().to_string(),
        host: url.host_str().map(str::to_string),
        port: url.port_or_known_default(),
        path: url.path().to_string(),
        query: url.query().map(str::to_string),
        headers: build_plugin_headers(headers),
        body: build_plugin_body(body),
    }
}

async fn collect_plugin_request_body(
    body: Body,
    body_access: bool,
) -> Result<PluginIncomingRequestBody, String> {
    if !body_access {
        return Ok(PluginIncomingRequestBody::Streaming(body));
    }

    body.collect()
        .await
        .map(|collected| PluginIncomingRequestBody::Buffered(collected.to_bytes()))
        .map_err(|error| format!("failed to read plugin request body: {error}"))
}

async fn collect_upstream_response(
    response: hyper::Response<hyper::body::Incoming>,
) -> Result<BufferedUpstreamResponse, String> {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .map(|collected| collected.to_bytes())
        .map_err(|error| format!("failed to read upstream response body: {error}"))?;

    Ok(BufferedUpstreamResponse {
        status,
        headers,
        body,
    })
}

fn prepare_plugin_request(
    method: Method,
    request_headers: &HeaderMap,
    request_body: PluginIncomingRequestBody,
    initial_request: PluginRequestContext,
    request_plan: Option<PluginRequestPlan>,
) -> Result<PreparedPluginRequest, String> {
    let mut headers = request_headers.clone();
    let mut body = request_body;
    let mut request = initial_request;
    let mut method = method;

    let (mut outcome, matched, request_patch) = match request_plan {
        Some(plan) => (plan.outcome, plan.matched, plan.request_patch),
        None => (
            PluginResolvedOutcome::Direct,
            None,
            PluginRequestPatch::default(),
        ),
    };

    if let Some(method_patch) = request_patch.method {
        method = method_patch.parse::<Method>().map_err(|error| {
            format!(
                "plugin request-stage returned invalid request method `{method_patch}`: {error}"
            )
        })?;
    }

    if let Some(url_patch) = request_patch.url {
        let patched_url = Url::parse(&url_patch).map_err(|error| {
            format!("plugin request-stage returned invalid request url `{url_patch}`: {error}")
        })?;
        request.url = patched_url.to_string();
        request.scheme = patched_url.scheme().to_string();
        request.host = patched_url.host_str().map(str::to_string);
        request.port = patched_url.port_or_known_default();
        request.path = patched_url.path().to_string();
        request.query = patched_url.query().map(str::to_string);

        if let PluginResolvedOutcome::Mirror(upstream) = &mut outcome {
            upstream.url = patched_url;
        }
    }

    apply_header_patches(&mut headers, &request_patch.headers).map_err(|error| {
        format!("plugin request-stage returned invalid request header patch: {error}")
    })?;

    if let Some(body_patch) = request_patch.body {
        body = PluginIncomingRequestBody::Buffered(body_patch);
        headers.remove(CONTENT_LENGTH);
        headers.remove(CONTENT_ENCODING);
    }

    request.method = method.to_string();
    request.headers = build_plugin_headers(&headers);
    request.body = build_plugin_body(body.bytes());

    Ok(PreparedPluginRequest {
        method,
        headers,
        body,
        context: request,
        outcome,
        matched,
    })
}

fn resolve_plugin_upstream<'a>(
    outcome: &'a PluginResolvedOutcome,
    request: &PluginRequestContext,
    source: Option<&'a str>,
) -> (UpstreamPlan, Option<&'a str>) {
    match outcome {
        PluginResolvedOutcome::Direct => {
            let url = Url::parse(&request.url)
                .expect("plugin request context should always contain a valid request url");
            (UpstreamPlan::direct(&url), source.or(Some("plugin-direct")))
        }
        PluginResolvedOutcome::Mirror(upstream) => {
            (upstream.clone(), source.or(Some("plugin-mirror")))
        }
        PluginResolvedOutcome::Reject(_) => unreachable!("reject outcomes do not resolve upstream"),
    }
}

async fn run_plugin_response_stage(
    plugins: &PluginRegistry,
    plugin_name: &str,
    request: PluginRequestContext,
    matched: Option<PluginMatchContext>,
    outcome: &PluginResolvedOutcome,
    response_status: StatusCode,
    response_headers: &HeaderMap,
    response_body: Option<&Bytes>,
) -> Result<Option<PluginResponsePlan>, String> {
    let context = PluginResponseStageContext::new(
        request,
        PluginMatchAction::from_outcome(outcome),
        PluginResponseContext {
            status: response_status.as_u16(),
            headers: build_plugin_headers(response_headers),
            body: build_plugin_body(response_body),
        },
    )
    .with_matched(matched);

    let response_plan = plugins
        .resolve_response(plugin_name, context)
        .await
        .map_err(|error| format!("plugin response-stage processing failed: {error}"))?;

    Ok(response_plan)
}

fn finalize_buffered_plugin_response(
    mut response: BufferedUpstreamResponse,
    response_plan: Result<Option<PluginResponsePlan>, String>,
    source: Option<&str>,
    target: &str,
) -> Response {
    let body_patch = match apply_plugin_response_patch(
        &mut response.status,
        &mut response.headers,
        response_plan,
    ) {
        Ok(body_patch) => body_patch,
        Err(error) => return json_error(StatusCode::BAD_GATEWAY, error),
    };

    if let Some(body) = body_patch {
        response.body = body;
        response.headers.remove(CONTENT_LENGTH);
        response.headers.remove(CONTENT_ENCODING);
    }

    build_buffered_response(response, source, target)
}

fn finalize_streaming_plugin_response(
    response: hyper::Response<hyper::body::Incoming>,
    response_plan: Result<Option<PluginResponsePlan>, String>,
    source: Option<&str>,
    target: &str,
) -> Response {
    let mut status = response.status();
    let mut headers = response.headers().clone();
    let body_override = match apply_plugin_response_patch(&mut status, &mut headers, response_plan)
    {
        Ok(body_override) => body_override,
        Err(error) => return json_error(StatusCode::BAD_GATEWAY, error),
    };

    if let Some(body) = body_override {
        return build_buffered_response(
            BufferedUpstreamResponse {
                status,
                headers,
                body,
            },
            source,
            target,
        );
    }

    build_streaming_response(status, headers, response.into_body(), source, target)
}

fn build_buffered_response(
    buffered: BufferedUpstreamResponse,
    source: Option<&str>,
    target: &str,
) -> Response {
    build_response(
        buffered.status,
        buffered.headers,
        Body::from(buffered.body),
        source,
        target,
    )
}

fn build_streaming_response(
    status: StatusCode,
    headers: HeaderMap,
    body: hyper::body::Incoming,
    source: Option<&str>,
    target: &str,
) -> Response {
    build_response(status, headers, Body::new(body), source, target)
}

fn build_response(
    status: StatusCode,
    headers: HeaderMap,
    body: Body,
    source: Option<&str>,
    target: &str,
) -> Response {
    let mut response = Response::builder().status(status);
    let response_headers = response.headers_mut().expect("response builder is valid");

    for (name, value) in &headers {
        response_headers.append(name, value.clone());
    }

    if let Some(source) = source {
        response_headers.insert(
            HeaderName::from_static("x-anymirror-mode"),
            source.parse().expect("static header value is valid"),
        );
    }
    response_headers.insert(
        HeaderName::from_static("x-anymirror-target"),
        target
            .parse()
            .unwrap_or_else(|_| "unavailable".parse().expect("fallback header is valid")),
    );

    response
        .body(body)
        .expect("response body build should not fail")
}

fn apply_plugin_response_patch(
    status: &mut StatusCode,
    headers: &mut HeaderMap,
    response_plan: Result<Option<PluginResponsePlan>, String>,
) -> Result<Option<Bytes>, String> {
    let response_plan = response_plan?;
    let Some(response_plan) = response_plan else {
        return Ok(None);
    };

    if let Some(patched_status) = response_plan.patch.status {
        *status = StatusCode::from_u16(patched_status).map_err(|_| {
            format!(
                "plugin response-stage returned invalid response status {}",
                patched_status
            )
        })?;
    }

    apply_header_patches(headers, &response_plan.patch.headers)
        .map_err(|error| format!("plugin response-stage returned invalid header patch: {error}"))?;

    Ok(response_plan.patch.body)
}

fn apply_header_patches(
    headers: &mut HeaderMap,
    patches: &[PluginHeaderPatch],
) -> Result<(), String> {
    for patch in patches {
        let name = HeaderName::try_from(patch.name.as_str())
            .map_err(|error| format!("invalid header name `{}`: {error}", patch.name))?;
        match &patch.value {
            Some(value) => {
                let value = HeaderValue::from_str(value).map_err(|error| {
                    format!("invalid header value for `{}`: {error}", patch.name)
                })?;
                headers.insert(name, value);
            }
            None => {
                headers.remove(name);
            }
        }
    }

    Ok(())
}

fn plugin_outcome_name(outcome: &PluginResolvedOutcome) -> &'static str {
    match outcome {
        PluginResolvedOutcome::Direct => "plugin-direct",
        PluginResolvedOutcome::Mirror(_) => "plugin-mirror",
        PluginResolvedOutcome::Reject(_) => "plugin-reject",
    }
}
