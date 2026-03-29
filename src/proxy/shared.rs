use axum::{
    Json,
    http::{HeaderMap, Method, StatusCode, Uri, header::HOST},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::rules::{Rewrite, RuleKind};

pub(crate) const ORIGINAL_URL_HEADER: &str = "x-anymirror-original-url";
pub(crate) const ORIGINAL_SCHEME_HEADER: &str = "x-anymirror-original-scheme";

#[derive(Debug, Deserialize)]
pub(crate) struct RewriteQuery {
    pub(crate) url: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct RewriteResponse {
    pub(crate) original: String,
    pub(crate) rewritten: String,
    pub(crate) kind: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

pub(crate) fn parse_request_url(raw: &str) -> Result<Url, Response> {
    Url::parse(raw)
        .map_err(|error| json_error(StatusCode::BAD_REQUEST, format!("invalid url: {error}")))
}

pub(crate) fn parse_absolute_url(raw_uri: &str) -> Result<Url, Response> {
    if !(raw_uri.starts_with("http://") || raw_uri.starts_with("https://")) {
        return Err(json_error(
            StatusCode::NOT_FOUND,
            "unknown route, try /rewrite?url=<url> or /fetch?url=<url>",
        ));
    }

    Url::parse(raw_uri).map_err(|error| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!("invalid absolute request uri: {error}"),
        )
    })
}

pub(crate) fn resolve_transparent_target(headers: &HeaderMap, uri: &Uri) -> Result<Url, Response> {
    if let Some(original_url) = read_optional_header(headers, ORIGINAL_URL_HEADER)? {
        return parse_request_url(&original_url);
    }

    if let Ok(url) = parse_absolute_url(&uri.to_string()) {
        return Ok(url);
    }

    let host = read_required_host(headers)?;
    let scheme = match read_optional_header(headers, ORIGINAL_SCHEME_HEADER)? {
        Some(scheme) => normalize_scheme(&scheme)?,
        None => "http".to_string(),
    };
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    parse_request_url(&format!("{scheme}://{host}{path_and_query}"))
}

pub(crate) fn ensure_supported_method(method: &Method) -> Result<(), Response> {
    if matches!(*method, Method::GET | Method::HEAD) {
        Ok(())
    } else {
        Err(json_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "only GET and HEAD are supported",
        ))
    }
}

pub(crate) fn json_error(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorResponse {
            error: message.into(),
        }),
    )
        .into_response()
}

pub(crate) fn rule_kind_name(rewrite: Rewrite<'_>) -> &'static str {
    match rewrite.rule.kind {
        RuleKind::Exact => "exact",
        RuleKind::Prefix => "prefix",
    }
}

pub(crate) async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn read_required_host(headers: &HeaderMap) -> Result<String, Response> {
    match read_optional_header_map_value(headers, HOST.as_str())? {
        Some(host) => Ok(host),
        None => Err(json_error(
            StatusCode::BAD_REQUEST,
            "transparent mode requires a Host header or x-anymirror-original-url",
        )),
    }
}

fn normalize_scheme(raw: &str) -> Result<String, Response> {
    match raw {
        "http" | "https" => Ok(raw.to_string()),
        _ => Err(json_error(
            StatusCode::BAD_REQUEST,
            format!("unsupported original scheme `{raw}`"),
        )),
    }
}

fn read_optional_header(headers: &HeaderMap, name: &str) -> Result<Option<String>, Response> {
    read_optional_header_map_value(headers, name)
}

fn read_optional_header_map_value(
    headers: &HeaderMap,
    name: &str,
) -> Result<Option<String>, Response> {
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };

    value
        .to_str()
        .map(|value| Some(value.to_string()))
        .map_err(|_| {
            json_error(
                StatusCode::BAD_REQUEST,
                format!("invalid `{name}` header value"),
            )
        })
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderValue, Uri, header::HOST};

    use super::{ORIGINAL_SCHEME_HEADER, ORIGINAL_URL_HEADER, resolve_transparent_target};

    #[test]
    fn resolves_transparent_target_from_original_url_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            ORIGINAL_URL_HEADER,
            HeaderValue::from_static("https://libraries.minecraft.net/a/b.jar"),
        );
        let uri: Uri = "/ignored".parse().unwrap();

        let url = resolve_transparent_target(&headers, &uri).unwrap();

        assert_eq!(url.as_str(), "https://libraries.minecraft.net/a/b.jar");
    }

    #[test]
    fn resolves_transparent_target_from_host_and_path() {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("libraries.minecraft.net"));
        headers.insert(ORIGINAL_SCHEME_HEADER, HeaderValue::from_static("https"));
        let uri: Uri = "/com/example/demo.jar?download=1".parse().unwrap();

        let url = resolve_transparent_target(&headers, &uri).unwrap();

        assert_eq!(
            url.as_str(),
            "https://libraries.minecraft.net/com/example/demo.jar?download=1"
        );
    }
}
