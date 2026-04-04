use axum::http::{HeaderMap, Method, StatusCode, Uri, header::HOST};
use axum::response::Response;
use url::Url;

use super::responses::json_error;

pub(crate) const ORIGINAL_URL_HEADER: &str = "x-anymirror-original-url";
pub(crate) const ORIGINAL_SCHEME_HEADER: &str = "x-anymirror-original-scheme";

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
    if method == Method::CONNECT {
        return Err(json_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "CONNECT method is not supported for plain HTTP forwarding yet",
        ));
    }
    Ok(())
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
