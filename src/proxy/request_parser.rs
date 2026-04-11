use axum::http::{HeaderMap, StatusCode, Uri, header::HOST, uri::Authority};
use axum::response::Response;
use url::Url;

use super::responses::json_error;

pub(crate) const ORIGINAL_URL_HEADER: &str = "x-anymirror-original-url";
pub(crate) const ORIGINAL_SCHEME_HEADER: &str = "x-anymirror-original-scheme";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnectAuthority {
    authority: String,
    host: String,
    port: u16,
}

impl ConnectAuthority {
    pub(crate) fn authority(&self) -> &str {
        &self.authority
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    pub(crate) fn host_header(&self) -> String {
        if self.port == 443 {
            format_authority_host(self.host())
        } else {
            format_url_authority(self.host(), self.port())
        }
    }

    pub(crate) fn https_authority(&self) -> String {
        format_url_authority(self.host(), self.port())
    }
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

pub(crate) fn parse_connect_authority(raw_uri: &str) -> Result<ConnectAuthority, Response> {
    let authority = raw_uri.parse::<Authority>().map_err(|error| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!("invalid CONNECT authority `{raw_uri}`: {error}"),
        )
    })?;

    if authority.port_u16().is_none() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            format!("CONNECT authority `{raw_uri}` must include an explicit port"),
        ));
    }

    Ok(ConnectAuthority {
        authority: authority.as_str().to_string(),
        host: authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string(),
        port: authority.port_u16().expect("checked above"),
    })
}

pub(crate) fn resolve_explicit_https_target(
    connect_target: &ConnectAuthority,
    uri: &Uri,
) -> Result<Url, Response> {
    let raw_uri = uri.to_string();
    if let Ok(url) = parse_absolute_url(&raw_uri) {
        validate_connect_target_url(connect_target, &url)?;
        return Ok(url);
    }

    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");

    parse_request_url(&format!(
        "https://{}{path_and_query}",
        connect_target.https_authority()
    ))
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

fn validate_connect_target_url(
    connect_target: &ConnectAuthority,
    url: &Url,
) -> Result<(), Response> {
    if url.scheme() != "https" {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            format!(
                "explicit HTTPS interception only accepts `https` absolute URIs inside CONNECT tunnels, got `{}`",
                url
            ),
        ));
    }

    let Some(host) = url.host_str() else {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            format!("absolute URI inside CONNECT tunnel is missing host: `{url}`"),
        ));
    };
    let port = url.port_or_known_default().ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            format!("absolute URI inside CONNECT tunnel is missing port: `{url}`"),
        )
    })?;

    if host != connect_target.host() || port != connect_target.port() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            format!(
                "absolute URI `{url}` does not match CONNECT target `{}`",
                connect_target.authority()
            ),
        ));
    }

    Ok(())
}

fn format_url_authority(host: &str, port: u16) -> String {
    if port == 443 {
        return format_authority_host(host);
    }

    format!("{}:{port}", format_authority_host(host))
}

fn format_authority_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
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
    use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header::HOST};

    use super::{
        ConnectAuthority, ORIGINAL_SCHEME_HEADER, ORIGINAL_URL_HEADER, parse_connect_authority,
        resolve_explicit_https_target, resolve_transparent_target,
    };

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

    #[test]
    fn parses_connect_authority_with_explicit_port() {
        let authority = parse_connect_authority("example.com:443").unwrap();

        assert_eq!(
            authority,
            ConnectAuthority {
                authority: "example.com:443".to_string(),
                host: "example.com".to_string(),
                port: 443,
            }
        );
    }

    #[test]
    fn parses_connect_authority_with_ipv6_host() {
        let authority = parse_connect_authority("[2001:db8::1]:8443").unwrap();

        assert_eq!(
            authority,
            ConnectAuthority {
                authority: "[2001:db8::1]:8443".to_string(),
                host: "2001:db8::1".to_string(),
                port: 8443,
            }
        );
    }

    #[test]
    fn rejects_connect_authority_without_port() {
        let response = parse_connect_authority("example.com").unwrap_err();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn resolves_explicit_https_target_from_origin_form() {
        let target = ConnectAuthority {
            authority: "example.com:443".to_string(),
            host: "example.com".to_string(),
            port: 443,
        };
        let uri: Uri = "/index.html?lang=en".parse().unwrap();

        let resolved = resolve_explicit_https_target(&target, &uri).unwrap();

        assert_eq!(resolved.as_str(), "https://example.com/index.html?lang=en");
    }

    #[test]
    fn rejects_absolute_uri_that_does_not_match_connect_target() {
        let target = ConnectAuthority {
            authority: "example.com:443".to_string(),
            host: "example.com".to_string(),
            port: 443,
        };
        let uri: Uri = "https://other.example.com/".parse().unwrap();

        let response = resolve_explicit_https_target(&target, &uri).unwrap_err();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}
