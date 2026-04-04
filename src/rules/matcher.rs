use anyhow::{bail, ensure, Result};
use url::Url;

pub(super) fn same_origin(left: &Url, right: &Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

pub(super) fn same_url(left: &Url, right: &Url) -> bool {
    same_origin(left, right) && left.path() == right.path() && left.query() == right.query()
}

pub(super) fn path_has_prefix(path: &str, prefix: &str) -> bool {
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

pub(super) fn join_paths(base: &str, suffix: &str) -> String {
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

pub(super) fn normalize_host(value: &str) -> Result<String> {
    let normalized = value.trim().trim_end_matches('.').to_ascii_lowercase();
    ensure!(!normalized.is_empty(), "host matcher must not be empty");
    ensure!(
        !normalized.contains("://") && !normalized.contains('/'),
        "host matcher must be a bare hostname: `{}`",
        value
    );
    Ok(normalized)
}

pub(super) fn normalize_host_suffix(value: &str) -> Result<String> {
    let normalized = value.trim().trim_matches('.').to_ascii_lowercase();
    ensure!(
        !normalized.is_empty(),
        "host_suffix matcher must not be empty"
    );
    ensure!(
        !normalized.contains("://") && !normalized.contains('/'),
        "host_suffix matcher must be a bare hostname suffix: `{}`",
        value
    );
    Ok(normalized)
}

pub(super) fn normalize_scheme(value: &str) -> Result<&str> {
    match value {
        "http" | "https" => Ok(value),
        _ => bail!(
            "rule.match.scheme must be `http` or `https`, got `{}`",
            value
        ),
    }
}

pub(super) fn normalize_path_prefix(value: &str) -> Result<&str> {
    ensure!(
        value.starts_with('/'),
        "rule.match.path_prefix must start with `/`, got `{}`",
        value
    );
    Ok(value)
}
