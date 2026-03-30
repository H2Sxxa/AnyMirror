use url::Url;

use super::RuleKind;

pub(super) fn infer_rule_kind(origin: &Url, raw_origin: &str) -> RuleKind {
    if origin.path() == "/" || raw_origin.ends_with('/') {
        RuleKind::Prefix
    } else {
        RuleKind::Exact
    }
}

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
