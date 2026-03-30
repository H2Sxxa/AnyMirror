use axum::http::{
    header::{
        CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING,
        UPGRADE,
    },
    HeaderName,
};

pub(super) fn is_forwardable_header(name: &HeaderName) -> bool {
    *name != HOST
        && *name != CONNECTION
        && *name != HeaderName::from_static("keep-alive")
        && *name != PROXY_AUTHENTICATE
        && *name != PROXY_AUTHORIZATION
        && *name != HeaderName::from_static("proxy-connection")
        && *name != TE
        && *name != TRAILER
        && *name != TRANSFER_ENCODING
        && *name != UPGRADE
}
