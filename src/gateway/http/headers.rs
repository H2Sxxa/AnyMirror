use axum::http::{
    HeaderName,
    header::{
        CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, TE, TRAILER, TRANSFER_ENCODING,
        UPGRADE,
    },
};

pub(crate) fn is_end_to_end_header(name: &HeaderName) -> bool {
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
