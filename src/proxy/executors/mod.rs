use std::{future::Future, pin::Pin};

use ::hyper::{Response, body::Incoming};
use anyhow::Result;
use axum::body::Body;
use axum::http::{HeaderMap, Method};

use crate::rules::model::UpstreamPlan;

pub(crate) mod hyper;

pub(crate) use hyper::HyperExecutor;

pub(crate) struct ExecutedUpstream {
    pub(crate) response: Response<Incoming>,
}

pub(crate) trait UpstreamExecutor: Clone + Send + Sync + 'static {
    fn execute(
        &self,
        method: Method,
        inbound_headers: &HeaderMap,
        original_url: &str,
        upstream: &UpstreamPlan,
        body: Body,
    ) -> Pin<Box<dyn Future<Output = Result<ExecutedUpstream>> + Send>>;
}
