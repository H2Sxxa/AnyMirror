use std::net::{IpAddr, SocketAddr};
use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::{anyhow, Result};
use axum::body::Body;
use axum::http::{header::HOST, HeaderMap, Method, Request};
// use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;

use crate::rules::UpstreamPlan;

use super::headers::is_forwardable_header;
use super::resolver::CustomResolver;

pub(crate) struct ExecutedUpstream {
    pub(crate) response: hyper::Response<hyper::body::Incoming>,
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

#[derive(Clone)]
pub(crate) struct HyperExecutor {
    tls_config: Arc<rustls::ClientConfig>,
}

impl HyperExecutor {
    pub(crate) fn new() -> Result<Self> {
        let mut root_cert_store = rustls::RootCertStore::empty();
        let certs_result = rustls_native_certs::load_native_certs();
        for cert in certs_result.certs {
            root_cert_store.add(cert)?;
        }

        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();

        Ok(Self {
            tls_config: Arc::new(tls_config),
        })
    }
}

impl UpstreamExecutor for HyperExecutor {
    fn execute(
        &self,
        method: Method,
        inbound_headers: &HeaderMap,
        original_url: &str,
        upstream: &UpstreamPlan,
        body: Body,
    ) -> Pin<Box<dyn Future<Output = Result<ExecutedUpstream>> + Send>> {
        let tls_config = self.tls_config.clone();
        let headers = inbound_headers.clone();
        let original_url = original_url.to_string();
        let upstream = upstream.clone();

        Box::pin(async move {
            let scheme = upstream.url.scheme();
            let is_https = scheme == "https";
            let port = upstream
                .url
                .port_or_known_default()
                .ok_or_else(|| anyhow!("Unknown target port"))?;

            // Determine the target IP for connection
            let target_ip = resolve_connection_ip(&upstream).await?;
            let target_addr = SocketAddr::new(target_ip, port);

            // Establish TCP connection
            let tcp = TcpStream::connect(target_addr).await?;

            // Build the HTTP request
            let path_and_query = match upstream.url.query() {
                Some(q) => format!("{}?{}", upstream.url.path(), q),
                None => upstream.url.path().to_string(),
            };

            let mut req = Request::builder().method(method).uri(&path_and_query);

            // Set Host header
            let host_header = if let Some(host) = upstream.host.as_deref() {
                host.to_string()
            } else if let Some(host) = upstream.url.host_str() {
                host.to_string()
            } else {
                return Err(anyhow!("No host in target URL"));
            };

            let req_headers = req.headers_mut().unwrap();
            req_headers.insert(HOST, host_header.parse()?);

            // Forward other request headers
            for (name, value) in &headers {
                if is_forwardable_header(name) {
                    req_headers.insert(name.clone(), value.clone());
                }
            }

            if upstream.url.as_str() != original_url {
                req_headers.insert("x-anymirror-original-url", original_url.parse()?);
            }

            let req = req.body(body)?;

            let response = if is_https {
                // Determine SNI
                let sni = upstream
                    .sni
                    .as_deref()
                    .or_else(|| upstream.url.host_str())
                    .ok_or_else(|| anyhow!("No SNI host"))?
                    .to_string();

                let domain = rustls_pki_types::ServerName::try_from(sni)?;
                let connector = TlsConnector::from(tls_config);
                let tls_stream = connector.connect(domain, tcp).await?;
                let io = TokioIo::new(tls_stream);

                let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
                spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::debug!("https connection failed: {:?}", e);
                    }
                });
                sender.send_request(req).await?
            } else {
                let io = TokioIo::new(tcp);
                let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
                spawn(async move {
                    if let Err(e) = conn.await {
                        tracing::debug!("http connection failed: {:?}", e);
                    }
                });
                sender.send_request(req).await?
            };

            Ok(ExecutedUpstream { response })
        })
    }
}

/// Resolve the final IP address to connect to
async fn resolve_connection_ip(upstream: &UpstreamPlan) -> Result<IpAddr> {
    if let Some(ip) = upstream.connect_ip {
        return Ok(ip);
    }

    let connect_host = upstream
        .connect_host
        .as_deref()
        .or_else(|| upstream.url.host_str())
        .ok_or_else(|| anyhow!("No host to connect to"))?;

    let resolver = if let Some(dns) = upstream.dns.as_ref() {
        CustomResolver::from_plan(dns).await?
    } else {
        CustomResolver::system()?
    };

    resolver.resolve(connect_host).await
}
