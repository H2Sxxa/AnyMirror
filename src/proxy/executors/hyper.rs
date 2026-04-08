use std::net::{IpAddr, SocketAddr};
use std::{future::Future, pin::Pin, sync::Arc};

use anyhow::{Result, anyhow};
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, header::HOST};
use hyper_util::rt::TokioIo;
use tokio::net::TcpStream;
use tokio::spawn;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;
use tracing::{Instrument, Span, field};

use crate::rules::model::UpstreamPlan;

use super::super::{headers::is_forwardable_header, resolver::CustomResolver};
use super::{ExecutedUpstream, UpstreamExecutor};

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
        let method_name = method.to_string();

        let execute_span = tracing::info_span!(
            "upstream.execute",
            request_method = %method_name,
            original_url = %original_url,
            upstream_url = %upstream.url,
            scheme = field::Empty,
            upstream_host = field::Empty,
            connect_host = field::Empty,
            connect_ip = field::Empty,
            sni = field::Empty,
            target_ip = field::Empty,
            target_port = field::Empty,
            response_status = field::Empty
        );

        Box::pin(
            async move {
                let scheme = upstream.url.scheme();
                let is_https = scheme == "https";
                Span::current().record("scheme", scheme);
                let port = upstream
                    .url
                    .port_or_known_default()
                    .ok_or_else(|| anyhow!("Unknown target port"))?;
                Span::current().record("target_port", port);

                if let Some(host) = upstream.host.as_deref().or_else(|| upstream.url.host_str()) {
                    Span::current().record("upstream_host", host);
                }
                if let Some(connect_host) = upstream
                    .connect_host
                    .as_deref()
                    .or_else(|| upstream.url.host_str())
                {
                    Span::current().record("connect_host", connect_host);
                }
                if let Some(connect_ip) = upstream.connect_ip {
                    Span::current().record("connect_ip", field::display(connect_ip));
                }

                let target_ip = resolve_connection_ip(&upstream).await?;
                Span::current().record("target_ip", field::display(target_ip));
                let target_addr = SocketAddr::new(target_ip, port);

                let tcp = async move { TcpStream::connect(target_addr).await }
                    .instrument(tracing::info_span!("tcp.connect", peer = %target_addr))
                    .await?;

                let path_and_query = match upstream.url.query() {
                    Some(query) => format!("{}?{}", upstream.url.path(), query),
                    None => upstream.url.path().to_string(),
                };

                let mut request = Request::builder().method(method).uri(&path_and_query);

                let host_header = if let Some(host) = upstream.host.as_deref() {
                    host.to_string()
                } else if let Some(host) = upstream.url.host_str() {
                    host.to_string()
                } else {
                    return Err(anyhow!("No host in target URL"));
                };

                let request_headers = request
                    .headers_mut()
                    .ok_or_else(|| anyhow!("request builder did not provide mutable headers"))?;
                request_headers.insert(
                    HOST,
                    host_header.parse().map_err(|error| {
                        anyhow!("invalid Host header value `{}`: {}", host_header, error)
                    })?,
                );

                for (name, value) in &headers {
                    if is_forwardable_header(name) {
                        request_headers.insert(name.clone(), value.clone());
                    }
                }

                if upstream.url.as_str() != original_url {
                    request_headers.insert(
                        "x-anymirror-original-url",
                        original_url.parse().map_err(|error| {
                            anyhow!(
                                "invalid x-anymirror-original-url header value `{}`: {}",
                                original_url,
                                error
                            )
                        })?,
                    );
                }

                let request = request.body(body)?;

                let response = if is_https {
                    let sni = upstream
                        .sni
                        .as_deref()
                        .or_else(|| upstream.url.host_str())
                        .ok_or_else(|| anyhow!("No SNI host"))?
                        .to_string();
                    Span::current().record("sni", sni.as_str());

                    let domain = rustls_pki_types::ServerName::try_from(sni)
                        .map_err(|error| anyhow!("invalid TLS server name: {}", error))?;
                    let connector = TlsConnector::from(tls_config);
                    let tls_stream = async move { connector.connect(domain, tcp).await }
                        .instrument(tracing::info_span!(
                            "tls.handshake",
                            peer = %target_addr
                        ))
                        .await?;
                    let io = TokioIo::new(tls_stream);

                    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
                    spawn(async move {
                        if let Err(error) = conn.await {
                            tracing::debug!("https connection failed: {:?}", error);
                        }
                    });

                    async move { sender.send_request(request).await }
                        .instrument(tracing::info_span!(
                            "http.upstream_send",
                            protocol = "https",
                            path = %path_and_query,
                            peer = %target_addr
                        ))
                        .await?
                } else {
                    let io = TokioIo::new(tcp);
                    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
                    spawn(async move {
                        if let Err(error) = conn.await {
                            tracing::debug!("http connection failed: {:?}", error);
                        }
                    });

                    async move { sender.send_request(request).await }
                        .instrument(tracing::info_span!(
                            "http.upstream_send",
                            protocol = "http",
                            path = %path_and_query,
                            peer = %target_addr
                        ))
                        .await?
                };

                Span::current().record("response_status", response.status().as_u16());
                Ok(ExecutedUpstream { response })
            }
            .instrument(execute_span),
        )
    }
}

async fn resolve_connection_ip(upstream: &UpstreamPlan) -> Result<IpAddr> {
    let resolve_span = tracing::info_span!(
        "upstream.resolve_address",
        connect_host = field::Empty,
        dns_mode = field::Empty,
        dns_server = field::Empty,
        resolved_ip = field::Empty
    );

    async {
        if let Some(ip) = upstream.connect_ip {
            Span::current().record("resolved_ip", field::display(ip));
            return Ok(ip);
        }

        let connect_host = upstream
            .connect_host
            .as_deref()
            .or_else(|| upstream.url.host_str())
            .ok_or_else(|| anyhow!("No host to connect to"))?;
        Span::current().record("connect_host", connect_host);

        let resolver = if let Some(dns) = upstream.dns.as_ref() {
            Span::current().record("dns_mode", field::debug(dns.mode));
            if let Some(server) = dns.server.as_deref() {
                Span::current().record("dns_server", server);
            }
            CustomResolver::from_plan(dns).await?
        } else {
            Span::current().record("dns_mode", "system");
            CustomResolver::system()?
        };

        let ip = resolver
            .resolve(connect_host)
            .instrument(tracing::info_span!("dns.lookup", hostname = %connect_host))
            .await?;
        Span::current().record("resolved_ip", field::display(ip));
        Ok(ip)
    }
    .instrument(resolve_span)
    .await
}
