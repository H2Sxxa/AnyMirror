use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Result, anyhow};
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, Uri, header::HOST};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::{
    Client,
    connect::{Connected, Connection},
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::spawn;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;
use tracing::{Instrument, Span, field};

use crate::rules::model::UpstreamPlan;

use super::super::{headers::is_forwardable_header, resolver::CustomResolver};
use super::{ExecutedUpstream, UpstreamExecutor};

type PooledHttp1Client = Client<PooledUpstreamConnector, Body>;
type UpstreamTlsStream = tokio_rustls::client::TlsStream<TcpStream>;

const POOLED_HTTP1_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const POOLED_HTTP1_MAX_IDLE_PER_HOST: usize = 8;

#[derive(Clone)]
pub(crate) struct HyperExecutor {
    tls_config: Arc<rustls::ClientConfig>,
    pooled_http1_client: PooledHttp1Client,
}

#[derive(Clone)]
struct PooledUpstreamConnector {
    tls_config: Arc<rustls::ClientConfig>,
}

struct PooledConnection {
    inner: TokioIo<PooledUpstreamStream>,
}

enum PooledUpstreamStream {
    Tcp(TcpStream),
    Tls(UpstreamTlsStream),
}

#[derive(Clone, Copy)]
enum UpstreamExecutionMode {
    SingleShot,
    PooledHttp1,
    // Reserved for a future pooled HTTP/2 path once authority semantics are modeled safely.
}

impl HyperExecutor {
    pub(crate) fn new() -> Result<Self> {
        let mut root_cert_store = rustls::RootCertStore::empty();
        let certs_result = rustls_native_certs::load_native_certs();
        for cert in certs_result.certs {
            root_cert_store.add(cert)?;
        }

        let tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth(),
        );
        let pooled_http1_client = build_pooled_http1_client(tls_config.clone());

        Ok(Self {
            tls_config,
            pooled_http1_client,
        })
    }
}

impl UpstreamExecutionMode {
    fn label(self) -> &'static str {
        match self {
            Self::SingleShot => "single-shot",
            Self::PooledHttp1 => "pooled-h1",
        }
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
        let pooled_http1_client = self.pooled_http1_client.clone();
        let headers = inbound_headers.clone();
        let original_url = original_url.to_string();
        let upstream = upstream.clone();
        let method_name = method.to_string();
        let execution_mode = select_execution_mode(&upstream);

        let execute_span = tracing::info_span!(
            "upstream.execute",
            request_method = %method_name,
            original_url = %original_url,
            upstream_url = %upstream.url,
            execution_mode = execution_mode.label(),
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

                let path_and_query = build_path_and_query(&upstream);
                let host_header = build_host_header(&upstream)?;

                let response = match execution_mode {
                    UpstreamExecutionMode::PooledHttp1 => {
                        let absolute_uri = build_absolute_request_uri(&upstream)?;
                        let request = build_request(
                            method,
                            absolute_uri.to_string(),
                            &host_header,
                            &headers,
                            &original_url,
                            &upstream,
                            body,
                        )?;

                        async move { pooled_http1_client.request(request).await }
                            .instrument(tracing::info_span!(
                                "http.upstream_send",
                                protocol = scheme,
                                path = %path_and_query
                            ))
                            .await
                            .map_err(|error| anyhow!("upstream request failed: {}", error))?
                    }
                    UpstreamExecutionMode::SingleShot => {
                        let target_ip = resolve_connection_ip(&upstream).await?;
                        Span::current().record("target_ip", field::display(target_ip));
                        let target_addr = SocketAddr::new(target_ip, port);

                        let tcp = async move { TcpStream::connect(target_addr).await }
                            .instrument(tracing::info_span!("tcp.connect", peer = %target_addr))
                            .await?;

                        let request = build_request(
                            method,
                            path_and_query.clone(),
                            &host_header,
                            &headers,
                            &original_url,
                            &upstream,
                            body,
                        )?;

                        if is_https {
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

                            let (mut sender, conn) =
                                hyper::client::conn::http1::handshake(io).await?;
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
                            let (mut sender, conn) =
                                hyper::client::conn::http1::handshake(io).await?;
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
                        }
                    }
                };

                Span::current().record("response_status", response.status().as_u16());
                Ok(ExecutedUpstream { response })
            }
            .instrument(execute_span),
        )
    }
}

impl tower::Service<Uri> for PooledUpstreamConnector {
    type Response = PooledConnection;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let tls_config = self.tls_config.clone();

        Box::pin(async move {
            let connect_span = tracing::info_span!(
                "upstream.connect",
                scheme = field::Empty,
                connect_host = field::Empty,
                sni = field::Empty,
                target_ip = field::Empty,
                target_port = field::Empty
            );

            async move {
                let scheme = dst
                    .scheme_str()
                    .ok_or_else(|| anyhow!("pooled upstream uri `{}` is missing scheme", dst))?;
                let host = dst
                    .host()
                    .ok_or_else(|| anyhow!("pooled upstream uri `{}` is missing host", dst))?;
                let port = dst
                    .port_u16()
                    .or_else(|| match scheme {
                        "http" => Some(80),
                        "https" => Some(443),
                        _ => None,
                    })
                    .ok_or_else(|| anyhow!("pooled upstream uri `{}` has unknown port", dst))?;

                Span::current().record("scheme", scheme);
                Span::current().record("connect_host", host);
                Span::current().record("target_port", port);

                let target_ip = resolve_connection_ip_for_host(host).await?;
                Span::current().record("target_ip", field::display(target_ip));
                let target_addr = SocketAddr::new(target_ip, port);

                let tcp = async move { TcpStream::connect(target_addr).await }
                    .instrument(tracing::info_span!("tcp.connect", peer = %target_addr))
                    .await?;

                if scheme == "https" {
                    Span::current().record("sni", host);
                    let domain = rustls_pki_types::ServerName::try_from(host.to_string())
                        .map_err(|error| anyhow!("invalid TLS server name: {}", error))?;
                    let connector = TlsConnector::from(tls_config);
                    let tls_stream = async move { connector.connect(domain, tcp).await }
                        .instrument(tracing::info_span!(
                            "tls.handshake",
                            peer = %target_addr
                        ))
                        .await?;
                    return Ok(PooledConnection::new(PooledUpstreamStream::Tls(tls_stream)));
                }

                Ok(PooledConnection::new(PooledUpstreamStream::Tcp(tcp)))
            }
            .instrument(connect_span)
            .await
        })
    }
}

impl PooledConnection {
    fn new(stream: PooledUpstreamStream) -> Self {
        Self {
            inner: TokioIo::new(stream),
        }
    }
}

impl Connection for PooledConnection {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

impl Read for PooledConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // SAFETY: projecting `inner` does not move the pinned connection.
        unsafe { self.map_unchecked_mut(|connection| &mut connection.inner) }.poll_read(cx, buf)
    }
}

impl Write for PooledConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        // SAFETY: projecting `inner` does not move the pinned connection.
        unsafe { self.map_unchecked_mut(|connection| &mut connection.inner) }.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Result<(), io::Error>> {
        // SAFETY: projecting `inner` does not move the pinned connection.
        unsafe { self.map_unchecked_mut(|connection| &mut connection.inner) }.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), io::Error>> {
        // SAFETY: projecting `inner` does not move the pinned connection.
        unsafe { self.map_unchecked_mut(|connection| &mut connection.inner) }.poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        // SAFETY: projecting `inner` does not move the pinned connection.
        unsafe { self.map_unchecked_mut(|connection| &mut connection.inner) }
            .poll_write_vectored(cx, bufs)
    }
}

impl AsyncRead for PooledUpstreamStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.as_mut().get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for PooledUpstreamStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        match self.as_mut().get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.as_mut().get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), io::Error>> {
        match self.as_mut().get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Tcp(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match self.as_mut().get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
        }
    }
}

fn build_pooled_http1_client(tls_config: Arc<rustls::ClientConfig>) -> PooledHttp1Client {
    let connector = PooledUpstreamConnector { tls_config };
    let timer = TokioTimer::new();
    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .pool_timer(timer)
        .pool_idle_timeout(POOLED_HTTP1_IDLE_TIMEOUT)
        .pool_max_idle_per_host(POOLED_HTTP1_MAX_IDLE_PER_HOST)
        .set_host(false);
    builder.build(connector)
}

fn select_execution_mode(upstream: &UpstreamPlan) -> UpstreamExecutionMode {
    if is_pooled_http1_eligible(upstream) {
        UpstreamExecutionMode::PooledHttp1
    } else {
        UpstreamExecutionMode::SingleShot
    }
}

fn is_pooled_http1_eligible(upstream: &UpstreamPlan) -> bool {
    upstream.host.is_none()
        && upstream.connect_host.is_none()
        && upstream.connect_ip.is_none()
        && upstream.sni.is_none()
        && upstream.dns.is_none()
}

fn build_path_and_query(upstream: &UpstreamPlan) -> String {
    match upstream.url.query() {
        Some(query) => format!("{}?{}", upstream.url.path(), query),
        None => upstream.url.path().to_string(),
    }
}

fn build_absolute_request_uri(upstream: &UpstreamPlan) -> Result<Uri> {
    let host = upstream
        .url
        .host_str()
        .ok_or_else(|| anyhow!("No host in target URL"))?;
    let authority = normalize_authority(host, upstream.url.port());
    let path_and_query = build_path_and_query(upstream);

    Uri::builder()
        .scheme(upstream.url.scheme())
        .authority(authority.as_str())
        .path_and_query(path_and_query.as_str())
        .build()
        .map_err(|error| {
            anyhow!(
                "failed to build pooled upstream uri for `{}`: {}",
                upstream.url,
                error
            )
        })
}

fn build_host_header(upstream: &UpstreamPlan) -> Result<String> {
    if let Some(host) = upstream.host.as_deref() {
        return Ok(host.to_string());
    }

    upstream
        .url
        .host_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("No host in target URL"))
}

fn build_request(
    method: Method,
    request_uri: String,
    host_header: &str,
    inbound_headers: &HeaderMap,
    original_url: &str,
    upstream: &UpstreamPlan,
    body: Body,
) -> Result<Request<Body>> {
    let mut request = Request::builder().method(method).uri(request_uri);
    let request_headers = request
        .headers_mut()
        .ok_or_else(|| anyhow!("request builder did not provide mutable headers"))?;

    request_headers.insert(
        HOST,
        host_header.parse().map_err(|error| {
            anyhow!("invalid Host header value `{}`: {}", host_header, error)
        })?,
    );

    for (name, value) in inbound_headers {
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

    request.body(body).map_err(Into::into)
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

async fn resolve_connection_ip_for_host(connect_host: &str) -> Result<IpAddr> {
    let resolve_span = tracing::info_span!(
        "upstream.resolve_address",
        connect_host = %connect_host,
        dns_mode = "system",
        dns_server = field::Empty,
        resolved_ip = field::Empty
    );

    async move {
        let resolver = CustomResolver::system()?;
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

fn normalize_authority(host: &str, port: Option<u16>) -> String {
    if host.contains(':') && !host.starts_with('[') {
        match port {
            Some(port) => format!("[{}]:{}", host, port),
            None => format!("[{}]", host),
        }
    } else {
        match port {
            Some(port) => format!("{}:{}", host, port),
            None => host.to_string(),
        }
    }
}
