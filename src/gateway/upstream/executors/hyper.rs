use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, Uri, Version};
use hyper::rt::{Read, ReadBufCursor, Write};
use hyper_util::client::legacy::{
    Client,
    connect::{Connected, Connection},
};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls;
use tracing::{Instrument, Span, field};

use crate::rules::model::UpstreamPlan;

use super::{ExecutedUpstream, UpstreamExecutor};
use crate::gateway::{http::headers::is_end_to_end_header, upstream::resolver::CustomResolver};

type PooledHttp1Client = Client<PooledTransportConnector, Body>;
type UpstreamTlsStream = tokio_rustls::client::TlsStream<TcpStream>;
type ResolverCache = Arc<Mutex<HashMap<ResolverIdentity, Arc<CustomResolver>>>>;
type DnsResultCache = Arc<Mutex<HashMap<DnsLookupKey, CachedDnsLookup>>>;

const POOLED_HTTP1_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
const POOLED_HTTP1_MAX_IDLE_PER_HOST: usize = 8;
const DNS_RESULT_CACHE_TTL: Duration = Duration::from_secs(10);
const POOLED_HTTP_ALPN_PROTOCOLS: &[&[u8]] = &[b"h2", b"http/1.1"];

#[derive(Clone)]
pub(crate) struct HyperExecutor {
    tls_config: Arc<rustls::ClientConfig>,
    pooled_http1_clients: Arc<Mutex<HashMap<TransportIdentity, PooledHttp1Client>>>,
    resolver_cache: ResolverCache,
    dns_result_cache: DnsResultCache,
}

#[derive(Clone)]
struct PooledTransportConnector {
    tls_config: Arc<rustls::ClientConfig>,
    transport: TransportIdentity,
    resolver_cache: ResolverCache,
    dns_result_cache: DnsResultCache,
}

struct PooledConnection {
    inner: TokioIo<PooledUpstreamStream>,
    negotiated_h2: bool,
}

struct PreparedExecution {
    scheme: String,
    path_and_query: String,
    transport: TransportIdentity,
}

enum PooledUpstreamStream {
    Tcp(TcpStream),
    Tls(UpstreamTlsStream),
}

#[derive(Clone, Copy)]
enum UpstreamExecutionMode {
    PooledHttp,
    // Reserved for future transport-specific tuning once pooled HTTP/2 usage is validated.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum TransportScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TransportDnsIdentity {
    Udp(String),
    Dot(String),
    Doh(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ResolverIdentity {
    System,
    Udp(String),
    Dot(String),
    Doh(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsLookupKey {
    resolver: ResolverIdentity,
    hostname: String,
}

#[derive(Debug, Clone, Copy)]
struct CachedDnsLookup {
    ip: IpAddr,
    expires_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TransportIdentity {
    scheme: TransportScheme,
    connect_host: String,
    request_authority: String,
    port: u16,
    host_header: String,
    sni: Option<String>,
    connect_ip: Option<IpAddr>,
    dns: Option<TransportDnsIdentity>,
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

        Ok(Self {
            tls_config,
            pooled_http1_clients: Arc::new(Mutex::new(HashMap::new())),
            resolver_cache: Arc::new(Mutex::new(HashMap::new())),
            dns_result_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }
}

impl UpstreamExecutionMode {
    fn label(self) -> &'static str {
        match self {
            Self::PooledHttp => "pooled-http",
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
        let pooled_http1_clients = self.pooled_http1_clients.clone();
        let resolver_cache = self.resolver_cache.clone();
        let dns_result_cache = self.dns_result_cache.clone();
        let headers = inbound_headers.clone();
        let original_url = original_url.to_string();
        let upstream = upstream.clone();
        let method_name = method.to_string();
        let execution_mode = UpstreamExecutionMode::PooledHttp;

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
            response_http_version = field::Empty,
            response_status = field::Empty
        );

        Box::pin(
            async move {
                let prepared = prepare_execution(&upstream)?;
                let response = execute_with_pooled_http(
                    pooled_http1_clients,
                    tls_config,
                    resolver_cache,
                    dns_result_cache,
                    method,
                    &headers,
                    &original_url,
                    &upstream,
                    body,
                    &prepared,
                )
                .await?;

                Span::current().record(
                    "response_http_version",
                    http_version_label(response.version()),
                );
                Span::current().record("response_status", response.status().as_u16());
                Ok(ExecutedUpstream { response })
            }
            .instrument(execute_span),
        )
    }
}

impl tower::Service<Uri> for PooledTransportConnector {
    type Response = PooledConnection;
    type Error = anyhow::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut TaskContext<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, dst: Uri) -> Self::Future {
        let tls_config = self.tls_config.clone();
        let transport = self.transport.clone();
        let resolver_cache = self.resolver_cache.clone();
        let dns_result_cache = self.dns_result_cache.clone();

        Box::pin(async move {
            let connect_span = tracing::info_span!(
                "upstream.connect",
                scheme = field::Empty,
                connect_host = field::Empty,
                request_authority = field::Empty,
                sni = field::Empty,
                dns_cache_hit = field::Empty,
                negotiated_protocol = field::Empty,
                target_ip = field::Empty,
                target_port = field::Empty
            );

            async move {
                validate_pooled_request_uri(&dst, &transport)?;

                Span::current().record("scheme", transport.scheme.label());
                Span::current().record("connect_host", transport.connect_host.as_str());
                Span::current().record("request_authority", transport.request_authority.as_str());
                Span::current().record("target_port", transport.port);

                let target_ip = resolve_connection_ip_for_transport(
                    &transport,
                    &resolver_cache,
                    &dns_result_cache,
                )
                .await?;
                Span::current().record("target_ip", field::display(target_ip));
                let target_addr = SocketAddr::new(target_ip, transport.port);

                let tcp = async move { TcpStream::connect(target_addr).await }
                    .instrument(tracing::info_span!("tcp.connect", peer = %target_addr))
                    .await?;

                if transport.scheme == TransportScheme::Https {
                    let sni = transport
                        .sni
                        .clone()
                        .unwrap_or_else(|| transport.connect_host.clone());
                    Span::current().record("sni", sni.as_str());
                    let domain = rustls_pki_types::ServerName::try_from(sni)
                        .map_err(|error| anyhow!("invalid TLS server name: {}", error))?;
                    let connector = TlsConnector::from(tls_config);
                    let tls_stream = async move {
                        connector
                            .with_alpn(
                                POOLED_HTTP_ALPN_PROTOCOLS
                                    .iter()
                                    .map(|protocol| protocol.to_vec())
                                    .collect(),
                            )
                            .connect(domain, tcp)
                            .await
                    }
                    .instrument(tracing::info_span!(
                        "tls.handshake",
                        peer = %target_addr
                    ))
                    .await?;
                    let negotiated_h2 = negotiated_h2(&tls_stream);
                    Span::current().record(
                        "negotiated_protocol",
                        if negotiated_h2 { "h2" } else { "http/1.1" },
                    );
                    return Ok(PooledConnection::new(
                        PooledUpstreamStream::Tls(tls_stream),
                        negotiated_h2,
                    ));
                }

                Span::current().record("negotiated_protocol", "http/1.1");
                Ok(PooledConnection::new(PooledUpstreamStream::Tcp(tcp), false))
            }
            .instrument(connect_span)
            .await
        })
    }
}

impl PooledConnection {
    fn new(stream: PooledUpstreamStream, negotiated_h2: bool) -> Self {
        Self {
            inner: TokioIo::new(stream),
            negotiated_h2,
        }
    }
}

impl Connection for PooledConnection {
    fn connected(&self) -> Connected {
        if self.negotiated_h2 {
            Connected::new().negotiated_h2()
        } else {
            Connected::new()
        }
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

fn build_pooled_http1_client(
    tls_config: Arc<rustls::ClientConfig>,
    transport: TransportIdentity,
    resolver_cache: ResolverCache,
    dns_result_cache: DnsResultCache,
) -> PooledHttp1Client {
    let connector = PooledTransportConnector {
        tls_config,
        transport,
        resolver_cache,
        dns_result_cache,
    };
    let timer = TokioTimer::new();
    let mut builder = Client::builder(TokioExecutor::new());
    builder
        .timer(timer.clone())
        .pool_timer(timer)
        .pool_idle_timeout(POOLED_HTTP1_IDLE_TIMEOUT)
        .pool_max_idle_per_host(POOLED_HTTP1_MAX_IDLE_PER_HOST)
        .set_host(false);
    builder.build(connector)
}

impl TransportScheme {
    fn label(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

fn get_or_create_pooled_http1_client(
    pooled_http1_clients: &Arc<Mutex<HashMap<TransportIdentity, PooledHttp1Client>>>,
    tls_config: Arc<rustls::ClientConfig>,
    resolver_cache: ResolverCache,
    dns_result_cache: DnsResultCache,
    transport: &TransportIdentity,
) -> Result<PooledHttp1Client> {
    let mut cache = pooled_http1_clients
        .lock()
        .map_err(|_| anyhow!("pooled upstream client cache lock was poisoned"))?;

    if let Some(client) = cache.get(transport) {
        return Ok(client.clone());
    }

    let client = build_pooled_http1_client(
        tls_config,
        transport.clone(),
        resolver_cache,
        dns_result_cache,
    );
    cache.insert(transport.clone(), client.clone());
    Ok(client)
}

fn build_transport_identity(upstream: &UpstreamPlan) -> Result<TransportIdentity> {
    let connect_host = upstream
        .connect_host
        .as_deref()
        .or_else(|| upstream.url.host_str())
        .ok_or_else(|| anyhow!("No host in target URL"))?
        .to_string();
    let host_header = build_host_header(upstream)?;
    let request_authority = build_request_authority(upstream)?;
    let port = upstream
        .url
        .port_or_known_default()
        .ok_or_else(|| anyhow!("Unknown target port"))?;
    let scheme = match upstream.url.scheme() {
        "http" => TransportScheme::Http,
        "https" => TransportScheme::Https,
        other => {
            return Err(anyhow!(
                "unsupported upstream scheme `{}` for pooled transport identity",
                other
            ));
        }
    };

    Ok(TransportIdentity {
        scheme,
        connect_host,
        request_authority,
        port,
        host_header,
        sni: upstream.sni.clone(),
        connect_ip: upstream.connect_ip,
        dns: normalize_dns_identity(upstream.dns.as_ref()),
    })
}

fn normalize_dns_identity(
    dns: Option<&crate::rules::model::DnsPlan>,
) -> Option<TransportDnsIdentity> {
    let dns = dns?;

    match dns.mode {
        crate::rules::model::DnsMode::System => None,
        crate::rules::model::DnsMode::Udp => dns
            .server
            .as_ref()
            .map(|server| TransportDnsIdentity::Udp(server.clone())),
        crate::rules::model::DnsMode::Dot => dns
            .server
            .as_ref()
            .map(|server| TransportDnsIdentity::Dot(server.clone())),
        crate::rules::model::DnsMode::Doh => dns
            .server
            .as_ref()
            .map(|server| TransportDnsIdentity::Doh(server.clone())),
    }
}

fn build_resolver_identity(transport: &TransportIdentity) -> Option<ResolverIdentity> {
    if transport.connect_ip.is_some() {
        return None;
    }

    match transport.dns.as_ref() {
        None => Some(ResolverIdentity::System),
        Some(TransportDnsIdentity::Udp(server)) => Some(ResolverIdentity::Udp(server.clone())),
        Some(TransportDnsIdentity::Dot(server)) => Some(ResolverIdentity::Dot(server.clone())),
        Some(TransportDnsIdentity::Doh(server)) => Some(ResolverIdentity::Doh(server.clone())),
    }
}

fn prepare_execution(upstream: &UpstreamPlan) -> Result<PreparedExecution> {
    let scheme = upstream.url.scheme().to_string();
    Span::current().record("scheme", scheme.as_str());

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

    Ok(PreparedExecution {
        scheme,
        path_and_query: build_path_and_query(upstream),
        transport: build_transport_identity(upstream)?,
    })
}

async fn execute_with_pooled_http(
    pooled_http1_clients: Arc<Mutex<HashMap<TransportIdentity, PooledHttp1Client>>>,
    tls_config: Arc<rustls::ClientConfig>,
    resolver_cache: ResolverCache,
    dns_result_cache: DnsResultCache,
    method: Method,
    headers: &HeaderMap,
    original_url: &str,
    upstream: &UpstreamPlan,
    body: Body,
    prepared: &PreparedExecution,
) -> Result<hyper::Response<hyper::body::Incoming>> {
    let pooled_http1_client = get_or_create_pooled_http1_client(
        &pooled_http1_clients,
        tls_config,
        resolver_cache,
        dns_result_cache,
        &prepared.transport,
    )?;
    let absolute_uri = build_pooled_request_uri(&prepared.transport, upstream)?;
    let request = build_request(
        method,
        absolute_uri.to_string(),
        headers,
        original_url,
        upstream,
        body,
    )?;

    async move { pooled_http1_client.request(request).await }
        .instrument(tracing::info_span!(
            "http.upstream_send",
            protocol = %prepared.scheme,
            path = %prepared.path_and_query
        ))
        .await
        .map_err(|error| anyhow!("upstream request failed: {}", error))
}

fn build_path_and_query(upstream: &UpstreamPlan) -> String {
    match upstream.url.query() {
        Some(query) => format!("{}?{}", upstream.url.path(), query),
        None => upstream.url.path().to_string(),
    }
}

fn build_pooled_request_uri(transport: &TransportIdentity, upstream: &UpstreamPlan) -> Result<Uri> {
    let path_and_query = build_path_and_query(upstream);

    Uri::builder()
        .scheme(transport.scheme.label())
        .authority(transport.request_authority.as_str())
        .path_and_query(path_and_query.as_str())
        .build()
        .map_err(|error| {
            anyhow!(
                "failed to build pooled upstream uri for request authority `{}` and target `{}`: {}",
                transport.request_authority,
                upstream.url,
                error
            )
        })
}

fn validate_pooled_request_uri(dst: &Uri, transport: &TransportIdentity) -> Result<()> {
    let scheme = dst
        .scheme_str()
        .ok_or_else(|| anyhow!("pooled upstream uri `{}` is missing scheme", dst))?;
    let authority = dst
        .authority()
        .ok_or_else(|| anyhow!("pooled upstream uri `{}` is missing authority", dst))?;

    if scheme != transport.scheme.label() || authority.as_str() != transport.request_authority {
        return Err(anyhow!(
            "pooled upstream uri `{}` does not match request authority `{}`://{}",
            dst,
            transport.scheme.label(),
            transport.request_authority
        ));
    }

    Ok(())
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

fn build_request_authority(upstream: &UpstreamPlan) -> Result<String> {
    if let Some(host) = upstream.host.as_deref() {
        return Ok(host.to_string());
    }

    let host = upstream
        .url
        .host_str()
        .ok_or_else(|| anyhow!("No host in target URL"))?;
    Ok(normalize_authority(host, upstream.url.port()))
}

fn build_request(
    method: Method,
    request_uri: String,
    inbound_headers: &HeaderMap,
    original_url: &str,
    upstream: &UpstreamPlan,
    body: Body,
) -> Result<Request<Body>> {
    let mut request = Request::builder().method(method).uri(request_uri);
    let request_headers = request
        .headers_mut()
        .ok_or_else(|| anyhow!("request builder did not provide mutable headers"))?;

    for (name, value) in inbound_headers {
        if is_end_to_end_header(name) {
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

async fn resolve_connection_ip_for_transport(
    transport: &TransportIdentity,
    resolver_cache: &ResolverCache,
    dns_result_cache: &DnsResultCache,
) -> Result<IpAddr> {
    let connect_span = Span::current();
    let resolve_span = tracing::info_span!(
        "upstream.resolve_address",
        connect_host = %transport.connect_host,
        dns_mode = field::Empty,
        dns_server = field::Empty,
        dns_cache_hit = field::Empty,
        resolved_ip = field::Empty
    );

    async move {
        if let Some(ip) = transport.connect_ip {
            Span::current().record("dns_mode", "connect-ip");
            record_dns_cache_hit(false, &connect_span);
            Span::current().record("resolved_ip", field::display(ip));
            return Ok(ip);
        }

        let resolver_identity = build_resolver_identity(transport)
            .ok_or_else(|| anyhow!("resolver identity missing for non connect-ip transport"))?;
        let lookup_key = build_dns_lookup_key(&resolver_identity, transport.connect_host.as_str());

        if let Some(cached_ip) = get_cached_dns_result(dns_result_cache, &lookup_key)? {
            record_resolver_identity(&resolver_identity);
            record_dns_cache_hit(true, &connect_span);
            Span::current().record("resolved_ip", field::display(cached_ip));
            return Ok(cached_ip);
        }

        record_dns_cache_hit(false, &connect_span);
        let resolver = get_or_create_resolver(&resolver_identity, resolver_cache).await?;

        let ip = resolver
            .resolve(transport.connect_host.as_str())
            .instrument(tracing::info_span!(
                "dns.lookup",
                hostname = %transport.connect_host
            ))
            .await?;
        cache_dns_result(dns_result_cache, lookup_key, ip)?;
        Span::current().record("resolved_ip", field::display(ip));
        Ok(ip)
    }
    .instrument(resolve_span)
    .await
}

fn record_dns_cache_hit(cache_hit: bool, connect_span: &Span) {
    connect_span.record("dns_cache_hit", cache_hit);
    Span::current().record("dns_cache_hit", cache_hit);
}

fn build_dns_lookup_key(resolver: &ResolverIdentity, hostname: &str) -> DnsLookupKey {
    DnsLookupKey {
        resolver: resolver.clone(),
        hostname: hostname.to_string(),
    }
}

fn get_cached_dns_result(
    dns_result_cache: &DnsResultCache,
    lookup_key: &DnsLookupKey,
) -> Result<Option<IpAddr>> {
    let now = Instant::now();
    let mut cache = dns_result_cache
        .lock()
        .map_err(|_| anyhow!("dns result cache lock was poisoned"))?;

    match cache.get(lookup_key).copied() {
        Some(entry) if entry.expires_at > now => Ok(Some(entry.ip)),
        Some(_) => {
            cache.remove(lookup_key);
            Ok(None)
        }
        None => Ok(None),
    }
}

fn cache_dns_result(
    dns_result_cache: &DnsResultCache,
    lookup_key: DnsLookupKey,
    ip: IpAddr,
) -> Result<()> {
    let entry = CachedDnsLookup {
        ip,
        expires_at: Instant::now() + DNS_RESULT_CACHE_TTL,
    };
    let mut cache = dns_result_cache
        .lock()
        .map_err(|_| anyhow!("dns result cache lock was poisoned"))?;
    cache.insert(lookup_key, entry);
    Ok(())
}

async fn get_or_create_resolver(
    resolver_identity: &ResolverIdentity,
    resolver_cache: &ResolverCache,
) -> Result<Arc<CustomResolver>> {
    record_resolver_identity(resolver_identity);

    {
        let cache = resolver_cache
            .lock()
            .map_err(|_| anyhow!("resolver cache lock was poisoned"))?;
        if let Some(resolver) = cache.get(resolver_identity) {
            return Ok(resolver.clone());
        }
    }

    let resolver = Arc::new(create_resolver(resolver_identity).await?);

    let mut cache = resolver_cache
        .lock()
        .map_err(|_| anyhow!("resolver cache lock was poisoned"))?;

    if let Some(existing) = cache.get(resolver_identity) {
        return Ok(existing.clone());
    }

    cache.insert(resolver_identity.clone(), resolver.clone());
    Ok(resolver)
}

fn record_resolver_identity(identity: &ResolverIdentity) {
    match identity {
        ResolverIdentity::System => {
            Span::current().record("dns_mode", "system");
        }
        ResolverIdentity::Udp(server) => {
            Span::current().record("dns_mode", "udp");
            Span::current().record("dns_server", server.as_str());
        }
        ResolverIdentity::Dot(server) => {
            Span::current().record("dns_mode", "dot");
            Span::current().record("dns_server", server.as_str());
        }
        ResolverIdentity::Doh(server) => {
            Span::current().record("dns_mode", "doh");
            Span::current().record("dns_server", server.as_str());
        }
    }
}

async fn create_resolver(identity: &ResolverIdentity) -> Result<CustomResolver> {
    match identity {
        ResolverIdentity::System => CustomResolver::system(),
        ResolverIdentity::Udp(server) => {
            CustomResolver::from_plan(&crate::rules::model::DnsPlan {
                mode: crate::rules::model::DnsMode::Udp,
                server: Some(server.clone()),
            })
            .await
        }
        ResolverIdentity::Dot(server) => {
            CustomResolver::from_plan(&crate::rules::model::DnsPlan {
                mode: crate::rules::model::DnsMode::Dot,
                server: Some(server.clone()),
            })
            .await
        }
        ResolverIdentity::Doh(server) => {
            CustomResolver::from_plan(&crate::rules::model::DnsPlan {
                mode: crate::rules::model::DnsMode::Doh,
                server: Some(server.clone()),
            })
            .await
        }
    }
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

fn negotiated_h2(tls_stream: &UpstreamTlsStream) -> bool {
    matches!(tls_stream.get_ref().1.alpn_protocol(), Some(protocol) if protocol == b"h2")
}

fn http_version_label(version: Version) -> &'static str {
    match version {
        Version::HTTP_09 => "0.9",
        Version::HTTP_10 => "1.0",
        Version::HTTP_11 => "1.1",
        Version::HTTP_2 => "2",
        Version::HTTP_3 => "3",
        _ => "unknown",
    }
}
