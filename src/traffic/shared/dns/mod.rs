mod fake_ip;
mod query;
mod resolution;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use hickory_resolver::{ResolveError, TokioResolver};
use hickory_server::server::{
    Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture,
};
use tokio::net::UdpSocket;
use tokio::sync::oneshot;

use crate::config::FakeDnsOptions;
use crate::rules::pool::LiveRuleSet;
use crate::socket::bind_dual_stack_tcp_listener;
use crate::workers::{ShutdownJoinHandle, Workers};

pub use fake_ip::FakeIpStore;

const DNS_TCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct FakeDnsServer {
    state: Arc<FakeDnsState>,
}

pub type FakeDnsRuntimeHandle = ShutdownJoinHandle;

#[derive(Debug)]
struct FakeDnsState {
    fake_ip_store: FakeIpStore,
    rules: LiveRuleSet,
    options: FakeDnsOptions,
    resolver: TokioResolver,
}

#[derive(Debug, Clone)]
struct FakeDnsHandler {
    state: Arc<FakeDnsState>,
}

#[derive(Debug, Clone)]
struct DnsLookupQuery {
    name: String,
    record_type: RecordType,
}

#[derive(Debug, Default)]
struct DnsResolution {
    response_code: ResponseCode,
    answers: Vec<Record>,
}

impl FakeDnsServer {
    pub fn new(options: FakeDnsOptions, rules: LiveRuleSet) -> Result<Self> {
        let state = Arc::new(FakeDnsState::new(options, rules)?);
        Ok(Self { state })
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.state.options.listen_addr
    }

    pub fn listen_port(&self) -> u16 {
        self.state.options.listen_addr.port()
    }

    pub fn resolve_fake_domain(&self, ip: IpAddr, now: Instant) -> Option<String> {
        self.state.fake_ip_store.resolve_domain(ip, now)
    }

    pub fn build_fake_response(&self, request_bytes: &[u8]) -> Result<Option<Vec<u8>>> {
        let request = Message::from_vec(request_bytes).context("invalid dns request packet")?;
        let queries = DnsLookupQuery::from_message(&request);
        let fake_answers = self.state.build_fake_answers(&queries)?;

        match fake_answers {
            Some(answers) => DnsResolution::from_answers(answers)
                .to_message_bytes(&request)
                .map(Some),
            None => Ok(None),
        }
    }

    pub async fn start_runtime(&self, workers: Workers) -> Result<FakeDnsRuntimeHandle> {
        let udp_socket = UdpSocket::bind(self.state.options.listen_addr)
            .await
            .with_context(|| {
                format!(
                    "failed to bind fake DNS UDP server on {}",
                    self.state.options.listen_addr
                )
            })?;
        let udp_addr = udp_socket.local_addr().with_context(|| {
            format!(
                "failed to read UDP socket address for {}",
                self.state.options.listen_addr
            )
        })?;
        let port = self.state.options.listen_addr.port();
        let tcp_listener = bind_dual_stack_tcp_listener(port, 1024)
            .with_context(|| format!("failed to bind fake DNS TCP server on [::]:{}", port))?;
        let tcp_addr = tcp_listener
            .local_addr()
            .context("failed to read fake DNS TCP listener address")?;

        let mut server = ServerFuture::new(FakeDnsHandler {
            state: self.state.clone(),
        });
        server.register_socket(udp_socket);
        server.register_listener(tcp_listener, DNS_TCP_REQUEST_TIMEOUT);

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let shutdown_token = server.shutdown_token().clone();
        let join = workers.spawn("fake-dns-server", async move {
            tokio::spawn(async move {
                let _ = shutdown_rx.await;
                shutdown_token.cancel();
            });
            if let Err(error) = server.block_until_done().await {
                tracing::error!(?error, "Fake DNS server exited unexpectedly");
            }
        });

        tracing::info!(
            udp_listener = %udp_addr,
            tcp_listener = %tcp_addr,
            fake_ipv4_range = %self.state.options.fake_ipv4_range,
            fake_ipv6_range = %self.state.options.fake_ipv6_range,
            ttl_secs = self.state.options.record_ttl.as_secs(),
            "Fake DNS server started"
        );

        Ok(ShutdownJoinHandle::new(shutdown_tx, join))
    }
}

impl FakeDnsState {
    fn new(options: FakeDnsOptions, rules: LiveRuleSet) -> Result<Self> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|error| anyhow!("Failed to create fake DNS resolver: {}", error))?
            .build();

        Ok(Self {
            fake_ip_store: FakeIpStore::new(options.fake_ipv4_range, options.fake_ipv6_range),
            rules,
            options,
            resolver,
        })
    }

    async fn resolve_queries(&self, queries: &[DnsLookupQuery]) -> Result<DnsResolution> {
        if let Some(fake_answers) = self.build_fake_answers(queries)? {
            return Ok(DnsResolution::from_answers(fake_answers));
        }

        let mut answers = Vec::new();
        for query in queries {
            let query_name = Name::from_ascii(query.name.clone())
                .with_context(|| format!("invalid DNS query name `{}`", query.name))?;
            match self.resolver.lookup(query_name, query.record_type).await {
                Ok(lookup) => {
                    answers.extend(lookup.record_iter().cloned());
                }
                Err(error) => {
                    return Ok(DnsResolution::from_error(
                        Self::map_resolve_error_to_response_code(&error),
                    ));
                }
            }
        }

        Ok(DnsResolution::from_answers(answers))
    }

    fn build_fake_answers(&self, queries: &[DnsLookupQuery]) -> Result<Option<Vec<Record>>> {
        let mut answers = Vec::new();
        let mut matched = false;
        let ttl = self.options.record_ttl;

        for query in queries {
            match query.record_type {
                RecordType::A if self.rules.matches_dns_host(&query.name) => {
                    let fake_ip = self.fake_ip_store.allocate_or_refresh_ipv4(
                        &query.name,
                        ttl,
                        Instant::now(),
                    )?;
                    answers.push(query.build_record(ttl, RData::A(A(fake_ip)))?);
                    matched = true;
                }
                RecordType::AAAA if self.rules.matches_dns_host(&query.name) => {
                    let fake_ip = self.fake_ip_store.allocate_or_refresh_ipv6(
                        &query.name,
                        ttl,
                        Instant::now(),
                    )?;
                    answers.push(query.build_record(ttl, RData::AAAA(AAAA(fake_ip)))?);
                    matched = true;
                }
                _ => {}
            }
        }

        if matched { Ok(Some(answers)) } else { Ok(None) }
    }

    fn map_resolve_error_to_response_code(error: &ResolveError) -> ResponseCode {
        if error.is_nx_domain() {
            ResponseCode::NXDomain
        } else if error.is_no_records_found() {
            ResponseCode::NoError
        } else {
            ResponseCode::ServFail
        }
    }
}

#[async_trait]
impl RequestHandler for FakeDnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let queries = DnsLookupQuery::from_lower_queries(request.queries());
        let resolution = match self.state.resolve_queries(&queries).await {
            Ok(resolution) => resolution,
            Err(error) => {
                tracing::warn!(?error, src = %request.src(), "Failed to resolve fake DNS request");
                DnsResolution::from_error(ResponseCode::ServFail)
            }
        };

        resolution
            .send_hickory_response(request, &mut response_handle)
            .await
    }
}
