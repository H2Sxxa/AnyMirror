mod fake_ip;

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use hickory_proto::{
    op::{Header, LowerQuery, Message, MessageType, ResponseCode},
    rr::{
        rdata::{A, AAAA},
        Name, RData, Record, RecordType,
    },
};
use hickory_resolver::{ResolveError, TokioResolver};
use hickory_server::{
    authority::MessageResponseBuilder,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo, ServerFuture},
};
use tokio::{
    net::UdpSocket,
    spawn,
};

use crate::config::FakeDnsOptions;
use crate::rules::types::Rules;
use crate::socket::bind_dual_stack_tcp_listener;

pub use fake_ip::FakeIpStore;

const DNS_TCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct FakeDnsServer {
    state: Arc<FakeDnsState>,
}

#[derive(Debug)]
struct FakeDnsState {
    fake_ip_store: FakeIpStore,
    rules: Rules,
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
    pub async fn start(options: FakeDnsOptions, rules: &Rules) -> Result<Self> {
        let state = Arc::new(FakeDnsState::new(options, rules)?);
        let server = Self { state };
        server.spawn().await?;
        Ok(server)
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

    async fn spawn(&self) -> Result<()> {
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

        spawn(async move {
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

        Ok(())
    }
}

impl FakeDnsState {
    fn new(options: FakeDnsOptions, rules: &Rules) -> Result<Self> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|error| anyhow!("Failed to create fake DNS resolver: {}", error))?
            .build();

        Ok(Self {
            fake_ip_store: FakeIpStore::new(options.fake_ipv4_range, options.fake_ipv6_range),
            rules: rules.clone(),
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

        if matched {
            Ok(Some(answers))
        } else {
            Ok(None)
        }
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

impl DnsLookupQuery {
    fn from_message(request: &Message) -> Vec<Self> {
        request
            .queries()
            .iter()
            .map(|query| Self::new(&query.name().to_utf8(), query.query_type()))
            .collect()
    }

    fn from_lower_queries(queries: &[LowerQuery]) -> Vec<Self> {
        queries
            .iter()
            .map(|query| Self::new(&query.name().to_utf8(), query.query_type()))
            .collect()
    }

    fn new(name: &str, record_type: RecordType) -> Self {
        Self {
            name: Self::normalize_name(name),
            record_type,
        }
    }

    fn build_record(&self, ttl: Duration, data: RData) -> Result<Record> {
        let record_name = Name::from_ascii(&self.name)
            .with_context(|| format!("invalid DNS record name `{}`", self.name))?;
        Ok(Record::from_rdata(record_name, ttl.as_secs() as u32, data))
    }

    fn normalize_name(name: &str) -> String {
        name.trim_end_matches('.').to_ascii_lowercase()
    }
}

impl DnsResolution {
    fn from_answers(answers: Vec<Record>) -> Self {
        Self {
            response_code: ResponseCode::NoError,
            answers,
        }
    }

    fn from_error(response_code: ResponseCode) -> Self {
        Self {
            response_code,
            answers: Vec::new(),
        }
    }

    async fn send_hickory_response<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: &mut R,
    ) -> ResponseInfo {
        let builder = MessageResponseBuilder::from_message_request(request);
        let fallback_header = Self::build_response_header(request.header(), ResponseCode::ServFail);

        let send_result = if self.response_code != ResponseCode::NoError {
            response_handle
                .send_response(builder.error_msg(request.header(), self.response_code))
                .await
        } else if self.answers.is_empty() {
            response_handle
                .send_response(builder.build_no_records(Self::build_response_header(
                    request.header(),
                    ResponseCode::NoError,
                )))
                .await
        } else {
            let empty_records: [Record; 0] = [];
            response_handle
                .send_response(builder.build(
                    Self::build_response_header(request.header(), ResponseCode::NoError),
                    self.answers.iter(),
                    empty_records.iter(),
                    empty_records.iter(),
                    empty_records.iter(),
                ))
                .await
        };

        match send_result {
            Ok(info) => info,
            Err(error) => {
                tracing::warn!(?error, src = %request.src(), "Failed to send fake DNS response");
                fallback_header.into()
            }
        }
    }

    fn to_message_bytes(&self, request: &Message) -> Result<Vec<u8>> {
        if self.response_code != ResponseCode::NoError {
            return Self::build_error_message_bytes(request, self.response_code);
        }

        let mut response = Self::build_response_message(request);
        for answer in &self.answers {
            response.add_answer(answer.clone());
        }

        response
            .to_vec()
            .context("failed to serialize fake DNS response")
    }

    fn build_error_message_bytes(
        request: &Message,
        response_code: ResponseCode,
    ) -> Result<Vec<u8>> {
        let mut response = Self::build_response_message(request);
        response.set_response_code(response_code);
        response
            .to_vec()
            .context("failed to serialize fake DNS error response")
    }

    fn build_response_message(request: &Message) -> Message {
        let mut response = Message::new();
        response
            .set_id(request.id())
            .set_message_type(MessageType::Response)
            .set_op_code(request.op_code())
            .set_recursion_desired(request.recursion_desired())
            .set_recursion_available(true)
            .set_response_code(ResponseCode::NoError);
        for query in request.queries() {
            response.add_query(query.clone());
        }
        response
    }

    fn build_response_header(request_header: &Header, response_code: ResponseCode) -> Header {
        let mut header = request_header.clone();
        header
            .set_message_type(MessageType::Response)
            .set_recursion_available(true)
            .set_response_code(response_code);
        header
    }
}
