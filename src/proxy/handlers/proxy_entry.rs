use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::{
    body::Body,
    extract::State,
    http::{Method, Request, StatusCode},
    response::Response,
};
use hyper::upgrade;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tracing::Instrument;

use super::super::{
    executors::UpstreamExecutor,
    handlers::explicit_https::handle_explicit_connect_https_request,
    request_parser::{ConnectAuthority, parse_absolute_url, parse_connect_authority},
    state::AppState,
    tls,
};
use super::common::forward_explicit_request;

const TLS_HANDSHAKE_RECORD_TYPE: u8 = 0x16;
const TLS_LEGACY_VERSION_MAJOR: u8 = 0x03;
const CONNECT_PEEK_BYTES: usize = 2;

pub(crate) async fn proxy_entry<E: UpstreamExecutor>(
    State(state): State<AppState<E>>,
    request: Request<Body>,
) -> Response {
    if request.method() == Method::CONNECT {
        return handle_connect(state, request).await;
    }

    forward_explicit_request(&state, request, "proxy", |request| {
        parse_absolute_url(&request.uri().to_string())
    })
    .await
}

async fn handle_connect<E: UpstreamExecutor>(
    state: AppState<E>,
    request: Request<Body>,
) -> Response {
    let connect_target = match parse_connect_authority(&request.uri().to_string()) {
        Ok(connect_target) => connect_target,
        Err(response) => return response,
    };

    let connect_uri = format!("connect://{}", connect_target.authority());
    tracing::Span::current().record("forwarding_source", "proxy-connect");
    tracing::Span::current().record("original_url", connect_uri.as_str());
    tracing::Span::current().record("upstream_url", connect_uri.as_str());

    let tunnel_span =
        tracing::info_span!("proxy.connect", connect_target = %connect_target.authority());
    tokio::spawn(
        async move {
            match upgrade::on(request).await {
                Ok(upgraded) => {
                    if let Err(error) =
                        handle_upgraded_connect(state, connect_target, TokioIo::new(upgraded)).await
                    {
                        tracing::debug!(?error, "CONNECT tunnel closed with error");
                    }
                }
                Err(error) => {
                    tracing::debug!(?error, "failed to upgrade CONNECT request");
                }
            }
        }
        .instrument(tunnel_span),
    );

    Response::builder()
        .status(StatusCode::OK)
        .body(Body::empty())
        .expect("empty CONNECT response should build")
}

async fn handle_upgraded_connect<E, S>(
    state: AppState<E>,
    connect_target: ConnectAuthority,
    upgraded: S,
) -> io::Result<()>
where
    E: UpstreamExecutor,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (upgraded, prefix, is_tls) = sniff_connect_stream(upgraded).await?;
    tracing::debug!(
        connect_target = %connect_target.authority(),
        prefix_len = prefix.len(),
        is_tls,
        "Sniffed CONNECT stream"
    );

    if is_tls {
        tracing::info!(
            connect_target = %connect_target.authority(),
            hostname = connect_target.host(),
            "Routing CONNECT stream into HTTPS interception"
        );
        let upgraded = PrefixedIo::new(upgraded, prefix);
        let hostname = connect_target.host().to_string();
        let request_state = state.clone();
        let request_target = connect_target.clone();
        return tls::serve_app_tls_stream(
            state.tls_intercept.clone(),
            upgraded,
            &hostname,
            move |request| {
                handle_explicit_connect_https_request(
                    request_state.clone(),
                    request_target.clone(),
                    request,
                )
            },
        )
        .await
        .map_err(|error| io::Error::other(error.to_string()));
    }

    tracing::info!(
        connect_target = %connect_target.authority(),
        "Routing CONNECT stream into plain TCP tunnel"
    );
    let upstream = TcpStream::connect(connect_target.authority()).await?;
    proxy_tunnel(upgraded, upstream, &prefix).await
}

async fn sniff_connect_stream<S>(mut stream: S) -> io::Result<(S, Vec<u8>, bool)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut prefix = vec![0u8; CONNECT_PEEK_BYTES];
    let mut bytes_read = 0usize;

    while bytes_read < CONNECT_PEEK_BYTES {
        let read = stream.read(&mut prefix[bytes_read..]).await?;
        if read == 0 {
            break;
        }
        bytes_read += read;
    }

    prefix.truncate(bytes_read);
    let is_tls = looks_like_tls_client_hello(&prefix);
    Ok((stream, prefix, is_tls))
}

fn looks_like_tls_client_hello(prefix: &[u8]) -> bool {
    matches!(
        prefix,
        [TLS_HANDSHAKE_RECORD_TYPE, TLS_LEGACY_VERSION_MAJOR, ..] | [TLS_HANDSHAKE_RECORD_TYPE]
    )
}

async fn proxy_tunnel<S>(
    mut downstream: S,
    mut upstream: TcpStream,
    prefix: &[u8],
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !prefix.is_empty() {
        upstream.write_all(prefix).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}

struct PrefixedIo<S> {
    inner: S,
    prefix: Vec<u8>,
    offset: usize,
}

impl<S> PrefixedIo<S> {
    fn new(inner: S, prefix: Vec<u8>) -> Self {
        Self {
            inner,
            prefix,
            offset: 0,
        }
    }
}

impl<S> AsyncRead for PrefixedIo<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset < self.prefix.len() && buf.remaining() > 0 {
            let remaining = &self.prefix[self.offset..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            self.offset += to_copy;
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PrefixedIo<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
