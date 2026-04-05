use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use netstack_smoltcp::{Runner, StackBuilder, TcpListener, TcpStream, UdpSocket};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpStream as TokioTcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tun_rs::{
    DeviceBuilder, Layer,
    async_framed::{BytesCodec, DeviceFramed},
};

use crate::workers::{ShutdownJoinHandle, Workers};

use super::TunRuntimeContext;

pub struct TransparentInterceptHandle {
    core_tasks: Vec<ShutdownJoinHandle>,
    bridge_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl TransparentInterceptHandle {
    pub async fn shutdown(self) {
        for task in self.core_tasks {
            task.shutdown().await;
        }

        let handles = {
            let Ok(mut guard) = self.bridge_tasks.lock() else {
                return;
            };
            guard.drain(..).collect::<Vec<_>>()
        };

        for handle in handles {
            handle.abort();
            let _ = handle.await;
        }
    }
}

pub fn run_transparent_tun_smoltcp_runtime(
    context: TunRuntimeContext,
    workers: Workers,
) -> Result<TransparentInterceptHandle> {
    let device = Arc::new(build_tun_device(&context).context("failed to create TUN device")?);
    let framed = DeviceFramed::new(device, BytesCodec::new());
    let (mut tun_read, mut tun_write) = framed.split();

    let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .build()
        .context("failed to initialize netstack-smoltcp")?;
    let Some(runner) = runner else {
        anyhow::bail!("netstack-smoltcp runner was not created");
    };
    let Some(udp_socket) = udp_socket else {
        anyhow::bail!("netstack-smoltcp UDP socket was not created");
    };
    let Some(tcp_listener) = tcp_listener else {
        anyhow::bail!("netstack-smoltcp TCP listener was not created");
    };
    let (mut stack_write, mut stack_read) = stack.split();

    let bridge_tasks = Arc::new(Mutex::new(Vec::new()));
    let mut core_tasks = Vec::new();

    core_tasks.push(spawn_shutdownable_task(
        &workers,
        "tun-smoltcp-runner",
        move |shutdown_rx| async move {
            run_smoltcp_runner(runner, shutdown_rx).await;
        },
    ));

    core_tasks.push(spawn_shutdownable_task(
        &workers,
        "tun-smoltcp-ingress",
        move |shutdown_rx| async move {
            run_tun_to_stack_loop(&mut tun_read, &mut stack_write, shutdown_rx).await;
        },
    ));

    core_tasks.push(spawn_shutdownable_task(
        &workers,
        "tun-smoltcp-egress",
        move |shutdown_rx| async move {
            run_stack_to_tun_loop(&mut stack_read, &mut tun_write, shutdown_rx).await;
        },
    ));

    let tcp_context = context.clone();
    let tcp_bridge_tasks = bridge_tasks.clone();
    core_tasks.push(spawn_shutdownable_task(
        &workers,
        "tun-smoltcp-tcp",
        move |shutdown_rx| async move {
            run_tcp_accept_loop(tcp_context, tcp_listener, tcp_bridge_tasks, shutdown_rx).await;
        },
    ));

    let udp_context = context.clone();
    core_tasks.push(spawn_shutdownable_task(
        &workers,
        "tun-smoltcp-udp",
        move |shutdown_rx| async move {
            run_udp_loop(udp_context, udp_socket, shutdown_rx).await;
        },
    ));

    tracing::info!(
        tun_name = %context.tun_name,
        tun_mtu = context.tun_mtu,
        fake_ipv4_range = %context.fake_ipv4_range,
        fake_ipv6_range = %context.fake_ipv6_range,
        tun_addr_ipv4 = %first_usable_ipv4(context.fake_ipv4_range),
        tun_addr_ipv6 = %first_usable_ipv6(context.fake_ipv6_range),
        tun_dns_ipv4 = %dns_server_ipv4(context.fake_ipv4_range),
        tun_dns_ipv6 = %dns_server_ipv6(context.fake_ipv6_range),
        dns_mode = "in-tunnel",
        proxy_port = context.proxy_redirect_addr.port(),
        tls_port = context.tls_port,
        "TUN smoltcp stack started"
    );

    Ok(TransparentInterceptHandle {
        core_tasks,
        bridge_tasks,
    })
}

async fn run_smoltcp_runner(runner: Runner, mut shutdown_rx: oneshot::Receiver<()>) {
    tokio::select! {
        _ = &mut shutdown_rx => {}
        result = runner => {
            if let Err(error) = result {
                tracing::error!(?error, "smoltcp runner exited unexpectedly");
            }
        }
    }
}

async fn run_tun_to_stack_loop<Read, Write>(
    tun_read: &mut Read,
    stack_write: &mut Write,
    mut shutdown_rx: oneshot::Receiver<()>,
) where
    Read: futures::Stream<Item = std::io::Result<bytes::BytesMut>> + Unpin,
    Write: futures::Sink<Vec<u8>, Error = std::io::Error> + Unpin,
{
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => return,
            packet = tun_read.next() => {
                let Some(packet) = packet else {
                    tracing::warn!("TUN framed reader ended unexpectedly");
                    return;
                };
                match packet {
                    Ok(packet) => {
                        if let Err(error) = stack_write.send(packet.to_vec()).await {
                            tracing::error!(?error, "Failed to forward TUN packet into smoltcp stack");
                            return;
                        }
                    }
                    Err(error) => {
                        tracing::error!(?error, "Failed to read packet from TUN device");
                        return;
                    }
                }
            }
        }
    }
}

async fn run_stack_to_tun_loop<Read, Write>(
    stack_read: &mut Read,
    tun_write: &mut Write,
    mut shutdown_rx: oneshot::Receiver<()>,
) where
    Read: futures::Stream<Item = std::io::Result<Vec<u8>>> + Unpin,
    Write: futures::Sink<Bytes, Error = std::io::Error> + Unpin,
{
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => return,
            packet = stack_read.next() => {
                let Some(packet) = packet else {
                    tracing::warn!("smoltcp stack output stream ended unexpectedly");
                    return;
                };
                match packet {
                    Ok(packet) => {
                        if let Err(error) = tun_write.send(Bytes::from(packet)).await {
                            tracing::error!(?error, "Failed to write smoltcp packet back into TUN device");
                            return;
                        }
                    }
                    Err(error) => {
                        tracing::error!(?error, "Failed to read packet from smoltcp stack");
                        return;
                    }
                }
            }
        }
    }
}

async fn run_tcp_accept_loop(
    context: TunRuntimeContext,
    mut tcp_listener: TcpListener,
    bridge_tasks: Arc<Mutex<Vec<JoinHandle<()>>>>,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = &mut shutdown_rx => return,
            stream = tcp_listener.next() => {
                let Some((stream, client_addr, target_addr)) = stream else {
                    tracing::warn!("smoltcp TCP listener ended unexpectedly");
                    return;
                };

                prune_bridge_tasks(&bridge_tasks);
                let task = if target_addr.port() == 53 {
                    let fake_dns_server = context.fake_dns_server.clone();
                    tokio::spawn(async move {
                        if let Err(error) =
                            handle_dns_tcp_stream(fake_dns_server, stream, client_addr, target_addr)
                                .await
                        {
                            tracing::warn!(
                                client_addr = %client_addr,
                                target_addr = %target_addr,
                                ?error,
                                "Failed to handle smoltcp TCP DNS stream in-tunnel"
                            );
                        }
                    })
                } else {
                    let outbound_target = select_tcp_dispatch_target(&context, target_addr);
                    let domain = context
                        .fake_dns_server
                        .resolve_fake_domain(target_addr.ip(), Instant::now());
                    tokio::spawn(async move {
                        if let Err(error) = bridge_tcp_stream(
                            stream,
                            client_addr,
                            target_addr,
                            outbound_target,
                            domain,
                        )
                        .await
                        {
                            tracing::warn!(
                                client_addr = %client_addr,
                                target_addr = %target_addr,
                                local_target = %outbound_target,
                                ?error,
                                "Failed to bridge smoltcp TCP stream into local listener"
                            );
                        } else {
                            tracing::debug!(
                                client_addr = %client_addr,
                                target_addr = %target_addr,
                                local_target = %outbound_target,
                                "smoltcp TCP bridge finished"
                            );
                        }
                    })
                };

                if let Ok(mut tasks) = bridge_tasks.lock() {
                    tasks.push(task);
                }
            }
        }
    }
}

async fn bridge_tcp_stream(
    mut smoltcp_stream: TcpStream,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    local_target: SocketAddr,
    domain: Option<String>,
) -> Result<()> {
    let mut local_stream = TokioTcpStream::connect(local_target)
        .await
        .with_context(|| format!("failed to connect local bridge target {}", local_target))?;

    tracing::info!(
        client_addr = %client_addr,
        target_addr = %target_addr,
        local_target = %local_target,
        domain = domain.as_deref().unwrap_or("<unknown>"),
        "Bridging smoltcp TCP stream into local listener"
    );

    let _ = copy_bidirectional(&mut smoltcp_stream, &mut local_stream)
        .await
        .with_context(|| {
            format!(
                "failed to relay traffic between smoltcp stream {} -> {} and local target {}",
                client_addr, target_addr, local_target
            )
        })?;

    Ok(())
}

async fn handle_dns_tcp_stream(
    fake_dns_server: crate::traffic::shared::dns::FakeDnsServer,
    mut smoltcp_stream: TcpStream,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
) -> Result<()> {
    tracing::info!(
        client_addr = %client_addr,
        target_addr = %target_addr,
        "Handling smoltcp TCP DNS stream in-tunnel"
    );

    loop {
        let mut length_bytes = [0u8; 2];
        match smoltcp_stream.read_exact(&mut length_bytes).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to read DNS-over-TCP length from smoltcp stream {} -> {}",
                        client_addr, target_addr
                    )
                });
            }
        }

        let request_len = u16::from_be_bytes(length_bytes) as usize;
        let mut request = vec![0u8; request_len];
        smoltcp_stream
            .read_exact(&mut request)
            .await
            .with_context(|| {
                format!(
                    "failed to read DNS-over-TCP payload of {} bytes from {} -> {}",
                    request_len, client_addr, target_addr
                )
            })?;

        let response = fake_dns_server
            .resolve_request(&request)
            .await
            .with_context(|| {
                format!(
                    "failed to resolve DNS-over-TCP request from {} -> {}",
                    client_addr, target_addr
                )
            })?;
        let response_len = u16::try_from(response.len())
            .context("DNS-over-TCP response exceeded 65535 bytes")?
            .to_be_bytes();

        smoltcp_stream
            .write_all(&response_len)
            .await
            .with_context(|| {
                format!(
                    "failed to write DNS-over-TCP response length to {} -> {}",
                    client_addr, target_addr
                )
            })?;
        smoltcp_stream.write_all(&response).await.with_context(|| {
            format!(
                "failed to write DNS-over-TCP response payload to {} -> {}",
                client_addr, target_addr
            )
        })?;
        smoltcp_stream.flush().await.with_context(|| {
            format!(
                "failed to flush DNS-over-TCP response to {} -> {}",
                client_addr, target_addr
            )
        })?;
    }
}

async fn run_udp_loop(
    context: TunRuntimeContext,
    udp_socket: UdpSocket,
    mut shutdown_rx: oneshot::Receiver<()>,
) {
    let (mut udp_read, mut udp_write) = udp_socket.split();

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => return,
            message = udp_read.next() => {
                let Some((payload, client_addr, target_addr)) = message else {
                    tracing::warn!("smoltcp UDP socket ended unexpectedly");
                    return;
                };

                if target_addr.port() == 53 {
                    match context.fake_dns_server.resolve_request(&payload).await {
                        Ok(response) => {
                            if let Err(error) = udp_write.send((response, target_addr, client_addr)).await {
                                tracing::warn!(
                                    client_addr = %client_addr,
                                    target_addr = %target_addr,
                                    ?error,
                                    "Failed to send UDP DNS response back through smoltcp"
                                );
                            }
                        }
                        Err(error) => {
                            tracing::warn!(
                                client_addr = %client_addr,
                                target_addr = %target_addr,
                                ?error,
                                "Failed to resolve smoltcp UDP DNS query in-tunnel"
                            );
                        }
                    }
                    continue;
                }

                if target_addr.port() == 443 {
                    log_quic_drop(&context, client_addr, target_addr);
                    continue;
                }

                tracing::debug!(
                    client_addr = %client_addr,
                    target_addr = %target_addr,
                    payload_len = payload.len(),
                    "Dropping unsupported smoltcp UDP payload"
                );
            }
        }
    }
}

fn select_tcp_dispatch_target(context: &TunRuntimeContext, target_addr: SocketAddr) -> SocketAddr {
    if target_addr.port() == 443 {
        return SocketAddr::new(context.proxy_redirect_addr.ip(), context.tls_port);
    }

    context.proxy_redirect_addr
}

fn log_quic_drop(context: &TunRuntimeContext, client_addr: SocketAddr, target_addr: SocketAddr) {
    let domain = context
        .fake_dns_server
        .resolve_fake_domain(target_addr.ip(), Instant::now());

    tracing::info!(
        client_addr = %client_addr,
        target_addr = %target_addr,
        domain = domain.as_deref().unwrap_or("<unknown>"),
        "Dropping smoltcp UDP/443 payload to force TCP/TLS fallback"
    );
}

fn prune_bridge_tasks(tasks: &Arc<Mutex<Vec<JoinHandle<()>>>>) {
    if let Ok(mut guard) = tasks.lock() {
        guard.retain(|handle| !handle.is_finished());
    }
}

fn build_tun_device(context: &TunRuntimeContext) -> std::io::Result<tun_rs::AsyncDevice> {
    let builder = DeviceBuilder::new()
        .name(&context.tun_name)
        .layer(Layer::L3)
        .mtu(context.tun_mtu)
        .ipv4(
            first_usable_ipv4(context.fake_ipv4_range),
            context.fake_ipv4_range.prefix_len(),
            None,
        )
        .ipv6(
            first_usable_ipv6(context.fake_ipv6_range),
            context.fake_ipv6_range.prefix_len(),
        )
        .with(|_options| {
            #[cfg(any(
                target_os = "linux",
                target_os = "macos",
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd"
            ))]
            {
                _options.packet_information(false);
            }
        });

    let device = builder.build_async()?;
    configure_windows_tun_dns(&device, context)?;
    Ok(device)
}

fn spawn_shutdownable_task<F, Fut>(
    workers: &Workers,
    worker_name: &'static str,
    task_factory: F,
) -> ShutdownJoinHandle
where
    F: FnOnce(oneshot::Receiver<()>) -> Fut,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let join = workers.spawn(worker_name, task_factory(shutdown_rx));
    ShutdownJoinHandle::new(shutdown_tx, join)
}

fn first_usable_ipv4(range: ipnet::Ipv4Net) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(range.network()).saturating_add(1))
}

fn first_usable_ipv6(range: ipnet::Ipv6Net) -> Ipv6Addr {
    Ipv6Addr::from(u128::from_be_bytes(range.network().octets()).saturating_add(1))
}

fn dns_server_ipv4(range: ipnet::Ipv4Net) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(range.network()).saturating_add(2))
}

fn dns_server_ipv6(range: ipnet::Ipv6Net) -> Ipv6Addr {
    Ipv6Addr::from(u128::from_be_bytes(range.network().octets()).saturating_add(2))
}

#[cfg(target_os = "windows")]
fn configure_windows_tun_dns(
    device: &tun_rs::AsyncDevice,
    context: &TunRuntimeContext,
) -> std::io::Result<()> {
    let dns_server = IpAddr::V4(dns_server_ipv4(context.fake_ipv4_range));
    device.set_dns_servers(&[dns_server])?;

    tracing::info!(
        tun_name = %context.tun_name,
        tun_dns = %dns_server,
        "Configured Windows TUN adapter DNS"
    );

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn configure_windows_tun_dns(
    _device: &tun_rs::AsyncDevice,
    _context: &TunRuntimeContext,
) -> std::io::Result<()> {
    Ok(())
}
