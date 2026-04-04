use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use anyhow::Result;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpListener;

pub(crate) fn bind_dual_stack_tcp_listener(port: u16, backlog: i32) -> Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
    socket.listen(backlog)?;
    Ok(TcpListener::from_std(socket.into())?)
}
