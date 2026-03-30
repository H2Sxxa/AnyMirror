use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};

use crate::rules::Rules;
use crate::traffic::windivert::default_filter;

pub(super) fn resolve_origin_target_ips(rules: &Rules) -> Vec<Ipv4Addr> {
    let mut target_ips = Vec::new();
    for host in rules.origin_hosts() {
        if let Ok(addrs) = ToSocketAddrs::to_socket_addrs(&(host.as_str(), 0)) {
            for addr in addrs {
                if let IpAddr::V4(ipv4) = addr.ip() {
                    if !target_ips.contains(&ipv4) {
                        target_ips.push(ipv4);
                    }
                }
            }
        }
    }
    target_ips
}

pub(super) fn build_transparent_filter(listen_addr: SocketAddr, target_ips: &[Ipv4Addr]) -> String {
    if target_ips.is_empty() {
        return default_filter(listen_addr, false);
    }

    let ip_conds: Vec<String> = target_ips
        .iter()
        .map(|ip| format!("ip.DstAddr == {}", ip))
        .collect();

    format!(
        "outbound and ip and tcp and ( (!loopback and tcp.DstPort != {} and tcp.DstPort != {} and ({})) or tcp.SrcPort == {} or tcp.SrcPort == {} )",
        listen_addr.port(),
        listen_addr.port() + 1,
        ip_conds.join(" or "),
        listen_addr.port(),
        listen_addr.port() + 1
    )
}
