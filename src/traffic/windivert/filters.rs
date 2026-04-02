use std::net::IpAddr;

/// Build TCP outbound capture filter
pub fn build_transparent_tcp_request_filter(proxy_port: u16, tls_port: u16) -> String {
    format!(
        "outbound and ip and tcp and !loopback and tcp.DstPort != {} and tcp.DstPort != {}",
        proxy_port, tls_port
    )
}

/// Build TCP targeted request capture filter
pub fn build_transparent_targeted_tcp_request_filter(
    proxy_port: u16,
    tls_port: u16,
    target_ips: &[IpAddr],
) -> Option<String> {
    let ip_conditions = target_ips
        .iter()
        .map(|ip| match ip {
            IpAddr::V4(value) => format!("ip.DstAddr == {}", value),
            IpAddr::V6(value) => format!("ipv6.DstAddr == {}", value),
        })
        .collect::<Vec<_>>();

    if ip_conditions.is_empty() {
        return None;
    }

    Some(format!(
        "outbound and ip and tcp and !loopback and tcp.DstPort != {} and tcp.DstPort != {} and ({})",
        proxy_port,
        tls_port,
        ip_conditions.join(" or ")
    ))
}

/// Build proxy response capture filter
pub fn build_transparent_tcp_proxy_response_filter(proxy_port: u16, tls_port: u16) -> String {
    format!(
        "outbound and ip and tcp and (tcp.SrcPort == {} or tcp.SrcPort == {})",
        proxy_port, tls_port
    )
}

/// Build DNS capture filter
pub fn build_transparent_dns_filter() -> String {
    "ip and !loopback and udp and (udp.SrcPort == 53 or udp.DstPort == 53)".to_string()
}
