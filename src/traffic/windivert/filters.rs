use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

/// Build TCP outbound capture filter for fake-ip transparent mode.
pub fn build_transparent_fake_ip_tcp_request_filter(
    proxy_port: u16,
    tls_port: u16,
    fake_ipv4_range: Ipv4Net,
    fake_ipv6_range: Ipv6Net,
) -> String {
    let destination_clause = fake_ip_destination_clause(fake_ipv4_range, fake_ipv6_range);

    format!(
        "outbound and tcp and !loopback and tcp.DstPort != {} and tcp.DstPort != {} and {}",
        proxy_port, tls_port, destination_clause
    )
}

/// Build proxy response capture filter
pub fn build_transparent_tcp_proxy_response_filter(
    proxy_port: u16,
    tls_port: u16,
    dns_port: u16,
) -> String {
    format!(
        "outbound and tcp and (tcp.SrcPort == {} or tcp.SrcPort == {} or tcp.SrcPort == {})",
        proxy_port, tls_port, dns_port
    )
}

/// Build outbound DNS query capture filter for fake-ip response synthesis.
pub fn build_transparent_dns_query_filter() -> String {
    "outbound and udp and !loopback and udp.DstPort == 53".to_string()
}

/// Build outbound DNS-over-TCP capture filter for redirection to the local DNS server.
pub fn build_transparent_dns_tcp_request_filter() -> String {
    "outbound and tcp and !loopback and tcp.DstPort == 53".to_string()
}

/// Build outbound QUIC capture filter for fake-ip addresses.
pub fn build_transparent_fake_ip_quic_filter(
    fake_ipv4_range: Ipv4Net,
    fake_ipv6_range: Ipv6Net,
) -> String {
    let destination_clause = fake_ip_destination_clause(fake_ipv4_range, fake_ipv6_range);

    format!(
        "outbound and udp and !loopback and udp.DstPort == 443 and {}",
        destination_clause
    )
}

fn fake_ip_destination_clause(fake_ipv4_range: Ipv4Net, fake_ipv6_range: Ipv6Net) -> String {
    format!(
        "((ip and ip.DstAddr >= {} and ip.DstAddr <= {}) or (ipv6 and ipv6.DstAddr >= {} and ipv6.DstAddr <= {}))",
        first_usable_ipv4(fake_ipv4_range),
        last_usable_ipv4(fake_ipv4_range),
        first_usable_ipv6(fake_ipv6_range),
        last_usable_ipv6(fake_ipv6_range)
    )
}

fn first_usable_ipv4(fake_ipv4_range: Ipv4Net) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(fake_ipv4_range.network()).saturating_add(1))
}

fn last_usable_ipv4(fake_ipv4_range: Ipv4Net) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(fake_ipv4_range.broadcast()).saturating_sub(1))
}

fn first_usable_ipv6(fake_ipv6_range: Ipv6Net) -> Ipv6Addr {
    Ipv6Addr::from(u128::from_be_bytes(fake_ipv6_range.network().octets()).saturating_add(1))
}

fn last_usable_ipv6(fake_ipv6_range: Ipv6Net) -> Ipv6Addr {
    let network = u128::from_be_bytes(fake_ipv6_range.network().octets());
    let host_mask = ipv6_host_mask(fake_ipv6_range.prefix_len());
    Ipv6Addr::from(network | host_mask)
}

fn ipv6_host_mask(prefix_len: u8) -> u128 {
    let host_bits = 128u32.saturating_sub(u32::from(prefix_len));
    match host_bits {
        0 => 0,
        128 => u128::MAX,
        bits => (1u128 << bits) - 1,
    }
}

#[cfg(test)]
mod tests {
    use ipnet::{Ipv4Net, Ipv6Net};

    use super::build_transparent_fake_ip_tcp_request_filter;

    #[test]
    fn fake_ip_request_filter_is_bound_to_fake_range() {
        let filter = build_transparent_fake_ip_tcp_request_filter(
            8787,
            8788,
            Ipv4Net::new("198.18.0.0".parse().unwrap(), 16).unwrap(),
            Ipv6Net::new("fd00:198:18::".parse().unwrap(), 48).unwrap(),
        );

        assert!(filter.contains("ip.DstAddr >= 198.18.0.1"));
        assert!(filter.contains("ip.DstAddr <= 198.18.255.254"));
        assert!(filter.contains("ipv6.DstAddr >= fd00:198:18::1"));
        assert!(filter.contains("ipv6.DstAddr <= fd00:198:18:ffff:ffff:ffff:ffff:ffff"));
    }
}
