mod platforms;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use ipnet::{Ipv4Net, Ipv6Net};

use crate::config::{TunDnsHijackSpec, TunDnsHijackTarget, TunDnsHijackTransport};

use super::TunRuntimeContext;

pub(in crate::traffic::tun) use self::platforms::PlatformDnsGuard;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TunDnsTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TunDnsPlan {
    pub tun_addr_v4: Ipv4Addr,
    pub tun_addr_v6: Ipv6Addr,
    pub dns_addr_v4: Ipv4Addr,
    pub dns_addr_v6: Ipv6Addr,
    pub first_fake_v4: Ipv4Addr,
    pub first_fake_v6: Ipv6Addr,
}

impl TunDnsPlan {
    pub(super) fn new(fake_ipv4_range: Ipv4Net, fake_ipv6_range: Ipv6Net) -> Self {
        let network_v4 = u32::from(fake_ipv4_range.network());
        let network_v6 = u128::from_be_bytes(fake_ipv6_range.network().octets());

        Self {
            tun_addr_v4: Ipv4Addr::from(network_v4.saturating_add(1)),
            tun_addr_v6: Ipv6Addr::from(network_v6.saturating_add(1)),
            dns_addr_v4: Ipv4Addr::from(network_v4.saturating_add(2)),
            dns_addr_v6: Ipv6Addr::from(network_v6.saturating_add(2)),
            first_fake_v4: Ipv4Addr::from(network_v4.saturating_add(3)),
            first_fake_v6: Ipv6Addr::from(network_v6.saturating_add(3)),
        }
    }

    pub(super) fn should_hijack_dns(
        &self,
        specs: &[TunDnsHijackSpec],
        transport: TunDnsTransport,
        target_addr: SocketAddr,
    ) -> bool {
        self.matches_reserved_dns_target(target_addr)
            || specs
                .iter()
                .any(|spec| spec_matches_dns_target(spec, transport, target_addr))
    }

    fn matches_reserved_dns_target(&self, target_addr: SocketAddr) -> bool {
        if target_addr.port() != 53 {
            return false;
        }

        target_addr.ip() == IpAddr::V4(self.dns_addr_v4)
            || target_addr.ip() == IpAddr::V6(self.dns_addr_v6)
    }
}

pub(super) fn configure_platform_dns(
    device: Arc<tun_rs::AsyncDevice>,
    context: &TunRuntimeContext,
) -> io::Result<PlatformDnsGuard> {
    platforms::configure(device, context)
}

fn spec_matches_dns_target(
    spec: &TunDnsHijackSpec,
    transport: TunDnsTransport,
    target_addr: SocketAddr,
) -> bool {
    if !spec_matches_transport(spec.transport, transport) {
        return false;
    }

    match &spec.target {
        TunDnsHijackTarget::Any(port) => target_addr.port() == *port,
        TunDnsHijackTarget::Exact(addr) => target_addr == *addr,
    }
}

fn spec_matches_transport(expected: TunDnsHijackTransport, actual: TunDnsTransport) -> bool {
    matches!(
        (expected, actual),
        (TunDnsHijackTransport::Udp, TunDnsTransport::Udp)
            | (TunDnsHijackTransport::Tcp, TunDnsTransport::Tcp)
    )
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use ipnet::{Ipv4Net, Ipv6Net};

    use super::{TunDnsPlan, TunDnsTransport};
    use crate::config::{TunDnsHijackSpec, TunDnsHijackTarget, TunDnsHijackTransport};

    #[test]
    fn reserved_dns_target_is_hijacked_for_both_transports() {
        let plan = TunDnsPlan::new(
            Ipv4Net::new("198.18.0.0".parse().unwrap(), 16).unwrap(),
            Ipv6Net::new("fd00:198:18::".parse().unwrap(), 48).unwrap(),
        );
        let target = SocketAddr::from((Ipv4Addr::new(198, 18, 0, 2), 53));

        assert!(plan.should_hijack_dns(&[], TunDnsTransport::Udp, target));
        assert!(plan.should_hijack_dns(&[], TunDnsTransport::Tcp, target));
    }

    #[test]
    fn any_rule_matches_only_its_transport() {
        let plan = TunDnsPlan::new(
            Ipv4Net::new("198.18.0.0".parse().unwrap(), 16).unwrap(),
            Ipv6Net::new("fd00:198:18::".parse().unwrap(), 48).unwrap(),
        );
        let specs = vec![TunDnsHijackSpec {
            transport: TunDnsHijackTransport::Udp,
            target: TunDnsHijackTarget::Any(53),
        }];
        let target = SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53));

        assert!(plan.should_hijack_dns(&specs, TunDnsTransport::Udp, target));
        assert!(!plan.should_hijack_dns(&specs, TunDnsTransport::Tcp, target));
    }
}
