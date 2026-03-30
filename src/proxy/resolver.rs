use anyhow::{anyhow, Result};
use std::net::IpAddr;
use std::str::FromStr;
use trust_dns_resolver::TokioAsyncResolver;

use crate::rules::{DnsMode, DnsPlan};

/// Custom DNS Resolver
///
/// This module provides flexible DNS resolution capabilities, supporting:
/// - System DNS
/// - UDP DNS (Standard DNS over UDP)
/// - DoH (DNS-over-HTTPS)
///
/// It provides unified DNS resolution support for the entire project,
/// and is integrated into the custom hyper HTTP connector.
#[allow(dead_code)]
pub struct CustomResolver {
    resolver: TokioAsyncResolver,
}

impl CustomResolver {
    /// Create the default system DNS resolver
    #[allow(dead_code)]
    pub fn system() -> Result<Self> {
        let resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| anyhow!("Failed to create system DNS resolver: {}", e))?;

        Ok(Self { resolver })
    }

    /// Create a resolver based on DnsPlan
    #[allow(dead_code)]
    pub async fn from_plan(plan: &DnsPlan) -> Result<Self> {
        match plan.mode {
            DnsMode::System => Self::system(),
            DnsMode::Udp => Self::udp(
                plan.server
                    .as_deref()
                    .ok_or_else(|| anyhow!("UDP DNS mode requires server address"))?,
            ),
            DnsMode::Doh => {
                Self::doh(
                    plan.server
                        .as_deref()
                        .ok_or_else(|| anyhow!("DoH mode requires server address"))?,
                )
                .await
            }
        }
    }

    /// Create a UDP DNS resolver (Standard DNS)
    #[allow(dead_code)]
    fn udp(server: &str) -> Result<Self> {
        let socket_addr: std::net::SocketAddr = if server.contains(':') {
            server
                .parse()
                .map_err(|e| anyhow!("Invalid DNS server address {}: {}", server, e))?
        } else {
            format!("{}:53", server)
                .parse()
                .map_err(|e| anyhow!("Invalid DNS server address {}: {}", server, e))?
        };

        let group = trust_dns_resolver::config::NameServerConfigGroup::from_ips_clear(
            &[socket_addr.ip()],
            socket_addr.port(),
            true,
        );
        let config = trust_dns_resolver::config::ResolverConfig::from_parts(None, vec![], group);

        let resolver =
            TokioAsyncResolver::tokio(config, trust_dns_resolver::config::ResolverOpts::default());

        Ok(Self { resolver })
    }

    /// Create a DoH (DNS-over-HTTPS) resolver
    #[allow(dead_code)]
    async fn doh(server: &str) -> Result<Self> {
        let server_url = if server.starts_with("http") {
            server.to_string()
        } else {
            format!("https://{}/dns-query", server)
        };
        let url = url::Url::parse(&server_url)
            .map_err(|e| anyhow!("Invalid DoH server URL {}: {}", server, e))?;

        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("No host found in DoH server URL"))?;
        let port = url.port_or_known_default().unwrap_or(443);

        // Resolve the DoH server's IP address using the system resolver first
        let system_resolver = TokioAsyncResolver::tokio_from_system_conf().map_err(|e| {
            anyhow!(
                "Failed to create system DNS resolver for DoH bootstrap: {}",
                e
            )
        })?;

        let lookup = system_resolver
            .lookup_ip(host)
            .await
            .map_err(|e| anyhow!("Failed to resolve DoH server host {}: {}", host, e))?;

        let ips: Vec<IpAddr> = lookup.iter().collect();
        if ips.is_empty() {
            return Err(anyhow!("No IPs found for DoH server {}", host));
        }

        // NameServerConfigGroup::from_ips_https requires an SNI name (spki_name)
        let group = trust_dns_resolver::config::NameServerConfigGroup::from_ips_https(
            &ips,
            port,
            host.to_string(),
            true, // trust_negative_responses
        );
        let config = trust_dns_resolver::config::ResolverConfig::from_parts(None, vec![], group);

        let opts = trust_dns_resolver::config::ResolverOpts::default();
        let resolver = TokioAsyncResolver::tokio(config, opts);
        Ok(Self { resolver })
    }

    /// Resolve a hostname to an IP address
    pub async fn resolve(&self, hostname: &str) -> Result<IpAddr> {
        // Return immediately if it's already an IP address
        if let Ok(ip) = IpAddr::from_str(hostname) {
            return Ok(ip);
        }

        // Use DNS resolution
        let lookup = self
            .resolver
            .lookup_ip(hostname)
            .await
            .map_err(|e| anyhow!("DNS resolution failed for {}: {}", hostname, e))?;

        lookup
            .iter()
            .next()
            .ok_or_else(|| anyhow!("No DNS records found for {}", hostname))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_resolve_ip_string() {
        let resolver = CustomResolver::system().unwrap();
        let result = resolver.resolve("127.0.0.1").await.unwrap();
        assert_eq!(result, IpAddr::from_str("127.0.0.1").unwrap());
    }
}
