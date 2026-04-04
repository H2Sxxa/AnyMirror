use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use anyhow::{anyhow, Result};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use url::Url;

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
    resolver: TokioResolver,
}

impl CustomResolver {
    /// Create the default system DNS resolver
    pub fn system() -> Result<Self> {
        let resolver = TokioResolver::builder_tokio()
            .map_err(|error| anyhow!("Failed to create system DNS resolver: {}", error))?
            .build();

        Ok(Self { resolver })
    }

    /// Create a resolver based on DnsPlan
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
    fn udp(server: &str) -> Result<Self> {
        let socket_addr: SocketAddr = if server.contains(':') {
            server
                .parse()
                .map_err(|error| anyhow!("Invalid DNS server address {}: {}", server, error))?
        } else {
            format!("{}:53", server)
                .parse()
                .map_err(|error| anyhow!("Invalid DNS server address {}: {}", server, error))?
        };

        let group =
            NameServerConfigGroup::from_ips_clear(&[socket_addr.ip()], socket_addr.port(), true);
        let config = ResolverConfig::from_parts(None, vec![], group);
        let resolver =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
                .with_options(ResolverOpts::default())
                .build();

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
        let url = Url::parse(&server_url)
            .map_err(|error| anyhow!("Invalid DoH server URL {}: {}", server, error))?;

        let host = url
            .host_str()
            .ok_or_else(|| anyhow!("No host found in DoH server URL"))?;
        let port = url.port_or_known_default().unwrap_or(443);

        let system_resolver = TokioResolver::builder_tokio()
            .map_err(|error| {
                anyhow!(
                    "Failed to create system DNS resolver for DoH bootstrap: {}",
                    error
                )
            })?
            .build();

        let lookup = system_resolver
            .lookup_ip(host)
            .await
            .map_err(|error| anyhow!("Failed to resolve DoH server host {}: {}", host, error))?;

        let ips = lookup.iter().collect::<Vec<IpAddr>>();
        if ips.is_empty() {
            return Err(anyhow!("No IPs found for DoH server {}", host));
        }

        let group = NameServerConfigGroup::from_ips_https(&ips, port, host.to_string(), true);
        let config = ResolverConfig::from_parts(None, vec![], group);
        let resolver =
            TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
                .with_options(ResolverOpts::default())
                .build();

        Ok(Self { resolver })
    }

    /// Resolve a hostname to an IP address
    pub async fn resolve(&self, hostname: &str) -> Result<IpAddr> {
        if let Ok(ip) = IpAddr::from_str(hostname) {
            return Ok(ip);
        }

        let lookup = self
            .resolver
            .lookup_ip(hostname)
            .await
            .map_err(|error| anyhow!("DNS resolution failed for {}: {}", hostname, error))?;

        lookup
            .iter()
            .next()
            .ok_or_else(|| anyhow!("No DNS records found for {}", hostname))
    }
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, str::FromStr};

    use super::CustomResolver;

    #[tokio::test]
    async fn test_resolve_ip_string() {
        let resolver = CustomResolver::system().unwrap();
        let result = resolver.resolve("127.0.0.1").await.unwrap();
        assert_eq!(result, IpAddr::from_str("127.0.0.1").unwrap());
    }
}
