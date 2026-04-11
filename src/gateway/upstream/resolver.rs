use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use anyhow::{Result, anyhow};
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use url::Url;

use crate::rules::model::{DnsMode, DnsPlan};

/// Custom DNS Resolver
///
/// This module provides flexible DNS resolution capabilities, supporting:
/// - System DNS
/// - UDP DNS (Standard DNS over UDP)
/// - DoT (DNS-over-TLS)
/// - DoH (DNS-over-HTTPS)
///
/// It provides unified DNS resolution support for the entire project,
/// and is integrated into the custom hyper HTTP connector.
#[derive(Clone)]
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
            DnsMode::Udp => Self::udp(require_server(plan, "UDP DNS mode")?),
            DnsMode::Dot => Self::dot(require_server(plan, "DoT mode")?).await,
            DnsMode::Doh => Self::doh(require_server(plan, "DoH mode")?).await,
        }
    }

    /// Create a UDP DNS resolver (Standard DNS)
    fn udp(server: &str) -> Result<Self> {
        let socket_addr = parse_socket_addr(server, 53)?;
        let group =
            NameServerConfigGroup::from_ips_clear(&[socket_addr.ip()], socket_addr.port(), true);
        Ok(Self {
            resolver: build_resolver(ResolverConfig::from_parts(None, vec![], group)),
        })
    }

    /// Create a DoT (DNS-over-TLS) resolver
    async fn dot(server: &str) -> Result<Self> {
        let server_config = parse_dot_server(server)?;
        let ips = resolve_bootstrap_ips(&server_config.bootstrap_host, "DoT").await?;
        let group = NameServerConfigGroup::from_ips_tls(
            &ips,
            server_config.port,
            server_config.server_name,
            true,
        );
        Ok(Self {
            resolver: build_resolver(ResolverConfig::from_parts(None, vec![], group)),
        })
    }

    /// Create a DoH (DNS-over-HTTPS) resolver
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
        let ips = resolve_bootstrap_ips(host, "DoH").await?;
        let group = NameServerConfigGroup::from_ips_https(&ips, port, host.to_string(), true);
        Ok(Self {
            resolver: build_resolver(ResolverConfig::from_parts(None, vec![], group)),
        })
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

struct DotServer {
    server_name: String,
    bootstrap_host: String,
    port: u16,
}

fn require_server<'a>(plan: &'a DnsPlan, mode_name: &str) -> Result<&'a str> {
    plan.server
        .as_deref()
        .ok_or_else(|| anyhow!("{} requires server address", mode_name))
}

fn parse_socket_addr(server: &str, default_port: u16) -> Result<SocketAddr> {
    let candidate = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:{default_port}")
    };

    candidate
        .parse()
        .map_err(|error| anyhow!("Invalid DNS server address {}: {}", server, error))
}

fn build_resolver(config: ResolverConfig) -> TokioResolver {
    TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(ResolverOpts::default())
        .build()
}

fn build_system_resolver(context: &str) -> Result<TokioResolver> {
    TokioResolver::builder_tokio()
        .map_err(|error| {
            anyhow!(
                "Failed to create system DNS resolver for {}: {}",
                context,
                error
            )
        })
        .map(|builder| builder.build())
}

async fn resolve_bootstrap_ips(host: &str, protocol: &str) -> Result<Vec<IpAddr>> {
    let system_resolver = build_system_resolver(&format!("{protocol} bootstrap"))?;
    let lookup = system_resolver.lookup_ip(host).await.map_err(|error| {
        anyhow!(
            "Failed to resolve {} server host {}: {}",
            protocol,
            host,
            error
        )
    })?;

    let ips = lookup.iter().collect::<Vec<IpAddr>>();
    if ips.is_empty() {
        return Err(anyhow!("No IPs found for {} server {}", protocol, host));
    }

    Ok(ips)
}

fn parse_dot_server(server: &str) -> Result<DotServer> {
    let trimmed = trim_dot_server(server);
    let host = trimmed.split(':').next().unwrap_or(trimmed);
    if host.is_empty() {
        return Err(anyhow!("Invalid DoT server address {}", server));
    }

    Ok(DotServer {
        server_name: host.to_string(),
        bootstrap_host: host.to_string(),
        port: trimmed
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse().ok())
            .unwrap_or(853),
    })
}

fn trim_dot_server(server: &str) -> &str {
    server
        .trim()
        .trim_start_matches("tls://")
        .trim_end_matches('/')
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
