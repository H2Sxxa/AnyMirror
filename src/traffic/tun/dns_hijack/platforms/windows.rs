use std::io;
use std::net::IpAddr;
use std::process::{Command, Output};
use std::sync::Arc;

use tun_rs::AsyncDevice;

use crate::traffic::tun::TunRuntimeContext;

pub(in crate::traffic::tun) struct WindowsPlatformDnsGuard {
    device: Arc<AsyncDevice>,
    original_ipv4_dns: Vec<IpAddr>,
    original_ipv6_dns: Vec<IpAddr>,
}

impl WindowsPlatformDnsGuard {
    pub(super) fn restore(self) -> io::Result<()> {
        restore_dns_family(&self.device, true, &self.original_ipv4_dns)?;
        restore_dns_family(&self.device, false, &self.original_ipv6_dns)?;
        tracing::info!(
            original_ipv4_dns = ?self.original_ipv4_dns,
            original_ipv6_dns = ?self.original_ipv6_dns,
            "Restored Windows TUN adapter DNS state"
        );
        Ok(())
    }
}

pub(super) fn configure(
    device: Arc<AsyncDevice>,
    context: &TunRuntimeContext,
) -> io::Result<WindowsPlatformDnsGuard> {
    let original_ipv4_dns = query_dns_servers(&device, "IPv4")?;
    let original_ipv6_dns = query_dns_servers(&device, "IPv6")?;
    let dns_server = IpAddr::V4(context.dns_plan.dns_addr_v4);
    device.set_dns_servers(&[dns_server])?;

    tracing::info!(
        tun_name = %context.tun_name,
        tun_dns = %dns_server,
        original_ipv4_dns = ?original_ipv4_dns,
        original_ipv6_dns = ?original_ipv6_dns,
        "Configured Windows TUN adapter DNS"
    );

    Ok(WindowsPlatformDnsGuard {
        device,
        original_ipv4_dns,
        original_ipv6_dns,
    })
}

fn restore_dns_family(
    device: &AsyncDevice,
    is_ipv4: bool,
    original_dns: &[IpAddr],
) -> io::Result<()> {
    if original_dns.is_empty() {
        return device.clear_dns_servers(is_ipv4);
    }

    device.set_dns_servers(original_dns)
}

fn query_dns_servers(device: &AsyncDevice, family: &str) -> io::Result<Vec<IpAddr>> {
    let interface_index = device.if_index()?;
    let command = format!(
        "$addresses = (Get-DnsClientServerAddress -InterfaceIndex {interface_index} -AddressFamily {family}).ServerAddresses; if ($null -eq $addresses) {{ '' }} else {{ [string]::Join(',', $addresses) }}"
    );
    let output = Command::new("powershell.exe")
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(command)
        .output()?;
    let stdout = ensure_success("query Windows TUN DNS state", output)?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    trimmed
        .split(',')
        .map(|entry| {
            entry.trim().parse::<IpAddr>().map_err(|error| {
                io::Error::other(format!("failed to parse DNS server `{entry}`: {error}"))
            })
        })
        .collect()
}

fn ensure_success(action: &str, output: Output) -> io::Result<String> {
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = if !stderr.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        stdout.trim().to_string()
    };

    Err(io::Error::other(format!(
        "failed to {}: {}",
        action, details
    )))
}
