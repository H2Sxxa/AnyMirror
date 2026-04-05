#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
mod other;
#[cfg(target_os = "windows")]
mod windows;

use std::io;
use std::sync::Arc;

use tun_rs::AsyncDevice;

use crate::config::TunPlatformDnsMode;
use crate::traffic::tun::TunRuntimeContext;

pub(in crate::traffic::tun) enum PlatformDnsGuard {
    Noop,
    #[cfg(target_os = "windows")]
    Windows(windows::WindowsPlatformDnsGuard),
    #[cfg(target_os = "linux")]
    Linux(linux::LinuxPlatformDnsGuard),
}

impl PlatformDnsGuard {
    pub(in crate::traffic::tun) fn restore(self) -> io::Result<()> {
        match self {
            Self::Noop => Ok(()),
            #[cfg(target_os = "windows")]
            Self::Windows(guard) => guard.restore(),
            #[cfg(target_os = "linux")]
            Self::Linux(guard) => guard.restore(),
        }
    }
}

pub(super) fn configure(
    device: Arc<AsyncDevice>,
    context: &TunRuntimeContext,
) -> io::Result<PlatformDnsGuard> {
    log_dns_setup_summary(device.as_ref(), context);

    if matches!(context.platform_dns, TunPlatformDnsMode::Manual) {
        log_manual_dns_guidance(device.as_ref(), context);
        return Ok(PlatformDnsGuard::Noop);
    }

    #[cfg(target_os = "windows")]
    {
        return windows::configure(device, context).map(PlatformDnsGuard::Windows);
    }

    #[cfg(target_os = "linux")]
    {
        return linux::configure(device, context).map(PlatformDnsGuard::Linux);
    }

    #[cfg(target_os = "macos")]
    {
        return macos::configure(device, context).map(|()| PlatformDnsGuard::Noop);
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        return other::configure(device, context).map(|()| PlatformDnsGuard::Noop);
    }
}

fn log_dns_setup_summary(device: &AsyncDevice, context: &TunRuntimeContext) {
    let interface_name = device.name().unwrap_or_else(|_| context.tun_name.clone());
    tracing::info!(
        tun_name = %context.tun_name,
        interface_name = %interface_name,
        platform_dns_mode = ?context.platform_dns,
        tun_dns_ipv4 = %context.dns_plan.dns_addr_v4,
        tun_dns_ipv6 = %context.dns_plan.dns_addr_v6,
        "TUN DNS setup summary"
    );
}

fn log_manual_dns_guidance(device: &AsyncDevice, context: &TunRuntimeContext) {
    let interface_name = device.name().unwrap_or_else(|_| context.tun_name.clone());

    #[cfg(target_os = "windows")]
    {
        tracing::warn!(
            tun_name = %context.tun_name,
            interface_name = %interface_name,
            tun_dns_ipv4 = %context.dns_plan.dns_addr_v4,
            tun_dns_ipv6 = %context.dns_plan.dns_addr_v6,
            "TUN platform DNS automation is disabled; set the Windows TUN adapter DNS to the reserved in-tunnel DNS addresses manually if you need DNS hijack"
        );
        tracing::warn!(
            interface_name = %interface_name,
            "Browser Secure DNS / DoH can bypass system DNS even when the TUN adapter DNS is configured"
        );
    }

    #[cfg(target_os = "linux")]
    {
        tracing::warn!(
            tun_name = %context.tun_name,
            interface_name = %interface_name,
            tun_dns_ipv4 = %context.dns_plan.dns_addr_v4,
            tun_dns_ipv6 = %context.dns_plan.dns_addr_v6,
            example_dns_command = %format!(
                "resolvectl dns {} {} {}",
                interface_name, context.dns_plan.dns_addr_v4, context.dns_plan.dns_addr_v6
            ),
            example_domain_command = %format!("resolvectl domain {} ~.", interface_name),
            "TUN platform DNS automation is disabled; configure Linux link DNS manually if you need DNS hijack"
        );
    }

    #[cfg(target_os = "macos")]
    {
        tracing::warn!(
            tun_name = %context.tun_name,
            interface_name = %interface_name,
            tun_dns_ipv4 = %context.dns_plan.dns_addr_v4,
            tun_dns_ipv6 = %context.dns_plan.dns_addr_v6,
            "TUN platform DNS automation is disabled; configure the macOS TUN service DNS manually or use a NetworkExtension host"
        );
        tracing::warn!(
            interface_name = %interface_name,
            "Encrypted client-side DNS such as Secure DNS / DoH can bypass system DNS settings"
        );
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        tracing::warn!(
            tun_name = %context.tun_name,
            interface_name = %interface_name,
            tun_dns_ipv4 = %context.dns_plan.dns_addr_v4,
            tun_dns_ipv6 = %context.dns_plan.dns_addr_v6,
            "TUN platform DNS automation is disabled; configure the interface DNS manually if you need DNS hijack"
        );
    }
}
