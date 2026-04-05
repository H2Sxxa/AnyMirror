use std::ffi::OsStr;
use std::io;
use std::process::{Command, Output};
use std::sync::Arc;

use tun_rs::AsyncDevice;

use crate::traffic::tun::TunRuntimeContext;

pub(super) struct ResolvectlDnsGuard {
    _device: Arc<AsyncDevice>,
    interface_name: String,
}

impl ResolvectlDnsGuard {
    pub(super) fn restore(self) -> io::Result<()> {
        run_resolvectl(
            ["revert", self.interface_name.as_str()],
            "restore Linux TUN DNS state",
        )?;
        tracing::info!(
            tun_name = %self.interface_name,
            "Restored Linux TUN interface DNS with resolvectl revert"
        );
        Ok(())
    }
}

pub(super) fn configure(
    device: Arc<AsyncDevice>,
    context: &TunRuntimeContext,
) -> io::Result<ResolvectlDnsGuard> {
    ensure_resolvectl_available()?;

    let interface_name = device.name()?;
    let dns_v4 = context.dns_plan.dns_addr_v4.to_string();
    let dns_v6 = context.dns_plan.dns_addr_v6.to_string();

    run_resolvectl(
        [
            "dns",
            interface_name.as_str(),
            dns_v4.as_str(),
            dns_v6.as_str(),
        ],
        "configure Linux TUN DNS servers",
    )?;
    run_resolvectl(
        ["domain", interface_name.as_str(), "~."],
        "configure Linux TUN DNS routing domain",
    )?;
    run_resolvectl(
        ["default-route", interface_name.as_str(), "yes"],
        "configure Linux TUN DNS default route",
    )?;
    run_resolvectl(
        ["llmnr", interface_name.as_str(), "no"],
        "disable Linux TUN LLMNR resolution",
    )?;
    run_resolvectl(
        ["mdns", interface_name.as_str(), "no"],
        "disable Linux TUN mDNS resolution",
    )?;

    tracing::info!(
        tun_name = %interface_name,
        tun_dns_ipv4 = %context.dns_plan.dns_addr_v4,
        tun_dns_ipv6 = %context.dns_plan.dns_addr_v6,
        "Configured Linux TUN interface DNS with resolvectl"
    );

    Ok(ResolvectlDnsGuard {
        _device: device,
        interface_name,
    })
}

fn ensure_resolvectl_available() -> io::Result<()> {
    let output = Command::new("resolvectl").arg("--version").output();
    match output {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(command_failure(
            "resolvectl",
            ["--version"],
            "verify Linux TUN DNS automation prerequisites",
            output,
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Linux TUN platform_dns=auto currently requires `resolvectl` from systemd-resolved; switch to manual or install/enable systemd-resolved",
        )),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!(
                "failed to execute `resolvectl --version` while verifying Linux TUN DNS automation prerequisites: {}",
                error
            ),
        )),
    }
}

fn run_resolvectl<const N: usize>(args: [&str; N], action: &str) -> io::Result<()> {
    let output = Command::new("resolvectl").args(args).output()?;
    if output.status.success() {
        return Ok(());
    }

    Err(command_failure("resolvectl", args, action, output))
}

fn command_failure<I, S>(command: &str, args: I, action: &str, output: Output) -> io::Error
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let rendered_args = args
        .into_iter()
        .map(|arg| arg.as_ref().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let details = if !stderr.trim().is_empty() {
        stderr.trim().to_string()
    } else {
        stdout.trim().to_string()
    };

    io::Error::other(format!(
        "failed to {} using `{}` with args {:?}: {}",
        action, command, rendered_args, details
    ))
}
