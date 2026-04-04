use ipnet::{Ipv4Net, Ipv6Net};
use std::borrow::Cow;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use windivert_sys::ChecksumFlags;
use windivert_sys::{
    WinDivertClose, WinDivertHelperCalcChecksums, WinDivertRecv, WinDivertSend, WinDivertShutdown,
    WinDivertShutdownMode, address::WINDIVERT_ADDRESS,
};
use windows::Win32::Foundation::HANDLE;

use crate::traffic::shared::dns::FakeDnsServer;
use crate::traffic::shared::nat::{TransparentNatTableV4, TransparentNatTableV6};
use crate::traffic::windivert::config::TransparentCaptureKind;

use super::packet::{handle_dns_query_packet, process_packet};

pub(super) fn run_raw_capture_loop(
    handle: HANDLE,
    capture_kind: TransparentCaptureKind,
    fake_dns_server: Option<FakeDnsServer>,
    fake_ipv4_range: Ipv4Net,
    fake_ipv6_range: Ipv6Net,
    nat_table_v4: TransparentNatTableV4,
    nat_table_v6: TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
    local_dns_port: u16,
    shutting_down: Arc<AtomicBool>,
) {
    let mut rx_buf = vec![0u8; 65535];
    loop {
        let mut recv_len = 0u32;
        let mut address = WINDIVERT_ADDRESS::default();
        let recv_ok = unsafe {
            WinDivertRecv(
                handle,
                rx_buf.as_mut_ptr().cast(),
                rx_buf.len() as u32,
                &mut recv_len,
                &mut address,
            )
        };

        if !recv_ok.as_bool() {
            let error = std::io::Error::last_os_error();
            if shutting_down.load(Ordering::Relaxed) {
                tracing::info!("WinDivert capture loop stopped");
            } else {
                tracing::error!(?error, "WinDivert recv failed");
            }
            break;
        }

        let mut packet = Cow::Borrowed(&rx_buf[..recv_len as usize]);
        let disposition = if matches!(capture_kind, TransparentCaptureKind::DnsResponder) {
            handle_dns_query_packet(&mut packet, &mut address, fake_dns_server.as_ref())
        } else {
            process_packet(
                packet.to_mut(),
                &mut address,
                &capture_kind,
                fake_dns_server.as_ref(),
                fake_ipv4_range,
                fake_ipv6_range,
                &nat_table_v4,
                &nat_table_v6,
                proxy_port,
                tls_port,
                local_dns_port,
            )
        };

        if disposition.should_recalculate_checksums() {
            let checksum_ok = unsafe {
                WinDivertHelperCalcChecksums(
                    packet.to_mut().as_mut_ptr().cast(),
                    packet.len() as u32,
                    &mut address,
                    ChecksumFlags::new(),
                )
            };
            if !checksum_ok.as_bool() {
                let error = std::io::Error::last_os_error();
                tracing::warn!(?error, "WinDivert checksum recalculation failed");
            }
        }

        if disposition.should_reinject() {
            let mut send_len = 0u32;
            let send_ok = unsafe {
                WinDivertSend(
                    handle,
                    packet.as_ptr().cast(),
                    packet.len() as u32,
                    &mut send_len,
                    &address,
                )
            };
            if !send_ok.as_bool() {
                let error = std::io::Error::last_os_error();
                tracing::error!(?error, "WinDivert send failed");
            }
        }
    }
}

pub(super) fn shutdown_raw_handle(handle: HANDLE, shutting_down: &AtomicBool) {
    shutting_down.store(true, Ordering::Relaxed);
    let shutdown_ok = unsafe { WinDivertShutdown(handle, WinDivertShutdownMode::Both) };
    if !shutdown_ok.as_bool() {
        let error = std::io::Error::last_os_error();
        tracing::warn!(?error, "WinDivert shutdown failed");
    }
    let close_ok = unsafe { WinDivertClose(handle) };
    if !close_ok.as_bool() {
        let error = std::io::Error::last_os_error();
        tracing::warn!(?error, "WinDivert close failed");
    }
}
