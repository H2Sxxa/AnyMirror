use ipnet::{Ipv4Net, Ipv6Net};
use windivert::{
    address::WinDivertAddress,
    error::WinDivertError,
    layer::{ForwardLayer, NetworkLayer, WinDivertLayerTrait},
    packet::WinDivertPacket,
    WinDivert,
};
use windivert_sys::ChecksumFlags;

use crate::traffic::shared::dns::FakeDnsServer;
use crate::traffic::shared::nat::{TransparentNatTableV4, TransparentNatTableV6};
use crate::traffic::windivert::config::TransparentCaptureKind;

use super::packet::{handle_dns_query_packet, process_packet, SetOutboundFlag};

pub(super) trait CaptureLoopHandle {
    type Layer: WinDivertLayerTrait;

    fn recv_packet<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> std::result::Result<WinDivertPacket<'a, Self::Layer>, WinDivertError>;

    fn send_packet(
        &self,
        packet: &WinDivertPacket<'_, Self::Layer>,
    ) -> std::result::Result<u32, WinDivertError>;

    fn recalculate_checksums(
        &self,
        packet: &mut WinDivertPacket<'_, Self::Layer>,
    ) -> std::result::Result<(), WinDivertError>;
}

impl CaptureLoopHandle for WinDivert<NetworkLayer> {
    type Layer = NetworkLayer;

    fn recv_packet<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> std::result::Result<WinDivertPacket<'a, Self::Layer>, WinDivertError> {
        self.recv(buffer)
    }

    fn send_packet(
        &self,
        packet: &WinDivertPacket<'_, Self::Layer>,
    ) -> std::result::Result<u32, WinDivertError> {
        self.send(packet)
    }

    fn recalculate_checksums(
        &self,
        packet: &mut WinDivertPacket<'_, Self::Layer>,
    ) -> std::result::Result<(), WinDivertError> {
        packet.recalculate_checksums(ChecksumFlags::new())
    }
}

impl CaptureLoopHandle for WinDivert<ForwardLayer> {
    type Layer = ForwardLayer;

    fn recv_packet<'a>(
        &self,
        buffer: Option<&'a mut [u8]>,
    ) -> std::result::Result<WinDivertPacket<'a, Self::Layer>, WinDivertError> {
        self.recv(buffer)
    }

    fn send_packet(
        &self,
        packet: &WinDivertPacket<'_, Self::Layer>,
    ) -> std::result::Result<u32, WinDivertError> {
        self.send(packet)
    }

    fn recalculate_checksums(
        &self,
        packet: &mut WinDivertPacket<'_, Self::Layer>,
    ) -> std::result::Result<(), WinDivertError> {
        packet.recalculate_checksums(ChecksumFlags::new())
    }
}

pub(super) fn run_capture_loop<H>(
    wd: H,
    capture_kind: TransparentCaptureKind,
    fake_dns_server: Option<FakeDnsServer>,
    fake_ipv4_range: Ipv4Net,
    fake_ipv6_range: Ipv6Net,
    nat_table_v4: TransparentNatTableV4,
    nat_table_v6: TransparentNatTableV6,
    proxy_port: u16,
    tls_port: u16,
    local_dns_port: u16,
) where
    H: CaptureLoopHandle,
    WinDivertAddress<H::Layer>: SetOutboundFlag,
{
    let mut rx_buf = vec![0u8; 65535];
    loop {
        match wd.recv_packet(Some(&mut rx_buf)) {
            Ok(mut packet) => {
                let disposition = if matches!(capture_kind, TransparentCaptureKind::DnsResponder) {
                    handle_dns_query_packet(
                        &mut packet.data,
                        &mut packet.address,
                        fake_dns_server.as_ref(),
                    )
                } else {
                    process_packet(
                        packet.data.to_mut(),
                        &mut packet.address,
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
                    let _ = wd.recalculate_checksums(&mut packet);
                }
                if disposition.should_reinject() {
                    if let Err(error) = wd.send_packet(&packet) {
                        tracing::error!(?error, "WinDivert send failed");
                    }
                }
            }
            Err(error) => {
                tracing::error!(?error, "WinDivert recv failed");
                break;
            }
        }
    }
}
