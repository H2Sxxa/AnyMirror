pub mod v4;
pub mod v6;

use std::net::IpAddr;

pub trait IpPacketFamily {
    type Addr: Copy + std::fmt::Display;
    type Range: Copy;

    const LABEL: &'static str;

    fn read_src_ip(data: &[u8]) -> Option<Self::Addr>;
    fn read_dst_ip(data: &[u8]) -> Option<Self::Addr>;
    fn to_ip_addr(addr: Self::Addr) -> IpAddr;
    fn set_request_destination_ip(data: &mut [u8], src_ip: Self::Addr);
    fn set_response_source_ip(data: &mut [u8], orig_dst_ip: Self::Addr);
    fn udp_header_len(data: &[u8]) -> Option<usize>;
    fn build_udp_response_packet(
        request_src_ip: Self::Addr,
        request_dst_ip: Self::Addr,
        request_src_port: u16,
        request_dst_port: u16,
        payload: &[u8],
    ) -> Option<Vec<u8>>;
    fn contains(range: Self::Range, addr: &Self::Addr) -> bool;
}
