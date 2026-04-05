use windivert::{
    address::WinDivertAddress,
    layer::{ForwardLayer, NetworkLayer},
};
use windivert_sys::address::WINDIVERT_ADDRESS;

use crate::traffic::shared::intercept::PacketMetadata;

pub(super) use crate::traffic::shared::intercept::{handle_dns_query_packet, process_packet};

impl PacketMetadata for WinDivertAddress<NetworkLayer> {
    fn set_outbound_flag(&mut self, outbound: bool) {
        self.set_outbound(outbound);
    }
}

impl PacketMetadata for WinDivertAddress<ForwardLayer> {
    fn set_outbound_flag(&mut self, outbound: bool) {
        self.set_outbound(outbound);
    }
}

impl PacketMetadata for WINDIVERT_ADDRESS {
    fn set_outbound_flag(&mut self, outbound: bool) {
        self.set_outbound(outbound);
    }
}
