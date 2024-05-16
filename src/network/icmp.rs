use crate::messages::SmolPacket;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    Icmpv4Message, Icmpv4Packet, Icmpv4Repr, Icmpv6Message, Icmpv6Packet, Icmpv6Repr, IpProtocol,
    Ipv4Packet, Ipv4Repr, Ipv6Packet, Ipv6Repr,
};

pub(super) fn handle_icmpv4_echo_request(
    mut input_packet: Ipv4Packet<Vec<u8>>,
) -> Option<SmolPacket> {
    let src_addr = input_packet.src_addr();
    let dst_addr = input_packet.dst_addr();

    // Parsing ICMP Packet
    let mut input_icmpv4_packet = match Icmpv4Packet::new_checked(input_packet.payload_mut()) {
        Ok(p) => p,
        Err(e) => {
            log::debug!("Received invalid ICMPv4 packet: {}", e);
            return None;
        }
    };

    // Checking that it is an ICMP Echo Request.
    if input_icmpv4_packet.msg_type() != Icmpv4Message::EchoRequest {
        log::debug!(
            "Unsupported ICMPv4 packet of type: {}",
            input_icmpv4_packet.msg_type()
        );
        return None;
    }

    // Creating fake response packet.
    let icmp_repr = Icmpv4Repr::EchoReply {
        ident: input_icmpv4_packet.echo_ident(),
        seq_no: input_icmpv4_packet.echo_seq_no(),
        data: input_icmpv4_packet.data_mut(),
    };
    let ip_repr = Ipv4Repr {
        // Directing fake reply back to the original source address.
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmp,
        payload_len: icmp_repr.buffer_len(),
        hop_limit: 255,
    };
    let buf = vec![0u8; ip_repr.buffer_len() + icmp_repr.buffer_len()];
    let mut output_ipv4_packet = Ipv4Packet::new_unchecked(buf);
    ip_repr.emit(&mut output_ipv4_packet, &ChecksumCapabilities::default());
    let mut output_ip_packet = SmolPacket::from(output_ipv4_packet);
    icmp_repr.emit(
        &mut Icmpv4Packet::new_unchecked(output_ip_packet.payload_mut()),
        &ChecksumCapabilities::default(),
    );
    Some(output_ip_packet)
}

pub(super) fn handle_icmpv6_echo_request(
    mut input_packet: Ipv6Packet<Vec<u8>>,
) -> Option<SmolPacket> {
    let src_addr = input_packet.src_addr();
    let dst_addr = input_packet.dst_addr();

    // Parsing ICMP Packet
    let mut input_icmpv6_packet = match Icmpv6Packet::new_checked(input_packet.payload_mut()) {
        Ok(p) => p,
        Err(e) => {
            log::debug!("Received invalid ICMPv6 packet: {}", e);
            return None;
        }
    };

    // Checking that it is an ICMP Echo Request.
    if input_icmpv6_packet.msg_type() != Icmpv6Message::EchoRequest {
        log::debug!(
            "Unsupported ICMPv6 packet of type: {}",
            input_icmpv6_packet.msg_type()
        );
        return None;
    }

    // Creating fake response packet.
    let icmp_repr = Icmpv6Repr::EchoReply {
        ident: input_icmpv6_packet.echo_ident(),
        seq_no: input_icmpv6_packet.echo_seq_no(),
        data: input_icmpv6_packet.payload_mut(),
    };
    let ip_repr = Ipv6Repr {
        // Directing fake reply back to the original source address.
        src_addr: dst_addr,
        dst_addr: src_addr,
        next_header: IpProtocol::Icmp,
        payload_len: icmp_repr.buffer_len(),
        hop_limit: 255,
    };
    let buf = vec![0u8; ip_repr.buffer_len() + icmp_repr.buffer_len()];
    let mut output_ipv6_packet = Ipv6Packet::new_unchecked(buf);
    ip_repr.emit(&mut output_ipv6_packet);
    let mut output_ip_packet = SmolPacket::from(output_ipv6_packet);
    icmp_repr.emit(
        // Directing fake reply back to the original source address.
        &dst_addr,
        &src_addr,
        &mut Icmpv6Packet::new_unchecked(output_ip_packet.payload_mut()),
        &ChecksumCapabilities::default(),
    );
    Some(output_ip_packet)
}
