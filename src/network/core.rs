use std::cmp::min;
use std::fmt;

use std::time::Duration;

use anyhow::Result;

use smoltcp::wire::IpProtocol;
use tokio::sync::mpsc::{Permit, Sender};

use crate::messages::{IpPacket, NetworkCommand, NetworkEvent, TransportCommand, TransportEvent};
use crate::network::icmp::{handle_icmpv4_echo_request, handle_icmpv6_echo_request};

use crate::network::tcp::TcpHandler;
use crate::network::udp::UdpHandler;

pub struct NetworkStack<'a> {
    tcp: TcpHandler<'a>,
    udp: UdpHandler,
    net_tx: Sender<NetworkCommand>,
}

impl<'a> NetworkStack<'a> {
    pub fn new(net_tx: Sender<NetworkCommand>) -> Self {
        Self {
            tcp: TcpHandler::new(net_tx.clone()),
            udp: UdpHandler::new(net_tx.clone()),
            net_tx,
        }
    }

    pub fn handle_network_event(
        &mut self,
        event: NetworkEvent,
        permit: Permit<'_, TransportEvent>,
    ) -> Result<()> {
        let (packet, tunnel_info) = match event {
            NetworkEvent::ReceivePacket {
                packet,
                tunnel_info,
            } => (packet, tunnel_info),
        };

        if let IpPacket::V4(p) = &packet {
            if !p.verify_checksum() {
                log::warn!("Received invalid IP packet (checksum error).");
                return Ok(());
            }
        }

        match packet.transport_protocol() {
            IpProtocol::Tcp => self.tcp.receive_packet(packet, tunnel_info, permit),
            IpProtocol::Udp => self.udp.receive_packet(packet, tunnel_info, permit),
            IpProtocol::Icmp => self.receive_packet_icmp(packet),
            _ => {
                log::debug!(
                    "Received IP packet for unknown protocol: {}",
                    packet.transport_protocol()
                );
                Ok(())
            }
        }
    }

    fn receive_packet_icmp(&mut self, packet: IpPacket) -> Result<()> {
        // Some apps check network connectivity by sending ICMP pings. ICMP traffic is currently
        // swallowed by mitmproxy_rs, which makes them believe that there is no network connectivity.
        // Generating fake ICMP replies as a simple workaround.

        if let Ok(permit) = self.net_tx.try_reserve() {
            // Generating and sending fake replies for ICMP echo requests. Ignoring all other ICMP types.
            let response_packet = match packet {
                IpPacket::V4(packet) => handle_icmpv4_echo_request(packet),
                IpPacket::V6(packet) => handle_icmpv6_echo_request(packet),
            };
            if let Some(response_packet) = response_packet {
                permit.send(NetworkCommand::SendPacket(response_packet));
            }
        } else {
            log::debug!("Channel full, discarding ICMP packet.");
        }
        Ok(())
    }

    pub fn handle_transport_command(&mut self, command: TransportCommand) {
        match command {
            TransportCommand::ReadData(id, n, tx) => match id & 1 == 1 {
                true => self.udp.read_data(id, tx),
                false => self.tcp.read_data(id, n, tx),
            },
            TransportCommand::WriteData(id, buf) => match id & 1 == 1 {
                true => self.udp.write_data(id, buf),
                false => self.tcp.write_data(id, buf),
            },
            TransportCommand::DrainWriter(id, tx) => match id & 1 == 1 {
                true => self.udp.drain_writer(id, tx),
                false => self.tcp.drain_writer(id, tx),
            },
            TransportCommand::CloseConnection(id, half_close) => match id & 1 == 1 {
                true => self.udp.close_connection(id),
                false => self.tcp.close_connection(id, half_close),
            },
            TransportCommand::SendDatagram {
                data: _,
                src_addr: _,
                dst_addr: _,
            } => {
                // TODO remove
                log::error!("Error: SendDatagram is deprecated.");
            }
        };
    }

    pub fn poll_delay(&mut self) -> Option<Duration> {
        match (self.tcp.poll_delay(), self.udp.poll_delay()) {
            (Some(a), Some(b)) => Some(min(a, b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }
    }

    pub fn poll(&mut self) -> Result<()> {
        self.udp.poll();
        self.tcp.poll()
    }
}

impl fmt::Debug for NetworkStack<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkIO").field("tcp", &self.tcp).finish()
    }
}
