use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{anyhow, Result};
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet};
use tokio::sync::oneshot;

#[derive(Debug, Clone)]
pub enum TunnelInfo {
    WireGuard {
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    },
    Windows {
        pid: u32,
        process_name: Option<String>,
    },
}

/// Events that are sent by WireGuard to the TCP stack.
#[derive(Debug)]
pub enum NetworkEvent {
    ReceivePacket {
        packet: IpPacket,
        tunnel_info: TunnelInfo,
    },
}

/// Commands that are sent by the TCP stack to WireGuard.
#[derive(Debug)]
pub enum NetworkCommand {
    SendPacket(IpPacket),
}

pub type ConnectionId = u32;

/// Events that are sent by the TCP stack to Python.
#[derive(Debug)]
pub enum TransportEvent {
    ConnectionEstablished {
        connection_id: ConnectionId,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tunnel_info: TunnelInfo,
    },
    DatagramReceived {
        data: Vec<u8>,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tunnel_info: TunnelInfo,
    },
}

/// Commands that are sent by the Python side to the TCP stack.
#[derive(Debug)]
pub enum TransportCommand {
    ReadData(ConnectionId, u32, oneshot::Sender<Vec<u8>>),
    WriteData(ConnectionId, Vec<u8>),
    DrainWriter(ConnectionId, oneshot::Sender<()>),
    CloseConnection(ConnectionId, bool),
    SendDatagram {
        data: Vec<u8>,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    },
}

/// Generic IPv4/IPv6 packet type that wraps both IPv4 and IPv6 packet buffers
#[derive(Debug)]
pub enum IpPacket {
    V4(Ipv4Packet<Vec<u8>>),
    V6(Ipv6Packet<Vec<u8>>),
}

impl From<Ipv4Packet<Vec<u8>>> for IpPacket {
    fn from(packet: Ipv4Packet<Vec<u8>>) -> Self {
        IpPacket::V4(packet)
    }
}

impl From<Ipv6Packet<Vec<u8>>> for IpPacket {
    fn from(packet: Ipv6Packet<Vec<u8>>) -> Self {
        IpPacket::V6(packet)
    }
}

impl TryFrom<Vec<u8>> for IpPacket {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        if value.is_empty() {
            return Err(anyhow!("Empty packet."));
        }

        match value[0] >> 4 {
            4 => Ok(IpPacket::V4(Ipv4Packet::new_checked(value)?)),
            6 => Ok(IpPacket::V6(Ipv6Packet::new_checked(value)?)),
            _ => Err(anyhow!("Not an IP packet: {:?}", value)),
        }
    }
}

impl IpPacket {
    pub fn src_ip(&self) -> IpAddr {
        match self {
            IpPacket::V4(packet) => IpAddr::V4(Ipv4Addr::from(packet.src_addr())),
            IpPacket::V6(packet) => IpAddr::V6(Ipv6Addr::from(packet.src_addr())),
        }
    }

    pub fn dst_ip(&self) -> IpAddr {
        match self {
            IpPacket::V4(packet) => IpAddr::V4(Ipv4Addr::from(packet.dst_addr())),
            IpPacket::V6(packet) => IpAddr::V6(Ipv6Addr::from(packet.dst_addr())),
        }
    }

    pub fn transport_protocol(&self) -> IpProtocol {
        match self {
            IpPacket::V4(packet) => packet.protocol(),
            IpPacket::V6(packet) => {
                log::debug!("TODO: Implement IPv6 next_header logic.");
                packet.next_header()
            }
        }
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        match self {
            IpPacket::V4(packet) => packet.payload_mut(),
            IpPacket::V6(packet) => packet.payload_mut(),
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        match self {
            IpPacket::V4(packet) => packet.into_inner(),
            IpPacket::V6(packet) => packet.into_inner(),
        }
    }

    pub fn fill_ip_checksum(&mut self) {
        match self {
            IpPacket::V4(packet) => packet.fill_checksum(),
            IpPacket::V6(_) => (),
        }
    }
}
