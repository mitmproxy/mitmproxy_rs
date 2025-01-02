use std::fmt;
use std::fmt::Formatter;
use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, Result};
use internet_packet::{InternetPacket, TransportProtocol};
use smoltcp::wire::{IpProtocol, Ipv4Packet, Ipv6Packet};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone)]
pub enum TunnelInfo {
    WireGuard {
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
    },
    LocalRedirector {
        pid: Option<u32>,
        process_name: Option<String>,
        /// macOS TCP connections may not have a valid sockname, but
        /// an unresolved remote_endpoint instead.
        remote_endpoint: Option<(String, u16)>,
    },
    None,
}

/// Events that are sent by WireGuard to the TCP stack.
#[derive(Debug)]
pub enum NetworkEvent {
    ReceivePacket {
        packet: SmolPacket,
        tunnel_info: TunnelInfo,
    },
}

/// Commands that are sent by the TCP stack to WireGuard.
#[derive(Debug)]
pub enum NetworkCommand {
    SendPacket(SmolPacket),
}

pub struct ConnectionIdGenerator(usize);
impl ConnectionIdGenerator {
    pub const fn tcp() -> Self {
        Self(2)
    }
    pub const fn udp() -> Self {
        Self(3)
    }
    pub fn next_id(&mut self) -> ConnectionId {
        let ret = ConnectionId(self.0);
        self.0 += 2;
        ret
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct ConnectionId(usize);
impl ConnectionId {
    pub fn is_tcp(&self) -> bool {
        self.0 & 1 == 0
    }
    pub const fn unassigned_udp() -> Self {
        ConnectionId(1)
    }
}
impl fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl fmt::Debug for ConnectionId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_tcp() {
            write!(f, "{}#TCP", self.0)
        } else {
            write!(f, "{}#UDP", self.0)
        }
    }
}

/// Events that are sent by the TCP stack to Python.
#[derive(Debug)]
pub enum TransportEvent {
    ConnectionEstablished {
        connection_id: ConnectionId,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        tunnel_info: TunnelInfo,
        // Channel over which the stream should emit commands.
        // If command_tx is None, the main channel is used.
        command_tx: Option<mpsc::UnboundedSender<TransportCommand>>,
    },
}

/// Commands that are sent by the Python side to the TCP stack.
#[derive(Debug)]
pub enum TransportCommand {
    ReadData(ConnectionId, u32, oneshot::Sender<Vec<u8>>),
    WriteData(ConnectionId, Vec<u8>),
    DrainWriter(ConnectionId, oneshot::Sender<()>),
    CloseConnection(ConnectionId, bool),
}

impl TransportCommand {
    pub fn connection_id(&self) -> &ConnectionId {
        match self {
            TransportCommand::ReadData(id, _, _) => id,
            TransportCommand::WriteData(id, _) => id,
            TransportCommand::DrainWriter(id, _) => id,
            TransportCommand::CloseConnection(id, _) => id,
        }
    }
}

/// Generic IPv4/IPv6 packet type that wraps smoltcp's IPv4 and IPv6 packet buffers
#[derive(Clone)]
pub enum SmolPacket {
    V4(Ipv4Packet<Vec<u8>>),
    V6(Ipv6Packet<Vec<u8>>),
}

impl fmt::Debug for SmolPacket {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct("SmolPacket");
        match TryInto::<InternetPacket>::try_into(self.clone()) {
            Ok(p) => {
                f.field("src", &p.src());
                f.field("dst", &p.dst());
                f.field("protocol", &p.protocol());
                if matches!(p.protocol(), TransportProtocol::Tcp) {
                    f.field("tcp_flags_str", &p.tcp_flag_str());
                }
                f.field("payload", &String::from_utf8_lossy(p.payload()));
                f.finish()
            }
            Err(_) => f
                .field("src_ip", &self.src_ip())
                .field("dst_ip", &self.dst_ip())
                .field("transport_protocol", &self.transport_protocol())
                .finish(),
        }
    }
}

impl From<Ipv4Packet<Vec<u8>>> for SmolPacket {
    fn from(packet: Ipv4Packet<Vec<u8>>) -> Self {
        SmolPacket::V4(packet)
    }
}

impl From<Ipv6Packet<Vec<u8>>> for SmolPacket {
    fn from(packet: Ipv6Packet<Vec<u8>>) -> Self {
        SmolPacket::V6(packet)
    }
}

impl TryInto<InternetPacket> for SmolPacket {
    type Error = internet_packet::ParseError;

    fn try_into(self) -> std::result::Result<InternetPacket, Self::Error> {
        match self {
            SmolPacket::V4(packet) => InternetPacket::try_from(packet),
            SmolPacket::V6(packet) => InternetPacket::try_from(packet),
        }
    }
}

impl TryFrom<Vec<u8>> for SmolPacket {
    type Error = anyhow::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        if value.is_empty() {
            return Err(anyhow!("Empty packet."));
        }

        match value[0] >> 4 {
            4 => Ok(SmolPacket::V4(Ipv4Packet::new_checked(value)?)),
            6 => Ok(SmolPacket::V6(Ipv6Packet::new_checked(value)?)),
            _ => Err(anyhow!("Not an IP packet: {:?}", value)),
        }
    }
}

impl SmolPacket {
    pub fn src_ip(&self) -> IpAddr {
        match self {
            SmolPacket::V4(packet) => IpAddr::V4(packet.src_addr()),
            SmolPacket::V6(packet) => IpAddr::V6(packet.src_addr()),
        }
    }

    pub fn dst_ip(&self) -> IpAddr {
        match self {
            SmolPacket::V4(packet) => IpAddr::V4(packet.dst_addr()),
            SmolPacket::V6(packet) => IpAddr::V6(packet.dst_addr()),
        }
    }

    pub fn transport_protocol(&self) -> IpProtocol {
        match self {
            SmolPacket::V4(packet) => packet.next_header(),
            SmolPacket::V6(packet) => match packet.next_header() {
                IpProtocol::Tcp => IpProtocol::Tcp,
                IpProtocol::Udp => IpProtocol::Udp,
                IpProtocol::Icmp => IpProtocol::Icmp,
                IpProtocol::Icmpv6 => IpProtocol::Icmpv6,
                other => {
                    log::debug!("TODO: Implement IPv6 next_header logic: {}", other);
                    other
                }
            },
        }
    }

    pub fn payload_mut(&mut self) -> &mut [u8] {
        match self {
            SmolPacket::V4(packet) => packet.payload_mut(),
            SmolPacket::V6(packet) => packet.payload_mut(),
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        match self {
            SmolPacket::V4(packet) => packet.into_inner(),
            SmolPacket::V6(packet) => packet.into_inner(),
        }
    }

    pub fn fill_ip_checksum(&mut self) {
        match self {
            SmolPacket::V4(packet) => packet.fill_checksum(),
            SmolPacket::V6(_) => (),
        }
    }
}
