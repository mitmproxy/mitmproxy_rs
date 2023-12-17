use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use lru_time_cache::LruCache;
use tokio::sync::mpsc::Permit;
use tokio::sync::oneshot;

use crate::messages::{
    ConnectionId, ConnectionIdGenerator, SmolPacket, TransportCommand, TransportEvent, TunnelInfo,
};
use internet_packet::InternetPacket;
use smoltcp::phy::ChecksumCapabilities;

use smoltcp::wire::{
    IpProtocol, IpRepr, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr,
    UdpRepr,
};

struct ConnectionState {
    remote_addr: SocketAddr,
    local_addr: SocketAddr,
    closed: bool,
    packets: VecDeque<Vec<u8>>,
    read_tx: Option<oneshot::Sender<Vec<u8>>>,
}

impl ConnectionState {
    fn new(remote_addr: SocketAddr, local_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            local_addr,
            closed: false,
            packets: VecDeque::new(),
            read_tx: None,
        }
    }
    fn add_packet(&mut self, data: Vec<u8>) {
        if self.closed {
            drop(data);
        } else if let Some(tx) = self.read_tx.take() {
            tx.send(data).ok();
        } else {
            self.packets.push_back(data);
        }
    }
    fn add_reader(&mut self, tx: oneshot::Sender<Vec<u8>>) {
        assert!(self.read_tx.is_none());
        if self.closed {
            drop(tx);
        } else if let Some(data) = self.packets.pop_front() {
            tx.send(data).ok();
        } else {
            self.read_tx = Some(tx);
        }
    }
    fn close(&mut self) {
        if self.closed {
            // already closed.
        } else if let Some(tx) = self.read_tx.take() {
            drop(tx);
        } else {
            self.packets.clear();
        }
        self.closed = true;
    }
}

pub const UDP_TIMEOUT: Duration = Duration::from_secs(60);

pub struct UdpHandler {
    connection_id_generator: ConnectionIdGenerator,
    id_lookup: LruCache<(SocketAddr, SocketAddr), ConnectionId>,
    connections: LruCache<ConnectionId, ConnectionState>,
}

impl UdpHandler {
    pub fn new() -> Self {
        // This implementation is largely based on the fact that LruCache eventually
        // drops the state, which closes the respective channels.
        let connections =
            LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(UDP_TIMEOUT);
        let id_lookup =
            LruCache::<(SocketAddr, SocketAddr), ConnectionId>::with_expiry_duration(UDP_TIMEOUT);
        Self {
            connections,
            id_lookup,
            connection_id_generator: ConnectionIdGenerator::udp(),
        }
    }

    pub(crate) fn handle_transport_command(
        &mut self,
        command: TransportCommand,
    ) -> Option<UdpPacket> {
        match command {
            TransportCommand::ReadData(id, _, tx) => {
                self.read_data(id, tx);
                None
            }
            TransportCommand::WriteData(id, data) => self.write_data(id, data),
            TransportCommand::DrainWriter(id, tx) => {
                self.drain_writer(id, tx);
                None
            }
            TransportCommand::CloseConnection(id, _) => {
                self.close_connection(id);
                None
            }
        }
    }

    pub fn read_data(&mut self, id: ConnectionId, tx: oneshot::Sender<Vec<u8>>) {
        if let Some(state) = self.connections.get_mut(&id) {
            state.add_reader(tx);
        }
    }

    pub(crate) fn write_data(&mut self, id: ConnectionId, data: Vec<u8>) -> Option<UdpPacket> {
        let Some(state) = self.connections.get(&id) else {
            return None;
        };
        // Refresh id lookup.
        self.id_lookup
            .insert((state.local_addr, state.remote_addr), id);

        if state.closed {
            return None;
        }

        Some(UdpPacket {
            src_addr: state.local_addr,
            dst_addr: state.remote_addr,
            payload: data,
        })
    }

    pub fn drain_writer(&mut self, _id: ConnectionId, tx: oneshot::Sender<()>) {
        tx.send(()).ok();
    }

    pub fn close_connection(&mut self, id: ConnectionId) {
        if let Some(state) = self.connections.get_mut(&id) {
            state.close();
        }
    }

    pub(crate) fn receive_data(
        &mut self,
        packet: UdpPacket,
        tunnel_info: TunnelInfo,
        permit: Permit<'_, TransportEvent>,
    ) {
        let potential_cid = self
            .id_lookup
            .get(&(packet.src_addr, packet.dst_addr))
            .cloned()
            .unwrap_or(ConnectionId::unassigned());

        match self.connections.get_mut(&potential_cid) {
            Some(state) => {
                state.add_packet(packet.payload);
            }
            None => {
                let mut state = ConnectionState::new(packet.src_addr, packet.dst_addr);
                state.add_packet(packet.payload);
                let connection_id = self.connection_id_generator.next_id();
                self.id_lookup
                    .insert((packet.src_addr, packet.dst_addr), connection_id);
                self.connections.insert(connection_id, state);
                permit.send(TransportEvent::ConnectionEstablished {
                    connection_id,
                    src_addr: packet.src_addr,
                    dst_addr: packet.dst_addr,
                    tunnel_info,
                    command_tx: None,
                });
            }
        };
    }

    pub fn poll_delay(&mut self) -> Option<Duration> {
        if self.connections.is_empty() {
            None
        } else {
            Some(Duration::from_secs(5))
        }
    }

    pub fn poll(&mut self) {
        // Creating an iterator removes expired entries.
        self.connections.iter();
        self.id_lookup.iter();
    }
}

pub(crate) struct UdpPacket {
    pub src_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub payload: Vec<u8>,
}
impl TryFrom<SmolPacket> for UdpPacket {
    type Error = internet_packet::ParseError;

    fn try_from(value: SmolPacket) -> Result<Self, Self::Error> {
        let packet: InternetPacket = value.try_into()?;
        Ok(UdpPacket {
            src_addr: packet.src(),
            dst_addr: packet.dst(),
            payload: packet.payload().to_vec(),
        })
    }
}

impl From<UdpPacket> for SmolPacket {
    fn from(value: UdpPacket) -> Self {
        let UdpPacket {
            src_addr,
            dst_addr,
            payload,
        } = value;

        let udp_repr = UdpRepr {
            src_port: src_addr.port(),
            dst_port: dst_addr.port(),
        };

        let ip_repr: IpRepr = match (src_addr, dst_addr) {
            (SocketAddr::V4(src_addr), SocketAddr::V4(dst_addr)) => IpRepr::Ipv4(Ipv4Repr {
                src_addr: Ipv4Address::from(*src_addr.ip()),
                dst_addr: Ipv4Address::from(*dst_addr.ip()),
                next_header: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + payload.len(),
                hop_limit: 255,
            }),
            (SocketAddr::V6(src_addr), SocketAddr::V6(dst_addr)) => IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::from(*src_addr.ip()),
                dst_addr: Ipv6Address::from(*dst_addr.ip()),
                next_header: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + payload.len(),
                hop_limit: 255,
            }),
            _ => unreachable!("Mismatched IP address versions"),
        };

        let buf = vec![0u8; ip_repr.buffer_len()];

        let mut smol_packet = match ip_repr {
            IpRepr::Ipv4(repr) => {
                let mut packet = Ipv4Packet::new_unchecked(buf);
                repr.emit(&mut packet, &ChecksumCapabilities::default());
                SmolPacket::from(packet)
            }
            IpRepr::Ipv6(repr) => {
                let mut packet = Ipv6Packet::new_unchecked(buf);
                repr.emit(&mut packet);
                SmolPacket::from(packet)
            }
        };

        udp_repr.emit(
            &mut smoltcp::wire::UdpPacket::new_unchecked(smol_packet.payload_mut()),
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            payload.len(),
            |buf| buf.copy_from_slice(payload.as_slice()),
            &ChecksumCapabilities::default(),
        );
        smol_packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const SRC: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 54321);
    const DST: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);

    #[test]
    fn test_connection_state_recv_recv_read_read() {
        let mut state = ConnectionState::new(SRC, DST);
        state.add_packet(vec![1, 2, 3]);
        state.add_packet(vec![4, 5, 6]);
        let (tx, rx) = oneshot::channel();
        state.add_reader(tx);
        assert_eq!(vec![1, 2, 3], rx.blocking_recv().unwrap());
        let (tx, rx) = oneshot::channel();
        state.add_reader(tx);
        assert_eq!(vec![4, 5, 6], rx.blocking_recv().unwrap());
    }

    #[test]
    fn test_connection_state_read_recv_recv() {
        let mut state = ConnectionState::new(SRC, DST);
        let (tx, rx) = oneshot::channel();
        state.add_reader(tx);
        state.add_packet(vec![1, 2, 3]);
        state.add_packet(vec![4, 5, 6]);
        assert_eq!(vec![1, 2, 3], rx.blocking_recv().unwrap());
    }

    #[test]
    fn test_connection_state_close_recv_read() {
        let mut state = ConnectionState::new(SRC, DST);
        let (tx, rx) = oneshot::channel();
        state.close();
        state.add_packet(vec![1, 2, 3]);
        state.add_reader(tx);
        assert!(rx.blocking_recv().is_err());
    }

    #[test]
    fn test_connection_state_read_close_recv() {
        let mut state = ConnectionState::new(SRC, DST);
        let (tx, rx) = oneshot::channel();
        state.add_reader(tx);
        state.close();
        state.add_packet(vec![1, 2, 3]);
        assert!(rx.blocking_recv().is_err());
    }
}
