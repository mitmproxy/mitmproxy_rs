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

#[derive(Default)]
pub struct ConnectionState {
    closed: bool,
    packets: VecDeque<Vec<u8>>,
    read_tx: Option<oneshot::Sender<Vec<u8>>>,
}

impl ConnectionState {
    pub fn add_packet(&mut self, data: Vec<u8>) {
        if self.closed {
            drop(data);
        } else if let Some(tx) = self.read_tx.take() {
            tx.send(data).ok();
        } else {
            self.packets.push_back(data);
        }
    }
    #[allow(dead_code)]
    pub fn packet_queue_len(&self) -> usize {
        self.packets.len()
    }
    pub fn add_reader(&mut self, tx: oneshot::Sender<Vec<u8>>) {
        assert!(self.read_tx.is_none());
        if self.closed {
            drop(tx);
        } else if let Some(data) = self.packets.pop_front() {
            tx.send(data).ok();
        } else {
            self.read_tx = Some(tx);
        }
    }
    pub fn close(&mut self) {
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

type FourTuple = (SocketAddr, SocketAddr);

pub struct UdpHandler {
    connection_id_generator: ConnectionIdGenerator,
    id_lookup: LruCache<FourTuple, ConnectionId>,
    connections: LruCache<ConnectionId, (ConnectionState, FourTuple)>,
}

impl UdpHandler {
    pub fn new() -> Self {
        // This implementation is largely based on the fact that LruCache eventually
        // drops the state, which closes the respective channels.
        Self {
            connections: LruCache::with_expiry_duration(UDP_TIMEOUT),
            id_lookup: LruCache::with_expiry_duration(UDP_TIMEOUT),
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
        if let Some((state, _)) = self.connections.get_mut(&id) {
            state.add_reader(tx);
        }
    }

    pub(crate) fn write_data(&mut self, id: ConnectionId, data: Vec<u8>) -> Option<UdpPacket> {
        let (state, addrs) = self.connections.get(&id)?;
        // Refresh id lookup.
        self.id_lookup.insert(*addrs, id);

        if state.closed {
            return None;
        }

        Some(UdpPacket {
            src_addr: addrs.1,
            dst_addr: addrs.0,
            payload: data,
        })
    }

    pub fn drain_writer(&mut self, _id: ConnectionId, tx: oneshot::Sender<()>) {
        tx.send(()).ok();
    }

    pub fn close_connection(&mut self, id: ConnectionId) {
        if let Some((state, _)) = self.connections.get_mut(&id) {
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
            .unwrap_or(ConnectionId::unassigned_udp());

        match self.connections.get_mut(&potential_cid) {
            Some((state, _)) => {
                state.add_packet(packet.payload);
            }
            None => {
                let mut state = ConnectionState::default();
                state.add_packet(packet.payload);
                let connection_id = self.connection_id_generator.next_id();
                self.id_lookup
                    .insert((packet.src_addr, packet.dst_addr), connection_id);
                self.connections
                    .insert(connection_id, (state, (packet.src_addr, packet.dst_addr)));
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
    use crate::packet_sources::udp::UdpConf;
    use crate::packet_sources::{PacketSourceConf, PacketSourceTask};
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;

    #[test]
    fn test_connection_state_recv_recv_read_read() {
        let mut state = ConnectionState::default();
        state.add_packet(vec![1, 2, 3]);
        state.add_packet(vec![4, 5, 6]);
        assert_eq!(state.packet_queue_len(), 2);
        let (tx, rx) = oneshot::channel();
        state.add_reader(tx);
        assert_eq!(vec![1, 2, 3], rx.blocking_recv().unwrap());
        let (tx, rx) = oneshot::channel();
        state.add_reader(tx);
        assert_eq!(vec![4, 5, 6], rx.blocking_recv().unwrap());
    }

    #[test]
    fn test_connection_state_read_recv_recv() {
        let mut state = ConnectionState::default();
        let (tx, rx) = oneshot::channel();
        state.add_reader(tx);
        state.add_packet(vec![1, 2, 3]);
        state.add_packet(vec![4, 5, 6]);
        assert_eq!(vec![1, 2, 3], rx.blocking_recv().unwrap());
    }

    #[test]
    fn test_connection_state_close_recv_read() {
        let mut state = ConnectionState::default();
        let (tx, rx) = oneshot::channel();
        state.close();
        state.add_packet(vec![1, 2, 3]);
        state.add_reader(tx);
        assert!(rx.blocking_recv().is_err());
    }

    #[test]
    fn test_connection_state_read_close_recv() {
        let mut state = ConnectionState::default();
        let (tx, rx) = oneshot::channel();
        state.add_reader(tx);
        state.close();
        state.add_packet(vec![1, 2, 3]);
        assert!(rx.blocking_recv().is_err());
    }

    #[tokio::test]
    async fn test_udp_server_echo() -> anyhow::Result<()> {
        let (commands_tx, commands_rx) = tokio::sync::mpsc::unbounded_channel();
        let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(10);
        let (task, addr) = UdpConf {
            host: "127.0.0.1".to_string(),
            port: 0,
        }
        .build(events_tx, commands_rx, shutdown_rx)
        .await?;

        let handle = tokio::spawn(task.run());

        let client = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await?;
        client.connect(addr).await?;
        client.send(b"Hello World!").await?;

        let TransportEvent::ConnectionEstablished {
            connection_id,
            command_tx: None,
            ..
        } = events_rx.recv().await.unwrap()
        else {
            panic!("unexpected command tx needs test adjustment");
        };

        let (data_tx, data_rx) = oneshot::channel();
        commands_tx.send(TransportCommand::ReadData(connection_id, 0, data_tx))?;
        assert_eq!(data_rx.await.unwrap(), b"Hello World!");

        commands_tx.send(TransportCommand::WriteData(
            connection_id,
            b"Hello back!".to_vec(),
        ))?;

        let mut recv_buf = [0u8; 20];
        let n = client.recv(&mut recv_buf).await?;
        assert_eq!(&recv_buf[..n], b"Hello back!");

        commands_tx.send(TransportCommand::CloseConnection(connection_id, false))?;
        let (data_tx, data_rx) = oneshot::channel();
        commands_tx.send(TransportCommand::ReadData(connection_id, 0, data_tx))?;
        assert!(data_rx.await.is_err());

        shutdown_tx.send(())?;
        handle.await??;

        Ok(())
    }
}
