use std::collections::VecDeque;
use std::net::SocketAddr;
use std::time::Duration;

use lru_time_cache::LruCache;
use tokio::sync::mpsc::{Permit, Sender};
use tokio::sync::oneshot;

use crate::messages::{ConnectionId, IpPacket, NetworkCommand, TransportEvent, TunnelInfo};
use anyhow::Result;
use internet_packet::InternetPacket;
use smoltcp::phy::ChecksumCapabilities;

use smoltcp::wire::{
    IpProtocol, IpRepr, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Address, Ipv6Packet, Ipv6Repr,
    UdpPacket, UdpRepr,
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
    fn receive_packet_payload(&mut self, data: Vec<u8>) {
        if self.closed {
        } else if let Some(tx) = self.read_tx.take() {
            tx.send(data).ok();
        } else {
            self.packets.push_back(data);
        }
    }
    fn read_packet_payload(&mut self, tx: oneshot::Sender<Vec<u8>>) {
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
        } else if let Some(tx) = self.read_tx.take() {
            drop(tx);
            self.closed = true;
        } else {
            self.packets.clear();
            self.closed = true;
        }
    }
}

pub struct UdpHandler {
    next_connection_id: ConnectionId,
    id_lookup: LruCache<(SocketAddr, SocketAddr), ConnectionId>,
    connections: LruCache<ConnectionId, ConnectionState>,
    net_tx: Sender<NetworkCommand>,
}

impl UdpHandler {
    pub fn new(net_tx: Sender<NetworkCommand>) -> Self {
        let connections = LruCache::<ConnectionId, ConnectionState>::with_expiry_duration(
            Duration::from_secs(60),
        );
        let id_lookup = LruCache::<(SocketAddr, SocketAddr), ConnectionId>::with_expiry_duration(
            Duration::from_secs(60),
        );
        Self {
            connections,
            id_lookup,
            net_tx,
            next_connection_id: 1,
        }
    }

    pub fn read_data(&mut self, id: ConnectionId, tx: oneshot::Sender<Vec<u8>>) {
        if let Some(state) = self.connections.get_mut(&id) {
            state.read_packet_payload(tx);
        }
    }

    pub fn write_data(&mut self, id: ConnectionId, data: Vec<u8>) {
        let Some(state) = self.connections.get(&id) else {
            return;
        };
        // Refresh id lookup.
        self.id_lookup
            .insert((state.local_addr, state.remote_addr), id);

        let permit = match self.net_tx.try_reserve() {
            Ok(p) => p,
            Err(_) => {
                log::debug!("Channel full, discarding UDP packet.");
                return;
            }
        };

        // We now know that there's space for us to send,
        // let's painstakingly reassemble the IP packet...

        let udp_repr = UdpRepr {
            src_port: state.local_addr.port(),
            dst_port: state.remote_addr.port(),
        };

        let ip_repr: IpRepr = match (state.local_addr, state.remote_addr) {
            (SocketAddr::V4(src_addr), SocketAddr::V4(dst_addr)) => IpRepr::Ipv4(Ipv4Repr {
                src_addr: Ipv4Address::from(*src_addr.ip()),
                dst_addr: Ipv4Address::from(*dst_addr.ip()),
                next_header: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + data.len(),
                hop_limit: 255,
            }),
            (SocketAddr::V6(src_addr), SocketAddr::V6(dst_addr)) => IpRepr::Ipv6(Ipv6Repr {
                src_addr: Ipv6Address::from(*src_addr.ip()),
                dst_addr: Ipv6Address::from(*dst_addr.ip()),
                next_header: IpProtocol::Udp,
                payload_len: udp_repr.header_len() + data.len(),
                hop_limit: 255,
            }),
            _ => {
                log::error!("Failed to assemble UDP datagram: mismatched IP address versions");
                return;
            }
        };

        let buf = vec![0u8; ip_repr.buffer_len()];

        let mut ip_packet = match ip_repr {
            IpRepr::Ipv4(repr) => {
                let mut packet = Ipv4Packet::new_unchecked(buf);
                repr.emit(&mut packet, &ChecksumCapabilities::default());
                IpPacket::from(packet)
            }
            IpRepr::Ipv6(repr) => {
                let mut packet = Ipv6Packet::new_unchecked(buf);
                repr.emit(&mut packet);
                IpPacket::from(packet)
            }
        };

        udp_repr.emit(
            &mut UdpPacket::new_unchecked(ip_packet.payload_mut()),
            &ip_repr.src_addr(),
            &ip_repr.dst_addr(),
            data.len(),
            |buf| buf.copy_from_slice(data.as_slice()),
            &ChecksumCapabilities::default(),
        );

        permit.send(NetworkCommand::SendPacket(ip_packet));
    }

    pub fn drain_writer(&mut self, _id: ConnectionId, tx: oneshot::Sender<()>) {
        tx.send(()).ok();
    }

    pub fn close_connection(&mut self, id: ConnectionId) {
        if let Some(state) = self.connections.get_mut(&id) {
            state.close();
        }
    }

    pub fn receive_packet(
        &mut self,
        packet: IpPacket,
        tunnel_info: TunnelInfo,
        permit: Permit<'_, TransportEvent>,
    ) -> Result<()> {
        let packet: InternetPacket = match packet.try_into() {
            Ok(p) => p,
            Err(e) => {
                log::debug!("Received invalid IP packet: {}", e);
                return Ok(());
            }
        };
        let src_addr = packet.src();
        let dst_addr = packet.dst();

        let potential_cid = self
            .id_lookup
            .get(&(src_addr, dst_addr))
            .cloned()
            .unwrap_or(0); // guaranteed to not exist.

        let payload = packet.payload().to_vec();

        match self.connections.get_mut(&potential_cid) {
            Some(state) => {
                state.receive_packet_payload(payload);
            }
            None => {
                let mut state = ConnectionState::new(src_addr, dst_addr);
                state.receive_packet_payload(payload);
                let connection_id = {
                    self.next_connection_id += 2; // only odd ids.
                    self.next_connection_id
                };
                self.id_lookup.insert((src_addr, dst_addr), connection_id);
                self.connections.insert(connection_id, state);
                permit.send(TransportEvent::ConnectionEstablished {
                    connection_id,
                    src_addr,
                    dst_addr,
                    tunnel_info,
                });
            }
        };

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    const SRC: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 54321);
    const DST: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80);

    #[test]
    fn test_connection_state_recv_recv_read_read() {
        let mut state = ConnectionState::new(SRC, DST);
        state.receive_packet_payload(vec![1, 2, 3]);
        state.receive_packet_payload(vec![4, 5, 6]);
        let (tx, rx) = oneshot::channel();
        state.read_packet_payload(tx);
        assert_eq!(vec![1, 2, 3], rx.blocking_recv().unwrap());
        let (tx, rx) = oneshot::channel();
        state.read_packet_payload(tx);
        assert_eq!(vec![4, 5, 6], rx.blocking_recv().unwrap());
    }

    #[test]
    fn test_connection_state_read_recv_recv() {
        let mut state = ConnectionState::new(SRC, DST);
        let (tx, rx) = oneshot::channel();
        state.read_packet_payload(tx);
        state.receive_packet_payload(vec![1, 2, 3]);
        state.receive_packet_payload(vec![4, 5, 6]);
        assert_eq!(vec![1, 2, 3], rx.blocking_recv().unwrap());
    }

    #[test]
    fn test_connection_state_close_recv_read() {
        let mut state = ConnectionState::new(SRC, DST);
        let (tx, rx) = oneshot::channel();
        state.close();
        state.receive_packet_payload(vec![1, 2, 3]);
        state.read_packet_payload(tx);
        assert!(rx.blocking_recv().is_err());
    }

    #[test]
    fn test_connection_state_read_close_recv() {
        let mut state = ConnectionState::new(SRC, DST);
        let (tx, rx) = oneshot::channel();
        state.read_packet_payload(tx);
        state.close();
        state.receive_packet_payload(vec![1, 2, 3]);
        assert!(rx.blocking_recv().is_err());
    }
}
