use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use boringtun::noise::{
    errors::WireGuardError, handshake::parse_handshake_anon, Packet, Tunn, TunnResult,
};
use boringtun::x25519::{PublicKey, StaticSecret};
use pretty_hex::pretty_hex;
use smoltcp::wire::{Ipv4Packet, Ipv6Packet};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::{
    net::UdpSocket,
    sync::{
        broadcast,
        mpsc::{Receiver, Sender},
        Mutex,
    },
};

use crate::messages::{
    NetworkCommand, NetworkEvent, SmolPacket, TransportCommand, TransportEvent, TunnelInfo,
};
use crate::network::{add_network_layer, MAX_PACKET_SIZE};
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};

// WireGuard headers are 60 bytes for IPv4 and 80 bytes for IPv6
const WG_HEADER_SIZE: usize = 80;

/// A WireGuard peer. We keep track of the tunnel state and the peer address.
pub struct WireGuardPeer {
    tunnel: Tunn,
    endpoint: Option<SocketAddr>,
}

pub struct WireGuardConf {
    pub host: String,
    pub port: u16,
    pub private_key: StaticSecret,
    pub peer_public_keys: Vec<PublicKey>,
}

impl PacketSourceConf for WireGuardConf {
    type Task = WireGuardTask;
    type Data = SocketAddr;

    fn name(&self) -> &'static str {
        "WireGuard server"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: broadcast::Receiver<()>,
    ) -> Result<(Self::Task, Self::Data)> {
        let (network_task_handle, net_tx, net_rx) =
            add_network_layer(transport_events_tx, transport_commands_rx, shutdown)?;

        // initialize WireGuard server
        let mut peers_by_idx = HashMap::new();
        let mut peers_by_key = HashMap::new();
        for public_key in self.peer_public_keys {
            let index = peers_by_idx.len() as u32;

            let tunnel = Tunn::new(
                self.private_key.clone(),
                public_key,
                None,
                Some(25),
                index,
                None,
            )
            .map_err(|error| anyhow!(error))?;

            let peer = Arc::new(Mutex::new(WireGuardPeer {
                tunnel,
                endpoint: None,
            }));

            peers_by_idx.insert(index, peer.clone());
            peers_by_key.insert(public_key, peer);
        }

        // bind to UDP socket(s)
        let socket_addrs = if self.host.is_empty() {
            vec![
                SocketAddr::new("0.0.0.0".parse().unwrap(), self.port),
                SocketAddr::new("::".parse().unwrap(), self.port),
            ]
        } else {
            vec![SocketAddr::new(self.host.parse()?, self.port)]
        };

        let socket = UdpSocket::bind(socket_addrs.as_slice()).await?;
        let local_addr = socket.local_addr()?;

        log::debug!(
            "WireGuard server listening for UDP connections on {} ...",
            socket_addrs
                .iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<String>>()
                .join(" and ")
        );

        let public_key = PublicKey::from(&self.private_key);

        Ok((
            WireGuardTask {
                socket,
                private_key: self.private_key,
                public_key,

                peers_by_idx,
                peers_by_key,
                peers_by_ip: HashMap::new(),
                wg_buf: [0u8; MAX_PACKET_SIZE],

                net_tx,
                net_rx,
                network_task_handle,
            },
            local_addr,
        ))
    }
}

pub struct WireGuardTask {
    socket: UdpSocket,
    private_key: StaticSecret,
    public_key: PublicKey,

    peers_by_idx: HashMap<u32, Arc<Mutex<WireGuardPeer>>>,
    peers_by_key: HashMap<PublicKey, Arc<Mutex<WireGuardPeer>>>,
    peers_by_ip: HashMap<IpAddr, Arc<Mutex<WireGuardPeer>>>,

    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,

    wg_buf: [u8; MAX_PACKET_SIZE],
    network_task_handle: tokio::task::JoinHandle<Result<()>>,
}

impl PacketSourceTask for WireGuardTask {
    async fn run(mut self) -> Result<()> {
        if self.peers_by_idx.is_empty() {
            return Err(anyhow!("No WireGuard peers were configured."));
        }

        let mut udp_buf = [0; MAX_PACKET_SIZE];

        loop {
            tokio::select! {
                exit = &mut self.network_task_handle => break exit.context("network task panic")?.context("network task error")?,
                // wait for WireGuard packets incoming on the UDP socket
                r = self.socket.recv_from(&mut udp_buf) => {
                    let (len, src_orig) = r.context("UDP recv() failed")?;
                    self.process_incoming_datagram(&udp_buf[..len], src_orig).await?;
                },
                // wait for outgoing IP packets
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            self.process_outgoing_packet(packet).await?;
                        }
                    }
                }
            }
        }

        // flush outgoing packet queue before shutdown
        while let Some(e) = self.net_rx.recv().await {
            match e {
                NetworkCommand::SendPacket(packet) => {
                    self.process_outgoing_packet(packet).await?;
                }
            }
        }

        log::debug!("WireGuard server task shutting down.");
        Ok(())
    }
}

impl WireGuardTask {
    fn find_peer_for_datagram(&self, data: &[u8]) -> Option<Arc<Mutex<WireGuardPeer>>> {
        let packet = match Tunn::parse_incoming_packet(data) {
            Ok(p) => p,
            Err(error) => {
                log::error!("Received invalid WireGuard packet: {:?}", error);
                return None;
            }
        };

        let peer = match packet {
            Packet::HandshakeInit(p) => {
                let parsed = parse_handshake_anon(&self.private_key, &self.public_key, &p);

                let handshake = match parsed {
                    Ok(hs) => hs,
                    Err(error) => {
                        log::info!(
                            "Failed to process a WireGuard handshake packet: {:?}",
                            error
                        );
                        return None;
                    }
                };

                let peer_public_key = PublicKey::from(handshake.peer_static_public);
                self.peers_by_key.get(&peer_public_key)
            }
            Packet::HandshakeResponse(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
            Packet::PacketCookieReply(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
            Packet::PacketData(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
        };

        if let Some(p) = peer {
            Some(p.clone())
        } else {
            log::error!("Received WireGuard packet from unknown peer.");
            None
        }
    }

    /// process WireGuard datagrams and forward the decrypted packets.
    async fn process_incoming_datagram(
        &mut self,
        data: &[u8],
        sender_addr: SocketAddr,
    ) -> Result<()> {
        let peer = match self.find_peer_for_datagram(data) {
            Some(p) => p,
            None => return Ok(()),
        };

        let mut result = {
            let mut peer = peer.lock().await;
            peer.endpoint = Some(sender_addr);
            peer.tunnel
                .decapsulate(Some(sender_addr.ip()), data, &mut self.wg_buf)
        };

        while let TunnResult::WriteToNetwork(b) = result {
            log::trace!("WG::process_incoming_datagram: WriteToNetwork");
            self.socket.send_to(b, sender_addr).await?;

            // check if there are more things to be handled
            result = peer
                .lock()
                .await
                .tunnel
                .decapsulate(None, &[0; 0], &mut self.wg_buf);
        }

        match result {
            TunnResult::Done => {
                log::trace!("WG::process_incoming_datagram: Done");
            }
            TunnResult::Err(error) => {
                if matches!(error, WireGuardError::NoCurrentSession) {
                    log::info!(
                        "No current session for incoming WireGuard packet: \
                        Wait for the next session handshake or reconnect your client."
                    );
                } else {
                    log::debug!("WG::process_incoming_datagram: Err: {:?}", error);
                }
            }
            TunnResult::WriteToTunnelV4(buf, src_addr) => {
                match Ipv4Packet::new_checked(buf.to_vec()) {
                    Ok(packet) => {
                        log::trace!(
                            "WG::process_incoming_datagram: WriteToTunnelV4
                            src_addr: {}, dst_addr: {}, origin: {}
                        {}",
                            packet.src_addr(),
                            packet.dst_addr(),
                            src_addr,
                            pretty_hex(&buf),
                        );

                        self.peers_by_ip
                            .insert(Ipv4Addr::from(packet.src_addr()).into(), peer);
                        let event = NetworkEvent::ReceivePacket {
                            packet: SmolPacket::from(packet),
                            tunnel_info: TunnelInfo::WireGuard {
                                src_addr: sender_addr,
                                dst_addr: self.socket.local_addr()?,
                            },
                        };

                        if self.net_tx.try_send(event).is_err() {
                            log::warn!("Dropping incoming packet, TCP channel is full.")
                        };
                    }
                    Err(error) => {
                        log::warn!("Invalid IPv4 packet: {}", error);
                    }
                }
            }
            TunnResult::WriteToTunnelV6(buf, src_addr) => {
                match Ipv6Packet::new_checked(buf.to_vec()) {
                    Ok(packet) => {
                        log::trace!(
                            "WG::process_incoming_datagram: WriteToTunnelV6
                            src_addr: {}, dst_addr: {}, origin: {}
                        {}",
                            packet.src_addr(),
                            packet.dst_addr(),
                            src_addr,
                            pretty_hex(&buf),
                        );

                        self.peers_by_ip
                            .insert(Ipv6Addr::from(packet.src_addr()).into(), peer);
                        let event = NetworkEvent::ReceivePacket {
                            packet: SmolPacket::from(packet),
                            tunnel_info: TunnelInfo::WireGuard {
                                src_addr: sender_addr,
                                dst_addr: self.socket.local_addr()?,
                            },
                        };

                        if self.net_tx.try_send(event).is_err() {
                            log::warn!("Dropping incoming packet, TCP channel is full.")
                        };
                    }
                    Err(error) => {
                        log::warn!("Invalid IPv6 packet: {}", error);
                    }
                }
            }
            TunnResult::WriteToNetwork(_) => unreachable!(),
        }
        Ok(())
    }

    /// process packets and send the encrypted WireGuard datagrams to the peer.
    async fn process_outgoing_packet(&mut self, packet: SmolPacket) -> Result<()> {
        let peer = self
            .peers_by_ip
            .get(&packet.dst_ip())
            .or_else(|| {
                log::warn!(
                    "No peer found for IP {}, falling back to first peer.",
                    packet.dst_ip()
                );
                self.peers_by_idx.values().next()
            })
            .unwrap();

        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();

        let packet_bytes = packet.into_inner();

        // Tunn.encapsulate panics if the packet is too big for the buffer
        if packet_bytes.len() > MAX_PACKET_SIZE - WG_HEADER_SIZE {
            log::error!(
                "Unable to send packet ({} -> {}), payload too large ({} bytes > {}).",
                src_ip,
                dst_ip,
                packet_bytes.len(),
                MAX_PACKET_SIZE - WG_HEADER_SIZE,
            );
            return Ok(());
        }

        let mut peer = peer.lock().await;
        match peer.tunnel.encapsulate(&packet_bytes, &mut self.wg_buf) {
            TunnResult::Done => {
                log::trace!("WG::process_outgoing_packet: Done");
            }
            TunnResult::Err(error) => {
                log::error!("WG::process_outgoing_packet: Err: {:?}", error);
            }
            TunnResult::WriteToNetwork(buf) => {
                let dst_addr = peer.endpoint.unwrap();
                drop(peer);

                log::trace!(
                    "WG::process_outgoing_packet: WriteToNetwork
                        src_ip: {}, dst_ip: {}, dst_addr: {}
                    {}",
                    src_ip,
                    dst_ip,
                    dst_addr,
                    pretty_hex(&buf),
                );

                self.socket.send_to(buf, dst_addr).await?;
            }
            // IPv4 packet
            TunnResult::WriteToTunnelV4(_, _) => {
                log::warn!("WG::process_outgoing_packet: WriteToTunnelV4: unexpected event");
            }
            // IPv6 packet
            TunnResult::WriteToTunnelV6(_, _) => {
                log::warn!("WG::process_outgoing_packet: WriteToTunnelV6: unexpected event");
            }
        }

        Ok(())
    }
}
