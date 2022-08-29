use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};

use pretty_hex::pretty_hex;

use smoltcp::wire::{Ipv4Packet, Ipv6Packet};

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{Notify, RwLock};

use crate::messages::{IpPacket, NetworkCommand, NetworkEvent};

/// A WireGuard peer. We keep track of the tunnel state and the peer address.
pub struct WireGuardPeer {
    tunnel: Box<Tunn>,
    endpoint: RwLock<Option<SocketAddr>>,
}

impl WireGuardPeer {
    pub async fn set_endpoint(&self, addr: SocketAddr) {
        let mut endpoint = self.endpoint.write().await;
        *endpoint = Some(addr);
    }
}

pub struct WireGuardTaskBuilder {
    private_key: Arc<X25519SecretKey>,

    peers_by_idx: HashMap<u32, Arc<WireGuardPeer>>,
    peers_by_key: HashMap<Arc<X25519PublicKey>, Arc<WireGuardPeer>>,
    peers_by_ip: HashMap<IpAddr, Arc<WireGuardPeer>>,

    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,

    sd_trigger: Arc<Notify>,
}

impl WireGuardTaskBuilder {
    pub fn new(
        private_key: Arc<X25519SecretKey>,
        net_tx: Sender<NetworkEvent>,
        net_rx: Receiver<NetworkCommand>,
        sd_trigger: Arc<Notify>,
    ) -> Self {
        WireGuardTaskBuilder {
            private_key,

            peers_by_idx: HashMap::new(),
            peers_by_key: HashMap::new(),
            peers_by_ip: HashMap::new(),

            net_tx,
            net_rx,

            sd_trigger,
        }
    }

    pub fn add_peer(&mut self, public_key: Arc<X25519PublicKey>, preshared_key: Option<[u8; 32]>) -> Result<()> {
        let index = self.peers_by_idx.len() as u32;

        let tunnel = Tunn::new(
            self.private_key.clone(),
            public_key.clone(),
            preshared_key,
            Some(25),
            index,
            None,
        )
        .map_err(|error| anyhow!(error))?;

        let peer = Arc::new(WireGuardPeer {
            tunnel,
            endpoint: RwLock::new(None),
        });

        self.peers_by_idx.insert(index, peer.clone());
        self.peers_by_key.insert(public_key, peer);

        Ok(())
    }

    pub fn build(self) -> Result<WireGuardTask> {
        let public_key = Arc::new(self.private_key.public_key());

        Ok(WireGuardTask {
            private_key: self.private_key,
            public_key,

            peers_by_idx: self.peers_by_idx,
            peers_by_key: self.peers_by_key,
            peers_by_ip: self.peers_by_ip,

            net_tx: self.net_tx,
            net_rx: self.net_rx,

            wg_buf: [0u8; 1500],
            sd_trigger: self.sd_trigger,
        })
    }
}

pub struct WireGuardTask {
    private_key: Arc<X25519SecretKey>,
    public_key: Arc<X25519PublicKey>,

    peers_by_idx: HashMap<u32, Arc<WireGuardPeer>>,
    peers_by_key: HashMap<Arc<X25519PublicKey>, Arc<WireGuardPeer>>,
    peers_by_ip: HashMap<IpAddr, Arc<WireGuardPeer>>,

    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,

    wg_buf: [u8; 1500],
    sd_trigger: Arc<Notify>,
}

impl WireGuardTask {
    pub async fn run(mut self, socket: UdpSocket) -> Result<()> {
        if self.peers_by_idx.is_empty() {
            return Err(anyhow!("No WireGuard peers were configured."));
        }

        let mut udp_buf = [0; 1500];
        let mut stop = false;

        while !stop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.sd_trigger.notified() => {
                    stop = true;
                },
                // wait for WireGuard packets incoming on the UDP socket
                Ok((len, src_addr)) = socket.recv_from(&mut udp_buf) => {
                    self.process_incoming_datagram(&socket, &udp_buf[..len], src_addr).await?;
                },
                // wait for outgoing IP packets
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            self.process_outgoing_packet(&socket, packet).await?;
                        }
                    }
                }
            }
        }

        // flush outgoing packet queue before shutdown
        while let Some(e) = self.net_rx.recv().await {
            match e {
                NetworkCommand::SendPacket(packet) => {
                    self.process_outgoing_packet(&socket, packet).await?;
                },
            }
        }

        log::debug!("WireGuard server task shutting down.");
        Ok(())
    }

    fn find_peer_for_datagram(&self, data: &[u8]) -> Option<Arc<WireGuardPeer>> {
        let packet = match Tunn::parse_incoming_packet(data) {
            Ok(p) => p,
            Err(error) => {
                log::error!("Received invalid WireGuard packet: {:?}", error);
                return None;
            },
        };

        let peer = match packet {
            Packet::HandshakeInit(p) => {
                let parsed = parse_handshake_anon(&self.private_key, &self.public_key, &p);

                let handshake = match parsed {
                    Ok(hs) => hs,
                    Err(error) => {
                        log::info!("Failed to process a WireGuard handshake packet: {:?}", error);
                        return None;
                    },
                };

                let peer_public_key = X25519PublicKey::from(handshake.peer_static_public.as_slice());
                self.peers_by_key.get(&peer_public_key)
            },
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
    async fn process_incoming_datagram(&mut self, socket: &UdpSocket, data: &[u8], src_addr: SocketAddr) -> Result<()> {
        let peer = match self.find_peer_for_datagram(data) {
            Some(p) => p,
            None => return Ok(()),
        };

        peer.set_endpoint(src_addr).await;
        let mut result = peer.tunnel.decapsulate(Some(src_addr.ip()), data, &mut self.wg_buf);

        while let TunnResult::WriteToNetwork(b) = result {
            log::trace!("WG::process_incoming_datagram: WriteToNetwork");
            socket.send_to(b, src_addr).await?;

            // check if there are more things to be handled
            result = peer.tunnel.decapsulate(None, &[0; 0], &mut self.wg_buf);
        }

        match result {
            TunnResult::Done => {
                log::trace!("WG::process_incoming_datagram: Done");
            },
            TunnResult::Err(error) => {
                log::error!("WG::process_incoming_datagram: Err: {:?}", error);
            },
            TunnResult::WriteToTunnelV4(buf, src_addr) => match Ipv4Packet::new_checked(buf.to_vec()) {
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

                    self.peers_by_ip.insert(Ipv4Addr::from(packet.src_addr()).into(), peer);
                    let event = NetworkEvent::ReceivePacket(IpPacket::from(packet));

                    if self.net_tx.try_send(event).is_err() {
                        log::warn!("Dropping incoming packet, TCP channel is full.")
                    };
                },
                Err(error) => {
                    log::warn!("Invalid IPv4 packet: {}", error);
                },
            },
            TunnResult::WriteToTunnelV6(buf, src_addr) => match Ipv6Packet::new_checked(buf.to_vec()) {
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

                    self.peers_by_ip.insert(Ipv6Addr::from(packet.src_addr()).into(), peer);
                    let event = NetworkEvent::ReceivePacket(IpPacket::from(packet));

                    if self.net_tx.try_send(event).is_err() {
                        log::warn!("Dropping incoming packet, TCP channel is full.")
                    };
                },
                Err(error) => {
                    log::warn!("Invalid IPv4 packet: {}", error);
                },
            },
            TunnResult::WriteToNetwork(_) => unreachable!(),
        }
        Ok(())
    }

    /// process packets and send the encrypted WireGuard datagrams to the peer.
    async fn process_outgoing_packet(&mut self, socket: &UdpSocket, packet: IpPacket) -> Result<()> {
        let peer = self
            .peers_by_ip
            .get(&packet.dst_ip())
            .or_else(|| {
                log::warn!("No peer found for IP {}, falling back to first peer.", packet.dst_ip());
                self.peers_by_idx.values().next()
            })
            .unwrap();

        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();

        match peer.tunnel.encapsulate(&packet.into_inner(), &mut self.wg_buf) {
            TunnResult::Done => {
                log::trace!("WG::process_outgoing_packet: Done");
            },
            TunnResult::Err(error) => {
                log::error!("WG::process_outgoing_packet: Err: {:?}", error);
            },
            TunnResult::WriteToNetwork(buf) => {
                let dst_addr = peer.endpoint.read().await.unwrap();

                log::trace!(
                    "WG::process_outgoing_packet: WriteToNetwork
                        src_ip: {}, dst_ip: {}, dst_addr: {}
                    {}",
                    src_ip,
                    dst_ip,
                    dst_addr,
                    pretty_hex(&buf),
                );

                socket.send_to(buf, dst_addr).await?;
            },
            // IPv4 packet
            TunnResult::WriteToTunnelV4(_, _) => {
                log::warn!("WG::process_outgoing_packet: WriteToTunnelV4: unexpected event");
            },
            // IPv6 packet
            TunnResult::WriteToTunnelV6(_, _) => {
                log::warn!("WG::process_outgoing_packet: WriteToTunnelV6: unexpected event");
            },
        }

        Ok(())
    }
}
