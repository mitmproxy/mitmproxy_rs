use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use pretty_hex::pretty_hex;
use smoltcp::wire::{Ipv4Packet, Ipv6Packet};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::RwLock;

use crate::messages::{IpPacket, NetworkCommand, NetworkEvent};

/// A WireGuard peer. We keep track of the tunnel state and the peer address.
pub struct WireguardPeer {
    tunnel: Box<Tunn>,
    endpoint: RwLock<Option<SocketAddr>>,
}

impl WireguardPeer {
    pub async fn set_endpoint(&self, addr: SocketAddr) {
        let mut endpoint = self.endpoint.write().await;
        *endpoint = Some(addr);
    }
}

pub struct WireguardServer {
    socket: UdpSocket,
    private_key: Arc<X25519SecretKey>,
    public_key: Arc<X25519PublicKey>,
    peers_by_idx: HashMap<u32, Arc<WireguardPeer>>,
    peers_by_key: HashMap<Arc<X25519PublicKey>, Arc<WireguardPeer>>,
    peers_by_ip: HashMap<IpAddr, Arc<WireguardPeer>>,
    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,
    buf: [u8; 1500],
}

impl WireguardServer {
    pub async fn new<A: ToSocketAddrs>(
        addr: A,
        private_key: Arc<X25519SecretKey>,
        peers: Vec<(Arc<X25519PublicKey>, Option<[u8; 32]>)>,
        net_tx: Sender<NetworkEvent>,
        net_rx: Receiver<NetworkCommand>,
    ) -> Result<Self> {
        if peers.is_empty() {
            return Err(anyhow!("No WireGuard peers."));
        }

        let socket = UdpSocket::bind(addr).await?;

        let public_key = Arc::new(private_key.public_key());

        let mut peers_by_idx = HashMap::with_capacity(peers.len());
        let mut peers_by_key = HashMap::with_capacity(peers.len());
        let peers_by_ip = HashMap::with_capacity(peers.len());

        for (i, (peer_pubkey, peer_psk)) in peers.into_iter().enumerate() {
            let i = i as u32;
            let tunnel = Tunn::new(private_key.clone(), peer_pubkey.clone(), peer_psk, Some(25), i, None)
                .map_err(|error: &str| anyhow!(error))?;
            let peer = Arc::new(WireguardPeer {
                tunnel,
                endpoint: RwLock::new(None),
            });
            peers_by_idx.insert(i, peer.clone());
            peers_by_key.insert(peer_pubkey, peer);
        }

        let buf = [0u8; 1500];

        Ok(Self {
            socket,
            peers_by_idx,
            peers_by_key,
            peers_by_ip,
            private_key,
            public_key,
            net_tx,
            net_rx,
            buf,
        })
    }

    pub async fn run(&mut self) -> Result<()> {
        let mut buf = [0; 1500];
        loop {
            tokio::select! {
                Ok((len, src_addr)) = self.socket.recv_from(&mut buf) => {
                    self.process_incoming_datagram(&buf[..len], src_addr).await?;
                },
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            self.process_outgoing_packet(packet).await?;
                        }
                    }
                }
            }
        }
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn find_peer_for_datagram(&self, data: &[u8]) -> Option<Arc<WireguardPeer>> {
        let packet = match Tunn::parse_incoming_packet(&data) {
            Ok(p) => p,
            Err(_) => {
                println!("Invalid packet.");
                return None;
            },
        };

        let peer = match packet {
            Packet::HandshakeInit(p) => {
                let hs = match parse_handshake_anon(&self.private_key, &self.public_key, &p) {
                    Ok(hs) => hs,
                    Err(e) => {
                        log::warn!("Cannot parse WireGuard packet ({:?}). You may have used invalid credentials.", e);
                        return None;
                    },
                };
                self.peers_by_key
                    .get(&X25519PublicKey::from(hs.peer_static_public.as_slice()))
            },
            Packet::HandshakeResponse(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
            Packet::PacketCookieReply(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
            Packet::PacketData(p) => self.peers_by_idx.get(&(p.receiver_idx >> 8)),
        };
        match peer {
            Some(p) => Some(p.clone()),
            None => {
                println!("Unknown peer.");
                None
            },
        }
    }

    /// process WireGuard datagrams and forward the decrypted packets.
    async fn process_incoming_datagram(&mut self, data: &[u8], src_addr: SocketAddr) -> Result<()> {
        let peer = match self.find_peer_for_datagram(&data) {
            Some(p) => p,
            None => return Ok(()),
        };

        peer.set_endpoint(src_addr).await;
        let mut result = peer.tunnel.decapsulate(Some(src_addr.ip()), &data, &mut self.buf);

        while let TunnResult::WriteToNetwork(b) = result {
            log::debug!("process_incoming_datagram: WriteToNetwork");
            self.socket.send_to(b, src_addr).await?;
            // check if there are more things to be handled
            result = peer.tunnel.decapsulate(None, &[0; 0], &mut self.buf);
        }

        match result {
            TunnResult::Done => {
                log::debug!("process_incoming_datagram: Done");
            },
            TunnResult::Err(error) => {
                log::error!("process_incoming_datagram: Err: {:?}", error);
            },
            TunnResult::WriteToTunnelV4(buf, src_addr) => match Ipv4Packet::new_checked(buf.to_vec()) {
                Ok(packet) => {
                    log::debug!(
                        "process_incoming_datagram: WriteToTunnelV4 {} -> {} (from {})",
                        packet.src_addr(),
                        packet.dst_addr(),
                        src_addr
                    );
                    log::trace!("{} {}", src_addr, pretty_hex(&buf));

                    self.peers_by_ip.insert(Ipv4Addr::from(packet.src_addr()).into(), peer);
                    match self
                        .net_tx
                        .try_send(NetworkEvent::ReceivePacket(IpPacket::from(packet)))
                    {
                        Ok(()) => {},
                        Err(_) => {
                            log::warn!("Dropping incoming packet, TCP channel is full.")
                        },
                    };
                },
                Err(e) => {
                    log::warn!("Invalid IPv4 packet: {}", e);
                },
            },
            TunnResult::WriteToTunnelV6(buf, src_addr) => match Ipv6Packet::new_checked(buf.to_vec()) {
                Ok(packet) => {
                    log::debug!(
                        "process_incoming_datagram: WriteToTunnelV6 {} -> {} (from {})",
                        packet.src_addr(),
                        packet.dst_addr(),
                        src_addr
                    );
                    log::trace!("{} {}", src_addr, pretty_hex(&buf));

                    self.peers_by_ip.insert(Ipv6Addr::from(packet.src_addr()).into(), peer);
                    match self
                        .net_tx
                        .try_send(NetworkEvent::ReceivePacket(IpPacket::from(packet)))
                    {
                        Ok(()) => {},
                        Err(_) => {
                            log::warn!("Dropping incoming packet, TCP channel is full.")
                        },
                    };
                },
                Err(e) => {
                    log::warn!("Invalid IPv6 packet: {}", e);
                },
            },
            TunnResult::WriteToNetwork(_) => unreachable!(),
        }
        Ok(())
    }

    /// process packets and send the encrypted WireGuard datagrams to the peer.
    async fn process_outgoing_packet(&mut self, packet: IpPacket) -> Result<()> {
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

        match peer.tunnel.encapsulate(&packet.into_inner(), &mut self.buf) {
            TunnResult::Done => {
                log::debug!("process_incoming_packet: Done");
            },
            TunnResult::Err(error) => {
                log::error!("process_incoming_packet: Err: {:?}", error);
            },
            TunnResult::WriteToNetwork(buf) => {
                let dst_addr = peer.endpoint.read().await.unwrap();
                log::debug!(
                    "process_incoming_packet: WriteToNetwork {} -> {} (to {})",
                    src_ip,
                    dst_ip,
                    dst_addr
                );
                self.socket.send_to(buf, dst_addr).await?;
            },
            // IPv4 packet
            TunnResult::WriteToTunnelV4(_, _) => {
                log::warn!("Unexpected WireGuard event (WriteToTunnelV4) when handling a response.");
            },
            // IPv6 packet
            TunnResult::WriteToTunnelV6(_, _) => {
                log::warn!("Unexpected WireGuard event (WriteToTunnelV6) when handling a response.");
            },
        }
        Ok(())
    }
}
