use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::messages::{
    NetworkCommand, NetworkEvent, SmolPacket, TransportCommand, TransportEvent, TunnelInfo,
};
use crate::network::{MAX_PACKET_SIZE, add_network_layer};
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};
use anyhow::{Context, Result, anyhow};
use boringtun::noise::{
    Packet, Tunn, TunnResult, errors::WireGuardError, handshake::parse_handshake_anon,
    rate_limiter::RateLimiter,
};
use boringtun::x25519::{PublicKey, StaticSecret};
use pretty_hex::pretty_hex;
use smoltcp::wire::{Ipv4Packet, Ipv6Packet};
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::{
    net::UdpSocket,
    sync::{
        Mutex,
        mpsc::{Receiver, Sender},
    },
    time::{MissedTickBehavior, interval},
};

use crate::packet_sources::udp::{create_and_bind_udp_socket, remote_host_closed_conn};
use crate::shutdown;

// WireGuard headers are 60 bytes for IPv4 and 80 bytes for IPv6
const WG_HEADER_SIZE: usize = 80;

/// Number of handshakes per second we accept before answering with cookie replies
/// (same value as boringtun's own device implementation).
const HANDSHAKE_RATE_LIMIT: u64 = 100;

/// A WireGuard peer. We keep track of the tunnel state and the peer address.
pub struct WireGuardPeer {
    tunnel: Tunn,
    endpoint: Option<SocketAddr>,
}

pub struct WireGuardConf {
    pub listen_addr: SocketAddr,
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
        shutdown: shutdown::Receiver,
    ) -> Result<(Self::Task, Self::Data)> {
        let (network_task_handle, net_tx, net_rx) =
            add_network_layer(transport_events_tx, transport_commands_rx, shutdown);

        // initialize WireGuard server
        let public_key = PublicKey::from(&self.private_key);

        // If no rate limiter is passed to `Tunn::new`, boringtun creates one per tunnel that only
        // gets reset from `Tunn::update_timers`, which we never call. Its counter would then
        // never be reset and all handshakes after the first ten would be answered with cookie
        // replies. Instead, we share a single rate limiter and reset it ourselves (see `run`).
        let rate_limiter = Arc::new(RateLimiter::new(&public_key, HANDSHAKE_RATE_LIMIT));

        let mut peers_by_idx = HashMap::new();
        let mut peers_by_key = HashMap::new();
        for peer_public_key in self.peer_public_keys {
            let index = peers_by_idx.len() as u32;

            let tunnel = Tunn::new(
                self.private_key.clone(),
                peer_public_key,
                None,
                Some(25),
                index,
                Some(rate_limiter.clone()),
            );

            let peer = Arc::new(Mutex::new(WireGuardPeer {
                tunnel,
                endpoint: None,
            }));

            peers_by_idx.insert(index, peer.clone());
            peers_by_key.insert(peer_public_key, peer);
        }

        let socket = create_and_bind_udp_socket(self.listen_addr)?;
        let local_addr = socket.local_addr()?;

        log::debug!("WireGuard server listening for UDP connections on {local_addr} ...");

        Ok((
            WireGuardTask {
                socket,
                private_key: self.private_key,
                public_key,
                rate_limiter,

                peers_by_idx,
                peers_by_key,
                peers_by_ip: HashMap::new(),
                wg_buf: vec![0u8; MAX_PACKET_SIZE],

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
    rate_limiter: Arc<RateLimiter>,

    peers_by_idx: HashMap<u32, Arc<Mutex<WireGuardPeer>>>,
    peers_by_key: HashMap<PublicKey, Arc<Mutex<WireGuardPeer>>>,
    peers_by_ip: HashMap<IpAddr, Arc<Mutex<WireGuardPeer>>>,

    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,

    wg_buf: Vec<u8>,
    network_task_handle: tokio::task::JoinHandle<Result<()>>,
}

impl PacketSourceTask for WireGuardTask {
    async fn run(mut self) -> Result<()> {
        if self.peers_by_idx.is_empty() {
            return Err(anyhow!("No WireGuard peers were configured."));
        }

        let mut udp_buf = vec![0; MAX_PACKET_SIZE];

        // boringtun expects the handshake rate limiter to be reset about once per second.
        let mut reset_rate_limiter = interval(Duration::from_secs(1));
        reset_rate_limiter.set_missed_tick_behavior(MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                exit = &mut self.network_task_handle => break exit.context("network task panic")?.context("network task error")?,
                _ = reset_rate_limiter.tick() => {
                    self.rate_limiter.reset_count();
                },
                // wait for WireGuard packets incoming on the UDP socket
                r = self.socket.recv_from(udp_buf.as_mut_slice()) => {
                    if remote_host_closed_conn(&r) {
                        continue;
                    }
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
                log::error!("Received invalid WireGuard packet: {error:?}");
                return None;
            }
        };

        let peer = match packet {
            Packet::HandshakeInit(p) => {
                let parsed = parse_handshake_anon(&self.private_key, &self.public_key, &p);

                let handshake = match parsed {
                    Ok(hs) => hs,
                    Err(error) => {
                        log::info!("Failed to process a WireGuard handshake packet: {error:?}");
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
                    log::debug!("WG::process_incoming_datagram: Err: {error:?}");
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

                        self.peers_by_ip.insert(packet.src_addr().into(), peer);
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
                        log::warn!("Invalid IPv4 packet: {error}");
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

                        self.peers_by_ip.insert(packet.src_addr().into(), peer);
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
                        log::warn!("Invalid IPv6 packet: {error}");
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
                log::error!("WG::process_outgoing_packet: Err: {error:?}");
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    const HANDSHAKE_RESPONSE: u8 = 2;
    const COOKIE_REPLY: u8 = 3;

    /// Send a new handshake initiation (without mac2) and return the type of the server's reply.
    async fn handshake(socket: &UdpSocket, client: &mut Tunn) -> u8 {
        let mut buf = [0u8; 256];
        let TunnResult::WriteToNetwork(initiation) =
            client.format_handshake_initiation(&mut buf, true)
        else {
            panic!("failed to create handshake initiation");
        };
        socket.send(initiation).await.unwrap();
        let mut reply = [0u8; 256];
        tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut reply))
            .await
            .expect("no reply from WireGuard server")
            .unwrap();
        reply[0]
    }

    #[tokio::test]
    async fn handshake_rate_limiter_is_reset() {
        let server_key = StaticSecret::from([1u8; 32]);
        let client_key = StaticSecret::from([2u8; 32]);
        let server_public_key = PublicKey::from(&server_key);

        let conf = WireGuardConf {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            private_key: server_key,
            peer_public_keys: vec![PublicKey::from(&client_key)],
        };
        let (transport_events_tx, _transport_events_rx) = mpsc::channel(256);
        let (_transport_commands_tx, transport_commands_rx) = mpsc::unbounded_channel();
        let (_shutdown_tx, shutdown_rx) = shutdown::channel();
        let (task, server_addr) = conf
            .build(transport_events_tx, transport_commands_rx, shutdown_rx)
            .await
            .unwrap();
        tokio::spawn(task.run());

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(server_addr).await.unwrap();
        // Reusing one client tunnel keeps the handshake timestamps strictly increasing.
        let mut client = Tunn::new(client_key, server_public_key, None, None, 0, None);

        // A burst of handshakes eventually puts the server under load: it answers with cookie replies.
        let mut under_load = false;
        for _ in 0..10 * HANDSHAKE_RATE_LIMIT {
            if handshake(&socket, &mut client).await == COOKIE_REPLY {
                under_load = true;
                break;
            }
        }
        assert!(under_load, "the handshake rate limiter never kicked in");

        // Once the burst is over, the rate limiter must be reset and handshakes must succeed again.
        // Previously, the per-tunnel rate limiter was never reset, so this never happened.
        let mut recovered = false;
        for _ in 0..10 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if handshake(&socket, &mut client).await == HANDSHAKE_RESPONSE {
                recovered = true;
                break;
            }
        }
        assert!(
            recovered,
            "the server still answers with cookie replies after the burst"
        );
    }
}
