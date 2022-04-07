use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};

use pretty_hex::pretty_hex;

use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket};

use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::tcp::{IpPacket, TcpHandler};

pub struct WgServer {
    addr: SocketAddr,
    sec_key: Arc<X25519SecretKey>,
    pub_key: Arc<X25519PublicKey>,

    next_peer_index: u32,
    peers: Vec<WgPeer>,

    // WireGuard message channels
    peer_send_by_idx: HashMap<u32, mpsc::Sender<(Vec<u8>, SocketAddr)>>,
    peer_send_by_key: HashMap<Arc<X25519PublicKey>, mpsc::Sender<(Vec<u8>, SocketAddr)>>,

    // WireGuard response channel
    wg_send: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    wg_recv: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
}

impl WgServer {
    pub fn new(addr: SocketAddr, sec_key: X25519SecretKey) -> WgServer {
        let (wg_back, wg_chan) = mpsc::channel(64);

        let sec_key = Arc::new(sec_key);
        let pub_key = Arc::new(sec_key.public_key());

        WgServer {
            addr,
            sec_key,
            pub_key,

            next_peer_index: 0,
            peers: Vec::new(),

            peer_send_by_idx: HashMap::new(),
            peer_send_by_key: HashMap::new(),

            wg_recv: wg_chan,
            wg_send: wg_back,
        }
    }

    pub fn add_peer(
        &mut self,
        pub_key: Arc<X25519PublicKey>,
        preshared_key: Option<[u8; 32]>,
    ) -> Result<(), anyhow::Error> {
        let result = Tunn::new(
            self.sec_key.clone(),
            pub_key.clone(),
            preshared_key,
            Some(25),
            self.next_peer_index,
            None,
        );

        match result {
            Ok(tunn) => {
                let index = self.next_peer_index;
                let (peer_send, peer_recv) = mpsc::channel(64);

                let peer = WgPeer::new(tunn, peer_recv, self.wg_send.clone());
                self.peers.push(peer);

                self.peer_send_by_idx.insert(index, peer_send.clone());
                self.peer_send_by_key.insert(pub_key, peer_send);

                self.next_peer_index += 1;
                Ok(())
            },
            Err(error) => Err(anyhow::anyhow!(error)),
        }
    }

    pub async fn serve(mut self) -> Result<(), anyhow::Error> {
        // spawn handlers for WireGuard peers
        for peer in self.peers {
            tokio::spawn(peer.handle());
        }

        // listen for incoming WireGuard connections
        let socket = UdpSocket::bind(self.addr).await?;
        let mut buf = [0u8; 1500];

        log::info!("Listening on {} for incoming connections.", &self.addr);

        loop {
            tokio::select!(
                // receive incoming WireGuard UDP packet and handle it
                ret = socket.recv_from(&mut buf) => {
                    let (read, addr) = ret.unwrap();

                    let packet = Tunn::parse_incoming_packet(&buf[..read]).unwrap();

                    let chan = match packet {
                        Packet::HandshakeInit(p) => {
                            let hs = parse_handshake_anon(&self.sec_key, &self.pub_key, &p).unwrap();
                            self.peer_send_by_key.get(&X25519PublicKey::from(hs.peer_static_public.as_slice()))
                        },
                        Packet::HandshakeResponse(p) => {
                            self.peer_send_by_idx.get(&(p.receiver_idx >> 8))
                        },
                        Packet::PacketCookieReply(p) => {
                            self.peer_send_by_idx.get(&(p.receiver_idx >> 8))
                        },
                        Packet::PacketData(p) => {
                            self.peer_send_by_idx.get(&(p.receiver_idx >> 8))
                        },
                    };

                    if let Some(chan) = chan {
                        chan.send(((&buf[..read]).to_vec(), addr)).await.unwrap();
                    };
                },
                // send outgoing WireGuard UDP packet from queue
                ret = self.wg_recv.recv() => {
                    if let Some((datagram, addr)) = ret {
                        socket.send_to(&datagram, addr).await.unwrap();
                    }
                }
            )
        }
    }
}

struct WgPeer {
    tunn: Box<Tunn>,
    wg_recv: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    wg_send: mpsc::Sender<(Vec<u8>, SocketAddr)>,
}

impl WgPeer {
    fn new(
        tunn: Box<Tunn>,
        wg_recv: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
        wg_send: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> WgPeer {
        WgPeer { tunn, wg_recv, wg_send }
    }
}

impl WgPeer {
    async fn handle(mut self) -> Result<(), anyhow::Error> {
        let mut buf = [0u8; 1500];

        let mut tcp_handler = TcpHandler::new();

        loop {
            tokio::select!(
                // handle packets that are incoming at the WireGuard tunnel
                ret = self.wg_recv.recv() => {
                    let (datagram, src_addr) = ret.unwrap();

                    let mut result = self.tunn.decapsulate(
                        Some(src_addr.ip()),
                        &datagram,
                        &mut buf
                    );

                    while let TunnResult::WriteToNetwork(b) = result {
                        log::debug!("WireGuard: WriteToNetwork");
                        self.wg_send.send((b.to_vec(), src_addr)).await.unwrap();

                        // check if there are more things to be handled
                        result = self.tunn.decapsulate(None, &[0; 0], &mut buf);
                    }

                    match result {
                        TunnResult::Done => {
                            log::debug!("WireGuard: Done");
                        },
                        TunnResult::Err(error) => {
                            log::error!("WireGuard Error: {:?}", error);
                        },
                        // all WriteToNetwork events should have been processed at this point
                        TunnResult::WriteToNetwork(_) => {
                            unreachable!();
                        },
                        // IPv4 packet
                        TunnResult::WriteToTunnelV4(buf, src_addr) => {
                            log::debug!("IPv4 source address: {}", src_addr);
                            log::debug!("{}", pretty_hex(&buf));

                            let ip_packet = Ipv4Packet::new_checked(buf.to_vec()).unwrap();
                            if ip_packet.protocol() != IpProtocol::Tcp {
                                // TODO: handle IP packet types other than TCP?
                                log::debug!("Unsupported IPv4 packet type: {}", ip_packet.protocol());
                            } else {
                                let src_ip: IpAddr = IpAddr::V4(ip_packet.src_addr().into());
                                let dst_ip: IpAddr = IpAddr::V4(ip_packet.dst_addr().into());

                                log::debug!("WireGuard: IPv4 src address: {}", src_ip);
                                log::debug!("WireGuard: IPv4 dst address: {}", dst_ip);

                                // handle immediate TCP response packages (handshake etc.)
                                let resp_packets = tcp_handler.recv4(ip_packet).await.unwrap();
                                for mut packet in resp_packets {
                                    let dst_ip = IpAddr::V4(Ipv4Addr::from(packet.dst_addr()));
                                    let tcp_packet = TcpPacket::new_checked(packet.payload_mut()).unwrap();

                                    let dst_addr = SocketAddr::new(dst_ip, tcp_packet.dst_port());
                                    self.wg_send.send((packet.into_inner(), dst_addr)).await.unwrap();
                                }
                            }
                        },
                        // IPv6 packet
                        TunnResult::WriteToTunnelV6(buf, src_addr) => {
                            log::debug!("IPv6 support not implemented yet.");
                            log::debug!("IPv6 source address: {}", src_addr);
                            log::debug!("{}", pretty_hex(&buf));

                            // TODO: IPv6 support
                        }
                    }
                },
                // handle packets that are outgoing through the WireGuard tunnel
                _ = tcp_handler.ready() => {
                    let ip_packet = if let Some(ip_packet) = tcp_handler.send().await.unwrap() {
                        ip_packet
                    } else {
                        continue;
                    };

                    let (mut result, dst_addr) = match ip_packet {
                        IpPacket::V4(mut packet) => {
                            let dst_ip = IpAddr::V4(Ipv4Addr::from(packet.dst_addr()));
                            let tcp_packet = TcpPacket::new_checked(packet.payload_mut()).unwrap();
                            let dst_addr = SocketAddr::new(dst_ip, tcp_packet.dst_port());

                            (self.tunn.encapsulate(&packet.into_inner(), &mut buf), dst_addr)
                        },
                        IpPacket::V6(_) => {
                            todo!()
                        }
                    };

                    while let TunnResult::WriteToNetwork(b) = result {
                        log::debug!("WireGuard: WriteToNetwork");
                        self.wg_send.send((b.to_vec(), dst_addr)).await.unwrap();

                        // check if there are more things to be handled
                        result = self.tunn.decapsulate(None, &[0; 0], &mut buf);
                    };

                    match result {
                        TunnResult::Done => {
                            log::debug!("WireGuard: Done");
                        },
                        TunnResult::Err(error) => {
                            log::error!("WireGuard Error: {:?}", error);
                        },
                        // all WriteToNetwork events should have been processed at this point
                        TunnResult::WriteToNetwork(_) => {
                            unreachable!();
                        },
                        // IPv4 packet
                        TunnResult::WriteToTunnelV4(_, _) => {
                            log::warn!("Unexpected WireGuard event (WriteToTunnelV4) when handling a response.");
                        },
                        // IPv6 packet
                        TunnResult::WriteToTunnelV6(_, _) => {
                            log::warn!("Unexpected WireGuard event (WriteToTunnelV6) when handling a response.");
                        }
                    }
                },
            );
        }
    }
}
