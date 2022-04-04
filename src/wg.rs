use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::{Tunn, TunnResult};

use pretty_hex::pretty_hex;

use smoltcp::wire::{IpProtocol, Ipv4Packet, TcpPacket};

use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};

pub struct WgServer {
    addr: SocketAddr,
    sec_key: Arc<X25519SecretKey>,
    tunns: Vec<WgPeerTunn>,

    // incoming wireguard packets
    wg_push: broadcast::Sender<(SocketAddr, Vec<u8>)>,
    // outgoing wireguard packets
    wg_pull: mpsc::Sender<(SocketAddr, Vec<u8>)>,

    // outgoing TCP packets
    tcp_push: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    // incoming TCP packets
    tcp_pull: broadcast::Sender<(SocketAddr, Vec<u8>)>,

    // store single receivers for later use
    wg_puller: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    tcp_pusher: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
}

impl WgServer {
    pub fn new(addr: SocketAddr, sec_key: X25519SecretKey) -> WgServer {
        let (wg_push, _) = broadcast::channel(64);
        let (wg_pull, wg_puller) = mpsc::channel(64);
        let (tcp_push, tcp_pusher) = mpsc::channel(64);
        let (tcp_pull, _) = broadcast::channel(64);

        let server = WgServer {
            addr,
            tunns: Vec::new(),
            sec_key: Arc::new(sec_key),
            wg_push,
            wg_pull,
            tcp_push,
            tcp_pull,
            wg_puller,
            tcp_pusher,
        };

        server
    }

    pub fn add_peer(&mut self, pub_key: X25519PublicKey) -> Result<(), anyhow::Error> {
        let result = Tunn::new(self.sec_key.clone(), Arc::new(pub_key), None, Some(25), 0, None);

        match result {
            Ok(tunn) => {
                self.tunns.push(WgPeerTunn::from(tunn));
                Ok(())
            },
            Err(error) => Err(anyhow::anyhow!(error)),
        }
    }

    pub async fn serve(mut self) -> Result<(), anyhow::Error> {
        // spawn handlers for WireGuard peers
        for peer in self.tunns {
            tokio::spawn(peer.handle(
                self.wg_push.subscribe(),
                self.wg_pull.clone(),
                self.tcp_push.clone(),
                self.tcp_pull.subscribe(),
            ));
        }

        // spawn handler for virtual TCP interface
        // TODO

        // listen for incoming WireGuard connections
        let socket = UdpSocket::bind(self.addr).await?;
        let mut buf = [0u8; 1500];

        log::info!("Listening on {} for incoming connections.", &self.addr);

        loop {
            tokio::select!(
                // receive incoming WireGuard UDP packet and handle it
                ret = socket.recv_from(&mut buf) => {
                    let (read, addr) = ret.unwrap();
                    self.wg_push.send((addr, buf[..read].to_vec())).unwrap();
                },
                // send outgoing WireGuard UDP packet from queue
                ret = self.wg_puller.recv() => {
                    if let Some((addr, packet)) = ret {
                        socket.send_to(&packet, addr).await.unwrap();
                    }
                }
            )
        }
    }
}

struct WgPeerTunn {
    tunn: Box<Tunn>,
}

impl From<Box<Tunn>> for WgPeerTunn {
    fn from(tunn: Box<Tunn>) -> Self {
        WgPeerTunn { tunn }
    }
}

impl WgPeerTunn {
    async fn handle(
        self,
        mut wg_push: broadcast::Receiver<(SocketAddr, Vec<u8>)>,
        wg_pull: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        tcp_push: mpsc::Sender<(SocketAddr, Vec<u8>)>,
        mut tcp_pull: broadcast::Receiver<(SocketAddr, Vec<u8>)>,
    ) -> Result<(), anyhow::Error> {
        let mut wg_buf = [0u8; 1500];

        loop {
            tokio::select!(
                // wait for an incoming WireGuard UDP packet
                ret = wg_push.recv() => {
                    let (src_addr, datagram) = ret.unwrap();

                    // decode and handle incoming WireGuard packet(s) and handshake
                    let mut result = self.tunn.decapsulate(Some(src_addr.ip()), &datagram, &mut wg_buf);

                    loop {
                        match result {
                            TunnResult::WriteToNetwork(b) => {
                                log::debug!("WireGuard: WriteToNetwork");
                                wg_pull.send((src_addr, b.to_vec())).await.unwrap();
                            },
                            _ => break,
                        }

                        // check if there are more things to be handled
                        result = self.tunn.decapsulate(None, &[0; 0], &mut wg_buf);
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

                            let mut ip_packet = Ipv4Packet::new_checked(buf).unwrap();
                            if ip_packet.protocol() != IpProtocol::Tcp {
                                // TODO: handle IP packet types other than TCP?
                                log::debug!("Unsupported IPv4 packet type: {}", ip_packet.protocol());
                                continue;
                            }

                            let src_ip = ip_packet.src_addr();
                            let dst_ip = ip_packet.dst_addr();

                            log::debug!("WireGuard: IPv4 src address: {}", src_ip);
                            log::debug!("WireGuard: IPv4 dst address: {}", dst_ip);

                            let tcp_packet = TcpPacket::new_checked(ip_packet.payload_mut()).unwrap();
                            let sock_addr = SocketAddr::new(IpAddr::V4(src_ip.into()), tcp_packet.src_port());

                            tcp_push.send((sock_addr, ip_packet.into_inner().to_vec())).await.unwrap();
                        },
                        // IPv6 packet
                        TunnResult::WriteToTunnelV6(buf, src_addr) => {
                            log::debug!("IPv6 support not implemented yet.");
                            log::debug!("IPv6 source address: {}", src_addr);
                            log::debug!("{}", pretty_hex(&buf));
                        }
                    }
                },
                // wait for outgoing data
                ret = tcp_pull.recv() => {
                    let (dst_addr, packet) = ret.unwrap();

                    let mut result = self.tunn.encapsulate(&packet, &mut wg_buf);

                    // encode and handle outgoing WireGuard packet(s)
                    loop {
                        match result {
                            TunnResult::WriteToNetwork(b) => {
                                log::debug!("WireGuard: WriteToNetwork");
                                wg_pull.send((dst_addr, b.to_vec())).await.unwrap();
                            },
                            _ => break,
                        }

                        // check if there are more things to be handled
                        result = self.tunn.decapsulate(None, &[0; 0], &mut wg_buf);
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
