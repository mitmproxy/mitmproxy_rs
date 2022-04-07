use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use anyhow::Context;

use pretty_hex::pretty_hex;
use smoltcp::iface::{Interface, InterfaceBuilder, SocketHandle};
use smoltcp::phy::{ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{Socket, TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, Ipv6Packet, TcpPacket};

#[allow(unused)]
pub enum IpPacket {
    V4(Ipv4Packet<Vec<u8>>),
    V6(Ipv6Packet<Vec<u8>>),
}

pub struct TcpHandler {
    handles: HashMap<SocketAddr, SocketHandle>,
    memory: HashMap<SocketHandle, (IpAddr, IpAddr)>,
    iface: VirtualInterface,
}

impl TcpHandler {
    pub fn new() -> TcpHandler {
        let handles = HashMap::new();
        let memory = HashMap::new();
        let iface = VirtualInterface::new();

        TcpHandler { handles, memory, iface }
    }

    // receive an IPv4 TCP packet over the WireGuard tunnel
    pub async fn recv4(
        &mut self,
        mut ip_packet: Ipv4Packet<Vec<u8>>,
    ) -> Result<Vec<Ipv4Packet<Vec<u8>>>, anyhow::Error> {
        let tcp_packet = TcpPacket::new_checked(
            ip_packet.payload_mut().to_vec()
        ).context("invalid TCP packet")?;

        let src_ip = IpAddr::V4(Ipv4Addr::from(ip_packet.src_addr()));
        let dst_ip = IpAddr::V4(Ipv4Addr::from(ip_packet.dst_addr()));

        log::debug!(
            "Outgoing IPv4 TCP packet: {} -> {}",
            src_ip,
            dst_ip
        );
        log::debug!("{}", pretty_hex(&ip_packet.payload_mut()));

        let dst_addr = SocketAddr::new(dst_ip, tcp_packet.dst_port());

        let syn = tcp_packet.syn();
        let fin = tcp_packet.fin();

        if syn {
            let mut socket = TcpSocket::new(
                TcpSocketBuffer::new(vec![0u8; 4096]),
                TcpSocketBuffer::new(vec![0u8; 4096]),
            );

            socket.set_ack_delay(None);
            socket.listen(dst_addr)?;

            let handle = self.iface.iface.add_socket(socket);
            self.handles.insert(dst_addr, handle);
            self.memory.insert(handle, (src_ip, dst_ip));

            // TODO: create connections with read/write streams for each new socket
            //       take connection handler as callback function and pass read/write streams
        }

        self.iface.recv_packet(ip_packet.into_inner().to_vec());

        if fin {
            if let Some(handle) = self.handles.get(&dst_addr) {
                self.iface.iface.remove_socket(*handle);
            }
        }

        let mut responses = Vec::new();
        while let Some(resp_packet) = self.iface.resp_packet() {
            let packet = Ipv4Packet::new_checked(resp_packet)?;
            responses.push(packet);
        }

        Ok(responses)
    }

    /*
    // receive an IPv6 TCP packet over the WireGuard tunnel
    pub async fn recv6(
        &mut self,
        mut _ip_packet: Ipv6Packet<Vec<u8>>,
    ) -> Result<Vec<Ipv6Packet<Vec<u8>>>, anyhow::Error> {
        todo!()
    }
    */

    // send an IPv4 or IPv6 TCP packet over the WireGuard tunnel
    pub async fn send(&mut self) -> Result<Option<IpPacket>, anyhow::Error> {
        for (handle, socket) in self.iface.iface.sockets_mut() {
            match socket {
                Socket::Tcp(s) => {
                    if s.can_recv() {
                        let (dst_addr, src_addr) = self.memory.get(&handle).unwrap();

                        match (dst_addr, src_addr) {
                            (IpAddr::V4(dst_addr), IpAddr::V4(src_addr)) => {
                                let mut buf = [0u8; 1500];
                                let size = s.recv_slice(&mut buf).unwrap();

                                // construct Ipv4 packet
                                let repr = Ipv4Repr {
                                    src_addr: Ipv4Address::from(*src_addr),
                                    dst_addr: Ipv4Address::from(*dst_addr),
                                    protocol: IpProtocol::Tcp,
                                    payload_len: size,
                                    hop_limit: 64,
                                };

                                let buffer = vec![0u8; repr.buffer_len() + repr.payload_len];
                                let mut ip_packet = Ipv4Packet::new_unchecked(buffer);
                                repr.emit(&mut ip_packet, &ChecksumCapabilities::default());

                                return Ok(Some(IpPacket::V4(ip_packet)));
                            },
                            (IpAddr::V6(_dst_addr), IpAddr::V6(_src_addr)) => {
                                log::debug!("IPv6 packets not supported yet.");
                                // TODO: IPv6 support
                            },
                            _ => {
                                log::error!("Unsupported address pair: mixed IPv4 / IPv6");
                            },
                        }
                    }
                },
                _ => log::error!("Unsupported socket type: {:?}", socket),
            }
        }

        Ok(None)
    }

    fn poll(&mut self, timestamp: Instant) -> smoltcp::Result<bool> {
        self.iface.iface.poll(timestamp)
    }

    async fn wait(&mut self) {
        if let Some(dur) = self.iface.iface.poll_delay(Instant::now()) {
            log::debug!("TCP poll delay: {}", dur);
            tokio::time::sleep(dur.into()).await;
        } else {
            // FIXME: Interface::poll_delay seems to always (?) return `None`.
            //        This statement was only added to avoid busy sleeping in this case.
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub async fn ready(&mut self) {
        loop {
            if let Ok(true) = self.poll(Instant::now()) {
                return;
            } else {
                self.wait().await
            }
        }
    }
}

struct VirtualInterface {
    iface: Interface<'static, VirtualDevice>,
}

impl VirtualInterface {
    /// construct a new virtual TCP interface
    pub fn new() -> VirtualInterface {
        let device = VirtualDevice::default();
        let builder = InterfaceBuilder::new(device, Vec::new());
        let iface = builder.any_ip(true).finalize();

        VirtualInterface { iface }
    }

    /// add a received packet
    pub fn recv_packet(&mut self, packet: Vec<u8>) {
        self.iface.device_mut().recv_packet(packet)
    }

    /// get a response packet
    pub fn resp_packet(&mut self) -> Option<Vec<u8>> {
        self.iface.device_mut().resp_packet()
    }
}

#[derive(Debug, Default)]
struct VirtualDevice {
    rx_buffer: VecDeque<Vec<u8>>,
    tx_buffer: VecDeque<Vec<u8>>,
}

impl VirtualDevice {
    pub fn recv_packet(&mut self, packet: Vec<u8>) {
        self.rx_buffer.push_back(packet);
    }

    pub fn resp_packet(&mut self) -> Option<Vec<u8>> {
        self.tx_buffer.pop_front()
    }
}

#[derive(Debug)]
struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(&mut self.buffer)
    }
}

#[derive(Debug)]
struct VirtualTxToken<'a> {
    device: &'a mut VirtualDevice,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);
        self.device.tx_buffer.push_back(buffer);
        result
    }
}

impl<'a> Device<'a> for VirtualDevice {
    type RxToken = VirtualRxToken;
    type TxToken = VirtualTxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        if let Some(buffer) = self.rx_buffer.pop_front() {
            let rx = Self::RxToken { buffer };
            let tx = Self::TxToken { device: self };
            Some((rx, tx))
        } else {
            None
        }
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        Some(VirtualTxToken { device: self })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}
