use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use smoltcp::iface::{Interface, InterfaceBuilder, SocketHandle};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::TcpPacket;

#[derive(Clone, Debug)]
pub struct TcpMessage {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub packet: TcpPacket<Vec<u8>>,
}

impl TcpMessage {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, packet: TcpPacket<Vec<u8>>) -> TcpMessage {
        TcpMessage { src_ip, dst_ip, packet }
    }
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

    // receive a TCP packet over the WireGuard tunnel
    pub async fn recv(&mut self, message: TcpMessage) -> Result<Vec<TcpMessage>, anyhow::Error> {
        let (src_ip, dst_ip, packet) = (message.src_ip, message.dst_ip, message.packet);
        log::debug!("Outgoing TCP packet: {} -> {}: {:?}", src_ip, dst_ip, packet);

        let _src_addr = SocketAddr::new(src_ip, packet.src_port());
        let dst_addr = SocketAddr::new(dst_ip, packet.dst_port());

        let syn = packet.syn();
        let fin = packet.fin();

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
        }

        self.iface.recv_packet(packet.into_inner());

        if fin {
            if let Some(handle) = self.handles.get(&dst_addr) {
                self.iface.iface.remove_socket(*handle);
            }
        }

        let mut responses = Vec::new();
        while let Some(resp_packet) = self.iface.resp_packet() {
            let packet = TcpPacket::new_checked(resp_packet)?;
            responses.push(TcpMessage::new(dst_ip, src_ip, packet));
        }

        Ok(responses)
    }

    // send a TCP packet over the WireGuard tunnel
    pub async fn send(&mut self) -> Result<TcpMessage, anyhow::Error> {
        todo!()
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
        // TODO: actually receive packet
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
        // TODO: actually send packet
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
