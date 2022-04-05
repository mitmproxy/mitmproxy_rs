use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use smoltcp::iface::{Interface, InterfaceBuilder, SocketHandle};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::Instant;
use smoltcp::wire::TcpPacket;

use tokio::sync::{broadcast, mpsc};

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
    pusher: mpsc::Receiver<TcpMessage>,
    puller: broadcast::Sender<TcpMessage>,
    handles: HashMap<SocketAddr, SocketHandle>,
    memory: HashMap<SocketHandle, (IpAddr, IpAddr)>,
    iface: VirtualInterface,
}

impl TcpHandler {
    pub fn new(pusher: mpsc::Receiver<TcpMessage>, puller: broadcast::Sender<TcpMessage>) -> TcpHandler {
        let handles = HashMap::new();
        let memory = HashMap::new();
        let iface = VirtualInterface::new();

        TcpHandler { pusher, puller, handles, memory, iface }
    }

    pub async fn handle(mut self) -> Result<(), anyhow::Error> {
        loop {
            if let Ok(true) = self.iface.iface.poll(Instant::now()) {
                tokio::select!(
                    // handle outgoing TCP packets
                    ret = self.pusher.recv() => {
                        if let Some(message) = ret {
                            let (src_ip, dst_ip, packet) = (message.src_ip, message.dst_ip, message.packet);
                            log::debug!("Outgoing TCP packet: {} -> {}: {:?}", src_ip, dst_ip, packet);

                            let _src_addr = SocketAddr::new(src_ip, packet.src_port());
                            let dst_addr = SocketAddr::new(dst_ip, packet.dst_port());

                            if packet.syn() {
                                let mut socket = TcpSocket::new(
                                    TcpSocketBuffer::new(vec![0u8; 4096]),
                                    TcpSocketBuffer::new(vec![0u8; 4096]),
                                );

                                socket.set_ack_delay(None);
                                socket.listen(dst_addr).unwrap();

                                let handle = self.iface.iface.add_socket(socket);
                                self.handles.insert(dst_addr, handle);
                                self.memory.insert(handle, (src_ip, dst_ip));
                            }

                            let fin = packet.fin();
                            self.iface.recv_packet(packet.into_inner());

                            if fin {
                                if let Some(handle) = self.handles.get(&dst_addr) {
                                    self.iface.iface.remove_socket(*handle);
                                }
                            }

                            while let Some(resp_packet) = self.iface.resp_packet() {
                                let pack = TcpPacket::new_checked(resp_packet).unwrap();
                                self.puller.send(TcpMessage::new(dst_ip, src_ip, pack)).unwrap();
                            }
                        }
                    },
                    // handle TCP response packets
                    /*
                    ret = std::future::ready(self.iface.resp_packet()) => {
                        if let Some(response) = ret {
                            // TODO: lookup src_addr, dst_addr based on which socket has received data
                            let resp_packet = TcpPacket::new_checked(response)?;
                            log::debug!("Response TCP packet: {:?}", resp_packet);
                            //self.puller.send((src_addr, resp_packet))?;
                        }
                    }
                    */
                )
            }

            if let Some(dur) = self.iface.iface.poll_delay(Instant::now()) {
                log::debug!("TCP poll delay: {}", dur);
                tokio::time::sleep(dur.into()).await;
            } else {
                // FIXME: Interface::poll_delay seems to always return `None`
                //        This statement was only added to avoid busy sleeping.
                tokio::time::sleep(Duration::from_millis(200)).await;
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
