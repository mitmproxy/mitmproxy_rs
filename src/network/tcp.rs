use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::{cmp, fmt};

use anyhow::Result;
use pretty_hex::pretty_hex;
use smoltcp::iface::{Config, SocketSet};
use smoltcp::socket::{tcp, Socket};
use smoltcp::wire::{HardwareAddress, Ipv6Address};
use smoltcp::{
    iface::{Interface, SocketHandle},
    time::Instant,
    wire::{IpAddress, IpCidr, Ipv4Address, TcpPacket},
};
use std::time::Duration;
use tokio::sync::{
    mpsc::{Permit, Sender},
    oneshot,
};

use crate::messages::{
    ConnectionId, ConnectionIdGenerator, NetworkCommand, SmolPacket, TransportCommand,
    TransportEvent, TunnelInfo,
};

use super::virtual_device::VirtualDevice;

/// Associated data for a smoltcp socket.
#[derive(Debug)]
struct SocketData {
    handle: SocketHandle,
    /// smoltcp can only operate with fixed-size buffers, but Python's stream implementation assumes
    /// an infinite buffer. So we have a second send buffer here, plus a boolean to indicate that
    /// we want to send a FIN.
    send_buffer: VecDeque<u8>,
    write_eof: bool,
    // Gets notified once there's data to be read.
    recv_waiter: Option<(u32, oneshot::Sender<Vec<u8>>)>,
    // Gets notified once there is enough space in the write buffer.
    drain_waiter: Vec<oneshot::Sender<()>>,
    addr_tuple: (SocketAddr, SocketAddr),
}

pub struct TcpHandler<'a> {
    connection_id_generator: ConnectionIdGenerator,
    iface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'a>,
    socket_data: HashMap<ConnectionId, SocketData>,
    remove_conns: Vec<ConnectionId>,
    active_connections: HashSet<(SocketAddr, SocketAddr)>,
}

impl TcpHandler<'_> {
    pub fn new(net_tx: Sender<NetworkCommand>) -> Self {
        let mut device = VirtualDevice::new(net_tx);

        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, Instant::now());

        iface.set_any_ip(true);

        iface.update_ip_addrs(|ip_address| {
            ip_address
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .unwrap();
            ip_address
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .unwrap();
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .unwrap();

        TcpHandler {
            iface,
            device,
            sockets: SocketSet::new(Vec::new()),
            socket_data: HashMap::new(),
            active_connections: HashSet::new(),
            connection_id_generator: ConnectionIdGenerator::tcp(),
            remove_conns: Vec::new(),
        }
    }

    pub fn receive_packet(
        &mut self,
        mut packet: SmolPacket,
        tunnel_info: TunnelInfo,
        permit: Permit<'_, TransportEvent>,
    ) -> Result<()> {
        let src_ip = packet.src_ip();
        let dst_ip = packet.dst_ip();

        let tcp_packet = match TcpPacket::new_checked(packet.payload_mut()) {
            // packet with correct length
            Ok(p) => {
                // packet with correct checksum
                if p.verify_checksum(&src_ip.into(), &dst_ip.into()) {
                    p
                } else {
                    // packet with incorrect checksum
                    log::warn!("Received invalid TCP packet (checksum error).");
                    return Ok(());
                }
            }
            // packet with incorrect length
            Err(e) => {
                log::debug!("Received invalid TCP packet ({}) with payload:", e);
                log::debug!("{}", pretty_hex(&packet.payload_mut()));
                return Ok(());
            }
        };

        let src_addr = SocketAddr::new(src_ip, tcp_packet.src_port());
        let dst_addr = SocketAddr::new(dst_ip, tcp_packet.dst_port());

        if tcp_packet.syn()
            && !tcp_packet.ack()
            && !self.active_connections.contains(&(src_addr, dst_addr))
        {
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
                tcp::SocketBuffer::new(vec![0u8; 64 * 1024]),
            );

            socket.listen(dst_addr)?;
            socket.set_timeout(Some(smoltcp::time::Duration::from_secs(60)));
            socket.set_keep_alive(Some(smoltcp::time::Duration::from_secs(28)));

            let handle = self.sockets.add(socket);

            let connection_id = self.connection_id_generator.next_id();

            let data = SocketData {
                handle,
                send_buffer: VecDeque::new(),
                write_eof: false,
                recv_waiter: None,
                drain_waiter: Vec::new(),
                addr_tuple: (src_addr, dst_addr),
            };
            self.socket_data.insert(connection_id, data);
            self.active_connections.insert((src_addr, dst_addr));

            let event = TransportEvent::ConnectionEstablished {
                connection_id,
                src_addr,
                dst_addr,
                tunnel_info,
                command_tx: None,
            };
            permit.send(event);
        }

        self.device.receive_packet(packet);
        Ok(())
    }

    pub fn poll_delay(&mut self) -> Option<Duration> {
        self.iface
            .poll_delay(Instant::now(), &self.sockets)
            .map(Duration::from)
    }

    pub fn handle_transport_command(&mut self, command: TransportCommand) {
        match command {
            TransportCommand::ReadData(id, n, tx) => self.read_data(id, n, tx),
            TransportCommand::WriteData(id, buf) => self.write_data(id, buf),
            TransportCommand::DrainWriter(id, tx) => self.drain_writer(id, tx),
            TransportCommand::CloseConnection(id, half_close) => {
                self.close_connection(id, half_close)
            }
        };
    }

    pub fn read_data(&mut self, id: ConnectionId, n: u32, tx: oneshot::Sender<Vec<u8>>) {
        if let Some(data) = self.socket_data.get_mut(&id) {
            assert!(data.recv_waiter.is_none());
            data.recv_waiter = Some((n, tx));
        } else {
            // connection is has already been removed because the connection is closed,
            // so we just drop the tx.
        }
    }

    pub fn write_data(&mut self, id: ConnectionId, buf: Vec<u8>) {
        if let Some(data) = self.socket_data.get_mut(&id) {
            data.send_buffer.extend(buf);
        } else {
            // connection is has already been removed because the connection is closed,
            // so we just ignore the write.
        }
    }

    pub fn drain_writer(&mut self, id: ConnectionId, tx: oneshot::Sender<()>) {
        if let Some(data) = self.socket_data.get_mut(&id) {
            data.drain_waiter.push(tx);
        } else {
            // connection is has already been removed because the connection is closed,
            // so we just drop the tx.
        }
    }

    pub fn close_connection(&mut self, id: ConnectionId, _half_close: bool) {
        if let Some(data) = self.socket_data.get_mut(&id) {
            // smoltcp does not have a good way to do a full close ("SHUT_RDWR"). We can't call
            // .abort() here because that sends a RST instead of a FIN (and breaks
            // retransmissions of the connection close packet). Alternatively, we could manually
            // set a timer on .close() and then forcibly .abort() once the timer expires (see
            // tcp-abort branch). This incurs a bit of unnecessary complexity, so we try something
            // dumber here: We simply close our end and then hope that either the client sends a FIN
            // or times out via the keepalive mechanism.

            data.write_eof = true;
        } else {
            // connection is already dead.
        }
    }

    pub fn poll(&mut self) -> Result<()> {
        // poll virtual network device
        #[cfg(debug_assertions)]
        log::debug!("Polling virtual network device ...");
        self.iface
            .poll(Instant::now(), &mut self.device, &mut self.sockets);

        // Process TCP socket I/O
        #[cfg(debug_assertions)]
        log::debug!("Processing TCP connections ...");
        self.process_tcp()?;

        // poll again. we may have new stuff to do.
        #[cfg(debug_assertions)]
        log::debug!("Polling virtual network device ...");
        self.iface
            .poll(Instant::now(), &mut self.device, &mut self.sockets);
        Ok(())
    }

    fn process_tcp(&mut self) -> Result<()> {
        for (connection_id, data) in self.socket_data.iter_mut() {
            let socket = self.sockets.get_mut::<tcp::Socket>(data.handle);

            // receive data over the socket
            if data.recv_waiter.is_some() {
                if socket.can_recv() {
                    let (n, tx) = data.recv_waiter.take().unwrap();
                    let bytes_available = socket.recv_queue();

                    let mut buf = vec![0u8; cmp::min(bytes_available, n as usize)];
                    let bytes_read = socket.recv_slice(&mut buf)?;

                    buf.truncate(bytes_read);
                    if tx.send(buf).is_err() {
                        log::debug!("Cannot send received data, channel was already closed.");
                    }
                } else {
                    // We can't use .may_recv() here as it returns false during establishment.
                    use tcp::State::*;
                    match socket.state() {
                        // can we still receive something in the future?
                        CloseWait | LastAck | Closed | Closing | TimeWait => {
                            let (_, tx) = data.recv_waiter.take().unwrap();
                            if tx.send(Vec::new()).is_err() {
                                log::debug!("Cannot send close, channel was already closed.");
                            }
                        }
                        _ => {}
                    }
                }
            }

            // send data over the socket
            if !data.send_buffer.is_empty() && socket.can_send() {
                let (a, b) = data.send_buffer.as_slices();
                let sent = socket.send_slice(a)? + socket.send_slice(b)?;
                data.send_buffer.drain(..sent);
            }

            // if necessary, drain write buffers:
            // either when drain has been requested explicitly, or when socket is being closed
            // TODO: benchmark different variants here. (e.g. only return on half capacity)
            if (!data.drain_waiter.is_empty() || data.write_eof)
                && socket.send_queue() < socket.send_capacity()
            {
                for waiter in data.drain_waiter.drain(..) {
                    if waiter.send(()).is_err() {
                        log::debug!("TcpStream already closed, cannot send notification about drained buffers.")
                    }
                }
            }

            #[cfg(debug_assertions)]
            log::debug!(
                "TCP connection {}: socket state {} for {:?}",
                connection_id,
                socket.state(),
                data.addr_tuple,
            );

            // if requested, close socket
            if data.write_eof && data.send_buffer.is_empty() {
                socket.close();
                data.write_eof = false;
            }

            // if socket is closed, mark connection for removal
            if socket.state() == tcp::State::Closed {
                self.remove_conns.push(*connection_id);
            }
        }

        for connection_id in self.remove_conns.drain(..) {
            let data = self.socket_data.remove(&connection_id).unwrap();
            self.sockets.remove(data.handle);
            self.active_connections.remove(&data.addr_tuple);
        }
        Ok(())
    }
}

impl fmt::Debug for TcpHandler<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sockets: Vec<String> = self
            .sockets
            .iter()
            .filter_map(|(_h, s)| match s {
                Socket::Tcp(s) => Some(s),
                _ => None,
            })
            .map(|sock| {
                format!(
                    "TCP {:<21} {:<21} {}",
                    sock.remote_endpoint()
                        .map(|e| e.to_string())
                        .as_ref()
                        .map_or("not connected", String::as_str),
                    sock.local_endpoint()
                        .map(|e| e.to_string())
                        .as_ref()
                        .map_or("not connected", String::as_str),
                    sock.state()
                )
            })
            .collect();

        f.debug_struct("NetworkIO")
            .field("sockets", &sockets)
            .finish()
    }
}
