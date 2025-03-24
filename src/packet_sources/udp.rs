use std::net::{Ipv4Addr, SocketAddr};

use anyhow::{Context, Result};

use crate::messages::{TransportCommand, TransportEvent, TunnelInfo};
use crate::network::udp::{UdpHandler, UdpPacket};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};
use crate::shutdown;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Permit, Sender, UnboundedReceiver};

pub fn remote_host_closed_conn<T>(_res: &Result<T, std::io::Error>) -> bool {
    #[cfg(windows)]
    if let Err(e) = _res {
        // Workaround for https://stackoverflow.com/a/73792103:
        // We get random errors here on Windows if a previous send() failed.
        const REMOTE_HOST_CLOSED_CONN_ERR: i32 = 10054;
        return matches!(e.raw_os_error(), Some(REMOTE_HOST_CLOSED_CONN_ERR));
    }
    false
}

/// Creates a nonblocking UDP socket bound to the specified address, restricted to either IPv4 or IPv6 only.
pub(crate) fn create_and_bind_udp_socket(addr: SocketAddr) -> Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    // We use socket2::Socket to set IPV6_V6ONLY and convert back to std::net::UdpSocket
    let sock2 = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    // Ensure that IPv6 sockets listen on IPv6 only
    if addr.is_ipv6() {
        sock2
            .set_only_v6(true)
            .context("Failed to set IPV6_V6ONLY flag")?;
    }

    sock2
        .bind(&addr.into())
        .context(format!("Failed to bind UDP socket to {}", addr))?;

    let std_sock: std::net::UdpSocket = sock2.into();
    std_sock
        .set_nonblocking(true)
        .context("Failed to make UDP socket non-blocking")?;
    let socket = UdpSocket::from_std(std_sock)?;

    Ok(socket)
}

pub struct UdpConf {
    pub listen_addr: SocketAddr,
}

impl PacketSourceConf for UdpConf {
    type Task = UdpTask;
    type Data = SocketAddr;

    fn name(&self) -> &'static str {
        "UDP server"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> Result<(Self::Task, Self::Data)> {
        let socket = create_and_bind_udp_socket(self.listen_addr)?;
        let local_addr: SocketAddr = socket.local_addr()?;

        log::debug!("UDP server listening on {} ...", local_addr);

        Ok((
            UdpTask {
                socket,
                local_addr,
                handler: UdpHandler::new(),
                transport_events_tx,
                transport_commands_rx,
                shutdown,
            },
            local_addr,
        ))
    }
}

pub struct UdpTask {
    socket: UdpSocket,
    local_addr: SocketAddr,

    handler: UdpHandler,

    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    shutdown: shutdown::Receiver,
}

impl PacketSourceTask for UdpTask {
    async fn run(mut self) -> Result<()> {
        let transport_events_tx = self.transport_events_tx.clone();
        let mut udp_buf = vec![0; MAX_PACKET_SIZE];

        let mut packet_needs_sending = false;
        let mut packet_payload = Vec::new();
        let mut packet_dst = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));

        let mut permit: Option<Permit<TransportEvent>> = None;

        loop {
            let py_tx_available = permit.is_some();

            tokio::select! {
                // wait for graceful shutdown
                _ = self.shutdown.recv() => break,
                // wait for transport_events_tx channel capacity...
                Ok(p) = transport_events_tx.reserve(), if !py_tx_available => {
                    permit = Some(p);
                },
                // ... or process incoming packets
                r = self.socket.recv_from(udp_buf.as_mut_slice()), if py_tx_available => {
                    if remote_host_closed_conn(&r) {
                        continue;
                    }
                    let (len, src_addr) = r.context("UDP recv() failed")?;
                    self.handler.receive_data(
                        UdpPacket {
                            src_addr,
                            dst_addr: self.local_addr,
                            payload: udp_buf[..len].to_vec(),
                        },
                        TunnelInfo::None {},
                        permit.take().unwrap()
                    );
                },
                // send_to is cancel safe, so we can use that for backpressure.
                r = self.socket.send_to(&packet_payload, packet_dst), if packet_needs_sending => {
                    let sent = r.context("UDP send_to() failed")?;
                    if sent != packet_payload.len() {
                        log::debug!("socket.send_to: {} of {} bytes sent.", sent, packet_payload.len());
                    }
                    packet_needs_sending = false;
                },
                Some(command) = self.transport_commands_rx.recv(), if !packet_needs_sending => {
                    if let Some(UdpPacket { payload, dst_addr, .. }) = self.handler.handle_transport_command(command) {
                        packet_payload = payload;
                        packet_dst = dst_addr;
                        packet_needs_sending = true;
                    }
                }
            }
        }
        log::debug!("UDP server task shutting down.");
        Ok(())
    }
}
