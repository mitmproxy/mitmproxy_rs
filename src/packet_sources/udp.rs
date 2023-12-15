use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Result;
use async_trait::async_trait;

use tokio::sync::mpsc::{Permit, UnboundedReceiver};
use tokio::{
    net::UdpSocket,
    sync::{broadcast, mpsc::Sender},
};

use crate::messages::{TransportCommand, TransportEvent, TunnelInfo};
use crate::network::udp::{UdpHandler, UdpPacket};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};

pub struct UdpConf {
    pub host: String,
    pub port: u16,
}

#[async_trait]
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
        shutdown: broadcast::Receiver<()>,
    ) -> Result<(Self::Task, Self::Data)> {
        // bind to UDP socket(s)

        let socket_addrs = if self.host.is_empty() {
            vec![
                // Windows quirks: We need to bind to 127.0.0.1 explicitly for IPv4.
                #[cfg(windows)]
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), self.port),
                #[cfg(not(windows))]
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.port),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), self.port),
            ]
        } else {
            vec![SocketAddr::new(self.host.parse()?, self.port)]
        };

        let socket = UdpSocket::bind(socket_addrs.as_slice()).await?;
        let local_addr = socket.local_addr()?;

        log::debug!(
            "UDP server listening on {} ...",
            socket_addrs
                .iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<String>>()
                .join(" and ")
        );

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
    shutdown: broadcast::Receiver<()>,
}

#[async_trait]
impl PacketSourceTask for UdpTask {
    async fn run(mut self) -> Result<()> {
        let transport_events_tx = self.transport_events_tx.clone();
        let mut udp_buf = [0; MAX_PACKET_SIZE];

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
                    continue;
                },
                // ... or process incoming packets
                Ok((len, src_addr)) = self.socket.recv_from(&mut udp_buf), if py_tx_available => {
                    self.process_incoming_datagram(&udp_buf[..len], src_addr, permit.take().unwrap()).await?;
                },
                // send_to is cancel safe, so we can use that for backpressure.
                _ = self.socket.send_to(&packet_payload, packet_dst), if packet_needs_sending => {
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

impl UdpTask {
    async fn process_incoming_datagram(
        &mut self,
        data: &[u8],
        sender_addr: SocketAddr,
        permit: Permit<'_, TransportEvent>,
    ) -> Result<()> {
        let packet = UdpPacket {
            src_addr: sender_addr,
            dst_addr: self.local_addr,
            payload: data.to_vec(),
        };
        let tunnel_info = TunnelInfo::WireGuard {
            src_addr: sender_addr,
            dst_addr: self.socket.local_addr()?,
        };
        self.handler.receive_data(packet, tunnel_info, permit);
        Ok(())
    }
}
