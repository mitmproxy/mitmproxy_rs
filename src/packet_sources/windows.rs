use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::broadcast;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;

use crate::messages::{IpPacket, NetworkCommand, NetworkEvent};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::{PacketSourceBuilder, PacketSourceTask};
use std::net::SocketAddr;

use std::str::FromStr;

pub struct WindowsBuilder {
    server: NamedPipeServer,
}

const PIPE_NAME: &str = r"\\.\pipe\mitmproxy-transparent-proxy";

impl WindowsBuilder {
    pub fn new() -> Result<Self> {
        let server = ServerOptions::new()
            .pipe_mode(PipeMode::Message)
            .first_pipe_instance(true)
            .max_instances(1)
            .in_buffer_size((MAX_PACKET_SIZE + 1) as u32)
            .out_buffer_size((MAX_PACKET_SIZE + 1) as u32)
            .create(PIPE_NAME)?;

        Ok(WindowsBuilder { server })
    }
}

impl PacketSourceBuilder for WindowsBuilder {
    type Task = WindowsTask;
    fn build(
        self,
        net_tx: Sender<NetworkEvent>,
        net_rx: Receiver<NetworkCommand>,
        sd_watcher: broadcast::Receiver<()>,
    ) -> WindowsTask {
        WindowsTask {
            server: self.server,
            read_buf: [0u8; MAX_PACKET_SIZE + 1],

            net_tx,
            net_rx,
            sd_watcher,
        }
    }
}

pub struct WindowsTask {
    server: NamedPipeServer,
    read_buf: [u8; MAX_PACKET_SIZE + 1],

    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,
    sd_watcher: broadcast::Receiver<()>,
}

#[async_trait]
impl PacketSourceTask for WindowsTask {
    async fn run(mut self) -> Result<()> {
        log::info!("{:?}", self.server.info());

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.sd_watcher.recv() => break,
                // wait for WireGuard packets incoming on the UDP socket

                Ok(size) = self.server.read(&mut self.read_buf) => {

                    let packet = match IpPacket::try_from(self.read_buf[..size].to_vec()) {
                        Ok(packet) => packet,
                        Err(e) => {
                            log::error!("Error parsing packet: {}", e);
                            continue;
                        }
                    };

                    let event = NetworkEvent::ReceivePacket {
                        packet,
                        src_orig: SocketAddr::from_str("0.0.0.0:1234").unwrap(),
                    };

                    if self.net_tx.try_send(event).is_err() {
                        log::warn!("Dropping incoming packet, TCP channel is full.")
                    };
                }
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            self.server.write(&packet.into_inner()).await?;
                        }
                    }
                }
            }
        }

        log::debug!("Windows OS proxy task shutting down.");
        Ok(())
    }
}
