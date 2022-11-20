
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bincode::{Encode, Decode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer};
use tokio::sync::broadcast;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};

use crate::messages::{IpPacket, NetworkCommand, NetworkEvent};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::{PacketSourceBuilder, PacketSourceTask};


pub const CONF: bincode::config::Configuration = bincode::config::standard();
pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 4;


pub type PID = u32;

#[derive(Decode, Encode, PartialEq, Debug)]
pub enum WinDivertIPC {
    Packet(Vec<u8>),
    InterceptInclude(Vec<PID>),
    InterceptExclude(Vec<PID>),
    Shutdown,
}


pub struct WinDivertBuilder {
    ipc_server: NamedPipeServer,
}

impl WinDivertBuilder {
    pub fn new(ipc_server: NamedPipeServer) -> Self {
        WinDivertBuilder { ipc_server }
    }
}

impl PacketSourceBuilder for WinDivertBuilder {
    type Task = WinDivertTask;
    fn build(
        self,
        net_tx: Sender<NetworkEvent>,
        net_rx: Receiver<NetworkCommand>,
        sd_watcher: broadcast::Receiver<()>,
    ) -> WinDivertTask {
        WinDivertTask {
            ipc_server: self.ipc_server,
            buf: [0u8; IPC_BUF_SIZE],
            net_tx,
            net_rx,
            sd_watcher,
        }
    }
}

pub struct WinDivertTask {
    ipc_server: NamedPipeServer,
    buf: [u8; IPC_BUF_SIZE],

    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,
    sd_watcher: broadcast::Receiver<()>,
}

#[async_trait]
impl PacketSourceTask for WinDivertTask {
    async fn run(mut self) -> Result<()> {
        log::info!("{:?}", self.ipc_server.info());

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.sd_watcher.recv() => break,
                // wait for WireGuard packets incoming on the UDP socket

                Ok(()) = self.ipc_server.readable() => {
                    let len = match self.ipc_server.read(&mut self.buf).await {
                        Ok(len) => len,
                        Err(error) => {
                            log::error!("Failed to read from IPC server: {}", error);
                            0
                        }
                    };
                    if len == 0 {
                        log::error!("IPC pipe empty");
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    let WinDivertIPC::Packet(data) = bincode::decode_from_slice(&self.buf[..len], CONF)?.0 else {
                        return Err(anyhow!("Received invalid IPC message: {:?}", &self.buf[..len]));
                    };
                    let event = NetworkEvent::ReceivePacket {
                        packet: IpPacket::try_from(data)?,
                        src_orig: None,
                    };
                    if self.net_tx.try_send(event).is_err() {
                        log::warn!("Dropping incoming packet, TCP channel is full.")
                    };
                },
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            let packet = WinDivertIPC::Packet(packet.into_inner());
                            let msg = bincode::encode_to_vec(packet, CONF)?;
                            self.ipc_server.write_all(&msg).await?;
                        }
                    }
                }
            }
        }

        log::info!("Windows OS proxy task shutting down.");
        Ok(())
    }
}
