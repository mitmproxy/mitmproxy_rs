use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bincode::{Decode, Encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::broadcast;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};
use windows::w;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

use crate::messages::{IpPacket, NetworkCommand, NetworkEvent};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};

pub const CONF: bincode::config::Configuration = bincode::config::standard();
pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 4;

pub type PID = u32;

#[derive(Decode, Encode, PartialEq, Eq, Debug)]
pub enum WinDivertIPC {
    Packet(Vec<u8>),
    InterceptInclude(Vec<PID>),
    InterceptExclude(Vec<PID>),
    Shutdown,
}

pub struct WinDivertConf {}

#[async_trait]
impl PacketSourceConf for WinDivertConf {
    type Task = WinDivertTask;
    async fn build(
        self,
        net_tx: Sender<NetworkEvent>,
        net_rx: Receiver<NetworkCommand>,
        sd_watcher: broadcast::Receiver<()>,
    ) -> Result<WinDivertTask> {
        let _pipe_name = format!(
            r"\\.\pipe\mitmproxy-transparent-proxy-{}",
            std::process::id()
        );
        // FIXME
        let pipe_name = r"\\.\pipe\mitmproxy-transparent-proxy";

        let mut ipc_server = ServerOptions::new()
            .pipe_mode(PipeMode::Message)
            .first_pipe_instance(true)
            //.max_instances(2)
            .in_buffer_size(IPC_BUF_SIZE as u32)
            .out_buffer_size(IPC_BUF_SIZE as u32)
            .create(pipe_name)?;

        unsafe {
            ShellExecuteW(None, w!("runas"), w!("cmd.exe"), None, None, SW_SHOWNORMAL);
        }

        ipc_server.connect().await?;
        let msg = bincode::encode_to_vec(
            WinDivertIPC::InterceptExclude(vec![std::process::id()]),
            CONF,
        )?;
        ipc_server.write_all(&msg).await?;

        Ok(WinDivertTask {
            ipc_server,
            buf: [0u8; IPC_BUF_SIZE],
            net_tx,
            net_rx,
            sd_watcher,
        })
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
