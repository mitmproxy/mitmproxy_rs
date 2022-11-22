use std::iter;
use anyhow::{anyhow, Result, Context};
use async_trait::async_trait;
use bincode::{Decode, Encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::broadcast;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;
use windows::core::PCWSTR;
use windows::w;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};

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
    type Data = ();
    async fn build(
        self,
        net_tx: Sender<NetworkEvent>,
        net_rx: Receiver<NetworkCommand>,
        sd_watcher: broadcast::Receiver<()>,
    ) -> Result<(WinDivertTask, Self::Data)> {
        let pipe_name = format!(
            r"\\.\pipe\mitmproxy-transparent-proxy-{}",
            std::process::id()
        );

        log::warn!("pipe_name: {}", pipe_name);

        let ipc_server = ServerOptions::new()
            .pipe_mode(PipeMode::Message)
            .first_pipe_instance(true)
            .max_instances(1)
            .in_buffer_size(IPC_BUF_SIZE as u32)
            .out_buffer_size(IPC_BUF_SIZE as u32)
            .create(&pipe_name)?;


        let pipe_name = pipe_name
            .encode_utf16()
            .chain(iter::once(0))
            .collect::<Vec<u16>>();

        unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                w!(r"C:\Users\user\git\mitmproxy-wireguard\target\debug\windows-redirector.exe"),
                PCWSTR::from_raw(pipe_name.as_ptr()),
                None,
                if cfg!(debug_assertions) { SW_SHOWNORMAL } else { SW_HIDE }
            );
        }

        Ok((WinDivertTask {
            ipc_server,
            buf: [0u8; IPC_BUF_SIZE],
            net_tx,
            net_rx,
            sd_watcher,
        }, ()))
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

        log::debug!("Waiting for IPC connection...");
        self.ipc_server.connect().await?;
        log::debug!("IPC connected!");
        let msg = bincode::encode_to_vec(
            WinDivertIPC::InterceptExclude(vec![std::process::id()]),
            //WinDivertIPC::InterceptInclude(vec![8016]),
            CONF,
        )?;
        self.ipc_server.write_all(&msg).await?;

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.sd_watcher.recv() => break,
                // wait for WireGuard packets incoming on the UDP socket

                r = self.ipc_server.read(&mut self.buf) => {
                    let len = r.context("IPC read error.")?;
                    if len == 0 {
                        return Err(anyhow!("Empty IPC read."));
                    }
                    let Ok((WinDivertIPC::Packet(data), _)) = bincode::decode_from_slice(&self.buf[..len], CONF) else {
                        return Err(anyhow!("Received invalid IPC message: {:?}", &self.buf[..len]));
                    };
                    let Ok(mut packet) = IpPacket::try_from(data) else {
                        log::error!("Skipping invalid packet: {:?}", &self.buf[..len]);
                        continue;
                    };
                    // WinDivert packets do not have correct IP checksums yet, we need fix that here
                    // otherwise smoltcp will be unhappy with us.
                    packet.fill_ip_checksum();

                    let event = NetworkEvent::ReceivePacket {
                        packet,
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
                            let len = bincode::encode_into_slice(&packet, &mut self.buf, CONF)?;
                            self.ipc_server.write_all(&self.buf[..len]).await?;
                        }
                    }
                }
            }
        }

        log::info!("Windows OS proxy task shutting down.");
        Ok(())
    }
}
