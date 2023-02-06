use std::iter;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bincode::{Decode, Encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::broadcast;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, Receiver, UnboundedReceiver, UnboundedSender};
use windows::core::PCWSTR;
use windows::w;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::Shell::SE_ERR_ACCESSDENIED;
use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};

use crate::intercept_conf::InterceptConf;
use crate::messages::{IpPacket, NetworkCommand, NetworkEvent, TunnelInfo};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};

pub const CONF: bincode::config::Configuration = bincode::config::standard();
pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 4;

#[derive(Decode, Encode, PartialEq, Eq, Debug)]
pub enum WindowsIpcRecv {
    Packet {
        data: Vec<u8>,
        pid: u32,
        process_name: Option<String>,
    },
}

#[derive(Decode, Encode, PartialEq, Eq, Debug)]
pub enum WindowsIpcSend {
    Packet(Vec<u8>),
    SetIntercept(InterceptConf),
}

pub struct WindowsConf {
    pub executable_path: PathBuf,
}

#[async_trait]
impl PacketSourceConf for WindowsConf {
    type Task = WindowsTask;
    type Data = UnboundedSender<WindowsIpcSend>;

    fn name(&self) -> &'static str {
        "Windows proxy"
    }

    async fn build(
        self,
        net_tx: Sender<NetworkEvent>,
        net_rx: Receiver<NetworkCommand>,
        sd_watcher: broadcast::Receiver<()>,
    ) -> Result<(WindowsTask, Self::Data)> {
        let pipe_name = format!(
            r"\\.\pipe\mitmproxy-transparent-proxy-{}",
            std::process::id()
        );

        let ipc_server = ServerOptions::new()
            .pipe_mode(PipeMode::Message)
            .first_pipe_instance(true)
            .max_instances(1)
            .in_buffer_size(IPC_BUF_SIZE as u32)
            .out_buffer_size(IPC_BUF_SIZE as u32)
            .reject_remote_clients(true)
            .create(&pipe_name)?;

        log::debug!("starting {} {}", self.executable_path.display(), pipe_name);

        let pipe_name = pipe_name
            .encode_utf16()
            .chain(iter::once(0))
            .collect::<Vec<u16>>();

        let executable_path = self
            .executable_path
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<u16>>();

        let result = unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                PCWSTR::from_raw(executable_path.as_ptr()),
                PCWSTR::from_raw(pipe_name.as_ptr()),
                None,
                if cfg!(debug_assertions) {
                    SW_SHOWNORMAL
                } else {
                    SW_HIDE
                },
            )
        };

        if cfg!(debug_assertions) {
            if result.0 <= 32 {
                let error_msg = unsafe { GetLastError().to_hresult().message().to_string_lossy() };
                log::warn!("Failed to start child process: {}", error_msg);
            }
        } else if result.0 == SE_ERR_ACCESSDENIED as isize {
            return Err(anyhow!(
                "Failed to start the interception process as administrator."
            ));
        } else if result.0 <= 32 {
            let error_msg = unsafe { GetLastError().to_hresult().message().to_string_lossy() };
            return Err(anyhow!("Failed to start the executable: {}", error_msg));
        }

        let (conf_tx, conf_rx) = unbounded_channel();

        Ok((
            WindowsTask {
                ipc_server,
                buf: [0u8; IPC_BUF_SIZE],
                net_tx,
                net_rx,
                conf_rx,
                sd_watcher,
            },
            conf_tx,
        ))
    }
}

pub struct WindowsTask {
    ipc_server: NamedPipeServer,
    buf: [u8; IPC_BUF_SIZE],

    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,
    conf_rx: UnboundedReceiver<WindowsIpcSend>,
    sd_watcher: broadcast::Receiver<()>,
}

#[async_trait]
impl PacketSourceTask for WindowsTask {
    async fn run(mut self) -> Result<()> {
        log::debug!("Waiting for IPC connection...");
        self.ipc_server.connect().await?;
        log::debug!("IPC connected!");

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.sd_watcher.recv() => break,
                // pipe through changes to the intercept list
                Some(cmd) = self.conf_rx.recv() => {
                    assert!(matches!(cmd, WindowsIpcSend::SetIntercept(_)));
                    let len = bincode::encode_into_slice(&cmd, &mut self.buf, CONF)?;
                    self.ipc_server.write_all(&self.buf[..len]).await?;
                },
                // read packets from the IPC pipe into our network stack.
                r = self.ipc_server.read(&mut self.buf) => {
                    let len = r.context("IPC read error.")?;
                    if len == 0 {
                        // https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
                        // Because the client is reading from the pipe in message-read mode, it is
                        // possible for the ReadFile operation to return zero after reading a partial
                        // message. This happens when the message is larger than the read buffer.
                        //
                        // We don't support messages larger than the buffer, so this cannot happen.
                        // Instead, empty reads indicate that the IPC client has disconnected.
                        return Err(anyhow!("redirect daemon exited prematurely."));
                    }
                    let Ok((WindowsIpcRecv::Packet { data, pid, process_name }, n)) = bincode::decode_from_slice(&self.buf[..len], CONF) else {
                        return Err(anyhow!("Received invalid IPC message: {:?}", &self.buf[..len]));
                    };
                    assert_eq!(n, len);
                    let Ok(mut packet) = IpPacket::try_from(data) else {
                        log::error!("Skipping invalid packet: {:?}", &self.buf[..len]);
                        continue;
                    };
                    // WinDivert packets do not have correct IP checksums yet, we need fix that here
                    // otherwise smoltcp will be unhappy with us.
                    packet.fill_ip_checksum();

                    let event = NetworkEvent::ReceivePacket {
                        packet,
                        tunnel_info: TunnelInfo::Windows {
                            pid,
                            process_name,
                        },
                    };
                    if self.net_tx.try_send(event).is_err() {
                        log::warn!("Dropping incoming packet, TCP channel is full.")
                    };
                },
                // write packets from the network stack to the IPC pipe to be reinjected.
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            let packet = WindowsIpcSend::Packet(packet.into_inner());
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
