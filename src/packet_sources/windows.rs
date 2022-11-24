use std::collections::HashSet;
use std::iter;

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
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};

use crate::messages::{IpPacket, NetworkCommand, NetworkEvent};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};
use crate::process::process_name;

pub const CONF: bincode::config::Configuration = bincode::config::standard();
pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 4;

pub type PID = u32;

#[derive(Decode, Encode, PartialEq, Eq, Debug)]
pub struct InterceptConf {
    pids: HashSet<PID>,
    process_names: Vec<String>,
    /// if true, matching items are the ones which are not intercepted.
    invert: bool,
}

impl InterceptConf {
    pub fn new(pids: Vec<PID>, process_names: Vec<String>, invert: bool) -> Self {
        let pids = HashSet::from_iter(pids.into_iter());
        if invert {
            assert!(!pids.is_empty() || !process_names.is_empty());
        }
        Self {
            pids,
            process_names,
            invert,
        }
    }

    pub fn should_intercept(&self, pid: PID) -> bool {
        self.invert ^ {
            if self.pids.contains(&pid) {
                return true;
            }
            if let Ok(name) = process_name(pid) {
                return self.process_names.iter().any(|n| name.contains(n));
            }
            false
        }
    }

    pub fn description(&self) -> String {
        if self.pids.is_empty() && self.process_names.is_empty() {
            return "Intercept nothing.".to_string();
        }
        let mut parts = vec![];
        if !self.pids.is_empty() {
            parts.push(format!("pids: {:?}", self.pids));
        }
        if !self.process_names.is_empty() {
            parts.push(format!("process names: {:?}", self.process_names));
        }
        let start = if self.invert {
            "Intercepting all packets but those from "
        } else {
            "Intercepting packets from "
        };
        format!("{}{}", start, parts.join(" or "))
    }
}

#[derive(Decode, Encode, PartialEq, Eq, Debug)]
pub enum WindowsIPC {
    Packet(Vec<u8>),
    SetIntercept(InterceptConf),
}

pub struct WindowsConf {
    pub executable_path: String,
}

#[async_trait]
impl PacketSourceConf for WindowsConf {
    type Task = WindowsTask;
    type Data = UnboundedSender<WindowsIPC>;
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
            .create(&pipe_name)?;

        let pipe_name = pipe_name
            .encode_utf16()
            .chain(iter::once(0))
            .collect::<Vec<u16>>();

        let executable_path = self
            .executable_path
            .encode_utf16()
            .chain(iter::once(0))
            .collect::<Vec<u16>>();

        unsafe {
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
            );
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
    conf_rx: UnboundedReceiver<WindowsIPC>,
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
                    assert!(matches!(cmd, WindowsIPC::SetIntercept(_)));
                    let len = bincode::encode_into_slice(&cmd, &mut self.buf, CONF)?;
                    self.ipc_server.write_all(&self.buf[..len]).await?;
                },
                // read packets from the IPC pipe into our network stack.
                r = self.ipc_server.read(&mut self.buf) => {
                    let len = r.context("IPC read error.")?;
                    if len == 0 {
                        return Err(anyhow!("Empty IPC read."));
                    }
                    let Ok((WindowsIPC::Packet(data), _)) = bincode::decode_from_slice(&self.buf[..len], CONF) else {
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
                // write packets from the network stack to the IPC pipe to be reinjected.
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            let packet = WindowsIPC::Packet(packet.into_inner());
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
