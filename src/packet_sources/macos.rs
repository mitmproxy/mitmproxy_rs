use std::iter;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use bincode::{Decode, Encode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe;
use tokio::sync::broadcast;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, Receiver, UnboundedReceiver, UnboundedSender};
use tun::Device;
use nix::{unistd::mkfifo, sys::stat::Mode};
// use windows::core::PCWSTR;
// use windows::w;
// use windows::Win32::Foundation::GetLastError;
// use windows::Win32::UI::Shell::ShellExecuteW;
// use windows::Win32::UI::Shell::SE_ERR_ACCESSDENIED;
// use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};

use crate::intercept_conf::InterceptConf;
use crate::messages::{IpPacket, NetworkCommand, NetworkEvent, TunnelInfo};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};

pub const CONF: bincode::config::Configuration = bincode::config::standard();
pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 4;

#[derive(Decode, Encode, PartialEq, Eq, Debug)]
pub enum MacosIpcRecv {
    Packet {
        data: Vec<u8>,
        pid: u32,
        process_name: Option<String>,
    },
}

#[derive(Decode, Encode, PartialEq, Eq, Debug)]
pub enum MacosIpcSend {
    Packet(Vec<u8>),
    SetIntercept(InterceptConf),
}

pub struct MacosConf;

#[async_trait]
impl PacketSourceConf for MacosConf {
    type Task = MacosTask;
    type Data = UnboundedSender<MacosIpcSend>;

    fn name(&self) -> &'static str {
        "Macos proxy"
    }

    async fn build(
        self,
        net_tx: Sender<NetworkEvent>,
        net_rx: Receiver<NetworkCommand>,
        sd_watcher: broadcast::Receiver<()>,
    ) -> Result<(MacosTask, Self::Data)> {
        
        // create tun device
        let gateway = "10.0.0.1";
        let netmask = "255.255.0.0";
        let mut config = tun::Configuration::default();
        config
            .layer(tun::Layer::L3)
            .address(gateway)
            .netmask(netmask)
            .up();

        let tun_device = match tun::create(&config) {
            Ok(dev) => dev,
            Err(e) => return Err(anyhow!("Tun creation failed: {:?}", e)),
        };

        //reset dns when terminate
        // #[cfg(target_os = "macos")]
        // tokio::spawn(async {
        //     use tokio::signal;
        //     if let Ok(_) = signal::ctrl_c().await {
        //         let _ = Command::new("networksetup")
        //             .args(["-setdnsservers", "Wi-Fi", "empty"])
        //             .output();
        //
        //         let _ = Command::new("route")
        //             .args(["-n", "delete", "default"])
        //             .output();
        //         let _ = Command::new("route")
        //             .args(["-n", "add", "default", "192.168.1.1"])
        //             .output();
        //         process::exit(0);
        //     }
        // });

        let _ = Command::new("route").args(["delete", "default"]).output();
        let _ = Command::new("route")
                .args(["-n", "add", "default", gateway])
                .output();

        //create the pipe
        let pipe_name = format!(
            r"\\.\pipe\mitmproxy-transparent-proxy-{}",
            std::process::id()
        );

        mkfifo(pipe_name.as_str(), Mode::S_IRWXU)?;

        let ipc_server = PipeServer::new(&pipe_name)?;

        //log::debug!("starting {} {}", self.executable_path.display(), pipe_name);

        // let pipe_name = pipe_name
        //     .encode_utf16()
        //     .chain(iter::once(0))
        //     .collect::<Vec<u16>>();
        //
        // let executable_path = self
        //     .executable_path
        //     .as_os_str()
        //     .encode_wide()
        //     .chain(iter::once(0))
        //     .collect::<Vec<u16>>();
        //
        // let result = unsafe {
        //     ShellExecuteW(
        //         None,
        //         w!("runas"),
        //         PCWSTR::from_raw(executable_path.as_ptr()),
        //         PCWSTR::from_raw(pipe_name.as_ptr()),
        //         None,
        //         if cfg!(debug_assertions) {
        //             SW_SHOWNORMAL
        //         } else {
        //             SW_HIDE
        //         },
        //     )
        // };

        // if cfg!(debug_assertions) {
        //     if result.0 <= 32 {
        //         let error_msg = unsafe { GetLastError().to_hresult().message().to_string_lossy() };
        //         log::warn!("Failed to start child process: {}", error_msg);
        //     }
        // } else if result.0 == SE_ERR_ACCESSDENIED as isize {
        //     return Err(anyhow!(
        //         "Failed to start the interception process as administrator."
        //     ));
        // } else if result.0 <= 32 {
        //     let error_msg = unsafe { GetLastError().to_hresult().message().to_string_lossy() };
        //     return Err(anyhow!("Failed to start the executable: {}", error_msg));
        // }
        //
        let (conf_tx, conf_rx) = unbounded_channel();

        Ok((
            MacosTask {
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

pub struct PipeServer{
    tx: pipe::Sender,
    rx: pipe::Receiver,
}
impl PipeServer {
    pub fn new(fifo_name: &str) -> Result<Self>{
       Ok(PipeServer{
            tx: pipe::OpenOptions::new().open_sender(fifo_name)?,
            rx: pipe::OpenOptions::new().open_receiver(fifo_name)?,
        })
    }
}

pub struct MacosTask {
    ipc_server: PipeServer,
    buf: [u8; IPC_BUF_SIZE],

    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,
    conf_rx: UnboundedReceiver<MacosIpcSend>,
    sd_watcher: broadcast::Receiver<()>,
}

#[async_trait]
impl PacketSourceTask for MacosTask {
    async fn run(mut self) -> Result<()> {
        log::debug!("Waiting for IPC connection...");
        // self.ipc_server.connect().await?;
        log::debug!("IPC connected!");

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.sd_watcher.recv() => break,
                // pipe through changes to the intercept list
                Some(cmd) = self.conf_rx.recv() => {
                    assert!(matches!(cmd, MacosIpcSend::SetIntercept(_)));
                    let len = bincode::encode_into_slice(&cmd, &mut self.buf, CONF)?;
                    self.ipc_server.tx.try_write(&self.buf[..len])?;
                },
                // read packets from the IPC pipe into our network stack.
                r = self.ipc_server.rx.read_exact(&mut self.buf) => {
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
                    let Ok((MacosIpcRecv::Packet { data, pid, process_name }, n)) = bincode::decode_from_slice(&self.buf[..len], CONF) else {
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
                        tunnel_info: TunnelInfo::Macos {
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
                            let packet = MacosIpcSend::Packet(packet.into_inner());
                            let len = bincode::encode_into_slice(&packet, &mut self.buf, CONF)?;
                            self.ipc_server.tx.try_write(&self.buf[..len])?;
                        }
                    }
                }
            }
        }

        log::info!("Macos OS proxy task shutting down.");
        Ok(())
    }
}
