use std::process::Command;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use std::fs;
use std::path::{Path, PathBuf};
//use bincode::{Decode, Encode};
use nix::{sys::stat::Mode, unistd::mkfifo};
use tokio::io::AsyncReadExt;
use tokio::net::unix::pipe;
use tokio::sync::broadcast;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, Receiver, UnboundedReceiver, UnboundedSender};

use crate::intercept_conf::InterceptConf;
use crate::messages::{IpPacket, NetworkCommand, NetworkEvent, TunnelInfo};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};
use home::home_dir;
use prost::Message;
use std::io::Cursor;

//pub const CONF: bincode::config::Configuration = bincode::config::standard();
pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 4;

pub mod raw_packet {
    include!(concat!(env!("OUT_DIR"), "/mitmproxy.raw_packet.rs"));
}

pub fn serialize_packet(raw_packet: &raw_packet::Packet) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.reserve(raw_packet.encoded_len());
    // Unwrap is safe, since we have reserved sufficient capacity in the vector.
    raw_packet.encode(&mut buf).unwrap();
    buf
}

pub fn deserialize_packet(buf: &[u8]) -> Result<MacosIpcRecv, prost::DecodeError> {
    if let Ok(packet) = raw_packet::Packet::decode(&mut Cursor::new(buf)) {
        return Ok(MacosIpcRecv::Packet {
            data: packet.data,
            process_name: Some(packet.process_name),
        });
    } else {
        return Err(prost::DecodeError::new("Failed to decode packet"));
    }
}

pub struct PipeServer {
    tx: pipe::Sender,
    rx: pipe::Receiver,
    path: PathBuf,
}

impl PipeServer {
    pub fn new(fifo_name: &str) -> Result<Self> {
        let home_dir = home_dir().unwrap();
        let fifo_path = Path::new(&home_dir).join(format!("Downloads/{}.pipe", &fifo_name));
        match mkfifo(&fifo_path, Mode::S_IRWXU) {
            Ok(_) => println!("created {:?}", fifo_path),
            Err(err) => println!("Error creating fifo: {}", err),
        }
        Ok(PipeServer {
            tx: pipe::OpenOptions::new().open_sender(&fifo_path)?,
            rx: pipe::OpenOptions::new().open_receiver(&fifo_path)?,
            path: fifo_path,
        })
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum MacosIpcRecv {
    Packet {
        data: Vec<u8>,
        process_name: Option<String>,
    },
}

#[derive(PartialEq, Eq, Debug)]
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

        let executable_path = "/Applications/MitmproxyAppleTunnel.app/";
        // copy_dir(
        //     Path::new("../apple-tunnel/MitmproxyAppleTunnel.app/"),
        //     Path::new(executable_path),
        // )?;

        // create new fifo and give read, write and execute rights to the owner

        let ipc_server = PipeServer::new("mitmproxy")?;

        log::debug!("starting {}", executable_path);

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

        let result = Command::new("open")
            .arg("-a")
            .arg(executable_path)
            .arg("--args")
            .arg(&ipc_server.path)
            .spawn()?;

        if let Some(err) = result.stderr {
            log::warn!("Failed to start child process: {:?}", err);
        }

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
                // Some(cmd) = self.conf_rx.recv() => {
                //     assert!(matches!(cmd, MacosIpcSend::SetIntercept(_)));
                //     let len = bincode::encode_into_slice(&cmd, &mut self.buf, CONF)?;
                //     self.ipc_server.tx.try_write(&self.buf[..len])?;
                // },
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

                    //let (splitted_msg, _) = &msg.split_at(n);
                    let Ok(MacosIpcRecv::Packet { data, process_name })  = deserialize_packet(&self.buf[..len]) else {
                        return Err(anyhow!("Received invalid IPC message: {:?}", &self.buf[..len]));
                    };
                    //println!("{:?}", raw_packet.title);
                    //msg.truncate(n);

                    //let Ok((MacosIpcRecv::Packet { data, pid, process_name }, n)) = bincode::decode_from_slice(&self.buf[..len], CONF) else {
                        //return Err(anyhow!("Received invalid IPC message: {:?}", &self.buf[..len]));
                    //};
                    //assert_eq!(n, len);
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
                            process_name,
                        },
                    };
                    if self.net_tx.try_send(event).is_err() {
                        log::warn!("Dropping incoming packet, TCP channel is full.")
                    };
                },
                // write packets from the network stack to the IPC pipe to be reinjected.
                // Some(e) = self.net_rx.recv() => {
                //     match e {
                //         NetworkCommand::SendPacket(packet) => {
                //             let packet = MacosIpcSend::Packet(packet.into_inner());
                //             let len = bincode::encode_into_slice(&packet, &mut self.buf, CONF)?;
                //             self.ipc_server.tx.try_write(&self.buf[..len])?;
                //         }
                //     }
                // }
            }
        }

        log::info!("Macos OS proxy task shutting down.");
        Ok(())
    }
}
