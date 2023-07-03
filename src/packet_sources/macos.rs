use std::process::Command;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use nix::errno::Errno;
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
    pub async fn new(fifo_name: &str) -> Result<Self> {
        let home_dir = match home_dir() {
            Some(path) => path,
            None => Err(anyhow!("Failed to get home directory"))?,
        };

        let path = Path::new(&home_dir).join(format!("Downloads/{}.pipe", &fifo_name));
        if !path.exists() {
            match mkfifo(&path, Mode::S_IRWXU) {
                Ok(_) => println!("created {:?}", path),
                Err(e) => Err(anyhow!("Failed to create fifo: {:?}", e))?,
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

        let rx = match pipe::OpenOptions::new()
            .unchecked(true)
            .open_receiver(&path)
        {
            Ok(rx) => rx,
            Err(e) => Err(anyhow!("Failed to open fifo receiver: {:?}", e))?,
        };

        let tx = match pipe::OpenOptions::new().unchecked(true).open_sender(&path) {
            Ok(tx) => tx,
            Err(e) => Err(anyhow!("Failed to open fifo sender: {:?}", e))?,
        };


        Ok(PipeServer { tx, rx, path })
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
        let executable_path = "/Applications/MitmproxyAppleTunnel.app/";

        let ipc_server = match PipeServer::new("mitmproxy").await {
            Ok(server) => server,
            Err(e) => Err(anyhow!("Failed to create pipe server: {:?}", e))?,
        };

        let result = Command::new("open")
            .arg("-a")
            .arg(executable_path)
            .arg("--args")
            .arg(&ipc_server.path)
            .arg(format!("{}", std::os::unix::process::parent_id()))
            .spawn();

        match result {
            Ok(_) => log::debug!("Started child process"),
            Err(e) => log::warn!("Failed to start child process: {:?}", e),
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
                //     //assert!(matches!(cmd, MacosIpcSend::SetIntercept(_)));
                //     //let len = bincode::encode_into_slice(&cmd, &mut self.buf, CONF)?;
                //     self.ipc_server.tx.try_write(&self.buf[..len])?;
                // },
                // read packets from the IPC pipe into our network stack.
                r = self.ipc_server.rx.readable() => {
                    // Try to read data, this may still fail with `WouldBlock`
                    // if the readiness event is a false positive.
                    match self.ipc_server.rx.try_read(&mut self.buf){
                        Ok(len) => {
                            if len == 0 {
                                // https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
                                // Because the client is reading from the pipe in message-read mode, it is
                                // possible for the ReadFile operation to return zero after reading a partial
                                // message. This happens when the message is larger than the read buffer.
                                //
                                // We don't support messages larger than the buffer, so this cannot happen.
                                // Instead, empty reads indicate that the IPC client has disconnected.
                                println!("IPC client disconnected.");
                                return Err(anyhow!("redirect daemon exited prematurely."));
                            }
                            //let (splitted_msg, _) = &self.buf.split_at(len);
                            let Ok(MacosIpcRecv::Packet { data, process_name }) = deserialize_packet(&self.buf[..len]) else {
                                panic!("Failed to deserialize packet");
                            };
                            let Ok(mut packet) = IpPacket::try_from(data) else {
                                println!("Skipping invalid packet: {:?}", &self.buf[..len]);
                                log::error!("Skipping invalid packet: {:?}", &self.buf[..len]);
                                continue;
                            };
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
                            //self.buf.truncate(n);
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => panic!("Error reading pipe: {}", e)
                    };
                },
                // r = self.ipc_server.rx.read_exact(&mut self.buf) => {
                //     let len = r.context("IPC read error.")?;
                //     if len == 0 {
                //         // https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
                //         // Because the client is reading from the pipe in message-read mode, it is
                //         // possible for the ReadFile operation to return zero after reading a partial
                //         // message. This happens when the message is larger than the read buffer.
                //         //
                //         // We don't support messages larger than the buffer, so this cannot happen.
                //         // Instead, empty reads indicate that the IPC client has disconnected.
                //         println!("IPC client disconnected.");
                //         return Err(anyhow!("redirect daemon exited prematurely."));
                //     }
                //
                //     //let (splitted_msg, _) = &msg.split_at(n);
                //     let Ok(MacosIpcRecv::Packet { data, process_name })  = deserialize_packet(&self.buf[..len]) else {
                //         println!("Received invalid IPC message: {:?}", &self.buf[..len]);
                //         return Err(anyhow!("Received invalid IPC message: {:?}", &self.buf[..len]));
                //     };
                //     //println!("{:?}", raw_packet.title);
                //     //msg.truncate(n);
                //
                //     //let Ok((MacosIpcRecv::Packet { data, pid, process_name }, n)) = bincode::decode_from_slice(&self.buf[..len], CONF) else {
                //         //return Err(anyhow!("Received invalid IPC message: {:?}", &self.buf[..len]));
                //     //};
                //     //assert_eq!(n, len);
                //     let Ok(mut packet) = IpPacket::try_from(data) else {
                //         println!("Skipping invalid packet: {:?}", &self.buf[..len]);
                //         log::error!("Skipping invalid packet: {:?}", &self.buf[..len]);
                //         continue;
                //     };
                //     packet.fill_ip_checksum();
                //
                //     let event = NetworkEvent::ReceivePacket {
                //         packet,
                //         tunnel_info: TunnelInfo::Macos {
                //             process_name,
                //         },
                //     };
                //     if self.net_tx.try_send(event).is_err() {
                //         log::warn!("Dropping incoming packet, TCP channel is full.")
                //     };
                // },
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
