use std::process::Command;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use nix::{sys::stat::Mode, unistd::mkfifo};
use tokio::net::unix::pipe;
use tokio::sync::broadcast;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, Receiver, UnboundedReceiver, UnboundedSender};
use crate::intercept_conf::InterceptConf;
use crate::messages::{IpPacket, NetworkCommand, NetworkEvent, TunnelInfo};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::{PacketSourceConf, PacketSourceTask, ipc};
use home::home_dir;
use prost::Message;
use std::io::Cursor;

pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 4;

pub fn serialize_packet(ipc: MacosIpcSend) -> Vec<u8> {
    let mut buf = Vec::new();
    let MacosIpcSend::Packet(ipc) = ipc else { panic!("Invalid packet")};
    let ipc =  ipc::Packet {data: ipc, process_name: format!{""} };
    buf.reserve(ipc.encoded_len());
    // Unwrap is safe, since we have reserved sufficient capacity in the vector.
    ipc.encode(&mut buf).unwrap();
    buf
}

pub fn deserialize_packet(buf: &[u8]) -> Result<MacosIpcRecv, prost::DecodeError> {
    if let Ok(packet) = ipc::Packet::decode(&mut Cursor::new(buf)) {
        return Ok(MacosIpcRecv::Packet {
            data: packet.data,
            process_name: Some(packet.process_name),
        });
    } else {
        return Err(prost::DecodeError::new("Failed to decode packet"));
    }
}

pub struct PipeServer {
    ip_rx: pipe::Receiver,
    ip_tx: pipe::Sender,
    net_rx: pipe::Receiver,
    net_tx: pipe::Sender,
    filter_rx: pipe::Receiver,
    filter_tx:pipe::Sender,
    ip_path: PathBuf,
    net_path: PathBuf,
    filter_path: PathBuf,
}

impl PipeServer {
    pub async fn new(ip_pipe: &str, net_pipe: &str, filter_pipe: &str) -> Result<Self> {
        let home_dir = match home_dir() {
            Some(ip_path) => ip_path,
            None => Err(anyhow!("Failed to get home directory"))?,
        };

        let ip_path = Path::new(&home_dir).join(format!("Downloads/{}.pipe", &ip_pipe));
        let net_path = Path::new(&home_dir).join(format!("Downloads/{}.pipe", &net_pipe));
        let filter_path = Path::new(&home_dir).join(format!("Downloads/{}.pipe", &filter_pipe));

        let (ip_rx, ip_tx) = Self::create_pipe(&ip_path)?;
        let (net_rx, net_tx) = Self::create_pipe(&net_path)?;
        let (filter_rx, filter_tx) = Self::create_pipe(&filter_path)?;

        Ok(PipeServer { ip_rx, ip_tx, net_rx, net_tx, filter_rx, filter_tx, ip_path, net_path, filter_path })
    }

    fn create_pipe(path: &PathBuf) -> Result<(pipe::Receiver, pipe::Sender)>{
        if !path.exists() {
            match mkfifo(path, Mode::S_IRWXU) {
                Ok(_) => println!("created {:?}", path),
                Err(e) => Err(anyhow!("Failed to create fifo: {:?}", e))?,
            }
        }
        let rx = match pipe::OpenOptions::new()
            .unchecked(true)
            .open_receiver(&path)
        {
            Ok(rx) => rx,
            Err(e) => Err(anyhow!("Failed to open fifo receiver: {:?}", e))?,
        };
        let tx = match pipe::OpenOptions::new()
            .unchecked(true)
            .open_sender(&path)
        {
            Ok(tx) => tx,
            Err(e) => Err(anyhow!("Failed to open fifo receiver: {:?}", e))?,
       };

        Ok((rx, tx))
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

        let ipc_server = match PipeServer::new("ip", "net", "filter").await {
            Ok(server) => server,
            Err(e) => Err(anyhow!("Failed to create pipe server: {:?}", e))?,
        };

        let result = Command::new("open")
            .arg("-a")
            .arg(executable_path)
            .arg("--args")
            .arg(&ipc_server.ip_path)
            .arg(&ipc_server.net_path)
            .arg(&ipc_server.filter_path)
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
        log::debug!("IPC connected!");

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.sd_watcher.recv() => break,
                // pipe through changes to the intercept list
                Some(cmd) = self.conf_rx.recv() => {
                    assert!(matches!(cmd, MacosIpcSend::SetIntercept(_)));
                    let MacosIpcSend::SetIntercept(cmd) = cmd else { log::error!("Invalid conf"); continue; };
                    let data = cmd.serialize();
                    self.ipc_server.filter_tx.try_write(&data)?;
                    println!("SetIntercept {:?}", cmd);
                },
                // read packets from the IPC pipe into our network stack.
                _ = self.ipc_server.ip_rx.readable() => {
                    // Try to read data, this may still fail with `WouldBlock`
                    // if the readiness event is a false positive.
                    match self.ipc_server.ip_rx.try_read(&mut self.buf){
                        Ok(len) => {
                            if len == 0 {
                                return Err(anyhow!("redirect daemon exited prematurely."));
                            }
                            let Ok(MacosIpcRecv::Packet { data, process_name }) = deserialize_packet(&self.buf[..len]) else {
                                panic!("Failed to deserialize packet");
                            };
                            let Ok(mut packet) = IpPacket::try_from(data) else {
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
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => panic!("Error reading pipe: {}", e)
                    };
                },
                //write packets from the network stack to the IPC pipe to be reinjected.
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            let packet = serialize_packet(MacosIpcSend::Packet(packet.into_inner()));

                            loop {
                                    // Wait for the pipe to be writable
                                    self.ipc_server.net_tx.writable().await?;

                                    // Try to write data, this may still fail with `WouldBlock`
                                    // if the readiness event is a false positive.
                                    match self.ipc_server.net_tx.try_write(&packet) {
                                        Ok(n) => {
                                            break;
                                        }
                                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                            continue;
                                        }
                                        Err(e) => {
                                            return Err(e.into());
                                        }
                                    }
                                }
                        }
                    }
                },
            }
        } 

        log::info!("Macos OS proxy task shutting down.");
        Ok(())
    }
}
