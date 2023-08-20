use crate::messages::{IpPacket, NetworkCommand, NetworkEvent, TunnelInfo};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::ipc::from_redirector::Message::Packet;
use crate::packet_sources::ipc::{FromRedirector, PacketWithMeta};
use crate::packet_sources::{ipc, PacketSourceConf, PacketSourceTask};
use anyhow::{anyhow, bail, Result};
use async_trait::async_trait;
use nix::{sys::stat::Mode, unistd::mkfifo};
use prost::Message;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::pipe;
use tokio::sync::broadcast;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, Receiver, UnboundedReceiver, UnboundedSender};

pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 4;

pub struct PipeServer {
    from_redirector_rx: pipe::Receiver,
    from_redirector_path: PathBuf,
    from_proxy_path: PathBuf,
}

impl PipeServer {
    pub async fn new(from_redirector_pipe: &str, from_proxy_pipe: &str) -> Result<Self> {
        let tmp_dir = match std::fs::create_dir_all("/tmp/mitmproxy/") {
            Ok(()) => Path::new("/tmp/mitmproxy/"),
            _ => Err(anyhow!("Failed to get tmp directory"))?,
        };

        let from_redirector_path =
            tmp_dir.join(format!("{}.pipe", &from_redirector_pipe));
        if from_redirector_path.exists() {
            std::fs::remove_file(&from_redirector_path)?;
        }
        mkfifo(&from_redirector_path, Mode::S_IRWXU)?;
        let from_redirector_rx = pipe::OpenOptions::new().open_receiver(&from_redirector_path)?;

        let from_proxy_path =
            tmp_dir.join(format!("{}.pipe", &from_proxy_pipe));
        if from_proxy_path.exists() {
            std::fs::remove_file(&from_proxy_path)?;
        }
        mkfifo(&from_proxy_path, Mode::S_IRWXU)?;

        Ok(PipeServer {
            from_redirector_rx,
            from_redirector_path,
            from_proxy_path,
        })
    }
}

pub struct MacosConf;

#[async_trait]
impl PacketSourceConf for MacosConf {
    type Task = MacosTask;
    type Data = UnboundedSender<ipc::FromProxy>;

    fn name(&self) -> &'static str {
        "macOS proxy"
    }

    async fn build(
        self,
        net_tx: Sender<NetworkEvent>,
        net_rx: Receiver<NetworkCommand>,
        sd_watcher: broadcast::Receiver<()>,
    ) -> Result<(MacosTask, Self::Data)> {
        let executable_path = "/Applications/MitmproxyAppleTunnel.app/";

        let ipc_server = match PipeServer::new("from_redirector", "from_proxy").await {
            Ok(server) => server,
            Err(e) => Err(anyhow!("Failed to create pipe server: {:?}", e))?,
        };

        let result = Command::new("open")
            .arg("-a")
            .arg(executable_path)
            .arg("--args")
            .arg(&ipc_server.from_redirector_path)
            .arg(&ipc_server.from_proxy_path)
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
    conf_rx: UnboundedReceiver<ipc::FromProxy>,
    sd_watcher: broadcast::Receiver<()>,
}

#[async_trait]
impl PacketSourceTask for MacosTask {
    async fn run(mut self) -> Result<()> {
        log::debug!("Waiting for IPC connection...");

        // We cannot open the pipe for writing yet: tokio uses non-blocking I/O,
        // and that requires a reader to be present or open_sender() will fail.
        // workaround: spawn reader first (in build() above), then use blocking I/O in a thread
        // to determine when we can safely open.
        let read_pipe_file = self.ipc_server.from_proxy_path.clone();
        tokio::task::spawn_blocking(move || {
            match std::fs::OpenOptions::new()
                .write(true)
                .open(&read_pipe_file)
            {
                Ok(_) => (),
                Err(err) => {
                    log::error!("Failed to open pipe {}: {}", read_pipe_file.display(), err)
                }
            }
        })
        .await?;
        let mut from_proxy_tx =
            pipe::OpenOptions::new().open_sender(&self.ipc_server.from_proxy_path)?;

        log::debug!("IPC connected!");

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.sd_watcher.recv() => break,
                // pipe through changes to the intercept list
                Some(cmd) = self.conf_rx.recv() => {
                    assert!(matches!(cmd, ipc::FromProxy { message: Some(ipc::from_proxy::Message::InterceptSpec(_)) }));
                    cmd.encode(&mut self.buf.as_mut_slice())?;
                    let len = cmd.encoded_len();
                    from_proxy_tx.write_all(&[&len.to_be_bytes(), &self.buf[..len]].concat()).await?;
                },
                // read packets from the IPC pipe into our network stack.
                _ = self.ipc_server.from_redirector_rx.readable() => {
                    match self.ipc_server.from_redirector_rx.read(&mut self.buf).await {
                        Ok(len) => {
                            if len == 0 {
                                return Err(anyhow!("redirect daemon exited prematurely."));
                            }
                            let mut cursor = Cursor::new(&self.buf[..len]);
                            let Ok(FromRedirector { message: Some(message)}) = FromRedirector::decode(&mut cursor) else {
                                return Err(anyhow!("Received invalid IPC message: {:?}", &self.buf[..len]));
                            };
                            assert_eq!(cursor.position(), len as u64);
                            let (data, pid, process_name) = match message {
                                Packet(PacketWithMeta { data, pid, process_name}) => (data, pid, process_name.map(PathBuf::from)),
                            };
                            let Ok(mut packet) = IpPacket::try_from(data) else {
                                log::error!("Skipping invalid packet: {:?}", &self.buf[..len]);
                                continue;
                            };
                            packet.fill_ip_checksum();
                            let event = NetworkEvent::ReceivePacket {
                                packet,
                                tunnel_info: TunnelInfo::OsProxy {
                                    pid,
                                    process_name,
                                },
                            };
                            if self.net_tx.try_send(event).is_err() {
                                log::warn!("Dropping incoming packet, TCP channel is full.");
                            };
                        },
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Err(e) => bail!("Error reading pipe: {}", e)
                    };
                },
                //write packets from the network stack to the IPC pipe to be reinjected.
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            let packet = ipc::FromProxy { message: Some(ipc::from_proxy::Message::Packet(packet.into_inner()))};
                            packet.encode(&mut self.buf.as_mut_slice())?;
                            let len = packet.encoded_len();
                            from_proxy_tx.write_all(&[&len.to_be_bytes(), &self.buf[..len]].concat()).await?;
                        }
                    }
                },
            }
        }

        log::info!("Macos OS proxy task shutting down.");
        Ok(())
    }
}
