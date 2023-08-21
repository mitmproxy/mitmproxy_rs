use crate::messages::{IpPacket, NetworkCommand, NetworkEvent, TunnelInfo};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::ipc::from_redirector::Message::Packet;
use crate::packet_sources::ipc::{from_proxy, FromRedirector, PacketWithMeta};
use crate::packet_sources::{ipc, PacketSourceConf, PacketSourceTask};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use futures_util::SinkExt;
use futures_util::StreamExt;

use nix::{sys::stat::Mode, unistd::mkfifo};
use prost::bytes::BytesMut;
use prost::Message;

use std::path::PathBuf;
use std::process::Stdio;
use tokio::net::unix::pipe;
use tokio::process::Command;
use tokio::sync::broadcast;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, Receiver, UnboundedReceiver, UnboundedSender};
use tokio_util::codec::{
    FramedRead, FramedWrite, LengthDelimitedCodec, LinesCodec, LinesCodecError,
};

pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 4;

pub struct MacosConf;

#[async_trait]
impl PacketSourceConf for MacosConf {
    type Task = MacOsTask;
    type Data = UnboundedSender<ipc::FromProxy>;

    fn name(&self) -> &'static str {
        "macOS proxy"
    }

    async fn build(
        self,
        net_tx: Sender<NetworkEvent>,
        net_rx: Receiver<NetworkCommand>,
        sd_watcher: broadcast::Receiver<()>,
    ) -> Result<(MacOsTask, Self::Data)> {
        let pipe_base = PathBuf::from(format!("/tmp/mitmproxy-{}", std::process::id()));

        // named after who is writing.
        let redirector_rx_path = pipe_base.with_extension("redir");
        let redirector_tx_path = pipe_base.with_extension("proxy");

        if redirector_rx_path.exists() {
            std::fs::remove_file(&redirector_rx_path)?;
        }
        if redirector_tx_path.exists() {
            std::fs::remove_file(&redirector_tx_path)?;
        }

        mkfifo(&redirector_rx_path, Mode::S_IRWXU)?;
        mkfifo(&redirector_tx_path, Mode::S_IRWXU)?;

        let redirector_rx = pipe::OpenOptions::new().open_receiver(&redirector_rx_path)?;

        let redirector_process =
            Command::new("/Applications/macos-redirector.app/Contents/MacOS/macos-redirector")
                .arg(&pipe_base)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .context("Failed to launch macos-redirector app.")?;

        let redirector_tx = {
            // We cannot open the pipe for writing yet: tokio uses non-blocking I/O,
            // and that requires a reader to be present or open_sender() will fail.
            // workaround: spawn reader first (in build() above), then use blocking I/O in a thread
            // to determine when we can safely open.
            log::debug!("Waiting for IPC connection...");
            tokio::task::spawn_blocking(move || {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(&redirector_tx_path)
                    .context("failed to open sync pipe")?;
                log::debug!("IPC connected!");
                pipe::OpenOptions::new()
                    .open_sender(&redirector_tx_path)
                    .context("failed to open async pipe")
            })
            .await??
        };

        let (conf_tx, conf_rx) = unbounded_channel();

        Ok((
            MacOsTask {
                redirector_process,
                redirector_tx,
                redirector_rx,
                buf: BytesMut::with_capacity(IPC_BUF_SIZE),
                net_tx,
                net_rx,
                conf_rx,
                sd_watcher,
            },
            conf_tx,
        ))
    }
}

pub struct MacOsTask {
    redirector_process: tokio::process::Child,
    redirector_rx: pipe::Receiver,
    redirector_tx: pipe::Sender,
    buf: BytesMut,
    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,
    conf_rx: UnboundedReceiver<ipc::FromProxy>,
    sd_watcher: broadcast::Receiver<()>,
}

fn logfmt(x: Result<String, LinesCodecError>) -> String {
    match x {
        Ok(s) => s,
        Err(e) => format!("{}", e),
    }
}

#[async_trait]
impl PacketSourceTask for MacOsTask {
    async fn run(mut self) -> Result<()> {
        let codec = LengthDelimitedCodec::new();
        let mut stdin = FramedWrite::new(self.redirector_process.stdin.unwrap(), codec.clone());
        let mut rx = FramedRead::new(self.redirector_rx, codec.clone());
        let mut tx = FramedWrite::new(self.redirector_tx, codec);

        let mut stdout =
            FramedRead::new(self.redirector_process.stdout.unwrap(), LinesCodec::new());
        let mut stderr =
            FramedRead::new(self.redirector_process.stderr.unwrap(), LinesCodec::new());

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.sd_watcher.recv() => break,
                // Forward print statements from Swift.
                Some(out) = stdout.next() => log::info!("[macos-redirector] {}", logfmt(out)),
                Some(err) = stderr.next() => log::error!("[macos-redirector] {}", logfmt(err)),
                // read packets from the IPC pipe into our network stack.
                pipe_read = rx.next() => {
                    match pipe_read {
                        Some(Ok(mut data)) => {
                            let Ok(FromRedirector { message: Some(message)}) = FromRedirector::decode(&mut data) else {
                                return Err(anyhow!("Received invalid IPC message: {:?}", &data));
                            };
                            let (ip_data, pid, process_name) = match message {
                                Packet(PacketWithMeta { data, pid, process_name}) => (data, pid, process_name.map(PathBuf::from)),
                            };
                            let Ok(mut packet) = IpPacket::try_from(ip_data) else {
                                log::error!("Skipping invalid packet: {:?}", &data);
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
                        Some(Err(e)) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                        Some(Err(e)) => bail!("Error reading pipe: {}", e),
                        None => bail!("Empty pipe read."),
                    }
                },
                // pipe through changes to the intercept list
                Some(cmd) = self.conf_rx.recv() => {
                    let ipc::FromProxy { message: Some(from_proxy::Message::InterceptSpec(msg)) } = cmd else {
                        unreachable!();
                    };
                    let len = msg.encoded_len();
                    self.buf.reserve(len);
                    msg.encode(&mut self.buf)?;
                    stdin.send(self.buf.split().freeze()).await?;
                },
                //write packets from the network stack to the IPC pipe to be reinjected.
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            let msg = ipc::Packet { data: packet.into_inner() };
                            let len = msg.encoded_len();
                            self.buf.reserve(len);
                            msg.encode(&mut self.buf)?;
                            tx.send(self.buf.split().freeze()).await?;
                        }
                    }
                },
            }
        }

        log::info!("Macos OS proxy task shutting down.");
        Ok(())
    }
}
