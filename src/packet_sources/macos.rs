use crate::messages::{TransportCommand, TransportEvent};
use crate::network::MAX_PACKET_SIZE;

use crate::packet_sources::ipc::{from_proxy};
use crate::packet_sources::{ipc, PacketSourceConf, PacketSourceTask};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use futures_util::SinkExt;
use futures_util::StreamExt;


use prost::bytes::BytesMut;
use prost::Message;


use std::process::Stdio;
use futures_util::future::Join;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use tokio::process::Command;
use tokio::sync::broadcast;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinSet;
use tokio_util::codec::{Framed, FramedRead, FramedWrite, LengthDelimitedCodec, LinesCodec, LinesCodecError};

pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 4;

pub struct MacosConf;

async fn start_redirector(listener_addr: String) -> Result<()> {
    log::debug!("Starting redirector app...");
    let mut redirector_process = Command::new(
            "/Applications/Mitmproxy Redirector.app/Contents/MacOS/Mitmproxy Redirector",
        )
        .arg(listener_addr)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to launch macos-redirector app.")?;

    let output = redirector_process.wait_with_output().await?;
    if !output.stdout.is_empty() {
        log::info!("[macos-redirector] {}", String::from_utf8_lossy(&output.stdout).trim());
    }
    if !output.stderr.is_empty() {
        log::error!("[macos-redirector] {}", String::from_utf8_lossy(&output.stderr).trim());
    }
    if !output.status.success() {
        bail!("macos-redirector exited with status {:?}", output.status.code());
    }
    log::debug!("Redirector app exited successfully.");
    Ok(())
}

#[async_trait]
impl PacketSourceConf for MacosConf {
    type Task = MacOsTask;
    type Data = UnboundedSender<ipc::FromProxy>;

    fn name(&self) -> &'static str {
        "macOS proxy"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: broadcast::Receiver<()>,
    ) -> Result<(MacOsTask, Self::Data)> {

        let listener_addr = format!("/tmp/mitmproxy-{}", std::process::id());
        let listener = UnixListener::bind(&listener_addr)?;

        start_redirector(listener_addr).await?;

        log::debug!("Waiting for control channel...");
        let control_channel = listener.accept().await?.0;
        log::debug!("Control channel connected.");

        let (conf_tx, conf_rx) = unbounded_channel();

        Ok((
            MacOsTask {
                control_channel,
                listener,
                connections: JoinSet::new(),
                transport_events_tx,
                transport_commands_rx,
                conf_rx,
                shutdown,
            },
            conf_tx,
        ))
    }
}

pub struct MacOsTask {
    control_channel: UnixStream,
    listener: UnixListener,
    connections: JoinSet<()>,
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    conf_rx: UnboundedReceiver<ipc::FromProxy>,
    shutdown: broadcast::Receiver<()>,
}

#[async_trait]
impl PacketSourceTask for MacOsTask {
    async fn run(mut self) -> Result<()> {
        let mut control_channel = Framed::new(self.control_channel, LengthDelimitedCodec::new());

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.shutdown.recv() => break,
                l = self.listener.accept() => {
                    match l {
                        Ok((_stream, _addr)) => {

                        },
                        Err(e) => {
                        log::error!("Error accepting connection from macos-redirector: {}", e);
                        }
                    }
                }
                // pipe through changes to the intercept list
                Some(cmd) = self.conf_rx.recv() => {
                    let ipc::FromProxy { message: Some(from_proxy::Message::InterceptSpec(msg)) } = cmd else {
                        unreachable!();
                    };
                    let len = msg.encoded_len();
                    let mut buf = BytesMut::with_capacity(len);
                    msg.encode(&mut buf)?;
                    control_channel.send(buf.freeze()).await?;
                },
                /*
                // read packets from the IPC pipe into our network stack.
                rx = packet_rx.next() => {
                    match rx {
                        Some(Ok(mut buf)) => {
                            let Ok(FromRedirector { message: Some(message)}) = FromRedirector::decode(&mut buf) else {
                                return Err(anyhow!("Received invalid IPC message: {:?}", &buf));
                            };
                            let Packet(PacketWithMeta { data, pid, process_name}) = message;
                            let Ok(mut packet) = IpPacket::try_from(data) else {
                                log::error!("Skipping invalid packet: {:?}", &buf);
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
                //write packets from the network stack to the IPC pipe to be reinjected.
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            let msg = ipc::Packet { data: packet.into_inner() };
                            let len = msg.encoded_len();
                            self.buf.reserve(len);
                            msg.encode(&mut self.buf)?;
                            packet_tx.send(self.buf.split().freeze()).await?;
                        }
                    }
                },
                 */
            }
        }

        log::info!("Macos OS proxy task shutting down.");
        Ok(())
    }
}
