use crate::messages::{TransportCommand, TransportEvent};
use crate::network::MAX_PACKET_SIZE;

use crate::packet_sources::ipc::{from_proxy};
use crate::packet_sources::{ipc, PacketSourceConf, PacketSourceTask};
use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::SinkExt;
use futures_util::StreamExt;


use prost::bytes::BytesMut;
use prost::Message;


use std::process::Stdio;
use tokio::net::{UnixListener};

use tokio::process::Command;
use tokio::sync::broadcast;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
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
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: broadcast::Receiver<()>,
    ) -> Result<(MacOsTask, Self::Data)> {

        let listener_addr = format!("/tmp/mitmproxy-{}", std::process::id());
        let listener = UnixListener::bind(&listener_addr)?;

        let redirector_process = Command::new(
            "/Applications/Mitmproxy Redirector.app/Contents/MacOS/Mitmproxy Redirector",
        )
        .arg(listener_addr)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("Failed to launch macos-redirector app.")?;

        let (conf_tx, conf_rx) = unbounded_channel();

        Ok((
            MacOsTask {
                buf: BytesMut::with_capacity(IPC_BUF_SIZE),
                redirector_process,
                listener,
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
    // IPC is a bit complicated on macOS. Instead of using one bidirectional message pipe,
    // we need to use two unidirectional byte streams created with mkfifo.
    // Additionally, the network extension cannot modify NEAppRule, only the hosting application
    // can. So we send spec updates to redirector_process's stdin.
    buf: BytesMut,
    redirector_process: tokio::process::Child,
    listener: UnixListener,
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    conf_rx: UnboundedReceiver<ipc::FromProxy>,
    shutdown: broadcast::Receiver<()>,
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
        let mut app_stdin = FramedWrite::new(self.redirector_process.stdin.unwrap(), LengthDelimitedCodec::new());
        let mut app_stdout =
            FramedRead::new(self.redirector_process.stdout.unwrap(), LinesCodec::new());
        let mut app_stderr =
            FramedRead::new(self.redirector_process.stderr.unwrap(), LinesCodec::new());

        let l = self.listener.accept().await;
        match l {
            Ok((stream, addr)) => {
                dbg!(stream);
                dbg!(addr);
            }
            Err(e) => {
                dbg!(e);
            }
        }

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.shutdown.recv() => break,
                // Forward print statements from Swift.
                Some(out) = app_stdout.next() => log::info!("[macos-redirector] {}", logfmt(out)),
                Some(err) = app_stderr.next() => log::error!("[macos-redirector] {}", logfmt(err)),
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
                    self.buf.reserve(len);
                    msg.encode(&mut self.buf)?;
                    app_stdin.send(self.buf.split().freeze()).await?;
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
                 *//*
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
