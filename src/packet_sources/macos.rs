use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::messages::{ConnectionId, TransportCommand, TransportEvent, TunnelInfo};
use crate::network::MAX_PACKET_SIZE;

use crate::packet_sources::ipc::from_proxy;
use crate::packet_sources::{ipc, PacketSourceConf, PacketSourceTask};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use futures_util::SinkExt;
use futures_util::StreamExt;

use prost::bytes::{Buf, BytesMut};
use prost::Message;

use std::process::Stdio;
use std::str::FromStr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinSet;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 4;

pub struct MacosConf;

async fn start_redirector(listener_addr: String) -> Result<()> {
    log::debug!("Starting redirector app...");
    let redirector_process =
        Command::new("/Applications/Mitmproxy Redirector.app/Contents/MacOS/Mitmproxy Redirector")
            .arg(listener_addr)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to launch macos-redirector app.")?;

    let output = redirector_process.wait_with_output().await?;
    if !output.stdout.is_empty() {
        log::info!(
            "[macos-redirector] {}",
            String::from_utf8_lossy(&output.stdout).trim()
        );
    }
    if !output.stderr.is_empty() {
        log::error!(
            "[macos-redirector] {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if !output.status.success() {
        bail!(
            "macos-redirector exited with status {:?}",
            output.status.code()
        );
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
                connection_commands: HashMap::new(),
                transport_events_tx,
                transport_commands_rx,
                conf_rx,
                shutdown,
            },
            conf_tx,
        ))
    }
}

struct ConnectionTask {
    id: ConnectionId,
    stream: UnixStream,
    commands: UnboundedReceiver<TransportCommand>,
    events: Sender<TransportEvent>,
    buf: BytesMut,
    read_tx: Option<(usize, oneshot::Sender<Vec<u8>>)>,
    drain_tx: Option<oneshot::Sender<()>>,
}

impl ConnectionTask {
    pub fn new(
        id: ConnectionId,
        stream: UnixStream,
        commands: UnboundedReceiver<TransportCommand>,
        events: Sender<TransportEvent>,
    ) -> Self {
        Self {
            id,
            stream,
            commands,
            events,
            buf: BytesMut::with_capacity(IPC_BUF_SIZE),
            read_tx: None,
            drain_tx: None,
        }
    }
    async fn run(mut self) -> Result<()> {
        let len = self.stream.read_u32().await? as usize;

        self.buf.resize(len, 0);
        self.stream.read_exact(&mut self.buf).await?;
        let Ok(msg) = ipc::NewFlow::decode(&self.buf[..]) else {
            bail!("Received invalid IPC message: {:?}", &self.buf[..]);
        };
        self.buf.clear();

        let dst_ip;
        let destination_hostname;
        if let Ok(ip) = IpAddr::from_str(&msg.hostname) {
            dst_ip = ip;
            destination_hostname = None;
        } else {
            dst_ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
            destination_hostname = Some(msg.hostname);
        }

        self.events
            .send(TransportEvent::ConnectionEstablished {
                connection_id: self.id,
                src_addr: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                dst_addr: SocketAddr::from((dst_ip, msg.port as u16)),
                tunnel_info: TunnelInfo::OsProxy {
                    pid: msg.tunnel_info.as_ref().map(|t| t.pid).unwrap_or(0),
                    process_name: msg.tunnel_info.and_then(|t| t.process_name),
                    dst_hostname: destination_hostname,
                },
            })
            .await?;

        loop {
            tokio::select! {
                Ok(()) = self.stream.writable(), if !self.buf.is_empty() => {
                    let _written = self.stream.write_buf(&mut self.buf).await?;
                    if self.buf.is_empty() {
                        if let Some(tx) = self.drain_tx.take() {
                            tx.send(()).ok();
                        }
                    }
                },
                Ok(()) = self.stream.readable(), if self.read_tx.is_some() => {
                    let (n, tx) = self.read_tx.take().unwrap();
                    let mut data = Vec::with_capacity(n);
                    self.stream.read_buf(&mut data).await?;
                    tx.send(data).ok();
                },
                command = self.commands.recv() => {
                    let Some(command) = command else {
                        return Ok(())
                    };
                    match command {
                        TransportCommand::ReadData(_, n, tx) => {
                            assert!(self.read_tx.is_none());
                            self.read_tx = Some((n as usize, tx));
                        },
                        TransportCommand::WriteData(_, data) => {
                            let mut c = std::io::Cursor::new(data);
                            self.stream.write_buf(&mut c).await?;
                            self.buf.extend_from_slice(c.chunk());
                        },
                        TransportCommand::DrainWriter(_, tx) => {
                            assert!(self.drain_tx.is_none());
                            if self.buf.is_empty() {
                                tx.send(()).ok();
                            } else {
                                self.drain_tx = Some(tx);
                            }
                        },
                        TransportCommand::CloseConnection(_, half_close) => {
                            self.stream.flush().await?; // supposedly this is a no-op on unix sockets.
                            self.stream.shutdown().await?;
                            if !half_close {
                                return Ok(())
                            }
                        },
                        TransportCommand::SendDatagram { .. } => unreachable!()
                    }
                }
            }
        }
    }
}

pub struct MacOsTask {
    control_channel: UnixStream,
    listener: UnixListener,
    connections: JoinSet<Result<()>>,
    connection_commands: HashMap<ConnectionId, UnboundedSender<TransportCommand>>,
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
                _ = control_channel.next() => {
                    bail!("macOS System Extension shut down.")
                },
                l = self.listener.accept() => {
                    match l {
                        Ok((stream, _)) => {
                            let (tx, rx) = unbounded_channel();
                            let connection_id = self.connections.len() as ConnectionId;
                            let task = ConnectionTask::new(connection_id, stream, rx, self.transport_events_tx.clone());
                            self.connections.spawn(task.run());
                            self.connection_commands.insert(
                                connection_id,
                                tx
                            );
                        },
                        Err(e) => {
                        log::error!("Error accepting connection from macos-redirector: {}", e);
                        }
                    }
                },
                cmd = self.transport_commands_rx.recv() => {
                    let Some(cmd) = cmd else {
                        bail!("Transport command channel closed.");
                    };
                    match cmd {
                        TransportCommand::ReadData(connection_id, _, _)
                        | TransportCommand::WriteData(connection_id, _)
                        | TransportCommand::DrainWriter(connection_id, _)
                        | TransportCommand::CloseConnection(connection_id, _) => {
                            let Some(conn_tx) = self.connection_commands.get(&connection_id) else {
                                bail!("Received command for unknown connection: {:?}", cmd);
                            };
                            conn_tx.send(cmd)?;
                        },
                        TransportCommand::SendDatagram { .. } => unimplemented!(),
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
