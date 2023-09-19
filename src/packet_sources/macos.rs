use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use crate::messages::{ConnectionId, TransportCommand, TransportEvent, TunnelInfo};

use crate::intercept_conf::InterceptConf;
use crate::packet_sources::ipc::{NewFlow, TcpFlow, UdpFlow};
use crate::packet_sources::{ipc, PacketSourceConf, PacketSourceTask};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use futures_util::SinkExt;
use futures_util::StreamExt;

use prost::bytes::{Buf, BytesMut};
use prost::Message;

use std::process::Stdio;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

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
    type Data = UnboundedSender<InterceptConf>;

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
        // XXX: Saw some hangs here during development, not sure why.
        let control_channel = timeout(Duration::new(5, 0), listener.accept())
            .await
            .context("failed to establish connection to macOS system extension")??
            .0;
        log::debug!("Control channel connected.");

        let (conf_tx, conf_rx) = unbounded_channel();
        Ok((
            MacOsTask {
                control_channel,
                listener,
                connections: JoinSet::new(),
                connection_by_id: HashMap::new(),
                connection_by_addr: HashMap::new(),
                next_connection_id: 0,
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
    connections: JoinSet<Result<(ConnectionId, Option<SocketAddr>)>>,
    connection_by_id: HashMap<ConnectionId, UnboundedSender<TransportCommand>>,
    connection_by_addr: HashMap<SocketAddr, UnboundedSender<TransportCommand>>,
    next_connection_id: ConnectionId,
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    shutdown: broadcast::Receiver<()>,
}

#[async_trait]
impl PacketSourceTask for MacOsTask {
    async fn run(mut self) -> Result<()> {
        let mut control_channel = Framed::new(self.control_channel, LengthDelimitedCodec::new());

        let (register_addr_tx, mut register_addr_rx) =
            unbounded_channel::<RegisterConnectionSocketAddr>();

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.shutdown.recv() => break,
                _ = control_channel.next() => {
                    // No messages expected here at the moment.
                    bail!("macOS System Extension shut down.")
                },
                Some(task) = self.connections.join_next() => {
                    match task {
                        Ok(Ok((cid, src_addr))) => {
                            self.connection_by_id.remove(&cid);
                            if let Some(src_addr) = src_addr {
                                self.connection_by_addr.remove(&src_addr);
                            }
                        },
                        Ok(Err(e)) => log::error!("Connection task failure: {e:?}"),
                        Err(e) => log::error!("Connection task panic: {e:?}"),
                    }
                },
                Some(RegisterConnectionSocketAddr(cid, addr, done)) = register_addr_rx.recv() => {
                    let tx = self.connection_by_id.get(&cid).unwrap().clone();
                    self.connection_by_addr.insert(addr, tx);
                    done.send(()).expect("ok channel dead");
                },
                l = self.listener.accept() => {
                    match l {
                        Ok((stream, _)) => {
                            let (conn_tx, conn_rx) = unbounded_channel();
                            let connection_id = {
                                self.next_connection_id += 1;
                                self.next_connection_id
                            };
                            self.connections.spawn(
                                ConnectionTask::new(connection_id, stream, conn_rx, self.transport_events_tx.clone(), register_addr_tx.clone())
                                .run()
                            );
                            self.connection_by_id.insert(
                                connection_id,
                                conn_tx
                            );
                        },
                        Err(e) => log::error!("Error accepting connection from macos-redirector: {}", e)
                    }
                },
                Some(cmd) = self.transport_commands_rx.recv() => {
                    match &cmd {
                        TransportCommand::ReadData(connection_id, _, _)
                        | TransportCommand::WriteData(connection_id, _)
                        | TransportCommand::DrainWriter(connection_id, _)
                        | TransportCommand::CloseConnection(connection_id, _) => {
                            let Some(conn_tx) = self.connection_by_id.get(connection_id) else {
                                log::error!("Received command for unknown connection: {:?}", &cmd);
                                continue;
                            };
                            conn_tx.send(cmd).ok();
                        },
                        TransportCommand::SendDatagram {
                            data: _,
                            src_addr,
                            dst_addr,
                        } => {
                            let Some(conn_tx) = self.connection_by_addr.get(dst_addr) else {
                                log::error!("Received command for unknown address: src={:?} dst={:?}", src_addr, dst_addr);
                                continue;
                            };
                            conn_tx.send(cmd).ok();
                        },
                    }
                }
                // pipe through changes to the intercept list
                Some(conf) = self.conf_rx.recv() => {
                    let msg = ipc::InterceptConf::from(conf);
                    let len = msg.encoded_len();
                    let mut buf = BytesMut::with_capacity(len);
                    msg.encode(&mut buf)?;
                    control_channel.send(buf.freeze()).await.context("Failed to write to control channel")?;
                },
            }
        }

        log::info!("Macos OS proxy task shutting down.");
        Ok(())
    }
}

struct RegisterConnectionSocketAddr(ConnectionId, SocketAddr, oneshot::Sender<()>);

struct ConnectionTask {
    id: ConnectionId,
    stream: UnixStream,
    commands: UnboundedReceiver<TransportCommand>,
    events: Sender<TransportEvent>,
    read_tx: Option<(usize, oneshot::Sender<Vec<u8>>)>,
    drain_tx: Option<oneshot::Sender<()>>,
    register_addr: UnboundedSender<RegisterConnectionSocketAddr>,
}

impl ConnectionTask {
    pub fn new(
        id: ConnectionId,
        stream: UnixStream,
        commands: UnboundedReceiver<TransportCommand>,
        events: Sender<TransportEvent>,
        register_addr: UnboundedSender<RegisterConnectionSocketAddr>,
    ) -> Self {
        Self {
            id,
            stream,
            commands,
            events,
            read_tx: None,
            drain_tx: None,
            register_addr,
        }
    }
    async fn run(mut self) -> Result<(ConnectionId, Option<SocketAddr>)> {
        let new_flow = {
            let len = self
                .stream
                .read_u32()
                .await
                .context("Failed to read handshake.")? as usize;
            let mut buf = BytesMut::zeroed(len);
            self.stream
                .read_exact(&mut buf)
                .await
                .context("Failed to read handshake contents.")?;
            NewFlow::decode(&buf[..]).context("Invalid handshake IPC")?
        };

        match new_flow {
            NewFlow {
                message: Some(ipc::new_flow::Message::Tcp(tcp_flow)),
            } => self.handle_tcp(tcp_flow).await,
            NewFlow {
                message: Some(ipc::new_flow::Message::Udp(udp_flow)),
            } => self.handle_udp(udp_flow).await,
            _ => bail!("Received invalid IPC message: {:?}", new_flow),
        }
    }

    async fn handle_udp(mut self, flow: UdpFlow) -> Result<(ConnectionId, Option<SocketAddr>)> {
        // For UDP connections, we pass length-delimited protobuf messages over the unix socket
        // in both directions.
        let mut write_buf = BytesMut::new();
        let mut stream = Framed::new(self.stream, LengthDelimitedCodec::new());

        let tunnel_info = {
            let Some(tun) = flow.tunnel_info else {
                bail!("no tunnel info")
            };
            TunnelInfo::OsProxy {
                pid: tun.pid,
                process_name: tun.process_name,
                remote_endpoint: None,
            }
        };
        let local_addr = {
            let Some(addr) = &flow.local_address else {
                bail!("no local address")
            };
            SocketAddr::try_from(addr)?
        };

        // Send our socket address to the main macos task and wait until it has been processed.
        let (done_tx, done_rx) = oneshot::channel();
        self.register_addr
            .send(RegisterConnectionSocketAddr(self.id, local_addr, done_tx))?;
        done_rx.await?;

        loop {
            tokio::select! {
                packet = stream.next() => {
                    let Some(packet) = packet else {
                        break;
                    };
                    let packet = ipc::UdpPacket::decode(
                        packet.context("IPC read error")?
                    ).context("invalid IPC message")?;

                    let dst_addr = {
                        let Some(dst_addr) = &packet.remote_address else { bail!("no remote addr") };
                        SocketAddr::try_from(dst_addr).context("invalid socket address")?
                    };

                    if let Err(e) = self.events.try_send(TransportEvent::DatagramReceived {
                        data: packet.data,
                        src_addr: local_addr,
                        dst_addr,
                        tunnel_info: tunnel_info.clone(),
                    }) {
                        log::debug!("Failed to send UDP packet: {}", e);
                    }
                },
                command = self.commands.recv() => {
                    let Some(command) = command else {
                        break;
                    };
                    match command {
                        TransportCommand::SendDatagram { data, src_addr, dst_addr } => {
                            assert_eq!(dst_addr, local_addr);
                            let packet = ipc::UdpPacket {
                                data,
                                remote_address: Some(src_addr.into()),
                            };
                            write_buf.reserve(packet.encoded_len());
                            packet.encode(&mut write_buf)?;
                            stream.send(write_buf.split().freeze()).await?;
                        },
                        TransportCommand::ReadData(_, _, _) |
                        TransportCommand::WriteData(_, _) |
                        TransportCommand::DrainWriter(_, _) |
                        TransportCommand::CloseConnection(_, _) => {
                            bail!("UDP connection received TCP event: {command:?}");
                        }
                    }
                }
            }
        }

        Ok((self.id, Some(local_addr)))
    }

    async fn handle_tcp(mut self, flow: TcpFlow) -> Result<(ConnectionId, Option<SocketAddr>)> {
        let mut write_buf = BytesMut::new();

        let remote = flow.remote_address.expect("no remote address");
        let src_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let dst_addr = match SocketAddr::try_from(&remote) {
            Ok(addr) => addr,
            Err(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        };
        let remote_endpoint = Some((remote.host, remote.port as u16));

        self.events
            .send(TransportEvent::ConnectionEstablished {
                connection_id: self.id,
                src_addr,
                dst_addr,
                tunnel_info: TunnelInfo::OsProxy {
                    pid: flow.tunnel_info.as_ref().map(|t| t.pid).unwrap_or(0),
                    process_name: flow.tunnel_info.and_then(|t| t.process_name),
                    remote_endpoint,
                },
            })
            .await?;

        loop {
            tokio::select! {
                Ok(()) = self.stream.writable(), if !write_buf.is_empty() => {
                    self.stream.write_buf(&mut write_buf).await.context("failed to write to socket from buf")?;
                    if write_buf.is_empty() {
                        if let Some(tx) = self.drain_tx.take() {
                            tx.send(()).ok();
                        }
                    }
                },
                Ok(()) = self.stream.readable(), if self.read_tx.is_some() => {
                    let (n, tx) = self.read_tx.take().unwrap();
                    let mut data = Vec::with_capacity(n);
                    self.stream.read_buf(&mut data).await.context("failed to read from socket")?;
                    tx.send(data).ok();
                },
                command = self.commands.recv() => {
                    let Some(command) = command else {
                        break;
                    };
                    match command {
                        TransportCommand::ReadData(_, n, tx) => {
                            assert!(self.read_tx.is_none());
                            self.read_tx = Some((n as usize, tx));
                        },
                        TransportCommand::WriteData(_, data) => {
                            let mut c = std::io::Cursor::new(data);
                            self.stream.write_buf(&mut c).await.context("failed to write to socket")?;
                            write_buf.extend_from_slice(c.chunk());
                        },
                        TransportCommand::DrainWriter(_, tx) => {
                            assert!(self.drain_tx.is_none());
                            if write_buf.is_empty() {
                                tx.send(()).ok();
                            } else {
                                self.drain_tx = Some(tx);
                            }
                        },
                        TransportCommand::CloseConnection(_, half_close) => {
                            self.stream.flush().await.ok(); // supposedly this is a no-op on unix sockets.
                            self.stream.shutdown().await.ok();
                            if !half_close {
                                break;
                            }
                        },
                        TransportCommand::SendDatagram { .. } => {
                            bail!("TCP connection received UDP event: {command:?}");
                        }
                    }
                }
            }
        }
        Ok((self.id, None))
    }
}
