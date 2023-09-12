use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};

use crate::messages::{ConnectionId, TransportCommand, TransportEvent, TunnelInfo};
use crate::network::MAX_PACKET_SIZE;

use crate::packet_sources::ipc::{from_proxy, NewFlow, TcpFlow, UdpFlow};
use crate::packet_sources::{ipc, PacketSourceConf, PacketSourceTask};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use futures_util::SinkExt;
use futures_util::StreamExt;

use prost::bytes::{Buf, BytesMut};
use prost::Message;

use std::process::Stdio;

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
                connection_commands_udp: HashMap::new(),
                transport_events_tx,
                transport_commands_rx,
                conf_rx,
                shutdown,
            },
            conf_tx,
        ))
    }
}

struct RegisterSocketAddr(ConnectionId, SocketAddr, oneshot::Sender<()>);

struct ConnectionTask {
    id: ConnectionId,
    stream: UnixStream,
    commands: UnboundedReceiver<TransportCommand>,
    events: Sender<TransportEvent>,
    read_tx: Option<(usize, oneshot::Sender<Vec<u8>>)>,
    drain_tx: Option<oneshot::Sender<()>>,
    register_addr: UnboundedSender<RegisterSocketAddr>,
}

impl ConnectionTask {
    pub fn new(
        id: ConnectionId,
        stream: UnixStream,
        commands: UnboundedReceiver<TransportCommand>,
        events: Sender<TransportEvent>,
        register_addr: UnboundedSender<RegisterSocketAddr>,
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
    async fn run(mut self) -> Result<()> {
        let len = self.stream.read_u32().await? as usize;

        let mut buf = BytesMut::zeroed(len);
        self.stream.read_exact(&mut buf).await?;
        let Ok(new_flow) = ipc::NewFlow::decode(&buf[..]) else {
            bail!("Received invalid IPC message: {:?}", &buf[..]);
        };

        match new_flow {
            NewFlow {
                message: Some(ipc::new_flow::Message::Tcp(tcp_flow)),
            } => self.handle_tcp(tcp_flow).await,
            NewFlow {
                message: Some(ipc::new_flow::Message::Udp(udp_flow)),
            } => self.handle_udp(udp_flow).await,
            _ => {
                bail!("Received invalid IPC message: {:?}", new_flow);
            }
        }
    }

    async fn handle_udp(mut self, flow: UdpFlow) -> Result<()> {
        dbg!(&flow);
        let mut write_buf = BytesMut::new();
        let mut stream = Framed::new(self.stream, LengthDelimitedCodec::new());

        let tunnel_info = {
            let tun = flow.tunnel_info.expect("no tunnel info");
            TunnelInfo::OsProxy {
                pid: tun.pid,
                process_name: tun.process_name,
                dst_hostname: None, // FIXME: correct?
            }
        };
        let src_addr = {
            let addr = flow.local_address.as_ref().expect("no local address");
            SocketAddr::try_from(addr)?
        };

        let (done_tx, done_rx) = oneshot::channel();
        self.register_addr
            .send(RegisterSocketAddr(self.id, src_addr, done_tx))?;
        done_rx.await?;

        loop {
            tokio::select! {
                next = stream.next() => {
                    let Some(next) = next else {
                        return Ok(())
                    };
                    let buf = next?;
                    let Ok(packet) = ipc::UdpPacket::decode(&buf[..]) else {
                        bail!("Received invalid IPC message: {:?}", &buf[..]);
                    };
                    dbg!("udp packet recvd", &packet.remote_address, &packet.data.len());
                    if let Err(e) = self.events.try_send(TransportEvent::DatagramReceived {
                        data: packet.data,
                        src_addr,
                        dst_addr: packet.remote_address.as_ref().expect("no remote addr").try_into()?,
                        tunnel_info: tunnel_info.clone(),
                    }) {
                        log::debug!("Failed to send UDP packet: {}", e);
                    }
                },
                command = self.commands.recv() => {
                    let Some(command) = command else {
                        return Ok(())
                    };
                    match command {
                        TransportCommand::SendDatagram { data, src_addr, dst_addr } => {
                            dbg!("sending to stream", data.len(), src_addr, dst_addr);
                            let packet = ipc::UdpPacket {
                                data,
                                remote_address: Some(src_addr.into()),
                            };
                            write_buf.reserve(packet.encoded_len());
                            packet.encode(&mut write_buf)?;
                            let d = write_buf.split().freeze();
                            dbg!(d.len());
                            stream.send(d).await?;
                            dbg!("send done");
                        },
                        TransportCommand::ReadData(_, _, _) |
                        TransportCommand::WriteData(_, _) |
                        TransportCommand::DrainWriter(_, _) |
                        TransportCommand::CloseConnection(_, _) => {
                            unreachable!()
                        }
                    }
                }
            }
        }
    }

    async fn handle_tcp(mut self, flow: TcpFlow) -> Result<()> {
        let mut write_buf = BytesMut::new();

        let remote_addr = flow.remote_address.expect("no remote address");

        let src_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let dst_addr = SocketAddr::try_from(&remote_addr)
            .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::UNSPECIFIED, remote_addr.port as u16)));
        let destination_hostname = dst_addr.ip().is_unspecified().then_some(remote_addr.host);
        self.events
            .send(TransportEvent::ConnectionEstablished {
                connection_id: self.id,
                src_addr,
                dst_addr,
                tunnel_info: TunnelInfo::OsProxy {
                    pid: flow.tunnel_info.as_ref().map(|t| t.pid).unwrap_or(0),
                    process_name: flow.tunnel_info.and_then(|t| t.process_name),
                    dst_hostname: destination_hostname,
                },
            })
            .await?;

        loop {
            tokio::select! {
                Ok(()) = self.stream.writable(), if !write_buf.is_empty() => {
                    let _written = self.stream.write_buf(&mut write_buf).await?;
                    if write_buf.is_empty() {
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
    connection_commands_udp: HashMap<SocketAddr, UnboundedSender<TransportCommand>>,
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    conf_rx: UnboundedReceiver<ipc::FromProxy>,
    shutdown: broadcast::Receiver<()>,
}

#[async_trait]
impl PacketSourceTask for MacOsTask {
    async fn run(mut self) -> Result<()> {
        let mut control_channel = Framed::new(self.control_channel, LengthDelimitedCodec::new());

        let (register_addr_tx, mut register_addr_rx) = unbounded_channel::<RegisterSocketAddr>();

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.shutdown.recv() => break,
                _ = control_channel.next() => {
                    bail!("macOS System Extension shut down.")
                },
                Some(RegisterSocketAddr(cid, addr, done)) = register_addr_rx.recv() => {
                    let tx = self.connection_commands.get(&cid).unwrap().clone();
                    self.connection_commands_udp.insert(addr, tx);
                    done.send(()).expect("ok channel dead");
                },
                l = self.listener.accept() => {
                    match l {
                        Ok((stream, _)) => {
                            let (tx, rx) = unbounded_channel();
                            let connection_id = self.connections.len() as ConnectionId;
                            let task = ConnectionTask::new(connection_id, stream, rx, self.transport_events_tx.clone(), register_addr_tx.clone());
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
                    match &cmd {
                        TransportCommand::ReadData(connection_id, _, _)
                        | TransportCommand::WriteData(connection_id, _)
                        | TransportCommand::DrainWriter(connection_id, _)
                        | TransportCommand::CloseConnection(connection_id, _) => {
                            let Some(conn_tx) = self.connection_commands.get(connection_id) else {
                                bail!("Received command for unknown connection: {:?}", &cmd);
                            };
                            conn_tx.send(cmd)?;
                        },
                        TransportCommand::SendDatagram {
                            data: _,
                            src_addr,
                            dst_addr,
                        } => {
                            dbg!("SendDatagram", src_addr, dst_addr);
                            let Some(conn_tx) = self.connection_commands_udp.get(dst_addr) else {
                                bail!("Received command for unknown address: src={:?} dst={:?}", src_addr, dst_addr);
                            };
                            conn_tx.send(cmd)?;
                        },
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
            }
        }

        log::info!("Macos OS proxy task shutting down.");
        Ok(())
    }
}
