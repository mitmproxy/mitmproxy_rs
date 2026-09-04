#![cfg_attr(not(target_os = "macos"), allow(dead_code, unused_imports))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::messages::{ConnectionIdGenerator, TransportCommand, TransportEvent, TunnelInfo};

use crate::intercept_conf::InterceptConf;
use crate::ipc;
use crate::ipc::{NewFlow, TcpFlow, UdpFlow};
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};
use crate::shutdown;
use anyhow::{Context, Result, bail};
use futures_util::SinkExt;
use futures_util::StreamExt;

use prost::Message;
use prost::bytes::Bytes;
use prost::bytes::BytesMut;

use std::process::Stdio;

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use crate::network::udp::ConnectionState;
use tokio::process::Command;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::sync::oneshot;
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

impl PacketSourceConf for MacosConf {
    type Task = MacOsTask;
    type Data = UnboundedSender<InterceptConf>;

    fn name(&self) -> &'static str {
        "macOS proxy"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        _transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> Result<(Self::Task, Self::Data)> {
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
                transport_events_tx,
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
    connections: JoinSet<Result<()>>,
    transport_events_tx: Sender<TransportEvent>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    shutdown: shutdown::Receiver,
}

impl PacketSourceTask for MacOsTask {
    async fn run(mut self) -> Result<()> {
        let mut control_channel = Framed::new(self.control_channel, LengthDelimitedCodec::new());

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
                        Ok(Ok(())) => (),
                        Ok(Err(e)) => log::error!("Connection task failure: {e:?}"),
                        Err(e) => log::error!("Connection task panic: {e:?}"),
                    }
                },
                l = self.listener.accept() => {
                    match l {
                        Ok((stream, _)) => {
                            let task = ConnectionTask::new(
                                stream,
                                self.transport_events_tx.clone(),
                                self.shutdown.clone(),
                            );
                            self.connections.spawn(task.run());
                        },
                        Err(e) => log::error!("Error accepting connection from macos-redirector: {e}")
                    }
                },
                // pipe through changes to the intercept list
                Some(conf) = self.conf_rx.recv() => {
                    let msg = ipc::InterceptConf::from(conf).encode_to_vec();
                    control_channel.send(Bytes::from(msg)).await.context("Failed to write to control channel")?;
                },
            }
        }

        log::info!("Macos OS proxy task shutting down.");
        Ok(())
    }
}

struct ConnectionTask {
    stream: UnixStream,
    events: Sender<TransportEvent>,
    shutdown: shutdown::Receiver,
}

impl ConnectionTask {
    pub fn new(
        stream: UnixStream,
        events: Sender<TransportEvent>,
        shutdown: shutdown::Receiver,
    ) -> Self {
        Self {
            stream,
            events,
            shutdown,
        }
    }
    async fn run(mut self) -> Result<()> {
        let new_flow = {
            let len = self
                .stream
                .read_u32()
                .await
                .context("Failed to read handshake.")? as usize;
            let mut buf = vec![0; len];
            self.stream
                .read_exact(&mut buf)
                .await
                .context("Failed to read handshake contents.")?;
            NewFlow::decode(buf.as_slice()).context("Invalid handshake IPC")?
        };

        match new_flow {
            NewFlow {
                message: Some(ipc::new_flow::Message::Tcp(tcp_flow)),
            } => self
                .handle_tcp(tcp_flow)
                .await
                .context("failed to handle TCP stream"),
            NewFlow {
                message: Some(ipc::new_flow::Message::Udp(udp_flow)),
            } => self
                .handle_udp(udp_flow)
                .await
                .context("failed to handle UDP stream"),
            _ => bail!("Received invalid IPC message: {new_flow:?}"),
        }
    }

    async fn handle_udp(mut self, flow: UdpFlow) -> Result<()> {
        // For UDP connections, we pass length-delimited protobuf messages over the unix socket
        // in both directions.
        let mut write_buf = BytesMut::new();
        let mut stream = Framed::new(self.stream, LengthDelimitedCodec::new());

        let tunnel_info = {
            let Some(tun) = flow.tunnel_info else {
                bail!("no tunnel info")
            };
            TunnelInfo::LocalRedirector {
                pid: tun.pid,
                process_name: tun.process_name,
                remote_endpoint: None,
            }
        };
        let local_address = {
            let Some(addr) = &flow.local_address else {
                bail!("no local address")
            };
            SocketAddr::try_from(addr)
                .with_context(|| format!("invalid local_address: {addr:?}"))?
        };
        let mut remote_address = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0);
        let (command_tx, mut command_rx) = unbounded_channel();

        let mut first_packet = Some((tunnel_info, local_address, command_tx));

        let mut state = ConnectionState::default();

        loop {
            tokio::select! {
                _ = self.shutdown.recv() => break,
                packet = stream.next(), if state.packet_queue_len() < 10 => {
                    let Some(packet) = packet else {
                        // extension closed the flow
                        state.close();
                        break;
                    };
                    let packet = ipc::UdpPacket::decode(
                        packet.context("IPC read error")?
                    ).context("invalid IPC message")?;
                    let dst_addr = {
                        let Some(dst_addr) = &packet.remote_address else { bail!("no remote addr") };
                        SocketAddr::try_from(dst_addr).with_context(|| format!("invalid remote_address: {dst_addr:?}"))?
                    };

                    // We can only send ConnectionEstablished once we know the destination address.
                    if let Some((tunnel_info, local_address, command_tx)) = first_packet.take() {
                        remote_address = dst_addr;
                        self.events.send(TransportEvent::ConnectionEstablished {
                            connection_id: ConnectionIdGenerator::udp().next_id(),
                            src_addr: local_address,
                            dst_addr,
                            tunnel_info,
                            command_tx: Some(command_tx),
                        }).await?;
                    } else if remote_address != dst_addr {
                        bail!("UDP packet destinations do not match: {remote_address} -> {dst_addr}")
                    }
                    // TODO: Make ConnectionState accept Bytes, not Vec<u8>
                    state.add_packet(packet.data.to_vec());
                },
                Some(command) = command_rx.recv() => {
                    match command {
                        TransportCommand::ReadData(_, _, tx) => {
                            state.add_reader(tx);
                        },
                        TransportCommand::WriteData(_, data) => {
                            assert!(first_packet.is_none());
                            let packet = ipc::UdpPacket {
                                data: Bytes::from(data),
                                remote_address: Some(remote_address.into()),
                            };
                            write_buf.reserve(packet.encoded_len());
                            packet.encode(&mut write_buf)?;
                            // Awaiting here isn't ideal because it blocks reading, but what to do.
                            stream.send(write_buf.split().freeze()).await.ok();
                        },
                        TransportCommand::DrainWriter(_, tx) => {
                            tx.send(()).ok();
                        },
                        TransportCommand::CloseConnection(_, half_close) => {
                            if !half_close {
                                state.close();
                                break;
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_tcp(mut self, flow: TcpFlow) -> Result<()> {
        let mut write_buf = BytesMut::new();
        let mut drain_tx: Option<oneshot::Sender<()>> = None;
        let mut read_tx: Option<(usize, oneshot::Sender<Vec<u8>>)> = None;

        let (command_tx, mut command_rx) = unbounded_channel();

        let remote = flow.remote_address.expect("no remote address");
        let src_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
        let dst_addr = SocketAddr::try_from(&remote)
            .unwrap_or_else(|_| SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)));
        let tunnel_info = TunnelInfo::LocalRedirector {
            pid: flow.tunnel_info.as_ref().and_then(|t| t.pid),
            process_name: flow.tunnel_info.and_then(|t| t.process_name),
            remote_endpoint: Some((remote.host, remote.port as u16)),
        };

        self.events
            .send(TransportEvent::ConnectionEstablished {
                connection_id: ConnectionIdGenerator::tcp().next_id(),
                src_addr,
                dst_addr,
                tunnel_info,
                command_tx: Some(command_tx),
            })
            .await?;

        loop {
            tokio::select! {
                _ = self.shutdown.recv() => break,
                Ok(()) = self.stream.writable(), if !write_buf.is_empty() => {
                    let Ok(_) = self.stream.write_buf(&mut write_buf).await else {
                        break;  // Client has disconnected.
                    };
                    if write_buf.is_empty()
                        && let Some(tx) = drain_tx.take() {
                            tx.send(()).ok();
                        }
                },
                Ok(()) = self.stream.readable(), if read_tx.is_some() => {
                    let (n, tx) = read_tx.take().unwrap();
                    let mut data = Vec::with_capacity(n);
                    self.stream.read_buf(&mut data).await.context("failed to read from socket")?;
                    tx.send(data).ok();
                },
                Some(command) = command_rx.recv() => {
                    match command {
                        TransportCommand::ReadData(_, n, tx) => {
                            assert!(read_tx.is_none());
                            read_tx = Some((n as usize, tx));
                        },
                        TransportCommand::WriteData(_, data) => {
                            write_buf.extend_from_slice(data.as_slice());
                        },
                        TransportCommand::DrainWriter(_, tx) => {
                            assert!(drain_tx.is_none());
                            if write_buf.is_empty() {
                                tx.send(()).ok();
                            } else {
                                drain_tx = Some(tx);
                            }
                        },
                        TransportCommand::CloseConnection(_, half_close) => {
                            self.stream.flush().await.ok(); // supposedly this is a no-op on unix sockets.
                            self.stream.shutdown().await.ok();
                            if !half_close {
                                break;
                            }
                        }
                    }
                },
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;
    use tokio::sync::watch;

    fn udp_handshake() -> NewFlow {
        NewFlow {
            message: Some(ipc::new_flow::Message::Udp(UdpFlow {
                local_address: Some(ipc::Address {
                    host: "127.0.0.1".into(),
                    port: 12345,
                }),
                tunnel_info: Some(ipc::TunnelInfo {
                    pid: Some(42),
                    process_name: Some("test".into()),
                }),
            })),
        }
    }

    async fn write_handshake(client: &mut UnixStream, handshake: &NewFlow) {
        let bytes = handshake.encode_to_vec();
        client.write_u32(bytes.len() as u32).await.unwrap();
        client.write_all(&bytes).await.unwrap();
        client.flush().await.unwrap();
    }

    async fn spawn_connection_task(
        server: UnixStream,
    ) -> (
        tokio::task::JoinHandle<Result<()>>,
        mpsc::Receiver<TransportEvent>,
        watch::Sender<()>,
    ) {
        let (events_tx, events_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = shutdown::channel();
        let handle = tokio::spawn(ConnectionTask::new(server, events_tx, shutdown_rx).run());
        (handle, events_rx, shutdown_tx)
    }

    /// Redirector EOF before the first datagram must complete the task.
    /// `Some(packet) = stream.next()` ignores `None`, so the UnixStream leaked forever.
    #[tokio::test]
    async fn udp_eof_before_first_datagram_completes() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (handle, mut events_rx, _shutdown_tx) = spawn_connection_task(server).await;

        write_handshake(&mut client, &udp_handshake()).await;
        drop(client);

        timeout(Duration::from_secs(1), handle)
            .await
            .expect("UDP task hung after redirector EOF before the first datagram")
            .unwrap()
            .unwrap();

        assert!(
            events_rx.try_recv().is_err(),
            "ConnectionEstablished must not be sent when no datagram arrived"
        );
    }

    /// EOF after a datagram must also complete without waiting for CloseConnection.
    #[tokio::test]
    async fn udp_eof_after_first_datagram_completes() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let (handle, mut events_rx, _shutdown_tx) = spawn_connection_task(server).await;

        write_handshake(&mut client, &udp_handshake()).await;

        let mut framed = Framed::new(client, LengthDelimitedCodec::new());
        let packet = ipc::UdpPacket {
            data: Bytes::from_static(b"hello"),
            remote_address: Some(ipc::Address {
                host: "8.8.8.8".into(),
                port: 53,
            }),
        };
        framed
            .send(Bytes::from(packet.encode_to_vec()))
            .await
            .unwrap();
        drop(framed);

        timeout(Duration::from_secs(1), handle)
            .await
            .expect("UDP task hung after redirector EOF following a datagram")
            .unwrap()
            .unwrap();

        match events_rx.try_recv() {
            Ok(TransportEvent::ConnectionEstablished { .. }) => {}
            other => panic!("expected ConnectionEstablished, got {other:?}"),
        }
    }
}
