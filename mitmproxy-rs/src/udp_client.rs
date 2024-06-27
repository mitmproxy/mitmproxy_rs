use anyhow::Context;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::Result;
use pyo3::prelude::*;
use tokio::net::{lookup_host, UdpSocket};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};
use tokio::sync::oneshot;

use crate::stream::{Stream, StreamState};
use mitmproxy::messages::{ConnectionId, TransportCommand, TunnelInfo};
use mitmproxy::MAX_PACKET_SIZE;

/// Start a UDP client that is configured with the given parameters:
///
/// - `host`: The host address.
/// - `port`: The listen port.
/// - `local_addr`: The local address to bind to.
#[pyfunction]
#[pyo3(signature = (host, port, *, local_addr = None))]
pub fn open_udp_connection(
    py: Python<'_>,
    host: String,
    port: u16,
    local_addr: Option<(String, u16)>,
) -> PyResult<Bound<PyAny>> {
    pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
        let socket = udp_connect(host, port, local_addr).await?;

        let peername = socket.peer_addr()?;
        let sockname = socket.local_addr()?;

        let (command_tx, command_rx) = unbounded_channel();

        tokio::spawn(async {
            let task = UdpClientTask {
                socket,
                transport_commands_rx: command_rx,
            };
            if let Err(e) = task.run().await {
                log::error!("UDP client errored: {e}");
            }
        });

        let stream = Stream {
            connection_id: ConnectionId::unassigned_udp(),
            state: StreamState::Open,
            command_tx,
            peername,
            sockname,
            tunnel_info: TunnelInfo::Udp,
        };

        Ok(stream)
    })
}

/// Open an UDP socket from bind_to to host:port.
/// This is a bit trickier than expected because we want to support IPv4 and IPv6.
async fn udp_connect(
    host: String,
    port: u16,
    local_addr: Option<(String, u16)>,
) -> Result<UdpSocket> {
    let addrs: Vec<SocketAddr> = lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("unable to resolve hostname: {host}"))?
        .collect();

    let socket = if let Some((host, port)) = local_addr {
        UdpSocket::bind((host.as_str(), port))
            .await
            .with_context(|| format!("unable to bind to ({}, {})", host, port))?
    } else if addrs.iter().any(|x| x.is_ipv4()) {
        // we initially tried to bind to IPv6 by default if that doesn't fail,
        // but binding mysteriously works if there are only IPv4 addresses in addrs,
        // and then we get a weird "invalid argument" error when calling socket.recv().
        // So we just do the lazy thing and do IPv4 by default.
        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            .await
            .context("unable to bind to 127.0.0.1:0")?
    } else {
        UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0))
            .await
            .context("unable to bind to [::]:0")?
    };

    socket
        .connect(addrs.as_slice())
        .await
        .with_context(|| format!("unable to connect to {host}"))?;
    Ok(socket)
}

#[derive(Debug)]
pub struct UdpClientTask {
    socket: UdpSocket,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
}

impl UdpClientTask {
    pub async fn run(mut self) -> Result<()> {
        let mut udp_buf = [0; MAX_PACKET_SIZE];

        // this here isn't perfect because we block the entire transport_commands_rx channel if we
        // cannot send (so we also block receiving new packets), but that's hopefully good enough.
        let mut packet_needs_sending = false;
        let mut packet_payload = Vec::new();

        let mut packet_tx: Option<oneshot::Sender<Vec<u8>>> = None;

        loop {
            tokio::select! {
                // wait for transport_events_tx channel capacity...
                len = self.socket.recv(&mut udp_buf), if packet_tx.is_some() => {
                    let len = len.context("UDP recv() failed")?;
                    packet_tx
                        .take()
                        .unwrap()
                        .send(udp_buf[..len].to_vec())
                        .ok();
                },
                // send_to is cancel safe, so we can use that for backpressure.
                e = self.socket.send(&packet_payload), if packet_needs_sending => {
                    e.context("UDP send() failed")?;
                    packet_needs_sending = false;
                },
                command = self.transport_commands_rx.recv(), if !packet_needs_sending => {
                    let Some(command) = command else {
                        break;
                    };
                    match command {
                        TransportCommand::ReadData(_,_,tx) => {
                            packet_tx = Some(tx);
                        },
                        TransportCommand::WriteData(_, data) => {
                            packet_payload = data;
                            packet_needs_sending = true;
                        },
                        TransportCommand::DrainWriter(_,tx) => {
                            tx.send(()).ok();
                        },
                        TransportCommand::CloseConnection(_, half_close) => {
                            if !half_close {
                                break;
                            }
                        },
                    }
                }
            }
        }

        assert!(!packet_needs_sending);

        log::debug!("UDP client task shutting down.");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_udp_client_echo() -> Result<()> {
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = server.local_addr()?;

        let socket = udp_connect(addr.ip().to_string(), addr.port(), None).await?;

        let (command_tx, command_rx) = unbounded_channel();

        let handle = tokio::spawn(
            UdpClientTask {
                socket,
                transport_commands_rx: command_rx,
            }
            .run(),
        );
        let cid = ConnectionId::unassigned_udp();

        command_tx.send(TransportCommand::WriteData(cid, b"Hello World".to_vec()))?;

        let mut recv_buf = [0u8; 20];
        let (n, src) = server.recv_from(&mut recv_buf).await?;
        assert_eq!(&recv_buf[..n], b"Hello World");

        server.send_to(b"Hello back", src).await?;

        let (tx, rx) = oneshot::channel();
        command_tx.send(TransportCommand::ReadData(cid, 0, tx))?;
        assert_eq!(rx.await?, b"Hello back");

        command_tx.send(TransportCommand::CloseConnection(cid, false))?;
        handle.await??;
        Ok(())
    }
}
