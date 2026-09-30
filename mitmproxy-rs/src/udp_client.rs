use anyhow::Context;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{Result, anyhow};
use pyo3::prelude::*;
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::mpsc::{UnboundedReceiver, unbounded_channel};
use tokio::sync::oneshot;

use crate::stream::{Stream, StreamState};
use mitmproxy::MAX_PACKET_SIZE;
use mitmproxy::messages::{ConnectionId, TransportCommand, TunnelInfo};
use mitmproxy::packet_sources::udp::remote_host_closed_conn;

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
) -> PyResult<Bound<'_, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
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
            tunnel_info: TunnelInfo::None,
        };

        Ok(stream)
    })
}

/// Open a UDP socket connected to `host:port`.
async fn udp_connect(
    host: String,
    port: u16,
    local_addr: Option<(String, u16)>,
) -> Result<UdpSocket> {
    let mut addrs: Vec<SocketAddr> = lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("unable to resolve hostname: {host}"))?
        .collect();
    mitmproxy::dns::interleave_inplace(&mut addrs, |a| a.is_ipv4());
    let local_addr = local_addr.as_ref().map(|(h, p)| (h.as_str(), *p));

    let mut last_err: Option<anyhow::Error> = None;
    for addr in addrs {
        let socket = match (local_addr, addr) {
            (Some((host, port)), _) => UdpSocket::bind((host, port)).await,
            (None, SocketAddr::V4(_)) => {
                UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)).await
            }
            (None, SocketAddr::V6(_)) => {
                UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).await
            }
        };
        let socket = match socket {
            Ok(s) => s,
            Err(e) => {
                last_err = Some(e.into());
                continue;
            }
        };
        match socket.connect(addr).await {
            Ok(()) => return Ok(socket),
            Err(e) => last_err = Some(e.into()),
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow!("unable to resolve hostname: no addresses for {host}")))
        .with_context(|| format!("unable to connect to {host}"))
}

#[derive(Debug)]
pub struct UdpClientTask {
    socket: UdpSocket,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
}

impl UdpClientTask {
    pub async fn run(mut self) -> Result<()> {
        let mut udp_buf = vec![0; MAX_PACKET_SIZE];

        // this here isn't perfect because we block the entire transport_commands_rx channel if we
        // cannot send (so we also block receiving new packets), but that's hopefully good enough.
        let mut packet_needs_sending = false;
        let mut packet_payload = Vec::new();
        #[cfg(target_os = "macos")]
        let mut send_handoff_retries = 0;

        let mut packet_tx: Option<oneshot::Sender<Vec<u8>>> = None;

        loop {
            tokio::select! {
                // wait for transport_events_tx channel capacity...
                r = self.socket.recv(udp_buf.as_mut_slice()), if packet_tx.is_some() => {
                    if remote_host_closed_conn(&r) {
                        continue;
                    }
                    let len = r.context("UDP recv() failed")?;
                    packet_tx
                        .take()
                        .unwrap()
                        .send(udp_buf[..len].to_vec())
                        .ok();
                },
                // send_to is cancel safe, so we can use that for backpressure.
                e = self.socket.send(&packet_payload), if packet_needs_sending => {
                    #[cfg(target_os = "macos")]
                    if let Err(error) = &e
                        && matches!(error.raw_os_error(), Some(libc::EDESTADDRREQ | libc::ENOTCONN))
                        && send_handoff_retries < 10
                    {
                        // Observed in macOS local mode: sends on our own (excluded) UDP sockets can
                        // briefly fail with EDESTADDRREQ/ENOTCONN, presumably while flow divert hands
                        // the socket back to the regular UDP stack. There is no Apple reference for this.
                        if send_handoff_retries == 0 {
                            log::debug!("macOS UDP connection handoff pending ({error}); retrying up to 10 times");
                        }
                        send_handoff_retries += 1;
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                        continue;
                    }
                    e.context("UDP send() failed")?;
                    #[cfg(target_os = "macos")]
                    {
                        send_handoff_retries = 0;
                    }
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

    #[cfg(target_os = "macos")]
    fn spawn_send(socket: UdpSocket, payload: Vec<u8>) -> tokio::task::JoinHandle<Result<()>> {
        let (tx, rx) = unbounded_channel();
        tx.send(TransportCommand::WriteData(
            ConnectionId::unassigned_udp(),
            payload,
        ))
        .unwrap();
        tokio::spawn(
            UdpClientTask {
                socket,
                transport_commands_rx: rx,
            }
            .run(),
        )
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn udp_send_recovers_when_connected_state_arrives() -> Result<()> {
        use std::time::Duration;
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        let socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        let connector = socket.try_clone()?;
        let task = spawn_send(UdpSocket::from_std(socket)?, b"once".to_vec());
        tokio::time::sleep(Duration::from_millis(2)).await;
        connector.connect(server.local_addr()?)?;
        tokio::time::timeout(Duration::from_secs(1), task).await???;
        let mut buffer = [0; 32];
        let (size, _) =
            tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buffer)).await??;
        assert_eq!(&buffer[..size], b"once");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), server.recv_from(&mut buffer))
                .await
                .is_err(),
            "a recovered send must not duplicate the datagram"
        );
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn udp_send_handoff_retry_is_bounded() -> Result<()> {
        use std::time::{Duration, Instant};
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let start = Instant::now();
        let error =
            tokio::time::timeout(Duration::from_secs(1), spawn_send(socket, b"fail".to_vec()))
                .await??
                .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::EDESTADDRREQ)
        );
        assert!(start.elapsed() >= Duration::from_millis(10));
        Ok(())
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn udp_send_preserves_non_handoff_errors() -> Result<()> {
        use std::time::Duration;
        let server = UdpSocket::bind("127.0.0.1:0").await?;
        let address = server.local_addr()?;
        let socket = udp_connect(address.ip().to_string(), address.port(), None).await?;
        let error =
            tokio::time::timeout(Duration::from_secs(1), spawn_send(socket, vec![0; 65536]))
                .await??
                .unwrap_err();
        assert_eq!(
            error
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::EMSGSIZE)
        );
        Ok(())
    }
}
