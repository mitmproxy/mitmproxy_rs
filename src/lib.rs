#![warn(missing_debug_implementations)]
#![allow(clippy::borrow_deref_ref)]

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;

use pyo3::prelude::*;
use pyo3::types::PyTuple;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, channel, unbounded_channel};
use tokio::sync::Notify;

mod cfg;
mod messages;
mod network;
mod python;
mod shutdown;
mod wireguard;

use cfg::Configuration;
use messages::TransportCommand;
use network::NetworkTask;
use python::{event_queue_unavailable, py_to_socketaddr, socketaddr_to_py, PyInteropTask, TcpStream};
use shutdown::ShutdownTask;
use wireguard::WireGuardTaskBuilder;

/// A running WireGuard server.
///
/// A new server can be started by calling the `start_server` coroutine. Its public API is intended
/// to be similar to the API provided by
/// [`asyncio.Server`](https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.Server)
/// from the Python standard library.
#[pyclass]
#[derive(Debug)]
pub struct Server {
    /// queue of events to be sent to the Python interop task
    event_tx: mpsc::UnboundedSender<TransportCommand>,
    /// local address of the WireGuard UDP socket
    local_addr: SocketAddr,
    /// barrier for notifying subtasks of requested server shutdown
    sd_trigger: Arc<Notify>,
    /// barrier for getting notified of successful server shutdown
    sd_handler: Arc<Notify>,
    /// flag to indicate whether server shutdown is in progress
    closing: bool,
}

#[pymethods]
impl Server {
    /// Send an individual UDP datagram using the specified source and destination addresses.
    ///
    /// The `src_addr` and `dst_addr` arguments are expected to be `(host: str, port: int)` tuples.
    pub fn send_datagram(&self, data: Vec<u8>, src_addr: &PyTuple, dst_addr: &PyTuple) -> PyResult<()> {
        let cmd = TransportCommand::SendDatagram {
            data,
            src_addr: py_to_socketaddr(src_addr)?,
            dst_addr: py_to_socketaddr(dst_addr)?,
        };

        self.event_tx.send(cmd).map_err(event_queue_unavailable)?;
        Ok(())
    }

    /// Request the WireGuard server to gracefully shut down.
    ///
    /// The server will stop accepting new connections on its UDP socket, but will flush pending
    /// outgoing data before shutting down.
    pub fn close(&mut self) {
        if !self.closing {
            self.closing = true;
            log::info!("Shutting down.");

            // notify tasks to shut down
            self.sd_trigger.notify_waiters();
            // notify waiters of server shutdown
            self.sd_handler.notify_one();
        }
    }

    /// Wait until the WireGuard server has shut down.
    ///
    /// This coroutine will yield once pending data has been flushed and all server tasks have
    /// successfully terminated after calling the `Server.close` method.
    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let barrier = self.sd_handler.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            barrier.notified().await;
            Ok(())
        })
    }

    /// Get the local socket address that the WireGuard server is listening on.
    pub fn getsockname(&self, py: Python) -> PyObject {
        socketaddr_to_py(py, self.local_addr)
    }

    pub fn __repr__(&self) -> String {
        format!("Server({})", self.local_addr)
    }
}

impl Server {
    /// Set up and initialize a new WireGuard server.
    pub async fn init(
        host: String,
        cfg: Configuration,
        py_tcp_handler: PyObject,
        py_udp_handler: PyObject,
    ) -> Result<Self> {
        log::debug!("Initializing WireGuard server ...");

        // initialize channels between the WireGuard server and the virtual network device
        let (wg_to_smol_tx, wg_to_smol_rx) = channel(16);
        let (smol_to_wg_tx, smol_to_wg_rx) = channel(16);

        // initialize channels between the virtual network device and the python interop task
        // - only used to notify of incoming connections and datagrams
        let (smol_to_py_tx, smol_to_py_rx) = channel(64);
        // - used to send data and to ask for packets
        // This channel needs to be unbounded because write() is not async.
        let (py_to_smol_tx, py_to_smol_rx) = unbounded_channel();

        let event_tx = py_to_smol_tx.clone();

        // bind to UDP socket(s)
        let socket_addrs = if host.is_empty() {
            vec![
                SocketAddr::new("0.0.0.0".parse().unwrap(), cfg.server_listen_port),
                SocketAddr::new("::".parse().unwrap(), cfg.server_listen_port),
            ]
        } else {
            vec![SocketAddr::new(host.parse()?, cfg.server_listen_port)]
        };

        let socket = UdpSocket::bind(socket_addrs.as_slice()).await?;
        let local_addr = socket.local_addr()?;

        log::debug!(
            "WireGuard server listening for UDP connections on {} ...",
            socket_addrs
                .iter()
                .map(|addr| addr.to_string())
                .collect::<Vec<String>>()
                .join(" and ")
        );

        // initialize barriers for handling graceful shutdown
        let sd_trigger = Arc::new(Notify::new());
        let sd_handler = Arc::new(Notify::new());

        // initialize WireGuard server
        let mut wg_task_builder =
            WireGuardTaskBuilder::new(cfg.server_private_key, wg_to_smol_tx, smol_to_wg_rx, sd_trigger.clone());
        for client in cfg.clients {
            wg_task_builder.add_peer(Arc::new(client.private_key.public_key()), None)?;
        }
        let wg_task = wg_task_builder.build()?;

        // initialize virtual network device
        let nw_task = NetworkTask::new(
            smol_to_wg_tx,
            wg_to_smol_rx,
            smol_to_py_tx,
            py_to_smol_rx,
            sd_trigger.clone(),
        )?;

        // initialize Python interop task
        // Note: Calling into the Python runtime needs to happen on the main thread, it doesn't
        //       seem to work when called from a different task.
        let (py_loop, run_coroutine_threadsafe) = Python::with_gil(|py| -> Result<(PyObject, PyObject)> {
            let py_loop = pyo3_asyncio::tokio::get_current_loop(py)?.into();
            let run_coroutine_threadsafe = py.import("asyncio")?.getattr("run_coroutine_threadsafe")?.into();
            Ok((py_loop, run_coroutine_threadsafe))
        })?;

        let py_task = PyInteropTask::new(
            local_addr,
            py_loop,
            run_coroutine_threadsafe,
            py_to_smol_tx,
            smol_to_py_rx,
            py_tcp_handler,
            py_udp_handler,
            sd_trigger.clone(),
        );

        // spawn tasks
        let wg_handle = tokio::spawn(async move { wg_task.run(socket).await });
        let net_handle = tokio::spawn(async move { nw_task.run().await });
        let py_handle = tokio::spawn(async move { py_task.run().await });

        // initialize and run shutdown handler
        let sd_task = ShutdownTask::new(py_handle, wg_handle, net_handle, sd_trigger.clone(), sd_handler.clone());
        tokio::spawn(async move { sd_task.run().await });

        log::debug!("WireGuard server successfully initialized.");

        Ok(Server {
            event_tx,
            local_addr,
            sd_trigger,
            sd_handler,
            closing: false,
        })
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.close()
    }
}

/// Start a WireGuard server that is configured with the given parameters:
///
/// - `host`: The host address for the WireGuard UDP socket.
/// - `conf`: The WireGuard server configuration.
/// - `handle_connection`: A coroutine that will be called for each new `TcpStream`.
/// - `receive_datagram`: A function that will be called for each received UDP datagram.
///
/// The `receive_datagram` function will be called with the following arguments:
///
/// - payload of the UDP datagram as `bytes`
/// - source address as `(host: str, port: int)` tuple
/// - destination address as `(host: str, port: int)` tuple
#[pyfunction]
pub fn start_server(
    py: Python<'_>,
    host: String,
    conf: Configuration,
    handle_connection: PyObject,
    receive_datagram: PyObject,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let server = Server::init(host, conf, handle_connection, receive_datagram).await?;
        Ok(server)
    })
}

/// This package contains a cross-platform, user-space WireGuard server implementation in Rust,
/// which provides a Python interface that is intended to be similar to the one provided by
/// [`asyncio.start_server`](https://docs.python.org/3/library/asyncio-stream.html#asyncio.start_server)
/// from the Python standard library.
#[pymodule]
pub fn mitmproxy_wireguard(_py: Python, m: &PyModule) -> PyResult<()> {
    // set up the Rust logger to send messages to the Python logger
    pyo3_log::init();

    // set up tracing subscriber for introspection with tokio-console
    #[cfg(feature = "tracing")]
    console_subscriber::init();

    m.add_function(wrap_pyfunction!(start_server, m)?)?;
    m.add_class::<Server>()?;
    m.add_class::<Configuration>()?;
    m.add_class::<TcpStream>()?;

    Ok(())
}
