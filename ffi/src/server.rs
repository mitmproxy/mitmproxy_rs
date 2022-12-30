use std::net::SocketAddr;
use std::sync::Arc;

#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use pyo3::{prelude::*, types::PyTuple};
use tokio::{sync::broadcast, sync::mpsc, sync::Notify};
use x25519_dalek::PublicKey;

use mitmproxy::messages::TransportCommand;
use mitmproxy::network::NetworkTask;
#[cfg(windows)]
use mitmproxy::packet_sources::windows::{InterceptConf, WindowsConf, WindowsIPC, PID};
use mitmproxy::packet_sources::wireguard::WireGuardConf;
use mitmproxy::packet_sources::{PacketSourceConf, PacketSourceTask};
use mitmproxy::shutdown::ShutdownTask;

use crate::task::PyInteropTask;
use crate::tcp_stream::event_queue_unavailable;
use crate::util::{py_to_socketaddr, socketaddr_to_py, string_to_key};

// use interprocess::os::windows::named_pipe::{PipeListenerOptions, PipeMode};
// use interprocess::os::windows::named_pipe::tokio::{DuplexMsgPipeStream, PipeListener, PipeListenerOptionsExt};

#[derive(Debug)]
pub struct Server {
    /// queue of events to be sent to the Python interop task
    event_tx: mpsc::UnboundedSender<TransportCommand>,
    /// channel for notifying subtasks of requested server shutdown
    sd_trigger: broadcast::Sender<()>,
    /// channel for getting notified of successful server shutdown
    sd_barrier: Arc<Notify>,
    /// flag to indicate whether server shutdown is in progress
    closing: bool,
}

impl Server {
    pub fn send_datagram(
        &self,
        data: Vec<u8>,
        src_addr: &PyTuple,
        dst_addr: &PyTuple,
    ) -> PyResult<()> {
        let cmd = TransportCommand::SendDatagram {
            data,
            src_addr: py_to_socketaddr(src_addr)?,
            dst_addr: py_to_socketaddr(dst_addr)?,
        };

        self.event_tx.send(cmd).map_err(event_queue_unavailable)?;
        Ok(())
    }

    pub fn close(&mut self) {
        if !self.closing {
            self.closing = true;
            log::info!("Shutting down.");

            // notify tasks to shut down
            let _ = self.sd_trigger.send(());
        }
    }

    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let barrier = self.sd_barrier.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            barrier.notified().await;
            Ok(())
        })
    }
}

impl Server {
    /// Set up and initialize a new WireGuard server.
    pub async fn init<T>(
        packet_source_conf: T,
        py_tcp_handler: PyObject,
        py_udp_handler: PyObject,
    ) -> Result<(Self, T::Data)>
    where
        T: PacketSourceConf,
    {
        log::debug!("Initializing WireGuard server ...");

        // initialize channels between the WireGuard server and the virtual network device
        let (wg_to_smol_tx, wg_to_smol_rx) = mpsc::channel(256);
        let (smol_to_wg_tx, smol_to_wg_rx) = mpsc::channel(256);

        // initialize channels between the virtual network device and the python interop task
        // - only used to notify of incoming connections and datagrams
        let (smol_to_py_tx, smol_to_py_rx) = mpsc::channel(256);
        // - used to send data and to ask for packets
        // This channel needs to be unbounded because write() is not async.
        let (py_to_smol_tx, py_to_smol_rx) = mpsc::unbounded_channel();

        let event_tx = py_to_smol_tx.clone();

        // initialize barriers for handling graceful shutdown
        let (sd_trigger, _sd_watcher) = broadcast::channel(1);
        let sd_barrier = Arc::new(Notify::new());

        let (wg_task, data) = packet_source_conf
            .build(wg_to_smol_tx, smol_to_wg_rx, sd_trigger.subscribe())
            .await?;

        // initialize virtual network device
        let nw_task = NetworkTask::new(
            smol_to_wg_tx,
            wg_to_smol_rx,
            smol_to_py_tx,
            py_to_smol_rx,
            sd_trigger.subscribe(),
        )?;

        // initialize Python interop task
        // Note: The current asyncio event loop needs to be determined here on the main thread.
        let py_loop: PyObject = Python::with_gil(|py| {
            let py_loop = pyo3_asyncio::tokio::get_current_loop(py)?.into_py(py);
            Ok::<PyObject, PyErr>(py_loop)
        })?;

        let py_task = PyInteropTask::new(
            py_loop,
            py_to_smol_tx,
            smol_to_py_rx,
            py_tcp_handler,
            py_udp_handler,
            sd_trigger.subscribe(),
        );

        // spawn tasks
        let wg_handle = tokio::spawn(async move { wg_task.run().await });
        let net_handle = tokio::spawn(async move { nw_task.run().await });
        let py_handle = tokio::spawn(async move { py_task.run().await });

        // initialize and run shutdown handler
        let sd_task = ShutdownTask::new(
            py_handle,
            wg_handle,
            net_handle,
            sd_trigger.clone(),
            sd_barrier.clone(),
        );
        tokio::spawn(async move { sd_task.run().await });

        log::debug!("WireGuard server successfully initialized.");

        Ok((
            Server {
                event_tx,
                sd_trigger,
                sd_barrier,
                closing: false,
            },
            data,
        ))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.close()
    }
}

#[cfg(windows)]
#[pyclass]
#[derive(Debug)]
pub struct WindowsProxy {
    server: Server,
    conf_tx: mpsc::UnboundedSender<WindowsIPC>,
}

#[cfg(windows)]
#[pymethods]
impl WindowsProxy {
    pub fn set_intercept(&self, spec: String) -> PyResult<()> {
        let conf = if spec.is_empty() {
            InterceptConf::new(vec![std::process::id()], vec![], true)
        } else {
            let mut pids = vec![];
            let mut procs = vec![];
            for part in spec.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    return Err(anyhow!("invalid intercept spec: {}", spec).into());
                }
                match part.parse::<PID>() {
                    Ok(pid) => pids.push(pid),
                    Err(_) => procs.push(part.to_string()),
                }
            }
            InterceptConf::new(pids, procs, false)
        };

        self.conf_tx
            .send(WindowsIPC::SetIntercept(conf))
            .map_err(event_queue_unavailable)?;
        Ok(())
    }

    pub fn send_datagram(
        &self,
        data: Vec<u8>,
        src_addr: &PyTuple,
        dst_addr: &PyTuple,
    ) -> PyResult<()> {
        self.server.send_datagram(data, src_addr, dst_addr)
    }

    pub fn close(&mut self) {
        self.server.close()
    }

    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        self.server.wait_closed(py)
    }
}

/// A running WireGuard server.
///
/// A new server can be started by calling the `start_wireguard_server` coroutine. Its public API is intended
/// to be similar to the API provided by
/// [`asyncio.Server`](https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.Server)
/// from the Python standard library.
#[pyclass]
#[derive(Debug)]
pub struct WireGuardServer {
    /// local address of the WireGuard UDP socket
    local_addr: SocketAddr,
    server: Server,
}

#[pymethods]
impl WireGuardServer {
    /// Send an individual UDP datagram using the specified source and destination addresses.
    ///
    /// The `src_addr` and `dst_addr` arguments are expected to be `(host: str, port: int)` tuples.
    pub fn send_datagram(
        &self,
        data: Vec<u8>,
        src_addr: &PyTuple,
        dst_addr: &PyTuple,
    ) -> PyResult<()> {
        self.server.send_datagram(data, src_addr, dst_addr)
    }

    /// Request the WireGuard server to gracefully shut down.
    ///
    /// The server will stop accepting new connections on its UDP socket, but will flush pending
    /// outgoing data before shutting down.
    pub fn close(&mut self) {
        self.server.close()
    }

    /// Wait until the WireGuard server has shut down.
    ///
    /// This coroutine will yield once pending data has been flushed and all server tasks have
    /// successfully terminated after calling the `Server.close` method.
    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        self.server.wait_closed(py)
    }

    /// Get the local socket address that the WireGuard server is listening on.
    pub fn getsockname(&self, py: Python) -> PyObject {
        socketaddr_to_py(py, self.local_addr)
    }

    pub fn __repr__(&self) -> String {
        format!("WireGuardServer({})", self.local_addr)
    }
}

/// Start a WireGuard server that is configured with the given parameters:
///
/// - `host`: The host address for the WireGuard UDP socket.
/// - `port`: The listen port for the WireGuard server. The default port for WireGuard is `51820`.
/// - `private_key`: The private X25519 key for the WireGuard server as a base64-encoded string.
/// - `peer_public_keys`: List of public X25519 keys for WireGuard peers as base64-encoded strings.
/// - `handle_connection`: A coroutine that will be called for each new `TcpStream`.
/// - `receive_datagram`: A function that will be called for each received UDP datagram.
///
/// The `receive_datagram` function will be called with the following arguments:
///
/// - payload of the UDP datagram as `bytes`
/// - source address as `(host: str, port: int)` tuple
/// - destination address as `(host: str, port: int)` tuple
#[pyfunction]
pub fn start_wireguard_server(
    py: Python<'_>,
    host: String,
    port: u16,
    private_key: String,
    peer_public_keys: Vec<String>,
    handle_connection: PyObject,
    receive_datagram: PyObject,
) -> PyResult<&PyAny> {
    let private_key = string_to_key(private_key)?;

    let peer_public_keys = peer_public_keys
        .into_iter()
        .map(string_to_key)
        .collect::<PyResult<Vec<PublicKey>>>()?;

    let conf = WireGuardConf {
        host,
        port,
        private_key,
        peer_public_keys,
    };

    pyo3_asyncio::tokio::future_into_py(py, async move {
        let (server, local_addr) = Server::init(conf, handle_connection, receive_datagram).await?;
        Ok(WireGuardServer { server, local_addr })
    })
}

#[cfg(windows)]
#[pyfunction]
pub fn start_windows_proxy(
    py: Python<'_>,
    handle_connection: PyObject,
    receive_datagram: PyObject,
) -> PyResult<&PyAny> {
    // 2022: Ideally we'd use importlib.resources here, but that only provides `as_file` for
    // individual files. We'd need something like `as_dir` to ensure that redirector.exe and the
    // WinDivert dll/lib/sys files are in a single directory. So we just use __file__for now. 🤷
    let module_dir = py.import("mitmproxy_rs")?.filename()?;
    let executable_path = format!(r"{}\{}", module_dir, "windows-redirector.exe");

    let conf = WindowsConf { executable_path };
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let (server, conf_tx) = Server::init(conf, handle_connection, receive_datagram).await?;

        Ok(WindowsProxy { server, conf_tx })
    })
}
