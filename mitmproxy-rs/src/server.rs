use crate::task::PyInteropTask;

use crate::util::{socketaddr_to_py, string_to_key};

use anyhow::Result;
use mitmproxy::intercept_conf::InterceptConf;

#[cfg(target_os = "macos")]
use mitmproxy::packet_sources::macos::MacosConf;
#[cfg(windows)]
use mitmproxy::packet_sources::windows::WindowsConf;
use mitmproxy::packet_sources::wireguard::WireGuardConf;
use mitmproxy::packet_sources::{PacketSourceConf, PacketSourceTask};
use mitmproxy::shutdown::ShutdownTask;
use pyo3::prelude::*;
use std::net::SocketAddr;
#[cfg(target_os = "macos")]
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

use tokio::{sync::broadcast, sync::mpsc};
use x25519_dalek::PublicKey;

#[derive(Debug)]
pub struct Server {
    /// channel for notifying subtasks of requested server shutdown
    sd_trigger: broadcast::Sender<()>,
    /// channel for getting notified of successful server shutdown
    sd_barrier: broadcast::Sender<()>,
    /// flag to indicate whether server shutdown is in progress
    closing: bool,
}

impl Server {
    pub fn close(&mut self) {
        if !self.closing {
            self.closing = true;
            // XXX: Does not really belong here.
            #[cfg(target_os = "macos")]
            {
                if Path::new("/Applications/MitmproxyAppleTunnel.app").exists() {
                    std::fs::remove_dir_all("/Applications/MitmproxyAppleTunnel.app").expect(
                        "Failed to remove MitmproxyAppleTunnel.app from Applications folder",
                    );
                }
            }
            log::info!("Shutting down.");
            // notify tasks to shut down
            let _ = self.sd_trigger.send(());
        }
    }

    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let mut barrier = self.sd_barrier.subscribe();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            barrier.recv().await.map_err(|_| {
                pyo3::exceptions::PyRuntimeError::new_err("Failed to wait for server shutdown.")
            })
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
        let typ = packet_source_conf.name();
        log::debug!("Initializing {} ...", typ);

        // initialize channels between the virtual network device and the python interop task
        // - only used to notify of incoming connections and datagrams
        let (transport_events_tx, transport_events_rx) = mpsc::channel(256);
        // - used to send data and to ask for packets
        // This channel needs to be unbounded because write() is not async.
        let (transport_commands_tx, transport_commands_rx) = mpsc::unbounded_channel();

        // initialize barriers for handling graceful shutdown
        let shutdown = broadcast::channel(1).0;
        let shutdown_done = broadcast::channel(1).0;

        let (packet_source_task, data) = packet_source_conf
            .build(
                transport_events_tx,
                transport_commands_rx,
                shutdown.subscribe(),
            )
            .await?;

        // initialize Python interop task
        // Note: The current asyncio event loop needs to be determined here on the main thread.
        let py_loop: PyObject = Python::with_gil(|py| {
            let py_loop = pyo3_asyncio::tokio::get_current_loop(py)?.into_py(py);
            Ok::<PyObject, PyErr>(py_loop)
        })?;

        let py_task = PyInteropTask::new(
            py_loop,
            transport_commands_tx,
            transport_events_rx,
            py_tcp_handler,
            py_udp_handler,
            shutdown.subscribe(),
        );

        // spawn tasks
        let wg_handle = tokio::spawn(async move { packet_source_task.run().await });
        let py_handle = tokio::spawn(async move { py_task.run().await });

        // initialize and run shutdown handler
        let sd_task = ShutdownTask::new(
            py_handle,
            wg_handle,
            shutdown.clone(),
            shutdown_done.clone(),
        );
        tokio::spawn(async move { sd_task.run().await });

        log::debug!("{} successfully initialized.", typ);

        Ok((
            Server {
                sd_trigger: shutdown,
                sd_barrier: shutdown_done,
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

#[pyclass(module = "mitmproxy_rs")]
#[derive(Debug)]
pub struct OsProxy {
    server: Server,
    conf_tx: mpsc::UnboundedSender<InterceptConf>,
}

#[pymethods]
impl OsProxy {
    /// Return a textual description of the given spec,
    /// or raise a ValueError if the spec is invalid.
    #[staticmethod]
    fn describe_spec(spec: &str) -> PyResult<String> {
        InterceptConf::try_from(spec)
            .map(|conf| conf.description())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Set a new intercept spec.
    pub fn set_intercept(&self, spec: String) -> PyResult<()> {
        let conf = InterceptConf::try_from(spec.as_str())?;
        self.conf_tx
            .send(conf)
            .map_err(crate::util::event_queue_unavailable)?;
        Ok(())
    }

    /// Close the OS proxy server.
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
#[pyclass(module = "mitmproxy_rs")]
#[derive(Debug)]
pub struct WireGuardServer {
    /// local address of the WireGuard UDP socket
    local_addr: SocketAddr,
    server: Server,
}

#[pymethods]
impl WireGuardServer {
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

/// Start an OS-level proxy to intercept traffic from the current machine.
///
/// *Availability: Windows*
#[pyfunction]
#[allow(unused_variables)]
pub fn start_os_proxy(
    py: Python<'_>,
    handle_connection: PyObject,
    receive_datagram: PyObject,
) -> PyResult<&PyAny> {
    #[cfg(windows)]
    {
        let executable_path: PathBuf = py
            .import("mitmproxy_windows")?
            .getattr("executable_path")?
            .extract()?;
        if !executable_path.exists() {
            return Err(anyhow::anyhow!("{} does not exist", executable_path.display()).into());
        }
        let conf = WindowsConf { executable_path };
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let (server, conf_tx) = Server::init(conf, handle_connection, receive_datagram).await?;

            Ok(OsProxy { server, conf_tx })
        })
    }
    #[cfg(target_os = "macos")]
    {
        let destination_path = Path::new("/Applications/Mitmproxy Redirector.app");
        if destination_path.exists() {
            log::info!("Using existing mitmproxy redirector app.");
        } else {
            let filename = py.import("mitmproxy_macos")?.filename()?;

            let source_path = Path::new(filename)
                .parent()
                .ok_or_else(|| anyhow::anyhow!("invalid path"))?
                .join("Mitmproxy Redirector.app.tar");

            if !source_path.exists() {
                return Err(anyhow::anyhow!("{} does not exist", source_path.display()).into());
            }

            // XXX: tokio here?
            let redirector_tar = std::fs::File::open(source_path)?;
            let mut archive = tar::Archive::new(redirector_tar);
            std::fs::create_dir(destination_path)?;
            archive.unpack(destination_path)?;
        }
        let conf = MacosConf;
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let (server, conf_tx) = Server::init(conf, handle_connection, receive_datagram).await?;
            Ok(OsProxy { server, conf_tx })
        })
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        "OS proxy mode is only available on Windows and macOS",
    ))
}
