use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Result};

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyTuple;

use tokio::net::UdpSocket;
use tokio::sync::mpsc::{self, channel, unbounded_channel};
use tokio::sync::Notify;

mod messages;
mod network;
mod python;
mod shutdown;
mod wireguard;

use messages::TransportCommand;
use network::NetworkTask;
use python::{event_queue_unavailable, py_to_socketaddr, socketaddr_to_py, PyInteropTask, TcpStream};
use shutdown::ShutdownTask;
use wireguard::WireGuardTaskBuilder;

#[pyclass]
struct WireguardServer {
    /// queue of events to be sent to the Python interop task
    event_tx: mpsc::UnboundedSender<TransportCommand>,
    /// local address of the WireGuard UDP socket
    local_addr: SocketAddr,
    /// barrier for notifying subtasks of requested server shutdown
    sd_trigger: Arc<Notify>,
    /// barrier for getting notified of successful server shutdown
    sd_handler: Arc<Notify>,
}

#[pymethods]
impl WireguardServer {
    /// Send an individual UDP datagram using the specified source and destination addresses.
    fn send_datagram(&self, data: Vec<u8>, src_addr: &PyTuple, dst_addr: &PyTuple) -> PyResult<()> {
        let cmd = TransportCommand::SendDatagram {
            data,
            src_addr: py_to_socketaddr(src_addr)?,
            dst_addr: py_to_socketaddr(dst_addr)?,
        };

        self.event_tx.send(cmd).map_err(event_queue_unavailable)?;
        Ok(())
    }

    /// Terminate the WireGuard server.
    fn stop(&self) {
        // notify tasks to shut down
        self.sd_trigger.notify_waiters();
        // notify waiters of server shutdown
        self.sd_handler.notify_one();
    }

    /// Wait until the WireGuard server terminates.
    fn wait<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let barrier = self.sd_handler.clone();

        pyo3_asyncio::tokio::future_into_py(py, async move {
            barrier.notified().await;
            Ok(())
        })
    }

    /// Get the local address the WireGuard server is listening on.
    fn getsockname(&self, py: Python) -> PyObject {
        socketaddr_to_py(py, self.local_addr)
    }

    fn __repr__(&self) -> String {
        format!("WireguardServer({})", self.local_addr)
    }
}

impl WireguardServer {
    pub async fn init(
        host: String,
        port: u16,
        private_key: String,
        peer_public_keys: Vec<(String, Option<[u8; 32]>)>,
        py_tcp_handler: PyObject,
        py_udp_handler: PyObject,
    ) -> Result<WireguardServer> {
        let private_key: Arc<X25519SecretKey> = Arc::new(private_key.parse().map_err(|error: &str| anyhow!(error))?);

        // configure WireGuard peers
        let peers = peer_public_keys
            .into_iter()
            .map(|(peer_public_key, preshared_key)| {
                let key = Arc::new(X25519PublicKey::from_str(&peer_public_key).map_err(|error: &str| anyhow!(error))?);
                Ok((key, preshared_key))
            })
            .collect::<Result<Vec<(Arc<X25519PublicKey>, Option<[u8; 32]>)>>>()?;

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

        // bind to UDP socket
        let socket = UdpSocket::bind((host, port)).await?;
        let local_addr = socket.local_addr()?;

        // initialize barriers for handling graceful shutdown
        let sd_trigger = Arc::new(Notify::new());
        let sd_handler = Arc::new(Notify::new());

        // initialize WireGuard server
        let mut wg_task_builder =
            WireGuardTaskBuilder::new(private_key, wg_to_smol_tx, smol_to_wg_rx, sd_trigger.clone());
        for (peer_public_key, preshared_key) in peers {
            wg_task_builder.add_peer(peer_public_key, preshared_key)?;
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

        Ok(WireguardServer {
            event_tx,
            local_addr,
            sd_trigger,
            sd_handler,
        })
    }
}

impl Drop for WireguardServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Start a WireGuard server.
#[pyfunction]
fn start_server(
    py: Python<'_>,
    host: String,
    port: u16,
    private_key: String,
    peer_public_keys: Vec<(String, Option<[u8; 32]>)>,
    handle_connection: PyObject,
    receive_datagram: PyObject,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let server = WireguardServer::init(
            host,
            port,
            private_key,
            peer_public_keys,
            handle_connection,
            receive_datagram,
        )
        .await?;
        Ok(server)
    })
}

/// Generate a WireGuard private key and return its base64-encoded representation.
#[pyfunction]
fn genkey() -> String {
    base64::encode(X25519SecretKey::new().as_bytes())
}

/// Return the base64-encoded public key for the passed private key.
#[pyfunction]
fn pubkey(private_key: String) -> PyResult<String> {
    let private_key: X25519SecretKey = private_key
        .parse()
        .map_err(|_| PyValueError::new_err("Invalid private key."))?;
    Ok(base64::encode(private_key.public_key().as_bytes()))
}

#[pymodule]
fn mitmproxy_wireguard(_py: Python, m: &PyModule) -> PyResult<()> {
    // set up the Rust logger to send messages to the Python logger
    pyo3_log::init();

    // set up tracing subscriber for introspection with tokio-console
    #[cfg(debug_assertions)]
    console_subscriber::init();

    m.add_function(wrap_pyfunction!(start_server, m)?)?;
    m.add_function(wrap_pyfunction!(genkey, m)?)?;
    m.add_function(wrap_pyfunction!(pubkey, m)?)?;
    m.add_class::<WireguardServer>()?;
    m.add_class::<TcpStream>()?;
    Ok(())
}
