use std::net::{IpAddr, SocketAddr};

use crate::util::string_to_key;

use mitmproxy::packet_sources::wireguard::WireGuardConf;

use pyo3::prelude::*;

use boringtun::x25519::PublicKey;

use crate::server::base::Server;

/// A running WireGuard server.
///
/// A new server can be started by calling `start_udp_server`.
/// The public API is intended to be similar to the API provided by
/// [`asyncio.Server`](https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.Server)
/// from the Python standard library.
#[pyclass(module = "mitmproxy_rs.wireguard")]
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
    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        self.server.wait_closed(py)
    }

    /// Get the local socket address that the WireGuard server is listening on.
    pub fn getsockname(&self) -> (String, u16) {
        (self.local_addr.ip().to_string(), self.local_addr.port())
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
/// - `handle_tcp_stream`: An async function that will be called for each new TCP `Stream`.
/// - `handle_udp_stream`: An async function that will be called for each new UDP `Stream`.
#[pyfunction]
pub fn start_wireguard_server(
    py: Python<'_>,
    host: IpAddr,
    port: u16,
    private_key: String,
    peer_public_keys: Vec<String>,
    handle_tcp_stream: PyObject,
    handle_udp_stream: PyObject,
) -> PyResult<Bound<PyAny>> {
    let private_key = string_to_key(private_key)?;
    let peer_public_keys = peer_public_keys
        .into_iter()
        .map(string_to_key)
        .collect::<PyResult<Vec<PublicKey>>>()?;
    let conf = WireGuardConf {
        listen_addr: SocketAddr::from((host, port)),
        private_key,
        peer_public_keys,
    };
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        let (server, local_addr) = Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;
        Ok(WireGuardServer { server, local_addr })
    })
}
