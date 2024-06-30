use std::net::SocketAddr;

use mitmproxy::packet_sources::udp::UdpConf;

use pyo3::prelude::*;

use crate::server::base::Server;

use crate::util::socketaddr_to_py;

/// A running UDP server.
///
/// A new server can be started by calling `start_udp_server`.
/// The public API is intended to be similar to the API provided by
/// [`asyncio.Server`](https://docs.python.org/3/library/asyncio-eventloop.html#asyncio.Server)
/// from the Python standard library.
#[pyclass(module = "mitmproxy_rs")]
#[derive(Debug)]
pub struct UdpServer {
    /// local address of the UDP socket
    local_addr: SocketAddr,
    server: Server,
}

#[pymethods]
impl UdpServer {
    /// Request the server to gracefully shut down.
    ///
    /// The server will stop accepting new connections on its UDP socket, but will flush pending
    /// outgoing data before shutting down.
    pub fn close(&mut self) {
        self.server.close()
    }

    /// Wait until the server has shut down.
    ///
    /// This coroutine will yield once pending data has been flushed and all server tasks have
    /// successfully terminated after calling the `Server.close` method.
    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        self.server.wait_closed(py)
    }

    /// Get the local socket address that the UDP server is listening on.
    pub fn getsockname(&self, py: Python) -> PyObject {
        socketaddr_to_py(py, self.local_addr)
    }

    pub fn __repr__(&self) -> String {
        format!("UdpServer({})", self.local_addr)
    }
}

/// Start a UDP server that is configured with the given parameters:
///
/// - `host`: The host address.
/// - `port`: The listen port.
/// - `handle_udp_stream`: An async function that will be called for each new UDP `Stream`.
#[pyfunction]
pub fn start_udp_server(
    py: Python<'_>,
    host: String,
    port: u16,
    handle_udp_stream: PyObject,
) -> PyResult<Bound<PyAny>> {
    let conf = UdpConf { host, port };
    let handle_tcp_stream = py.None();
    pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
        let (server, local_addr) = Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;
        Ok(UdpServer { server, local_addr })
    })
}
