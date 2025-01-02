use crate::server::base::Server;
use pyo3::prelude::*;

#[cfg(target_os = "linux")]
use nix::unistd;

/// An open TUN interface.
///
/// A new tun interface can be created by calling `create_tun_interface`.
#[pyclass(module = "mitmproxy_rs.tun")]
#[derive(Debug)]
pub struct TunInterface {
    tun_name: String,
    server: Server,
}

#[pymethods]
impl TunInterface {
    /// Get the tunnel interface name.
    pub fn tun_name(&self) -> &str {
        &self.tun_name
    }

    /// Request the interface to be closed.
    pub fn close(&mut self) {
        self.server.close()
    }

    /// Wait until the interface has shut down.
    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        self.server.wait_closed(py)
    }

    /// Returns a `str` describing why tun mode is unavailable, or `None` if TUN mode is available.
    ///
    /// Reasons for unavailability may be an unsupported platform, or missing privileges.
    #[staticmethod]
    pub fn unavailable_reason() -> Option<String> {
        #[cfg(target_os = "linux")]
        if !unistd::geteuid().is_root() {
            Some(String::from("mitmproxy is not running as root"))
        } else {
            None
        }

        #[cfg(not(target_os = "linux"))]
        Some(String::from("OS not supported for TUN proxy mode"))
    }

    pub fn __repr__(&self) -> String {
        format!("TunInterface({})", self.tun_name)
    }
}

/// Create a TUN interface that is configured with the given parameters:
///
/// - `handle_tcp_stream`: An async function that will be called for each new TCP `Stream`.
/// - `handle_udp_stream`: An async function that will be called for each new UDP `Stream`.
/// - `tun_name`: An optional string to specify the tunnel name. By default, tun0, ... will be used.
///
/// *Availability: Linux*
#[pyfunction]
#[allow(unused_variables)]
#[pyo3(signature = (handle_tcp_stream, handle_udp_stream, tun_name=None))]
pub fn create_tun_interface(
    py: Python<'_>,
    handle_tcp_stream: PyObject,
    handle_udp_stream: PyObject,
    tun_name: Option<String>,
) -> PyResult<Bound<PyAny>> {
    #[cfg(target_os = "linux")]
    {
        let conf = mitmproxy::packet_sources::tun::TunConf { tun_name };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (server, tun_name) =
                Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;
            Ok(TunInterface { server, tun_name })
        })
    }
    #[cfg(not(target_os = "linux"))]
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        TunInterface::unavailable_reason(),
    ))
}
