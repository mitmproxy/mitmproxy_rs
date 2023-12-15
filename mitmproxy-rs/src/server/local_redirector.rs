use mitmproxy::intercept_conf::InterceptConf;

#[cfg(target_os = "macos")]
use mitmproxy::packet_sources::macos::MacosConf;
#[cfg(windows)]
use mitmproxy::packet_sources::windows::WindowsConf;

use pyo3::prelude::*;
#[cfg(target_os = "macos")]
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

use crate::server::base::Server;
use tokio::sync::mpsc;

#[pyclass(module = "mitmproxy_rs")]
#[derive(Debug)]
pub struct LocalRedirector {
    server: Server,
    conf_tx: mpsc::UnboundedSender<InterceptConf>,
    spec: String,
}

#[pymethods]
impl LocalRedirector {
    /// Return a textual description of the given spec,
    /// or raise a ValueError if the spec is invalid.
    #[staticmethod]
    fn describe_spec(spec: &str) -> PyResult<String> {
        InterceptConf::try_from(spec)
            .map(|conf| conf.description())
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
    }

    /// Set a new intercept spec.
    pub fn set_intercept(&mut self, spec: String) -> PyResult<()> {
        let conf = InterceptConf::try_from(spec.as_str())?;
        self.spec = spec;
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

    pub fn __repr__(&self) -> String {
        format!("Local Redirector({})", self.spec)
    }
}

/// Start an OS-level proxy to intercept traffic from the current machine.
///
/// - `handle_tcp_stream`: An async function that will be called for each new TCP `Stream`.
/// - `handle_udp_stream`: An async function that will be called for each new UDP `Stream`.
///
/// *Availability: Windows and macOS*
#[pyfunction]
#[allow(unused_variables)]
pub fn start_local_redirector(
    py: Python<'_>,
    handle_tcp_stream: PyObject,
    handle_udp_stream: PyObject,
) -> PyResult<&PyAny> {
    #[cfg(windows)]
    {
        let executable_path: PathBuf = py
            .import("mitmproxy_windows")?
            .call_method0("executable_path")?
            .extract()?;
        if !executable_path.exists() {
            return Err(anyhow::anyhow!("{} does not exist", executable_path.display()).into());
        }
        let conf = WindowsConf { executable_path };
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let (server, conf_tx) =
                Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;

            Ok(LocalRedirector {
                server,
                conf_tx,
                spec: "inactive".to_string(),
            })
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
            archive.unpack(destination_path.parent().unwrap())?;
        }
        let conf = MacosConf;
        pyo3_asyncio::tokio::future_into_py(py, async move {
            let (server, conf_tx) = Server::init(conf, handle_connection, receive_datagram).await?;
            Ok(LocalRedirector { server, conf_tx })
        })
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        "OS proxy mode is only available on Windows and macOS",
    ))
}
