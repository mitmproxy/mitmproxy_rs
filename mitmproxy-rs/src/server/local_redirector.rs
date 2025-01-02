use mitmproxy::intercept_conf::InterceptConf;

#[cfg(target_os = "linux")]
use mitmproxy::packet_sources::linux::LinuxConf;
#[cfg(target_os = "macos")]
use mitmproxy::packet_sources::macos::MacosConf;
#[cfg(windows)]
use mitmproxy::packet_sources::windows::WindowsConf;

use pyo3::prelude::*;

use crate::server::base::Server;
use tokio::sync::mpsc;

#[pyclass(module = "mitmproxy_rs.local")]
#[derive(Debug)]
pub struct LocalRedirector {
    server: Server,
    conf_tx: mpsc::UnboundedSender<InterceptConf>,
    spec: String,
}

impl LocalRedirector {
    pub fn new(server: Server, conf_tx: mpsc::UnboundedSender<InterceptConf>) -> Self {
        Self {
            server,
            conf_tx,
            spec: "inactive".to_string(),
        }
    }
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

    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        self.server.wait_closed(py)
    }

    /// Returns a `str` describing why local redirect mode is unavailable, or `None` if it is available.
    ///
    /// Reasons for unavailability may be an unsupported platform, or missing privileges.
    #[staticmethod]
    pub fn unavailable_reason() -> Option<String> {
        #[cfg(any(windows, target_os = "macos"))]
        return None;

        #[cfg(target_os = "linux")]
        if nix::unistd::geteuid().is_root() {
            None
        } else {
            Some("mitmproxy is not running as root.".to_string())
        }

        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        Some(format!(
            "Local redirect mode is not supported on {}",
            std::env::consts::OS
        ))
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
/// *Availability: Windows, Linux, and macOS*
#[pyfunction]
#[allow(unused_variables)]
pub fn start_local_redirector(
    py: Python<'_>,
    handle_tcp_stream: PyObject,
    handle_udp_stream: PyObject,
) -> PyResult<Bound<PyAny>> {
    #[cfg(windows)]
    {
        let executable_path: std::path::PathBuf = py
            .import("mitmproxy_windows")?
            .call_method0("executable_path")?
            .extract()?;
        if !executable_path.exists() {
            return Err(anyhow::anyhow!("{} does not exist", executable_path.display()).into());
        }
        let conf = WindowsConf { executable_path };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (server, conf_tx) =
                Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;

            Ok(LocalRedirector::new(server, conf_tx))
        })
    }
    #[cfg(target_os = "linux")]
    {
        let executable_path: std::path::PathBuf = py
            .import("mitmproxy_linux")?
            .call_method0("executable_path")?
            .extract()?;
        if !executable_path.exists() {
            return Err(anyhow::anyhow!("{} does not exist", executable_path.display()).into());
        }
        let conf = LinuxConf { executable_path };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (server, conf_tx) =
                Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;

            Ok(LocalRedirector::new(server, conf_tx))
        })
    }
    #[cfg(target_os = "macos")]
    {
        let mut copy_task = None;
        let destination_path = std::path::Path::new("/Applications/Mitmproxy Redirector.app");
        if destination_path.exists() {
            log::info!("Using existing mitmproxy redirector app.");
        } else {
            let filename = py.import("mitmproxy_macos")?.filename()?;

            let source_path = std::path::Path::new(filename.to_str()?)
                .parent()
                .ok_or_else(|| anyhow::anyhow!("invalid path"))?
                .join("Mitmproxy Redirector.app.tar");

            if !source_path.exists() {
                return Err(anyhow::anyhow!("{} does not exist", source_path.display()).into());
            }

            copy_task = Some(move || {
                let redirector_tar = std::fs::File::open(source_path)?;
                let mut archive = tar::Archive::new(redirector_tar);
                archive.unpack(destination_path.parent().unwrap())
            });
        }
        let conf = MacosConf;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if let Some(copy_task) = copy_task {
                tokio::task::spawn_blocking(copy_task)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to copy: {}", e))??;
            }
            let (server, conf_tx) =
                Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;
            Ok(LocalRedirector::new(server, conf_tx))
        })
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        LocalRedirector::unavailable_reason(),
    ))
}
