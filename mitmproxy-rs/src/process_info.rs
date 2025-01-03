use std::path::{Path, PathBuf};

#[cfg(any(windows, target_os = "macos"))]
use anyhow::Context;
use pyo3::prelude::*;
#[cfg(any(windows, target_os = "macos"))]
use pyo3::IntoPyObjectExt;

#[cfg(any(windows, target_os = "macos", target_os = "linux"))]
use mitmproxy::processes;

#[pyclass(module = "mitmproxy_rs.process_info", frozen)]
pub struct Process(mitmproxy::processes::ProcessInfo);

#[pymethods]
impl Process {
    /// Absolute path for the executable.
    #[getter]
    fn executable(&self) -> &Path {
        &self.0.executable
    }
    /// Process name suitable for display in the UI.
    #[getter]
    fn display_name(&self) -> &str {
        &self.0.display_name
    }
    /// `True` if the process has a visible window, `False` otherwise.
    /// This information is useful when sorting the process list.
    #[getter]
    fn is_visible(&self) -> bool {
        self.0.is_visible
    }
    /// `True` if the process is a system process, `False` otherwise.
    /// This information is useful to hide noise in the process list.
    #[getter]
    fn is_system(&self) -> bool {
        self.0.is_system
    }
    fn __repr__(&self) -> String {
        format!(
            "Process(executable={:?}, display_name={:?}, is_visible={}, is_system={})",
            self.executable(),
            self.display_name(),
            self.is_visible(),
            self.is_system(),
        )
    }
}

/// Return a list of all running executables.
/// Note that this groups multiple processes by executable name.
///
/// *Availability: Windows, macOS, Linux*
#[pyfunction]
pub fn active_executables() -> PyResult<Vec<Process>> {
    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    {
        processes::active_executables()
            .map(|p| p.into_iter().map(Process).collect())
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        "active_executables not supported on the current OS",
    ))
}

/// Get a PNG icon for an executable path.
///
/// *Availability: Windows, macOS*
#[pyfunction]
#[allow(unused_variables)]
pub fn executable_icon(py: Python<'_>, path: PathBuf) -> PyResult<PyObject> {
    #[cfg(any(windows, target_os = "macos"))]
    {
        let mut icon_cache = processes::ICON_CACHE.lock().unwrap();
        icon_cache
            .get_png(path)
            .context("failed to get image")?
            .into_py_any(py)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        "executable_icon is only available on Windows",
    ))
}
