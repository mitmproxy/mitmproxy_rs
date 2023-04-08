use std::collections::HashMap;
use std::io::Cursor;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use mitmproxy::windows::processes::{active_executables, image, ProcessList};

#[pyclass(module = "mitmproxy_rs", frozen)]
pub struct Process(mitmproxy::windows::processes::ProcessInfo);

#[pymethods]
impl Process {
    #[getter]
    fn executable(&self) -> &str {
        &self.0.executable
    }
    #[getter]
    fn display_name(&self) -> &str {
        &self.0.display_name
    }
    #[getter]
    fn icon(&self) -> Option<u64> {
        self.0.icon
    }
    #[getter]
    fn is_visible(&self) -> bool {
        self.0.is_visible
    }
    #[getter]
    fn is_system(&self) -> bool {
        self.0.is_system
    }
    fn __repr__(&self) -> String {
        format!(
            "Process(executable={:?}, display_name={:?}, icon={:?}, is_visible={}, is_windows={})",
            self.executable(),
            self.display_name(),
            self.icon(),
            self.is_visible(),
            self.is_system(),
        )
    }
}


#[pyclass(module = "mitmproxy_rs", frozen)]
pub struct ProcessIcon(image::RgbaImage);

#[pymethods]
impl ProcessIcon {
    fn png_bytes(&self, py: Python<'_>) -> PyResult<PyObject> {
        let mut c = Cursor::new(Vec::new());
        self.0.write_to(
            &mut c,
            image::ImageOutputFormat::Png,
        ).map_err(|e| PyRuntimeError::new_err(format!("{}", e)))?;
        Ok(PyBytes::new(py, &c.into_inner()).into())
    }
}


/// Return a list of all running processes.
#[pyfunction]
pub fn process_list(_py: Python<'_>) -> PyResult<(Vec<Process>, HashMap<u64, ProcessIcon>)> {
    let ProcessList { icons, processes } =
        active_executables()
            .map_err(|e| PyRuntimeError::new_err(format!("{}", e)))?;

    let icons = icons.into_iter().map(|(k, v)| (k, ProcessIcon(v))).collect();
    let processes = processes.into_iter().map(Process).collect();
    /*let processes: Vec<&PyDict> = {
        let mut v = Vec::with_capacity(processes.len());
        for p in processes {
            let dict = PyDict::new(py);
            dict.set_item("executable", p.executable)?;
            dict.set_item("display_name", p.display_name)?;
            dict.set_item("icon", p.icon)?;
            dict.set_item("is_visible", p.is_visible)?;
            dict.set_item("is_windows", p.is_windows)?;
            v.push(dict);
        }
        v
    };*/
    Ok((processes, icons))
}
