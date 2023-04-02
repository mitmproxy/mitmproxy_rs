use pyo3::prelude::*;

#[pyclass]
#[derive(Debug)]
pub struct ProcessInfo {
    name: String
}


/// Return a list of all running processes.
#[pyfunction]
pub fn process_list() -> PyResult<Vec<ProcessInfo>> {
    Ok(vec![ProcessInfo { name: "a".into() }, ProcessInfo { name: "b".into() }])
}
