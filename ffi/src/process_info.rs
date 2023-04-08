use pyo3::prelude::*;
use mitmproxy::windows::processes::active_executables;


#[pyclass(get_all)]
pub struct ProcessList(mitmproxy::windows::processes::ProcessList);
/*
#[pymethods]
impl ProcessList {
    fn method1(&self) -> PyResult<i32> {
        Ok(10)
    }

    fn set_method(&mut self, value: i32) -> PyResult<()> {
        self.num = value;
        Ok(())
    }
}
 */

/// Return a list of all running processes.
#[pyfunction]
pub fn process_list() -> PyResult<ProcessList> {


    Ok(ProcessList(
        active_executables()?
    ))
}
