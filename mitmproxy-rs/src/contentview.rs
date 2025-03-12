use anyhow::Result;
use mitmproxy::contentviews::Contentview;
use pyo3::prelude::*;

#[pyclass]
pub struct PyContentview(&'static dyn Contentview);

impl PyContentview {
    pub fn new<'py>(
        py: Python<'py>,
        contentview: &'static dyn Contentview,
    ) -> PyResult<Bound<'py, Self>> {
        PyContentview(contentview).into_pyobject(py)
    }
}

#[pymethods]
impl PyContentview {
    #[getter]
    pub fn name(&self) -> &str {
        self.0.name()
    }

    pub fn deserialize<'py>(&self, data: Vec<u8>) -> Result<String> {
        self.0.deserialize(data)
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!("<{} Contentview>", self.0.name()))
    }
}
