use anyhow::{anyhow, Result};
use mitmproxy::contentviews::{Prettify, Reencode};
use pyo3::prelude::*;

#[pyclass(frozen, module = "mitmproxy_rs.contentviews", subclass)]
pub struct Contentview(&'static dyn Prettify);

impl Contentview {
    pub fn new<'py>(
        py: Python<'py>,
        contentview: &'static dyn Prettify,
    ) -> PyResult<Bound<'py, Self>> {
        Contentview(contentview).into_pyobject(py)
    }
}

#[pymethods]
impl Contentview {
    /// The name of this contentview.
    #[getter]
    pub fn name(&self) -> &str {
        self.0.name()
    }

    /// Pretty-print an (encoded) message.
    pub fn prettify<'py>(&self, data: Vec<u8>) -> Result<String> {
        self.0.prettify(data).map_err(|e| anyhow!("{e}"))
    }

    fn __repr__(&self) -> PyResult<String> {
        Ok(format!(
            "<mitmproxy_rs.contentview.Contentview: {}>",
            self.0.name()
        ))
    }
}

#[pyclass(frozen, module = "mitmproxy_rs.contentviews", extends=Contentview)]
pub struct InteractiveContentview(&'static dyn Reencode);

impl InteractiveContentview {
    /// Argument passed twice because of https://github.com/rust-lang/rust/issues/65991
    pub fn new<'py, T: Prettify + Reencode>(
        py: Python<'py>,
        cv: &'static T,
    ) -> PyResult<Bound<'py, Self>> {
        let cls =
            PyClassInitializer::from(Contentview(cv)).add_subclass(InteractiveContentview(cv));
        Bound::new(py, cls)
    }
}

#[pymethods]
impl InteractiveContentview {
    pub fn reencode<'py>(&self, data: String) -> Result<Vec<u8>> {
        self.0.reencode(data).map_err(|e| anyhow!("{e}"))
    }

    fn __repr__(self_: PyRef<'_, Self>) -> PyResult<String> {
        Ok(format!(
            "<mitmproxy_rs.contentview.InteractiveContentview: {}>",
            self_.as_super().name()
        ))
    }
}
