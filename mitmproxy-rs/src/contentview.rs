use mitmproxy::contentviews::{Metadata, Prettify, Reencode};
use pyo3::{exceptions::PyValueError, prelude::*};

pub struct PythonMetadata<'py>(Bound<'py, PyAny>);

impl Metadata for PythonMetadata<'_> {
    fn content_type(&self) -> Option<String> {
        self.0
            .getattr("content_type")
            .ok()?
            .extract::<String>()
            .ok()
    }
}

impl<'py> FromPyObject<'py> for PythonMetadata<'py> {
    fn extract_bound(ob: &Bound<'py, PyAny>) -> PyResult<Self> {
        Ok(PythonMetadata(ob.clone()))
    }
}

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
    pub fn prettify(&self, data: Vec<u8>, metadata: PythonMetadata) -> PyResult<String> {
        self.0
            .prettify(&data, &metadata)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Return the priority of this view for rendering data.
    pub fn render_priority(&self, data: Vec<u8>, metadata: PythonMetadata) -> PyResult<f64> {
        Ok(self.0.render_priority(&data, &metadata))
    }

    /// Optional syntax highlighting that should be applied to the prettified output.
    #[getter]
    pub fn syntax_highlight(&self) -> String {
        self.0.syntax_highlight().to_string()
    }

    fn __lt__(&self, py: Python<'_>, other: PyObject) -> PyResult<bool> {
        Ok(self.name() < other.getattr(py, "name")?.extract::<String>(py)?.as_str())
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
    pub fn reencode(&self, data: &str, metadata: PythonMetadata) -> PyResult<Vec<u8>> {
        self.0
            .reencode(data, &metadata)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    fn __repr__(self_: PyRef<'_, Self>) -> PyResult<String> {
        Ok(format!(
            "<mitmproxy_rs.contentview.InteractiveContentview: {}>",
            self_.as_super().name()
        ))
    }
}
