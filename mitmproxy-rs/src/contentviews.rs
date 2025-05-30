use mitmproxy_contentviews::{Metadata, Prettify, Reencode};
use pyo3::{exceptions::PyValueError, prelude::*};
use std::cell::OnceCell;
use std::path::{Path, PathBuf};

pub struct PythonMetadata<'py> {
    inner: Bound<'py, PyAny>,
    content_type: OnceCell<Option<String>>,
    protobuf_definitions: OnceCell<Option<std::path::PathBuf>>,
    path: OnceCell<Option<String>>,
}

impl<'py> PythonMetadata<'py> {
    pub fn new(inner: Bound<'py, PyAny>) -> Self {
        PythonMetadata {
            inner,
            content_type: OnceCell::new(),
            protobuf_definitions: OnceCell::new(),
            path: OnceCell::new(),
        }
    }
}

impl Metadata for PythonMetadata<'_> {
    fn content_type(&self) -> Option<&str> {
        self.content_type
            .get_or_init(|| {
                self.inner
                    .getattr("content_type")
                    .ok()?
                    .extract::<String>()
                    .ok()
            })
            .as_deref()
    }

    fn get_header(&self, name: &str) -> Option<String> {
        let http_message = self.inner.getattr("http_message").ok()?;
        let headers = http_message.getattr("headers").ok()?;
        headers.get_item(name).ok()?.extract::<String>().ok()
    }

    fn get_path(&self) -> Option<&str> {
        self.path
            .get_or_init(|| {
                let flow = self.inner.getattr("flow").ok()?;
                let request = flow.getattr("request").ok()?;
                request.getattr("path").ok()?.extract::<String>().ok()
            })
            .as_deref()
    }

    fn protobuf_definitions(&self) -> Option<&Path> {
        self.protobuf_definitions
            .get_or_init(|| {
                self.inner
                    .getattr("protobuf_definitions")
                    .ok()?
                    .extract::<PathBuf>()
                    .ok()
            })
            .as_deref()
    }

    fn is_http_request(&self) -> bool {
        let Ok(http_message) = self.inner.getattr("http_message") else {
            return false;
        };
        let Ok(request) = self
            .inner
            .getattr("flow")
            .and_then(|flow| flow.getattr("request"))
        else {
            return false;
        };
        http_message.is(&request)
    }
}

impl<'py> FromPyObject<'py> for PythonMetadata<'py> {
    fn extract_bound(ob: &Bound<'py, PyAny>) -> PyResult<Self> {
        Ok(PythonMetadata::new(ob.clone()))
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
            .map_err(|e| PyValueError::new_err(format!("{:?}", e)))
    }

    /// Return the priority of this view for rendering data.
    pub fn render_priority(&self, data: Vec<u8>, metadata: PythonMetadata) -> PyResult<f32> {
        Ok(self.0.render_priority(&data, &metadata))
    }

    /// Optional syntax highlighting that should be applied to the prettified output.
    #[getter]
    pub fn syntax_highlight(&self) -> &'static str {
        self.0.syntax_highlight().as_str()
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
            .map_err(|e| PyValueError::new_err(format!("{:?}", e)))
    }

    fn __repr__(self_: PyRef<'_, Self>) -> PyResult<String> {
        Ok(format!(
            "<mitmproxy_rs.contentview.InteractiveContentview: {}>",
            self_.as_super().name()
        ))
    }
}
