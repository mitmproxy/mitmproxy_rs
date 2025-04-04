#[allow(unused_imports)]
use anyhow::{anyhow, Result};

use pyo3::{exceptions::PyValueError, prelude::*};

fn str_to_language(s: &str) -> PyResult<mitmproxy::syntax_highlight::Language> {
    match s {
        "xml" => Ok(mitmproxy::syntax_highlight::Language::Xml),
        "yaml" => Ok(mitmproxy::syntax_highlight::Language::Yaml),
        other => Err(PyErr::new::<PyValueError, _>(format!(
            "Unsupported language: {other}"
        ))),
    }
}

/// Transform a text into tagged chunks for text.
#[pyfunction]
pub fn highlight(s: String, language: &str) -> PyResult<Vec<(&'static str, String)>> {
    let language = str_to_language(language)?;
    language.highlight(s.as_bytes())
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// Return the list of all possible tags for a given language.
#[pyfunction]
pub fn all_tags(language: &str) -> PyResult<&[&str]> {
    let language = str_to_language(language)?;
    Ok(language.all_tags())
}
