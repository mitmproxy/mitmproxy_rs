#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use std::str::FromStr;

use mitmproxy_highlight::{Language, Tag};
use pyo3::{exceptions::PyValueError, prelude::*};

/// Transform text into a list of tagged chunks.
///
/// Example:
///
/// ```python
/// from mitmproxy_rs.syntax_highlight import highlight
/// highlighted = highlight("key: 42", "yaml")
/// print(highlighted)  # [('name', 'key'), ('', ': '), ('number', '42')]
/// ```
#[pyfunction]
pub fn highlight(text: String, language: &str) -> PyResult<Vec<(&'static str, String)>> {
    let language = Language::from_str(language)?;
    language
        .highlight(text.as_bytes())
        .map(|chunks| {
            chunks
                .into_iter()
                .map(|(tag, text)| (tag.as_str(), text))
                .collect()
        })
        .map_err(|e| PyValueError::new_err(format!("{:?}", e)))
}

/// Return the list of all possible syntax highlight tags.
#[pyfunction]
pub fn tags() -> PyResult<Vec<&'static str>> {
    Ok(Tag::VALUES
        .iter()
        .map(|tag| tag.as_str())
        .filter(|&x| !x.is_empty())
        .collect())
}

/// Return the list of all supported languages for syntax highlighting.
#[pyfunction]
pub fn languages() -> PyResult<Vec<&'static str>> {
    Ok(Language::VALUES.iter().map(|lang| lang.as_str()).collect())
}
