use hickory_resolver::TokioAsyncResolver;
use hickory_resolver::config::*;
use pyo3::prelude::*;
use hickory_resolver::proto::rr::RecordType;
use pyo3::exceptions::PyValueError;

#[pyfunction]
#[pyo3(signature = (host, record_type))]
pub fn getaddrinfo(
    py: Python<'_>,
    host: String,
    record_type: u32,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let record_type = match record_type {
            1 => RecordType::A,
            28 => RecordType::AAAA,
            // TODO: Add more record types
            _ => return Err(PyValueError::new_err("Unsupported record type"))
        };
        let resolver = TokioAsyncResolver::tokio(
                ResolverConfig::default(),
                ResolverOpts::default()
            );
        let response = resolver.lookup(host, record_type).await.unwrap();
        let addresses: Vec<String> = response.iter().map(|addr| addr.to_string()).collect();
        Ok(addresses)
    })
}
