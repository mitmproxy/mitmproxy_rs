use hickory_resolver::config::{LookupIpStrategy, ResolverConfig, ResolverOpts};
use hickory_resolver::TokioAsyncResolver;
use pyo3::types::PyAny;
use pyo3::prelude::{pyfunction, PyResult, Python};

#[pyfunction]
#[pyo3(signature = (host, is_ipv6))]
pub fn getaddrinfo(py: Python<'_>, host: String, is_ipv6: bool) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let mut opts = ResolverOpts::default();
        if is_ipv6 {
            opts.ip_strategy = LookupIpStrategy::Ipv6Only;
        }
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), opts);
        let response = resolver.lookup_ip(host).await.unwrap();
        let addresses: Vec<String> = response.iter().map(|addr| addr.to_string()).collect();
        Ok(addresses)
    })
}
