use hickory_resolver::config::LookupIpStrategy;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::TokioAsyncResolver;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::{pyfunction, PyResult, Python, Bound};
use pyo3::types::PyAny;
use std::collections::HashSet;

#[pyfunction]
#[pyo3(signature = (host, family=0, use_hosts_file=true))]
pub fn getaddrinfo(py: Python<'_>, host: String, family: u8, use_hosts_file: bool) -> PyResult<Bound<PyAny>> {
    let (config, mut opts) = read_system_conf().unwrap();
    opts.use_hosts_file = use_hosts_file;

    opts.ip_strategy = match family {
        0 => Ok(LookupIpStrategy::Ipv4AndIpv6),
        1 => Ok(LookupIpStrategy::Ipv4Only),
        2 => Ok(LookupIpStrategy::Ipv6Only),
        3 => Ok(LookupIpStrategy::Ipv4thenIpv6),
        4 => Ok(LookupIpStrategy::Ipv6thenIpv4),
        _ => Err(PyValueError::new_err("Invalid family type specified"))
    }.unwrap();

    pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
        let resolver = TokioAsyncResolver::tokio(config, opts);
        let response = resolver.lookup_ip(host).await.unwrap();
        let addresses: Vec<String> = response.iter().map(|addr| addr.to_string()).collect();
        Ok(addresses)
    })
}

#[pyfunction]
pub fn get_system_dns_server() -> PyResult<HashSet<String>> {
    let (config, _opts) = read_system_conf().unwrap();
    let name_servers: HashSet<String> = config.name_servers()
    .iter()
    .map(|ns| ns.socket_addr.ip().to_string())
    .collect();
    Ok(name_servers)
}
