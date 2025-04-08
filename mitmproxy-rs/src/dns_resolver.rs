use mitmproxy::dns::{ResolveError, DNS_SERVERS};
use pyo3::exceptions::socket::gaierror;
use pyo3::prelude::*;
use pyo3::types::PyAny;
use std::sync::OnceLock;
use std::{net::IpAddr, net::SocketAddr, sync::Arc};

/// A DNS resolver backed by [hickory-dns](https://github.com/hickory-dns/hickory-dns).
/// This can serve as a replacement for `getaddrinfo` with configurable resolution behavior.
///
/// By default, the resolver will use the name servers configured by the operating system.
/// It can optionally be configured to use custom name servers or ignore the hosts file.
#[pyclass]
pub struct DnsResolver(Arc<mitmproxy::dns::DnsResolver>);

#[pymethods]
impl DnsResolver {
    #[new]
    #[pyo3(signature = (*, name_servers=None, use_hosts_file=true))]
    fn new(name_servers: Option<Vec<IpAddr>>, use_hosts_file: bool) -> PyResult<Self> {
        let name_servers = name_servers.map(|ns| {
            ns.into_iter()
                .map(|ip| SocketAddr::from((ip, 53)))
                .collect()
        });
        let resolver =
            mitmproxy::dns::DnsResolver::new(name_servers, use_hosts_file).map_err(|e| {
                pyo3::exceptions::PyRuntimeError::new_err(format!(
                    "failed to create dns resolver: {}",
                    e
                ))
            })?;
        Ok(Self(Arc::new(resolver)))
    }

    /// Lookup the IPv4 and IPv6 addresses for a hostname.
    ///
    /// Raises `socket.gaierror` if the domain does not exist, has no records, or there is a general connectivity failure.
    pub fn lookup_ip<'py>(&self, py: Python<'py>, host: String) -> PyResult<Bound<'py, PyAny>> {
        let resolver = self.0.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let resolved = resolver.lookup_ip(host).await;
            resolve_result_to_py(resolved)
        })
    }

    /// Lookup the IPv4 addresses for a hostname.
    ///
    /// Raises `socket.gaierror` if the domain does not exist, has no records, or there is a general connectivity failure.
    pub fn lookup_ipv4<'py>(&self, py: Python<'py>, host: String) -> PyResult<Bound<'py, PyAny>> {
        let resolver = self.0.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let resolved = resolver.lookup_ipv4(host).await;
            resolve_result_to_py(resolved)
        })
    }

    /// Lookup the IPv6 addresses for a hostname.
    ///
    /// Raises `socket.gaierror` if the domain does not exist, has no records, or there is a general connectivity failure.
    pub fn lookup_ipv6<'py>(&self, py: Python<'py>, host: String) -> PyResult<Bound<'py, PyAny>> {
        let resolver = self.0.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let resolved = resolver.lookup_ipv6(host).await;
            resolve_result_to_py(resolved)
        })
    }
}

/// Returns the operating system's DNS servers as IP addresses.
/// Raises a RuntimeError on unsupported platforms.
///
/// *Availability: Windows, Unix*
#[pyfunction]
pub fn get_system_dns_servers() -> PyResult<Vec<String>> {
    DNS_SERVERS.clone().map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("failed to get dns servers: {}", e))
    })
}

struct AddrInfoErrorConst(&'static str, OnceLock<isize>);
impl AddrInfoErrorConst {
    const fn new(identifier: &'static str) -> Self {
        AddrInfoErrorConst(identifier, OnceLock::new())
    }
    fn get(&self) -> isize {
        *self.1.get_or_init(|| {
            Python::with_gil(|py| {
                py.import("socket")
                    .and_then(|m| m.getattr(self.0))
                    .and_then(|m| m.extract())
                    .unwrap_or_else(|e| {
                        log::error!("Failed to resolve socket constant: {e}");
                        0
                    })
            })
        })
    }
}

static EAI_AGAIN: AddrInfoErrorConst = AddrInfoErrorConst::new("EAI_AGAIN");
static EAI_NONAME: AddrInfoErrorConst = AddrInfoErrorConst::new("EAI_NONAME");
static EAI_NODATA: AddrInfoErrorConst = AddrInfoErrorConst::new("EAI_NODATA");

fn resolve_result_to_py(resolved: Result<Vec<IpAddr>, ResolveError>) -> Result<Vec<String>, PyErr> {
    match resolved {
        Ok(resp) => Ok(resp
            .into_iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()),
        Err(e) if e.is_nx_domain() => Err(gaierror::new_err((EAI_NONAME.get(), "NXDOMAIN"))),
        Err(e) if e.is_no_records_found() => Err(gaierror::new_err((EAI_NODATA.get(), "NOERROR"))),
        Err(e) => Err(gaierror::new_err((EAI_AGAIN.get(), e.to_string()))),
    }
}
