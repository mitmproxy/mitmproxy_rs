use mitmproxy::dns::{ResolveErrorKind, ResponseCode, DNS_SERVERS};
use pyo3::exceptions::socket::gaierror;
use pyo3::prelude::*;
use pyo3::types::PyAny;
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
    #[pyo3(signature = (*, name_servers, use_hosts_file=true))]
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
        pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
            match resolver.lookup_ip(host).await {
                Ok(resp) => Ok(resp
                    .into_iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<String>>()),
                Err(e) => match *e.kind() {
                    ResolveErrorKind::NoRecordsFound {
                        response_code: ResponseCode::NXDomain,
                        ..
                    } => Err(gaierror::new_err("NXDOMAIN")),
                    ResolveErrorKind::NoRecordsFound {
                        response_code: ResponseCode::NoError,
                        ..
                    } => Err(gaierror::new_err("NOERROR")),
                    _ => Err(gaierror::new_err(e.to_string())),
                },
            }
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
