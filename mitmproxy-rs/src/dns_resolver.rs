use pyo3::types::PyAny;
use pyo3::prelude::*;
use pyo3::exceptions::socket::gaierror;

use mitmproxy::dns::{LookupIpStrategy, ResolveErrorKind, ResponseCode, DNS_SERVERS};


#[pyclass]
#[derive(Copy, Clone)]
pub enum AddressFamily {
    Ipv6Only,
    Ipv4Only,
    DualStack,
}

impl From<AddressFamily> for LookupIpStrategy {
    fn from(value: AddressFamily) -> Self {
        match value {
            AddressFamily::DualStack => LookupIpStrategy::Ipv4AndIpv6,
            AddressFamily::Ipv4Only => LookupIpStrategy::Ipv4Only,
            AddressFamily::Ipv6Only => LookupIpStrategy::Ipv6Only,
        }
    }
}


#[pyfunction]
#[pyo3(signature = (host, family, use_hosts_file=true))]
pub fn getaddrinfo(py: Python<'_>, host: String, family: AddressFamily, use_hosts_file: bool) -> PyResult<Bound<PyAny>> {
    pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
        match mitmproxy::dns::getaddrinfo(host, family.into(), use_hosts_file).await {
            Ok(resp) => {
                Ok(resp.into_iter().map(|ip| ip.to_string()).collect::<Vec<String>>())
            },
            Err(e) => match *e.kind() {
                    ResolveErrorKind::NoRecordsFound { response_code: ResponseCode::NXDomain, .. } => {
                        Err(gaierror::new_err("NXDOMAIN"))
                    }
                    ResolveErrorKind::NoRecordsFound { response_code: ResponseCode::NoError, .. } => {
                        Err(gaierror::new_err("NOERROR"))
                    }
                    _ => Err(gaierror::new_err(e.to_string())),
                }

        }
    })
}

#[pyfunction]
pub fn get_system_dns_servers() -> PyResult<Vec<String>> {
    DNS_SERVERS
        .clone()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("{}", e)))
}
