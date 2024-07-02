use mitmproxy::dns::{
    NameServerConfig, Protocol, ResolveErrorKind, ResolverConfig, ResponseCode, DNS_SERVERS,
};
use pyo3::exceptions::socket::gaierror;
use pyo3::prelude::*;
use pyo3::types::PyAny;
use std::{net::IpAddr, net::SocketAddr, sync::Arc};

#[pyclass]
pub struct DnsResolverBuilder(mitmproxy::dns::DnsResolverBuilder);

#[pymethods]
impl DnsResolverBuilder {
    #[new]
    fn new() -> Self {
        Self(mitmproxy::dns::DnsResolverBuilder::default())
    }

    fn use_hosts_file(&mut self, value: bool) {
        self.0.use_hosts_file(value);
    }

    fn use_name_servers(&mut self, value: Vec<IpAddr>) {
        let mut conf = ResolverConfig::new();
        for ip in value.into_iter() {
            let addr = SocketAddr::from((ip, 53));
            conf.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
            conf.add_name_server(NameServerConfig::new(addr, Protocol::Tcp));
        }
        self.0.use_config(conf);
    }

    fn build(&self) -> PyResult<DnsResolver> {
        let inner = self.0.build().map_err(|e| {
            pyo3::exceptions::PyRuntimeError::new_err(format!(
                "failed to build dns resolver: {}",
                e
            ))
        })?;
        Ok(DnsResolver(Arc::new(inner)))
    }
}

#[pyclass]
pub struct DnsResolver(Arc<mitmproxy::dns::DnsResolver>);

#[pymethods]
impl DnsResolver {
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

#[pyfunction]
pub fn get_system_dns_servers() -> PyResult<Vec<String>> {
    DNS_SERVERS.clone().map_err(|e| {
        pyo3::exceptions::PyRuntimeError::new_err(format!("failed to get dns servers: {}", e))
    })
}
