use hickory_resolver::config::{LookupIpStrategy, ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::TokioAsyncResolver;
use once_cell::sync::Lazy;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::{pyfunction, PyResult, Python, Bound};
use pyo3::types::PyAny;
use std::collections::HashSet;
use std::net::IpAddr;

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const AF_UNSPEC: u8 = 0;

static SYSTEM_CONF: Lazy<(ResolverConfig, ResolverOpts)> = Lazy::new(|| read_system_conf().unwrap());

#[pyfunction]
#[pyo3(signature = (host, family=0, use_hosts_file=true))]
pub fn getaddrinfo(py: Python<'_>, host: String, family: u8, use_hosts_file: bool) -> PyResult<Bound<PyAny>> {
    let (config, mut opts) = SYSTEM_CONF.clone();
    opts.use_hosts_file = use_hosts_file;

    opts.ip_strategy = match family {
        AF_UNSPEC => Ok(LookupIpStrategy::Ipv4AndIpv6),
        AF_INET => Ok(LookupIpStrategy::Ipv4Only),
        AF_INET6 => Ok(LookupIpStrategy::Ipv6Only),
        _ => Err(PyValueError::new_err("Invalid family type specified"))
    }.unwrap();

    pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
        let resolver = TokioAsyncResolver::tokio(config, opts);
        let response = resolver.lookup_ip(host).await;
        match response {
            Ok(resp) => {
                let mut addresses = resp.iter().collect();
                if family == AF_UNSPEC {
                    addresses = _interleave_addrinfos(addresses, 1);
                }

                let addresses_str: Vec<String> = addresses.iter().map(|addr| addr.to_string()).collect();
                Ok(addresses_str)
            },
            Err(e) => match *e.kind() {
                    ResolveErrorKind::NoRecordsFound { response_code, .. }
                    if response_code == ResponseCode::NXDomain => {
                        Err(PyValueError::new_err(e.to_string()))
                    }
                    _ => Err(PyRuntimeError::new_err(e.to_string())),
                }

        }
    })
}

#[pyfunction]
pub fn get_system_dns_server() -> PyResult<HashSet<String>> {
    let (config, _opts) = SYSTEM_CONF.clone();
    // using HashSet to eliminate duplicate name_servers
    let name_servers: HashSet<String> = config.name_servers()
    .iter()
    .map(|ns| ns.socket_addr.ip().to_string())
    .collect();
    Ok(name_servers)
}

fn _interleave_addrinfos(addrinfos: Vec<IpAddr>, first_address_family_count: usize) -> Vec<IpAddr> {
    let (mut ipv4_addrs, mut ipv6_addrs): (Vec<IpAddr>, Vec<IpAddr>) = addrinfos
        .into_iter()
        .partition(|addr| addr.is_ipv4());

    let mut reordered = Vec::new();

    if first_address_family_count > 1 {
        let take_count = (first_address_family_count - 1).min(ipv4_addrs.len());
        reordered.extend(ipv4_addrs.drain(0..take_count));
    }

    let min_size = ipv4_addrs.len().min(ipv6_addrs.len());
    for _ in 0..min_size {
        reordered.push(ipv4_addrs.pop().unwrap());
        reordered.push(ipv6_addrs.pop().unwrap());
    }
    if !ipv4_addrs.is_empty() {
        reordered.extend(ipv4_addrs.drain(..));
    }
    if !ipv6_addrs.is_empty() {
        reordered.extend(ipv6_addrs.drain(..));
    }

    reordered
}
