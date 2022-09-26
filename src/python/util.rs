use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use pyo3::{
    exceptions::PyValueError,
    prelude::*,
    types::{PyString, PyTuple},
};

pub fn socketaddr_to_py(py: Python, s: SocketAddr) -> PyObject {
    match s {
        SocketAddr::V4(addr) => (addr.ip().to_string(), addr.port()).into_py(py),
        SocketAddr::V6(addr) => {
            log::debug!(
                "Converting IPv6 address/port to Python equivalent (not sure if this is correct): {:?}",
                (addr.ip().to_string(), addr.port())
            );
            (addr.ip().to_string(), addr.port()).into_py(py)
        }
    }
}

pub fn py_to_socketaddr(t: &PyTuple) -> PyResult<SocketAddr> {
    if t.len() == 2 {
        let host = t.get_item(0)?.downcast::<PyString>()?;
        let port: u16 = t.get_item(1)?.extract()?;

        let addr = IpAddr::from_str(host.to_str()?)?;
        Ok(SocketAddr::from((addr, port)))
    } else {
        Err(PyValueError::new_err("not a socket address"))
    }
}
