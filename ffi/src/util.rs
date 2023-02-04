use data_encoding::BASE64;
use pyo3::exceptions::PyOSError;
use pyo3::types::{PyString, PyTuple};
use pyo3::{exceptions::PyValueError, prelude::*};
use rand_core::OsRng;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use tokio::sync::mpsc;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn string_to_key<T>(data: String) -> PyResult<T>
where
    T: From<[u8; 32]>,
{
    BASE64
        .decode(data.as_bytes())
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(T::from)
        .ok_or_else(|| PyValueError::new_err("Invalid key."))
}

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

pub fn event_queue_unavailable<T>(_: mpsc::error::SendError<T>) -> PyErr {
    PyOSError::new_err("Server has been shut down.")
}

/// Generate a WireGuard private key, analogous to the `wg genkey` command.
#[pyfunction]
pub fn genkey() -> String {
    BASE64.encode(&StaticSecret::new(OsRng).to_bytes())
}

/// Derive a WireGuard public key from a private key, analogous to the `wg pubkey` command.
#[pyfunction]
pub fn pubkey(private_key: String) -> PyResult<String> {
    let private_key: StaticSecret = string_to_key(private_key)?;
    Ok(BASE64.encode(PublicKey::from(&private_key).as_bytes()))
}
