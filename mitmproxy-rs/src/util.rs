#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use data_encoding::BASE64;
#[cfg(target_os = "macos")]
use mitmproxy::macos;
use mitmproxy::messages::TunnelInfo;
use pyo3::exceptions::{PyKeyError, PyOSError};
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
    BASE64.encode(&StaticSecret::random_from_rng(OsRng).to_bytes())
}

/// Derive a WireGuard public key from a private key, analogous to the `wg pubkey` command.
#[pyfunction]
pub fn pubkey(private_key: String) -> PyResult<String> {
    let private_key: StaticSecret = string_to_key(private_key)?;
    Ok(BASE64.encode(PublicKey::from(&private_key).as_bytes()))
}

/// Convert pem certificate to der certificate and add it to macos keychain.
#[pyfunction]
#[allow(unused_variables)]
pub fn add_cert(py: Python<'_>, pem: String) -> PyResult<()> {
    #[cfg(target_os = "macos")]
    {
        let pem_body = pem
            .lines()
            .skip(1)
            .take_while(|&line| line != "-----END CERTIFICATE-----")
            .collect::<String>();

        let filename = py.import("mitmproxy_rs")?.filename()?;
        let executable_path = std::path::Path::new(filename)
            .parent()
            .ok_or_else(|| anyhow!("invalid path"))?
            .join("macos-certificate-truster.app");
        if !executable_path.exists() {
            return Err(anyhow!("{} does not exist", executable_path.display()).into());
        }
        let der = BASE64.decode(pem_body.as_bytes()).unwrap();
        match macos::add_cert(der, executable_path.to_str().unwrap()) {
            Ok(_) => Ok(()),
            Err(e) => Err(PyErr::new::<PyOSError, _>(format!(
                "Failed to add certificate: {:?}",
                e
            ))),
        }
    }
    #[cfg(not(target_os = "macos"))]
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        "OS proxy mode is only available on macos",
    ))
}

/// Delete mitmproxy certificate from the keychain.
#[pyfunction]
pub fn remove_cert() -> PyResult<()> {
    #[cfg(target_os = "macos")]
    {
        match macos::remove_cert() {
            Ok(_) => Ok(()),
            Err(e) => Err(PyErr::new::<PyOSError, _>(format!(
                "Failed to remove certificate: {:?}",
                e
            ))),
        }
    }
    #[cfg(not(target_os = "macos"))]
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        "OS proxy mode is only available on macos",
    ))
}

pub(crate) fn get_tunnel_info(
    tunnel: &TunnelInfo,
    py: Python,
    name: String,
    default: Option<PyObject>,
) -> PyResult<PyObject> {
    match tunnel {
        TunnelInfo::WireGuard { src_addr, dst_addr } => match name.as_str() {
            "original_src" => return Ok(socketaddr_to_py(py, *src_addr)),
            "original_dst" => return Ok(socketaddr_to_py(py, *dst_addr)),
            _ => (),
        },
        TunnelInfo::OsProxy {
            pid,
            process_name,
            remote_endpoint,
        } => match name.as_str() {
            "pid" => return Ok(pid.into_py(py)),
            "process_name" => return Ok(process_name.clone().into_py(py)),
            "remote_endpoint" => return Ok(remote_endpoint.clone().into_py(py)),
            _ => (),
        },
    }
    match default {
        Some(x) => Ok(x),
        None => Err(PyKeyError::new_err(name)),
    }
}
