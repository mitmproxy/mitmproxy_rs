#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use data_encoding::BASE64;
#[cfg(target_os = "macos")]
use mitmproxy::certificates;

use pyo3::exceptions::PyOSError;
use pyo3::{exceptions::PyValueError, prelude::*, IntoPyObjectExt};
use rand_core::OsRng;

use std::net::SocketAddr;

use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::sync::mpsc;

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

pub fn socketaddr_to_py(py: Python, s: SocketAddr) -> PyResult<PyObject> {
    (s.ip().to_string(), s.port()).into_py_any(py)
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

/// Convert pem certificate to der certificate and add it to macOS keychain.
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
        let executable_path = std::path::Path::new(filename.to_str()?)
            .parent()
            .ok_or_else(|| anyhow!("invalid path"))?
            .join("macos-certificate-truster.app");
        if !executable_path.exists() {
            return Err(anyhow!("{} does not exist", executable_path.display()).into());
        }
        let der = BASE64.decode(pem_body.as_bytes()).unwrap();
        match certificates::add_cert(der, executable_path.to_str().unwrap()) {
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
        match certificates::remove_cert() {
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
