use pyo3::{exceptions::PyValueError, prelude::*};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub fn string_to_key<T>(data: String) -> PyResult<T>
where
    T: From<[u8; 32]>,
{
    base64::decode(data)
        .ok()
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .map(T::from)
        .ok_or_else(|| PyValueError::new_err("Invalid key."))
}

/// Generate a WireGuard private key, analogous to the `wg genkey` command.
#[pyfunction]
pub fn genkey() -> String {
    base64::encode(StaticSecret::new(OsRng).to_bytes())
}

/// Derive a WireGuard public key from a private key, analogous to the `wg pubkey` command.
#[pyfunction]
pub fn pubkey(private_key: String) -> PyResult<String> {
    let private_key: StaticSecret = string_to_key(private_key)?;
    Ok(base64::encode(PublicKey::from(&private_key).as_bytes()))
}
