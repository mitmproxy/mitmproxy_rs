use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum WireguardConfError {
    #[error("Invalid configuration format: {inner}")]
    InvalidFormat {
        #[from]
        inner: ini::ParseError,
    },
    #[error("Invalid port number: {inner}")]
    InvalidPort {
        #[from]
        inner: std::num::ParseIntError,
    },
    #[error("Invalid preshared key in [Peer] section {peer}: {inner}")]
    InvalidPresharedKey { peer: usize, inner: String },
    #[error("Invalid private X25519 server key: {inner}")]
    InvalidPrivateKey { inner: &'static str },
    #[error("Invalid public X25519 key in [Peer] section {peer}: {inner}")]
    InvalidPublicKey { peer: usize, inner: &'static str },
    #[error("Missing key(s) in [{section}]: {names}")]
    MissingKeys { section: &'static str, names: String },
    #[error("Section [Interface] was specified multiple times.")]
    MultipleInterfaces,
    #[error("Section [Interface] is missing.")]
    NoInterface,
    #[error("No Peers were specified.")]
    NoPeers,
}

impl WireguardConfError {
    pub fn invalid_port(inner: std::num::ParseIntError) -> Self {
        WireguardConfError::InvalidPort { inner }
    }

    pub fn invalid_preshared_key(peer: usize, inner: String) -> Self {
        WireguardConfError::InvalidPresharedKey { peer, inner }
    }

    pub fn invalid_private_key(inner: &'static str) -> Self {
        WireguardConfError::InvalidPrivateKey { inner }
    }

    pub fn invalid_public_key(peer: usize, inner: &'static str) -> Self {
        WireguardConfError::InvalidPublicKey { peer, inner }
    }

    pub fn missing_keys(section: &'static str, names: Vec<&'static str>) -> Self {
        WireguardConfError::MissingKeys {
            section,
            names: names.join(", "),
        }
    }
}

impl IntoPy<PyErr> for WireguardConfError {
    fn into_py(self, _py: Python<'_>) -> PyErr {
        PyValueError::new_err(self.to_string())
    }
}
