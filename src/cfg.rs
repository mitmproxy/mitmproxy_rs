use std::io::Cursor;
use std::sync::Arc;

use boringtun::crypto::X25519SecretKey;
use ini::Ini;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

/// WireGuard configuration for both servers and clients.
#[pyclass]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Configuration {
    pub(crate) server_listen_port: u16,
    #[serde(with = "x25519_base64")]
    pub(crate) server_private_key: Arc<X25519SecretKey>,
    pub(crate) clients: Vec<Client>,
}

#[pymethods]
impl Configuration {
    /// Build a new WireGuard configuration with randomly generated encryption keys.
    #[staticmethod]
    #[args(listen_port = 51820, peers = 1)]
    pub fn generate(listen_port: u16, peers: usize) -> PyResult<Self> {
        Ok(Self::build(listen_port, peers))
    }

    /// Deserialize WireGuard configuration from JSON.
    pub fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(self).map_err(invalid_json)
    }

    /// Pretty-print configuration file contents for WireGuard clients.
    pub fn pretty_print(
        &self,
        address: Vec<String>,
        allowed_ips: Vec<String>,
        endpoint: (String, u16),
    ) -> PyResult<Vec<String>> {
        let mut outputs = Vec::new();

        let public_key = base64::encode(self.server_private_key.public_key().as_bytes());
        let address_str = address.join(", ");
        let allowed_ips_str = allowed_ips.join(", ");
        let endpoint_str = format!("{}:{}", endpoint.0, endpoint.1);

        for client in &self.clients {
            let mut conf = Ini::new();

            let private_key = base64::encode(client.private_key.as_bytes());

            // fill [Interface] section
            conf.with_section(Some("Interface"))
                .set("PrivateKey", &private_key)
                .set("Address", &address_str);

            // fill [Peer] section
            conf.with_section(Some("Peer"))
                .set("PublicKey", &public_key)
                .set("AllowedIPs", &allowed_ips_str)
                .set("Endpoint", &endpoint_str);

            // write to an in-memory buffer instead of to a file
            let mut out: Vec<u8> = Vec::new();
            let mut buf = Cursor::new(&mut out);

            // both writing to our own buffer and decoding our own UTF-8 data should be safe
            conf.write_to(&mut buf).unwrap();
            outputs.push(String::from_utf8(out).unwrap());
        }

        Ok(outputs)
    }

    /// Deserialize WireGuard configuration to JSON.
    #[staticmethod]
    pub fn from_json(string: String) -> PyResult<Self> {
        serde_json::from_str(&string).map_err(invalid_json)
    }

    /// Instantiate a custom WireGuard configuration.
    #[staticmethod]
    pub fn custom(
        server_listen_port: u16,
        server_private_key: String,
        client_private_keys: Vec<String>,
    ) -> PyResult<Self> {
        let server_key = Arc::new(server_private_key.parse().map_err(invalid_key)?);
        let client_keys = client_private_keys
            .iter()
            .map(|client_private_key| {
                client_private_key
                    .parse::<X25519SecretKey>()
                    .map(Arc::new)
                    .map_err(invalid_key)
            })
            .collect::<Result<Vec<Arc<X25519SecretKey>>, _>>()?;

        Ok(Configuration::new(server_listen_port, server_key, &client_keys))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Client {
    #[serde(with = "x25519_base64")]
    pub(crate) private_key: Arc<X25519SecretKey>,
    // preshared_key: Option<[u8; 32]>,
}

impl Default for Configuration {
    fn default() -> Self {
        let default_port: u16 = 51820;
        let server_private_key = Arc::new(X25519SecretKey::new());
        let client_private_key = Arc::new(X25519SecretKey::new());

        Self::new(default_port, server_private_key, &[client_private_key])
    }
}

impl Configuration {
    pub fn new(
        server_listen_port: u16,
        server_private_key: Arc<X25519SecretKey>,
        client_private_keys: &[Arc<X25519SecretKey>],
    ) -> Self {
        Configuration {
            server_listen_port,
            server_private_key,
            clients: client_private_keys
                .iter()
                .map(|client_private_key| Client {
                    private_key: client_private_key.clone(),
                })
                .collect(),
        }
    }

    pub fn build(server_listen_port: u16, peers: usize) -> Self {
        let server_private_key = Arc::new(X25519SecretKey::new());

        let client_private_keys: Vec<Arc<X25519SecretKey>> =
            (0..=peers).map(|_| Arc::new(X25519SecretKey::new())).collect();

        Self::new(server_listen_port, server_private_key, &client_private_keys)
    }
}

fn invalid_key(error: &str) -> PyErr {
    PyValueError::new_err(format!("Invalid X25519 secret key: {}", error))
}

fn invalid_json(error: serde_json::Error) -> PyErr {
    PyValueError::new_err(format!("Invalid JSON: {}", error))
}

// custom de/serialization support for Arc<X25519SecretKey>
pub(crate) mod x25519_base64 {
    use std::sync::Arc;

    use boringtun::crypto::X25519SecretKey;
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &Arc<X25519SecretKey>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string = base64::encode(key.as_bytes());
        serializer.serialize_str(&string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<X25519SecretKey>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        match string.parse() {
            Ok(result) => Ok(Arc::new(result)),
            Err(error) => Err(error).map_err(serde::de::Error::custom),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl PartialEq for Configuration {
        fn eq(&self, other: &Self) -> bool {
            self.server_listen_port == other.server_listen_port
                && self.server_private_key.as_bytes() == other.server_private_key.as_bytes()
                && self.clients == other.clients
        }
    }

    impl PartialEq for Client {
        fn eq(&self, other: &Self) -> bool {
            self.private_key.as_bytes() == other.private_key.as_bytes()
        }
    }

    #[test]
    fn json_roundtrip_default() {
        let cfg = Configuration::default();

        assert_eq!(
            cfg,
            serde_json::from_str(&serde_json::to_string_pretty(&cfg).unwrap()).unwrap()
        );
    }

    #[test]
    fn json_roundtrip_custom() {
        let cfg = Configuration::build(51821, 2);

        assert_eq!(
            cfg,
            serde_json::from_str(&serde_json::to_string_pretty(&cfg).unwrap()).unwrap()
        );
    }
}
