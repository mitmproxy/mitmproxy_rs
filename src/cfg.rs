use std::sync::Arc;

use boringtun::crypto::X25519SecretKey;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde::{Deserialize, Serialize};

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
    pub fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(self).map_err(invalid_json)
    }

    #[staticmethod]
    pub fn from_json(string: String) -> PyResult<Self> {
        serde_json::from_str(&string).map_err(invalid_json)
    }

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
    fn json_roundtrip() {
        let cfg = Configuration::default();

        assert_eq!(
            cfg,
            serde_json::from_str(&serde_json::to_string_pretty(&cfg).unwrap()).unwrap()
        );
    }
}
