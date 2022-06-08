use std::fs::read_to_string;
use std::sync::Arc;

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use ini::Ini;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum WgConfError {
    #[error("Invalid configuration format: {inner}")]
    InvalidFormat {
        #[from]
        inner: ini::ParseError,
    },
    #[error("Could not open file: {inner}")]
    FileIo {
        #[from]
        inner: std::io::Error,
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
    #[error("Missing section(s): {names}")]
    MissingSections { names: String },
    #[error("Section [Interface] was specified multiple times.")]
    MultipleInterfaces,
}

impl WgConfError {
    pub fn invalid_port(inner: std::num::ParseIntError) -> Self {
        WgConfError::InvalidPort { inner }
    }

    pub fn invalid_preshared_key(peer: usize, inner: String) -> Self {
        WgConfError::InvalidPresharedKey { peer, inner }
    }

    pub fn invalid_private_key(inner: &'static str) -> Self {
        WgConfError::InvalidPrivateKey { inner }
    }

    pub fn invalid_public_key(peer: usize, inner: &'static str) -> Self {
        WgConfError::InvalidPublicKey { peer, inner }
    }

    pub fn missing_keys(section: &'static str, names: Vec<&'static str>) -> Self {
        WgConfError::MissingKeys {
            section,
            names: names.join(", "),
        }
    }

    pub fn missing_sections(names: Vec<&'static str>) -> Self {
        WgConfError::MissingSections {
            names: names.join(", "),
        }
    }

    pub fn multiple_interfaces() -> Self {
        WgConfError::MultipleInterfaces
    }
}

impl IntoPy<PyErr> for WgConfError {
    fn into_py(self, _py: Python<'_>) -> PyErr {
        PyValueError::new_err(self.to_string())
    }
}

/// WireGuard server configuration.
#[pyclass]
#[derive(Clone)]
pub struct WireguardConf {
    pub interface: Interface,
    pub peers: Vec<Peer>,
}

#[derive(Clone)]
pub struct Interface {
    pub private_key: Arc<X25519SecretKey>,
    pub listen_port: u16,
    //pub fwmark: Option<u32>,
}

#[derive(Clone)]
pub struct Peer {
    pub public_key: Arc<X25519PublicKey>,
    pub preshared_key: Option<[u8; 32]>,
    //pub allowed_ips: Vec<?>,
    //pub endpoint: Option<?>,
    //pub persistent_keepalive: Option<u16>,
}

#[pymethods]
impl WireguardConf {
    /// Build a new WireGuard server configuration manually.
    ///
    /// - `listen_port`: The port number for the WireGuard UDP socket. The default port for
    ///   WireGuard servers is `51820`.
    /// - `server_private_key`: The base64-encoded private key for the WireGuard server. This can be
    ///   a fixed value, or randomly generated each time by calling the `genkey` function.
    /// - `peer_keys`: Public keys and optional preshared keys of the WireGuard peers that will be
    ///   configured. The argument is expected to be a list of tuples, where the first tuple element
    ///   must the the base64-encoded public key of the peer, and the second tuple element must
    ///   either be a base64-encoded preshared key (32 bytes), or `None`.
    #[staticmethod]
    pub fn build(
        py: Python<'_>,
        listen_port: u16,
        server_private_key: String,
        peer_keys: Vec<(String, Option<String>)>,
    ) -> PyResult<Self> {
        Self::new(listen_port, server_private_key, peer_keys).map_err(|error| error.into_py(py))
    }

    /// Load the WireGuard server configuration from a file at the specified path.
    #[staticmethod]
    pub fn load_from_path(py: Python<'_>, path: &str) -> PyResult<Self> {
        Self::from_path(path).map_err(|error| error.into_py(py))
    }

    /// Load the WireGuard server configuration from a string.
    #[staticmethod]
    pub fn load_from_str(py: Python<'_>, string: &str) -> PyResult<Self> {
        Self::from_str(string).map_err(|error| error.into_py(py))
    }
}

impl WireguardConf {
    pub fn new(
        listen_port: u16,
        server_private_key: String,
        peer_keys: Vec<(String, Option<String>)>,
    ) -> Result<Self, WgConfError> {
        let private_key: Arc<X25519SecretKey> = match server_private_key.parse() {
            Ok(private_key) => Arc::new(private_key),
            Err(error) => return Err(WgConfError::invalid_private_key(error)),
        };

        let interface = Interface {
            private_key,
            listen_port,
        };

        let mut peers: Vec<Peer> = Vec::new();
        for (i, (public_key, preshared_key)) in peer_keys.into_iter().enumerate() {
            let public_key: Arc<X25519PublicKey> = match public_key.parse() {
                Ok(public_key) => Arc::new(public_key),
                Err(error) => return Err(WgConfError::invalid_public_key(i, error)),
            };

            let preshared_key: Option<[u8; 32]> = if let Some(preshared_key) = preshared_key {
                let preshared_key = match base64::decode(preshared_key) {
                    Ok(preshared_key) => preshared_key,
                    Err(error) => return Err(WgConfError::invalid_preshared_key(i, error.to_string())),
                };

                match preshared_key.try_into() {
                    Ok(preshared_key) => Some(preshared_key),
                    Err(invalid_bytes) => {
                        return Err(WgConfError::invalid_preshared_key(
                            i,
                            format!("Length {} instead of 32 bytes", invalid_bytes.len()),
                        ))
                    },
                }
            } else {
                None
            };

            peers.push(Peer {
                public_key,
                preshared_key,
            })
        }

        Ok(WireguardConf { interface, peers })
    }

    pub fn from_path(path: &str) -> Result<Self, WgConfError> {
        let string = read_to_string(path)?;
        WireguardConf::from_str(&string)
    }

    pub fn from_str(string: &str) -> Result<Self, WgConfError> {
        let conf = Ini::load_from_str(string)?;

        // parse [Interface] section
        let mut interface_section = conf.section_all(Some("Interface"));
        let interface = match interface_section.next() {
            Some(interface_conf) => {
                let private_key = interface_conf.get("PrivateKey");
                let listen_port = interface_conf.get("ListenPort");

                match (private_key, listen_port) {
                    // happy path: both keys are present
                    (Some(private_key), Some(listen_port)) => {
                        let private_key: Arc<X25519SecretKey> = match private_key.parse() {
                            Ok(private_key) => Arc::new(private_key),
                            Err(error) => return Err(WgConfError::invalid_private_key(error)),
                        };
                        let listen_port: u16 = match listen_port.parse() {
                            Ok(listen_port) => listen_port,
                            Err(error) => return Err(WgConfError::invalid_port(error)),
                        };
                        Ok(Interface {
                            private_key,
                            listen_port,
                        })
                    },
                    // sad path: at least one required key is missing
                    (Some(_), None) => {
                        return Err(WgConfError::missing_keys("Interface", vec!["ListenPort"]));
                    },
                    (None, Some(_)) => {
                        return Err(WgConfError::missing_keys("Interface", vec!["PrivateKey"]));
                    },
                    (None, None) => {
                        return Err(WgConfError::missing_keys("Interface", vec!["PrivateKey", "ListenPort"]));
                    },
                }
            },
            None => Err(WgConfError::missing_sections(vec!["Interface"])),
        }?;

        // error if the [Interface] section was specified multiple times
        if let Some(_) = interface_section.next() {
            return Err(WgConfError::multiple_interfaces());
        }

        // parse [Peer] sections
        let peer_sections = conf.section_all(Some("Peer"));
        let mut peers: Vec<Peer> = Vec::new();

        for (i, peer_section) in peer_sections.enumerate() {
            let public_key = peer_section.get("PublicKey");
            let preshared_key = peer_section.get("PresharedKey");

            if let Some(public_key) = public_key {
                let public_key: Arc<X25519PublicKey> = match public_key.parse() {
                    Ok(public_key) => Arc::new(public_key),
                    Err(error) => return Err(WgConfError::invalid_public_key(i, error)),
                };

                let preshared_key: Option<[u8; 32]> = if let Some(preshared_key) = preshared_key {
                    let preshared_key = match base64::decode(preshared_key) {
                        Ok(preshared_key) => preshared_key,
                        Err(error) => return Err(WgConfError::invalid_preshared_key(i, error.to_string())),
                    };

                    match preshared_key.try_into() {
                        Ok(preshared_key) => Some(preshared_key),
                        Err(invalid_bytes) => {
                            return Err(WgConfError::invalid_preshared_key(
                                i,
                                format!("Length {} instead of 32 bytes", invalid_bytes.len()),
                            ))
                        },
                    }
                } else {
                    None
                };

                peers.push(Peer {
                    public_key,
                    preshared_key,
                })
            } else {
                return Err(WgConfError::missing_keys("Peer", vec!["PublicKey"]));
            }
        }

        if peers.is_empty() {
            return Err(WgConfError::missing_sections(vec!["Peer"]));
        }

        Ok(WireguardConf { interface, peers })
    }
}

#[cfg(test)]
mod tests {
    // example configurations derived from the wg(8) manpage
    use super::{WgConfError, WireguardConf};

    #[test]
    fn valid_one_peer() {
        let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

        let conf = WireguardConf::from_str(string).unwrap();

        assert_eq!(conf.interface.listen_port, 51820);
        assert_eq!(
            conf.interface.private_key.as_bytes(),
            base64::decode("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=").unwrap(),
        );

        assert_eq!(conf.peers.len(), 1);
        assert_eq!(
            conf.peers[0].public_key.as_bytes(),
            base64::decode("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap(),
        );
        assert!(conf.peers[0].preshared_key.is_none());
    }

    #[test]
    fn valid_two_peers() {
        let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
PresharedKey = sN7qr4ejf5jdc+Z25FFmEiVrGwyPM0d1FaSca/JaIHQ=
";

        let conf = WireguardConf::from_str(string).unwrap();

        assert_eq!(conf.interface.listen_port, 51820);
        assert_eq!(
            conf.interface.private_key.as_bytes(),
            base64::decode("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=").unwrap(),
        );

        assert_eq!(conf.peers.len(), 2);
        assert_eq!(
            conf.peers[0].public_key.as_bytes(),
            base64::decode("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=").unwrap(),
        );
        assert!(conf.peers[0].preshared_key.is_none());

        assert_eq!(
            conf.peers[1].public_key.as_bytes(),
            base64::decode("TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=").unwrap(),
        );
        assert_eq!(
            conf.peers[1].preshared_key.unwrap().to_vec(),
            base64::decode("sN7qr4ejf5jdc+Z25FFmEiVrGwyPM0d1FaSca/JaIHQ=").unwrap(),
        );
    }

    #[test]
    fn invalid_empty() {
        let string = "";

        assert!(
            matches!(WireguardConf::from_str(string), Err(WgConfError::MissingSections { names }) if names == "Interface")
        );
    }

    #[test]
    fn invalid_missing_interface() {
        let string = "\
[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

        assert!(
            matches!(WireguardConf::from_str(string), Err(WgConfError::MissingSections { names }) if names == "Interface")
        );
    }

    #[test]
    fn invalid_multiple_interfaces() {
        let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Interface]
PrivateKey = SA7v+rddcb/KJAD41Jb12tHEpLMN1XsovpbBeqOD+Fg=
ListenPort = 51821
";

        assert!(matches!(
            WireguardConf::from_str(string),
            Err(WgConfError::MultipleInterfaces)
        ));
    }

    #[test]
    fn invalid_no_peers() {
        let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820
";

        assert!(matches!(
            WireguardConf::from_str(string),
            Err(WgConfError::MissingSections { names }) if names == "Peer"),);
    }

    #[test]
    fn invalid_missing_private_key() {
        let string = "\
[Interface]
ListenPort = 51820

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

        assert!(matches!(
            WireguardConf::from_str(string),
            Err(WgConfError::MissingKeys { section, names }) if section == "Interface" && names == "PrivateKey"),);
    }

    #[test]
    fn invalid_missing_port() {
        let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

        assert!(matches!(
            WireguardConf::from_str(string),
            Err(WgConfError::MissingKeys { section, names }) if section == "Interface" && names == "ListenPort"),);
    }

    #[test]
    fn invalid_missing_public_key() {
        let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PresharedKey = sN7qr4ejf5jdc+Z25FFmEiVrGwyPM0d1FaSca/JaIHQ=
";

        assert!(matches!(
            WireguardConf::from_str(string),
            Err(WgConfError::MissingKeys { section, names }) if section == "Peer" && names == "PublicKey"),);
    }

    #[test]
    fn invalid_private_key() {
        let string = "\
[Interface]
PrivateKey = HELLOWORLD
ListenPort = 51820

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

        assert!(matches!(
            WireguardConf::from_str(string),
            Err(WgConfError::InvalidPrivateKey { .. })
        ));
    }

    #[test]
    fn invalid_port() {
        let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = HELLOWORLD

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

        assert!(matches!(
            WireguardConf::from_str(string),
            Err(WgConfError::InvalidPort { .. })
        ));
    }

    #[test]
    fn invalid_port_overflow() {
        let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 518202938293829839293829382

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
";

        assert!(matches!(
            WireguardConf::from_str(string),
            Err(WgConfError::InvalidPort { .. })
        ));
    }

    #[test]
    fn invalid_public_key() {
        let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PublicKey = HELLOWORLD
";

        assert!(matches!(
            WireguardConf::from_str(string),
            Err(WgConfError::InvalidPublicKey { .. })
        ));
    }

    #[test]
    fn invalid_preshared_key() {
        let string = "\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
PresharedKey = HELLOWORLD
";

        assert!(matches!(
            WireguardConf::from_str(string),
            Err(WgConfError::InvalidPresharedKey { .. })
        ));
    }
}
