use std::fmt::{Display, Formatter};
use std::fs::read_to_string;
use std::io::{Cursor, ErrorKind};
use std::str::FromStr;
use std::sync::Arc;

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use ini::{Ini, Properties, SectionEntry};
use pyo3::exceptions::PyIOError;
use pyo3::prelude::*;

use super::client::{ClientPeer, PeerInterface, WireguardClientConf};
use super::error::WireguardConfError;

/// WireGuard server configuration.
#[pyclass]
#[derive(Clone, Debug, PartialEq)]
pub struct WireguardServerConf {
    pub interface: ServerInterface,
    pub peers: Vec<ServerPeer>,
}

#[derive(Clone, Debug)]
pub struct ServerInterface {
    pub private_key: Arc<X25519SecretKey>,
    pub listen_port: u16,
    //pub fwmark: Option<u32>,
}

impl Default for ServerInterface {
    fn default() -> Self {
        ServerInterface {
            private_key: Arc::new(X25519SecretKey::new()),
            listen_port: 51820,
        }
    }
}

impl PartialEq for ServerInterface {
    fn eq(&self, other: &Self) -> bool {
        self.listen_port == other.listen_port && self.private_key.as_bytes() == other.private_key.as_bytes()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerPeer {
    pub public_key: Arc<X25519PublicKey>,
    pub preshared_key: Option<[u8; 32]>,
    //pub allowed_ips: Vec<?>,
    //pub endpoint: Option<?>,
    //pub persistent_keepalive: Option<u16>,
}

impl ServerPeer {
    pub fn from_private_key(private_key: &X25519SecretKey) -> Self {
        ServerPeer {
            public_key: Arc::new(private_key.public_key()),
            preshared_key: None,
        }
    }
}

#[pymethods]
impl WireguardServerConf {
    /// Initialize WireGuard configuration
    ///
    /// This method will attempt to read WireGuard configuration files that have already been
    /// written to disk, and will fall back to generating new configuration files.
    #[staticmethod]
    pub fn default(py: Python<'_>, name: String, peers: usize) -> PyResult<Self> {
        match read_to_string(server_conf_path(&name)) {
            // configuration file already exists: attempt to parse
            Ok(contents) => Ok(WireguardServerConf::from_str(&contents).map_err(|error| error.into_py(py))?),
            // configuration file does not exist yet: generate new ones
            Err(error) if error.kind() == ErrorKind::NotFound => Self::generate(py, name, peers),
            // configuration file could not be read
            Err(error) => Err(PyIOError::new_err(error.to_string())),
        }
    }

    /// Generate new WireGuard configurations with default settings.
    ///
    /// - listen on default port 51820 for incoming WireGuard connections
    /// - generate random keypairs for server and the specified number of clients
    /// - writes files to disk as `$name.conf`, `$name_peer1.conf`, `$name_peer2.conf`, etc.
    #[staticmethod]
    pub fn generate(py: Python<'_>, name: String, peers: usize) -> PyResult<Self> {
        let (server_conf, peer_confs) = generate_default_configs(peers).map_err(|error| error.into_py(py))?;

        std::fs::write(server_conf_path(&name), server_conf.to_string())
            .map_err(|error| PyIOError::new_err(error.to_string()))?;

        for (i, peer_conf) in peer_confs.iter().enumerate() {
            std::fs::write(peer_conf_path(&name, i), peer_conf.to_string())
                .map_err(|error| PyIOError::new_err(error.to_string()))?;
        }

        Ok(server_conf)
    }

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
}

impl WireguardServerConf {
    pub fn new(
        listen_port: u16,
        server_private_key: String,
        peer_keys: Vec<(String, Option<String>)>,
    ) -> Result<Self, WireguardConfError> {
        let private_key: Arc<X25519SecretKey> = match server_private_key.parse() {
            Ok(private_key) => Arc::new(private_key),
            Err(error) => return Err(WireguardConfError::invalid_private_key(error)),
        };

        let interface = ServerInterface {
            private_key,
            listen_port,
        };

        let mut peers: Vec<ServerPeer> = Vec::new();
        for (i, (public_key, preshared_key)) in peer_keys.into_iter().enumerate() {
            let public_key: Arc<X25519PublicKey> = match public_key.parse() {
                Ok(public_key) => Arc::new(public_key),
                Err(error) => return Err(WireguardConfError::invalid_public_key(i, error)),
            };

            let preshared_key: Option<[u8; 32]> = if let Some(preshared_key) = preshared_key {
                let preshared_key = match base64::decode(preshared_key) {
                    Ok(preshared_key) => preshared_key,
                    Err(error) => return Err(WireguardConfError::invalid_preshared_key(i, error.to_string())),
                };

                match preshared_key.try_into() {
                    Ok(preshared_key) => Some(preshared_key),
                    Err(invalid_bytes) => {
                        return Err(WireguardConfError::invalid_preshared_key(
                            i,
                            format!("Length {} instead of 32 bytes", invalid_bytes.len()),
                        ))
                    },
                }
            } else {
                None
            };

            peers.push(ServerPeer {
                public_key,
                preshared_key,
            })
        }

        Ok(WireguardServerConf { interface, peers })
    }
}

impl Display for WireguardServerConf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut conf = Ini::new();

        // fill [Interface] section
        conf.with_section(Some("Interface"))
            .set("PrivateKey", base64::encode(self.interface.private_key.as_bytes()))
            .set("ListenPort", self.interface.listen_port.to_string());

        // fill [Peer] sections
        for peer in self.peers.iter() {
            let mut props = Properties::new();
            props.append("PublicKey", base64::encode(peer.public_key.as_bytes()));
            if let Some(preshared_key) = peer.preshared_key {
                props.append("PresharedKey", base64::encode(preshared_key));
            }

            match conf.entry(Some(String::from("Peer"))) {
                SectionEntry::Vacant(vac) => {
                    vac.insert(props);
                },
                SectionEntry::Occupied(mut occ) => {
                    occ.append(props);
                },
            }
        }

        // write to an in-memory buffer instead of to a file
        let mut out: Vec<u8> = Vec::new();
        let mut buf = Cursor::new(&mut out);
        conf.write_to(&mut buf).unwrap();

        // the contents of the buffer must be valid UTF-8 because we just built it
        f.write_str(&String::from_utf8(out).unwrap())
    }
}

impl FromStr for WireguardServerConf {
    type Err = WireguardConfError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let conf = Ini::load_from_str(s)?;

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
                            Err(error) => return Err(WireguardConfError::invalid_private_key(error)),
                        };
                        let listen_port: u16 = match listen_port.parse() {
                            Ok(listen_port) => listen_port,
                            Err(error) => return Err(WireguardConfError::invalid_port(error)),
                        };
                        Ok(ServerInterface {
                            private_key,
                            listen_port,
                        })
                    },
                    // sad path: at least one required key is missing
                    (Some(_), None) => {
                        return Err(WireguardConfError::missing_keys("Interface", vec!["ListenPort"]));
                    },
                    (None, Some(_)) => {
                        return Err(WireguardConfError::missing_keys("Interface", vec!["PrivateKey"]));
                    },
                    (None, None) => {
                        return Err(WireguardConfError::missing_keys(
                            "Interface",
                            vec!["PrivateKey", "ListenPort"],
                        ));
                    },
                }
            },
            None => Err(WireguardConfError::NoInterface),
        }?;

        // error if the [Interface] section was specified multiple times
        if interface_section.next().is_some() {
            return Err(WireguardConfError::MultipleInterfaces);
        }

        // parse [Peer] sections
        let peer_sections = conf.section_all(Some("Peer"));
        let mut peers: Vec<ServerPeer> = Vec::new();

        for (i, peer_section) in peer_sections.enumerate() {
            let public_key = peer_section.get("PublicKey");
            let preshared_key = peer_section.get("PresharedKey");

            if let Some(public_key) = public_key {
                let public_key: Arc<X25519PublicKey> = match public_key.parse() {
                    Ok(public_key) => Arc::new(public_key),
                    Err(error) => return Err(WireguardConfError::invalid_public_key(i, error)),
                };

                let preshared_key: Option<[u8; 32]> = if let Some(preshared_key) = preshared_key {
                    let preshared_key = match base64::decode(preshared_key) {
                        Ok(preshared_key) => preshared_key,
                        Err(error) => return Err(WireguardConfError::invalid_preshared_key(i, error.to_string())),
                    };

                    match preshared_key.try_into() {
                        Ok(preshared_key) => Some(preshared_key),
                        Err(invalid_bytes) => {
                            return Err(WireguardConfError::invalid_preshared_key(
                                i,
                                format!("Length {} instead of 32 bytes", invalid_bytes.len()),
                            ))
                        },
                    }
                } else {
                    None
                };

                peers.push(ServerPeer {
                    public_key,
                    preshared_key,
                })
            } else {
                return Err(WireguardConfError::missing_keys("Peer", vec!["PublicKey"]));
            }
        }

        if peers.is_empty() {
            return Err(WireguardConfError::NoPeers);
        }

        Ok(WireguardServerConf { interface, peers })
    }
}

pub fn generate_default_configs(
    peer_number: usize,
) -> Result<(WireguardServerConf, Vec<WireguardClientConf>), WireguardConfError> {
    if peer_number == 0 {
        return Err(WireguardConfError::NoPeers);
    }

    let interface = ServerInterface::default();

    let peer_private_keys: Vec<Arc<X25519SecretKey>> =
        (0..peer_number).map(|_| Arc::new(X25519SecretKey::new())).collect();
    let peers: Vec<ServerPeer> = peer_private_keys
        .iter()
        .map(|private_key| ServerPeer::from_private_key(private_key))
        .collect();

    let peer_confs: Vec<WireguardClientConf> = peer_private_keys
        .iter()
        .map(|private_key| WireguardClientConf {
            interface: PeerInterface {
                private_key: private_key.clone(),
            },
            peer: ClientPeer {
                public_key: Arc::new(private_key.public_key()),
                preshared_key: None,
                allowed_ips: vec![String::from("0.0.0.0/0")],
                endpoint: format!("127.0.0.1:{}", interface.listen_port).parse().unwrap(),
            },
        })
        .collect();

    let conf = WireguardServerConf { interface, peers };

    Ok((conf, peer_confs))
}

fn server_conf_path(name: &str) -> String {
    format!("{}.conf", name)
}

fn peer_conf_path(name: &str, number: usize) -> String {
    format!("{}_peer{}.conf", name, number)
}
