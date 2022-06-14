use std::fmt::{Display, Formatter};
use std::io::Cursor;
use std::net::SocketAddr;
use std::sync::Arc;

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use ini::Ini;

/// WireGuard client configuration.
#[derive(Clone, Debug)]
pub struct WireguardClientConf {
    pub interface: PeerInterface,
    pub peer: ClientPeer,
}

#[derive(Clone, Debug)]
pub struct PeerInterface {
    pub private_key: Arc<X25519SecretKey>,
}

#[derive(Clone, Debug)]
pub struct ClientPeer {
    pub public_key: Arc<X25519PublicKey>,
    pub preshared_key: Option<[u8; 32]>,
    pub allowed_ips: Vec<String>,
    pub endpoint: SocketAddr,
}

impl Display for WireguardClientConf {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut conf = Ini::new();

        // fill [Interface] section
        conf.with_section(Some("Interface"))
            .set("PrivateKey", base64::encode(self.interface.private_key.as_bytes()));

        // fill [Peer] section
        if let Some(preshared_key) = self.peer.preshared_key {
            conf.with_section(Some("Peer"))
                .set("PublicKey", base64::encode(self.peer.public_key.as_bytes()))
                .set("PresharedKey", base64::encode(preshared_key))
                .set("AllowedIPs", self.peer.allowed_ips.join(", "))
                .set("Endpoint", self.peer.endpoint.to_string());
        } else {
            conf.with_section(Some("Peer"))
                .set("PublicKey", base64::encode(self.peer.public_key.as_bytes()))
                .set("AllowedIPs", self.peer.allowed_ips.join(", "))
                .set("Endpoint", self.peer.endpoint.to_string());
        }

        // write to an in-memory buffer instead of to a file
        let mut out: Vec<u8> = Vec::new();
        let mut buf = Cursor::new(&mut out);
        conf.write_to(&mut buf).unwrap();

        // the contents of the buffer must be valid UTF-8 because we just built it
        f.write_str(&String::from_utf8(out).unwrap())
    }
}
