use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::anyhow;

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};

mod tcp;

mod wg;
use wg::WgServer;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    // TODO: lower default verbosity to LevelFilter::Info
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .parse_env("MG_LOG")
        .init();

    console_subscriber::init();

    // TODO: make configurable
    let server_priv_key: X25519SecretKey = "c72d788fd0916b1185177fd7fa392451192773c889d17ac739571a63482c18bb"
        .parse()
        .map_err(|error: &str| anyhow!(error))?;

    // TODO: make configurable
    let peer_pub_key: X25519PublicKey = "DbwqnNYZWk5e19uuSR6WomO7VPaVbk/uKhmyFEnXdH8="
        .parse()
        .map_err(|error: &str| anyhow!(error))?;

    // TODO: make configurable
    let server_addr: SocketAddr = "0.0.0.0:51820".parse()?;

    let mut wg_server = WgServer::new(server_addr, server_priv_key);

    // TODO: make configurable
    wg_server.add_peer(Arc::new(peer_pub_key), None)?;

    // start WireGuard server
    wg_server.serve().await
}
