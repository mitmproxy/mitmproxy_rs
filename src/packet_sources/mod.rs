use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc};

use crate::messages::{TransportCommand, TransportEvent};

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(windows)]
pub mod windows;
pub mod wireguard;

pub mod ipc {
    use std::net::{AddrParseError, IpAddr, SocketAddr};
    use std::str::FromStr;
    include!(concat!(env!("OUT_DIR"), "/mitmproxy.ipc.rs"));

    impl TryFrom<&Address> for SocketAddr {
        type Error = AddrParseError;

        fn try_from(address: &Address) -> Result<Self, Self::Error> {
            let ip = IpAddr::from_str(&address.host)?;
            Ok(SocketAddr::from((ip, address.port as u16)))
        }
    }
    impl From<SocketAddr> for Address {
        fn from(val: SocketAddr) -> Self {
            Address {
                host: val.ip().to_string(),
                port: val.port() as u32,
            }
        }
    }
}

#[async_trait]
pub trait PacketSourceConf {
    type Task: PacketSourceTask + Send + 'static;
    type Data: Send + 'static;

    fn name(&self) -> &'static str;

    async fn build(
        self,
        transport_events_tx: mpsc::Sender<TransportEvent>,
        transport_commands_rx: mpsc::UnboundedReceiver<TransportCommand>,
        shutdown: broadcast::Receiver<()>,
    ) -> Result<(Self::Task, Self::Data)>;
}

#[async_trait]
pub trait PacketSourceTask {
    async fn run(mut self) -> Result<()>;
}
