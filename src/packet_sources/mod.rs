use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc};

pub use windivert::WinDivertConf;
pub use wireguard::WireGuardConf;

use crate::messages::{NetworkCommand, NetworkEvent};

pub mod windivert;
mod wireguard;

#[async_trait]
pub trait PacketSourceConf {
    type Task: PacketSourceTask + Send + 'static;

    async fn build(
        self,
        net_tx: mpsc::Sender<NetworkEvent>,
        net_rx: mpsc::Receiver<NetworkCommand>,
        sd_watcher: broadcast::Receiver<()>,
    ) -> Result<Self::Task>;
}

#[async_trait]
pub trait PacketSourceTask {
    async fn run(mut self) -> Result<()>;
}
