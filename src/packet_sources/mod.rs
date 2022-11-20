use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc};

pub use windivert::WinDivertBuilder;
pub use wireguard::WireGuardBuilder;

use crate::messages::{NetworkCommand, NetworkEvent};

pub mod windivert;
mod wireguard;

pub trait PacketSourceBuilder {
    type Task: PacketSourceTask + Send + 'static;

    fn build<'a>(
        self,
        net_tx: mpsc::Sender<NetworkEvent>,
        net_rx: mpsc::Receiver<NetworkCommand>,
        sd_watcher: broadcast::Receiver<()>,
    ) -> Self::Task;
}

#[async_trait]
pub trait PacketSourceTask {
    async fn run(mut self) -> Result<()>;
}
