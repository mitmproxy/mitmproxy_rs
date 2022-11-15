use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc};

pub use wireguard::WireGuardTaskBuilder;

use crate::messages::{NetworkCommand, NetworkEvent};

pub mod wireguard;


pub trait PacketSourceBuilder {
    type Task: PacketSourceTask;

    fn build(
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
