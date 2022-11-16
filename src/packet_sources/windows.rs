use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::broadcast;
use tokio::sync::mpsc::Receiver;
use tokio::sync::mpsc::Sender;

use crate::messages::{NetworkCommand, NetworkEvent};
use crate::packet_sources::{PacketSourceBuilder, PacketSourceTask};

pub struct WindowsBuilder {}

impl WindowsBuilder {
    pub fn new() -> Self {
        WindowsBuilder {}
    }
}

impl PacketSourceBuilder for WindowsBuilder {
    type Task = WindowsTask;
    fn build(
        self,
        net_tx: Sender<NetworkEvent>,
        net_rx: Receiver<NetworkCommand>,
        sd_watcher: broadcast::Receiver<()>,
    ) -> WindowsTask {
        WindowsTask {
            net_tx,
            net_rx,
            sd_watcher,
        }
    }
}

pub struct WindowsTask {
    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,
    sd_watcher: broadcast::Receiver<()>,
}

#[async_trait]
impl PacketSourceTask for WindowsTask {
    async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.sd_watcher.recv() => break,
            }
        }

        log::debug!("Windows OS proxy task shutting down.");
        Ok(())
    }
}
