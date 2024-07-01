use anyhow::Result;
use std::future::Future;
use tokio::sync::{broadcast, mpsc};

use crate::messages::{TransportCommand, TransportEvent};

#[cfg(target_os = "macos")]
pub mod macos;
pub mod udp;
#[cfg(windows)]
pub mod windows;
pub mod wireguard;

pub trait PacketSourceConf {
    type Task: PacketSourceTask + Send + 'static;
    type Data: Send + 'static;

    fn name(&self) -> &'static str;

    fn build(
        self,
        transport_events_tx: mpsc::Sender<TransportEvent>,
        transport_commands_rx: mpsc::UnboundedReceiver<TransportCommand>,
        shutdown: broadcast::Receiver<()>,
    ) -> impl Future<Output = Result<(Self::Task, Self::Data)>> + Send;
}

pub trait PacketSourceTask: Send {
    fn run(self) -> impl Future<Output = Result<()>> + Send;
}
