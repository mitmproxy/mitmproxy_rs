use std::io::Cursor;
use std::iter;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::time::Duration;
use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::broadcast;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, Receiver, UnboundedReceiver, UnboundedSender};

use crate::intercept_conf::InterceptConf;
use crate::ipc;
use crate::ipc::PacketWithMeta;
use crate::messages::{
    NetworkCommand, NetworkEvent, SmolPacket, TransportCommand, TransportEvent, TunnelInfo,
};
use crate::network::{add_network_layer, MAX_PACKET_SIZE};
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};
use prost::Message;
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;
use tokio::time::timeout;
use crate::packet_sources::macos::MacOsTask;

pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 1024;

pub struct LinuxConf {
    pub executable_path: PathBuf,
}

impl PacketSourceConf for LinuxConf {
    type Task = LinuxTask;
    type Data = UnboundedSender<InterceptConf>;

    fn name(&self) -> &'static str {
        "Linux proxy"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: broadcast::Receiver<()>,
    ) -> Result<(Self::Task, Self::Data)> {
        let listener_addr = format!("/tmp/mitmproxy-{}", std::process::id());
        let listener = UnixListener::bind(&listener_addr)?;

        unimplemented!("FIXME");
        start_redirector(listener_addr).await?;

        log::debug!("Waiting for control channel...");
        let control_channel = timeout(Duration::new(5, 0), listener.accept())
            .await
            .context("failed to establish connection to Linux redirector")??
            .0;
        log::debug!("Control channel connected.");

        let (conf_tx, conf_rx) = unbounded_channel();
        Ok((
            LinuxTask {
                // FIXME
                control_channel,
                listener,
                conf_rx,
                shutdown,
            },
            conf_tx,
        ))
    }
}

pub struct LinuxTask {
    control_channel: UnixStream,
    listener: UnixListener,
    buf: Vec<u8>,

    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    network_task_handle: tokio::task::JoinHandle<Result<()>>,
}

impl PacketSourceTask for LinuxTask {
    async fn run(mut self) -> Result<()> {
        unimplemented!();

        log::info!("Linux OS proxy task shutting down.");
        Ok(())
    }
}
