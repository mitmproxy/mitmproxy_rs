use anyhow::{anyhow, bail, Context, Result};
use std::io::Cursor;
use std::iter;
use std::path::PathBuf;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use log::{debug, error, info, warn};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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
use crate::packet_sources::{PacketForwarderTask, PacketSourceConf, PacketSourceTask};
use prost::Message;
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::task::JoinSet;
use tokio::time::timeout;

pub const IPC_BUF_SIZE: usize = MAX_PACKET_SIZE + 1024;


async fn start_redirector(executable: PathBuf, listener_addr: String) -> Result<()> {
    debug!("Elevating privileges...");
    // Try to elevate privileges using a dummy sudo invocation.
    // The idea here is to block execution and give the user time to enter their password.
    // For now, we naively assume that all systems 1) have sudo and 2) timestamp_timeout > 0.
    let mut sudo = Command::new("sudo")
        .arg("echo")
        .arg("-n")
        .spawn()
        .context("Failed to run sudo.")?;
    sudo.stdin.take();
    if !sudo.wait().await.is_ok_and(|x| x.success()) {
        bail!("Failed to elevate privileges");
    }

    debug!("Starting mitmproxy-linux-redirector...");
    let mut redirector_process =
        Command::new("sudo")
            .arg("--non-interactive")
            .arg("--preserve-env")
            .arg(executable)
            .arg(listener_addr)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to launch mitmproxy-linux-redirector.")?;

    let mut stdout = BufReader::new(redirector_process.stdout.take().unwrap()).lines();
    let mut stderr = BufReader::new(redirector_process.stderr.take().unwrap()).lines();

    tokio::spawn(async move {
        while let Ok(Some(line)) = stdout.next_line().await {
            info!("[linux-redirector] {}", line);
        }
    });
    tokio::spawn(async move {
        while let Ok(Some(line)) = stderr.next_line().await {
            error!("[linux-redirector] {}", line);
        }
    });
    tokio::spawn(async move {
        match redirector_process.wait().await {
            Ok(status) if status.success() => {
                debug!("[linux-redirector] exited successfully.")
            }
            other => {
                error!("[linux-redirector] exited: {:?}", other)
            }
        }
    });

    Ok(())
}

pub struct LinuxConf {
    pub executable_path: PathBuf,
}

impl PacketSourceConf for LinuxConf {
    type Task = PacketForwarderTask<UnixListener, UnixStream>;
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

        start_redirector(self.executable_path, listener_addr).await?;

        debug!("Waiting for redirector...");
        let channel = timeout(Duration::new(5, 0), listener.accept())
            .await
            .context("failed to establish connection to Linux redirector")??
            .0;
        debug!("Redirector connected.");

        let (conf_tx, conf_rx) = unbounded_channel();
        let (network_task_handle, net_tx, net_rx) =
            add_network_layer(transport_events_tx, transport_commands_rx, shutdown)?;

        Ok((
            PacketForwarderTask {
                listener,
                channel,
                net_tx,
                net_rx,
                conf_rx,
                network_task_handle,
            },
            conf_tx,
        ))
    }
}