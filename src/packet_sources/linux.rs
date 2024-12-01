use anyhow::{bail, Context, Result};
use log::{debug, error, log, Level};
use std::path::PathBuf;
use std::process::Stdio;
use std::str::FromStr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::broadcast;
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::intercept_conf::InterceptConf;
use crate::messages::{TransportCommand, TransportEvent};
use crate::network::MAX_PACKET_SIZE;
use crate::packet_sources::{forward_packets, PacketSourceConf, PacketSourceTask};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
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
    let mut redirector_process = Command::new("sudo")
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
            error!("[linux-redirector] {}", line);
        }
    });
    tokio::spawn(async move {
        let mut level = Level::Error;
        while let Ok(Some(line)) = stderr.next_line().await {
            let new_level = line
                .strip_prefix("[")
                .and_then(|s| s.split_once(" "))
                .and_then(|(level, line)| {
                    Level::from_str(level)
                        .ok()
                        .map(|l| (l, line.trim_ascii_start()))
                });
            if let Some((l, line)) = new_level {
                level = l;
                log!(level, "[{line}");
            } else {
                log!(level, "{line}");
            }
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

        start_redirector(self.executable_path, listener_addr).await?;

        debug!("Waiting for redirector...");
        let stream = timeout(Duration::new(5, 0), listener.accept())
            .await
            .context("failed to establish connection to Linux redirector")??
            .0;
        debug!("Redirector connected.");

        let (conf_tx, conf_rx) = unbounded_channel();

        Ok((
            LinuxTask {
                listener,
                stream,
                transport_events_tx,
                transport_commands_rx,
                conf_rx,
                shutdown,
            },
            conf_tx,
        ))
    }
}

pub struct LinuxTask {
    // XXX: Can we drop the listener already, or does that close the channel?
    #[allow(dead_code)]
    listener: UnixListener,
    stream: UnixStream,
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    shutdown: broadcast::Receiver<()>,
}

impl PacketSourceTask for LinuxTask {
    async fn run(self) -> Result<()> {
        forward_packets(
            self.stream,
            self.transport_events_tx,
            self.transport_commands_rx,
            self.conf_rx,
            self.shutdown,
        )
        .await
    }
}
