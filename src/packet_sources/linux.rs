use anyhow::{bail, Context, Result};
use log::{debug, error, log, Level};
use std::io::Error;
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::str::FromStr;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader, ReadBuf};
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::intercept_conf::InterceptConf;
use crate::messages::{TransportCommand, TransportEvent};
use crate::packet_sources::{forward_packets, PacketSourceConf, PacketSourceTask};
use crate::shutdown;
use tempfile::{tempdir, TempDir};
use tokio::net::UnixDatagram;
use tokio::process::Command;
use tokio::time::timeout;

async fn start_redirector(
    executable: &Path,
    listener_addr: &Path,
    shutdown: shutdown::Receiver,
) -> Result<PathBuf> {
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

    let stdout = redirector_process.stdout.take().unwrap();
    let stderr = redirector_process.stderr.take().unwrap();
    let shutdown2 = shutdown.clone();
    tokio::spawn(async move {
        let mut stderr = BufReader::new(stderr).lines();
        let mut level = Level::Error;
        while let Ok(Some(line)) = stderr.next_line().await {
            if shutdown2.is_shutting_down() {
                // We don't want to log during exit, https://github.com/vorner/pyo3-log/issues/30
                eprintln!("{}", line);
                continue;
            }

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
                if shutdown.is_shutting_down() {
                    // We don't want to log during exit, https://github.com/vorner/pyo3-log/issues/30
                } else {
                    debug!("[linux-redirector] exited successfully.")
                }
            }
            other => {
                if shutdown.is_shutting_down() {
                    eprintln!("[linux-redirector] exited during shutdown: {:?}", other)
                } else {
                    error!("[linux-redirector] exited: {:?}", other)
                }
            }
        }
    });

    timeout(
        Duration::from_secs(5),
        BufReader::new(stdout).lines().next_line(),
    )
    .await
    .context("failed to establish connection to Linux redirector")?
    .context("failed to read redirector stdout")?
    .map(PathBuf::from)
    .context("redirector did not produce stdout")
}

pub struct LinuxConf {
    pub executable_path: PathBuf,
}

// We implement AsyncRead/AsyncWrite for UnixDatagram to have a common interface
// with Windows' NamedPipeServer.
pub struct AsyncUnixDatagram(UnixDatagram);

impl AsyncRead for AsyncUnixDatagram {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.0.poll_recv(cx, buf)
    }
}
impl AsyncWrite for AsyncUnixDatagram {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, Error>> {
        self.0.poll_send(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), Error>> {
        self.0.poll_send_ready(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), Error>> {
        Poll::Ready(self.0.shutdown(Shutdown::Write))
    }
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
        shutdown: shutdown::Receiver,
    ) -> Result<(Self::Task, Self::Data)> {
        let datagram_dir = tempdir().context("failed to create temp dir")?;

        let channel = UnixDatagram::bind(datagram_dir.path().join("mitmproxy"))?;
        let dst =
            start_redirector(&self.executable_path, datagram_dir.path(), shutdown.clone()).await?;

        channel
            .connect(&dst)
            .with_context(|| format!("Failed to connect to redirector at {}", dst.display()))?;

        let (conf_tx, conf_rx) = unbounded_channel();

        Ok((
            LinuxTask {
                datagram_dir,
                channel: AsyncUnixDatagram(channel),
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
    datagram_dir: TempDir,
    channel: AsyncUnixDatagram,
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    shutdown: shutdown::Receiver,
}

impl PacketSourceTask for LinuxTask {
    async fn run(self) -> Result<()> {
        forward_packets(
            self.channel,
            self.transport_events_tx,
            self.transport_commands_rx,
            self.conf_rx,
            self.shutdown,
        )
        .await?;
        drop(self.datagram_dir);
        Ok(())
    }
}
