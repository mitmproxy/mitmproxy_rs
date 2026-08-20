use anyhow::{Context, Result, bail};
use log::{Level, debug, error, log};
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
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::intercept_conf::InterceptConf;
use crate::messages::{TransportCommand, TransportEvent};
use crate::packet_sources::{PacketSourceConf, PacketSourceTask, forward_packets};
use crate::shutdown;
use tempfile::{TempDir, tempdir};
use tokio::net::UnixDatagram;
use tokio::process::Command;
use tokio::time::timeout;

/// Returns `true` if the current process is running as root (uid 0).
#[cfg(unix)]
fn is_root() -> bool {
    // SAFETY: getuid() is always safe to call.
    unsafe { libc::getuid() == 0 }
}

/// Builds the [`std::process::Command`] used to launch the redirector binary.
///
/// When `already_root` is `true`, the redirector is invoked directly so that
/// environments without `sudo` (e.g. a privileged Kubernetes container) work
/// out of the box.  Otherwise `sudo --non-interactive --preserve-env` is
/// prepended to perform privilege escalation.
///
/// Extracted as a pure helper so it can be unit-tested without spawning
/// real processes.
fn build_redirector_command(
    executable: &Path,
    listener_addr: &Path,
    already_root: bool,
) -> Command {
    if already_root {
        let mut cmd = Command::new(executable);
        cmd.arg(listener_addr);
        cmd
    } else {
        let mut cmd = Command::new("sudo");
        cmd.arg("--non-interactive")
            .arg("--preserve-env")
            .arg(executable)
            .arg(listener_addr);
        cmd
    }
}

async fn start_redirector(
    executable: &Path,
    listener_addr: &Path,
    shutdown: shutdown::Receiver,
) -> Result<PathBuf> {
    let already_root = is_root();

    if already_root {
        debug!("Already running as root, skipping privilege elevation.");
    } else {
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
    }

    debug!("Starting mitmproxy-linux-redirector...");
    let mut redirector_process = build_redirector_command(executable, listener_addr, already_root)
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
                eprintln!("{line}");
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
                    eprintln!("[linux-redirector] exited during shutdown: {other:?}")
                } else {
                    error!("[linux-redirector] exited: {other:?}")
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::path::Path;

    // -----------------------------------------------------------------------
    // is_root()
    // -----------------------------------------------------------------------

    /// `is_root()` must agree with the raw `getuid()` syscall.
    #[test]
    fn is_root_matches_getuid() {
        let uid = unsafe { libc::getuid() };
        assert_eq!(is_root(), uid == 0);
    }

    /// Running `cargo test` without privileges means we are NOT root.
    /// This guards against accidentally shipping a build where `is_root()`
    /// is hardcoded to `true`.
    #[test]
    fn is_root_is_false_when_unprivileged() {
        if unsafe { libc::getuid() } == 0 {
            // Explicitly skip when the test runner itself is root (e.g. CI
            // root-tests run). Use the `root_*` tests below instead.
            return;
        }
        assert!(!is_root(), "expected is_root() == false for non-root user");
    }

    /// When tests are explicitly run as root (feature `root-tests`), confirm
    /// that `is_root()` returns `true`.
    #[cfg(feature = "root-tests")]
    #[test]
    fn is_root_is_true_when_privileged() {
        assert!(is_root(), "expected is_root() == true when running as root");
    }

    // -----------------------------------------------------------------------
    // build_redirector_command()
    // -----------------------------------------------------------------------

    /// Helper: extract the program name from a `tokio::process::Command`.
    fn program_of(cmd: &Command) -> String {
        // as_std() gives std::process::Command whose Debug format is:
        //   "program" "arg1" "arg2" ...
        let dbg = format!("{:?}", cmd.as_std());
        dbg.trim_start_matches('"')
            .split('"')
            .next()
            .unwrap_or("")
            .to_string()
    }

    /// Helper: collect all arguments from a `tokio::process::Command`.
    fn args_of(cmd: &Command) -> Vec<String> {
        // std::process::Command Debug format: `"prog" "a" "b" ...`
        let dbg = format!("{:?}", cmd.as_std());
        let mut tokens = dbg.split('"').filter(|s| !s.trim().is_empty());
        tokens.next(); // skip program
        tokens.map(|s| s.to_string()).collect()
    }

    /// When already root, the command must start with the redirector executable
    /// itself — *not* with `sudo`.
    #[test]
    fn command_as_root_runs_executable_directly() {
        let exe = Path::new("/usr/lib/mitmproxy/mitmproxy-linux-redirector");
        let addr = Path::new("/tmp/mitmproxy-test");
        let cmd = build_redirector_command(exe, addr, /* already_root = */ true);
        let prog = program_of(&cmd);
        assert!(
            prog.ends_with("mitmproxy-linux-redirector"),
            "expected executable as first token, got: {prog:?}"
        );
        assert!(
            !prog.contains("sudo"),
            "sudo must NOT appear as the program when already root, got: {prog:?}"
        );
    }

    /// When NOT root, the command must start with `sudo`.
    #[test]
    fn command_without_root_uses_sudo() {
        let exe = Path::new("/usr/lib/mitmproxy/mitmproxy-linux-redirector");
        let addr = Path::new("/tmp/mitmproxy-test");
        let cmd = build_redirector_command(exe, addr, /* already_root = */ false);
        let prog = program_of(&cmd);
        assert!(
            prog.ends_with("sudo"),
            "expected 'sudo' as first token, got: {prog:?}"
        );
    }

    /// When NOT root, the sudo invocation must pass `--non-interactive` and
    /// `--preserve-env` so that the redirector inherits the user's environment
    /// variables without prompting for a password.
    #[test]
    fn sudo_command_has_required_flags() {
        let exe = Path::new("/usr/lib/mitmproxy/mitmproxy-linux-redirector");
        let addr = Path::new("/tmp/mitmproxy-test");
        let cmd = build_redirector_command(exe, addr, false);
        let args = args_of(&cmd);
        assert!(
            args.iter().any(|a| a == "--non-interactive"),
            "--non-interactive flag missing from sudo invocation; args={args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--preserve-env"),
            "--preserve-env flag missing from sudo invocation; args={args:?}"
        );
    }

    /// The listener address must be the last argument in both the root and
    /// non-root command variants.
    #[test]
    fn listener_addr_is_last_argument() {
        let exe = Path::new("/usr/lib/mitmproxy/mitmproxy-linux-redirector");
        let addr = Path::new("/tmp/mitmproxy-9999");

        for already_root in [true, false] {
            let cmd = build_redirector_command(exe, addr, already_root);
            let args = args_of(&cmd);
            let last = args.last().cloned().unwrap_or_default();
            assert_eq!(
                OsStr::new(&last),
                addr.as_os_str(),
                "listener_addr must be the last argument (already_root={already_root}); args={args:?}"
            );
        }
    }
}
