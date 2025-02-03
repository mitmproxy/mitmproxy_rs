use std::iter;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use anyhow::{anyhow, Result};
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use windows::core::w;
use windows::core::PCWSTR;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::Shell::SE_ERR_ACCESSDENIED;
use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};

use crate::intercept_conf::InterceptConf;
use crate::messages::{TransportCommand, TransportEvent};
use crate::packet_sources::{forward_packets, PacketSourceConf, PacketSourceTask, IPC_BUF_SIZE};
use crate::shutdown;

pub struct WindowsConf {
    pub executable_path: PathBuf,
}

impl PacketSourceConf for WindowsConf {
    type Task = WindowsTask;
    type Data = UnboundedSender<InterceptConf>;

    fn name(&self) -> &'static str {
        "Windows proxy"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> Result<(Self::Task, Self::Data)> {
        let pipe_name = format!(
            r"\\.\pipe\mitmproxy-transparent-proxy-{}",
            std::process::id()
        );

        let ipc_server = ServerOptions::new()
            .pipe_mode(PipeMode::Message)
            .first_pipe_instance(true)
            .max_instances(1)
            .in_buffer_size(IPC_BUF_SIZE as u32)
            .out_buffer_size(IPC_BUF_SIZE as u32)
            .reject_remote_clients(true)
            .create(&pipe_name)?;

        log::debug!("starting {} {}", self.executable_path.display(), pipe_name);

        let pipe_name = pipe_name
            .encode_utf16()
            .chain(iter::once(0))
            .collect::<Vec<u16>>();

        let executable_path = self
            .executable_path
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<u16>>();

        let result = unsafe {
            ShellExecuteW(
                None,
                w!("runas"),
                PCWSTR::from_raw(executable_path.as_ptr()),
                PCWSTR::from_raw(pipe_name.as_ptr()),
                None,
                if cfg!(debug_assertions) {
                    SW_SHOWNORMAL
                } else {
                    SW_HIDE
                },
            )
        };

        if cfg!(debug_assertions) {
            if result.0 as u32 <= 32 {
                let err = windows::core::Error::from_win32();
                log::warn!("Failed to start child process: {}", err);
            }
        } else if result.0 as u32 == SE_ERR_ACCESSDENIED {
            return Err(anyhow!(
                "Failed to start the interception process as administrator."
            ));
        } else if result.0 as u32 <= 32 {
            let err = windows::core::Error::from_win32();
            return Err(anyhow!("Failed to start the executable: {}", err));
        }

        let (conf_tx, conf_rx) = unbounded_channel();

        Ok((
            WindowsTask {
                ipc_server,
                transport_events_tx,
                transport_commands_rx,
                conf_rx,
                shutdown,
            },
            conf_tx,
        ))
    }
}

pub struct WindowsTask {
    ipc_server: NamedPipeServer,
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    shutdown: shutdown::Receiver,
}

impl PacketSourceTask for WindowsTask {
    async fn run(self) -> Result<()> {
        log::debug!("Waiting for IPC connection...");
        self.ipc_server.connect().await?;
        log::debug!("IPC connected!");

        forward_packets(
            self.ipc_server,
            self.transport_events_tx,
            self.transport_commands_rx,
            self.conf_rx,
            self.shutdown,
        )
        .await
    }
}
