use anyhow::{anyhow, Context, Result};
use std::future::Future;
use std::io::Cursor;
use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{broadcast, mpsc};
use tokio::sync::mpsc::{Receiver, Sender, UnboundedReceiver};
use crate::intercept_conf::InterceptConf;
use crate::ipc;
use crate::ipc::PacketWithMeta;
use crate::messages::{NetworkCommand, NetworkEvent, SmolPacket, TransportCommand, TransportEvent, TunnelInfo};
use crate::packet_sources::linux::IPC_BUF_SIZE;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "linux")]
pub mod tun;
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

pub struct PacketForwarderTask<S: Send, T: AsyncRead + AsyncWrite + Send> {
    listener: S,
    channel: T,
    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,
    conf_rx: UnboundedReceiver<InterceptConf>,
    network_task_handle: tokio::task::JoinHandle<Result<()>>,
}
impl<S: Send, T: AsyncRead + AsyncWrite + Send + Unpin> PacketSourceTask for PacketForwarderTask<S, T> {
    async fn run(mut self) -> Result<()> {
        let mut buf = vec![0u8; IPC_BUF_SIZE];
        loop {
            tokio::select! {
                // Monitor the network task for errors or planned shutdown.
                // This way we implicitly monitor the shutdown broadcast channel.
                exit = &mut self.network_task_handle => break exit.context("network task panic")?.context("network task error")?,
                // pipe through changes to the intercept list
                Some(conf) = self.conf_rx.recv() => {
                    let msg = ipc::FromProxy {
                        message: Some(ipc::from_proxy::Message::InterceptConf(conf.into())),
                    };
                    msg.encode(&mut buf.as_mut_slice())?;
                    let len = msg.encoded_len();

                    self.channel.write_all(&buf[..len]).await?;
                },
                // read packets from the IPC pipe into our network stack.
                r = self.channel.read(&mut buf) => {
                    let len = r.context("IPC read error.")?;
                    if len == 0 {
                        // https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-client
                        // Because the client is reading from the pipe in message-read mode, it is
                        // possible for the ReadFile operation to return zero after reading a partial
                        // message. This happens when the message is larger than the read buffer.
                        //
                        // We don't support messages larger than the buffer, so this cannot happen.
                        // Instead, empty reads indicate that the IPC client has disconnected.
                        return Err(anyhow!("redirect daemon exited prematurely."));
                    }

                    let mut cursor = Cursor::new(&buf[..len]);
                    let Ok(PacketWithMeta { data, tunnel_info: Some(ipc::TunnelInfo { pid, process_name })}) = PacketWithMeta::decode(&mut cursor) else {
                        return Err(anyhow!("Received invalid IPC message: {:?}", &buf[..len]));
                    };
                    assert_eq!(cursor.position(), len as u64);

                    let Ok(mut packet) = SmolPacket::try_from(data) else {
                        log::error!("Skipping invalid packet: {:?}", &buf[..len]);
                        continue;
                    };
                    // WinDivert packets do not have correct IP checksums yet, we need fix that here
                    // otherwise smoltcp will be unhappy with us.
                    packet.fill_ip_checksum();

                    let event = NetworkEvent::ReceivePacket {
                        packet,
                        tunnel_info: TunnelInfo::LocalRedirector {
                            pid,
                            process_name,
                            remote_endpoint: None,
                        },
                    };
                    if self.net_tx.try_send(event).is_err() {
                        log::warn!("Dropping incoming packet, TCP channel is full.")
                    };
                },
                // write packets from the network stack to the IPC pipe to be reinjected.
                Some(e) = self.net_rx.recv() => {
                    match e {
                        NetworkCommand::SendPacket(packet) => {
                            let packet = ipc::FromProxy { message: Some(ipc::from_proxy::Message::Packet( ipc::Packet { data: packet.into_inner() }))};
                            packet.encode(&mut buf.as_mut_slice())?;
                            let len = packet.encoded_len();
                            self.channel.write_all(&buf[..len]).await?;
                        }
                    }
                }
            }
        }

        log::info!("Local redirector shutting down.");
        Ok(())
    }
}
