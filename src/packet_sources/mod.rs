use crate::intercept_conf::InterceptConf;
use crate::ipc;
use crate::ipc::PacketWithMeta;
use crate::messages::{
    NetworkCommand, NetworkEvent, SmolPacket, TransportCommand, TransportEvent, TunnelInfo,
};
use crate::network::add_network_layer;
use crate::packet_sources::linux::IPC_BUF_SIZE;
use anyhow::{anyhow, Context, Result};
use prost::Message;
use std::future::Future;
use std::io::Cursor;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc::{Sender, UnboundedReceiver};
use tokio::sync::{broadcast, mpsc};

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

/// Feed packets from a socket into smol, and the other way around.
async fn forward_packets<T: AsyncRead + AsyncWrite + Unpin>(
    mut channel: T,
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    mut conf_rx: UnboundedReceiver<InterceptConf>,
    shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    let mut buf = vec![0u8; IPC_BUF_SIZE];
    let (mut network_task_handle, net_tx, mut net_rx) =
        add_network_layer(transport_events_tx, transport_commands_rx, shutdown);

    loop {
        tokio::select! {
            // Monitor the network task for errors or planned shutdown.
            // This way we implicitly monitor the shutdown broadcast channel.
            exit = &mut network_task_handle => break exit.context("network task panic")?.context("network task error")?,
            // pipe through changes to the intercept list
            Some(conf) = conf_rx.recv() => {
                let msg = ipc::FromProxy {
                    message: Some(ipc::from_proxy::Message::InterceptConf(conf.into())),
                };
                msg.encode(&mut buf.as_mut_slice())?;
                let len = msg.encoded_len();

                channel.write_all(&buf[..len]).await?;
            },
            // read packets from the IPC pipe into our network stack.
            r = channel.read(&mut buf) => {
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
                if net_tx.try_send(event).is_err() {
                    log::warn!("Dropping incoming packet, TCP channel is full.")
                };
            },
            // write packets from the network stack to the IPC pipe to be reinjected.
            Some(e) = net_rx.recv() => {
                match e {
                    NetworkCommand::SendPacket(packet) => {
                        let packet = ipc::FromProxy { message: Some(ipc::from_proxy::Message::Packet( ipc::Packet { data: packet.into_inner() }))};
                        packet.encode(&mut buf.as_mut_slice())?;
                        let len = packet.encoded_len();
                        channel.write_all(&buf[..len]).await?;
                    }
                }
            }
        }
    }
    log::info!("Redirector shutting down.");
    Ok(())
}
