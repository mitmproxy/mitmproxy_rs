use anyhow::{Context, Result};

use crate::messages::{
    NetworkCommand, NetworkEvent, SmolPacket, TransportCommand, TransportEvent, TunnelInfo,
};
use crate::network::{add_network_layer, MAX_PACKET_SIZE};
use crate::packet_sources::{PacketSourceConf, PacketSourceTask};
use tokio::sync::mpsc::{Permit, Receiver, UnboundedReceiver};
use tokio::sync::{broadcast, mpsc::Sender};
use tun2::AbstractDevice;

pub struct TunConf {
    pub tun_name: Option<String>,
}

impl PacketSourceConf for TunConf {
    type Task = TunTask;
    type Data = String;

    fn name(&self) -> &'static str {
        "TUN interface"
    }

    async fn build(
        self,
        transport_events_tx: Sender<TransportEvent>,
        transport_commands_rx: UnboundedReceiver<TransportCommand>,
        shutdown: broadcast::Receiver<()>,
    ) -> Result<(Self::Task, Self::Data)> {
        let mut config = tun2::Configuration::default();
        config.mtu(MAX_PACKET_SIZE as u16);
        // Setting a local address is required on Linux.
        config.address("169.254.0.1");
        config.up();
        if let Some(tun_name) = self.tun_name {
            config.tun_name(&tun_name);
        }

        let device = tun2::create_as_async(&config).context("Failed to create TUN device")?;
        let tun_name = device.tun_name().context("Failed to get TUN name")?;

        let (network_task_handle, net_tx, net_rx) =
            add_network_layer(transport_events_tx, transport_commands_rx, shutdown)?;

        Ok((
            TunTask {
                device,
                net_tx,
                net_rx,
                network_task_handle,
            },
            tun_name,
        ))
    }
}

pub struct TunTask {
    device: tun2::AsyncDevice,

    net_tx: Sender<NetworkEvent>,
    net_rx: Receiver<NetworkCommand>,
    network_task_handle: tokio::task::JoinHandle<Result<()>>,
}

impl PacketSourceTask for TunTask {
    async fn run(mut self) -> Result<()> {
        let size = self.device.mtu()? as usize + tun2::PACKET_INFORMATION_LENGTH;
        let mut buf = vec![0; size];

        let mut packet_to_send = Vec::new();
        let mut permit: Option<Permit<NetworkEvent>> = None;

        // Required on macOS, but currently crashes on Linux with tokio.
        //let (mut writer, mut reader) = self.device.split().context("failed to split device")?;

        loop {
            tokio::select! {
                // Monitor the network task for errors or planned shutdown.
                // This way we implicitly monitor the shutdown broadcast channel.
                exit = &mut self.network_task_handle => break exit.context("network task panic")?.context("network task error")?,
                // wait for transport_events_tx channel capacity...
                Ok(p) = self.net_tx.reserve(), if permit.is_none() => {
                    permit = Some(p);
                },
                // ... or process incoming packets
                r = self.device.recv(buf.as_mut_slice()), if permit.is_some() => {
                    let len = r.context("TUN read() failed")?;

                    let Ok(packet) = SmolPacket::try_from(buf[..len].to_vec()) else {
                        log::error!("Skipping invalid packet from tun interface: {:?}", &buf[..len]);
                        continue;
                    };
                    dbg!(&packet);
                    permit.take().unwrap().send(NetworkEvent::ReceivePacket {
                        packet,
                        tunnel_info: TunnelInfo::None,
                    });
                },
                // send_to is cancel safe, so we can use that for backpressure.
                r = self.device.send(&packet_to_send), if !packet_to_send.is_empty() => {
                    r.context("TUN write() failed")?;
                    packet_to_send.clear();
                },
                Some(command) = self.net_rx.recv(), if packet_to_send.is_empty() => {
                    match command {
                        NetworkCommand::SendPacket(packet) => {
                            dbg!(&packet);
                            packet_to_send = packet.into_inner();
                        }
                    }
                }
            }
        }
        log::debug!("TUN interface task shutting down.");
        Ok(())
    }
}
