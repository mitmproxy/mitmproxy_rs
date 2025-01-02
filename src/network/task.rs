use std::fmt;

use anyhow::Result;

use std::time::Duration;
use tokio::sync::{
    mpsc,
    mpsc::{Permit, Receiver, Sender, UnboundedReceiver},
};
use tokio::task::JoinHandle;

use crate::messages::{NetworkCommand, NetworkEvent, TransportCommand, TransportEvent};
use crate::network::core::NetworkStack;
use crate::shutdown;

pub struct NetworkTask<'a> {
    net_tx: Sender<NetworkCommand>,
    net_rx: Receiver<NetworkEvent>,
    py_tx: Sender<TransportEvent>,
    py_rx: UnboundedReceiver<TransportCommand>,

    shutdown: shutdown::Receiver,
    io: NetworkStack<'a>,
}

#[allow(clippy::type_complexity)]
pub fn add_network_layer(
    transport_events_tx: Sender<TransportEvent>,
    transport_commands_rx: UnboundedReceiver<TransportCommand>,
    shutdown: shutdown::Receiver,
) -> (
    JoinHandle<Result<()>>,
    Sender<NetworkEvent>,
    Receiver<NetworkCommand>,
) {
    // initialize channels between the WireGuard server and the virtual network device
    let (network_events_tx, network_events_rx) = mpsc::channel(256);
    let (network_commands_tx, network_commands_rx) = mpsc::channel(256);

    let task = NetworkTask::new(
        network_commands_tx,
        network_events_rx,
        transport_events_tx,
        transport_commands_rx,
        shutdown,
    );
    let h = tokio::spawn(Box::pin(async move { task.run().await }));
    (h, network_events_tx, network_commands_rx)
}

impl NetworkTask<'_> {
    pub fn new(
        net_tx: Sender<NetworkCommand>,
        net_rx: Receiver<NetworkEvent>,
        py_tx: Sender<TransportEvent>,
        py_rx: UnboundedReceiver<TransportCommand>,
        shutdown: shutdown::Receiver,
    ) -> Self {
        let io = NetworkStack::new(net_tx.clone());
        Self {
            net_tx,
            net_rx,
            py_tx,
            py_rx,
            shutdown,
            io,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let mut py_tx_permit: Option<Permit<TransportEvent>> = None;
        let mut delay: Option<Duration> = None;

        'task: loop {
            // On a high level, we do three things in our main loop:
            // 1. Wait for an event from either side and handle it, or wait until the next smoltcp timeout.
            // 2. `.poll()` the smoltcp interface until it's finished with everything for now.
            // 3. Check if we can wake up any waiters, move more data in the send buffer, or clean up sockets.

            #[cfg(debug_assertions)]
            if let Some(d) = delay {
                log::debug!("Waiting for device timeout: {:?} ...", d);
            }

            #[cfg(debug_assertions)]
            log::debug!("Waiting for events ...");

            let py_tx_available = py_tx_permit.is_some();
            let net_tx_available = self.net_tx.capacity() > 0;

            tokio::select! {
                // wait for graceful shutdown
                _ = self.shutdown.recv() => break 'task,
                // wait for timeouts when the device is idle
                _ = async { tokio::time::sleep(delay.unwrap()).await }, if delay.is_some() => {},
                // wait for py_tx channel capacity...
                Ok(permit) = self.py_tx.reserve(), if !py_tx_available => {
                    py_tx_permit = Some(permit);
                    continue 'task;
                },
                // ...or process incoming packets
                Some(e) = self.net_rx.recv(), if py_tx_available => {
                    // handle pending network events until channel is full
                    self.io.handle_network_event(e, py_tx_permit.take().unwrap())?;
                    while let Ok(p) = self.py_tx.try_reserve() {
                        if let Ok(e) = self.net_rx.try_recv() {
                            self.io.handle_network_event(e, p)?;
                        } else {
                            break;
                        }
                    }
                },
                // wait for net_tx capacity...
                Ok(permit) = self.net_tx.reserve(), if !net_tx_available => {
                    drop(permit); // smoltcp's device stuff is not permit-based.
                    continue 'task;
                },
                // ...or process outgoing packets
                Some(c) = self.py_rx.recv(), if net_tx_available => {
                    // handle pending transport commands until channel is full
                    self.io.handle_transport_command(c);
                    while self.net_tx.capacity() > 0 {
                        if let Ok(c) = self.py_rx.try_recv() {
                            self.io.handle_transport_command(c);
                        } else {
                            break;
                        }
                    }
                },
            }

            self.io.poll()?;
            delay = self.io.poll_delay();
        }

        // TODO: process remaining pending data after the shutdown request was received?

        log::debug!("Virtual Network device task shutting down.");
        Ok(())
    }
}

impl fmt::Debug for NetworkTask<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetworkTask").field("io", &self.io).finish()
    }
}
