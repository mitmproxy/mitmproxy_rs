use std::collections::VecDeque;

use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc::{Permit, Sender};

use crate::messages::{NetworkCommand, SmolPacket};

/// A virtual smoltcp device into which we manually feed packets using
/// [VirtualDevice::receive_packet] and which send outgoing packets to a channel.
pub struct VirtualDevice {
    rx_buffer: VecDeque<Vec<u8>>,
    tx_channel: Sender<NetworkCommand>,
}

impl VirtualDevice {
    pub fn new(tx_channel: Sender<NetworkCommand>) -> Self {
        VirtualDevice {
            rx_buffer: VecDeque::new(),
            tx_channel,
        }
    }

    pub fn receive_packet(&mut self, packet: SmolPacket) {
        self.rx_buffer.push_back(packet.into_inner());
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = VirtualRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = VirtualTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.rx_buffer.is_empty() {
            return None;
        }

        if let Ok(permit) = self.tx_channel.try_reserve() {
            if let Some(buffer) = self.rx_buffer.pop_front() {
                let rx = Self::RxToken { buffer };
                let tx = VirtualTxToken { permit };
                return Some((rx, tx));
            }
        }

        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        match self.tx_channel.try_reserve() {
            Ok(permit) => Some(VirtualTxToken { permit }),
            Err(_) => None,
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = 1420;
        capabilities
    }
}

pub struct VirtualTxToken<'a> {
    permit: Permit<'a, NetworkCommand>,
}

impl TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);

        match SmolPacket::try_from(buffer) {
            Ok(packet) => {
                self.permit.send(NetworkCommand::SendPacket(packet));
            }
            Err(err) => {
                log::error!("Failed to parse packet from smol: {:?}", err)
            }
        }

        result
    }
}

pub struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer[..])
    }
}
