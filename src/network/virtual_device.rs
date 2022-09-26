use std::collections::VecDeque;

use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc::{Permit, Sender};

use crate::messages::{IpPacket, NetworkCommand};

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

    pub fn receive_packet(&mut self, packet: IpPacket) {
        self.rx_buffer.push_back(packet.into_inner());
    }
}

impl<'a> Device<'a> for VirtualDevice {
    type RxToken = VirtualRxToken;
    type TxToken = VirtualTxToken<'a>;

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
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

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
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

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, _timestamp: Instant, len: usize, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        let mut buffer = vec![0; len];
        let result = f(&mut buffer);

        if result.is_ok() {
            let cmd = NetworkCommand::SendPacket(
                IpPacket::try_from(buffer).map_err(|_| smoltcp::Error::Malformed)?,
            );
            self.permit.send(cmd);
        }
        result
    }
}

pub struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(mut self, _timestamp: Instant, f: F) -> smoltcp::Result<R>
    where
        F: FnOnce(&mut [u8]) -> smoltcp::Result<R>,
    {
        f(&mut self.buffer[..])
    }
}
