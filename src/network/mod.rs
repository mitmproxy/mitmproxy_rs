mod task;
pub use task::add_network_layer;
pub use task::NetworkTask;

mod virtual_device;

mod core;
mod icmp;
mod tcp;
#[cfg(test)]
mod tests;
pub(crate) mod udp;

pub const MAX_PACKET_SIZE: usize = 65535;
