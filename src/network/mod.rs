mod task;
pub use task::add_network_layer;
pub use task::NetworkTask;

mod virtual_device;

#[cfg(test)]
mod tests;

pub const MAX_PACKET_SIZE: usize = 65535;
