pub use network::MAX_PACKET_SIZE;

pub mod certificates;
pub mod contentviews;
pub mod dns;
pub mod intercept_conf;
pub mod ipc;
pub mod messages;
pub mod network;
pub mod packet_sources;
pub mod processes;
pub mod shutdown;
pub mod syntax_highlight;
#[cfg(windows)]
pub mod windows;
