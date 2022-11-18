use std::sync::RwLock;

use once_cell::sync::Lazy;
use pyo3::{exceptions::PyException, prelude::*};

pub mod messages;
pub mod network;
pub mod packet_sources;
pub mod server;
pub mod shutdown;
pub mod util;

pub use network::MAX_PACKET_SIZE;
