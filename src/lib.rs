#![warn(missing_debug_implementations)]
#![allow(clippy::borrow_deref_ref)]

use std::sync::RwLock;

use once_cell::sync::Lazy;
use pyo3::{exceptions::PyException, prelude::*};

mod messages;
mod network;
mod packet_sources;
pub mod python;
pub mod server;
mod shutdown;
pub mod util;

pub use network::MAX_PACKET_SIZE;
