#![warn(missing_debug_implementations)]
#![allow(clippy::borrow_deref_ref)]

use std::sync::RwLock;

use once_cell::sync::Lazy;
use pyo3::{exceptions::PyException, prelude::*};

mod messages;
mod network;
mod python;
mod server;
mod shutdown;
mod util;
mod wireguard;

static LOGGER_INITIALIZED: Lazy<RwLock<bool>> = Lazy::new(|| RwLock::new(false));

fn init_logger() -> PyResult<()> {
    if *LOGGER_INITIALIZED.read().unwrap() {
        // logger already initialized
        Ok(())
    } else if pyo3_log::try_init().is_ok() {
        // logger successfully initialized
        *LOGGER_INITIALIZED.write().unwrap() = true;
        Ok(())
    } else {
        // logger was not initialized and could not be initialized
        Err(PyException::new_err(
            "Failed to initialize mitmproxy_wireguard logger.",
        ))
    }
}

/// This package contains a cross-platform, user-space WireGuard server implementation in Rust,
/// which provides a Python interface that is intended to be similar to the one provided by
/// [`asyncio.start_server`](https://docs.python.org/3/library/asyncio-stream.html#asyncio.start_server)
/// from the Python standard library.
#[pymodule]
pub fn mitmproxy_wireguard(_py: Python, m: &PyModule) -> PyResult<()> {
    // set up the Rust logger to send messages to the Python logger
    init_logger()?;

    // set up tracing subscriber for introspection with tokio-console
    #[cfg(feature = "tracing")]
    console_subscriber::init();

    m.add_function(wrap_pyfunction!(server::start_server, m)?)?;
    m.add_function(wrap_pyfunction!(util::genkey, m)?)?;
    m.add_function(wrap_pyfunction!(util::pubkey, m)?)?;
    m.add_class::<server::Server>()?;
    m.add_class::<python::TcpStream>()?;

    Ok(())
}
