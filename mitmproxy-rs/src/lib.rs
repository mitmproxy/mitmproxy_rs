extern crate core;

use std::sync::RwLock;

use once_cell::sync::Lazy;
use pyo3::{exceptions::PyException, prelude::*};

mod dns_resolver;
mod process_info;
mod server;
mod stream;
mod task;
mod udp_client;
mod util;

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
            "Failed to initialize mitmproxy_rs logger.",
        ))
    }
}

#[allow(unused)]
#[pymodule]
pub fn mitmproxy_rs(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // set up the Rust logger to send messages to the Python logger
    init_logger()?;

    // set up tracing subscriber for introspection with tokio-console
    #[cfg(feature = "tracing")]
    console_subscriber::init();

    m.add_function(wrap_pyfunction!(server::start_wireguard_server, m)?)?;
    m.add_class::<server::WireGuardServer>()?;
    m.add_function(wrap_pyfunction!(util::genkey, m)?)?;
    m.add_function(wrap_pyfunction!(util::pubkey, m)?)?;
    m.add_function(wrap_pyfunction!(util::add_cert, m)?)?;
    m.add_function(wrap_pyfunction!(util::remove_cert, m)?)?;

    m.add_function(wrap_pyfunction!(server::start_local_redirector, m)?)?;
    m.add_class::<server::LocalRedirector>()?;

    m.add_function(wrap_pyfunction!(server::start_udp_server, m)?)?;
    m.add_class::<server::UdpServer>()?;

    m.add_function(wrap_pyfunction!(udp_client::open_udp_connection, m)?)?;

    m.add_function(wrap_pyfunction!(process_info::active_executables, m)?)?;
    m.add_class::<process_info::Process>()?;
    m.add_function(wrap_pyfunction!(process_info::executable_icon, m)?)?;

    m.add_class::<dns_resolver::DnsResolver>()?;
    m.add_function(wrap_pyfunction!(dns_resolver::get_system_dns_servers, m)?)?;

    m.add_class::<stream::Stream>()?;

    // Import platform-specific modules here so that missing dependencies are raising immediately.
    #[cfg(target_os = "macos")]
    py.import_bound("mitmproxy_macos")?;
    #[cfg(windows)]
    py.import_bound("mitmproxy_windows")?;

    Ok(())
}
