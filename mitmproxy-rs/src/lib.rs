extern crate core;

use std::sync::RwLock;

use crate::contentview::{Contentview, InteractiveContentview};
use mitmproxy::contentviews::{Prettify, Reencode};
use once_cell::sync::Lazy;
use pyo3::{exceptions::PyException, prelude::*};

mod contentview;
mod dns_resolver;
mod process_info;
mod server;
mod stream;
pub mod task;
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

#[pymodule]
mod mitmproxy_rs {
    use super::*;

    #[pymodule]
    mod certs {
        #[pymodule_export]
        use crate::util::{add_cert, remove_cert};
    }

    #[pymodule]
    mod dns {
        #[pymodule_export]
        use crate::dns_resolver::{get_system_dns_servers, DnsResolver};
    }

    #[pymodule]
    mod local {
        #[pymodule_export]
        use crate::server::{start_local_redirector, LocalRedirector};
    }

    #[pymodule]
    mod process_info {
        #[pymodule_export]
        use crate::process_info::{active_executables, executable_icon, Process};
    }

    #[pymodule]
    mod tun {
        #[pymodule_export]
        use crate::server::{create_tun_interface, TunInterface};
    }

    #[pymodule]
    mod udp {
        #[pymodule_export]
        use crate::server::{start_udp_server, UdpServer};
        #[pymodule_export]
        use crate::udp_client::open_udp_connection;
    }

    #[pymodule]
    mod wireguard {
        #[pymodule_export]
        use crate::server::{start_wireguard_server, WireGuardServer};
        #[pymodule_export]
        use crate::util::{genkey, pubkey};
    }

    #[pymodule]
    mod contentviews {
        use super::*;
        #[pymodule_export]
        use crate::contentview::Contentview;
        #[pymodule_export]
        use crate::contentview::InteractiveContentview;
        use mitmproxy::contentviews::{HexDump, HexStream};

        #[pymodule_init]
        fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
            m.add_contentview(&HexDump)?;
            m.add_interactive_contentview(&HexStream)?;
            Ok(())
        }
    }

    #[pymodule_export]
    use crate::stream::Stream;

    #[pymodule_init]
    #[allow(unused_variables)]
    fn init(m: &Bound<'_, PyModule>) -> PyResult<()> {
        // set up the Rust logger to send messages to the Python logger
        init_logger()?;

        // set up tracing subscriber for introspection with tokio-console
        #[cfg(feature = "tracing")]
        console_subscriber::init();

        // Import platform-specific modules here so that missing dependencies are raising immediately.
        #[cfg(target_os = "macos")]
        m.py().import("mitmproxy_macos")?;
        #[cfg(all(target_os = "linux", not(feature = "docs")))]
        m.py().import("mitmproxy_linux")?;
        #[cfg(windows)]
        m.py().import("mitmproxy_windows")?;

        Ok(())
    }
}

trait AddContentview {
    fn add_contentview<T: Prettify>(&self, cv: &'static T) -> PyResult<()>;
    fn add_interactive_contentview<T: Prettify + Reencode>(&self, i: &'static T) -> PyResult<()>;
}

impl AddContentview for Bound<'_, PyModule> {
    fn add_contentview<T: Prettify>(&self, cv: &'static T) -> PyResult<()> {
        let view = Contentview::new(self.py(), cv)?;
        self.add(cv.instance_name(), view)
    }
    fn add_interactive_contentview<T: Prettify + Reencode>(&self, cv: &'static T) -> PyResult<()> {
        let view = InteractiveContentview::new(self.py(), cv)?;
        self.add(cv.instance_name(), view)
    }
}
