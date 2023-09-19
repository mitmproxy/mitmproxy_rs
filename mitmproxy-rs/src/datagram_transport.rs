use std::net::SocketAddr;

use pyo3::prelude::*;
use pyo3::types::PyTuple;
use tokio::sync::mpsc;

use crate::util::get_tunnel_info;
use mitmproxy::messages::{TransportCommand, TunnelInfo};

use crate::util::{event_queue_unavailable, py_to_socketaddr, socketaddr_to_py};

#[pyclass(module = "mitmproxy_rs")]
#[derive(Debug)]
pub struct DatagramTransport {
    pub event_tx: mpsc::UnboundedSender<TransportCommand>,
    pub peername: SocketAddr,
    pub sockname: SocketAddr,
    pub tunnel_info: TunnelInfo,
}

#[pymethods]
impl DatagramTransport {
    #[pyo3(text_signature = "(self, data, addr=None)")]
    fn sendto(&self, data: Vec<u8>, addr: Option<&PyTuple>) -> PyResult<()> {
        let dst_addr = match addr {
            Some(addr) => py_to_socketaddr(addr)?,
            None => self.peername,
        };
        self.event_tx
            .send(TransportCommand::SendDatagram {
                data,
                src_addr: self.sockname,
                dst_addr,
            })
            .map_err(event_queue_unavailable)?;
        Ok(())
    }

    /// Query the UDP transport for details of the underlying network connection.
    ///
    /// Supported values: `peername`, `sockname`, `original_src`, and `original_dst`.
    #[pyo3(text_signature = "(self, name, default=None)")]
    fn get_extra_info(
        &self,
        py: Python,
        name: String,
        default: Option<PyObject>,
    ) -> PyResult<PyObject> {
        match name.as_str() {
            "peername" => Ok(socketaddr_to_py(py, self.peername)),
            "sockname" => Ok(socketaddr_to_py(py, self.sockname)),
            _ => get_tunnel_info(&self.tunnel_info, py, name, default),
        }
    }

    /// Close the UDP transport.
    /// This method is a no-op and only exists for API compatibility with DatagramTransport
    fn close(&mut self) -> PyResult<()> {
        Ok(())
    }

    /// Check whether this UDP transport is being closed.
    /// This method is a no-op and only exists for API compatibility with DatagramTransport
    fn is_closing(&self) -> PyResult<bool> {
        Ok(false)
    }

    /// Wait until the UDP transport is closed.
    /// This method is a no-op and only exists for API compatibility with DatagramTransport
    fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        pyo3_asyncio::tokio::future_into_py(py, std::future::ready(Ok(())))
    }

    fn get_protocol(self_: Py<Self>) -> Py<Self> {
        self_
    }

    fn drain<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        pyo3_asyncio::tokio::future_into_py(py, std::future::ready(Ok(())))
    }
}
