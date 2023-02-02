use std::net::SocketAddr;

use pyo3::types::PyTuple;
use pyo3::{exceptions::PyKeyError, prelude::*};
use tokio::sync::mpsc;

use mitmproxy::messages::{TransportCommand, TunnelInfo};

use crate::util::{event_queue_unavailable, py_to_socketaddr, socketaddr_to_py};

#[pyclass]
#[derive(Debug)]
pub struct DatagramTransport {
    pub event_tx: mpsc::UnboundedSender<TransportCommand>,
    pub peername: SocketAddr,
    pub sockname: SocketAddr,
    pub tunnel_info: TunnelInfo,
}

#[pymethods]
impl DatagramTransport {
    #[args(addr = "None")]
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
    #[args(default = "None")]
    fn get_extra_info(
        &self,
        py: Python,
        name: String,
        default: Option<PyObject>,
    ) -> PyResult<PyObject> {
        match (name.as_str(), default) {
            ("peername", _) => Ok(socketaddr_to_py(py, self.peername)),
            ("sockname", _) => Ok(socketaddr_to_py(py, self.sockname)),
            ("original_src", _) => match self.tunnel_info {
                TunnelInfo::WireGuard { src_addr, .. } => Ok(socketaddr_to_py(py, src_addr)),
                TunnelInfo::Windows { .. } => Ok(py.None()),
            },
            ("original_dst", _) => match self.tunnel_info {
                TunnelInfo::WireGuard { dst_addr, .. } => Ok(socketaddr_to_py(py, dst_addr)),
                TunnelInfo::Windows { .. } => Ok(py.None()),
            },
            ("pid", _) => match &self.tunnel_info {
                TunnelInfo::Windows { pid, .. } => Ok(pid.into_py(py)),
                TunnelInfo::WireGuard { .. } => Ok(py.None()),
            },
            ("process_name", _) => match &self.tunnel_info {
                TunnelInfo::Windows {
                    process_name: Some(x),
                    ..
                } => Ok(x.into_py(py)),
                _ => Ok(py.None()),
            },
            (_, Some(default)) => Ok(default),
            _ => Err(PyKeyError::new_err(name)),
        }
    }

    fn get_protocol(self_: Py<Self>) -> Py<Self> {
        self_
    }

    fn drain<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        pyo3_asyncio::tokio::future_into_py(py, std::future::ready(Ok(())))
    }
}
