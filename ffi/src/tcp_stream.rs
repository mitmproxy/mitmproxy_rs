use std::net::SocketAddr;

use pyo3::{
    exceptions::{PyKeyError, PyOSError},
    prelude::*,
    types::PyBytes,
};
use tokio::sync::{
    mpsc::{self},
    oneshot::{self, error::RecvError},
};

use mitmproxy::messages::{ConnectionId, TransportCommand, TunnelInfo};

use crate::util::{event_queue_unavailable, socketaddr_to_py};

/// An individual TCP stream with an API that is similar to
/// [`asyncio.StreamReader` and `asyncio.StreamWriter`](https://docs.python.org/3/library/asyncio-stream.html)
/// from the Python standard library.
#[pyclass]
#[derive(Debug)]
pub struct TcpStream {
    pub connection_id: ConnectionId,
    pub event_tx: mpsc::UnboundedSender<TransportCommand>,
    pub peername: SocketAddr,
    pub sockname: SocketAddr,
    pub tunnel_info: TunnelInfo,
    pub is_closing: bool,
}

#[pymethods]
impl TcpStream {
    /// Read up to `n` bytes from the TCP stream.
    ///
    /// If the connection was closed, this returns an empty `bytes` object.
    fn read<'p>(&self, py: Python<'p>, n: u32) -> PyResult<&'p PyAny> {
        let (tx, rx) = oneshot::channel();

        self.event_tx
            .send(TransportCommand::ReadData(self.connection_id, n, tx))
            .map_err(event_queue_unavailable)?;

        pyo3_asyncio::tokio::future_into_py::<_, Py<PyBytes>>(py, async move {
            let data = rx.await.map_err(connection_closed)?;
            Python::with_gil(|py| Ok(PyBytes::new(py, &data).into_py(py)))
        })
    }

    /// Write bytes onto the TCP stream.
    ///
    /// This queues the data into a write buffer. To wait until the TCP connection can be written to
    /// again, use the `TcpStream.drain` coroutine.
    fn write(&self, data: Vec<u8>) -> PyResult<()> {
        self.event_tx
            .send(TransportCommand::WriteData(self.connection_id, data))
            .map_err(event_queue_unavailable)?;

        Ok(())
    }

    /// Wait until the TCP stream can be written to again.
    fn drain<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let (tx, rx) = oneshot::channel();

        self.event_tx
            .send(TransportCommand::DrainWriter(self.connection_id, tx))
            .map_err(event_queue_unavailable)?;

        pyo3_asyncio::tokio::future_into_py(py, async move {
            rx.await.map_err(connection_closed)?;
            Ok(())
        })
    }

    /// Close the stream after flushing the write buffer.
    fn write_eof(&mut self) -> PyResult<()> {
        self.is_closing = true;
        self.event_tx
            .send(TransportCommand::CloseConnection(self.connection_id, true))
            .map_err(event_queue_unavailable)?;

        Ok(())
    }

    /// Close the TCP stream and the underlying socket immediately.
    fn close(&mut self) -> PyResult<()> {
        self.is_closing = true;
        self.event_tx
            .send(TransportCommand::CloseConnection(self.connection_id, false))
            .map_err(event_queue_unavailable)?;

        Ok(())
    }

    /// Check whether this TCP stream is being closed.
    fn is_closing(&self) -> PyResult<bool> {
        Ok(self.is_closing)
    }

    /// Wait until the TCP stream is closed (currently a no-op).
    fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        pyo3_asyncio::tokio::future_into_py(py, std::future::ready(Ok(())))
    }

    /// Query the TCP stream for details of the underlying network connection.
    ///
    /// Supported values: `peername`, `sockname`, `original_dst`, and `original_src`.
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

    fn __repr__(&self) -> String {
        format!(
            "TcpStream({}, peer={}, sock={}, tunnel_info={:?})",
            self.connection_id, self.peername, self.sockname, self.tunnel_info,
        )
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            log::debug!("Failed to close TCP stream during clean up: {}", error);
        }
    }
}

pub fn connection_closed(_: RecvError) -> PyErr {
    PyOSError::new_err("connection closed")
}
