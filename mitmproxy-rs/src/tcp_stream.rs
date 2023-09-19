use std::net::SocketAddr;

use pyo3::{exceptions::PyOSError, prelude::*, types::PyBytes};

use tokio::sync::{
    mpsc::{self},
    oneshot::{self, error::RecvError},
};

use mitmproxy::messages::{ConnectionId, TransportCommand, TunnelInfo};

use crate::util::{event_queue_unavailable, get_tunnel_info, socketaddr_to_py};

#[derive(Debug)]
pub enum TcpStreamState {
    Open,
    HalfClosed,
    Closed,
}

/// An individual TCP stream with an API that is similar to
/// [`asyncio.StreamReader` and `asyncio.StreamWriter`](https://docs.python.org/3/library/asyncio-stream.html)
/// from the Python standard library.
#[pyclass(module = "mitmproxy_rs")]
#[derive(Debug)]
pub struct TcpStream {
    pub connection_id: ConnectionId,
    pub state: TcpStreamState,
    pub event_tx: mpsc::UnboundedSender<TransportCommand>,
    pub peername: SocketAddr,
    pub sockname: SocketAddr,
    pub tunnel_info: TunnelInfo,
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
        match self.state {
            TcpStreamState::Open => {
                self.state = TcpStreamState::HalfClosed;
                self.event_tx
                    .send(TransportCommand::CloseConnection(self.connection_id, true))
                    .map_err(event_queue_unavailable)
            }
            TcpStreamState::HalfClosed => Ok(()),
            TcpStreamState::Closed => Ok(()),
        }
    }

    /// Close the TCP stream and the underlying socket immediately.
    fn close(&mut self) -> PyResult<()> {
        match self.state {
            TcpStreamState::Open | TcpStreamState::HalfClosed => {
                self.state = TcpStreamState::Closed;
                self.event_tx
                    .send(TransportCommand::CloseConnection(self.connection_id, false))
                    .map_err(event_queue_unavailable)
            }
            TcpStreamState::Closed => Ok(()),
        }
    }

    /// Check whether this TCP stream is being closed.
    fn is_closing(&self) -> bool {
        match self.state {
            TcpStreamState::Open => false,
            TcpStreamState::HalfClosed | TcpStreamState::Closed => true,
        }
    }

    /// Wait until the TCP stream is closed (currently a no-op).
    fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        pyo3_asyncio::tokio::future_into_py(py, std::future::ready(Ok(())))
    }

    /// Query the TCP stream for details of the underlying network connection.
    ///
    /// Supported values: `peername`, `sockname`, `original_dst`, and `original_src`.
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
