use std::net::SocketAddr;

use pyo3::{
    exceptions::{PyKeyError, PyOSError},
    prelude::*,
    types::PyBytes,
};
use tokio::sync::{
    mpsc::{self, error::SendError},
    oneshot::{self, error::RecvError},
};

use mitmproxy::messages::{ConnectionId, TransportCommand};

use crate::util::socketaddr_to_py;

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
    pub original_dst: SocketAddr,
    pub original_src: Option<SocketAddr>,
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

        pyo3_asyncio::tokio::future_into_py(py, async move {
            let data = rx.await.map_err(connection_closed)?;
            let bytes: Py<PyBytes> = Python::with_gil(|py| PyBytes::new(py, &data).into_py(py));
            Ok(bytes)
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
            ("original_dst", _) => Ok(socketaddr_to_py(py, self.original_dst)),
            ("original_src", _) => {
                if let Some(original_src) = self.original_src {
                    Ok(socketaddr_to_py(py, original_src))
                } else {
                    Ok(py.None())
                }
            }
            (_, Some(default)) => Ok(default),
            _ => Err(PyKeyError::new_err(name)),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "TcpStream({}, peer={}, sock={}, src={:?}, dst={})",
            self.connection_id, self.peername, self.sockname, self.original_src, self.original_dst,
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

pub fn event_queue_unavailable<T>(_: SendError<T>) -> PyErr {
    PyOSError::new_err("Server has been shut down.")
}

pub fn connection_closed(_: RecvError) -> PyErr {
    PyOSError::new_err("connection closed")
}
