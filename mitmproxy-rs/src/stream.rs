use std::net::SocketAddr;

use pyo3::exceptions::PyKeyError;
use pyo3::{exceptions::PyOSError, intern, prelude::*, IntoPyObjectExt};

use tokio::sync::{
    mpsc::{self},
    oneshot::{self},
};

use mitmproxy::messages::{ConnectionId, TransportCommand, TunnelInfo};

use crate::util::{event_queue_unavailable, socketaddr_to_py};

#[derive(Debug)]
pub enum StreamState {
    Open,
    HalfClosed,
    Closed,
}

/// An individual TCP or UDP stream with an API that is similar to
/// [`asyncio.StreamReader` and `asyncio.StreamWriter`](https://docs.python.org/3/library/asyncio-stream.html)
/// from the Python standard library.
#[pyclass(module = "mitmproxy_rs")]
#[derive(Debug)]
pub struct Stream {
    pub connection_id: ConnectionId,
    pub state: StreamState,
    pub command_tx: mpsc::UnboundedSender<TransportCommand>,
    pub peername: SocketAddr,
    pub sockname: SocketAddr,
    pub tunnel_info: TunnelInfo,
}

#[pymethods]
impl Stream {
    /// Read up to `n` bytes of a TCP stream, or a single UDP packet (`n` is ignored for UDP).
    ///
    /// Return an empty `bytes` object if the connection was closed
    /// or the server has been shut down.
    fn read<'py>(&self, py: Python<'py>, n: u32) -> PyResult<Bound<'py, PyAny>> {
        match self.state {
            StreamState::Open | StreamState::HalfClosed => {
                let (tx, rx) = oneshot::channel();

                self.command_tx
                    .send(TransportCommand::ReadData(self.connection_id, n, tx))
                    .ok(); // if this fails tx is dropped and rx.await will error.

                pyo3_async_runtimes::tokio::future_into_py(py, async move {
                    Ok(rx.await.unwrap_or_default())
                })
            }
            StreamState::Closed => {
                pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(Vec::<u8>::new()) })
            }
        }
    }

    /// Write bytes onto the TCP stream, or send a single UDP packet.
    ///
    /// For TCP, this queues the data into a write buffer. To wait until the stream can be written
    /// to again, await `Stream.drain`.
    ///
    /// Raises:
    ///     OSError if the connection has previously been closed or if server has been shut down.
    fn write(&self, data: Vec<u8>) -> PyResult<()> {
        match self.state {
            StreamState::Open => self
                .command_tx
                .send(TransportCommand::WriteData(self.connection_id, data))
                .map_err(event_queue_unavailable),
            StreamState::HalfClosed => Err(PyOSError::new_err("connection closed")),
            StreamState::Closed => Err(PyOSError::new_err("connection closed")),
        }
    }

    /// Wait until the stream can be written to again.
    ///
    /// Raises:
    ///     OSError if the stream is closed or the server has been shut down.
    fn drain<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let (tx, rx) = oneshot::channel();

        self.command_tx
            .send(TransportCommand::DrainWriter(self.connection_id, tx))
            .map_err(event_queue_unavailable)?;

        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            rx.await
                .map_err(|_| PyOSError::new_err("connection closed"))
        })
    }

    /// Close the TCP stream after flushing the write buffer.
    /// This method is a no-op for UDP streams, but may still raise an error (see below).
    ///
    /// Raises:
    ///     OSError if the server has been shut down.
    fn write_eof(&mut self) -> PyResult<()> {
        match self.state {
            StreamState::Open => {
                self.state = StreamState::HalfClosed;
                self.command_tx
                    .send(TransportCommand::CloseConnection(self.connection_id, true))
                    .map_err(event_queue_unavailable)
            }
            StreamState::HalfClosed => Ok(()),
            StreamState::Closed => Ok(()),
        }
    }

    /// Close the stream for both reading and writing.
    ///
    /// Raises:
    ///     OSError if the server has been shut down.
    fn close(&mut self) -> PyResult<()> {
        match self.state {
            StreamState::Open | StreamState::HalfClosed => {
                self.state = StreamState::Closed;
                self.command_tx
                    .send(TransportCommand::CloseConnection(self.connection_id, false))
                    .map_err(event_queue_unavailable)
            }
            StreamState::Closed => Ok(()),
        }
    }

    /// Check whether this stream is being closed.
    fn is_closing(&self) -> bool {
        match self.state {
            StreamState::Open => false,
            StreamState::HalfClosed | StreamState::Closed => true,
        }
    }

    /// Wait until the stream is closed (currently a no-op).
    fn wait_closed<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, std::future::ready(Ok(())))
    }

    /// Query the stream for details of the underlying network connection.
    ///
    /// Supported values:
    ///   - Always available: `transport_protocol`, `peername`, `sockname`
    ///   - WireGuard mode: `original_dst`, `original_src`
    ///   - Local redirector mode: `pid`, `process_name`, `remote_endpoint`
    #[pyo3(signature = (name, default=None))]
    fn get_extra_info(
        &self,
        py: Python,
        name: String,
        default: Option<PyObject>,
    ) -> PyResult<PyObject> {
        match name.as_str() {
            "transport_protocol" => {
                let proto = if self.connection_id.is_tcp() {
                    intern!(py, "tcp")
                } else {
                    intern!(py, "udp")
                };
                return Ok(proto.clone().unbind().into_any());
            }
            "peername" => return socketaddr_to_py(py, self.peername),
            "sockname" => return socketaddr_to_py(py, self.sockname),
            _ => (),
        }
        match &self.tunnel_info {
            TunnelInfo::WireGuard { src_addr, dst_addr } => match name.as_str() {
                "original_src" => return socketaddr_to_py(py, *src_addr),
                "original_dst" => return socketaddr_to_py(py, *dst_addr),
                _ => (),
            },
            TunnelInfo::LocalRedirector {
                pid,
                process_name,
                remote_endpoint,
            } => match name.as_str() {
                "pid" => return pid.into_py_any(py),
                "process_name" => return process_name.clone().into_py_any(py),
                "remote_endpoint" => {
                    if let Some(endpoint) = remote_endpoint {
                        return endpoint.into_py_any(py);
                    }
                }
                _ => (),
            },
            TunnelInfo::None => (),
        }
        match default {
            Some(x) => Ok(x),
            None => Err(PyKeyError::new_err(name)),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "Stream({}, peer={}, sock={}, tunnel_info={:?})",
            self.connection_id, self.peername, self.sockname, self.tunnel_info,
        )
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.close().ok();
    }
}
