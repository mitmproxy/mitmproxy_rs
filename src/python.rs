use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;

use pyo3::exceptions::{PyKeyError, PyOSError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyString, PyTuple};

use tokio::sync::mpsc::{self, error::SendError};
use tokio::sync::oneshot::{self, error::RecvError};
use tokio::sync::Notify;

use crate::messages::{ConnectionId, TransportCommand, TransportEvent};

pub fn event_queue_unavailable(_: SendError<TransportCommand>) -> PyErr {
    PyOSError::new_err("WireGuard server has been shut down.")
}

pub fn connection_closed(_: RecvError) -> PyErr {
    PyOSError::new_err("connection closed")
}

/// An individual TCP stream with an API that is similar to
/// [`asyncio.StreamReader` and `asyncio.StreamWriter`](https://docs.python.org/3/library/asyncio-stream.html)
/// from the Python standard library.
#[pyclass]
#[derive(Debug)]
pub struct TcpStream {
    connection_id: ConnectionId,
    event_tx: mpsc::UnboundedSender<TransportCommand>,
    peername: SocketAddr,
    sockname: SocketAddr,
    original_dst: SocketAddr,
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
    fn write_eof(&self) -> PyResult<()> {
        self.event_tx
            .send(TransportCommand::CloseConnection(self.connection_id, true))
            .map_err(event_queue_unavailable)?;

        Ok(())
    }

    /// Close the TCP stream and the underlying socket immediately.
    fn close(&self) -> PyResult<()> {
        self.event_tx
            .send(TransportCommand::CloseConnection(self.connection_id, false))
            .map_err(event_queue_unavailable)?;

        Ok(())
    }

    /// Query the TCP stream for details of the underlying network connection.
    ///
    /// Supported values: `peername`, `sockname`, `original_dst`.
    #[args(default = "None")]
    fn get_extra_info(&self, py: Python, name: String, default: Option<PyObject>) -> PyResult<PyObject> {
        match (name.as_str(), default) {
            ("peername", _) => Ok(socketaddr_to_py(py, self.peername)),
            ("sockname", _) => Ok(socketaddr_to_py(py, self.sockname)),
            ("original_dst", _) => Ok(socketaddr_to_py(py, self.original_dst)),
            (_, Some(default)) => Ok(default),
            _ => Err(PyKeyError::new_err(name)),
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "TcpStream({}, peer={}, sock={}, dst={})",
            self.connection_id, self.peername, self.sockname, self.original_dst,
        )
    }
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            log::error!("Failed to close TCP stream during clean up: {}", error);
        }
    }
}

pub fn socketaddr_to_py(py: Python, s: SocketAddr) -> PyObject {
    match s {
        SocketAddr::V4(addr) => (addr.ip().to_string(), addr.port()).into_py(py),
        SocketAddr::V6(addr) => {
            log::debug!(
                "Converting IPv6 address/port to Python equivalent (not sure if this is correct): {:?}",
                (addr.ip().to_string(), addr.port())
            );
            (addr.ip().to_string(), addr.port()).into_py(py)
        },
    }
}

pub fn py_to_socketaddr(t: &PyTuple) -> PyResult<SocketAddr> {
    if t.len() == 2 {
        let host = t.get_item(0)?.downcast::<PyString>()?;
        let port: u16 = t.get_item(1)?.extract()?;

        let addr = IpAddr::from_str(host.to_str()?)?;
        Ok(SocketAddr::from((addr, port)))
    } else {
        Err(PyValueError::new_err("not a socket address"))
    }
}

pub struct PyInteropTask {
    local_addr: SocketAddr,
    py_loop: PyObject,
    run_coroutine_threadsafe: PyObject,
    py_to_smol_tx: mpsc::UnboundedSender<TransportCommand>,
    smol_to_py_rx: mpsc::Receiver<TransportEvent>,
    py_tcp_handler: PyObject,
    py_udp_handler: PyObject,
    sd_trigger: Arc<Notify>,
}

impl PyInteropTask {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_addr: SocketAddr,
        py_loop: PyObject,
        run_coroutine_threadsafe: PyObject,
        py_to_smol_tx: mpsc::UnboundedSender<TransportCommand>,
        smol_to_py_rx: mpsc::Receiver<TransportEvent>,
        py_tcp_handler: PyObject,
        py_udp_handler: PyObject,
        sd_trigger: Arc<Notify>,
    ) -> Self {
        PyInteropTask {
            local_addr,
            py_loop,
            run_coroutine_threadsafe,
            py_to_smol_tx,
            smol_to_py_rx,
            py_tcp_handler,
            py_udp_handler,
            sd_trigger,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let mut stop = false;
        while !stop {
            tokio::select!(
                // wait for graceful shutdown
                _ = self.sd_trigger.notified() => {
                    stop = true;
                },
                // wait for network events
                event = self.smol_to_py_rx.recv() => {
                    if let Some(event) = event {
                        match event {
                            TransportEvent::ConnectionEstablished {
                                connection_id,
                                src_addr,
                                dst_addr,
                            } => {
                                let stream = TcpStream {
                                    connection_id,
                                    event_tx: self.py_to_smol_tx.clone(),
                                    peername: src_addr,
                                    sockname: self.local_addr,
                                    original_dst: dst_addr,
                                };

                                Python::with_gil(|py| {
                                    let stream = stream.into_py(py);

                                    let coro = match self.py_tcp_handler.call1(py,(stream,)) {
                                        Ok(coro) => coro,
                                        Err(err) => {
                                            err.print(py);
                                            return;
                                        },
                                    };

                                    if let Err(err) = self.run_coroutine_threadsafe.call1(
                                        py,
                                        (coro, self.py_loop.as_ref(py))
                                    ) {
                                        err.print(py);
                                    }
                                });
                            },
                            TransportEvent::DatagramReceived {
                                data,
                                src_addr,
                                dst_addr,
                            } => {
                                Python::with_gil(|py| {
                                    let bytes: Py<PyBytes> = PyBytes::new(py, &data).into_py(py);

                                    if let Err(err) = self.py_loop.call_method1(
                                        py,
                                        "call_soon_threadsafe",
                                        (
                                            self.py_udp_handler.as_ref(py),
                                            bytes,
                                            socketaddr_to_py(py, src_addr),
                                            socketaddr_to_py(py, dst_addr),
                                        ),
                                    ) {
                                        err.print(py);
                                    }
                                });
                            },
                        }
                    } else {
                        // channel was closed
                        stop = true;
                    }
                },
            );
        }

        log::debug!("Python interoperability task shutting down.");
        Ok(())
    }
}
