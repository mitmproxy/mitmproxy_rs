use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use pyo3::prelude::*;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

type ConnectionId = u32;

#[derive(Clone, Debug)]
struct PySockAddr(SocketAddr);

impl Display for PySockAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl IntoPy<PyObject> for PySockAddr {
    fn into_py(self, py: Python<'_>) -> PyObject {
        match self.0 {
            SocketAddr::V4(addr) => (addr.ip().to_string(), addr.port()).into_py(py),
            SocketAddr::V6(addr) => {
                log::debug!("converting ipv6 to python, not sure if this is correct: {:?}",
                    (addr.ip().to_string(), addr.port())
                );
                (addr.ip().to_string(), addr.port()).into_py(py)
            }
        }
    }
}

#[pyclass]
#[derive(Debug)]
struct ConnectionEstablished {
    #[pyo3(get)]
    connection_id: ConnectionId,
    #[pyo3(get)]
    src_addr: PySockAddr,
    #[pyo3(get)]
    dst_addr: PySockAddr,
}

#[pymethods]
impl ConnectionEstablished {
    fn __repr__(&self) -> String {
        format!("ConnectionEstablished({}, {}, {})", self.connection_id, self.src_addr, self.dst_addr)
    }
}


#[pyclass]
#[derive(Debug)]
struct DataReceived {
    #[pyo3(get)]
    connection_id: ConnectionId,
    #[pyo3(get)]
    data: Vec<u8>,
}

#[pymethods]
impl DataReceived {
    fn __repr__(&self) -> String {
        format!("DataReceived({}, {:x?})", self.connection_id, self.data)
    }
}


#[pyclass]
#[derive(Debug)]
struct ConnectionClosed {
    #[pyo3(get)]
    connection_id: ConnectionId,
}

#[pymethods]
impl ConnectionClosed {
    fn __repr__(&self) -> String {
        format!("ConnectionClosed({})", self.connection_id)
    }
}

#[pyclass]
#[derive(Debug)]
struct DatagramReceived {
    #[pyo3(get)]
    src_addr: PySockAddr,
    #[pyo3(get)]
    dst_addr: PySockAddr,
    #[pyo3(get)]
    data: Vec<u8>,
}

#[pymethods]
impl DatagramReceived {
    fn __repr__(&self) -> String {
        format!("DatagramReceived({}, {}, {:x?})", self.src_addr, self.dst_addr, self.data)
    }
}


#[derive(Debug)]
enum Events {
    ConnectionEstablished(ConnectionEstablished),
    DataReceived(DataReceived),
    ConnectionClosed(ConnectionClosed),
    DatagramReceived(DatagramReceived),
}

impl IntoPy<PyObject> for Events {
    fn into_py(self, py: Python<'_>) -> PyObject {
        match self {
            Events::ConnectionEstablished(e) => e.into_py(py),
            Events::DataReceived(e) => e.into_py(py),
            Events::ConnectionClosed(e) => e.into_py(py),
            Events::DatagramReceived(e) => e.into_py(py),
        }
    }
}


#[pyclass]
struct WireguardServer {
    python_callback_task: JoinHandle<()>,
}

#[pymethods]
impl WireguardServer {
    fn tcp_send(&self, connection_id: ConnectionId, data: Vec<u8>) -> PyResult<()> {
        todo!()
    }

    fn tcp_close(&self, connection_id: ConnectionId) -> PyResult<()> {
        todo!()
    }

    fn stop(&self) -> PyResult<()> {
        self._stop();
        Ok(())
    }
}

impl WireguardServer {
    pub fn new(on_event: PyObject) -> WireguardServer {
        let (tx, mut rx) = mpsc::channel::<Events>(64);

        // random sender for testing.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                tx.send(Events::ConnectionEstablished(ConnectionEstablished {
                    connection_id: 42,
                    src_addr: PySockAddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 4242)),
                    dst_addr: PySockAddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80)),
                })).await.unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
                tx.send(Events::DataReceived(DataReceived { connection_id: 42, data: vec![0, 1, 2] })).await.unwrap();
                tokio::time::sleep(Duration::from_secs(1)).await;
                tx.send(Events::ConnectionClosed(ConnectionClosed { connection_id: 42 })).await.unwrap();
            }
        });

        // this task feeds events into the Python callback.
        let call_python_callback = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                Python::with_gil(|py| {
                    if let Err(err) = on_event.call1(py, (event, )) {
                        err.print(py);
                    }
                });
            }
        });

        WireguardServer {
            python_callback_task: call_python_callback
        }
    }
    fn _stop(&self) {
        self.python_callback_task.abort();
        // TODO: this is not completely trivial. we should probably close all connections somehow.
        //       does smoltcp do something for us here?
    }
}

impl Drop for WireguardServer {
    fn drop(&mut self) {
        self._stop();
    }
}

#[pyfunction]
fn start_server(
    py: Python<'_>,
    host: String,
    port: u16,
    on_event: PyObject,
) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async move {
        let server = WireguardServer::new(on_event);
        Ok(server)
    })
}

#[pymodule]
fn mitmproxy_wireguard(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(start_server, m)?)?;
    m.add_class::<ConnectionEstablished>()?;
    m.add_class::<DataReceived>()?;
    m.add_class::<ConnectionClosed>()?;
    m.add_class::<DatagramReceived>()?;
    Ok(())
}
