use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3_asyncio::TaskLocals;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[pyclass]
#[derive(Debug)]
struct DataReceived {
    #[pyo3(get)]
    connection_id: u32,
    #[pyo3(get)]
    data: Vec<u8>,
}

#[pymethods]
impl DataReceived {
    fn __repr__(&self) -> String {
        format!("DataReceived({}, {:x?})", self.connection_id, self.data)
    }
}

#[derive(Debug)]
enum Events {
    // ConnectionEstablished(ConnectionEstablished),
    DataReceived(DataReceived),
    // ConnectionClosed(ConnectionClosed),
    // DatagramReceived(DatagramReceived),
}

impl IntoPy<PyObject> for Events {
    fn into_py(self, py: Python<'_>) -> PyObject {
        match self {
            Events::DataReceived(d) => d.into_py(py)
        }
    }
}


#[pyclass]
struct WireguardServer {
    python_callback_task: JoinHandle<()>,
}

#[pymethods]
impl WireguardServer {
    fn tcp_send(&self) -> PyResult<()> {
        todo!()
    }

    fn tcp_close(&self) -> PyResult<()> {
        todo!()
    }

    fn stop(&self) -> PyResult<()> {
        todo!()
    }
}

impl WireguardServer {
    pub fn new(on_event: PyObject) -> WireguardServer {
        let (tx, mut rx) = mpsc::channel::<Events>(64);

        // random sender for testing.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                tx.send(Events::DataReceived(DataReceived { connection_id: 42, data: vec![0, 1, 2] })).await;
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
}

impl Drop for WireguardServer {
    fn drop(&mut self) {
        self.python_callback_task.abort();
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
    m.add_class::<DataReceived>()?;
    Ok(())
}
