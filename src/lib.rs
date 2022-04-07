use pyo3::prelude::*;


#[pyclass]
struct WireguardServer {
    inner: i32,
}

#[pymethods]
impl WireguardServer {
    fn tcp_send(&self) -> PyResult<i32> {
        todo!();
        Ok(42)
    }

    fn tcp_close(&self) -> PyResult<i32> {
        todo!();
        Ok(42)
    }

    fn stop(&self) -> PyResult<i32> {
        todo!();
        Ok(42)
    }
}

#[pyfunction]
fn start_server(py: Python<'_>, host: String, port: u16) -> PyResult<&PyAny> {
    pyo3_asyncio::tokio::future_into_py(py, async {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        Ok(WireguardServer { inner: 42 })
    })
}

#[pymodule]
fn mitmproxy_wireguard(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(start_server, m)?)?;
    Ok(())
}
