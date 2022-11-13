use std::net::SocketAddr;

use anyhow::Result;
use pyo3::{prelude::*, types::PyBytes};
use tokio::sync::{broadcast::Receiver as BroadcastReceiver, mpsc};

use super::{socketaddr_to_py, TcpStream};
use crate::messages::{TransportCommand, TransportEvent};

pub struct PyInteropTask {
    local_addr: SocketAddr,
    py_loop: PyObject,
    py_to_smol_tx: mpsc::UnboundedSender<TransportCommand>,
    smol_to_py_rx: mpsc::Receiver<TransportEvent>,
    py_tcp_handler: PyObject,
    py_udp_handler: PyObject,
    sd_watcher: BroadcastReceiver<()>,
}

impl PyInteropTask {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        local_addr: SocketAddr,
        py_loop: PyObject,
        py_to_smol_tx: mpsc::UnboundedSender<TransportCommand>,
        smol_to_py_rx: mpsc::Receiver<TransportEvent>,
        py_tcp_handler: PyObject,
        py_udp_handler: PyObject,
        sd_watcher: BroadcastReceiver<()>,
    ) -> Self {
        PyInteropTask {
            local_addr,
            py_loop,
            py_to_smol_tx,
            smol_to_py_rx,
            py_tcp_handler,
            py_udp_handler,
            sd_watcher,
        }
    }

    pub async fn run(mut self) -> Result<()> {
        let mut tcp_connection_handler_tasks = Vec::new();

        loop {
            tokio::select!(
                // wait for graceful shutdown
                _ = self.sd_watcher.recv() => break,
                // wait for network events
                event = self.smol_to_py_rx.recv() => {
                    if let Some(event) = event {
                        match event {
                            TransportEvent::ConnectionEstablished {
                                connection_id,
                                src_addr,
                                dst_addr,
                                src_orig,
                            } => {
                                let stream = TcpStream {
                                    connection_id,
                                    event_tx: self.py_to_smol_tx.clone(),
                                    peername: src_addr,
                                    sockname: self.local_addr,
                                    original_dst: dst_addr,
                                    original_src: src_orig,
                                    is_closing: false,
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

                                    let locals = pyo3_asyncio::TaskLocals::new(self.py_loop.as_ref(py))
                                        .copy_context(self.py_loop.as_ref(py).py()).unwrap();
                                    let future = pyo3_asyncio::into_future_with_locals(&locals, coro.as_ref(py)).unwrap();

                                    let handle = tokio::spawn(async {
                                        if let Err(err) = future.await {
                                            log::error!("TCP connection handler coroutine raised an exception:\n{}", err)}
                                        }
                                    );

                                    tcp_connection_handler_tasks.push(handle);
                                });
                            },
                            TransportEvent::DatagramReceived {
                                data,
                                src_addr,
                                dst_addr,
                                ..
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
                        break;
                    }
                },
            );
        }

        log::debug!("Python interoperability task shutting down.");

        // clean up TCP connection handler coroutines
        for handle in tcp_connection_handler_tasks {
            if handle.is_finished() {
                // Future is already finished: just await;
                // Python exceptions are already logged by the wrapper coroutine
                if let Err(err) = handle.await {
                    log::warn!(
                        "TCP connection handler coroutine could not be joined: {}",
                        err
                    );
                }
            } else {
                // Future is not finished: abort tokio task
                handle.abort();

                if let Err(err) = handle.await {
                    if !err.is_cancelled() {
                        // JoinError was not caused by cancellation: coroutine panicked, log error
                        log::error!("TCP connection handler coroutine panicked: {}", err);
                    }
                }
            }
        }

        Ok(())
    }
}
