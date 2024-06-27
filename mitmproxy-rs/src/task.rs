use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use pyo3::prelude::*;
use pyo3_asyncio_0_21::TaskLocals;
use tokio::sync::{broadcast, mpsc, Mutex};

use mitmproxy::messages::{TransportCommand, TransportEvent};

use crate::stream::Stream;
use crate::stream::StreamState;

pub struct PyInteropTask {
    locals: TaskLocals,
    transport_commands: mpsc::UnboundedSender<TransportCommand>,
    transport_events: mpsc::Receiver<TransportEvent>,
    py_tcp_handler: PyObject,
    py_udp_handler: PyObject,
    shutdown: broadcast::Receiver<()>,
}

impl PyInteropTask {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transport_commands: mpsc::UnboundedSender<TransportCommand>,
        transport_events: mpsc::Receiver<TransportEvent>,
        py_tcp_handler: PyObject,
        py_udp_handler: PyObject,
        shutdown: broadcast::Receiver<()>,
    ) -> Result<Self> {
        // Note: The current asyncio event loop needs to be determined here on the main thread.
        let locals = Python::with_gil(|py| -> Result<TaskLocals, PyErr> {
            let py_loop = pyo3_asyncio_0_21::tokio::get_current_loop(py)?;
            TaskLocals::new(py_loop).copy_context(py)
        })
        .context("failed to get python task locals")?;

        Ok(PyInteropTask {
            locals,
            transport_commands,
            transport_events,
            py_tcp_handler,
            py_udp_handler,
            shutdown,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        let active_streams = Arc::new(Mutex::new(HashMap::new()));

        loop {
            tokio::select! {
                // wait for graceful shutdown
                _ = self.shutdown.recv() => break,
                // wait for network events
                event = self.transport_events.recv() => {
                    let Some(event) = event else {
                        // channel was closed
                        break;
                    };
                    match event {
                        TransportEvent::ConnectionEstablished {
                            connection_id,
                            src_addr,
                            dst_addr,
                            tunnel_info,
                            command_tx,
                        } => {
                            let command_tx = command_tx.unwrap_or_else(|| self.transport_commands.clone());
                            // initialize new stream
                            let stream = Stream {
                                connection_id,
                                state: StreamState::Open,
                                command_tx,
                                peername: src_addr,
                                sockname: dst_addr,
                                tunnel_info,
                            };

                            let mut conns = active_streams.lock().await;

                            // spawn connection handler coroutine
                            if let Err(err) = Python::with_gil(|py| -> Result<(), PyErr> {
                                let stream = stream.into_py(py);

                                // calling Python coroutine object yields an awaitable object
                                let coro = if connection_id.is_tcp() {
                                    self.py_tcp_handler.call1(py, (stream, ))?
                                } else {
                                    self.py_udp_handler.call1(py, (stream, ))?
                                };

                                // convert Python awaitable into Rust Future
                                let future = pyo3_asyncio_0_21::into_future_with_locals(&self.locals, coro.into_bound(py))?;

                                // run Future on a new Tokio task
                                let handle = {
                                    let active_streams = active_streams.clone();
                                    tokio::spawn(async move {
                                        if let Err(err) = future.await {
                                            log::error!("TCP connection handler coroutine raised an exception:\n{}", err)
                                        }
                                        active_streams.lock().await.remove(&connection_id);
                                    })
                                };

                                conns.insert(connection_id, handle);

                                Ok(())
                            }) {
                                log::error!("Failed to spawn connection handler:\n{}", err);
                            };
                        },
                    }
                }
            };
        }

        log::debug!("Python interoperability task shutting down.");

        while let Some((_, handle)) = active_streams.lock().await.drain().next() {
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
