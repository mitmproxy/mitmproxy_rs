use crate::task::PyInteropTask;

use anyhow::Result;

use mitmproxy::packet_sources::{PacketSourceConf, PacketSourceTask};
use mitmproxy::shutdown::ShutdownTask;
use pyo3::prelude::*;
#[cfg(target_os = "macos")]
use std::path::Path;

use tokio::{sync::broadcast, sync::mpsc};

#[derive(Debug)]
pub struct Server {
    /// channel for notifying subtasks of requested server shutdown
    sd_trigger: broadcast::Sender<()>,
    /// channel for getting notified of successful server shutdown
    sd_barrier: broadcast::Sender<()>,
    /// flag to indicate whether server shutdown is in progress
    closing: bool,
}

impl Server {
    pub fn close(&mut self) {
        if !self.closing {
            self.closing = true;
            // XXX: Does not really belong here.
            #[cfg(target_os = "macos")]
            {
                if Path::new("/Applications/MitmproxyAppleTunnel.app").exists() {
                    std::fs::remove_dir_all("/Applications/MitmproxyAppleTunnel.app").expect(
                        "Failed to remove MitmproxyAppleTunnel.app from Applications folder",
                    );
                }
            }
            log::info!("Shutting down.");
            // notify tasks to shut down
            let _ = self.sd_trigger.send(());
        }
    }

    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<&'p PyAny> {
        let mut barrier = self.sd_barrier.subscribe();
        pyo3_asyncio::tokio::future_into_py(py, async move {
            barrier.recv().await.map_err(|_| {
                pyo3::exceptions::PyRuntimeError::new_err("Failed to wait for server shutdown.")
            })
        })
    }
}

impl Server {
    /// Set up and initialize a new WireGuard server.
    pub async fn init<T>(
        packet_source_conf: T,
        py_tcp_handler: PyObject,
        py_udp_handler: PyObject,
    ) -> Result<(Self, T::Data)>
    where
        T: PacketSourceConf,
    {
        let typ = packet_source_conf.name();
        log::debug!("Initializing {} ...", typ);

        // initialize channels between the virtual network device and the python interop task
        // - only used to notify of incoming connections and datagrams
        let (transport_events_tx, transport_events_rx) = mpsc::channel(256);
        // - used to send data and to ask for packets
        // This channel needs to be unbounded because write() is not async.
        let (transport_commands_tx, transport_commands_rx) = mpsc::unbounded_channel();

        // initialize barriers for handling graceful shutdown
        let shutdown = broadcast::channel(1).0;
        let shutdown_done = broadcast::channel(1).0;

        let (packet_source_task, data) = packet_source_conf
            .build(
                transport_events_tx,
                transport_commands_rx,
                shutdown.subscribe(),
            )
            .await?;

        // initialize Python interop task
        // Note: The current asyncio event loop needs to be determined here on the main thread.
        let py_loop: PyObject = Python::with_gil(|py| {
            let py_loop = pyo3_asyncio::tokio::get_current_loop(py)?.into_py(py);
            Ok::<PyObject, PyErr>(py_loop)
        })?;

        let py_task = PyInteropTask::new(
            py_loop,
            transport_commands_tx,
            transport_events_rx,
            py_tcp_handler,
            py_udp_handler,
            shutdown.subscribe(),
        );

        // spawn tasks
        let wg_handle = tokio::spawn(async move { packet_source_task.run().await });
        let py_handle = tokio::spawn(async move { py_task.run().await });

        // initialize and run shutdown handler
        let sd_task = ShutdownTask::new(
            py_handle,
            wg_handle,
            shutdown.clone(),
            shutdown_done.clone(),
        );
        tokio::spawn(async move { sd_task.run().await });

        log::debug!("{} successfully initialized.", typ);

        Ok((
            Server {
                sd_trigger: shutdown,
                sd_barrier: shutdown_done,
                closing: false,
            },
            data,
        ))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.close()
    }
}
