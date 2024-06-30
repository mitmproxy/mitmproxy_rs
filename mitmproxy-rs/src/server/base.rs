use crate::task::PyInteropTask;

use anyhow::Result;

use mitmproxy::packet_sources::{PacketSourceConf, PacketSourceTask};
use mitmproxy::shutdown::shutdown_task;
use pyo3::prelude::*;

use tokio::task::JoinSet;
use tokio::{sync::broadcast, sync::mpsc};

#[derive(Debug)]
pub struct Server {
    shutdown_done: broadcast::Receiver<()>,
    start_shutdown: Option<broadcast::Sender<()>>,
}

impl Server {
    pub fn close(&mut self) {
        if let Some(trigger) = self.start_shutdown.take() {
            log::debug!("Shutting down.");
            trigger.send(()).ok();
        }
    }

    pub fn wait_closed<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let mut receiver = self.shutdown_done.resubscribe();
        pyo3_asyncio_0_21::tokio::future_into_py(py, async move {
            receiver.recv().await.ok();
            Ok(())
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

        // Channel used to notify Python land of incoming connections.
        let (transport_events_tx, transport_events_rx) = mpsc::channel(256);
        // Channel used to send data and ask for packets.
        // This needs to be unbounded because write() is not async.
        let (transport_commands_tx, transport_commands_rx) = mpsc::unbounded_channel();
        // Channel used to trigger graceful shutdown
        let (shutdown_start_tx, shutdown_start_rx) = broadcast::channel(1);

        let (packet_source_task, data) = packet_source_conf
            .build(
                transport_events_tx,
                transport_commands_rx,
                shutdown_start_rx.resubscribe(),
            )
            .await?;

        // initialize Python interop task
        let py_task = PyInteropTask::new(
            transport_commands_tx,
            transport_events_rx,
            py_tcp_handler,
            py_udp_handler,
            shutdown_start_rx,
        )?;

        // spawn tasks
        let mut tasks = JoinSet::new();
        tasks.spawn(async move { packet_source_task.run().await });
        tasks.spawn(async move { py_task.run().await });

        let (shutdown_done_tx, shutdown_done_rx) = broadcast::channel(1);
        tokio::spawn(shutdown_task(tasks, shutdown_done_tx));

        log::debug!("{} successfully initialized.", typ);

        Ok((
            Server {
                shutdown_done: shutdown_done_rx,
                start_shutdown: Some(shutdown_start_tx),
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
