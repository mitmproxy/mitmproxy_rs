use std::sync::Arc;

use anyhow::Result;
use tokio::{
    sync::{broadcast::Sender as BroadcastSender, Notify, RwLock},
    task::JoinHandle,
};

pub struct ShutdownTask {
    py_handle: JoinHandle<Result<()>>,
    wg_handle: JoinHandle<Result<()>>,
    nw_handle: JoinHandle<Result<()>>,
    sd_trigger: BroadcastSender<()>,
    sd_barrier: Arc<Notify>,
}

impl ShutdownTask {
    pub fn new(
        py_handle: JoinHandle<Result<()>>,
        wg_handle: JoinHandle<Result<()>>,
        nw_handle: JoinHandle<Result<()>>,
        sd_trigger: BroadcastSender<()>,
        sd_barrier: Arc<Notify>,
    ) -> Self {
        ShutdownTask {
            py_handle,
            wg_handle,
            nw_handle,
            sd_trigger,
            sd_barrier,
        }
    }

    pub async fn run(self) {
        let mut sd_watcher = self.sd_trigger.subscribe();
        let shutting_down = Arc::new(RwLock::new(false));

        // wait for Python interop task to return
        let py_sd_trigger = self.sd_trigger.clone();
        let py_shutting_down = shutting_down.clone();
        let py_task_handle = tokio::spawn(async move {
            if let Err(error) = self.py_handle.await {
                log::error!("Python interop task failed: {}", error);
            }

            if !*py_shutting_down.read().await {
                log::error!("Python interop task shut down early, exiting.");
                let _ = py_sd_trigger.send(());
            }
        });

        // wait for WireGuard server task to return
        let wg_sd_trigger = self.sd_trigger.clone();
        let wg_shutting_down = shutting_down.clone();
        let wg_task_handle = tokio::spawn(async move {
            if let Err(error) = self.wg_handle.await {
                log::error!("WireGuard server task failed: {}", error);
            }

            if !*wg_shutting_down.read().await {
                log::error!("WireGuard server task shut down early, exiting.");
                let _ = wg_sd_trigger.send(());
            }
        });

        // wait for networking task to return
        let nw_sd_trigger = self.sd_trigger.clone();
        let nw_shutting_down = shutting_down.clone();
        let nw_task_handle = tokio::spawn(async move {
            if let Err(error) = self.nw_handle.await {
                log::error!("Networking task failed: {}", error);
            }

            if !*nw_shutting_down.read().await {
                log::error!("Networking task shut down early, exiting.");
                let _ = nw_sd_trigger.send(());
            }
        });

        // wait for shutdown trigger:
        // - either `Server.stop` was called, or
        // - one of the subtasks failed early
        let _ = sd_watcher.recv().await;
        *shutting_down.write().await = true;

        // wait for all tasks to terminate and log any errors
        if let Err(error) = py_task_handle.await {
            log::error!("Shutdown of Python interop task failed: {}", error);
        }
        if let Err(error) = wg_task_handle.await {
            log::error!("Shutdown of WireGuard server task failed: {}", error);
        }
        if let Err(error) = nw_task_handle.await {
            log::error!("Shutdown of network task failed: {}", error);
        }

        // make `Server.wait_closed` method yield
        self.sd_barrier.notify_one();
    }
}
