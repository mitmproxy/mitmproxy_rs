use std::sync::Arc;

use anyhow::Result;

use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub struct ShutdownTask {
    py_handle: JoinHandle<Result<()>>,
    wg_handle: JoinHandle<Result<()>>,
    nw_handle: JoinHandle<Result<()>>,
    sd_trigger: Arc<Notify>,
    sd_handler: Arc<Notify>,
}

impl ShutdownTask {
    pub fn new(
        py_handle: JoinHandle<Result<()>>,
        wg_handle: JoinHandle<Result<()>>,
        nw_handle: JoinHandle<Result<()>>,
        sd_trigger: Arc<Notify>,
        sd_handler: Arc<Notify>,
    ) -> Self {
        ShutdownTask {
            py_handle,
            wg_handle,
            nw_handle,
            sd_trigger,
            sd_handler,
        }
    }

    pub async fn run(self) {
        self.sd_trigger.notified().await;

        // wait for all tasks to terminate and log any errors
        if let Err(error) = self.py_handle.await {
            log::error!("Python interop task failed: {}", error);
        }
        if let Err(error) = self.wg_handle.await {
            log::error!("WireGuard server task failed: {}", error);
        }
        if let Err(error) = self.nw_handle.await {
            log::error!("Virtual network stack task failed: {}", error);
        }

        self.sd_handler.notify_one();
    }
}
