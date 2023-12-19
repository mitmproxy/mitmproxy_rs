use anyhow::Result;

use tokio::sync::broadcast;
use tokio::task::JoinSet;

pub async fn shutdown_task(mut tasks: JoinSet<Result<()>>, shutdown_done: broadcast::Sender<()>) {
    while let Some(task) = tasks.join_next().await {
        match task {
            Ok(Ok(())) => (),
            Ok(Err(error)) => {
                log::error!("Task failed: {}\n{}", error, error.backtrace().to_string());
                tasks.shutdown().await;
            }
            Err(error) => {
                if error.is_cancelled() {
                    log::error!("Task cancelled: {}", error);
                } else {
                    log::error!("Task panicked: {}", error);
                }
                tasks.shutdown().await;
            }
        }
    }
    shutdown_done.send(()).ok();
}
