use anyhow::Result;
use std::fmt::{Debug, Formatter};

use tokio::sync::watch;
use tokio::task::JoinSet;

#[derive(Clone)]
pub struct Receiver(watch::Receiver<()>);

impl Receiver {
    pub async fn recv(&mut self) {
        self.0.changed().await.ok();
        self.0.mark_changed();
    }

    pub fn is_shutting_down(&self) -> bool {
        self.0.has_changed().unwrap_or(true)
    }
}

impl Debug for Receiver {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Shutdown")
            .field(&self.is_shutting_down())
            .finish()
    }
}

pub fn channel() -> (watch::Sender<()>, Receiver) {
    let (tx, rx) = watch::channel(());
    (tx, Receiver(rx))
}

pub async fn shutdown_task(mut tasks: JoinSet<Result<()>>, shutdown_done: watch::Sender<()>) {
    while let Some(task) = tasks.join_next().await {
        match task {
            Ok(Ok(())) => (),
            Ok(Err(error)) => {
                log::error!("Task failed: {:?}\n{}", error, error.backtrace());
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_channel() {
        let (tx, mut rx1) = channel();
        let rx2 = rx1.clone();
        assert!(!rx1.is_shutting_down());
        assert!(!rx2.is_shutting_down());
        tx.send(()).unwrap();
        rx1.recv().await;
        assert!(rx1.is_shutting_down());
        assert!(rx2.is_shutting_down());
        assert!(rx1.is_shutting_down());
        assert!(rx2.is_shutting_down());
        rx1.recv().await;
        assert!(rx1.is_shutting_down());
    }
}
