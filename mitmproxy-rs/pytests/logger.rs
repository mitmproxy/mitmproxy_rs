use log::{LevelFilter, Log, Metadata, Record};
use std::sync::LazyLock;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::{mpsc, Mutex, MutexGuard};

/// A logger for tests to ensure that log statements are made.
pub struct TestLogger {
    tx: UnboundedSender<String>,
    rx: Mutex<UnboundedReceiver<String>>,
    buf: Mutex<Vec<String>>,
}
impl Log for TestLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        self.tx.send(format!("{}", record.args())).unwrap()
    }

    fn flush(&self) {}
}
impl TestLogger {
    /// Wait for a log line to appear. If the log message already appeared,
    /// we return immediately.
    pub async fn wait_for(&self, needle: &str) {
        let mut buf = self.buf.lock().await;
        if buf.iter().any(|m| m.contains(needle)) {
            return;
        }

        let mut rx = self.rx.lock().await;
        while let Some(m) = rx.recv().await {
            let done = m.contains(needle);
            buf.push(m);
            if done {
                break;
            }
        }
    }

    /// Get a copy of all log lines so far.
    pub async fn logs(&self) -> Vec<String> {
        let mut buf = self.buf.lock().await;
        let mut rx = self.rx.lock().await;
        while let Ok(m) = rx.try_recv() {
            buf.push(m);
        }
        buf.clone()
    }

    /// Clear log buffer.
    pub async fn clear(&self) {
        while let Ok(x) = self.rx.lock().await.try_recv() {
            drop(x);
        }
        self.buf.lock().await.clear();
    }
}
static _LOGGER: LazyLock<Mutex<&'static TestLogger>> = LazyLock::new(|| {
    let (tx, rx) = mpsc::unbounded_channel();
    let logger = Box::leak(Box::new(TestLogger {
        tx,
        rx: Mutex::new(rx),
        buf: Mutex::new(vec![]),
    }));
    log::set_logger(logger).expect("cannot set logger");
    log::set_max_level(LevelFilter::Debug);
    Mutex::new(logger)
});

/// Initialize the logger.
/// pyo3_async_runtimes tests all run in parallel in the same runtime, so we use a mutex to ensure
/// that only one test that uses TestLogger runs at the same time.
pub async fn setup_logger() -> MutexGuard<'static, &'static TestLogger> {
    let logger = _LOGGER.lock().await;
    logger.clear().await;
    logger
}
