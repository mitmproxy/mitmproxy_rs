mod logger;

mod tests {
    
    use std::future::Future;

    use mitmproxy::messages::{ConnectionId, TransportEvent, TunnelInfo};
    use mitmproxy_rs::task::PyInteropTask;
    use pyo3::prelude::*;
    use pyo3::types::PyDict;

    use crate::logger::setup_logger;
    use tokio::sync::broadcast;
    use tokio::sync::mpsc;

    #[pyo3_asyncio_0_21::tokio::test]
    async fn test_handler_invalid_signature() -> PyResult<()> {
        let logger = setup_logger().await;
        _test_task_error_handling(
            "async def handler(): pass",
            logger.wait_for("Failed to spawn connection handler"),
        )
        .await?;
        logger.wait_for("shutting down").await;
        Ok(())
    }

    #[pyo3_asyncio_0_21::tokio::test]
    async fn test_handler_runtime_error() -> PyResult<()> {
        let logger = setup_logger().await;
        _test_task_error_handling(
            "async def handler(stream): raise RuntimeError('task failed successfully')",
            logger.wait_for("RuntimeError: task failed successfully"),
        )
        .await?;
        logger.wait_for("shutting down").await;
        Ok(())
    }

    #[pyo3_asyncio_0_21::tokio::test]
    async fn test_handler_cancelled() -> PyResult<()> {
        let logger = setup_logger().await;
        _test_task_error_handling(
            "async def handler(stream): import asyncio; asyncio.current_task().cancel()",
            async {},
        )
        .await?;
        logger.wait_for("shutting down").await;
        assert!(!logger
            .logs()
            .await
            .into_iter()
            .any(|l| l.contains("exception")));
        Ok(())
    }

    async fn _test_task_error_handling<F>(code: &str, verify: F) -> PyResult<()>
    where
        F: Future<Output = ()>,
    {
        let (command_tx, _command_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

        let conn_handler = Python::with_gil(|py| {
            let locals = PyDict::new_bound(py);
            py.run_bound(code, None, Some(&locals)).unwrap();
            locals.get_item("handler").unwrap().unwrap().to_object(py)
        });

        let task = PyInteropTask::new(
            command_tx,
            event_rx,
            conn_handler.clone(),
            conn_handler,
            shutdown_rx,
        )?;
        let task = tokio::spawn(task.run());

        event_tx
            .send(TransportEvent::ConnectionEstablished {
                connection_id: ConnectionId::unassigned_udp(),
                src_addr: "127.0.0.1:51232".parse()?,
                dst_addr: "127.0.0.1:53".parse()?,
                tunnel_info: TunnelInfo::Udp,
                command_tx: None,
            })
            .await
            .unwrap();
        // ensure previous event is processed.
        let _ = event_tx.reserve().await.unwrap();

        verify.await;

        shutdown_tx.send(()).unwrap();
        task.await.unwrap()?;
        Ok(())
    }
}

#[pyo3_asyncio_0_21::tokio::main]
async fn main() -> pyo3::PyResult<()> {
    pyo3_asyncio_0_21::testing::main().await
}
