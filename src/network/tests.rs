use std::sync::Arc;

use anyhow::Result;
use tokio::sync::{
    mpsc::{channel, unbounded_channel},
    Notify,
};

use super::task::NetworkTask;

#[tokio::test]
#[allow(unused)]
async fn do_nothing() -> Result<()> {
    // begin setup
    let (wg_to_smol_tx, wg_to_smol_rx) = channel(16);
    let (smol_to_wg_tx, smol_to_wg_rx) = channel(16);
    let (smol_to_py_tx, smol_to_py_rx) = channel(64);
    let (py_to_smol_tx, py_to_smol_rx) = unbounded_channel();
    let sd_trigger = Arc::new(Notify::new());

    let task = NetworkTask::new(
        smol_to_wg_tx,
        wg_to_smol_rx,
        smol_to_py_tx,
        py_to_smol_rx,
        sd_trigger.clone(),
    )?;
    // end setup

    // spawn task
    let handle = tokio::spawn(task.run());

    // begin checks
    //wg_to_smol_tx.send(x);
    //let y = wg_to_smol_rx.recv().await;

    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    // end checks

    // shut task down
    sd_trigger.notify_waiters();

    // check for errors
    handle.await.unwrap().unwrap();

    Ok(())
}
