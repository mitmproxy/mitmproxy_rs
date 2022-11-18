use std::iter;

use tokio::io::{AsyncWriteExt};
use tokio::net::windows::named_pipe::ClientOptions;
use windows::core::PCWSTR;
use windows::w;
use windows::Win32::UI::WindowsAndMessaging::{MB_OK, MessageBoxW};

use mitmproxy_rs::MAX_PACKET_SIZE;

fn fail(error: &str) -> ! {
    unsafe {
        let err = error
            .encode_utf16()
            .chain(iter::once(0))
            .collect::<Vec<u16>>();
        MessageBoxW(
            None,
            PCWSTR::from_raw(err.as_ptr()),
            w!("mitmproxy-windows-redirector.exe"),
            MB_OK,
        );
    }
    std::process::exit(1);
}

#[cfg(windows)]
#[tokio::main]
async fn main() {
    let Ok(mut client) = ClientOptions::new().open(
        r"\\.\pipe\mitmproxy-transparent-proxy",
    ) else {
        fail("Failed to open pipe.");
    };

    let buf = [0u8; MAX_PACKET_SIZE + 1];

    client.write_all(&buf[..42]).await.unwrap();
}
