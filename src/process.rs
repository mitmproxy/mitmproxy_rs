use anyhow::{anyhow, Result};
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, MAX_PATH};
use windows::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_NATIVE, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

use crate::packet_sources::windows::PID;

pub fn process_name(pid: PID) -> Result<String> {
    let mut buffer = [0u16; MAX_PATH as usize];
    let path = PWSTR(buffer.as_mut_ptr());
    let mut len = buffer.len() as u32;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        // K32GetProcessImageFileNameW(handle, &mut buffer);
        let query_ok = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, path, &mut len)
            .ok()
            .or_else(|_|
            // WSL wants PROCESS_NAME_NATIVE, see https://github.com/microsoft/WSL/issues/3478
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_NATIVE,
                path,
                &mut len,
            ).ok());
        CloseHandle(handle).ok()?;
        // checking for success only after closing the handle.
        query_ok?;
        path.to_string().map_err(|e| anyhow!(e))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let name = super::process_name(std::process::id()).unwrap();
        assert!(name.contains("mitmproxy"));
    }
}
