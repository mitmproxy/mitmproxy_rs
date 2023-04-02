
use std::collections::{HashMap, HashSet};
use std::collections::hash_map::{Entry};
use std::mem::{size_of};


use anyhow::{anyhow, Result};
use image::{RgbaImage};
use windows::core::PWSTR;
use windows::Win32::Foundation::{BOOL, CloseHandle, HANDLE, HMODULE, HWND, LPARAM, MAX_PATH};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};

use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::ProcessStatus::EnumProcesses;
use windows::Win32::System::Threading::{IsProcessCritical, OpenProcess, PROCESS_NAME_NATIVE, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};

use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsIconic, IsWindowVisible};

use crate::intercept_conf::PID;
use crate::windows::icons::{icon_for_executable};

pub fn get_process_name(pid: PID) -> Result<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        let path = process_name(handle);
        CloseHandle(handle).ok()?;
        path
    }
}


unsafe fn process_name(handle: HANDLE) -> Result<String> {
    let mut buffer = Vec::with_capacity(MAX_PATH as usize);
    let path = PWSTR(buffer.as_mut_ptr());
    let mut len = buffer.capacity() as u32;

    QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, path, &mut len)
        .ok()
        .or_else(|_|
            // WSL wants PROCESS_NAME_NATIVE, see https://github.com/microsoft/WSL/issues/3478
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_NATIVE,
                path,
                &mut len,
            ).ok())?;
    path.to_string().map_err(|e| anyhow!(e))
}


unsafe fn is_critical(handle: HANDLE) -> Result<bool> {
    let mut is_critical = BOOL::default();
    IsProcessCritical(handle, &mut is_critical).ok()?;  // we're ok if this fails.
    Ok(is_critical.as_bool())
}


#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub executable: String,
    pub icon: u64,
    pub is_visible: bool,
    pub is_windows: bool,
}

#[derive(Debug)]
pub struct ProcessList {
    pub processes: Vec<ProcessInfo>,
    pub icons: HashMap<u64, RgbaImage>,
}

fn enumerate_pids() -> Result<Vec<PID>> {
    let mut pids: Vec<PID> = Vec::with_capacity(1024);
    loop {
        let bytes_available = (size_of::<PID>() * pids.capacity()) as u32;
        let mut bytes_needed = 0;
        unsafe {
            EnumProcesses(
                pids.as_mut_ptr(),
                bytes_available,
                &mut bytes_needed,
            ).ok()?;
        }
        if bytes_needed < bytes_available {
            unsafe { pids.set_len((bytes_needed / 4) as usize) }
            break;
        }
        pids.reserve(2 * pids.capacity());
    }
    Ok(pids)
}

/// Get the icon for a process.
/// Updates icons to include the icon, and returns the icon's hash.
fn get_icon(executable: &str, icons: &mut HashMap<u64, RgbaImage>, hinst: HMODULE) -> Result<u64> {
    let icon = unsafe { icon_for_executable(executable, hinst)? };
    let icon_hash = icon.hash();
    icons.entry(icon_hash).or_insert_with(|| icon.to_image());
    Ok(icon_hash)
}

pub fn active_executables() -> Result<ProcessList> {
    let hinst = unsafe { GetModuleHandleW(None)? };

    let mut executables: HashMap<String, ProcessInfo> = HashMap::new();

    let mut icons: HashMap<u64, RgbaImage> = HashMap::new();
    let visible = visible_windows()?;

    for pid in enumerate_pids()? {
        let (executable, is_critical) = unsafe {
            let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
                continue;
            };
            let path = process_name(handle);
            let is_critical = is_critical(handle);
            CloseHandle(handle).ok()?;
            (path?, is_critical?)
        };

        match executables.entry(executable) {
            Entry::Occupied(mut e) => {
                e.get_mut().is_visible |= visible.contains(&pid);
            }
            Entry::Vacant(e) => {
                let executable = e.key().clone();
                let icon = get_icon(&executable, &mut icons, hinst).unwrap_or(0);
                let is_visible = visible.contains(&pid);
                e.insert(ProcessInfo {
                    executable,
                    icon,
                    is_visible,
                    is_windows: is_critical,
                });
            }
        }
    }

    Ok(ProcessList {
        processes: executables.into_values().collect(),
        icons,
    })
}

pub fn visible_windows() -> Result<HashSet<PID>> {
    let mut pids: HashSet<PID> = HashSet::new();

    enum_windows(|window| {
        unsafe {
            let mut pid: u32 = 0;
            if GetWindowThreadProcessId(window, Some(&mut pid)) == 0 {
                return true;  // If the window handle is invalid, the return value is zero.
            }
            let is_visible = IsWindowVisible(window).as_bool();
            let is_iconic = IsIconic(window).as_bool();
            let is_cloaked = {
                let mut cloaked = BOOL::default();
                if let Err(e) = DwmGetWindowAttribute(window, DWMWA_CLOAKED, &mut cloaked as *mut BOOL as *mut _, size_of::<BOOL>() as u32) {
                    log::debug!("DwmGetWindowAttribute failed: {:#}", e);
                    false
                } else {
                    cloaked.as_bool()
                }
            };

            if is_visible && !is_iconic && !is_cloaked {
                pids.insert(pid);
                /*
                let procname = get_process_name(pid).unwrap_or("unknown".to_string());
                dbg!("================", procname, pid, is_visible, is_iconic, is_cloaked);
                 */
            }
            true
        }
    })?;
    Ok(pids)
}

pub fn enum_windows<F>(func: F) -> Result<()>
    where F: FnMut(HWND) -> bool,
{
    unsafe {
        EnumWindows(
            Some(enum_windows_proc::<F> as _),
            LPARAM(&func as *const _ as _),
        ).ok()?
    }
    Ok(())
}

extern "system" fn enum_windows_proc<F>(hwnd: HWND, lparam: LPARAM) -> BOOL
    where F: FnMut(HWND) -> bool,
{
    let func = unsafe { &mut *(lparam.0 as *mut F) };
    func(hwnd).into()
}

#[cfg(test)]
mod tests {
    

    #[test]
    fn visible_windows() {
        let pids = super::visible_windows().unwrap();
        // no asserts here because tests should work on headless systems.
        for pid in pids {
            let procname = super::get_process_name(pid).unwrap_or_else(|e| format!("<{:?}>", e));
            println!("{pid: >6} {procname}");
        }
    }

    #[test]
    fn get_process_name() {
        let name = super::get_process_name(std::process::id()).unwrap();
        assert!(name.contains("mitmproxy"));
    }

    #[test]
    fn process_list() {
        let lst = super::active_executables().unwrap();
        assert!(!lst.processes.is_empty());
        assert!(!lst.icons.is_empty());

        for proc in &lst.processes {
            println!("{:?}", proc);
        }
        dbg!(lst.processes.len());
        dbg!(lst.icons.len());
    }
}
