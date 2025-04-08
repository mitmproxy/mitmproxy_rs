use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::iter;
use std::mem::size_of;
use std::os::windows::prelude::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

use anyhow::{anyhow, Result};
use windows::core::w;
use windows::core::{BOOL, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, LPARAM, MAX_PATH};
use windows::Win32::Graphics::Dwm::{DwmGetWindowAttribute, DWMWA_CLOAKED};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows::Win32::System::ProcessStatus::EnumProcesses;
use windows::Win32::System::Threading::{
    IsProcessCritical, OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_NATIVE,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    EnumWindows, GetWindowThreadProcessId, IsIconic, IsWindowVisible,
};

use crate::intercept_conf::PID;
use crate::processes::{ProcessInfo, ProcessList};

pub fn get_process_name(pid: PID) -> Result<PathBuf> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        let path = process_name(handle);
        CloseHandle(handle)?;
        path
    }
}

unsafe fn process_name(handle: HANDLE) -> Result<PathBuf> {
    let mut buffer = Vec::with_capacity(MAX_PATH as usize);
    let path = PWSTR(buffer.as_mut_ptr());
    let mut len = buffer.capacity() as u32;

    QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, path, &mut len).or_else(|_|
            // WSL wants PROCESS_NAME_NATIVE, see https://github.com/microsoft/WSL/issues/3478
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_NATIVE,
                path,
                &mut len,
            ))?;
    Ok(PathBuf::from(OsString::from_wide(path.as_wide())))
}

pub fn get_is_critical(pid: PID) -> Result<bool> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)?;
        let critical = is_critical(handle);
        CloseHandle(handle)?;
        critical
    }
}

unsafe fn is_critical(handle: HANDLE) -> Result<bool> {
    let mut is_critical = BOOL::default();
    IsProcessCritical(handle, &mut is_critical)?; // we're ok if this fails.
    Ok(is_critical.as_bool())
}

pub fn enumerate_pids() -> Result<Vec<PID>> {
    let mut pids: Vec<PID> = Vec::with_capacity(1024);
    loop {
        let bytes_available = (size_of::<PID>() * pids.capacity()) as u32;
        let mut bytes_needed = 0;
        unsafe {
            EnumProcesses(pids.as_mut_ptr(), bytes_available, &mut bytes_needed)?;
        }
        if bytes_needed < bytes_available {
            unsafe { pids.set_len((bytes_needed / 4) as usize) }
            break;
        }
        pids.reserve(2 * pids.capacity());
    }
    Ok(pids)
}

pub static DISPLAY_NAME_CACHE: LazyLock<Mutex<DisplayNameCache>> =
    LazyLock::new(|| Mutex::new(DisplayNameCache::default()));

#[derive(Default)]
pub struct DisplayNameCache(HashMap<PathBuf, Result<String>>);

impl DisplayNameCache {
    pub fn get(&mut self, executable: PathBuf) -> &Result<String> {
        self.0
            .entry(executable)
            .or_insert_with_key(|path| get_display_name(path))
    }
}

pub fn get_display_name(executable: &Path) -> Result<String> {
    unsafe {
        let executable_path = executable
            .as_os_str()
            .encode_wide()
            .chain(iter::once(0))
            .collect::<Vec<u16>>();

        let version_info_size = {
            let size = GetFileVersionInfoSizeW(PCWSTR::from_raw(executable_path.as_ptr()), None);
            if size == 0 {
                return Err(windows::core::Error::from_win32().into());
            }
            size
        };
        let mut version_info_buf = vec![0u8; version_info_size as usize];
        GetFileVersionInfoW(
            PCWSTR::from_raw(executable_path.as_ptr()),
            None,
            version_info_size,
            version_info_buf.as_mut_ptr() as _,
        )?;

        // this is a pointer to an array of lang/codepage word pairs,
        // but in practice almost all apps only ship with one language.
        // we just treat it as a single thing for simplicity.
        let mut lang_ptr: *const (u16, u16) = std::ptr::null_mut();
        let mut len = 0;

        VerQueryValueW(
            version_info_buf.as_mut_ptr() as _,
            w!("\\VarFileInfo\\Translation"),
            &mut lang_ptr as *const _ as _,
            &mut len,
        )
        .ok()?;
        if len == 0 {
            return Err(anyhow!("no translation info"));
        }

        let sub_block = format!(
            "\\StringFileInfo\\{:04x}{:04x}\\FileDescription\0",
            (*lang_ptr).0,
            (*lang_ptr).1
        )
        .encode_utf16()
        .collect::<Vec<u16>>();
        let mut file_description_ptr: *const u16 = std::ptr::null();
        VerQueryValueW(
            version_info_buf.as_mut_ptr() as _,
            PCWSTR::from_raw(sub_block.as_ptr()),
            &mut file_description_ptr as *const _ as _,
            &mut len,
        )
        .ok()?;
        if len == 0 {
            return Err(anyhow!("no file description"));
        }

        let file_description = std::slice::from_raw_parts(file_description_ptr, len as usize - 1);
        let file_description = String::from_utf16_lossy(file_description);

        Ok(file_description)
    }
}

pub fn active_executables() -> Result<ProcessList> {
    let mut executables: HashMap<PathBuf, ProcessInfo> = HashMap::new();
    let visible = visible_windows()?;

    for pid in enumerate_pids()? {
        let (executable, is_critical) = unsafe {
            let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
                continue;
            };
            let path = process_name(handle);
            let is_critical = is_critical(handle);
            CloseHandle(handle)?;
            (path?, is_critical?)
        };

        match executables.entry(executable) {
            Entry::Occupied(mut e) => {
                let process_info = e.get();
                if !process_info.is_visible && visible.contains(&pid) {
                    let mut display_name_cache = DISPLAY_NAME_CACHE.lock().unwrap();
                    if let Ok(d) = display_name_cache.get(e.key().clone()) {
                        e.get_mut().display_name.clone_from(d);
                    }
                    e.get_mut().is_visible = true;
                }
            }
            Entry::Vacant(e) => {
                let executable = e.key().clone();
                let is_visible = visible.contains(&pid);
                let display_name = {
                    let dn = if is_visible {
                        let mut display_name_cache = DISPLAY_NAME_CACHE.lock().unwrap();
                        if let Ok(d) = display_name_cache.get(executable.clone()) {
                            Some(d.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    dn.unwrap_or_else(|| {
                        executable
                            .to_string_lossy()
                            .rsplit('\\')
                            .next()
                            .unwrap()
                            .to_string()
                    })
                };
                e.insert(ProcessInfo {
                    executable,
                    display_name,
                    is_visible,
                    is_system: is_critical,
                });
            }
        }
    }

    Ok(executables.into_values().collect())
}

pub fn visible_windows() -> Result<HashSet<PID>> {
    let mut pids: HashSet<PID> = HashSet::new();

    enum_windows(|window| {
        unsafe {
            let mut pid: u32 = 0;
            if GetWindowThreadProcessId(window, Some(&mut pid)) == 0 {
                return true; // If the window handle is invalid, the return value is zero.
            }
            let is_visible = IsWindowVisible(window).as_bool();
            let is_iconic = IsIconic(window).as_bool();
            let is_cloaked = {
                let mut cloaked = BOOL::default();
                if let Err(e) = DwmGetWindowAttribute(
                    window,
                    DWMWA_CLOAKED,
                    &mut cloaked as *mut BOOL as *mut _,
                    size_of::<BOOL>() as u32,
                ) {
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
where
    F: FnMut(HWND) -> bool,
{
    unsafe {
        EnumWindows(
            Some(enum_windows_proc::<F> as _),
            LPARAM(&func as *const _ as _),
        )?
    }
    Ok(())
}

extern "system" fn enum_windows_proc<F>(hwnd: HWND, lparam: LPARAM) -> BOOL
where
    F: FnMut(HWND) -> bool,
{
    let func = unsafe { &mut *(lparam.0 as *mut F) };
    func(hwnd).into()
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;

    #[test]
    fn visible_windows() {
        let pids = super::visible_windows().unwrap();
        // no asserts here because tests should work on headless systems.
        for pid in pids {
            let procname = super::get_process_name(pid)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|e| format!("<{:?}>", e));

            println!("{: >6} {}", pid, procname);
        }
    }

    #[test]
    fn get_process_name() {
        let name = super::get_process_name(std::process::id()).unwrap();
        assert!(name.as_os_str().to_string_lossy().contains("mitmproxy"));
    }

    #[test]
    fn get_executable_name() {
        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("benches\\openvpnserv.exe");
        assert_eq!(super::get_display_name(&d).unwrap(), "OpenVPN Service");
    }

    #[test]
    fn process_list() {
        let lst = super::active_executables().unwrap();
        assert!(!lst.is_empty());

        for proc in &lst {
            if proc.is_visible {
                dbg!(proc);
            }
        }
        dbg!(lst.len());
    }
}
