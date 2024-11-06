use crate::intercept_conf::PID;
use crate::processes::{ProcessInfo, ProcessList};
use anyhow::Result;
use cocoa::base::nil;
use cocoa::foundation::NSString;
use core_foundation::number::kCFNumberSInt32Type;
use core_foundation::number::CFNumberGetValue;
use core_foundation::number::CFNumberRef;
use core_graphics::display::{
    kCGNullWindowID, kCGWindowListExcludeDesktopElements, kCGWindowListOptionOnScreenOnly,
    CFArrayGetCount, CFArrayGetValueAtIndex, CFDictionaryGetValueIfPresent, CFDictionaryRef,
    CGWindowListCopyWindowInfo,
};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::path::PathBuf;
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};

pub fn active_executables() -> Result<ProcessList> {
    let mut executables: HashMap<PathBuf, ProcessInfo> = HashMap::new();
    let visible = visible_windows()?;
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    for (pid, process) in sys.processes() {
        let pid = pid.as_u32();
        let display_name = process.name().to_string();
        let executable = process.exe().to_path_buf();
        let is_system = executable.starts_with("/System/");
        match executables.entry(executable) {
            Entry::Occupied(mut e) => {
                let process_info = e.get();
                if !process_info.is_visible && visible.contains(&pid) {
                    e.get_mut().is_visible = true;
                }
            }
            Entry::Vacant(e) => {
                let executable = e.key().clone();
                let is_visible = visible.contains(&pid);
                e.insert(ProcessInfo {
                    executable,
                    display_name,
                    is_visible,
                    is_system,
                });
            }
        }
    }
    Ok(executables.into_values().collect())
}

pub fn visible_windows() -> Result<HashSet<PID>> {
    let mut pids: HashSet<PID> = HashSet::new();
    unsafe {
        let windows_info_list = CGWindowListCopyWindowInfo(
            kCGWindowListOptionOnScreenOnly + kCGWindowListExcludeDesktopElements,
            kCGNullWindowID,
        );
        let count = CFArrayGetCount(windows_info_list);

        for i in 0..count - 1 {
            let dic_ref = CFArrayGetValueAtIndex(windows_info_list, i);
            let key = NSString::alloc(nil).init_str("kCGWindowOwnerPID");
            let mut pid: *const c_void = std::ptr::null_mut();

            if CFDictionaryGetValueIfPresent(
                dic_ref as CFDictionaryRef,
                key as *const c_void,
                &mut pid,
            ) != 0
            {
                let pid_cf_ref = pid as CFNumberRef;
                let mut pid: i32 = 0;
                if CFNumberGetValue(
                    pid_cf_ref,
                    kCFNumberSInt32Type,
                    &mut pid as *mut i32 as *mut c_void,
                ) {
                    pids.insert(pid as u32);
                }
            }
        }
        Ok(pids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_list() {
        let lst = active_executables().unwrap();
        assert!(!lst.is_empty());

        for proc in &lst {
            if !proc.is_visible {
                dbg!(&proc.display_name);
            }
        }
        dbg!(lst.len());
    }

    #[test]
    fn visible_windows_list() {
        let open_windows_pids = visible_windows().unwrap();
        assert!(!open_windows_pids.is_empty());
        dbg!(open_windows_pids.len());
    }
}
