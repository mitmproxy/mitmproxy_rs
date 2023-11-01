use std::collections::{HashMap, HashSet};
use std::collections::hash_map::Entry;
use crate::processes::{ProcessInfo, ProcessList};
use anyhow::{bail, Result};
use base64::engine::general_purpose;
use base64::Engine;
use cocoa::base::id;
use cocoa::base::nil;
use cocoa::foundation::NSString;
use core_foundation::number::CFNumberGetValue;
use core_foundation::number::CFNumberRef;
use core_foundation::number::kCFNumberSInt32Type;
use core_foundation::string::CFStringGetCString;
use core_foundation::string::CFStringRef;
use core_foundation::string::kCFStringEncodingUTF8;
use core_graphics::display::{CFDictionaryGetValueIfPresent, CGWindowListCopyWindowInfo, CFArrayGetCount, CFArrayGetValueAtIndex, CFDictionaryRef, kCGNullWindowID, kCGWindowListOptionOnScreenOnly, kCGWindowListExcludeDesktopElements};
use std::ffi::{c_void, CStr};
use objc::{class, msg_send, sel, sel_impl};
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};
use std::path::PathBuf;
use crate::intercept_conf::PID;
use once_cell::sync::Lazy;
use std::sync::Mutex;

pub static DISPLAY_NAME_CACHE: Lazy<Mutex<DisplayNameCache>> = Lazy::new(|| Mutex::new(DisplayNameCache::default()));

#[derive(Default)]
pub struct DisplayNameCache(HashMap<PathBuf, Result<String>>);

impl DisplayNameCache {
    pub fn get(&mut self, executable: PathBuf) -> &Result<String> {
        self.0
            .entry(executable)
            .or_insert_with_key(|path| get_display_name(path))
    }
}

pub fn active_executables() -> Result<ProcessList> {
    let mut executables: HashMap<PathBuf, ProcessInfo> = HashMap::new();
    let mut visible = visible_windows()?;
    let mut sys = System::new();
    let mut list: ProcessList = vec![];
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    for (pid, process) in sys.processes() {
        let pid = pid.as_u32();
        let display_name = process.name().to_string();
        let executable = process.exe().to_path_buf();
        // let mut icon = vec![];
        match executables.entry(executable) {
            Entry::Occupied(mut e) => {
                let process_info = e.get();
                if !process_info.is_visible && visible.contains(&pid){
                    let mut display_name_cache = DISPLAY_NAME_CACHE.lock().unwrap();
                    if let Ok(d) = display_name_cache.get(e.key().clone()) {
                        e.get_mut().display_name = d.clone();
                    }
                    e.get_mut().is_visible = true;
                }
            }
            Entry::Vacant(e) => {
            }
                    
        }

        unsafe {
            let app: id = msg_send![class!(NSRunningApplication), runningApplicationWithProcessIdentifier: pid.as_u32()];
            if !app.is_null() {
                let app: id = msg_send![app, delegate];
                let windows: id = msg_send![app, orderedWindows];
                dbg!(windows);
                let windows_len: usize = msg_send![windows, count];
                dbg!(windows_len);
                for i in 0..windows_len {
                    let window: id = msg_send![windows, objectAtIndex: i];
                    dbg!(window);
                    let occlusion_state: u64 = msg_send![window, occlusionState];
                    dbg!(occlusion_state);
                }
                //is_visible = occlusion_state == 2; 
                // let img: id = msg_send![app, icon];
                // let tif: id = msg_send![img, TIFFRepresentation];
                // let bitmap: id = msg_send![class!(NSBitmapImageRep), imageRepWithData: tif];
                // let png: id = msg_send![bitmap, representationUsingType: 4 properties: 0];
                // let length: usize = msg_send![png, length];
                // if let Some(len) = base64::encoded_len(length, true) {
                //     let bytes: *const u8 = msg_send![png, bytes];
                //     let s = std::slice::from_raw_parts(bytes, length).to_vec();
                    // icon.resize(len, 0);
                    // match general_purpose::STANDARD.encode_slice(s, &mut icon) {
                    //     Ok(len) => icon.truncate(len),
                    //     Err(e) => bail!(e),
                    // }
                // }
            }
        }
        list.push(ProcessInfo {
            executable: executable.to_path_buf(),
            display_name,
            is_system: executable.starts_with("/System/"),
            is_visible,
        });
    }
    Ok(list)
}

pub fn visible_windows() -> Result<HashSet<PID>> {
    let mut pids: HashSet<PID> = HashSet::new();

    unsafe{
        let windows_info_list = CGWindowListCopyWindowInfo( kCGWindowListOptionOnScreenOnly + kCGWindowListExcludeDesktopElements, kCGNullWindowID);
        let count = CFArrayGetCount(windows_info_list);

        for i in 0..count-1 {
            let dic_ref = CFArrayGetValueAtIndex(windows_info_list, i);
            let key = NSString::alloc(nil).init_str("kCGWindowOwnerPID");
            let mut pid: *const c_void = std::ptr::null_mut();

            if CFDictionaryGetValueIfPresent(dic_ref as CFDictionaryRef, key as *const c_void, &mut pid) != 0{
                let pid_cf_ref = pid as CFNumberRef;
                let mut pid:i32 = 0;
                if CFNumberGetValue(pid_cf_ref, kCFNumberSInt32Type, &mut pid as *mut i32 as *mut c_void) {
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
             // dbg!(&proc.display_name);
            if !proc.is_visible {
                dbg!("VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV");
                dbg!(&proc.display_name);
                dbg!("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
            }
        }
        dbg!(lst.len());
    }

    #[test]
    fn visible_windows_list() {
        let lst = visible_windows().unwrap();
        assert!(!lst.is_empty());

        for pid in &lst {
            dbg!("VVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVVV");
            dbg!(&pid);
            dbg!("^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^");
        }
        dbg!(lst.len());
    }
}
