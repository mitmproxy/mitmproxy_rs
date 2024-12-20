use anyhow::Result;
use cocoa::base::nil;
use cocoa::foundation::NSString;
use core_foundation::number::{kCFNumberSInt32Type, CFNumberGetValue, CFNumberRef};
use core_graphics::display::{
    kCGNullWindowID, kCGWindowListExcludeDesktopElements, kCGWindowListOptionOnScreenOnly,
    CFArrayGetCount, CFArrayGetValueAtIndex, CFDictionaryGetValueIfPresent, CFDictionaryRef,
    CGWindowListCopyWindowInfo,
};
use crate::intercept_conf::PID;
use std::ffi::c_void;
use std::collections::HashSet;

pub fn macos_visible_windows() -> Result<HashSet<PID>> {
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
