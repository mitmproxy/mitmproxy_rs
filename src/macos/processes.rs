use crate::processes::{ProcessInfo, ProcessList};
use anyhow::{bail, Result};
use base64::engine::general_purpose;
use base64::Engine;
use cocoa::base::id;
use objc::{class, msg_send, sel, sel_impl};
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};

pub fn active_executables() -> Result<ProcessList> {
    let mut sys = System::new();
    let mut list: ProcessList = vec![];
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    for proc in sys.processes() {
        let display_name = proc.1.name().to_string();
        let mut activation_policy = None;
        let mut _icon: Option<i32> = None;
        let executable = proc.1.exe();
        let mut icon = vec![];
        let app: id = unsafe {
            msg_send![class!(NSRunningApplication), runningApplicationWithProcessIdentifier: proc.0.as_u32()]
        };
        if !app.is_null() {
            activation_policy = Some(unsafe { msg_send![app, activationPolicy] });
            let img: id = unsafe { msg_send![app, icon] };
            let tif: id = unsafe { msg_send![img, TIFFRepresentation] };
            let bitmap: id = unsafe { msg_send![class!(NSBitmapImageRep), imageRepWithData: tif] };
            let png: id = unsafe { msg_send![bitmap, representationUsingType: 4 properties: 0] };
            let length: usize = unsafe { msg_send![png, length] };
            if let Some(len) = base64::encoded_len(length, true) {
                let bytes: *const u8 = unsafe { msg_send![png, bytes] };
                let s = unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec();
                icon.resize(len, 0);
                match general_purpose::STANDARD.encode_slice(s, &mut icon) {
                    Ok(len) => icon.truncate(len),
                    Err(e) => bail!(e),
                }
            }
        }
        list.push(ProcessInfo {
            executable: executable.to_path_buf(),
            display_name,
            activation_policy,
            is_system: executable.starts_with("/System/"),
            icon,
        });
    }
    Ok(list)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_list() {
        let lst = active_executables().unwrap();
        assert!(!lst.is_empty());

        for proc in &lst {
             dbg!(proc);
        }
        dbg!(lst.len());
    }
}
