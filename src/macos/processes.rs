use anyhow::Result;
use crate::processes::{ProcessList, ProcessInfo};
use sysinfo::{PidExt, ProcessRefreshKind, System, SystemExt, ProcessExt};
use cacao::foundation::{id,  NSString};
use objc::{class, msg_send, sel, sel_impl};

pub fn active_executables() -> Result<ProcessList> {
    dbg!("active_executables");
    let mut sys = System::new();
    let mut list: ProcessList = vec![];
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    for proc in sys.processes() {
        let app: id = unsafe{msg_send![class!(NSRunningApplication), runningApplicationWithProcessIdentifier: proc.0.as_u32()]};
        let display_name = if !app.is_null() {
            let localized_name: id = unsafe{msg_send![app, localizedName]};
            NSString::retain(localized_name).to_string()
        } else {
            proc.1.name().to_string()
        };
        let executable = proc.1.exe();
        let activation_policy: u8 = unsafe {msg_send![app, activationPolicy]};

        list.push(
            ProcessInfo {
                executable: executable.to_path_buf(),
                display_name,
                activation_policy, 
                is_system: executable.starts_with("/System/"),
            }
        );
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
