use anyhow::Result;
use objc2::ffi::id;
use objc2::msg_send;
use objc2::class;
use sysinfo::{PidExt, ProcessRefreshKind, System, SystemExt};
use crate::processes::ProcessList;

pub fn active_executables() -> Result<ProcessList> {

    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    for proc in sys.processes() {
        dbg!(proc);

        let int_value = proc.0.as_u32();
        let pid: i32 = msg_send![pid, intValue];
        let p: id = msg_send![
            class!(NSRunningApplication),
            runningApplicationWithProcessIdentifier: proc.0.as_u32()
        ];


    }

    Ok(vec![])
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
