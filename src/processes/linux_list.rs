use crate::processes::{ProcessInfo, ProcessList};
use anyhow::Result;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::path::PathBuf;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};

pub fn active_executables() -> Result<ProcessList> {
    let mut executables: HashMap<PathBuf, ProcessInfo> = HashMap::new();
    let mut sys = System::new_all();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::everything(),
    );

    for process in sys.processes().values() {
        // process.exe() will return empty path if there was an error while trying to read /proc/<pid>/exe.
        if let Some(exec) = process.exe() {
            let exec_buf = exec.to_path_buf();

            match executables.entry(exec_buf) {
                Entry::Occupied(_) => {}
                Entry::Vacant(e) => {
                    let exec_buf = e.key().clone();
                    // process display name can contain non-UTF-8 characters, forcing us to use to_string_lossy
                    let display_name = process.name().to_string_lossy().to_string();
                    e.insert(ProcessInfo {
                        executable: exec_buf,
                        display_name,
                        is_visible: false,
                        is_system: false,
                    });
                }
            }
        }
    }
    Ok(executables.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_list() {
        let lst = active_executables().unwrap();
        assert!(!lst.is_empty());
    }
}
