use crate::processes::{ProcessInfo, ProcessList};
use anyhow::Result;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::path::PathBuf;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

pub fn active_executables() -> Result<ProcessList> {
    let mut executables: HashMap<PathBuf, ProcessInfo> = HashMap::new();
    let mut sys = System::new();

    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );

    for process in sys.processes().values() {
        // process.exe() will return an empty path if there was an error while trying to read /proc/<pid>/exe.
        if let Some(path) = process.exe() {
            let executable = path.to_path_buf();

            match executables.entry(executable) {
                Entry::Occupied(_) => {}
                Entry::Vacant(e) => {
                    let executable = e.key().clone();
                    // .file_name() returns `None` if the path terminates in `..`
                    // We use the absolute path in such a case.
                    let display_name = match path.file_name() {
                        Some(s) => s.to_string_lossy().to_string(),
                        None => path.to_string_lossy().to_string(),
                    };
                    e.insert(ProcessInfo {
                        executable,
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
