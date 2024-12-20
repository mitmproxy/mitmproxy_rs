use crate::intercept_conf::PID;
use crate::processes::{ProcessInfo, ProcessList};
use anyhow::Result;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[cfg(target_os = "macos")]
use crate::processes::macos_visible_windows::macos_visible_windows;

pub fn active_executables() -> Result<ProcessList> {
    let mut executables: HashMap<PathBuf, ProcessInfo> = HashMap::new();
    let visible = visible_windows()?;
    let mut sys = System::new();
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet),
    );
    for (pid, process) in sys.processes() {
        // process.exe() will return empty path if there was an error while trying to read /proc/<pid>/exe.
        if let Some(path) = process.exe() {
            let pid = pid.as_u32();
            let executable = path.to_path_buf();
            match executables.entry(executable) {
                Entry::Occupied(mut e) => {
                    let process_info = e.get();
                    if !process_info.is_visible && visible.contains(&pid) {
                        e.get_mut().is_visible = true;
                    }
                }
                Entry::Vacant(e) => {
                    let executable = e.key().clone();
                    // .file_name() returns `None` if the path terminates in `..`
                    // We use the absolute path in such a case.
                    let display_name = path
                        .file_name()
                        .unwrap_or(path.as_os_str())
                        .to_string_lossy()
                        .to_string();
                    let is_system = is_system(&executable);
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
    }
    Ok(executables.into_values().collect())
}

pub fn visible_windows() -> Result<HashSet<PID>> {
    #[cfg(target_os = "macos")]
    return macos_visible_windows();

    #[cfg(target_os = "linux")]
    // Finding visible windows is less useful on Linux, where more applications tend to be CLI-based.
    // So we skip all the X11/Wayland complexity.
    return Ok(HashSet::new());
}

fn is_system(executable: &PathBuf) -> bool {
    #[cfg(target_os = "macos")]
    let sys_paths = vec!["/sbin", "/usr/sbin", "/usr/libexec", "/System/"];
    #[cfg(target_os = "linux")]
    let sys_paths = vec!["/sbin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/systemd/"];

    sys_paths
        .into_iter()
        .any(|path| executable.starts_with(path))
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

    #[cfg(target_os = "macos")]
    #[test]
    fn visible_windows_list() {
        let open_windows_pids = visible_windows().unwrap();
        assert!(!open_windows_pids.is_empty());
        dbg!(open_windows_pids.len());
    }
}
