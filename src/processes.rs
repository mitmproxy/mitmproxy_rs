use std::path::PathBuf;

use anyhow::Result;
pub use image;

#[cfg(windows)]
use crate::windows;

pub type PID = u32;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub executable: PathBuf,
    pub display_name: String,
    pub is_visible: bool,
    pub is_system: bool,
}

pub type ProcessList = Vec<ProcessInfo>;

pub fn get_process_name(pid: PID) -> Result<PathBuf> {
    #[cfg(windows)]
    return windows::processes::get_process_name(pid);
    #[cfg(not(windows))]
    anyhow::bail!("this method is available on Windows only.");
}
