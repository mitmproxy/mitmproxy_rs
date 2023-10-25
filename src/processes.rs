pub use image;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub executable: PathBuf,
    pub display_name: String,
    pub activation_policy: u8,
    pub is_system: bool,
}

pub type ProcessList = Vec<ProcessInfo>;
