pub use image;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub executable: PathBuf,
    pub display_name: String,
    pub activation_policy: Option<u8>,
    pub is_system: bool,
    pub icon: Vec<u8>,
}

pub type ProcessList = Vec<ProcessInfo>;
