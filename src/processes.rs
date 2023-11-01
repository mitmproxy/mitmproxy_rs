pub use image;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub executable: PathBuf,
    pub display_name: String,
    pub is_visible: bool,
    pub is_system: bool,
}

pub type ProcessList = Vec<ProcessInfo>;
