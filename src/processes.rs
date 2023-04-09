pub use image;
use image::RgbaImage;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub executable: String,
    pub display_name: String,
    pub icon: Option<u64>,
    pub is_visible: bool,
    pub is_system: bool,
}

#[derive(Debug)]
pub struct ProcessList {
    pub processes: Vec<ProcessInfo>,
    pub icons: HashMap<u64, RgbaImage>,
}
