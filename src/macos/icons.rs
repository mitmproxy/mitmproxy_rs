use anyhow::{bail, Result};
use cocoa::base::id;
use image::ImageEncoder;
use objc::{class, msg_send, sel, sel_impl};
use once_cell::sync::Lazy;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::path::PathBuf;
use std::{collections::hash_map::Entry, sync::Mutex};
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};

pub static ICON_CACHE: Lazy<Mutex<IconCache>> = Lazy::new(|| Mutex::new(IconCache::default()));

#[derive(Default)]
pub struct IconCache {
    /// executable name -> icon hash
    executables: HashMap<PathBuf, u64>,
    /// icon hash -> png bytes
    icons: HashMap<u64, Vec<u8>>,
}

impl IconCache {
    pub fn get_png(&mut self, executable: PathBuf) -> Result<&Vec<u8>> {
        match self.executables.entry(executable) {
            Entry::Occupied(e) => {
                // Guaranteed to exist because we never clear the cache.
                Ok(self.icons.get(e.get()).unwrap())
            }
            Entry::Vacant(e) => {
                let tif = unsafe { tif_data_for_executable(e.key())? };
                let icon = tif_to_png(&tif)?;
                let mut hasher = DefaultHasher::new();
                icon.hash(&mut hasher);
                let icon_hash = hasher.finish();
                e.insert(icon_hash);
                let icon = self.icons.entry(icon_hash).or_insert(icon);
                Ok(icon)
            }
        }
    }
}

pub fn tif_to_png(tif: &[u8]) -> Result<Vec<u8>> {
    let tif_image = image::load_from_memory(tif)?;
    let mut png_image: Vec<u8> = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut png_image);
    encoder.write_image(
        tif_image.as_rgba8().unwrap(),
        tif_image.width(),
        tif_image.height(),
        image::ColorType::Rgba8,
    )?;
    Ok(png_image)
}

unsafe fn tif_data_for_executable(executable: &Path) -> Result<Vec<u8>> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    for (pid, process) in sys.processes() {
        let pid = pid.as_u32();
        if executable == process.exe().to_path_buf() {
            let app: id = msg_send![
                class!(NSRunningApplication),
                runningApplicationWithProcessIdentifier: pid
            ];
            if !app.is_null() {
                let img: id = msg_send![app, icon];
                let tif: id = msg_send![img, TIFFRepresentation];
                let length: usize = msg_send![tif, length];
                let bytes: *const u8 = msg_send![tif, bytes];
                let data = std::slice::from_raw_parts(bytes, length).to_vec();
                return Ok(data);
            }
        }
    }
    bail!("unable to extract icon");
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose, Engine as _};

    #[test]
    fn png() {
        let path = PathBuf::from("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder");
        let mut icon_cache = IconCache::default();
        let vec = icon_cache.get_png(path).unwrap();
        assert!(vec.len() > 0);
        dbg!(vec.len());
        let base64_png = general_purpose::STANDARD.encode(&vec);
        dbg!(base64_png);
    }
}
