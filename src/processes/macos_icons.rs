use anyhow::{bail, Result};
use cocoa::base::id;
use objc::{class, msg_send, sel, sel_impl};
use std::collections::hash_map::DefaultHasher;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};

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
                let tiff = unsafe { tiff_data_for_executable(e.key())? };
                let mut hasher = DefaultHasher::new();
                tiff.hash(&mut hasher);
                let tiff_hash = hasher.finish();
                e.insert(tiff_hash);
                let icon = self
                    .icons
                    .entry(tiff_hash)
                    .or_insert_with(|| tiff_to_png(&tiff));
                Ok(icon)
            }
        }
    }
}

pub fn tiff_to_png(tiff: &[u8]) -> Vec<u8> {
    let mut c = Cursor::new(Vec::new());
    let tiff_image = image::load_from_memory_with_format(tiff, image::ImageFormat::Tiff)
        .unwrap()
        .resize(32, 32, image::imageops::FilterType::Triangle);
    tiff_image
        .write_to(&mut c, image::ImageFormat::Png)
        .unwrap();
    c.into_inner()
}

pub unsafe fn tiff_data_for_executable(executable: &Path) -> Result<Vec<u8>> {
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
                let tiff: id = msg_send![img, TIFFRepresentation];
                let length: usize = msg_send![tiff, length];
                let bytes: *const u8 = msg_send![tiff, bytes];
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
    use data_encoding::BASE64;

    #[test]
    fn png() {
        let path = PathBuf::from("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder");
        let mut icon_cache = IconCache::default();
        let vec = icon_cache.get_png(path).unwrap();
        assert!(!vec.is_empty());
        dbg!(vec.len());
        let base64_png = BASE64.encode(vec);
        dbg!(base64_png);
    }

    #[ignore]
    #[test]
    fn memory_leak() {
        let path = PathBuf::from("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder");
        for _ in 0..500 {
            _ = unsafe { &tiff_data_for_executable(&path) };
        }
    }
}
