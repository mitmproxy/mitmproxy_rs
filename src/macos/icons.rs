use once_cell::sync::Lazy;
use std::{sync::Mutex, collections::hash_map::Entry};
use cocoa::base::id;
use sysinfo::{PidExt, ProcessExt, ProcessRefreshKind, System, SystemExt};
use objc::{class, msg_send, sel, sel_impl};
use std::path::PathBuf;
use std::path::Path; use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use anyhow::{bail, Result};
use std::hash::{Hasher, Hash};


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
                let icon = unsafe { png_data_for_executable(e.key())? };
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

unsafe fn png_data_for_executable(executable: &Path) -> Result<Vec<u8>> {
    let mut sys = System::new();
    sys.refresh_processes_specifics(ProcessRefreshKind::new());
    for (pid, process) in sys.processes() {
        let pid = pid.as_u32();
        if executable == process.exe().to_path_buf(){
            let app: id = msg_send![class!(NSRunningApplication), runningApplicationWithProcessIdentifier: pid];
            if !app.is_null() {
                let img: id = msg_send![app, icon];
                let tif: id = msg_send![img, TIFFRepresentation];
                let bitmap: id = msg_send![class!(NSBitmapImageRep), imageRepWithData: tif];
                let png: id = msg_send![bitmap, representationUsingType: 4 properties: 0];
                let length: usize = msg_send![png, length];
                let bytes: *const u8 = msg_send![png, bytes];
                let data = std::slice::from_raw_parts(bytes, length).to_vec();
                return Ok(data)
            }
        }
    }
    bail!("unable to extract icon");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png() {
        let path = PathBuf::from("/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder");
        let mut icon_cache = IconCache::default();
        let vec = icon_cache.get_png(path).unwrap();
        dbg!(vec.len());
    }
}
