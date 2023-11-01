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
                let pixels = unsafe {
                    let hinst = GetModuleHandleW(None)?;
                    icon_for_executable(e.key(), hinst)?
                };
                let pixel_hash = pixels.hash();
                e.insert(pixel_hash);
                let icon = self.icons.entry(pixel_hash).or_insert_with(|| {
                    let mut c = Cursor::new(Vec::new());
                    pixels
                        .to_image()
                        .write_to(&mut c, image::ImageOutputFormat::Png)
                        .unwrap();
                    c.into_inner()
                });
                Ok(icon)
            }
        }
    }
}

