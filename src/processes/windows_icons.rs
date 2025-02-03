use std::collections::hash_map::{DefaultHasher, Entry};
use std::collections::HashMap;

use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::mem::MaybeUninit;
use std::os::windows::prelude::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::addr_of_mut;
use std::{iter, mem};

use anyhow::{bail, Result};
use image::RgbaImage;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::Graphics::Gdi::{
    DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFOHEADER, BI_RGB,
    DIB_RGB_COLORS, HDC,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Shell::ExtractAssociatedIconW;
use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, HICON};

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
                if !e.key().exists() {
                    // ExtractAssociatedIconW always returns a placeholder icon for invalid paths.
                    // We want unknown paths to raise on all platforms.
                    bail!("Executable does not exist.");
                }
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
                        .write_to(&mut c, image::ImageFormat::Png)
                        .unwrap();
                    c.into_inner()
                });
                Ok(icon)
            }
        }
    }
}

struct PixelData {
    bgra: Vec<u32>,
    width: u32,
    height: u32,
}

impl PixelData {
    fn to_image(&self) -> RgbaImage {
        RgbaImage::from_fn(self.width, self.height, |x, y| {
            let idx = y * self.width + x;
            let [b, g, r, a] = self.bgra[idx as usize].to_le_bytes();
            [r, g, b, a].into()
        })
    }

    fn hash(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.bgra.hash(&mut hasher);
        hasher.finish()
    }
}

unsafe fn icon_for_executable(executable: &Path, hinst: HMODULE) -> Result<PixelData> {
    let mut icon_path_u16: [u16; 128] = executable
        .as_os_str()
        .encode_wide()
        .chain(iter::repeat(0))
        .take(128)
        .collect::<Vec<u16>>()
        .try_into()
        .unwrap();
    let mut icon_idx = 0;
    let icon = ExtractAssociatedIconW(
        Some(hinst.into()),
        &mut icon_path_u16, // XXX: [u16; 128] is weird.
        &mut icon_idx,
    );
    if icon.is_invalid() {
        bail!("unable to extract icon");
    }

    let pixels = icon_to_pixels(icon);
    DestroyIcon(icon)?;

    Ok(pixels)
}

/// adapted from https://users.rust-lang.org/t/how-to-convert-hicon-to-png/90975/10
unsafe fn icon_to_pixels(icon: HICON) -> PixelData {
    let bitmap_size_i32 = i32::try_from(mem::size_of::<BITMAP>()).unwrap();
    let biheader_size_u32 = u32::try_from(mem::size_of::<BITMAPINFOHEADER>()).unwrap();

    let mut info = MaybeUninit::uninit();
    GetIconInfo(icon, info.as_mut_ptr()).unwrap();
    let info = info.assume_init_ref();
    DeleteObject(info.hbmMask.into()).unwrap();

    let mut bitmap: MaybeUninit<BITMAP> = MaybeUninit::uninit();
    let result = GetObjectW(
        info.hbmColor.into(),
        bitmap_size_i32,
        Some(bitmap.as_mut_ptr().cast()),
    );
    assert!(result == bitmap_size_i32);
    let bitmap = bitmap.assume_init_ref();

    let width_u32 = u32::try_from(bitmap.bmWidth).unwrap();
    let height_u32 = u32::try_from(bitmap.bmHeight).unwrap();
    let width_usize = usize::try_from(bitmap.bmWidth).unwrap();
    let height_usize = usize::try_from(bitmap.bmHeight).unwrap();
    let buf_size = width_usize.checked_mul(height_usize).unwrap();
    let mut buf: Vec<u32> = Vec::with_capacity(buf_size);

    let dc = GetDC(None);
    assert!(dc != HDC(std::ptr::null_mut()));

    let mut bitmap_info = BITMAPINFOHEADER {
        biSize: biheader_size_u32,
        biWidth: bitmap.bmWidth,
        biHeight: -bitmap.bmHeight,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB.0,
        biSizeImage: 0,
        biXPelsPerMeter: 0,
        biYPelsPerMeter: 0,
        biClrUsed: 0,
        biClrImportant: 0,
    };
    let result = GetDIBits(
        dc,
        info.hbmColor,
        0,
        height_u32,
        Some(buf.as_mut_ptr().cast()),
        addr_of_mut!(bitmap_info).cast(),
        DIB_RGB_COLORS,
    );
    assert!(result == bitmap.bmHeight);
    buf.set_len(buf.capacity());

    let result = ReleaseDC(None, dc);
    assert!(result == 1);
    DeleteObject(info.hbmColor.into()).unwrap();

    PixelData {
        bgra: buf,
        width: width_u32,
        height: height_u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png() {
        let path = PathBuf::from("C:\\Windows\\System32\\calc.exe");
        let mut icon_cache = IconCache::default();
        let vec = icon_cache.get_png(path).unwrap();
        assert!(!vec.is_empty());
    }

    #[test]
    fn no_icon_found() {
        let path = PathBuf::from("invalid path");
        let mut icon_cache = IconCache::default();
        assert!(icon_cache.get_png(path).is_err());
    }
}
