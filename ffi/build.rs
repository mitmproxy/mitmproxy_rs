use std::{fs, io, path::Path};

#[allow(unused)]
pub fn copy_dir(src: &Path, dst: &Path) -> Result<(), io::Error> {
    for entry in src.read_dir()? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            fs::create_dir_all(&dst_path)?;
            copy_dir(&src_path, &dst_path)?;
        } else {
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

#[allow(unused)]
const TARGET: &str = if cfg!(debug_assertions) {
    "debug"
} else {
    "release"
};

#[allow(unused)]
fn panic_unless_ci(message: &str) {
    if std::env::var("CI").is_ok() {
        println!("cargo:warning={}", message);
    } else {
        panic!("{}", message);
    }
}

fn main() {
    #[cfg(target_os = "macos")]
    {
        // macos-certificate-truster binary
        copy_dir(
            Path::new("../macos-certificate-truster/macos-certificate-truster.app/"),
            Path::new("mitmproxy_rs/macos-certificate-truster.app"),
        )
        .unwrap();
        fs::create_dir_all("mitmproxy_rs/macos-certificate-truster.app/Contents/MacOS/").unwrap();
        if let Err(_) = fs::copy(
            format!("../target/{TARGET}/macos-certificate-truster"),
            "mitmproxy_rs/macos-certificate-truster.app/Contents/MacOS/macos-certificate-truster",
        ) {
            panic_unless_ci("Failed to copy macos-certificate-truster. Has it been built yet?");
        }

        if copy_dir(
            Path::new("../macos-redirector/dist/Mitmproxy Redirector.app/"),
            Path::new("mitmproxy_rs/Mitmproxy Redirector.app/"),
        )
        .is_err()
        {
            if Path::new("/Applications/Mitmproxy Redirector.app/").exists() {
                println!("cargo:warning=Using already-installed redirector app.");
            } else {
                panic_unless_ci("Failed to copy macos-redirector. Has it been built yet?");
            }
        }
    }
}
