#[cfg(target_os = "macos")]
use home::home_dir;
use std::{fs, path::Path};

pub fn copy_dir(src: &Path, dst: &Path) {
    println!("{} -> {}", src.display(), dst.display());
    for entry in src.read_dir().unwrap() {
        let entry = entry.unwrap();
        let ty = entry.file_type().expect("Failed to get file type");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if ty.is_dir() {
            fs::create_dir_all(&dst_path).expect("Failed to create directory");
            copy_dir(&src_path, &dst_path);
        } else {
            fs::copy(&src_path, &dst_path).expect("Failed to copy {src_path} to {dst_path}");
        }
    }
}

fn main() {
    #[cfg(windows)]
    {
        // This is slightly terrible:
        // We want to bundle WinDivert with all Windows wheels, so we dynamically copy it into tree.
        // Alternatively we could include_bytes!() it, but then we would need to extract to a temporary
        // directory during execution, which is even worse.

        // Ideally we should also do https://github.com/rust-lang/cargo/issues/9096 here,
        // but for now we want to stay on stable Rust.

        // xxx: untested
        println!("cargo:rerun-if-changed=../target/debug/windows-redirector.exe");
        println!("cargo:rerun-if-changed=../target/release/windows-redirector.exe");
        println!("cargo:rerun-if-changed=../windows-redirector/windivert/");

        let windivert_files = ["WinDivert.dll", "WinDivert.lib", "WinDivert64.sys"];
        if cfg!(debug_assertions) {
            fs::copy(
                "../target/debug/windows-redirector.exe",
                "mitmproxy_rs/windows-redirector.exe",
            )
        } else {
            fs::copy(
                "../target/release/windows-redirector.exe",
                "mitmproxy_rs/windows-redirector.exe",
            )
        }
        .expect("Failed to copy windows-redirector.exe. Has it been built yet?");
        for file in windivert_files {
            if fs::copy(
                format!("../windows-redirector/windivert/{file}"),
                format!("mitmproxy_rs/{file}"),
            )
            .is_err()
            {
                // WinDivert64.sys is sometimes weirdly locked, we can ignore that.
                if file != "WinDivert64.sys" {
                    panic!("Failed to copy {file}")
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macos-certificate-truster binary
        copy_dir(
            Path::new("../macos-certificate-truster/macos-certificate-truster.app/"),
            Path::new("mitmproxy_rs/macos-certificate-truster.app"),
        );
        if cfg!(debug_assertions) {
            fs::copy(
                "../target/debug/macos-certificate-truster",
                "mitmproxy_rs/macos-certificate-truster.app/Contents/MacOS/macos-certificate-truster",
            )
        } else {
            fs::copy(
                "../target/release/macos-certificate-truster",
                "mitmproxy_rs/macos-certificate-truster.app/Contents/MacOS/macos-certificate-truster",
            )
        }
        .expect("Failed to copy macos-certificate-truster. Has it been built yet?");

        // macos-redirector app
        let forlder_path = home_dir()
            .unwrap()
            .join("Library")
            .join("Developer")
            .join("Xcode")
            .join("DerivedData");

        let entries = fs::read_dir(forlder_path).unwrap();

        //I need to do this because xcode renames the build folder with an ever-changing hash suffix,
        //since previously I totally clean the DerivedData folder inside it there is only a name
        //starting with MitmproxyAppleTunnel-

        for entry in entries {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_dir() {
                    let file_name = path.file_name().unwrap().to_string_lossy();
                    if file_name.starts_with("MitmproxyAppleTunnel-") {
                        let build_path = path
                            .join("Build")
                            .join("Products")
                            .join("Release")
                            .join("MitmproxyAppleTunnel.app");

                        copy_dir(
                            &build_path,
                            Path::new("mitmproxy_rs/MitmProxyAppleTunnel.app"),
                        );
                    }
                }
            }
        }
    }
}
