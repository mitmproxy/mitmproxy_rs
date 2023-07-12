use std::{fs, path::Path};

pub fn copy_dir(src: &Path, dst: &Path) {
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
        copy_dir(
            Path::new("../macos-redirector/MitmproxyAppleTunnel.app/"),
            Path::new("/Applications/MitmproxyAppleTunnel.app/"),
        );
    }
}
