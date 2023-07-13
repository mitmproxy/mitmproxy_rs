use std::fs;

fn main() {
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
    if cfg!(windows) {
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
    } else {
        fs::remove_file("mitmproxy_rs/windows-redirector.exe").ok();
        for wd_file in windivert_files {
            fs::remove_file(format!("mitmproxy_rs/{wd_file}")).ok();
        }
    }
}
