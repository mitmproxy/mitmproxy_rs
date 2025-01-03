#[cfg(target_os = "linux")]
use std::{
    env, fs,
    io::{BufRead as _, BufReader},
    path::PathBuf,
    process::{Child, Command, Stdio},
};

#[cfg(target_os = "linux")]
use cargo_metadata::{
    Artifact, CompilerMessage, Message, Metadata, MetadataCommand, Package, Target,
};

#[cfg(not(target_os = "linux"))]
fn main() {}

/// Based on https://github.com/aya-rs/aya-template/blob/main/%7B%7Bproject-name%7D%7D/build.rs
#[cfg(target_os = "linux")]
fn main() {
    let Metadata { packages, .. } = MetadataCommand::new().no_deps().exec().unwrap();
    let ebpf_package = packages
        .into_iter()
        .find(|Package { name, .. }| name == "mitmproxy-linux-ebpf")
        .unwrap();

    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = PathBuf::from(out_dir);

    let endian = env::var_os("CARGO_CFG_TARGET_ENDIAN").unwrap();
    let target = if endian == "big" {
        "bpfeb"
    } else if endian == "little" {
        "bpfel"
    } else {
        panic!("unsupported endian={:?}", endian)
    };

    let arch = env::var_os("CARGO_CFG_TARGET_ARCH").unwrap();

    let target = format!("{target}-unknown-none");

    let Package { manifest_path, .. } = ebpf_package;
    let ebpf_dir = manifest_path.parent().unwrap();

    // We have a build-dependency on `mitmproxy-linux-ebpf`, so cargo will automatically rebuild us
    // if `mitmproxy-linux-ebpf`'s *library* target or any of its dependencies change. Since we
    // depend on `mitmproxy-linux-ebpf`'s *binary* targets, that only gets us half of the way. This
    // stanza ensures cargo will rebuild us on changes to the binaries too, which gets us the
    // rest of the way.
    println!("cargo:rerun-if-changed={}", ebpf_dir.as_str());

    let mut cmd = Command::new("cargo");
    cmd.args([
        "build",
        "-Z",
        "build-std=core",
        "--bins",
        "--message-format=json",
        "--release",
        "--target",
        &target,
    ]);

    cmd.env("CARGO_CFG_BPF_TARGET_ARCH", arch);

    // Workaround to make sure that the rust-toolchain.toml is respected.
    for key in ["RUSTUP_TOOLCHAIN", "RUSTC", "RUSTC_WORKSPACE_WRAPPER"] {
        cmd.env_remove(key);
    }
    cmd.current_dir(ebpf_dir);

    // Workaround for https://github.com/rust-lang/cargo/issues/6412 where cargo flocks itself.
    let ebpf_target_dir = out_dir.join("mitmproxy-linux-ebpf");
    cmd.arg("--target-dir").arg(&ebpf_target_dir);

    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("failed to spawn {cmd:?}: {err}"));
    let Child { stdout, stderr, .. } = &mut child;

    // Trampoline stdout to cargo warnings.
    let stderr = stderr.take().unwrap();
    let stderr = BufReader::new(stderr);
    let stderr = std::thread::spawn(move || {
        for line in stderr.lines() {
            let line = line.unwrap();
            let skip = line.contains("info: latest update on")
                || line.contains("syncing channel updates")
                || line.contains("downloading component")
                || line.contains("installing component")
                || line.contains("Updating crates.io index")
                || line.contains("Updating git repository")
                || line.contains("Downloading")
                || line.contains("Downloaded")
                || line.contains("Compiling ")
                || line.contains("Finished `");
            if !skip {
                println!("cargo:warning={line}");
            }
        }
    });

    let stdout = stdout.take().unwrap();
    let stdout = BufReader::new(stdout);
    let mut executables = Vec::new();
    for message in Message::parse_stream(stdout) {
        #[allow(clippy::collapsible_match)]
        match message.expect("valid JSON") {
            Message::CompilerArtifact(Artifact {
                executable,
                target: Target { name, .. },
                ..
            }) => {
                if let Some(executable) = executable {
                    executables.push((name, executable.into_std_path_buf()));
                }
            }
            Message::CompilerMessage(CompilerMessage { message, .. }) => {
                for line in message.rendered.unwrap_or_default().split('\n') {
                    println!("cargo:warning={line}");
                }
            }
            Message::TextLine(line) => {
                println!("cargo:warning={line}");
            }
            _ => {}
        }
    }

    let status = child
        .wait()
        .unwrap_or_else(|err| panic!("failed to wait for {cmd:?}: {err}"));
    assert_eq!(status.code(), Some(0), "{cmd:?} failed: {status:?}");

    stderr.join().map_err(std::panic::resume_unwind).unwrap();

    for (name, binary) in executables {
        let dst = out_dir.join(name);
        let _: u64 = fs::copy(&binary, &dst)
            .unwrap_or_else(|err| panic!("failed to copy {binary:?} to {dst:?}: {err}"));
    }
}
