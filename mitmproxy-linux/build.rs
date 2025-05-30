#[cfg(target_os = "linux")]
use anyhow::{anyhow, Context as _};

#[cfg(target_os = "linux")]
use aya_build::cargo_metadata;

#[cfg(not(target_os = "linux"))]
fn main() {}

/// Based on https://github.com/aya-rs/aya-template/blob/main/%7B%7Bproject-name%7D%7D/build.rs
#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "mitmproxy-linux-ebpf")
        .ok_or_else(|| anyhow!("mitmproxy-linux-ebpf package not found"))?;
    aya_build::build_ebpf([ebpf_package])
}
