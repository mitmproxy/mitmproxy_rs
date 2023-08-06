extern crate prost_build;

fn main() {
    if std::env::var_os("PROTOC")
        .map(std::path::PathBuf::from)
        .or_else(|| which::which("protoc").ok())
        .is_none()
    {
        std::env::set_var(
            "PROTOC",
            protoc_bin_vendored::protoc_bin_path().expect("Protoc binary not found"),
        );
    }

    prost_build::compile_protos(
        &["./src/packet_sources/ipc.proto"],
        &["./src/packet_sources/"],
    )
    .unwrap();
}
