extern crate prost_build;

fn main() {
    std::env::set_var(
        "PROTOC",
        protoc_bin_vendored::protoc_bin_path().expect("protoc binary not found"),
    );
    prost_build::compile_protos(
        &["./src/packet_sources/ipc.proto"],
        &["./src/packet_sources/"],
    )
    .unwrap();
}
