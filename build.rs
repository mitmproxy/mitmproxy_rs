extern crate prost_build;
use protoc_bin_vendored;

fn main() {
    std::env::set_var("PROTOC", protoc_bin_vendored::protoc_bin_path().unwrap());
    prost_build::compile_protos(
        &["./src/packet_sources/ipc.proto"],
        &["./src/packet_sources/"],
    )
    .unwrap();
}
