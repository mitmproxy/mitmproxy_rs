extern crate prost_build;

fn main() {
    prost_build::compile_protos(
        &["./src/packet_sources/ipc.proto"],
        &["./src/packet_sources/"],
    )
    .unwrap();
}
