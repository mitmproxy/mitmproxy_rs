extern crate prost_build;

fn main() {
    prost_build::compile_protos(
        &["./src/packet_sources/raw_packet.proto"],
        &["./src/packet_sources/"],
    )
    .unwrap();
}
