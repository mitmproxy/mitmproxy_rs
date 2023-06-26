extern crate prost_build;

fn main() {
    prost_build::compile_protos(&["apple-tunnel/raw_packet.proto"],
                                &["src/"]).unwrap();
