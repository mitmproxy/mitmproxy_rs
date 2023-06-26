extern crate prost_build;

fn main() {
    prost_build::compile_protos(&["src/raw_packet.proto"],
                                &["src/"]).unwrap();
