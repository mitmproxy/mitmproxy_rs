#!/usr/bin/bash

set -e

export RUSTFLAGS="-Cinstrument-coverage"
cargo build
export LLVM_PROFILE_FILE="mitmguard-%p-%m.profraw"
cargo test
grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./target/debug/coverage/
rm *.profraw

