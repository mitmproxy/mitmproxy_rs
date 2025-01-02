# mitmproxy-linux

This package contains the following precompiled binaries for Linux:
 
 - `mitmproxy-linux-redirector`: A Rust executable that redirects traffic to mitmproxy via eBPF.


## Redirector Development Setup

1. Install [bpf-linker](https://github.com/aya-rs/bpf-linker): `cargo install --locked bpf-linker`
2. Run `pip install -e .` to install `mitmproxy_linux` as editable.
3. Run something along the lines of `mitmdump --mode local:curl`.  
   You should see a `Development mode: Compiling mitmproxy-linux-redirector...` message.
