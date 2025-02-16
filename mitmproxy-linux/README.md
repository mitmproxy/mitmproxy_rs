# mitmproxy-linux

This package contains the following precompiled binaries for Linux:
 
 - `mitmproxy-linux-redirector`: A Rust executable that redirects traffic to mitmproxy via eBPF.


## Build Dependencies

This package requires the following software to build (via https://aya-rs.dev/book/start/development/#prerequisites):

 - Rust nightly.
 - [bpf-linker]: `cargo install --locked bpf-linker`

## Redirector Development Setup

1. Install build dependencies (see above).
2. Install mitmproxy_linux as editable: `pip install -e .`
3. Remove `$VIRTUAL_ENV/bin/mitmproxy-linux-redirector`
4. Run something along the lines of `mitmdump --mode local:curl`.  
   You should see a `Development mode: Compiling mitmproxy-linux-redirector...` message.


[bpf-linker]: https://github.com/aya-rs/bpf-linker
