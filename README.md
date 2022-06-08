# mitmproxy_wireguard

Transparently proxy any device that can be configured as a WireGuard client!

*Work-In-Progress.*

## Architecture

![library architecture](architecture.png)

## DONE

* multi-threaded / asynchronous WireGuard server using tokio:
  * one worker thread for the user-space WireGuard server
  * one worker thread for the user-space network stack
  * one worker thread for communicating with the Python runtime
* basic TCP/IPv4 functionality, IPv6 only partially supported
* basic UDP functionality
* Python interface similar to the one provided by `asyncio.start_server`
* basic support for reading WireGuard configuration files

## TODO

* better and more complete IPv6 support
* better and more helpful logging
* unit tests
* mitmproxy Integration
* various other `TODO` and `FIXME` items (documented in the code)

## Hacking

Setting up the development environment is relatively straightforward,
as only a Rust toolchain and Python 3 are required:

```shell
# set up a new venv
python3 -m venv venv

# enter venv (use the activation script for your shell)
source ./venv/bin/activate

# install maturin and pdoc
pip install maturin pdoc
```

Compiling the native Rust module then becomes easy:

```shell
# compile native Rust module and install it in venv
maturin develop

# compile native Rust module with optimizations
maturin develop --release
```

Once that's done (phew! Rust sure does take a while to compile!), the test
echo server should work correctly. It will print instructions for connecting to
it over a WireGuard VPN:

```shell
python3 ./echo_test_server.py
```

## Docs

Documentation for the Python module can be built with `pdoc`.

The documentation is built from the `mitmproxy_wireguard.pyi` type stubs and the
rustdoc documentation strings themselves. So to generate the documentation, the
native module needs to be rebuilt, as well:

```shell
maturin develop
pdoc mitmproxy_wireguard
```

By default, this will build the documentation in HTML format and serve it on
<http://localhost:8080>.

**Note**: This requires version `>=11.2.0` of pdoc. It is the first version that
supports generating documentation for "native-only" Python modules (like our
`mitmproxy_wireguard` PyO3 module).

## Introspecting the tokio runtime

The asynchronous runtime can be introspected using `tokio-console` when using
a debug build of the native module:

```shell
tokio-console http://localhost:6669
```

There should be no task that is busy when the program is idle, i.e. there should
be no busy waiting.

**Note**: This requires `maturin>=0.12.15`, as earlier versions accidentally
clobbered the `RUSTFLAGS` that were passed to the Rust compiler, breaking use
of the `console_subscriber` for `tokio-console`, which requires using the
`--cfg tokio_unstable` flag.

## Code style

The format for Rust code is enforced by `rustfmt.toml`. Some used configuration
options are only available on nightly Rust. To apply the formatting rules, use:

```shell
cargo +nightly fmt
```

The format for Python code (i.e. the test echo server and the type stubs in
`mitmproxy_wireguard.pyi`) is enforced with `black` and can be applied with:

```shell
black echo_test_server.py mitmproxy_wireguard.pyi
```
