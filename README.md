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

## TODO

* better and more complete IPv6 support
* better and more helpful logging
* unit tests
* mitmproxy Integration
* various other `TODO` and `FIXME` items (documented in the code)

## Hacking

Run the following commands to set up a Python virtual environment and compile
our Rust module, then follow the WireGuard instructions from the final command:

```shell
python3 -m venv venv
source ./venv/bin/activate
pip install maturin
maturin develop
python3 ./echo_test_server.py
```

Use `maturin develop --release` to compile the native module with optimizations
turned on. This will improve performance and reduce the size of the binary to
about 4MB.

---

The asynchronous runtime can be introspected using `tokio-console` when using
a debug build of the native module:

```shell
tokio-console http://localhost:6669
```

There should be no task that is busy when the program is idle, i.e. there should
be no busy waiting.

Note: This requires `maturin>=0.12.15`, as earlier versions accidentally
clobbered the `RUSTFLAGS` that were passed to the Rust compiler, breaking use
of the `console_subscriber` for `tokio-console`, which requires using the
`--cfg tokio_unstable` flag.
