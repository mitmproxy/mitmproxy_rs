> **Note**
> This repository is unreleased work-in-progress, but mitmproxy 9 ships with [mitmproxy_wireguard](https://github.com/decathorpe/mitmproxy_wireguard) already!


# mitmproxy_rs

[![autofix.ci: enabled](https://shields.mitmproxy.org/badge/autofix.ci-yes-success?logo=data:image/svg+xml;base64,PHN2ZyBmaWxsPSIjZmZmIiB2aWV3Qm94PSIwIDAgMTI4IDEyOCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCB0cmFuc2Zvcm09InNjYWxlKDAuMDYxLC0wLjA2MSkgdHJhbnNsYXRlKC0yNTAsLTE3NTApIiBkPSJNMTMyNSAtMzQwcS0xMTUgMCAtMTY0LjUgMzIuNXQtNDkuNSAxMTQuNXEwIDMyIDUgNzAuNXQxMC41IDcyLjV0NS41IDU0djIyMHEtMzQgLTkgLTY5LjUgLTE0dC03MS41IC01cS0xMzYgMCAtMjUxLjUgNjJ0LTE5MSAxNjl0LTkyLjUgMjQxcS05MCAxMjAgLTkwIDI2NnEwIDEwOCA0OC41IDIwMC41dDEzMiAxNTUuNXQxODguNSA4MXExNSA5OSAxMDAuNSAxODAuNXQyMTcgMTMwLjV0MjgyLjUgNDlxMTM2IDAgMjU2LjUgLTQ2IHQyMDkgLTEyNy41dDEyOC41IC0xODkuNXExNDkgLTgyIDIyNyAtMjEzLjV0NzggLTI5OS41cTAgLTEzNiAtNTggLTI0NnQtMTY1LjUgLTE4NC41dC0yNTYuNSAtMTAzLjVsLTI0MyAtMzAwdi01MnEwIC0yNyAzLjUgLTU2LjV0Ni41IC01Ny41dDMgLTUycTAgLTg1IC00MS41IC0xMTguNXQtMTU3LjUgLTMzLjV6TTEzMjUgLTI2MHE3NyAwIDk4IDE0LjV0MjEgNTcuNXEwIDI5IC0zIDY4dC02LjUgNzN0LTMuNSA0OHY2NGwyMDcgMjQ5IHEtMzEgMCAtNjAgNS41dC01NCAxMi41bC0xMDQgLTEyM3EtMSAzNCAtMiA2My41dC0xIDU0LjVxMCA2OSA5IDEyM2wzMSAyMDBsLTExNSAtMjhsLTQ2IC0yNzFsLTIwNSAyMjZxLTE5IC0xNSAtNDMgLTI4LjV0LTU1IC0yNi41bDIxOSAtMjQydi0yNzZxMCAtMjAgLTUuNSAtNjB0LTEwLjUgLTc5dC01IC01OHEwIC00MCAzMCAtNTMuNXQxMDQgLTEzLjV6TTEyNjIgNjE2cS0xMTkgMCAtMjI5LjUgMzQuNXQtMTkzLjUgOTYuNWw0OCA2NCBxNzMgLTU1IDE3MC41IC04NXQyMDQuNSAtMzBxMTM3IDAgMjQ5IDQ1LjV0MTc5IDEyMXQ2NyAxNjUuNWg4MHEwIC0xMTQgLTc3LjUgLTIwNy41dC0yMDggLTE0OXQtMjg5LjUgLTU1LjV6TTgwMyA1OTVxODAgMCAxNDkgMjkuNXQxMDggNzIuNWwyMjEgLTY3bDMwOSA4NnE0NyAtMzIgMTA0LjUgLTUwdDExNy41IC0xOHE5MSAwIDE2NSAzOHQxMTguNSAxMDMuNXQ0NC41IDE0Ni41cTAgNzYgLTM0LjUgMTQ5dC05NS41IDEzNHQtMTQzIDk5IHEtMzcgMTA3IC0xMTUuNSAxODMuNXQtMTg2IDExNy41dC0yMzAuNSA0MXEtMTAzIDAgLTE5Ny41IC0yNnQtMTY5IC03Mi41dC0xMTcuNSAtMTA4dC00MyAtMTMxLjVxMCAtMzQgMTQuNSAtNjIuNXQ0MC41IC01MC41bC01NSAtNTlxLTM0IDI5IC01NCA2NS41dC0yNSA4MS41cS04MSAtMTggLTE0NSAtNzB0LTEwMSAtMTI1LjV0LTM3IC0xNTguNXEwIC0xMDIgNDguNSAtMTgwLjV0MTI5LjUgLTEyM3QxNzkgLTQ0LjV6Ii8+PC9zdmc+)](https://autofix.ci)
[![Continuous Integration Status](https://github.com/mitmproxy/mitmproxy_rs/workflows/CI/badge.svg?branch=main)](https://github.com/mitmproxy/mitmproxy_rs/actions?query=branch%3Amain)
[![Latest Version](https://shields.mitmproxy.org/pypi/v/mitmproxy-wireguard.svg)](https://pypi.python.org/pypi/mitmproxy-wireguard)
[![Supported Python versions](https://shields.mitmproxy.org/pypi/pyversions/mitmproxy.svg)](https://pypi.python.org/pypi/mitmproxy)
![PyPI - Wheel](https://shields.mitmproxy.org/pypi/wheel/mitmproxy-wireguard)
[![dev documentation](https://shields.mitmproxy.org/badge/docs-dev-brightgreen.svg)](https://mitmproxy.github.io/mitmproxy_rs/)


This repository contains mitmproxy's Rust bits, most notably:

 - WireGuard Mode: The ability to proxy any device that can be configured as a WireGuard client.
 - Windows OS Proxy Mode: The ability to proxy arbitrary Windows applications by name or pid.

## Supported Architectures

`mitmproxy_wireguard` should work on most architectures / targets - including,
but not limited to Windows, macOS, and Linux, running on x86_64 (x64) and
aarch64 (arm64) CPUs.

Binary wheels for the following targets are available from PyPI:

- Windows / x64 (`x86_64-windows-msvc`)
- macOS / Intel (`x86_64-apple-darwin`)
- macos / Apple Silicon (`aarch64-apple-darwin`) via "Universal 2" binaries
- Linux / x86_64 (`x86_64-unknown-linux-gnu`)
- Linux / aarch64 (`aarch64-unknown-linux-gnu`), i.e. for Raspberry Pi 2+ and similar devices

## Architecture

![library architecture](architecture.png)

## Build Requirements

- Python 3.9+
- Rust 1.65+
- maturin 0.14+

## Python API 

[![dev documentation](https://shields.mitmproxy.org/badge/docs-dev-brightgreen.svg)](https://mitmproxy.github.io/mitmproxy_rs/)

## Hacking

Setting up the development environment is relatively straightforward,
as only a Rust toolchain and Python 3 are required:

```shell
# set up a new venv
python3 -m venv venv

# enter venv (use the activation script for your shell)
source ./venv/bin/activate

pip install maturin
```

Compiling the native Rust module then becomes easy:

```shell
# compile native Rust module and install it in venv
maturin develop
```

Once that's done (phew! Rust sure does take a while to compile!), the test
echo server should work correctly. It will print instructions for connecting to
it over a WireGuard VPN:

```shell
python3 ./wireguard_echo_test_server.py
```

The included `mitm-wg-test-client` binary can be used to test this echo test
server, which can be built by running `cargo build` inside the `test-client`
directory, and launched from `target/debug/mitm-wg-test-client`.

## Introspecting the tokio runtime

The asynchronous runtime can be introspected using `tokio-console` if the crate
was built with the `tracing` feature:

```shell
tokio-console http://localhost:6669
```

There should be no task that is busy when the program is idle, i.e. there should
be no busy waiting.

## Code style

The format for Rust code is enforced by `rustfmt`.
To apply the formatting rules, use:

```shell
cargo fmt
```

The format for Python code (i.e. the test echo server and the type stubs in
`mitmproxy_wireguard.pyi`) is enforced with `black` and can be applied with:

```shell
black wireguard_echo_test_server.py mitmproxy_rs.pyi benches/*.py
```
