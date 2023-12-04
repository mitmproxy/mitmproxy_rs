# mitmproxy_rs

[![autofix.ci: enabled](https://shields.mitmproxy.org/badge/autofix.ci-yes-success?logo=data:image/svg+xml;base64,PHN2ZyBmaWxsPSIjZmZmIiB2aWV3Qm94PSIwIDAgMTI4IDEyOCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48cGF0aCB0cmFuc2Zvcm09InNjYWxlKDAuMDYxLC0wLjA2MSkgdHJhbnNsYXRlKC0yNTAsLTE3NTApIiBkPSJNMTMyNSAtMzQwcS0xMTUgMCAtMTY0LjUgMzIuNXQtNDkuNSAxMTQuNXEwIDMyIDUgNzAuNXQxMC41IDcyLjV0NS41IDU0djIyMHEtMzQgLTkgLTY5LjUgLTE0dC03MS41IC01cS0xMzYgMCAtMjUxLjUgNjJ0LTE5MSAxNjl0LTkyLjUgMjQxcS05MCAxMjAgLTkwIDI2NnEwIDEwOCA0OC41IDIwMC41dDEzMiAxNTUuNXQxODguNSA4MXExNSA5OSAxMDAuNSAxODAuNXQyMTcgMTMwLjV0MjgyLjUgNDlxMTM2IDAgMjU2LjUgLTQ2IHQyMDkgLTEyNy41dDEyOC41IC0xODkuNXExNDkgLTgyIDIyNyAtMjEzLjV0NzggLTI5OS41cTAgLTEzNiAtNTggLTI0NnQtMTY1LjUgLTE4NC41dC0yNTYuNSAtMTAzLjVsLTI0MyAtMzAwdi01MnEwIC0yNyAzLjUgLTU2LjV0Ni41IC01Ny41dDMgLTUycTAgLTg1IC00MS41IC0xMTguNXQtMTU3LjUgLTMzLjV6TTEzMjUgLTI2MHE3NyAwIDk4IDE0LjV0MjEgNTcuNXEwIDI5IC0zIDY4dC02LjUgNzN0LTMuNSA0OHY2NGwyMDcgMjQ5IHEtMzEgMCAtNjAgNS41dC01NCAxMi41bC0xMDQgLTEyM3EtMSAzNCAtMiA2My41dC0xIDU0LjVxMCA2OSA5IDEyM2wzMSAyMDBsLTExNSAtMjhsLTQ2IC0yNzFsLTIwNSAyMjZxLTE5IC0xNSAtNDMgLTI4LjV0LTU1IC0yNi41bDIxOSAtMjQydi0yNzZxMCAtMjAgLTUuNSAtNjB0LTEwLjUgLTc5dC01IC01OHEwIC00MCAzMCAtNTMuNXQxMDQgLTEzLjV6TTEyNjIgNjE2cS0xMTkgMCAtMjI5LjUgMzQuNXQtMTkzLjUgOTYuNWw0OCA2NCBxNzMgLTU1IDE3MC41IC04NXQyMDQuNSAtMzBxMTM3IDAgMjQ5IDQ1LjV0MTc5IDEyMXQ2NyAxNjUuNWg4MHEwIC0xMTQgLTc3LjUgLTIwNy41dC0yMDggLTE0OXQtMjg5LjUgLTU1LjV6TTgwMyA1OTVxODAgMCAxNDkgMjkuNXQxMDggNzIuNWwyMjEgLTY3bDMwOSA4NnE0NyAtMzIgMTA0LjUgLTUwdDExNy41IC0xOHE5MSAwIDE2NSAzOHQxMTguNSAxMDMuNXQ0NC41IDE0Ni41cTAgNzYgLTM0LjUgMTQ5dC05NS41IDEzNHQtMTQzIDk5IHEtMzcgMTA3IC0xMTUuNSAxODMuNXQtMTg2IDExNy41dC0yMzAuNSA0MXEtMTAzIDAgLTE5Ny41IC0yNnQtMTY5IC03Mi41dC0xMTcuNSAtMTA4dC00MyAtMTMxLjVxMCAtMzQgMTQuNSAtNjIuNXQ0MC41IC01MC41bC01NSAtNTlxLTM0IDI5IC01NCA2NS41dC0yNSA4MS41cS04MSAtMTggLTE0NSAtNzB0LTEwMSAtMTI1LjV0LTM3IC0xNTguNXEwIC0xMDIgNDguNSAtMTgwLjV0MTI5LjUgLTEyM3QxNzkgLTQ0LjV6Ii8+PC9zdmc+)](https://autofix.ci)
[![Continuous Integration Status](https://github.com/mitmproxy/mitmproxy_rs/workflows/CI/badge.svg?branch=main)](https://github.com/mitmproxy/mitmproxy_rs/actions?query=branch%3Amain)
[![Latest Version](https://shields.mitmproxy.org/pypi/v/mitmproxy-rs.svg)](https://pypi.python.org/pypi/mitmproxy-wireguard)
[![Supported Python versions](https://shields.mitmproxy.org/pypi/pyversions/mitmproxy.svg)](https://pypi.python.org/pypi/mitmproxy)
![PyPI - Wheel](https://shields.mitmproxy.org/pypi/wheel/mitmproxy-rs)


This repository contains mitmproxy's Rust bits, most notably:

 - WireGuard Mode: The ability to proxy any device that can be configured as a WireGuard client.
 - Local Redirect Mode: The ability to proxy arbitrary macOS or Windows applications by name or pid.


## Contributing

[![Dev Guide](https://shields.mitmproxy.org/badge/docs-CONTRIBUTING.md-blue)](https://github.com/mitmproxy/mitmproxy_rs/blob/main/CONTRIBUTING.md)
[![dev documentation](https://shields.mitmproxy.org/badge/docs-Python%20API-blue.svg)](https://mitmproxy.github.io/mitmproxy_rs/)

### Structure

- [`src/`](./src): The `mitmproxy` crate containing most of the "meat".
- [`mitmproxy-rs/`](./mitmproxy-rs): The `mitmproxy-rs` Python package,
  which provides PyO3 bindings for the Rust crate.  
  Source and binary distributions are available [on PyPI](https://pypi.org/project/mitmproxy-rs/).
- [`mitmproxy-macos/`](./mitmproxy-macos): The `mitmproxy-macos` Python package, which
  contains a macOS Network Extension to transparently intercept macOS traffic.  
  Only a binary distribution is available [on PyPI](https://pypi.org/project/mitmproxy-macos/)
  due to code signing and notarization requirements.
- [`mitmproxy-windows/`](./mitmproxy-windows): The `mitmproxy-windows` Python package, which
  contains the Windows traffic redirector based on WinDivert.  
  Only a binary distribution is available [on PyPI](https://pypi.org/project/mitmproxy-windows/)
  due to build complexity.

### Architecture

![library architecture](architecture.png)
