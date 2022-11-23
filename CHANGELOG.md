## 0.2.0

- `mitmproxy_wireguard` is now `mitmproxy_rs`.
  As indicated by the name change, the scope of the project now goes beyond WireGuard.
- Add transparent proxy functionality for Windows.

## 0.1.18

- Expose the "original" (i.e. not the address inside the WireGuard tunnel) source address
  of WireGuard UDP packets in TcpStream via `TcpStream.get_extra_info("original_src")`.
- Internal refactoring to simplify code for spawning TCP connection handler coroutines,
  which makes it possible to check whether they raised an exception (which were previously
  just silently ignored).
- Update all Rust dependencies, including an update to PyO3 v0.17.3, which is the first
  release that marked support for Python 3.11 as official.

## 0.1.17

- Ensure that the virtual network device does not block unnecessarily and that
  it is always polled when necessary. Fixes a regression that was introduced
  in version 0.1.16.

## 0.1.16

- Optimize event processing in the internal network stack by always consuming as
  many events as possible before polling the virtual network device and processing
  open TCP sockets.
- Ensure that only one TCP socket is created per connection, even if `SYN` packets
  are resent for some reason.
- Channel sizes for processing events in the internal network stack are increased
  to avoid errors with full channels when some tasks don't keep up.
- Logging calls are removed from the network task's hot loop unless the project
  is built in `debug` mode.
- Failures to send to channels that were already closed when processing data
  that was received for sockets are now ignored to avoid crashes.

## 0.1.15

- Manually include source files for the test client binary in published `sdist`s to
  ensure the sources which are published on PyPI can actually be built.

## 0.1.14

- Increase buffer size for WireGuard packets to accommodate large outgoing packets.
- Check length of outgoing packets and drop packets that are larger than the maximum
  possible WireGuard packet payload (maximum packet size - WireGuard header length)
  to avoid crashes with super-sized packets.

## 0.1.13

- Update dependencies to the latest versions (pyo3 v0.17, pyo3-asyncio v0.17, pyo3-log v0.7),
  now that pyo3-asyncio v0.17 was released with pyo3 v0.17 support.
- Switch back from patched version of pyo3-asyncio to the official releases, since v0.17
  incorporates our patch.

## 0.1.12

- Fix a race condition in the shutdown code that could cause shutdown to never happen.
- Make logger setup more robust and only try to initialize once.

## 0.1.11

- Make failures to initialize the Rust -> Python logger non-fatal.

## 0.1.10

- Temporarily use a patched version of `pyo3-asyncio` to fix a race condition in the handling
  of Python `Future`s which caused frequent race conditions.
- Implement `is_closing(self) -> bool` method on `TcpStream` to match `asyncio.StreamWriter`.

## 0.1.9

- Simplified GitHub actions for CI and publishing wheels to PyPI.
- Failed sub-tasks are now handled immediately and cause a server shutdown
  instead of silently returning and only yielding an error when shutting down
  the server manually.

## 0.1.8

- Fix building binary wheels for `aarch64-unknown-linux-gnu`.

## 0.1.7

- Do not exit the network task when a draining TcpStream is already closed. 
- Make log messages for "no current WireGuard session" more user-friendly.
- Attempt to build binary wheels for `aarch64-unknown-linux-gnu` for Raspberry
  Pi support.

## 0.1.6

- Fix test client to only send valid packets.

## 0.1.5

- Adapt the test client to handle EAGAIN gracefully.

## 0.1.4

- Split test client into separate workspace crate to speed up builds and
  hopefully fix them on macOS.

## 0.1.3

- Adapt test client to produce packets with correct checksums.
- Build test client binaries in the `publish` GitHub Action.
- Stop building binary wheels for 32-bit Linux and Windows targets.
- Validate TCP checksums and reject invalid incoming packets early.
- Lower priority of log messages for non-fatal `TcpStream` cleanup errors during
  server shutdown.

## 0.1.2

- Revert addition of `ChecksumCapabilities::ignored` to the virtual network device.
  This change in v0.1.1 completely broke TCP connection handling.

## 0.1.1

- Added a simple test client binary (`mitm-wg-test-client`).
- Ignore TCP checksums in network device code, they are already checked in other places.
- Port to boringtun v0.5.

## 0.1.0

Initial Release.
