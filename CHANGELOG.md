## 0.1.4

- Split test client into separate workspace crate to speed up builds and
  and hopefully fix them on macos.

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
