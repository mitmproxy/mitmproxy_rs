## 0.1.2

- Revert addition of `ChecksumCapabilities::ignored` to the virtual network device.
  This change in v0.1.1 completely broke TCP connection handling.

## 0.1.1

- Added a simple test client binary (`mitm-wg-test-client`).
- Ignore TCP checksums in network device code, they are already checked in other places.
- Port to boringtun v0.5.

## 0.1.0

Initial Release.
