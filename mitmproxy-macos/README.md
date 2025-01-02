# mitmproxy-macos

This package contains the following precompiled binaries for macOS:

 - `macos-certificate-truster.app`: A helper app written in Rust to mark the mitmproxy CA as trusted.
 - `Mitmproxy Redirector.app`: The app bundle that sets up and hosts the network extension for redirecting traffic.

## Redirector Development Setup

The macOS Network System Extension needs to be signed and notarized during development.
You need to reconfigure the XCode project to use your own (paid) Apple Developer Account.