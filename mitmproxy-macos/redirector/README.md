# Mitmproxy Redirector for macOS

- `macos-redirector`: The app bundle that sets up and hosts the network extension.
- `network-extension`: The network extension that redirects traffic.
- `ipc`: Inter-process protobuf communication between proxy (Rust) and redirector (Swift).


## High-Level Overview

When starting transparent interception on macOS, the following things happen:

1. mitmproxy-rs' `start_local_redirector` copies the redirector application into `/Applications`,
   which is a prerequisite for installing system extensions.
2. mitmproxy-rs opens a unix socket listener.
2. mitmproxy-rs starts the `macos-redirector` app, passing the unix socket as an argument.
3. The macos-redirector app installs system extension and sets up the transparent proxy configuration.
4. As a result the network extension is started by the OS. It immediately opens a unix socket to mitmproxy-rs acting as a control channel.
5. mitmproxy-rs will pass the intercept spec (describing which apps to intercept) to the network extension.
6. The network extension receives all new TCP/UDP flows on the system. 
   If the intercept spec matches, it intercepts the connection, opens a new unix socket to mitmproxy-rs and copies over all message contents.
   Using a separate unix socket per flow ensure that each connection has its own dedicated buffers + backpressure.
