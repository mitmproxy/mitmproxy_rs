# mitmproxy_wireguard

Transparently proxy any device that can be configured as a WireGuard client!

*Work-In-Progress.*

## Architecture

![library architecture](architecture.png)

## DONE

* multi-threaded / asynchronous WireGuard server using tokio:
  * one worker thread for WireGuard UDP connection
  * one worker thread for each configured WireGuard peer
* (very) basic TCP/IPv4 functionality
* hook up remaining entry points of the TCP stack
* expose Reader/Writer pairs for every socket connection
* provide `asyncio.start_server` compatible python bindings with PyO3
  (accept handler / callback function (reader, writer) as argument)

## TODO

* basic IPv6 support
* better error handling / logging
* various other `TODO` and `FIXME` items documented in the source code
* Tests
* Mitmproxy Integration

## Hacking

Run the following commands to set up a Python virtual environment
and compile our Rust module, then follow the WireGuard instructions from the final command:

```shell
python3 -m venv venv
source ./venv/bin/activate
pip install maturin
maturin develop
python3 ./echo_test_server.py
```

---------------------

For debug builds, the library can be introspected using `tokio-console`:

```shell
tokio-console http://localhost:6669
```

There should be no task that is busy when the program is idle, i.e. there should be no busy waiting.
