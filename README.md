# mitmguard

work-in-progress WireGuard front for mitmproxy

## Architecture

![](architecture.png)

## DONE

* multi-threaded / asynchronous WireGuard server using tokio:
  * one worker thread for WireGuard UDP connection
  * one worker thread for each configured WireGuard peer
* (very) basic TCP/IPv4 functionality

## TODO

* hook up remaining entry points of the TCP stack
* basic IPv6 support
* expose Reader/Writer pairs for every socket connection
* provide `asyncio.start_server` compatible python bindings with PyO3
  (accept handler / callback function (reader, writer) as argument)
* better error handling / logging
* various other `TODO` and `FIXME` items documented in the source code
