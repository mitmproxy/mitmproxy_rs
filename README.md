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

## Hacking

Right now, the default logger is configured to print all messages with
level `DEBUG` or higher. This will be raised to `INFO` once the project is
no longer in the prototype phase. To set the logger verbosity manually,
use the `MG_LOG` environment variable (i.e. `MG_LOG=info`).

The mitmguard binary provides support for using `tokio-console` to introspect
the current state of the tokio runtime, with the default settings:

```
$ tokio-console http://localhost:6669
```

There should be no task that is busy when the program is idle, i.e. there
should be no busy waiting.

