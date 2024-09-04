# mitmproxy-windows

This package contains the following precompiled binaries for Windows:
 
 - `windows-redirector.exe`: A Rust executable that redirects traffic to mitmproxy via a Windows named pipe.
 - A vendored copy of [WinDivert](https://reqrypt.org/windivert.html), used by the redirector.


## Redirector Development Setup

1. Run `pip install -e .` to install `mitmproxy_windows` as editable.
2. Add an empty file called `editable.marker` to the `mitmproxy_windows` directory.
3. Run something along the lines of `mitmdump --mode local:curl`.  
   You should see a `Development mode: Compiling windows-redirector.exe...` message.
