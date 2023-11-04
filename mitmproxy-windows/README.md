# mitmproxy-windows

This package contains the following precompiled binaries for Windows:
 
 - `windows-redirector.exe`: A Rust executable that redirects traffic to mitmproxy via a Windows named pipe.
 - A vendored copy of [WinDivert](https://reqrypt.org/windivert.html), used by the redirector.


## Redirector Development Setup

1. Run `pip install -e .` to install `mitmproxy_windows` as editable.
2. Run something along the lines of `mitmdump --mode local:curl`.  
   You should see a `Development mode: Compiling windows-redirector.exe...` message.
