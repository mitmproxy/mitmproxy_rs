import sysconfig
import os.path

binaries = [
    (os.path.join(sysconfig.get_path("scripts"), "mitmproxy-linux-redirector"), ".")
]
