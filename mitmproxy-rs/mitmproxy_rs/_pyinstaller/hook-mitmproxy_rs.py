import platform
from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("mitmproxy_rs")

hiddenimports = []

match platform.system():
    case "Darwin":
        hiddenimports.append("mitmproxy_macos")
    case "Windows":
        hiddenimports.append("mitmproxy_windows")
    case "Linux":
        hiddenimports.append("mitmproxy_linux")
