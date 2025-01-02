import sys
import sysconfig
from pathlib import Path


def executable_path() -> Path:
    """
    Return the Path for mitmproxy-linux-redirector.

    For PyInstaller binaries this is the bundled executable,
    for wheels this is the file in the package,
    for development setups this may invoke cargo to build it.
    """

    if getattr(sys, 'frozen', False) and (pyinstaller_dir := getattr(sys, '_MEIPASS')):
        return Path(pyinstaller_dir) / "mitmproxy-linux-redirector"
    else:
        here = Path(__file__).parent.absolute()
        scripts = Path(sysconfig.get_path("scripts")).absolute()
        exe = scripts / "mitmproxy-linux-redirector"

        # Development path: This should never happen with precompiled wheels.
        if not exe.exists() and (here / "../Cargo.toml").exists():
            import logging
            import subprocess

            logger = logging.getLogger(__name__)
            logger.warning("Development mode: Compiling mitmproxy-linux-redirector...")

            # Build Redirector
            subprocess.run(["cargo", "build"], cwd=here.parent, check=True)
            target_debug = here.parent.parent / "target/debug"

            logger.warning("Development mode: Using target/debug/linux-redirector...")
            exe = target_debug / "mitmproxy-linux-redirector"

        return exe
