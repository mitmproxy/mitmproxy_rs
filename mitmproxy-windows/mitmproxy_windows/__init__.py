from pathlib import Path

here = Path(__file__).parent.absolute()
executable_path = here / "windows-redirector.exe"

# Development path: This should never happen with precompiled wheels.
if not executable_path.exists() and (here / "editable.marker").exists():
    import logging
    import shutil
    import subprocess

    logger = logging.getLogger(__name__)
    logger.warning("Development mode: Compiling windows-redirector.exe...")

    # Build Redirector
    subprocess.run(["cargo", "build"], cwd=here.parent / "redirector", check=True)
    # Copy WinDivert to target/debug/
    target_debug = here.parent.parent / "target/debug"
    for f in ["WinDivert.dll", "WinDivert.lib", "WinDivert64.sys"]:
        if not (target_debug / f).exists():
            shutil.copy(here / f, target_debug / f)

    logger.warning("Development mode: Using target/debug/windows-redirector.exe...")
    executable_path = target_debug / "windows-redirector.exe"
