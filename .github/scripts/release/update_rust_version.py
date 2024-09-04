#!/usr/bin/env -S python3 -u
import logging
import re
import subprocess
import sys
from pathlib import Path

from common import get_version

logger = logging.getLogger(__name__)


def update_rust_version(version: str = ""):
    logger.info("➡️ Updating Cargo.toml...")
    path = Path("Cargo.toml")
    cl = path.read_text("utf8")
    cl, ok = re.subn(
        r"""
    (
        ^\[(?:workspace\.)?package]\n # [package] or [workspace.package] toml block
        (?:(?!\[).*\n)*               # lines not starting a new section
        version[ \t]*=[ \t]*"         # beginning of the version line
    )
    [^"]+
    """,
        rf"\g<1>{version or get_version()}",
        cl,
        flags=re.VERBOSE | re.MULTILINE,
    )
    assert ok == 1, f"{ok=}"
    path.write_text(cl, "utf8")

    subprocess.check_call(["cargo", "update", "--workspace"])


if __name__ == "__main__":
    update_rust_version(sys.argv[1] if len(sys.argv) > 1 else "")
