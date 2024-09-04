#!/usr/bin/env -S python3 -u
import logging
import subprocess
import sys

from common import project, get_version

logger = logging.getLogger(__name__)


def git_commit(message: str = ""):
    logger.info("➡️ Git commit...")
    subprocess.check_call(
        [
            "git",
            *("-c", f"user.name={project} run bot"),
            *("-c", "user.email=git-run-bot@maximilianhils.com"),
            "commit",
            "--all",
            *("-m", message or f"{project} {get_version()}"),
        ]
    )


if __name__ == "__main__":
    git_commit(sys.argv[1] if len(sys.argv) > 1 else "")
