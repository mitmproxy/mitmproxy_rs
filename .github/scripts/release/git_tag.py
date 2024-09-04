#!/usr/bin/env -S python3 -u
import logging
import subprocess

from common import get_tag_name

logger = logging.getLogger(__name__)


def git_tag(name: str = ""):
    logger.info("➡️ Git tag...")
    subprocess.check_call(["git", "tag", name or get_tag_name()])


if __name__ == "__main__":
    git_tag()
