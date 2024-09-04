#!/usr/bin/env -S python3 -u
import logging
import subprocess

from common import branch, get_tag_name

logger = logging.getLogger(__name__)


def git_push(*identifiers: str):
    logger.info("➡️ Git push...")
    if not identifiers:
        identifiers = [
            branch,
            get_tag_name(),
        ]
    subprocess.check_call(["git", "push", "--atomic", "origin", *identifiers])


if __name__ == "__main__":
    git_push()
