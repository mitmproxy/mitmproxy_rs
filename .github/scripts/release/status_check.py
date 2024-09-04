#!/usr/bin/env -S python3 -u
import logging
import os
import subprocess

from common import branch, github_repository, http_get_json

logger = logging.getLogger(__name__)


def status_check():
    if os.environ.get("STATUS_CHECK_SKIP_GIT", None) == "true":
        logger.warning("⚠️ Skipping check whether Git repo is clean.")
    else:
        logger.info("➡️ Working dir clean?")
        out = subprocess.check_output(["git", "status", "--porcelain"])
        assert not out, "repository is not clean"

    if os.environ.get("STATUS_CHECK_SKIP_CI", None) == "true":
        logger.warning(f"⚠️ Skipping status check for {branch}.")
    else:
        logger.info(f"➡️ CI is passing for {branch}?")
        check_runs = http_get_json(
            f"https://api.github.com/repos/{github_repository}/commits/{branch}/check-runs"
        )["check_runs"]
        for check_run in check_runs:
            match check_run["conclusion"]:
                case "success" | "skipped":
                    pass
                case None:
                    logger.warning(f"⚠️ CI job still running: {check_run['name']}")
                case _:
                    raise RuntimeError(f"❌ CI job failed: {check_run['name']}")



if __name__ == "__main__":
    status_check()
