import os
import re
import subprocess
import logging
import http.client
import json
from typing import Callable

logging.basicConfig(format="[%(asctime)s] %(message)s", level=logging.INFO)

logger = logging.getLogger(__name__)

github_repository: str
project: str
branch: str
get_version: Callable[[], str]

if github_repository := os.environ.get("GITHUB_REPOSITORY", None):
    logger.info(f"Got repository from environment: {github_repository}")
else:
    _origin_url = subprocess.check_output(
        ["git", "remote", "get-url", "--push", "origin"], text=True
    ).strip()
    github_repository = re.search(r"^git@github\.com:(.+)\.git$", _origin_url)[1]
    logger.info(f"Got repository from Git: {github_repository}")

if project := os.environ.get("PROJECT_NAME", None):
    logger.info(f"Got project name from $PROJECT_NAME: {project}")
else:
    project = github_repository.partition("/")[2]
    logger.info(f"Got project name from repository url: {project}")

branch = subprocess.check_output(["git", "branch", "--show-current"], text=True).strip()

_version: str | None
if _version := os.environ.get("PROJECT_VERSION", None):
    logger.info(f"Got project version from $PROJECT_VERSION: {_version}")
elif os.environ.get("GITHUB_REF", "").startswith("refs/tags/"):
    _version = os.environ["GITHUB_REF_NAME"]
    logger.info(f"Got project version from $GITHUB_REF: {_version}")
else:
    _version = None
    logger.info("No version information found.")


def get_version() -> str:
    if _version is None:
        raise RuntimeError("No version information found.")
    assert re.match(r"^\d+\.\d+\.\d+$", _version), f"Invalid version: {_version}"
    return _version


def get_next_dev_version() -> str:
    version = get_version().split(".")
    if version[0] == "0":
        version[1] = str(int(version[1]) + 1)
    else:
        version[0] = str(int(version[0]) + 1)
    return ".".join(version) + "-dev"


def get_tag_name() -> str:
    return f"{os.environ.get('GIT_TAG_PREFIX', '')}{get_version()}"


def http_get(url: str) -> http.client.HTTPResponse:
    assert url.startswith("https://")
    host, path = re.split(r"(?=/)", url.removeprefix("https://"), maxsplit=1)
    logger.info(f"GET {host} {path}")
    conn = http.client.HTTPSConnection(host)
    conn.request("GET", path, headers={"User-Agent": "mhils/run-tools"})
    resp = conn.getresponse()
    print(f"HTTP {resp.status} {resp.reason}")
    return resp


def http_get_json(url: str) -> dict:
    resp = http_get(url)
    body = resp.read()
    try:
        return json.loads(body)
    except Exception as e:
        raise RuntimeError(f"{resp.status=} {body=}") from e
