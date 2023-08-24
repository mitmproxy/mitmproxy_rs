#!/usr/bin/env python3

import tomllib
from pathlib import Path

with open("Cargo.toml", "rb") as f:
    version = tomllib.load(f)["workspace"]["package"]["version"]

pyproject_toml = Path("mitmproxy-rs/pyproject.toml")
contents = pyproject_toml.read_text()
contents = (
    contents
    .replace(f"mitmproxy_windows", f"mitmproxy_windows=={version}")
    .replace(f"mitmproxy_macos", f"mitmproxy_macos=={version}")
)
pyproject_toml.write_text(contents)
