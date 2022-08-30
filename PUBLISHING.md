## Publishing to PyPI

### Building and publishing with GitHub actions

For every tag that is pushed to the mitmproxy_wireguard project on [GitHub], a
GitHub action is triggered that builds binary wheels and a source distribution
for all specified targets. If this is successful, the source distribution and
binary wheels are automatically uploaded to PyPI.

[GitHub]: https://github.com/decathorpe/mitmproxy_wireguard

To upload files manually, use something like this command, assuming that
username and password (or API token) are set up in configuration files or
set in environment variables:

```shell
twine upload dist/*
```

### Building and publishing manually

A docker container provided by the `maturin` project needs to be used to publish
manylinux-compatible wheels on PyPI.

```shell
docker run --rm -v $(pwd):/io ghcr.io/pyo3/maturin publish --username FOO --password BAR
```

If 2-Factor-Authentication is enabled on the PyPI account, the token-based
authentication method needs to be used instead:

```shell
docker run --rm -v $(pwd):/io ghcr.io/pyo3/maturin publish --username __token__ --password TOKEN
```

**NOTE**: When using `podman` instead of `docker`, the `--privileged` flag needs
to be supplied to the `run` command to ensure the `/io` directory is mounted
correctly.

