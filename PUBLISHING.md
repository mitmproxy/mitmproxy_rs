## Publishing to PyPI

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

