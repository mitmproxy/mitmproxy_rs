# Contributing

## Development Setup

To get started hacking on mitmproxy_rs, please [install mitmproxy as described 
in the main mitmproxy repository](https://github.com/mitmproxy/mitmproxy/blob/main/CONTRIBUTING.md#development-setup)
and [install the latest Rust release](https://www.rust-lang.org/tools/install). Make sure that you have mitmproxy's
virtualenv activated and then run the following:

```shell
git clone https://github.com/mitmproxy/mitmproxy_rs.git
cd mitmproxy_rs/mitmproxy-rs
maturin develop
```

mitmproxy now uses your locally-compiled version of `mitmproxy_rs`. **After applying any changes to the Rust code, 
re-run `maturin develop` and restart mitmproxy** for changes to apply.


## Testing

If you've followed the procedure above, you can run the basic test suite as follows:

```shell
cargo test
```

Please ensure that all patches are accompanied by matching changes in the test suite.


## Code Style

The format for Rust code is enforced by `cargo fmt`.  
Pull requests will be automatically fixed by CI.


## Introspecting the tokio runtime

The asynchronous runtime can be introspected using `tokio-console` if the crate
was built with the `tracing` feature:

```shell
tokio-console http://localhost:6669
```

There should be no task that is busy when the program is idle, i.e. there should
be no busy waiting.


## Release Process

If you are the current maintainer of mitmproxy_rs,
you can perform the following steps to ship a release:

1. Make sure that CI is passing without errors.
2. Make sure that CHANGELOG.md is up-to-date with all entries in the "Unreleased" section.
3. Invoke the release workflow from the GitHub UI: https://github.com/mitmproxy/mitmproxy_rs/actions/workflows/release.yml
4. The spawned workflow run will require manual deploy confirmation on GitHub: https://github.com/mitmproxy/mitmproxy/actions
