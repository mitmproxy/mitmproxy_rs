# Contributing

## Development Setup

To get started hacking on mitmproxy_rs, please [install mitmproxy as described 
in the main mitmproxy repository](https://github.com/mitmproxy/mitmproxy/blob/main/CONTRIBUTING.md#development-setup)
and [install the latest Rust release](https://www.rust-lang.org/tools/install). Make sure that you have mitmproxy's
virtualenv acticvated and run the following:

```shell
pip install maturin
git clone https://github.com/mitmproxy/mitmproxy_rs.git

# Windows only workaround for https://github.com/rust-lang/cargo/issues/9096
cd mitmproxy_rs && cargo build --package windows-redirector && cd ..

cd mitmproxy_rs/ffi
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

1. Make sure that...
   - you are on the `main` branch with a clean working tree.
   - `cargo test` is passing without errors.
2. Bump the version in [`Cargo.toml`](Cargo.toml).
3. Update [`CHANGELOG.md`](./CHANGELOG.md).
4. Commit the changes and tag them.
   - Convention: Tag name is simply the version number, e.g. `1.0.1`.
5. Manually confirm the CI deploy step on GitHub.
