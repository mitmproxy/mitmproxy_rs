use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(windows)]
use mitmproxy::process::process_name;

#[allow(unused_variables)]
fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(windows)]
    let pid = std::process::id();
    #[cfg(windows)]
    c.bench_function("current process name", |b| b.iter(|| process_name(pid)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
