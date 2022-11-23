use criterion::{criterion_group, criterion_main, Criterion};
use mitmproxy::process::process_name;


fn criterion_benchmark(c: &mut Criterion) {
    let pid = std::process::id();
    c.bench_function("current process name", |b| b.iter(|| process_name(pid)));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
