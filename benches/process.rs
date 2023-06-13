use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(windows)]
use mitmproxy::windows::{icons, processes};

#[cfg(windows)]
use windows::Win32::System::LibraryLoader::GetModuleHandleW;

#[allow(unused_variables)]
fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(windows)]
    {
        let hinst = unsafe { GetModuleHandleW(None).unwrap() };
        let pid = std::process::id();
        let mut test_exe = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_exe.push("benches\\openvpnserv.exe");
        let test_exe = test_exe;

        c.bench_function("is_critical", |b| {
            b.iter(|| processes::get_is_critical(pid))
        });
        c.bench_function("get_process_name", |b| {
            b.iter(|| processes::get_process_name(pid))
        });
        c.bench_function("enumerate_pids", |b| b.iter(processes::enumerate_pids));
        c.bench_function("get_display_name", |b| {
            b.iter(|| processes::get_display_name(&test_exe))
        });
        c.bench_function("get_icon", |b| {
            b.iter(|| {
                icons::IconCache::default()
                    .get_png(test_exe.clone())
                    .unwrap();
            })
        });

        let mut icon_cache = icons::IconCache::default();
        c.bench_function("get_icon (cached)", |b| {
            b.iter(|| {
                icon_cache.get_png(test_exe.clone()).unwrap();
            })
        });

        c.bench_function("visible_windows", |b| b.iter(processes::visible_windows));
        c.bench_function("active_executables", |b| {
            b.iter(processes::active_executables)
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
