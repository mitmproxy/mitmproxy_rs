use criterion::{criterion_group, criterion_main, Criterion};
#[cfg(target_os = "macos")]
use mitmproxy::processes;
#[cfg(windows)]
use mitmproxy::windows::{icons, processes};

#[cfg(windows)]
use windows::Win32::System::LibraryLoader::GetModuleHandleW;

#[allow(unused_variables)]
fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(windows)]
    {
        // FIXME Outdated
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
    }

    #[cfg(any(windows, target_os = "macos"))]
    {
        c.bench_function("active_executables", |b| {
            b.iter(processes::active_executables)
        });

        c.bench_function("visible_windows", |b| {
            b.iter(processes::bench::visible_windows)
        });

        #[cfg(target_os = "macos")]
        let test_executable = std::path::PathBuf::from(
            "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
        );
        #[cfg(windows)]
        let test_executable = {
            let mut test_executable = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            test_executable.push("benches\\openvpnserv.exe");
            test_executable
        };

        c.bench_function("get_png", |b| {
            b.iter(|| {
                processes::bench::IconCache::default()
                    .get_png(test_executable.clone())
                    .unwrap();
            })
        });

        let mut cache = processes::bench::IconCache::default();
        cache.get_png(test_executable.clone()).unwrap();
        c.bench_function("get_png (cached)", |b| {
            b.iter(|| {
                cache.get_png(test_executable.clone()).unwrap();
            })
        });

        #[cfg(target_os = "macos")]
        c.bench_function("tiff_data_for_executable", |b| {
            b.iter(|| unsafe {
                processes::bench::tiff_data_for_executable(&test_executable).unwrap();
            })
        });

        #[cfg(target_os = "macos")]
        c.bench_function("tiff_to_png", |b| {
            let tiff =
                unsafe { processes::bench::tiff_data_for_executable(&test_executable).unwrap() };
            b.iter(|| {
                processes::bench::tiff_to_png(&tiff);
            })
        });
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
