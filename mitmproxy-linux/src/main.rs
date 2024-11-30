#[cfg(target_os = "linux")]
include!("main2.rs");

#[cfg(not(target_os = "linux"))]
pub fn main() {
    panic!("The Linux redirector works on Linux only.");
}
